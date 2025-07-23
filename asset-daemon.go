package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"assetmanager/pkg/config"
	"assetmanager/pkg/network"
	"assetmanager/utilities"
)

type AssetResult struct {
	Timestamp   string          `json:"timestamp"`
	TotalHosts  int             `json:"total_hosts"`
	ScanTime    string          `json:"scan_time"`
	LocalNet    string          `json:"local_network"`
	FileTargets int             `json:"file_targets"`
	Assets      []network.Asset `json:"assets"`
}

func main() {
	log.Println("Asset Management Daemon Starting...")

	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		log.Printf("Config load failed, using defaults: %v", err)
		cfg = config.GetDefaultConfig()
		saveDefaultConfig()
	}

	log.Printf("Service: %s", cfg.Service.Name)
	log.Printf("Scan Interval: %s", cfg.Service.ScanInterval)

	discovery, err := createAssetDiscovery(cfg)
	if err != nil {
		log.Fatalf("Failed to create asset discovery: %v", err)
	}
	defer discovery.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := createTicker(cfg.Service.ScanInterval)
	defer ticker.Stop()

	log.Println("Daemon started. Press Ctrl+C to stop.")

	performScan(cfg, discovery)

	for {
		select {
		case <-ticker.C:
			performScan(cfg, discovery)
		case <-stop:
			log.Println("Daemon stopping...")
			return
		}
	}
}

func createAssetDiscovery(cfg *config.Config) (*network.AssetDiscovery, error) {
	arpTimeout, err := cfg.GetARPTimeout()
	if err != nil {
		log.Printf("Invalid ARP timeout, using default: %v", err)
		arpTimeout = 2 * time.Second
	}

	portTimeout, err := cfg.GetPortScanTimeout()
	if err != nil {
		log.Printf("Invalid port timeout, using default: %v", err)
		portTimeout = 2 * time.Second
	}

	rateLimit, err := cfg.GetARPRateLimit()
	if err != nil {
		log.Printf("Invalid ARP rate limit, using default: %v", err)
		rateLimit = 100 * time.Millisecond
	}

	interfaceName := cfg.Network.Interface
	if interfaceName == "auto" {

		ifAutoInterface, err := utilities.GetMainNetworkInterface()
		if err != nil {
			log.Fatalf("Failed to get main network interface: %v", err)
		}
		interfaceName = ifAutoInterface.Name
	}

	discovery, err := network.NewAssetDiscovery(
		interfaceName,
		arpTimeout,
		portTimeout,
		cfg.ARP.Workers,
		rateLimit,
	)
	if err != nil {
		return nil, err
	}

	return discovery, nil
}

func performScan(cfg *config.Config, discovery *network.AssetDiscovery) {
	log.Println("Starting asset discovery scan...")
	startTime := time.Now()

	var allAssets []network.Asset
	localCIDR := getLocalNetwork(cfg)

	// Scan local network using ARP
	if cfg.Network.ScanLocalNetwork {
		localAssets := scanLocalNetwork(cfg, discovery)
		allAssets = append(allAssets, localAssets...)
		log.Printf("Local network: found %d assets", len(localAssets))
	}

	// Scan file targets using ARP (excluding local network)
	if cfg.Network.ScanFileList {
		fileAssets := scanFileTargetsExcluding(cfg, discovery, localCIDR)
		allAssets = append(allAssets, fileAssets...)
		log.Printf("File targets (ARP): found %d assets", len(fileAssets))
	}

	// Scan public assets using ping/TCP/UDP
	if cfg.PublicScan.Enabled {
		publicAssets := scanPublicAssets(cfg)
		allAssets = append(allAssets, publicAssets...)
		log.Printf("Public assets: found %d assets", len(publicAssets))
	}

	uniqueAssets := removeDuplicateAssets(allAssets)
	log.Printf("After deduplication: %d unique assets (reduced from %d)", len(uniqueAssets), len(allAssets))

	scanDuration := time.Since(startTime)

	result := AssetResult{
		Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
		TotalHosts:  len(uniqueAssets),
		ScanTime:    scanDuration.String(),
		LocalNet:    localCIDR,
		FileTargets: countFileTargets(cfg.Files.IPListFile),
		Assets:      uniqueAssets,
	}

	saveResult(result, cfg.Files.OutputFile)
	log.Printf("Scan completed: %d unique assets in %v", len(uniqueAssets), scanDuration)
}

func scanLocalNetwork(cfg *config.Config, discovery *network.AssetDiscovery) []network.Asset {
	localCIDR := getLocalNetwork(cfg)
	if localCIDR == "" {
		return []network.Asset{}
	}

	log.Printf("Scanning local network: %s", localCIDR)

	assets, err := discovery.DiscoverAssets(localCIDR, cfg.PortScan.Enabled)
	if err != nil {
		log.Printf("Local network scan failed: %v", err)
		return []network.Asset{}
	}

	return assets
}

func scanFileTargetsExcluding(cfg *config.Config, discovery *network.AssetDiscovery, excludeCIDR string) []network.Asset {
	cidrs, err := network.ReadCIDRsFromFile(cfg.Files.IPListFile)
	if err != nil {
		log.Printf("Failed to read CIDR file: %v", err)
		return []network.Asset{}
	}

	var allAssets []network.Asset
	for _, cidr := range cidrs {
		if cidr == excludeCIDR {
			log.Printf("Skipping %s (already scanned as local network)", cidr)
			continue
		}

		log.Printf("Scanning file target: %s", cidr)
		assets, err := discovery.DiscoverAssets(cidr, cfg.PortScan.Enabled)
		if err != nil {
			log.Printf("Error scanning CIDR %s: %v", cidr, err)
			continue
		}
		allAssets = append(allAssets, assets...)
	}

	return allAssets
}

// scanPublicAssets scans public IP addresses using ping, TCP, and UDP
func scanPublicAssets(cfg *config.Config) []network.Asset {
	// Read targets from file
	targets, err := network.ReadTargetsFromFile(cfg.Files.IPListFile)
	if err != nil {
		log.Printf("Failed to read targets from file: %v", err)
		return []network.Asset{}
	}

	if len(targets) == 0 {
		log.Println("No public targets found in file")
		return []network.Asset{}
	}

	localCIDR := getLocalNetwork(cfg)
	filteredTargets := filterOutLocalIPs(targets, localCIDR)

	if len(filteredTargets) == 0 {
		log.Println("No public targets remaining after filtering local IPs")
		return []network.Asset{}
	}

	log.Printf("Scanning %d public targets", len(filteredTargets))

	timeout, err := cfg.GetPublicScanTimeout()
	if err != nil {
		log.Printf("Invalid public scan timeout, using default: %v", err)
		timeout = 5 * time.Second
	}

	scanner := network.NewPublicAssetScanner(timeout, cfg.PublicScan.Workers, 2)
	defer scanner.Close()

	tcpPorts := cfg.PublicScan.TCPPorts
	if len(tcpPorts) == 0 {
		tcpPorts = network.GetCommonTCPPorts()
	}

	udpPorts := cfg.PublicScan.UDPPorts
	if len(udpPorts) == 0 {
		udpPorts = network.GetCommonUDPPorts()
	}

	publicAssets, err := scanner.ScanPublicAssets(filteredTargets, tcpPorts, udpPorts)
	if err != nil {
		log.Printf("Public scan failed: %v", err)
		return []network.Asset{}
	}

	var assets []network.Asset
	for _, publicAsset := range publicAssets {
		assets = append(assets, publicAsset.ToAsset())
	}

	return assets
}

func filterOutLocalIPs(targets []string, localCIDR string) []string {
	if localCIDR == "" {
		return targets
	}

	_, localNet, err := net.ParseCIDR(localCIDR)
	if err != nil {
		log.Printf("Invalid local CIDR %s: %v", localCIDR, err)
		return targets
	}

	var filtered []string
	for _, target := range targets {
		ip := net.ParseIP(target)
		if ip != nil && !localNet.Contains(ip) {
			filtered = append(filtered, target)
		}
	}

	return filtered
}

func saveResult(result AssetResult, outputFile string) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Printf("JSON marshal failed: %v", err)
		return
	}

	err = ioutil.WriteFile(outputFile, data, 0644)
	if err != nil {
		log.Printf("File write failed: %v", err)
		return
	}

	log.Printf("Results saved to: %s", outputFile)
}

func getLocalNetwork(cfg *config.Config) string {
	if cfg.Network.AutoDetectLocal {
		if localCIDR, err := network.GetLocalNetworkCIDR(); err == nil {
			return localCIDR
		}
	}
	return cfg.Network.DefaultCIDR
}

func countFileTargets(filename string) int {
	targets, err := network.ReadCIDRsFromFile(filename)
	if err != nil {
		return 0
	}
	return len(targets)
}

func createTicker(interval string) *time.Ticker {
	duration, err := time.ParseDuration(interval)
	if err != nil {
		duration = 5 * time.Minute
	}
	return time.NewTicker(duration)
}

func saveDefaultConfig() {
	cfg := config.GetDefaultConfig()
	err := config.SaveConfig(cfg, "config.json")
	if err != nil {
		log.Printf("Failed to save default config: %v", err)
	} else {
		log.Println("Default config.json created")
	}
}

func removeDuplicateAssets(assets []network.Asset) []network.Asset {
	assetMap := make(map[string]*network.Asset)

	for _, asset := range assets {
		if existing, ok := assetMap[asset.IP]; ok {
			if existing.MAC == "" && asset.MAC != "" {
				existing.MAC = asset.MAC
			}

			if existing.Vendor == "" && asset.Vendor != "" {
				existing.Vendor = asset.Vendor
			}

			if existing.Hostname == "" && asset.Hostname != "" {
				existing.Hostname = asset.Hostname
			}

			if len(asset.OpenPorts) > 0 {
				existing.OpenPorts = mergePortResults(existing.OpenPorts, asset.OpenPorts)
			}

			if asset.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = asset.LastSeen
			}

			if asset.ARPResponse {
				existing.ARPResponse = true
			}

		} else {
			newAsset := asset
			assetMap[asset.IP] = &newAsset
		}
	}

	var uniqueAssets []network.Asset
	for _, asset := range assetMap {
		uniqueAssets = append(uniqueAssets, *asset)
	}

	return uniqueAssets
}

func mergePortResults(existing, new []network.PortScanResult) []network.PortScanResult {
	portMap := make(map[int]network.PortScanResult)

	for _, port := range existing {
		portMap[port.Port] = port
	}

	for _, port := range new {
		portMap[port.Port] = port
	}

	var merged []network.PortScanResult
	for _, port := range portMap {
		merged = append(merged, port)
	}

	return merged
}
