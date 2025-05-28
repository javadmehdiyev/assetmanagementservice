package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"assetmanager/pkg/config"
	"assetmanager/pkg/network"
)

// AssetResult represents the final asset discovery result for JSON output
type AssetResult struct {
	Timestamp   string          `json:"timestamp"`
	TotalHosts  int             `json:"total_hosts"`
	ScanTime    string          `json:"scan_time"`
	LocalNet    string          `json:"local_network"`
	FileTargets int             `json:"file_targets"`
	Assets      []network.Asset `json:"assets"`
}

func main() {
	log.Println("🚀 Asset Management Daemon Starting...")

	// Load configuration
	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		log.Printf("Config load failed, using defaults: %v", err)
		cfg = config.GetDefaultConfig()
		saveDefaultConfig()
	}

	log.Printf("Service: %s", cfg.Service.Name)
	log.Printf("Scan Interval: %s", cfg.Service.ScanInterval)

	// Create asset discovery service
	discovery, err := createAssetDiscovery(cfg)
	if err != nil {
		log.Fatalf("Failed to create asset discovery: %v", err)
	}
	defer discovery.Close()

	// Setup graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start daemon loop
	ticker := createTicker(cfg.Service.ScanInterval)
	defer ticker.Stop()

	log.Println("✅ Daemon started. Press Ctrl+C to stop.")

	// First scan immediately
	performScan(cfg, discovery)

	for {
		select {
		case <-ticker.C:
			performScan(cfg, discovery)
		case <-stop:
			log.Println("🛑 Daemon stopping...")
			return
		}
	}
}

func createAssetDiscovery(cfg *config.Config) (*network.AssetDiscovery, error) {
	// Get timeouts from configuration
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

	// Determine interface
	interfaceName := cfg.Network.Interface
	if interfaceName == "auto" {
		interfaceName = "ens33" // fallback
	}

	// Create asset discovery service
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
	log.Println("📡 Starting asset discovery scan...")
	startTime := time.Now()

	var allAssets []network.Asset

	// Get local network CIDR for overlap detection
	localCIDR := getLocalNetwork(cfg)

	// 1. Scan local network
	if cfg.Network.ScanLocalNetwork {
		localAssets := scanLocalNetwork(cfg, discovery)
		allAssets = append(allAssets, localAssets...)
		log.Printf("Local network: found %d assets", len(localAssets))
	}

	// 2. Scan targets from file (excluding local network to avoid duplicates)
	if cfg.Network.ScanFileList {
		fileAssets := scanFileTargetsExcluding(cfg, discovery, localCIDR)
		allAssets = append(allAssets, fileAssets...)
		log.Printf("File targets: found %d assets", len(fileAssets))
	}

	// 3. Remove any remaining duplicates and merge information
	uniqueAssets := removeDuplicateAssets(allAssets)
	log.Printf("After deduplication: %d unique assets (reduced from %d)", len(uniqueAssets), len(allAssets))

	scanDuration := time.Since(startTime)

	// 4. Create result
	result := AssetResult{
		Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
		TotalHosts:  len(uniqueAssets),
		ScanTime:    scanDuration.String(),
		LocalNet:    localCIDR,
		FileTargets: countFileTargets(cfg.Files.IPListFile),
		Assets:      uniqueAssets,
	}

	// 5. Save result to JSON
	saveResult(result, cfg.Files.OutputFile)

	log.Printf("✅ Scan completed: %d unique assets in %v", len(uniqueAssets), scanDuration)
}

func scanLocalNetwork(cfg *config.Config, discovery *network.AssetDiscovery) []network.Asset {
	// Get local network
	localCIDR := getLocalNetwork(cfg)
	if localCIDR == "" {
		return []network.Asset{}
	}

	log.Printf("Scanning local network: %s", localCIDR)
	
	// Use the proper AssetDiscovery module
	assets, err := discovery.DiscoverAssets(localCIDR, cfg.PortScan.Enabled)
	if err != nil {
		log.Printf("Local network scan failed: %v", err)
		return []network.Asset{}
	}

	return assets
}

func scanFileTargetsExcluding(cfg *config.Config, discovery *network.AssetDiscovery, excludeCIDR string) []network.Asset {
	// Read CIDR ranges from file
	cidrs, err := network.ReadCIDRsFromFile(cfg.Files.IPListFile)
	if err != nil {
		log.Printf("Failed to read CIDR file: %v", err)
		return []network.Asset{}
	}

	var allAssets []network.Asset
	for _, cidr := range cidrs {
		// Skip if this CIDR is the same as local network to avoid duplicates
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

	log.Printf("📄 Results saved to: %s", outputFile)
}

// Helper functions
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
		duration = 5 * time.Minute // Default
	}
	return time.NewTicker(duration)
}

func saveDefaultConfig() {
	cfg := config.GetDefaultConfig()
	err := config.SaveConfig(cfg, "config.json")
	if err != nil {
		log.Printf("Failed to save default config: %v", err)
	} else {
		log.Println("📄 Default config.json created")
	}
}

// removeDuplicateAssets removes duplicate assets and merges their information
func removeDuplicateAssets(assets []network.Asset) []network.Asset {
	assetMap := make(map[string]*network.Asset)

	for _, asset := range assets {
		if existing, ok := assetMap[asset.IP]; ok {
			// Merge information from duplicate
			
			// Keep MAC address if we don't have one or if new one is not empty
			if existing.MAC == "" && asset.MAC != "" {
				existing.MAC = asset.MAC
			}
			
			// Keep vendor if we don't have one or if new one is not empty
			if existing.Vendor == "" && asset.Vendor != "" {
				existing.Vendor = asset.Vendor
			}
			
			// Keep hostname if we don't have one or if new one is not empty
			if existing.Hostname == "" && asset.Hostname != "" {
				existing.Hostname = asset.Hostname
			}
			
			// Merge open ports (avoid duplicates)
			if len(asset.OpenPorts) > 0 {
				existing.OpenPorts = mergePortResults(existing.OpenPorts, asset.OpenPorts)
			}
			
			// Update last seen to latest
			if asset.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = asset.LastSeen
			}
			
			// Update ARP response if new asset has it
			if asset.ARPResponse {
				existing.ARPResponse = true
			}
			
		} else {
			// Create new asset copy
			newAsset := asset
			assetMap[asset.IP] = &newAsset
		}
	}

	// Convert map back to slice
	var uniqueAssets []network.Asset
	for _, asset := range assetMap {
		uniqueAssets = append(uniqueAssets, *asset)
	}

	return uniqueAssets
}

// mergePortResults merges two slices of port results, removing duplicates
func mergePortResults(existing, new []network.PortScanResult) []network.PortScanResult {
	portMap := make(map[int]network.PortScanResult)
	
	// Add existing ports
	for _, port := range existing {
		portMap[port.Port] = port
	}
	
	// Add new ports (will overwrite if same port with potentially newer info)
	for _, port := range new {
		portMap[port.Port] = port
	}
	
	// Convert back to slice
	var merged []network.PortScanResult
	for _, port := range portMap {
		merged = append(merged, port)
	}
	
	return merged
} 