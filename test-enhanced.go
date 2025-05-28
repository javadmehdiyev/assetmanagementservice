package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"assetmanager/pkg/config"
	"assetmanager/pkg/network"
)

func main() {
	// Load enhanced configuration
	configPath := "config.enhanced-discovery.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("Warning: Failed to load config from %s: %v\n", configPath, err)
		fmt.Println("Using default enhanced configuration...")
		cfg = getEnhancedConfig()
	}

	fmt.Printf("=== %s ===\n", cfg.Service.Name)
	fmt.Printf("Configuration: %s\n", configPath)

	// Get timeouts from configuration
	arpTimeout, err := cfg.GetARPTimeout()
	if err != nil {
		log.Fatalf("Invalid ARP timeout: %v", err)
	}

	portTimeout, err := cfg.GetPortScanTimeout()
	if err != nil {
		log.Fatalf("Invalid port timeout: %v", err)
	}

	arpRateLimit, err := cfg.GetARPRateLimit()
	if err != nil {
		log.Fatalf("Invalid ARP rate limit: %v", err)
	}

	// ICMP settings (use same timeout as ARP if not configured)
	icmpTimeout := arpTimeout
	icmpWorkers := 20

	// Determine interface
	interfaceName := cfg.Network.Interface
	if interfaceName == "auto" {
		interfaceName = "ens33" // fallback
	}

	// Create enhanced discovery service
	discovery, err := network.NewEnhancedDiscovery(
		interfaceName,
		arpTimeout,
		portTimeout,
		cfg.ARP.Workers,
		arpRateLimit,
		icmpWorkers,
		icmpTimeout,
	)
	if err != nil {
		log.Fatalf("Failed to create enhanced discovery: %v", err)
	}
	defer discovery.Close()

	// Get target network
	var targetCIDR string
	if cfg.Network.AutoDetectLocal {
		localCIDR, err := network.GetLocalNetworkCIDR()
		if err != nil {
			fmt.Printf("Warning: Failed to auto-detect local network: %v\n", err)
			targetCIDR = cfg.Network.DefaultCIDR
		} else {
			targetCIDR = localCIDR
		}
	} else {
		targetCIDR = cfg.Network.DefaultCIDR
	}

	fmt.Printf("\n=== Enhanced Discovery Test ===\n")
	fmt.Printf("Target Network: %s\n", targetCIDR)
	fmt.Printf("Methods: ARP + ICMP + TCP Discovery\n")
	fmt.Printf("Port Scanning: %v\n", cfg.PortScan.Enabled)

	// Perform enhanced discovery
	results, err := discovery.DiscoverHosts(targetCIDR, cfg.PortScan.Enabled)
	if err != nil {
		log.Fatalf("Enhanced discovery failed: %v", err)
	}

	// Print results
	network.PrintDiscoveryResults(results)

	// Comparison with original ARP-only method
	fmt.Printf("\n=== Comparison with ARP-only Discovery ===\n")
	testARPOnly(cfg, targetCIDR, interfaceName, arpTimeout, arpRateLimit)
}

func testARPOnly(cfg *config.Config, targetCIDR, interfaceName string, arpTimeout, arpRateLimit time.Duration) {
	// Original ARP-only discovery
	scanner, err := network.NewParallelARPScanner(interfaceName, arpTimeout, cfg.ARP.Workers, arpRateLimit)
	if err != nil {
		log.Printf("Failed to create ARP scanner: %v", err)
		return
	}
	defer scanner.Close()

	fmt.Printf("Running ARP-only discovery on %s...\n", targetCIDR)
	arpResults, err := scanner.ScanNetworkParallel(targetCIDR)
	if err != nil {
		log.Printf("ARP scan failed: %v", err)
		return
	}

	fmt.Printf("ARP-only Results: %d hosts found\n", len(arpResults))
	for i, result := range arpResults {
		fmt.Printf("%d. %s - %s (%s)\n", i+1, result.IP, result.MAC, result.Vendor)
	}
}

func getEnhancedConfig() *config.Config {
	cfg := config.GetDefaultConfig()
	
	// Enhanced settings
	cfg.Service.Name = "Asset Management Service - Enhanced Discovery"
	cfg.ARP.Timeout = "5s"
	cfg.ARP.Workers = 10
	cfg.ARP.RateLimit = "50ms"
	cfg.ARP.RetryCount = 3
	
	cfg.PortScan.Enabled = true
	cfg.PortScan.Timeout = "3s"
	cfg.PortScan.Workers = 100
	cfg.PortScan.ScanUDP = true
	
	cfg.Logging.Level = "debug"
	
	return cfg
} 