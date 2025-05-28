package main

import (
	"fmt"
	"log"
	"os"

	"assetmanager/pkg/config"
	"assetmanager/pkg/network"
)

func main() {
	// Load configuration
	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("Warning: Failed to load config from %s: %v\n", configPath, err)
		fmt.Println("Creating default configuration...")
		
		// Create default config and save it
		cfg = config.GetDefaultConfig()
		if err := config.SaveConfig(cfg, configPath); err != nil {
			log.Fatalf("Failed to save default config: %v", err)
		}
		fmt.Printf("Default configuration saved to %s\n", configPath)
	}

	fmt.Printf("=== %s Started ===\n", cfg.Service.Name)
	fmt.Printf("Configuration loaded from: %s\n", configPath)

	// Choose which demo to run based on configuration
	demoARP := cfg.ARP.Enabled
	demoPortScan := cfg.PortScan.Enabled
	demoAssetDiscovery := true // Always run asset discovery if enabled

	if demoARP {
		testARPScanner(cfg)
	}

	if demoPortScan {
		testPortScanner(cfg)
	}

	if demoAssetDiscovery {
		testAssetDiscovery(cfg)
	}
}

func testARPScanner(cfg *config.Config) {
	fmt.Println("\n=== ARP Scanner Demo ===")

	// Get timeouts from configuration
	arpTimeout, err := cfg.GetARPTimeout()
	if err != nil {
		log.Fatalf("Invalid ARP timeout in config: %v", err)
	}

	rateLimit, err := cfg.GetARPRateLimit()
	if err != nil {
		log.Fatalf("Invalid ARP rate limit in config: %v", err)
	}

	// Determine interface
	interfaceName := cfg.Network.Interface
	if interfaceName == "auto" {
		// You might want to implement auto-detection logic here
		interfaceName = "ens33" // fallback
	}

	// Create a parallel scanner with configuration values
	scanner, err := network.NewParallelARPScanner(
		interfaceName,
		arpTimeout,
		cfg.ARP.Workers,
		rateLimit,
	)
	if err != nil {
		log.Fatalf("Failed to create parallel ARP scanner: %v", err)
	}
	defer scanner.Close()

	// Get network to scan
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

	fmt.Printf("Scanning network: %s\n", targetCIDR)
	results, err := scanner.ScanNetworkParallel(targetCIDR)
	if err != nil {
		log.Fatalf("Parallel ARP scan failed: %v", err)
	}

	printARPResults(results)
}

func testPortScanner(cfg *config.Config) {
	fmt.Println("\n=== Port Scanner Demo ===")

	// Get timeout from configuration
	portTimeout, err := cfg.GetPortScanTimeout()
	if err != nil {
		log.Fatalf("Invalid port scan timeout in config: %v", err)
	}

	// Create a port scanner with configuration values
	scanner := network.NewPortScanner(portTimeout, cfg.PortScan.Workers, 1)

	// Use a test IP - you might want to make this configurable too
	ip := "127.0.0.1"
	fmt.Printf("Scanning %s for configured ports...\n", ip)

	// If common ports are configured, scan them
	if len(cfg.PortScan.CommonPorts) > 0 {
		fmt.Printf("Scanning %d common ports...\n", len(cfg.PortScan.CommonPorts))
		for _, port := range cfg.PortScan.CommonPorts {
			if cfg.PortScan.ScanTCP {
				results, err := scanner.ScanPorts(ip, port, port, network.ScanTCP)
				if err != nil {
					log.Printf("TCP port scan failed for port %d: %v", port, err)
					continue
				}
				printPortResults(results)
			}
		}
	}

	// If custom ports are configured, scan them
	if len(cfg.PortScan.CustomPorts) > 0 {
		fmt.Printf("Scanning %d custom ports...\n", len(cfg.PortScan.CustomPorts))
		for _, port := range cfg.PortScan.CustomPorts {
			if cfg.PortScan.ScanTCP {
				results, err := scanner.ScanPorts(ip, port, port, network.ScanTCP)
				if err != nil {
					log.Printf("TCP port scan failed for port %d: %v", port, err)
					continue
				}
				printPortResults(results)
			}
		}
	}

	// If range scanning is enabled
	if cfg.PortScan.PortRangeStart > 0 && cfg.PortScan.PortRangeEnd > 0 {
		fmt.Printf("Scanning port range %d-%d on %s...\n", 
			cfg.PortScan.PortRangeStart, cfg.PortScan.PortRangeEnd, ip)
		
		if cfg.PortScan.ScanTCP {
			rangeResults, err := scanner.ScanPorts(ip, 
				cfg.PortScan.PortRangeStart, 
				cfg.PortScan.PortRangeEnd, 
				network.ScanTCP)
			if err != nil {
				log.Fatalf("Port range scan failed: %v", err)
			}
			printPortResults(rangeResults)
		}
	}
}

func testAssetDiscovery(cfg *config.Config) {
	fmt.Println("\n=== Asset Discovery Demo ===")

	// Get timeouts from configuration
	arpTimeout, err := cfg.GetARPTimeout()
	if err != nil {
		log.Fatalf("Invalid ARP timeout in config: %v", err)
	}

	portTimeout, err := cfg.GetPortScanTimeout()
	if err != nil {
		log.Fatalf("Invalid port scan timeout in config: %v", err)
	}

	rateLimit, err := cfg.GetARPRateLimit()
	if err != nil {
		log.Fatalf("Invalid ARP rate limit in config: %v", err)
	}

	// Determine interface
	interfaceName := cfg.Network.Interface
	if interfaceName == "auto" {
		interfaceName = "ens33" // fallback - you might want to implement auto-detection
	}

	// Create asset discovery service with configuration values
	discovery, err := network.NewAssetDiscovery(
		interfaceName,
		arpTimeout,
		portTimeout,
		cfg.ARP.Workers,
		rateLimit,
	)
	if err != nil {
		log.Fatalf("Failed to create asset discovery service: %v", err)
	}
	defer discovery.Close()

	// Discover assets from local network if enabled
	if cfg.Network.ScanLocalNetwork {
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

		fmt.Printf("Discovering assets on %s (port scanning: %v)...\n", 
			targetCIDR, cfg.PortScan.Enabled)
		
		assets, err := discovery.DiscoverAssets(targetCIDR, cfg.PortScan.Enabled)
		if err != nil {
			log.Fatalf("Asset discovery failed: %v", err)
		}
		printAssets(assets)
	}

	// Discover assets from file if enabled
	if cfg.Network.ScanFileList {
		fmt.Printf("\nDiscovering assets from %s...\n", cfg.Files.IPListFile)
		fileAssets, err := discovery.DiscoverAssetsFromFile(cfg.Files.IPListFile, cfg.PortScan.Enabled)
		if err != nil {
			log.Printf("Warning: File-based asset discovery failed: %v", err)
		} else {
			printAssets(fileAssets)
		}
	}

	// Save results to output file if configured
	if cfg.Files.OutputFile != "" {
		fmt.Printf("\nNote: Results can be saved to %s (not implemented in demo)\n", cfg.Files.OutputFile)
	}
}

func printARPResults(results []network.ARPResult) {
	fmt.Println("ARP Scan Results:")
	if len(results) == 0 {
		fmt.Println("No devices found.")
	} else {
		for _, result := range results {
			fmt.Printf("IP: %s, MAC: %s, Vendor: %s\n", result.IP, result.MAC, result.Vendor)
		}
	}
}

func printPortResults(results []network.PortScanResult) {
	fmt.Println("Port Scan Results:")
	if len(results) == 0 {
		fmt.Println("No open ports found.")
	} else {
		openPorts := 0
		for _, result := range results {
			if result.State == network.PortOpen {
				fmt.Printf("Open port: %s:%d (%s) %s\n",
					result.IP, result.Port, result.Protocol, result.Service)
				if result.Banner != "" {
					fmt.Printf("  Banner: %s\n", result.Banner)
				}
				openPorts++
			}
		}

		if openPorts == 0 {
			fmt.Println("No open ports found.")
		}
	}
}

func printAssets(assets []network.Asset) {
	fmt.Printf("Discovered %d assets:\n", len(assets))
	if len(assets) == 0 {
		fmt.Println("No assets found.")
	} else {
		for i, asset := range assets {
			fmt.Printf("%d. IP: %s, MAC: %s, Vendor: %s\n",
				i+1, asset.IP, asset.MAC, asset.Vendor)

			if asset.Hostname != "" {
				fmt.Printf("   Hostname: %s\n", asset.Hostname)
			}

			if len(asset.OpenPorts) > 0 {
				fmt.Printf("   Open ports: %d\n", len(asset.OpenPorts))
				for _, port := range asset.OpenPorts {
					fmt.Printf("     %d/%s (%s)\n",
						port.Port, port.Protocol, port.Service)
					if port.Banner != "" {
						fmt.Printf("       Banner: %s\n", port.Banner)
					}
				}
			}
		}
	}
}
