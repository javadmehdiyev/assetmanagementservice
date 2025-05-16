package main

import (
	"fmt"
	"log"
	"time"

	"assetmanager/pkg/network"
)

func main() {
	// Choose which demo to run
	demoCIDR := true           // CIDR to IP conversion demo
	demoARP := false           // ARP scanning demo
	demoPortScan := true       // Port scanning demo
	demoAssetDiscovery := true // Asset discovery demo

	if demoCIDR {
		testCIDRConversion()
	}

	if demoARP {
		testARPScanner()
	}

	if demoPortScan {
		testPortScanner()
	}

	if demoAssetDiscovery {
		testAssetDiscovery()
	}
}

func testCIDRConversion() {
	fmt.Println("\n=== CIDR to IP Conversion Demo ===")

	// Example 1: Parse CIDR to IP range
	cidr := "192.168.1.0/28"
	ips, err := network.CIDRToIPRange(cidr)
	if err != nil {
		log.Fatalf("Failed to parse CIDR: %v", err)
	}
	fmt.Printf("CIDR %s contains %d IP addresses\n", cidr, len(ips))

	// Example 2: Get local network CIDR
	localCIDR, err := network.GetLocalNetworkCIDR()
	if err != nil {
		log.Printf("Failed to get local network CIDR: %v", err)
	} else {
		fmt.Printf("Local network CIDR: %s\n", localCIDR)
	}
}

func testARPScanner() {
	fmt.Println("\n=== ARP Scanner Demo ===")

	// Create a parallel scanner with 5 workers and 100ms rate limit
	scanner, err := network.NewParallelARPScanner("eth0", 2*time.Second, 5, 100*time.Millisecond)
	if err != nil {
		log.Fatalf("Failed to create parallel ARP scanner: %v", err)
	}
	defer scanner.Close()

	// Get local network for scanning
	localCIDR, err := network.GetLocalNetworkCIDR()
	if err != nil {
		localCIDR = "172.26.52.43/28" // Fallback to a smaller range
	}

	fmt.Printf("Scanning local network: %s\n", localCIDR)
	results, err := scanner.ScanNetworkParallel(localCIDR)
	if err != nil {
		log.Fatalf("Parallel ARP scan failed: %v", err)
	}

	printARPResults(results)
}

func testPortScanner() {
	fmt.Println("\n=== Port Scanner Demo ===")

	// Create a port scanner
	scanner := network.NewPortScanner(2*time.Second, 50, 1)

	// Scan localhost
	ip := "127.0.0.1"
	fmt.Printf("Scanning localhost (%s) for common ports...\n", ip)

	results, err := scanner.ScanHost(ip)
	if err != nil {
		log.Fatalf("Port scan failed: %v", err)
	}

	printPortResults(results)

	// Optional: Scan a specific port range
	fmt.Printf("\nScanning port range 80-85 on %s...\n", ip)
	rangeResults, err := scanner.ScanPorts(ip, 80, 85, network.ScanTCP)
	if err != nil {
		log.Fatalf("Port range scan failed: %v", err)
	}

	printPortResults(rangeResults)
}

func testAssetDiscovery() {
	fmt.Println("\n=== Asset Discovery Demo ===")

	// Create asset discovery service
	discovery, err := network.NewAssetDiscovery(
		"eth0",              // Interface name
		2*time.Second,       // ARP timeout
		1*time.Second,       // Port scan timeout
		50,                  // Number of workers
		50*time.Millisecond, // Rate limit
	)
	if err != nil {
		log.Fatalf("Failed to create asset discovery service: %v", err)
	}
	defer discovery.Close()

	// Get local network for scanning
	localCIDR, err := network.GetLocalNetworkCIDR()
	if err != nil {
		localCIDR = "172.26.52.43/28" // Fallback to a smaller range
	}

	// Discover assets (with port scanning)
	fmt.Printf("Discovering assets on %s (with port scanning)...\n", localCIDR)
	assets, err := discovery.DiscoverAssets(localCIDR, true)
	if err != nil {
		log.Fatalf("Asset discovery failed: %v", err)
	}

	printAssets(assets)

	// Optionally test file-based discovery
	fmt.Println("\nDiscovering assets from list.txt...")
	fileAssets, err := discovery.DiscoverAssetsFromFile("list.txt", true)
	if err != nil {
		log.Printf("Warning: File-based asset discovery failed: %v", err)
	} else {
		printAssets(fileAssets)
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
