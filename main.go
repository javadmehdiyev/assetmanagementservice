package main

import (
	"fmt"
	"log"
	"time"

	"assetmanager/pkg/network"
)

func main() {
	// Example 1: Parse CIDR to IP range
	cidr := "192.168.123.0/24"
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

	// Choose which scanner to test
	useParallelScanner := true

	if useParallelScanner {
		testParallelScanner()
	} else {
		testBasicScanner()
	}
}

func testBasicScanner() {
	// Example 3: Basic ARP scan
	fmt.Println("\nTesting basic ARP scanner...")

	// Note: This requires root/admin privileges
	scanner, err := network.NewARPScanner("eth0", 2*time.Second)
	if err != nil {
		log.Fatalf("Failed to create ARP scanner: %v", err)
	}
	defer scanner.Close()

	testCIDR := "172.26.52.40/29" // Small range for testing
	fmt.Printf("Scanning IP range: %s\n", testCIDR)

	results, err := scanner.ScanNetwork(testCIDR)
	if err != nil {
		log.Fatalf("ARP scan failed: %v", err)
	}

	printResults(results)
}

func testParallelScanner() {
	// Example 4: Parallel ARP scan
	fmt.Println("\nTesting parallel ARP scanner...")

	// Create a parallel scanner with 5 workers and 100ms rate limit
	scanner, err := network.NewParallelARPScanner("eth0", 2*time.Second, 100, 100*time.Millisecond)
	if err != nil {
		log.Fatalf("Failed to create parallel ARP scanner: %v", err)
	}
	defer scanner.Close()

	// Test option 1: Scan a specific CIDR
	testCIDR := "172.26.48.0/20" // Small range for testing
	fmt.Printf("Scanning IP range: %s\n", testCIDR)

	results, err := scanner.ScanNetworkParallel(testCIDR)
	if err != nil {
		log.Fatalf("Parallel ARP scan failed: %v", err)
	}

	printResults(results)

	// Test option 2: Scan from list.txt file
	fmt.Println("\nScanning from list.txt file...")
	fileResults, err := scanner.ScanCIDRFiles("list.txt")
	if err != nil {
		log.Printf("Warning: File-based scanning failed: %v", err)
	} else {
		printResults(fileResults)
	}
}

func printResults(results []network.ARPResult) {
	fmt.Println("ARP Scan Results:")
	if len(results) == 0 {
		fmt.Println("No devices found.")
	} else {
		for _, result := range results {
			fmt.Printf("IP: %s, MAC: %s, Vendor: %s\n", result.IP, result.MAC, result.Vendor)
		}
	}
}
