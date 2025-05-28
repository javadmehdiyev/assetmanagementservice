package main

import (
	"fmt"
	"log"
	"time"

	"assetmanager/pkg/network"
)

func main() {
	// Network configuration
	targetCIDR := "192.168.123.0/24"  // You can change this to your network
	interfaceName := "ens33"           // You can change this to your interface
	
	fmt.Printf("=== Quick Discovery Comparison ===\n")
	fmt.Printf("Target Network: %s\n", targetCIDR)
	fmt.Printf("Interface: %s\n\n", interfaceName)

	// Test 1: Original ARP-only discovery
	fmt.Printf("1. Testing ARP-only discovery...\n")
	arpStart := time.Now()
	arpResults := testARPOnly(targetCIDR, interfaceName)
	arpDuration := time.Since(arpStart)
	
	fmt.Printf("   ARP Results: %d hosts found in %v\n", len(arpResults), arpDuration)
	for i, result := range arpResults {
		fmt.Printf("   %d. %s - %s (%s)\n", i+1, result.IP, result.MAC, result.Vendor)
	}

	fmt.Printf("\n" + "="*50 + "\n\n")

	// Test 2: Enhanced discovery (ARP + ICMP + TCP) without port scanning
	fmt.Printf("2. Testing Enhanced discovery (ARP + ICMP + TCP)...\n")
	enhancedStart := time.Now()
	enhancedResults := testEnhancedDiscovery(targetCIDR, interfaceName)
	enhancedDuration := time.Since(enhancedStart)
	
	fmt.Printf("   Enhanced Results: %d hosts found in %v\n", len(enhancedResults), enhancedDuration)
	for i, result := range enhancedResults {
		fmt.Printf("   %d. %s", i+1, result.IP)
		
		var methods []string
		if result.FoundByARP {
			methods = append(methods, "ARP")
		}
		if result.FoundByICMP {
			methods = append(methods, "ICMP")
		}
		if result.FoundByTCP {
			methods = append(methods, "TCP")
		}
		fmt.Printf(" (Found by: %s)", fmt.Sprintf("%v", methods))
		
		if result.MAC != "" {
			fmt.Printf(" - %s", result.MAC)
		}
		if result.Vendor != "" {
			fmt.Printf(" (%s)", result.Vendor)
		}
		fmt.Println()
	}

	// Summary
	fmt.Printf("\n" + "="*50 + "\n")
	fmt.Printf("SUMMARY:\n")
	fmt.Printf("ARP-only:       %d hosts in %v\n", len(arpResults), arpDuration)
	fmt.Printf("Enhanced:       %d hosts in %v\n", len(enhancedResults), enhancedDuration)
	fmt.Printf("Improvement:    +%d hosts (%.1f%% increase)\n", 
		len(enhancedResults)-len(arpResults), 
		float64(len(enhancedResults)-len(arpResults))/float64(len(arpResults))*100)
	
	// Show hosts found only by enhanced methods
	arpIPs := make(map[string]bool)
	for _, result := range arpResults {
		arpIPs[result.IP] = true
	}
	
	var onlyEnhanced []network.DiscoveryResult
	for _, result := range enhancedResults {
		if !arpIPs[result.IP] {
			onlyEnhanced = append(onlyEnhanced, result)
		}
	}
	
	if len(onlyEnhanced) > 0 {
		fmt.Printf("\nHosts found ONLY by enhanced methods:\n")
		for i, result := range onlyEnhanced {
			var methods []string
			if result.FoundByICMP {
				methods = append(methods, "ICMP")
			}
			if result.FoundByTCP {
				methods = append(methods, "TCP")
			}
			fmt.Printf("  %d. %s (Found by: %v)\n", i+1, result.IP, methods)
		}
	}
}

func testARPOnly(targetCIDR, interfaceName string) []network.ARPResult {
	scanner, err := network.NewParallelARPScanner(
		interfaceName, 
		5*time.Second,  // timeout
		10,             // workers
		50*time.Millisecond, // rate limit
	)
	if err != nil {
		log.Printf("Failed to create ARP scanner: %v", err)
		return []network.ARPResult{}
	}
	defer scanner.Close()

	results, err := scanner.ScanNetworkParallel(targetCIDR)
	if err != nil {
		log.Printf("ARP scan failed: %v", err)
		return []network.ARPResult{}
	}

	return results
}

func testEnhancedDiscovery(targetCIDR, interfaceName string) []network.DiscoveryResult {
	discovery, err := network.NewEnhancedDiscovery(
		interfaceName,
		5*time.Second,   // ARP timeout
		3*time.Second,   // Port timeout
		10,              // ARP workers
		50*time.Millisecond, // ARP rate limit
		20,              // ICMP workers
		3*time.Second,   // ICMP timeout
	)
	if err != nil {
		log.Printf("Failed to create enhanced discovery: %v", err)
		return []network.DiscoveryResult{}
	}
	defer discovery.Close()

	results, err := discovery.DiscoverHosts(targetCIDR, false) // No port scanning for speed
	if err != nil {
		log.Printf("Enhanced discovery failed: %v", err)
		return []network.DiscoveryResult{}
	}

	return results
} 