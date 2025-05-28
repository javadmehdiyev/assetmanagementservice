package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"assetmanager/pkg/network"
)

func main() {
	// Fast discovery configuration
	targetCIDR := "192.168.123.0/24"  // Change this to your network
	interfaceName := "ens33"           // Change this to your interface
	
	fmt.Printf("=== FAST Discovery Mode ===\n")
	fmt.Printf("Target: %s | Interface: %s\n", targetCIDR, interfaceName)
	fmt.Printf("Optimized for speed with short timeouts\n\n")

	startTime := time.Now()

	// Run fast comparison
	fmt.Println("1. Fast ARP-only scan...")
	arpStart := time.Now()
	arpResults := fastARPScan(targetCIDR, interfaceName)
	arpDuration := time.Since(arpStart)
	fmt.Printf("   ARP Results: %d hosts in %v\n", len(arpResults), arpDuration)

	fmt.Println("\n2. Fast ICMP ping sweep...")
	icmpStart := time.Now()
	icmpResults := fastICMPScan(targetCIDR)
	icmpDuration := time.Since(icmpStart)
	fmt.Printf("   ICMP Results: %d hosts in %v\n", len(icmpResults), icmpDuration)

	fmt.Println("\n3. Fast TCP port sweep...")
	tcpStart := time.Now()
	tcpResults := fastTCPScan(targetCIDR)
	tcpDuration := time.Since(tcpStart)
	fmt.Printf("   TCP Results: %d hosts in %v\n", len(tcpResults), tcpDuration)

	totalDuration := time.Since(startTime)

	// Merge and deduplicate results
	allHosts := mergeResults(arpResults, icmpResults, tcpResults)

	fmt.Printf("\n" + strings.Repeat("=", 50) + "\n")
	fmt.Printf("FAST DISCOVERY SUMMARY:\n")
	fmt.Printf("Total Time: %v\n", totalDuration)
	fmt.Printf("ARP Only: %d hosts (%v)\n", len(arpResults), arpDuration)
	fmt.Printf("ICMP Only: %d hosts (%v)\n", len(icmpResults), icmpDuration)
	fmt.Printf("TCP Only: %d hosts (%v)\n", len(tcpResults), tcpDuration)
	fmt.Printf("Combined: %d unique hosts\n", len(allHosts))

	// Show detailed results
	fmt.Printf("\nDetailed Results:\n")
	printFastResults(arpResults, icmpResults, tcpResults, allHosts)

	// Performance analysis
	fmt.Printf("\nPerformance Analysis:\n")
	fmt.Printf("- ARP speed: %.1f hosts/sec\n", float64(len(arpResults))/arpDuration.Seconds())
	fmt.Printf("- ICMP speed: %.1f hosts/sec\n", float64(len(icmpResults))/icmpDuration.Seconds())
	fmt.Printf("- TCP speed: %.1f hosts/sec\n", float64(len(tcpResults))/tcpDuration.Seconds())
	fmt.Printf("- Overall: %.1f hosts/sec\n", float64(len(allHosts))/totalDuration.Seconds())

	if totalDuration.Seconds() < 60 {
		fmt.Printf("🚀 FAST! Completed in under 1 minute\n")
	} else {
		fmt.Printf("⚠️  SLOW: Took over 1 minute, needs optimization\n")
	}
}

func fastARPScan(cidr, interfaceName string) []string {
	scanner, err := network.NewParallelARPScanner(
		interfaceName,
		500*time.Millisecond, // Very fast timeout
		20,                   // More workers
		10*time.Millisecond,  // Very fast rate
	)
	if err != nil {
		log.Printf("ARP scanner error: %v", err)
		return []string{}
	}
	defer scanner.Close()

	results, err := scanner.ScanNetworkParallel(cidr)
	if err != nil {
		log.Printf("ARP scan error: %v", err)
		return []string{}
	}

	var ips []string
	for _, result := range results {
		ips = append(ips, result.IP)
	}
	return ips
}

func fastICMPScan(cidr string) []string {
	ips, err := network.CIDRToIPRange(cidr)
	if err != nil {
		return []string{}
	}

	var activeIPs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent pings
	semaphore := make(chan struct{}, 50)

	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release

			if fastPing(targetIP) {
				mu.Lock()
				activeIPs = append(activeIPs, targetIP)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return activeIPs
}

func fastTCPScan(cidr string) []string {
	ips, err := network.CIDRToIPRange(cidr)
	if err != nil {
		return []string{}
	}

	var activeIPs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Fast TCP ports (most common)
	ports := []int{22, 80, 443, 135, 139, 445}

	semaphore := make(chan struct{}, 100) // High concurrency

	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if fastTCPCheck(targetIP, ports) {
				mu.Lock()
				activeIPs = append(activeIPs, targetIP)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return activeIPs
}

func fastPing(ip string) bool {
	// Try TCP ping first (faster than ICMP)
	return fastTCPCheck(ip, []int{80, 443, 22, 135})
}

func fastTCPCheck(ip string, ports []int) bool {
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func mergeResults(arp, icmp, tcp []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, ip := range arp {
		if !seen[ip] {
			seen[ip] = true
			unique = append(unique, ip)
		}
	}
	for _, ip := range icmp {
		if !seen[ip] {
			seen[ip] = true
			unique = append(unique, ip)
		}
	}
	for _, ip := range tcp {
		if !seen[ip] {
			seen[ip] = true
			unique = append(unique, ip)
		}
	}

	return unique
}

func printFastResults(arp, icmp, tcp, all []string) {
	// Create maps for quick lookup
	arpMap := make(map[string]bool)
	icmpMap := make(map[string]bool)
	tcpMap := make(map[string]bool)

	for _, ip := range arp {
		arpMap[ip] = true
	}
	for _, ip := range icmp {
		icmpMap[ip] = true
	}
	for _, ip := range tcp {
		tcpMap[ip] = true
	}

	fmt.Printf("\nHost-by-host breakdown:\n")
	for i, ip := range all {
		var methods []string
		if arpMap[ip] {
			methods = append(methods, "ARP")
		}
		if icmpMap[ip] {
			methods = append(methods, "ICMP")
		}
		if tcpMap[ip] {
			methods = append(methods, "TCP")
		}

		fmt.Printf("%d. %s (found by: %v)\n", i+1, ip, methods)
	}

	// Show hosts found only by specific methods
	var arpOnly, icmpOnly, tcpOnly []string
	
	for _, ip := range arp {
		if !icmpMap[ip] && !tcpMap[ip] {
			arpOnly = append(arpOnly, ip)
		}
	}
	for _, ip := range icmp {
		if !arpMap[ip] && !tcpMap[ip] {
			icmpOnly = append(icmpOnly, ip)
		}
	}
	for _, ip := range tcp {
		if !arpMap[ip] && !icmpMap[ip] {
			tcpOnly = append(tcpOnly, ip)
		}
	}

	if len(arpOnly) > 0 {
		fmt.Printf("\nHosts found ONLY by ARP: %v\n", arpOnly)
	}
	if len(icmpOnly) > 0 {
		fmt.Printf("Hosts found ONLY by ICMP: %v\n", icmpOnly)
	}
	if len(tcpOnly) > 0 {
		fmt.Printf("Hosts found ONLY by TCP: %v\n", tcpOnly)
	}
} 