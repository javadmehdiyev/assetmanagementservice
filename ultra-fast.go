package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"assetmanager/pkg/network"
)

func main() {
	targetCIDR := "192.168.123.0/24"
	
	fmt.Printf("🚀 ULTRA-FAST Discovery\n")
	fmt.Printf("Target: %s\n", targetCIDR)
	fmt.Printf("Timeout: 100ms per host\n\n")

	start := time.Now()

	// Get IPs to scan
	ips, _ := network.CIDRToIPRange(targetCIDR)
	fmt.Printf("Scanning %d IPs...\n", len(ips))

	// Ultra-fast TCP scan (most reliable)
	var activeHosts []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	sem := make(chan struct{}, 100) // High concurrency

	for _, ip := range ips {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Try only the most common ports with very short timeout
			if isHostUp(host) {
				mu.Lock()
				activeHosts = append(activeHosts, host)
				mu.Unlock()
				fmt.Printf("✓ %s\n", host) // Live feedback
			}
		}(ip)
	}

	wg.Wait()
	duration := time.Since(start)

	fmt.Printf("\n🎯 RESULTS:\n")
	fmt.Printf("Found %d active hosts in %v\n", len(activeHosts), duration)
	fmt.Printf("Speed: %.1f hosts/sec\n", float64(len(activeHosts))/duration.Seconds())
	
	if len(activeHosts) > 0 {
		fmt.Printf("\nActive hosts:\n")
		for i, host := range activeHosts {
			fmt.Printf("%d. %s\n", i+1, host)
		}
	}

	// Performance assessment
	if duration.Seconds() < 10 {
		fmt.Printf("\n🚀 EXCELLENT: Under 10 seconds!\n")
	} else if duration.Seconds() < 30 {
		fmt.Printf("\n✅ GOOD: Under 30 seconds\n")
	} else {
		fmt.Printf("\n⚠️  SLOW: Over 30 seconds\n")
	}

	fmt.Printf("\nComparison:\n")
	fmt.Printf("- Your original: 17 hosts (ARP-only)\n")
	fmt.Printf("- Goby tool:     26 hosts\n")
	fmt.Printf("- Ultra-fast:    %d hosts (TCP-only)\n", len(activeHosts))
}

func isHostUp(ip string) bool {
	// Try most common ports with ultra-short timeout
	ports := []int{80, 443, 22}
	
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
} 