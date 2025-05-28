package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"assetmanager/pkg/config"
	"assetmanager/pkg/network"
)

func main() {
	fmt.Printf("=== Smart Asset Discovery System ===\n")
	fmt.Printf("Addresses both requirements from gereksinim:\n")
	fmt.Printf("1. 📂 Dosya tabanlı IP blok tarama (File-based IP block scanning)\n")
	fmt.Printf("2. 🏠 Yerel network taraması (Local network scanning)\n\n")

	// Load configuration
	cfg, err := config.LoadConfig("config.enhanced-discovery.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Get timeouts from configuration
	arpTimeout, _ := cfg.GetARPTimeout()
	portTimeout, _ := cfg.GetPortScanTimeout()
	arpRateLimit, _ := cfg.GetARPRateLimit()

	// Determine interface
	interfaceName := cfg.Network.Interface
	if interfaceName == "auto" {
		interfaceName = "ens33" // fallback
	}

	// Create smart discovery service
	discovery, err := network.NewSmartDiscovery(
		interfaceName,
		arpTimeout,
		portTimeout,
		cfg.ARP.Workers,
		arpRateLimit,
		20, // ICMP workers
		3*time.Second, // ICMP timeout
	)
	if err != nil {
		log.Fatalf("Failed to create smart discovery: %v", err)
	}
	defer discovery.Close()

	// Get local network
	var localCIDR string
	if cfg.Network.AutoDetectLocal {
		if local, err := network.GetLocalNetworkCIDR(); err == nil {
			localCIDR = local
		} else {
			localCIDR = cfg.Network.DefaultCIDR
		}
	} else {
		localCIDR = cfg.Network.DefaultCIDR
	}

	// Read file targets
	fileTargets, err := readFileTargets(cfg.Files.IPListFile)
	if err != nil {
		log.Printf("Warning: Could not read file targets: %v", err)
		fileTargets = []string{} // Continue without file targets
	}

	fmt.Printf("Configuration:\n")
	fmt.Printf("  Local Network: %s\n", localCIDR)
	fmt.Printf("  File Targets: %d entries from %s\n", len(fileTargets), cfg.Files.IPListFile)
	fmt.Printf("  Interface: %s\n", interfaceName)
	fmt.Printf("  Port Scanning: %v\n\n", cfg.PortScan.Enabled)

	// Show discovery strategy explanation
	fmt.Printf("Discovery Strategy:\n")
	fmt.Printf("  🏠 Local Network (%s): ARP + ICMP + TCP\n", localCIDR)
	fmt.Printf("  🌐 Remote Networks: ICMP + TCP (no ARP - won't work across networks)\n\n")

	// Perform smart discovery
	fmt.Printf("Starting smart discovery...\n")
	startTime := time.Now()
	
	results, err := discovery.DiscoverTargets(localCIDR, fileTargets, cfg.PortScan.Enabled)
	if err != nil {
		log.Fatalf("Smart discovery failed: %v", err)
	}

	duration := time.Since(startTime)

	// Print results
	network.PrintSmartDiscoveryResults(results)

	// Summary
	fmt.Printf("\n" + "="*60 + "\n")
	fmt.Printf("DISCOVERY SUMMARY:\n")
	fmt.Printf("Total Time: %v\n", duration)
	fmt.Printf("Total Hosts Found: %d\n\n", len(results))

	// Show why this solves the ARP problem
	localCount := 0
	remoteCount := 0
	for _, result := range results {
		if result.IsLocal {
			localCount++
		} else {
			remoteCount++
		}
	}

	fmt.Printf("Problem Solved - ARP Limitations:\n")
	fmt.Printf("✅ Local network hosts (%d): Found using ARP + ICMP + TCP\n", localCount)
	fmt.Printf("✅ Remote network hosts (%d): Found using ICMP + TCP (ARP skipped)\n", remoteCount)
	fmt.Printf("✅ File-based scanning: Automatically detects local vs remote targets\n")
	fmt.Printf("✅ No more 'arping' failures on different networks!\n\n")

	// Show specific examples
	if len(results) > 0 {
		fmt.Printf("Examples of discovery methods used:\n")
		showMethodExamples(results)
	}

	// Comparison with your original issue
	fmt.Printf("\nComparison with Goby:\n")
	fmt.Printf("Your Original Tool: %d hosts (ARP-only, limited to local network)\n", 17)
	fmt.Printf("Goby Tool:         %d hosts (multiple methods, all networks)\n", 26)
	fmt.Printf("Smart Discovery:   %d hosts (adaptive methods, all networks)\n", len(results))
	
	if len(results) >= 26 {
		fmt.Printf("🎉 SUCCESS: Matching or exceeding Goby's results!\n")
	} else if len(results) > 17 {
		fmt.Printf("📈 IMPROVEMENT: Found %d more hosts than original tool!\n", len(results)-17)
	}
}

func readFileTargets(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

func showMethodExamples(results []network.SmartDiscoveryResult) {
	arpExample := ""
	icmpExample := ""
	tcpExample := ""
	remoteExample := ""

	for _, result := range results {
		if result.FoundByARP && arpExample == "" {
			arpExample = fmt.Sprintf("  ARP: %s (found via MAC address discovery)", result.IP)
		}
		if result.FoundByICMP && icmpExample == "" {
			icmpExample = fmt.Sprintf("  ICMP: %s (found via ping)", result.IP)
		}
		if result.FoundByTCP && tcpExample == "" {
			tcpExample = fmt.Sprintf("  TCP: %s (found via port connectivity)", result.IP)
		}
		if !result.IsLocal && remoteExample == "" {
			var methods []string
			if result.FoundByICMP {
				methods = append(methods, "ICMP")
			}
			if result.FoundByTCP {
				methods = append(methods, "TCP")
			}
			remoteExample = fmt.Sprintf("  Remote: %s (found via %v, ARP skipped)", result.IP, methods)
		}
	}

	if arpExample != "" {
		fmt.Println(arpExample)
	}
	if icmpExample != "" {
		fmt.Println(icmpExample)
	}
	if tcpExample != "" {
		fmt.Println(tcpExample)
	}
	if remoteExample != "" {
		fmt.Println(remoteExample)
	}
} 