package network

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// SmartDiscovery automatically chooses the best discovery method based on target
type SmartDiscovery struct {
	localNetwork    *net.IPNet
	arpScanner      *ParallelARPScanner
	icmpScanner     *ICMPScanner
	portScanner     *PortScanner
	interfaceName   string
}

// DiscoveryStrategy represents the strategy used for discovery
type DiscoveryStrategy string

const (
	StrategyLocal  DiscoveryStrategy = "local"   // Use ARP + ICMP + TCP for local network
	StrategyRemote DiscoveryStrategy = "remote"  // Use ICMP + TCP for remote networks
	StrategyAuto   DiscoveryStrategy = "auto"    // Automatically choose based on target
)

// SmartDiscoveryResult extends DiscoveryResult with strategy information
type SmartDiscoveryResult struct {
	DiscoveryResult
	Strategy     DiscoveryStrategy
	IsLocal      bool
	NetworkSegment string
}

// NewSmartDiscovery creates a new smart discovery service
func NewSmartDiscovery(interfaceName string, arpTimeout, portTimeout time.Duration, arpWorkers int, arpRateLimit time.Duration, icmpWorkers int, icmpTimeout time.Duration) (*SmartDiscovery, error) {
	// Get local network information
	localNet, err := getLocalNetwork(interfaceName)
	if err != nil {
		log.Printf("Warning: Could not determine local network: %v", err)
	}

	// Create scanners
	var arpScanner *ParallelARPScanner
	if localNet != nil {
		arpScanner, err = NewParallelARPScanner(interfaceName, arpTimeout, arpWorkers, arpRateLimit)
		if err != nil {
			log.Printf("Warning: Could not create ARP scanner: %v", err)
		}
	}

	icmpScanner := NewICMPScanner(icmpTimeout, icmpWorkers)
	portScanner := NewPortScanner(portTimeout, 50, 1)

	return &SmartDiscovery{
		localNetwork:  localNet,
		arpScanner:    arpScanner,
		icmpScanner:   icmpScanner,
		portScanner:   portScanner,
		interfaceName: interfaceName,
	}, nil
}

// Close cleanup resources
func (sd *SmartDiscovery) Close() {
	if sd.arpScanner != nil {
		sd.arpScanner.Close()
	}
}

// DiscoverTargets discovers hosts from multiple sources (local network + file list)
func (sd *SmartDiscovery) DiscoverTargets(localCIDR string, fileTargets []string, enablePortScan bool) ([]SmartDiscoveryResult, error) {
	var allResults []SmartDiscoveryResult

	// 1. Discover local network if specified
	if localCIDR != "" {
		fmt.Printf("Discovering local network: %s\n", localCIDR)
		localResults, err := sd.discoverNetwork(localCIDR, StrategyLocal, enablePortScan)
		if err != nil {
			log.Printf("Local network discovery failed: %v", err)
		} else {
			allResults = append(allResults, localResults...)
		}
	}

	// 2. Discover targets from file
	if len(fileTargets) > 0 {
		fmt.Printf("Discovering %d targets from file...\n", len(fileTargets))
		for _, target := range fileTargets {
			target = strings.TrimSpace(target)
			if target == "" || strings.HasPrefix(target, "#") {
				continue
			}

			results, err := sd.discoverTarget(target, enablePortScan)
			if err != nil {
				log.Printf("Failed to discover target %s: %v", target, err)
				continue
			}
			allResults = append(allResults, results...)
		}
	}

	return allResults, nil
}

// discoverTarget discovers a single target (IP or CIDR) using the appropriate strategy
func (sd *SmartDiscovery) discoverTarget(target string, enablePortScan bool) ([]SmartDiscoveryResult, error) {
	// Determine if target is local or remote
	strategy := sd.determineStrategy(target)
	
	fmt.Printf("Scanning %s using %s strategy...\n", target, strategy)
	
	return sd.discoverNetwork(target, strategy, enablePortScan)
}

// discoverNetwork discovers hosts in a network using the specified strategy
func (sd *SmartDiscovery) discoverNetwork(cidr string, strategy DiscoveryStrategy, enablePortScan bool) ([]SmartDiscoveryResult, error) {
	// Parse target
	ips, err := parseTarget(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target %s: %v", cidr, err)
	}

	fmt.Printf("  Scanning %d IP addresses...\n", len(ips))

	var results []SmartDiscoveryResult

	switch strategy {
	case StrategyLocal:
		// Use all methods for local network
		results, err = sd.discoverLocal(ips, cidr, enablePortScan)
	case StrategyRemote:
		// Use only ICMP + TCP for remote networks
		results, err = sd.discoverRemote(ips, cidr, enablePortScan)
	default:
		return nil, fmt.Errorf("unknown strategy: %s", strategy)
	}

	if err != nil {
		return nil, err
	}

	fmt.Printf("  Found %d active hosts\n", len(results))
	return results, nil
}

// discoverLocal uses ARP + ICMP + TCP for local network discovery
func (sd *SmartDiscovery) discoverLocal(ips []string, network string, enablePortScan bool) ([]SmartDiscoveryResult, error) {
	fmt.Println("    Phase 1: ARP + ICMP + TCP Discovery...")
	
	// Use enhanced discovery for local networks
	if sd.arpScanner == nil {
		// Fallback to remote discovery if ARP is not available
		return sd.discoverRemote(ips, network, enablePortScan)
	}

	// Create enhanced discovery
	enhanced, err := NewEnhancedDiscovery(
		sd.interfaceName,
		5*time.Second,   // ARP timeout
		3*time.Second,   // Port timeout
		10,              // ARP workers
		50*time.Millisecond, // Rate limit
		20,              // ICMP workers
		3*time.Second,   // ICMP timeout
	)
	if err != nil {
		return nil, err
	}
	defer enhanced.Close()

	discoveryResults, err := enhanced.DiscoverHosts(network, enablePortScan)
	if err != nil {
		return nil, err
	}

	// Convert to SmartDiscoveryResult
	var results []SmartDiscoveryResult
	for _, result := range discoveryResults {
		results = append(results, SmartDiscoveryResult{
			DiscoveryResult: result,
			Strategy:        StrategyLocal,
			IsLocal:         true,
			NetworkSegment:  network,
		})
	}

	return results, nil
}

// discoverRemote uses ICMP + TCP for remote network discovery (no ARP)
func (sd *SmartDiscovery) discoverRemote(ips []string, network string, enablePortScan bool) ([]SmartDiscoveryResult, error) {
	fmt.Println("    Phase 1: ICMP + TCP Discovery (no ARP)...")
	
	var results []SmartDiscoveryResult

	// ICMP Discovery
	fmt.Println("      ICMP ping sweep...")
	icmpResults := sd.icmpScanner.PingHosts(ips)
	
	// TCP Discovery
	fmt.Println("      TCP connect sweep...")
	tcpResults := sd.performTCPSweep(ips)

	// Merge results
	resultsMap := make(map[string]*SmartDiscoveryResult)

	// Process ICMP results
	for _, ping := range icmpResults {
		if ping.Success {
			result := &SmartDiscoveryResult{
				DiscoveryResult: DiscoveryResult{
					IP:           ping.IP,
					FoundByICMP:  true,
					ResponseTime: ping.RTT,
				},
				Strategy:       StrategyRemote,
				IsLocal:        false,
				NetworkSegment: network,
			}
			resultsMap[ping.IP] = result
		}
	}

	// Process TCP results
	for _, tcpIP := range tcpResults {
		if existing, exists := resultsMap[tcpIP]; exists {
			existing.FoundByTCP = true
		} else {
			result := &SmartDiscoveryResult{
				DiscoveryResult: DiscoveryResult{
					IP:         tcpIP,
					FoundByTCP: true,
				},
				Strategy:       StrategyRemote,
				IsLocal:        false,
				NetworkSegment: network,
			}
			resultsMap[tcpIP] = result
		}
	}

	// Convert to slice
	for _, result := range resultsMap {
		results = append(results, *result)
	}

	// Port scanning if enabled
	if enablePortScan && len(results) > 0 {
		fmt.Printf("    Phase 2: Port scanning %d active hosts...\n", len(results))
		sd.performPortScanning(&results)
	}

	return results, nil
}

// performTCPSweep performs TCP connectivity tests on common ports
func (sd *SmartDiscovery) performTCPSweep(ips []string) []string {
	tcpPorts := []int{22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5900}
	
	var activeIPs []string
	
	for _, ip := range ips {
		for _, port := range tcpPorts {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
			if err == nil {
				conn.Close()
				activeIPs = append(activeIPs, ip)
				break // Found one open port, move to next IP
			}
		}
	}
	
	return activeIPs
}

// performPortScanning performs detailed port scanning
func (sd *SmartDiscovery) performPortScanning(results *[]SmartDiscoveryResult) {
	for i := range *results {
		result := &(*results)[i]
		
		// Try to get hostname
		if names, err := net.LookupAddr(result.IP); err == nil && len(names) > 0 {
			result.Hostname = strings.TrimSuffix(names[0], ".")
		}
		
		// Scan common ports
		portResults, err := sd.portScanner.ScanHost(result.IP)
		if err != nil {
			log.Printf("Port scan failed for %s: %v", result.IP, err)
			continue
		}
		
		// Collect open ports
		for _, portResult := range portResults {
			if portResult.State == PortOpen {
				result.OpenPorts = append(result.OpenPorts, portResult)
			}
		}
	}
}

// determineStrategy determines the best discovery strategy for a target
func (sd *SmartDiscovery) determineStrategy(target string) DiscoveryStrategy {
	if sd.localNetwork == nil {
		return StrategyRemote
	}

	// Parse target to get first IP
	ips, err := parseTarget(target)
	if err != nil || len(ips) == 0 {
		return StrategyRemote
	}

	// Check if first IP is in local network
	ip := net.ParseIP(ips[0])
	if ip != nil && sd.localNetwork.Contains(ip) {
		return StrategyLocal
	}

	return StrategyRemote
}

// Helper functions
func parseTarget(target string) ([]string, error) {
	// Check if it's a CIDR
	if strings.Contains(target, "/") {
		return CIDRToIPRange(target)
	}
	
	// Single IP
	if net.ParseIP(target) != nil {
		return []string{target}, nil
	}
	
	return nil, fmt.Errorf("invalid target format: %s", target)
}

func getLocalNetwork(interfaceName string) (*net.IPNet, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet, nil
			}
		}
	}

	return nil, fmt.Errorf("no IPv4 address found for interface %s", interfaceName)
}

// PrintSmartDiscoveryResults prints smart discovery results with strategy info
func PrintSmartDiscoveryResults(results []SmartDiscoveryResult) {
	fmt.Printf("\n=== Smart Discovery Results ===\n")
	fmt.Printf("Found %d active hosts:\n\n", len(results))
	
	if len(results) == 0 {
		fmt.Println("No hosts discovered.")
		return
	}
	
	// Group by strategy
	localHosts := 0
	remoteHosts := 0
	
	for i, result := range results {
		fmt.Printf("%d. IP: %s", i+1, result.IP)
		
		// Show discovery methods and strategy
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
		
		strategyColor := ""
		if result.Strategy == StrategyLocal {
			strategyColor = "🏠"
			localHosts++
		} else {
			strategyColor = "🌐"
			remoteHosts++
		}
		
		fmt.Printf(" %s [%s] (Found by: %v)", strategyColor, result.Strategy, methods)
		
		if result.MAC != "" {
			fmt.Printf("\n   MAC: %s", result.MAC)
		}
		if result.Vendor != "" {
			fmt.Printf(" | Vendor: %s", result.Vendor)
		}
		if result.Hostname != "" {
			fmt.Printf("\n   Hostname: %s", result.Hostname)
		}
		if result.ResponseTime > 0 {
			fmt.Printf("\n   Response Time: %v", result.ResponseTime)
		}
		
		fmt.Printf("\n   Network: %s", result.NetworkSegment)
		
		if len(result.OpenPorts) > 0 {
			fmt.Printf("\n   Open Ports: %d", len(result.OpenPorts))
			for _, port := range result.OpenPorts {
				fmt.Printf("\n     %d/%s (%s)", port.Port, port.Protocol, port.Service)
				if port.Banner != "" {
					fmt.Printf(" - %s", port.Banner)
				}
			}
		}
		
		fmt.Println()
	}
	
	// Statistics
	fmt.Printf("Discovery Statistics:\n")
	fmt.Printf("🏠 Local Network Hosts:  %d\n", localHosts)
	fmt.Printf("🌐 Remote Network Hosts: %d\n", remoteHosts)
	fmt.Printf("📊 Total Hosts Found:    %d\n", len(results))
} 