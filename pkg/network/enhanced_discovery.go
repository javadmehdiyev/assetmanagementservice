package network

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// EnhancedDiscovery combines multiple discovery methods for maximum coverage
type EnhancedDiscovery struct {
	arpScanner  *ParallelARPScanner
	icmpScanner *ICMPScanner
	portScanner *PortScanner
	interface_  string
}

// DiscoveryResult contains the combined results from all discovery methods
type DiscoveryResult struct {
	IP              string
	FoundByARP      bool
	FoundByICMP     bool
	FoundByTCP      bool
	MAC             string
	Vendor          string
	Hostname        string
	OpenPorts       []PortScanResult
	ARPError        error
	ICMPError       error
	ResponseTime    time.Duration
}

// NewEnhancedDiscovery creates a new enhanced discovery service
func NewEnhancedDiscovery(interfaceName string, arpTimeout, portTimeout time.Duration, arpWorkers int, arpRateLimit time.Duration, icmpWorkers int, icmpTimeout time.Duration) (*EnhancedDiscovery, error) {
	// Create ARP scanner
	arpScanner, err := NewParallelARPScanner(interfaceName, arpTimeout, arpWorkers, arpRateLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to create ARP scanner: %v", err)
	}

	// Create ICMP scanner
	icmpScanner := NewICMPScanner(icmpTimeout, icmpWorkers)

	// Create port scanner
	portScanner := NewPortScanner(portTimeout, 50, 1)

	return &EnhancedDiscovery{
		arpScanner:  arpScanner,
		icmpScanner: icmpScanner,
		portScanner: portScanner,
		interface_:  interfaceName,
	}, nil
}

// Close cleanup resources
func (ed *EnhancedDiscovery) Close() {
	if ed.arpScanner != nil {
		ed.arpScanner.Close()
	}
}

// DiscoverHosts performs comprehensive host discovery using multiple methods
func (ed *EnhancedDiscovery) DiscoverHosts(cidr string, enablePortScan bool) ([]DiscoveryResult, error) {
	fmt.Printf("Starting enhanced discovery for %s...\n", cidr)
	
	ips, err := CIDRToIPRange(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDR: %v", err)
	}

	fmt.Printf("Scanning %d IP addresses using multiple methods...\n", len(ips))

	// Phase 1: Parallel discovery using ARP and ICMP
	var wg sync.WaitGroup
	// Make the channel buffer large enough for worst case: each IP found by all methods
	resultChan := make(chan DiscoveryResult, len(ips)*3)

	// ARP Discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("Phase 1a: ARP Discovery...")
		ed.performARPDiscovery(ips, resultChan)
	}()

	// ICMP Discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("Phase 1b: ICMP Ping Discovery...")
		ed.performICMPDiscovery(ips, resultChan)
	}()

	// TCP Discovery (SYN scanning on common ports)
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("Phase 1c: TCP Discovery...")
		ed.performTCPDiscovery(ips, resultChan)
	}()

	// Wait for all discovery methods to complete and close channel
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect and merge results while discovery is running
	resultsMap := make(map[string]*DiscoveryResult)
	for result := range resultChan {
		if existing, exists := resultsMap[result.IP]; exists {
			// Merge results for the same IP
			ed.mergeResults(existing, &result)
		} else {
			resultsMap[result.IP] = &result
		}
	}

	// Convert map to slice and filter active hosts
	var activeResults []DiscoveryResult
	for _, result := range resultsMap {
		if result.FoundByARP || result.FoundByICMP || result.FoundByTCP {
			activeResults = append(activeResults, *result)
		}
	}

	fmt.Printf("Phase 1 complete: Found %d active hosts\n", len(activeResults))

	// Phase 2: Port scanning on discovered hosts (if enabled)
	if enablePortScan && len(activeResults) > 0 {
		fmt.Printf("Phase 2: Port scanning %d active hosts...\n", len(activeResults))
		ed.performPortScanning(&activeResults)
	}

	// Sort results by IP for consistent output
	sort.Slice(activeResults, func(i, j int) bool {
		return ipToInt(activeResults[i].IP) < ipToInt(activeResults[j].IP)
	})

	return activeResults, nil
}

// performARPDiscovery executes ARP discovery
func (ed *EnhancedDiscovery) performARPDiscovery(ips []string, resultChan chan<- DiscoveryResult) {
	arpResults, err := ed.arpScanner.ScanNetworkParallel(ipsToNetwork(ips))
	if err != nil {
		log.Printf("ARP discovery failed: %v", err)
		return
	}

	for _, arp := range arpResults {
		result := DiscoveryResult{
			IP:         arp.IP,
			FoundByARP: true,
			MAC:        arp.MAC,
			Vendor:     arp.Vendor,
		}
		resultChan <- result
	}
}

// performICMPDiscovery executes ICMP ping discovery
func (ed *EnhancedDiscovery) performICMPDiscovery(ips []string, resultChan chan<- DiscoveryResult) {
	icmpResults := ed.icmpScanner.PingHosts(ips)
	
	for _, ping := range icmpResults {
		if ping.Success {
			result := DiscoveryResult{
				IP:           ping.IP,
				FoundByICMP:  true,
				ResponseTime: ping.RTT,
			}
			resultChan <- result
		}
	}
}

// performTCPDiscovery executes TCP discovery on common ports
func (ed *EnhancedDiscovery) performTCPDiscovery(ips []string, resultChan chan<- DiscoveryResult) {
	// TCP discovery ports (most common services)
	tcpPorts := []int{22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5900}
	
	for _, ip := range ips {
		found := false
		for _, port := range tcpPorts {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
			if err == nil {
				conn.Close()
				found = true
				break
			}
		}
		
		if found {
			result := DiscoveryResult{
				IP:         ip,
				FoundByTCP: true,
			}
			resultChan <- result
		}
	}
}

// mergeResults combines results from different discovery methods for the same IP
func (ed *EnhancedDiscovery) mergeResults(existing, new *DiscoveryResult) {
	if new.FoundByARP {
		existing.FoundByARP = true
		if new.MAC != "" {
			existing.MAC = new.MAC
		}
		if new.Vendor != "" {
			existing.Vendor = new.Vendor
		}
	}
	
	if new.FoundByICMP {
		existing.FoundByICMP = true
		if new.ResponseTime > 0 {
			existing.ResponseTime = new.ResponseTime
		}
	}
	
	if new.FoundByTCP {
		existing.FoundByTCP = true
	}
}

// performPortScanning executes detailed port scanning on discovered hosts
func (ed *EnhancedDiscovery) performPortScanning(results *[]DiscoveryResult) {
	for i := range *results {
		result := &(*results)[i]
		
		// Try to get hostname
		if names, err := net.LookupAddr(result.IP); err == nil && len(names) > 0 {
			result.Hostname = strings.TrimSuffix(names[0], ".")
		}
		
		// Scan common ports
		portResults, err := ed.portScanner.ScanHost(result.IP)
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

// Helper functions
func ipsToNetwork(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	// Simple implementation - assumes all IPs are in same /24
	parts := strings.Split(ips[0], ".")
	if len(parts) == 4 {
		return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
	}
	return ""
}

func ipToInt(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	var result uint32
	for i, part := range parts {
		var val uint32
		fmt.Sscanf(part, "%d", &val)
		result |= val << (8 * (3 - i))
	}
	return result
}

// PrintDiscoveryResults prints the enhanced discovery results
func PrintDiscoveryResults(results []DiscoveryResult) {
	fmt.Printf("\n=== Enhanced Discovery Results ===\n")
	fmt.Printf("Found %d active hosts:\n\n", len(results))
	
	if len(results) == 0 {
		fmt.Println("No hosts discovered.")
		return
	}
	
	for i, result := range results {
		fmt.Printf("%d. IP: %s", i+1, result.IP)
		
		// Show discovery methods that found this host
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
		fmt.Printf(" (Found by: %s)", strings.Join(methods, ", "))
		
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
	arpCount := 0
	icmpCount := 0
	tcpCount := 0
	for _, result := range results {
		if result.FoundByARP {
			arpCount++
		}
		if result.FoundByICMP {
			icmpCount++
		}
		if result.FoundByTCP {
			tcpCount++
		}
	}
	
	fmt.Printf("Discovery Statistics:\n")
	fmt.Printf("  ARP: %d hosts\n", arpCount)
	fmt.Printf("  ICMP: %d hosts\n", icmpCount)
	fmt.Printf("  TCP: %d hosts\n", tcpCount)
	fmt.Printf("  Total unique: %d hosts\n", len(results))
} 