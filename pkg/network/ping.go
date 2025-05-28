package network

import (
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// PingResult represents the result of an ICMP ping
type PingResult struct {
	IP       string
	Success  bool
	RTT      time.Duration
	Error    error
}

// ICMPScanner handles ICMP ping operations
type ICMPScanner struct {
	timeout time.Duration
	workers int
}

// NewICMPScanner creates a new ICMP scanner
func NewICMPScanner(timeout time.Duration, workers int) *ICMPScanner {
	return &ICMPScanner{
		timeout: timeout,
		workers: workers,
	}
}

// PingHost sends an ICMP ping to a single host
func (s *ICMPScanner) PingHost(ip string) PingResult {
	result := PingResult{
		IP:      ip,
		Success: false,
	}

	start := time.Now()
	
	// Try multiple methods for ping detection
	if s.pingICMP(ip) || s.pingTCP(ip) {
		result.Success = true
		result.RTT = time.Since(start)
	} else {
		result.Error = fmt.Errorf("host unreachable")
	}

	return result
}

// pingICMP performs ICMP ping (requires root privileges)
func (s *ICMPScanner) pingICMP(ip string) bool {
	// Create raw ICMP connection
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		// Fallback to TCP ping if ICMP fails (no root privileges)
		return false
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(s.timeout))

	// Create ICMP message
	message := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("asset-discovery"),
		},
	}

	data, err := message.Marshal(nil)
	if err != nil {
		return false
	}

	// Send ping
	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return false
	}

	_, err = conn.WriteTo(data, dst)
	if err != nil {
		return false
	}

	// Read response
	reply := make([]byte, 1500)
	_, _, err = conn.ReadFrom(reply)
	return err == nil
}

// pingTCP performs TCP connect test (fallback method)
func (s *ICMPScanner) pingTCP(ip string) bool {
	// Try common ports for TCP connectivity test
	ports := []int{22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5900}
	
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), s.timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// PingNetwork scans an entire network range using ICMP ping
func (s *ICMPScanner) PingNetwork(cidr string) ([]PingResult, error) {
	ips, err := CIDRToIPRange(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDR: %v", err)
	}

	return s.PingHosts(ips), nil
}

// PingHosts scans multiple hosts using parallel workers
func (s *ICMPScanner) PingHosts(ips []string) []PingResult {
	if len(ips) == 0 {
		return []PingResult{}
	}

	// Create channels for work distribution
	ipChan := make(chan string, len(ips))
	resultChan := make(chan PingResult, len(ips))

	// Send IPs to channel
	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	// Start workers
	var wg sync.WaitGroup
	workers := s.workers
	if workers > len(ips) {
		workers = len(ips)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				result := s.PingHost(ip)
				resultChan <- result
			}
		}()
	}

	// Wait for completion and close result channel
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var results []PingResult
	for result := range resultChan {
		results = append(results, result)
	}

	return results
}

// GetActiveHosts returns only the hosts that responded to ping
func (s *ICMPScanner) GetActiveHosts(cidr string) ([]string, error) {
	results, err := s.PingNetwork(cidr)
	if err != nil {
		return nil, err
	}

	var activeHosts []string
	for _, result := range results {
		if result.Success {
			activeHosts = append(activeHosts, result.IP)
		}
	}

	return activeHosts, nil
} 