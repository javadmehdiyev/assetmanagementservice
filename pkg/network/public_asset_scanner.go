package network

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PublicAsset represents a discovered public network asset
type PublicAsset struct {
	IP           string           `json:"ip"`
	Hostname     string           `json:"hostname,omitempty"`
	OpenPorts    []PortScanResult `json:"open_ports,omitempty"`
	LastSeen     time.Time        `json:"last_seen"`
	FirstSeen    time.Time        `json:"first_seen"`
	PingReply    bool             `json:"ping_reply"`
	ResponseTime time.Duration    `json:"response_time"`
}

// ToAsset converts a PublicAsset to an Asset for integration with the main asset management system
func (pa *PublicAsset) ToAsset() Asset {
	return Asset{
		IP:          pa.IP,
		MAC:         "", // Public assets don't have MAC addresses
		Vendor:      "", // Public assets don't have vendor info
		OpenPorts:   pa.OpenPorts,
		LastSeen:    pa.LastSeen,
		FirstSeen:   pa.FirstSeen,
		Hostname:    pa.Hostname,
		ARPResponse: false, // Public assets don't respond to ARP
	}
}

// PublicAssetScanner handles scanning of public network assets
type PublicAssetScanner struct {
	timeout     time.Duration
	concurrency int
	retries     int
	mu          sync.RWMutex
	assets      map[string]*PublicAsset
}

// NewPublicAssetScanner creates a new public asset scanner
func NewPublicAssetScanner(timeout time.Duration, concurrency int, retries int) *PublicAssetScanner {
	if concurrency <= 0 {
		concurrency = 50
	}
	if retries < 0 {
		retries = 2
	}
	return &PublicAssetScanner{
		timeout:     timeout,
		concurrency: concurrency,
		retries:     retries,
		assets:      make(map[string]*PublicAsset),
	}
}

// ScanPublicAssets performs comprehensive scanning on public targets
func (p *PublicAssetScanner) ScanPublicAssets(targets []string, tcpPorts []int, udpPorts []int) ([]*PublicAsset, error) {
	log.Printf("Starting public asset scan on %d targets", len(targets))

	// Step 1: Ping scan to identify live hosts
	log.Println("Phase 1: Host discovery (Ping scan)")
	liveHosts := p.performPingScan(targets)
	log.Printf("Found %d live hosts", len(liveHosts))

	if len(liveHosts) == 0 {
		return []*PublicAsset{}, nil
	}

	// Extract live host IPs
	var liveIPs []string
	for ip := range liveHosts {
		liveIPs = append(liveIPs, ip)
	}

	// Step 2: TCP SYN scan on live hosts
	if len(tcpPorts) > 0 {
		log.Printf("Phase 2: TCP SYN scan on %d ports", len(tcpPorts))
		tcpResults := p.performTCPScan(liveIPs, tcpPorts)

		// Add TCP results to assets
		for ip, ports := range tcpResults {
			if asset, exists := liveHosts[ip]; exists {
				asset.OpenPorts = append(asset.OpenPorts, ports...)
			}
		}
	}

	// Step 3: UDP scan on live hosts
	if len(udpPorts) > 0 {
		log.Printf("Phase 3: UDP scan on %d ports", len(udpPorts))
		udpResults := p.performUDPScan(liveIPs, udpPorts)

		// Add UDP results to assets
		for ip, ports := range udpResults {
			if asset, exists := liveHosts[ip]; exists {
				asset.OpenPorts = append(asset.OpenPorts, ports...)
			}
		}
	}

	// Convert map to slice
	var results []*PublicAsset
	for _, asset := range liveHosts {
		results = append(results, asset)
	}

	log.Printf("Scan completed. Found %d live hosts with %d total open ports",
		len(results), p.countTotalOpenPorts(results))

	return results, nil
}

// performPingScan performs ICMP ping scan on targets
func (p *PublicAssetScanner) performPingScan(targets []string) map[string]*PublicAsset {
	results := make(map[string]*PublicAsset)
	var mu sync.Mutex

	jobs := make(chan string, len(targets))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < p.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				asset := p.pingHost(target)
				if asset != nil {
					mu.Lock()
					results[target] = asset
					mu.Unlock()
				}
			}
		}()
	}

	// Send jobs
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	wg.Wait()

	return results
}

// pingHost performs ping on a single host
func (p *PublicAssetScanner) pingHost(target string) *PublicAsset {
	start := time.Now()

	// Use system ping command for reliability
	cmd := exec.Command("ping", "-c", "1", "-W", strconv.Itoa(int(p.timeout.Seconds())), target)
	err := cmd.Run()

	if err == nil {
		duration := time.Since(start)
		hostname := p.resolveHostname(target)

		return &PublicAsset{
			IP:           target,
			Hostname:     hostname,
			PingReply:    true,
			ResponseTime: duration,
			FirstSeen:    time.Now(),
			LastSeen:     time.Now(),
			OpenPorts:    make([]PortScanResult, 0),
		}
	}

	return nil
}

// performTCPScan performs TCP SYN scan on targets and ports
func (p *PublicAssetScanner) performTCPScan(targets []string, ports []int) map[string][]PortScanResult {
	results := make(map[string][]PortScanResult)
	var mu sync.Mutex

	type scanJob struct {
		target string
		port   int
	}

	jobs := make(chan scanJob, len(targets)*len(ports))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < p.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				result := p.scanTCPPort(job.target, job.port)
				if result != nil && result.State == PortOpen {
					mu.Lock()
					results[job.target] = append(results[job.target], *result)
					mu.Unlock()
				}
			}
		}()
	}

	// Send jobs
	for _, target := range targets {
		for _, port := range ports {
			jobs <- scanJob{target: target, port: port}
		}
	}
	close(jobs)
	wg.Wait()

	return results
}

// scanTCPPort scans a single TCP port
func (p *PublicAssetScanner) scanTCPPort(target string, port int) *PortScanResult {
	address := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("tcp", address, p.timeout)
	if err != nil {
		return nil // Only return open ports for public scans
	}
	defer conn.Close()

	// Try to grab banner
	banner := p.grabBanner(conn)

	return &PortScanResult{
		IP:       target,
		Port:     port,
		Protocol: ScanTCP,
		State:    PortOpen,
		Service:  lookupService(port, ScanTCP),
		Banner:   banner,
	}
}

// performUDPScan performs UDP scan on targets and ports
func (p *PublicAssetScanner) performUDPScan(targets []string, ports []int) map[string][]PortScanResult {
	results := make(map[string][]PortScanResult)
	var mu sync.Mutex

	type scanJob struct {
		target string
		port   int
	}

	jobs := make(chan scanJob, len(targets)*len(ports))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < p.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				result := p.scanUDPPort(job.target, job.port)
				if result != nil {
					mu.Lock()
					results[job.target] = append(results[job.target], *result)
					mu.Unlock()
				}
			}
		}()
	}

	// Send jobs
	for _, target := range targets {
		for _, port := range ports {
			jobs <- scanJob{target: target, port: port}
		}
	}
	close(jobs)
	wg.Wait()

	return results
}

// scanUDPPort scans a single UDP port
func (p *PublicAssetScanner) scanUDPPort(target string, port int) *PortScanResult {
	address := fmt.Sprintf("%s:%d", target, port)

	conn, err := net.DialTimeout("udp", address, p.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Send UDP probe packet
	probe := p.getUDPProbe(port)
	_, err = conn.Write(probe)
	if err != nil {
		return nil
	}

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(p.timeout))

	// Try to read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)

	state := PortFiltered
	banner := ""

	if err == nil && n > 0 {
		// Got a response, port is likely open
		state = PortOpen
		banner = strings.TrimSpace(string(buffer[:n]))
	}

	// Return result even if filtered for UDP (helps with inventory)
	return &PortScanResult{
		IP:       target,
		Port:     port,
		Protocol: ScanUDP,
		State:    state,
		Service:  lookupService(port, ScanUDP),
		Banner:   banner,
	}
}

// getUDPProbe returns appropriate UDP probe packet for specific ports
func (p *PublicAssetScanner) getUDPProbe(port int) []byte {
	switch port {
	case 53: // DNS
		// DNS query for google.com
		return []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01}
	case 123: // NTP
		// NTP request packet
		return []byte{0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 161: // SNMP
		// SNMP GetRequest
		return []byte{0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x1c, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x94, 0x78, 0x01, 0x02, 0x07, 0x03, 0x05, 0x00}
	default:
		// Generic empty UDP packet
		return []byte{}
	}
}

// grabBanner attempts to grab service banner
func (p *PublicAssetScanner) grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	banner := strings.TrimSpace(string(buffer[:n]))
	// Clean up binary data
	if len(banner) > 100 {
		banner = banner[:100] + "..."
	}
	return banner
}

// resolveHostname attempts to resolve IP to hostname
func (p *PublicAssetScanner) resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// countTotalOpenPorts counts total open ports across all assets
func (p *PublicAssetScanner) countTotalOpenPorts(assets []*PublicAsset) int {
	total := 0
	for _, asset := range assets {
		for _, port := range asset.OpenPorts {
			if port.State == PortOpen {
				total++
			}
		}
	}
	return total
}

// GetCommonTCPPorts returns commonly scanned TCP ports
func GetCommonTCPPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888,
	}
}

// GetCommonUDPPorts returns commonly scanned UDP ports
func GetCommonUDPPorts() []int {
	return []int{
		53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 500, 514, 520, 1194, 4500,
	}
}

// Close cleans up the scanner resources
func (p *PublicAssetScanner) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.assets = nil
	return nil
}

// ReadTargetsFromFile reads IP addresses and CIDR ranges from a file for public scanning
func ReadTargetsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if it's a CIDR range
		if strings.Contains(line, "/") {
			// Parse CIDR and expand to individual IPs
			ips, err := expandCIDRToIPs(line)
			if err != nil {
				log.Printf("Warning: Failed to parse CIDR %s: %v", line, err)
				continue
			}
			targets = append(targets, ips...)
		} else {
			// Single IP address
			if net.ParseIP(line) != nil {
				targets = append(targets, line)
			} else {
				log.Printf("Warning: Invalid IP address: %s", line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filePath, err)
	}

	return targets, nil
}

// expandCIDRToIPs expands a CIDR range to individual IP addresses
func expandCIDRToIPs(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for IPv4
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	// Limit to reasonable number of IPs for public scanning
	if len(ips) > 254 {
		log.Printf("Warning: CIDR %s expands to %d IPs, limiting to first 254", cidr, len(ips))
		ips = ips[:254]
	}

	return ips, nil
}

// incIP increments an IP address
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
