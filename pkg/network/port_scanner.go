package network

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// PortState represents the state of a port
type PortState string

const (
	// PortOpen indicates the port is open
	PortOpen PortState = "open"
	// PortClosed indicates the port is closed
	PortClosed PortState = "closed"
	// PortFiltered indicates the port is filtered (no response)
	PortFiltered PortState = "filtered"
)

// ScanType represents the type of port scan
type ScanType string

const (
	// ScanTCP scans TCP ports
	ScanTCP ScanType = "tcp"
	// ScanUDP scans UDP ports
	ScanUDP ScanType = "udp"
)

// PortScanResult represents the result of a port scan
type PortScanResult struct {
	IP       string    `json:"ip"`
	Port     int       `json:"port"`
	Protocol ScanType  `json:"protocol"`
	State    PortState `json:"state"`
	Service  string    `json:"service"`
	Banner   string    `json:"banner,omitempty"`
}

// PortScanner represents a port scanner
type PortScanner struct {
	timeout     time.Duration
	concurrency int
	retries     int
}

// NewPortScanner creates a new port scanner
func NewPortScanner(timeout time.Duration, concurrency int, retries int) *PortScanner {
	if concurrency <= 0 {
		concurrency = 100 // Default concurrency
	}
	if retries < 0 {
		retries = 2 // Default retries
	}
	return &PortScanner{
		timeout:     timeout,
		concurrency: concurrency,
		retries:     retries,
	}
}

// ScanPort scans a single port
func (s *PortScanner) ScanPort(ip string, port int, protocol ScanType) (*PortScanResult, error) {
	switch protocol {
	case ScanTCP:
		return s.scanTCPPort(ip, port)
	case ScanUDP:
		return s.scanUDPPort(ip, port)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// scanTCPPort scans a single TCP port using SYN packets
func (s *PortScanner) scanTCPPort(ip string, port int) (*PortScanResult, error) {
	target := net.JoinHostPort(ip, strconv.Itoa(port))

	// Create a TCP dialer with the appropriate timeout
	dialer := net.Dialer{
		Timeout: s.timeout,
	}

	// This is a half-open SYN scan using the system's TCP stack
	// For a true SYN scan without completing the handshake, we would need raw sockets
	// which requires admin privileges and is more complex
	conn, err := dialer.Dial("tcp", target)

	result := &PortScanResult{
		IP:       ip,
		Port:     port,
		Protocol: ScanTCP,
		Service:  lookupService(port, ScanTCP),
	}

	if err != nil {
		// Check the error type to determine if the port is closed or filtered
		if opErr, ok := err.(*net.OpError); ok {
			// Connection refused means the port is closed but reachable
			if syscallErr, ok := opErr.Err.(*os.SyscallError); ok && syscallErr.Err == syscall.ECONNREFUSED {
				result.State = PortClosed
				return result, nil
			}
			// Timeout means the port is likely filtered
			if opErr.Timeout() {
				result.State = PortFiltered
				return result, nil
			}
		}
		result.State = PortFiltered
		return result, nil
	}

	// If we get here, the port is open
	result.State = PortOpen

	// Try to get a banner
	if conn != nil {
		defer conn.Close()

		// Set a read deadline
		conn.SetReadDeadline(time.Now().Add(s.timeout))

		// Try to read a banner
		banner := make([]byte, 1024)
		n, err := conn.Read(banner)
		if err == nil && n > 0 {
			result.Banner = string(banner[:n])
		}
	}

	return result, nil
}

// scanUDPPort scans a single UDP port
func (s *PortScanner) scanUDPPort(ip string, port int) (*PortScanResult, error) {
	target := net.JoinHostPort(ip, strconv.Itoa(port))

	// Create a UDP connection
	conn, err := net.DialTimeout("udp", target, s.timeout)
	if err != nil {
		return &PortScanResult{
			IP:       ip,
			Port:     port,
			Protocol: ScanUDP,
			State:    PortFiltered,
			Service:  lookupService(port, ScanUDP),
		}, nil
	}

	// Try to send something
	_, err = conn.Write([]byte("Hello\n"))
	if err != nil {
		conn.Close()
		return &PortScanResult{
			IP:       ip,
			Port:     port,
			Protocol: ScanUDP,
			State:    PortFiltered,
			Service:  lookupService(port, ScanUDP),
		}, nil
	}

	// Set a read deadline
	conn.SetReadDeadline(time.Now().Add(s.timeout))

	// Try to read a response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)

	// Close the connection
	conn.Close()

	result := &PortScanResult{
		IP:       ip,
		Port:     port,
		Protocol: ScanUDP,
		Service:  lookupService(port, ScanUDP),
	}

	// If we got a response, the port is open
	if err == nil && n > 0 {
		result.State = PortOpen
		result.Banner = string(buf[:n])
		return result, nil
	}

	// For UDP, no response could mean the port is open but not responding,
	// or it could be filtered. It's harder to tell with UDP.
	// We'll mark it as filtered for now.
	result.State = PortFiltered
	return result, nil
}

// ScanPorts scans multiple ports on a single host
func (s *PortScanner) ScanPorts(ip string, startPort, endPort int, protocol ScanType) ([]PortScanResult, error) {
	var results []PortScanResult
	var wg sync.WaitGroup
	resultChan := make(chan PortScanResult, endPort-startPort+1)

	// Create a semaphore to limit concurrency
	sem := make(chan struct{}, s.concurrency)

	// Scan ports
	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			result, err := s.ScanPort(ip, p, protocol)
			if err == nil && result != nil {
				resultChan <- *result
			}
		}(port)
	}

	// Wait for all scans to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		results = append(results, result)
	}

	return results, nil
}

// ScanHost scans common ports on a host
func (s *PortScanner) ScanHost(ip string) ([]PortScanResult, error) {
	// Common TCP ports to scan
	commonTCPPorts := []int{
		20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
		445, 993, 995, 1723, 3306, 3389, 5900, 8080,
	}

	// Common UDP ports to scan
	commonUDPPorts := []int{
		53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 514, 631, 1900,
	}

	var results []PortScanResult
	var wg sync.WaitGroup
	resultChan := make(chan PortScanResult, len(commonTCPPorts)+len(commonUDPPorts))

	// Scan TCP ports
	wg.Add(1)
	go func() {
		defer wg.Done()

		for _, port := range commonTCPPorts {
			result, err := s.ScanPort(ip, port, ScanTCP)
			if err == nil && result != nil {
				resultChan <- *result
			}
		}
	}()

	// Scan UDP ports
	wg.Add(1)
	go func() {
		defer wg.Done()

		for _, port := range commonUDPPorts {
			result, err := s.ScanPort(ip, port, ScanUDP)
			if err == nil && result != nil {
				resultChan <- *result
			}
		}
	}()

	// Wait for all scans to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		results = append(results, result)
	}

	return results, nil
}

// lookupService returns the service name for a port
func lookupService(port int, protocol ScanType) string {
	// Common TCP services
	tcpServices := map[int]string{
		20:   "FTP-data",
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		111:  "RPC",
		135:  "RPC",
		139:  "NetBIOS",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		993:  "IMAP-SSL",
		995:  "POP3-SSL",
		1723: "PPTP",
		3306: "MySQL",
		3389: "RDP",
		5900: "VNC",
		8080: "HTTP-Proxy",
	}

	// Common UDP services
	udpServices := map[int]string{
		53:   "DNS",
		67:   "DHCP-Server",
		68:   "DHCP-Client",
		69:   "TFTP",
		123:  "NTP",
		135:  "RPC",
		137:  "NetBIOS-NS",
		138:  "NetBIOS-DGM",
		161:  "SNMP",
		162:  "SNMP-Trap",
		445:  "SMB",
		514:  "Syslog",
		631:  "IPP",
		1900: "SSDP",
	}

	if protocol == ScanTCP {
		if service, ok := tcpServices[port]; ok {
			return service
		}
	} else if protocol == ScanUDP {
		if service, ok := udpServices[port]; ok {
			return service
		}
	}

	return "unknown"
}
