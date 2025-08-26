package network

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// PortScanResult represents the result of a port scan (optimized)
type PortScanResult struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// PortScanner represents a port scanner
type PortScanner struct {
	timeout     time.Duration
	concurrency int
	retries     int
}

// NewPortScanner creates a new port scanner
func NewPortScanner(timeout time.Duration, concurrency int, retries int) *PortScanner {
	return &PortScanner{
		timeout:     timeout,
		concurrency: concurrency,
		retries:     retries,
	}
}

// IsPortOpen checks if a specific port is open on a host
func (ps *PortScanner) IsPortOpen(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	// Use faster timeout for host alive checks
	timeout := 500 * time.Millisecond
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// ScanCommonPorts scans common ports on a host and returns only open ports
func (ps *PortScanner) ScanCommonPorts(host string) []PortScanResult {
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 
		1723, 3389, 5900, 8080, 8443, 5353, 62078, 6379, 3306, 5432, 1521,
		8000, 3000, 9000, 8888, 9999, 8181, 8282, 9090, 7001, 7002,
	}

	var results []PortScanResult
	var wg sync.WaitGroup
	resultsChan := make(chan PortScanResult, len(commonPorts))
	
	// Limit concurrency to avoid overwhelming the target
	semaphore := make(chan struct{}, 20)

	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if ps.IsPortOpen(host, p) {
				result := PortScanResult{
					Port:    p,
					Service: lookupService(p, "tcp"),
				}
				resultsChan <- result
			}
		}(port)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

// lookupService returns the service name for a port
func lookupService(port int, protocol string) string {
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
		8443: "HTTPS-Alt",
		5353: "mDNS",
		62078: "AirPlay",
		6379: "Redis",
		5432: "PostgreSQL",
		1521: "Oracle",
		8000: "HTTP-Alt",
		3000: "HTTP-Dev",
		9000: "HTTP-Alt",
		8888: "HTTP-Alt",
		9999: "HTTP-Alt",
		8181: "HTTP-Alt",
		8282: "HTTP-Alt",
		9090: "HTTP-Alt",
		7001: "Cassandra",
		7002: "Cassandra",
	}

	// Common UDP services
	udpServices := map[int]string{
		53:   "DNS",
		67:   "DHCP-Server",
		68:   "DHCP-Client",
		69:   "TFTP",
		123:  "NTP",
		137:  "NetBIOS-NS",
		138:  "NetBIOS-DGM",
		161:  "SNMP",
		162:  "SNMP-Trap",
		445:  "SMB",
		514:  "Syslog",
		631:  "IPP",
		1900: "SSDP",
	}

	if protocol == "tcp" {
		if service, ok := tcpServices[port]; ok {
			return service
		}
	} else if protocol == "udp" {
		if service, ok := udpServices[port]; ok {
			return service
		}
	}

	return "unknown"
}
