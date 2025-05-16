package network

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// ParallelARPScanner extends the ARPScanner with parallel scanning capabilities
type ParallelARPScanner struct {
	*ARPScanner
	workers    int
	rateLimit  time.Duration // Time to wait between scans per worker
	scanResult chan *ARPResult
}

// NewParallelARPScanner creates a new parallel ARP scanner
func NewParallelARPScanner(interfaceName string, timeout time.Duration, workers int, rateLimit time.Duration) (*ParallelARPScanner, error) {
	baseScanner, err := NewARPScanner(interfaceName, timeout)
	if err != nil {
		return nil, err
	}

	// If workers is <= 0, use a default value
	if workers <= 0 {
		workers = 10
	}

	return &ParallelARPScanner{
		ARPScanner: baseScanner,
		workers:    workers,
		rateLimit:  rateLimit,
		scanResult: make(chan *ARPResult),
	}, nil
}

// ScanNetworkParallel performs ARP scanning in parallel using multiple goroutines
func (s *ParallelARPScanner) ScanNetworkParallel(cidr string) ([]ARPResult, error) {
	ips, err := CIDRToIPRange(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDR: %w", err)
	}

	var results []ARPResult
	var wg sync.WaitGroup
	ipChan := make(chan string, len(ips))
	resultChan := make(chan ARPResult, len(ips))
	errChan := make(chan error, 1)
	doneChan := make(chan struct{})

	// Start worker goroutines
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for ip := range ipChan {
				// Rate limiting per worker
				if s.rateLimit > 0 {
					time.Sleep(s.rateLimit)
				}

				// Create a new client for each worker to avoid race conditions
				clientTimeout := s.timeout
				client, err := NewARPScanner(s.ARPScanner.iface.Name, clientTimeout)
				if err != nil {
					select {
					case errChan <- fmt.Errorf("worker %d failed to create ARP client: %w", workerID, err):
					default:
					}
					return
				}

				// Perform the scan
				result, err := s.scanIPWithRetry(client, ip, 2) // 2 retries
				if err == nil && result != nil {
					resultChan <- *result
				}

				// Close the client
				client.Close()
			}
		}(i)
	}

	// Result collector goroutine
	go func() {
		for result := range resultChan {
			results = append(results, result)
		}
		close(doneChan)
	}()

	// Send IPs to workers
	for _, ip := range ips {
		select {
		case ipChan <- ip:
		case err := <-errChan:
			close(ipChan)
			return nil, err
		}
	}
	close(ipChan)

	// Wait for all workers to finish
	wg.Wait()
	close(resultChan)
	<-doneChan

	return results, nil
}

// scanIPWithRetry attempts to scan an IP with retries
func (s *ParallelARPScanner) scanIPWithRetry(client *ARPScanner, ip string, retries int) (*ARPResult, error) {
	var lastErr error
	for i := 0; i <= retries; i++ {
		// Parse the IP address
		netIP, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address %s: %w", ip, err)
		}

		// Set deadline
		err = client.client.SetDeadline(time.Now().Add(client.timeout))
		if err != nil {
			lastErr = fmt.Errorf("failed to set deadline: %w", err)
			continue
		}

		// Send ARP request
		mac, err := client.client.Resolve(netIP)
		if err != nil {
			lastErr = fmt.Errorf("ARP request failed for IP %s: %w", ip, err)
			continue
		}

		// Success
		return &ARPResult{
			IP:     ip,
			MAC:    mac.String(),
			Vendor: lookupVendor(mac),
		}, nil
	}
	return nil, lastErr
}

// ScanCIDRFiles scans multiple CIDR ranges from a file
func (s *ParallelARPScanner) ScanCIDRFiles(filePath string) ([]ARPResult, error) {
	// Read the CIDR ranges from the file
	cidrs, err := ReadCIDRsFromFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CIDR file: %w", err)
	}

	var allResults []ARPResult
	for _, cidr := range cidrs {
		results, err := s.ScanNetworkParallel(cidr)
		if err != nil {
			fmt.Printf("Error scanning CIDR %s: %v\n", cidr, err)
			continue
		}
		allResults = append(allResults, results...)
	}

	return allResults, nil
}
