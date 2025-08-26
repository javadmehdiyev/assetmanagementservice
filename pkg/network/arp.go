package network

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/arp"
)

// ARPScanner represents an ARP scanner
type ARPScanner struct {
	iface   *net.Interface
	client  *arp.Client
	timeout time.Duration
}

// ARPResult represents the result of an ARP scan
type ARPResult struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Vendor string `json:"vendor"`
}

// NewARPScanner creates a new ARP scanner for the given interface
func NewARPScanner(interfaceName string, timeout time.Duration) (*ARPScanner, error) {
	if interfaceName == "" {
		return nil, fmt.Errorf("interface name cannot be empty")
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", interfaceName, err)
	}

	client, err := arp.Dial(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to create ARP client: %w", err)
	}

	return &ARPScanner{
		iface:   iface,
		client:  client,
		timeout: timeout,
	}, nil
}

// Close closes the ARP scanner
func (s *ARPScanner) Close() error {
	return s.client.Close()
}

// ScanIP performs an ARP request for a single IP address
func (s *ARPScanner) ScanIP(ip string) (*ARPResult, error) {
	err := s.client.SetDeadline(time.Now().Add(s.timeout))
	if err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	netIP, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address: %w", err)
	}

	// Retry mechanism for ARP requests
	var mac net.HardwareAddr
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		mac, err = s.client.Resolve(netIP)
		if err == nil {
			break
		}
		if attempt < maxRetries-1 {
			time.Sleep(time.Duration(50+attempt*25) * time.Millisecond)
		}
	}
	
	if err != nil {
		return nil, fmt.Errorf("ARP request failed after %d attempts: %w", maxRetries, err)
	}

	result := &ARPResult{
		IP:     ip,
		MAC:    mac.String(),
		Vendor: lookupVendor(mac),
	}

	return result, nil
}

func (s *ARPScanner) ScanNetwork(cidr string) ([]ARPResult, error) {
	ips, err := CIDRToIPRange(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDR: %w", err)
	}

	var results []ARPResult
	for _, ip := range ips {
		result, err := s.ScanIP(ip)
		if err == nil {
			results = append(results, *result)
		}
	}

	return results, nil
}

// lookupVendor returns the vendor name for a MAC address
func lookupVendor(mac net.HardwareAddr) string {
	// TODO: Implement vendor lookup using an OUI database
	// For now, return an empty string
	return ""
}
