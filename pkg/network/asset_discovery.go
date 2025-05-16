package network

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Asset represents a discovered network asset
type Asset struct {
	IP          string           `json:"ip"`
	MAC         string           `json:"mac"`
	Vendor      string           `json:"vendor"`
	OpenPorts   []PortScanResult `json:"open_ports,omitempty"`
	LastSeen    time.Time        `json:"last_seen"`
	FirstSeen   time.Time        `json:"first_seen"`
	Hostname    string           `json:"hostname,omitempty"`
	ARPResponse bool             `json:"arp_response"`
}

// AssetID returns a unique identifier for the asset
func (a *Asset) AssetID() string {
	return a.IP
}

// AssetDiscovery represents an asset discovery service
type AssetDiscovery struct {
	arpScanner   *ParallelARPScanner
	portScanner  *PortScanner
	assets       map[string]*Asset
	mu           sync.RWMutex
	scanInterval time.Duration
}

// NewAssetDiscovery creates a new asset discovery service
func NewAssetDiscovery(interfaceName string, arpTimeout, portTimeout time.Duration, workers int, rateLimit time.Duration) (*AssetDiscovery, error) {
	// Create ARP scanner
	arpScanner, err := NewParallelARPScanner(interfaceName, arpTimeout, workers, rateLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to create ARP scanner: %w", err)
	}

	// Create port scanner
	portScanner := NewPortScanner(portTimeout, workers, 2)

	return &AssetDiscovery{
		arpScanner:   arpScanner,
		portScanner:  portScanner,
		assets:       make(map[string]*Asset),
		scanInterval: 10 * time.Minute, // Default scan interval
	}, nil
}

// Close closes the asset discovery service
func (d *AssetDiscovery) Close() error {
	return d.arpScanner.Close()
}

// SetScanInterval sets the interval between scans
func (d *AssetDiscovery) SetScanInterval(interval time.Duration) {
	d.scanInterval = interval
}

// DiscoverAssets discovers assets on the network
func (d *AssetDiscovery) DiscoverAssets(cidr string, scanPorts bool) ([]Asset, error) {
	// Step 1: Perform ARP scan to discover devices
	arpResults, err := d.arpScanner.ScanNetworkParallel(cidr)
	if err != nil {
		return nil, fmt.Errorf("ARP scan failed: %w", err)
	}

	var assets []Asset
	var wg sync.WaitGroup
	assetChan := make(chan Asset, len(arpResults))

	// Step 2: Process discovered devices
	for _, result := range arpResults {
		wg.Add(1)

		go func(r ARPResult) {
			defer wg.Done()

			now := time.Now()
			asset := Asset{
				IP:          r.IP,
				MAC:         r.MAC,
				Vendor:      r.Vendor,
				LastSeen:    now,
				FirstSeen:   now,
				ARPResponse: true,
			}

			// Step 3: Optionally scan ports
			if scanPorts {
				// Scan common ports
				portResults, err := d.portScanner.ScanHost(r.IP)
				if err == nil {
					// Filter for open ports only
					for _, port := range portResults {
						if port.State == PortOpen {
							asset.OpenPorts = append(asset.OpenPorts, port)
						}
					}
				}
			}

			// Try to resolve hostname
			if hostname, err := lookupHostname(r.IP); err == nil {
				asset.Hostname = hostname
			}

			assetChan <- asset

			// Update asset database
			d.updateAsset(&asset)
		}(result)
	}

	// Wait for all asset processing to complete
	go func() {
		wg.Wait()
		close(assetChan)
	}()

	// Collect assets
	for asset := range assetChan {
		assets = append(assets, asset)
	}

	return assets, nil
}

// DiscoverAssetsFromFile discovers assets from a file containing CIDR ranges
func (d *AssetDiscovery) DiscoverAssetsFromFile(filePath string, scanPorts bool) ([]Asset, error) {
	// Read CIDR ranges from file
	cidrs, err := ReadCIDRsFromFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CIDR file: %w", err)
	}

	var allAssets []Asset
	for _, cidr := range cidrs {
		assets, err := d.DiscoverAssets(cidr, scanPorts)
		if err != nil {
			fmt.Printf("Error scanning CIDR %s: %v\n", cidr, err)
			continue
		}
		allAssets = append(allAssets, assets...)
	}

	return allAssets, nil
}

// updateAsset updates the asset database
func (d *AssetDiscovery) updateAsset(asset *Asset) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if asset already exists
	if existing, ok := d.assets[asset.IP]; ok {
		// Update existing asset
		existing.LastSeen = asset.LastSeen
		existing.MAC = asset.MAC
		existing.Vendor = asset.Vendor
		existing.ARPResponse = true

		// Only update hostname if it was found
		if asset.Hostname != "" {
			existing.Hostname = asset.Hostname
		}

		// Update ports if scan was performed
		if len(asset.OpenPorts) > 0 {
			existing.OpenPorts = asset.OpenPorts
		}
	} else {
		// Add new asset
		d.assets[asset.IP] = asset
	}
}

// GetAssets returns all discovered assets
func (d *AssetDiscovery) GetAssets() []Asset {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var assets []Asset
	for _, asset := range d.assets {
		assets = append(assets, *asset)
	}
	return assets
}

// GetAssetByIP returns an asset by IP address
func (d *AssetDiscovery) GetAssetByIP(ip string) (*Asset, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	asset, ok := d.assets[ip]
	if !ok {
		return nil, false
	}
	return asset, true
}

// lookupHostname tries to resolve an IP address to a hostname
func lookupHostname(ip string) (string, error) {
	hostnames, err := net.LookupAddr(ip)
	if err != nil {
		return "", err
	}
	if len(hostnames) > 0 {
		return hostnames[0], nil
	}
	return "", fmt.Errorf("no hostname found for IP %s", ip)
}
