package network

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Asset represents a discovered network asset
type Asset struct {
	IP                  string               `json:"ip"`
	MAC                 string               `json:"mac"`
	Vendor              string               `json:"vendor"`
	Ports               []PortScanResult     `json:"ports,omitempty"`
	OpenPorts           []PortScanResult     `json:"open_ports,omitempty"`
	CredentialResults   []CredentialResult   `json:"credential_results,omitempty"`
	ScreenshotResults   []ScreenshotResult   `json:"screenshot_results,omitempty"`
	DeviceInfo          *DeviceInfo          `json:"device_info,omitempty"`
	LastSeen            time.Time            `json:"last_seen"`
	FirstSeen           time.Time            `json:"first_seen"`
	Hostname            string               `json:"hostname,omitempty"`
	ARPResponse         bool                 `json:"arp_response"`
	HasDefaultCreds     bool                 `json:"has_default_creds"`
	HasWebServices      bool                 `json:"has_web_services"`
	VulnerableServices  []string             `json:"vulnerable_services,omitempty"`
	WebServices         []string             `json:"web_services,omitempty"`
}

// AssetID returns a unique identifier for the asset
func (a *Asset) AssetID() string {
	return a.IP
}

// AssetDiscovery represents an asset discovery service
type AssetDiscovery struct {
	arpScanner        *ParallelARPScanner
	portScanner       *PortScanner
	credentialChecker *CredentialChecker
	screenshotCapture *ScreenshotCapture
	hostnameDetector  *AdvancedHostnameDetector
	assets            map[string]*Asset
	mu                sync.RWMutex
	scanInterval      time.Duration
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
		arpScanner:        arpScanner,
		portScanner:       portScanner,
		credentialChecker: nil, // Will be set separately if enabled
		screenshotCapture: nil, // Will be set separately if enabled
		hostnameDetector:  NewAdvancedHostnameDetector(5 * time.Second),
		assets:            make(map[string]*Asset),
		scanInterval:      10 * time.Minute, // Default scan interval
	}, nil
}

// Close closes the asset discovery service
func (d *AssetDiscovery) Close() error {
	return d.arpScanner.Close()
}

// SetCredentialChecker sets the credential checker for this discovery service
func (d *AssetDiscovery) SetCredentialChecker(checker *CredentialChecker) {
	d.credentialChecker = checker
}

// SetScreenshotCapture sets the screenshot capture for this discovery service
func (d *AssetDiscovery) SetScreenshotCapture(capture *ScreenshotCapture) {
	d.screenshotCapture = capture
}

// SetScanInterval sets the interval between scans
func (d *AssetDiscovery) SetScanInterval(interval time.Duration) {
	d.scanInterval = interval
}

// DiscoverAssets discovers assets on the network
func (d *AssetDiscovery) DiscoverAssets(cidr string, scanPorts bool, testCredentials bool, captureScreenshots bool) ([]Asset, error) {
	// Step 1: Perform ARP scan to discover devices
	arpResults, err := d.arpScanner.ScanNetworkParallel(cidr)
	if err != nil {
		// If ARP scan fails, try a simple ping scan instead
		fmt.Printf("ARP scan failed, trying ping scan: %v\n", err)
		return d.discoverWithPingScan(cidr, scanPorts, testCredentials, captureScreenshots)
	}

	fmt.Printf("Found %d devices via ARP scan\n", len(arpResults))

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
					// Filter for open ports only and add all ports to asset
					for _, port := range portResults {
						asset.Ports = append(asset.Ports, port)
						if port.State == PortOpen {
							asset.OpenPorts = append(asset.OpenPorts, port)
						}
					}
				}
			}

			// Step 4: Test credentials if enabled and we have open ports
			if testCredentials && d.credentialChecker != nil && len(asset.OpenPorts) > 0 {
				credResults := d.credentialChecker.testAssetCredentials(asset)
				asset.CredentialResults = credResults
				
				// Check if any credentials were successful
				for _, result := range credResults {
					if result.Successful {
						asset.HasDefaultCreds = true
						asset.VulnerableServices = append(asset.VulnerableServices, result.Service)
					}
				}
			}

			// Step 5: Capture screenshots if enabled and we have HTTP services
			if captureScreenshots && d.screenshotCapture != nil && len(asset.OpenPorts) > 0 {
				// Check for HTTP services
				hasHTTP := false
				for _, port := range asset.OpenPorts {
					if d.screenshotCapture.isHTTPService(port.Port) {
						hasHTTP = true
						asset.WebServices = append(asset.WebServices, fmt.Sprintf("%s:%d", r.IP, port.Port))
					}
				}
				
				if hasHTTP {
					asset.HasWebServices = true
					// Capture screenshots for this single asset
					screenshots := d.screenshotCapture.CaptureScreenshots([]Asset{asset})
					asset.ScreenshotResults = screenshots
				}
			}

			// Step 6: Advanced hostname and OS detection
			if d.hostnameDetector != nil {
				deviceInfo := d.hostnameDetector.DetectDeviceInfo(asset)
				asset.DeviceInfo = &deviceInfo
				
				// Update basic fields from advanced detection
				if asset.Hostname == "" && deviceInfo.Hostname != "" {
					asset.Hostname = deviceInfo.Hostname
				}
			}

			// Fallback: Try basic hostname lookup if advanced detection didn't find one
			if asset.Hostname == "" {
				if hostname, err := lookupHostname(r.IP); err == nil {
					asset.Hostname = hostname
				}
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
func (d *AssetDiscovery) DiscoverAssetsFromFile(filePath string, scanPorts bool, testCredentials bool, captureScreenshots bool) ([]Asset, error) {
	// Read CIDR ranges from file
	cidrs, err := ReadCIDRsFromFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CIDR file: %w", err)
	}

	var allAssets []Asset
	for _, cidr := range cidrs {
		assets, err := d.DiscoverAssets(cidr, scanPorts, testCredentials, captureScreenshots)
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

// discoverWithPingScan performs discovery using ping scan as fallback
func (d *AssetDiscovery) discoverWithPingScan(cidr string, scanPorts bool, testCredentials bool, captureScreenshots bool) ([]Asset, error) {
	ips, err := parseNetworkCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDR: %w", err)
	}

	var assets []Asset
	var wg sync.WaitGroup
	assetChan := make(chan Asset, len(ips))

	// Limit concurrent pings to avoid overwhelming the system
	semaphore := make(chan struct{}, 50)

	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Simple port check instead of ping (more reliable)
			if d.isHostAlive(targetIP) {
				asset := Asset{
					IP:          targetIP,
					ARPResponse: false, // Since we didn't use ARP
					FirstSeen:   time.Now(),
					LastSeen:    time.Now(),
				}

				// Try to get hostname
				if hostname, err := lookupHostname(targetIP); err == nil {
					asset.Hostname = hostname
				}

				// Perform port scan if requested
				if scanPorts {
					asset.OpenPorts = d.portScanner.ScanCommonPorts(targetIP)
					asset.Ports = asset.OpenPorts // For backward compatibility
					
					// Simple OS detection based on open ports
					asset.DeviceInfo = d.detectOSFromPorts(asset)
				}

				// Test credentials if requested and we have services that support it
				if testCredentials && d.credentialChecker != nil && len(asset.OpenPorts) > 0 {
					credResults := d.credentialChecker.TestCredentials([]Asset{asset})
					if len(credResults) > 0 {
						asset.CredentialResults = credResults
						asset.HasDefaultCreds = true
					}
				}

				// Capture screenshots if requested and we have web services
				if captureScreenshots && d.screenshotCapture != nil {
					webPorts := d.findWebServices(asset.OpenPorts)
					if len(webPorts) > 0 {
						asset.WebServices = webPorts
						asset.HasWebServices = true
						screenshots := d.screenshotCapture.CaptureScreenshots([]Asset{asset})
						asset.ScreenshotResults = screenshots
					}
				}

				assetChan <- asset
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(assetChan)
	}()

	for asset := range assetChan {
		assets = append(assets, asset)
	}

	fmt.Printf("Ping scan completed, found %d assets\n", len(assets))
	return assets, nil
}

// isHostAlive checks if a host is alive by testing common ports
func (d *AssetDiscovery) isHostAlive(ip string) bool {
	// Test common ports to see if host is alive
	commonPorts := []int{22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900, 8080}
	
	for _, port := range commonPorts {
		if d.portScanner.IsPortOpen(ip, port) {
			return true
		}
	}
	return false
}

// detectOSFromPorts detects OS based on open ports (simple but effective)
func (d *AssetDiscovery) detectOSFromPorts(asset Asset) *DeviceInfo {
	deviceInfo := &DeviceInfo{
		IP:       asset.IP,
		Hostname: asset.Hostname,
		Services: make(map[string]string),
	}

	hasNetBIOS := false
	hasSSH := false
	hasRDP := false
	hasApplePorts := false

	for _, port := range asset.OpenPorts {
		portNum := port.Port
		
		// Add service information
		switch portNum {
		case 22:
			deviceInfo.Services["ssh"] = "present"
			hasSSH = true
		case 23:
			deviceInfo.Services["telnet"] = "present"
		case 25:
			deviceInfo.Services["smtp"] = "present"
		case 53:
			deviceInfo.Services["dns"] = "present"
		case 80:
			deviceInfo.Services["http"] = "present"
		case 110:
			deviceInfo.Services["pop3"] = "present"
		case 135:
			deviceInfo.Services["rpc"] = "present"
			hasNetBIOS = true
		case 139, 445:
			deviceInfo.Services["smb"] = "present"
			hasNetBIOS = true
		case 443:
			deviceInfo.Services["https"] = "present"
		case 3389:
			deviceInfo.Services["rdp"] = "present"
			hasRDP = true
		case 5353:
			deviceInfo.Services["mdns"] = "present"
			hasApplePorts = true
		case 62078:
			deviceInfo.Services["airplay"] = "present"
			hasApplePorts = true
		case 5900:
			deviceInfo.Services["vnc"] = "present"
		case 21:
			deviceInfo.Services["ftp"] = "present"
		case 6379:
			deviceInfo.Services["redis"] = "present"
		}
	}

	// Simple OS detection logic
	if hasNetBIOS || hasRDP {
		deviceInfo.OSFamily = "Windows"
		deviceInfo.DeviceType = "computer"
		if hasRDP {
			deviceInfo.OSVersion = "Windows (RDP enabled)"
		}
	} else if hasApplePorts {
		deviceInfo.OSFamily = "macOS/iOS"
		deviceInfo.DeviceType = "apple_device"
		deviceInfo.Manufacturer = "Apple"
	} else if hasSSH && !hasNetBIOS {
		deviceInfo.OSFamily = "Linux/Unix"
		deviceInfo.DeviceType = "server"
	}

	// Get manufacturer from MAC if available
	if asset.MAC != "" {
		manufacturer := d.getManufacturerFromMACAPI(asset.MAC)
		if manufacturer != "" {
			deviceInfo.Manufacturer = manufacturer
		}
	}

	return deviceInfo
}

// findWebServices identifies web service ports
func (d *AssetDiscovery) findWebServices(ports []PortScanResult) []string {
	var webServices []string
	for _, port := range ports {
		if port.Port == 80 || port.Port == 443 || port.Port == 8080 || port.Port == 8443 || port.Port == 8000 || port.Port == 3000 {
			protocol := "http"
			if port.Port == 443 || port.Port == 8443 {
				protocol = "https"
			}
			webServices = append(webServices, fmt.Sprintf("%s://%s:%d", protocol, "", port.Port))
		}
	}
	return webServices
}

// parseNetworkCIDR parses CIDR and returns list of IPs to scan
func parseNetworkCIDR(cidr string) ([]string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := network.IP.Mask(network.Mask); network.Contains(ip); incrementIPAddr(ip) {
		ips = append(ips, ip.String())
	}
	
	// Remove network and broadcast addresses
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

// incrementIPAddr increments an IP address
func incrementIPAddr(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// getManufacturerFromMACAPI gets manufacturer info from MAC address using external API
func (d *AssetDiscovery) getManufacturerFromMACAPI(mac string) string {
	if d.hostnameDetector != nil {
		return d.hostnameDetector.getManufacturerFromMAC(mac)
	}
	return ""
}
