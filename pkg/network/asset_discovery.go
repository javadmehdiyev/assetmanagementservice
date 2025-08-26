package network

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Asset represents a discovered network asset (optimized)
type Asset struct {
	IP                string             `json:"ip"`
	MAC               string             `json:"mac,omitempty"`
	Vendor            string             `json:"vendor,omitempty"`
	Hostname          string             `json:"hostname,omitempty"`
	OpenPorts         []PortScanResult   `json:"open_ports,omitempty"`
	OS                string             `json:"os,omitempty"`
	DeviceType        string             `json:"device_type,omitempty"`
	CredentialResults []CredentialResult `json:"credentials,omitempty"`
	Screenshots       []string           `json:"screenshots,omitempty"`
	LastSeen          time.Time          `json:"last_seen"`
	ARPResponse       bool               `json:"arp_response"`
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

	// Step 2: Process discovered devices in parallel
	for _, result := range arpResults {
		wg.Add(1)
		go func(r ARPResult) {
			defer wg.Done()

			asset := Asset{
				IP:          r.IP,
				MAC:         r.MAC,
				Vendor:      r.Vendor,
				LastSeen:    time.Now(),
				ARPResponse: true,
			}

			// Try to get hostname
			if hostname, err := lookupHostname(r.IP); err == nil {
				asset.Hostname = hostname
			}

			// Step 3: Optionally scan ports
			if scanPorts {
				asset.OpenPorts = d.portScanner.ScanCommonPorts(r.IP)
				
				// Simple OS detection based on open ports
				osInfo := d.detectOSFromPorts(asset)
				if osInfo != nil {
					asset.OS = osInfo.OSFamily
					asset.DeviceType = osInfo.DeviceType
					if osInfo.Manufacturer != "" {
						asset.Vendor = osInfo.Manufacturer
					}
				}
			}

			// Step 4: Test credentials if enabled and we have open ports
			if testCredentials && d.credentialChecker != nil && len(asset.OpenPorts) > 0 {
				credResults := d.credentialChecker.TestCredentials([]Asset{asset})
				if len(credResults) > 0 {
					asset.CredentialResults = credResults
				}
			}

			// Step 5: Capture screenshots if enabled and we have HTTP services
			if captureScreenshots && d.screenshotCapture != nil {
				webPorts := d.findWebServices(asset.OpenPorts)
				if len(webPorts) > 0 {
					screenshots := d.screenshotCapture.CaptureScreenshots([]Asset{asset})
					var screenshotFiles []string
					for _, screenshot := range screenshots {
						if screenshot.Success {
							screenshotFiles = append(screenshotFiles, screenshot.FilePath)
						}
					}
					asset.Screenshots = screenshotFiles
				}
			}

			assetChan <- asset
		}(result)
	}

	go func() {
		wg.Wait()
		close(assetChan)
	}()

	for asset := range assetChan {
		assets = append(assets, asset)
	}

	fmt.Printf("Asset discovery completed, found %d assets\n", len(assets))
	return assets, nil
}

// GetAssets returns all discovered assets
func (d *AssetDiscovery) GetAssets() []Asset {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	assets := make([]Asset, 0, len(d.assets))
	for _, asset := range d.assets {
		assets = append(assets, *asset)
	}
	return assets
}

// updateAsset updates an asset in the database
func (d *AssetDiscovery) updateAsset(asset *Asset) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.assets[asset.IP] = asset
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
					LastSeen:    time.Now(),
				}

				// Try to get hostname
				if hostname, err := lookupHostname(targetIP); err == nil {
					asset.Hostname = hostname
				}

				// Perform port scan if requested
				if scanPorts {
					asset.OpenPorts = d.portScanner.ScanCommonPorts(targetIP)
					
					// Simple OS detection based on open ports
					osInfo := d.detectOSFromPorts(asset)
					if osInfo != nil {
						asset.OS = osInfo.OSFamily
						asset.DeviceType = osInfo.DeviceType
						asset.Vendor = osInfo.Manufacturer
					}
				}

				// Test credentials if requested and we have services that support it
				if testCredentials && d.credentialChecker != nil && len(asset.OpenPorts) > 0 {
					credResults := d.credentialChecker.TestCredentials([]Asset{asset})
					if len(credResults) > 0 {
						asset.CredentialResults = credResults
					}
				}

				// Capture screenshots if requested and we have web services
				if captureScreenshots && d.screenshotCapture != nil {
					webPorts := d.findWebServices(asset.OpenPorts)
					if len(webPorts) > 0 {
						screenshots := d.screenshotCapture.CaptureScreenshots([]Asset{asset})
						var screenshotFiles []string
						for _, screenshot := range screenshots {
							if screenshot.Success {
								screenshotFiles = append(screenshotFiles, screenshot.FilePath)
							}
						}
						asset.Screenshots = screenshotFiles
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
	// More comprehensive port list like Goby uses
	commonPorts := []int{
		// Basic services
		21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
		// Windows specific
		135, 139, 445, 3389, 1433, 1521, 5985, 5986,
		// Network devices
		161, 162, 514, 623, 631, 8080, 8443,
		// Databases & Apps
		3306, 5432, 6379, 27017, 9200, 11211,
		// Remote access
		5900, 5901, 1723, 4899,
		// Apple/macOS
		5353, 62078, 88, 548, 626,
		// Other common
		8000, 8888, 9090, 7001, 10000, 2222, 2323,
	}
	
	// Test ports in parallel for speed
	portChan := make(chan bool, len(commonPorts))
	var wg sync.WaitGroup
	
	// Limit concurrent connections to avoid overwhelming
	semaphore := make(chan struct{}, 10)
	
	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			if d.portScanner.IsPortOpen(ip, p) {
				select {
				case portChan <- true:
				default:
				}
			}
		}(port)
	}
	
	go func() {
		wg.Wait()
		close(portChan)
	}()
	
	// Return true if any port is open
	for range portChan {
		return true
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
