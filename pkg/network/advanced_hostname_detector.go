package network

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DeviceInfo represents detailed device information
type DeviceInfo struct {
	IP              string            `json:"ip"`
	Hostname        string            `json:"hostname"`
	OSFamily        string            `json:"os_family"`
	OSVersion       string            `json:"os_version"`
	DeviceType      string            `json:"device_type"`
	Manufacturer    string            `json:"manufacturer"`
	Model           string            `json:"model"`
	Services        map[string]string `json:"services"`
	DetectionMethods []string         `json:"detection_methods"`
}

// AdvancedHostnameDetector handles advanced hostname and OS detection
type AdvancedHostnameDetector struct {
	timeout    time.Duration
	httpClient *http.Client
	mu         sync.RWMutex
}

// NewAdvancedHostnameDetector creates a new advanced detector
func NewAdvancedHostnameDetector(timeout time.Duration) *AdvancedHostnameDetector {
	return &AdvancedHostnameDetector{
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// DetectDeviceInfo performs comprehensive device detection
func (ahd *AdvancedHostnameDetector) DetectDeviceInfo(asset Asset) DeviceInfo {
	deviceInfo := DeviceInfo{
		IP:               asset.IP,
		Hostname:         asset.Hostname,
		Services:         make(map[string]string),
		DetectionMethods: []string{},
	}

	var wg sync.WaitGroup
	results := make(chan DeviceInfo, 10)

	// Method 1: Enhanced DNS lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if info := ahd.enhancedDNSLookup(asset.IP); info.Hostname != "" {
			results <- info
		}
	}()

	// Method 2: mDNS/Bonjour detection (Apple devices)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if info := ahd.detectAppleDevices(asset.IP); info.Hostname != "" {
			results <- info
		}
	}()

	// Method 3: NetBIOS name resolution (Windows)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if info := ahd.detectWindowsDevices(asset.IP); info.Hostname != "" {
			results <- info
		}
	}()

	// Method 4: SNMP detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		if info := ahd.detectSNMPInfo(asset.IP); info.Hostname != "" {
			results <- info
		}
	}()

	// Method 5: HTTP banner analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if info := ahd.analyzeHTTPBanners(asset); info.Hostname != "" {
			results <- info
		}
	}()

	// Method 6: SSH banner analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if info := ahd.analyzeSSHBanners(asset); info.OSFamily != "" {
			results <- info
		}
	}()

	// Wait for all methods to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Merge results
	for info := range results {
		ahd.mergeDeviceInfo(&deviceInfo, info)
	}

	// Analyze MAC address for manufacturer info
	if asset.MAC != "" {
		deviceInfo.Manufacturer = ahd.getManufacturerFromMAC(asset.MAC)
	}

	return deviceInfo
}

// enhancedDNSLookup performs enhanced DNS lookup with PTR and additional records
func (ahd *AdvancedHostnameDetector) enhancedDNSLookup(ip string) DeviceInfo {
	info := DeviceInfo{
		IP:               ip,
		DetectionMethods: []string{"dns"},
		Services:         make(map[string]string),
	}

	// Standard reverse DNS lookup
	hostnames, err := net.LookupAddr(ip)
	if err == nil && len(hostnames) > 0 {
		info.Hostname = strings.TrimSuffix(hostnames[0], ".")
		
		// Analyze hostname for OS and device type hints
		hostname := strings.ToLower(info.Hostname)
		
		if strings.Contains(hostname, "iphone") || strings.Contains(hostname, "ipad") {
			info.OSFamily = "iOS"
			info.DeviceType = "mobile"
			info.Manufacturer = "Apple"
		} else if strings.Contains(hostname, "android") {
			info.OSFamily = "Android"
			info.DeviceType = "mobile"
		} else if strings.Contains(hostname, "mac") || strings.Contains(hostname, "apple") {
			info.OSFamily = "macOS"
			info.DeviceType = "computer"
			info.Manufacturer = "Apple"
		} else if strings.Contains(hostname, "win") || strings.Contains(hostname, "pc") {
			info.OSFamily = "Windows"
			info.DeviceType = "computer"
		} else if strings.Contains(hostname, "linux") || strings.Contains(hostname, "ubuntu") || strings.Contains(hostname, "debian") {
			info.OSFamily = "Linux"
			info.DeviceType = "computer"
		}
	}

	return info
}

// detectAppleDevices detects Apple devices using mDNS patterns
func (ahd *AdvancedHostnameDetector) detectAppleDevices(ip string) DeviceInfo {
	info := DeviceInfo{
		IP:               ip,
		DetectionMethods: []string{"mdns"},
		Services:         make(map[string]string),
	}

	// Try to connect to common Apple service ports
	applePorts := []int{5353, 62078, 49152, 49153, 49154}
	
	for _, port := range applePorts {
		if ahd.isPortOpen(ip, port) {
			// This might be an Apple device
			info.Manufacturer = "Apple"
			info.DetectionMethods = append(info.DetectionMethods, fmt.Sprintf("apple_port_%d", port))
			
			// Try to get more info from Bonjour/AirPlay services
			if port == 5353 {
				info.Services["mdns"] = "present"
			}
			if port == 62078 {
				info.Services["airplay"] = "present"
				info.DeviceType = "media_device"
			}
		}
	}

	return info
}

// detectWindowsDevices detects Windows devices using NetBIOS
func (ahd *AdvancedHostnameDetector) detectWindowsDevices(ip string) DeviceInfo {
	info := DeviceInfo{
		IP:               ip,
		DetectionMethods: []string{"netbios"},
		Services:         make(map[string]string),
	}

	// Check for NetBIOS ports (137, 139, 445)
	netbiosPorts := []int{137, 139, 445}
	
	for _, port := range netbiosPorts {
		if ahd.isPortOpen(ip, port) {
			info.OSFamily = "Windows"
			info.DeviceType = "computer"
			info.Services[fmt.Sprintf("netbios_%d", port)] = "open"
			
			// Try to get NetBIOS name
			if hostname := ahd.getNetBIOSName(ip); hostname != "" {
				info.Hostname = hostname
			}
		}
	}

	return info
}

// detectSNMPInfo detects device info using SNMP
func (ahd *AdvancedHostnameDetector) detectSNMPInfo(ip string) DeviceInfo {
	info := DeviceInfo{
		IP:               ip,
		DetectionMethods: []string{"snmp"},
		Services:         make(map[string]string),
	}

	if ahd.isPortOpen(ip, 161) {
		info.Services["snmp"] = "present"
		// TODO: Implement SNMP queries for system description
		// This would require SNMP library to get sysDescr, sysName, etc.
	}

	return info
}

// analyzeHTTPBanners analyzes HTTP server banners for OS/device information
func (ahd *AdvancedHostnameDetector) analyzeHTTPBanners(asset Asset) DeviceInfo {
	info := DeviceInfo{
		IP:               asset.IP,
		DetectionMethods: []string{"http_banner"},
		Services:         make(map[string]string),
	}

	for _, port := range asset.OpenPorts {
		if port.Port == 80 || port.Port == 443 || port.Port == 8080 || port.Port == 8443 {
			protocol := "http"
			if port.Port == 443 || port.Port == 8443 {
				protocol = "https"
			}
			
			url := fmt.Sprintf("%s://%s:%d", protocol, asset.IP, port.Port)
			
			resp, err := ahd.httpClient.Get(url)
			if err == nil {
				defer resp.Body.Close()
				
				// Analyze server header
				server := resp.Header.Get("Server")
				if server != "" {
					info.Services["http_server"] = server
					
					// Extract OS information from server header
					serverLower := strings.ToLower(server)
					if strings.Contains(serverLower, "microsoft") || strings.Contains(serverLower, "iis") {
						info.OSFamily = "Windows"
					} else if strings.Contains(serverLower, "apache") && strings.Contains(serverLower, "ubuntu") {
						info.OSFamily = "Linux"
						info.OSVersion = "Ubuntu"
					} else if strings.Contains(serverLower, "nginx") && strings.Contains(serverLower, "debian") {
						info.OSFamily = "Linux"
						info.OSVersion = "Debian"
					}
				}
				
				// Check for X-Powered-By header
				poweredBy := resp.Header.Get("X-Powered-By")
				if poweredBy != "" {
					info.Services["powered_by"] = poweredBy
				}
			}
		}
	}

	return info
}

// analyzeSSHBanners analyzes SSH banners for OS information
func (ahd *AdvancedHostnameDetector) analyzeSSHBanners(asset Asset) DeviceInfo {
	info := DeviceInfo{
		IP:               asset.IP,
		DetectionMethods: []string{"ssh_banner"},
		Services:         make(map[string]string),
	}

	for _, port := range asset.OpenPorts {
		if port.Port == 22 {
			banner := ahd.getSSHBanner(asset.IP, port.Port)
			if banner != "" {
				info.Services["ssh_banner"] = banner
				
				// Analyze SSH banner for OS hints
				bannerLower := strings.ToLower(banner)
				if strings.Contains(bannerLower, "ubuntu") {
					info.OSFamily = "Linux"
					info.OSVersion = "Ubuntu"
				} else if strings.Contains(bannerLower, "debian") {
					info.OSFamily = "Linux"
					info.OSVersion = "Debian"
				} else if strings.Contains(bannerLower, "centos") || strings.Contains(bannerLower, "rhel") {
					info.OSFamily = "Linux"
					info.OSVersion = "RedHat/CentOS"
				} else if strings.Contains(bannerLower, "openssh") && strings.Contains(bannerLower, "macos") {
					info.OSFamily = "macOS"
				}
			}
		}
	}

	return info
}

// isPortOpen checks if a port is open
func (ahd *AdvancedHostnameDetector) isPortOpen(ip string, port int) bool {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, time.Second*2)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// getNetBIOSName attempts to get NetBIOS name
func (ahd *AdvancedHostnameDetector) getNetBIOSName(ip string) string {
	// This is a simplified NetBIOS name query
	// A full implementation would require proper NetBIOS protocol implementation
	address := net.JoinHostPort(ip, "137")
	conn, err := net.DialTimeout("udp", address, time.Second*2)
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	// TODO: Implement proper NetBIOS name query
	return ""
}

// getSSHBanner gets SSH banner from the server
func (ahd *AdvancedHostnameDetector) getSSHBanner(ip string, port int) string {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, time.Second*3)
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	
	// Read SSH banner
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	
	return strings.TrimSpace(banner)
}

// getManufacturerFromMAC gets manufacturer from MAC address using external API
func (ahd *AdvancedHostnameDetector) getManufacturerFromMAC(mac string) string {
	// Clean and format MAC address
	cleanMAC := strings.ReplaceAll(strings.ToUpper(mac), ":", "")
	if len(cleanMAC) < 6 {
		return ""
	}
	
	// Extract OUI (first 6 characters - 3 octets)
	oui := cleanMAC[:6]
	
	// Try multiple OUI lookup APIs
	manufacturers := []string{
		ahd.queryMACVendorAPI(oui),
		ahd.queryOUILookupAPI(oui),
		ahd.queryMACAddressAPI(oui),
	}
	
	// Return first successful result
	for _, manufacturer := range manufacturers {
		if manufacturer != "" {
			return manufacturer
		}
	}
	
	return ""
}

// queryMACVendorAPI queries macvendors.com API
func (ahd *AdvancedHostnameDetector) queryMACVendorAPI(oui string) string {
	if len(oui) < 6 {
		return ""
	}
	
	// Format OUI with colons: AB:CD:EF
	formattedOUI := fmt.Sprintf("%s:%s:%s", oui[:2], oui[2:4], oui[4:6])
	url := fmt.Sprintf("https://api.macvendors.com/%s", formattedOUI)
	
	resp, err := ahd.httpClient.Get(url)
	if err != nil {
		log.Printf("MAC vendor API error: %v", err)
		return ""
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return ""
		}
		
		vendor := strings.TrimSpace(string(body))
		if vendor != "" && !strings.Contains(vendor, "error") && !strings.Contains(vendor, "Not Found") {
			return vendor
		}
	}
	
	return ""
}

// queryOUILookupAPI queries an alternative OUI lookup service
func (ahd *AdvancedHostnameDetector) queryOUILookupAPI(oui string) string {
	if len(oui) < 6 {
		return ""
	}
	
	// Format OUI without separators
	url := fmt.Sprintf("https://www.macvendorlookup.com/api/v2/%s", oui)
	
	resp, err := ahd.httpClient.Get(url)
	if err != nil {
		log.Printf("OUI lookup API error: %v", err)
		return ""
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return ""
		}
		
		// This API returns JSON, but we'll do simple string parsing
		response := string(body)
		
		// Look for company field in JSON response
		companyRegex := regexp.MustCompile(`"company"\s*:\s*"([^"]+)"`)
		matches := companyRegex.FindStringSubmatch(response)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	
	return ""
}

// queryMACAddressAPI queries maclookup.app API
func (ahd *AdvancedHostnameDetector) queryMACAddressAPI(oui string) string {
	if len(oui) < 6 {
		return ""
	}
	
	url := fmt.Sprintf("https://api.maclookup.app/v2/macs/%s", oui)
	
	resp, err := ahd.httpClient.Get(url)
	if err != nil {
		log.Printf("MAC address API error: %v", err)
		return ""
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return ""
		}
		
		// This API returns JSON, parse for company field
		response := string(body)
		
		// Look for company field in JSON response
		companyRegex := regexp.MustCompile(`"company"\s*:\s*"([^"]+)"`)
		matches := companyRegex.FindStringSubmatch(response)
		if len(matches) > 1 {
			return matches[1]
		}
		
		// Alternative: look for vendor field
		vendorRegex := regexp.MustCompile(`"vendor"\s*:\s*"([^"]+)"`)
		matches = vendorRegex.FindStringSubmatch(response)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	
	return ""
}

// mergeDeviceInfo merges detection results
func (ahd *AdvancedHostnameDetector) mergeDeviceInfo(target *DeviceInfo, source DeviceInfo) {
	ahd.mu.Lock()
	defer ahd.mu.Unlock()
	
	if source.Hostname != "" && target.Hostname == "" {
		target.Hostname = source.Hostname
	}
	
	if source.OSFamily != "" && target.OSFamily == "" {
		target.OSFamily = source.OSFamily
	}
	
	if source.OSVersion != "" && target.OSVersion == "" {
		target.OSVersion = source.OSVersion
	}
	
	if source.DeviceType != "" && target.DeviceType == "" {
		target.DeviceType = source.DeviceType
	}
	
	if source.Manufacturer != "" && target.Manufacturer == "" {
		target.Manufacturer = source.Manufacturer
	}
	
	if source.Model != "" && target.Model == "" {
		target.Model = source.Model
	}
	
	// Merge services
	for key, value := range source.Services {
		target.Services[key] = value
	}
	
	// Merge detection methods
	target.DetectionMethods = append(target.DetectionMethods, source.DetectionMethods...)
}
