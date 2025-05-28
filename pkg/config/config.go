package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

// Config represents the application configuration
type Config struct {
	// Service settings
	Service ServiceConfig `json:"service"`
	
	// Network scanning settings
	Network NetworkConfig `json:"network"`
	
	// ARP scanning settings
	ARP ARPConfig `json:"arp"`
	
	// Port scanning settings
	PortScan PortScanConfig `json:"port_scan"`
	
	// Discovery settings
	Discovery DiscoveryConfig `json:"discovery"`
	
	// File settings
	Files FileConfig `json:"files"`
	
	// Logging settings
	Logging LoggingConfig `json:"logging"`
}

// ServiceConfig contains service-level settings
type ServiceConfig struct {
	Name            string `json:"name"`
	RunAsDaemon     bool   `json:"run_as_daemon"`
	ScanInterval    string `json:"scan_interval"`    // e.g., "5m", "1h"
	AutoStart       bool   `json:"auto_start"`
	EnableWebUI     bool   `json:"enable_web_ui"`
	WebUIPort       int    `json:"web_ui_port"`
}

// NetworkConfig contains network scanning settings
type NetworkConfig struct {
	Interface         string   `json:"interface"`
	AutoDetectLocal   bool     `json:"auto_detect_local"`
	DefaultCIDR       string   `json:"default_cidr"`
	ScanLocalNetwork  bool     `json:"scan_local_network"`
	ScanFileList      bool     `json:"scan_file_list"`
	EnableIPv6        bool     `json:"enable_ipv6"`
	CustomDNSServers  []string `json:"custom_dns_servers"`
}

// ARPConfig contains ARP scanning settings
type ARPConfig struct {
	Enabled       bool   `json:"enabled"`
	Timeout       string `json:"timeout"`        // e.g., "2s", "3s"
	Workers       int    `json:"workers"`
	RateLimit     string `json:"rate_limit"`     // e.g., "100ms", "50ms"
	RetryCount    int    `json:"retry_count"`
	EnableVendor  bool   `json:"enable_vendor"`
}

// PortScanConfig contains port scanning settings
type PortScanConfig struct {
	Enabled         bool     `json:"enabled"`
	Timeout         string   `json:"timeout"`        // e.g., "2s", "5s"
	Workers         int      `json:"workers"`
	ScanTCP         bool     `json:"scan_tcp"`
	ScanUDP         bool     `json:"scan_udp"`
	CommonPorts     []int    `json:"common_ports"`
	CustomPorts     []int    `json:"custom_ports"`
	EnableBanner    bool     `json:"enable_banner"`
	ServiceDetection bool    `json:"service_detection"`
	ScanAllPorts    bool     `json:"scan_all_ports"`
	PortRangeStart  int      `json:"port_range_start"`
	PortRangeEnd    int      `json:"port_range_end"`
}

// DiscoveryConfig contains discovery settings
type DiscoveryConfig struct {
	EnableICMPPing        bool     `json:"enable_icmp_ping"`
	EnableTCPSynDiscovery bool     `json:"enable_tcp_syn_discovery"`
	ICMPTimeout           string   `json:"icmp_timeout"`
	ICMPWorkers           int      `json:"icmp_workers"`
	TCPDiscoveryPorts     []int    `json:"tcp_discovery_ports"`
	CombineMethods        bool     `json:"combine_methods"`
}

// FileConfig contains file-related settings
type FileConfig struct {
	IPListFile      string `json:"ip_list_file"`
	OutputFile      string `json:"output_file"`
	LogFile         string `json:"log_file"`
	DatabaseFile    string `json:"database_file"`
	BackupEnabled   bool   `json:"backup_enabled"`
	BackupInterval  string `json:"backup_interval"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level          string `json:"level"`           // debug, info, warn, error
	EnableConsole  bool   `json:"enable_console"`
	EnableFile     bool   `json:"enable_file"`
	MaxFileSize    string `json:"max_file_size"`   // e.g., "100MB"
	MaxBackups     int    `json:"max_backups"`
	EnableSyslog   bool   `json:"enable_syslog"`
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(configPath string) (*Config, error) {
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", configPath)
	}

	// Read the config file
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse JSON
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %v", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return &config, nil
}

// SaveConfig saves configuration to a JSON file
func SaveConfig(config *Config, configPath string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := ioutil.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate service interval
	if c.Service.ScanInterval != "" {
		if _, err := time.ParseDuration(c.Service.ScanInterval); err != nil {
			return fmt.Errorf("invalid scan_interval: %v", err)
		}
	}

	// Validate ARP timeout
	if c.ARP.Timeout != "" {
		if _, err := time.ParseDuration(c.ARP.Timeout); err != nil {
			return fmt.Errorf("invalid ARP timeout: %v", err)
		}
	}

	// Validate ARP rate limit
	if c.ARP.RateLimit != "" {
		if _, err := time.ParseDuration(c.ARP.RateLimit); err != nil {
			return fmt.Errorf("invalid ARP rate_limit: %v", err)
		}
	}

	// Validate port scan timeout
	if c.PortScan.Timeout != "" {
		if _, err := time.ParseDuration(c.PortScan.Timeout); err != nil {
			return fmt.Errorf("invalid port scan timeout: %v", err)
		}
	}

	// Validate port ranges
	if c.PortScan.PortRangeStart < 1 || c.PortScan.PortRangeStart > 65535 {
		return fmt.Errorf("invalid port_range_start: must be 1-65535")
	}
	if c.PortScan.PortRangeEnd < 1 || c.PortScan.PortRangeEnd > 65535 {
		return fmt.Errorf("invalid port_range_end: must be 1-65535")
	}
	if c.PortScan.PortRangeStart > c.PortScan.PortRangeEnd {
		return fmt.Errorf("port_range_start cannot be greater than port_range_end")
	}

	// Validate logging level
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("invalid logging level: must be debug, info, warn, or error")
	}

	return nil
}

// GetScanInterval returns the scan interval as time.Duration
func (c *Config) GetScanInterval() (time.Duration, error) {
	if c.Service.ScanInterval == "" {
		return 5 * time.Minute, nil // Default to 5 minutes
	}
	return time.ParseDuration(c.Service.ScanInterval)
}

// GetARPTimeout returns the ARP timeout as time.Duration
func (c *Config) GetARPTimeout() (time.Duration, error) {
	if c.ARP.Timeout == "" {
		return 2 * time.Second, nil // Default to 2 seconds
	}
	return time.ParseDuration(c.ARP.Timeout)
}

// GetARPRateLimit returns the ARP rate limit as time.Duration
func (c *Config) GetARPRateLimit() (time.Duration, error) {
	if c.ARP.RateLimit == "" {
		return 100 * time.Millisecond, nil // Default to 100ms
	}
	return time.ParseDuration(c.ARP.RateLimit)
}

// GetPortScanTimeout returns the port scan timeout as time.Duration
func (c *Config) GetPortScanTimeout() (time.Duration, error) {
	if c.PortScan.Timeout == "" {
		return 2 * time.Second, nil // Default to 2 seconds
	}
	return time.ParseDuration(c.PortScan.Timeout)
}

// GetDefaultConfig returns a default configuration
func GetDefaultConfig() *Config {
	return &Config{
		Service: ServiceConfig{
			Name:         "Asset Management Service",
			RunAsDaemon:  true,
			ScanInterval: "5m",
			AutoStart:    true,
			EnableWebUI:  false,
			WebUIPort:    8080,
		},
		Network: NetworkConfig{
			Interface:        "auto",
			AutoDetectLocal:  true,
			DefaultCIDR:      "192.168.1.0/24",
			ScanLocalNetwork: true,
			ScanFileList:     true,
			EnableIPv6:       false,
			CustomDNSServers: []string{"8.8.8.8", "8.8.4.4"},
		},
		ARP: ARPConfig{
			Enabled:      true,
			Timeout:      "2s",
			Workers:      5,
			RateLimit:    "100ms",
			RetryCount:   2,
			EnableVendor: true,
		},
		PortScan: PortScanConfig{
			Enabled:          true,
			Timeout:          "2s",
			Workers:          50,
			ScanTCP:          true,
			ScanUDP:          false,
			CommonPorts:      []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900},
			CustomPorts:      []int{},
			EnableBanner:     true,
			ServiceDetection: true,
			ScanAllPorts:     false,
			PortRangeStart:   1,
			PortRangeEnd:     1024,
		},
		Discovery: DiscoveryConfig{
			EnableICMPPing:        false,
			EnableTCPSynDiscovery: false,
			ICMPTimeout:           "3s",
			ICMPWorkers:           10,
			TCPDiscoveryPorts:     []int{22, 80, 443},
			CombineMethods:        true,
		},
		Files: FileConfig{
			IPListFile:     "list.txt",
			OutputFile:     "assets.json",
			LogFile:        "asset_manager.log",
			DatabaseFile:   "assets.db",
			BackupEnabled:  true,
			BackupInterval: "24h",
		},
		Logging: LoggingConfig{
			Level:         "info",
			EnableConsole: true,
			EnableFile:    true,
			MaxFileSize:   "100MB",
			MaxBackups:    5,
			EnableSyslog:  false,
		},
	}
} 