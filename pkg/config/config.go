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
	
	// File settings
	Files FileConfig `json:"files"`
}

// ServiceConfig contains service-level settings
type ServiceConfig struct {
	Name         string `json:"name"`
	RunAsDaemon  bool   `json:"run_as_daemon"`
	ScanInterval string `json:"scan_interval"`    // e.g., "5m", "1h"
	AutoStart    bool   `json:"auto_start"`
}

// NetworkConfig contains network scanning settings
type NetworkConfig struct {
	Interface       string `json:"interface"`
	AutoDetectLocal bool   `json:"auto_detect_local"`
	DefaultCIDR     string `json:"default_cidr"`
	ScanLocalNetwork bool  `json:"scan_local_network"`
	ScanFileList    bool   `json:"scan_file_list"`
}

// ARPConfig contains ARP scanning settings
type ARPConfig struct {
	Enabled   bool   `json:"enabled"`
	Timeout   string `json:"timeout"`        // e.g., "2s", "3s"
	Workers   int    `json:"workers"`
	RateLimit string `json:"rate_limit"`     // e.g., "100ms", "50ms"
}

// PortScanConfig contains port scanning settings
type PortScanConfig struct {
	Enabled bool   `json:"enabled"`
	Timeout string `json:"timeout"`        // e.g., "2s", "5s"
	Workers int    `json:"workers"`
}

// FileConfig contains file-related settings
type FileConfig struct {
	IPListFile   string `json:"ip_list_file"`
	OutputFile   string `json:"output_file"`
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
		},
		Network: NetworkConfig{
			Interface:        "auto",
			AutoDetectLocal:  true,
			DefaultCIDR:      "192.168.1.0/24",
			ScanLocalNetwork: true,
			ScanFileList:     true,
		},
		ARP: ARPConfig{
			Enabled:   true,
			Timeout:   "2s",
			Workers:   5,
			RateLimit: "100ms",
		},
		PortScan: PortScanConfig{
			Enabled: false,
			Timeout: "2s",
			Workers: 20,
		},
		Files: FileConfig{
			IPListFile:     "list.txt",
			OutputFile:     "assets.json",
		},
	}
} 