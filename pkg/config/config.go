package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

type Config struct {
	Service  ServiceConfig  `json:"service"`
	Network  NetworkConfig  `json:"network"`
	ARP      ARPConfig      `json:"arp"`
	PortScan PortScanConfig `json:"port_scan"`
	Files    FileConfig     `json:"files"`
}

type ServiceConfig struct {
	Name         string `json:"name"`
	RunAsDaemon  bool   `json:"run_as_daemon"`
	ScanInterval string `json:"scan_interval"`
	AutoStart    bool   `json:"auto_start"`
}

type NetworkConfig struct {
	Interface        string `json:"interface"`
	AutoDetectLocal  bool   `json:"auto_detect_local"`
	DefaultCIDR      string `json:"default_cidr"`
	ScanLocalNetwork bool   `json:"scan_local_network"`
	ScanFileList     bool   `json:"scan_file_list"`
}

type ARPConfig struct {
	Enabled   bool   `json:"enabled"`
	Timeout   string `json:"timeout"`
	Workers   int    `json:"workers"`
	RateLimit string `json:"rate_limit"`
}

type PortScanConfig struct {
	Enabled bool   `json:"enabled"`
	Timeout string `json:"timeout"`
	Workers int    `json:"workers"`
}

type FileConfig struct {
	IPListFile string `json:"ip_list_file"`
	OutputFile string `json:"output_file"`
}

func LoadConfig(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", configPath)
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %v", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return &config, nil
}

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

func (c *Config) Validate() error {
	if c.Service.ScanInterval != "" {
		if _, err := time.ParseDuration(c.Service.ScanInterval); err != nil {
			return fmt.Errorf("invalid scan_interval: %v", err)
		}
	}

	if c.ARP.Timeout != "" {
		if _, err := time.ParseDuration(c.ARP.Timeout); err != nil {
			return fmt.Errorf("invalid ARP timeout: %v", err)
		}
	}

	if c.ARP.RateLimit != "" {
		if _, err := time.ParseDuration(c.ARP.RateLimit); err != nil {
			return fmt.Errorf("invalid ARP rate_limit: %v", err)
		}
	}

	if c.PortScan.Timeout != "" {
		if _, err := time.ParseDuration(c.PortScan.Timeout); err != nil {
			return fmt.Errorf("invalid port scan timeout: %v", err)
		}
	}

	return nil
}

func (c *Config) GetScanInterval() (time.Duration, error) {
	if c.Service.ScanInterval == "" {
		return 5 * time.Minute, nil
	}
	return time.ParseDuration(c.Service.ScanInterval)
}

func (c *Config) GetARPTimeout() (time.Duration, error) {
	if c.ARP.Timeout == "" {
		return 2 * time.Second, nil
	}
	return time.ParseDuration(c.ARP.Timeout)
}

func (c *Config) GetARPRateLimit() (time.Duration, error) {
	if c.ARP.RateLimit == "" {
		return 100 * time.Millisecond, nil
	}
	return time.ParseDuration(c.ARP.RateLimit)
}

func (c *Config) GetPortScanTimeout() (time.Duration, error) {
	if c.PortScan.Timeout == "" {
		return 2 * time.Second, nil
	}
	return time.ParseDuration(c.PortScan.Timeout)
}

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
			IPListFile: "list.txt",
			OutputFile: "assets.json",
		},
	}
}