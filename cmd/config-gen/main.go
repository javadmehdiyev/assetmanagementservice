package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"assetmanager/pkg/config"
)

func main() {
	var (
		outputFile   = flag.String("output", "config.json", "Output configuration file path")
		validateFile = flag.String("validate", "", "Validate an existing configuration file")
		showHelp     = flag.Bool("help", false, "Show help information")
	)
	flag.Parse()

	if *showHelp {
		showUsage()
		return
	}

	// Validate mode
	if *validateFile != "" {
		validateConfig(*validateFile)
		return
	}

	// Generate mode (default)
	generateConfig(*outputFile)
}

func generateConfig(outputFile string) {
	fmt.Printf("Generating default configuration file: %s\n", outputFile)

	// Check if file exists
	if _, err := os.Stat(outputFile); err == nil {
		fmt.Printf("Warning: File %s already exists. Overwrite? (y/N): ", outputFile)
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Operation cancelled.")
			return
		}
	}

	// Create default configuration
	cfg := config.GetDefaultConfig()

	// Save to file
	if err := config.SaveConfig(cfg, outputFile); err != nil {
		log.Fatalf("Failed to save configuration: %v", err)
	}

	fmt.Printf("Configuration file created successfully: %s\n", outputFile)
	fmt.Println("\nConfiguration summary:")
	printConfigSummary(cfg)
}

func validateConfig(configFile string) {
	fmt.Printf("Validating configuration file: %s\n", configFile)

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	fmt.Println("✓ Configuration is valid!")
	fmt.Println("\nConfiguration summary:")
	printConfigSummary(cfg)
}

func printConfigSummary(cfg *config.Config) {
	fmt.Printf("Service Name: %s\n", cfg.Service.Name)
	fmt.Printf("Run as Daemon: %v\n", cfg.Service.RunAsDaemon)
	fmt.Printf("Scan Interval: %s\n", cfg.Service.ScanInterval)
	fmt.Printf("Auto Start: %v\n", cfg.Service.AutoStart)
	
	fmt.Printf("\nNetwork Settings:\n")
	fmt.Printf("  Interface: %s\n", cfg.Network.Interface)
	fmt.Printf("  Auto Detect Local: %v\n", cfg.Network.AutoDetectLocal)
	fmt.Printf("  Default CIDR: %s\n", cfg.Network.DefaultCIDR)
	fmt.Printf("  Scan Local Network: %v\n", cfg.Network.ScanLocalNetwork)
	fmt.Printf("  Scan File List: %v\n", cfg.Network.ScanFileList)
	
	fmt.Printf("\nARP Settings:\n")
	fmt.Printf("  Enabled: %v\n", cfg.ARP.Enabled)
	fmt.Printf("  Timeout: %s\n", cfg.ARP.Timeout)
	fmt.Printf("  Workers: %d\n", cfg.ARP.Workers)
	fmt.Printf("  Rate Limit: %s\n", cfg.ARP.RateLimit)
	
	fmt.Printf("\nPort Scan Settings:\n")
	fmt.Printf("  Enabled: %v\n", cfg.PortScan.Enabled)
	fmt.Printf("  Timeout: %s\n", cfg.PortScan.Timeout)
	fmt.Printf("  Workers: %d\n", cfg.PortScan.Workers)
	fmt.Printf("  Scan TCP: %v\n", cfg.PortScan.ScanTCP)
	fmt.Printf("  Scan UDP: %v\n", cfg.PortScan.ScanUDP)
	fmt.Printf("  Common Ports: %d configured\n", len(cfg.PortScan.CommonPorts))
	fmt.Printf("  Enable Banner: %v\n", cfg.PortScan.EnableBanner)
	
	fmt.Printf("\nFile Settings:\n")
	fmt.Printf("  IP List File: %s\n", cfg.Files.IPListFile)
	fmt.Printf("  Output File: %s\n", cfg.Files.OutputFile)
	fmt.Printf("  Log File: %s\n", cfg.Files.LogFile)
	
	fmt.Printf("\nLogging Settings:\n")
	fmt.Printf("  Level: %s\n", cfg.Logging.Level)
	fmt.Printf("  Console: %v\n", cfg.Logging.EnableConsole)
	fmt.Printf("  File: %v\n", cfg.Logging.EnableFile)
}

func showUsage() {
	fmt.Println("Asset Management Service - Configuration Generator")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  config-gen [flags]")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -output string")
	fmt.Println("        Output configuration file path (default \"config.json\")")
	fmt.Println("  -validate string")
	fmt.Println("        Validate an existing configuration file")
	fmt.Println("  -help")
	fmt.Println("        Show this help information")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  config-gen                           # Generate default config.json")
	fmt.Println("  config-gen -output custom.json       # Generate custom configuration file")
	fmt.Println("  config-gen -validate config.json     # Validate existing configuration")
} 