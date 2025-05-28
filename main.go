package main

import (
	"fmt"
	"log"
	"os"

	"assetmanager/pkg/config"
)

func main() {
	fmt.Println("Asset Management Service")
	fmt.Println("========================")
	
	// Check if config exists
	if _, err := os.Stat("config.json"); os.IsNotExist(err) {
		fmt.Println("No config.json found, creating default...")
		cfg := config.GetDefaultConfig()
		err := config.SaveConfig(cfg, "config.json")
		if err != nil {
			log.Fatalf("Failed to create config: %v", err)
		}
		fmt.Println("✅ Default config.json created")
	}

	// Check if list.txt exists
	if _, err := os.Stat("list.txt"); os.IsNotExist(err) {
		fmt.Println("No list.txt found, creating sample...")
		createSampleList()
		fmt.Println("✅ Sample list.txt created")
	}

	fmt.Println("\nChoose option:")
	fmt.Println("1. Run daemon (go run asset-daemon.go)")
	fmt.Println("2. Run test (go run test-daemon.go)")
	fmt.Println("3. View current config")
	
	var choice string
	fmt.Print("\nEnter choice (1-3): ")
	fmt.Scanln(&choice)
	
	switch choice {
	case "1":
		fmt.Println("Starting daemon...")
		runDaemon()
	case "2":
		fmt.Println("Running test...")
		runTest()
	case "3":
		showConfig()
	default:
		fmt.Println("Invalid choice")
	}
}

func runDaemon() {
	// This would start the daemon
	fmt.Println("Run: go run asset-daemon.go")
}

func runTest() {
	// This would run the test
	fmt.Println("Run: go run test-daemon.go")
}

func showConfig() {
	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		return
	}
	
	fmt.Printf("\nCurrent Configuration:\n")
	fmt.Printf("  Service: %s\n", cfg.Service.Name)
	fmt.Printf("  Interval: %s\n", cfg.Service.ScanInterval)
	fmt.Printf("  Local Network: %s\n", cfg.Network.DefaultCIDR)
	fmt.Printf("  ARP Enabled: %v\n", cfg.ARP.Enabled)
	fmt.Printf("  Port Scan: %v\n", cfg.PortScan.Enabled)
}

func createSampleList() {
	sample := `# Asset Management - IP Block List
# Lines starting with # are comments

# Local networks
192.168.1.0/24
10.0.0.0/24

# Individual IPs  
8.8.8.8
1.1.1.1`
	
	err := os.WriteFile("list.txt", []byte(sample), 0644)
	if err != nil {
		log.Printf("Failed to create list.txt: %v", err)
	}
}
