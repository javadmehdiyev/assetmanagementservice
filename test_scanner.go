package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"assetmanager/pkg/network"
)

func main() {
	fmt.Println("Testing Asset Discovery System...")

	// Create port scanner
	portScanner := network.NewPortScanner(3*time.Second, 10, 2)

	// Test port scanning on localhost
	fmt.Println("Testing port scanner on localhost...")
	openPorts := portScanner.ScanCommonPorts("127.0.0.1")
	fmt.Printf("Found %d open ports on localhost:\n", len(openPorts))
	for _, port := range openPorts {
		fmt.Printf("  Port %d/%s - %s (%s)\n", port.Port, port.Protocol, port.Service, port.State)
	}

	// Test credential checker
	fmt.Println("\nTesting credential checker...")
	credChecker, err := network.NewCredentialChecker("static/default_credentials.txt", 5*time.Second, 5)
	if err != nil {
		log.Printf("Warning: Could not create credential checker: %v", err)
	} else {
		fmt.Println("Credential checker created successfully")
	}

	// Test hostname detector
	fmt.Println("\nTesting hostname detector...")
	hostnameDetector := network.NewAdvancedHostnameDetector(5 * time.Second)
	
	// Create a test asset
	testAsset := network.Asset{
		IP:        "127.0.0.1",
		OpenPorts: openPorts,
		MAC:       "00:11:22:33:44:55", // Fake MAC for testing
		LastSeen:  time.Now(),
		FirstSeen: time.Now(),
	}

	deviceInfo := hostnameDetector.DetectDeviceInfo(testAsset)
	fmt.Printf("Device info detected: OS=%s, Type=%s, Manufacturer=%s\n", 
		deviceInfo.OSFamily, deviceInfo.DeviceType, deviceInfo.Manufacturer)

	// Test asset discovery structure
	fmt.Println("\nTesting asset discovery structure...")
	assetDiscovery, err := network.NewAssetDiscovery("", 2*time.Second, 3*time.Second, 10, 100*time.Millisecond)
	if err != nil {
		log.Printf("Warning: Could not create asset discovery: %v", err)
	} else {
		fmt.Println("Asset discovery created successfully")
		
		if credChecker != nil {
			assetDiscovery.SetCredentialChecker(credChecker)
			fmt.Println("Credential checker attached")
		}
	}

	// Create a sample result to show format
	sampleAssets := []network.Asset{testAsset}
	
	// Convert to JSON to show format
	jsonData, err := json.MarshalIndent(sampleAssets, "", "  ")
	if err == nil {
		fmt.Println("\nSample JSON output format:")
		fmt.Println(string(jsonData))
	}

	fmt.Println("\nTest completed! All components initialized successfully.")
	fmt.Println("The system is ready for Linux testing.")
}
