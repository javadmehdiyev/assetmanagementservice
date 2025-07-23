package utilities

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type NetworkInterface struct {
	Name         string
	RxPackets    uint64
	TxPackets    uint64
	TotalPackets uint64
}

func GetMainNetworkInterface() (*NetworkInterface, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/net/dev: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var interfaces []NetworkInterface
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		if lineNum <= 2 {
			continue
		}

		interface_, err := parseInterfaceLine(line)
		if err != nil {
			fmt.Printf("Warning: failed to parse line %d: %v\n", lineNum, err)
			continue
		}

		if isValidInterface(interface_.Name) {
			interfaces = append(interfaces, *interface_)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no valid network interfaces found")
	}

	var mainInterface *NetworkInterface
	maxPackets := uint64(0)

	for i := range interfaces {
		if interfaces[i].TotalPackets > maxPackets {
			maxPackets = interfaces[i].TotalPackets
			mainInterface = &interfaces[i]
		}
	}

	return mainInterface, nil
}

func parseInterfaceLine(line string) (*NetworkInterface, error) {
	parts := strings.Split(line, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid line format")
	}

	interfaceName := strings.TrimSpace(parts[0])

	stats := strings.Fields(parts[1])
	if len(stats) < 16 {
		return nil, fmt.Errorf("insufficient statistics fields")
	}

	rxPackets, err := strconv.ParseUint(stats[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RX packets: %v", err)
	}

	txPackets, err := strconv.ParseUint(stats[9], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TX packets: %v", err)
	}

	return &NetworkInterface{
		Name:         interfaceName,
		RxPackets:    rxPackets,
		TxPackets:    txPackets,
		TotalPackets: rxPackets + txPackets,
	}, nil
}

func isValidInterface(name string) bool {
	if name == "lo" {
		return false
	}

	skipPrefixes := []string{"docker", "veth", "br-", "virbr", "tun", "tap"}
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}

	return true
}
