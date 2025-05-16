package network

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// ReadCIDRsFromFile reads CIDR ranges from a file, one per line
func ReadCIDRsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	var cidrs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Validate CIDR format
		_, _, err := net.ParseCIDR(line)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR format in line: %s, error: %w", line, err)
		}
		cidrs = append(cidrs, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filePath, err)
	}

	return cidrs, nil
}

// WriteCIDRsToFile writes CIDR ranges to a file, one per line
func WriteCIDRsToFile(filePath string, cidrs []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, cidr := range cidrs {
		_, err := writer.WriteString(cidr + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to file %s: %w", filePath, err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer for file %s: %w", filePath, err)
	}

	return nil
}
