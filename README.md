# Asset Management Service

A comprehensive network asset discovery and management tool written in Go that performs ARP scanning, port scanning, and asset tracking based on JSON configuration.

## Features

- **File-based IP Block Scanning**: Reads IP blocks from `list.txt` for targeted scanning
- **Local Network Discovery**: Automatically detects and scans the local network
- **Parallel ARP Scanning**: Multi-threaded ARP discovery with rate limiting
- **Port Scanning**: TCP/UDP port scanning with service detection and banner grabbing
- **JSON Configuration**: Flexible configuration system with validation
- **Background Service**: Designed to run as a daemon/service
- **Asset Management**: Comprehensive asset tracking and reporting

## Quick Start

1. **Build and run the application:**
   ```bash
   go run main.go
   ```

2. **Use a custom configuration file:**
   ```bash
   go run main.go config.production.json
   ```

3. **Generate a new configuration file:**
   ```bash
   go run cmd/config-gen/main.go -output my-config.json
   ```

4. **Validate a configuration file:**
   ```bash
   go run cmd/config-gen/main.go -validate config.json
   ```

## Configuration

The application uses a JSON configuration file (`config.json` by default) to control all aspects of operation.

### Configuration Structure

#### Service Settings
```json
{
  "service": {
    "name": "Asset Management Service",
    "run_as_daemon": true,
    "scan_interval": "5m",
    "auto_start": true,
    "enable_web_ui": false,
    "web_ui_port": 8080
  }
}
```

- **name**: Service display name
- **run_as_daemon**: Whether to run as a background service
- **scan_interval**: How often to perform scans (e.g., "5m", "1h", "30s")
- **auto_start**: Enable automatic startup
- **enable_web_ui**: Enable web-based management interface
- **web_ui_port**: Port for web interface

#### Network Settings
```json
{
  "network": {
    "interface": "auto",
    "auto_detect_local": true,
    "default_cidr": "192.168.1.0/24",
    "scan_local_network": true,
    "scan_file_list": true,
    "enable_ipv6": false,
    "custom_dns_servers": ["8.8.8.8", "8.8.4.4"]
  }
}
```

- **interface**: Network interface to use ("auto" for auto-detection)
- **auto_detect_local**: Automatically detect local network CIDR
- **default_cidr**: Fallback CIDR if auto-detection fails
- **scan_local_network**: Enable local network scanning
- **scan_file_list**: Enable scanning from IP list file
- **enable_ipv6**: Enable IPv6 support
- **custom_dns_servers**: DNS servers for hostname resolution

#### ARP Scanning Settings
```json
{
  "arp": {
    "enabled": true,
    "timeout": "2s",
    "workers": 5,
    "rate_limit": "100ms",
    "retry_count": 2,
    "enable_vendor": true
  }
}
```

- **enabled**: Enable ARP scanning
- **timeout**: ARP request timeout
- **workers**: Number of parallel ARP workers
- **rate_limit**: Delay between ARP requests
- **retry_count**: Number of retries for failed requests
- **enable_vendor**: Enable MAC vendor lookup

#### Port Scanning Settings
```json
{
  "port_scan": {
    "enabled": true,
    "timeout": "2s",
    "workers": 50,
    "scan_tcp": true,
    "scan_udp": false,
    "common_ports": [21, 22, 23, 25, 53, 80, 443],
    "custom_ports": [],
    "enable_banner": true,
    "service_detection": true,
    "scan_all_ports": false,
    "port_range_start": 1,
    "port_range_end": 1024
  }
}
```

- **enabled**: Enable port scanning
- **timeout**: Port scan timeout per port
- **workers**: Number of parallel port scan workers
- **scan_tcp**: Enable TCP port scanning
- **scan_udp**: Enable UDP port scanning
- **common_ports**: List of commonly scanned ports
- **custom_ports**: Additional custom ports to scan
- **enable_banner**: Enable banner grabbing
- **service_detection**: Enable service detection
- **scan_all_ports**: Scan all 65535 ports (overrides port lists)
- **port_range_start/end**: Port range for scanning

#### File Settings
```json
{
  "files": {
    "ip_list_file": "list.txt",
    "output_file": "assets.json",
    "log_file": "asset_manager.log",
    "database_file": "assets.db",
    "backup_enabled": true,
    "backup_interval": "24h"
  }
}
```

- **ip_list_file**: File containing IP blocks to scan
- **output_file**: Output file for discovered assets
- **log_file**: Application log file
- **database_file**: SQLite database for asset storage
- **backup_enabled**: Enable automatic backups
- **backup_interval**: Backup frequency

#### Logging Settings
```json
{
  "logging": {
    "level": "info",
    "enable_console": true,
    "enable_file": true,
    "max_file_size": "100MB",
    "max_backups": 5,
    "enable_syslog": false
  }
}
```

- **level**: Log level (debug, info, warn, error)
- **enable_console**: Enable console logging
- **enable_file**: Enable file logging
- **max_file_size**: Maximum log file size before rotation
- **max_backups**: Number of backup log files to keep
- **enable_syslog**: Enable syslog output

## IP List File Format

The `list.txt` file supports both individual IPs and CIDR notation:

```
# Comments start with #
192.168.1.0/24
10.0.0.0/24
172.16.1.1
192.168.100.50
```

## Configuration Examples

### Development Configuration
```json
{
  "service": {
    "scan_interval": "30s",
    "run_as_daemon": false
  },
  "arp": {
    "workers": 2,
    "rate_limit": "200ms"
  },
  "port_scan": {
    "workers": 10,
    "scan_udp": false
  },
  "logging": {
    "level": "debug",
    "enable_console": true
  }
}
```

### Production Configuration
```json
{
  "service": {
    "scan_interval": "15m",
    "run_as_daemon": true,
    "enable_web_ui": true
  },
  "arp": {
    "workers": 10,
    "rate_limit": "50ms"
  },
  "port_scan": {
    "workers": 100,
    "scan_udp": true,
    "timeout": "5s"
  },
  "logging": {
    "level": "warn",
    "enable_console": false,
    "enable_syslog": true
  }
}
```

## Configuration Management

### Generate Default Configuration
```bash
go run cmd/config-gen/main.go
```

### Generate Custom Configuration
```bash
go run cmd/config-gen/main.go -output production.json
```

### Validate Configuration
```bash
go run cmd/config-gen/main.go -validate config.json
```

### View Configuration Help
```bash
go run cmd/config-gen/main.go -help
```

## Building

### Build Main Application
```bash
go build -o assetmanager main.go
```

### Build Configuration Tool
```bash
go build -o config-gen cmd/config-gen/main.go
```

## Requirements

- Go 1.24.3 or later
- Linux (tested on Ubuntu/Debian)
- Root privileges for ARP scanning
- Network interface access

## Dependencies

- `github.com/mdlayher/arp` - ARP protocol implementation
- Standard Go libraries for networking and JSON

## Usage Examples

### Basic Scanning
```bash
# Scan with default configuration
./assetmanager

# Scan with custom configuration
./assetmanager config.production.json
```

### Configuration Management
```bash
# Create new configuration
./config-gen -output my-config.json

# Validate configuration
./config-gen -validate my-config.json

# View configuration summary
./config-gen -validate config.json
```

## Architecture

The application is structured in modular packages:

- **`pkg/config`**: Configuration management and JSON parsing
- **`pkg/network`**: Network scanning functionality
  - `arp.go`: Basic ARP scanning
  - `arp_parallel.go`: Parallel ARP scanning
  - `port_scanner.go`: Port scanning with service detection
  - `asset_discovery.go`: Combined asset discovery
  - `cidr.go`: CIDR and IP utilities
  - `file_utils.go`: File-based IP list management
- **`cmd/config-gen`**: Configuration generation utility

## License

This project is part of an asset management system implementation based on specified requirements (see `gereksinim` file).

## Contributing

This tool was developed to meet specific asset management requirements including:
1. File-based IP block scanning
2. Local network discovery
3. Background service operation
4. JSON configuration support
5. Comprehensive asset tracking 