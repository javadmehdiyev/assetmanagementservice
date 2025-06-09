# Asset Management Service Package

## Package Structure

```
assetmanagementservice/
├── README.md              # Comprehensive integration guide
├── setup.sh              # Automated setup script
├── 
├── Core Service Files:
├── asset-daemon.go        # Main daemon service (294 lines)
├── main.go               # Configuration setup utility (88 lines)
├── test-daemon.go        # Service testing utility (169 lines)
├── 
├── Configuration:
├── config.json           # Service configuration
├── list.txt             # Target IP blocks/ranges
├── 
├── Web Interface:
├── assets-ui.php         # Modern web dashboard (299 lines)
├── 
├── Go Modules:
├── go.mod               # Go module definition
├── go.sum               # Dependency checksums
├── 
├── Core Packages:
├── pkg/config/
│   └── config.go        # Configuration management (155 lines)
└── pkg/network/
    ├── arp.go           # ARP scanning functionality
    ├── arp_parallel.go  # Parallel ARP operations
    ├── asset_discovery.go # Core discovery engine
    ├── cidr.go          # CIDR network utilities
    ├── file_utils.go    # File operations
    └── port_scanner.go  # TCP port scanning
```

## File Purposes

### Service Components

**asset-daemon.go**
- Main background service daemon
- Handles continuous asset discovery
- Manages scan scheduling and JSON output
- Provides graceful shutdown capabilities

**main.go**
- Interactive setup utility
- Creates default configurations
- Provides service management menu
- Generates sample target lists

**test-daemon.go**
- Service validation utility
- Tests all major components
- Verifies network connectivity
- Outputs test results in JSON format

### Configuration Files

**config.json**
- Complete service configuration
- Network scanning parameters
- ARP and port scan settings
- File paths and intervals

**list.txt**
- Target IP blocks and ranges
- CIDR notation support
- Individual IP addresses
- Comment support with # prefix

### Integration Interface

**assets-ui.php**
- Modern web dashboard
- Real-time asset visualization
- Service status monitoring
- Auto-refresh capabilities
- Mobile-responsive design

## Service Output

**assets.json** (Generated at runtime)
- Complete asset inventory
- JSON format for easy integration
- Includes MAC addresses, vendors, hostnames
- Port scan results when enabled
- Timestamp and scan duration info

## Package Features

### Multi-Method Discovery
- ARP scanning for local networks
- TCP scanning for remote networks
- MAC address to vendor mapping
- Hostname resolution

### Integration Ready
- JSON-based output format
- File-based monitoring support
- HTTP/REST API compatibility
- Database import examples

### Performance Optimized
- Parallel scanning workers
- Configurable timeouts
- Rate limiting support
- Minimal resource usage

### Production Ready
- Systemd service support
- Docker containerization
- Comprehensive error handling
- Graceful shutdown procedures

## Quick Start

1. **Setup**: `./setup.sh`
2. **Configure**: Edit `config.json` and `list.txt`
3. **Start Service**: `go run asset-daemon.go`
4. **View Results**: `cat assets.json` or open web UI

## Integration Points

### File-Based
- Monitor `assets.json` for changes
- Parse JSON for asset information
- Use timestamps for freshness checks

### HTTP-Based
- Serve `assets-ui.php` via web server
- Create custom REST API wrappers
- Implement real-time WebSocket updates

### Database Integration
- Import JSON data to SQL databases
- Use provided schema examples
- Implement automated sync processes

## Dependencies

- Go 1.19+ (required)
- Network interface access (CAP_NET_RAW for ARP)
- PHP 7.4+ (optional, for web interface)

## License

Internal use software package. Modify and distribute according to organizational policies. 