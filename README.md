# Asset Management Service

A high-performance network asset discovery daemon that provides JSON-based asset information for integration with other applications.

## Features

- **Multi-Method Discovery**: Combines ARP scanning for local networks and TCP scanning for remote networks
- **File-Based Target Lists**: Supports CIDR blocks and individual IPs from configuration files
- **JSON Output**: Structured data format for easy integration
- **Real-Time Monitoring**: Configurable scan intervals with live status updates
- **Web Interface**: Modern PHP-based dashboard for asset visualization
- **Vendor Detection**: MAC address to vendor mapping for device identification

## Quick Start

### Installation

```bash
git clone <repository>
cd assetmanagementservice
go mod tidy
```

### Basic Usage

1. **Initialize Configuration**:
```bash
go run main.go
```

2. **Start the Daemon**:
```bash
go run asset-daemon.go
```

3. **View Results**:
```bash
cat assets.json
```

## Service Integration

### JSON Output Format

The service generates `assets.json` with the following structure:

```json
{
  "timestamp": "2024-01-15 10:30:45",
  "total_hosts": 15,
  "scan_time": "2.5s",
  "local_network": "192.168.1.0/24",
  "file_targets": 4,
  "assets": [
    {
      "ip": "192.168.1.10",
      "hostname": "server.local",
      "mac": "aa:bb:cc:dd:ee:ff",
      "vendor": "Intel Corporate",
      "discovery_method": "ARP",
      "arp_response": true,
      "open_ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "service": "ssh"
        },
        {
          "port": 80,
          "protocol": "tcp",
          "service": "http"
        }
      ],
      "last_seen": "2024-01-15T10:30:45Z"
    }
  ]
}
```

### Integration Methods

#### 1. File-Based Integration

Monitor `assets.json` for changes:

```bash
# Using inotify (Linux)
inotifywait -m -e modify assets.json

# Using fswatch (macOS/Linux)
fswatch assets.json
```

#### 2. HTTP API Integration

Use the included PHP interface:

```bash
# Start a web server
php -S localhost:8080 assets-ui.php
```

Access at: `http://localhost:8080`

#### 3. Direct File Reading

```python
import json
import time
from datetime import datetime

def read_assets():
    try:
        with open('assets.json', 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        return None

# Example usage
assets = read_assets()
if assets:
    print(f"Found {assets['total_hosts']} assets")
    for asset in assets['assets']:
        print(f"- {asset['ip']} ({asset.get('vendor', 'Unknown')})")
```

#### 4. Database Integration

```sql
-- Example PostgreSQL schema
CREATE TABLE assets (
    ip INET PRIMARY KEY,
    hostname VARCHAR(255),
    mac_address MACADDR,
    vendor VARCHAR(255),
    discovery_method VARCHAR(50),
    last_seen TIMESTAMP,
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Import data using JSON processing
INSERT INTO assets (ip, hostname, mac_address, vendor, discovery_method, last_seen)
SELECT 
    (asset->>'ip')::inet,
    asset->>'hostname',
    (asset->>'mac')::macaddr,
    asset->>'vendor',
    asset->>'discovery_method',
    (asset->>'last_seen')::timestamp
FROM json_array_elements((pg_read_file('assets.json')::json->'assets')) as asset;
```

## Configuration

### config.json Structure

```json
{
  "service": {
    "name": "Asset Management Service",
    "scan_interval": "5m"
  },
  "network": {
    "interface": "auto",
    "auto_detect_local": true,
    "default_cidr": "192.168.1.0/24",
    "scan_local_network": true,
    "scan_file_list": true
  },
  "arp": {
    "enabled": true,
    "timeout": "2s",
    "workers": 5,
    "rate_limit": "100ms"
  },
  "port_scan": {
    "enabled": false,
    "timeout": "2s",
    "workers": 20
  },
  "files": {
    "ip_list_file": "list.txt",
    "output_file": "assets.json"
  }
}
```

### Target Lists (list.txt)

```
# CIDR blocks
192.168.1.0/24
10.0.0.0/24

# Individual IPs
8.8.8.8
1.1.1.1
```

## Performance Tuning

### Fast Discovery Mode

For rapid scanning, adjust timeouts:

```json
{
  "arp": {
    "timeout": "500ms",
    "rate_limit": "50ms"
  },
  "port_scan": {
    "timeout": "1s"
  }
}
```

### High-Throughput Mode

For large networks:

```json
{
  "arp": {
    "workers": 20,
    "rate_limit": "10ms"
  },
  "port_scan": {
    "workers": 50
  }
}
```

## Monitoring and Alerting

### Daemon Status Check

```bash
# Check if daemon is running
pgrep -f asset-daemon

# Monitor log output
tail -f daemon.log
```

### Integration Alerts

```python
import json
import time
import smtplib
from datetime import datetime, timedelta

def check_asset_freshness():
    try:
        with open('assets.json', 'r') as f:
            data = json.load(f)
        
        scan_time = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S')
        age = datetime.now() - scan_time
        
        if age > timedelta(minutes=10):
            send_alert(f"Asset data is {age} old")
            
    except Exception as e:
        send_alert(f"Failed to read assets: {e}")

def send_alert(message):
    # Implement your alerting logic
    print(f"ALERT: {message}")
```

## API Examples

### REST API Wrapper

```python
from flask import Flask, jsonify
import json
import os

app = Flask(__name__)

@app.route('/api/assets')
def get_assets():
    try:
        with open('assets.json', 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except:
        return jsonify({'error': 'Assets not available'}), 503

@app.route('/api/assets/<ip>')
def get_asset(ip):
    try:
        with open('assets.json', 'r') as f:
            data = json.load(f)
        
        for asset in data['assets']:
            if asset['ip'] == ip:
                return jsonify(asset)
        
        return jsonify({'error': 'Asset not found'}), 404
    except:
        return jsonify({'error': 'Assets not available'}), 503

@app.route('/api/status')
def get_status():
    return jsonify({
        'daemon_running': os.system('pgrep -f asset-daemon') == 0,
        'assets_file_exists': os.path.exists('assets.json'),
        'last_modified': os.path.getmtime('assets.json') if os.path.exists('assets.json') else None
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### WebSocket Integration

```javascript
// Real-time asset updates
const fs = require('fs');
const WebSocket = require('ws');

const wss = new WebSocket.Server({ port: 8080 });

fs.watchFile('assets.json', (curr, prev) => {
    const data = fs.readFileSync('assets.json', 'utf8');
    const assets = JSON.parse(data);
    
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
                type: 'assets_update',
                data: assets
            }));
        }
    });
});
```

## Deployment

### Systemd Service

```ini
[Unit]
Description=Asset Management Service
After=network.target

[Service]
Type=simple
User=assetmanager
WorkingDirectory=/opt/assetmanager
ExecStart=/opt/assetmanager/asset-daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Docker Deployment

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o asset-daemon asset-daemon.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/asset-daemon .
COPY --from=builder /app/config.json .
COPY --from=builder /app/list.txt .
CMD ["./asset-daemon"]
```

## Troubleshooting

### Common Issues

1. **No assets found**: Check network interface and CIDR configuration
2. **Permission denied**: Run with appropriate network privileges
3. **High CPU usage**: Increase scan intervals or reduce worker counts
4. **Missing vendor info**: Ensure MAC addresses are being captured

### Debug Mode

```bash
# Enable verbose logging
go run asset-daemon.go -debug
```

## License

This software is provided as-is for internal use. Modify and distribute according to your organization's policies.

## Support

For integration questions or issues, check the generated log files and configuration settings. The service is designed to be self-contained and require minimal maintenance. 