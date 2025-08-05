# Asset Management API

This API provides endpoints to access and manage discovered network assets.

## Getting Started

### Build and Run the API Server

```bash
# Build the server
go build -o bin/api-server cmd/server/main.go

# Run the server
./bin/api-server
```

The server will start on port 8080.

## Endpoints

### Health Check
- **URL**: `/health`
- **Method**: `GET`
- **Description**: Check if the API server is running
- **Response**: 
```json
{
  "service": "asset-management-api",
  "status": "healthy"
}
```

### Get Assets
- **URL**: `/api/v1/assets` or `/api/v1/getAssets`
- **Method**: `GET`
- **Description**: Retrieve all discovered network assets from assets.json
- **Response**: 
```json
{
  "success": true,
  "data": {
    "timestamp": "2025-07-18 09:38:23",
    "total_hosts": 0,
    "scan_time": "15.9785ms",
    "local_network": "",
    "file_targets": 0,
    "assets": [
      {
        "ip": "192.168.1.1",
        "mac": "aa:bb:cc:dd:ee:ff",
        "vendor": "Cisco Systems",
        "open_ports": [
          {
            "port": 22,
            "service": "ssh",
            "banner": "OpenSSH 7.4"
          }
        ],
        "last_seen": "2025-07-18T09:38:23Z",
        "first_seen": "2025-07-18T09:38:23Z",
        "hostname": "router.local",
        "arp_response": true
      }
    ]
  },
  "response_timestamp": "2025-08-05 15:43:11"
}
```

### Error Response Format
When an error occurs, the API returns:
```json
{
  "success": false,
  "message": "Error description",
  "response_timestamp": "2025-08-05 15:43:11"
}
```

## Examples

### Using curl

```bash
# Get all assets
curl -X GET "http://localhost:8080/api/v1/getAssets"

# Health check
curl -X GET "http://localhost:8080/health"
```

### Using JavaScript/Fetch

```javascript
// Get assets
fetch('http://localhost:8080/api/v1/getAssets')
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      console.log('Assets:', data.data.assets);
    } else {
      console.error('Error:', data.message);
    }
  });
```

## CORS Support

The API includes CORS headers to allow cross-origin requests from web applications.

## Features

- ✅ JSON response format
- ✅ Error handling
- ✅ CORS support
- ✅ Health check endpoint
- ✅ Structured logging
- ✅ Asset data validation

## Next Steps

You can extend this API by adding:
- Asset filtering (by IP, MAC, vendor, etc.)
- Asset search functionality
- Real-time asset scanning triggers
- Authentication/Authorization
- Rate limiting
- Asset modification endpoints (POST, PUT, DELETE)
