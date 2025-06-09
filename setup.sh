#!/bin/bash

echo "Asset Management Service Setup"
echo "=============================="

if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go 1.19 or later."
    exit 1
fi

echo "Building dependencies..."
go mod tidy

echo "Testing configuration..."
if [ ! -f "config.json" ]; then
    echo "Creating default configuration..."
    go run main.go <<< "3"
fi

echo "Testing daemon functionality..."
go run test-daemon.go

echo ""
echo "Setup complete!"
echo ""
echo "To start the service:"
echo "  go run asset-daemon.go"
echo ""
echo "To view web interface:"
echo "  php -S localhost:8080 assets-ui.php"
echo ""
echo "Configuration files:"
echo "  config.json - Service configuration"
echo "  list.txt    - Target IP blocks"
echo ""
echo "Output:"
echo "  assets.json - Discovered assets (JSON format)" 