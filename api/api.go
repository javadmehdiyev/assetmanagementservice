package api

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"assetmanager/pkg/network"

	"github.com/gin-gonic/gin"
)

// AssetResult represents the structure of the assets.json file
type AssetResult struct {
	Timestamp   string          `json:"timestamp"`
	TotalHosts  int             `json:"total_hosts"`
	ScanTime    string          `json:"scan_time"`
	LocalNet    string          `json:"local_network"`
	FileTargets int             `json:"file_targets"`
	Assets      []network.Asset `json:"assets"`
}

// GetAssetsResponse represents the API response format
type GetAssetsResponse struct {
	Success     bool         `json:"success"`
	Message     string       `json:"message,omitempty"`
	Data        *AssetResult `json:"data,omitempty"`
	AssetsCount int          `json:"assets_count"`
	HasAssets   bool         `json:"has_assets"`
	Timestamp   string       `json:"response_timestamp"`
}

func HandleHome(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Asset Management API",
		"version": "1.0.0",
		"endpoints": []string{
			"GET /assets - Get all discovered assets",
		},
	})
}

// GetAssets handles the /getAssets endpoint
func GetAssets(c *gin.Context) {
	// Read the assets.json file
	data, err := os.ReadFile("assets.json")
	if err != nil {
		c.JSON(http.StatusInternalServerError, GetAssetsResponse{
			Success:     false,
			Message:     "Failed to read assets file: " + err.Error(),
			AssetsCount: 0,
			HasAssets:   false,
			Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
		})
		return
	}

	// Parse the JSON data
	var assetResult AssetResult
	if err := json.Unmarshal(data, &assetResult); err != nil {
		c.JSON(http.StatusInternalServerError, GetAssetsResponse{
			Success:     false,
			Message:     "Failed to parse assets data: " + err.Error(),
			AssetsCount: 0,
			HasAssets:   false,
			Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
		})
		return
	}

	// Handle null assets case - initialize empty slice if assets is null
	if assetResult.Assets == nil {
		assetResult.Assets = []network.Asset{}
	}

	// Determine if we have assets and get count
	assetsCount := len(assetResult.Assets)
	hasAssets := assetsCount > 0

	// Prepare response message based on assets availability
	var message string
	if !hasAssets {
		if assetResult.TotalHosts == 0 {
			message = "No assets have been discovered yet. Run asset discovery scan to populate data."
		} else {
			message = "Asset scan completed but no active hosts found."
		}
	} else {
		message = "Assets retrieved successfully."
	}

	// Return successful response with asset information
	c.JSON(http.StatusOK, GetAssetsResponse{
		Success:     true,
		Message:     message,
		Data:        &assetResult,
		AssetsCount: assetsCount,
		HasAssets:   hasAssets,
		Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
	})
}
