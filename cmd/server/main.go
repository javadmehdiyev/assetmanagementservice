package main

import (
	"log"
	"net/http"

	"assetmanager/api"

	"github.com/gin-gonic/gin"
)

func main() {
	// Create Gin router
	r := gin.Default()

	// Enable CORS middleware
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// API routes
	v1 := r.Group("/api/v1")
	{
		v1.GET("/", api.HandleHome)
		v1.GET("/assets", api.GetAssets)
		v1.GET("/getAssets", api.GetAssets) // Alternative endpoint name
	}

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "asset-management-api",
		})
	})

	// Start server
	log.Println("Starting Asset Management API server on :8080")
	log.Println("Available endpoints:")
	log.Println("  GET /api/v1/assets - Get all discovered assets")
	log.Println("  GET /api/v1/getAssets - Get all discovered assets (alternative)")
	log.Println("  GET /health - Health check")

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
