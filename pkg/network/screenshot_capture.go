package network

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// ScreenshotResult represents the result of a screenshot capture
type ScreenshotResult struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	URL         string `json:"url"`
	FilePath    string `json:"file_path"`
	Success     bool   `json:"success"`
	ErrorMsg    string `json:"error_msg,omitempty"`
	CaptureTime string `json:"capture_time"`
	FileSize    int64  `json:"file_size,omitempty"`
}

// ScreenshotCapture handles web service screenshot capturing
type ScreenshotCapture struct {
	outputDir     string
	timeout       time.Duration
	workers       int
	headless      bool
	windowWidth   int
	windowHeight  int
}

// NewScreenshotCapture creates a new screenshot capture instance
func NewScreenshotCapture(outputDir string, timeout time.Duration, workers int) *ScreenshotCapture {
	return &ScreenshotCapture{
		outputDir:    outputDir,
		timeout:      timeout,
		workers:      workers,
		headless:     true,
		windowWidth:  1920,
		windowHeight: 1080,
	}
}

// CaptureScreenshots captures screenshots for multiple assets with HTTP services
func (sc *ScreenshotCapture) CaptureScreenshots(assets []Asset) []ScreenshotResult {
	var results []ScreenshotResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Create work channel for HTTP services
	jobs := make(chan ScreenshotJob, 100)
	
	// Start workers
	for i := 0; i < sc.workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for job := range jobs {
				result := sc.captureScreenshot(job)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				
				if result.Success {
					log.Printf("Worker %d: Screenshot captured for %s - %s", workerID, result.URL, result.FilePath)
				} else {
					log.Printf("Worker %d: Screenshot failed for %s - %s", workerID, result.URL, result.ErrorMsg)
				}
			}
		}(i)
	}
	
	// Send jobs for HTTP services
	for _, asset := range assets {
		for _, port := range asset.OpenPorts {
			if sc.isHTTPService(port.Port) {
				jobs <- ScreenshotJob{
					Host: asset.IP,
					Port: port.Port,
				}
			}
		}
	}
	close(jobs)
	
	// Wait for completion
	wg.Wait()
	
	return results
}

// ScreenshotJob represents a screenshot job
type ScreenshotJob struct {
	Host string
	Port int
}

// isHTTPService checks if a port typically runs HTTP services
func (sc *ScreenshotCapture) isHTTPService(port int) bool {
	httpPorts := []int{80, 443, 8080, 8443, 8000, 8001, 8008, 8888, 9000, 9090, 3000, 5000}
	for _, p := range httpPorts {
		if port == p {
			return true
		}
	}
	return false
}

// captureScreenshot captures a screenshot for a single HTTP service
func (sc *ScreenshotCapture) captureScreenshot(job ScreenshotJob) ScreenshotResult {
	result := ScreenshotResult{
		Host:        job.Host,
		Port:        job.Port,
		CaptureTime: time.Now().Format("2006-01-02 15:04:05"),
	}
	
	// Try both HTTP and HTTPS
	protocols := []string{"http", "https"}
	if job.Port == 443 || job.Port == 8443 {
		protocols = []string{"https", "http"} // Try HTTPS first for SSL ports
	}
	
	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s:%d", protocol, job.Host, job.Port)
		result.URL = url
		
		success, filePath, fileSize, errMsg := sc.takeScreenshot(url, job.Host, job.Port)
		if success {
			result.Success = true
			result.FilePath = filePath
			result.FileSize = fileSize
			return result
		}
		
		result.ErrorMsg = errMsg
	}
	
	return result
}

// takeScreenshot captures a screenshot of a web page
func (sc *ScreenshotCapture) takeScreenshot(url, host string, port int) (bool, string, int64, string) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), sc.timeout)
	defer cancel()
	
	// Setup Chrome options
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", sc.headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.WindowSize(sc.windowWidth, sc.windowHeight),
	)
	
	allocCtx, cancel2 := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel2()
	
	// Create Chrome context
	chromeCtx, cancel3 := chromedp.NewContext(allocCtx)
	defer cancel3()
	
	// Generate filename
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%d_%s.png", host, port, timestamp)
	filePath := filepath.Join(sc.outputDir, filename)
	
	// Capture screenshot
	var buf []byte
	err := chromedp.Run(chromeCtx,
		chromedp.Navigate(url),
		chromedp.Sleep(3*time.Second), // Wait for page to load
		chromedp.CaptureScreenshot(&buf),
	)
	
	if err != nil {
		return false, "", 0, err.Error()
	}
	
	// Save screenshot
	err = os.WriteFile(filePath, buf, 0644)
	if err != nil {
		return false, "", 0, fmt.Sprintf("failed to save screenshot: %v", err)
	}
	
	// Get file size
	fileInfo, err := os.Stat(filePath)
	var fileSize int64
	if err == nil {
		fileSize = fileInfo.Size()
	}
	
	return true, filePath, fileSize, ""
}

// CaptureScreenshotSingle captures a screenshot for a single URL (utility function)
func (sc *ScreenshotCapture) CaptureScreenshotSingle(url string) ScreenshotResult {
	result := ScreenshotResult{
		URL:         url,
		CaptureTime: time.Now().Format("2006-01-02 15:04:05"),
	}
	
	// Extract host and port from URL for filename
	host := "unknown"
	port := 80
	
	success, filePath, fileSize, errMsg := sc.takeScreenshot(url, host, port)
	result.Success = success
	result.FilePath = filePath
	result.FileSize = fileSize
	result.ErrorMsg = errMsg
	
	return result
}
