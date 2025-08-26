package network

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"
	"golang.org/x/crypto/ssh"
)

// CredentialPair represents a username/password combination
type CredentialPair struct {
	Username string
	Password string
}

// CredentialResult represents the result of a credential test
type CredentialResult struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Service     string `json:"service"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Successful  bool   `json:"successful"`
	TestTime    string `json:"test_time"`
	ErrorMsg    string `json:"error_msg,omitempty"`
}

// CredentialChecker handles default credential testing
type CredentialChecker struct {
	credentials []CredentialPair
	workers     int
	timeout     time.Duration
}

// NewCredentialChecker creates a new credential checker instance
func NewCredentialChecker(credentialsFile string, workers int, timeout time.Duration) (*CredentialChecker, error) {
	creds, err := loadCredentials(credentialsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials: %v", err)
	}

	return &CredentialChecker{
		credentials: creds,
		workers:     workers,
		timeout:     timeout,
	}, nil
}

// loadCredentials reads credentials from file
func loadCredentials(filename string) ([]CredentialPair, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var credentials []CredentialPair
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.Split(line, ":")
		if len(parts) >= 2 {
			username := parts[0]
			password := strings.Join(parts[1:], ":") // Handle passwords with colons
			credentials = append(credentials, CredentialPair{
				Username: username,
				Password: password,
			})
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	
	return credentials, nil
}

// TestCredentials tests default credentials for multiple assets
func (cc *CredentialChecker) TestCredentials(assets []Asset) []CredentialResult {
	var results []CredentialResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Create work channel
	jobs := make(chan Asset, len(assets))
	
	// Start workers
	for i := 0; i < cc.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for asset := range jobs {
				assetResults := cc.testAssetCredentials(asset)
				mu.Lock()
				results = append(results, assetResults...)
				mu.Unlock()
			}
		}()
	}
	
	// Send jobs
	for _, asset := range assets {
		jobs <- asset
	}
	close(jobs)
	
	// Wait for completion
	wg.Wait()
	
	return results
}

// testAssetCredentials tests credentials for a single asset
func (cc *CredentialChecker) testAssetCredentials(asset Asset) []CredentialResult {
	var results []CredentialResult
	
	// Test each open port that supports authentication
	for _, port := range asset.Ports {
		if port.State != "open" {
			continue
		}
		
		service := cc.identifyService(port.Port)
		if service == "" {
			continue
		}
		
		log.Printf("Testing %s credentials for %s:%d (%s)", service, asset.IP, port.Port, service)
		
		for _, cred := range cc.credentials {
			result := cc.testSingleCredential(asset.IP, port.Port, service, cred)
			
			// Only save successful results to avoid bloating the output
			if result.Successful {
				results = append(results, result)
				log.Printf("SUCCESS: %s:%d - %s/%s", asset.IP, port.Port, cred.Username, cred.Password)
			}
		}
	}
	
	return results
}

// identifyService identifies the service type based on port number
func (cc *CredentialChecker) identifyService(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 80, 8080, 8081, 8000:
		return "http"
	case 443, 8443:
		return "https"
	case 3389:
		return "rdp"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 1433:
		return "mssql"
	case 5985, 5986:
		return "winrm"
	case 6379:
		return "redis"
	default:
		return ""
	}
}

// testSingleCredential tests a single credential combination
func (cc *CredentialChecker) testSingleCredential(host string, port int, service string, cred CredentialPair) CredentialResult {
	result := CredentialResult{
		Host:     host,
		Port:     port,
		Service:  service,
		Username: cred.Username,
		Password: cred.Password,
		TestTime: time.Now().Format("2006-01-02 15:04:05"),
	}
	
	switch service {
	case "ssh":
		result.Successful, result.ErrorMsg = cc.testSSH(host, port, cred)
	case "ftp":
		result.Successful, result.ErrorMsg = cc.testFTP(host, port, cred)
	case "http", "https":
		result.Successful, result.ErrorMsg = cc.testHTTP(host, port, service, cred)
	case "redis":
		result.Successful, result.ErrorMsg = cc.testRedis(host, port, cred)
	case "rdp":
		result.Successful, result.ErrorMsg = cc.testRDP(host, port, cred)
	default:
		result.ErrorMsg = "unsupported service"
	}
	
	return result
}

// testSSH tests SSH credentials
func (cc *CredentialChecker) testSSH(host string, port int, cred CredentialPair) (bool, string) {
	config := &ssh.ClientConfig{
		User: cred.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(cred.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         cc.timeout,
	}
	
	address := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return false, err.Error()
	}
	defer client.Close()
	
	return true, ""
}

// testFTP tests FTP credentials
func (cc *CredentialChecker) testFTP(host string, port int, cred CredentialPair) (bool, string) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	c, err := ftp.Dial(address, ftp.DialWithTimeout(cc.timeout))
	if err != nil {
		return false, err.Error()
	}
	defer c.Quit()
	
	err = c.Login(cred.Username, cred.Password)
	if err != nil {
		return false, err.Error()
	}
	
	return true, ""
}

// testHTTP tests HTTP basic auth or form-based authentication
func (cc *CredentialChecker) testHTTP(host string, port int, service string, cred CredentialPair) (bool, string) {
	protocol := "http"
	if service == "https" {
		protocol = "https"
	}
	
	url := fmt.Sprintf("%s://%s:%d", protocol, host, port)
	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: cc.timeout,
	}
	
	// Try basic auth first
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err.Error()
	}
	
	req.SetBasicAuth(cred.Username, cred.Password)
	
	resp, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	
	// Check if authentication was successful
	if resp.StatusCode == http.StatusOK {
		return true, ""
	}
	
	return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
}

// testRedis tests Redis credentials
func (cc *CredentialChecker) testRedis(host string, port int, cred CredentialPair) (bool, string) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	
	// Connect to Redis
	conn, err := net.DialTimeout("tcp", address, cc.timeout)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()
	
	// Set connection deadline
	conn.SetDeadline(time.Now().Add(cc.timeout))
	
	// Try AUTH command if password is provided
	if cred.Password != "" {
		authCmd := fmt.Sprintf("AUTH %s\r\n", cred.Password)
		_, err = conn.Write([]byte(authCmd))
		if err != nil {
			return false, err.Error()
		}
		
		// Read response
		response := make([]byte, 1024)
		n, err := conn.Read(response)
		if err != nil {
			return false, err.Error()
		}
		
		responseStr := string(response[:n])
		if strings.Contains(responseStr, "+OK") {
			return true, ""
		} else if strings.Contains(responseStr, "-ERR") {
			return false, "authentication failed"
		}
	}

	


	// TODO: DataBase Default Credentials Test






	// Test PING command to verify connection
	pingCmd := "PING\r\n"
	_, err = conn.Write([]byte(pingCmd))
	if err != nil {
		return false, err.Error()
	}
	
	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return false, err.Error()
	}
	
	responseStr := string(response[:n])
	if strings.Contains(responseStr, "+PONG") {
		return true, ""
	}
	
	return false, "ping failed"
}

// testRDP tests RDP credentials using basic TCP connection test
func (cc *CredentialChecker) testRDP(host string, port int, cred CredentialPair) (bool, string) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	
	// Try to establish TCP connection to RDP port
	conn, err := net.DialTimeout("tcp", address, cc.timeout)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()
	
	conn.SetDeadline(time.Now().Add(cc.timeout))
	
	rdpHandshake := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00,
		0x00, 0x00, 0x00,
	}
	
	_, err = conn.Write(rdpHandshake)
	if err != nil {
		return false, err.Error()
	}
	
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return false, err.Error()
	}
	
	if n > 4 && response[0] == 0x03 && response[1] == 0x00 {
		return true, "RDP service detected (credential testing requires full RDP protocol implementation)"
	}
	
	return false, "not an RDP service or connection failed"
}
