package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
	"github.com/jlaffaye/ftp"
	"golang.org/x/crypto/ssh"
)

type DefaultCredentialEnabled struct {
	Host    string
	Port    int
	Service string
	User    string
}

var userNameList []string = []string{
	"admin",
	"administrator",
	"root",
	"guest",
	"test",
	"support",
	"miri",
	"anonymous",
}

func main() {
	GetFields("http://10.1.1.29:8080")
}

func CheckForSsh(list []string) DefaultCredentialEnabled {
	var myDefaultOlanSey DefaultCredentialEnabled
	for _, user := range list {
		_, err := ssh.Dial("tcp", "10.1.1.29:22", &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password("1"),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		})
		fmt.Println(err)
		if err == nil {
			myDefaultOlanSey = DefaultCredentialEnabled{Host: "10.1.1.29", Port: 22, Service: "ssh", User: user}
		}
	}
	return myDefaultOlanSey
}

func CheckForFtp(list []string) DefaultCredentialEnabled {
	var myDefaultOlanSey DefaultCredentialEnabled

	for _, user := range list {
		c, err := ftp.Dial("10.1.1.29:21", ftp.DialWithTimeout(1*time.Second))

		if err != nil {
			log.Fatal(err)
		}
		err = c.Login(user, "1")
		if err == nil {
			myDefaultOlanSey = DefaultCredentialEnabled{Host: "10.1.1.29", Port: 21, Service: "FTP", User: user}
		}
		fmt.Println(err)
	}
	return myDefaultOlanSey
}

func TakeScreenShot(url string) {

	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	var buf []byte
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second),
		chromedp.CaptureScreenshot(&buf),
	); err != nil {
		fmt.Println(err)
		return
	}
	if err := os.WriteFile("screenshot.png", buf, 0644); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("SS aldim")
	}
}

func GetFields(url string) {

	var username string
	var password string
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Failed to fetch URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Unexpected status code: %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Fatalf("Failed to parse HTML: %v", err)
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		fmt.Printf("Input Element %d:\n", i+1)

		id, _ := s.Attr("id")
		name, _ := s.Attr("name")

		inputType, _ := s.Attr("type")
		value, _ := s.Attr("value")

		fmt.Printf("  ID: %s\n", id)
		fmt.Printf("  Name: %s\n", name)
		fmt.Printf("  Type: %s\n", inputType)
		fmt.Printf("  Value: %s\n", value)

		s.Each(func(_ int, s *goquery.Selection) {
			for _, attr := range s.Nodes[0].Attr {
				fmt.Printf("  %s: %s\n", attr.Key, attr.Val)
			}
		})
		fmt.Println("---")
	})
}
