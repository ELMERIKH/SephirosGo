package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	// X Packages
	"golang.org/x/crypto/argon2"

	// 3rd Party
	"github.com/fatih/color"
)

func writeToFile(filename string, data []byte) {
	err := ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Println("[!]Error writing to file:", err)
		os.Exit(1)
	}
}


func main() {
	verbose := flag.Bool("v", false, "Enable verbose output")
	encryptionType := flag.String("type", "", "The type of encryption to use [xor, aes256, rc4, null]")
	key := flag.String("key", "", "Encryption key")
	b64 := flag.Bool("base64", false, "Base64 encode the output. Can be used with or without encryption")
	input := flag.String("i", "", "Input file path of binary file")
	output := flag.String("o", "", "Output file path")
	mode := flag.String("mode", "encrypt", "Mode of operation to perform on the input file [encrypt,decrypt]")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	// Check to make sure the input file exists
	_, errInputFile := os.Stat(*input)

	if os.IsNotExist(errInputFile) {
		color.Red(fmt.Sprintf("[!]The file does not exist: %s", *input))
		os.Exit(1)
	}

	shellcode, errShellcode := ioutil.ReadFile(*input)

	if errShellcode != nil {
		color.Red(fmt.Sprintf("[!]%s", errShellcode.Error()))
		os.Exit(1)
	}

	// Check to make sure an output file was provided
	if *output == "" {
		color.Red("[!]The -o output argument is required")
		os.Exit(1)
	}

	// Check to make sure the output directory exists
	dir, outFile := filepath.Split(*output)
	if *verbose {
		color.Yellow(fmt.Sprintf("[-]Output directory: %s", dir))
		color.Yellow(fmt.Sprintf("[-]Output file name: %s", outFile))
	}

	outDir, errOutDir := os.Stat(dir)
	if errOutDir != nil {
		color.Red(fmt.Sprintf("[!]%s", errOutDir.Error()))
		os.Exit(1)
	}

	if !outDir.IsDir() {
		color.Red(fmt.Sprintf("[!]The output directory does not exist: %s", dir))
	}

	if *verbose {
		color.Yellow(fmt.Sprintf("[-]File contents (hex): %x", shellcode))
	}

	if strings.ToUpper(*mode) != "ENCRYPT" && strings.ToUpper(*mode) != "DECRYPT" {
		color.Red("[!]Invalid mode provided. Must be either encrypt or decrypt")
		os.Exit(1)
	}

	// Make sure a key was provided
	

	var outputBytes []byte

	switch strings.ToUpper(*mode) {
	case "ENCRYPT":
		var encryptedBytes []byte
		switch strings.ToUpper(*encryptionType) {
		case "XOR":
			// https://kylewbanks.com/blog/xor-encryption-using-go
			if *verbose {
				color.Yellow(fmt.Sprintf("[-]XOR encrypting input file with key: %s", *key))
			}
			encryptedBytes = make([]byte, len(shellcode))
			
			tempKey := *key
			for k, v := range shellcode {
				encryptedBytes[k] = v ^ tempKey[k%len(tempKey)]
			}
			keyFile := "key.bin"
			writeToFile(keyFile, []byte(*key))
			
		case "AES256":
			
			if *verbose {
				color.Yellow("[-]AES256 encrypting input file")
			}

			// Generate a salt that is used to generate a 32 byte key with Argon2
			salt := make([]byte, 32)
			_, errReadFull := io.ReadFull(rand.Reader, salt)
			if errReadFull != nil {
				color.Red(fmt.Sprintf("[!]%s", errReadFull.Error()))
				os.Exit(1)
			}
			color.Green(fmt.Sprintf("[+]Argon2 salt (hex): %x", salt))

			// Generate Argon2 ID key from input password using a randomly generated salt
			aesKey := argon2.IDKey([]byte(*key), salt, 1, 64*1024, 4, 32)
			// I leave it up to the operator to use the password + salt for decryption or just the Argon2 key
			color.Green(fmt.Sprintf("[+]AES256 key (32-bytes) derived from input password %s (hex): %x", *key, aesKey))

			// Generate AES Cipher Block
			cipherBlock, err := aes.NewCipher(aesKey)
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", err.Error()))
			}
			gcm, errGcm := cipher.NewGCM(cipherBlock)
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", errGcm.Error()))
				os.Exit(1)
			}

			// Generate a nonce (or IV) for use with the AES256 function
			nonce := make([]byte, gcm.NonceSize())
			_, errNonce := io.ReadFull(rand.Reader, nonce)
			if errNonce != nil {
				color.Red(fmt.Sprintf("[!]%s", errNonce.Error()))
				os.Exit(1)
			}

			color.Green(fmt.Sprintf("[+]AES256 nonce (hex): %x", nonce))
			passwordBase64 := base64.StdEncoding.EncodeToString([]byte(*key))

			encryptedBytes = gcm.Seal(nil, nonce, shellcode, nil)
			keyData := append(aesKey, salt...)
			keyData = append(keyData, nonce...)
			keyData = append(keyData, []byte(passwordBase64)...)

			hexKeyData := hex.EncodeToString(keyData)
			writeToFile("key.bin", []byte(hexKeyData))
			fmt.Println("pass:", passwordBase64)
			// Write encrypted data to output file
			
			
		case "RC4":
			if *verbose {
				color.Yellow("[-]RC4 encrypting input file")
			}
			cipher, err := rc4.NewCipher([]byte(*key))
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", err.Error()))
				os.Exit(1)
			}
			encryptedBytes = make([]byte, len(shellcode))
			cipher.XORKeyStream(encryptedBytes, shellcode)
			keyFile := "key.bin"
			writeToFile(keyFile, []byte(*key))
		case "":
			if *verbose {
				color.Yellow("[-]No encryption type provided, continuing on...")
			}
			encryptedBytes = append(encryptedBytes, shellcode...)
		default:
			color.Red(fmt.Sprintf("[!]Invalid method type: %s", *encryptionType))
			os.Exit(1)
		}

		if len(encryptedBytes) <= 0 {
			color.Red("[!]Encrypted byte slice length is equal to or less than 0")
			os.Exit(1)
		}
		if *b64 {
			outputBytes = make([]byte, base64.StdEncoding.EncodedLen(len(encryptedBytes)))
			base64.StdEncoding.Encode(outputBytes, encryptedBytes)
		} else {
			outputBytes = append(outputBytes, encryptedBytes...)
		}
	case "DECRYPT":
		var decryptedBytes []byte
		switch strings.ToUpper(*encryptionType) {
		case "AES256":
			// Read key data from file
			keyData, err := ioutil.ReadFile("key.bin")
			if err != nil {
				fmt.Printf("[!]Error reading key.bin: %s\n", err.Error())
				os.Exit(1)
			}

			decodedKeyData:= string(keyData)
			fmt.Println("Contents of key.bin:", decodedKeyData)
			

    // Print the decoded password
    

			Key := decodedKeyData[:64]
			salt := decodedKeyData[64:128] // Corrected indices for salt
			nonce := decodedKeyData[128:152]
			ps :=decodedKeyData[152:]
			bytes, err := hex.DecodeString(string(ps))
			if err != nil {
				fmt.Println("Error decoding hex string:", err)
				return
			}
			pass64 := string(bytes)
			pay , err:= base64.StdEncoding.DecodeString(pass64)
			if err != nil {
				fmt.Println("Error decoding hex string:", err)
				return
			}
			pass := string(pay)
			fmt.Println("Key:", Key)
			fmt.Println("Salt:", salt)
			fmt.Println("Nonce:", nonce)
			fmt.Println("Decoded Password:", pass)
			if *verbose {
				color.Yellow("[-]AES256 decrypting input file")
			}
			
			
			if len(salt) != 64 {
				color.Red("[!]A 32-byte salt in hex format must be provided with the -salt argument to decrypt AES256 input file")
				color.Red(fmt.Sprintf("[!]A %d byte salt was provided", len(salt)/2))
				os.Exit(1)
			}

			saltDecoded, errSaltDecoded := hex.DecodeString(string(salt))
			if errShellcode != nil {
				color.Red(fmt.Sprintf("[!]%s", errSaltDecoded.Error()))
				os.Exit(1)
			}
			if *verbose {
				color.Yellow("[-]Argon2 salt (hex): %x", saltDecoded)
			}
			
			aesKey := argon2.IDKey([]byte(pass), saltDecoded, 1, 64*1024, 4, 32)
			if *verbose {
				color.Yellow("[-]AES256 key (hex): %x", aesKey)
			}

			cipherBlock, err := aes.NewCipher(aesKey)
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", err.Error()))
			}

			gcm, errGcm := cipher.NewGCM(cipherBlock)
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", errGcm.Error()))
				os.Exit(1)
			}

			if len(shellcode) < gcm.NonceSize() {
				color.Red("[!]Malformed ciphertext is larger than nonce")
				os.Exit(1)
			}

			if len(nonce) != gcm.NonceSize()*2 {
				color.Red("[!]A nonce, in hex, must be provided with the -nonce argument to decrypt the AES256 input file")
				color.Red(fmt.Sprintf("[!]A %d byte nonce was provided but %d byte nonce was expected", len(nonce)/2, gcm.NonceSize()))
				os.Exit(1)
			}
			decryptNonce, errDecryptNonce := hex.DecodeString(string(nonce))
			if errDecryptNonce != nil {
				color.Red("[!]%s", errDecryptNonce.Error())
				os.Exit(1)
			}
			if *verbose {
				color.Yellow(fmt.Sprintf("[-]AES256 nonce (hex): %x", decryptNonce))
			}

			var errDecryptedBytes error
			decryptedBytes, errDecryptedBytes = gcm.Open(nil, decryptNonce, shellcode, nil)
			if errDecryptedBytes != nil {
				color.Red("[!]%s", errDecryptedBytes.Error())
				os.Exit(1)
			}
		case "XOR":
			keyFromFile, err := ioutil.ReadFile("key.bin")
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", err.Error()))
				os.Exit(1)
			}

			// Use the key obtained from the key.bin file for decryption
			tempKey := string(keyFromFile)
			
			decryptedBytes = make([]byte, len(shellcode))
			
			for k, v := range shellcode {
				decryptedBytes[k] = v ^ tempKey[k%len(tempKey)]
			}
		case "RC4":
			keyFromFile, err := ioutil.ReadFile("key.bin")
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", err.Error()))
				os.Exit(1)
			}
			tempKey := string(keyFromFile)
			if *verbose {
				color.Yellow("[-]RC4 decrypting input file")
			}
			cipher, err := rc4.NewCipher([]byte(tempKey))
			if err != nil {
				color.Red(fmt.Sprintf("[!]%s", err.Error()))
				os.Exit(1)
			}
			decryptedBytes = make([]byte, len(shellcode))
			cipher.XORKeyStream(decryptedBytes, shellcode)
		default:
			color.Red("[!]Invalid method")
			os.Exit(1)
		}
		if len(decryptedBytes) <= 0 {
			color.Red("[!]Decrypted byte slice length is equal to or less than 0")
			os.Exit(1)
		}
		if *b64 {
			outputBytes = make([]byte, base64.StdEncoding.EncodedLen(len(decryptedBytes)))
			base64.StdEncoding.Encode(outputBytes, decryptedBytes)
		} else {
			outputBytes = append(outputBytes, decryptedBytes...)
		}
	}

	if *verbose {
		if *b64 {
			color.Green("[+]Output (string):\r\n")
			fmt.Println(fmt.Sprintf("%s", outputBytes))
		} else {
			color.Green("[+]Output (hex):\r\n")
			fmt.Println(fmt.Sprintf("%x", outputBytes))
		}
	}

	// Write the file
	err := ioutil.WriteFile(*output, outputBytes, 0660)
	if err != nil {
		color.Red(fmt.Sprintf("[!]%s", err.Error()))
		os.Exit(1)
	}
	color.Green(fmt.Sprintf("[+]%s %s input and wrote %d bytes to: %s", *encryptionType, *mode, len(outputBytes), *output))

}