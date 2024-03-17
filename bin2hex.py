import binascii
import sys

def bin_to_hex(bin_file_path, hex_file_path):
    try:
        # Read binary shellcode from file
        with open(bin_file_path, 'rb') as bin_file:
            bin_shellcode = bin_file.read()

        # Convert binary shellcode to hexadecimal
        hex_shellcode = binascii.hexlify(bin_shellcode).decode('utf-8')

        # Write hexadecimal shellcode to file
        with open(hex_file_path, 'w') as hex_file:
            hex_file.write(hex_shellcode)

        print("Binary shellcode converted to hexadecimal and saved to", hex_file_path)
    except Exception as e:
        print("Error:", str(e))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script_name.py <binary_shellcode_file> <hex_output_file>")
    else:
        bin_file_path = sys.argv[1]
        hex_file_path = sys.argv[2]
        bin_to_hex(bin_file_path, hex_file_path)

