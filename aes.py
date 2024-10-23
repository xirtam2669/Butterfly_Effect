from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import os
import sys

shellcode_file = sys.argv[1]
with open(shellcode_file, "rb") as f:
    shellcode = f.read()

key = b'1234567890123456'  # 16-byte key for AES-128

# AES Initialization Vector (IV) - must be 16 bytes long for AES
iv = b'1234567890123456'  # Static IV

key_raw = binascii.hexlify(key)
iv_raw = binascii.hexlify(iv)

# Create AES cipher in CBC mode
cipher = AES.new(key, AES.MODE_CBC, iv)

padded_shellcode = pad(shellcode, AES.block_size) #Make sure this actually works

# Encrypt the padded shellcode
encrypted_shellcode = cipher.encrypt(padded_shellcode)

# Convert encrypted shellcode to hexadecimal for display
encrypted_shellcode_hex = binascii.hexlify(encrypted_shellcode)

print(f"IV (Hex): {iv_raw}")
print(f"Key (Hex): {key_raw}")
print(f"Encrypted Shellcode (Hex): {encrypted_shellcode_hex.decode()}")
