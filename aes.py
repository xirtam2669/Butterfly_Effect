from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import os
import sys

def to_csharp_byte_array(data):
    return ', '.join(f'0x{byte:02x}' for byte in data)

shellcode_file = sys.argv[1]
with open(shellcode_file, "rb") as f:
    shellcode = f.read()

# AES key
key = b'1234567890123456'  # 16-byte key for AES-128

# AES Initialization Vector (IV) - must be 16 bytes long for AES-128
iv = b'1234567890123456'  # Static IV

# Create AES cipher in CBC mode
cipher = AES.new(key, AES.MODE_CBC, iv)

#Pad shellcode
padded_shellcode = pad(shellcode, AES.block_size)

# Encrypt the padded shellcode
encrypted_shellcode = cipher.encrypt(padded_shellcode)

#Uncomment if you'd plan to change key/IV, as you'll need this to update butterflyeffect
#print("byte[] key = new byte[] { " + csharp_byte_array_key + " };")
#print("byte[] iv = new byte[] { " + csharp_byte_array_iv + " };")

with open("cipher.bin", "wb") as f:
    f.write(encrypted_shellcode)

print("Encrypted shellcode has been written to file: cipher.bin")

