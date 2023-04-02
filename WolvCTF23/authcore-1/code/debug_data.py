import binascii 
debug_d = "64 84 B0 59 1E 6B 24 6D CC 6E 29 B7 DD 5E 08 B5 26 68 F5 09 68 08 51 0B BC 0D 5D 85 82 79 67 E2 44 BA 87 74 1F 6B 25 6D C7 6E 29 F7 DD 1E 08 BD 26 C8 F5 09 1F 6B 25 6D C7 6E 29 F7 DD 1E 08 BD 26 C8 F5 09 50 38 70 40 88 3A 79 D7 F5 68 39 93 17 E1 F5 09 1F 6B 25 6D C7 6E 29 F7 DD 1E 08 BD 26 C8 F5 09 E0 DC 0E EA" 

debug_d = debug_d.replace(" ", '')
ciphertext = binascii.unhexlify(debug_d)

def xor_encrypt(key: bytes, data: bytes) -> bytes:
    return bytes([key[i % len(key)] ^ data[i] for i in range(len(data))])

# Known header from RE:
# 0x0: uint32_t magic
# 0x4: uint16_t major_version
# 0x6: uint16_t minor_version
# 0x8: uint16_t flags 
# 0xc: uint16_t addr 
# 0x10: uint32_t size 
# 0x14: uint8_t[16] key
MAGIC = b'BLEP'
MAJOR = b'\x01\x00'
MINOR = b'\x01\x00'
ADDR = b'\x00\x40\x00\x08'
header = b''
header += MAGIC 
header += MAJOR 
header += MINOR
header += b'\x0b' + b'\x00'*2 + b'\x40'
header += ADDR

# The enc algorithm looks like a CTR stream cipher with a nonce 
fixed_xor = ciphertext[:16]
key_slice = xor_encrypt(header, fixed_xor) 
plaintext = xor_encrypt(key_slice, ciphertext)
print(plaintext)
