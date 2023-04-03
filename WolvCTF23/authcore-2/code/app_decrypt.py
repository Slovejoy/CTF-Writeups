import unicorn as uni
# ARM registers 

ENC_KEY = b'wctf{ctr_go_brr}'
CIPHERTEXT = "parsed.bin"
BOOTLOADER = "bootloader_extracted.bin"

NONCE = 0x57435446   # 'WCTF' 
BOOT_BASEADDR = 0x08000000
ENC_FUNCADDR = 0x08000a82
ENC_FUNCADDR_END = 0x08000b2e 
CODE_FUNCADDR = 0x08000cac
CODE_FUNCADDR_END = 0x08000cc4
KEYMEM = 0xE0000000
# Working memory for decryption 
WMEM = 0x60000000 
# Anywhere is fine, so long as we don't blast other stuff
TEXT = 0xC00000000
STACK = 0xF0000000
SRAM_BASE   = 0x20000400
SRAM_BUFFER = 0x200004BB


uc = uni.Uc(uni.UC_ARCH_ARM, uni.UC_MODE_THUMB)
bootloader = open(BOOTLOADER, 'rb').read()

def init_uc():
    """
    Initialize the Unicorn instance memory.
    """
    # Map memory for binary
    # Must map multiple of 1024
    uc.mem_map(BOOT_BASEADDR, 0x2000)
    uc.mem_map(TEXT, 1024)
    uc.mem_map(KEYMEM, 1024)
    uc.mem_map(WMEM, 1024)
    uc.mem_map(STACK, 1024)
    uc.mem_map(SRAM_BASE, 0x800)
    uc.mem_write(KEYMEM, ENC_KEY)
    uc.mem_write(BOOT_BASEADDR, bootloader) 
    uc.reg_write(uni.arm_const.UC_ARM_REG_SP, STACK+1020)
    return 


def uc_ctr_decrypt(ctext: bytes, ctr: int) -> bytes:
    """
    Emulate the symmetric encryption/decryption CTR routine in the bootloader.
    Setup CTR, 
    """
    assert len(ctext) == 16
    assert uc.mem_read(KEYMEM, 16) == ENC_KEY
    # The ciphertext is overwritten with the plaintext
    uc.mem_write(WMEM, bytes(ctext))
    # Setup argument registers
    uc.reg_write(uni.arm_const.UC_ARM_REG_LR, 0xFFFFFFFF) 
    uc.reg_write(uni.arm_const.UC_ARM_REG_R0, KEYMEM)
    uc.reg_write(uni.arm_const.UC_ARM_REG_R1, WMEM)
    # R2 is fixed to be 0x10 in this routine -- 1 block 
    uc.reg_write(uni.arm_const.UC_ARM_REG_R2, 0x10)
    uc.reg_write(uni.arm_const.UC_ARM_REG_R3, NONCE)
    # Pass the last argument on the stack 
    uc.reg_write(uni.arm_const.UC_ARM_REG_SP, STACK+1020)
    uc.mem_write(uc.reg_read(uni.arm_const.UC_ARM_REG_SP), ctr.to_bytes(4, 'little'))
    # Emulate
    try:
        # ' | 1 ' starts the function in thumb mode 
        uc.emu_start(ENC_FUNCADDR | 1, ENC_FUNCADDR_END)
    except:
        # Breakpoint if something goes wrong 
        import ipdb; ipdb.set_trace()
    # Read the output to the 'dst' argument
    return uc.mem_read(WMEM, 16)


def uc_some_symmetric_encoding(code: bytes) -> bytes:
    """
    Mass decode this 0x400 byte chunk.
    This function uses a global buffer. So we must use that.
    """
    assert len(code) == 0x400
    uc.mem_write(SRAM_BUFFER, code) 
    # Constant 
    uc.reg_write(uni.arm_const.UC_ARM_REG_R0, 0x400)
    try:
        uc.emu_start(CODE_FUNCADDR | 1, CODE_FUNCADDR_END)
    except:
        import ipdb; ipdb.set_trace()
    return uc.reg_read(uni.arm_const.UC_ARM_REG_R0)


def main() -> None:
    """
    Main function.
    Initialize Unicorn instance then decrypt data.
    """
    init_uc()
    out = b''
    ciphertext = open(CIPHERTEXT, 'rb').read()
    for chunkndx in range(len(ciphertext)//0x400):
        # Break into 0x400 sized chunk 
        chunk = ciphertext[chunkndx*0x400:chunkndx*0x400+0x400]
        # decoded = uc_some_symmetric_encoding(chunk)
        for blocknr in range(len(chunk)//16):
            out += uc_ctr_decrypt(chunk[blocknr*16:blocknr*16+16], 0x40*chunkndx+blocknr)
    fh = open('test.bin', 'wb')
    fh.write(out)
    fh.close()
    print(f"App decrypted to {fh.name}")
    return 

if __name__ == "__main__":
    main()
