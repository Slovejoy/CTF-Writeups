# WolvCTF 2023 Authcore Series Writeup 
This is a writeup for University of Michigan's 2023 WolvCTF competition.
The following problems, authcore-1 and authcore-2, were part of a 3 part RE and pwn series. 
I was the only solve for authcore-1, and present a partial writeup for the unsolved authcore-2. 
I participated in this CTF alone, and am currently not participating in a competitive team. 

## Authcore-1 Introduction and ISA Identification
Authcore-1 begins with a description roughly paraphrased "recover the application binary from this bootloader". 
There's an attached binary blob called "bootloader\_extracted.bin" that we're tasked with reverse engineering. 
This is a pretty small binary, so I take the first couple steps and run `file`, `binwalk`, and `strings`.  
![Quick forensic check on bootloader\_extracted.bin](images/forensics.png)  

While this could have been more helpful, `file` tells us that the binary blob is not structured.
`Binwalk` tells us that there are no binary signatures from this file, hinting that the ISA might be a lesser known architecture.
Finally, `strings` provides us the most helpful information in that the binary is likely not compressed or packed, and can directly imported into other tools.  

However, we still don't have an ISA, so inserting into Ghidra isn't a good option yet. 
For bootloader RE, a good practice is to look at the first chunk of the file.  

![Hexdump of bootloader\_extracted.bin](images/hexdump.png)

Here are a few good tricks to identifying some of the common architectures.
 - For x86 or x64, function prologues typically start with lots of consecutive '5X' bytes. 
 - For ARM or ARM64, every ~4 bytes with have nibbles with 'e' in them. 
 - For MIPS, the stack allocation/deallocation instruction is `27 bd` (BE) or `bd 27` (LE)

These tricks can become surprisingly helpful when staring at hex, which even when equipped with the best tools can be surprisingly relevant.
Looking at the hexdump of the bootloader, we observe at the start of the file many addresses looking like `7d 12 00 08` or similar. 
This is almost assuredly some kind of interrupt vector table, or IVT (also called an exception vector table). 
Since these values are pointers, it gives us a hint about the image base of the program. 
At around hex address **0x150** we start seeing bytes deviating from the pattern, I take the snippet at **0x150** and feed it into an online disassembler [disasm.pro](https://disasm.pro).
This reveals the ARM-thumb instruction `push {r4, lr}`, a function prologue; we now have all the information we need to feed the bootloader into Ghidra. 

## Authcore-1 -- Static Analysis 
While I won't go into too much detail about looking at the binary, I will point out a few critical functions as they come up.
Additionally, emulation of this bootloader, especially full-system emulation, is extremely limited and static analysis is for sure the way to go for RISC architecture raw binaries. 
Ghidra's autoanalysis won't do much good until we give it the correct image base.
So, using the IVT, I observe that the image base for the bootloader is `0x08000000`, then run autoanalysis.
Next I identify bootloader code based off of references to strings. 
Looking at the code, I can identify important user interaction with calls to `getchar` and `putchar`.
Interestingly, one find is the string "> BL Recovery Console ([H] for Help)<", which is used in an *unreached* function of interest.
The recovery console function is XREF'ed by the following horrifically decompiled snippet,

```
  do {
    recovery_mode_main();
LAB_0800078e:
    iVar5 = FUN_0800097c();
    if ((iVar5 == 0) || (iVar5 = getchar((uint)bVar3), iVar5 != 0x20)) {
      boot_main_app();
    }
  } while( true );
```

In most bootloaders, the boot process is automatic unless the user hits some interrupt key, like a function key. 
Testing on the live system, knowing that `0x20` corresponds to the space key, if I spam the spacebar while the application is booting I'll drop into the recovery menu!
The recovery menu has many subcommands, but the only two of interest is the 'Debug' subcommand, which prints information about a very important structure in the SRAM region. The other interesting subcommand is the 'Read' command, which dumps the application binary, which will be relevant in authcore-2. 

## Authcore-1 -- The flag 
When we run the 'D' command from the recover menu, it'll spit back the following encrypted hex  
```
64 84 B0 59 1E 6B 24 6D CC 6E 29 B7 DD 5E 08 B5 26 68 F5 09 68 08 51 0B BC 0D 5D 85 82 79 67 E2 44 BA 87 74 1F 6B 25 6D C7 6E 29 F7 DD 1E 08 BD 26 C8 F5 09 1F 6B 25 6D C7 6E 29 F7 DD 1E 08 BD 26 C8 F5 09 50 38 70 40 88 3A 79 D7 F5 68 39 93 17 E1 F5 09 1F 6B 25 6D C7 6E 29 F7 DD 1E 08 BD 26 C8 F5 09 E0 DC 0E EA
```
This subcommand encrypts the `struct appinfo` global structure in SRAM, then sends it over the TCP connectoin. Crtically, the structure contains the cryptographic key that is required to recover the application binary, and thus solve the problem. Upon examing the code that does this operation, I find the following decompiled snippet in `recovery_mode_main` corresponding to the 'D' subcommand, 

```
puts(PTR_s_!_DEBUG_DATA_!_080005d0);
uVar5 = 0x68;
do {
  iVar9 = *(int *)puVar1;
  pbVar10 = app_struct;
  pbVar12 = (byte *)(iVar9 + iVar6);
  /* memcpy(pbVar10, pbVar12, 16); */ 
  do {
    pbVar11 = pbVar12 + 1;
    *pbVar10 = *pbVar12;
    pbVar10 = pbVar10 + 1;
    pbVar12 = pbVar11;
  } while (pbVar11 != (byte *)(iVar9 + 0x10 + iVar6));
  uVar13 = uVar5;
  if (0xf < uVar5) {
    uVar13 = 0x10;
  }
  FUN_08000a82(iVar9 + 0x14,app_struct,uVar13 & 0xff,uVar2,0);
/* pretty printing // hexlifying inlined to follow */
```
This is pretty messy, but if the debug data is encrypted then its `FUN_08000a82` that's doing it. 
In `FUN_08000a82`, we observe the following decompiled code,
```
void encrypt_read_buffer(byte *key,int dst,uint length,uint nonce,uint index)
{
  byte *pbVar1;
  uint *puVar2;
  uint uVar3;
  byte *pbVar4;
  uint *puVar5;
  uint local_58;
  uint local_54;
  uint local_50;
  uint local_4c;
  uint auStack_48 [4];
  uint auStack_38 [4];
  uint local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  
  local_50 = ~nonce;
  local_54 = ~index;
  local_4c = index;
  pbVar4 = key;
  puVar2 = auStack_38;
  puVar5 = auStack_48;
  do {
    pbVar1 = pbVar4 + 4;
    uVar3 = (uint)pbVar4[2] << 0x10 | (uint)pbVar4[1] << 8 | (uint)*pbVar4 | (uint)pbVar4[3] << 0x18
    ;
    *puVar5 = uVar3;
    *puVar2 = ~uVar3;
    pbVar4 = pbVar1;
    puVar2 = puVar2 + 1;
    puVar5 = puVar5 + 1;
  } while (key + 0x10 != pbVar1);
  local_58 = nonce;
  FUN_08000a3e(&local_58,auStack_48);
  FUN_08000a3e(&local_50,auStack_38);
  if (0xf < length) {
    length = 0x10;
  }
  local_28 = local_58 & 0xaaaaaaaa | local_4c & 0x55555555;
  local_24 = local_58 & 0x55555555 | local_4c & 0xaaaaaaaa;
  local_20 = local_54 & 0xaaaaaaaa | local_50 & 0x55555555;
  local_1c = local_54 & 0x55555555 | local_50 & 0xaaaaaaaa;
  pbVar4 = (byte *)(dst + -1);
  puVar2 = &local_28;
  while ((int)(pbVar4 + (1 - dst)) < (int)length) {
    pbVar4 = pbVar4 + 1;
    *pbVar4 = *(byte *)puVar2 ^ *pbVar4;
    puVar2 = (uint *)((int)puVar2 + 1);
  }
  return;
}
```
Identifying this function is central to success in the problem. 

<details>
<summary>What common cryptographic function is this?</summary>
It's CTR mode encryption/decryption. 

Looking back to where the CTR encrypt function is called, we notice that the final argument, or *nonce*, is always 0. 
Fixed-nonce CTR can be treated as a repeating-key XOR cipher, or in classical terms, a Vigenere Cipher.
The key-length is 16, and from other reverse engineering efforts, we can derive the first 16-bytes of the bootloader header as
</details>


```
struct boot_header {
  uint32_t magic;         // BLEP
  uint16_t major_version; // 1
  uint16_t minor_version; // 1
  uint32_t flags;         // 0x4000000b 
  uint32_t start_addr;    // 0x08004000
  // Extra stuff 
  uint32_t app_size; 
  uint8_t key[16]; 
};
```
The following python code will decrypt the rest of the structure and print the flag.
```
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
# 0x8: uint32_t flags 
# 0xc: uint32_t addr 
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
```
