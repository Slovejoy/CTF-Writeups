# WolvCTF 2023 Authcore Series Writeup 
This is a writeup for University of Michigan's 2023 WolvCTF competition.
The following problems, [authcore-1](../authcore-1/authcore-1.md) and authcore-2, were part of a 3 part RE and pwn series. 
I was the only solve for authcore-1, and present a partial writeup for the unsolved authcore-2. 
I participated in this CTF alone, and am currently not participating in a competitive team. 

## Authcore-2 Introduction
In authcore-1, we recovered the cryptographic key used for the decrypting the application binary. In authcore-2, we're tasked with RE'ing the application binary and exploiting a vulnerability inside of it. We're supplied a datasheet that contains the following useful table

![HMAC MMIO table](images/hmac_mmio.png)

# Authcore-2 -- Decrypting the Application Binary 
In authcore-1, we discovered a "read" subcommand hidden in the recovery mode bootloader. This subcommand uses CTR-mode encryption function to send the application binary ciphertext over the problem's TCP connection. However, in authcore-1 the nonce was reused, allowing us to ignore the cryptography and treat the ciphertext as a weak Vigenere cipher. The read function increments the counter, eliminating this tactic. 

![CTR encrypt](https://upload.wikimedia.org/wikipedia/commons/4/4d/CTR_encryption_2.svg)
![CTR decrypt](https://upload.wikimedia.org/wikipedia/commons/3/3c/CTR_decryption_2.svg) 

*Images from [Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)*

One important note about CTR mode is that encryption and decryption are the same operation, just with plaintext/ciphertext respectively. While it is certainly possibly to recreate the previously discussed `FUN_08000a82` or *encrypt\_read\_buffer* entirely in python, I instead opt to recreate this decryption routine using the Unicorn emulation framework. The following excerpt, from [app\_decrypt.py](code/app_decrypt.py), shows the emulation of the *encrypt\_read\_buffer* routine,

```
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
```

We know that the app has strings in it, so if we run strings and see human-readable text, we've decrypted it correctly. 

![decrypted app strings](images/app_strings.png)

## Authcore-2 -- Reverse Engineering
The application binary has a menu with 5 options inside of it. The goal of the problem is to demonstrate arbitrary code execution by use the memory-mapped HMAC module to generate a unique hash from a given sequence. In the *Generate OTP code* function, I identify the following snippet of interest.  

```
	LAB_080043be                                    XREF[1]:     080043c2(j)  
080043be 23 68           ldr        r3,[r4,#0x0]=>hmac_is_ready                      = ??
080043c0 00 2b           cmp        r3,#0x0
080043c2 fc d0           beq        LAB_080043be
```

In C, this would look like `while (!(*hmac_is_ready)) {};`, and is common practice for waiting for an interrupt to occur. This is suggestive that the challenge may have operated with actual hardware (shoutout to the dev), or at least some sophisticated emulation! If we cross-reference this global variable, we come across the IRQ handler. 

```
void copy_hmac_interrupt(void)
{
  undefined *puVar1;
  int iVar2;
  undefined *puVar3;
  int iVar4;
  
  puVar1 = PTR_hmac_is_ready_080042ac;
  iVar2 = *(int *)PTR_hmac_is_ready_080042ac;
  puVar3 = PTR_computed_hmac_080042b0;
  if (iVar2 == 0) {
    do {
      iVar4 = iVar2 * 4;
      iVar2 = iVar2 + 1;
      *puVar3 = (char)((uint)*(undefined4 *)(&DAT_4000a040 + iVar4) >> 0x18);
      puVar3[1] = (char)((uint)*(undefined4 *)(&DAT_4000a040 + iVar4) >> 0x10);
      puVar3[2] = (char)((uint)*(undefined4 *)(&DAT_4000a040 + iVar4) >> 8);
      puVar3[3] = (char)*(undefined4 *)(&DAT_4000a040 + iVar4);
      puVar3 = puVar3 + 4;
    } while (iVar2 != 8);
    *(undefined4 *)puVar1 = 1;
  }
  return;
}
```

This function reads from the memory-mapped output registers of the HMAC module, and puts them into a global buffer in SRAM. Execution then returns to the *Generate OTP function*, where it'll break out of the loop. This yields the following memory map, 

 - 0x08000000 bootlader 
 - 0x08004000 OTP application 
 - 0x20000000 SRAM 
 - 0x4000A000 Memory Mapped IO (HMAC module)

Know that we've reverse engineered the binary a bit, and understand where the payload must write to, we're ready to tackle VR. 

## Authcore-2 -- Vulnerability Research 
Back to the shell, we're at the same five functions. I notice that in the *List OTP providers* function, I see the following code,

```
  /* Function prologue omitted */ 
  iVar2 = 0;
  pcVar3 = (otp *)PTR_struct_array[0].name[0]_080042e4;
  do {
    printf(__format,iVar2);
    __s = (otp *)puVar1;
    if (pcVar3[-1].ctr != 0) {
      __s = pcVar3;
    }
    iVar2 = iVar2 + 1;
    puts((char *)__s);
    pcVar3 = pcVar3 + 1;
  } while (iVar2 != 4);
  return;
```

This iterates through a global array of structures, printing information about each. These structures are formatted as follows,

```
struct otp_object {
  uint32_t enabled; 
  uint32_t pad;
  uint64_t uid;
  uint64_t counter;
  char name[16]; 
}; 
```

The loop suggests that the global array is contains four of these structures (each 0x28 = 40 bytes). However, the generate function lets us write *up to 5* of these. In my research, I expect this to be an off-by-one error yielding a 40-byte out-of-bounds write. This is further backed up by the XREFs to this memory region observed in Ghidra. 

However, this is where my VR effort fell short. Despite a few hours trying, I was unable to observe any artifacts from my write-primitive. Below is a non-exhaustive list of things I tried,

- Perform the OOB write inserting pointers to known strings 
- Perform the OOB write inserting pointers to the OTP object table in SRAM
- Perform the OOB write, treating some entitites as lengths and some as pointers 
- Inserting format strings into the name fields of each entity 
- OOB write with format strings in other fields 

As for other vulnerabilities, the bootloader update mechanism is not key-signed, so I could update custom firmware, although this was disabled for this challenge. Additionally, it seems the app is entirely statically allocated, leaving no room for heap exploitation. Were I to devote more time to this problem, I believe the next step would be to expand the emulation framework to create formal data-dependence graphs and control-flow graphs. This could be done either with [Unicorn](https://github.com/unicorn-engine/unicorn), or potentially [Qiling](https://github.com/qilingframework/qiling). 

That, or I'm missing something very obvious ¯\\\_(ツ)\_/¯
