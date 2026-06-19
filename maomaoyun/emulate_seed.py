#!/usr/bin/env python3
"""Emulate the key/IV seed builder at the top of Java_com_mt_Core_queryConfiguration
in libcore.so, to recover the constant 3DES seed (key material)."""
import sys
from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.arm64_const import *

LIB = sys.argv[1] if len(sys.argv) > 1 else "lib/arm64-v8a/libcore.so"
FUNC = 0x1658          # Java_com_mt_Core_queryConfiguration
STOP = 0x17dc          # right after the 8 seed bytes are written

f = open(LIB, "rb"); elf = ELFFile(f); raw = open(LIB, "rb").read()

uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
# map the whole file image (load segments) at page granularity
def align(x, a=0x1000): return x & ~(a-1)
for seg in elf.iter_segments():
    if seg['p_type'] != 'PT_LOAD':
        continue
    va = align(seg['p_vaddr']); end = seg['p_vaddr'] + seg['p_memsz']
    size = align(end - va + 0xfff)
    try: uc.mem_map(va, size)
    except UcError: pass
    uc.mem_write(seg['p_vaddr'], raw[seg['p_offset']:seg['p_offset']+seg['p_filesz']])

# stack
STACK = 0x70000000; uc.mem_map(STACK, 0x100000)
sp = STACK + 0x80000
uc.reg_write(UC_ARM64_REG_SP, sp)
# TLS base for `mrs x28, tpidr_el0` + stack canary at [x28+0x28]
TLS = 0x60000000; uc.mem_map(TLS, 0x1000)
uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS)
uc.mem_write(TLS + 0x28, b"\x11\x22\x33\x44\x55\x66\x77\x88")

# PLT stubs we must service before STOP: time() and __strlen_chk()
PLT_TIME = 0x2ab0
PLT_STRLEN_CHK = 0x2b00

def hook_code(uc, addr, size, ud):
    if addr == PLT_TIME:
        uc.reg_write(UC_ARM64_REG_X0, 1)           # time() > 0
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
    elif addr == PLT_STRLEN_CHK:
        # __strlen_chk(s, maxlen) -> strlen("KEY") = 3
        uc.reg_write(UC_ARM64_REG_X0, 3)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

uc.hook_add(UC_HOOK_CODE, hook_code)
uc.reg_write(UC_ARM64_REG_X0, 0)   # JNIEnv (unused before STOP)
uc.reg_write(UC_ARM64_REG_X2, 0)   # arg jstring (unused before STOP)

try:
    uc.emu_start(FUNC, STOP)
except UcError as e:
    print("emu stopped:", e)

x29 = uc.reg_read(UC_ARM64_REG_X29)
seed = uc.mem_read(x29 - 0xb0, 8)
print("seed bytes :", seed.hex())
print("seed ascii :", "".join(chr(b) if 32 <= b < 127 else '.' for b in seed))
