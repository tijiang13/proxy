import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

path = sys.argv[1]
target = sys.argv[2]
f = open(path, 'rb')
elf = ELFFile(f)

# symbol -> (addr, size)
syms = {}
for sec in elf.iter_sections():
    if sec.header['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM'):
        for s in sec.iter_symbols():
            if s.name:
                syms[s.name] = (s['st_value'], s['st_size'])

# build vaddr->fileoffset mapping via sections
def vaddr_to_off(va):
    for sec in elf.iter_sections():
        a = sec['sh_addr']; sz = sec['sh_size']
        if a <= va < a+sz and sec['sh_type'] != 'SHT_NOBITS':
            return sec['sh_offset'] + (va - a)
    return None

addr, size = syms[target]
off = vaddr_to_off(addr)
f.seek(off); code = f.read(size)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
print(f"; {target} @ {hex(addr)} size {size}")
for ins in md.disasm(code, addr):
    print(f"{ins.address:#x}\t{ins.mnemonic}\t{ins.op_str}")
