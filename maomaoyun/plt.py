import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

f = open(sys.argv[1],'rb'); elf = ELFFile(f)
dynsym = elf.get_section_by_name('.dynsym')

# map GOT/PLT relocations: r_offset -> symbol name
relnames = {}
for sec in elf.iter_sections():
    if isinstance(sec, RelocationSection):
        for r in sec.iter_relocations():
            si = r['r_info_sym']
            if si and si < dynsym.num_symbols():
                relnames[r['r_offset']] = dynsym.get_symbol(si).name

# .plt: each stub is 16 bytes; resolve its GOT target by decoding adrp/ldr
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
plt = elf.get_section_by_name('.plt')
out = {}
if plt:
    base = plt['sh_addr']; data = plt.data()
    # iterate 16-byte stubs
    i = 0
    while i < len(data):
        stub = data[i:i+16]
        addr = base + i
        page = None; got = None
        for ins in md.disasm(stub, addr):
            if ins.mnemonic == 'adrp':
                page = ins.operands[1].imm
            elif ins.mnemonic in ('ldr',) and page is not None:
                # ldr xN, [xM, #imm]
                for op in ins.operands:
                    if op.type == 3:  # mem
                        got = page + op.mem.disp
        if got and got in relnames:
            out[addr] = relnames[got]
        i += 16
for a in sorted(out): print(f"{a:#x}\t{out[a]}")
