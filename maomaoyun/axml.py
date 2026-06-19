import struct, sys

data = open(sys.argv[1], 'rb').read()
def u16(o): return struct.unpack_from('<H', data, o)[0]
def u32(o): return struct.unpack_from('<I', data, o)[0]

def parse_string_pool(off):
    string_count = u32(off+8)
    flags = u32(off+16)
    strings_start = u32(off+20)
    is_utf8 = (flags & (1<<8)) != 0
    str_offsets = [u32(off+28+i*4) for i in range(string_count)]
    base = off + strings_start
    res = []
    for so in str_offsets:
        p = base + so
        if is_utf8:
            if data[p] & 0x80: p += 2
            else: p += 1
            bl = data[p]
            if bl & 0x80: bl = ((bl & 0x7f) << 8) | data[p+1]; p += 2
            else: p += 1
            res.append(data[p:p+bl].decode('utf-8','replace'))
        else:
            n = u16(p); p += 2
            if n & 0x8000: n = ((n & 0x7fff) << 16) | u16(p); p += 2
            res.append(data[p:p+n*2].decode('utf-16-le','replace'))
    return res

# common android: attribute resource ids -> names
ANDROID_ATTR = {
0x01010003:'name',0x01010001:'label',0x01010002:'icon',0x0101000f:'required',
0x01010010:'screenOrientation',0x01010018:'authorities',0x0101001b:'permission',
0x0101001c:'exported',0x0101000d:'theme',0x01010000:'theme',0x0101021b:'value',
0x01010024:'resource',0x01010570:'roundIcon',0x010103a0:'configChanges',
0x0101001d:'process',0x01010271:'installLocation',0x01010204:'glEsVersion',
0x010102b2:'targetSdkVersion',0x0101020c:'minSdkVersion',0x01010572:'extractNativeLibs',
0x01010580:'usesCleartextTraffic',0x0101055b:'supportsRtl',0x01010594:'roundIcon',
0x01010003:'name',0x01010357:'windowSoftInputMode',0x010100d0:'id',
0x01010273:'protectionLevel',0x0101026f:'maxSdkVersion',0x01010119:'launchMode',
0x0101001e:'enabled',0x01010220:'directBootAware',0x01010366:'isGame',
0x01010477:'fullBackupContent',0x010104ea:'appComponentFactory',0x01010540:'networkSecurityConfig',
0x0101048d:'requestLegacyExternalStorage',0x010103f6:'allowBackup',0x010100b3:'priority',
0x01010616:'localeConfig',
}

assert u16(0) == 0x0003, "not AXML"
sp_off = 8
strings = parse_string_pool(sp_off)
sp_size = u32(sp_off+4)

# resource map chunk (0x0180) right after string pool
off = sp_off + sp_size
resmap = []
if u16(off) == 0x0180:
    rsize = u32(off+4)
    cnt = (rsize-8)//4
    resmap = [u32(off+8+i*4) for i in range(cnt)]
    off += rsize

out = []
indent = 0
def s(i): return strings[i] if 0 <= i < len(strings) else '?'

def attrname(idx):
    if idx != 0xFFFFFFFF and idx < len(strings) and strings[idx]:
        return strings[idx]
    if idx < len(resmap):
        rid = resmap[idx]
        return 'android:'+ANDROID_ATTR.get(rid, hex(rid))
    return '?'

while off < len(data):
    ctype = u16(off); csize = u32(off+4)
    if ctype == 0x0102:
        name = u32(off+0x14)
        attr_start = u16(off+0x18); attr_count = u16(off+0x1c)
        line = '  '*indent + '<' + s(name)
        ab = off + 0x10 + attr_start
        for i in range(attr_count):
            a = ab + i*0x14
            a_name = u32(a+4); a_rawval = u32(a+8)
            a_type = data[a+0x0f]; a_data = u32(a+0x10)
            an = attrname(a_name)
            if a_type == 0x03: av = s(a_rawval)
            elif a_type == 0x10: av = str(struct.unpack('<i',struct.pack('<I',a_data))[0])
            elif a_type == 0x12: av = 'true' if a_data else 'false'
            elif a_type == 0x01: av = '@'+hex(a_data)
            else: av = hex(a_data)
            line += ' %s="%s"' % (an, av)
        out.append(line+'>'); indent += 1
    elif ctype == 0x0103: indent -= 1
    off += csize
    if csize == 0: break
print('\n'.join(out))
