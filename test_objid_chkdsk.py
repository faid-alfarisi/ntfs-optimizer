import ctypes, struct, subprocess

h = ctypes.windll.kernel32.CreateFileW(r'\\.\F:', 0xC0000000, 3, None, 3, 0, None)
if h == -1:
    print("Cannot open F: for write:", ctypes.GetLastError())
    exit(1)

# First format with ntfs-optimizer with standard settings
ctypes.windll.kernel32.CloseHandle(h)

subprocess.run([r'.\ntfs-optimizer.exe', '-mode', 'format', '-target', 'F:', '-yes'], check=True)

# Now open F: and read Record 25 ($ObjId)
h = ctypes.windll.kernel32.CreateFileW(r'\\.\F:', 0xC0000000, 3, None, 3, 0, None)

def read_at(pos, sz):
    class LI(ctypes.Structure):
        _fields_ = [('QuadPart', ctypes.c_longlong)]
    ctypes.windll.kernel32.SetFilePointerEx(h, LI(pos), None, 0)
    b = ctypes.create_string_buffer(sz)
    r = ctypes.c_ulong(0)
    ctypes.windll.kernel32.ReadFile(h, b, sz, ctypes.byref(r), None)
    return bytes(b[:r.value])

def write_at(pos, data):
    class LI(ctypes.Structure):
        _fields_ = [('QuadPart', ctypes.c_longlong)]
    ctypes.windll.kernel32.SetFilePointerEx(h, LI(pos), None, 0)
    r = ctypes.c_ulong(0)
    ctypes.windll.kernel32.WriteFile(h, data, len(data), ctypes.byref(r), None)
    return r.value

buf = read_at(0, 512)
bytes_per_sec = struct.unpack('<H', buf[0x0B:0x0D])[0]
sec_per_clus = buf[0x0D]
clus_sz = bytes_per_sec * sec_per_clus
mft_lcn = struct.unpack('<Q', buf[0x30:0x38])[0]

# Modify Record 25 on disk:
# Let's change Attr 0xA0 in Record 25 to 128 MB (32768 clusters),
# but keep Attr 0xB0 resident with 8 bytes (or 64 bytes).
rec25_raw = read_at(mft_lcn * clus_sz + 25 * 1024, 1024)

def unfix(rec):
    fixup_off = struct.unpack('<H', rec[4:6])[0]
    fixup_cnt = struct.unpack('<H', rec[6:8])[0]
    r = bytearray(rec)
    for i in range(1, fixup_cnt):
        r[i*512 - 2: i*512] = rec[fixup_off + i*2 : fixup_off + i*2 + 2]
    return r, fixup_off, fixup_cnt

def apply_fix(r, fixup_off, fixup_cnt):
    seq = struct.unpack('<H', r[fixup_off:fixup_off+2])[0] + 1
    struct.pack_into('<H', r, fixup_off, seq)
    for i in range(1, fixup_cnt):
        sec_off = i * 512 - 2
        r[fixup_off + i*2 : fixup_off + i*2 + 2] = r[sec_off:sec_off+2]
        struct.pack_into('<H', r, sec_off, seq)
    return bytes(r)

r, fixup_off, fixup_cnt = unfix(rec25_raw)
off = struct.unpack('<H', r[20:22])[0]
while off < len(r):
    atype, alen = struct.unpack_from('<II', r, off)
    if atype == 0xFFFFFFFF: break
    if atype == 0xA0: # $INDEX_ALLOCATION
        # Change total clusters to 32768 (128 MB)
        # 0x18: ending VCN
        struct.pack_into('<Q', r, off+0x18, 32768 - 1)
        # 0x28: allocSize
        struct.pack_into('<Q', r, off+0x28, 32768 * 4096)
        # 0x30: realSize
        struct.pack_into('<Q', r, off+0x30, 32768 * 4096)
        # 0x38: initSize
        struct.pack_into('<Q', r, off+0x38, 32768 * 4096)
        # runlist: at off+0x40. Run for length 32768 (0x8000) at lcn 16515 (0x4083)
        # encode run: length size 2, lcn size 2 -> header 0x22
        # clen = 0x8000 (0x00, 0x80), lcn = 0x4083 (0x83, 0x40), 0x00
        run_off = struct.unpack('<H', r[off+0x20:off+0x22])[0]
        r[off+run_off : off+run_off+6] = bytes([0x22, 0x00, 0x80, 0x83, 0x40, 0x00])
        print("Patched 0xA0 to 128 MB!")
    off += alen

new_rec25 = apply_fix(r, fixup_off, fixup_cnt)
write_at(mft_lcn * clus_sz + 25 * 1024, new_rec25)
ctypes.windll.kernel32.CloseHandle(h)

# Now test chkdsk
res = subprocess.run('cmd /c "echo n | chkdsk F:"', shell=True, capture_output=True, text=True)
print("chkdsk returncode:", res.returncode)
print(res.stdout)

