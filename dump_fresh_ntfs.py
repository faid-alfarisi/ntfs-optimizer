import struct

# Read from \\.\E: directly
with open(r'\\.\E:', 'rb') as f:
    boot = f.read(512)
    bytes_per_sec = struct.unpack_from('<H', boot, 11)[0]
    sec_per_clus = boot[13]
    mft_lcn = struct.unpack_from('<Q', boot, 0x30)[0]
    cluster_sz = bytes_per_sec * sec_per_clus
    print(f'bytes_per_sec={bytes_per_sec}, sec_per_clus={sec_per_clus}, cluster_sz={cluster_sz}, mft_lcn={mft_lcn}')
    
    # seek to MFT
    f.seek(mft_lcn * cluster_sz)
    mft_data = f.read(64 * 1024) # first 64 records

def dump_record_info(rec, idx):
    if rec[:4] != b'FILE':
        return
    flags = struct.unpack_from('<H', rec, 22)[0]
    seq = struct.unpack_from('<H', rec, 16)[0]
    if (flags & 1) == 0:
        return
    
    # parse attributes
    d = bytearray(rec)
    usa_off, usa_cnt = struct.unpack_from('<HH', d, 4)
    for i in range(usa_cnt - 1):
        sec_off = (i + 1) * 512 - 2
        d[sec_off:sec_off+2] = d[usa_off + 2 + i*2 : usa_off + 4 + i*2]
    
    attr_off = struct.unpack_from('<H', d, 20)[0]
    off = attr_off
    names = []
    attr_list = []
    while off < len(d):
        atype, alen = struct.unpack_from('<II', d, off)
        if atype == 0xFFFFFFFF or alen == 0:
            break
        non_res = d[off+8]
        name_len = d[off+9]
        name_off = struct.unpack_from('<H', d, off+10)[0]
        aname = d[off+name_off:off+name_off+name_len*2].decode('utf-16le') if name_len else ''
        attr_list.append((hex(atype), aname, f'non_res={non_res}'))
        
        if atype == 0x30:
            val_off = struct.unpack_from('<H', d, off+0x14)[0]
            parent_ref = struct.unpack_from('<Q', d, off+val_off)[0]
            p_frs = parent_ref & 0x0000FFFFFFFFFFFF
            fn_len = d[off+val_off+64]
            fname = d[off+val_off+66:off+val_off+66+fn_len*2].decode('utf-16le', errors='ignore')
            names.append(f'{fname} (parent={p_frs})')
        off += alen
    print(f'Record {idx} (seq={seq}, flags={flags}): names={names}')
    print(f'    Attrs: {attr_list}')

for i in range(64):
    dump_record_info(mft_data[i*1024:(i+1)*1024], i)

