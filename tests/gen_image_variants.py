#!/usr/bin/env python3
"""gen_image_variants.py OUTDIR -- write uncompressed raster files in the layouts NanoZip's image
detectors look for (BMP 8/16/24/32-bit, PGM/PPM/PBM binary, TGA 24/32, TIFF 8/16-bit uncompressed),
with smooth 2-D content so the image model's predictor modes get exercised."""
import os, struct, sys, math
out = sys.argv[1]; os.makedirs(out, exist_ok=True)
W, H = 320, 200
def px(x, y):  # smooth gradient + a disc: neighbouring pixels correlate in both directions
    r = int(127 + 100 * math.sin(x / 23.0)); g = int(127 + 100 * math.cos(y / 17.0)); b = (x * 3 + y * 5) & 0xff
    if (x - 160) ** 2 + (y - 100) ** 2 < 60 ** 2: r, g, b = 255 - r, 255 - g, 200
    return r & 0xff, g & 0xff, b & 0xff
def bmp(path, bpp):
    row = ((W * bpp + 31) // 32) * 4; img = bytearray()
    for y in range(H - 1, -1, -1):
        line = bytearray()
        for x in range(W):
            r, g, b = px(x, y)
            if bpp == 24: line += bytes((b, g, r))
            elif bpp == 32: line += bytes((b, g, r, 0))
            elif bpp == 16: line += struct.pack('<H', ((r >> 3) << 10) | ((g >> 3) << 5) | (b >> 3))
            elif bpp == 8: line += bytes(((r + g + b) // 3,))
        line += b'\0' * (row - len(line)); img += line
    pal = b''.join(bytes((i, i, i, 0)) for i in range(256)) if bpp == 8 else b''
    off = 14 + 40 + len(pal)
    hdr = b'BM' + struct.pack('<IHHI', off + len(img), 0, 0, off) + struct.pack('<IiiHHIIiiII', 40, W, H, 1, bpp, 0, len(img), 2835, 2835, 256 if bpp == 8 else 0, 0)
    open(path, 'wb').write(hdr + pal + img)
def pnm(path, kind):
    if kind == 'pgm': open(path, 'wb').write(b'P5\n%d %d\n255\n' % (W, H) + bytes((sum(px(x, y)) // 3) for y in range(H) for x in range(W)))
    elif kind == 'ppm': open(path, 'wb').write(b'P6\n%d %d\n255\n' % (W, H) + b''.join(bytes(px(x, y)) for y in range(H) for x in range(W)))
    elif kind == 'pbm':
        rows = bytearray()
        for y in range(H):
            bits = 0; n = 0
            for x in range(W):
                bits = (bits << 1) | (1 if sum(px(x, y)) < 380 else 0); n += 1
                if n == 8: rows.append(bits); bits = 0; n = 0
            if n: rows.append(bits << (8 - n))
        open(path, 'wb').write(b'P4\n%d %d\n' % (W, H) + bytes(rows))
    elif kind == 'pgm16': open(path, 'wb').write(b'P5\n%d %d\n65535\n' % (W, H) + b''.join(struct.pack('>H', (sum(px(x, y)) // 3) * 257) for y in range(H) for x in range(W)))
def tga(path, bpp):
    hdr = struct.pack('<BBBHHBHHHHBB', 0, 0, 2, 0, 0, 0, 0, 0, W, H, bpp, 0x20 if bpp == 32 else 0x08 if False else 0)
    body = b''.join((bytes((px(x, y)[2], px(x, y)[1], px(x, y)[0])) if bpp == 24 else bytes((px(x, y)[2], px(x, y)[1], px(x, y)[0], 255))) for y in range(H) for x in range(W))
    open(path, 'wb').write(hdr + body)
def tiff(path, bits):
    spp = 3 if bits == 8 else 1
    data = b''.join(bytes(px(x, y)) for y in range(H) for x in range(W)) if bits == 8 else b''.join(struct.pack('<H', (sum(px(x, y)) // 3) * 257) for y in range(H) for x in range(W))
    entries = []
    def ent(tag, typ, cnt, val): entries.append(struct.pack('<HHII', tag, typ, cnt, val))
    n = 10 + (1 if bits == 8 else 0); ifd_off = 8; data_off = 8 + 2 + n * 12 + 4 + (8 if bits == 8 else 0)
    bps_off = 8 + 2 + n * 12 + 4
    ent(256, 4, 1, W); ent(257, 4, 1, H)
    if bits == 8: ent(258, 3, 3, bps_off)
    else: ent(258, 3, 1, 16)
    ent(259, 3, 1, 1); ent(262, 3, 1, 2 if bits == 8 else 1); ent(273, 4, 1, data_off); ent(277, 3, 1, spp); ent(278, 4, 1, H); ent(279, 4, 1, len(data)); ent(284, 3, 1, 1)
    if bits == 8: pass
    ifd = struct.pack('<H', len(entries)) + b''.join(sorted(entries, key=lambda e: struct.unpack('<H', e[:2])[0])) + struct.pack('<I', 0)
    extra = struct.pack('<HHH', 8, 8, 8) + b'\0\0' if bits == 8 else b''
    open(path, 'wb').write(b'II*\0' + struct.pack('<I', ifd_off) + ifd + extra + data)
bmp(f'{out}/g8.bmp', 8); bmp(f'{out}/g16.bmp', 16); bmp(f'{out}/g24.bmp', 24); bmp(f'{out}/g32.bmp', 32)
pnm(f'{out}/g.pgm', 'pgm'); pnm(f'{out}/g.ppm', 'ppm'); pnm(f'{out}/g.pbm', 'pbm'); pnm(f'{out}/g16.pgm', 'pgm16')
tga(f'{out}/g24.tga', 24); tga(f'{out}/g32.tga', 32); tiff(f'{out}/g8.tif', 8); tiff(f'{out}/g16.tif', 16)
print('\n'.join(sorted(os.listdir(out))))
