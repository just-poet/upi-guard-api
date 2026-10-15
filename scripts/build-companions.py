"""Reproducible, credential-free extension/Windows distribution archives."""
import math
from pathlib import Path
import struct
import zlib
import zipfile

ROOT=Path(__file__).resolve().parent.parent

def icon(size):
    def segment(x,y,a,b):
        ax,ay=a;bx,by=b;dx=bx-ax;dy=by-ay;t=max(0,min(1,((x-ax)*dx+(y-ay)*dy)/(dx*dx+dy*dy)))
        return math.hypot(x-ax-t*dx,y-ay-t*dy)
    rows=[]
    for y in range(size):
        row=bytearray([0])
        for x in range(size):
            fx=(x+.5)/size;fy=(y+.5)/size
            if math.hypot(fx-.5,fy-.5)>.49:color=(0,0,0,0)
            else:
                color=(8,127,122,255)
                if min(segment(fx,fy,(.28,.49),(.45,.66)),segment(fx,fy,(.45,.66),(.74,.34)))<.045:color=(255,255,255,255)
            row.extend(color)
        rows.append(bytes(row))
    def chunk(kind,data):return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data)&0xffffffff)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!2I5B',size,size,8,6,0,0,0))+chunk(b'IDAT',zlib.compress(b''.join(rows),9))+chunk(b'IEND',b'')

icons=ROOT/'browser-extension/icons';icons.mkdir(exist_ok=True)
for size in (16,32,48,128):(icons/f'icon-{size}.png').write_bytes(icon(size))
image=icon(128);(ROOT/'windows-companion/icon.png').write_bytes(image)
(ROOT/'windows-companion/upi-guard.ico').write_bytes(struct.pack('<HHH',0,1,1)+struct.pack('<BBBBHHII',128,128,0,0,1,32,len(image),22)+image)
out=ROOT/'dist/downloads';out.mkdir(parents=True,exist_ok=True)
for folder,name in [('browser-extension','upi-guard-extension.zip'),('windows-companion','upi-guard-windows.zip')]:
    root=ROOT/folder
    with zipfile.ZipFile(out/name,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for path in sorted(root.rglob('*')):
            if not path.is_file() or '__pycache__' in path.parts or path.suffix in ('.pyc','.bin','.log'):continue
            data=path.read_bytes()
            if b'sk-proj-' in data:raise RuntimeError('A credential marker was found in a client package.')
            info=zipfile.ZipInfo(path.relative_to(root).as_posix(),date_time=(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o644<<16
            archive.writestr(info,data)
    print(f'Built {name}: {(out/name).stat().st_size:,} bytes')
