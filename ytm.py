"""ytminload maintenance tool (no dependencies, Python 3.8+).
<base> is an IPA, or a directory whose highest-version com.google.ios.youtube-<version>.ipa is used.

  python3 ytm.py check <base>                Check Tweak.mm hook targets and injection preconditions.
  python3 ytm.py dump  <base> <dir>          Write classes.txt, selrefs.txt and cstrings.txt for searching.
  python3 ytm.py pack  <base> <dylib> [out]  Inject the dylib and drop app extensions.
                                             Default out: ytminload-<version>.ipa next to base.
"""
import hashlib, os, plistlib, re, shutil, struct, sys, zipfile

DYLIB = '@rpath/ytminload.dylib'
RPATH = '@executable_path/Frameworks'
LOAD_CMDS = {0xC, 0x20, 0x80000018, 0x8000001F, 0x80000023}
TWEAK = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Tweak.mm')


def fail(msg):
    sys.exit(f'error: {msg}')


def latest(path):
    if os.path.isfile(path):
        return path
    names = os.listdir(path) if os.path.isdir(path) else []
    found = [(tuple(map(int, m.group(1).split('.'))), f) for f in names
             if (m := re.fullmatch(r'com\.google\.ios\.youtube-(\d+(?:\.\d+)*)\.ipa', f))]
    if not found:
        fail(f'no com.google.ios.youtube-<version>.ipa in {path}')
    return os.path.join(path, max(found)[1])


class MachO:
    """Load commands and ObjC metadata of a thin arm64 Mach-O, with chained fixups."""

    def __init__(self, m):
        self.m = m
        magic, cpu, _, self.filetype, ncmds, self.sizeofcmds = struct.unpack_from('<6I', m, 0)
        if magic != 0xFEEDFACF or cpu != 0x0100000C:
            fail('not a thin arm64 Mach-O')
        self.cmds, self.segs, self.sects = [], [], {}
        self.chained = self.cryptid = None
        off = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<2I', m, off)
            self.cmds.append((cmd, off, size))
            if cmd == 0x19:  # LC_SEGMENT_64
                name = m[off + 8:off + 24].split(b'\0')[0].decode()
                vmaddr, _, fileoff, filesize = struct.unpack_from('<4Q', m, off + 24)
                self.segs.append((name, vmaddr, fileoff, filesize))
                for i in range(self.u32(off + 64)):
                    s = off + 72 + i * 80
                    key = (m[s + 16:s + 32].split(b'\0')[0].decode(), m[s:s + 16].split(b'\0')[0].decode())
                    addr, ssize = struct.unpack_from('<2Q', m, s + 32)
                    self.sects[key] = (addr, ssize, self.u32(s + 48))
            elif cmd == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
                self.chained = self.u32(off + 8)
            elif cmd == 0x2C:  # LC_ENCRYPTION_INFO_64
                self.cryptid = self.u32(off + 16)
            off += size
        self.base = next(s[1] for s in self.segs if s[0] == '__TEXT')
        self.imports, self.ptr_format = [], None
        if self.chained:
            co = self.chained
            _, starts_off, imp_off, sym_off, imp_cnt, imp_fmt, _ = struct.unpack_from('<7I', m, co)
            so = co + starts_off
            for i in range(self.u32(so)):
                sio = self.u32(so + 4 + 4 * i)
                if sio:
                    self.ptr_format = struct.unpack_from('<H', m, so + sio + 6)[0]
                    break
            for i in range(imp_cnt):
                if imp_fmt == 1:
                    name_off = self.u32(co + imp_off + 4 * i) >> 9
                elif imp_fmt == 2:
                    name_off = self.u32(co + imp_off + 8 * i) >> 9
                else:
                    name_off = self.u64(co + imp_off + 16 * i) >> 32
                no = co + sym_off + name_off
                self.imports.append(m[no:m.find(b'\0', no)].decode('utf-8', 'replace'))

    def u32(self, o): return struct.unpack_from('<I', self.m, o)[0]
    def i32(self, o): return struct.unpack_from('<i', self.m, o)[0]
    def u64(self, o): return struct.unpack_from('<Q', self.m, o)[0]

    def lc_string(self, off, size):
        start = off + self.u32(off + 8)
        return self.m[start:off + size].split(b'\0')[0].decode()

    def v2o(self, va):
        for _, vmaddr, fileoff, filesize in self.segs:
            if vmaddr <= va < vmaddr + filesize:
                return fileoff + (va - vmaddr)
        return None

    def ptr(self, va_or_off, is_off=False):
        o = va_or_off if is_off else self.v2o(va_or_off)
        if o is None:
            return None
        v = self.u64(o)
        if v == 0:
            return 0
        if self.chained:
            if v >> 63:
                i = v & 0xFFFFFF
                return ('bind', self.imports[i] if i < len(self.imports) else '?')
            tgt = v & 0xFFFFFFFFF
            return tgt + self.base if self.ptr_format == 6 or tgt < self.base else tgt
        return v

    def cstr(self, va):
        if not isinstance(va, int):
            return None
        o = self.v2o(va)
        return None if o is None else self.m[o:self.m.find(b'\0', o)].decode('utf-8', 'replace')

    def sect(self, name):
        for seg in ('__DATA_CONST', '__DATA', '__AUTH_CONST'):
            if (seg, name) in self.sects:
                return self.sects[(seg, name)]
        return None

    def methods(self, va):
        if not isinstance(va, int) or va == 0 or self.v2o(va) is None:
            return []
        o = self.v2o(va)
        entflags, count = self.u32(o), self.u32(o + 4)
        es = entflags & 0xFFFC
        if es not in (12, 24) or count > 20000 or o + 8 + count * es > len(self.m):
            return [('<bad method list>', hex(va))]
        out = []
        for i in range(count):
            ea = va + 8 + i * es
            if entflags & 0x80000000:  # relative method list
                nva = ea + self.i32(o + 8 + i * es)
                sel = self.cstr(self.ptr(nva)) if entflags & 0x40000000 == 0 else self.cstr(nva)
                out.append((sel, self.cstr(ea + 4 + self.i32(o + 8 + i * es + 4))))
            else:
                out.append((self.cstr(self.ptr(ea)), self.cstr(self.ptr(ea + 8))))
        return out

    def _list(self, va, entry_size, fields):
        if not isinstance(va, int) or va == 0 or self.v2o(va) is None:
            return []
        o = self.v2o(va)
        es, count = self.u32(o), self.u32(o + 4)
        if es != entry_size or count > 20000:
            return []
        return [tuple(self.cstr(self.ptr(va + 8 + i * es + f)) for f in fields) for i in range(count)]

    def props(self, va): return self._list(va, 16, (0, 8))
    def ivars(self, va): return self._list(va, 32, (8, 16))

    def class_info(self, cva):
        if not isinstance(cva, int):
            return None
        data = self.ptr(cva + 32)
        if not isinstance(data, int):
            return None
        ro = data & ~7
        return dict(name=self.cstr(self.ptr(ro + 24)), sup=self.ptr(cva + 8), ro=ro, isa=self.ptr(cva))

    def class_name_of(self, p):
        if p is None or p == 0:
            return '-'
        if isinstance(p, tuple):
            return p[1].replace('_OBJC_CLASS_$_', '')
        ci = self.class_info(p)
        return ci['name'] if ci else '?'

    def dump_lines(self):
        lines = []
        cl = self.sect('__objc_classlist')
        for i in range(cl[1] // 8):
            ci = self.class_info(self.ptr(cl[2] + i * 8, is_off=True))
            if not ci:
                continue
            ro = ci['ro']
            lines.append(f"@class {ci['name']} : {self.class_name_of(ci['sup'])}")
            lines += [f'  - {s}  {t}' for s, t in self.methods(self.ptr(ro + 32))]
            meta = self.class_info(ci['isa'])
            if meta:
                lines += [f'  + {s}  {t}' for s, t in self.methods(self.ptr(meta['ro'] + 32))]
            lines += [f'  @property {n}  {a}' for n, a in self.props(self.ptr(ro + 64))]
            lines += [f'  ivar {n}  {t}' for n, t in self.ivars(self.ptr(ro + 48))]
        cat = self.sect('__objc_catlist')
        for i in range(cat[1] // 8 if cat else 0):
            cva = self.ptr(cat[2] + i * 8, is_off=True)
            if not isinstance(cva, int):
                continue
            lines.append(f'@category {self.class_name_of(self.ptr(cva + 8))} ({self.cstr(self.ptr(cva))})')
            lines += [f'  - {s}  {t}' for s, t in self.methods(self.ptr(cva + 16))]
            lines += [f'  + {s}  {t}' for s, t in self.methods(self.ptr(cva + 24))]
            lines += [f'  @property {n}  {a}' for n, a in self.props(self.ptr(cva + 40))]
        pl = self.sect('__objc_protolist')
        for i in range(pl[1] // 8 if pl else 0):
            pva = self.ptr(pl[2] + i * 8, is_off=True)
            if not isinstance(pva, int):
                continue
            lines.append(f'@protocol {self.cstr(self.ptr(pva + 8))}')
            for k, lab in ((24, '-'), (32, '+'), (40, '-?'), (48, '+?')):
                lines += [f'  {lab} {s}  {t}' for s, t in self.methods(self.ptr(pva + k))]
        return lines

    def selrefs(self):
        sr = self.sect('__objc_selrefs')
        return [(sr[0] + i * 8, self.cstr(self.ptr(sr[2] + i * 8, is_off=True))) for i in range(sr[1] // 8)]

    def load_info(self):
        """(rpaths, loaded dylibs, end of load commands, file offset of the first section)"""
        rpaths = [self.lc_string(o, s) for c, o, s in self.cmds if c == 0x8000001C]
        loads = [self.lc_string(o, s) for c, o, s in self.cmds if c in LOAD_CMDS]
        first = min(self.u32(o + 72 + i * 80 + 48) or len(self.m)
                    for c, o, _ in self.cmds if c == 0x19 for i in range(self.u32(o + 64)))
        return rpaths, loads, 32 + self.sizeofcmds, first


def objc_index(lines):
    """classes.txt lines to (per-class '-sel'/'+sel' sets, superclasses, protocol names)"""
    members, supers, protocols, cur = {}, {}, set(), None
    for line in lines:
        if line.startswith('@class '):
            p = line.split()
            cur = p[1]
            supers[cur] = p[3]
            members.setdefault(cur, set())
        elif line.startswith('@category '):
            cur = line.split()[1]
            members.setdefault(cur, set())
        elif line.startswith('@protocol '):
            protocols.add(line.split()[1])
            cur = None
        elif cur and line[:4] in ('  - ', '  + '):
            members[cur].add(line[2] + line.split()[1])
        elif cur and line.startswith('  @property '):
            members[cur].add('-' + line.split()[1])
    return members, supers, protocols


def tweak_targets():
    """Tweak.mm hook rows [(group, class, selector, is_class_method)] and kNeeds [(class, selector)]"""
    row = re.compile(r'\{"(\w+)",\s*"([^"]+)",\s*\(IMP\)\w+(?:,\s*(true|false))?(?:,\s*&\w+)?\}')
    need = re.compile(r'\{"(\w+)",\s*"([^"]+)"\}')
    group_re = re.compile(r'//\s*([ABCIL])\.\s')
    rows, needs, group = [], [], '?'
    for line in open(TWEAK, encoding='utf-8'):
        g = group_re.search(line)
        if g:
            group = g.group(1)
        r = row.search(line)
        if r:
            rows.append((group, r.group(1), r.group(2), r.group(3) == 'true'))
        elif need.search(line):
            needs.append(need.search(line).groups())
    return rows, needs


def open_ipa(path):
    z = zipfile.ZipFile(path)
    plist = next(n for n in z.namelist()
                 if n.startswith('Payload/') and n.endswith('.app/Info.plist') and n.count('/') == 2)
    root = plist[:-len('Info.plist')]
    info = plistlib.loads(z.read(plist))
    return z, root, info, root + info['CFBundleExecutable']


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def check(ipa):
    ipa = latest(ipa)
    z, root, info, main = open_ipa(ipa)
    mo = MachO(z.read(main))
    print(ipa)
    print(f"YouTube {info.get('CFBundleShortVersionString')} ({info.get('CFBundleIdentifier')})  "
          f"MinimumOSVersion {info.get('MinimumOSVersion')}  sha256 {sha256(ipa)}")
    fails = warns = 0

    def report(ok, text, warn=False):
        nonlocal fails, warns
        if not ok:
            fails += not warn
            warns += warn
        print(f"  {'OK  ' if ok else 'WARN' if warn else 'FAIL'} {text}")

    rpaths, loads, end, first = mo.load_info()
    print('[injection preconditions]')
    report(mo.cryptid == 0, f'main binary decrypted (cryptid={mo.cryptid})')
    report(RPATH in rpaths, f'rpath {RPATH}')
    report(DYLIB not in loads, 'not injected yet')
    report(first - end >= 48, f'header free space {first - end} bytes (needs 48)')
    report('audio' in info.get('UIBackgroundModes', []), 'UIBackgroundModes has audio (B background playback, C PiP)')

    members, supers, protocols = objc_index(mo.dump_lines())
    called = {s for _, s in mo.selrefs()}

    def lookup(cls, key):
        seen = set()
        while cls in members and cls not in seen:
            seen.add(cls)
            if key in members[cls]:
                return True
            cls = supers.get(cls)
        return None if cls not in members and cls not in (None, '-') else False

    def target(cls, sel, meta, need_call):
        if cls not in members:
            return False, 'class missing' + (' (only a protocol)' if cls in protocols else '')
        found = lookup(cls, ('+' if meta else '-') + sel)
        if found is None:
            return None, 'inherited from a system class, cannot verify'
        if not found:
            other = lookup(cls, ('-' if meta else '+') + sel)
            return False, 'method missing' + (' (+/- kind is reversed)' if other else '')
        if need_call and sel not in called:
            return None, 'app code never calls it (selrefs), may have no effect'
        return True, ''

    rows, needs = tweak_targets()
    print(f'[hook rows: {len(rows)}]')
    if not rows:
        report(False, 'no hook rows parsed from Tweak.mm (check the row format)')
    groups = {}
    for group, cls, sel, meta in rows:
        ok, why = target(cls, sel, meta, True)
        groups.setdefault(group, []).append(ok)
        if ok is not True:
            report(False, f"{group} {cls} {'+' if meta else '-'}{sel}: {why}", warn=ok is None)
    for group, oks in groups.items():
        print(f'  {group}: {sum(o is True for o in oks)}/{len(oks)}')
    print(f'[kNeeds getters for filter rows: {len(needs)}]')
    bad = [(c, s, why) for c, s in needs for ok, why in [target(c, s, False, False)] if ok is not True]
    for c, s, why in bad:
        report(False, f'{c} -{s}: {why} (if any is missing, no filter row is installed)')
    if not bad:
        print(f'  {len(needs)}/{len(needs)}')
    print(f'result: FAIL {fails}, WARN {warns}')
    return 1 if fails else 0


def dump(ipa, outdir):
    z, _, _, main = open_ipa(latest(ipa))
    mo = MachO(z.read(main))
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, 'classes.txt'), 'w', encoding='utf-8') as w:
        w.write('\n'.join(mo.dump_lines()))
    with open(os.path.join(outdir, 'selrefs.txt'), 'w', encoding='utf-8') as w:
        w.writelines(f'{a:#x} {s}\n' for a, s in mo.selrefs())
    cs = mo.sects.get(('__TEXT', '__cstring'))
    with open(os.path.join(outdir, 'cstrings.txt'), 'w', encoding='utf-8') as w:
        o, stop = cs[2], cs[2] + cs[1]
        while o < stop:
            e = mo.m.find(b'\0', o, stop)
            if e < 0:
                break
            if e > o:
                w.write(f'{cs[0] + (o - cs[2]):#x} ' + mo.m[o:e].decode('utf-8', 'replace').replace('\n', '\\n') + '\n')
            o = e + 1
    print(f'written classes.txt, selrefs.txt, cstrings.txt to {outdir}')
    return 0


def entry(name, like, compress_type=None, external_attr=None):
    z = zipfile.ZipInfo(name, like.date_time)
    z.create_system = like.create_system
    z.compress_type = like.compress_type if compress_type is None else compress_type
    z.external_attr = like.external_attr if external_attr is None else external_attr
    z.file_size = like.file_size
    return z


def pack(ipa, dylib_path, out=None):
    ipa = latest(ipa)
    with open(dylib_path, 'rb') as f:
        dylib = f.read()
    d = MachO(dylib)
    ids = [d.lc_string(o, s) for c, o, s in d.cmds if c == 0xD]  # LC_ID_DYLIB
    if d.filetype != 6 or ids != [DYLIB]:
        fail(f'dylib must be an MH_DYLIB with install name {DYLIB} (got {ids})')

    with zipfile.ZipFile(ipa) as zin:
        _, root, info, main = open_ipa(ipa)
        out = out or os.path.join(os.path.dirname(ipa), f"ytminload-{info.get('CFBundleShortVersionString')}.ipa")
        if os.path.abspath(ipa) == os.path.abspath(out):
            fail('output must differ from the base IPA')
        m = zin.read(main)
        mo = MachO(m)
        rpaths, loads, end, first = mo.load_info()
        name = DYLIB.encode() + b'\0'
        size = (24 + len(name) + 7) & ~7
        if RPATH not in rpaths:
            fail(f'main binary has no rpath {RPATH}')
        if DYLIB in loads:
            fail('ytminload is already injected')
        if end + size > first or any(m[end:end + size]):
            fail(f'not enough header space ({first - end} bytes, needs {size})')
        patched = bytearray(m)
        # dylib_command: name at offset 24, timestamp and versions 0
        patched[end:end + size] = struct.pack('<6I', 0xC, size, 24, 0, 0, 0) + name.ljust(size - 24, b'\0')
        struct.pack_into('<2I', patched, 16, len(mo.cmds) + 1, mo.sizeofcmds + size)

        skip = (root + 'PlugIns/', root + 'Extensions/')
        dropped = set()
        with zipfile.ZipFile(out + '.tmp', 'w') as zout:
            for item in zin.infolist():
                if item.filename.startswith(skip):
                    parts = item.filename.split('/')
                    if len(parts) > 4:
                        dropped.add('/'.join(parts[2:4]))
                elif item.filename == main:
                    zout.writestr(entry(item.filename, item), bytes(patched))
                else:
                    with zin.open(item) as src, zout.open(entry(item.filename, item), 'w') as dst:
                        shutil.copyfileobj(src, dst, 1 << 20)
            dylib_item = entry(root + 'Frameworks/ytminload.dylib', zin.getinfo(main),
                               zipfile.ZIP_DEFLATED, 0o100755 << 16)
            dylib_item.file_size = len(dylib)
            zout.writestr(dylib_item, dylib)
    os.replace(out + '.tmp', out)
    print(f"YouTube {info.get('CFBundleShortVersionString')}  {info.get('CFBundleIdentifier')}")
    print(f'added    LC_LOAD_DYLIB {DYLIB}, {root}Frameworks/ytminload.dylib')
    print(f"dropped  {len(dropped)} extensions: {', '.join(sorted(dropped)) or '-'}")
    print(f'base     {sha256(ipa)}  {ipa}')
    print(f'output   {sha256(out)}  {out}')
    return 0


if __name__ == '__main__':
    cmd, args = (sys.argv[1], sys.argv[2:]) if len(sys.argv) > 1 else (None, [])
    if cmd == 'check' and len(args) == 1:
        sys.exit(check(*args))
    if cmd == 'dump' and len(args) == 2:
        sys.exit(dump(*args))
    if cmd == 'pack' and len(args) in (2, 3):
        sys.exit(pack(*args))
    sys.exit(__doc__)
