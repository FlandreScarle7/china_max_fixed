import ipaddress, struct

class MMDB:
    MARKER = b"\xab\xcd\xefMaxMind.com"

    def __init__(self, path):
        self.buf = open(path, "rb").read()
        i = self.buf.rfind(self.MARKER)
        if i < 0:
            raise ValueError("不是 MMDB 文件")
        meta_start = i + len(self.MARKER)
        self.meta, _ = self._decode(meta_start, meta_start)
        self.node_count = self.meta["node_count"]
        self.record_size = self.meta["record_size"]
        self.ip_version = self.meta["ip_version"]
        self.node_bytes = self.record_size * 2 // 8
        self.tree_size = self.node_count * self.node_bytes
        self.data_start = self.tree_size + 16
        self._memo = {}

    def _size(self, off):
        ctrl = self.buf[off]; off += 1
        t = ctrl >> 5
        if t == 0:
            t = self.buf[off] + 7; off += 1
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + self.buf[off]; off += 1
        elif size == 30:
            size = 285 + int.from_bytes(self.buf[off:off+2], "big"); off += 2
        elif size == 31:
            size = 65821 + int.from_bytes(self.buf[off:off+3], "big"); off += 3
        return t, size, off, ctrl

    def _decode(self, off, base):
        t, size, off, ctrl = self._size(off)
        if t == 1:
            ps = (ctrl >> 3) & 0x3
            v = ctrl & 0x7
            if ps == 0:
                p = (v << 8) | self.buf[off]; off += 1
            elif ps == 1:
                p = (v << 16) | int.from_bytes(self.buf[off:off+2], "big"); off += 2; p += 2048
            elif ps == 2:
                p = (v << 24) | int.from_bytes(self.buf[off:off+3], "big"); off += 3; p += 526336
            else:
                p = int.from_bytes(self.buf[off:off+4], "big"); off += 4
            val, _ = self._decode(base + p, base)
            return val, off
        if t == 2:
            return self.buf[off:off+size].decode("utf8", "replace"), off + size
        if t == 3:
            return struct.unpack(">d", self.buf[off:off+8])[0], off + 8
        if t == 4:
            return self.buf[off:off+size], off + size
        if t in (5, 6, 9, 10):
            return int.from_bytes(self.buf[off:off+size], "big"), off + size
        if t == 7:
            d = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                d[k] = v
            return d, off
        if t == 8:
            n = int.from_bytes(self.buf[off:off+size], "big", signed=True) if size else 0
            return n, off + size
        if t == 11:
            a = []
            for _ in range(size):
                v, off = self._decode(off, base)
                a.append(v)
            return a, off
        if t == 14:
            return bool(size), off
        if t == 15:
            return struct.unpack(">f", self.buf[off:off+4])[0], off + 4
        return None, off + size

    def _rec(self, node, side):
        b = self.buf
        o = node * self.node_bytes
        rs = self.record_size
        if rs == 24:
            return int.from_bytes(b[o+3*side:o+3*side+3], "big")
        if rs == 28:
            if side == 0:
                return ((b[o+3] & 0xF0) << 20) | int.from_bytes(b[o:o+3], "big")
            return ((b[o+3] & 0x0F) << 24) | int.from_bytes(b[o+4:o+7], "big")
        if rs == 32:
            return int.from_bytes(b[o+4*side:o+4*side+4], "big")
        raise ValueError(f"不支持 record_size={rs}")

    def get(self, ip):
        a = ipaddress.ip_address(ip)
        if a.version == 4 and self.ip_version == 6:
            bits = 96 + 32
            val = int(a) | (0 << 32)
            packed = b"\x00" * 12 + a.packed
        else:
            packed = a.packed
            bits = len(packed) * 8
        node = 0
        for i in range(bits):
            if node >= self.node_count:
                break
            byte = packed[i >> 3]
            side = (byte >> (7 - (i & 7))) & 1
            node = self._rec(node, side)
        if node == self.node_count:
            return None
        if node > self.node_count:
            off = self.tree_size + node - self.node_count
            v, _ = self._decode(off, self.data_start)
            return v
        return None

    def is_cn(self, ip):

        v = self._memo.get(ip)
        if v is None:
            d = self.get(ip)
            c = d.get("country") if isinstance(d, dict) else None
            v = isinstance(c, dict) and c.get("iso_code") == "CN"
            self._memo[ip] = v
        return v

    def country(self, ip):
        d = self.get(ip)
        if not d:
            return None
        for k in ("country", "registered_country"):
            if isinstance(d.get(k), dict) and d[k].get("iso_code"):
                return d[k]["iso_code"]
        return "?"
