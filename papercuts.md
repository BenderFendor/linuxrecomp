## 2026-09-18 15:11

**What happened:** python 3.14 struct.unpack requires the buffer to be exactly the format size

**Probable cause:** CPython 3.14 tightened struct.unpack: unpack('<I', 12 bytes) raises struct.error 'requires a buffer of 4 bytes'. Code that reads a whole record and unpacks a leading field looks correct and only fails on inputs that reach that path.

**Fix or workaround:** Use struct.unpack_from(fmt, buf, 0), or slice to exactly struct.calcsize(fmt) before unpacking.

---

