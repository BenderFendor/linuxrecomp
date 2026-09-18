## 2026-09-18 15:11

**What happened:** python 3.14 struct.unpack requires the buffer to be exactly the format size

**Probable cause:** CPython 3.14 tightened struct.unpack: unpack('<I', 12 bytes) raises struct.error 'requires a buffer of 4 bytes'. Code that reads a whole record and unpacks a leading field looks correct and only fails on inputs that reach that path.

**Fix or workaround:** Use struct.unpack_from(fmt, buf, 0), or slice to exactly struct.calcsize(fmt) before unpacking.

---

## 2026-09-18 16:33

**What happened:** gdb is unusable on this host (libboost_regex.so.1.91.0 missing), so core dumps plus eu-stack/coredumpctl were the only way to unwind a Wine process crash

**Probable cause:** system gdb built against a newer boost than installed

**Fix or workaround:** use coredumpctl info / eu-stack for crash analysis; treat gdb as unavailable

---

## 2026-09-18 16:33

**What happened:** WINEDEBUG=+seh makes failing wine runs hang instead of reporting; +virtual is reliable

**Probable cause:** Wine's debug channels change timing and output volume

**Fix or workaround:** use WINEDEBUG=+virtual for memory questions, and avoid +seh

---

