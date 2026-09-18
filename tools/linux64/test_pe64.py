"""Checks for the PE32+ reader, function recovery and spec emission.

Run: py -3.11 tools/linux64/test_pe64.py   (or: python -m tools.linux64 selftest)

Part 1 builds a synthetic PE32+ image in memory and asserts exact parse
results, so it runs anywhere with no compiler and no fixture binaries. Part 2
checks the real MinGW fixtures under ``work/linux64/fixtures`` when they are
present (``./scripts/build-win64-fixtures.sh``); it reports SKIP when they are
not, rather than passing silently.

The synthetic image deliberately includes the awkward cases: an ordinal import
next to a name import, a zero RUNTIME_FUNCTION slot, a section whose
VirtualSize is smaller than SizeOfRawData, a BSS section, an ABSOLUTE
relocation that must be skipped, and a TLS callback that is not first.
"""

from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import functions as fn
import schema_check
import spec as spec_mod
from pe64 import PE64Image, PEFormatError

IMAGE_BASE = 0x140000000
FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000

TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
BSS_RVA = 0x3000
ODD_RVA = 0x4000

RDATA_FILE = 0x800
ODD_FILE = 0x1000
FILE_SIZE = 0x1200

KERNEL32_STRING_RVA = 0x2340
ORDINAL_STRING_RVA = 0x2350
HINT_NAME_RVA = 0x2360
EXPORT_NAME_RVA = 0x2334
EXPORT_DLL_NAME_RVA = 0x2370
ILT_RVA = 0x2040
IAT_RVA = 0x2080
ORDINAL_ILT_RVA = 0x2050
ORDINAL_IAT_RVA = 0x2090
PDATA_RVA = 0x2100
UNWIND0_RVA = 0x2140
UNWIND1_RVA = 0x2150
TLS_RVA = 0x2180
TLS_CALLBACKS_RVA = 0x2200
RELOC_RVA = 0x2280
EXPORT_RVA = 0x2300
EXPORT_EAT_RVA = 0x2328
EXPORT_ENPT_RVA = 0x232C
EXPORT_ORDINALS_RVA = 0x2330
HANDLER_RVA = 0x1300

SECTION_COUNT = 4


def _write_section_header(buf: bytearray, index: int, name: str, rva: int,
                          virtual_size: int, raw_offset: int, raw_size: int,
                          characteristics: int) -> None:
    off = 0x188 + index * 40
    buf[off:off + 8] = name.encode().ljust(8, b"\x00")
    struct.pack_into("<IIII", buf, off + 8, virtual_size, rva, raw_size, raw_offset)
    struct.pack_into("<I", buf, off + 36, characteristics)


def synth_image() -> bytes:
    buf = bytearray(FILE_SIZE)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)

    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x84,
                     0x8664, SECTION_COUNT, 0x5F000000, 0, 0, 0xF0, 0x0022)

    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x20B)
    buf[opt + 2] = 14
    buf[opt + 3] = 0
    struct.pack_into("<IIIII", buf, opt + 4, 0x400, 0x800, 0, TEXT_RVA, TEXT_RVA)
    struct.pack_into("<Q", buf, opt + 24, IMAGE_BASE)
    struct.pack_into("<II", buf, opt + 32, SECTION_ALIGN, FILE_ALIGN)
    struct.pack_into("<HHHHHH", buf, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", buf, opt + 52, 0, 0x5000, 0x400)
    struct.pack_into("<HH", buf, opt + 68, 3, 0x0140)  # console, dynamic base + NX
    struct.pack_into("<QQQQII", buf, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000,
                     0, 16)

    directories = {
        0: (EXPORT_RVA, 40),
        1: (0x2000, 60),
        3: (PDATA_RVA, 36),
        5: (RELOC_RVA, 16),
        9: (TLS_RVA, 40),
        12: (IAT_RVA, 0x20),
    }
    for index in range(16):
        rva, size = directories.get(index, (0, 0))
        struct.pack_into("<II", buf, opt + 112 + index * 8, rva, size)

    _write_section_header(buf, 0, ".text", TEXT_RVA, 0x400, 0x400, 0x400,
                          0x60000020)
    _write_section_header(buf, 1, ".rdata", RDATA_RVA, 0x800, RDATA_FILE, 0x800,
                          0x40000040)
    _write_section_header(buf, 2, ".bss", BSS_RVA, 0x100, 0, 0, 0xC0000080)
    # VirtualSize 0 with real raw data: the loader still maps the raw tail.
    _write_section_header(buf, 3, ".odd", ODD_RVA, 0, ODD_FILE, 0x200, 0x40000040)

    # .text: mov rax, 42; ret at the entry point, and a second stub at 0x1020.
    buf[0x400:0x408] = b"\x48\xc7\xc0\x2a\x00\x00\x00\xc3"
    buf[0x420:0x423] = b"\x31\xc0\xc3"
    buf[ODD_FILE:ODD_FILE + 0x200] = b"\xAA" * 0x200

    # Import descriptors: one name import, one ordinal import.
    struct.pack_into("<IIIII", buf, RDATA_FILE, ILT_RVA, 0, 0,
                     KERNEL32_STRING_RVA, IAT_RVA)
    struct.pack_into("<IIIII", buf, RDATA_FILE + 20, ORDINAL_ILT_RVA, 0, 0,
                     ORDINAL_STRING_RVA, ORDINAL_IAT_RVA)
    struct.pack_into("<IIIII", buf, RDATA_FILE + 40, 0, 0, 0, 0, 0)

    # Each DLL gets its own ILT block and a mirrored IAT block, 8 bytes per
    # entry, terminated by a zero thunk -- the PE32+ shape.
    iat_bias = IAT_RVA - ILT_RVA
    for base_rva, entries in ((ILT_RVA, [HINT_NAME_RVA, 0]),
                              (ORDINAL_ILT_RVA, [0x8000000000000123, 0])):
        for index, value in enumerate(entries):
            struct.pack_into("<Q", buf, RDATA_FILE + (base_rva - RDATA_RVA) + index * 8,
                             value)
            struct.pack_into("<Q", buf,
                             RDATA_FILE + (base_rva + iat_bias - RDATA_RVA) + index * 8,
                             value)

    def rdata(offset: int) -> int:
        return RDATA_FILE + (offset - RDATA_RVA)

    buf[rdata(KERNEL32_STRING_RVA):rdata(KERNEL32_STRING_RVA) + 13] = b"KERNEL32.dll\x00"
    buf[rdata(ORDINAL_STRING_RVA):rdata(ORDINAL_STRING_RVA) + 12] = b"ORDINAL.dll\x00"
    struct.pack_into("<H", buf, rdata(HINT_NAME_RVA), 0x0100)
    buf[rdata(HINT_NAME_RVA) + 2:rdata(HINT_NAME_RVA) + 8] = b"Sleep\x00"

    # Exception directory: two real entries plus a zero slot to be skipped.
    struct.pack_into("<III", buf, rdata(PDATA_RVA), TEXT_RVA, TEXT_RVA + 0x10,
                     UNWIND0_RVA)
    struct.pack_into("<III", buf, rdata(PDATA_RVA) + 12, TEXT_RVA + 0x20,
                     TEXT_RVA + 0x40, UNWIND1_RVA)
    struct.pack_into("<III", buf, rdata(PDATA_RVA) + 24, 0, 0, 0)

    # Unwind info: plain prolog, then one with an exception handler.
    buf[rdata(UNWIND0_RVA):rdata(UNWIND0_RVA) + 4] = bytes([0x01, 0x04, 0x00, 0x00])
    struct.pack_into("<BBBB", buf, rdata(UNWIND1_RVA), 0x09, 0x08, 0x02, 0x00)
    struct.pack_into("<HH", buf, rdata(UNWIND1_RVA) + 4, 0x0000, 0x0000)
    struct.pack_into("<I", buf, rdata(UNWIND1_RVA) + 8, HANDLER_RVA)

    # TLS: raw data in .bss, callbacks in .rdata.
    struct.pack_into("<QQQQII", buf, rdata(TLS_RVA),
                     IMAGE_BASE + BSS_RVA, IMAGE_BASE + BSS_RVA + 0x10,
                     IMAGE_BASE + BSS_RVA + 0x10,
                     IMAGE_BASE + TLS_CALLBACKS_RVA, 0x20, 0)
    struct.pack_into("<QQ", buf, rdata(TLS_CALLBACKS_RVA),
                     IMAGE_BASE + TEXT_RVA, 0)

    # Relocations: two DIR64, one HIGHLOW, one ABSOLUTE that must be dropped.
    struct.pack_into("<II", buf, rdata(RELOC_RVA), TEXT_RVA, 8 + 4 * 2)
    entries = (0xA010, 0x3004, 0x0000, 0xA018)
    for index, value in enumerate(entries):
        struct.pack_into("<H", buf, rdata(RELOC_RVA) + 8 + index * 2, value)

    # Export directory with one named function.
    struct.pack_into("<IIHHIIIIIII", buf, rdata(EXPORT_RVA), 0, 0, 0, 0,
                     EXPORT_DLL_NAME_RVA, 1, 1, 1, EXPORT_EAT_RVA,
                     EXPORT_ENPT_RVA, EXPORT_ORDINALS_RVA)
    struct.pack_into("<I", buf, rdata(EXPORT_EAT_RVA), TEXT_RVA)
    struct.pack_into("<I", buf, rdata(EXPORT_ENPT_RVA), EXPORT_NAME_RVA)
    struct.pack_into("<H", buf, rdata(EXPORT_ORDINALS_RVA), 0)
    buf[rdata(EXPORT_NAME_RVA):rdata(EXPORT_NAME_RVA) + 12] = b"exported_fn\x00"
    buf[rdata(EXPORT_DLL_NAME_RVA):rdata(EXPORT_DLL_NAME_RVA) + 12] = b"fixture.dll\x00"

    return bytes(buf)


def test_headers_and_sections() -> None:
    image = PE64Image.from_bytes(synth_image(), "synth.exe")
    assert image.is_amd64 and image.machine_name == "x86-64"
    assert image.image_base == IMAGE_BASE
    assert image.entrypoint_rva == TEXT_RVA
    assert image.entrypoint_va == IMAGE_BASE + TEXT_RVA
    assert image.subsystem_name == "windows-console"
    assert not image.is_dll
    assert image.has_dynamic_base and not image.is_large_address_aware
    assert image.va(TEXT_RVA) == IMAGE_BASE + TEXT_RVA
    assert image.rva_of(IMAGE_BASE + TEXT_RVA) == TEXT_RVA
    assert image.num_sections == SECTION_COUNT

    text, rdata, bss, odd = image.sections
    assert (text.name, rdata.name, bss.name, odd.name) == (".text", ".rdata", ".bss", ".odd")
    assert text.is_code and text.is_executable and not text.is_writable
    assert bss.is_writable and not bss.has_raw_data
    assert text.mapped_size == 0x400
    # VirtualSize smaller than SizeOfRawData: the raw tail is still mapped.
    assert odd.virtual_size == 0 and odd.mapped_size == 0x200
    assert odd.contains_rva(ODD_RVA + 0x1FF)
    assert not odd.contains_rva(ODD_RVA + 0x200)
    assert image.rva_to_offset(ODD_RVA + 0x100) == ODD_FILE + 0x100
    assert image.rva_to_offset(ODD_RVA + 0x300) is None      # past raw data
    assert image.rva_to_offset(BSS_RVA + 0x10) is None       # zero fill
    assert image.rva_to_offset(0x900000) is None             # unmapped
    assert image.read_rva(TEXT_RVA, 8) == b"\x48\xc7\xc0\x2a\x00\x00\x00\xc3"
    assert image.section_for_rva(TEXT_RVA).name == ".text"
    assert len(image.code_sections) == 1 and image.code_ranges() == ((TEXT_RVA, TEXT_RVA + 0x400),)


def test_directories_and_imports() -> None:
    image = PE64Image.from_bytes(synth_image(), "synth.exe")
    assert image.directory(1).present and image.directory(2).present is False

    imports = image.imports
    assert len(imports) == 2, imports
    sleep, ordinal = imports
    assert (sleep.dll, sleep.name, sleep.hint) == ("KERNEL32.dll", "Sleep", 0x0100)
    assert sleep.iat_rva == IAT_RVA and sleep.ilt_rva == ILT_RVA
    assert ordinal.dll == "ORDINAL.dll" and ordinal.name is None and ordinal.ordinal == 0x123
    assert ordinal.iat_rva == ORDINAL_IAT_RVA
    assert ordinal.label == "ordinal_291"
    # PE32+ thunks are 8 bytes; a 4-byte walk finds one import per DLL instead.
    assert ORDINAL_IAT_RVA - IAT_RVA == 0x10
    assert sleep.iat_rva % 8 == 0 and ordinal.iat_rva % 8 == 0
    assert image.import_dlls == ("KERNEL32.dll", "ORDINAL.dll")


def test_exports_and_relocations() -> None:
    image = PE64Image.from_bytes(synth_image(), "synth.exe")
    exports = image.exports
    assert len(exports) == 1
    assert exports[0].name == "exported_fn" and exports[0].rva == TEXT_RVA
    assert exports[0].ordinal == 1 and exports[0].forwarder is None

    relocations = image.relocations
    assert [(r.kind, r.rva) for r in relocations] == [
        ("dir64", TEXT_RVA + 0x10),
        ("highlow", TEXT_RVA + 0x04),
        ("dir64", TEXT_RVA + 0x18),
    ], relocations
    assert image.relocation_counts() == {"dir64": 2, "highlow": 1}


def test_tls_and_unwind() -> None:
    image = PE64Image.from_bytes(synth_image(), "synth.exe")
    tls = image.tls
    assert tls is not None
    assert (tls.raw_start_va, tls.raw_end_va) == (IMAGE_BASE + BSS_RVA,
                                                  IMAGE_BASE + BSS_RVA + 0x10)
    assert tls.raw_size == 0x10 and tls.zero_fill_size == 0x20
    assert tls.callbacks == (IMAGE_BASE + TEXT_RVA,)

    entries = image.runtime_functions
    assert len(entries) == 2, entries           # the zero slot is skipped
    assert (entries[0].begin_rva, entries[0].end_rva) == (TEXT_RVA, TEXT_RVA + 0x10)
    assert entries[0].size == 0x10

    plain = image.unwind_info(UNWIND0_RVA)
    assert (plain.version, plain.flags, plain.prolog_size, plain.code_slots) == (1, 0, 4, 0)
    assert not plain.has_exception_handler and plain.handler_rva is None

    handled = image.unwind_info(UNWIND1_RVA)
    assert (handled.version, handled.flags, handled.prolog_size) == (1, 1, 8)
    assert handled.code_slots == 2 and handled.has_exception_handler
    assert handled.handler_rva == HANDLER_RVA
    assert not handled.is_chained


def test_rejections() -> None:
    pe32 = bytearray(synth_image())
    struct.pack_into("<H", pe32, 0x98, 0x10B)
    try:
        PE64Image.from_bytes(bytes(pe32), "hard32.exe")
    except PEFormatError as exc:
        assert "PE32" in str(exc) and "32-bit pipeline" in str(exc), exc
    else:
        raise AssertionError("accepted a PE32 optional header")

    for name, blob in (("empty", b""), ("notpe", b"ZZ" + bytes(200)),
                       ("mzonly", b"MZ" + bytes(200))):
        try:
            PE64Image.from_bytes(blob, f"{name}.bin")
        except PEFormatError:
            pass
        else:
            raise AssertionError(f"accepted {name} as a PE32+ image")


def test_function_recovery() -> None:
    image = PE64Image.from_bytes(synth_image(), "synth.exe")
    functions, notes = fn.recover_functions(image)
    assert [(f.start_rva, f.end_rva, f.source) for f in functions] == [
        (TEXT_RVA, TEXT_RVA + 0x10, "pdata"),
        (TEXT_RVA + 0x20, TEXT_RVA + 0x40, "pdata"),
    ], functions
    assert functions[0].name == "exported_fn"     # export name attached to the pdata range
    assert functions[1].name is None
    assert notes == set()
    assert fn.validate_ranges(image, functions) == ()

    # An external start inside a pdata range is a split, not a function.
    bounds = ((IMAGE_BASE + TEXT_RVA + 0x08, IMAGE_BASE + TEXT_RVA + 0x10),
              (IMAGE_BASE + TEXT_RVA + 0x80, IMAGE_BASE + TEXT_RVA + 0x90))
    merged, notes = fn.recover_functions(image, bounds)
    assert [f.source for f in merged] == ["pdata", "pdata", "ghidra"]
    assert merged[2].start_rva == TEXT_RVA + 0x80
    assert notes == {"split_starts"}
    assert fn.validate_ranges(image, merged) == ()
    stats = fn.summarize(merged)
    assert stats == {"count": 3, "by_source": {"pdata": 2, "ghidra": 1},
                     "unknown_end": 0, "covered_bytes": 0x10 + 0x20 + 0x10}

    # A start only inside an executable section is legal; outside it is reported.
    bad = (fn.Function(start_rva=BSS_RVA + 4, end_rva=BSS_RVA + 8, source="ghidra"),
           fn.Function(start_rva=TEXT_RVA, end_rva=TEXT_RVA + 0x10, source="pdata"),
           fn.Function(start_rva=TEXT_RVA + 0x4, end_rva=TEXT_RVA + 0x8, source="ghidra"))
    problems = fn.validate_ranges(image, sorted(bad, key=lambda f: f.start_rva))
    assert any("outside executable" in p for p in problems), problems
    assert any("overlaps" in p for p in problems), problems


def test_bounds_csv(tmp: str) -> None:
    path = os.path.join(tmp, "bounds.csv")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# start,end\n140001100,140001130\n\n140001200,140001240\n")
    assert fn.load_bounds_csv(path) == ((0x140001100, 0x140001130),
                                        (0x140001200, 0x140001240))
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("140001240,140001200\n")
    try:
        fn.load_bounds_csv(path)
    except ValueError as exc:
        assert "end < start" in str(exc), exc
    else:
        raise AssertionError("accepted a reversed bounds row")


def test_spec_document(tmp: str) -> None:
    image = PE64Image.from_bytes(synth_image(), "synth.exe")
    functions, notes = fn.recover_functions(image)
    problems = fn.validate_ranges(image, functions)
    document = spec_mod.build_spec(image, functions, notes=notes, problems=problems)

    assert document["format"] == "linuxrecomp-spec-v1"
    assert document["arch"] == "amd64"
    assert document["image"]["entrypoint"] == IMAGE_BASE + TEXT_RVA
    assert document["image"]["image_base"] == IMAGE_BASE
    assert document["sections"][3]["mapped_size"] == 0x200
    assert [s["name"] for s in document["sections"]] == [".text", ".rdata", ".bss", ".odd"]
    assert document["functions"][0] == {"start": IMAGE_BASE + TEXT_RVA,
                                        "end": IMAGE_BASE + TEXT_RVA + 0x10,
                                        "name": "exported_fn", "source": "pdata"}
    assert document["imports"][0]["iat_va"] == IMAGE_BASE + IAT_RVA
    assert document["unwind"][1]["handler_va"] == IMAGE_BASE + HANDLER_RVA
    assert document["tls"]["callbacks"] == [IMAGE_BASE + TEXT_RVA]
    assert document["recon"]["relocation_counts"] == {"dir64": 2, "highlow": 1}
    assert document["generator"]["source_sha256"] == image.sha256

    spec_mod.validate_spec(document)          # the shipped schema must accept it

    path = os.path.join(tmp, "program.json")
    spec_mod.write_spec(document, path)
    assert spec_mod.load_spec(path) == document

    # The schema has to reject real breakage, not just accept good input.
    import copy
    for mutate, why in (
        (lambda d: d.update(format="something-else"), "wrong format"),
        (lambda d: d["functions"][0].update(source="guessed"), "unknown source"),
        (lambda d: d["functions"][0].pop("start"), "missing start"),
        (lambda d: d["functions"][0].update(end="lots"), "non-integer end"),
        (lambda d: d["image"].update(entrypoint=-1), "negative entrypoint"),
        (lambda d: d.pop("imports"), "missing imports"),
        (lambda d: d["sections"][0].pop("flags"), "missing section flags"),
    ):
        broken = copy.deepcopy(document)
        mutate(broken)
        try:
            spec_mod.validate_spec(broken)
        except schema_check.SchemaError:
            pass
        else:
            raise AssertionError(f"schema accepted {why}")


def _fixture_dir() -> str:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, "work", "linux64", "fixtures")


def test_fixtures() -> int:
    fixture_dir = _fixture_dir()
    targets = {"return42.exe": ("Sleep", "TlsGetValue", "VirtualProtect"),
               "kernel32.exe": ("GetTickCount64", "Sleep")}
    missing = [name for name in targets if not os.path.exists(os.path.join(fixture_dir, name))]
    if missing:
        print(f"fixtures: SKIP (missing {', '.join(missing)}; "
              f"run ./scripts/build-win64-fixtures.sh)")
        return 0

    checked = 0
    for name, expected_imports in targets.items():
        image = PE64Image.load(os.path.join(fixture_dir, name))
        assert image.is_amd64 and not image.is_dll
        assert image.image_base == IMAGE_BASE, hex(image.image_base)

        names = {symbol.name for symbol in image.imports}
        for expected in expected_imports:
            assert expected in names, (name, expected, sorted(names))
        # The PE32+ stride: IAT slots are 8 bytes apart and unique.
        iats = [symbol.iat_rva for symbol in image.imports]
        assert len(iats) == len(set(iats)), name
        assert all(iat % 8 == 0 for iat in iats), name
        assert "KERNEL32.dll" in image.import_dlls, image.import_dlls

        entry = image.runtime_functions
        assert len(entry) >= 10, (name, len(entry))
        code = image.code_ranges()
        for runtime in entry:
            assert runtime.end_rva > runtime.begin_rva, (name, runtime)
            assert any(start <= runtime.begin_rva < end for start, end in code), \
                (name, hex(runtime.begin_rva))
        assert set(image.relocation_counts()) <= {"dir64", "absolute"}, \
            image.relocation_counts()

        functions, _notes = fn.recover_functions(image)
        assert fn.validate_ranges(image, functions) == ()
        sources = fn.summarize(functions)["by_source"]
        assert sources.get("pdata", 0) >= 10, (name, sources)

        if name == "return42.exe":
            export = next(symbol for symbol in image.exports if symbol.name == "add_then_mul")
            covering = [f for f in functions
                        if f.end_rva is not None and f.start_rva <= export.rva < f.end_rva]
            assert len(covering) == 1, (hex(export.rva), covering)
            assert covering[0].name == "add_then_mul"
            tls = image.tls
            assert tls is not None and tls.callbacks, "MinGW TLS callbacks not recovered"
        checked += 1

    print(f"fixtures: ok ({checked} images)")
    return checked


def test_msvc_rtti_fixture() -> int:
    """Recon and the ported x64 RTTI parser must agree on the same image.

    ``rtti_msvc.exe`` is MSVC-ABI on purpose, because the parser reads MSVC's
    x64 RTTI records (locator signature 1, image-relative pointer fields).
    A vtable slot is proof that a function starts there, so a slot landing in
    the *interior* of a recovered range means one of the two is wrong. Leaf
    methods carry no ``.pdata`` entry, so the check is "no interior hits",
    not "every method is covered" — methods outside any range must still be
    inside executable code.
    """
    path = os.path.join(_fixture_dir(), "rtti_msvc.exe")
    if not os.path.exists(path):
        print("rtti fixture: SKIP (run ./scripts/build-win64-fixtures.sh)")
        return 0

    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cpp"))
    import rtti

    image = PE64Image.load(path)
    functions, _notes = fn.recover_functions(image)
    result = rtti.recover(path)

    classes = sorted({rtti.demangle(name) for _, name, _, _ in result["vtables"]})
    assert "Derived" in classes, classes
    methods = rtti.seeds(result)
    assert len(methods) >= 3, [hex(m) for m in methods]

    code = image.code_ranges()
    starts = {image.va(function.start_rva) for function in functions}
    interior = []
    for method in methods:
        rva = image.rva_of(method)
        assert any(start <= rva < end for start, end in code), \
            f"RTTI method 0x{method:X} is not in executable code"
        for function in functions:
            if function.end_rva is None:
                continue
            if image.va(function.start_rva) < method < image.va(function.end_rva):
                interior.append((method, function))
    assert not interior, [(hex(m), hex(image.va(f.start_rva))) for m, f in interior]
    assert starts & set(methods), "no RTTI method matched a recovered function start"

    export = [symbol for symbol in image.exports if symbol.name == "mainCRTStartup"]
    assert len(export) == 1, [symbol.name for symbol in image.exports]
    assert image.va(export[0].rva) in starts, hex(image.va(export[0].rva))

    assert fn.validate_ranges(image, functions) == ()
    print(f"rtti fixture: ok ({len(classes)} class, {len(methods)} methods, "
          f"{len(starts & set(methods))} on recovered starts, 0 interior)")
    return len(methods)


def main() -> int:
    import tempfile

    schema_check._selftest()
    test_headers_and_sections()
    test_directories_and_imports()
    test_exports_and_relocations()
    test_tls_and_unwind()
    test_rejections()
    test_function_recovery()
    with tempfile.TemporaryDirectory() as tmp:
        test_bounds_csv(tmp)
        test_spec_document(tmp)
    print("pe64 synthetic: ok")
    test_fixtures()
    test_msvc_rtti_fixture()
    return 0


if __name__ == "__main__":
    sys.exit(main())
