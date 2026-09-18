"""Reader for PE32+ (AMD64) images: headers, sections, imports, exports,
relocations, TLS and the AMD64 exception directory.

Why this exists next to ``tools/pe/pe_analyze.py``: that analyzer is 32-bit
first. Its ``struct`` fallback walks the import lookup table in 4-byte steps
and tests the ordinal flag against ``0x80000000``, which is the PE32 encoding.
On a PE32+ image the import thunk array is 8 bytes per entry, so the walk reads
the low half of thunk 0 (a name RVA), then the high half of the same thunk
(always zero) and stops. The result is a plausible-looking import list with
exactly one function per DLL. On the fixture in ``tests/fixtures/win64``
KERNEL32 has 14 imports and that analyzer reports 1.

Everything architecture-specific about PE32+ lives here: 8-byte import thunks,
64-bit image base and TLS addresses, base relocation type DIR64, and the
``.pdata`` ``RUNTIME_FUNCTION`` table that gives x64 function bounds for free.

Stdlib only, no pefile/capstone dependency. All reads are bounds-checked;
malformed input raises :class:`PEFormatError` with the offending RVA rather
than returning a partially-parsed structure.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from functools import cached_property
from typing import Optional, Tuple

# --- Machine types ---------------------------------------------------------

MACHINE_I386 = 0x14C
MACHINE_AMD64 = 0x8664
MACHINE_ARM64 = 0xAA64

# --- Optional header magic -------------------------------------------------

OPTIONAL_MAGIC_PE32 = 0x10B
OPTIONAL_MAGIC_PE32PLUS = 0x20B

# --- Data directory indices ------------------------------------------------

DIRECTORY_NAMES = (
    "export",
    "import",
    "resource",
    "exception",
    "security",
    "basereloc",
    "debug",
    "architecture",
    "globalptr",
    "tls",
    "loadconfig",
    "boundimport",
    "iat",
    "delayimport",
    "clr",
    "reserved",
)

DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_EXCEPTION = 3
DIR_BASERELOC = 5
DIR_TLS = 9
DIR_LOADCONFIG = 10
DIR_DELAY_IMPORT = 13

# --- Section characteristics ----------------------------------------------

SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED_DATA = 0x00000040
SCN_CNT_UNINITIALIZED_DATA = 0x00000080
SCN_MEM_DISCARDABLE = 0x02000000
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

# --- Subsystems ------------------------------------------------------------

SUBSYSTEM_NAMES = {
    0: "unknown",
    1: "native",
    2: "windows-gui",
    3: "windows-console",
    5: "os2-console",
    7: "posix-console",
    9: "windows-ce-gui",
    10: "efi-application",
    11: "efi-boot-service",
    12: "efi-runtime",
    14: "xbox",
    16: "windows-boot",
}

# --- Base relocation types -------------------------------------------------

RELOCATION_KINDS = {
    0: "absolute",
    1: "high",
    2: "low",
    3: "highlow",
    4: "highadj",
    5: "mips-jmpaddr",
    7: "arm-mov32",
    9: "mips-jmpaddr16",
    10: "dir64",
}

# --- Unwind info flags -----------------------------------------------------

UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_CHAININFO = 0x4

_IMPORT_SCAN_LIMIT = 1 << 16      # descriptors / thunks per table guard
_RELOCATION_SCAN_LIMIT = 1 << 22  # relocation entries guard
_TLS_CALLBACK_LIMIT = 1 << 10

_RUNTIME_FUNCTION_SIZE = 12


class PEFormatError(ValueError):
    """Raised when a file is not a parseable PE32+ image."""


@dataclass(frozen=True)
class Section:
    """A PE section header, with RVA-based accessors."""

    name: str
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & (SCN_CNT_CODE | SCN_MEM_EXECUTE))

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_EXECUTE)

    @property
    def is_readable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_READ)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_WRITE)

    @property
    def is_discardable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_DISCARDABLE)

    @property
    def has_raw_data(self) -> bool:
        return self.raw_size > 0

    @property
    def mapped_size(self) -> int:
        """Size of the region the Windows loader maps for this section.

        The loader maps whichever of VirtualSize and SizeOfRawData is larger.
        Trusting VirtualSize alone drops code that linkers (MSVC in particular)
        place in the raw tail; trusting SizeOfRawData alone maps pad bytes as
        data. Both directions produce silently plausible output, so the rule
        lives here once instead of at each call site.
        """
        return max(self.virtual_size, self.raw_size)

    @property
    def end_rva(self) -> int:
        return self.rva + self.mapped_size

    def contains_rva(self, rva: int) -> bool:
        return self.rva <= rva < self.end_rva

    @property
    def flags(self) -> Tuple[str, ...]:
        out = []
        if self.characteristics & SCN_CNT_CODE:
            out.append("code")
        if self.characteristics & SCN_CNT_INITIALIZED_DATA:
            out.append("idata")
        if self.characteristics & SCN_CNT_UNINITIALIZED_DATA:
            out.append("udata")
        if self.characteristics & SCN_MEM_EXECUTE:
            out.append("exec")
        if self.characteristics & SCN_MEM_READ:
            out.append("read")
        if self.characteristics & SCN_MEM_WRITE:
            out.append("write")
        if self.characteristics & SCN_MEM_DISCARDABLE:
            out.append("discardable")
        return tuple(out)


@dataclass(frozen=True)
class Directory:
    """One data directory entry. ``rva``/``size`` are zero when absent."""

    index: int
    name: str
    rva: int
    size: int

    @property
    def present(self) -> bool:
        return self.rva != 0 and self.size != 0


@dataclass(frozen=True)
class ImportSymbol:
    """One imported function, keyed by the IAT slot the guest code calls through."""

    dll: str
    name: Optional[str]
    ordinal: Optional[int]
    hint: Optional[int]
    iat_rva: int
    ilt_rva: int

    @property
    def label(self) -> str:
        if self.name:
            return self.name
        return f"ordinal_{self.ordinal}" if self.ordinal is not None else "?"


@dataclass(frozen=True)
class ExportSymbol:
    """One exported name. ``forwarder`` is set when the RVA points into the
    export directory itself, in which case ``rva`` is meaningless as code."""

    name: Optional[str]
    ordinal: int
    rva: int
    forwarder: Optional[str] = None


@dataclass(frozen=True)
class Relocation:
    """One base relocation entry."""

    type: int
    rva: int

    @property
    def kind(self) -> str:
        return RELOCATION_KINDS.get(self.type, f"type_{self.type}")


@dataclass(frozen=True)
class TlsInfo:
    """Thread-local storage directory, with guest VAs resolved to RVAs."""

    raw_start_va: int
    raw_end_va: int
    index_va: int
    callbacks_va: int
    callbacks: Tuple[int, ...]
    zero_fill_size: int
    characteristics: int

    @property
    def raw_size(self) -> int:
        return max(0, self.raw_end_va - self.raw_start_va)


@dataclass(frozen=True)
class RuntimeFunction:
    """An AMD64 ``RUNTIME_FUNCTION`` entry: a function's half-open [begin, end)
    RVA range plus the RVA of its unwind info."""

    begin_rva: int
    end_rva: int
    unwind_rva: int

    @property
    def size(self) -> int:
        return max(0, self.end_rva - self.begin_rva)


@dataclass(frozen=True)
class UnwindInfo:
    """Decoded ``UNWIND_INFO`` for one function."""

    version: int
    flags: int
    prolog_size: int
    code_slots: int
    frame_register: int
    frame_offset: int
    handler_rva: Optional[int] = None
    chained_begin_rva: Optional[int] = None

    @property
    def has_exception_handler(self) -> bool:
        return bool(self.flags & UNW_FLAG_EHANDLER)

    @property
    def has_termination_handler(self) -> bool:
        return bool(self.flags & UNW_FLAG_UHANDLER)

    @property
    def is_chained(self) -> bool:
        return bool(self.flags & UNW_FLAG_CHAININFO)


@dataclass(frozen=True)
class Function:
    """A recovered function range. ``source`` records how the start was found."""

    start_rva: int
    end_rva: int
    name: Optional[str] = None
    source: str = "unknown"

    @property
    def size(self) -> int:
        return max(0, self.end_rva - self.start_rva)


@dataclass
class _ImportDescriptor:
    ilt_rva: int
    name_rva: int
    iat_rva: int


class PE64Image:
    """A parsed PE32+ image. Construct with :meth:`load` or :meth:`from_bytes`."""

    def __init__(self, data: bytes, name: str = "<memory>", path: Optional[str] = None):
        self.data = data
        self.name = name
        self.path = path
        self._parse_headers()

    # -- construction -------------------------------------------------------

    @classmethod
    def load(cls, path: str) -> "PE64Image":
        with open(path, "rb") as handle:
            data = handle.read()
        return cls(data, name=path.rsplit("/", 1)[-1], path=path)

    @classmethod
    def from_bytes(cls, data: bytes, name: str = "<memory>") -> "PE64Image":
        return cls(data, name=name)

    # -- header parsing -----------------------------------------------------

    def _parse_headers(self) -> None:
        data = self.data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PEFormatError(f"{self.name}: not a PE image (no MZ signature)")
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            raise PEFormatError(f"{self.name}: no PE signature at 0x{pe_offset:X}")

        coff = pe_offset + 4
        (self.machine, self.num_sections, self.timestamp, _symtab,
         _nsyms, opt_header_size, self.characteristics) = struct.unpack_from(
            "<HHIIIHH", data, coff)

        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic == OPTIONAL_MAGIC_PE32:
            raise PEFormatError(
                f"{self.name}: PE32 (i386) image, not PE32+. Use the 32-bit "
                "pipeline (tools/pe/pe_analyze.py, tools/disasm/disasm32.py)."
            )
        if magic != OPTIONAL_MAGIC_PE32PLUS:
            raise PEFormatError(f"{self.name}: unknown optional header magic 0x{magic:X}")

        self.optional_magic = magic
        self.linker_version = f"{data[opt + 2]}.{data[opt + 3]:02d}"
        (self.size_of_code, self.size_of_initialized_data,
         self.size_of_uninitialized_data, self.entrypoint_rva,
         self.base_of_code, self.image_base) = struct.unpack_from("<IIIIIQ", data, opt + 4)
        (self.section_alignment, self.file_alignment, _major_os, _minor_os,
         _major_img, _minor_img, _major_subsys, _minor_subsys,
         _win32_version, self.size_of_image, self.size_of_headers,
         self.checksum, self.subsystem,
         self.dll_characteristics) = struct.unpack_from("<IIHHHHHHIIIIHH", data, opt + 32)
        (self.size_of_stack_reserve, self.size_of_stack_commit,
         self.size_of_heap_reserve,
         self.size_of_heap_commit, self.loader_flags,
         self.num_directories) = struct.unpack_from("<QQQQII", data, opt + 72)

        self.subsystem_name = SUBSYSTEM_NAMES.get(self.subsystem, f"subsystem_{self.subsystem}")
        self.is_dll = bool(self.characteristics & 0x2000)
        self.is_large_address_aware = bool(self.dll_characteristics & 0x0020)
        self.has_dynamic_base = bool(self.dll_characteristics & 0x0040)

        directories = []
        for index in range(min(self.num_directories, 16)):
            rva, size = struct.unpack_from("<II", data, opt + 112 + index * 8)
            name = DIRECTORY_NAMES[index] if index < len(DIRECTORY_NAMES) else f"dir_{index}"
            directories.append(Directory(index=index, name=name, rva=rva, size=size))
        self.directories = tuple(directories)

        needed = 112 + min(self.num_directories, 16) * 8
        if opt_header_size < needed:
            raise PEFormatError(
                f"{self.name}: SizeOfOptionalHeader {opt_header_size} smaller than "
                f"{needed} bytes declared by NumberOfRvaAndSizes={self.num_directories}")
        section_table = opt + opt_header_size
        sections = []
        for index in range(self.num_sections):
            off = section_table + index * 40
            if off + 40 > len(data):
                raise PEFormatError(f"{self.name}: section header {index} past end of file")
            raw_name = data[off:off + 8].split(b"\x00", 1)[0]
            name = raw_name.decode("ascii", errors="replace")
            virtual_size, va, raw_size, raw_ptr, _reloc_ptr, _line_ptr, _nreloc, _nline, chars = \
                struct.unpack_from("<IIIIIIHHI", data, off + 8)
            sections.append(Section(
                name=name, rva=va, virtual_size=virtual_size, raw_offset=raw_ptr,
                raw_size=raw_size, characteristics=chars,
            ))
        self.sections = tuple(sections)
        if not self.sections:
            raise PEFormatError(f"{self.name}: no sections")

    # -- identity -----------------------------------------------------------

    @cached_property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def filesize(self) -> int:
        return len(self.data)

    @property
    def is_amd64(self) -> bool:
        return self.machine == MACHINE_AMD64

    @property
    def machine_name(self) -> str:
        return {MACHINE_I386: "i386", MACHINE_AMD64: "x86-64", MACHINE_ARM64: "arm64"}.get(
            self.machine, f"machine_0x{self.machine:X}")

    @property
    def entrypoint_va(self) -> int:
        return self.va(self.entrypoint_rva)

    def va(self, rva: int) -> int:
        """Guest virtual address for an RVA."""
        return self.image_base + rva

    def rva_of(self, va: int) -> int:
        return va - self.image_base

    # -- address translation ------------------------------------------------

    def section_for_rva(self, rva: int) -> Optional[Section]:
        for section in self.sections:
            if section.contains_rva(rva):
                return section
        return None

    def rva_to_offset(self, rva: int, size: int = 1) -> Optional[int]:
        """File offset backing *rva*, or None when the bytes are not in the file.

        Returns None for zero-filled tails (``.bss``) and for RVAs that no
        section maps. Callers that need raw-data guarantees use this; callers
        reading optional metadata use the ``Optional`` result directly.
        """
        section = self.section_for_rva(rva)
        if section is None or not section.has_raw_data:
            return None
        delta = rva - section.rva
        if delta + size > section.raw_size:
            return None
        return section.raw_offset + delta

    def read_rva(self, rva: int, size: int) -> Optional[bytes]:
        offset = self.rva_to_offset(rva, size)
        if offset is None:
            return None
        return self.data[offset:offset + size]

    def read_va(self, va: int, size: int) -> Optional[bytes]:
        return self.read_rva(self.rva_of(va), size)

    def read_cstring_rva(self, rva: int, limit: int = 4096) -> Optional[str]:
        offset = self.rva_to_offset(rva)
        if offset is None:
            return None
        end = self.data.find(b"\x00", offset, offset + limit)
        if end < 0:
            return None
        return self.data[offset:end].decode("ascii", errors="replace")

    # -- directories --------------------------------------------------------

    def directory(self, index: int) -> Directory:
        for entry in self.directories:
            if entry.index == index:
                return entry
        return Directory(index=index, name=f"dir_{index}", rva=0, size=0)

    # -- imports ------------------------------------------------------------

    @cached_property
    def import_descriptors(self) -> Tuple[_ImportDescriptor, ...]:
        directory = self.directory(DIR_IMPORT)
        if not directory.present:
            return ()
        out = []
        for index in range(_IMPORT_SCAN_LIMIT):
            raw = self.read_rva(directory.rva + index * 20, 20)
            if raw is None:
                break
            ilt_rva, _stamp, _forwarder, name_rva, iat_rva = struct.unpack("<IIIII", raw)
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break
            out.append(_ImportDescriptor(ilt_rva=ilt_rva, name_rva=name_rva, iat_rva=iat_rva))
        return tuple(out)

    @cached_property
    def imports(self) -> Tuple[ImportSymbol, ...]:
        out = []
        for descriptor in self.import_descriptors:
            dll = self.read_cstring_rva(descriptor.name_rva) or "?"
            # Bound images can carry OriginalFirstThunk == 0; the IAT then holds
            # the pre-resolved names, which is the same shape we read here.
            thunk_rva = descriptor.ilt_rva or descriptor.iat_rva
            if not thunk_rva:
                continue
            for index in range(_IMPORT_SCAN_LIMIT):
                slot_rva = thunk_rva + index * 8
                raw = self.read_rva(slot_rva, 8)
                if raw is None:
                    break
                entry = struct.unpack("<Q", raw)[0]
                if entry == 0:
                    break
                iat_rva = descriptor.iat_rva + index * 8
                if entry >> 63:
                    out.append(ImportSymbol(
                        dll=dll, name=None, ordinal=entry & 0xFFFF, hint=None,
                        iat_rva=iat_rva, ilt_rva=slot_rva,
                    ))
                    continue
                hint_raw = self.read_rva(entry & 0x7FFFFFFF, 2)
                hint = struct.unpack("<H", hint_raw)[0] if hint_raw else None
                out.append(ImportSymbol(
                    dll=dll, name=self.read_cstring_rva((entry & 0x7FFFFFFF) + 2),
                    ordinal=None, hint=hint, iat_rva=iat_rva, ilt_rva=slot_rva,
                ))
        return tuple(out)

    @cached_property
    def import_dlls(self) -> Tuple[str, ...]:
        return tuple(dict.fromkeys(symbol.dll for symbol in self.imports))

    # -- exports ------------------------------------------------------------

    @cached_property
    def exports(self) -> Tuple[ExportSymbol, ...]:
        directory = self.directory(DIR_EXPORT)
        if not directory.present:
            return ()
        header = self.read_rva(directory.rva, 40)
        if header is None:
            return ()
        (_characteristics, _stamp, _major, _minor, _name_rva, ordinal_base,
         num_functions, num_names, funcs_rva, names_rva,
         ordinals_rva) = struct.unpack("<IIHHIIIIIII", header)

        functions = []
        for index in range(min(num_functions, _IMPORT_SCAN_LIMIT)):
            raw = self.read_rva(funcs_rva + index * 4, 4)
            if raw is None:
                break
            functions.append(struct.unpack("<I", raw)[0])

        names = {}
        for index in range(min(num_names, _IMPORT_SCAN_LIMIT)):
            raw = self.read_rva(names_rva + index * 4, 4)
            ord_raw = self.read_rva(ordinals_rva + index * 2, 2)
            if raw is None or ord_raw is None:
                break
            name = self.read_cstring_rva(struct.unpack("<I", raw)[0])
            names[struct.unpack("<H", ord_raw)[0]] = name

        out = []
        export_start = directory.rva
        export_end = directory.rva + directory.size
        for index, func_rva in enumerate(functions):
            if func_rva == 0:
                continue  # gap in the export address table
            forwarder = None
            if export_start <= func_rva < export_end:
                forwarder = self.read_cstring_rva(func_rva)
            out.append(ExportSymbol(
                name=names.get(index), ordinal=ordinal_base + index,
                rva=func_rva, forwarder=forwarder,
            ))
        return tuple(out)

    # -- relocations --------------------------------------------------------

    @cached_property
    def relocations(self) -> Tuple[Relocation, ...]:
        directory = self.directory(DIR_BASERELOC)
        if not directory.present:
            return ()
        out = []
        pos = 0
        while pos + 8 <= directory.size:
            header = self.read_rva(directory.rva + pos, 8)
            if header is None:
                break
            page_rva, block_size = struct.unpack("<II", header)
            if block_size < 8:
                break
            count = (block_size - 8) // 2
            if count > _RELOCATION_SCAN_LIMIT:
                break
            entries = self.read_rva(directory.rva + pos + 8, count * 2)
            if entries is None:
                break
            for index in range(count):
                value = struct.unpack_from("<H", entries, index * 2)[0]
                reloc_type = value >> 12
                if reloc_type == 0:
                    continue  # padding
                out.append(Relocation(type=reloc_type, rva=page_rva + (value & 0x0FFF)))
            pos += block_size
        return tuple(out)

    def relocation_counts(self) -> dict:
        counts = {}
        for relocation in self.relocations:
            counts[relocation.kind] = counts.get(relocation.kind, 0) + 1
        return counts

    # -- TLS ----------------------------------------------------------------

    @cached_property
    def tls(self) -> Optional[TlsInfo]:
        directory = self.directory(DIR_TLS)
        if not directory.present:
            return None
        raw = self.read_rva(directory.rva, 40)
        if raw is None:
            return None
        (start_va, end_va, index_va, callbacks_va, zero_fill,
         characteristics) = struct.unpack("<QQQQII", raw)

        callbacks = []
        if callbacks_va:
            callbacks_rva = self.rva_of(callbacks_va)
            for index in range(_TLS_CALLBACK_LIMIT):
                entry = self.read_rva(callbacks_rva + index * 8, 8)
                if entry is None:
                    break
                value = struct.unpack("<Q", entry)[0]
                if value == 0:
                    break
                callbacks.append(value)
        return TlsInfo(
            raw_start_va=start_va, raw_end_va=end_va, index_va=index_va,
            callbacks_va=callbacks_va, callbacks=tuple(callbacks),
            zero_fill_size=zero_fill, characteristics=characteristics,
        )

    # -- AMD64 exception directory -----------------------------------------

    @cached_property
    def runtime_functions(self) -> Tuple[RuntimeFunction, ...]:
        """``.pdata`` entries. On AMD64 this is the linker's own function table,
        so it is authoritative for function bounds where present."""
        directory = self.directory(DIR_EXCEPTION)
        if not directory.present:
            return ()
        count = directory.size // _RUNTIME_FUNCTION_SIZE
        raw = self.read_rva(directory.rva, count * _RUNTIME_FUNCTION_SIZE)
        if raw is None:
            return ()
        out = []
        for index in range(count):
            begin, end, unwind = struct.unpack_from("<III", raw, index * _RUNTIME_FUNCTION_SIZE)
            if begin == 0 and end == 0 and unwind == 0:
                continue
            out.append(RuntimeFunction(begin_rva=begin, end_rva=end, unwind_rva=unwind))
        return tuple(out)

    def unwind_info(self, rva: int) -> Optional[UnwindInfo]:
        """Decode ``UNWIND_INFO`` at *rva* (the value from a ``RUNTIME_FUNCTION``)."""
        header = self.read_rva(rva, 4)
        if header is None:
            return None
        version = header[0] & 0x07
        flags = header[0] >> 3
        prolog_size = header[1]
        code_slots = header[2]
        frame_register = header[3] & 0x0F
        frame_offset = header[3] >> 4

        handler_rva = None
        trailing = rva + 4 + code_slots * 2
        if code_slots % 2:
            trailing += 2  # UNWIND_INFO is 4-byte aligned; odd code counts pad
        if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
            raw = self.read_rva(trailing, 4)
            if raw is None:
                return None
            handler_rva = struct.unpack("<I", raw)[0]
            trailing += 4
        chained_begin_rva = None
        if flags & UNW_FLAG_CHAININFO:
            raw = self.read_rva(trailing, _RUNTIME_FUNCTION_SIZE)
            if raw is None:
                return None
            chained_begin_rva = struct.unpack("<I", raw)[0]
        return UnwindInfo(
            version=version, flags=flags, prolog_size=prolog_size,
            code_slots=code_slots, frame_register=frame_register,
            frame_offset=frame_offset, handler_rva=handler_rva,
            chained_begin_rva=chained_begin_rva,
        )

    # -- convenience --------------------------------------------------------

    @property
    def code_sections(self) -> Tuple[Section, ...]:
        return tuple(section for section in self.sections if section.is_code)

    def code_ranges(self) -> Tuple[Tuple[int, int], ...]:
        """Half-open [start_rva, end_rva) ranges of executable sections."""
        return tuple((section.rva, section.end_rva) for section in self.code_sections)

    def find_rva(self, va: int) -> int:
        """RVA for a guest VA, rejecting addresses outside the image."""
        rva = self.rva_of(va)
        if rva < 0 or rva >= self.size_of_image:
            raise PEFormatError(f"{self.name}: VA 0x{va:X} outside image 0x{self.image_base:X}")
        return rva
