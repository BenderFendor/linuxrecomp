"""
stdcall_argc.py - Derive Win32 stdcall argument counts without typing them.

Every import shim in a recompiled Win32 program has to pop exactly the argument
slots the real API pops. Get one wrong and the simulated stack silently
desynchronises: every value read after that call is garbage, and the symptom
shows up nowhere near the cause. It is a bad thing to get from a hand-typed
table -- and hand-typed tables do drift. The one carried by the Fury3/Hellbender
projects gives `waveOutOpen` 7 arguments; the real one takes 6.

The answer is already on the machine. In the Windows SDK's **32-bit** import
libraries, stdcall exports are decorated `_Name@N`, where N is the argument byte
count the compiler computed from the real header. Four bytes per 32-bit slot.

    from stdcall_argc import ArgcResolver
    r = ArgcResolver()
    r.lookup('KERNEL32.dll', 'CreateFileA')     -> 7
    r.lookup('DSOUND.dll',   'ordinal_1')       -> 3   (via DirectSoundCreate)
    r.lookup('KERNEL32.dll', 'NoSuchExport')    -> None

Imports referenced by ordinal are resolved against the system copy of the DLL's
export table first, then looked up by name.

That covers plain Win32. A real game's import table has three more kinds, and
an SDK-only lookup returns None for every one of them -- on Star Wars: Force
Commander it resolved 135 of 307:

  * **Third-party stdcall DLLs.** `mss32.dll` (Miles) imports
    `_AIL_waveOutOpen@16`. The count is already *in the name the binary asked
    for*, and no import library is needed to read it.
  * **cdecl.** Every `MSVCRT.dll` import -- `fopen`, `memmove`, `_ftol`. A cdecl
    callee pops **nothing**; the caller cleans up. The answer is 0, and it is
    not a guess.

    Telling cdecl from stdcall cannot be done by looking for `@N` in the DLL's
    export table, which is the obvious idea and is wrong: `KERNEL32.dll`
    exports `Sleep` undecorated and `dinput.dll` exports `DirectInputCreateA`
    undecorated, and both are stdcall. The `@N` lives in the *import library*,
    not the export table. So the undecorated-export rule is restricted to the
    C-runtime DLL families, which are cdecl by definition; anything else with
    no import library stays None.
  * **C++ mangled names.** `MSVCP60.dll` imports 85 `basic_string` and iostream
    methods. The mangling encodes the calling convention, so the cdecl ones
    (`YA`, `SA`) are certain; `__thiscall`/`__stdcall` members are not, because
    the argument *byte* count needs the parameter types and a struct passed by
    value has no knowable size. Those stay None on purpose.

`lookup` returns None rather than guessing. Callers should refuse to emit an
import they could not resolve: a placeholder count is the exact failure this
module exists to prevent. `lookup_ex` returns *why*, so a caller can tell "cdecl,
pops nothing" from "no idea" -- they need opposite handling and both used to
arrive as None.

Part of the pcrecomp toolbox.
"""
import glob
import os
import re

__all__ = ['ArgcResolver', 'mangled_convention',
           'DEFAULT_SDK_GLOB', 'DEFAULT_SYSTEM_DIR']

# 32-bit import libraries. On a 64-bit host the 32-bit system DLLs are the
# SysWOW64 ones, despite the name.
DEFAULT_SDK_GLOB = r"C:\Program Files (x86)\Windows Kits\10\Lib\*\um\x86"
DEFAULT_SYSTEM_DIR = r"C:\Windows\SysWOW64"

_DECORATED = re.compile(rb'_([A-Za-z_][A-Za-z0-9_]*)@(\d+)')
_ORDINAL = re.compile(r'ordinal_(\d+)$', re.I)

# A name the binary already asked for in decorated form: `_AIL_waveOutOpen@16`.
_SELF_DECORATED = re.compile(r'^_([A-Za-z_][A-Za-z0-9_]*)@(\d+)$')

# DLLs whose exports are cdecl C runtime functions. `msvcrt.lib` is not in the
# Windows SDK (it ships with the compiler), so for these the export table is the
# only evidence available -- and for these it is sufficient, because a C runtime
# does not export stdcall. Every other DLL exports WINAPI undecorated too, so
# the same inference there would be wrong.
_CRT_FAMILY = ('msvcrt', 'msvcr', 'msvcp', 'crtdll', 'ucrtbase', 'vcruntime',
               'libcmt', 'atl', 'mfc')


def _is_crt_dll(dll):
    stem = os.path.splitext(dll)[0].lower()
    return stem.startswith(_CRT_FAMILY)


# MSVC function-modifier letter -> calling convention. It sits right after the
# access/cv letters in a mangled name: `?f@@YAXXZ` is YA, `?f@@QAEXXZ` is QAE.
_CONVENTION = {
    'A': 'cdecl', 'B': 'cdecl',
    'C': 'pascal', 'D': 'pascal',
    'E': 'thiscall', 'F': 'thiscall',
    'G': 'stdcall', 'H': 'stdcall',
    'I': 'fastcall', 'J': 'fastcall',
}

# Access/storage letters that introduce a *member* function: the convention
# letter follows one cv letter. `Y`/`Z` are free functions and `S`/`T` static
# members, where the convention letter follows immediately.
_MEMBER_ACCESS = set('QRSTUVWABCDEFGHIJKLMNOP')
_FREE_ACCESS = set('YZ')


def mangled_convention(name):
    """Calling convention of an MSVC-mangled function, or None.

    Only the convention is read, not the signature. That is deliberate: the
    convention decides *whether* the callee pops anything, and for cdecl -- the
    common case in an STL import table -- that settles the answer at 0 without
    needing to size a single parameter.
    """
    if not name.startswith('?'):
        return None
    # `?name@scope@@3<type><cv>` is a data symbol, not a function. It is
    # imported through its IAT slot like anything else, but it is never called,
    # so it has no argument count and a caller must not emit a call shim.
    for m in re.finditer(r'@@', name):
        tail = name[m.end():]
        if tail[:1] == '3':
            return 'data'
        if tail[:1] in ('2', '4', '5', '6', '7', '8', '9'):
            return 'data'
        if tail:
            break
    # Skip the qualified name: `?ident@scope@@` -- the signature starts after
    # the `@@` that closes it. Templates contain `@@` too, so find the first
    # `@@` that is followed by a plausible signature letter.
    for m in re.finditer(r'@@', name):
        sig = name[m.end():]
        if not sig:
            continue
        a = sig[0]
        if a in _FREE_ACCESS and len(sig) > 1:
            return _CONVENTION.get(sig[1])
        if a in ('S', 'T') and len(sig) > 1:
            return _CONVENTION.get(sig[1])
        if a in _MEMBER_ACCESS and len(sig) > 2:
            conv = _CONVENTION.get(sig[2])
            if conv:
                return conv
    return None


class ArgcResolver:
    """Resolve (dll, import name) -> stdcall argument slot count.

    Lookups are cached per DLL, so scanning a whole import table costs one read
    of each import library.
    """

    def __init__(self, sdk_dir=None, system_dir=DEFAULT_SYSTEM_DIR):
        self.sdk_dir = sdk_dir or self._newest_sdk()
        self.system_dir = system_dir
        self._lib_cache = {}
        self._ord_cache = {}

    @staticmethod
    def _newest_sdk(pattern=DEFAULT_SDK_GLOB):
        dirs = sorted(glob.glob(pattern))
        if not dirs:
            raise RuntimeError(
                "no 32-bit Windows SDK library directory found under %s -- "
                "install the SDK's x86 libraries, or pass sdk_dir=" % pattern)
        return dirs[-1]

    def _lib(self, dll):
        """name -> argument slot count, from this DLL's import library."""
        key = dll.lower()
        if key not in self._lib_cache:
            path = os.path.join(self.sdk_dir,
                                os.path.splitext(dll)[0] + ".lib")
            table = {}
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    data = fh.read()
                for m in _DECORATED.finditer(data):
                    table[m.group(1).decode()] = int(m.group(2)) // 4
            self._lib_cache[key] = table
        return self._lib_cache[key]

    def _ordinals(self, dll):
        """ordinal -> export name, from the system copy of the DLL."""
        key = dll.lower()
        if key not in self._ord_cache:
            table = {}
            path = os.path.join(self.system_dir, dll)
            if os.path.exists(path):
                try:
                    import pefile
                    pe = pefile.PE(path, fast_load=True)
                    pe.parse_data_directories(directories=[
                        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
                    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                        table = {e.ordinal: e.name.decode()
                                 for e in pe.DIRECTORY_ENTRY_EXPORT.symbols
                                 if e.name}
                except Exception:
                    table = {}          # no pefile, or an unreadable DLL
            self._ord_cache[key] = table
        return self._ord_cache[key]

    def real_name(self, dll, name):
        """The exported name, resolving `ordinal_N` against the system DLL."""
        m = _ORDINAL.match(name)
        if not m:
            return name
        return self._ordinals(dll).get(int(m.group(1)), name)

    def _exports(self, dll):
        """Undecorated export names of the system copy of this DLL.

        Used only to prove a name is cdecl: a stdcall export in a 32-bit DLL
        carries `@N`, so a name present undecorated is not stdcall.
        """
        key = 'x' + dll.lower()
        if key not in self._ord_cache:
            self._ord_cache[key] = set(self._ordinals(dll).values())
        return self._ord_cache[key]

    def lookup_ex(self, dll, name):
        """(argc, convention, source). argc is None when it is not derivable.

        `convention` is 'stdcall', 'cdecl', 'thiscall', ... or None; `source`
        names the evidence, so an unresolved import can be triaged instead of
        just counted.
        """
        real = self.real_name(dll, name)

        # 1. The binary already spelled the count: `_AIL_waveOutOpen@16`.
        m = _SELF_DECORATED.match(real)
        if m:
            return int(m.group(2)) // 4, 'stdcall', 'decorated-name'

        # 2. A C++ mangled name states its convention. cdecl pops nothing, so
        #    that is an answer; the rest need parameter sizes we cannot get.
        conv = mangled_convention(real)
        if conv == 'data':
            return 0, 'data', 'mangled-data-symbol'
        if conv == 'cdecl':
            return 0, 'cdecl', 'mangled-convention'
        if conv is not None:
            return None, conv, 'mangled-convention'

        # 3. The SDK import library, which is authoritative for plain Win32.
        argc = self._lib(dll).get(real)
        if argc is not None:
            return argc, 'stdcall', 'sdk-import-lib'

        # 4. A C runtime DLL exports cdecl and nothing else, so an export it
        #    names is cdecl and pops nothing. Restricted to that family on
        #    purpose -- see the note in the module docstring.
        if _is_crt_dll(dll) and real in self._exports(dll):
            return 0, 'cdecl', 'crt-undecorated-export'

        return None, None, 'unresolved'

    def lookup(self, dll, name):
        """Argument slot count, or None if it could not be derived."""
        return self.lookup_ex(dll, name)[0]

    def resolve_iat(self, iat):
        """Resolve a whole {va: (dll, name)} IAT map.

        Returns (rows, unresolved):
          rows       [(va, dll, name, real_name, argc)] sorted by va
          unresolved [(va, dll, name, real_name)]
        """
        rows, unresolved = [], []
        for va, (dll, name) in sorted(iat.items()):
            real = self.real_name(dll, name)
            argc, conv, src = self.lookup_ex(dll, name)
            if argc is None:
                unresolved.append((va, dll, name, real))
            else:
                rows.append((va, dll, name, real, argc))
        return rows, unresolved

    def resolve_iat_ex(self, iat):
        """As resolve_iat, but every row carries its convention and evidence.

        [(va, dll, name, real_name, argc, convention, source)], sorted by va.
        Unresolved rows are included with argc None -- a caller that must refuse
        them can, and one triaging an import table can see which kind they are.
        """
        out = []
        for va, (dll, name) in sorted(iat.items()):
            real = self.real_name(dll, name)
            argc, conv, src = self.lookup_ex(dll, name)
            out.append((va, dll, name, real, argc, conv, src))
        return out


def _selftest():
    """Check against argument counts that are fixed by published Win32 headers."""
    r = ArgcResolver()
    expected = {
        ('KERNEL32.dll', 'CreateFileA'): 7,
        ('KERNEL32.dll', 'ReadFile'): 5,
        ('KERNEL32.dll', 'VirtualAlloc'): 4,
        ('KERNEL32.dll', 'Sleep'): 1,
        ('KERNEL32.dll', 'GetLastError'): 0,
        ('USER32.dll', 'CreateWindowExA'): 12,
        ('USER32.dll', 'MessageBoxA'): 4,
        ('GDI32.dll', 'CreateDIBSection'): 6,
        ('WINMM.dll', 'waveOutOpen'): 6,      # the hand-typed tables say 7
        ('WSOCK32.dll', 'socket'): 3,
        ('DDRAW.dll', 'DirectDrawCreate'): 3,
    }
    for (dll, fn), want in expected.items():
        got = r.lookup(dll, fn)
        assert got == want, "%s!%s: expected %d, got %r" % (dll, fn, want, got)

    # Ordinal resolution: DirectSound is imported by ordinal in several titles.
    assert r.real_name('DSOUND.dll', 'ordinal_1') == 'DirectSoundCreate'
    assert r.lookup('DSOUND.dll', 'ordinal_1') == 3

    # An export that does not exist must resolve to None, never a guess.
    assert r.lookup('KERNEL32.dll', 'NoSuchExportHere') is None

    rows, unresolved = r.resolve_iat({
        0x1000: ('KERNEL32.dll', 'Sleep'),
        0x1004: ('KERNEL32.dll', 'NoSuchExportHere'),
    })
    assert rows == [(0x1000, 'KERNEL32.dll', 'Sleep', 'Sleep', 1)], rows
    assert len(unresolved) == 1 and unresolved[0][0] == 0x1004

    # --- the three kinds an SDK-only lookup used to miss -------------------

    # Convention parsing is pure string work, so it is checked without a DLL.
    conv_cases = {
        # free function, __cdecl:  ?_Xran@std@@YAXXZ
        '?_Xran@std@@YAXXZ': 'cdecl',
        # public member, __thiscall: basic_string::max_size
        '?max_size@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QBEIXZ':
            'thiscall',
        # private member, __thiscall: basic_string::_Eos
        '?_Eos@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAEXI@Z':
            'thiscall',
        # operator+ as a free __cdecl function
        '??Hstd@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@0@ABV10@0@Z':
            'cdecl',
        # static member, __cdecl: char_traits<char>::length
        '?length@?$char_traits@D@std@@SAIPBD@Z': 'cdecl',
        # a plain C name is not mangled at all
        'fopen': None,
        '_AIL_startup@0': None,
    }
    for nm, want in conv_cases.items():
        got = mangled_convention(nm)
        assert got == want, "%s: expected %r, got %r" % (nm[:40], want, got)

    # 1. Self-decorated third-party stdcall: the count is in the name.
    #    Miles imports these, and no import library for mss32 exists anywhere.
    assert r.lookup_ex('mss32.dll', '_AIL_waveOutOpen@16')[:2] == (4, 'stdcall')
    assert r.lookup_ex('mss32.dll', '_AIL_startup@0')[:2] == (0, 'stdcall')
    assert r.lookup_ex('mss32.dll', '_AIL_set_named_sample_file@20')[0] == 5

    # 2. cdecl from the mangled convention letter -> pops nothing.
    assert r.lookup_ex('MSVCP60.dll', '?_Xran@std@@YAXXZ')[:2] == (0, 'cdecl')

    # 3. __thiscall members stay unresolved, and say so rather than guessing.
    argc, conv, src = r.lookup_ex(
        'MSVCP60.dll',
        '?_Eos@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAEXI@Z')
    assert argc is None and conv == 'thiscall', (argc, conv, src)

    # 4. cdecl proven by a C-runtime export table. msvcrt.lib is not in the
    #    Windows SDK, so this path is the only one available for MSVCRT.
    for fn in ('fopen', 'memmove', 'sprintf', 'realloc', '_ftol'):
        argc, conv, src = r.lookup_ex('MSVCRT.dll', fn)
        assert (argc, conv) == (0, 'cdecl'), (fn, argc, conv, src)

    # A stdcall export must NOT be mistaken for cdecl.
    assert r.lookup_ex('KERNEL32.dll', 'Sleep')[:2] == (1, 'stdcall')

    # And the regression that motivated narrowing the rule: DirectX DLLs export
    # WINAPI functions undecorated, exactly like a C runtime does. dinput.lib is
    # not in the modern SDK, so DirectInputCreateA has no import library -- it
    # must come back unresolved, NOT as cdecl/0. Claiming 0 here would leave
    # four argument slots on the simulated stack at every call.
    argc, conv, src = r.lookup_ex('DINPUT.dll', 'DirectInputCreateA')
    assert argc is None, ('DirectInputCreateA', argc, conv, src)
    assert not _is_crt_dll('DINPUT.dll') and _is_crt_dll('MSVCRT.dll')
    assert _is_crt_dll('MSVCP60.dll') and not _is_crt_dll('KERNEL32.dll')

    # Mangled *data* symbols are imported but never called.
    assert mangled_convention('?nothrow@std@@3Unothrow_t@1@B') == 'data'
    assert r.lookup_ex('MSVCP60.dll', '?nothrow@std@@3Unothrow_t@1@B')[1] == 'data'

    ex = r.resolve_iat_ex({0x10: ('mss32.dll', '_AIL_startup@0'),
                           0x14: ('MSVCRT.dll', 'fopen')})
    assert [row[4] for row in ex] == [0, 0], ex
    assert [row[5] for row in ex] == ['stdcall', 'cdecl'], ex

    print("stdcall_argc.py self-test OK (%d checks)"
          % (len(expected) + 5 + len(conv_cases) + 18))


if __name__ == '__main__':
    import sys
    if sys.argv[1:2] == ['--selftest']:
        _selftest()
    else:
        res = ArgcResolver()
        print("SDK libs: %s" % res.sdk_dir)
        for arg in sys.argv[1:]:
            dll, _, fn = arg.partition('!')
            print("  %-22s %s" % (arg, res.lookup(dll, fn)))
