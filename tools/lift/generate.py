"""
Fast code generation using linear sweep disassembly.

Instead of recursive descent per function (slow), this uses a single linear
sweep through the entire code section and splits by known function boundaries.
"""

import sys
import os
import re
import time
import json

# The lifter and the PE reader are siblings under tools/, not a package. This
# file used to import them as `tools.pe_analyze` / `tools.lifter`, which have
# never been the paths -- so it did not import at all, and every project forked
# it instead of using it.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in ('pe', 'lift'):
    _p = os.path.join(_TOOLS, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import lift32
from pe_analyze import analyze_pe, build_iat_map
from lift32 import Lifter
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM


COND_JUMPS = {
    'je', 'jne', 'jz', 'jnz', 'ja', 'jae', 'jb', 'jbe',
    'jg', 'jge', 'jl', 'jle', 'js', 'jns', 'jo', 'jno',
    'jp', 'jnp', 'jcxz', 'jecxz',
}


class LinearInstruction:
    """Lightweight instruction wrapper matching the Lifter's expected interface."""
    __slots__ = ['address', 'size', 'mnemonic', 'op_str', 'bytes', 'operands',
                 'is_call', 'is_ret', 'is_cond_jump', 'is_uncond_jump', 'is_jump']

    def __init__(self, insn):
        self.address = insn.address
        self.size = insn.size
        self.mnemonic = insn.mnemonic
        self.op_str = insn.op_str
        self.bytes = bytes(insn.bytes)
        self.operands = list(insn.operands) if insn.operands else []
        self.is_call = insn.mnemonic == 'call'
        self.is_ret = insn.mnemonic in ('ret', 'retn', 'retf')
        self.is_cond_jump = insn.mnemonic in COND_JUMPS
        self.is_uncond_jump = insn.mnemonic == 'jmp'
        self.is_jump = self.is_cond_jump or self.is_uncond_jump

    @property
    def end_address(self):
        return self.address + self.size

    def get_branch_target(self):
        from capstone.x86 import X86_OP_IMM
        if self.operands:
            op = self.operands[0]
            if op.type == X86_OP_IMM:
                return op.imm & 0xFFFFFFFF
        return None

    def __repr__(self):
        return f"0x{self.address:08X}: {self.mnemonic} {self.op_str}"


def find_entries(code_data, code_start, code_end):
    """Find function entry points via call target + prologue scanning."""
    call_targets = set()
    for i in range(len(code_data) - 5):
        if code_data[i] == 0xE8:
            rel = struct.unpack_from('<i', code_data, i + 1)[0]
            target = (code_start + i + 5 + rel) & 0xFFFFFFFF
            if code_start <= target < code_end:
                call_targets.add(target)

    prologues = set()
    for i in range(len(code_data) - 3):
        if code_data[i:i+3] == b'\x55\x8B\xEC':
            prologues.add(code_start + i)
        # sub esp, imm8 after padding
        if i > 0 and code_data[i-1] in (0xCC, 0x90, 0xC3):
            if code_data[i] == 0x83 and code_data[i+1] == 0xEC:
                prologues.add(code_start + i)

    return sorted(call_targets | prologues)


def linear_disassemble_function(md, code_data, code_start, func_start, func_end):
    """
    Disassemble a function using linear sweep between known boundaries.
    Returns list of LinearInstruction and set of basic block leaders.
    """
    offset = func_start - code_start
    size = func_end - func_start
    if offset < 0 or offset + size > len(code_data):
        return [], set()

    raw = code_data[offset:offset + size]
    instructions = []
    leaders = {func_start}  # First instruction is always a leader

    for insn in md.disasm(raw, func_start):
        li = LinearInstruction(insn)
        instructions.append(li)

        if li.is_cond_jump:
            target = li.get_branch_target()
            if target and func_start <= target < func_end:
                leaders.add(target)
            leaders.add(li.end_address)  # fallthrough
        elif li.is_uncond_jump:
            target = li.get_branch_target()
            if target and func_start <= target < func_end:
                leaders.add(target)
            # Next instruction (if any) is a new leader
            leaders.add(li.end_address)

        # int3 is inter-function padding -- but MSVC also emits it INSIDE a
        # function, as the unreachable fallthrough of __assume(0) and of a
        # range-checked switch:
        #
        #     0077C86F  jbe  0x77c872
        #     0077C871  int3
        #     0077C872  <the rest of the function>
        #
        # Breaking at the first one truncated the body there. The extent walk
        # had the right answer and 0x0077C872 was already a known leader, but
        # the instructions were gone, so generate.py had a label it could not
        # place, emitted a tail transfer instead, and RECOMP_ITAIL could not
        # resolve a VA that was never lifted -- the transfer silently did
        # nothing and the function fell through to its caller. In Force
        # Commander that handed a null `this` to the DX7 pixel-pipe manager,
        # several calls away, with one "ITAIL: unresolved VA" line as the only
        # evidence.
        #
        # So an int3 ends the body only when the instruction after it is not
        # a leader -- i.e. nothing in this function jumps over it.
        #
        # "Any leader beyond it" was tried first and is far too loose: in a
        # region of overlapping entries with a distant reachability bound it
        # let the sweep run for thousands of instructions through data, and one
        # 400-function chunk came out at 104 MB. The branch that steps over an
        # int3 lands on the very next byte, so that is the test.
        if li.mnemonic == 'int3' and li.end_address not in leaders:
            break

    return instructions, leaders


# The x87 condition-code helper the lifter emits for fcom-family compares.
FPU_CMP = {'EQ': '==', 'NE': '!=', 'B': '<', 'BE': '<=', 'A': '>', 'AE': '>=',
           'L': '<', 'LE': '<=', 'G': '>', 'GE': '>='}


def lift_function_linear(lifter, name, instructions, leaders, func_start):
    """Lift a linearly-disassembled function to C code.

    The preamble comes from `lift32.FUNCTION_LOCALS`, not from a list written
    out here. That list used to be hand-copied into every project driver, and
    every copy went stale the moment the lifter started using a new local --
    which is why lift32 declares the contract and this asks for it.

    Two of the declarations this function used to emit were not merely stale,
    they were wrong, and both failed quietly:

      * `double _st[8]` / `int _fp_top` / `uint16_t _fpu_cw`. recomp_types.h
        defines `_st` as `g_st`, so those lines expanded to locals *named*
        g_st/g_fp_top/g_fpu_cw that shadowed the globals. The x87 stack is
        shared across calls -- MSVC returns a float in st0 -- so a private copy
        per function silently drops every floating-point return value.
      * `uint32_t ebp = 0`. An optimising compiler splits one function's blocks
        across the image and jumps between them, and each block addresses the
        same frame through ebp. Lifted as separate bodies, a private ebp starts
        each at 0 and the first `[ebp-0x20]` reads 0xFFFFFFE0.
    """
    va = func_start & 0xFFFFFFFF
    lines = [f'void {name}(void) {{']
    for decl in lift32.FUNCTION_LOCALS:
        lines.append(f'    {decl}')
    lines.append(f'    RECOMP_ENTER(0x{va:08X}u);')
    lines.append('')

    lifter._flag_state = None

    # An indirect jump inside a function (a switch/jump table) can compute a
    # target that lands on ANY instruction in it, so when one is present every
    # instruction needs a label for the local dispatch below to reach.
    has_indirect = any(i.is_uncond_jump and i.get_branch_target() is None
                       for i in instructions)

    for insn in instructions:
        if has_indirect or insn.address in leaders:
            lines.append(f'L_{insn.address:08X}:')
        for line in lifter.lift_instruction(insn):
            lines.append(f'    {line}')

    # Ensure function doesn't fall off the end without return
    if instructions and not instructions[-1].is_ret:
        lines.append('    return; /* end of function */')

    # Intra-function indirect jumps lift to RECOMP_ITAIL(expr), but the global
    # dispatch table only knows function *entries* -- it cannot resolve a label
    # inside this body, so every switch statement would break. Route indirect
    # tails through a local label dispatch first and fall back to the global one
    # for genuine cross-function tail calls.
    body = '\n'.join(lines)
    defined = sorted(set(re.findall(r'(?m)^\s*(L_[0-9A-Fa-f]{8})\s*:', body)))
    indirect = [i for i, l in enumerate(lines)
                if 'RECOMP_ITAIL(' in l and 'RECOMP_ITAIL(0x' not in l]
    if indirect and defined:
        for i in indirect:
            m = re.search(r'RECOMP_ITAIL\((.+?)\);\s*return;', lines[i])
            if m:
                lines[i] = ('    { _itail_tgt = (uint32_t)(%s); goto _ljump; }'
                            % m.group(1))
        lines.append('  _ljump:')
        lines.append('    switch (_itail_tgt) {')
        for lbl in defined:
            lines.append(f'      case 0x{int(lbl[2:], 16):08X}u: goto {lbl};')
        lines.append('      default: RECOMP_ITAIL(_itail_tgt); return;')
        lines.append('    }')

    # A `goto L_x` whose label is outside this body (the disassembly split a
    # function the compiler did not) has to become a real tail call.
    refed = set(re.findall(r'goto\s+(L_[0-9A-Fa-f]{8})', '\n'.join(lines)))
    for lbl in sorted(refed - set(defined)):
        lines.append(f'    {lbl}: RECOMP_ITAIL(0x{int(lbl[2:], 16):08X}u); return;')

    lines.append('}')
    out = '\n'.join(lines)
    return re.sub(r'CMP_(\w+)\(_fpu_cmp\)',
                  lambda m: f'((_fpu_cmp) {FPU_CMP.get(m.group(1), "==")} 0)', out)


def write_chunk(output_dir, file_idx, funcs):
    """Write function code to a source file."""
    filename = f'recomp_{file_idx:04d}.c'
    filepath = os.path.join(output_dir, filename)
    with open(filepath, 'w') as f:
        f.write('/* Auto-generated by XWA recompiler - DO NOT EDIT */\n')
        f.write(f'/* File {file_idx}: {len(funcs)} functions */\n\n')
        f.write('#define RECOMP_GENERATED_CODE\n')
        f.write('#include "recomp_types.h"\n')
        f.write('#include "recomp_funcs.h"\n')
        f.write('#include <math.h>\n')
        f.write('#include <string.h>\n\n')
        for code, addr, name in funcs:
            f.write(code)
            f.write('\n\n')


def _selftest():
    """Lift a hand-assembled function and check the emitted C.

    This file spent its whole life unimportable -- `from tools.pe_analyze import
    ...` was never a valid path -- so every project forked it instead. A test
    that merely imports it would already have caught that, which is most of why
    this exists.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    #   push ebp / mov ebp,esp / mov eax,[ebp+8] / jmp eax   (indirect tail)
    code = bytes([0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0xFF, 0xE0])
    base = 0x00401000
    insns, leaders = linear_disassemble_function(
        md, code, base, base, base + len(code))
    assert insns, 'nothing disassembled'
    assert any(i.is_uncond_jump and i.get_branch_target() is None for i in insns),         'the indirect jmp was not recognised'

    out = lift_function_linear(Lifter(iat_map={}), 'sub_00401000',
                              insns, leaders, base)

    # The preamble is the contract lift32 publishes, and nothing more.
    for decl in lift32.FUNCTION_LOCALS:
        assert decl in out, 'missing declared local: %s' % decl

    # The two declarations that used to be emitted here and were wrong. Both
    # expand through recomp_types.h macros, so a local of the same name shadows
    # the global and the breakage is silent.
    for bad in ('double _st[8]', 'int _fp_top = 0', 'uint16_t _fpu_cw',
                'uint32_t ebp = 0'):
        assert bad not in out, 'emitted a shadowing declaration: %s' % bad

    assert 'RECOMP_ENTER(0x00401000u);' in out, out

    # An indirect jump must route through the local label dispatch, so a switch
    # arm inside this same function is reachable; the global dispatch table only
    # knows function entries and would fail to resolve it.
    assert '_ljump:' in out and 'switch (_itail_tgt)' in out, out
    assert 'default: RECOMP_ITAIL(_itail_tgt);' in out, out
    # ...and with an indirect jump present, every instruction gets a label.
    labels = re.findall(r'(?m)^\s*(L_[0-9A-Fa-f]{8})\s*:', out)
    assert len(labels) >= len(insns) - 1, (len(labels), len(insns))

    # int3 is padding BETWEEN functions and unreachable filler INSIDE one.
    #   cmp ebx,0x6c / jbe +1 / int3 / xor eax,eax / ret
    # MSVC emits exactly this for __assume(0), and breaking at the int3 dropped
    # everything a jcc jumped over -- silently, because the target was still a
    # known leader, so the body kept a label it could not place and turned it
    # into a tail transfer to a VA nobody lifted.
    over = bytes([0x83, 0xFB, 0x6C,        # cmp ebx, 0x6c
                  0x76, 0x01,              # jbe +1  (over the int3)
                  0xCC,                    # int3
                  0x33, 0xC0, 0xC3])       # xor eax,eax / ret
    i3, l3 = linear_disassemble_function(md, over, base, base, base + len(over))
    assert i3[-1].mnemonic == 'ret', [i.mnemonic for i in i3]
    assert base + 6 in l3, 'the jumped-over continuation is not a leader'
    out3 = lift_function_linear(Lifter(iat_map={}), 'sub_00401000', i3, l3, base)
    assert 'RECOMP_ITAIL' not in out3, 'the continuation became a tail transfer'

    # ...and trailing int3 padding still ends the body: the first one is
    # emitted (it lifts to a trap, which is correct for unreachable filler) and
    # the sweep stops rather than decoding the rest of the padding run.
    pad = bytes([0x33, 0xC0, 0xC3, 0xCC, 0xCC, 0xCC])
    i4, _ = linear_disassemble_function(md, pad, base, base, base + len(pad))
    assert [i.mnemonic for i in i4] == ['xor', 'ret', 'int3'],         [i.mnemonic for i in i4]

    # A straight-line function needs no dispatch machinery at all.
    ret = bytes([0x33, 0xC0, 0xC3])            # xor eax,eax / ret
    i2, l2 = linear_disassemble_function(md, ret, base, base, base + len(ret))
    out2 = lift_function_linear(Lifter(iat_map={}), 'sub_00401000', i2, l2, base)
    assert '_ljump' not in out2 and 'switch (_itail_tgt)' not in out2, out2

    # MSVC's float comparison, which is the shape that matters: the branch is
    # taken on `ah`, not on the compare, so `fnstsw` has to produce a real
    # status word. Emitted as a comment it left `ah` stale and every float
    # comparison in the binary branched on whatever was in it.
    #
    #   fld dword [ebp+8] / fcomp dword [ebp+0xc] / fnstsw ax / test ah,0x41 / ret
    fcmp = bytes([0xD9, 0x45, 0x08,
                  0xD8, 0x5D, 0x0C,
                  0xDF, 0xE0,
                  0xF6, 0xC4, 0x41,
                  0xC3])
    i3, l3 = linear_disassemble_function(md, fcmp, base, base, base + len(fcmp))
    out3 = lift_function_linear(Lifter(iat_map={}), 'sub_00401000', i3, l3, base)
    assert '_fpu_cmp' in out3, out3
    assert 'fnstsw - FPU status to ax' not in out3, 'fnstsw is still a comment'
    assert '0x4000u' in out3 and '0x0100u' in out3, out3
    assert 'eax = (eax & 0xFFFF0000u)' in out3, out3

    print('generate.py self-test OK')


def main():
    if '--selftest' in sys.argv:
        _selftest()
        return
    exe_path = sys.argv[1] if len(sys.argv) > 1 else 'config/xwingalliance_decrypted.exe'
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'src/game/recomp/gen'
    split_size = int(sys.argv[3]) if len(sys.argv) > 3 else 500

    os.makedirs(output_dir, exist_ok=True)

    print(f'[*] Loading PE: {exe_path}', flush=True)
    info = analyze_pe(exe_path)
    iat_map = build_iat_map(info)

    with open(exe_path, 'rb') as f:
        pe_data = f.read()

    code_start = info.code_start
    code_end = info.code_end

    # Read code section
    text_sect = [s for s in info.sections if s.name == '.text'][0]
    offset = text_sect.raw_offset
    size = min(text_sect.virtual_size, text_sect.raw_size)
    code_data = pe_data[offset:offset + size]
    print(f'[*] Code: 0x{code_start:08X}-0x{code_end:08X} ({len(code_data):,} bytes)', flush=True)

    # Phase 1: Find entries
    print('[*] Phase 1: Finding function entries...', flush=True)
    entries = find_entries(code_data, code_start, code_end)
    print(f'[*] Found {len(entries)} function entries', flush=True)

    # Phase 2: Disassemble + lift
    print('[*] Phase 2: Disassembling and lifting...', flush=True)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lifter = Lifter(iat_map=iat_map)

    all_entries = []
    func_stats = []
    error_count = 0
    file_idx = 0
    chunk_funcs = []
    start = time.time()

    for idx, addr in enumerate(entries):
        # Function end = next entry or code end (cap at 64KB)
        if idx + 1 < len(entries):
            func_end = min(entries[idx + 1], addr + 65536)
        else:
            func_end = min(code_end, addr + 65536)

        if func_end - addr < 2:
            continue

        name = f'sub_{addr:08X}'

        try:
            instructions, leaders = linear_disassemble_function(
                md, code_data, code_start, addr, func_end)

            if not instructions:
                continue

            # Trim: stop at first int3, and skip garbage after ret
            # unless a label follows (which indicates a reachable block)
            trimmed = []
            seen_ret = False
            for insn in instructions:
                if insn.mnemonic == 'int3':
                    break
                # After a ret, only continue if this address is a jump target
                if seen_ret:
                    if insn.address not in leaders:
                        continue  # skip garbage between ret and next label
                    seen_ret = False  # found a label, resume
                trimmed.append(insn)
                if insn.is_ret:
                    seen_ret = True
            if not trimmed:
                continue

            code = lift_function_linear(lifter, name, trimmed, leaders, addr)
            chunk_funcs.append((code, addr, name))
            all_entries.append((addr, name))

            func_stats.append({
                'address': f'0x{addr:08X}',
                'address_int': addr,
                'name': name,
                'num_instructions': len(trimmed),
            })

        except Exception as e:
            stub = f'/* ERROR: {name} at 0x{addr:08X}: {e} */\nvoid {name}(void) {{ /* error */ }}\n'
            chunk_funcs.append((stub, addr, name))
            all_entries.append((addr, name))
            error_count += 1

        # Write chunk
        if len(chunk_funcs) >= split_size:
            write_chunk(output_dir, file_idx, chunk_funcs)
            elapsed = time.time() - start
            rate = len(all_entries) / elapsed if elapsed > 0 else 0
            print(f'[*] {len(all_entries)}/{len(entries)} functions '
                  f'({file_idx + 1} files, {rate:.0f}/s, {error_count} err)', flush=True)
            file_idx += 1
            chunk_funcs = []

    # Write remaining
    if chunk_funcs:
        write_chunk(output_dir, file_idx, chunk_funcs)
        file_idx += 1

    # Phase 3: Header + dispatch
    print('[*] Phase 3: Generating header and dispatch table...', flush=True)

    header_path = os.path.join(output_dir, 'recomp_funcs.h')
    with open(header_path, 'w') as f:
        f.write('#pragma once\n#include <stdint.h>\n\n')
        f.write(f'/* {len(all_entries)} recompiled functions */\n\n')
        for addr, name in all_entries:
            f.write(f'void {name}(void);  /* 0x{addr:08X} */\n')

    dispatch_path = os.path.join(output_dir, 'recomp_dispatch.c')
    with open(dispatch_path, 'w') as f:
        f.write('#include "recomp_types.h"\n')
        f.write('#include "recomp_funcs.h"\n\n')
        f.write('const recomp_dispatch_entry_t recomp_dispatch_table[] = {\n')
        for addr, name in sorted(all_entries, key=lambda x: x[0]):
            f.write(f'    {{ 0x{addr:08X}u, {name} }},\n')
        f.write('};\n\n')
        f.write(f'const uint32_t recomp_dispatch_count = {len(all_entries)};\n')

    # Export function list
    with open('config/functions.json', 'w') as f:
        json.dump(func_stats, f, indent=2)

    elapsed = time.time() - start
    total_lines = 0
    total_bytes = 0
    for fn in os.listdir(output_dir):
        fp = os.path.join(output_dir, fn)
        if os.path.isfile(fp):
            total_bytes += os.path.getsize(fp)
            with open(fp, 'r') as f:
                total_lines += sum(1 for _ in f)

    print(f'\n[*] === COMPLETE ===', flush=True)
    print(f'[*] {len(all_entries)} functions recompiled', flush=True)
    print(f'[*] {file_idx} source files + header + dispatch', flush=True)
    print(f'[*] {error_count} errors', flush=True)
    print(f'[*] {total_lines:,} total lines of C', flush=True)
    print(f'[*] {total_bytes / 1048576:.1f} MB of generated code', flush=True)
    print(f'[*] Time: {elapsed:.1f}s', flush=True)


if __name__ == '__main__':
    main()
