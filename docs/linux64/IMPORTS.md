# Imports: how a recompiled program reaches the outside world

A lifted PE calls an import the way the original did: it loads a slot from the
image's import address table and calls what is there. The slot therefore has to hold
something that works, and in this project that something is Wine's implementation.

`runtime/linux64/imports.{h,c}` is the shared part: it walks the import directory of
the mapped image, resolves each thunk through the host, and writes the result into the
guest's IAT. Only `host_resolve_import` differs per host, which is why the walk is
plain C:

| Host | File | Resolution |
|---|---|---|
| winelib | `imports_wine.c` | `LoadLibraryA` next to the image first, then Wine's search path, then `GetProcAddress` |
| native | `imports_host.c` | resolves nothing, and `imports_host_available()` says so |

The IAT normally sits in a read-only section, so binding makes it writable first and
restores the section's own protection afterwards, the way a real loader does.

## Calling a Win32 function from lifted code

`__remill_function_call` and `__remill_jump` check the import table before they look
for lifted guest code, because an import's address is a host address and the
dispatcher would otherwise report a missing function. The call uses the Microsoft x64
convention, which is what the import was compiled for: four arguments in RCX, RDX, R8
and R9, four more from the guest's own stack above the return address, and the result
in RAX. Eight arguments are always passed; a callee reads only the ones it declares.

The lifted `call` has already pushed a return address on the guest stack, so after the
import returns the runtime pops it, which is what the callee's `ret` would have done. A
tail jump into an import (`jmp qword ptr [IAT]`) takes the same path, with the caller's
return address as the one that gets popped.

## The one place Wine's implementation is not used

Wine's `HeapAlloc` returns *host* memory. A recompiled program writes through what it
allocated, and a host pointer is outside the address space the runtime describes: the
first HLExtract run to reach `HeapAlloc` stopped with

```
write of unmapped guest address 0x7ffffe231460 (4 bytes)
```

`0x7ffffe231460` was Wine's pointer. So the allocation family is thunked to
`guest_heap.c`, a first-fit allocator over a reserved slice of guest memory, and the
memory a program owns is memory it can address. The entries are:

`GetProcessHeap`, `HeapAlloc`, `HeapReAlloc`, `HeapFree`, `HeapSize`, `VirtualAlloc`,
`VirtualFree`, `GetProcAddress`.

This is the documented exception to "no shim for an import that exists in Wine": the
implementation is not wrong, its memory is in the wrong address space. Everything else,
`CreateFileA`, the console calls, the string calls, goes to Wine unchanged.

`GetProcAddress` needs a thunk for a different reason: it returns an address the
program will call, and a call the runtime cannot route is a stop. The thunk asks the
host and registers the answer in the import table as it is found.

## Limits worth knowing

* Only integer and pointer arguments cross the boundary. A call that also passes
  floating point would need XMM handling, and none of the imports a target has reached
  so far does.
* A struct returned by value is not handled.
* `VirtualAlloc` with an explicit address is refused (it returns 0, which a program is
  expected to handle), because an arbitrary reservation would have to be added to the
  memory model first. The "anywhere" form is served from the guest heap.
* An import's *output* buffer is the guest's (for example `GetStartupInfoA` writes into
  guest memory, which is right), but any *pointer inside* such a structure still points
  at the host. Nothing reached so far depends on one.
