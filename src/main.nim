## Build (see build.sh at the project root, which builds a binary named `86arm`):
##   nim c -d:release -o:86arm --passL:"-lunicorn" main.nim
##
## Usage:
##   86arm <arm64-file>             # quiet by default: only the process's own output is printed
##   86arm --verbose <arm64-file>   # also show loader/syscall diagnostics
##   86arm --trace <arm64-file>     # full per-instruction trace (implies --verbose)
##   86arm --hello                  # self-contained demo, no external file needed, always works
##
## REAL LIMITATIONS (read before filing a bug):
##   - `load` mode only maps segments and jumps to the entry point. If that
##     binary calls any XNU syscall outside the small translation table below
##     (write, read, open, close, lseek, getpid, mmap, munmap, mprotect, exit),
##     or needs dyld to resolve a symbol from an external dylib (libSystem...),
##     it WILL crash. This is not a bug to fix — it's an inherent limitation
##     since there is no dyld emulation.
##   - The syscall table follows XNU (bsd/kern/syscalls.master); XNU syscall
##     numbers are DIFFERENT from Linux/host-macOS, so nothing can be
##     "passed through" directly to the host — each one is translated by hand.

import unicorn_ffi
import machparse
import std/[os, strformat, posix]

const
  CodeBase: uint64 = 0x1000
  StackBase: uint64 = 0x100000
  StackSize: uint64 = 0x10000
  MmapArenaBase: uint64 = 0x200000000'u64  # dedicated region for virtual mmap, away from __TEXT/__LINKEDIT

# ---- XNU syscall translation table (numbers looked up from the real
# bsd/kern/syscalls.master, stable across XNU versions — see README.md
# for sources) ----
# XNU dispatches syscalls via `svc #0x80`, with the number in x16 (not x8
# like Linux).
const UC_ARM64_REG_X16: cint = 215

var mmapNextFree: uint64 = MmapArenaBase  # simple bump allocator, no real free
var traceCount = 0
const traceMax = 200
var verboseMode = false  # off by default: only the process's own output and real errors are shown

proc onCode(uc: UcHandle, address: culonglong, size: uint32, userData: pointer) {.cdecl.} =
  inc traceCount
  if traceCount <= traceMax:
    echo &"[trace] pc=0x{uint64(address):x} size={size}"
  elif traceCount == traceMax + 1:
    echo &"[trace] ... stopping trace output after {traceMax} instructions"

proc onMemUnmapped(uc: UcHandle, memType: cint, address: culonglong,
                    size: cint, value: clonglong, userData: pointer): bool {.cdecl.} =
  if verboseMode:
    echo &"[fault] unmapped memory access — type={memType} addr=0x{uint64(address):x} size={size}"
  return false  # do not resolve it; let uc_emu_start return the real error after logging

proc readGuestString(uc: UcHandle, addr0: uint64, maxLen: int = 4096): string =
  ## Read a null-terminated string from guest memory, used for open()'s path.
  var buf = newSeq[byte](maxLen)
  if uc_mem_read(uc, addr0, addr buf[0], csize_t maxLen) != 0:
    return ""
  var n = 0
  while n < maxLen and buf[n] != 0:
    inc n
  result = newString(n)
  if n > 0:
    copyMem(addr result[0], addr buf[0], n)

proc onIntr(uc: UcHandle, intno: uint32, userData: pointer) {.cdecl.} =
  if intno != 2'u32:   # EXCP_SWI on ARM64 in QEMU/Unicorn = 2
    return
  try:
    var syscallNo: culonglong
    discard uc_reg_read(uc, UC_ARM64_REG_X16, addr syscallNo)

    case int(syscallNo)
    of 4: # write(fd, buf, len)
      var fd, bufAddr, length: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr fd)
      discard uc_reg_read(uc, UC_ARM64_REG_X1, addr bufAddr)
      discard uc_reg_read(uc, UC_ARM64_REG_X2, addr length)

      var buf = newSeq[byte](int length)
      if length > 0:
        discard uc_mem_read(uc, bufAddr, addr buf[0], csize_t length)
      stdout.write(cast[string](buf))
      stdout.flushFile()

      var ret: culonglong = length
      discard uc_reg_write(uc, UC_ARM64_REG_X0, addr ret)

    of 3: # read(fd, buf, len)
      var fd, bufAddr, length: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr fd)
      discard uc_reg_read(uc, UC_ARM64_REG_X1, addr bufAddr)
      discard uc_reg_read(uc, UC_ARM64_REG_X2, addr length)

      var hostBuf = newSeq[byte](int length)
      let n = if length > 0: posix.read(cint fd, cast[pointer](addr hostBuf[0]), int length) else: 0
      var ret: culonglong
      if n < 0:
        ret = culonglong(0xFFFFFFFFFFFFFFFF'u64)  # -1
      else:
        if n > 0:
          discard uc_mem_write(uc, bufAddr, addr hostBuf[0], csize_t n)
        ret = culonglong(n)
      discard uc_reg_write(uc, UC_ARM64_REG_X0, addr ret)

    of 5: # open(path, flags, mode)
      var pathAddr, flags, mode: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr pathAddr)
      discard uc_reg_read(uc, UC_ARM64_REG_X1, addr flags)
      discard uc_reg_read(uc, UC_ARM64_REG_X2, addr mode)

      let path = readGuestString(uc, pathAddr)
      let fd = posix.open(path.cstring, cint flags, Mode(mode))
      var ret: culonglong = culonglong(cast[int32](fd))
      discard uc_reg_write(uc, UC_ARM64_REG_X0, addr ret)

    of 6: # close(fd)
      var fd: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr fd)
      let r = posix.close(cint fd)
      var ret: culonglong = culonglong(cast[int32](r))
      discard uc_reg_write(uc, UC_ARM64_REG_X0, addr ret)

    of 199: # lseek(fd, offset, whence)
      var fd, offset, whence: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr fd)
      discard uc_reg_read(uc, UC_ARM64_REG_X1, addr offset)
      discard uc_reg_read(uc, UC_ARM64_REG_X2, addr whence)
      let r = posix.lseek(cint fd, Off(offset), cint whence)
      var ret: culonglong = culonglong(r)
      discard uc_reg_write(uc, UC_ARM64_REG_X0, addr ret)

    of 20: # getpid()
      var ret: culonglong = culonglong(posix.getpid())
      discard uc_reg_write(uc, UC_ARM64_REG_X0, addr ret)

    of 197: # mmap(addr, len, prot, flags, fd, pos) — anonymous ONLY
      var reqAddr, length, prot, flags, fd: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr reqAddr)
      discard uc_reg_read(uc, UC_ARM64_REG_X1, addr length)
      discard uc_reg_read(uc, UC_ARM64_REG_X2, addr prot)
      discard uc_reg_read(uc, UC_ARM64_REG_X3, addr flags)
      discard uc_reg_read(uc, UC_ARM64_REG_X4, addr fd)

      const MAP_ANON = 0x1000'u64  # real XNU value; guest and host are both macOS so the bit matches
      if (uint64(flags) and MAP_ANON) == 0:
        if verboseMode:
          echo "[emu] file-backed mmap not supported (anonymous only) — returning error"
        var ret: culonglong = culonglong(0xFFFFFFFFFFFFFFFF'u64)
        discard uc_reg_write(uc, UC_ARM64_REG_X0, addr ret)
      else:
        let mapSize = (uint64(length) + 0xFFF'u64) and not 0xFFF'u64
        let base = if reqAddr != 0: uint64(reqAddr) else: mmapNextFree
        var uperms: uint32 = 0
        if (uint64(prot) and 1) != 0: uperms = uperms or uint32(UC_PROT_READ)
        if (uint64(prot) and 2) != 0: uperms = uperms or uint32(UC_PROT_WRITE)
        if (uint64(prot) and 4) != 0: uperms = uperms or uint32(UC_PROT_EXEC)

        let mapErr = uc_mem_map(uc, base, csize_t mapSize, uperms)
        if mapErr != 0:
          if verboseMode:
            echo "[emu] mmap failed: ", $uc_strerror(mapErr)
          var ret: culonglong = culonglong(0xFFFFFFFFFFFFFFFF'u64)
          discard uc_reg_write(uc, UC_ARM64_REG_X0, addr ret)
        else:
          if reqAddr == 0:
            mmapNextFree = base + mapSize
          var ret: culonglong = culonglong(base)
          discard uc_reg_write(uc, UC_ARM64_REG_X0, addr ret)

    of 73: # munmap(addr, len) — the bump allocator can't really free; treat as a no-op success
      var ret: culonglong = 0
      discard uc_reg_write(uc, UC_ARM64_REG_X0, addr ret)

    of 74: # mprotect(addr, len, prot)
      var addr0, length, prot: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr addr0)
      discard uc_reg_read(uc, UC_ARM64_REG_X1, addr length)
      discard uc_reg_read(uc, UC_ARM64_REG_X2, addr prot)

      var uperms: uint32 = 0
      if (uint64(prot) and 1) != 0: uperms = uperms or uint32(UC_PROT_READ)
      if (uint64(prot) and 2) != 0: uperms = uperms or uint32(UC_PROT_WRITE)
      if (uint64(prot) and 4) != 0: uperms = uperms or uint32(UC_PROT_EXEC)

      let mapSize = (uint64(length) + 0xFFF'u64) and not 0xFFF'u64
      let r = uc_mem_protect(uc, addr0, csize_t mapSize, uperms)
      var ret: culonglong = if r == 0: 0'u64 else: 0xFFFFFFFFFFFFFFFF'u64
      discard uc_reg_write(uc, UC_ARM64_REG_X0, addr ret)

    of 1: # exit(code)
      var code: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr code)
      if verboseMode:
        echo &"\n[emu] process exited with code {code}"
      discard uc_emu_stop(uc)

    else:
      echo &"[emu] untranslated XNU syscall number {syscallNo} — stopping (not in the translation table)"
      discard uc_emu_stop(uc)

  except CatchableError as e:
    echo "[emu] internal error while handling syscall: ", e.msg
    discard uc_emu_stop(uc)

proc newEngine(): UcHandle =
  var uc: UcHandle
  let err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, addr uc)
  if err != 0:
    raise newException(CatchableError, "uc_open failed: " & $uc_strerror(err))
  var hh: UcHook
  checkErr(uc, uc_hook_add_intr(uc, addr hh, UC_HOOK_INTR, onIntr, nil, 1, 0), "hook_add")
  result = uc

proc runHello() =
  ## Hand-assembled ARM64 machine code (no external toolchain) for:
  ##   write(1, "Hello from ARM64 inside Unicorn on x86!\n", 41)
  ##   exit(0)
  ## Encoding checked by hand against the ARMv8 ISA, using svc #0x80 +
  ## x16=syscallno (the real XNU convention, unlike Linux's x8+svc#0).
  let msg = "Hello from ARM64 inside Unicorn on x86!\n"
  let msgAddr: uint64 = CodeBase + 0x400

  var code: seq[uint32]
  # mov x0, #1          (fd = stdout)
  code.add 0xD2800020'u32
  # mov x1, msgAddr (low 16 bits) via movz/movk since the address can be >16bit
  let lo16 = uint32(msgAddr and 0xFFFF)
  let hi16 = uint32((msgAddr shr 16) and 0xFFFF)
  code.add (0xD2800001'u32 or (lo16 shl 5))          # movz x1, #lo16
  if hi16 != 0:
    code.add (0xF2A00001'u32 or (hi16 shl 5))         # movk x1, #hi16, lsl #16
  # mov x2, #len
  code.add (0xD2800002'u32 or (uint32(msg.len) shl 5)) # movz x2, #len
  # mov x16, #4          (syscall write)
  code.add 0xD2800090'u32
  # svc #0x80
  code.add 0xD4001001'u32
  # mov x0, #0
  code.add 0xD2800000'u32
  # mov x16, #1          (syscall exit)
  code.add 0xD2800030'u32
  # svc #0x80
  code.add 0xD4001001'u32

  let uc = newEngine()
  defer: discard uc_close(uc)

  checkErr(uc, uc_mem_map(uc, CodeBase, 0x1000, uint32(UC_PROT_ALL)), "map code")
  checkErr(uc, uc_mem_map(uc, StackBase, StackSize, uint32(UC_PROT_READ or UC_PROT_WRITE)), "map stack")

  checkErr(uc, uc_mem_write(uc, CodeBase, addr code[0], csize_t(code.len * 4)), "write code")
  checkErr(uc, uc_mem_write(uc, msgAddr, unsafeAddr msg[0], csize_t msg.len), "write msg")

  var sp: culonglong = StackBase + StackSize - 0x10
  discard uc_reg_write(uc, UC_ARM64_REG_SP, addr sp)

  let err = uc_emu_start(uc, CodeBase, CodeBase + culonglong(code.len * 4), 0, 0)
  if err != 0:
    echo "uc_emu_start error: ", $uc_strerror(err)

proc runLoad(path: string, trace: bool = false) =
  let info = parseMachO(path)
  if verboseMode:
    echo &"[load] {info.segments.len} segments, entry file-offset = 0x{info.entryOffset:x}"

  let uc = newEngine()
  defer: discard uc_close(uc)

  var memHook: UcHook
  const MemUnmappedMask = 16 or 32 or 64  # UC_HOOK_MEM_READ/WRITE/FETCH_UNMAPPED combined
  checkErr(uc, uc_hook_add_mem(uc, addr memHook, MemUnmappedMask, onMemUnmapped, nil, 1, 0), "hook_add_mem")

  if trace:
    var codeHook: UcHook
    checkErr(uc, uc_hook_add_code(uc, addr codeHook, UC_HOOK_CODE, onCode, nil, 1, 0), "hook_add_code")

  var textVmaddr: uint64 = 0
  var highestAddr: uint64 = 0
  for seg in info.segments:
    if seg.vmsize == 0: continue

    # __PAGEZERO (and any other prot=0 segment) only exists to trap
    # null-derefs, with no real content — mapping it would actually
    # allocate real host memory for nothing (__PAGEZERO is usually 4GB)
    # and could collide with wherever we place the stack. Skip it:
    # unmapped accesses fault naturally, which matches real behavior.
    if seg.initprot == 0:
      if verboseMode:
        echo &"  skipping {seg.name} (prot=0, guard region, no memory allocated)"
      continue

    var perms: uint32 = 0
    if (seg.initprot and 1) != 0: perms = perms or uint32(UC_PROT_READ)
    if (seg.initprot and 2) != 0: perms = perms or uint32(UC_PROT_WRITE)
    if (seg.initprot and 4) != 0: perms = perms or uint32(UC_PROT_EXEC)
    if perms == 0: perms = uint32(UC_PROT_READ)

    let mapSize = ((seg.vmsize + 0xFFF) and not 0xFFF'u64)  # align to 4K
    checkErr(uc, uc_mem_map(uc, seg.vmaddr, csize_t mapSize, perms),
             &"map segment {seg.name}")

    if seg.filesize > 0:
      let content = readFileRange(path, seg.fileoff, seg.filesize)
      if content.len > 0:
        checkErr(uc, uc_mem_write(uc, seg.vmaddr, unsafeAddr content[0], csize_t content.len),
                 &"write segment {seg.name}")

    if seg.name == "__TEXT":
      textVmaddr = seg.vmaddr

    let segEnd = seg.vmaddr + mapSize
    if segEnd > highestAddr: highestAddr = segEnd

    if verboseMode:
      echo &"  mapped {seg.name}: vmaddr=0x{seg.vmaddr:x} size=0x{seg.vmsize:x} prot={seg.initprot}"

  if textVmaddr == 0:
    echo "No __TEXT segment found, cannot determine entry point."
    return

  let entryAddr = textVmaddr + info.entryOffset

  # Place the stack right after the highest mapped segment, with a gap so
  # it doesn't sit page-adjacent to __LINKEDIT — not hardcoded, because
  # __PAGEZERO (when present) occupies the entire low address range.
  let stackBase = (highestAddr + 0x100000'u64 + 0xFFF'u64) and not 0xFFF'u64
  checkErr(uc, uc_mem_map(uc, stackBase, StackSize, uint32(UC_PROT_READ or UC_PROT_WRITE)), "map stack")
  var sp: culonglong = stackBase + StackSize - 0x10
  discard uc_reg_write(uc, UC_ARM64_REG_SP, addr sp)

  if verboseMode:
    echo &"[load] jumping to entry 0x{entryAddr:x} — if the binary needs dyld/libSystem, it will stop at the first unsupported syscall/instruction."
  # NOTE: passing until=0 is a known Unicorn quirk that can make emulation
  # stop prematurely/unpredictably (see unicorn-engine issue reports on
  # "emulation stops when address 0 is reached" even though 0 was only meant
  # as a placeholder for "run until manually stopped"). We rely entirely on
  # the exit syscall hook to call uc_emu_stop(), so pass a real sentinel
  # address that's unreachable in practice instead of 0.
  const Sentinel: culonglong = 0xFFFFFFFFFFFFFFFF'u64
  let err = uc_emu_start(uc, entryAddr, Sentinel, 0, 0)
  if verboseMode:
    echo &"[load] uc_emu_start returned: {err} ({$uc_strerror(err)})"
  elif err != 0:
    # even in quiet mode, a real failure should not be silent
    echo &"86arm: emulation stopped with an error ({$uc_strerror(err)})"

when isMainModule:
  var args = commandLineParams()
  if args.len == 0:
    echo "Usage: 86arm [--verbose] [--trace] <arm64-file>   (or: 86arm --hello for the built-in demo)"
  elif args[0] == "--hello":
    runHello()
  else:
    var trace = false
    while args.len > 0 and (args[0] == "--verbose" or args[0] == "--trace"):
      if args[0] == "--verbose": verboseMode = true
      if args[0] == "--trace":
        trace = true
        verboseMode = true  # tracing without the surrounding load/exit context is not very useful
      args = args[1..^1]
    if args.len == 0:
      echo "Usage: 86arm [--verbose] [--trace] <arm64-file>"
    else:
      # main syntax: 86arm <arm64-file>
      runLoad(args[0], trace = trace)