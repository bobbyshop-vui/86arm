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
import objc_ffi
import std/[os, strformat, strutils, posix, tables, dynlib, math, random]

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

const
  ThunkBase: uint64 = 0x300000000'u64  # dedicated region for thunk trampolines, never real guest code
  ThunkSlotSize: uint64 = 16

# ---- REAL host libSystem functions, called directly since 86arm itself is
# a native process linked against the host's real libSystem. Each thunk
# reads its arguments from ARM64 registers per AAPCS64 (x0, x1, ... for
# integer/pointer args), calls the real host implementation, writes the
# result to x0, then sets PC = LR so execution "returns" to the caller.
proc c_getpid(): cint {.importc: "getpid", header: "<unistd.h>".}
proc c_malloc(size: csize_t): pointer {.importc: "malloc", header: "<stdlib.h>".}
proc c_free(p: pointer) {.importc: "free", header: "<stdlib.h>".}

# ---- objc_msgSend: NOT a fixed signature — real Objective-C messages take
# a variable number/type of arguments depending on the selector. Without
# libffi + runtime type-encoding lookup (not implemented yet), we can only
# support a FIXED set of call shapes, each cast to its own function-pointer
# type. This covers two common shapes:
#   0 extra args, pointer return  — e.g. -description, -length, -count
#   1 pointer arg, pointer return — e.g. -initWithUTF8String:, +alloc-style
# Any other selector arity (2+ args, non-pointer args, struct returns,
# floating-point args) is NOT covered and will call through the wrong
# signature — likely a crash or garbage result, not silent success.
type
  ObjcMsgSend1 = proc(self: pointer, sel: pointer, a1: pointer): pointer {.cdecl.}
  AutoreleasePoolPushFn = proc(): pointer {.cdecl.}
  AutoreleasePoolPopFn = proc(token: pointer) {.cdecl.}

proc readGuestString(uc: UcHandle, addr0: uint64, maxLen: int = 4096): string =
  ## Read a null-terminated string from guest memory (open()'s path, selector
  ## names, C-string arguments...). Reads in small chunks so a string sitting
  ## near the end of a mapped segment doesn't make the whole read fail.
  var buf = newSeq[byte](64)
  var cur = addr0
  while result.len < maxLen:
    var got = 0
    var chunk = 64
    while chunk >= 1:
      if uc_mem_read(uc, cur, addr buf[0], csize_t chunk) == 0:
        got = chunk
        break
      chunk = chunk div 2
    if got == 0: return
    for i in 0 ..< got:
      if buf[i] == 0: return
      result.add(char(buf[i]))
    cur += uint64(got)

proc readGuestBytes(uc: UcHandle, addr0: uint64, n: int): seq[byte] =
  result = newSeq[byte](n)
  if n > 0 and uc_mem_read(uc, addr0, addr result[0], csize_t n) != 0:
    result = @[]

let libobjc = loadLib("/usr/lib/libobjc.A.dylib")
var objcMsgSendAddr: pointer = nil
var objcGetClassAddr: pointer = nil
var selRegisterNameAddr: pointer = nil
var objcAutoreleasePoolPushAddr: pointer = nil
var objcAutoreleasePoolPopAddr: pointer = nil
if libobjc != nil:
  objcMsgSendAddr = symAddr(libobjc, "objc_msgSend")
  objcGetClassAddr = symAddr(libobjc, "objc_getClass")
  selRegisterNameAddr = symAddr(libobjc, "sel_registerName")
  objcAutoreleasePoolPushAddr = symAddr(libobjc, "objc_autoreleasePoolPush")
  objcAutoreleasePoolPopAddr = symAddr(libobjc, "objc_autoreleasePoolPop")
if objcMsgSendAddr == nil and verboseMode:
  echo "[thunk] warning: could not dlsym real objc_msgSend from libobjc.A.dylib"

# ---- Foundation / CoreFoundation: needed for NSLog and for the
# compile-time NSConstantString literal's `isa` bind
# (___CFConstantStringClassReference). Loaded the same way as libobjc
# above — these are real host frameworks, already present on every macOS
# system, so no new files/downloads are involved. ----
let libFoundation = loadLib("/System/Library/Frameworks/Foundation.framework/Foundation")
let libCF = loadLib("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
# AppKit (and thereby the real WindowServer connection, run loop, windows...)
# lives on the HOST — the arm64 guest only ever drives it through thunks.
let libAppKit = loadLib("/System/Library/Frameworks/AppKit.framework/AppKit")
let libSystemH = loadLib("/usr/lib/libSystem.B.dylib")
var nsLogAddr: pointer = nil
var cfConstantStringClassAddr: pointer = nil
if libFoundation != nil:
  nsLogAddr = symAddr(libFoundation, "NSLog")
if libCF != nil:
  # This is the real global CFConstantString class object CoreFoundation
  # exports; clang's compile-time @"..." literals bind their `isa` field
  # to exactly this symbol. It's DATA (a pointer value to read), same
  # shape as _OBJC_CLASS_$_* below, not a function to thunk.
  cfConstantStringClassAddr = symAddr(libCF, "__CFConstantStringClassReference")
if verboseMode:
  if nsLogAddr == nil:
    echo "[thunk] warning: could not dlsym real NSLog from Foundation"
  if cfConstantStringClassAddr == nil:
    echo "[thunk] warning: could not dlsym __CFConstantStringClassReference from CoreFoundation"

var blockClassAddrs: seq[uint64]   # host addresses of the 3 _NSConcrete*Block classes
var stackBlockIsa: uint64 = 0
var globalBlockIsa: uint64 = 0
for nm in ["_NSConcreteStackBlock", "_NSConcreteGlobalBlock", "_NSConcreteMallocBlock"]:
  if libSystemH != nil:
    let p = symAddr(libSystemH, nm)
    if p != nil:
      blockClassAddrs.add(cast[uint64](p))
      if nm == "_NSConcreteStackBlock": stackBlockIsa = cast[uint64](p)
      if nm == "_NSConcreteGlobalBlock": globalBlockIsa = cast[uint64](p)

let objcFfiReady = initObjcFfi(verboseMode)
if verboseMode:
  if objcFfiReady:
    echo "[thunk] generic libffi + runtime-introspection objc_msgSend path available"
  else:
    echo "[thunk] generic libffi path unavailable — falling back to hand-written selector cases only"

type
  ObjcGetClassFn = proc(name: cstring): pointer {.cdecl.}
  SelRegisterNameFn = proc(name: cstring): pointer {.cdecl.}

proc resolveSel(uc: UcHandle, guestSelAddr: uint64): pointer =
  ## The `sel` argument the guest passes is a pointer into GUEST memory
  ## (Unicorn's own address space) — NOT a valid pointer in the real host
  ## process. Passing it straight to the real objc_msgSend crashes (this
  ## was confirmed: SIGSEGV reading a guest-space "pointer" as if it were
  ## a real host address). Fix: read the actual selector STRING out of
  ## guest memory ourselves, then ask the REAL host runtime for the real,
  ## valid SEL via sel_registerName — never pass a guest address to a host
  ## function expecting a host pointer.
  if selRegisterNameAddr == nil: return nil
  let name = readGuestString(uc, guestSelAddr, 256)
  let fn = cast[SelRegisterNameFn](selRegisterNameAddr)
  fn(name.cstring)

proc resolveDataSymbol(name: string): tuple[ok: bool, value: uint64] =
  ## Handles bind symbols that are DATA (a value to be read), not CODE (a
  ## function to call through the thunk region). Two patterns supported:
  ##   1. `_OBJC_CLASS_$_<Name>` — every Objective-C class reference the
  ##      compiler emits — via the REAL host objc_getClass("<Name>").
  ##   2. `___CFConstantStringClassReference` — the `isa` bind every
  ##      compile-time @"..." string literal carries, resolved via the
  ##      REAL host CoreFoundation's own exported class object. Needed so
  ##      NSLog(@"...", ...) receives a literal whose isa actually points
  ##      at a valid real class, instead of a dangling guest-space value.
  ## Either way we hand back a REAL host pointer, so anything built from
  ## it (msgSend calls, NSLog reading the format's isa, etc.) stays
  ## consistent with real host-side objects.
  const objcPrefix = "_OBJC_CLASS_$_"
  if name.startsWith(objcPrefix) and objcGetClassAddr != nil:
    let className = name[objcPrefix.len ..< name.len]
    let fn = cast[ObjcGetClassFn](objcGetClassAddr)
    let cls = fn(className.cstring)
    if cls != nil:
      return (true, cast[uint64](cls))
  if name == "___CFConstantStringClassReference" and cfConstantStringClassAddr != nil:
    return (true, cast[uint64](cfConstantStringClassAddr))
  # Block runtime classes + the main dispatch queue: the guest takes their
  # ADDRESS (a block's isa; dispatch_get_main_queue() is &_dispatch_main_q).
  if (name.startsWith("__NSConcrete") or name == "__dispatch_main_q") and libSystemH != nil:
    let p = symAddr(libSystemH, name[1 .. ^1])
    if p != nil: return (true, cast[uint64](p))
  return (false, 0'u64)

# ---- guest <-> host translation helpers --------------------------------------
var guestRanges: seq[tuple[lo, hi: uint64]]   # every guest-mapped region (filled in runLoad)
var literalCache = initTable[uint64, uint64]()  # guest CFString literal addr -> retained host NSString

proc inGuest(a: uint64): bool =
  for r in guestRanges:
    if a >= r.lo and a < r.hi: return true
  false

const CallbackRet: uint64 = 0x500000000'u64   # LR target that ends a nested guest call
var activeUc: UcHandle = nil
proc syncShadowVars(uc: UcHandle)   # defined below

proc callGuest(uc: UcHandle, fn: uint64, args: openArray[uint64]): uint64 =
  ## Runs a GUEST (arm64) function to completion from host code, by re-entering
  ## Unicorn (nested uc_emu_start), and returns its X0. The outer emulation's
  ## full register context is saved/restored around it.
  var ctx: pointer = nil
  discard uc_context_alloc(uc, addr ctx)
  discard uc_context_save(uc, ctx)
  for i in 0 ..< min(args.len, 8):
    var v: culonglong = args[i]
    discard uc_reg_write(uc, UC_ARM64_REG_X0 + cint(i), addr v)
  var sp: culonglong
  discard uc_reg_read(uc, UC_ARM64_REG_SP, addr sp)
  sp = (sp - 0x400) and not 0xF'u64
  discard uc_reg_write(uc, UC_ARM64_REG_SP, addr sp)
  var lr: culonglong = CallbackRet
  discard uc_reg_write(uc, UC_ARM64_REG_X30, addr lr)
  let err = uc_emu_start(uc, culonglong(fn), culonglong CallbackRet, 0, 0)
  if err != 0 and verboseMode:
    echo &"[callback] nested guest call ended with {$uc_strerror(err)}"
  var x0: culonglong
  discard uc_reg_read(uc, UC_ARM64_REG_X0, addr x0)
  discard uc_context_restore(uc, ctx)
  discard uc_context_free(ctx)
  syncShadowVars(uc)
  uint64 x0

proc readU64(b: seq[byte], off: int): uint64 =
  for i in 0 ..< 8: result = result or (uint64(b[off + i]) shl (8 * i))

proc makeHostNSString(text: string): uint64 =
  let nsStringCls = cast[ObjcGetClassFn](objcGetClassAddr)("NSString")
  let selAlloc = cast[SelRegisterNameFn](selRegisterNameAddr)("alloc")
  let selInit = cast[SelRegisterNameFn](selRegisterNameAddr)("initWithUTF8String:")
  let raw = callObjcMsgSendRaw(objcMsgSendAddr, nsStringCls, selAlloc, @[])
  let hostBuf = c_malloc(csize_t(text.len + 1))
  if text.len > 0: copyMem(hostBuf, unsafeAddr text[0], text.len)
  cast[ptr UncheckedArray[byte]](hostBuf)[text.len] = 0
  let obj = callObjcMsgSendRaw(objcMsgSendAddr, raw, selInit, @[hostBuf])
  c_free(hostBuf)
  cast[uint64](obj)

# ---- blocks (^{...}) ----------------------------------------------------------
# A guest block is a struct in GUEST memory: {isa, flags, reserved, invoke,
# descriptor, captures...}; `invoke` is guest code. The host can't read that
# memory, so whenever a block crosses to the host we build a REAL host block
# whose invoke is a libffi closure that re-enters the emulator and calls the
# guest `invoke(guestBlock, args...)`. Up to 4 pointer-sized args (integer
# registers) are forwarded.
var hostBlockCache = initTable[uint64, uint64]()

type BlockCtx = object
  guestBlock: uint64
  guestInvoke: uint64

proc blockInvokeHandler(cif: pointer, ret: pointer, args: pointer, ud: pointer) {.cdecl.} =
  let c = cast[ptr BlockCtx](ud)
  let a = cast[ptr UncheckedArray[pointer]](args)
  if verboseMode:
    echo &"[callback] host -> guest block invoke 0x{c.guestInvoke:x}"
  var g: array[5, uint64]
  g[0] = c.guestBlock
  for i in 1 .. 4: g[i] = cast[ptr uint64](a[i])[]
  cast[ptr uint64](ret)[] = callGuest(activeUc, c.guestInvoke, g)

proc makeHostBlock(uc: UcHandle, gb: uint64, isa: uint64): uint64 =
  let cacheable = isa != stackBlockIsa   # a stack block's address gets reused
  if cacheable and hostBlockCache.hasKey(gb): return hostBlockCache[gb]
  let hdr = readGuestBytes(uc, gb, 32)
  if hdr.len < 32: return gb
  let ctx = cast[ptr BlockCtx](c_malloc(16))
  ctx.guestBlock = gb
  ctx.guestInvoke = readU64(hdr, 16)
  let imp = makeImpClosure(blockInvokeHandler, ctx)
  if imp == nil or globalBlockIsa == 0: return gb
  let blk = cast[ptr UncheckedArray[uint64]](c_malloc(32))
  let desc = cast[ptr UncheckedArray[uint64]](c_malloc(16))
  desc[0] = 0; desc[1] = 32
  blk[0] = globalBlockIsa                  # global blocks are never copied/freed
  blk[1] = (1'u64 shl 28)                  # BLOCK_IS_GLOBAL; reserved = 0
  blk[2] = cast[uint64](imp)
  blk[3] = cast[uint64](desc)
  let r = cast[uint64](blk)
  if cacheable: hostBlockCache[gb] = r
  r

proc guestToHostObj(uc: UcHandle, a: uint64): uint64 =
  ## Translate an object/block pointer the guest hands to the host:
  ##  - guest compile-time @"..." literal -> real, retained host NSString
  ##  - guest block                       -> real host block calling back in
  ## Anything else (host objects are already real host pointers) is unchanged.
  if a == 0 or not inGuest(a): return a
  if literalCache.hasKey(a): return literalCache[a]
  let b = readGuestBytes(uc, a, 32)
  if b.len < 32: return a
  let isa = readU64(b, 0)
  if isa in blockClassAddrs: return makeHostBlock(uc, a, isa)
  if cfConstantStringClassAddr == nil or isa != cast[uint64](cfConstantStringClassAddr):
    # clang >= 14 can emit constant collection/number literals straight into
    # __DATA ({isa, count, objects*} etc). Their isa is a real host class, but
    # the object itself is guest memory -> rebuild a real host object.
    let pName = symAddr(libobjc, "class_getName")
    if pName != nil and isa != 0:
      let cn = callHostPtrFn(pName, @[isa])
      if cn != 0:
        let clsName = $cast[cstring](cast[pointer](cn))
        if verboseMode: echo &"[translate] guest object 0x{a:x} isa class {clsName}"
        let sr = cast[SelRegisterNameFn](selRegisterNameAddr)
        let pRetain = symAddr(libobjc, "objc_retain")
        case clsName
        of "NSConstantArray":
          let count = int readU64(b, 8)
          if verboseMode: echo &"[translate] NSConstantArray count={count} objs@0x{readU64(b, 16):x}"
          let raw = readGuestBytes(uc, readU64(b, 16), count * 8)
          if raw.len == count * 8 and count < 100000:
            let buf = cast[ptr UncheckedArray[uint64]](c_malloc(csize_t(max(count, 1) * 8)))
            for i in 0 ..< count:
              buf[i] = guestToHostObj(uc, readU64(raw, i * 8))
            let arrCls = cast[ObjcGetClassFn](objcGetClassAddr)("NSArray")
            let r = callObjcMsgSendRaw(objcMsgSendAddr, arrCls, sr("arrayWithObjects:count:"),
                                       @[cast[pointer](buf), cast[pointer](count)])
            c_free(cast[pointer](buf))
            if verboseMode: echo &"[translate] built host NSArray 0x{cast[uint64](r):x}"
            let obj = callHostPtrFn(pRetain, @[cast[uint64](r)])
            literalCache[a] = obj
            return obj
        of "NSConstantIntegerNumber":
          let numCls = cast[ObjcGetClassFn](objcGetClassAddr)("NSNumber")
          let r = callObjcMsgSendRaw(objcMsgSendAddr, numCls, sr("numberWithLongLong:"),
                                     @[cast[pointer](readU64(b, 8))])
          let obj = callHostPtrFn(pRetain, @[cast[uint64](r)])
          literalCache[a] = obj
          return obj
        else: discard
    return a
  let text = readGuestString(uc, readU64(b, 16), 65536)
  let obj = makeHostNSString(text)
  literalCache[a] = obj
  obj

# ---- NSString <-> Nim string, and a printf engine for GUEST varargs ---------
proc nsStringToNim(uc: UcHandle, obj: uint64): string =
  if obj == 0: return "(null)"
  if inGuest(obj):
    let b = readGuestBytes(uc, obj, 32)
    if b.len == 32: return readGuestString(uc, readU64(b, 16), 65536)
    return ""
  let sel = cast[SelRegisterNameFn](selRegisterNameAddr)("UTF8String")
  let p = callObjcMsgSendRaw(objcMsgSendAddr, cast[pointer](obj), sel, @[])
  if p == nil: return ""
  $cast[cstring](p)

proc describeObj(uc: UcHandle, obj: uint64): string =
  if obj == 0: return "(null)"
  if inGuest(obj): return nsStringToNim(uc, obj)
  let sel = cast[SelRegisterNameFn](selRegisterNameAddr)("description")
  let d = callObjcMsgSendRaw(objcMsgSendAddr, cast[pointer](obj), sel, @[])
  nsStringToNim(uc, cast[uint64](d))

proc c_snprintf_i(buf: cstring, n: csize_t, fmt: cstring, a: clonglong): cint {.importc: "snprintf", header: "<stdio.h>".}
proc c_snprintf_d(buf: cstring, n: csize_t, fmt: cstring, a: cdouble): cint {.importc: "snprintf", header: "<stdio.h>".}
proc c_snprintf_s(buf: cstring, n: csize_t, fmt: cstring, a: cstring): cint {.importc: "snprintf", header: "<stdio.h>".}

proc formatGuest(uc: UcHandle, fmt: string, nextArg: proc(): uint64): string =
  ## printf-style formatting where every vararg comes from `nextArg` (Apple
  ## arm64 passes ALL variadic args in 8-byte stack slots, ints and doubles
  ## alike). Adds %@ (object description). Each piece is formatted by the host
  ## libc snprintf, so flags/width/precision behave exactly like C.
  var i = 0
  var buf = newString(2048)
  while i < fmt.len:
    if fmt[i] != '%':
      result.add(fmt[i]); inc i; continue
    inc i
    if i >= fmt.len: break
    if fmt[i] == '%': result.add('%'); inc i; continue
    var flags, width, prec, lenmod: string
    while i < fmt.len and fmt[i] in {'-', '+', ' ', '#', '0'}: flags.add(fmt[i]); inc i
    if i < fmt.len and fmt[i] == '*':
      width = $int32(nextArg() and 0xFFFFFFFF'u64); inc i
    else:
      while i < fmt.len and fmt[i] in {'0'..'9'}: width.add(fmt[i]); inc i
    var hasPrec = false
    if i < fmt.len and fmt[i] == '.':
      hasPrec = true; inc i
      if i < fmt.len and fmt[i] == '*':
        prec = $int32(nextArg() and 0xFFFFFFFF'u64); inc i
      else:
        while i < fmt.len and fmt[i] in {'0'..'9'}: prec.add(fmt[i]); inc i
    while i < fmt.len and fmt[i] in {'h', 'l', 'q', 'L', 'z', 'j', 't'}: lenmod.add(fmt[i]); inc i
    if i >= fmt.len: break
    let conv = fmt[i]; inc i
    let precPart = (if hasPrec: "." & prec else: "")
    let wide = lenmod.len > 0 and lenmod[0] in {'l', 'q', 'z', 'j', 't'}
    case conv
    of 'd', 'i', 'u', 'x', 'X', 'o', 'c':
      let raw = nextArg()
      var v: clonglong
      if wide: v = cast[clonglong](raw)
      elif conv in {'d', 'i'}: v = clonglong(cast[int32](uint32(raw and 0xFFFFFFFF'u64)))
      else: v = clonglong(raw and 0xFFFFFFFF'u64)
      let spec = "%" & flags & width & precPart & "ll" & (if conv == 'c': "c" else: $conv)
      let n = c_snprintf_i(buf.cstring, 2048, spec.cstring, v)
      if n > 0: result.add(buf[0 ..< min(int(n), 2047)])
    of 'f', 'F', 'e', 'E', 'g', 'G', 'a', 'A':
      let d = cast[cdouble](nextArg())
      let spec = "%" & flags & width & precPart & $conv
      let n = c_snprintf_d(buf.cstring, 2048, spec.cstring, d)
      if n > 0: result.add(buf[0 ..< min(int(n), 2047)])
    of 's':
      let p = nextArg()
      let str = (if p == 0: "(null)" else: readGuestString(uc, p, 65536))
      let spec = "%" & flags & width & precPart & "s"
      let n = c_snprintf_s(buf.cstring, 2048, spec.cstring, str.cstring)
      if n > 0: result.add(buf[0 ..< min(int(n), 2047)])
    of 'p':
      result.add("0x" & toHex(nextArg(), 1).toLowerAscii.strip(chars = {'0'}, trailing = false))
    of '@':
      result.add(describeObj(uc, nextArg()))
    else:
      result.add('%'); result.add(conv)

proc stackArgReader(uc: UcHandle): proc(): uint64 =
  ## Variadic args of the call currently being thunked: [sp], [sp+8], ...
  var spv: culonglong
  discard uc_reg_read(uc, UC_ARM64_REG_SP, addr spv)
  var idx = 0
  let base = uint64 spv
  result = proc(): uint64 =
    var v: uint64 = 0
    discard uc_mem_read(uc, base + uint64(idx * 8), addr v, 8)
    inc idx
    v

proc guestToHostSel(uc: UcHandle, a: uint64): uint64 =
  if a == 0 or not inGuest(a): return a
  cast[uint64](resolveSel(uc, a))

# ---- host DATA variables (e.g. NSApp, NSDefaultRunLoopMode) ------------------
# A bind to a data symbol makes the guest load the variable's value through
# the GOT slot, i.e. the slot must hold a GUEST-readable address. We give each
# such variable a "shadow cell" in guest memory and re-copy the real host
# value into it after every thunk call (NSApp only becomes non-nil once the
# guest has called +sharedApplication, for instance).
const
  ShadowBase: uint64 = 0x400000000'u64
  ShadowSize: uint64 = 0x1000'u64
  shadowVarNames = ["_NSApp", "_NSDefaultRunLoopMode", "_NSEventTrackingRunLoopMode",
                    "_NSModalPanelRunLoopMode", "_NSRunLoopCommonModes",
                    "_NSPasteboardTypeString", "_NSFontAttributeName",
                    "_NSForegroundColorAttributeName", "_NSBackgroundColorAttributeName",
                    "_NSParagraphStyleAttributeName", "___stack_chk_guard"]

type ShadowVar = object
  name: string
  hostAddr: pointer
  guestAddr: uint64

var shadowVars: seq[ShadowVar]

var stackGuardValue: uint64 = 0x5a17c0de5eed0001'u64

proc findHostData(sym: string): pointer =
  if sym == "___stack_chk_guard": return addr stackGuardValue
  let n = sym[1 .. ^1]  # strip the leading underscore
  for lib in [libAppKit, libFoundation, libCF]:
    if lib != nil:
      let p = symAddr(lib, n)
      if p != nil: return p
  nil

proc syncShadowVars(uc: UcHandle) =
  for sv in shadowVars:
    var v: uint64 = cast[ptr uint64](sv.hostAddr)[]
    discard uc_mem_write(uc, sv.guestAddr, addr v, 8)

type ThunkProc = proc(uc: UcHandle) {.closure.}

proc thunkReturn(uc: UcHandle, x0: uint64) =
  var v: culonglong = x0
  discard uc_reg_write(uc, UC_ARM64_REG_X0, addr v)
  var lr: culonglong
  discard uc_reg_read(uc, UC_ARM64_REG_X30, addr lr)
  var pc: culonglong = lr
  discard uc_reg_write(uc, UC_ARM64_REG_PC, addr pc)

proc thunkReturnStruct2(uc: UcHandle, w0: uint64, w1: uint64) =
  ## Same as thunkReturn, but also writes X1 — needed for small (≤16
  ## byte, no float/double field) struct returns, which AAPCS64 packs
  ## as raw memory bytes across X0 (bytes 0-7) then X1 (bytes 8-15)
  ## rather than a single register. See objc_ffi.nim's
  ## CallGenericResult.retIsStruct for where these words come from.
  var v0: culonglong = w0
  discard uc_reg_write(uc, UC_ARM64_REG_X0, addr v0)
  var v1: culonglong = w1
  discard uc_reg_write(uc, UC_ARM64_REG_X1, addr v1)
  var lr: culonglong
  discard uc_reg_read(uc, UC_ARM64_REG_X30, addr lr)
  var pc: culonglong = lr
  discard uc_reg_write(uc, UC_ARM64_REG_PC, addr pc)

proc thunkReturnVoidKeepRegs(uc: UcHandle) =
  ## Return to the caller (PC = LR) without touching X0 / return registers.
  var lr: culonglong
  discard uc_reg_read(uc, UC_ARM64_REG_X30, addr lr)
  var pc: culonglong = lr
  discard uc_reg_write(uc, UC_ARM64_REG_PC, addr pc)

proc thunkReturnFloat(uc: UcHandle, bits: uint64) =
  ## For scalar float/double returns: AAPCS64 returns these in D0, NOT
  ## X0 — writing X0 instead (as an earlier version of this code did
  ## implicitly, before float/double return support existed at all)
  ## would leave the guest reading garbage/stale D0 content. X0 is left
  ## untouched here deliberately (guest code for a float/double-
  ## returning call reads D0 only, never X0, so X0's value doesn't matter).
  var v: culonglong = bits
  discard uc_reg_write(uc, UC_ARM64_REG_D0, addr v)
  var lr: culonglong
  discard uc_reg_read(uc, UC_ARM64_REG_X30, addr lr)
  var pc: culonglong = lr
  discard uc_reg_write(uc, UC_ARM64_REG_PC, addr pc)

const
  GuestHeapBase: uint64 = 0x600000000'u64
  GuestHeapSize: uint64 = 0x10000000'u64
var guestHeapNext: uint64 = GuestHeapBase

proc guestAlloc(uc: UcHandle, n: uint64): uint64 =
  let total = ((n + 15) and not 15'u64) + 16
  if guestHeapNext + total > GuestHeapBase + GuestHeapSize: return 0
  var sz = n
  discard uc_mem_write(uc, guestHeapNext, addr sz, 8)
  result = guestHeapNext + 16
  guestHeapNext += total

proc guestSizeOf(uc: UcHandle, p: uint64): uint64 =
  discard uc_mem_read(uc, p - 16, addr result, 8)

proc writeGuestCStr(uc: UcHandle, dst: uint64, str: string) =
  var b = newSeq[byte](str.len + 1)
  for i, c in str: b[i] = byte(c)
  discard uc_mem_write(uc, dst, addr b[0], csize_t b.len)

proc reg(uc: UcHandle, i: int): uint64 =
  var v: culonglong
  discard uc_reg_read(uc, UC_ARM64_REG_X0 + cint(i), addr v)
  uint64 v

proc hostObjBuffer(uc: UcHandle, guestPtr: uint64, n: int): pointer =
  ## copy a guest array of object pointers into a host buffer, translating each
  let buf = cast[ptr UncheckedArray[uint64]](c_malloc(csize_t(max(n, 1) * 8)))
  let raw = readGuestBytes(uc, guestPtr, n * 8)
  for i in 0 ..< n:
    buf[i] = (if raw.len == n * 8: guestToHostObj(uc, readU64(raw, i * 8)) else: 0'u64)
  cast[pointer](buf)

proc handleBufferSelector(uc: UcHandle, selfPtr: uint64, selName: string): bool =
  ## Collection-literal constructors take C arrays of objects that live in
  ## GUEST memory (the host can't read them): copy them over, element-wise.
  let sr = cast[SelRegisterNameFn](selRegisterNameAddr)
  case selName
  of "arrayWithObjects:count:", "initWithObjects:count:", "setWithObjects:count:":
    let n = int reg(uc, 3)
    let objs = hostObjBuffer(uc, reg(uc, 2), n)
    let r = callObjcMsgSendRaw(objcMsgSendAddr, cast[pointer](selfPtr), sr(selName.cstring),
                               @[objs, cast[pointer](n)])
    c_free(objs)
    thunkReturn(uc, cast[uint64](r))
    return true
  of "dictionaryWithObjects:forKeys:count:", "initWithObjects:forKeys:count:":
    let n = int reg(uc, 4)
    let vals = hostObjBuffer(uc, reg(uc, 2), n)
    let keys = hostObjBuffer(uc, reg(uc, 3), n)
    let r = callObjcMsgSendRaw(objcMsgSendAddr, cast[pointer](selfPtr), sr(selName.cstring),
                               @[vals, keys, cast[pointer](n)])
    c_free(vals); c_free(keys)
    thunkReturn(uc, cast[uint64](r))
    return true
  else:
    return false

proc handleFormatSelector(uc: UcHandle, selfPtr: uint64, selName: string): bool =
  ## Variadic Objective-C format methods can't go through the generic path
  ## (the runtime reports a fixed arg count; the real varargs sit on the guest
  ## stack). Format the string ourselves, then hand the host a finished string.
  if selName notin ["stringWithFormat:", "initWithFormat:", "localizedStringWithFormat:", "appendFormat:"]:
    return false
  var x2: culonglong
  discard uc_reg_read(uc, UC_ARM64_REG_X2, addr x2)
  let text = formatGuest(uc, nsStringToNim(uc, uint64 x2), stackArgReader(uc))
  let str = makeHostNSString(text)
  let sr = cast[SelRegisterNameFn](selRegisterNameAddr)
  case selName
  of "initWithFormat:":
    thunkReturn(uc, cast[uint64](callObjcMsgSendRaw(objcMsgSendAddr, cast[pointer](selfPtr),
      sr("initWithString:"), @[cast[pointer](str)])))
  of "appendFormat:":
    discard callObjcMsgSendRaw(objcMsgSendAddr, cast[pointer](selfPtr), sr("appendString:"), @[cast[pointer](str)])
    thunkReturn(uc, 0)
  else:
    thunkReturn(uc, str)
  true

var thunkTable = {
  "_getpid": ThunkProc(proc(uc: UcHandle) =
    thunkReturn(uc, uint64 c_getpid())
  ),
  "_malloc": ThunkProc(proc(uc: UcHandle) =
    var size: culonglong
    discard uc_reg_read(uc, UC_ARM64_REG_X0, addr size)
    let p = c_malloc(csize_t size)
    thunkReturn(uc, cast[uint64](p))
  ),
  "_free": ThunkProc(proc(uc: UcHandle) =
    var p: culonglong
    discard uc_reg_read(uc, UC_ARM64_REG_X0, addr p)
    c_free(cast[pointer](uint64 p))
    thunkReturn(uc, 0)
  ),
  "_objc_msgSend": ThunkProc(proc(uc: UcHandle) =
    ## Two layers, tried in order:
    ##   1. Generic: ask the REAL host runtime for this selector's actual
    ##      method signature (method_getReturnType/method_getArgumentType)
    ##      and marshal the call via libffi accordingly (objc_ffi.nim).
    ##      Covers pointer/integer/float/double args and returns, and
    ##      struct returns up to 16 bytes with no float/double field
    ##      (e.g. NSRange) — see objc_ffi.nim's header comment for the
    ##      remaining gaps (struct arguments, >16-byte or float-containing
    ##      struct returns, blocks, unions/arrays, max 6 real args).
    ##   2. Fallback: the old colon-count heuristic + hand-written cases,
    ##      used only when (1) reports ok=false — e.g. libffi/runtime
    ##      unavailable, or a signature outside its documented limits.
    if objcMsgSendAddr == nil:
      echo "86arm: objc_msgSend thunk unavailable (libobjc not loaded) — stopping."
      discard uc_emu_stop(uc)
    else:
      var selfPtr, selPtr: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr selfPtr)
      discard uc_reg_read(uc, UC_ARM64_REG_X1, addr selPtr)
      selfPtr = culonglong(guestToHostObj(uc, uint64 selfPtr))
      let selName = readGuestString(uc, uint64 selPtr, 256)
      let realSel = resolveSel(uc, uint64 selPtr)

      var handled = handleFormatSelector(uc, uint64 selfPtr, selName) or handleBufferSelector(uc, uint64 selfPtr, selName)
      if (not handled) and objcFfiReady:
        let genResult = callObjcMsgSendGeneric(
          uc, objcMsgSendAddr, uint64 selfPtr, realSel, selName,
          proc(a: uint64): string = readGuestString(uc, a, 4096),
          proc(sz: csize_t): pointer = c_malloc(sz),
          proc(p: pointer) = c_free(p),
          proc(a: uint64): uint64 = guestToHostObj(uc, a),
          proc(a: uint64): uint64 = guestToHostSel(uc, a),
          proc(a: uint64, n: int): seq[byte] = readGuestBytes(uc, a, n)
        )
        if genResult.ok:
          if verboseMode:
            echo &"[thunk] objc_msgSend: '{selName}' handled generically via libffi, retVal={genResult.retVal:#x}"
          if genResult.retIsHfa:
            # HFA struct return: one member per D register
            for k in 0 ..< genResult.retHfaCount:
              var bits: uint64 = 0
              for b in 0 ..< genResult.retHfaElemSize:
                bits = bits or (uint64(genResult.retBytes[k * genResult.retHfaElemSize + b]) shl (8 * b))
              var v: culonglong = bits
              discard uc_reg_write(uc, UC_ARM64_REG_D0 + cint(k), addr v)
            thunkReturnVoidKeepRegs(uc)
          elif genResult.retIndirect:
            var x8: culonglong
            discard uc_reg_read(uc, UC_ARM64_REG_X8, addr x8)
            if genResult.retBytes.len > 0:
              discard uc_mem_write(uc, uint64 x8, unsafeAddr genResult.retBytes[0], csize_t genResult.retBytes.len)
            thunkReturn(uc, uint64 x8)
          elif genResult.retIsStruct:
            thunkReturnStruct2(uc, genResult.retWords[0], genResult.retWords[1])
          elif genResult.retIsScalarFloat:
            thunkReturnFloat(uc, genResult.retVal)
          elif genResult.retIsCString and genResult.retVal != 0:
            # host char* (UTF8String, ...) lives in HOST memory; give the guest a copy it can read
            let cs = $cast[cstring](cast[pointer](genResult.retVal))
            let gp = guestAlloc(uc, uint64(cs.len + 1))
            if gp != 0: writeGuestCStr(uc, gp, cs)
            thunkReturn(uc, gp)
          else:
            thunkReturn(uc, genResult.retVal)
          handled = true
        elif verboseMode:
          echo &"[thunk] objc_msgSend: '{selName}' generic path declined ({genResult.reason}) — using fallback"

      if not handled:
        let colonCount = selName.count(':')
        if colonCount == 0:
          let ret = callObjcMsgSendRaw(objcMsgSendAddr, cast[pointer](uint64 selfPtr), realSel, @[])
          thunkReturn(uc, cast[uint64](ret))
        elif colonCount == 1 and selName == "stringWithUTF8String:":
          # The guest passes a pointer to a C string living in GUEST memory
          # (Unicorn's address space) — not valid in the real host process.
          # Same translation principle as resolveSel: read the actual bytes
          # out of guest memory ourselves, copy them into a real host
          # buffer, and pass THAT pointer to the real host function.
          var a1: culonglong
          discard uc_reg_read(uc, UC_ARM64_REG_X2, addr a1)
          let s = readGuestString(uc, uint64 a1, 4096)
          let hostBuf = c_malloc(csize_t(s.len + 1))
          if s.len > 0:
            copyMem(hostBuf, unsafeAddr s[0], s.len)
          cast[ptr UncheckedArray[byte]](hostBuf)[s.len] = 0
          # NOTE: uses callObjcMsgSendRaw (libffi), not a direct
          # {.cdecl.} function-pointer cast — the direct-cast approach
          # was observed to return garbage values on at least one real
          # host, see objc_ffi.nim's callObjcMsgSendRaw doc comment.
          let ret = callObjcMsgSendRaw(objcMsgSendAddr, cast[pointer](uint64 selfPtr), realSel, @[hostBuf])
          c_free(hostBuf)
          thunkReturn(uc, cast[uint64](ret))
        else:
          # Unknown 1+-arg selector the generic path also declined: fall
          # back to the old 0-arg-shape call rather than guess wrong
          # pointer/value semantics — documented gap, now only reached
          # for signatures objc_ffi.nim explicitly doesn't support yet
          # (floats/doubles/structs/blocks/>6 args).
          if verboseMode:
            echo &"[thunk] objc_msgSend: selector '{selName}' has no handler — calling as 0-arg shape (may be wrong)"
          let ret = callObjcMsgSendRaw(objcMsgSendAddr, cast[pointer](uint64 selfPtr), realSel, @[])
          thunkReturn(uc, cast[uint64](ret))
  ),
  "_NSLog": ThunkProc(proc(uc: UcHandle) =
    ## NSLog(NSString *format, ...) — variadic in its C declaration, but
    ## that only matters to the CALLEE's own va_arg codegen (already
    ## compiled and working inside the real host Foundation — we never
    ## touch that code). At the ABI level, the first N register arguments
    ## of a variadic call are passed exactly like a normal call; nothing
    ## special is required on the caller (thunk) side for pointer args
    ## that fit in registers. test_foundation.m always calls this as
    ## NSLog(@"%@", s) — exactly 2 pointer args — so casting the real
    ## host function pointer to a plain 2-arg non-variadic signature and
    ## calling it that way is valid and avoids needing any va_list
    ## machinery here at all.
    if nsLogAddr == nil:
      echo "86arm: NSLog thunk unavailable (Foundation not loaded) — stopping."
      discard uc_emu_stop(uc)
    elif objcMsgSendAddr == nil or objcGetClassAddr == nil or selRegisterNameAddr == nil:
      echo "86arm: NSLog thunk needs objc_msgSend/objc_getClass/sel_registerName (not loaded) — stopping."
      discard uc_emu_stop(uc)
    else:
      var fmtPtr: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr fmtPtr)
      if verboseMode:
        echo &"[nslog-debug] entry: fmtPtr=0x{uint64(fmtPtr):x}"
      # fmtPtr points at the compile-time NSConstantString struct — but
      # that struct physically lives ONLY inside Unicorn's emulated guest
      # memory arena, which is NOT mapped into the real host process's
      # address space at that address. Passing fmtPtr straight through to
      # the real host NSLog (as an earlier version of this thunk did) made
      # NSLog dereference a bogus host address and SIGSEGV — every
      # pointer handed to a real host function must point at REAL host
      # memory, no exceptions, even if the guest struct's bytes "look"
      # self-contained.
      #
      # Fix: read the struct's `str` field ourselves out of guest memory
      # (struct __NSConstantString_tag { const int *isa; int flags; const
      # char *str; long length; } — isa@0, flags@8, str@16, length@24;
      # `str` sits at offset 16 because it's a pointer field needing
      # 8-byte alignment, forcing 4 bytes of padding after the 4-byte
      # `flags` field. This exact layout has been stable across Apple's
      # toolchains for a long time, but is NOT independently re-verified
      # against current Xcode output in this sandbox — if this ever reads
      # garbage, dump the 32 bytes at fmtPtr with --trace and check
      # whether offset 16 really holds a plausible pointer.)
      var structBytes: array[32, byte]
      if uc_mem_read(uc, uint64 fmtPtr, addr structBytes[0], csize_t 32) != 0:
        echo "86arm: NSLog thunk could not read the format literal's struct from guest memory — stopping."
        discard uc_emu_stop(uc)
      else:
        var strFieldGuestAddr: uint64 = 0
        for i in 0 ..< 8:
          strFieldGuestAddr = strFieldGuestAddr or (uint64(structBytes[16 + i]) shl (8 * i))
        if verboseMode:
          echo &"[nslog-debug] fmtPtr=0x{uint64(fmtPtr):x} extracted str-field guest addr=0x{strFieldGuestAddr:x}"
        let formatText = readGuestString(uc, strFieldGuestAddr, 4096)
        if verboseMode:
          echo &"[nslog-debug] formatText = '{formatText}' (len={formatText.len})"
        let nsStringCls = cast[ObjcGetClassFn](objcGetClassAddr)("NSString")
        if verboseMode:
          echo &"[nslog-debug] nsStringCls = {cast[uint64](nsStringCls):#x}"
        let sel = cast[SelRegisterNameFn](selRegisterNameAddr)("stringWithUTF8String:")
        if verboseMode:
          echo &"[nslog-debug] sel = {cast[uint64](sel):#x}"
        let hostCBuf = c_malloc(csize_t(formatText.len + 1))
        if formatText.len > 0:
          copyMem(hostCBuf, unsafeAddr formatText[0], formatText.len)
        cast[ptr UncheckedArray[byte]](hostCBuf)[formatText.len] = 0
        if verboseMode:
          echo &"[nslog-debug] hostCBuf ready, about to call real objc_msgSend for format NSString..."
        # NOTE: uses callObjcMsgSendRaw (libffi), not a direct
        # {.cdecl.} function-pointer cast — see objc_ffi.nim's doc
        # comment on callObjcMsgSendRaw for why.
        let realFormatObj = callObjcMsgSendRaw(objcMsgSendAddr, nsStringCls, sel, @[hostCBuf])
        c_free(hostCBuf)
        if verboseMode:
          echo &"[nslog-debug] realFormatObj = {cast[uint64](realFormatObj):#x} — about to call real NSLog..."

        # THE FIX: a real variadic function's OWN va_arg reads route
        # float/double arguments through the FP register bank (XMM on
        # x86_64 host, D-regs on arm64 host) — completely separate from
        # the GP bank pointer/integer arguments use. An earlier version
        # of this thunk called NSLog through a plain 2-arg {.cdecl.}
        # function-pointer cast that always placed its one vararg in a
        # GP register — harmless for %@/%lu (pointer/integer values,
        # correct bank by luck), but wrong for %f (a double needs XMM,
        # not GP), producing 0.000000 instead of the real value.
        #
        # Fix: parse the REAL format string's conversion specifiers
        # ourselves (the same information NSLog's own internal va_arg
        # loop derives) to learn each vararg's real type, read that many
        # 8-byte stack slots (ARM64's variadic ABI spills ALL varargs to
        # the stack uniformly regardless of type — confirmed via otool on
        # every test binary so far, including this one), and call the
        # real host NSLog via callVariadicHostFn (libffi), which routes
        # each value through the correct register bank for its real type.
        var argKinds: seq[VariadicArgKind] = @[]
        var i = 0
        while i < formatText.len:
          if formatText[i] == '%':
            inc i
            if i < formatText.len and formatText[i] == '%':
              inc i  # literal "%%", not a real conversion — skip, no arg
              continue
            # Skip flags/width/precision/length-modifier characters;
            # only the FINAL conversion character matters for picking
            # a register bank (pointer/GP vs double/FP).
            while i < formatText.len and formatText[i] notin
                {'d','i','u','x','X','o','f','F','e','E','g','G','a','A',
                 'c','s','p','@','n'}:
              inc i
            if i < formatText.len:
              case formatText[i]
              of 'f', 'F', 'e', 'E', 'g', 'G', 'a', 'A':
                argKinds.add(vakDouble)
              else:
                argKinds.add(vakPointer)
              inc i
          else:
            inc i

        var spVal: culonglong
        discard uc_reg_read(uc, UC_ARM64_REG_SP, addr spVal)
        var callArgs: seq[tuple[kind: VariadicArgKind, bits: uint64]] = @[]
        for idx, kind in argKinds:
          var slotBytes: array[8, byte]
          var bits: uint64 = 0
          if uc_mem_read(uc, uint64(spVal) + uint64(idx * 8), addr slotBytes[0], csize_t 8) == 0:
            for b in 0 ..< 8:
              bits = bits or (uint64(slotBytes[b]) shl (8 * b))
          callArgs.add((kind, bits))
          if verboseMode:
            echo &"[nslog-debug] vararg {idx}: kind={kind} bits=0x{bits:x} (from [sp+{idx*8}])"

        var fullArgs = @[(vakPointer, cast[uint64](realFormatObj))]
        fullArgs.add(callArgs)
        let ok = callVariadicHostFn(nsLogAddr, fullArgs)
        if verboseMode:
          echo &"[nslog-debug] real NSLog call via libffi returned ok={ok}"
        thunkReturn(uc, 0)
  ),
  "_objc_msgSend$1arg": ThunkProc(proc(uc: UcHandle) =
    ## Not a real symbol name — not currently reachable from the bind
    ## table (dyld only ever emits one `_objc_msgSend` bind regardless of
    ## call-site arity), kept here to show the 1-arg shape exists and is
    ## ready to be wired up once selector-aware dispatch is added.
    if objcMsgSendAddr == nil:
      discard uc_emu_stop(uc)
    else:
      var selfPtr, selPtr, a1: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr selfPtr)
      discard uc_reg_read(uc, UC_ARM64_REG_X1, addr selPtr)
      discard uc_reg_read(uc, UC_ARM64_REG_X2, addr a1)
      let realSel = resolveSel(uc, uint64 selPtr)
      # NOTE: a1 is passed through as-is — if the real call's argument is
      # itself a guest-space pointer (e.g. a C string for
      # initWithUTF8String:), this will crash the same way selPtr did
      # before resolveSel. Not fixed yet; needs the same kind of
      # translation, chosen per-selector once real signature lookup exists.
      let fn = cast[ObjcMsgSend1](objcMsgSendAddr)
      let ret = fn(cast[pointer](uint64 selfPtr), realSel, cast[pointer](uint64 a1))
      thunkReturn(uc, cast[uint64](ret))
  ),
  "_objc_autoreleasePoolPush": ThunkProc(proc(uc: UcHandle) =
    ## Called with 0 args, returns an opaque "pool token" pointer that
    ## must later be handed back unchanged to objc_autoreleasePoolPop.
    ## It's a real host pointer end to end — the guest never dereferences
    ## it itself, just carries it around and passes it back — so no
    ## guest<->host translation is needed here at all, unlike selector
    ## strings or C-string arguments.
    if objcAutoreleasePoolPushAddr == nil:
      echo "86arm: objc_autoreleasePoolPush thunk unavailable (libobjc not loaded) — stopping."
      discard uc_emu_stop(uc)
    else:
      let fn = cast[AutoreleasePoolPushFn](objcAutoreleasePoolPushAddr)
      let token = fn()
      thunkReturn(uc, cast[uint64](token))
  ),
  "_objc_autoreleasePoolPop": ThunkProc(proc(uc: UcHandle) =
    if objcAutoreleasePoolPopAddr == nil:
      echo "86arm: objc_autoreleasePoolPop thunk unavailable (libobjc not loaded) — stopping."
      discard uc_emu_stop(uc)
    else:
      var tokenPtr: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0, addr tokenPtr)
      let fn = cast[AutoreleasePoolPopFn](objcAutoreleasePoolPopAddr)
      fn(cast[pointer](uint64 tokenPtr))
      thunkReturn(uc, 0)
  ),
}.toTable


# ---- plain "pointer args in, pointer out" libobjc entry points the compiler
# emits instead of objc_msgSend (ARC helpers, objc_alloc, ...). Object args
# are run through guestToHostObj so guest @"..." literals are valid hosts-side.
proc makeSimpleThunk(fn: pointer, nargs: int, passthrough: bool = false): ThunkProc =
  ## passthrough: for retain/release-style calls, if arg0 is a GUEST object
  ## (literal/block) that had to be translated, don't touch the host copy;
  ## just hand the guest pointer back (guest objects are never refcounted).
  result = proc(uc: UcHandle) =
    var args: seq[uint64]
    var orig0: uint64 = 0
    for i in 0 ..< nargs:
      var v: culonglong
      discard uc_reg_read(uc, UC_ARM64_REG_X0 + cint(i), addr v)
      if i == 0: orig0 = uint64 v
      args.add(if i == 0: guestToHostObj(uc, uint64 v) else: uint64 v)
    if passthrough and nargs >= 1 and inGuest(orig0):
      thunkReturn(uc, orig0)
    else:
      thunkReturn(uc, callHostPtrFn(fn, args))

if libobjc != nil:
  for (nm, n) in [("objc_alloc", 1), ("objc_allocWithZone", 2), ("objc_alloc_init", 1),
                  ("objc_opt_new", 1), ("objc_opt_class", 1), ("objc_opt_isKindOfClass", 2),
                  ("objc_retain", 1), ("objc_release", 1), ("objc_autorelease", 1),
                  ("objc_retainAutoreleasedReturnValue", 1), ("objc_autoreleaseReturnValue", 1),
                  ("objc_retainAutorelease", 1), ("objc_retainAutoreleaseReturnValue", 1),
                  ("objc_unsafeClaimAutoreleasedReturnValue", 1)]:
    let p = symAddr(libobjc, nm)
    if p != nil and not thunkTable.hasKey("_" & nm):
      thunkTable["_" & nm] = makeSimpleThunk(p, n, passthrough = nm.startsWith("objc_retain") or
        nm.startsWith("objc_release") or nm.startsWith("objc_autorelease") or nm.startsWith("objc_unsafeClaim"))


# ---- guest-defined Objective-C classes (runtime API) + host->guest callbacks --
# A guest program can build a class at runtime with the plain C runtime API
# (objc_allocateClassPair / class_addMethod / objc_registerClassPair), giving
# class_addMethod a pointer to one of ITS OWN arm64 functions as the IMP. We
# register a real host function (a libffi closure) as the IMP instead; when
# AppKit (running natively on the host) invokes it — e.g. on a button click —
# the closure re-enters Unicorn (nested uc_emu_start) and runs the guest
# function, then returns its result to the host.
proc guestImpHandler(cif: pointer, ret: pointer, args: pointer, ud: pointer) {.cdecl.} =
  let a = cast[ptr UncheckedArray[pointer]](args)
  if verboseMode:
    echo &"[callback] host -> guest IMP 0x{cast[uint64](ud):x} (nested uc_emu_start)"
  var g: array[5, uint64]
  for i in 0 .. 4: g[i] = cast[ptr uint64](a[i])[]
  cast[ptr uint64](ret)[] = callGuest(activeUc, cast[uint64](ud), g)

proc hostCStr(uc: UcHandle, a: uint64): pointer =
  let str = readGuestString(uc, a, 4096)
  let p = c_malloc(csize_t(str.len + 1))
  if str.len > 0: copyMem(p, unsafeAddr str[0], str.len)
  cast[ptr UncheckedArray[byte]](p)[str.len] = 0
  p

if libobjc != nil:
  let pGetClass = symAddr(libobjc, "objc_getClass")
  let pSelReg = symAddr(libobjc, "sel_registerName")
  let pAlloc = symAddr(libobjc, "objc_allocateClassPair")
  let pAddM = symAddr(libobjc, "class_addMethod")
  let pReg = symAddr(libobjc, "objc_registerClassPair")
  thunkTable["_objc_getClass"] = ThunkProc(proc(uc: UcHandle) =
    let n = hostCStr(uc, reg(uc, 0))
    let r = callHostPtrFn(pGetClass, @[cast[uint64](n)])
    c_free(n); thunkReturn(uc, r))
  thunkTable["_sel_registerName"] = ThunkProc(proc(uc: UcHandle) =
    let n = hostCStr(uc, reg(uc, 0))
    let r = callHostPtrFn(pSelReg, @[cast[uint64](n)])
    c_free(n); thunkReturn(uc, r))
  thunkTable["_objc_allocateClassPair"] = ThunkProc(proc(uc: UcHandle) =
    let n = hostCStr(uc, reg(uc, 1))
    let r = callHostPtrFn(pAlloc, @[guestToHostObj(uc, reg(uc, 0)), cast[uint64](n), reg(uc, 2)])
    thunkReturn(uc, r))  # name buffer intentionally leaked: runtime may keep it
  thunkTable["_class_addMethod"] = ThunkProc(proc(uc: UcHandle) =
    let impGuest = reg(uc, 2)
    let imp = makeImpClosure(guestImpHandler, cast[pointer](impGuest))
    let types = hostCStr(uc, reg(uc, 3))
    let r = callHostPtrFn(pAddM, @[reg(uc, 0), guestToHostSel(uc, reg(uc, 1)), cast[uint64](imp), cast[uint64](types)])
    thunkReturn(uc, r and 0xFF))
  thunkTable["_objc_registerClassPair"] = ThunkProc(proc(uc: UcHandle) =
    discard callHostPtrFn(pReg, @[reg(uc, 0)])
    thunkReturn(uc, 0))


# ---- minimal guest-memory libc: these operate on GUEST memory, so they must
# be emulated here rather than forwarded to the host's libc.
proc guestCopy(uc: UcHandle, dst, src: uint64, n: int) =
  if n <= 0: return
  var buf = newSeq[byte](n)
  if uc_mem_read(uc, src, addr buf[0], csize_t n) == 0:
    discard uc_mem_write(uc, dst, addr buf[0], csize_t n)

thunkTable["_memcpy"] = ThunkProc(proc(uc: UcHandle) =
  guestCopy(uc, reg(uc, 0), reg(uc, 1), int reg(uc, 2)); thunkReturn(uc, reg(uc, 0)))
thunkTable["_memmove"] = thunkTable["_memcpy"]
thunkTable["_memset"] = ThunkProc(proc(uc: UcHandle) =
  let n = int reg(uc, 2)
  if n > 0:
    var buf = newSeq[byte](n)
    for i in 0 ..< n: buf[i] = byte(reg(uc, 1) and 0xFF)
    discard uc_mem_write(uc, reg(uc, 0), addr buf[0], csize_t n)
  thunkReturn(uc, reg(uc, 0)))
thunkTable["_strlen"] = ThunkProc(proc(uc: UcHandle) =
  thunkReturn(uc, uint64 readGuestString(uc, reg(uc, 0), 1 shl 20).len))
thunkTable["___stack_chk_fail"] = ThunkProc(proc(uc: UcHandle) =
  echo "86arm: guest stack smashing detected (__stack_chk_fail) — stopping."
  discard uc_emu_stop(uc))


# ======================= guest heap =============================================
# malloc & friends must hand the guest GUEST-readable memory (the old thunk
# returned host pointers the guest couldn't dereference). Simple bump
# allocator in a dedicated mapped region; free() is a no-op.
thunkTable["_malloc"] = ThunkProc(proc(uc: UcHandle) = thunkReturn(uc, guestAlloc(uc, reg(uc, 0))))
thunkTable["_calloc"] = ThunkProc(proc(uc: UcHandle) = thunkReturn(uc, guestAlloc(uc, reg(uc, 0) * reg(uc, 1))))
thunkTable["_realloc"] = ThunkProc(proc(uc: UcHandle) =
  let old = reg(uc, 0)
  let n = reg(uc, 1)
  let np = guestAlloc(uc, n)
  if old != 0 and np != 0:
    guestCopy(uc, np, old, int min(guestSizeOf(uc, old), n))
  thunkReturn(uc, np))
thunkTable["_free"] = ThunkProc(proc(uc: UcHandle) = thunkReturn(uc, 0))
thunkTable["_strdup"] = ThunkProc(proc(uc: UcHandle) =
  let str = readGuestString(uc, reg(uc, 0), 1 shl 20)
  let p = guestAlloc(uc, uint64(str.len + 1))
  if p != 0: writeGuestCStr(uc, p, str)
  thunkReturn(uc, p))

# ======================= Block_copy / Block_release ===============================
proc blockCopy(uc: UcHandle, b: uint64): uint64 =
  if b == 0: return 0
  if not inGuest(b):
    let hostCopy = (if libSystemH != nil: symAddr(libSystemH, "_Block_copy") else: nil)
    return (if hostCopy != nil: callHostPtrFn(hostCopy, @[b]) else: b)
  let hdr = readGuestBytes(uc, b, 32)
  if hdr.len < 32 or readU64(hdr, 0) != stackBlockIsa: return b   # global / already heap
  let desc = readGuestBytes(uc, readU64(hdr, 24), 32)
  if desc.len < 16: return b
  let size = readU64(desc, 8)
  let nb = guestAlloc(uc, size)
  if nb == 0: return b
  guestCopy(uc, nb, b, int size)
  var flags: uint32 = uint32(hdr[8]) or (uint32(hdr[9]) shl 8) or (uint32(hdr[10]) shl 16) or (uint32(hdr[11]) shl 24)
  flags = flags or (1'u32 shl 24)            # BLOCK_NEEDS_FREE
  var isa: uint64 = (if blockClassAddrs.len >= 3: blockClassAddrs[2] else: stackBlockIsa)  # malloc block
  discard uc_mem_write(uc, nb, addr isa, 8)
  discard uc_mem_write(uc, nb + 8, addr flags, 4)
  if (flags and (1'u32 shl 25)) != 0 and desc.len >= 24:   # BLOCK_HAS_COPY_DISPOSE
    discard callGuest(uc, readU64(desc, 16), [nb, b])
  nb

thunkTable["__Block_copy"] = ThunkProc(proc(uc: UcHandle) = thunkReturn(uc, blockCopy(uc, reg(uc, 0))))
thunkTable["_objc_retainBlock"] = thunkTable["__Block_copy"]
thunkTable["__Block_release"] = ThunkProc(proc(uc: UcHandle) = thunkReturn(uc, 0))  # copies are leaked, never freed

# ======================= libdispatch (main queue only) ============================
# Unicorn is not thread-safe, so EVERY queue is mapped onto the main queue and
# all guest blocks run on the main thread (serialised with the emulator).
let mainQ: uint64 = (if libSystemH != nil: cast[uint64](symAddr(libSystemH, "_dispatch_main_q")) else: 0'u64)
proc hostSym(n: string): pointer = (if libSystemH != nil: symAddr(libSystemH, n) else: nil)

proc guestBlockInvoke(uc: UcHandle, blk: uint64) =
  ## run a block inline, synchronously
  if blk == 0: return
  if inGuest(blk):
    let hdr = readGuestBytes(uc, blk, 32)
    if hdr.len == 32: discard callGuest(uc, readU64(hdr, 16), [blk])

thunkTable["_dispatch_get_global_queue"] = ThunkProc(proc(uc: UcHandle) = thunkReturn(uc, mainQ))
thunkTable["_dispatch_queue_create"] = ThunkProc(proc(uc: UcHandle) = thunkReturn(uc, mainQ))
thunkTable["_dispatch_get_current_queue"] = thunkTable["_dispatch_get_global_queue"]
thunkTable["_dispatch_retain"] = ThunkProc(proc(uc: UcHandle) = thunkReturn(uc, 0))
thunkTable["_dispatch_release"] = thunkTable["_dispatch_retain"]
let pDispatchAsync = hostSym("dispatch_async")
let pDispatchAfter = hostSym("dispatch_after")
let pDispatchMain = hostSym("dispatch_main")
thunkTable["_dispatch_async"] = ThunkProc(proc(uc: UcHandle) =
  discard callHostPtrFn(pDispatchAsync, @[mainQ, guestToHostObj(uc, reg(uc, 1))]); thunkReturn(uc, 0))
thunkTable["_dispatch_after"] = ThunkProc(proc(uc: UcHandle) =
  discard callHostPtrFn(pDispatchAfter, @[reg(uc, 0), mainQ, guestToHostObj(uc, reg(uc, 2))]); thunkReturn(uc, 0))
thunkTable["_dispatch_sync"] = ThunkProc(proc(uc: UcHandle) =
  guestBlockInvoke(uc, reg(uc, 1)); thunkReturn(uc, 0))   # inline: sync onto main from main would deadlock
thunkTable["_dispatch_once"] = ThunkProc(proc(uc: UcHandle) =
  let pred = reg(uc, 0)
  var tok: uint64 = 0
  discard uc_mem_read(uc, pred, addr tok, 8)
  if tok == 0:
    var done: uint64 = 0xFFFFFFFFFFFFFFFF'u64
    discard uc_mem_write(uc, pred, addr done, 8)
    guestBlockInvoke(uc, reg(uc, 1))
  thunkReturn(uc, 0))
thunkTable["_dispatch_main"] = ThunkProc(proc(uc: UcHandle) =
  if pDispatchMain != nil: discard callHostPtrFn(pDispatchMain, @[])
  thunkReturn(uc, 0))

# ======================= libc on guest memory =====================================
proc readFpD(uc: UcHandle, i: int): float64 =
  var v: culonglong
  discard uc_reg_read(uc, UC_ARM64_REG_D0 + cint(i), addr v)
  cast[float64](uint64 v)

proc writeFpD0(uc: UcHandle, x: float64) =
  var r: culonglong = cast[uint64](x)
  discard uc_reg_write(uc, UC_ARM64_REG_D0, addr r)
  thunkReturnVoidKeepRegs(uc)

proc c_fmod(a, b: cdouble): cdouble {.importc: "fmod", header: "<math.h>".}
proc c_sranddev() {.importc: "srand", header: "<stdlib.h>".}

template math1(name: string, f: untyped) =
  thunkTable[name] = ThunkProc(proc(uc: UcHandle) = writeFpD0(uc, float64(f(readFpD(uc, 0)))))
template math2(name: string, f: untyped) =
  thunkTable[name] = ThunkProc(proc(uc: UcHandle) = writeFpD0(uc, float64(f(readFpD(uc, 0), readFpD(uc, 1)))))
math1("_sqrt", sqrt); math1("_sin", sin); math1("_cos", cos); math1("_tan", tan)
math1("_asin", arcsin); math1("_acos", arccos); math1("_atan", arctan)
math1("_sinh", sinh); math1("_cosh", cosh); math1("_tanh", tanh)
math1("_exp", exp); math1("_log", ln); math1("_log2", log2); math1("_log10", log10)
math1("_floor", floor); math1("_ceil", ceil); math1("_round", round); math1("_trunc", trunc)
math1("_fabs", abs)
math2("_pow", pow); math2("_atan2", arctan2); math2("_fmod", c_fmod)

thunkTable["_strcpy"] = ThunkProc(proc(uc: UcHandle) =
  writeGuestCStr(uc, reg(uc, 0), readGuestString(uc, reg(uc, 1), 1 shl 20)); thunkReturn(uc, reg(uc, 0)))
thunkTable["_strncpy"] = ThunkProc(proc(uc: UcHandle) =
  let n = int reg(uc, 2)
  var str = readGuestString(uc, reg(uc, 1), n)
  while str.len < n: str.add('\0')
  var b = newSeq[byte](n)
  for i in 0 ..< n: b[i] = byte(str[i])
  if n > 0: discard uc_mem_write(uc, reg(uc, 0), addr b[0], csize_t n)
  thunkReturn(uc, reg(uc, 0)))
thunkTable["_strcat"] = ThunkProc(proc(uc: UcHandle) =
  let d = readGuestString(uc, reg(uc, 0), 1 shl 20)
  writeGuestCStr(uc, reg(uc, 0) + uint64(d.len), readGuestString(uc, reg(uc, 1), 1 shl 20))
  thunkReturn(uc, reg(uc, 0)))
thunkTable["_strcmp"] = ThunkProc(proc(uc: UcHandle) =
  let a = readGuestString(uc, reg(uc, 0), 1 shl 20)
  let b = readGuestString(uc, reg(uc, 1), 1 shl 20)
  thunkReturn(uc, cast[uint64](int64(cmp(a, b)))))
thunkTable["_strncmp"] = ThunkProc(proc(uc: UcHandle) =
  let n = int reg(uc, 2)
  let a = readGuestString(uc, reg(uc, 0), n)
  let b = readGuestString(uc, reg(uc, 1), n)
  thunkReturn(uc, cast[uint64](int64(cmp(a, b)))))
thunkTable["_memcmp"] = ThunkProc(proc(uc: UcHandle) =
  let n = int reg(uc, 2)
  let a = readGuestBytes(uc, reg(uc, 0), n)
  let b = readGuestBytes(uc, reg(uc, 1), n)
  var r = 0
  for i in 0 ..< min(a.len, b.len):
    if a[i] != b[i]: r = int(a[i]) - int(b[i]); break
  thunkReturn(uc, cast[uint64](int64 r)))
thunkTable["_strchr"] = ThunkProc(proc(uc: UcHandle) =
  let str = readGuestString(uc, reg(uc, 0), 1 shl 20)
  let c = char(reg(uc, 1) and 0xFF)
  let i = (if c == '\0': str.len else: str.find(c))
  thunkReturn(uc, (if i < 0: 0'u64 else: reg(uc, 0) + uint64(i))))
thunkTable["_atoi"] = ThunkProc(proc(uc: UcHandle) =
  let str = readGuestString(uc, reg(uc, 0), 64).strip()
  var v = 0
  try: v = parseInt(str) except ValueError:
    var k = 0
    var neg = false
    if str.len > 0 and str[0] in {'-', '+'}: neg = str[0] == '-'; k = 1
    while k < str.len and str[k] in {'0'..'9'}: v = v * 10 + int(str[k]) - 48; inc k
    if neg: v = -v
  thunkReturn(uc, cast[uint64](int64 v)))
thunkTable["_abs"] = ThunkProc(proc(uc: UcHandle) =
  let v = int32(reg(uc, 0) and 0xFFFFFFFF'u64)
  thunkReturn(uc, uint64(uint32(abs(v)))))
thunkTable["_labs"] = ThunkProc(proc(uc: UcHandle) = thunkReturn(uc, uint64(abs(cast[int64](reg(uc, 0))))))
thunkTable["_rand"] = ThunkProc(proc(uc: UcHandle) = thunkReturn(uc, uint64(rand(0x7FFFFFFF))))
thunkTable["_srand"] = ThunkProc(proc(uc: UcHandle) = randomize(int(reg(uc, 0))); thunkReturn(uc, 0))
thunkTable["_usleep"] = ThunkProc(proc(uc: UcHandle) = sleep(int(reg(uc, 0) div 1000)); thunkReturn(uc, 0))
thunkTable["_exit"] = ThunkProc(proc(uc: UcHandle) = stdout.flushFile(); quit(int(reg(uc, 0) and 0xFF)))
thunkTable["__exit"] = thunkTable["_exit"]
thunkTable["_abort"] = ThunkProc(proc(uc: UcHandle) = stdout.flushFile(); quit(134))

# printf family: ARM64 Darwin passes variadic args in 8-byte stack slots
thunkTable["_printf"] = ThunkProc(proc(uc: UcHandle) =
  let text = formatGuest(uc, readGuestString(uc, reg(uc, 0), 65536), stackArgReader(uc))
  stdout.write(text); stdout.flushFile(); thunkReturn(uc, uint64 text.len))
thunkTable["_puts"] = ThunkProc(proc(uc: UcHandle) =
  stdout.write(readGuestString(uc, reg(uc, 0), 65536) & "\n"); stdout.flushFile(); thunkReturn(uc, 1))
thunkTable["_putchar"] = ThunkProc(proc(uc: UcHandle) =
  stdout.write(char(reg(uc, 0) and 0xFF)); stdout.flushFile(); thunkReturn(uc, reg(uc, 0)))
thunkTable["_snprintf"] = ThunkProc(proc(uc: UcHandle) =
  let text = formatGuest(uc, readGuestString(uc, reg(uc, 2), 65536), stackArgReader(uc))
  let cap = int reg(uc, 1)
  if cap > 0: writeGuestCStr(uc, reg(uc, 0), text[0 ..< min(text.len, cap - 1)])
  thunkReturn(uc, uint64 text.len))
thunkTable["_sprintf"] = ThunkProc(proc(uc: UcHandle) =
  let text = formatGuest(uc, readGuestString(uc, reg(uc, 1), 65536), stackArgReader(uc))
  writeGuestCStr(uc, reg(uc, 0), text)
  thunkReturn(uc, uint64 text.len))

# NSLog: format ourselves (so %@ may be a guest literal and varargs of any
# type work), then hand the host NSLog a finished string via "%@".
thunkTable["_NSLog"] = ThunkProc(proc(uc: UcHandle) =
  if nsLogAddr == nil:
    echo "86arm: NSLog thunk unavailable (Foundation not loaded) — stopping."
    discard uc_emu_stop(uc)
  else:
    let text = formatGuest(uc, nsStringToNim(uc, reg(uc, 0)), stackArgReader(uc))
    discard callVariadicHostFn(nsLogAddr, @[(vakPointer, makeHostNSString("%@")), (vakPointer, makeHostNSString(text))])
    thunkReturn(uc, 0))


# ---- _Block_object_assign / _dispose: the compiler-generated block copy/dispose
# helpers call these for every captured __block variable / object / block.
let pObjcRetain = (if libobjc != nil: symAddr(libobjc, "objc_retain") else: nil)
thunkTable["__Block_object_assign"] = ThunkProc(proc(uc: UcHandle) =
  let dst = reg(uc, 0)
  let src = reg(uc, 1)
  let flags = reg(uc, 2) and 0x3F
  var val = src
  if (flags and 8) != 0 and inGuest(src):            # BLOCK_FIELD_IS_BYREF: promote __block var to the heap
    let hdr = readGuestBytes(uc, src, 24)
    if hdr.len == 24:
      let fwd = readU64(hdr, 8)
      if fwd == src:
        let size = uint64(hdr[20]) or (uint64(hdr[21]) shl 8) or (uint64(hdr[22]) shl 16) or (uint64(hdr[23]) shl 24)
        let nb = guestAlloc(uc, size)
        guestCopy(uc, nb, src, int size)
        var nbv = nb
        discard uc_mem_write(uc, nb + 8, addr nbv, 8)    # new->forwarding = new
        discard uc_mem_write(uc, src + 8, addr nbv, 8)   # old->forwarding = new
        val = nb
      else:
        val = fwd
  elif (flags and 15) == 7:                          # BLOCK_FIELD_IS_BLOCK
    val = blockCopy(uc, src)
  elif (flags and 15) == 3 and src != 0 and not inGuest(src) and pObjcRetain != nil:
    discard callHostPtrFn(pObjcRetain, @[src])        # captured host object
  discard uc_mem_write(uc, dst, addr val, 8)
  thunkReturn(uc, 0))
thunkTable["__Block_object_dispose"] = ThunkProc(proc(uc: UcHandle) = thunkReturn(uc, 0))

let pDispatchTime = hostSym("dispatch_time")
thunkTable["_dispatch_time"] = ThunkProc(proc(uc: UcHandle) =
  thunkReturn(uc, callHostPtrFn(pDispatchTime, @[reg(uc, 0), reg(uc, 1)])))

# ---- _FORTIFY_SOURCE variants clang picks for strcpy/snprintf/... : same
# semantics, extra (ignored) object-size args.
thunkTable["___strcpy_chk"] = thunkTable["_strcpy"]
thunkTable["___strcat_chk"] = thunkTable["_strcat"]
thunkTable["___strncpy_chk"] = thunkTable["_strncpy"]
thunkTable["___memcpy_chk"] = thunkTable["_memcpy"]
thunkTable["___memmove_chk"] = thunkTable["_memmove"]
thunkTable["___memset_chk"] = thunkTable["_memset"]
thunkTable["___snprintf_chk"] = ThunkProc(proc(uc: UcHandle) =   # (buf, n, flag, slen, fmt, ...)
  let text = formatGuest(uc, readGuestString(uc, reg(uc, 4), 65536), stackArgReader(uc))
  let cap = int reg(uc, 1)
  if cap > 0: writeGuestCStr(uc, reg(uc, 0), text[0 ..< min(text.len, cap - 1)])
  thunkReturn(uc, uint64 text.len))
thunkTable["___sprintf_chk"] = ThunkProc(proc(uc: UcHandle) =    # (buf, flag, slen, fmt, ...)
  let text = formatGuest(uc, readGuestString(uc, reg(uc, 3), 65536), stackArgReader(uc))
  writeGuestCStr(uc, reg(uc, 0), text)
  thunkReturn(uc, uint64 text.len))

var thunkSlotName: Table[uint64, string]  # thunk slot address -> symbol name, filled per-load

proc onThunkCode(uc: UcHandle, address: culonglong, size: uint32, userData: pointer) {.cdecl.} =
  let addr0 = uint64(address)
  if thunkSlotName.hasKey(addr0):
    let name = thunkSlotName[addr0]
    if thunkTable.hasKey(name):
      if verboseMode:
        var lrDbg: culonglong
        discard uc_reg_read(uc, UC_ARM64_REG_X30, addr lrDbg)
        echo &"[thunk] calling real host function for {name} (thunk-slot pc=0x{addr0:x}, LR(X30)=0x{uint64(lrDbg):x})"
      thunkTable[name](uc)
      syncShadowVars(uc)
    else:
      echo &"86arm: hit thunk slot for '{name}' but no host implementation is wired up for it yet — stopping."
      discard uc_emu_stop(uc)

proc onCode(uc: UcHandle, address: culonglong, size: uint32, userData: pointer) {.cdecl.} =
  inc traceCount
  if traceCount <= traceMax:
    echo &"[trace] pc=0x{uint64(address):x} size={size}"
  elif traceCount == traceMax + 1:
    echo &"[trace] ... stopping trace output after {traceMax} instructions"

const ReturnFromMainSentinel: uint64 = 0x0000dead_00000000'u64
  ## A `ret` at the end of a real `int main()`-style binary jumps to
  ## whatever address was in X30/LR when execution reached main — but our
  ## loader jumps straight to the entry point with no real crt/dyld caller
  ## to have set that up first, so X30 previously held garbage/zero,
  ## making the final `ret` look like a scary generic fault at addr=0x0
  ## even on a fully successful run (all real output had already printed
  ## correctly by that point — see test_foundation.m/test_nsarray.m runs).
  ## Writing this recognizable, deliberately-unmapped sentinel into X30
  ## before starting emulation lets onMemUnmapped tell "the program
  ## finished and returned from main, as expected" apart from an actual
  ## unexpected fault elsewhere.

proc onMemUnmapped(uc: UcHandle, memType: cint, address: culonglong,
                    size: cint, value: clonglong, userData: pointer): bool {.cdecl.} =
  if uint64(address) == ReturnFromMainSentinel:
    echo "[load] process returned normally from main (reached the return-address sentinel, as expected for a real `int main()` binary with no real crt/dyld caller)."
  elif verboseMode:
    echo &"[fault] unmapped memory access — type={memType} addr=0x{uint64(address):x} size={size}"
  return false  # do not resolve it; let uc_emu_start return the real error after logging

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
      if verboseMode:
        echo &"[emu] untranslated XNU syscall number {syscallNo} — stopping (not in the translation table)"
      discard uc_emu_stop(uc)

  except CatchableError as e:
    if verboseMode:
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
  let dylibs = listImports(path)
  let fixups = parseChainedFixups(info)
  let bound = fixups.binds
  let rebases = fixups.rebases
  var thunkedCount = 0
  var unthunkedNames: seq[string]
  var dataResolvableCount = 0
  if bound.len > 0:
    for b in bound:
      if thunkTable.hasKey(b.symbolName):
        inc thunkedCount
      elif resolveDataSymbol(b.symbolName).ok or b.symbolName in shadowVarNames:
        inc dataResolvableCount
      elif b.symbolName notin unthunkedNames:
        unthunkedNames.add(b.symbolName)
    if verboseMode:
      echo &"[bind] {bound.len} bound symbols from {dylibs.len} dylib(s); {thunkedCount} code thunk(s), {dataResolvableCount} data symbol(s) resolvable."
      if unthunkedNames.len > 0:
        echo &"  not resolvable yet (will crash if actually used): {unthunkedNames.join(\", \")}"
      if rebases.len > 0:
        echo &"[rebase] {rebases.len} internal pointer(s) to fix up (selectors, vtables, string refs, ...)"

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
    guestRanges.add((seg.vmaddr, segEnd))

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
  guestRanges.add((stackBase, stackBase + StackSize))
  activeUc = uc
  checkErr(uc, uc_mem_map(uc, GuestHeapBase, csize_t GuestHeapSize, uint32(UC_PROT_READ or UC_PROT_WRITE)), "map guest heap")
  guestRanges.add((GuestHeapBase, GuestHeapBase + GuestHeapSize))
  guestHeapNext = GuestHeapBase
  checkErr(uc, uc_mem_map(uc, CallbackRet, 0x1000, uint32(UC_PROT_READ or UC_PROT_EXEC)), "map callback-return page")

  # ---- shadow cells for host DATA variables bound by this binary ----
  shadowVars.setLen(0)
  var shadowMapped = false
  var shadowNext = ShadowBase
  for b in bound:
    if b.symbolName in shadowVarNames:
      let hp = findHostData(b.symbolName)
      if hp == nil: continue
      if not shadowMapped:
        checkErr(uc, uc_mem_map(uc, ShadowBase, csize_t ShadowSize, uint32(UC_PROT_READ or UC_PROT_WRITE)), "map shadow")
        guestRanges.add((ShadowBase, ShadowBase + ShadowSize))
        shadowMapped = true
      shadowVars.add(ShadowVar(name: b.symbolName, hostAddr: hp, guestAddr: shadowNext))
      var slot: uint64 = shadowNext
      discard uc_mem_write(uc, b.address, addr slot, 8)
      if verboseMode:
        echo &"[bind] {b.symbolName} -> shadow cell 0x{shadowNext:x} mirroring host variable"
      shadowNext += 8
  syncShadowVars(uc)

  # ---- apply rebase fixups: internal pointer slots (Objective-C selector
  # refs, vtables, string pointers...) whose raw bytes are just encoded
  # chain data until corrected to the real in-image address.
  for r in rebases:
    var v: uint64 = r.targetVmaddr
    discard uc_mem_write(uc, r.address, addr v, 8)
  if verboseMode and rebases.len > 0:
    echo &"[rebase] applied {rebases.len} internal pointer fixup(s)"

  # ---- patch DATA bind symbols directly (e.g. _OBJC_CLASS_$_NSObject): the
  # GOT slot gets the real resolved value itself, not a thunk trampoline —
  # these are read as values, never branched into.
  for b in bound:
    let resolved = resolveDataSymbol(b.symbolName)
    if resolved.ok:
      var v: uint64 = resolved.value
      discard uc_mem_write(uc, b.address, addr v, 8)
      if verboseMode:
        echo &"[bind] {b.symbolName} -> real host value 0x{resolved.value:x} (GOT slot 0x{b.address:x} patched)"

  # ---- real thunking: for every bound symbol we have a host implementation
  # for, patch its GOT slot to point at a dedicated "thunk slot" address
  # instead of leaving it at 0 (unresolved). When the guest calls through
  # that GOT slot (a normal `ldr`+`br` stub the compiler already emits for
  # any external call), execution lands in our thunk region; onThunkCode
  # intercepts it, calls the REAL host libSystem function, and returns.
  if thunkedCount > 0:
    let rawThunkSize = uint64(bound.len) * ThunkSlotSize
    let thunkRegionSize = (rawThunkSize + 0xFFF'u64) and not 0xFFF'u64  # uc_mem_map requires page-aligned size
    checkErr(uc, uc_mem_map(uc, ThunkBase, csize_t thunkRegionSize, uint32(UC_PROT_READ or UC_PROT_EXEC)), "map thunk region")
    # Fill with `ret` (0xD65F03C0) so that if a slot is ever reached without
    # being redirected by the hook first, it fails safely (returns) instead
    # of executing garbage.
    var retInstr: array[4, byte] = [0xC0'u8, 0x03, 0x5F, 0xD6]
    var slotIdx = 0
    for b in bound:
      if thunkTable.hasKey(b.symbolName):
        let slotAddr = ThunkBase + uint64(slotIdx) * ThunkSlotSize
        discard uc_mem_write(uc, slotAddr, addr retInstr[0], 4)
        thunkSlotName[slotAddr] = b.symbolName
        # patch the GOT slot itself (b.address) to point at our thunk slot
        var slotVal: uint64 = slotAddr
        discard uc_mem_write(uc, b.address, addr slotVal, 8)
        if verboseMode:
          echo &"[bind] {b.symbolName} -> thunk slot 0x{slotAddr:x} (GOT slot 0x{b.address:x} patched)"
        inc slotIdx

    var thunkHook: UcHook
    checkErr(uc, uc_hook_add_code(uc, addr thunkHook, UC_HOOK_CODE, onThunkCode, nil,
                                   culonglong ThunkBase, culonglong(ThunkBase + thunkRegionSize)),
             "hook_add_thunk")

  if verboseMode:
    echo &"[load] jumping to entry 0x{entryAddr:x} — if the binary needs dyld/libSystem, it will stop at the first unsupported syscall/instruction."
  # See ReturnFromMainSentinel's comment: give a real `int main()`-style
  # binary's final `ret` somewhere recognizable to jump to, instead of
  # whatever garbage/zero X30 happened to hold, so a clean finish doesn't
  # print like a scary unexpected fault.
  var lrSentinel: culonglong = ReturnFromMainSentinel
  discard uc_reg_write(uc, UC_ARM64_REG_X30, addr lrSentinel)
  # NOTE: passing until=0 is a known Unicorn quirk that can make emulation
  # stop prematurely/unpredictably (see unicorn-engine issue reports on
  # "emulation stops when address 0 is reached" even though 0 was only meant
  # as a placeholder for "run until manually stopped"). We rely entirely on
  # the exit syscall hook to call uc_emu_stop(), so pass a real sentinel
  # address that's unreachable in practice instead of 0.
  const Sentinel: culonglong = 0xFFFFFFFFFFFFFFFF'u64
  let err = uc_emu_start(uc, entryAddr, Sentinel, 0, 0)
  var pcAtStop: culonglong
  discard uc_reg_read(uc, UC_ARM64_REG_PC, addr pcAtStop)
  let cleanReturnFromMain = (err != 0) and (uint64(pcAtStop) == ReturnFromMainSentinel)
  if verboseMode:
    if cleanReturnFromMain:
      echo &"[load] uc_emu_start returned: {err} ({$uc_strerror(err)}) — expected: this is the return-from-main sentinel, not a real error."
    else:
      echo &"[load] uc_emu_start returned: {err} ({$uc_strerror(err)})"
  elif err != 0 and not cleanReturnFromMain:
    if verboseMode:
      echo &"86arm: emulation stopped with an error ({$uc_strerror(err)})"

# ---- actual program entry point (was incorrectly nested inside
# runNativeBridge, as dead code after its `result` assignment — that meant
# NOTHING here ever ran, so every invocation of the compiled binary
# silently did nothing and exited 0 with zero output). Moved to top-level
# so it's Nim's real main.
#
# The old needsNativeBridge()/runNativeBridge() cputype-spoof + libaah86
# fault-capture path has been removed: it never got past its own
# documented stub (aah86_emulate_at() always just printed a message and
# _exit(70)), and every binary in this project's own test suite is now
# fully covered by the hand-wired thunk table + resolveDataSymbol above
# (including Foundation/NSLog, see the _NSLog thunk and the
# ___CFConstantStringClassReference case). If a future binary binds a
# symbol neither of those recognizes, onThunkCode already fails loudly
# and safely (see its `else` branch) instead of silently doing nothing —
# no separate bridge path is needed for that either. ----
var args = commandLineParams()
if args.len == 0:
  echo "Usage: 86arm [--verbose] [--trace] <arm64-file>   (or: 86arm --hello for the built-in demo)"
elif args[0] == "--hello":
  runHello()
elif args[0] == "--deps" and args.len >= 2:
  let info = parseMachO(args[1])
  let dylibs = listImports(args[1])
  if dylibs.len == 0:
    echo "No LC_LOAD_DYLIB dependencies (fully static binary)."
  else:
    echo "Dylib dependencies:"
    for imp in dylibs:
      echo "  ", imp.fromDylib
    echo ""
    let fixups = parseChainedFixups(info)
    let bound = fixups.binds
    if bound.len == 0:
      if info.hasClassicBindInfo:
        echo "No LC_DYLD_CHAINED_FIXUPS found — this binary uses the OLDER classic bind-opcode format (LC_DYLD_INFO/LC_DYLD_INFO_ONLY) instead, which this parser doesn't read yet. Try a newer deployment target (e.g. -target arm64-apple-macos12 or later) to get chained fixups."
      else:
        echo "No LC_DYLD_CHAINED_FIXUPS bind entries found (fully static, or no dynamic symbols at all)."
    else:
      echo &"{bound.len} bound symbols (address -> symbol, from dylib ordinal):"
      for b in bound:
        echo &"  0x{b.address:x}  {b.symbolName}  (lib ordinal {b.libOrdinal})"
    if fixups.rebases.len > 0:
      echo &"\n{fixups.rebases.len} internal rebase pointer(s) (selectors, vtables, string refs, ...)"
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
    # Self-contained loader + hand-wired thunk table handles everything
    # this project's test suite links against, including Foundation (see
    # the _NSLog thunk and ___CFConstantStringClassReference above). A
    # binary that binds something neither covers will simply stop with a
    # clear message from onThunkCode when it's first reached — no
    # separate native-bridge dispatch needed.
    discard parseMachO(args[0])  # currently unused here, but validates the file is a real Mach-O early
    runLoad(args[0], trace = trace)