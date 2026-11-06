## objc_ffi.nim — generic Objective-C method-call marshaling via libffi +
## real runtime type introspection, instead of a hand-maintained
## selector-name whitelist (the approach main.nim used before this file
## existed, which only covered "new" and "stringWithUTF8String:").
##
## THE IDEA: the real host Objective-C runtime already knows the exact
## signature of every method that exists (return type + each argument's
## type, in @encode notation) via method_getReturnType/
## method_getArgumentType. We don't need to guess arity from counting
## colons in the selector name — we can ask the runtime directly, then
## use libffi to build a call with exactly the right C ABI shape for
## that signature and invoke the real host implementation.
##
## macOS ships libffi.dylib as a system library at /usr/lib (used
## internally by things like Python's ctypes/PyObjC) — no Homebrew
## dependency needed, same as libobjc.A.dylib.
##
## REAL, DOCUMENTED LIMITS OF THIS APPROACH (read before filing a bug):
##   - Scalar pointer/integer/float/double argument and return types are
##     supported (id/Class/SEL/char*/generic pointers, 8/16/32/64-bit
##     integers incl. BOOL, and float/double — the latter via the D0-D7
##     FP register bank, tracked independently from the X2-X7 GP bank
##     per AAPCS64's real calling convention).
##   - Struct-by-value RETURN types are supported up to 16 bytes, as
##     long as no field (recursively) is a float/double — e.g. NSRange
##     works, but a struct containing so much as one CGFloat field does
##     not yet (AAPCS64 uses different, HFA-specific FP-register packing
##     rules for those, not implemented here).
##   - Struct-by-value ARGUMENTS are NOT supported at all yet (any arg
##     whose encoding starts with '{' is declined outright): AAPCS64
##     packs small struct arguments into 1-2 registers (GP or FP bank
##     depending on field composition) or passes larger ones by a
##     caller-made copy's address — genuinely different, unimplemented
##     machinery from both the struct-return case above and from how
##     scalar arguments are read.
##   - Struct return types over 16 bytes are NOT supported: AAPCS64
##     returns those via an INDIRECT convention (a hidden pointer in X8
##     that the guest call site expects), which this project's thunk
##     dispatch doesn't read/thread through at all yet.
##   - At most 6 real arguments (beyond self+_cmd) are supported, since
##     AAPCS64 only has 8 integer/pointer argument registers total and
##     self+_cmd already consume 2 of them. Calls needing a 7th+ real
##     argument (which AAPCS64 would pass on the stack) are rejected.
##   - `char*` ('*') arguments ARE translated guest->host (the same
##     translation stringWithUTF8String: needed by hand before): the
##     guest pointer is read as a NUL-terminated string and copied into a
##     real host buffer before the call. `char*` RETURN values are NOT
##     translated the other way — the raw host pointer is handed back to
##     the guest as-is. This is fine as long as guest code only ever
##     passes such a pointer on to another thunked call rather than
##     dereferencing it directly (exactly how id/object pointers already
##     work throughout this project) but will crash if the guest tries to
##     read through it itself.
##   - Generic `^`-prefixed pointers (pointer-to-something-not-otherwise-
##     listed) are passed through as raw values with NO translation in
##     either direction — correct if the value already is a real host
##     pointer (e.g. one that originated from a previous real call), but
##     wrong (and likely a crash inside the real implementation) if the
##     guest meant to pass a pointer to guest-local memory.

import std/[strformat, strutils, dynlib]
import unicorn_ffi

proc c_malloc(size: csize_t): pointer {.importc: "malloc", header: "<stdlib.h>".}
proc c_free(p: pointer) {.importc: "free", header: "<stdlib.h>".}

{.push dynlib: "/usr/lib/libobjc.A.dylib".}
proc objc_getClass_rt(name: cstring): pointer {.importc: "objc_getClass".}
proc object_getClass_rt(obj: pointer): pointer {.importc: "object_getClass".}
proc class_getInstanceMethod_rt(cls: pointer, sel: pointer): pointer {.importc: "class_getInstanceMethod".}
proc method_getNumberOfArguments_rt(m: pointer): cuint {.importc: "method_getNumberOfArguments".}
proc method_getReturnType_rt(m: pointer, dst: cstring, dstLen: csize_t) {.importc: "method_getReturnType".}
proc method_getArgumentType_rt(m: pointer, index: cuint, dst: cstring, dstLen: csize_t) {.importc: "method_getArgumentType".}
{.pop.}

# ---- libffi bindings — only the pieces needed for a plain "call this
# function pointer with these arg types, get this return type" shape.
# ffi_cif/ffi_type are real structs with real layouts, but we never need
# their fields directly from Nim — ffi_type_* globals are referenced only
# by address (libffi's own predefined type descriptors), and ffi_cif is
# only ever passed around as a raw byte buffer we allocate ourselves,
# sized generously above libffi's real (much smaller, but version-
# dependent) struct size. This avoids needing to model the exact struct
# layout, which differs across libffi versions/platforms.
#
# Resolved at RUNTIME via loadLib/symAddr (same pattern main.nim already
# uses for libobjc/Foundation/CoreFoundation) across several candidate
# paths, rather than a single hardcoded compile-time dynlib path: unlike
# libobjc.A.dylib (a long-stable public path), libffi's exact location
# has genuinely varied across macOS versions and install methods (system
# copy vs. Homebrew, which is keg-only and lives under a version-specific
# prefix on both Intel and Apple Silicon). Probing multiple real
# candidates and reporting which one (if any) worked is more robust than
# guessing one path and failing outright if it's wrong on a given
# machine. ----

const FfiCifBufSize = 256  # real struct is well under this on every known platform/arch

const libffiCandidates = [
  "/usr/lib/libffi.dylib",
  "/opt/homebrew/opt/libffi/lib/libffi.dylib",       # Homebrew, Apple Silicon (keg-only)
  "/usr/local/opt/libffi/lib/libffi.dylib",          # Homebrew, Intel (keg-only)
  "/opt/homebrew/lib/libffi.dylib",
  "/usr/local/lib/libffi.dylib",
]

var libffiHandle: LibHandle = nil
var libffiPathUsed = ""

var ffi_type_void: pointer = nil
var ffi_type_pointer: pointer = nil
var ffi_type_sint8: pointer = nil
var ffi_type_uint8: pointer = nil
var ffi_type_sint16: pointer = nil
var ffi_type_uint16: pointer = nil
var ffi_type_sint32: pointer = nil
var ffi_type_uint32: pointer = nil
var ffi_type_sint64: pointer = nil
var ffi_type_uint64: pointer = nil
var ffi_type_float: pointer = nil
var ffi_type_double: pointer = nil
var ffiPrepCifAddr: pointer = nil
var ffiCallAddr: pointer = nil
var ffiClosureAllocAddr: pointer = nil
var ffiPrepClosureLocAddr: pointer = nil

type FfiPrepCifFn = proc(cif: pointer, abi: cuint, nargs: cuint, rtype: pointer, atypes: pointer): cint {.cdecl.}
type FfiCallFn = proc(cif: pointer, fn: pointer, rvalue: pointer, avalue: pointer) {.cdecl.}

proc loadLibffi(): bool =
  for path in libffiCandidates:
    let h = loadLib(path)
    if h != nil:
      libffiHandle = h
      libffiPathUsed = path
      break
  if libffiHandle == nil:
    return false
  ffi_type_void = symAddr(libffiHandle, "ffi_type_void")
  ffi_type_pointer = symAddr(libffiHandle, "ffi_type_pointer")
  ffi_type_sint8 = symAddr(libffiHandle, "ffi_type_sint8")
  ffi_type_uint8 = symAddr(libffiHandle, "ffi_type_uint8")
  ffi_type_sint16 = symAddr(libffiHandle, "ffi_type_sint16")
  ffi_type_uint16 = symAddr(libffiHandle, "ffi_type_uint16")
  ffi_type_sint32 = symAddr(libffiHandle, "ffi_type_sint32")
  ffi_type_uint32 = symAddr(libffiHandle, "ffi_type_uint32")
  ffi_type_sint64 = symAddr(libffiHandle, "ffi_type_sint64")
  ffi_type_uint64 = symAddr(libffiHandle, "ffi_type_uint64")
  ffi_type_float = symAddr(libffiHandle, "ffi_type_float")
  ffi_type_double = symAddr(libffiHandle, "ffi_type_double")
  ffiPrepCifAddr = symAddr(libffiHandle, "ffi_prep_cif")
  ffiCallAddr = symAddr(libffiHandle, "ffi_call")
  ffiClosureAllocAddr = symAddr(libffiHandle, "ffi_closure_alloc")
  ffiPrepClosureLocAddr = symAddr(libffiHandle, "ffi_prep_closure_loc")
  result = ffi_type_pointer != nil and ffiPrepCifAddr != nil and ffiCallAddr != nil

proc ffi_prep_cif(cif: pointer, abi: cuint, nargs: cuint, rtype: pointer, atypes: pointer): cint =
  let fn = cast[FfiPrepCifFn](ffiPrepCifAddr)
  fn(cif, abi, nargs, rtype, atypes)

proc ffi_call(cif: pointer, fn: pointer, rvalue: pointer, avalue: pointer) =
  let f = cast[FfiCallFn](ffiCallAddr)
  f(cif, fn, rvalue, avalue)

const FFI_TYPE_STRUCT: cushort = 13
  ## Stable, publicly-documented libffi enum value (ffi.h's ffi_type_enum:
  ## VOID=0, INT=1, FLOAT=2, DOUBLE=3, LONGDOUBLE=4, UINT8=5, SINT8=6,
  ## UINT16=7, SINT16=8, UINT32=9, SINT32=10, UINT64=11, SINT64=12,
  ## STRUCT=13, POINTER=14). This numbering has been stable across libffi
  ## versions for a very long time (it's part of libffi's public, widely-
  ## depended-upon ABI — used directly by CPython's ctypes, PyObjC,
  ## etc.), unlike the earlier X6/X7 Unicorn register numbers which were
  ## an educated guess — this one is a documented public constant.

type FfiTypeRaw = object
  ## Mirrors libffi's real, public `struct _ffi_type` layout exactly:
  ##   typedef struct _ffi_type {
  ##     size_t size; unsigned short alignment; unsigned short type;
  ##     struct _ffi_type **elements;
  ##   } ffi_type;
  ## `size`/`alignment` are OUTPUT fields libffi computes and fills in
  ## itself during ffi_prep_cif when `type == FFI_TYPE_STRUCT` and they're
  ## left as 0 going in — we never compute struct layout math ourselves.
  size: csize_t
  alignment: cushort
  typeTag: cushort
  elements: pointer  # ptr UncheckedArray[pointer], NULL-terminated

proc skipQuotedFieldName(enc: string, pos: var int) =
  ## Modern clang @encode output embeds a quoted field name before each
  ## struct field's type (e.g. `{CGRect="origin"{CGPoint="x"d"y"d}...}`).
  ## Purely cosmetic for our purposes — skip it if present.
  if pos < enc.len and enc[pos] == '"':
    inc pos
    while pos < enc.len and enc[pos] != '"': inc pos
    if pos < enc.len: inc pos

proc skipQualifierChars(enc: string, pos: var int) =
  while pos < enc.len and enc[pos] in {'r', 'n', 'N', 'o', 'O', 'R', 'V'}:
    inc pos

proc parseEncodedType(enc: string, pos: var int): tuple[ok: bool, ty: pointer, hasFloat: bool, isCString: bool]

proc parseStructBody(enc: string, pos: var int): tuple[ok: bool, ty: pointer, hasFloat: bool] =
  ## enc[pos] == '{' on entry.
  inc pos
  while pos < enc.len and enc[pos] != '=' and enc[pos] != '}':
    inc pos  # skip the struct's tag name
  if pos < enc.len and enc[pos] == '=':
    inc pos
  var fieldTypes: seq[pointer] = @[]
  var anyFloat = false
  while pos < enc.len and enc[pos] != '}':
    skipQuotedFieldName(enc, pos)
    if pos >= enc.len or enc[pos] == '}': break
    let f = parseEncodedType(enc, pos)
    if not f.ok:
      return (false, nil, false)
    fieldTypes.add(f.ty)
    if f.hasFloat: anyFloat = true
  if pos < enc.len and enc[pos] == '}':
    inc pos
  # Build the elements array (NULL-terminated) and the new ffi_type,
  # exactly matching libffi's real struct layout — see FfiTypeRaw above.
  let elemArr = cast[ptr UncheckedArray[pointer]](
    c_malloc(csize_t((fieldTypes.len + 1) * sizeof(pointer))))
  for i, t in fieldTypes: elemArr[i] = t
  elemArr[fieldTypes.len] = nil
  let newType = cast[ptr FfiTypeRaw](c_malloc(csize_t(sizeof(FfiTypeRaw))))
  newType.size = 0
  newType.alignment = 0
  newType.typeTag = FFI_TYPE_STRUCT
  newType.elements = cast[pointer](elemArr)
  return (true, cast[pointer](newType), anyFloat)

proc parseEncodedType(enc: string, pos: var int): tuple[ok: bool, ty: pointer, hasFloat: bool, isCString: bool] =
  ## General recursive @encode parser: handles primitives, pointers,
  ## char* (flagged for guest->host translation same as before), and
  ## arbitrarily nested structs. Does NOT handle bitfields ('b'), unions
  ## ('('), fixed-size arrays ('['), or blocks ('@?') — these remain
  ## unsupported and cause an outright decline (ok=false) wherever they
  ## appear, same conservative behavior as before, just reachable from
  ## deeper inside a struct now too.
  skipQualifierChars(enc, pos)
  if pos >= enc.len:
    return (false, nil, false, false)
  case enc[pos]
  of '{':
    let s = parseStructBody(enc, pos)
    return (s.ok, s.ty, s.hasFloat, false)
  of '@', '#', ':':
    inc pos
    return (true, ffi_type_pointer, false, false)
  of '^':
    inc pos
    # Best-effort: consume whatever pointee type-spec follows so `pos`
    # ends up past it, but the pointer itself is always just passed
    # through as an opaque value regardless of what it points to.
    discard parseEncodedType(enc, pos)
    return (true, ffi_type_pointer, false, false)
  of '*':
    inc pos
    return (true, ffi_type_pointer, false, true)
  of 'c':
    inc pos; return (true, ffi_type_sint8, false, false)
  of 'C', 'B':
    inc pos; return (true, ffi_type_uint8, false, false)
  of 's':
    inc pos; return (true, ffi_type_sint16, false, false)
  of 'S':
    inc pos; return (true, ffi_type_uint16, false, false)
  of 'i':
    inc pos; return (true, ffi_type_sint32, false, false)
  of 'I':
    inc pos; return (true, ffi_type_uint32, false, false)
  of 'l', 'q':
    inc pos; return (true, ffi_type_sint64, false, false)
  of 'L', 'Q':
    inc pos; return (true, ffi_type_uint64, false, false)
  of 'f':
    inc pos; return (true, ffi_type_float, true, false)
  of 'd':
    inc pos; return (true, ffi_type_double, true, false)
  else:
    return (false, nil, false, false)  # bitfield/union/array/block — not supported

const FFI_DEFAULT_ABI: cuint = when defined(arm64): 1 else: 2
  ## Real libffi enum values (ffi_abi), taken from libffi's own
  ## <arm/ffitarget.h> (FFI_SYSV=1 is the only calling convention on
  ## arm64) and <x86_64/ffitarget.h> (FFI_UNIX64=2). These are stable
  ## ABI-defining constants, not implementation details likely to drift.
  ## NOTE: this is compiled for the HOST architecture (the machine
  ## running 86arm itself, x86_64 or Apple Silicon) — not the ARM64
  ## guest — since libffi here is making a REAL host-side call.

var runtimeReady = false

proc initObjcFfi*(verbose: bool = false): bool =
  ## Call once at startup. Verifies libobjc resolves AND probes the
  ## libffi candidate paths above, reporting which path worked (or that
  ## none did) when verbose is set.
  try:
    discard objc_getClass_rt("NSObject")
    let ffiOk = loadLibffi()
    if verbose:
      if ffiOk:
        echo "[objc_ffi] libffi loaded from " & libffiPathUsed
      else:
        echo "[objc_ffi] libffi not found in any candidate path — generic objc_msgSend path disabled"
    runtimeReady = ffiOk
  except CatchableError:
    runtimeReady = false
  result = runtimeReady

type MarshalArg = object
  storage: uint64          # raw little-endian storage; libffi reads only
                           # the low N bytes matching the chosen ffi_type,
                           # which is exactly correct on little-endian
                           # ARM64/x86_64
  hostBufToFree: pointer   # non-nil only for translated char* args

proc callObjcMsgSendRaw*(objcMsgSendAddr: pointer, selfPtr: pointer, sel: pointer, args: seq[pointer]): pointer =
  ## Minimal, always-available id-returning objc_msgSend call: self + sel +
  ## N plain pointer arguments, all marshaled via libffi (the SAME
  ## mechanism callObjcMsgSendGeneric already uses successfully) instead
  ## of a direct Nim {.cdecl.} function-pointer-cast call. Added because
  ## the direct-cast approach was observed in practice to return garbage
  ## values on at least one real host (Intel macOS) — the exact
  ## underlying ABI mismatch wasn't root-caused, but libffi's own
  ## conservative call-construction avoided it entirely, so this is the
  ## safe default for any raw msgSend call from now on, not just the
  ## fully-generic signature-introspected path.
  if not runtimeReady:
    return nil
  let nargs = args.len + 2
  var types = newSeq[pointer](nargs)
  types[0] = ffi_type_pointer
  types[1] = ffi_type_pointer
  for i in 0 ..< args.len: types[i + 2] = ffi_type_pointer
  var storage = newSeq[uint64](nargs)
  storage[0] = cast[uint64](selfPtr)
  storage[1] = cast[uint64](sel)
  for i in 0 ..< args.len: storage[i + 2] = cast[uint64](args[i])
  var valPtrs = newSeq[pointer](nargs)
  for i in 0 ..< nargs: valPtrs[i] = addr storage[i]
  var cifBuf = newString(FfiCifBufSize)
  let prepErr = ffi_prep_cif(cifBuf.cstring, FFI_DEFAULT_ABI, cuint(nargs), ffi_type_pointer, addr types[0])
  if prepErr != 0:
    return nil
  var retStorage: uint64 = 0
  ffi_call(cifBuf.cstring, objcMsgSendAddr, addr retStorage, addr valPtrs[0])
  result = cast[pointer](retStorage)

type VariadicArgKind* = enum vakPointer, vakDouble

proc callVariadicHostFn*(fnAddr: pointer, args: seq[tuple[kind: VariadicArgKind, bits: uint64]]): bool =
  ## Calls a real host variadic function (e.g. NSLog) with an explicit,
  ## caller-supplied type for each argument, via libffi — so a `double`
  ## argument gets routed through the FP register bank (XMM on x86_64
  ## host, D-regs on arm64 host) and a pointer/integer argument through
  ## the GP bank, matching whatever the REAL host ABI actually requires.
  ## This exists because a plain fixed-arg Nim {.cdecl.} function-pointer
  ## cast (the approach used before) passes EVERY argument through the
  ## GP bank regardless of its real type — harmless for pointer/integer
  ## values (their raw bits are meaningful there), but wrong for
  ## float/double values, which the real function's own va_arg reads
  ## from the FP bank and finds garbage in if we only ever wrote GP.
  ## Returns false (does nothing) if libffi isn't available.
  if not runtimeReady:
    return false
  let n = args.len
  var types = newSeq[pointer](n)
  var storage = newSeq[uint64](n)
  for i, a in args:
    types[i] = (if a.kind == vakDouble: ffi_type_double else: ffi_type_pointer)
    storage[i] = a.bits
  var valPtrs = newSeq[pointer](n)
  for i in 0 ..< n: valPtrs[i] = addr storage[i]
  var cifBuf = newString(FfiCifBufSize)
  let prepErr = ffi_prep_cif(cifBuf.cstring, FFI_DEFAULT_ABI, cuint(n), ffi_type_void,
                              (if n > 0: addr types[0] else: nil))
  if prepErr != 0:
    return false
  var dummyRet: uint64 = 0
  ffi_call(cifBuf.cstring, fnAddr, addr dummyRet, (if n > 0: addr valPtrs[0] else: nil))
  return true

proc ffiTypeAndKindForEncoding(rawEnc: string): tuple[ok: bool, ty: pointer, isCString: bool] =
  ## Thin wrapper around the general parseEncodedType parser, preserving
  ## the exact shape existing callers expect. Qualifier-stripping,
  ## pointer/primitive handling, and now struct handling too all live in
  ## parseEncodedType — this just adapts its richer result.
  var pos = 0
  let r = parseEncodedType(rawEnc, pos)
  (r.ok, r.ty, r.isCString)

proc ffiTypeAndKindForEncodingFull(rawEnc: string): tuple[ok: bool, ty: pointer, isCString: bool, hasFloat: bool] =
  var pos = 0
  let r = parseEncodedType(rawEnc, pos)
  (r.ok, r.ty, r.isCString, r.hasFloat)


# ---- AAPCS64 helpers for struct-by-value arguments/returns -------------------
#
# The GUEST is arm64 (AAPCS64), the HOST is x86_64 (SysV). libffi handles the
# HOST side of struct passing for us; what we must do ourselves is decode the
# GUEST side: where did the arm64 caller put the struct's bytes?
#   - Homogeneous Floating-point Aggregate (HFA: 1..4 members, all float or all
#     double)           -> one FP register (D0..D7) per member
#   - other, size <= 16 -> packed into 1-2 consecutive GP registers
#   - size > 16         -> caller passes a POINTER (in a GP reg) to a copy
# Struct RETURNS follow the same split, except >16 bytes uses the hidden X8
# pointer ("indirect result") rather than a register.

proc leafChars(enc: string, pos: var int, outp: var seq[char]) =
  ## Flattens an @encode string into its scalar leaf type characters.
  skipQualifierChars(enc, pos)
  if pos >= enc.len: return
  case enc[pos]
  of '{':
    inc pos
    while pos < enc.len and enc[pos] notin {'=', '}'}: inc pos
    if pos < enc.len and enc[pos] == '=': inc pos
    while pos < enc.len and enc[pos] != '}':
      skipQuotedFieldName(enc, pos)
      if pos >= enc.len or enc[pos] == '}': break
      leafChars(enc, pos, outp)
    if pos < enc.len: inc pos
  of '^':
    inc pos
    var tmp: seq[char]
    leafChars(enc, pos, tmp)
    outp.add('^')
  else:
    outp.add(enc[pos])
    inc pos

proc hfaInfo(enc: string): tuple[isHfa: bool, count: int, elemSize: int] =
  var pos = 0
  var leaves: seq[char]
  leafChars(enc, pos, leaves)
  if leaves.len < 1 or leaves.len > 4: return (false, 0, 0)
  let c0 = leaves[0]
  if c0 != 'f' and c0 != 'd': return (false, 0, 0)
  for c in leaves:
    if c != c0: return (false, 0, 0)
  (true, leaves.len, (if c0 == 'f': 4 else: 8))

proc structSizeOf(ty: pointer): int =
  ## libffi only fills in a struct ffi_type's size/alignment inside
  ## ffi_prep_cif — run a throwaway cif over it to make it compute them.
  var cif = newString(FfiCifBufSize)
  var t = ty
  discard ffi_prep_cif(cif.cstring, FFI_DEFAULT_ABI, 1, ffi_type_void, addr t)
  int(cast[ptr FfiTypeRaw](ty).size)

proc callHostPtrFn*(fnAddr: pointer, args: seq[uint64]): uint64 =
  ## Calls a real host function taking N pointer-sized integer arguments and
  ## returning a pointer-sized value (objc_alloc, objc_retain, ...), via libffi.
  if not runtimeReady: return 0
  let n = args.len
  var types = newSeq[pointer](n)
  var storage = newSeq[uint64](n)
  var valPtrs = newSeq[pointer](n)
  for i in 0 ..< n:
    types[i] = ffi_type_pointer
    storage[i] = args[i]
  for i in 0 ..< n: valPtrs[i] = addr storage[i]
  var cifBuf = newString(FfiCifBufSize)
  if ffi_prep_cif(cifBuf.cstring, FFI_DEFAULT_ABI, cuint(n), ffi_type_pointer,
                  (if n > 0: addr types[0] else: nil)) != 0:
    return 0
  var ret: uint64 = 0
  ffi_call(cifBuf.cstring, fnAddr, addr ret, (if n > 0: addr valPtrs[0] else: nil))
  ret

type
  CallGenericResult* = object
    ok*: bool
    retVal*: uint64
    retIsStruct*: bool
      ## Small (<=16 byte), non-HFA struct return: write retWords[0] -> X0,
      ## retWords[1] -> X1.
    retWords*: array[2, uint64]
    retSize*: int  # only meaningful when retIsStruct / retIsHfa / retIndirect
    retIsScalarFloat*: bool
      ## Scalar float/double return: write retVal's bits into D0.
    retIsHfa*: bool
      ## HFA struct return: member k goes into Dk (retBytes holds the
      ## members back to back, each retHfaElemSize bytes).
    retHfaCount*: int
    retHfaElemSize*: int
    retIndirect*: bool
      ## >16 byte struct return: the guest's X8 holds the address of a guest
      ## buffer that must receive retBytes.
    retBytes*: seq[byte]
    retIsCString*: bool
      ## return type is char* — the pointer is into HOST memory; the caller
      ## copies the string into guest memory before handing it over.
    reason*: string  # only meaningful when ok == false, for --verbose logging

proc readGpArgReg(uc: UcHandle, idx: int): uint64 =
  ## idx is the AAPCS64 GP argument register index (2..7 == X2..X7 — X0/X1
  ## are always self/_cmd, never a "real" argument here).
  var v: culonglong
  case idx
  of 2: discard uc_reg_read(uc, UC_ARM64_REG_X2, addr v)
  of 3: discard uc_reg_read(uc, UC_ARM64_REG_X3, addr v)
  of 4: discard uc_reg_read(uc, UC_ARM64_REG_X4, addr v)
  of 5: discard uc_reg_read(uc, UC_ARM64_REG_X5, addr v)
  of 6: discard uc_reg_read(uc, UC_ARM64_REG_X6, addr v)
  of 7: discard uc_reg_read(uc, UC_ARM64_REG_X7, addr v)
  else: v = 0
  uint64(v)

proc readFpArgReg(uc: UcHandle, idx: int): uint64 =
  ## idx is the AAPCS64 FP argument register index (0..7 == D0..D7),
  ## tracked completely independently from the GP index above.
  var v: culonglong
  case idx
  of 0: discard uc_reg_read(uc, UC_ARM64_REG_D0, addr v)
  of 1: discard uc_reg_read(uc, UC_ARM64_REG_D1, addr v)
  of 2: discard uc_reg_read(uc, UC_ARM64_REG_D2, addr v)
  of 3: discard uc_reg_read(uc, UC_ARM64_REG_D3, addr v)
  of 4: discard uc_reg_read(uc, UC_ARM64_REG_D4, addr v)
  of 5: discard uc_reg_read(uc, UC_ARM64_REG_D5, addr v)
  of 6: discard uc_reg_read(uc, UC_ARM64_REG_D6, addr v)
  of 7: discard uc_reg_read(uc, UC_ARM64_REG_D7, addr v)
  else: v = 0
  uint64(v)

type ArgKind = enum akScalar, akStruct

proc callObjcMsgSendGeneric*(
  uc: UcHandle,
  objcMsgSendAddr: pointer,
  selfPtr: uint64,
  realSel: pointer,
  selName: string,
  readGuestString: proc(addr0: uint64): string,
  cMalloc: proc(size: csize_t): pointer,
  cFree: proc(p: pointer),
  translateObj: proc(a: uint64): uint64 = nil,
  translateSel: proc(a: uint64): uint64 = nil,
  readGuestBytes: proc(a: uint64, n: int): seq[byte] = nil,
): CallGenericResult =
  ## Fully generic objc_msgSend using the real runtime's own method
  ## signature. Returns ok=false (never touching guest state) if the
  ## signature can't be handled so the caller can fall back.
  ##
  ## Guest->host translation hooks (all optional):
  ##   translateObj: object ('@') args that are guest-memory objects (e.g.
  ##                 compile-time @"..." literals) -> real host objects
  ##   translateSel: SEL (':') args (guest selector refs) -> real host SELs
  ##   readGuestBytes: needed for structs > 16 bytes passed by reference
  result = CallGenericResult(ok: false, retVal: 0, reason: "")
  if not runtimeReady:
    result.reason = "libffi/objc runtime not available"
    return

  let cls = object_getClass_rt(cast[pointer](selfPtr))
  if cls == nil:
    result.reason = "object_getClass returned nil"
    return
  let meth = class_getInstanceMethod_rt(cls, realSel)
  if meth == nil:
    result.reason = &"no Method found for selector '{selName}' on resolved class"
    return

  let totalArgs = int(method_getNumberOfArguments_rt(meth))  # includes self + _cmd
  let realArgCount = totalArgs - 2
  if realArgCount < 0 or realArgCount > 6:
    result.reason = &"unsupported arg count {realArgCount} (only 0..6 supported)"
    return

  # ---- return type ----
  var retBuf = newString(64)
  method_getReturnType_rt(meth, retBuf.cstring, csize_t 64)
  let retEnc = $(retBuf.cstring)
  let isVoidReturn = retEnc.len > 0 and retEnc[0] == 'v'
  var retType: pointer = ffi_type_void
  var retIsStruct = false
  var retHasFloat = false
  var retIsScalarFloat = false
  if not isVoidReturn:
    let rinfo = ffiTypeAndKindForEncodingFull(retEnc)
    if not rinfo.ok:
      result.reason = &"unsupported return type encoding '{retEnc}'"
      return
    retType = rinfo.ty
    var qpos = 0
    while qpos < retEnc.len and retEnc[qpos] in {'r', 'n', 'N', 'o', 'O', 'R', 'V'}: inc qpos
    retIsStruct = qpos < retEnc.len and retEnc[qpos] == '{'
    retHasFloat = rinfo.hasFloat
    retIsScalarFloat = (not retIsStruct) and retHasFloat

  # ---- argument types (pass 1) ----
  var argTypes = newSeq[pointer](realArgCount)
  var argEncs = newSeq[string](realArgCount)
  var argKinds = newSeq[ArgKind](realArgCount)
  var argCStr = newSeq[bool](realArgCount)
  var argHasFloat = newSeq[bool](realArgCount)
  for i in 0 ..< realArgCount:
    var argBuf = newString(64)
    method_getArgumentType_rt(meth, cuint(i + 2), argBuf.cstring, csize_t 64)
    let enc = $(argBuf.cstring)
    argEncs[i] = enc
    let info = ffiTypeAndKindForEncodingFull(enc)
    if not info.ok:
      result.reason = &"unsupported arg {i} type encoding '{enc}'"
      return
    argTypes[i] = info.ty
    argCStr[i] = info.isCString
    argHasFloat[i] = info.hasFloat
    var qpos = 0
    while qpos < enc.len and enc[qpos] in {'r', 'n', 'N', 'o', 'O', 'R', 'V'}: inc qpos
    argKinds[i] = (if qpos < enc.len and enc[qpos] == '{': akStruct else: akScalar)

  # ---- marshal argument VALUES (pass 2) ----
  var margs = newSeq[MarshalArg](realArgCount)
  var structBufs = newSeq[seq[byte]](realArgCount)
  var nextGp = 2   # X2 is the first available GP argument register
  var nextFp = 0   # D0 is the first available FP argument register

  template cleanupAndFail(msg: string) =
    for j in 0 ..< realArgCount:
      if margs[j].hostBufToFree != nil: cFree(margs[j].hostBufToFree)
    result.reason = msg
    return

  for i in 0 ..< realArgCount:
    let enc = argEncs[i]
    if argKinds[i] == akStruct:
      let sz = structSizeOf(argTypes[i])
      var buf = newSeq[byte](max(sz, 16))
      let h = hfaInfo(enc)
      if h.isHfa:
        if nextFp + h.count > 8:
          cleanupAndFail(&"arg {i} ('{enc}'): HFA ran out of FP registers")
        for k in 0 ..< h.count:
          let bits = readFpArgReg(uc, nextFp + k)
          for b in 0 ..< h.elemSize:
            buf[k * h.elemSize + b] = byte((bits shr (8 * b)) and 0xFF)
        nextFp += h.count
      elif sz <= 16:
        let words = (sz + 7) div 8
        if nextGp + words > 8:
          cleanupAndFail(&"arg {i} ('{enc}'): struct ran out of GP registers")
        for w in 0 ..< words:
          let bits = readGpArgReg(uc, nextGp + w)
          for b in 0 ..< 8:
            buf[w * 8 + b] = byte((bits shr (8 * b)) and 0xFF)
        nextGp += words
      else:
        if nextGp > 7 or readGuestBytes == nil:
          cleanupAndFail(&"arg {i} ('{enc}'): large struct needs a GP register + guest memory reader")
        let p = readGpArgReg(uc, nextGp)
        inc nextGp
        let bytes = readGuestBytes(p, sz)
        if bytes.len != sz:
          cleanupAndFail(&"arg {i} ('{enc}'): could not read {sz} bytes of struct from guest memory")
        for b in 0 ..< sz: buf[b] = bytes[b]
      structBufs[i] = buf
      continue

    var rawVal: uint64
    if argHasFloat[i]:
      if nextFp > 7:
        cleanupAndFail(&"arg {i}: ran out of FP argument registers (D0-D7 all used)")
      rawVal = readFpArgReg(uc, nextFp)
      inc nextFp
    else:
      if nextGp > 7:
        cleanupAndFail(&"arg {i}: ran out of GP argument registers (X2-X7 all used)")
      rawVal = readGpArgReg(uc, nextGp)
      inc nextGp
    var m = MarshalArg(storage: rawVal, hostBufToFree: nil)
    var q = 0
    while q < enc.len and enc[q] in {'r', 'n', 'N', 'o', 'O', 'R', 'V'}: inc q
    if argCStr[i]:
      # rawVal is a GUEST address — copy the C string into a real host buffer.
      let s = readGuestString(rawVal)
      let hostBuf = cMalloc(csize_t(s.len + 1))
      if s.len > 0:
        copyMem(hostBuf, unsafeAddr s[0], s.len)
      cast[ptr UncheckedArray[byte]](hostBuf)[s.len] = 0
      m.storage = cast[uint64](hostBuf)
      m.hostBufToFree = hostBuf
    elif q < enc.len and enc[q] == '@' and translateObj != nil:
      m.storage = translateObj(rawVal)
    elif q < enc.len and enc[q] == ':' and translateSel != nil:
      m.storage = translateSel(rawVal)
    margs[i] = m

  # ---- full type/value arrays: self (id) + _cmd (SEL), then the real args ----
  var allTypes = newSeq[pointer](realArgCount + 2)
  allTypes[0] = ffi_type_pointer
  allTypes[1] = ffi_type_pointer
  for i in 0 ..< realArgCount: allTypes[i + 2] = argTypes[i]

  var cifBuf = newString(FfiCifBufSize)
  let prepErr = ffi_prep_cif(cifBuf.cstring, FFI_DEFAULT_ABI, cuint(realArgCount + 2),
                              retType, addr allTypes[0])
  if prepErr != 0:
    cleanupAndFail(&"ffi_prep_cif failed (code {prepErr})")

  var allValStorage = newSeq[uint64](realArgCount + 2)
  allValStorage[0] = selfPtr
  allValStorage[1] = cast[uint64](realSel)
  for i in 0 ..< realArgCount: allValStorage[i + 2] = margs[i].storage
  var allValPtrs = newSeq[pointer](realArgCount + 2)
  allValPtrs[0] = addr allValStorage[0]
  allValPtrs[1] = addr allValStorage[1]
  for i in 0 ..< realArgCount:
    allValPtrs[i + 2] =
      (if argKinds[i] == akStruct: cast[pointer](addr structBufs[i][0])
       else: cast[pointer](addr allValStorage[i + 2]))

  var structRetSize = 0
  if retIsStruct:
    structRetSize = int(cast[ptr FfiTypeRaw](retType).size)
    if structRetSize == 0: structRetSize = structSizeOf(retType)

  var retStorage = newSeq[byte](max(structRetSize, 16) + 16)  # zeroed
  ffi_call(cifBuf.cstring, objcMsgSendAddr, addr retStorage[0], addr allValPtrs[0])

  for m in margs:
    if m.hostBufToFree != nil: cFree(m.hostBufToFree)

  proc word(b: seq[byte], k: int): uint64 =
    for j in 0 ..< 8: result = result or (uint64(b[k * 8 + j]) shl (8 * j))

  result.ok = true
  block:
    var q = 0
    while q < retEnc.len and retEnc[q] in {'r', 'n', 'N', 'o', 'O', 'R', 'V'}: inc q
    result.retIsCString = q < retEnc.len and retEnc[q] == '*'
  if retIsStruct:
    result.retSize = structRetSize
    result.retBytes = retStorage[0 ..< structRetSize]
    let h = hfaInfo(retEnc)
    if h.isHfa:
      result.retIsHfa = true
      result.retHfaCount = h.count
      result.retHfaElemSize = h.elemSize
    elif structRetSize <= 16:
      result.retIsStruct = true
      result.retWords = [word(retStorage, 0), word(retStorage, 1)]
      result.retVal = result.retWords[0]
    else:
      result.retIndirect = true
  elif retIsScalarFloat:
    result.retIsScalarFloat = true
    result.retVal = word(retStorage, 0)
    # libffi writes a float into the low 4 bytes / a double into all 8; D0
    # only needs those raw bits (S0 aliases the low 32 bits of D0).
  else:
    result.retVal = (if isVoidReturn: 0'u64 else: word(retStorage, 0))


# ---- host->guest callbacks: native IMPs backed by libffi closures ------------
type GuestImpHandler* = proc(cif: pointer, ret: pointer, args: pointer, userData: pointer) {.cdecl.}

var closureCifs: seq[pointer]  # keep cifs + type arrays alive forever

proc makeImpClosure*(handler: GuestImpHandler, userData: pointer): pointer =
  ## Returns a real, callable host function pointer with the shape
  ## `id fn(id self, SEL _cmd, id a1, id a2, id a3)`; calling it invokes
  ## `handler`. Extra trailing args are harmless on x86_64 SysV (they're
  ## just registers). Used as the IMP for guest-defined Objective-C methods.
  if not runtimeReady or ffiClosureAllocAddr == nil or ffiPrepClosureLocAddr == nil:
    return nil
  type AllocFn = proc(size: csize_t, code: ptr pointer): pointer {.cdecl.}
  type PrepFn = proc(closure: pointer, cif: pointer, fun: pointer, ud: pointer, codeLoc: pointer): cint {.cdecl.}
  let cif = c_malloc(FfiCifBufSize)
  let types = cast[ptr UncheckedArray[pointer]](c_malloc(5 * sizeof(pointer)))
  for i in 0 ..< 5: types[i] = ffi_type_pointer
  if ffi_prep_cif(cif, FFI_DEFAULT_ABI, 5, ffi_type_pointer, types) != 0: return nil
  closureCifs.add(cif)
  var code: pointer = nil
  let closure = cast[AllocFn](ffiClosureAllocAddr)(256, addr code)
  if closure == nil: return nil
  if cast[PrepFn](ffiPrepClosureLocAddr)(closure, cif, cast[pointer](handler), userData, code) != 0:
    return nil
  code
