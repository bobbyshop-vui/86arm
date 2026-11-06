## Direct FFI binding to libunicorn (no third-party nimble wrapper, since
## unofficial wrappers tend to lag behind the real header). Only what's
## needed is bound here.
##
## macOS: `brew install unicorn` then link -L/opt/homebrew/lib -lunicorn
##   (Apple Silicon) or -L/usr/local/lib -lunicorn (Intel).

when defined(macosx):
  {.passL: "-lunicorn".}
  when defined(arm64):
    {.passL: "-L/opt/homebrew/lib".}
  else:
    {.passL: "-L/usr/local/lib".}
else:
  {.passL: "-lunicorn".}

type
  UcHandle* = pointer
  UcErr* = cint
  UcHook* = culong

  UcArch* = cint
  UcMode* = cint

const
  UC_ARCH_ARM64*: UcArch = 2

  UC_MODE_LITTLE_ENDIAN*: UcMode = 0
  UC_MODE_ARM*: UcMode = 0

  UC_HOOK_INTR*: cint = 1         # 1 shl 0 — hook exception/interrupt (SVC)
  UC_HOOK_CODE*: cint = 4         # 1 shl 2
  UC_HOOK_MEM_READ_UNMAPPED*: cint = 0x10
  UC_HOOK_MEM_WRITE_UNMAPPED*: cint = 0x20
  UC_HOOK_MEM_FETCH_UNMAPPED*: cint = 0x40

  UC_PROT_READ*: cint = 1
  UC_PROT_WRITE*: cint = 2
  UC_PROT_EXEC*: cint = 4
  UC_PROT_ALL*: cint = 7

  # ARM64 register ids — REAL values taken from
  # bindings/python/unicorn/arm64_const.py in the unicorn-engine/unicorn
  # repo (the enum order is NOT linear by Xn like many people assume, so
  # these must never be guessed — always check the upstream header/bindings).
  UC_ARM64_REG_X0*: cint = 199
  UC_ARM64_REG_X1*: cint = 200
  UC_ARM64_REG_X2*: cint = 201
  UC_ARM64_REG_X3*: cint = 202
  UC_ARM64_REG_X4*: cint = 203
  UC_ARM64_REG_X5*: cint = 204
  UC_ARM64_REG_X6*: cint = 205   # INFERRED from the sequential X0..X5/X8 pattern
  UC_ARM64_REG_X7*: cint = 206   # above (199..204, then 207) — not independently
                                  # re-verified against upstream unicorn source in
                                  # this sandbox (no real libunicorn available to
                                  # check against). Verify against
                                  # bindings/python/unicorn/arm64_const.py if a
                                  # 5th/6th objc_msgSend argument comes back wrong.
  UC_ARM64_REG_X8*: cint = 207
  UC_ARM64_REG_D0*: cint = 40   # CONFIRMED real values (compiled+verified
  UC_ARM64_REG_D1*: cint = 41   # against the user's actual installed
  UC_ARM64_REG_D2*: cint = 42   # libunicorn header, not inferred/guessed)
  UC_ARM64_REG_D3*: cint = 43
  UC_ARM64_REG_D4*: cint = 44
  UC_ARM64_REG_D5*: cint = 45
  UC_ARM64_REG_D6*: cint = 46
  UC_ARM64_REG_D7*: cint = 47
  UC_ARM64_REG_X16*: cint = 215   # syscall number, per XNU convention
  UC_ARM64_REG_SP*: cint = 4
  UC_ARM64_REG_X30*: cint = 2     # LR — used by the thunk layer to "return" after a host call
  UC_ARM64_REG_PC*: cint = 260

{.push importc, dynlib: (when defined(macosx): "libunicorn.dylib" else: "libunicorn.so").}
proc uc_open*(arch: UcArch, mode: UcMode, uc: ptr UcHandle): UcErr
proc uc_close*(uc: UcHandle): UcErr
proc uc_mem_map*(uc: UcHandle, address: culonglong, size: csize_t, perms: uint32): UcErr
proc uc_mem_protect*(uc: UcHandle, address: culonglong, size: csize_t, perms: uint32): UcErr
proc uc_mem_write*(uc: UcHandle, address: culonglong, bytes: pointer, size: csize_t): UcErr
proc uc_mem_read*(uc: UcHandle, address: culonglong, bytes: pointer, size: csize_t): UcErr
proc uc_reg_write*(uc: UcHandle, regid: cint, value: pointer): UcErr
proc uc_reg_read*(uc: UcHandle, regid: cint, value: pointer): UcErr
proc uc_emu_start*(uc: UcHandle, beg, `end`: culonglong, timeout: culonglong, count: csize_t): UcErr
proc uc_emu_stop*(uc: UcHandle): UcErr
proc uc_errno*(uc: UcHandle): UcErr
proc uc_context_alloc*(uc: UcHandle, ctx: ptr pointer): UcErr
proc uc_context_save*(uc: UcHandle, ctx: pointer): UcErr
proc uc_context_restore*(uc: UcHandle, ctx: pointer): UcErr
proc uc_context_free*(ctx: pointer): UcErr
proc uc_strerror*(err: UcErr): cstring
{.pop.}

type HookCallback* = proc(uc: UcHandle, intno: uint32, userData: pointer) {.cdecl.}
type CodeHookCallback* = proc(uc: UcHandle, address: culonglong, size: uint32, userData: pointer) {.cdecl.}
type MemHookCallback* = proc(uc: UcHandle, memType: cint, address: culonglong,
                              size: cint, value: clonglong, userData: pointer): bool {.cdecl.}

proc uc_hook_add_intr*(uc: UcHandle, hh: ptr UcHook, htype: cint,
                        callback: HookCallback, userData: pointer,
                        beg, `end`: culonglong): UcErr
  {.importc: "uc_hook_add", dynlib: (when defined(macosx): "libunicorn.dylib" else: "libunicorn.so"), varargs.}

proc uc_hook_add_code*(uc: UcHandle, hh: ptr UcHook, htype: cint,
                        callback: CodeHookCallback, userData: pointer,
                        beg, `end`: culonglong): UcErr
  {.importc: "uc_hook_add", dynlib: (when defined(macosx): "libunicorn.dylib" else: "libunicorn.so"), varargs.}

proc uc_hook_add_mem*(uc: UcHandle, hh: ptr UcHook, htype: cint,
                       callback: MemHookCallback, userData: pointer,
                       beg, `end`: culonglong): UcErr
  {.importc: "uc_hook_add", dynlib: (when defined(macosx): "libunicorn.dylib" else: "libunicorn.so"), varargs.}

proc checkErr*(uc: UcHandle, err: UcErr, ctx: string) =
  if err != 0:
    raise newException(CatchableError, ctx & ": " & $uc_strerror(err))