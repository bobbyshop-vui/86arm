## Mach-O parser using nimpy to call the real Python `LIEF` library.
##
## Replaces the previous macholib + hand-rolled LC_DYLD_CHAINED_FIXUPS byte
## parser. LIEF understands chained fixups natively (unlike macholib, whose
## command table predates cmd 0x80000034) and exposes a single unified
## `.bindings` list covering every bound external symbol, plus `.relocations`
## for internal rebase pointers — so all of the raw struct/bitfield parsing
## that used to live here (dyld_chained_fixups_header, page starts, chain
## walking, DYLD_CHAINED_PTR_64 bit layout, import table decoding, etc.) is
## no longer needed. LIEF has already done it and verified correct against
## this project's own real test_foundation binary: same 6 bound symbols,
## same 2 rebase pointers as the old parser produced.
##
## Install before building:
##   pip3 install lief
##   nimble install nimpy

import nimpy
import std/[os, strformat, strutils]

type
  Segment* = object
    name*: string
    vmaddr*: uint64
    vmsize*: uint64
    fileoff*: uint64
    filesize*: uint64
    maxprot*: int32
    initprot*: int32

  MachOInfo* = object
    entryOffset*: uint64      ## file offset of the entry point
    cpuType*: int             ## Mach-O CPU type, e.g. ARM64 or x86_64
    segments*: seq[Segment]
    path*: string
    hasChainedFixups*: bool
    hasClassicBindInfo*: bool ## true if LC_DYLD_INFO(_ONLY) is present instead

  ImportedSymbol* = object
    name*: string
    fromDylib*: string

  BoundSymbol* = object
    address*: uint64      ## guest vmaddr where this bound pointer lives
    ordinal*: int         ## library ordinal, for cross-checking / display
    symbolName*: string
    libOrdinal*: int

  RebaseEntry* = object
    address*: uint64       ## guest vmaddr of the pointer slot
    targetVmaddr*: uint64  ## the correct in-image address it should point to

let lief = pyImport("lief")

const CPU_TYPE_ARM64 = 0x0100000C
const CPU_TYPE_X86_64 = 0x01000007

proc readFileRange*(path: string, offset, size: uint64): seq[byte] =
  ## Read `size` bytes at `offset` directly from the file. Used by main.nim
  ## to load each segment's raw bytes into Unicorn's emulated memory —
  ## nothing to do with chained-fixups parsing (that part now goes through
  ## LIEF), so this stays as a plain, dependency-free file helper.
  var f = open(path, fmRead)
  defer: f.close()
  f.setFilePos(int64 offset)
  result = newSeq[byte](size)
  if size > 0:
    let n = f.readBytes(result, 0, int size)
    if uint64(n) != size:
      result.setLen(n)

proc loadBinary(path: string): PyObject =
  ## lief.parse() handles both real files; raise if it can't produce a
  ## Mach-O (e.g. wrong format, or a fat binary LIEF can't disambiguate).
  if not fileExists(path):
    raise newException(IOError, &"File not found: {path}")
  let b = lief.parse(path)
  # NOTE: nimpy has no isNone()/is-None check built in (see
  # yglukhov/nimpy#164 — never added). `b.isNone` is also wrong even if it
  # existed, since nimpy's `.` on PyObject always means "look up this
  # Python attribute", not a Nim proc call. Compare the stringified repr
  # instead — nimpy implements `$` on PyObject via Python's str(), and
  # lief.parse() returns Python None on failure, whose str() is "None".
  if $b == "None":
    raise newException(ValueError, &"LIEF could not parse {path} as Mach-O")
  result = b

proc parseMachO*(path: string): MachOInfo =
  ## Parse a real Mach-O file via LIEF: header, LC_SEGMENT_64 entries,
  ## entry point, and whether chained fixups / classic bind info is present.
  let b = loadBinary(path)
  result.path = path

  let cputype = b.header.cpu_type.value.to(int)
  if cputype != CPU_TYPE_ARM64 and cputype != CPU_TYPE_X86_64:
    raise newException(ValueError, "No supported Mach-O slice found (expected ARM64 or x86_64)")
  result.cpuType = cputype

  for seg in b.segments:
    result.segments.add(Segment(
      name: seg.name.to(string).strip(chars = {'\0'}),
      vmaddr: seg.virtual_address.to(uint64),
      vmsize: seg.virtual_size.to(uint64),
      fileoff: seg.file_offset.to(uint64),
      filesize: seg.file_size.to(uint64),
      maxprot: seg.max_protection.to(int32),
      initprot: seg.init_protection.to(int32),
    ))

  if b.has_main_command.to(bool):
    result.entryOffset = b.main_command.entrypoint.to(uint64)
  elif b.has_entrypoint.to(bool):
    # Some binaries (e.g. raw -nostdlib -Wl,-e,__start ones) don't carry
    # LC_MAIN but LIEF still resolves an entrypoint vmaddr for them.
    result.entryOffset = b.virtual_address_to_offset(b.entrypoint).to(uint64)

  result.hasChainedFixups = b.has_dyld_chained_fixups.to(bool)
  result.hasClassicBindInfo = b.has_dyld_info.to(bool)

proc listImports*(path: string): seq[ImportedSymbol] =
  ## Lists which dylibs this binary depends on (LC_LOAD_DYLIB). For the
  ## actual per-symbol bind list with addresses, see parseChainedFixups.
  let b = loadBinary(path)
  for lib in b.libraries:
    result.add(ImportedSymbol(
      name: "(see parseChainedFixups for per-symbol detail)",
      fromDylib: lib.name.to(string).strip(chars = {'\0'})
    ))

proc parseChainedFixups*(info: MachOInfo): tuple[binds: seq[BoundSymbol], rebases: seq[RebaseEntry]] =
  ## Returns every bound external symbol (binds) and internal pointer fixup
  ## (rebases) in the binary, via LIEF's unified `.bindings` / `.relocations`
  ## — works for both the modern LC_DYLD_CHAINED_FIXUPS format and the
  ## classic LC_DYLD_INFO bind-opcode format transparently, so callers no
  ## longer need to special-case which format a given binary uses.
  if not info.hasChainedFixups and not info.hasClassicBindInfo:
    return  # fully static binary — nothing to bind or rebase

  let b = loadBinary(info.path)

  for bnd in b.bindings:
    let symName = if bnd.has_symbol.to(bool): bnd.symbol.name.to(string) else: "(anonymous)"
    result.binds.add(BoundSymbol(
      address: bnd.address.to(uint64),
      ordinal: bnd.library_ordinal.to(int),
      symbolName: symName,
      libOrdinal: bnd.library_ordinal.to(int)
    ))

  for r in b.relocations:
    # Only internal (non-symbol) relocations are rebases; symbol-carrying
    # ones are already covered above via .bindings.
    if not r.has_symbol.to(bool):
      result.rebases.add(RebaseEntry(
        address: r.address.to(uint64),
        targetVmaddr: r.target.to(uint64)
      ))