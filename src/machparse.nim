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


proc rd32(d: string, o: int): uint32 =
  for i in 0 ..< 4: result = result or (uint32(ord(d[o + i])) shl (8 * i))
proc rd64(d: string, o: int): uint64 =
  for i in 0 ..< 8: result = result or (uint64(ord(d[o + i])) shl (8 * i))
proc rd16(d: string, o: int): uint16 =
  uint16(ord(d[o])) or (uint16(ord(d[o + 1])) shl 8)

proc walkChainedFixups*(path: string, imageBase: uint64): tuple[binds: seq[BoundSymbol], rebases: seq[RebaseEntry]] =
  ## Independent walk of LC_DYLD_CHAINED_FIXUPS (formats DYLD_CHAINED_PTR_64 /
  ## _64_OFFSET). LIEF was observed to drop the FIRST fixup of some chains
  ## (e.g. the first slot of a constant-array's element table), leaving the
  ## guest with a still-encoded pointer; this walk is the source of truth and
  ## its results are merged with LIEF's by the caller.
  let d = readFile(path)
  if d.len < 32 or rd32(d, 0) != 0xFEEDFACF'u32: return
  let ncmds = int rd32(d, 16)
  var off = 32
  var dataoff = 0
  for _ in 0 ..< ncmds:
    let cmd = rd32(d, off)
    let sz = int rd32(d, off + 4)
    if cmd == 0x80000034'u32: dataoff = int rd32(d, off + 8)
    off += sz
  if dataoff == 0: return
  let f = dataoff
  let startsOff = f + int rd32(d, f + 4)
  let importsOff = f + int rd32(d, f + 8)
  let symbolsOff = f + int rd32(d, f + 12)
  let importsFmt = rd32(d, f + 20)
  let segCount = int rd32(d, startsOff)
  for si in 0 ..< segCount:
    let sio = int rd32(d, startsOff + 4 + si * 4)
    if sio == 0: continue
    let seg = startsOff + sio
    let pageSize = uint64 rd16(d, seg + 4)
    let fmt = rd16(d, seg + 6)
    let segOffset = rd64(d, seg + 8)
    let pageCount = int rd16(d, seg + 20)
    if fmt != 2 and fmt != 6: continue
    for pi in 0 ..< pageCount:
      let ps = rd16(d, seg + 22 + pi * 2)
      if ps == 0xFFFF'u16: continue
      var addrV = imageBase + segOffset + uint64(pi) * pageSize + uint64 ps
      # the chain's slots live in the FILE at (segment fileoff + (addr - segvm)); map addr->file
      # using the segment table is overkill: segment fileoff == segment vm offset
      # for the Mach-O layouts clang/ld64 emit (fileoff = vmaddr - base).
      while true:
        let fo = int(addrV - imageBase)
        if fo + 8 > d.len: break
        let raw = rd64(d, fo)
        let nxt = int((raw shr 51) and 0xFFF)
        if (raw shr 63) == 1:
          let ordinal = int(raw and 0xFFFFFF'u64)
          var name = ""
          let iOff = importsOff + (if importsFmt == 2: ordinal * 8 else: ordinal * 4)
          let w = rd32(d, iOff)
          let libOrd = int(w and 0xFF)
          let nameOff = int(w shr 9)
          var k = symbolsOff + nameOff
          while k < d.len and d[k] != '\0':
            name.add(d[k]); inc k
          result.binds.add(BoundSymbol(address: addrV, ordinal: libOrd, symbolName: name, libOrdinal: libOrd))
        else:
          let target = raw and 0xFFFFFFFFF'u64
          let high8 = (raw shr 36) and 0xFF
          let tv = (if fmt == 6: imageBase + target else: target)
          result.rebases.add(RebaseEntry(address: addrV, targetVmaddr: (high8 shl 56) or tv))
        if nxt == 0: break
        addrV += uint64(nxt) * 4

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

  # ---- merge with an independent chain walk (fills anything LIEF missed) ----
  var imageBase: uint64 = 0
  for sgm in info.segments:
    if sgm.name == "__TEXT": imageBase = sgm.vmaddr
  if imageBase != 0:
    let w = walkChainedFixups(info.path, imageBase)
    var haveBind: seq[uint64]
    for b in result.binds: haveBind.add(b.address)
    for b in w.binds:
      if b.address notin haveBind: result.binds.add(b)
    var haveRb: seq[uint64]
    for r in result.rebases: haveRb.add(r.address)
    for r in w.rebases:
      if r.address notin haveRb: result.rebases.add(r)
