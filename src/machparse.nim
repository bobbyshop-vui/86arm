## Mach-O parser using nimpy to call the real Python `macholib` — reads the
## header, load commands, and LC_SEGMENT_64 entries of an ARM64 binary.
##
## Install before building:
##   pip3 install macholib
##   nimble install nimpy
##
## Note: macholib is mostly used for dependency (dylib) analysis; it doesn't
## expose raw segment bytes directly. We use `macholib.MachO` only to get
## the already-parsed header + load commands (saves writing the struct
## layout from scratch), then read the actual bytes ourselves via
## (fileoff, filesize).

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
    entryOffset*: uint64      ## file offset of the entry point (from LC_MAIN)
    segments*: seq[Segment]
    path*: string

let py = pyBuiltinsModule()
let machoMod = pyImport("macholib.MachO")

proc parseMachO*(path: string): MachOInfo =
  ## Parse a real Mach-O file via macholib, extracting LC_SEGMENT_64 and LC_MAIN.
  if not fileExists(path):
    raise newException(IOError, &"File not found: {path}")

  let macho = machoMod.MachO(path)
  result.path = path

  # macholib exposes macho.headers -> list of MachOHeader (a fat binary can
  # have several); pick the first one matching arm64 (cputype 0x0100000C).
  const CPU_TYPE_ARM64 = 0x0100000C
  var chosenHeader: PyObject = nil
  for header in macho.headers:
    let cputype = header.header.cputype.to(int)
    if cputype == CPU_TYPE_ARM64:
      chosenHeader = header
      break
  if chosenHeader.isNil:
    raise newException(ValueError, "No ARM64 slice found in this Mach-O (check whether it's a fat binary containing arm64)")

  for cmdTuple in chosenHeader.commands:
    # each element is a tuple (load_command, cmd_struct, data)
    let lc = cmdTuple[0]
    let cmdStruct = cmdTuple[1]
    let cmdName = lc.get_cmd_name().to(string)

    if cmdName == "LC_SEGMENT_64":
      var seg: Segment
      seg.name = cmdStruct.segname.to(string).strip(chars = {'\0'})
      seg.vmaddr = cmdStruct.vmaddr.to(uint64)
      seg.vmsize = cmdStruct.vmsize.to(uint64)
      seg.fileoff = cmdStruct.fileoff.to(uint64)
      seg.filesize = cmdStruct.filesize.to(uint64)
      seg.maxprot = cmdStruct.maxprot.to(int32)
      seg.initprot = cmdStruct.initprot.to(int32)
      result.segments.add(seg)

    elif cmdName == "LC_MAIN":
      result.entryOffset = cmdStruct.entryoff.to(uint64)

proc readFileRange*(path: string, offset, size: uint64): seq[byte] =
  ## Read `size` bytes at `offset` directly from the file — used to get the
  ## real contents of each segment after parseMachO gives us (fileoff, filesize).
  var f = open(path, fmRead)
  defer: f.close()
  f.setFilePos(int64 offset)
  result = newSeq[byte](size)
  if size > 0:
    let n = f.readBytes(result, 0, int size)
    if uint64(n) != size:
      result.setLen(n)