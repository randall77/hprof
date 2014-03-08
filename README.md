hprof
=====

Heap profile reader for Go

Runtime patch: https://codereview.appspot.com/37540043/

You call debug.DumpHeap(fd uintptr) to write a heap dump to the given
file descriptor from within your Go program (that's runtime/debug).

The code in this directory is for a hprof utility which converts
from the internal dump format to the hprof format.

go build
hprof dumpfile dump.hprof
jhat dump.hprof  (might need to download jhat)

then navigate a browser to localhost:7000 and poke around.  A good example is "show heap histogram".

jhat is one simple analysis tool - there are a bunch of others out
there.  My converter only fills in data that jhat requires, though,
other tools may need more info to work.

It's a java-centric format, so there is a lot of junk that doesn't
translate well from Go.

The Go heap contains no type information for objects which have no
pointers in them.  You'll just see "noptrX" types for different sizes
X.

The Go heap also contains no field names for objects, so you'll just
see fX for different offsets X in the object.

Below is a description of the internal format of the heap dump.

The file starts with the bytes "go1.3 heap dump\n".  The rest of the
file is encoded in records of different kind.  Most values in these
records are encoded with a variable-sized integer encoding (uvarint)
compatible with ReadUvarint in encoding/binary.

Each record starts with a "kind" which is uvarint encoded.  These
are the possible kinds:
   1: object
   3: eof
   4: stackroot
   5: dataroot
   6: otherroot
   7: type
   8: stack frame
   9: stack
  10: dump params

Strings are encoded with a Uvarint size followed by that many bytes of string (UTF8 encoded)

Each kind of record has a different layout.  Here are the layouts:

object:
  1       uvarint
  addr    uvarint     address of object start
  type    uvarint     address of type, 0 if unknown
  kind    uvarint     0 - regular T, 1 - array of T, 2 - channel of T (must be 0 if type is 0)
  size    uvarint     total size (size of sizeclass, type.size may be a bit smaller)
  data    size bytes

eof:
  3       uvarint

stackroot:
  4       uvarint
  rootptr uvarint     possible ptr to an object
  frame   uvarint     sp of frame this pointer came from

dataroot:
  5       uvarint
  addr    uvarint     address where pointer was found
  rootptr uvarint     possible ptr to an object
  TODO: containing symbol & offset?  Might need to use dwarf to figure that out

otherroot:
  6       uvarint
  rootptr uvarint     possible ptr to an object
  TODO: some sort of description of otherness?

type:
  7       uvarint
  addr    uvarint     identifier for type (Type*)
  size    uvarint     size of this type of object
  name    string
  nptrs   uvarint     number of pointers in an object of this type.
  ptroffset uvarint*  list of offsets of pointers.  Increasing order.
  TODO: field names, ...

thread:
  8       uvarint
  addr    uvarint     thread identifier
  tos     uvarint     top frame of stack

stack frame:
  9       uvarint
  addr    uvarint     sp of frame
  parent  uvarint     sp of parent's frame, or nil if bottom of stack
  name    string      function name

dump params:
  10      uvarint
  endian  uvarint     0=little endian, 1=big endian
  ptrsize uvarint     ptr size in bits.  4 or 8
