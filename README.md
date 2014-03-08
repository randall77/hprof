hprof
=====

Heap profile reader for Go
Runtime patch:

https://codereview.appspot.com/37540043/

You call runtime.DumpHeap(filename string) to get a heap dump from within your Go program.

The code in this directory is for a dumptohprof utility which converts from the internal dump format to the hprof format.

go build dumptohprof.go readdump.go
./dumptohprof dumpfile dump.hprof
jhat dump.hprof  (might need to download jhat)

then navigate a browser to localhost:7000 and poke around.  A good example is "show heap histogram".

jhat is one simple analysis tool - there are a bunch of others out there.  My converter only fills in data that jhat requires, though, other tools may need more info to work.

It's a java-centric format, so there is a lot of junk that doesn't translate well from Go.

The Go heap contains no type information for objects which have no pointers in them.  You'll just see "noptrX" types for different sizes X.  You could recompile Go and change src/pkg/runtime/malloc.goc:179 from this:

	if(UseSpanType && !(flag & FlagNoScan) && typ != 0) {

to this:

	if(UseSpanType && typ != 0) {

The Go heap also contains no field names for objects, so you'll just see fX for different offsets X in the object.

Below is a description of the internal format of the heap dump.

// encoding
//
// kind (Uvarint) ... type specific...

// strings are encoded with a Uvarint size followed by that many bytes of string (UTF8 encoded)

// kinds of record:
//   1: object
//   2: edge
//   3: eof
//   4: stackroot
//   5: dataroot
//   6: otherroot
//   7: type
//   8: stack frame
//   9: stack
//  10: dump params
//
// object:
//   1       uvarint
//   addr    uvarint
//   type    uvarint     0 if unknown
//   kind    uvarint     0 - regular T, 1 - array of T, 2 - channel of T (must be 0 if type is 0)
//   size    uvarint     total size (size of sizeclass, type.size may be a bit smaller)
//   data    size bytes

// eof:
//   3       uvarint

// stackroot:
//   4       uvarint
//   rootptr uvarint
//   frame   uvarint

// dataroot:
//   5       uvarint
//   rootptr uvarint

// otherroot:
//   6       uvarint
//   rootptr uvarint

// type:
//   7       uvarint
//   addr    uvarint     identifier for type (Type*)
//   size    uvarint
//   name    string
//   nptrs   uvarint     number of pointers in an object of this type.
//   ptroffset uvarint*  list of offsets of pointers.  Increasing order.
//  TODO: field names, ...

// thread:
//   8       uvarint
//   addr    uvarint
//   tos     uvarint

// stack frame:
//   9       uvarint
//   addr    uvarint     sp of frame
//   parent  uvarint     sp of parent's frame, or nil if bottom of stack
//   name    string      function name

// dump params:
//   10      uvarint
//   endian  uvarint     0=little endian, 1=big endian
//   ptrsize uvarint     32 or 64
