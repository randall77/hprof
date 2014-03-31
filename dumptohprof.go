package main

// https://java.net/downloads/heap-snapshot/hprof-binary-format.html
// http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b14/com/sun/tools/hat/internal/parser/HprofReader.java?av=f

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
)

// hprof constants
const (
	HPROF_UTF8         = 1
	HPROF_LOAD_CLASS   = 2
	HPROF_UNLOAD_CLASS = 3
	HPROF_FRAME        = 4
	HPROF_TRACE        = 5
	HPROF_START_THREAD = 10
	HPROF_HEAP_DUMP    = 12

	HPROF_GC_ROOT_JAVA_FRAME = 3
	HPROF_GC_ROOT_THREAD_OBJ = 8
	HPROF_GC_CLASS_DUMP      = 32
	HPROF_GC_INSTANCE_DUMP   = 33
	HPROF_GC_OBJ_ARRAY_DUMP  = 34
	HPROF_GC_PRIM_ARRAY_DUMP = 35
	HPROF_GC_ROOT_UNKNOWN    = 255

	T_CLASS   = 2
	T_BOOLEAN = 4
	T_FLOAT   = 6
	T_DOUBLE  = 7
	T_BYTE    = 8
	T_SHORT   = 9
	T_INT     = 10
	T_LONG    = 11
)

const (
	// Special class IDs that represent big noptr/ptr arrays.
	// Used when objects are too big to enumerate all their fields.
	bigNoPtrArray = 1
	bigPtrArray   = 2
)

// set of all the object pointers in the file
var usedIds map[uint64]struct{}

// allocate a new, unused Id
var idAlloc uint64 = 104

func newId() uint64 {
	for {
		idAlloc += 8
		if _, ok := usedIds[idAlloc]; !ok {
			return idAlloc
		}
	}
}

var serialAlloc uint32 = 100

func newSerial() uint32 {
	serialAlloc++
	return serialAlloc
}

// fake entries
var java_lang_class uint64
var java_lang_classloader uint64
var java_lang_object uint64
var java_lang_object_ser uint32
var java_lang_string uint64
var go_class uint64
var go_class_ser uint32

// big object types
var java_lang_objectarray uint64

// heap data
var d *Dump

// the full file
var hprof []byte

// the dump tag
var dump []byte

// cache of strings already generated
var stringCache map[string]uint64

// map from threads to thread serial numbers
var threadSerialNumbers map[*GoRoutine]uint32
var stackTraceSerialNumbers map[*GoRoutine]uint32

func main() {
	flag.Parse()
	args := flag.Args()
	d = Read(args[0], args[1])

	// some setup
	usedIds = make(map[uint64]struct{}, 0)
	for _, typ := range d.types {
		usedIds[typ.addr] = struct{}{}
	}
	for _, obj := range d.objects {
		usedIds[obj.addr] = struct{}{}
	}
	stringCache = make(map[string]uint64, 0)
	threadSerialNumbers = make(map[*GoRoutine]uint32, 0)
	stackTraceSerialNumbers = make(map[*GoRoutine]uint32, 0)

	// std header
	hprof = append(hprof, []byte("JAVA PROFILE 1.0.1\x00")...)
	hprof = append32(hprof, 8) // IDs are 8 bytes (TODO: d.ptrSize?)
	hprof = append32(hprof, 0) // dummy base time
	hprof = append32(hprof, 0) // dummy base time

	// fake entries to make java tools happy
	java_lang_class, _ = addLoadClass("java.lang.Class")
	java_lang_classloader, _ = addLoadClass("java.lang.ClassLoader")
	java_lang_object, java_lang_object_ser = addLoadClass("java.lang.Object")
	java_lang_string, _ = addLoadClass("java.lang.String")
	java_lang_objectarray, _ = addLoadClass("Object[]")
	go_class, go_class_ser = addLoadClass("go")
	addLoadClass("bool[]")
	addLoadClass("char[]")
	addLoadClass("float[]")
	addLoadClass("double[]")
	addLoadClass("byte[]")
	addLoadClass("short[]")
	addLoadClass("int[]")
	addLoadClass("long[]")

	addStackTrace() // stack trace must come after addLoadClass(java.lang.Object)
	addDummyThread()

	addThreads()

	// the full heap is one big tag
	addHeapDump()

	// write final file to output
	file, err := os.Create(args[2])
	if err != nil {
		log.Fatal(err)
	}
	file.Write(hprof)
	file.Close()
}

// temporary
var class_serial_number uint32 = 3
var thread_serial_number uint32 = 7
var stack_trace_serial_number uint32 = 11

// appends the tag with given tag and body to the hprof file
func addTag(tag byte, body []byte) {
	hprof = append(hprof, tag)
	hprof = append32(hprof, 0) // dummy delta time
	if uint64(uint32(len(body))) != uint64(len(body)) {
		log.Fatal("tag body too long")
	}
	hprof = append32(hprof, uint32(len(body)))
	hprof = append(hprof, body...)
}

// Adds a string entry and returns the Id for it.  Ids are cached.
func addString(s string) uint64 {
	id := stringCache[s]
	if id != 0 {
		return id
	}
	id = newId()
	var body []byte
	body = appendId(body, id)
	body = append(body, []byte(s)...)
	addTag(HPROF_UTF8, body)
	stringCache[s] = id
	return id
}

func addDummyThread() {
	var body []byte
	body = append32(body, thread_serial_number)
	body = appendId(body, 0) // thread object id(TODO: ptr to G object?)
	body = append32(body, stack_trace_serial_number)
	body = appendId(body, addString("the one thread"))
	body = appendId(body, addString("the one thread group"))
	body = appendId(body, addString("the one thread parent group"))
	addTag(HPROF_START_THREAD, body)
}

func addThreads() {
	for _, f := range d.frames {
		var body []byte
		body = appendId(body, f.addr)
		body = appendId(body, addString(f.name))
		body = appendId(body, addString(""))
		body = appendId(body, addString("dummysource.go"))
		body = append32(body, go_class_ser)
		body = append32(body, 0) // line # info
		addTag(HPROF_FRAME, body)
	}

	for _, t := range d.goroutines {
		n := 0
		for f := t.bos; f != nil; f = f.parent {
			n++
		}

		tid := newSerial() // thread serial number
		sid := newSerial() // stack trace serial number

		// stack trace
		var body []byte
		body = append32(body, sid)
		body = append32(body, tid)
		body = append32(body, uint32(n))
		for f := t.bos; f != nil; f = f.parent {
			body = appendId(body, f.addr)
		}
		addTag(HPROF_TRACE, body)

		// thread record
		body = nil
		body = append32(body, tid)
		body = appendId(body, t.addr)
		body = append32(body, sid)
		body = appendId(body, addString("threadname"))
		body = appendId(body, addString("threadgroup"))
		body = appendId(body, addString("threadparentgroup"))
		addTag(HPROF_START_THREAD, body)

		threadSerialNumbers[t] = tid
		stackTraceSerialNumbers[t] = sid
	}
}

// Emits a fake load class entry.  Returns the class id and serial number.
func addLoadClass(c string) (uint64, uint32) {
	var body []byte
	id := newId()
	sid := newSerial()
	body = append32(body, sid)
	body = appendId(body, id)
	body = append32(body, stack_trace_serial_number)
	body = appendId(body, addString(c))
	addTag(HPROF_LOAD_CLASS, body)
	return id, sid
}

func addStackFrame(name string, sig string, file string) uint64 {
	var body []byte
	id := newId()
	body = appendId(body, id)
	body = appendId(body, addString(name))
	body = appendId(body, addString(sig))
	body = appendId(body, addString(file))
	body = append32(body, go_class_ser)
	body = append32(body, 0) // line #
	addTag(HPROF_FRAME, body)
	return id
}

func addStackTrace() {
	var body []byte
	body = append32(body, stack_trace_serial_number)
	body = append32(body, thread_serial_number)
	body = append32(body, 1) // # of frames
	body = appendId(body, addStackFrame("unknown", "", "unknown.go"))
	addTag(HPROF_TRACE, body)
}

func fakeClassDump(id uint64, superid uint64) []byte {
	var body []byte
	body = append(body, HPROF_GC_CLASS_DUMP)
	body = appendId(body, id)
	body = append32(body, stack_trace_serial_number)
	body = appendId(body, superid)
	body = appendId(body, 0) // class loader
	body = appendId(body, 0) // signers
	body = appendId(body, 0) // protection
	body = appendId(body, 0) // reserved
	body = appendId(body, 0) // reserved
	body = append32(body, 0) // instance size
	body = append16(body, 0) // # constant pool entries
	body = append16(body, 0) // # static fields
	body = append16(body, 0) // # instance fields
	return body
}

type JavaField struct {
	kind byte
	name string
}

// allocates a class, issues a load command for it.
func addClass(id uint64, size uint64, name string, fields []JavaField) {
	// write load class command
	var body []byte
	sid := newSerial()
	body = append32(body, sid)
	body = appendId(body, id)
	body = append32(body, stack_trace_serial_number)
	body = appendId(body, addString(name))
	addTag(HPROF_LOAD_CLASS, body)

	// write a class dump subcommand
	dump = append(dump, HPROF_GC_CLASS_DUMP)
	dump = appendId(dump, id)
	dump = append32(dump, stack_trace_serial_number)
	dump = appendId(dump, 0) // superclass
	dump = appendId(dump, 0) // class loader
	dump = appendId(dump, 0) // signers
	dump = appendId(dump, 0) // protection domain
	dump = appendId(dump, 0) // reserved
	dump = appendId(dump, 0) // reserved
	if uint64(uint32(size)) != size {
		log.Fatal("object size too big")
	}
	dump = append32(dump, uint32(size))
	dump = append16(dump, 0) // constant pool size
	dump = append16(dump, 0) // # of static fields
	dump = append16(dump, uint16(len(fields)))
	for _, field := range fields {
		dump = appendId(dump, addString(field.name))
		dump = append(dump, field.kind)
	}
}

// each global is represented as a java Class with a few static fields.
// TODO: have a class per package with all globals from that package in it?
func addGlobal(name string, kind fieldKind, data []byte) {
	var names []string
	var types []byte
	var values [][]byte
	uintptr := byte(T_LONG)
	if d.ptrSize == 4 {
		uintptr = T_INT
	}
	switch kind {
	default:
		// scalars - worth outputting anything?
		return
	case fieldKindPtr:
		names = append(names, "ptr")
		types = append(types, T_CLASS)
		values = append(values, data[:d.ptrSize])
	case fieldKindString:
		names = append(names, "str")
		types = append(types, T_CLASS)
		values = append(values, data[:d.ptrSize])
		names = append(names, "len")
		types = append(types, uintptr)
		values = append(values, data[d.ptrSize:2*d.ptrSize])
	case fieldKindSlice:
		names = append(names, "array")
		types = append(types, T_CLASS)
		values = append(values, data[:d.ptrSize])
		names = append(names, "len")
		types = append(types, uintptr)
		values = append(values, data[d.ptrSize:2*d.ptrSize])
		names = append(names, "cap")
		types = append(types, uintptr)
		values = append(values, data[2*d.ptrSize:3*d.ptrSize])
	case fieldKindIface:
		names = append(names, "itab")
		types = append(types, T_CLASS)
		values = append(values, data[:d.ptrSize])
		names = append(names, "data")
		types = append(types, T_CLASS)
		values = append(values, data[d.ptrSize:2*d.ptrSize])
	case fieldKindEface:
		names = append(names, "type")
		types = append(types, T_CLASS)
		values = append(values, data[:d.ptrSize])
		names = append(names, "data")
		types = append(types, T_CLASS)
		values = append(values, data[d.ptrSize:2*d.ptrSize])
	}

	// fix endianness of values
	for _, v := range values {
		switch len(v) {
		case 2:
			bigEndian2(v)
		case 4:
			bigEndian4(v)
		case 8:
			bigEndian8(v)
		}
	}

	c := newId()

	// write load class command
	var body []byte
	sid := newSerial()
	body = append32(body, sid)
	body = appendId(body, c)
	body = append32(body, stack_trace_serial_number)
	body = appendId(body, addString(name))
	addTag(HPROF_LOAD_CLASS, body)
	
	// write a class dump subcommand
	dump = append(dump, HPROF_GC_CLASS_DUMP)
	dump = appendId(dump, c)
	dump = append32(dump, stack_trace_serial_number)
	dump = appendId(dump, 0)                  // superclass
	dump = appendId(dump, 0)                  // class loader
	dump = appendId(dump, 0)                  // signers
	dump = appendId(dump, 0)                  // protection domain
	dump = appendId(dump, 0)                  // reserved
	dump = appendId(dump, 0)                  // reserved
	dump = append32(dump, 0)                  // object size
	dump = append16(dump, 0)                  // constant pool size
	dump = append16(dump, uint16(len(names))) // # of static fields
	for i := range names {
		// string id, type, data for that type
		dump = appendId(dump, addString(names[i]))
		dump = append(dump, types[i])
		dump = append(dump, values[i]...)
	}
	dump = append16(dump, 0) // # of instance fields

	// TODO: need to HPROF_GC_ROOT_STICKY_CLASS this class?	
}

// map from the size to the noptr object to the id of the fake class that represents them
var noPtrClass map[uint64]uint64 = make(map[uint64]uint64, 0)

func NoPtrClass(size uint64) uint64 {
	c := noPtrClass[size]
	if c == 0 {
		c = newId()
		p := prefix(size)
		var jf []JavaField
		for i := uint64(0); i < size; i += 8 {
			jf = append(jf, JavaField{T_LONG, fmt.Sprintf(p, i)})
		}
		addClass(c, size, fmt.Sprintf("noptr%d", size), jf)
		noPtrClass[size] = c
	}
	return c
}

// This is a prefix to put in front of all field names to
// make them sort correctly.  we use the byte offset in hex with
// just enough digits to fit.
func prefix(size uint64) string {
	d := 0
	for size > 0 {
		d++
		size /= 16
	}
	return fmt.Sprintf("0x%%0%dx | ", d)
}

func appendPad(jf []JavaField, prefix string, base uint64, n uint64) []JavaField {
	if n&1 != 0 {
		jf = append(jf, JavaField{8, fmt.Sprintf(prefix+"<pad>", base)})
		base += 1
		n -= 1
	}
	if n&2 != 0 {
		jf = append(jf, JavaField{9, fmt.Sprintf(prefix+"<pad>", base)})
		base += 2
		n -= 2
	}
	if n&4 != 0 {
		jf = append(jf, JavaField{10, fmt.Sprintf(prefix+"<pad>", base)})
		base += 4
		n -= 4
	}
	for n != 0 {
		jf = append(jf, JavaField{11, fmt.Sprintf(prefix+"<pad>", base)})
		base += 8
		n -= 8
	}
	return jf
}

func appendJavaFields(jf []JavaField, t *Type, prefix string, base uint64, idx int64) []JavaField {
	off := uint64(0)
	uintptr := byte(T_LONG)
	if d.ptrSize == 4 {
		uintptr = T_INT
	}
	for _, f := range t.fields {
		// hprof format needs fields for the holes
		if f.offset < off {
			log.Fatal("out of order fields")
		}
		if f.offset > off {
			jf = appendPad(jf, prefix, base+off, f.offset-off)
			off = f.offset
		}

		name := f.name
		if idx >= 0 {
			if name != "" {
				name = fmt.Sprintf("%d.%s", idx, name)
			} else {
				name = fmt.Sprintf("%d", idx)
			}
		}
		switch f.kind {
		case fieldKindBool:
			jf = append(jf, JavaField{T_BOOLEAN, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off++
		case fieldKindUInt8:
			jf = append(jf, JavaField{T_BYTE, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off++
		case fieldKindSInt8:
			jf = append(jf, JavaField{T_BYTE, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off++
		case fieldKindUInt16:
			jf = append(jf, JavaField{T_SHORT, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off += 2
		case fieldKindSInt16:
			jf = append(jf, JavaField{T_SHORT, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off += 2
		case fieldKindUInt32:
			jf = append(jf, JavaField{T_INT, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off += 4
		case fieldKindSInt32:
			jf = append(jf, JavaField{T_INT, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off += 4
		case fieldKindUInt64:
			jf = append(jf, JavaField{T_LONG, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off += 8
		case fieldKindSInt64:
			jf = append(jf, JavaField{T_LONG, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off += 8
		case fieldKindFloat32:
			jf = append(jf, JavaField{T_FLOAT, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off += 4
		case fieldKindFloat64:
			jf = append(jf, JavaField{T_DOUBLE, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off += 8
		case fieldKindComplex64:
			jf = append(jf, JavaField{T_FLOAT, fmt.Sprintf(prefix+"%s.real", base+f.offset, name)})
			jf = append(jf, JavaField{T_FLOAT, fmt.Sprintf(prefix+"%s.imag", base+f.offset+4, name)})
			off += 8
		case fieldKindComplex128:
			jf = append(jf, JavaField{T_DOUBLE, fmt.Sprintf(prefix+"%s.real", base+f.offset, name)})
			jf = append(jf, JavaField{T_DOUBLE, fmt.Sprintf(prefix+"%s.imag", base+f.offset+8, name)})
			off += 16
		case fieldKindPtr:
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s", base+f.offset, name)})
			off += d.ptrSize
		case fieldKindString:
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.str", base+f.offset, name)})
			jf = append(jf, JavaField{uintptr, fmt.Sprintf(prefix+"%s.len", base+f.offset+d.ptrSize, name)})
			off += 2 * d.ptrSize
		case fieldKindSlice:
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.array", base+f.offset, name)})
			jf = append(jf, JavaField{uintptr, fmt.Sprintf(prefix+"%s.len", base+f.offset+d.ptrSize, name)})
			jf = append(jf, JavaField{uintptr, fmt.Sprintf(prefix+"%s.cap", base+f.offset+2*d.ptrSize, name)})
			off += 3 * d.ptrSize
		// Data fields of interfaces might be pointers, might not be.  hprof has
		// no good way to represent this.  We always choose pointer.
		case fieldKindIface:
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.itab", base+f.offset, name)})
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.data", base+f.offset+d.ptrSize, name)})
			off += 2 * d.ptrSize
		case fieldKindEface:
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.type", base+f.offset, name)})
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.data", base+f.offset+d.ptrSize, name)})
			off += 2 * d.ptrSize
		default:
			log.Fatalf("unknown field kind %d\n", f.kind)
		}
	}
	if off > t.size {
		log.Fatalf("too much field data")
	}
	if off < t.size {
		jf = appendPad(jf, prefix, base+off, t.size-off)
	}
	return jf
}

// maps from type addr to the fake class object we use to represent that type
var stdClass map[uint64]uint64 = make(map[uint64]uint64, 0)

func StdClass(t *Type, size uint64) uint64 {
	p := prefix(size)
	c := stdClass[t.addr]
	if c == 0 {
		var jf []JavaField
		jf = appendJavaFields(jf, t, p, 0, -1)
		jf = appendPad(jf, p, t.size, size-t.size) // pad to sizeclass
		if len(jf) < 0x10000 {
			c = newId()
			addClass(c, size, t.name, jf)
			stdClass[t.addr] = c
		} else {
			c = bigNoPtrArray
			for _, f := range jf {
				if f.kind == T_CLASS {
					c = bigPtrArray
				}
			}
			stdClass[t.addr] = c
		}
	}
	return c
}

// maps from type addr to the fake class object we use to represent that type
type ArrayKey struct {
	typaddr uint64
	size    uint64
}

var arrayClass map[ArrayKey]uint64 = make(map[ArrayKey]uint64, 0)

func ArrayClass(t *Type, size uint64) uint64 {
	p := prefix(size)
	k := ArrayKey{t.addr, size}
	c := arrayClass[k]
	if c == 0 {
		c = newId()
		nelem := size / t.size
		var jf []JavaField
		for i := uint64(0); i < nelem; i++ {
			jf = appendJavaFields(jf, t, p, i*t.size, int64(i))
		}
		jf = appendPad(jf, p, nelem*t.size, size-nelem*t.size) // pad to sizeclass
		addClass(c, size, fmt.Sprintf("array{%d}%s", nelem, t.name), jf)
		arrayClass[k] = c
	}
	return c
}

// maps from type addr to the fake class object we use to represent that type
type ChanKey struct {
	typaddr uint64
	size    uint64
}

var chanClass map[ChanKey]uint64 = make(map[ChanKey]uint64, 0)

func ChanClass(t *Type, size uint64) uint64 {
	uintptr := byte(11)
	if d.ptrSize == 4 {
		uintptr = 10
	}
	p := prefix(size)
	k := ChanKey{t.addr, size}
	c := chanClass[k]
	if c == 0 {
		c = newId()
		nelem := (size - d.hChanSize) / t.size
		var jf []JavaField
		for i := uint64(0); i < d.hChanSize; i += d.ptrSize {
			jf = append(jf, JavaField{uintptr, "chanhdr"})
		}
		for i := uint64(0); i < nelem; i++ {
			jf = appendJavaFields(jf, t, p, d.hChanSize+i*t.size, int64(i))
		}
		jf = appendPad(jf, p, nelem*t.size, size-nelem*t.size) // pad to sizeclass
		addClass(c, size, fmt.Sprintf("chan{%d}%s", nelem, t.name), jf)
		chanClass[k] = c
	}
	return c
}

func addHeapDump() {
	// a few fake class dumps to keep java tools happy
	dump = append(dump, fakeClassDump(java_lang_object, 0)...)
	dump = append(dump, fakeClassDump(java_lang_class, java_lang_object)...)
	dump = append(dump, fakeClassDump(java_lang_classloader, java_lang_object)...)
	dump = append(dump, fakeClassDump(java_lang_string, java_lang_object)...)

	// output each object as an instance
	for _, x := range d.objects {
		if len(x.data) >= 8<<32 {
			// file format can't record objects this big.  TODO: error/warning?
			continue
		}

		// figure out what class to use for this object
		var c uint64
		if x.typ == nil {
			c = NoPtrClass(uint64(len(x.data)))
		} else {
			switch x.kind {
			case typeKindObject:
				c = StdClass(x.typ, uint64(len(x.data)))
			case typeKindArray:
				c = ArrayClass(x.typ, uint64(len(x.data)))
			case typeKindChan:
				c = ChanClass(x.typ, uint64(len(x.data)))
			default:
				log.Fatal("unhandled kind")
			}
		}

		// make copy of object data so we can modify it
		data := make([]byte, len(x.data))
		copy(data, x.data)

		// Any pointers to objects get adjusted to point to the object head.
		for _, e := range x.edges {
			writePtr(data[e.fromoffset:], e.to.addr)
		}

		// convert to big-endian representation
		if x.typ == nil {
			// don't know fields, just do words
			for i := 0; i < len(data); i += 8 {
				bigEndian8(data[i:])
			}
		} else {
			var size uint64
			var n uint64
			switch x.kind {
			case typeKindObject:
				n = 1
			case typeKindArray:
				size = x.typ.size
				n = uint64(len(x.data)) / size
			case typeKindChan:
				size = x.typ.size
				n = (uint64(len(x.data)) - d.hChanSize) / size
				// TODO: need offset?
			}
			for i := uint64(0); i < n; i++ {
				for _, f := range x.typ.fields {
					switch f.kind {
					case fieldKindBool:
					case fieldKindUInt8:
					case fieldKindSInt8:
					case fieldKindSInt16:
						bigEndian2(data[i*size+f.offset:])
					case fieldKindUInt16:
						bigEndian2(data[i*size+f.offset:])
					case fieldKindSInt32:
						bigEndian4(data[i*size+f.offset:])
					case fieldKindUInt32:
						bigEndian4(data[i*size+f.offset:])
					case fieldKindSInt64:
						bigEndian8(data[i*size+f.offset:])
					case fieldKindUInt64:
						bigEndian8(data[i*size+f.offset:])
					case fieldKindFloat32:
						bigEndian4(data[i*size+f.offset:])
					case fieldKindFloat64:
						bigEndian8(data[i*size+f.offset:])
					case fieldKindComplex64:
						bigEndian4(data[i*size+f.offset:])
						bigEndian4(data[i*size+f.offset+4:])
					case fieldKindComplex128:
						bigEndian8(data[i*size+f.offset:])
						bigEndian8(data[i*size+f.offset+8:])
					case fieldKindPtr:
						bigEndian8(data[i*size+f.offset:])
					case fieldKindString:
						bigEndian8(data[i*size+f.offset:])
						bigEndian8(data[i*size+f.offset+8:])
					case fieldKindSlice:
						bigEndian8(data[i*size+f.offset:])
						bigEndian8(data[i*size+f.offset+8:])
						bigEndian8(data[i*size+f.offset+16:])
					case fieldKindIface:
						bigEndian8(data[i*size+f.offset:])
						bigEndian8(data[i*size+f.offset+8:])
					case fieldKindEface:
						bigEndian8(data[i*size+f.offset:])
						bigEndian8(data[i*size+f.offset+8:])
					default:
						log.Fatal("uknown field type")
					}
				}
			}
		}

		// dump object header
		if c == bigNoPtrArray {
			dump = append(dump, HPROF_GC_PRIM_ARRAY_DUMP)
			dump = appendId(dump, x.addr)
			dump = append32(dump, stack_trace_serial_number)
			dump = append32(dump, uint32(len(x.data)/8))
			dump = append(dump, T_LONG)
		} else if c == bigPtrArray {
			dump = append(dump, HPROF_GC_OBJ_ARRAY_DUMP)
			dump = appendId(dump, x.addr)
			dump = append32(dump, stack_trace_serial_number)
			dump = append32(dump, uint32(len(x.data)/8))
			dump = appendId(dump, java_lang_objectarray)
		} else {
			dump = append(dump, HPROF_GC_INSTANCE_DUMP)
			dump = appendId(dump, x.addr)
			dump = append32(dump, stack_trace_serial_number)
			dump = appendId(dump, c)
			dump = append32(dump, uint32(len(x.data)))
		}
		// dump object data
		dump = append(dump, data...)
	}

	// output threads
	for _, t := range d.goroutines {
		dump = append(dump, HPROF_GC_ROOT_THREAD_OBJ)
		dump = appendId(dump, t.addr)
		dump = append32(dump, threadSerialNumbers[t])
		dump = append32(dump, stackTraceSerialNumbers[t])
	}

	// stack roots
	for _, t := range d.goroutines {
		for f := t.bos; f != nil; f = f.parent {
			for _, e := range f.edges {
				dump = append(dump, HPROF_GC_ROOT_JAVA_FRAME)
				dump = appendId(dump, e.to.addr)
				dump = append32(dump, threadSerialNumbers[t])
				dump = append32(dump, uint32(f.depth))
			}
		}
	}
	// data roots
	for _, x := range []*Data{d.data, d.bss} {
		// adjust edges to point to object beginnings
		for _, e := range x.edges {
			writePtr(x.data[e.fromoffset:], e.to.addr)
		}
		for _, f := range x.fields {
			//fmt.Printf("global %s %v\n", f.name, x.data[f.offset:f.offset+16])
			addGlobal(f.name, f.kind, x.data[f.offset:])
		}
	}
	for _, t := range d.otherroots {
		if t.e.to == nil {
			continue
		}
		dump = append(dump, HPROF_GC_ROOT_UNKNOWN)
		dump = appendId(dump, t.e.to.addr)
	}

	addTag(HPROF_HEAP_DUMP, dump)
}

// NOTE: hprof is a big-endian format
func append16(b []byte, x uint16) []byte {
	return append(b, byte(x>>8), byte(x>>0))
}
func append32(b []byte, x uint32) []byte {
	return append(b, byte(x>>24), byte(x>>16), byte(x>>8), byte(x>>0))
}
func append64(b []byte, x uint64) []byte {
	return append(b, byte(x>>56), byte(x>>48), byte(x>>40), byte(x>>32), byte(x>>24), byte(x>>16), byte(x>>8), byte(x>>0))
}
func appendId(b []byte, x uint64) []byte {
	return append64(b, x)
}

func bigEndian2(x []byte) {
	if d.order == binary.BigEndian {
		return
	}
	x[0], x[1] = x[1], x[0]
}
func bigEndian4(x []byte) {
	if d.order == binary.BigEndian {
		return
	}
	x[0], x[1], x[2], x[3] = x[3], x[2], x[1], x[0]
}
func bigEndian8(x []byte) {
	if d.order == binary.BigEndian {
		return
	}
	x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7] = x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]
}

// TODO: works as long as all data is 8 bytes, but for <= 4 byte things this will
// misattribute the data.
func endianSwap(b []byte) {
	for ; len(b) >= 8; b = b[8:] {
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7] = b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]
	}
}

func writePtr(b []byte, v uint64) {
	switch {
	case d.order == binary.LittleEndian && d.ptrSize == 4:
		b[0] = byte(v >> 0)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
	case d.order == binary.BigEndian && d.ptrSize == 4:
		b[3] = byte(v >> 0)
		b[2] = byte(v >> 8)
		b[1] = byte(v >> 16)
		b[0] = byte(v >> 24)
	case d.order == binary.LittleEndian && d.ptrSize == 8:
		b[0] = byte(v >> 0)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
		b[4] = byte(v >> 32)
		b[5] = byte(v >> 40)
		b[6] = byte(v >> 48)
		b[7] = byte(v >> 56)
	case d.order == binary.BigEndian && d.ptrSize == 8:
		b[7] = byte(v >> 0)
		b[6] = byte(v >> 8)
		b[5] = byte(v >> 16)
		b[4] = byte(v >> 24)
		b[3] = byte(v >> 32)
		b[2] = byte(v >> 40)
		b[1] = byte(v >> 48)
		b[0] = byte(v >> 56)
	default:
		log.Fatal("unsupported order=%v ptrSize=%d", d.order, d.ptrSize)
	}
}
