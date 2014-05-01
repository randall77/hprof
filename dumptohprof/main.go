package main

// https://java.net/downloads/heap-snapshot/hprof-binary-format.html
// http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b14/com/sun/tools/hat/internal/parser/HprofReader.java?av=f

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/randall77/hprof/read"
	"log"
	"os"
)

// hprof constants
const (
	HPROF_UTF8         = 1
	HPROF_LOAD_CLASS   = 2
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
	// These are for internal use only - they never make it to the hprof file.
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
var d *read.Dump

// the full file
var hprof []byte

// the dump tag
var dump []byte

// cache of strings already generated
var stringCache map[string]uint64

// map from threads to thread serial numbers
var threadSerialNumbers map[*read.GoRoutine]uint32
var stackTraceSerialNumbers map[*read.GoRoutine]uint32

func main() {
	flag.Parse()
	args := flag.Args()
	var outfile string
	if len(args) == 2 {
		d = read.Read(args[0], "")
		outfile = args[1]
	} else {
		d = read.Read(args[0], args[1])
		outfile = args[2]
	}

	// some setup
	usedIds = make(map[uint64]struct{}, 0)
	for _, typ := range d.Types {
		usedIds[typ.Addr] = struct{}{}
	}
	for i := 0; i < d.NumObjects(); i++ {
		usedIds[d.Addr(read.ObjId(i))] = struct{}{}
	}
	stringCache = make(map[string]uint64, 0)
	threadSerialNumbers = make(map[*read.GoRoutine]uint32, 0)
	stackTraceSerialNumbers = make(map[*read.GoRoutine]uint32, 0)

	// std header
	hprof = append(hprof, []byte("JAVA PROFILE 1.0.1\x00")...)
	hprof = append32(hprof, 8) // IDs are 8 bytes (TODO: d.PtrSize?)
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

	addDummyThread() // must come after addLoadClass(java.lang.Object)

	addThreads()

	// the full heap is one big tag
	addHeapDump()

	// write final file to output
	file, err := os.Create(outfile)
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

	body = nil
	frameId := newId()
	body = appendId(body, frameId)
	body = appendId(body, addString("unknown"))
	body = appendId(body, addString(""))
	body = appendId(body, addString("unknown.go"))
	body = append32(body, go_class_ser)
	body = append32(body, 0) // line #
	addTag(HPROF_FRAME, body)

	body = nil
	body = append32(body, stack_trace_serial_number)
	body = append32(body, thread_serial_number)
	body = append32(body, 1) // # of frames
	body = appendId(body, frameId)
	addTag(HPROF_TRACE, body)
}

func addThreads() {
	for _, t := range d.Goroutines {
		tid := newSerial() // thread serial number
		sid := newSerial() // stack trace serial number

		// thread record
		var body []byte
		body = append32(body, tid)
		body = appendId(body, t.Addr)
		body = append32(body, sid)
		body = appendId(body, addString("threadname"))
		body = appendId(body, addString("threadgroup"))
		body = appendId(body, addString("threadparentgroup"))
		addTag(HPROF_START_THREAD, body)

		// frames
		n := 0
		for f := t.Bos; f != nil; f = f.Parent {
			body = nil
			body = appendId(body, f.Addr)
			body = appendId(body, addString(f.Name))
			body = appendId(body, addString(""))
			body = appendId(body, addString("dummysource.go"))
			body = append32(body, go_class_ser)
			body = append32(body, 0) // line # info
			addTag(HPROF_FRAME, body)
			n++
		}

		// stack trace
		body = nil
		body = append32(body, sid)
		body = append32(body, tid)
		body = append32(body, uint32(n))
		for f := t.Bos; f != nil; f = f.Parent {
			body = appendId(body, f.Addr)
		}
		addTag(HPROF_TRACE, body)

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
func addGlobal(name string, kind read.FieldKind, data []byte) {
	var names []string
	var types []byte
	var values [][]byte
	uintptr := byte(T_LONG)
	if d.PtrSize == 4 {
		uintptr = T_INT
	}
	switch kind {
	default:
		// scalars - worth outputting anything?
		return
	case read.FieldKindPtr:
		names = append(names, "ptr")
		types = append(types, T_CLASS)
		values = append(values, data[:d.PtrSize])
	case read.FieldKindString:
		names = append(names, "str")
		types = append(types, T_CLASS)
		values = append(values, data[:d.PtrSize])
		names = append(names, "len")
		types = append(types, uintptr)
		values = append(values, data[d.PtrSize:2*d.PtrSize])
	case read.FieldKindSlice:
		names = append(names, "array")
		types = append(types, T_CLASS)
		values = append(values, data[:d.PtrSize])
		names = append(names, "len")
		types = append(types, uintptr)
		values = append(values, data[d.PtrSize:2*d.PtrSize])
		names = append(names, "cap")
		types = append(types, uintptr)
		values = append(values, data[2*d.PtrSize:3*d.PtrSize])
	case read.FieldKindIface:
		names = append(names, "itab")
		types = append(types, T_CLASS)
		values = append(values, data[:d.PtrSize])
		names = append(names, "data")
		types = append(types, T_CLASS)
		values = append(values, data[d.PtrSize:2*d.PtrSize])
	case read.FieldKindEface:
		names = append(names, "type")
		types = append(types, T_CLASS)
		values = append(values, data[:d.PtrSize])
		names = append(names, "data")
		types = append(types, T_CLASS)
		values = append(values, data[d.PtrSize:2*d.PtrSize])
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

func appendJavaFields(jf []JavaField, t *read.Type, prefix string, base uint64, idx int64) []JavaField {
	off := uint64(0)
	uintptr := byte(T_LONG)
	if d.PtrSize == 4 {
		uintptr = T_INT
	}
	for _, f := range t.Fields {
		// hprof format needs fields for the holes
		if f.Offset < off {
			log.Fatal("out of order fields")
		}
		if f.Offset > off {
			jf = appendPad(jf, prefix, base+off, f.Offset-off)
			off = f.Offset
		}

		name := f.Name
		if idx >= 0 {
			if name != "" {
				name = fmt.Sprintf("%d.%s", idx, name)
			} else {
				name = fmt.Sprintf("%d", idx)
			}
		}
		switch f.Kind {
		case read.FieldKindBool:
			jf = append(jf, JavaField{T_BOOLEAN, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off++
		case read.FieldKindUInt8:
			jf = append(jf, JavaField{T_BYTE, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off++
		case read.FieldKindSInt8:
			jf = append(jf, JavaField{T_BYTE, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off++
		case read.FieldKindUInt16:
			jf = append(jf, JavaField{T_SHORT, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off += 2
		case read.FieldKindSInt16:
			jf = append(jf, JavaField{T_SHORT, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off += 2
		case read.FieldKindUInt32:
			jf = append(jf, JavaField{T_INT, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off += 4
		case read.FieldKindSInt32:
			jf = append(jf, JavaField{T_INT, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off += 4
		case read.FieldKindUInt64:
			jf = append(jf, JavaField{T_LONG, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off += 8
		case read.FieldKindSInt64:
			jf = append(jf, JavaField{T_LONG, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off += 8
		case read.FieldKindFloat32:
			jf = append(jf, JavaField{T_FLOAT, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off += 4
		case read.FieldKindFloat64:
			jf = append(jf, JavaField{T_DOUBLE, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off += 8
		case read.FieldKindComplex64:
			jf = append(jf, JavaField{T_FLOAT, fmt.Sprintf(prefix+"%s.real", base+f.Offset, name)})
			jf = append(jf, JavaField{T_FLOAT, fmt.Sprintf(prefix+"%s.imag", base+f.Offset+4, name)})
			off += 8
		case read.FieldKindComplex128:
			jf = append(jf, JavaField{T_DOUBLE, fmt.Sprintf(prefix+"%s.real", base+f.Offset, name)})
			jf = append(jf, JavaField{T_DOUBLE, fmt.Sprintf(prefix+"%s.imag", base+f.Offset+8, name)})
			off += 16
		case read.FieldKindPtr:
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s", base+f.Offset, name)})
			off += d.PtrSize
		case read.FieldKindString:
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.str", base+f.Offset, name)})
			jf = append(jf, JavaField{uintptr, fmt.Sprintf(prefix+"%s.len", base+f.Offset+d.PtrSize, name)})
			off += 2 * d.PtrSize
		case read.FieldKindSlice:
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.array", base+f.Offset, name)})
			jf = append(jf, JavaField{uintptr, fmt.Sprintf(prefix+"%s.len", base+f.Offset+d.PtrSize, name)})
			jf = append(jf, JavaField{uintptr, fmt.Sprintf(prefix+"%s.cap", base+f.Offset+2*d.PtrSize, name)})
			off += 3 * d.PtrSize
		// Data fields of interfaces might be pointers, might not be.  hprof has
		// no good way to represent this.  We always choose pointer.
		case read.FieldKindIface:
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.itab", base+f.Offset, name)})
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.data", base+f.Offset+d.PtrSize, name)})
			off += 2 * d.PtrSize
		case read.FieldKindEface:
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.type", base+f.Offset, name)})
			jf = append(jf, JavaField{T_CLASS, fmt.Sprintf(prefix+"%s.data", base+f.Offset+d.PtrSize, name)})
			off += 2 * d.PtrSize
		default:
			log.Fatalf("unknown field kind %d\n", f.Kind)
		}
	}
	if off > t.Size {
		log.Fatalf("too much field data")
	}
	if off < t.Size {
		jf = appendPad(jf, prefix, base+off, t.Size-off)
	}
	return jf
}

// javaFields maps from class id to the list of java fields for that class
// if the object is too big to have explicit fields, it will not appear here.
var javaFields map[uint64][]JavaField = make(map[uint64][]JavaField, 0)

// stdClass maps from type addr to the Java class object we use to represent that type
var stdClass map[uint64]uint64 = make(map[uint64]uint64, 0)

func StdClass(t *read.Type, size uint64) uint64 {
	p := prefix(size)
	c := stdClass[t.Addr]
	if c == 0 {
		var jf []JavaField
		jf = appendJavaFields(jf, t, p, 0, -1)
		jf = appendPad(jf, p, t.Size, size-t.Size) // pad to sizeclass
		if len(jf) < 0x10000 {
			c = newId()
			addClass(c, size, t.Name, jf)
			javaFields[c] = jf
		} else {
			c = bigNoPtrArray
			for _, f := range jf {
				if f.kind == T_CLASS {
					c = bigPtrArray
				}
			}
		}
		stdClass[t.Addr] = c
	}
	return c
}

// noPtrClass maps from the size to the noptr object to the id of the fake class that represents them
var noPtrClass map[uint64]uint64 = make(map[uint64]uint64, 0)

func NoPtrClass(size uint64) uint64 {
	c := noPtrClass[size]
	if c == 0 {
		p := prefix(size)
		var jf []JavaField
		for i := uint64(0); i < size; i += 8 {
			jf = append(jf, JavaField{T_LONG, fmt.Sprintf(p, i)})
		}
		if len(jf) < 0x10000 {
			c = newId()
			addClass(c, size, fmt.Sprintf("noptr%d", size), jf)
			javaFields[c] = jf
		} else {
			c = bigNoPtrArray
		}
		noPtrClass[size] = c
	}
	return c
}

// arrayClass maps from type addr + size to the fake class object we use to represent that type/size
type ArrayKey struct {
	typaddr uint64
	size    uint64
}

var arrayClass map[ArrayKey]uint64 = make(map[ArrayKey]uint64, 0)

func ArrayClass(t *read.Type, size uint64) uint64 {
	k := ArrayKey{t.Addr, size}
	c := arrayClass[k]
	if c == 0 {
		p := prefix(size)
		nelem := size / t.Size
		var jf []JavaField
		for i := uint64(0); i < nelem; i++ {
			jf = appendJavaFields(jf, t, p, i*t.Size, int64(i))
		}
		jf = appendPad(jf, p, nelem*t.Size, size-nelem*t.Size) // pad to sizeclass
		if len(jf) < 0x10000 {
			c = newId()
			addClass(c, size, fmt.Sprintf("array{%d}%s", nelem, t.Name), jf)
			javaFields[c] = jf
		} else {
			c = bigNoPtrArray
			for _, f := range jf {
				if f.kind == T_CLASS {
					c = bigPtrArray
				}
			}
		}
		arrayClass[k] = c
	}
	return c
}

// chanClass maps from type addr + size to the fake class object we use to represent that type/size
type ChanKey struct {
	typaddr uint64
	size    uint64
}

var chanClass map[ChanKey]uint64 = make(map[ChanKey]uint64, 0)

func ChanClass(t *read.Type, size uint64) uint64 {
	k := ChanKey{t.Addr, size}
	c := chanClass[k]
	if c == 0 {
		uintptr := byte(T_LONG)
		if d.PtrSize == 4 {
			uintptr = T_INT
		}
		p := prefix(size)
		var jf []JavaField
		for i := uint64(0); i < d.HChanSize; i += d.PtrSize {
			// TODO: name these fields appropriately (len, cap, sendidx, recvidx,...)
			jf = append(jf, JavaField{uintptr, fmt.Sprintf(p+"chanhdr", i)})
		}
		total := d.HChanSize
		var name string
		if t.Size == 0 {
			name = fmt.Sprintf("chan{?}%s", t.Name)
		} else {
			nelem := (size - d.HChanSize) / t.Size
			name = fmt.Sprintf("chan{%d}%s", nelem, t.Name)
			for i := uint64(0); i < nelem; i++ {
				jf = appendJavaFields(jf, t, p, d.HChanSize+i*t.Size, int64(i))
			}
			total += nelem * t.Size
		}
		jf = appendPad(jf, p, total, size-total) // pad to sizeclass
		if len(jf) < 0x10000 {
			c = newId()
			addClass(c, size, name, jf)
			javaFields[c] = jf
		} else {
			c = bigNoPtrArray
			for _, f := range jf {
				if f.kind == T_CLASS {
					c = bigPtrArray
				}
			}
		}
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

	// scratch space for modifying object data
	var data []byte

	// output each object as an instance
	for i := 0; i < d.NumObjects(); i++ {
		x := read.ObjId(i)
		if d.Size(x) >= 8<<32 {
			// file format can't record objects this big.  TODO: error/warning?  Truncate?
			continue
		}

		// figure out what class to use for this object
		var c uint64
		if d.Ft(x).Typ == nil {
			c = NoPtrClass(d.Size(x))
		} else {
			switch d.Ft(x).Kind {
			case read.TypeKindObject:
				c = StdClass(d.Ft(x).Typ, d.Size(x))
			case read.TypeKindArray:
				c = ArrayClass(d.Ft(x).Typ, d.Size(x))
			case read.TypeKindChan:
				c = ChanClass(d.Ft(x).Typ, d.Size(x))
			// TODO: TypeKindConservative
			default:
				log.Fatal("unhandled kind")
			}
		}

		// make a copy of the object data so we can modify it
		data = append(data[:0], d.Contents(x)...)

		// Any pointers to objects get adjusted to point to the object head.
		for _, e := range d.Edges(x) {
			writePtr(data[e.FromOffset:], d.Addr(e.To))
		}

		// convert to big-endian representation
		if c == bigNoPtrArray {
			for i := uint64(0); i < uint64(len(data)); i += 8 {
				bigEndian8(data[i:])
			}
		} else if c == bigPtrArray {
			for i := uint64(0); i < uint64(len(data)); i += d.PtrSize {
				bigEndianP(data[i:])
			}
		} else {
			off := uint64(0)
			for _, f := range javaFields[c] {
				switch f.kind {
				case T_CLASS:
					bigEndianP(data[off:])
					off += d.PtrSize
				case T_BOOLEAN:
					off++
				case T_FLOAT:
					bigEndian4(data[off:])
					off += 4
				case T_DOUBLE:
					bigEndian8(data[off:])
					off += 8
				case T_BYTE:
					off++
				case T_SHORT:
					bigEndian2(data[off:])
					off += 2
				case T_INT:
					bigEndian4(data[off:])
					off += 4
				case T_LONG:
					bigEndian8(data[off:])
					off += 8
				default:
					log.Fatalf("bad type %d\n", f.kind)
				}
			}
		}

		// dump object header
		if c == bigNoPtrArray {
			dump = append(dump, HPROF_GC_PRIM_ARRAY_DUMP)
			dump = appendId(dump, d.Addr(x))
			dump = append32(dump, stack_trace_serial_number)
			dump = append32(dump, uint32(d.Size(x)/8))
			dump = append(dump, T_LONG)
		} else if c == bigPtrArray {
			dump = append(dump, HPROF_GC_OBJ_ARRAY_DUMP)
			dump = appendId(dump, d.Addr(x))
			dump = append32(dump, stack_trace_serial_number)
			dump = append32(dump, uint32(d.Size(x)/8))
			dump = appendId(dump, java_lang_objectarray)
		} else {
			dump = append(dump, HPROF_GC_INSTANCE_DUMP)
			dump = appendId(dump, d.Addr(x))
			dump = append32(dump, stack_trace_serial_number)
			dump = appendId(dump, c)
			dump = append32(dump, uint32(d.Size(x)))
		}
		// dump object data
		dump = append(dump, data...)
	}

	// output threads
	for _, t := range d.Goroutines {
		dump = append(dump, HPROF_GC_ROOT_THREAD_OBJ)
		dump = appendId(dump, t.Addr)
		dump = append32(dump, threadSerialNumbers[t])
		dump = append32(dump, stackTraceSerialNumbers[t])
	}

	// stack roots
	for _, t := range d.Goroutines {
		for f := t.Bos; f != nil; f = f.Parent {
			for _, e := range f.Edges {
				// we make one "thread" per field, because the roots
				// get identified by "thread" in jhat.
				id := newId()      // id of thread object
				cid := newId()     // id of class of thread object
				tid := newSerial() // thread serial number

				// this is the class of the thread object.  Its name
				// is what gets displayed with the root entry.
				addClass(cid, 0, f.Name+"."+e.FieldName, nil)

				// new thread object
				dump = append(dump, HPROF_GC_INSTANCE_DUMP)
				dump = appendId(dump, id)
				dump = append32(dump, stack_trace_serial_number)
				dump = appendId(dump, cid)
				dump = append32(dump, 0) // no data

				// mark it as a thread
				dump = append(dump, HPROF_GC_ROOT_THREAD_OBJ)
				dump = appendId(dump, id)
				dump = append32(dump, tid)
				dump = append32(dump, stack_trace_serial_number)

				// finally, make root come from this thread
				dump = append(dump, HPROF_GC_ROOT_JAVA_FRAME)
				dump = appendId(dump, d.Addr(e.To))
				dump = append32(dump, tid)
				dump = append32(dump, 0) // depth
			}
		}
	}
	// data roots
	for _, x := range []*read.Data{d.Data, d.Bss} {
		// adjust edges to point to object beginnings
		for _, e := range x.Edges {
			writePtr(x.Data[e.FromOffset:], d.Addr(e.To))
		}
		for _, f := range x.Fields {
			addGlobal(f.Name, f.Kind, x.Data[f.Offset:])
		}
	}
	for _, t := range d.Otherroots {
		for _, e := range t.Edges {
			dump = append(dump, HPROF_GC_ROOT_UNKNOWN)
			dump = appendId(dump, d.Addr(e.To))
		}
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
	if d.Order == binary.BigEndian {
		return
	}
	x[0], x[1] = x[1], x[0]
}
func bigEndian4(x []byte) {
	if d.Order == binary.BigEndian {
		return
	}
	x[0], x[1], x[2], x[3] = x[3], x[2], x[1], x[0]
}
func bigEndian8(x []byte) {
	if d.Order == binary.BigEndian {
		return
	}
	x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7] = x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]
}
func bigEndianP(x []byte) {
	if d.PtrSize == 4 {
		bigEndian4(x)
	} else {
		bigEndian8(x)
	}
}

func writePtr(b []byte, v uint64) {
	switch {
	case d.Order == binary.LittleEndian && d.PtrSize == 4:
		b[0] = byte(v >> 0)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
	case d.Order == binary.BigEndian && d.PtrSize == 4:
		b[3] = byte(v >> 0)
		b[2] = byte(v >> 8)
		b[1] = byte(v >> 16)
		b[0] = byte(v >> 24)
	case d.Order == binary.LittleEndian && d.PtrSize == 8:
		b[0] = byte(v >> 0)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
		b[4] = byte(v >> 32)
		b[5] = byte(v >> 40)
		b[6] = byte(v >> 48)
		b[7] = byte(v >> 56)
	case d.Order == binary.BigEndian && d.PtrSize == 8:
		b[7] = byte(v >> 0)
		b[6] = byte(v >> 8)
		b[5] = byte(v >> 16)
		b[4] = byte(v >> 24)
		b[3] = byte(v >> 32)
		b[2] = byte(v >> 40)
		b[1] = byte(v >> 48)
		b[0] = byte(v >> 56)
	default:
		log.Fatal("unsupported order=%v PtrSize=%d", d.Order, d.PtrSize)
	}
}
