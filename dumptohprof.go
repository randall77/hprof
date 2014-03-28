package main

import (
	"fmt"
	"os"
	"flag"
	"log"
	"encoding/binary"
)

// set of all the object pointers in the file
var usedIds map[uint64]struct{}

// allocate a new, unused Id
var idAlloc uint64

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
	hprof = append32(hprof, 8) // IDs are 8 bytes
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
	addTag(0x01, body)
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
	addTag(0x0a, body)
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
		addTag(0x04, body)
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
		addTag(0x05, body)

		// thread record
		body = nil
		body = append32(body, tid)
		body = appendId(body, t.addr)
		body = append32(body, sid)
		body = appendId(body, addString("threadname"))
		body = appendId(body, addString("threadgroup"))
		body = appendId(body, addString("threadparentgroup"))
		addTag(0x0a, body)

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
	addTag(0x02, body)
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
	addTag(0x04, body)
	return id
}

func addStackTrace() {
	var body []byte
	body = append32(body, stack_trace_serial_number)
	body = append32(body, thread_serial_number)
	body = append32(body, 1) // # of frames
	body = appendId(body, addStackFrame("unknown", "", "unknown.go"))
	addTag(0x5, body)
}

func fakeClassDump(id uint64, superid uint64) []byte {
	var body []byte
	body = append(body, 0x20)
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

// allocates a class, issues a load command for it,
// returns the class dump sub-tag missing only # instance fields
func addClass(id uint64, size uint64, name string, fields []JavaField) {
	// write load class command
	var body []byte
	sid := newSerial()
	body = append32(body, sid)
	body = appendId(body, id)
	body = append32(body, stack_trace_serial_number)
	body = appendId(body, addString(name))
	//fmt.Printf("%d == %s\n", sid, name)
	addTag(0x02, body)

	// write a class dump subcommand
	dump = append(dump, 0x20)
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

// map from the size to the noptr object to the id of the fake class that represents them
var noPtrClass map[uint64]uint64 = make(map[uint64]uint64, 0)

func NoPtrClass(size uint64) uint64 {
	c := noPtrClass[size]
	if c == 0 {
		c = newId()
		addClass(c, size, fmt.Sprintf("noptr%d", size), []JavaField{})
		noPtrClass[size] = c
	}
	return c
}

// maps from type addr to the fake class object we use to represent that type
var stdClass map[uint64]uint64 = make(map[uint64]uint64, 0)

func StdClass(t *Type, size uint64) uint64 {
	c := stdClass[t.addr]
	if c == 0 {
		c = newId()
		f := make([]JavaField, size/8)
		for i := uint64(0); i < size/8; i++ {
			f[i].kind = 11 // long
			if i*8 < t.size {
				f[i].name = fmt.Sprintf("f%03d", i*8)
			} else {
				f[i].name = "sizeclass_pad"
			}
		}
		for _, fld := range t.fields {
			switch fld.kind {
			case fieldKindPtr:
				f[fld.offset/8].kind = 2 // Object
			// data fields might be pointers, might not be.  hprof has
			// no good way to represent this.
			case fieldKindIface:
				f[fld.offset/8].kind = 2 // Object
				f[fld.offset/8+1].kind = 2 // Object
			case fieldKindEface:
				f[fld.offset/8].kind = 2 // Object
				f[fld.offset/8+1].kind = 2 // Object
			}
		}
		addClass(c, size, t.name, f)
		stdClass[t.addr] = c
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
	k := ArrayKey{t.addr, size}
	c := arrayClass[k]
	if c == 0 {
		c = newId()
		f := make([]JavaField, size/8)
		nelem := size / t.size
		for i := uint64(0); i < size/8; i++ {
			f[i].kind = 11 // long
			if i*8 < nelem*t.size {
				f[i].name = fmt.Sprintf("f%03d_%03d", i*8/t.size, i*8%t.size)
			} else {
				f[i].name = "sizeclass_pad"
			}
		}
		for i := uint64(0); i <= size - t.size; i += t.size {
			for _, fld := range t.fields {
				switch fld.kind {
				case fieldKindPtr:
					f[(i+fld.offset)/8].kind = 2 // Object
				case fieldKindIface:
					f[(i+fld.offset)/8].kind = 2 // Object
					f[(i+fld.offset)/8+1].kind = 2 // Object
				case fieldKindEface:
					f[(i+fld.offset)/8].kind = 2 // Object
					f[(i+fld.offset)/8+1].kind = 2 // Object
				}
			}
		}
		addClass(c, size, fmt.Sprintf("array{%d}%s", nelem, t.name), f)
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
	k := ChanKey{t.addr, size}
	c := chanClass[k]
	if c == 0 {
		c = newId()
		f := make([]JavaField, size/8)
		nelem := (size - d.hChanSize) / t.size
		for i := uint64(0); i < size/8; i++ {
			f[i].kind = 11 // long
			if i*8 < d.hChanSize {
				f[i].name = "chanhdr"
			} else if i*8 < d.hChanSize+t.size*nelem {
				f[i].name = fmt.Sprintf("f%03d_%03d", (i*8-d.hChanSize)/t.size, (i*8-d.hChanSize)%t.size)
			} else {
				f[i].name = "sizeclass_pad"
			}
		}
		for i := d.hChanSize; i <= size - t.size; i += t.size {
			for _, fld := range t.fields {
				switch fld.kind {
				case fieldKindPtr:
					f[(i+fld.offset)/8].kind = 2 // Object
				case fieldKindIface:
					f[(i+fld.offset)/8].kind = 2 // Object
					f[(i+fld.offset)/8+1].kind = 2 // Object
				case fieldKindEface:
					f[(i+fld.offset)/8].kind = 2 // Object
					f[(i+fld.offset)/8+1].kind = 2 // Object
				}
			}
		}
		addClass(c, size, fmt.Sprintf("chan{%d}%s", nelem, t.name), f)
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
		// figure out what class to use for this object
		var c uint64
		if len(x.data) >= 65536*8 {
			// Object is too big to enumerate each field.
			// Make it an []Object.
			dump = append(dump, 0x22) // object array dump
			dump = appendId(dump, x.addr)
			dump = append32(dump, stack_trace_serial_number)
			dump = append32(dump, uint32(len(x.data)/8))
			dump = appendId(dump, java_lang_objectarray)
			endianSwap(x.data)
			dump = append(dump, x.data...)
			endianSwap(x.data)
			continue
		} else if x.typ == nil {
			c = NoPtrClass(uint64(len(x.data)))
		} else {
			switch x.kind {
			case typeKindObject:
				c = StdClass(x.typ, uint64(len(x.data)))
			case typeKindArray:
				c = ArrayClass(x.typ, uint64(len(x.data)))
			case typeKindChan:
				fmt.Printf("dumping chan %x\n", x.addr)
				c = ChanClass(x.typ, uint64(len(x.data)))
			default:
				log.Fatal("unhandled kind")
			}
		}
		dump = append(dump, 0x21) // instance dump
		dump = appendId(dump, x.addr)
		dump = append32(dump, stack_trace_serial_number)
		dump = appendId(dump, c)
		dump = append32(dump, uint32(len(x.data)))

		// adjust ptr fields.  Any pointers outside the heap get zeroed,
		// and any pointers to objects get adjusted to point to the object head.
		for _, e := range x.edges {
			writePtr(x.data[e.fromoffset:], e.to.addr)
		}

		endianSwap(x.data)
		dump = append(dump, x.data...)
		endianSwap(x.data)
	}

	// output threads
	for _, t := range d.goroutines {
		dump = append(dump, 0x08) // root thread object
		dump = appendId(dump, t.addr)
		dump = append32(dump, threadSerialNumbers[t])
		dump = append32(dump, stackTraceSerialNumbers[t])
	}

	// stack roots
	for _, t := range d.goroutines {
	for f := t.bos; f != nil; f = f.parent {
	    for _, e := range f.edges {
		dump = append(dump, 0x03) // root java frame
		dump = appendId(dump, e.to.addr)
		dump = append32(dump, threadSerialNumbers[t])
		dump = append32(dump, uint32(f.depth))
	}
}
}
	// data roots
	for _, x := range []*Data{d.data, d.bss} {
	for _, e := range x.edges {
		dump = append(dump, 0x01) // root jni global
		dump = appendId(dump, e.to.addr)
		dump = appendId(dump, x.addr + e.fromoffset) // jni global ref id
	}
}
	for _, t := range d.otherroots {
		if t.e.to == nil {
			continue
		}
		dump = append(dump, 0xff) // root unknown
		dump = appendId(dump, t.e.to.addr)
	}

	addTag(0x0c, dump)
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
