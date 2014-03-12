package main

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"io"
	"log"
	"os"
	"sort"
)

type fieldKind int
type typeKind int

const (
	fieldKindPtr   fieldKind = 0
	fieldKindIface           = 1
	fieldKindEface           = 2

	typeKindObject typeKind = 0
	typeKindArray           = 1
	typeKindChan            = 2
)

type Dump struct {
	order      binary.ByteOrder
	ptrSize    uint64 // in bytes
	hChanSize  uint64 // channel header size in bytes
	types      []*Type
	objects    []*Object
	frames     []*Frame
	threads    []*Thread
	stackroots []*StackRoot
	dataroots  []*DataRoot
	otherroots []*OtherRoot
	finalizers []*Finalizer
	itabs      []*Itab
}

// An edge is a directed connection between two objects.  The source
// object is implicit.  It includes information about where the edge
// leaves the source object and where it lands in the destination obj.
type Edge struct {
	to         *Object // object pointed to
	fromoffset uint64  // offset in source object where ptr was found
	tooffset   uint64  // offset in destination object where ptr lands
}

type Object struct {
	typ   *Type
	kind  typeKind
	data  []byte // length is sizeclass size, may be bigger then typ.size
	edges []Edge

	addr    uint64
	typaddr uint64
}

type StackRoot struct {
	frame *Frame
	e     Edge

	fromaddr  uint64
	toaddr    uint64
	frameaddr uint64
}
type DataRoot struct {
	name string // name of global variable
	e    Edge

	fromaddr uint64
	toaddr   uint64
}
type OtherRoot struct {
	description string
	e           Edge

	toaddr uint64
}

// Object fromaddr has a finalizer that requires
// data from toaddr.
type Finalizer struct {
	fromaddr uint64
	toaddr   uint64
}

// For the given itab value, is the corresponding
// interface data field a pointer?
type Itab struct {
	addr uint64
	ptr  bool
}

// A Field is a location in an object where there
// might be a pointer.
type Field struct {
	kind   fieldKind
	offset uint64
}

type Type struct {
	name     string // not necessarily unique
	size     uint64
	efaceptr bool   // Efaces with this type have a data field which is a pointer
	fields   []Field

	addr uint64
}

type Thread struct {
	tos *Frame // frame at the top of the stack

	addr    uint64
	tosaddr uint64
}

type Frame struct {
	name   string
	parent *Frame
	thread *Thread
	depth  uint64

	addr       uint64
	parentaddr uint64
}

func readUint64(r io.ByteReader) uint64 {
	x, err := binary.ReadUvarint(r)
	if err != nil {
		log.Fatal(err)
	}
	return x
}
func readNBytes(r io.ByteReader, n uint64) []byte {
	s := make([]byte, n)
	for i := range s {
		b, err := r.ReadByte()
		if err != nil {
			log.Fatal(err)
		}
		s[i] = b
	}
	return s
}
func readString(r io.ByteReader) string {
	n := readUint64(r)
	return string(readNBytes(r, n))
}

// Reads heap dump into memory.
func rawRead(filename string) *Dump {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	r := bufio.NewReader(file)

	// check for header
	hdr, prefix, err := r.ReadLine()
	if err != nil {
		log.Fatal(err)
	}
	if prefix || string(hdr) != "go1.3 heap dump" {
		log.Fatal("not a go1.3 heap dump file")
	}

	var d Dump
	for {
		kind := readUint64(r)
		switch kind {
		case 1:
			obj := &Object{}
			obj.addr = readUint64(r)
			obj.typaddr = readUint64(r)
			obj.kind = typeKind(readUint64(r))
			size := readUint64(r)
			obj.data = readNBytes(r, size)
			d.objects = append(d.objects, obj)
		case 3:
			return &d
		case 4:
			t := &StackRoot{}
			t.fromaddr = readUint64(r)
			t.toaddr = readUint64(r)
			t.frameaddr = readUint64(r)
			d.stackroots = append(d.stackroots, t)
		case 5:
			t := &DataRoot{}
			t.fromaddr = readUint64(r)
			t.toaddr = readUint64(r)
			d.dataroots = append(d.dataroots, t)
		case 6:
			t := &OtherRoot{}
			t.description = readString(r)
			t.toaddr = readUint64(r)
			d.otherroots = append(d.otherroots, t)
		case 7:
			typ := &Type{}
			typ.addr = readUint64(r)
			typ.size = readUint64(r)
			typ.name = readString(r)
			typ.efaceptr = readUint64(r) > 0
			nptr := readUint64(r)
			typ.fields = make([]Field, nptr)
			for i := uint64(0); i < nptr; i++ {
				typ.fields[i].kind = fieldKind(readUint64(r))
				typ.fields[i].offset = readUint64(r)
			}
			d.types = append(d.types, typ)
		case 8:
			t := &Thread{}
			t.addr = readUint64(r)
			t.tosaddr = readUint64(r)
			d.threads = append(d.threads, t)
		case 9:
			t := &Frame{}
			t.addr = readUint64(r)
			t.parentaddr = readUint64(r)
			t.name = readString(r)
			d.frames = append(d.frames, t)
		case 10:
			if readUint64(r) == 0 {
				d.order = binary.LittleEndian
			} else {
				d.order = binary.BigEndian
			}
			d.ptrSize = readUint64(r)
			d.hChanSize = readUint64(r)
		case 11:
			t := &Finalizer{}
			t.fromaddr = readUint64(r)
			t.toaddr = readUint64(r)
			d.finalizers = append(d.finalizers, t)
		case 12:
			t := &Itab{}
			t.addr = readUint64(r)
			t.ptr = readUint64(r) > 0
			d.itabs = append(d.itabs, t)
		default:
			log.Fatal("unknown record kind %d", kind)
		}
	}
}

type Heap []*Object

func (h Heap) Len() int           { return len(h) }
func (h Heap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h Heap) Less(i, j int) bool { return h[i].addr < h[j].addr }

// returns the object containing the pointed-to address, or nil if none.
func (h Heap) find(p uint64) *Object {
	j := sort.Search(len(h), func(i int) bool { return p < h[i].addr+uint64(len(h[i].data)) })
	if j < len(h) && p >= h[j].addr {
		return h[j]
	}
	return nil
}

type Global struct {
	name string
	addr uint64
}
type Globals []Global

func (g Globals) Len() int           { return len(g) }
func (g Globals) Swap(i, j int)      { g[i], g[j] = g[j], g[i] }
func (g Globals) Less(i, j int) bool { return g[i].addr < g[j].addr }

// returns the global variable containing the given address.
func (g Globals) find(p uint64) Global {
	j := sort.Search(len(g), func(i int) bool { return p < g[i].addr })
	if j == 0 {
		return Global{"unknown global", 0}
	}
	return g[j-1]
}

func globalMap(d *Dump, execname string) Globals {
	var g Globals
	f, err := elf.Open(execname)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	w, err := f.DWARF()
	if err != nil {
		log.Fatal(err)
	}
	r := w.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			log.Fatal(err)
		}
		if e == nil {
			break
		}
		if e.Tag != dwarf.TagVariable {
			continue
		}
		name := e.Val(dwarf.AttrName).(string)
		locexpr := e.Val(dwarf.AttrLocation).([]uint8)
		if len(locexpr) > 0 && locexpr[0] == 0x03 { // DW_OP_addr
			loc := readPtr(d, locexpr[1:])
			g = append(g, Global{name, loc})
		}
	}
	sort.Sort(g)
	return g
}

func linkFields(info *LinkInfo, x *Object, fields []Field, offset uint64) {
	for _, f := range fields {
		off := offset + f.offset
		s := x.data[off:]
		switch f.kind {
		case fieldKindPtr:
			p := readPtr(info.dump, s)
			q := info.heap.find(p)
			if q != nil {
				x.edges = append(x.edges, Edge{q, off, p - q.addr})
			}
		case fieldKindEface:
			tp := readPtr(info.dump, s)
			if tp != 0 {
				t := info.types[tp]
				if t == nil {
					log.Fatal("can't find eface type")
				}
				if t.efaceptr {
					p := readPtr(info.dump, s[info.dump.ptrSize:])
					q := info.heap.find(p)
					if q != nil {
						x.edges = append(x.edges, Edge{q, off, p - q.addr})
					}
				}
			}
		case fieldKindIface:
			tp := readPtr(info.dump, s)
			if tp != 0 {
				t := info.itabs[tp]
				if t == nil {
					log.Fatal("can't find iface tab")
				}
				if t.ptr {
					p := readPtr(info.dump, s[info.dump.ptrSize:])
					q := info.heap.find(p)
					if q != nil {
						x.edges = append(x.edges, Edge{q, off, p - q.addr})
					}
				}
			}
		}
	}
}

// various maps used to link up data structures
type LinkInfo struct {
	dump    *Dump
	types   map[uint64]*Type
	itabs   map[uint64]*Itab
	frames  map[uint64]*Frame
	globals Globals
	heap    Heap
}

func link(d *Dump, execname string) {
	// initialize some maps used for linking
	var info LinkInfo
	info.dump = d
	info.types = make(map[uint64]*Type, len(d.types))
	info.itabs = make(map[uint64]*Itab, len(d.itabs))
	info.frames = make(map[uint64]*Frame, len(d.frames))
	for _, x := range d.types {
		// Note: there may be duplicate type records in a dump.
		// The duplicates get thrown away here.
		info.types[x.addr] = x
	}
	for _, x := range d.itabs {
		info.itabs[x.addr] = x
	}
	for _, x := range d.frames {
		info.frames[x.addr] = x
	}

	// Binary-searchable map of global variables
	info.globals = globalMap(d, execname)

	// Binary-searchable map of objects
	for _, x := range d.objects {
		info.heap = append(info.heap, x)
	}
	sort.Sort(info.heap)

	// link objects to types
	for _, x := range d.objects {
		if x.typaddr == 0 {
			x.typ = nil
		} else {
			x.typ = info.types[x.typaddr]
			if x.typ == nil {
				log.Fatal("type is missing")
			}
		}
	}

	// link up frames in sequence
	for _, f := range d.frames {
		f.parent = info.frames[f.parentaddr]
		// NOTE: the base frame of the stack (runtime.goexit usually)
		// will fail the lookup here and set a nil pointer.
	}

	// link threads to frames & vice versa
	for _, t := range d.threads {
		t.tos = info.frames[t.tosaddr]
		if t.tos == nil {
			log.Fatal("tos missing")
		}
		d := uint64(0)
		for f := t.tos; f != nil; f = f.parent {
			f.thread = t
			f.depth = d
			d++
		}
	}

	// link up roots to objects
	for _, r := range d.stackroots {
		r.frame = info.frames[r.frameaddr]
		x := info.heap.find(r.toaddr)
		if x != nil {
			r.e = Edge{x, r.fromaddr - r.frameaddr, r.toaddr - x.addr}
		}
	}
	for _, r := range d.dataroots {
		g := info.globals.find(r.fromaddr)
		r.name = g.name
		q := info.heap.find(r.toaddr)
		if q != nil {
			r.e = Edge{q, r.fromaddr - g.addr, r.toaddr - q.addr}
		}
	}
	for _, r := range d.otherroots {
		x := info.heap.find(r.toaddr)
		if x != nil {
			r.e = Edge{x, 0, r.toaddr - x.addr}
		}
	}

	// link objects to each other
	for _, x := range d.objects {
		t := x.typ
		if t == nil {
			continue // typeless objects have no pointers
		}
		switch x.kind {
		case typeKindObject:
			linkFields(&info, x, t.fields, 0)
		case typeKindArray:
			for i := uint64(0); i <= uint64(len(x.data)) - t.size; i += t.size {
				linkFields(&info, x, t.fields, i)
			}
		case typeKindChan:
			for i := d.hChanSize; i <= uint64(len(x.data)) - t.size; i += t.size {
				linkFields(&info, x, t.fields, i)
			}
		}
	}

	// Add links for finalizers
	for _, f := range d.finalizers {
		x := info.heap.find(f.fromaddr)
		y := info.heap.find(f.toaddr)
		if x != nil && y != nil {
			x.edges = append(x.edges, Edge{x, 0, f.toaddr - y.addr})
			// TODO: mark edge as arising from a finalizer somehow?
		}
	}
}

func Read(dumpname, execname string) *Dump {
	d := rawRead(dumpname)
	link(d, execname)
	return d
}

func readPtr(d *Dump, b []byte) uint64 {
	switch {
	case d.order == binary.LittleEndian && d.ptrSize == 4:
		return uint64(b[0]) + uint64(b[1])<<8 + uint64(b[2])<<16 + uint64(b[3])<<24
	case d.order == binary.BigEndian && d.ptrSize == 4:
		return uint64(b[3]) + uint64(b[2])<<8 + uint64(b[1])<<16 + uint64(b[0])<<24
	case d.order == binary.LittleEndian && d.ptrSize == 8:
		return uint64(b[0]) + uint64(b[1])<<8 + uint64(b[2])<<16 + uint64(b[3])<<24 + uint64(b[4])<<32 + uint64(b[5])<<40 + uint64(b[6])<<48 + uint64(b[7])<<56
	case d.order == binary.BigEndian && d.ptrSize == 8:
		return uint64(b[7]) + uint64(b[6])<<8 + uint64(b[5])<<16 + uint64(b[4])<<24 + uint64(b[3])<<32 + uint64(b[2])<<40 + uint64(b[1])<<48 + uint64(b[0])<<56
	default:
		log.Fatal("unsupported order=%v ptrSize=%d", d.order, d.ptrSize)
		return 0
	}
}
