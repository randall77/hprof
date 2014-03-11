package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
)

// TODO: encode in dump
const hchansize = 11 * 8

type Dump struct {
	order      binary.ByteOrder
	ptrSize    int // in bytes
	types      []*Type
	objects    []*Object
	frames     []*Frame
	threads    []*Thread
	stackroots []*StackRoot
	dataroots  []*DataRoot
	otherroots []*OtherRoot
}

type Object struct {
	typ   *Type
	kind  uint64
	data  []byte // length is sizeclass size, may be bigger then typ.size
	edges []*Object

	addr    uint64
	typaddr uint64
}

type StackRoot struct {
	to    *Object
	frame *Frame

	toaddr    uint64
	frameaddr uint64
}
type DataRoot struct {
	to *Object

	fromaddr uint64
	toaddr   uint64
}
type OtherRoot struct {
	to *Object

	toaddr uint64
}

type Type struct {
	name string // not necessarily unique
	size uint64
	ptrs []uint64 // offsets of pointer fields

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

// reads data in
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

	types := make(map[uint64]struct{}, 0)

	var d Dump
	for {
		kind := readUint64(r)
		switch kind {
		case 1:
			obj := &Object{}
			obj.addr = readUint64(r)
			obj.typaddr = readUint64(r)
			obj.kind = readUint64(r)
			size := readUint64(r)
			obj.data = readNBytes(r, size)
			d.objects = append(d.objects, obj)
		case 3:
			return &d
		case 4:
			t := &StackRoot{}
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
			t.toaddr = readUint64(r)
			d.otherroots = append(d.otherroots, t)
		case 7:
			typ := &Type{}
			typ.addr = readUint64(r)
			typ.size = readUint64(r)
			typ.name = readString(r)
			nptr := readUint64(r)
			typ.ptrs = make([]uint64, nptr)
			for i := uint64(0); i < nptr; i++ {
				typ.ptrs[i] = readUint64(r)
			}
			// We may get several records for a type.  Keep just
			// one; they should all be identical.
			if _, ok := types[typ.addr]; !ok {
				types[typ.addr] = struct{}{}
				d.types = append(d.types, typ)
			}
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
			d.ptrSize = int(readUint64(r))
		default:
			panic("bad kind " + fmt.Sprintf("%d", kind))
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

func link(d *Dump) {
	types := make(map[uint64]*Type, len(d.types))
	frames := make(map[uint64]*Frame, len(d.frames))
	for _, x := range d.types {
		types[x.addr] = x
	}
	for _, x := range d.frames {
		frames[x.addr] = x
	}

	// link objects to types
	for _, x := range d.objects {
		if x.typaddr == 0 {
			x.typ = nil
		} else {
			x.typ = types[x.typaddr]
			if x.typ == nil {
				panic("type is missing")
			}
		}
	}
	// link up frames in sequence
	for _, f := range d.frames {
		f.parent = frames[f.parentaddr]
		// NOTE: the base frame of the stack (runtime.goexit usually)
		// will fail the lookup here and set a nil pointer.
	}
	// link threads to frames & vice versa
	for _, t := range d.threads {
		t.tos = frames[t.tosaddr]
		if t.tos == nil {
			panic("tos missing")
		}
		d := uint64(0)
		for f := t.tos; f != nil; f = f.parent {
			f.thread = t
			f.depth = d
			d++
		}
	}

	// Accumulate ranges for each object into a "heap" for quick lookup.
	// We need this heap so we can pinpoint the destination of pointers
	// that point to the middle of an object.
	var heap Heap
	for _, x := range d.objects {
		heap = append(heap, x)
	}
	sort.Sort(heap)

	// link up roots
	for _, r := range d.stackroots {
		r.to = heap.find(r.toaddr)
		r.frame = frames[r.frameaddr]
	}
	for _, r := range d.dataroots {
		r.to = heap.find(r.toaddr)
	}
	for _, r := range d.otherroots {
		r.to = heap.find(r.toaddr)
	}

	// link objects to each other
	for _, x := range d.objects {
		t := x.typ
		if t == nil {
			continue // typeless objects have no pointers
		}
		switch x.kind {
		case 0:
			// simple object
			for _, offset := range t.ptrs {
				s := x.data[offset : offset+8]
				p := readPtr(d, s)
				q := heap.find(p)
				if q == nil {
					writePtr(d, s, 0)
				} else {
					writePtr(d, s, q.addr)
					x.edges = append(x.edges, q)
				}
			}
		case 1:
			// array object
			for i := uint64(0); i < uint64(len(x.data))/t.size; i++ {
				for _, offset := range t.ptrs {
					s := x.data[i*t.size+offset : i*t.size+offset+8]
					p := readPtr(d, s)
					q := heap.find(p)
					if q == nil {
						writePtr(d, s, 0)
					} else {
						writePtr(d, s, q.addr)
						x.edges = append(x.edges, q)
					}
				}
			}
		case 2:
			// channel object.
			for i := uint64(0); i < uint64(len(x.data)-hchansize)/t.size; i++ {
				for _, offset := range t.ptrs {
					s := x.data[hchansize+i*t.size+offset : hchansize+i*t.size+offset+8]
					p := readPtr(d, s)
					q := heap.find(p)
					if q == nil {
						writePtr(d, s, 0)
					} else {
						writePtr(d, s, q.addr)
						x.edges = append(x.edges, q)
					}
				}
			}
		}
	}
}

func Read(dumpname string) *Dump {
	d := rawRead(dumpname)
	link(d)
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
		panic(fmt.Sprintf("unsupported order=%v ptrSize=%d", d.order, d.ptrSize))
	}
}
func writePtr(d *Dump, b []byte, v uint64) {
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
		panic(fmt.Sprintf("unsupported order=%v ptrSize=%d", d.order, d.ptrSize))
	}
}
