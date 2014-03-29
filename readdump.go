package main

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"runtime"
)

type fieldKind int
type typeKind int

const (
	fieldKindEol    fieldKind = 0
	fieldKindPtr              = 1
	fieldKindString           = 2
	fieldKindSlice            = 3
	fieldKindIface            = 4
	fieldKindEface            = 5

	typeKindObject       typeKind = 0
	typeKindArray                 = 1
	typeKindChan                  = 2
	typeKindConservative          = 127

	tagEOF        = 0
	tagObject     = 1
	tagOtherRoot  = 2
	tagType       = 3
	tagGoRoutine  = 4
	tagStackFrame = 5
	tagParams     = 6
	tagFinalizer  = 7
	tagItab       = 8
	tagOSThread   = 9
	tagMemStats   = 10
	tagQFinal     = 11
	tagData       = 12
	tagBss        = 13
	tagDefer      = 14
	tagPanic      = 15

	// DWARF constants
	dw_op_call_frame_cfa = 156
	dw_op_consts         = 17
	dw_op_plus           = 34
	dw_op_addr           = 3
)

type Dump struct {
	order      binary.ByteOrder
	ptrSize    uint64 // in bytes
	hChanSize  uint64 // channel header size in bytes
	heapStart  uint64
	heapEnd    uint64
	thechar    byte
	experiment string
	ncpu       uint64
	types      []*Type
	objects    []*Object
	frames     []*StackFrame
	goroutines []*GoRoutine
	otherroots []*OtherRoot
	finalizers []*Finalizer  // pending finalizers, object still live
	qfinal     []*QFinalizer // finalizers which are ready to run
	itabs      []*Itab
	osthreads  []*OSThread
	memstats   *runtime.MemStats
	data       *Data
	bss        *Data
	defers     []*Defer
	panics     []*Panic
}

// An edge is a directed connection between two objects.  The source
// object is implicit.  An edge includes information about where it
// leaves the source object and where it lands in the destination obj.
type Edge struct {
	to         *Object // object pointed to
	fromoffset uint64  // offset in source object where ptr was found
	tooffset   uint64  // offset in destination object where ptr lands

	// name of field / offset within field, if known
	fieldname   string
	fieldoffset uint64
}

type Object struct {
	typ   *Type
	kind  typeKind
	data  []byte // length is sizeclass size, may be bigger then typ.size
	edges []Edge

	addr    uint64
	typaddr uint64
}

type OtherRoot struct {
	description string
	e           Edge

	toaddr uint64
}

// Object obj has a finalizer.
type Finalizer struct {
	obj  uint64
	fn   uint64 // function to be run (a FuncVal*)
	code uint64 // code ptr (fn->fn)
	fint uint64 // type of function argument
	ot   uint64 // type of object
}

// Finalizer that's ready to run
type QFinalizer struct {
	obj   uint64
	fn    uint64 // function to be run (a FuncVal*)
	code  uint64 // code ptr (fn->fn)
	fint  uint64 // type of function argument
	ot    uint64 // type of object
	edges []Edge
}

type Defer struct {
	addr uint64
	gp   uint64
	argp uint64
	pc   uint64
	fn   uint64
	code uint64
	link uint64
}

type Panic struct {
	addr uint64
	gp   uint64
	typ  uint64
	data uint64
	defr uint64
	link uint64
}

type Data struct {
	addr   uint64
	data   []byte
	fields []Field
	edges  []Edge
}

// For the given itab value, is the corresponding
// interface data field a pointer?
type Itab struct {
	addr uint64
	ptr  bool
}

type OSThread struct {
	addr   uint64
	id     uint64
	procid uint64
}

// A Field is a location in an object where there
// might be a pointer.
type Field struct {
	kind   fieldKind
	offset uint64
	name   string
}

type Type struct {
	name     string // not necessarily unique
	size     uint64
	efaceptr bool // Efaces with this type have a data field which is a pointer
	fields   []Field

	addr uint64
}

type GoRoutine struct {
	bos  *StackFrame // frame at the top of the stack (i.e. currently running)
	ctxt *Object

	addr         uint64
	bosaddr      uint64
	goid         uint64
	gopc         uint64
	status       uint64
	issystem     bool
	isbackground bool
	waitsince    uint64
	waitreason   string
	ctxtaddr     uint64
	maddr        uint64
	deferaddr    uint64
	panicaddr    uint64
}

type StackFrame struct {
	name      string
	parent    *StackFrame
	goroutine *GoRoutine
	depth     uint64
	data      []byte
	edges     []Edge

	addr      uint64
	childaddr uint64
	entry     uint64
	pc        uint64
	fields    []Field
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
	// TODO: faster
	for i := range s {
		b, err := r.ReadByte()
		if err != nil {
			log.Fatal(err)
		}
		s[i] = b
	}
	return s
}

func readBytes(r io.ByteReader) []byte {
	n := readUint64(r)
	return readNBytes(r, n)
}

func readString(r io.ByteReader) string {
	return string(readBytes(r))
}

func readBool(r io.ByteReader) bool {
	b, err := r.ReadByte()
	if err != nil {
		log.Fatal(err)
	}
	return b != 0
}

func readFields(r io.ByteReader) []Field {
	var x []Field
	for {
		kind := fieldKind(readUint64(r))
		if kind == fieldKindEol {
			return x
		}
		x = append(x, Field{kind: kind, offset: readUint64(r)})
	}
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
		case tagObject:
			obj := &Object{}
			obj.addr = readUint64(r)
			obj.typaddr = readUint64(r)
			obj.kind = typeKind(readUint64(r))
			obj.data = readBytes(r)
			d.objects = append(d.objects, obj)
		case tagEOF:
			return &d
		case tagOtherRoot:
			t := &OtherRoot{}
			t.description = readString(r)
			t.toaddr = readUint64(r)
			d.otherroots = append(d.otherroots, t)
		case tagType:
			typ := &Type{}
			typ.addr = readUint64(r)
			typ.size = readUint64(r)
			typ.name = readString(r)
			typ.efaceptr = readBool(r)
			typ.fields = readFields(r)
			d.types = append(d.types, typ)
		case tagGoRoutine:
			g := &GoRoutine{}
			g.addr = readUint64(r)
			g.bosaddr = readUint64(r)
			g.goid = readUint64(r)
			g.gopc = readUint64(r)
			g.status = readUint64(r)
			g.issystem = readBool(r)
			g.isbackground = readBool(r)
			g.waitsince = readUint64(r)
			g.waitreason = readString(r)
			g.ctxtaddr = readUint64(r)
			g.maddr = readUint64(r)
			g.deferaddr = readUint64(r)
			g.panicaddr = readUint64(r)
			d.goroutines = append(d.goroutines, g)
		case tagStackFrame:
			t := &StackFrame{}
			t.addr = readUint64(r)
			t.depth = readUint64(r)
			t.childaddr = readUint64(r)
			t.data = readBytes(r)
			t.entry = readUint64(r)
			t.pc = readUint64(r)
			t.name = readString(r)
			t.fields = readFields(r)
			d.frames = append(d.frames, t)
		case tagParams:
			if readUint64(r) == 0 {
				d.order = binary.LittleEndian
			} else {
				d.order = binary.BigEndian
			}
			d.ptrSize = readUint64(r)
			d.hChanSize = readUint64(r)
			d.heapStart = readUint64(r)
			d.heapEnd = readUint64(r)
			d.thechar = byte(readUint64(r))
			d.experiment = readString(r)
			d.ncpu = readUint64(r)
		case tagFinalizer:
			t := &Finalizer{}
			t.obj = readUint64(r)
			t.fn = readUint64(r)
			t.code = readUint64(r)
			t.fint = readUint64(r)
			t.ot = readUint64(r)
			d.finalizers = append(d.finalizers, t)
		case tagQFinal:
			t := &QFinalizer{}
			t.obj = readUint64(r)
			t.fn = readUint64(r)
			t.code = readUint64(r)
			t.fint = readUint64(r)
			t.ot = readUint64(r)
			d.qfinal = append(d.qfinal, t)
		case tagData:
			t := &Data{}
			t.addr = readUint64(r)
			t.data = readBytes(r)
			t.fields = readFields(r)
			d.data = t
		case tagBss:
			t := &Data{}
			t.addr = readUint64(r)
			t.data = readBytes(r)
			t.fields = readFields(r)
			d.bss = t
		case tagItab:
			t := &Itab{}
			t.addr = readUint64(r)
			t.ptr = readBool(r)
			d.itabs = append(d.itabs, t)
		case tagOSThread:
			t := &OSThread{}
			t.addr = readUint64(r)
			t.id = readUint64(r)
			t.procid = readUint64(r)
			d.osthreads = append(d.osthreads, t)
		case tagMemStats:
			t := &runtime.MemStats{}
			t.Alloc = readUint64(r)
			t.TotalAlloc = readUint64(r)
			t.Sys = readUint64(r)
			t.Lookups = readUint64(r)
			t.Mallocs = readUint64(r)
			t.Frees = readUint64(r)
			t.HeapAlloc = readUint64(r)
			t.HeapSys = readUint64(r)
			t.HeapIdle = readUint64(r)
			t.HeapInuse = readUint64(r)
			t.HeapReleased = readUint64(r)
			t.HeapObjects = readUint64(r)
			t.StackInuse = readUint64(r)
			t.StackSys = readUint64(r)
			t.MSpanInuse = readUint64(r)
			t.MSpanSys = readUint64(r)
			t.MCacheInuse = readUint64(r)
			t.MCacheSys = readUint64(r)
			t.BuckHashSys = readUint64(r)
			t.GCSys = readUint64(r)
			t.OtherSys = readUint64(r)
			t.NextGC = readUint64(r)
			t.LastGC = readUint64(r)
			t.PauseTotalNs = readUint64(r)
			for i := 0; i < 256; i++ {
				t.PauseNs[i] = readUint64(r)
			}
			t.NumGC = uint32(readUint64(r))
			d.memstats = t
		case tagDefer:
			t := &Defer{}
			t.addr = readUint64(r)
			t.gp = readUint64(r)
			t.argp = readUint64(r)
			t.pc = readUint64(r)
			t.fn = readUint64(r)
			t.code = readUint64(r)
			t.link = readUint64(r)
			d.defers = append(d.defers, t)
		case tagPanic:
			t := &Panic{}
			t.addr = readUint64(r)
			t.gp = readUint64(r)
			t.typ = readUint64(r)
			t.data = readUint64(r)
			t.defr = readUint64(r)
			t.link = readUint64(r)
			d.panics = append(d.panics, t)
		default:
			log.Fatal("unknown record kind %d", kind)
		}
	}
}

func getDwarf(execname string) *dwarf.Data {
	e, err := elf.Open(execname)
	if err == nil {
		defer e.Close()
		d, err := e.DWARF()
		if err == nil {
			return d
		}
	}
	m, err := macho.Open(execname)
	if err == nil {
		defer m.Close()
		d, err := m.DWARF()
		if err == nil {
			return d
		}
	}
	p, err := pe.Open(execname)
	if err == nil {
		defer p.Close()
		d, err := p.DWARF()
		if err == nil {
			return d
		}
	}
	log.Fatal("can't get dwarf info from executable", err)
	return nil
}

func readUleb(b []byte) ([]byte, uint64) {
	r := uint64(0)
	s := uint(0)
	for {
		x := b[0]
		b = b[1:]
		r |= uint64(x&127) << s
		if x&128 == 0 {
			break
		}
		s += 7

	}
	return b, r
}
func readSleb(b []byte) ([]byte, int64) {
	c, v := readUleb(b)
	// sign extend
	k := (len(b) - len(c)) * 7
	return c, int64(v) << uint(64-k) >> uint(64-k)
}

type dwarfType interface {
	// Name returns the name of this type
	Name() string
	// Size returns the size of this type in bytes
	Size() uint64
	// Fields returns a map from the offset within the object to
	// the name of the field at that offset.  Returns nil if
	// there is a single unnamed field at offset 0.
	Fields() map[uint64]string
}
type dwarfTypeImpl struct {
	name string
	size uint64
}
type dwarfBaseType struct {
	dwarfTypeImpl
}
type dwarfTypedef struct {
	dwarfTypeImpl
	type_ dwarfType
}
type dwarfStructType struct {
	dwarfTypeImpl
	members []dwarfTypeMember
	fields  map[uint64]string
}
type dwarfTypeMember struct {
	name   string
	offset uint64
	type_  dwarfType
}
type dwarfPtrType struct {
	dwarfTypeImpl
	elem dwarfType
}
type dwarfArrayType struct {
	dwarfTypeImpl
	elem   dwarfType
	fields map[uint64]string
}
type dwarfFuncType struct {
	dwarfTypeImpl
}

func (t *dwarfTypeImpl) Name() string {
	return t.name
}
func (t *dwarfTypeImpl) Size() uint64 {
	return t.size
}
func (t *dwarfTypeImpl) Fields() map[uint64]string {
	return nil
}
func (t *dwarfTypedef) Fields() map[uint64]string {
	return t.type_.Fields()
}
func (t *dwarfTypedef) Size() uint64 {
	return t.type_.Size()
}
func (t *dwarfStructType) Fields() map[uint64]string {
	// don't look inside strings, interfaces, slices
	if t.name == "string" || t.name == "runtime.iface" || len(t.name) >= 2 && t.name[:2] == "[]" {
		return nil
	}
	if t.fields != nil {
		return t.fields
	}
	t.fields = make(map[uint64]string)
	for _, m := range t.members {
		f := m.type_.Fields()
		if f == nil {
			t.fields[m.offset] = m.name
		} else {
			for k, v := range f {
				t.fields[m.offset+k] = fmt.Sprintf("%s.%s", m.name, v)
			}
		}
	}
	return t.fields
}
func (t *dwarfArrayType) Fields() map[uint64]string {
	if t.fields != nil {
		return t.fields
	}
	t.fields = make(map[uint64]string)
	f := t.elem.Fields()
	e := t.elem.Size()
	if e == 0 {
		return t.fields
	}
	n := t.Size() / e
	for i := uint64(0); i < n; i++ {
		if f == nil {
			t.fields[i*e] = fmt.Sprintf("%d", i)
		} else {
			for k, v := range f {
				t.fields[i*e+k] = fmt.Sprintf("%d.%s", i, v)
			}
		}
	}
	return t.fields
}

// Some type names in the dwarf info don't match the corresponding
// type names in the binary.  We'll use the rewrites here to map
// between the two.
// TODO: just struct names for now.  Rename this?
type adjTypeName struct {
	matcher   *regexp.Regexp
	formatter string
}

var adjTypeNames = []adjTypeName{
	{regexp.MustCompile(`hash<(.*),(.*)>`), "map.hdr[%s]%s"},
	{regexp.MustCompile(`bucket<(.*),(.*)>`), "map.bucket[%s]%s"},
}

// load a map of all of the dwarf types
func typeMap(d *Dump, w *dwarf.Data) map[dwarf.Offset]dwarfType {
	t := make(map[dwarf.Offset]dwarfType)

	// pass 1: make a dwarfType for all of the types in the file
	r := w.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			log.Fatal(err)
		}
		if e == nil {
			break
		}
		switch e.Tag {
		case dwarf.TagBaseType:
			x := new(dwarfBaseType)
			x.name = e.Val(dwarf.AttrName).(string)
			x.size = uint64(e.Val(dwarf.AttrByteSize).(int64))
			t[e.Offset] = x
		case dwarf.TagPointerType:
			x := new(dwarfPtrType)
			x.name = e.Val(dwarf.AttrName).(string)
			x.size = d.ptrSize
			t[e.Offset] = x
		case dwarf.TagStructType:
			x := new(dwarfStructType)
			x.name = e.Val(dwarf.AttrName).(string)
			x.size = uint64(e.Val(dwarf.AttrByteSize).(int64))
			for _, a := range adjTypeNames {
				if k := a.matcher.FindStringSubmatch(x.name); k != nil {
					var i []interface{}
					for _, j := range k[1:] {
						i = append(i, j)
					}
					x.name = fmt.Sprintf(a.formatter, i...)
				}
			}
			t[e.Offset] = x
		case dwarf.TagArrayType:
			x := new(dwarfArrayType)
			x.name = e.Val(dwarf.AttrName).(string)
			x.size = uint64(e.Val(dwarf.AttrByteSize).(int64))
			t[e.Offset] = x
		case dwarf.TagTypedef:
			x := new(dwarfTypedef)
			x.name = e.Val(dwarf.AttrName).(string)
			t[e.Offset] = x
		case dwarf.TagSubroutineType:
			x := new(dwarfFuncType)
			x.name = e.Val(dwarf.AttrName).(string)
			t[e.Offset] = x
		}
	}

	// pass 2: fill in / link up the types
	r = w.Reader()
	var currentStruct *dwarfStructType
	for {
		e, err := r.Next()
		if err != nil {
			log.Fatal(err)
		}
		if e == nil {
			break
		}
		switch e.Tag {
		case dwarf.TagTypedef:
			t[e.Offset].(*dwarfTypedef).type_ = t[e.Val(dwarf.AttrType).(dwarf.Offset)]
			if t[e.Offset].(*dwarfTypedef).type_ == nil {
				log.Fatalf("can't find referent for %s %d\n", t[e.Offset].(*dwarfTypedef).name, e.Val(dwarf.AttrType).(dwarf.Offset))
			}
		case dwarf.TagPointerType:
			i := e.Val(dwarf.AttrType)
			if i != nil {
				t[e.Offset].(*dwarfPtrType).elem = t[i.(dwarf.Offset)]
			}
			// The only nil cases are unsafe.Pointer and reflect.iword
		case dwarf.TagArrayType:
			t[e.Offset].(*dwarfArrayType).elem = t[e.Val(dwarf.AttrType).(dwarf.Offset)]
		case dwarf.TagStructType:
			currentStruct = t[e.Offset].(*dwarfStructType)
		case dwarf.TagMember:
			name := e.Val(dwarf.AttrName).(string)
			type_ := t[e.Val(dwarf.AttrType).(dwarf.Offset)]
			loc := e.Val(dwarf.AttrDataMemberLoc).([]uint8)
			var offset uint64
			if len(loc) == 0 {
				offset = 0
			} else if len(loc) >= 2 && loc[0] == dw_op_consts && loc[len(loc)-1] == dw_op_plus {
				loc, offset = readUleb(loc[1 : len(loc)-1])
				if len(loc) != 0 {
					break
				}
			}
			currentStruct.members = append(currentStruct.members, dwarfTypeMember{name, offset, type_})
		}
	}
	return t
}

type localKey struct {
	funcname string
	offset   uint64 // distance down from frame pointer
}

// Makes a map from <function name, distance before top of frame> to name of field.
func localsMap(d *Dump, w *dwarf.Data, t map[dwarf.Offset]dwarfType) map[localKey]string {
	m := make(map[localKey]string, 0)
	r := w.Reader()
	var funcname string
	for {
		e, err := r.Next()
		if err != nil {
			log.Fatal(err)
		}
		if e == nil {
			break
		}
		switch e.Tag {
		case dwarf.TagSubprogram:
			funcname = e.Val(dwarf.AttrName).(string)
		case dwarf.TagVariable:
			name := e.Val(dwarf.AttrName).(string)
			typ := t[e.Val(dwarf.AttrType).(dwarf.Offset)]
			loc := e.Val(dwarf.AttrLocation).([]uint8)
			if len(loc) == 0 || loc[0] != dw_op_call_frame_cfa {
				break
			}
			var offset int64
			if len(loc) == 1 {
				offset = 0
			} else if len(loc) >= 3 && loc[1] == dw_op_consts && loc[len(loc)-1] == dw_op_plus {
				loc, offset = readSleb(loc[2 : len(loc)-1])
				if len(loc) != 0 {
					break
				}
			}
			f := typ.Fields()
			if f == nil {
				m[localKey{funcname, uint64(-offset)}] = name
			} else {
				for k, v := range f {
					m[localKey{funcname, uint64(-offset) - k}] = fmt.Sprintf("%s.%s", name, v)
				}
			}
		}
	}
	return m
}

// argsMap returns a map from function name to a *Heap.  The heap
// contains pairs (x,y) where x is the distance above parentaddr of
// the start of that variable, and y is the name of the variable.
func argsMap(d *Dump, w *dwarf.Data) map[string]*Heap {
	return nil
}

// map from global address to name of field at that address
func globalsMap(d *Dump, w *dwarf.Data, t map[dwarf.Offset]dwarfType) *Heap {
	h := new(Heap)
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
		typ := t[e.Val(dwarf.AttrType).(dwarf.Offset)]
		locexpr := e.Val(dwarf.AttrLocation).([]uint8)
		if len(locexpr) == 0 || locexpr[0] != dw_op_addr {
			continue
		}
		loc := readPtr(d, locexpr[1:])
		if typ == nil {
			// lots of non-Go global symbols hit here (rodata, reflect.cvtFloat·f, ...)
			h.Insert(loc, "~"+name)
			continue
		}
		f := typ.Fields()
		if f == nil {
			h.Insert(loc, name)
		} else {
			for k, v := range f {
				h.Insert(loc+k, fmt.Sprintf("%s.%s", name, v))
			}
		}
	}
	return h
}

// various maps used to link up data structures
type LinkInfo struct {
	dump    *Dump
	types   map[uint64]*Type
	itabs   map[uint64]*Itab
	objects *Heap
}

// stack frames may be zero-sized, so we add call depth
// to the key to ensure uniqueness.
type frameKey struct {
	sp    uint64
	depth uint64
}

func (info *LinkInfo) findObj(addr uint64) *Object {
	_, xi := info.objects.Lookup(addr)
	if xi == nil {
		return nil
	}
	x := xi.(*Object)
	if addr >= x.addr+uint64(len(x.data)) {
		return nil
	}
	return x
}

// appendEdge might add an edge to edges.  Returns new edges.
//   Requires data[off:] be a pointer
//   Adds an edge if that pointer points to a valid object.
func (info *LinkInfo) appendEdge(edges []Edge, data []byte, off uint64, f Field, arrayidx int64) []Edge {
	p := readPtr(info.dump, data[off:])
	q := info.findObj(p)
	if q != nil {
		var fieldoffset uint64 // TODO
		fieldname := f.name
		if arrayidx >= 0 {
			if fieldname != "" {
				fieldname = fmt.Sprintf("%d.%s", arrayidx, fieldname)
			} else {
				fieldname = fmt.Sprintf("%d", arrayidx)
			}
		}
		edges = append(edges, Edge{q, off, p - q.addr, fieldname, fieldoffset})
	}
	return edges
}

func (info *LinkInfo) appendFields(edges []Edge, data []byte, fields []Field, offset uint64, arrayidx int64) []Edge {
	for _, f := range fields {
		off := offset + f.offset
		if off >= uint64(len(data)) {
			// TODO: what the heck is this?
			continue
		}
		switch f.kind {
		case fieldKindPtr:
			edges = info.appendEdge(edges, data, off, f, arrayidx)
		case fieldKindString:
			edges = info.appendEdge(edges, data, off, f, arrayidx)
		case fieldKindSlice:
			edges = info.appendEdge(edges, data, off, f, arrayidx)
		case fieldKindEface:
			edges = info.appendEdge(edges, data, off, f, arrayidx)
			tp := readPtr(info.dump, data[off:])
			if tp != 0 {
				t := info.types[tp]
				if t == nil {
					log.Fatal("can't find eface type")
				}
				if t.efaceptr {
					edges = info.appendEdge(edges, data, off+info.dump.ptrSize, f, arrayidx)
				}
			}
		case fieldKindIface:
			tp := readPtr(info.dump, data[off:])
			if tp != 0 {
				t := info.itabs[tp]
				if t == nil {
					log.Fatal("can't find iface tab")
				}
				if t.ptr {
					edges = info.appendEdge(edges, data, off+info.dump.ptrSize, f, arrayidx)
				}
			}
		}
	}
	return edges
}

// Names the fields it can for better debugging output
func namefields(d *Dump, execname string) {
	w := getDwarf(execname)
	t := typeMap(d, w)

	// name fields fields in all types
	// TODO: what about identically named types?  There doesn't seem to be
	// any way to 1-1 match up runtime types and dwarf types if two types
	// have the same name.
	m := make(map[string]dwarfType)
	for _, x := range t {
		m[x.Name()] = x
	}
	for _, t := range d.types {
		dt := m[t.name]
		if dt == nil {
			continue
		}
		for i, f := range t.fields {
			t.fields[i].name = dt.Fields()[f.offset]
		}
	}

	// name all frame fields
	locals := localsMap(d, w, t)
	for _, r := range d.frames {
		for i, f := range r.fields {
			name := locals[localKey{r.name, uint64(len(r.data)) - f.offset}]
			if name == "" {
				name = fmt.Sprintf("~%d", f.offset)
			}
			r.fields[i].name = name
		}
	}
	// TODO: argsmap

	// naming for globals
	globals := globalsMap(d, w, t)
	for _, x := range []*Data{d.data, d.bss} {
		for i, f := range x.fields {
			addr := x.addr + f.offset
			a, v := globals.Lookup(addr)
			if v == nil {
				continue
			}
			name := v.(string)
			if a != addr {
				name = fmt.Sprintf("%s:%d", name, addr-a)
			}
			x.fields[i].name = name
		}
	}
}

func link(d *Dump) {
	// initialize some maps used for linking
	var info LinkInfo
	info.dump = d
	info.types = make(map[uint64]*Type, len(d.types))
	info.itabs = make(map[uint64]*Itab, len(d.itabs))
	for _, x := range d.types {
		// Note: there may be duplicate type records in a dump.
		// The duplicates get thrown away here.
		info.types[x.addr] = x
	}
	for _, x := range d.itabs {
		info.itabs[x.addr] = x
	}
	frames := make(map[frameKey]*StackFrame, len(d.frames))
	for _, x := range d.frames {
		frames[frameKey{x.addr, x.depth}] = x
	}

	// Binary-searchable map of objects
	info.objects = &Heap{}
	for _, x := range d.objects {
		info.objects.Insert(x.addr, x)
	}

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

	// link stack frames to objects
	for _, f := range d.frames {
		f.edges = info.appendFields(f.edges, f.data, f.fields, 0, -1)
	}

	// link up frames in sequence
	for _, f := range d.frames {
		if f.depth == 0 {
			continue
		}
		g := frames[frameKey{f.childaddr, f.depth - 1}]
		g.parent = f
	}

	// link goroutines to frames & vice versa
	for _, g := range d.goroutines {
		g.bos = frames[frameKey{g.bosaddr, 0}]
		if g.bos == nil {
			log.Fatal("bos missing")
		}
		for f := g.bos; f != nil; f = f.parent {
			f.goroutine = g
		}
		x := info.findObj(g.ctxtaddr)
		if x != nil {
			g.ctxt = x
		}
	}

	// link data roots
	for _, x := range []*Data{d.data, d.bss} {
		x.edges = info.appendFields(x.edges, x.data, x.fields, 0, -1)
	}

	// link other roots
	for _, r := range d.otherroots {
		x := info.findObj(r.toaddr)
		if x != nil {
			r.e = Edge{x, 0, r.toaddr - x.addr, "", 0}
		}
	}

	// link objects to each other
	for _, x := range d.objects {
		t := x.typ
		if t == nil && x.kind != typeKindConservative {
			continue // typeless objects have no pointers
		}
		switch x.kind {
		case typeKindObject:
			x.edges = info.appendFields(x.edges, x.data, t.fields, 0, -1)
		case typeKindArray:
			for i := uint64(0); i <= uint64(len(x.data))-t.size; i += t.size {
				x.edges = info.appendFields(x.edges, x.data, t.fields, i, int64(i/t.size))
			}
		case typeKindChan:
			for i := d.hChanSize; i <= uint64(len(x.data))-t.size; i += t.size {
				x.edges = info.appendFields(x.edges, x.data, t.fields, i, int64(i/t.size))
			}
		case typeKindConservative:
			for i := uint64(0); i < uint64(len(x.data)); i += d.ptrSize {
				x.edges = info.appendEdge(x.edges, x.data, i, Field{fieldKindPtr, i, fmt.Sprintf("~%d", i)}, -1)
			}
		}
	}

	// Add links for finalizers
	for _, f := range d.finalizers {
		x := info.findObj(f.obj)
		for _, addr := range []uint64{f.fn, f.fint, f.ot} {
			y := info.findObj(addr)
			if x != nil && y != nil {
				x.edges = append(x.edges, Edge{y, 0, addr - y.addr, "finalizer", 0})
			}
		}
	}
	for _, f := range d.qfinal {
		for _, addr := range []uint64{f.obj, f.fn, f.fint, f.ot} {
			x := info.findObj(addr)
			if x != nil {
				f.edges = append(f.edges, Edge{x, 0, addr - x.addr, "", 0})
			}
		}
	}
}

func Read(dumpname, execname string) *Dump {
	d := rawRead(dumpname)
	namefields(d, execname)
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
		log.Fatal("unsupported order=%v ptrSize=%d", d.order, d.ptrSize)
		return 0
	}
}
