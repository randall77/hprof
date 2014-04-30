package read

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime"
	"sort"
)

type FieldKind int
type TypeKind int

const (
	FieldKindEol    FieldKind = 0
	FieldKindPtr              = 1
	FieldKindString           = 2
	FieldKindSlice            = 3
	FieldKindIface            = 4
	FieldKindEface            = 5

	FieldKindBool       FieldKind = 6
	FieldKindUInt8                = 7
	FieldKindSInt8                = 8
	FieldKindUInt16               = 9
	FieldKindSInt16               = 10
	FieldKindUInt32     FieldKind = 11
	FieldKindSInt32               = 12
	FieldKindUInt64     FieldKind = 13
	FieldKindSInt64               = 14
	FieldKindFloat32              = 15
	FieldKindFloat64              = 16
	FieldKindComplex64            = 17
	FieldKindComplex128           = 18

	FieldKindBytes8  = 19
	FieldKindBytes16 = 20

	TypeKindObject       TypeKind = 0
	TypeKindArray                 = 1
	TypeKindChan                  = 2
	TypeKindConservative          = 127

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
	dw_ate_boolean       = 2
	dw_ate_complex_float = 3 // complex64/complex128
	dw_ate_float         = 4 // float32/float64
	dw_ate_signed        = 5 // int8/int16/int32/int64/int
	dw_ate_unsigned      = 7 // uint8/uint16/uint32/uint64/uint/uintptr

	// Size of buckets for findObj.  Bigger buckets use less memory
	// but make findObj take longer.  256 byte buckets use about 3%
	// of the total heap size and require us to look at at most
	// 32 objects.
	bucketSize = 256
)

type Dump struct {
	Order      binary.ByteOrder
	PtrSize    uint64 // in bytes
	HChanSize  uint64 // channel header size in bytes
	HeapStart  uint64
	HeapEnd    uint64
	TheChar    byte
	Experiment string
	Ncpu       uint64
	Types      []*Type
	Objects    []*Object
	Frames     []*StackFrame
	Goroutines []*GoRoutine
	Otherroots []*OtherRoot
	Finalizers []*Finalizer  // pending finalizers, object still live
	QFinal     []*QFinalizer // finalizers which are ready to run
	Osthreads  []*OSThread
	Memstats   *runtime.MemStats
	Data       *Data
	Bss        *Data
	Defers     []*Defer
	Panics     []*Panic

	// handle to dump file
	r io.ReaderAt

	buf []byte // temporary space for Contents calls

	edges []Edge // temporary space for Edges calls

	// list of full types, indexed by ID
	FTList []*FullType

	// map from type address to type
	TypeMap map[uint64]*Type

	// map from itab address whether the data field of an iface
	// with that itab contains a pointer.
	ItabMap map[uint64]bool

	// array for fast lookup of objects
	// maps (addr - HeapStart) / bucketSize to the first object
	// that starts in those bucketSize bytes.
	// with 8 byte ints this will consume ~3% of the dump's heap size
	idx []int
}

type Type struct {
	Name     string // not necessarily unique
	Size     uint64
	efaceptr bool    // Efaces with this type have a data field which is a pointer
	Fields   []Field // ordered in increasing offset order

	Addr uint64
}

type FullType struct {
	Id     int
	Typ    *Type
	Kind   TypeKind
	Size   uint64
	Name   string
	Fields []Field
}

// An edge is a directed connection between two objects.  The source
// object is implicit.  An edge includes information about where it
// leaves the source object and where it lands in the destination obj.
type Edge struct {
	To         ObjId  // index of target object in array
	FromOffset uint64 // offset in source object where ptr was found
	ToOffset   uint64 // offset in destination object where ptr lands

	// name of field in the source object, if known
	FieldName string
}

// Object represents an object in the heap.
// There will be a lot of these.  They need to be small.
type Object struct {
	Ft     *FullType
	offset int64 // position of object contents in dump file
	Addr   uint64
}

type ObjId int

const (
	ObjNil ObjId = -1
)

func (d *Dump) Contents(i ObjId) []byte {
	x := d.Objects[i]
	b := d.buf
	if uint64(cap(b)) < x.Ft.Size {
		b = make([]byte, x.Ft.Size)
		d.buf = b
	}
	b = b[:x.Ft.Size]
	n, err := d.r.ReadAt(b, x.offset)
	if err != nil && !(n == len(b) && err == io.EOF) {
		// TODO: propagate to caller
		log.Fatal(err)
	}
	return b
}
func (d *Dump) Addr(x ObjId) uint64 {
	return d.Objects[x].Addr
}
func (d *Dump) Size(x ObjId) uint64 {
	return d.Objects[x].Ft.Size
}
func (d *Dump) Ft(x ObjId) *FullType {
	return d.Objects[x].Ft
}

// findObj returns the object id containing the address addr, or -1 if no object contains addr.
func (d *Dump) findObj(addr uint64) ObjId {
	if addr < d.HeapStart || addr >= d.HeapEnd { // quick exit.  Includes nil.
		return ObjNil
	}
	// linear search among all the objects that map to the same bucketSize byte bucket.
	for i := d.idx[(addr-d.HeapStart)/bucketSize]; i < len(d.Objects); i++ {
		x := d.Objects[i]
		if addr < x.Addr {
			return ObjNil
		}
		if addr < x.Addr+x.Ft.Size {
			return ObjId(i)
		}
	}
	return ObjNil
}

func (d *Dump) Edges(i ObjId) []Edge {
	x := d.Objects[i]
	e := d.edges[:0]
	b := d.Contents(i)
	for _, f := range x.Ft.Fields {
		switch f.Kind {
		case FieldKindPtr, FieldKindString, FieldKindSlice:
			p := readPtr(d, b[f.Offset:])
			y := d.findObj(p)
			if y != ObjNil {
				e = append(e, Edge{y, f.Offset, p - d.Objects[y].Addr, f.Name})
			}
		case FieldKindEface:
			taddr := readPtr(d, b[f.Offset:])
			if taddr != 0 {
				t := d.TypeMap[taddr]
				if t == nil {
					log.Fatal("can't find eface type", taddr)
				}
				if t.efaceptr {
					p := readPtr(d, b[f.Offset+d.PtrSize:])
					y := d.findObj(p)
					if y != ObjNil {
						e = append(e, Edge{y, f.Offset + d.PtrSize, p - d.Objects[y].Addr, f.Name})
					}
				}
			}
		case FieldKindIface:
			itabaddr := readPtr(d, b[f.Offset:])
			if itabaddr != 0 {
				ptr, ok := d.ItabMap[itabaddr]
				if !ok {
					log.Fatal("can't find itab", itabaddr)
				}
				if ptr {
					p := readPtr(d, b[f.Offset+d.PtrSize:])
					y := d.findObj(p)
					if y != ObjNil {
						e = append(e, Edge{y, f.Offset + d.PtrSize, p - d.Objects[y].Addr, f.Name})
					}
				}
			}
		default:
			continue
		}
	}
	d.edges = e
	return e
}

type OtherRoot struct {
	Description string
	E           Edge

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
	Edges []Edge
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
	Addr   uint64
	Data   []byte
	Fields []Field
	Edges  []Edge
}

type OSThread struct {
	addr   uint64
	id     uint64
	procid uint64
}

// A Field is a location in an object where there
// might be a pointer.
type Field struct {
	Kind   FieldKind
	Offset uint64
	Name   string
}

type GoRoutine struct {
	Bos  *StackFrame // frame at the top of the stack (i.e. currently running)
	Ctxt ObjId

	Addr         uint64
	bosaddr      uint64
	Goid         uint64
	Gopc         uint64
	Status       uint64
	IsSystem     bool
	IsBackground bool
	WaitSince    uint64
	WaitReason   string
	ctxtaddr     uint64
	maddr        uint64
	deferaddr    uint64
	panicaddr    uint64
}

type StackFrame struct {
	Name      string
	Parent    *StackFrame
	Goroutine *GoRoutine
	Depth     uint64
	Data      []byte
	Edges     []Edge

	Addr      uint64
	childaddr uint64
	entry     uint64
	pc        uint64
	Fields    []Field
}

// both an io.Reader and an io.ByteReader
type Reader interface {
	Read(p []byte) (n int, err error)
	ReadByte() (c byte, err error)
}

func readUint64(r Reader) uint64 {
	x, err := binary.ReadUvarint(r)
	if err != nil {
		log.Fatal(err)
	}
	return x
}

func readNBytes(r Reader, n uint64) []byte {
	s := make([]byte, n)
	_, err := io.ReadFull(r, s)
	if err != nil {
		log.Fatal(err)
	}
	return s
}

func readBytes(r Reader) []byte {
	n := readUint64(r)
	return readNBytes(r, n)
}

func readString(r Reader) string {
	return string(readBytes(r))
}

func readBool(r Reader) bool {
	b, err := r.ReadByte()
	if err != nil {
		log.Fatal(err)
	}
	return b != 0
}

func readFields(r Reader) []Field {
	var x []Field
	for {
		kind := FieldKind(readUint64(r))
		if kind == FieldKindEol {
			// TODO: sort by offset, or check that it is sorted
			return x
		}
		x = append(x, Field{Kind: kind, Offset: readUint64(r)})
	}
}

// A Reader that can tell you its current offset in the file.
type myReader struct {
	r   *bufio.Reader
	cnt int64
}

func (r *myReader) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	r.cnt += int64(n)
	return
}
func (r *myReader) ReadByte() (c byte, err error) {
	c, err = r.r.ReadByte()
	if err != nil {
		return
	}
	r.cnt++
	return
}
func (r *myReader) ReadLine() (line []byte, isPrefix bool, err error) {
	line, isPrefix, err = r.r.ReadLine()
	r.cnt += int64(len(line)) + 1
	return
}
func (r *myReader) Skip(n int64) error {
	k, err := io.CopyN(ioutil.Discard, r.r, n)
	r.cnt += k
	return err
}
func (r *myReader) Count() int64 {
	return r.cnt
}

type tkey struct {
	typaddr uint64
	kind    TypeKind
	size    uint64
}

func (d *Dump) makeFullType(typaddr uint64, kind TypeKind, size uint64) *FullType {
	t := d.TypeMap[typaddr]
	if typaddr != 0 && t == nil {
		log.Fatal("types appear before use of that type")
	}
	var name string
	switch kind {
	case TypeKindObject:
		if t != nil {
			name = t.Name
		} else {
			name = fmt.Sprintf("noptr%d", size)
		}
	case TypeKindArray:
		name = fmt.Sprintf("{%d}%s", size/t.Size, t.Name)
	case TypeKindChan:
		if d.HChanSize == 0 {
			log.Fatal("hchansize must be before objects")
		}
		if t.Size > 0 {
			name = fmt.Sprintf("chan{%d}%s", (size-d.HChanSize)/t.Size, t.Name)
		} else {
			name = fmt.Sprintf("chan{inf}%s", t.Name)
		}
	case TypeKindConservative:
		name = fmt.Sprintf("conservative%d", size)
	}
	ft := &FullType{len(d.FTList), t, kind, size, name, nil}
	d.FTList = append(d.FTList, ft)
	return ft
}

// Reads heap dump into memory.
func rawRead(filename string) *Dump {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	r := &myReader{r: bufio.NewReader(file)}

	// check for header
	hdr, prefix, err := r.ReadLine()
	if err != nil {
		log.Fatal(err)
	}
	if prefix || string(hdr) != "go1.3 heap dump" {
		log.Fatal("not a go1.3 heap dump file")
	}

	var d Dump
	d.r = file
	d.ItabMap = map[uint64]bool{}
	d.TypeMap = map[uint64]*Type{}
	ftmap := map[tkey]*FullType{} // full type dedup
	for {
		kind := readUint64(r)
		switch kind {
		case tagObject:
			obj := &Object{}
			obj.Addr = readUint64(r)
			typaddr := readUint64(r)
			kind := TypeKind(readUint64(r))
			size := readUint64(r)
			k := tkey{typaddr, kind, size}
			ft := ftmap[k]
			if ft == nil {
				ft = d.makeFullType(typaddr, kind, size)
				ftmap[k] = ft
			}
			obj.Ft = ft
			obj.offset = r.Count()
			r.Skip(int64(ft.Size))
			d.Objects = append(d.Objects, obj)
		case tagEOF:
			return &d
		case tagOtherRoot:
			t := &OtherRoot{}
			t.Description = readString(r)
			t.toaddr = readUint64(r)
			d.Otherroots = append(d.Otherroots, t)
		case tagType:
			typ := &Type{}
			typ.Addr = readUint64(r)
			typ.Size = readUint64(r)
			typ.Name = readString(r)
			typ.efaceptr = readBool(r)
			typ.Fields = readFields(r)
			// Note: there may be duplicate type records in a dump.
			// The duplicates get thrown away here.
			if _, ok := d.TypeMap[typ.Addr]; !ok {
				d.TypeMap[typ.Addr] = typ
				d.Types = append(d.Types, typ)
			}
		case tagGoRoutine:
			g := &GoRoutine{}
			g.Addr = readUint64(r)
			g.bosaddr = readUint64(r)
			g.Goid = readUint64(r)
			g.Gopc = readUint64(r)
			g.Status = readUint64(r)
			g.IsSystem = readBool(r)
			g.IsBackground = readBool(r)
			g.WaitSince = readUint64(r)
			g.WaitReason = readString(r)
			g.ctxtaddr = readUint64(r)
			g.maddr = readUint64(r)
			g.deferaddr = readUint64(r)
			g.panicaddr = readUint64(r)
			d.Goroutines = append(d.Goroutines, g)
		case tagStackFrame:
			t := &StackFrame{}
			t.Addr = readUint64(r)
			t.Depth = readUint64(r)
			t.childaddr = readUint64(r)
			t.Data = readBytes(r)
			t.entry = readUint64(r)
			t.pc = readUint64(r)
			t.Name = readString(r)
			t.Fields = readFields(r)
			d.Frames = append(d.Frames, t)
		case tagParams:
			if readUint64(r) == 0 {
				d.Order = binary.LittleEndian
			} else {
				d.Order = binary.BigEndian
			}
			d.PtrSize = readUint64(r)
			d.HChanSize = readUint64(r)
			d.HeapStart = readUint64(r)
			d.HeapEnd = readUint64(r)
			d.TheChar = byte(readUint64(r))
			d.Experiment = readString(r)
			d.Ncpu = readUint64(r)
		case tagFinalizer:
			t := &Finalizer{}
			t.obj = readUint64(r)
			t.fn = readUint64(r)
			t.code = readUint64(r)
			t.fint = readUint64(r)
			t.ot = readUint64(r)
			d.Finalizers = append(d.Finalizers, t)
		case tagQFinal:
			t := &QFinalizer{}
			t.obj = readUint64(r)
			t.fn = readUint64(r)
			t.code = readUint64(r)
			t.fint = readUint64(r)
			t.ot = readUint64(r)
			d.QFinal = append(d.QFinal, t)
		case tagData:
			t := &Data{}
			t.Addr = readUint64(r)
			t.Data = readBytes(r)
			t.Fields = readFields(r)
			d.Data = t
		case tagBss:
			t := &Data{}
			t.Addr = readUint64(r)
			t.Data = readBytes(r)
			t.Fields = readFields(r)
			d.Bss = t
		case tagItab:
			addr := readUint64(r)
			ptr := readBool(r)
			d.ItabMap[addr] = ptr
		case tagOSThread:
			t := &OSThread{}
			t.addr = readUint64(r)
			t.id = readUint64(r)
			t.procid = readUint64(r)
			d.Osthreads = append(d.Osthreads, t)
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
			d.Memstats = t
		case tagDefer:
			t := &Defer{}
			t.addr = readUint64(r)
			t.gp = readUint64(r)
			t.argp = readUint64(r)
			t.pc = readUint64(r)
			t.fn = readUint64(r)
			t.code = readUint64(r)
			t.link = readUint64(r)
			d.Defers = append(d.Defers, t)
		case tagPanic:
			t := &Panic{}
			t.addr = readUint64(r)
			t.gp = readUint64(r)
			t.typ = readUint64(r)
			t.data = readUint64(r)
			t.defr = readUint64(r)
			t.link = readUint64(r)
			d.Panics = append(d.Panics, t)
		default:
			log.Fatal("unknown record kind ", kind)
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

func joinNames(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return fmt.Sprintf("%s.%s", a, b)
}

type dwarfType interface {
	// Name returns the name of this type
	Name() string
	// Size returns the size of this type in bytes
	Size() uint64
	// Fields returns a list of fields within the object, in increasing offset order.
	Fields() []Field
}
type dwarfTypeImpl struct {
	name   string
	size   uint64
	fields []Field
}
type dwarfBaseType struct {
	dwarfTypeImpl
	encoding int64
}
type dwarfTypedef struct {
	dwarfTypeImpl
	type_ dwarfType
}
type dwarfStructType struct {
	dwarfTypeImpl
	members []dwarfTypeMember
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
	elem dwarfType
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
func (t *dwarfBaseType) Fields() []Field {
	if t.fields != nil {
		return t.fields
	}
	switch {
	case t.encoding == dw_ate_boolean:
		t.fields = append(t.fields, Field{FieldKindBool, 0, ""})
	case t.encoding == dw_ate_signed && t.size == 1:
		t.fields = append(t.fields, Field{FieldKindSInt8, 0, ""})
	case t.encoding == dw_ate_unsigned && t.size == 1:
		t.fields = append(t.fields, Field{FieldKindUInt8, 0, ""})
	case t.encoding == dw_ate_signed && t.size == 2:
		t.fields = append(t.fields, Field{FieldKindSInt16, 0, ""})
	case t.encoding == dw_ate_unsigned && t.size == 2:
		t.fields = append(t.fields, Field{FieldKindUInt16, 0, ""})
	case t.encoding == dw_ate_signed && t.size == 4:
		t.fields = append(t.fields, Field{FieldKindSInt32, 0, ""})
	case t.encoding == dw_ate_unsigned && t.size == 4:
		t.fields = append(t.fields, Field{FieldKindUInt32, 0, ""})
	case t.encoding == dw_ate_signed && t.size == 8:
		t.fields = append(t.fields, Field{FieldKindSInt64, 0, ""})
	case t.encoding == dw_ate_unsigned && t.size == 8:
		t.fields = append(t.fields, Field{FieldKindUInt64, 0, ""})
	case t.encoding == dw_ate_float && t.size == 4:
		t.fields = append(t.fields, Field{FieldKindFloat32, 0, ""})
	case t.encoding == dw_ate_float && t.size == 8:
		t.fields = append(t.fields, Field{FieldKindFloat64, 0, ""})
	case t.encoding == dw_ate_complex_float && t.size == 8:
		t.fields = append(t.fields, Field{FieldKindComplex64, 0, ""})
	case t.encoding == dw_ate_complex_float && t.size == 16:
		t.fields = append(t.fields, Field{FieldKindComplex128, 0, ""})
	default:
		log.Fatalf("unknown encoding type encoding=%d size=%d", t.encoding, t.size)
	}
	return t.fields
}
func (t *dwarfTypedef) Fields() []Field {
	return t.type_.Fields()
}
func (t *dwarfTypedef) Size() uint64 {
	return t.type_.Size()
}
func (t *dwarfPtrType) Fields() []Field {
	if t.fields == nil {
		t.fields = append(t.fields, Field{FieldKindPtr, 0, ""})
	}
	return t.fields
}
func (t *dwarfFuncType) Fields() []Field {
	if t.fields == nil {
		t.fields = append(t.fields, Field{FieldKindPtr, 0, ""})
	}
	return t.fields
}

func (t *dwarfStructType) Fields() []Field {
	if t.fields != nil {
		return t.fields
	}
	// Iterate over members, flatten fields.
	// Don't look inside strings, interfaces, slices.
	switch {
	case t.name == "string":
		t.fields = append(t.fields, Field{FieldKindString, 0, ""})
	case t.name == "runtime.iface":
		t.fields = append(t.fields, Field{FieldKindIface, 0, ""})
	case t.name == "runtime.eface":
		t.fields = append(t.fields, Field{FieldKindEface, 0, ""})
	default:
		// Detect slices.  TODO: This could be fooled by the right user
		// code, so find a better way.
		if len(t.members) == 3 &&
			t.members[0].name == "array" &&
			t.members[1].name == "len" &&
			t.members[2].name == "cap" &&
			t.members[0].offset == 0 &&
			t.members[1].offset == t.members[0].type_.Size() &&
			t.members[2].offset == 2*t.members[0].type_.Size() {
			_, aok := t.members[0].type_.(*dwarfPtrType)
			l, lok := t.members[1].type_.(*dwarfBaseType)
			c, cok := t.members[2].type_.(*dwarfBaseType)
			if aok && lok && cok && l.encoding == dw_ate_unsigned && c.encoding == dw_ate_unsigned {
				t.fields = append(t.fields, Field{FieldKindSlice, 0, ""})
				break
			}
		}

		for _, m := range t.members {
			for _, f := range m.type_.Fields() {
				t.fields = append(t.fields, Field{f.Kind, m.offset + f.Offset, joinNames(m.name, f.Name)})
			}
		}
	}
	return t.fields
}
func (t *dwarfArrayType) Fields() []Field {
	if t.fields != nil {
		return t.fields
	}
	s := t.elem.Size()
	if s == 0 {
		return t.fields
	}
	n := t.Size() / s
	fields := t.elem.Fields()
	for i := uint64(0); i < n; i++ {
		for _, f := range fields {
			t.fields = append(t.fields, Field{f.Kind, i*s + f.Offset, joinNames(fmt.Sprintf("%d", i), f.Name)})
		}
	}
	return t.fields
}

// Some type names in the dwarf info don't match the corresponding
// type names in the binary.  We'll use the rewrites here to map
// between the two.
// TODO: just map names for now.  Rename this?  Do this conversion in the dwarf dumper?
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
			x.encoding = e.Val(dwarf.AttrEncoding).(int64)
			t[e.Offset] = x
		case dwarf.TagPointerType:
			x := new(dwarfPtrType)
			x.name = e.Val(dwarf.AttrName).(string)
			x.size = d.PtrSize
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
			x.size = d.PtrSize
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
			for _, f := range typ.Fields() {
				m[localKey{funcname, uint64(-offset) - f.Offset}] = joinNames(name, f.Name)
			}
		}
	}
	return m
}

// Makes a map from <function name, offset in arg area> to name of field.
func argsMap(d *Dump, w *dwarf.Data, t map[dwarf.Offset]dwarfType) map[localKey]string {
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
		case dwarf.TagFormalParameter:
			if e.Val(dwarf.AttrName) == nil {
				continue
			}
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
			for _, f := range typ.Fields() {
				m[localKey{funcname, uint64(offset)}] = joinNames(name, f.Name)
			}
		}
	}
	return m
}

// map from global address to Field at that address
func globalsMap(d *Dump, w *dwarf.Data, t map[dwarf.Offset]dwarfType) *heap {
	h := new(heap)
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
			h.Insert(loc, Field{FieldKindPtr, 0, "~" + name})
			continue
		}
		for _, f := range typ.Fields() {
			h.Insert(loc+f.Offset, Field{f.Kind, 0, joinNames(name, f.Name)})
		}
	}
	return h
}

// stack frames may be zero-sized, so we add call depth
// to the key to ensure uniqueness.
type frameKey struct {
	sp    uint64
	depth uint64
}

// appendEdge might add an edge to edges.  Returns new edges.
//   Requires data[off:] be a pointer
//   Adds an edge if that pointer points to a valid object.
func (d *Dump) appendEdge(edges []Edge, data []byte, off uint64, f Field) []Edge {
	p := readPtr(d, data[off:])
	q := d.findObj(p)
	if q != ObjNil {
		edges = append(edges, Edge{q, off, p - d.Objects[q].Addr, f.Name})
	}
	return edges
}

func (d *Dump) appendFields(edges []Edge, data []byte, fields []Field) []Edge {
	for _, f := range fields {
		off := f.Offset
		if off >= uint64(len(data)) {
			// TODO: what the heck is this?
			continue
		}
		switch f.Kind {
		case FieldKindPtr:
			edges = d.appendEdge(edges, data, off, f)
		case FieldKindString:
			edges = d.appendEdge(edges, data, off, f)
		case FieldKindSlice:
			edges = d.appendEdge(edges, data, off, f)
		case FieldKindEface:
			edges = d.appendEdge(edges, data, off, f)
			tp := readPtr(d, data[off:])
			if tp != 0 {
				t := d.TypeMap[tp]
				if t == nil {
					//log.Fatal("can't find eface type")
					continue
				}
				if t.efaceptr {
					edges = d.appendEdge(edges, data, off+d.PtrSize, f)
				}
			}
		case FieldKindIface:
			tp := readPtr(d, data[off:])
			if tp != 0 {
				if d.ItabMap[tp] {
					edges = d.appendEdge(edges, data, off+d.PtrSize, f)
				}
			}
		}
	}
	return edges
}

// Names the fields it can for better debugging output
func nameWithDwarf(d *Dump, execname string) {
	w := getDwarf(execname)
	t := typeMap(d, w)

	// name fields in all types
	m := make(map[string]dwarfType)
	for _, x := range t {
		m[x.Name()] = x
	}
	for _, t := range d.Types {
		dt := m[t.Name]
		if dt == nil {
			// A type in the dump has no entry in the Dwarf info.
			// This can happen for unexported types, e.g. reflect.ptrGC.
			//log.Printf("type %s has no dwarf info", t.Name)
			continue
		}
		// Check that the Dwarf type is consistent with the type we got from
		// the heap dump.  The heap dump type is the root truth, but it is
		// missing non-pointer-bearing fields and has no field names.  If the
		// Dwarf type is consistent with the heap dump type, then we'll use
		// the fields from the Dwarf type instead.
		consistent := true

		// load Dwarf fields into layout
		df := dt.Fields()
		layout := make(map[uint64]Field)
		for _, f := range df {
			layout[f.Offset] = f
		}
		// A field in the heap dump must match the corresponding Dwarf field
		// in both kind and offset.
		for _, f := range t.Fields {
			if layout[f.Offset].Kind != f.Kind {
				log.Printf("dwarf field kind doesn't match dump kind %s.%d dwarf=%d dump=%d", t.Name, f.Offset, layout[f.Offset].Kind, f.Kind)
				consistent = false
			}
			delete(layout, f.Offset)
		}
		// all remaining fields must not be pointer-containing
		for _, f := range layout {
			switch f.Kind {
			case FieldKindPtr, FieldKindString, FieldKindSlice, FieldKindIface, FieldKindEface:
				log.Printf("dwarf type has additional ptr field %s %d %d", f.Name, f.Offset, f.Kind)
				consistent = false
			}
		}
		if consistent {
			// Dwarf info looks good, overwrite the fields from the dump
			// with fields from the Dwarf info.
			t.Fields = df
		} else {
			log.Print("inconsistent type for", t.Name)
		}
	}

	// link up frames in sequence
	// TODO: already do this later in link
	frames := make(map[frameKey]*StackFrame, len(d.Frames))
	for _, x := range d.Frames {
		frames[frameKey{x.Addr, x.Depth}] = x
	}
	for _, f := range d.Frames {
		if f.Depth == 0 {
			continue
		}
		g := frames[frameKey{f.childaddr, f.Depth - 1}]
		g.Parent = f
	}
	for _, g := range d.Goroutines {
		g.Bos = frames[frameKey{g.bosaddr, 0}]
	}

	// name all frame fields
	locals := localsMap(d, w, t)
	args := argsMap(d, w, t)
	for _, g := range d.Goroutines {
		var c *StackFrame
		for r := g.Bos; r != nil; r = r.Parent {
			for i, f := range r.Fields {
				name := locals[localKey{r.Name, uint64(len(r.Data)) - f.Offset}]
				if name == "" && c != nil {
					name = args[localKey{c.Name, f.Offset}]
					if name != "" {
						name = "outarg." + name
					}
				}
				if name == "" {
					name = fmt.Sprintf("~%d", f.Offset)
				}
				r.Fields[i].Name = name
			}
			c = r
		}
	}

	// naming for globals
	globals := globalsMap(d, w, t)
	for _, x := range []*Data{d.Data, d.Bss} {
		for i, f := range x.Fields {
			addr := x.Addr + f.Offset
			a, v := globals.Lookup(addr)
			if v == nil {
				continue
			}
			ff := v.(Field)
			if a != addr {
				ff.Name = fmt.Sprintf("%s:%d", ff.Name, addr-a)
			}
			ff.Offset = f.Offset
			x.Fields[i] = ff
		}
	}
}

func link(d *Dump) {
	// sort objects in increasing address order
	sort.Sort(byAddr(d.Objects))

	// initialize index array
	idx := make([]int, (d.HeapEnd-d.HeapStart)/bucketSize)
	for i := 0; i < len(idx); i++ {
		idx[i] = len(d.Objects)
	}
	for i := len(d.Objects) - 1; i >= 0; i-- {
		idx[(d.Objects[i].Addr-d.HeapStart)/bucketSize] = i
	}
	d.idx = idx

	// initialize some maps used for linking
	frames := make(map[frameKey]*StackFrame, len(d.Frames))
	for _, x := range d.Frames {
		frames[frameKey{x.Addr, x.Depth}] = x
	}

	// link objects to types
	/*
		for _, x := range d.Objects {
			if x.typaddr == 0 {
				x.Typ = nil
			} else {
				x.Typ = d.types[x.typaddr]
				if x.Typ == nil {
					log.Fatal("type is missing")
				}
			}
		}
	*/

	// link stack frames to objects
	for _, f := range d.Frames {
		f.Edges = d.appendFields(f.Edges, f.Data, f.Fields)
	}

	// link up frames in sequence
	for _, f := range d.Frames {
		if f.Depth == 0 {
			continue
		}
		g := frames[frameKey{f.childaddr, f.Depth - 1}]
		g.Parent = f
	}

	// link goroutines to frames & vice versa
	for _, g := range d.Goroutines {
		g.Bos = frames[frameKey{g.bosaddr, 0}]
		if g.Bos == nil {
			log.Fatal("bos missing")
		}
		for f := g.Bos; f != nil; f = f.Parent {
			f.Goroutine = g
		}
		x := d.findObj(g.ctxtaddr)
		if x != ObjNil {
			g.Ctxt = x
		}
	}

	// link data roots
	for _, x := range []*Data{d.Data, d.Bss} {
		x.Edges = d.appendFields(x.Edges, x.Data, x.Fields)
	}

	// link other roots
	for _, r := range d.Otherroots {
		x := d.findObj(r.toaddr)
		if x != ObjNil {
			r.E = Edge{x, 0, r.toaddr - d.Objects[x].Addr, ""}
		}
	}

	// Add links for finalizers
	// TODO: how do we represent these?
	/*
		for _, f := range d.Finalizers {
			x := d.findObj(f.obj)
			for _, addr := range []uint64{f.fn, f.fint, f.ot} {
				y := d.findObj(addr)
				if x != nil && y != nil {
					x.Edges = append(x.Edges, Edge{y, 0, addr - y.Addr, "finalizer", 0})
				}
			}
		}
	*/
	for _, f := range d.QFinal {
		for _, addr := range []uint64{f.obj, f.fn, f.fint, f.ot} {
			x := d.findObj(addr)
			if x != ObjNil {
				f.Edges = append(f.Edges, Edge{x, 0, addr - d.Objects[x].Addr, ""})
			}
		}
	}
}

func nameFallback(d *Dump) {
	// No dwarf info, just name generically
	for _, t := range d.Types {
		for i := range t.Fields {
			t.Fields[i].Name = fmt.Sprintf("field%d", i)
		}
	}
	// name all frame fields
	for _, r := range d.Frames {
		for i := range r.Fields {
			r.Fields[i].Name = fmt.Sprintf("var%d", i)
		}
	}
	// name all globals
	for i := range d.Data.Fields {
		d.Data.Fields[i].Name = fmt.Sprintf("data%d", i)
	}
	for i := range d.Bss.Fields {
		d.Bss.Fields[i].Name = fmt.Sprintf("bss%d", i)
	}
}

// needs to be kept in sync with src/pkg/runtime/chan.h in
// the main Go distribution.
var chanFields = map[uint64]map[uint64]string{
	4: map[uint64]string{
		0:  "len",
		4:  "cap",
		20: "next send index",
		24: "next receive index",
	},
	8: map[uint64]string{
		0:  "len",
		8:  "cap",
		32: "next send index",
		40: "next receive index",
	},
}

func nameFullTypes(d *Dump) {
	for _, ft := range d.FTList {
		t := ft.Typ
		switch {
		case ft.Typ == nil && ft.Kind == TypeKindConservative:
			// could all be pointers
			for i := uint64(0); i < ft.Size; i += d.PtrSize {
				ft.Fields = append(ft.Fields, Field{FieldKindPtr, i, fmt.Sprintf("~%d", i)})
			}
		case ft.Typ == nil && ft.Kind == TypeKindObject:
			// no pointers.  Emit psuedo field records
			for i := uint64(0); i < ft.Size; i += 16 {
				s := ft.Size - i
				if s > 16 {
					s = 16
				}
				switch s {
				case 16:
					ft.Fields = append(ft.Fields, Field{FieldKindBytes16, i, fmt.Sprintf("offset %x", i)})
				case 8:
					ft.Fields = append(ft.Fields, Field{FieldKindBytes8, i, fmt.Sprintf("offset %x", i)})
				default:
					log.Fatalf("weird size obj", ft.Size)
				}
			}
		case ft.Typ != nil && ft.Kind == TypeKindObject:
			ft.Fields = ft.Typ.Fields
		case ft.Typ != nil && ft.Kind == TypeKindArray:
			t := ft.Typ
			for i := uint64(0); i <= ft.Size-t.Size; i += t.Size {
				for _, f := range t.Fields {
					var name string
					if f.Name != "" {
						name = fmt.Sprintf("%d.%s", i/t.Size, f.Name)
					} else {
						name = fmt.Sprintf("%d", i/t.Size)
					}
					ft.Fields = append(ft.Fields, Field{f.Kind, i + f.Offset, name})
				}
			}
		case ft.Typ != nil && ft.Kind == TypeKindChan:
			fmap := chanFields[d.PtrSize]
			if fmap == nil {
				log.Fatal("can't find channel header info for ptr size")
			}
			k := FieldKindUInt64
			if d.PtrSize == 4 {
				k = FieldKindUInt32
			}
			for i := uint64(0); i < d.HChanSize; i += d.PtrSize {
				if name, ok := fmap[i]; ok {
					ft.Fields = append(ft.Fields, Field{k, i, name})
				} else {
					ft.Fields = append(ft.Fields, Field{k, i, "chanhdr"})
				}
			}
			if t.Size > 0 {
				for i := d.HChanSize; i <= ft.Size-t.Size; i += t.Size {
					for _, f := range t.Fields {
						var name string
						if f.Name != "" {
							name = fmt.Sprintf("%d.%s", (i-d.HChanSize)/t.Size, f.Name)
						} else {
							name = fmt.Sprintf("%d", (i-d.HChanSize)/t.Size)
						}
						ft.Fields = append(ft.Fields, Field{f.Kind, i + f.Offset, name})
					}
				}
			}
		default:
			log.Fatal("bad type/kind combo", ft.Typ, ft.Kind)
		}
	}
}

type byAddr []*Object

func (a byAddr) Len() int           { return len(a) }
func (a byAddr) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byAddr) Less(i, j int) bool { return a[i].Addr < a[j].Addr }

func Read(dumpname, execname string) *Dump {
	d := rawRead(dumpname)
	if execname != "" {
		nameWithDwarf(d, execname)
	} else {
		nameFallback(d)
	}
	nameFullTypes(d)
	link(d)
	return d
}

func readPtr(d *Dump, b []byte) uint64 {
	switch {
	case d.Order == binary.LittleEndian && d.PtrSize == 4:
		return uint64(b[0]) + uint64(b[1])<<8 + uint64(b[2])<<16 + uint64(b[3])<<24
	case d.Order == binary.BigEndian && d.PtrSize == 4:
		return uint64(b[3]) + uint64(b[2])<<8 + uint64(b[1])<<16 + uint64(b[0])<<24
	case d.Order == binary.LittleEndian && d.PtrSize == 8:
		return uint64(b[0]) + uint64(b[1])<<8 + uint64(b[2])<<16 + uint64(b[3])<<24 + uint64(b[4])<<32 + uint64(b[5])<<40 + uint64(b[6])<<48 + uint64(b[7])<<56
	case d.Order == binary.BigEndian && d.PtrSize == 8:
		return uint64(b[7]) + uint64(b[6])<<8 + uint64(b[5])<<16 + uint64(b[4])<<24 + uint64(b[3])<<32 + uint64(b[2])<<40 + uint64(b[1])<<48 + uint64(b[0])<<56
	default:
		log.Fatal("unsupported order=%v PtrSize=%d", d.Order, d.PtrSize)
		return 0
	}
}
