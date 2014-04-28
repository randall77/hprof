package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/randall77/hprof/read"
	"html"
	"log"
	"net/http"
	"sort"
	"strconv"
	"text/template"
	"os"
	"runtime"
	"runtime/debug"
)

const (
	defaultAddr = ":8080" // default webserver address
)
var (
	httpAddr = flag.String("http", defaultAddr, "HTTP service address")
)

// d is the loaded heap dump.
var d *read.Dump

// link to type's page
func typeLink(ft *read.FullType) string {
	return fmt.Sprintf("<a href=\"type?id=%d\">%s</a>", ft.Id, ft.Name)
}

// returns an html string representing the target of an Edge
func edgeLink(e read.Edge) string {
	value := fmt.Sprintf("<a href=obj?id=%x>object %x</a>", e.To.Addr, e.To.Addr)
	if e.ToOffset != 0 {
		value = fmt.Sprintf("%s+%d", value, e.ToOffset)
	}
	return value
}

// the first d.PtrSize bytes of b contain a pointer.  Return html
// to represent that pointer.
func nonheapPtr(b []byte) string {
	p := readPtr(b)
	if p == 0 {
		return "nil"
	} else {
		// TODO: look up symbol in executable
		return fmt.Sprintf("outsideheap_%x", p)
	}
}

func edgeSource(x *read.Object, e read.Edge) string {
	if e.FieldName != "" {
		s := fmt.Sprintf("<a href=obj?id=%x>object %x</a> %s", x.Addr, x.Addr, e.FieldName)
		if e.FieldOffset != 0 {
			s = fmt.Sprintf("%s.%d", s, e.FieldOffset)
		}
		return s
	} else {
		return fmt.Sprintf("<a href=obj?id=%x>object %x</a>+%d", x.Addr, x.Addr, e.FromOffset)
	}
}

type Field struct {
	Name  string
	Typ   string
	Value string
}

// getFields uses the data in b to fill in the values for the fields passed in.
// edges is a map recording known connecting edges, adjusted with offset.
func getFields(b []byte, fields []read.Field, emap map[uint64]read.Edge, offset uint64) []Field {
	var r []Field
	off := uint64(0)
	for _, f := range fields {
		if f.Offset < off {
			log.Fatal("out of order fields")
		}
		if f.Offset > off {
			r = append(r, Field{fmt.Sprintf("<font color=LightGray>pad %d</font>", f.Offset-off), "", ""})
			off = f.Offset
		}
		var value string
		var typ string
		switch f.Kind {
		case read.FieldKindBool:
			if b[off] == 0 {
				value = "false"
			} else {
				value = "true"
			}
			typ = "bool"
			off++
		case read.FieldKindUInt8:
			value = fmt.Sprintf("%d", b[off])
			typ = "uint8"
			off++
		case read.FieldKindSInt8:
			value = fmt.Sprintf("%d", int8(b[off]))
			typ = "int8"
			off++
		case read.FieldKindUInt16:
			value = fmt.Sprintf("%d", read16(b[off:]))
			typ = "uint16"
			off += 2
		case read.FieldKindSInt16:
			value = fmt.Sprintf("%d", int16(read16(b[off:])))
			typ = "int16"
			off += 2
		case read.FieldKindUInt32:
			value = fmt.Sprintf("%d", read32(b[off:]))
			typ = "uint32"
			off += 4
		case read.FieldKindSInt32:
			value = fmt.Sprintf("%d", int32(read32(b[off:])))
			typ = "int32"
			off += 4
		case read.FieldKindUInt64:
			value = fmt.Sprintf("%d", read64(b[off:]))
			typ = "uint64"
			off += 8
		case read.FieldKindSInt64:
			value = fmt.Sprintf("%d", int64(read64(b[off:])))
			typ = "int64"
			off += 8
		case read.FieldKindPtr:
			typ = "ptr"
			// TODO: get ptr base type somehow?  Also for slices,chans.
			if e, ok := emap[offset+off]; ok {
				value = edgeLink(e)
			} else {
				value = nonheapPtr(b[off:])
			}
			off += d.PtrSize
		case read.FieldKindIface:
			// TODO: the itab part?
			typ = "interface{...}"
			if e, ok := emap[offset+off+d.PtrSize]; ok {
				value = edgeLink(e)
			} else {
				value = nonheapPtr(b[off+d.PtrSize:])
			}
			off += 2 * d.PtrSize
		case read.FieldKindEface:
			// TODO: the type part
			typ = "interface{}"
			if e, ok := emap[offset+off+d.PtrSize]; ok {
				value = edgeLink(e)
			} else {
				value = nonheapPtr(b[off+d.PtrSize:])
			}
			off += 2 * d.PtrSize
		case read.FieldKindString:
			typ = "string"
			if e, ok := emap[offset+off]; ok {
				value = edgeLink(e)
			} else {
				value = nonheapPtr(b[off:])
			}
			value = fmt.Sprintf("%s/%d", value, readPtr(b[off+d.PtrSize:]))
			off += 2 * d.PtrSize
		case read.FieldKindSlice:
			typ = "slice"
			if e, ok := emap[offset+off]; ok {
				value = edgeLink(e)
			} else {
				value = nonheapPtr(b[off:])
			}
			value = fmt.Sprintf("%s/%d/%d", value, readPtr(b[off+d.PtrSize:]), readPtr(b[off+2*d.PtrSize:]))
			off += 3 * d.PtrSize
		}
		r = append(r, Field{f.Name, typ, value})
	}
	if uint64(len(b)) > off {
		r = append(r, Field{fmt.Sprintf("<font color=LightGray>sizeclass pad %d</font>", uint64(len(b))-off), "", ""})
	}
	return r
}

func fields(x *read.Object) []Field {
	// map the known edges
	emap := map[uint64]read.Edge{}
	for _, e := range x.Edges {
		emap[e.FromOffset] = e
	}
	b := d.Contents(x)

	var r []Field
	switch x.Kind() {
	case read.TypeKindObject:
		if x.Type() != nil {
			r = getFields(b, x.Type().Fields, emap, 0)
		} else {
			// raw data
			if len(emap) > 0 {
				log.Fatal("edges in raw data")
			}
			for i := uint64(0); i < x.Size(); i += 16 {
				n := x.Size() - i
				if n > 16 {
					n = 16
				}
				v := ""
				s := ""
				for j := uint64(0); j < n; j++ {
					c := b[i+j]
					v += fmt.Sprintf("%.2x ", c)
					if c <= 32 || c >= 127 {
						c = 46
					}
					s += fmt.Sprintf("%c", c)
				}
				r = append(r, Field{fmt.Sprintf("offset %x", i), "raw bytes", v + " | " + html.EscapeString(s)})
			}
		}
	case read.TypeKindArray:
		n := x.Size() / x.Type().Size
		for i := uint64(0); i < n; i++ {
			s := getFields(b[i*x.Type().Size:(i+1)*x.Type().Size], x.Type().Fields, emap, i*x.Type().Size)
			for _, f := range s {
				if f.Name == "" {
					f.Name = fmt.Sprintf("%d", i)
				} else {
					f.Name = fmt.Sprintf("%d.%s", i, f.Name)
				}
				r = append(r, f)
			}
		}
	case read.TypeKindChan:
		fmap := chanFields[d.PtrSize]
		if fmap == nil {
			log.Fatal("can't find channel header info for ptr size")
		}
		for i := uint64(0); i < d.HChanSize; i += d.PtrSize {
			if name, ok := fmap[i]; ok {
				r = append(r, Field{name, "int", fmt.Sprintf("%d", readPtr(b[i:]))})
			} else {
				r = append(r, Field{"<font color=LightGray>chanhdr</font>", "<font color=LightGray>int</font>", fmt.Sprintf("<font color=LightGray>%d</font>", readPtr(b[i:]))})
			}
		}

		if x.Type().Size > 0 {
			n := (x.Size() - d.HChanSize) / x.Type().Size
			for i := uint64(0); i < n; i++ {
				s := getFields(b[d.HChanSize+i*x.Type().Size:d.HChanSize+(i+1)*x.Type().Size], x.Type().Fields, emap, d.HChanSize+i*x.Type().Size)
				for _, f := range s {
					if f.Name == "" {
						f.Name = fmt.Sprintf("%d", i)
					} else {
						f.Name = fmt.Sprintf("%d.%s", i, f.Name)
					}
					r = append(r, f)
				}
			}
		}
	case read.TypeKindConservative:
		for i := uint64(0); i < x.Size(); i += d.PtrSize {
			if e, ok := emap[i]; ok {
				r = append(r, Field{fmt.Sprintf("~%d", i), "ptr", edgeLink(e)})
			} else {
				r = append(r, Field{fmt.Sprintf("~%d", i), "ptr", nonheapPtr(b[i:])})
			}
		}
	}
	return r
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

type objInfo struct {
	Id        uint64
	Typ       string
	Size      uint64
	Fields    []Field
	Referrers []string
	ReachableMem uint64
}

var objTemplate = template.Must(template.New("obj").Parse(`
<html>
<head>
<style>
table
{
border-collapse:collapse;
}
table, td, th
{
border:1px solid grey;
}
</style>
<title>Object {{printf "%x" .Id}}</title>
</head>
<body>
<tt>
<h2>Object {{printf "%x" .Id}} : {{.Typ}}</h2>
<h3>{{.Size}} bytes</h3>
<table>
<tr>
<td>Field</td>
<td>Type</td>
<td>Value</td>
</tr>
{{range .Fields}}
<tr>
<td>{{.Name}}</td>
<td>{{.Typ}}</td>
<td>{{.Value}}</td>
</tr>
{{end}}
</table>
<h3>Referrers</h3>
{{range .Referrers}}
{{.}}
<br>
{{end}}
<h3>Reachable Memory</h3>
{{.ReachableMem}} bytes
</tt>
</body>
</html>
`))

func objHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v := q["id"]
	if len(v) != 1 {
		http.Error(w, "id parameter missing", 405)
		return
	}
	addr, err := strconv.ParseUint(v[0], 16, 64)
	if err != nil {
		http.Error(w, err.Error(), 405)
		return
	}

	var x *read.Object
	for _, y := range d.Objects {
		if y.Addr == addr {
			x = y
			break
		}
	}
	if x == nil {
		http.Error(w, "object not found", 405)
		return
	}

	reachableMem := uint64(0)
	h := map[*read.Object]struct{}{}
	var queue []*read.Object
	h[x] = struct{}{}
	queue = append(queue, x)
	for len(queue) > 0 {
		y := queue[0]
		queue = queue[1:]
		reachableMem += y.Size()
		for _, e := range y.Edges {
			if _, ok := h[e.To]; !ok {
				h[e.To] = struct{}{}
				queue = append(queue, e.To)
			}
		}
	}

	if err := objTemplate.Execute(w, objInfo{x.Addr, typeLink(x.Ft), x.Size(), fields(x), referrers[x], reachableMem}); err != nil {
		log.Print(err)
	}
}

type typeInfo struct {
	Name      string
	Size      uint64
	Instances []*read.Object
}

var typeTemplate = template.Must(template.New("type").Parse(`
<html>
<head>
<title>Type {{.Name}}</title>
</head>
<body>
<tt>
<h2>{{.Name}}</h2>
<h3>Size {{.Size}}</h3>
<h3>Instances</h3>
<table>
{{range .Instances}}
<tr><td><a href=obj?id={{printf "%x" .Addr}}>object {{printf "%x" .Addr}}</a></td></tr>
{{end}}
</table>
</tt>
</body>
</html>
`))

func typeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s := q["id"]
	if len(s) != 1 {
		http.Error(w, "type id missing", 405)
		return
	}
	id, err := strconv.ParseUint(s[0], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), 405)
		return
	}

	if id >= uint64(len(d.FTList)) {
		http.Error(w, "can't find type", 405)
		return
	}

	ft := d.FTList[id]
	if err := typeTemplate.Execute(w, typeInfo{ft.Name, ft.Size, byType[ft.Id].objects}); err != nil {
		log.Print(err)
	}
}

type hentry struct {
	Name  string
	Count int
	Bytes uint64
}

var histoTemplate = template.Must(template.New("histo").Parse(`
<html>
<head>
<style>
table
{
border-collapse:collapse;
}
table, td, th
{
border:1px solid grey;
}
</style>
<title>Type histogram</title>
</head>
<body>
<tt>
<table>
<col align="left">
<col align="right">
<col align="right">
<tr>
<td>Type</td>
<td align="right">Count</td>
<td align="right">Bytes</td>
</tr>
{{range .}}
<tr>
<td>{{.Name}}</td>
<td align="right">{{.Count}}</td>
<td align="right">{{.Bytes}}</td>
</tr>
{{end}}
</table>
</tt>
</body>
</html>
`))

func histoHandler(w http.ResponseWriter, r *http.Request) {
	// build sorted list of types
	var s []hentry
	for id, b := range byType {
		ft := d.FTList[id]
		s = append(s, hentry{typeLink(ft), len(b.objects), b.bytes})
	}
	sort.Sort(ByBytes(s))

	if err := histoTemplate.Execute(w, s); err != nil {
		log.Print(err)
	}
}

type ByBytes []hentry

func (a ByBytes) Len() int           { return len(a) }
func (a ByBytes) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByBytes) Less(i, j int) bool { return a[i].Bytes > a[j].Bytes }

var mainTemplate = template.Must(template.New("histo").Parse(`
<html>
<head>
<title>Heap dump viewer</title>
</head>
<body>
<tt>

<h2>Heap dump viewer</h2>
<br>
Heap size: {{.Memstats.Alloc}} bytes
<br>
Heap objects: {{len .Objects}}
<br>
<a href="histo">Type Histogram</a>
<a href="globals">Globals</a>
<a href="goroutines">Goroutines</a>
<a href="others">Miscellaneous Roots</a>
</tt>
</body>
</html>
`))

func mainHandler(w http.ResponseWriter, r *http.Request) {
	if err := mainTemplate.Execute(w, d); err != nil {
		log.Print(err)
	}
}

var globalsTemplate = template.Must(template.New("globals").Parse(`
<html>
<head>
<style>
table
{
border-collapse:collapse;
}
table, td, th
{
border:1px solid grey;
}
</style>
<title>Global roots</title>
</head>
<body>
<tt>
<h2>Global roots</h2>
<table>
<tr>
<td>Name</td>
<td>Type</td>
<td>Value</td>
</tr>
{{range .}}
<tr>
<td>{{.Name}}</td>
<td>{{.Typ}}</td>
<td>{{.Value}}</td>
</tr>
{{end}}
</table>
</tt>
</body>
</html>
`))

func globalsHandler(w http.ResponseWriter, r *http.Request) {
	var f []Field
	for _, x := range []*read.Data{d.Data, d.Bss} {
		emap := map[uint64]read.Edge{}
		for _, e := range x.Edges {
			emap[e.FromOffset] = e
		}
		f = append(f, getFields(x.Data, x.Fields, emap, 0)...)
	}
	if err := globalsTemplate.Execute(w, f); err != nil {
		log.Print(err)
	}
}

var othersTemplate = template.Must(template.New("others").Parse(`
<html>
<head>
<style>
table
{
border-collapse:collapse;
}
table, td, th
{
border:1px solid grey;
}
</style>
<title>Other roots</title>
</head>
<body>
<tt>
<h2>Other roots</h2>
<table>
<tr>
<td>Name</td>
<td>Type</td>
<td>Value</td>
</tr>
{{range .}}
<tr>
<td>{{.Name}}</td>
<td>{{.Typ}}</td>
<td>{{.Value}}</td>
</tr>
{{end}}
</table>
</tt>
</body>
</html>
`))

func othersHandler(w http.ResponseWriter, r *http.Request) {
	var f []Field
	for _, x := range d.Otherroots {
		f = append(f, Field{x.Description, "unknown", edgeLink(x.E)})
	}
	if err := othersTemplate.Execute(w, f); err != nil {
		log.Print(err)
	}
}

type goListInfo struct {
	Name  string
	State string
}

var goListTemplate = template.Must(template.New("golist").Parse(`
<html>
<head>
<style>
table
{
border-collapse:collapse;
}
table, td, th
{
border:1px solid grey;
}
</style>
<title>Goroutines</title>
</head>
<body>
<tt>
<h2>Goroutines</h2>
<table>
<tr>
<td>Name</td>
<td>State</td>
</tr>
{{range .}}
<tr>
<td>{{.Name}}</td>
<td>{{.State}}</td>
</tr>
{{end}}
</table>
</tt>
</body>
</html>
`))

func goListHandler(w http.ResponseWriter, r *http.Request) {
	var i []goListInfo
	for _, g := range d.Goroutines {
		name := fmt.Sprintf("<a href=go?id=%x>goroutine %x</a>", g.Addr, g.Addr)
		var state string
		switch g.Status {
		case 0:
			state = "idle"
		case 1:
			state = "runnable"
		case 2:
			// running - shouldn't happen
			log.Fatal("found running goroutine in heap dump")
		case 3:
			state = "syscall"
		case 4:
			state = g.WaitReason
		case 5:
			state = "dead"
		default:
			log.Fatal("unknown goroutine status")
		}
		i = append(i, goListInfo{name, state})
	}
	// sort by state
	sort.Sort(ByState(i))
	if err := goListTemplate.Execute(w, i); err != nil {
		log.Print(err)
	}
}

type ByState []goListInfo

func (a ByState) Len() int           { return len(a) }
func (a ByState) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByState) Less(i, j int) bool { return a[i].State < a[j].State }

type goInfo struct {
	Addr   uint64
	State  string
	Frames []string
}

var goTemplate = template.Must(template.New("go").Parse(`
<html>
<head>
<style>
table
{
border-collapse:collapse;
}
table, td, th
{
border:1px solid grey;
}
</style>
<title>Goroutine {{printf "%x" .Addr}}</title>
</head>
<body>
<tt>
<h2>Goroutine {{printf "%x" .Addr}}</h2>
<h3>{{.State}}</h3>
<h3>Stack</h3>
{{range .Frames}}
{{.}}
<br>
{{end}}
</tt>
</body>
</html>
`))

func goHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v := q["id"]
	if len(v) != 1 {
		http.Error(w, "id parameter missing", 405)
		return
	}
	addr, err := strconv.ParseUint(v[0], 16, 64)
	if err != nil {
		http.Error(w, err.Error(), 405)
		return
	}
	var g *read.GoRoutine
	for _, x := range d.Goroutines {
		if x.Addr == addr {
			g = x
			break
		}
	}
	if g == nil {
		http.Error(w, "goroutine not found", 405)
		return
	}

	var i goInfo
	i.Addr = g.Addr
	switch g.Status {
	case 0:
		i.State = "idle"
	case 1:
		i.State = "runnable"
	case 2:
		// running - shouldn't happen
		log.Fatal("found running goroutine in heap dump")
	case 3:
		i.State = "syscall"
	case 4:
		i.State = g.WaitReason
	case 5:
		i.State = "dead"
	default:
		log.Fatal("unknown goroutine status")
	}

	for f := g.Bos; f != nil; f = f.Parent {
		i.Frames = append(i.Frames, fmt.Sprintf("<a href=frame?id=%x&depth=%d>%s</a>", f.Addr, f.Depth, f.Name))
	}

	if err := goTemplate.Execute(w, i); err != nil {
		log.Print(err)
	}
}

type frameInfo struct {
	Addr      uint64
	Name      string
	Depth     uint64
	Goroutine string
	Vars      []Field
}

var frameTemplate = template.Must(template.New("frame").Parse(`
<html>
<head>
<style>
table
{
border-collapse:collapse;
}
table, td, th
{
border:1px solid grey;
}
</style>
<title>Frame {{.Name}}</title>
</head>
<body>
<tt>
<h2>Frame {{.Name}}</h2>
<h3>In {{.Goroutine}}</h3>
<h3>Variables</h3>
<table>
<tr>
<td>Name</td>
<td>Type</td>
<td>Value</td>
</tr>
{{range .Vars}}
<tr>
<td>{{.Name}}</td>
<td>{{.Typ}}</td>
<td>{{.Value}}</td>
</tr>
{{end}}
</table>
</tt>
</body>
</html>
`))

func frameHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v := q["id"]
	if len(v) != 1 {
		http.Error(w, "id parameter missing", 405)
		return
	}
	addr, err := strconv.ParseUint(v[0], 16, 64)
	if err != nil {
		http.Error(w, err.Error(), 405)
		return
	}
	z := q["depth"]
	if len(z) != 1 {
		http.Error(w, "depth parameter missing", 405)
		return
	}
	depth, err := strconv.ParseUint(z[0], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), 405)
		return
	}

	var f *read.StackFrame
	for _, g := range d.Frames {
		if g.Addr == addr && g.Depth == depth {
			f = g
			break
		}
	}
	if f == nil {
		http.Error(w, "stack frame not found", 405)
		return
	}

	var i frameInfo
	i.Addr = f.Addr
	i.Name = f.Name
	i.Depth = f.Depth
	i.Goroutine = fmt.Sprintf("<a href=go?id=%x>goroutine %x</a>", f.Goroutine.Addr, f.Goroutine.Addr)

	// variables
	emap := map[uint64]read.Edge{}
	for _, e := range f.Edges {
		emap[e.FromOffset] = e
	}
	i.Vars = getFields(f.Data, f.Fields, emap, 0)

	if err := frameTemplate.Execute(w, i); err != nil {
		log.Print(err)
	}
}

// So meta.
func heapdumpHandler(w http.ResponseWriter, r *http.Request) {
	f, err := os.Create("metadump")
	if err != nil {
		panic(err)
	}
	runtime.GC()
	debug.WriteHeapDump(f.Fd())
	f.Close()
	w.Write([]byte("done"))
}

func usage() {
	fmt.Fprintf(os.Stderr,
		"usage: hview heapdump [executable]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	fmt.Println("Loading...")
	args := flag.Args()
	if len(args) == 1 {
		d = read.Read(args[0], "")
	} else {
		d = read.Read(args[0], args[1])
	}

	fmt.Println("Analyzing...")
	prepare()

	fmt.Println("Ready.  Point your browser to localhost" + *httpAddr)
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/obj", objHandler)
	http.HandleFunc("/type", typeHandler)
	http.HandleFunc("/histo", histoHandler)
	http.HandleFunc("/globals", globalsHandler)
	http.HandleFunc("/goroutines", goListHandler)
	http.HandleFunc("/go", goHandler)
	http.HandleFunc("/frame", frameHandler)
	http.HandleFunc("/others", othersHandler)
	http.HandleFunc("/heapdump", heapdumpHandler)
	if err := http.ListenAndServe(*httpAddr, nil); err != nil {
		log.Fatal(err)
	}
}

type bucket struct {
	bytes   uint64
	objects []*read.Object
}

// histogram by full type id
var byType []bucket

var referrers map[*read.Object][]string

func prepare() {
	// group objects by type
	byType = make([]bucket, len(d.FTList))
	for _, x := range d.Objects {
		b := byType[x.Ft.Id]
		b.bytes += x.Size()
		b.objects = append(b.objects, x)
		byType[x.Ft.Id] = b
	}

	// compute referrers
	referrers = map[*read.Object][]string{}
	for _, x := range d.Objects {
		for _, e := range x.Edges {
			referrers[e.To] = append(referrers[e.To], edgeSource(x, e))
		}
	}
	for _, x := range []*read.Data{d.Data, d.Bss} {
		for _, e := range x.Edges {
			v := e.FieldName
			if e.FieldOffset != 0 {
				v = fmt.Sprintf("%s+%d", v, e.FieldOffset)
			}
			v = "global " + v
			referrers[e.To] = append(referrers[e.To], v)
		}
	}
	for _, f := range d.Frames {
		for _, e := range f.Edges {
			v := e.FieldName
			if e.FieldOffset != 0 {
				v = fmt.Sprintf("%s+%d", v, e.FieldOffset)
			}
			v = fmt.Sprintf("<a href=frame?id=%x&depth=%d>%s</a>.%s", f.Addr, f.Depth, f.Name, v)
			referrers[e.To] = append(referrers[e.To], v)
		}
	}
	for _, x := range d.Otherroots {
		e := x.E
		referrers[e.To] = append(referrers[e.To], x.Description)
	}
}

func readPtr(b []byte) uint64 {
	switch d.PtrSize {
	case 4:
		return read32(b)
	case 8:
		return read64(b)
	default:
		log.Fatal("unsupported PtrSize=%d", d.PtrSize)
		return 0
	}
}

func read64(b []byte) uint64 {
	switch {
	case d.Order == binary.LittleEndian:
		return uint64(b[0]) + uint64(b[1])<<8 + uint64(b[2])<<16 + uint64(b[3])<<24 + uint64(b[4])<<32 + uint64(b[5])<<40 + uint64(b[6])<<48 + uint64(b[7])<<56
	case d.Order == binary.BigEndian:
		return uint64(b[7]) + uint64(b[6])<<8 + uint64(b[5])<<16 + uint64(b[4])<<24 + uint64(b[3])<<32 + uint64(b[2])<<40 + uint64(b[1])<<48 + uint64(b[0])<<56
	default:
		log.Fatal("unsupported order=%v", d.Order)
		return 0
	}
}

func read32(b []byte) uint64 {
	switch {
	case d.Order == binary.LittleEndian:
		return uint64(b[0]) + uint64(b[1])<<8 + uint64(b[2])<<16 + uint64(b[3])<<24
	case d.Order == binary.BigEndian:
		return uint64(b[3]) + uint64(b[2])<<8 + uint64(b[1])<<16 + uint64(b[0])<<24
	default:
		log.Fatal("unsupported order=%v", d.Order)
		return 0
	}
}
func read16(b []byte) uint64 {
	switch {
	case d.Order == binary.LittleEndian:
		return uint64(b[0]) + uint64(b[1])<<8
	case d.Order == binary.BigEndian:
		return uint64(b[1]) + uint64(b[0])<<8
	default:
		log.Fatal("unsupported order=%v", d.Order)
		return 0
	}
}
