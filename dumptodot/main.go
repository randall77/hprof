package main

import (
	"flag"
	"fmt"
	"github.com/randall77/hprof/read"
)

func main() {
	flag.Parse()
	args := flag.Args()
	var d *read.Dump
	if len(args) == 2 {
		d = read.Read(args[0], args[1])
	} else {
		d = read.Read(args[0], "")
	}

	// eliminate unreachable objects
	// TODO: have reader do this?
	reachable := map[*read.Object]struct{}{}
	var q []*read.Object
	for _, f := range d.Frames {
		for _, e := range f.Edges {
			if _, ok := reachable[e.To]; !ok {
				reachable[e.To] = struct{}{}
				q = append(q, e.To)
			}
		}
	}
	for _, x := range []*read.Data{d.Data, d.Bss} {
		for _, e := range x.Edges {
			if e.To != nil {
				if _, ok := reachable[e.To]; !ok {
					reachable[e.To] = struct{}{}
					q = append(q, e.To)
				}
			}
		}
	}
	for _, r := range d.Otherroots {
		if r.E.To != nil {
			if _, ok := reachable[r.E.To]; !ok {
				reachable[r.E.To] = struct{}{}
				q = append(q, r.E.To)
			}
		}
	}
	for _, f := range d.QFinal {
		for _, e := range f.Edges {
			if _, ok := reachable[e.To]; !ok {
				reachable[e.To] = struct{}{}
				q = append(q, e.To)
			}

		}
	}
	for _, g := range d.Goroutines {
		if g.Ctxt != nil {
			if _, ok := reachable[g.Ctxt]; !ok {
				reachable[g.Ctxt] = struct{}{}
				q = append(q, g.Ctxt)
			}
		}
	}
	for len(q) > 0 {
		x := q[0]
		q = q[1:]
		for _, e := range x.Edges {
			if _, ok := reachable[e.To]; !ok {
				reachable[e.To] = struct{}{}
				q = append(q, e.To)
			}
		}
	}

	fmt.Printf("digraph {\n")

	// print object graph
	for _, x := range d.Objects {
		if _, ok := reachable[x]; !ok {
			fmt.Printf("  v%x [style=filled fillcolor=gray];\n", x.Addr)
		}
		if x.Type() != nil {
			name := x.Type().Name
			switch x.Kind() {
			case read.TypeKindArray:
				name = fmt.Sprintf("{%d}%s", x.Size()/x.Type().Size, name)
			case read.TypeKindChan:
				if x.Type().Size == 0 {
					name = fmt.Sprintf("chan{?}%s", name)
				} else {
					name = fmt.Sprintf("chan{%d}%s", (x.Size()-d.HChanSize)/x.Type().Size, name)
				}
			}
			// NOTE: sizes are max sizes given sizeclass - the actual size of a
			// chan or array might be smaller.
			fmt.Printf("  v%x [label=\"%s\\n%d\"];\n", x.Addr, name, x.Size())
		} else {
			fmt.Printf("  v%x [label=\"%d\"];\n", x.Addr, x.Size())
		}
		for _, e := range x.Edges {
			var taillabel, headlabel string
			if e.FieldName != "" {
				if e.FieldOffset == 0 {
					taillabel = fmt.Sprintf(" [taillabel=\"%s\"]", e.FieldName)
				} else {
					taillabel = fmt.Sprintf(" [taillabel=\"%s:%d\"]", e.FieldName, e.FieldOffset)
				}
			} else if e.FromOffset != 0 {
				taillabel = fmt.Sprintf(" [taillabel=\"%d\"]", e.FromOffset)
			}
			if e.ToOffset != 0 {
				headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.ToOffset)
			}
			fmt.Printf("  v%x -> v%x%s%s;\n", x.Addr, e.To.Addr, taillabel, headlabel)
		}
	}

	// goroutines and stacks
	for _, t := range d.Goroutines {
		fmt.Printf("  \"goroutines\" [shape=diamond];\n")
		fmt.Printf("  \"goroutines\" -> v%x_0;\n", t.Bos.Addr)
	}

	// stack frames
	for _, f := range d.Frames {
		fmt.Printf("  v%x_%d [label=\"%s\\n%d\" shape=rectangle];\n", f.Addr, f.Depth, f.Name, len(f.Data))
		if f.Parent != nil {
			fmt.Printf("  v%x_%d -> v%x_%d;\n", f.Addr, f.Depth, f.Parent.Addr, f.Parent.Depth)
		}
		for _, e := range f.Edges {
			if e.To != nil {
				var taillabel, headlabel string
				if e.FieldName != "" {
					if e.FieldOffset == 0 {
						taillabel = fmt.Sprintf(" [taillabel=\"%s\"]", e.FieldName)
					} else {
						taillabel = fmt.Sprintf(" [taillabel=\"%s:%d\"]", e.FieldName, e.FieldOffset)
					}
				} else if e.FromOffset != 0 {
					taillabel = fmt.Sprintf(" [taillabel=\"%d\"]", e.FromOffset)
				}
				if e.ToOffset != 0 {
					headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.ToOffset)
				}
				fmt.Printf("  v%x_%d -> v%x%s%s;\n", f.Addr, f.Depth, e.To.Addr, taillabel, headlabel)
			}
		}
	}
	for _, x := range []*read.Data{d.Data, d.Bss} {
		for _, e := range x.Edges {
			if e.To != nil {
				var headlabel string
				if e.ToOffset != 0 {
					headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.ToOffset)
				}
				fmt.Printf("  \"%s\" [shape=diamond];\n", e.FieldName)
				fmt.Printf("  \"%s\" -> v%x%s;\n", e.FieldName, e.To.Addr, headlabel)
			}
		}
	}
	for _, r := range d.Otherroots {
		e := r.E
		if e.To != nil {
			var headlabel string
			if e.ToOffset != 0 {
				headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.ToOffset)
			}
			fmt.Printf("  \"%s\" [shape=diamond];\n", r.Description)
			fmt.Printf("  \"%s\" -> v%x%s;\n", r.Description, e.To.Addr, headlabel)
		}
	}
	for _, f := range d.QFinal {
		for _, e := range f.Edges {
			var headlabel string
			if e.ToOffset != 0 {
				headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.ToOffset)
			}
			fmt.Printf("  \"queued finalizers\" [shape=diamond];\n")
			fmt.Printf("  \"queued finalizers\" -> v%x%s;\n", e.To.Addr, headlabel)
		}
	}

	fmt.Printf("}\n")
}
