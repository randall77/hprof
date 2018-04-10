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
	reachable := make([]bool, d.NumObjects())
	var q []read.ObjId
	for _, f := range d.Frames {
		for _, e := range f.Edges {
			if !reachable[e.To] {
				reachable[e.To] = true
				q = append(q, e.To)
			}
		}
	}
	for _, x := range []*read.Data{d.Data, d.Bss} {
		for _, e := range x.Edges {
			if !reachable[e.To] {
				reachable[e.To] = true
				q = append(q, e.To)
			}
		}
	}
	for _, r := range d.Otherroots {
		for _, e := range r.Edges {
			if !reachable[e.To] {
				reachable[e.To] = true
				q = append(q, e.To)
			}
		}
	}
	for _, f := range d.QFinal {
		for _, e := range f.Edges {
			if !reachable[e.To] {
				reachable[e.To] = true
				q = append(q, e.To)
			}

		}
	}
	for _, g := range d.Goroutines {
		if g.Ctxt != read.ObjNil {
			if !reachable[g.Ctxt] {
				reachable[g.Ctxt] = true
				q = append(q, g.Ctxt)
			}
		}
	}
	for len(q) > 0 {
		x := q[0]
		q = q[1:]
		for _, e := range d.Edges(x) {
			if !reachable[e.To] {
				reachable[e.To] = true
				q = append(q, e.To)
			}
		}
	}

	fmt.Printf("digraph {\n")

	// print object graph
	for i := 0; i < d.NumObjects(); i++ {
		x := read.ObjId(i)
		if !reachable[x] {
			fmt.Printf("  v%d [style=filled fillcolor=gray];\n", x)
		}
		fmt.Printf("  v%d [label=\"\\n%d\"];\n", x, d.Size(x))
		for _, e := range d.Edges(x) {
			var taillabel, headlabel string
			if e.FieldName != "" {
				taillabel = fmt.Sprintf(" [taillabel=\"%s\"]", e.FieldName)
			} else if e.FromOffset != 0 {
				taillabel = fmt.Sprintf(" [taillabel=\"%d\"]", e.FromOffset)
			}
			if e.ToOffset != 0 {
				headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.ToOffset)
			}
			fmt.Printf("  v%d -> v%d%s%s;\n", x, e.To, taillabel, headlabel)
		}
	}

	// goroutines and stacks
	for _, t := range d.Goroutines {
		fmt.Printf("  \"goroutines\" [shape=diamond];\n")
		fmt.Printf("  \"goroutines\" -> f%x_0;\n", t.Bos.Addr)
	}

	// stack frames
	for _, f := range d.Frames {
		fmt.Printf("  f%x_%d [label=\"%s\\n%d\" shape=rectangle];\n", f.Addr, f.Depth, f.Name, len(f.Data))
		if f.Parent != nil {
			fmt.Printf("  f%x_%d -> f%x_%d;\n", f.Addr, f.Depth, f.Parent.Addr, f.Parent.Depth)
		}
		for _, e := range f.Edges {
			if e.To != read.ObjNil {
				var taillabel, headlabel string
				if e.FieldName != "" {
					taillabel = fmt.Sprintf(" [taillabel=\"%s\"]", e.FieldName)
				} else if e.FromOffset != 0 {
					taillabel = fmt.Sprintf(" [taillabel=\"%d\"]", e.FromOffset)
				}
				if e.ToOffset != 0 {
					headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.ToOffset)
				}
				fmt.Printf("  f%x_%d -> v%d%s%s;\n", f.Addr, f.Depth, e.To, taillabel, headlabel)
			}
		}
	}
	for _, x := range []*read.Data{d.Data, d.Bss} {
		for _, e := range x.Edges {
			if e.To != read.ObjNil {
				var headlabel string
				if e.ToOffset != 0 {
					headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.ToOffset)
				}
				fmt.Printf("  \"%s\" [shape=diamond];\n", e.FieldName)
				fmt.Printf("  \"%s\" -> v%d%s;\n", e.FieldName, e.To, headlabel)
			}
		}
	}
	for _, r := range d.Otherroots {
		for _, e := range r.Edges {
			var headlabel string
			if e.ToOffset != 0 {
				headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.ToOffset)
			}
			fmt.Printf("  \"%s\" [shape=diamond];\n", r.Description)
			fmt.Printf("  \"%s\" -> v%d%s;\n", r.Description, e.To, headlabel)
		}
	}
	for _, f := range d.QFinal {
		for _, e := range f.Edges {
			var headlabel string
			if e.ToOffset != 0 {
				headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.ToOffset)
			}
			fmt.Printf("  \"queued finalizers\" [shape=diamond];\n")
			fmt.Printf("  \"queued finalizers\" -> v%d%s;\n", e.To, headlabel)
		}
	}

	fmt.Printf("}\n")
}
