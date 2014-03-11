package main

import (
	"flag"
	"fmt"
)

func main() {
	flag.Parse()
	args := flag.Args()
	d := Read(args[0], args[1])

	// eliminate unreachable objects
	// TODO: have reader do this?
	reachable := map[*Object]struct{}{}
	var q []*Object
	for _, r := range d.stackroots {
		if r.e.to != nil {
			if _, ok := reachable[r.e.to]; !ok {
				reachable[r.e.to] = struct{}{}
				q = append(q, r.e.to)
			}
		}
	}
	for _, r := range d.dataroots {
		if r.e.to != nil {
			if _, ok := reachable[r.e.to]; !ok {
				reachable[r.e.to] = struct{}{}
				q = append(q, r.e.to)
			}
		}
	}
	for _, r := range d.otherroots {
		if r.e.to != nil {
			if _, ok := reachable[r.e.to]; !ok {
				reachable[r.e.to] = struct{}{}
				q = append(q, r.e.to)
			}
		}
	}
	for len(q) > 0 {
		x := q[0]
		q = q[1:]
		for _, e := range x.edges {
			if _, ok := reachable[e.to]; !ok {
				reachable[e.to] = struct{}{}
				q = append(q, e.to)
			}
		}
	}

	fmt.Printf("digraph {\n")

	// print object graph
	for _, x := range d.objects {
		if _, ok := reachable[x]; !ok {
			continue
		}
		if x.typ != nil {
			name := x.typ.name
			switch x.kind {
			case 1:
				name += "{" + fmt.Sprintf("%d", uint64(len(x.data))/x.typ.size) + "}"
			case 2:
				name += "chan " + name
			}
			fmt.Printf("  v%x [label=\"%s\\n%d\"];\n", x.addr, name, len(x.data))
		} else {
			fmt.Printf("  v%x [label=\"%d\"];\n", x.addr, len(x.data))
		}
		for _, e := range x.edges {
			var taillabel, headlabel string
			if e.fromoffset != 0 {
				taillabel = fmt.Sprintf(" [taillabel=\"%d\"]", e.fromoffset)
			}
			if e.tooffset != 0 {
				headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.tooffset)
			}
			fmt.Printf("  v%x -> v%x%s%s;\n", x.addr, e.to.addr, taillabel, headlabel)
		}
	}

	// threads and stacks
	for _, f := range d.frames {
		fmt.Printf("  v%x [label=\"%s\\n%d\" shape=rectangle];\n", f.addr, f.name, f.parentaddr-f.addr)
		if f.parent != nil {
			fmt.Printf("  v%x -> v%x;\n", f.addr, f.parent.addr)
		}
	}
	for _, t := range d.threads {
		fmt.Printf("  \"threads\" [shape=diamond];\n")
		fmt.Printf("  \"threads\" -> v%x;\n", t.tos.addr)
	}

	// roots
	for _, r := range d.stackroots {
		e := r.e
		if e.to != nil {
			var taillabel, headlabel string
			if e.fromoffset != 0 {
				taillabel = fmt.Sprintf(" [taillabel=\"%d\"]", e.fromoffset)
			}
			if e.tooffset != 0 {
				headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.tooffset)
			}
			fmt.Printf("  v%x -> v%x%s%s;\n", r.frame.addr, e.to.addr, taillabel, headlabel)
		}
	}
	for _, r := range d.dataroots {
		e := r.e
		if e.to != nil {
			var taillabel, headlabel string
			if r.e.fromoffset != 0 {
				taillabel = fmt.Sprintf(" [taillabel=\"%d\"]", e.fromoffset)
			}
			if e.tooffset != 0 {
				headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.tooffset)
			}
			fmt.Printf("  \"%s\" [shape=diamond];\n", r.name)
			fmt.Printf("  \"%s\" -> v%x%s%s;\n", r.name, e.to.addr, taillabel, headlabel)
		}
	}
	for _, r := range d.otherroots {
		e := r.e
		if e.to != nil {
			var headlabel string
			if e.tooffset != 0 {
				headlabel = fmt.Sprintf(" [headlabel=\"%d\"]", e.tooffset)
			}
			fmt.Printf("  \"%s\" [shape=diamond];\n", r.description)
			fmt.Printf("  \"%s\" -> v%x%s;\n", r.description, e.to.addr, headlabel)
		}
	}

	fmt.Printf("}\n")
}
