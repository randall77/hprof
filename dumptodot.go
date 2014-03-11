package main

import (
	"fmt"
	"flag"
)

func main() {
	flag.Parse()
	args := flag.Args()
	d := Read(args[0], args[1])

	fmt.Printf("digraph {\n")

	// object graph
	for _, x := range d.objects {
		if x.typ != nil {
			name := x.typ.name
			switch x.kind {
			case 1:
				name += "{" + fmt.Sprintf("%d", uint64(len(x.data))/x.typ.size) + "}"
			case 2:
				name += "chan " + name
			}
			fmt.Printf("  v%x [label=\"%d\\n%s\"];\n", x.addr, len(x.data), name)
		} else {
			if true { continue }
			fmt.Printf("  v%x [label=\"%d\"];\n", x.addr, len(x.data))
		}
		for _, to := range x.edges {
			fmt.Printf("  v%x -> v%x;\n", x.addr, to.addr)
		}
	}

	// roots
	for _, f := range d.frames {
		fmt.Printf("  v%x [label=\"%s\" shape=rectangle];\n", f.addr, f.name)
	}
	for _, t := range d.threads {
		fmt.Printf("  \"threads\" -> v%x;\n", t.tos.addr)
		for f := t.tos; f != nil; f = f.parent {
			if f.parent != nil {
				fmt.Printf("  v%x -> v%x;\n", f.addr, f.parent.addr)
			}
		}
	}
	fmt.Printf("  \"threads\" [shape=diamond]\n")
	fmt.Printf("  \"data root\" [shape=diamond]\n")
	fmt.Printf("  \"other root\" [shape=diamond]\n")
	for _, r := range d.stackroots {
		if r.to != nil {
			fmt.Printf("  v%x -> v%x;\n", r.frame.addr, r.to.addr)
		}
	}
	for _, r := range d.dataroots {
		if r.to != nil {
			fmt.Printf("  \"%s/%x\" -> v%x;\n", r.name, r.offset, r.to.addr)
		}
	}
	for _, r := range d.otherroots {
		if r.to != nil {
			fmt.Printf("  \"other root\" -> v%x;\n", r.to.addr)
		}
	}

	fmt.Printf("}\n")

	// TODO: dump hprof
}
