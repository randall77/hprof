package read

import (
	"sort"
)

// You put some (address,value) pairs in, then ask it about an
// address.  It returns the closest (address,value) pair below
// or equal to that address.

// TODO: this could really use generics

type heap struct {
	entries []entry
	sorted  bool
}

// Insert adds the pair <addr,value> to the heap.
func (h *heap) Insert(addr uint64, value interface{}) {
	h.entries = append(h.entries, entry{addr, value})
	h.sorted = false
}

// Lookup finds and returns the pair whose address is maximum among
// all the inserted pairs with address less than or equal to addr.  If
// none exist, returns 0, nil.
func (h *heap) Lookup(addr uint64) (uint64, interface{}) {
	if !h.sorted {
		sort.Sort(byEntryAddr(h.entries))
		h.sorted = true
	}
	j := sort.Search(len(h.entries), func(i int) bool { return addr < h.entries[i].addr })
	if j == 0 {
		return 0, nil
	}
	return h.entries[j-1].addr, h.entries[j-1].value
}

type entry struct {
	addr  uint64
	value interface{}
}

type byEntryAddr []entry
func (h byEntryAddr) Len() int           { return len(h) }
func (h byEntryAddr) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h byEntryAddr) Less(i, j int) bool { return h[i].addr < h[j].addr }
