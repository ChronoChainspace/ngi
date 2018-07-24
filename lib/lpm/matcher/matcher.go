/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package matcher

import (
	"../../lpm"
)

type Type uint32

type TypeMatcher struct {
	node
}

type node struct {
	val   *Type
	table map[string]*node
}

func (n *node) Empty() bool {
	return n.val == nil && len(n.table) == 0
}

func deref(val *Type) (Type, bool) {
	if val == nil {
		var t Type
		return t, false
	}
	return *val, true
}

func (n *node) Match(key []lpm.Component) (val Type, found bool) {
	if len(key) == 0 {
		return deref(n.val)
	}
	if n.table == nil {
		return deref(n.val)
	}
	child, ok := n.table[string(key[0])]
	if !ok {
		return deref(n.val)
	}
	return child.Match(key[1:])
}

func (n *node) Get(key []lpm.Component) (val Type, found bool) {
	if len(key) == 0 {
		return deref(n.val)
	}
	if n.table == nil {
		return deref(nil)
	}
	child, ok := n.table[string(key[0])]
	if !ok {
		return deref(nil)
	}
	return child.Get(key[1:])
}

func (n *node) Update(key []lpm.Component, val Type) {
	if len(key) == 0 {
		n.val = &val
		return
	}
	if n.table == nil {
		n.table = make(map[string]*node)
	}
	if _, ok := n.table[string(key[0])]; !ok {
		n.table[string(key[0])] = &node{}
	}
	n.table[string(key[0])].Update(key[1:], val)
}

func (n *node) Delete(key []lpm.Component) {
	if len(key) == 0 {
		n.val = nil
		return
	}
	if n.table == nil {
		return
	}
	child, ok := n.table[string(key[0])]
	if !ok {
		return
	}
	child.Delete(key[1:])
	if child.Empty() {
		delete(n.table, string(key[0]))
	}
}

type UpdateFunc func([]lpm.Component, Type) (val Type, del bool)

func (n *node) UpdateAll(key []lpm.Component, f UpdateFunc) {
	for i := len(key); i > 0; i-- {
		k := key[:i]
		val, _ := n.Get(k)
		val2, del := f(k, val)
		if !del {
			n.Update(k, val2)
		} else {
			n.Delete(k)
		}
	}
}

func (n *node) visit(key []lpm.Component, f func([]lpm.Component)) {
	for k, v := range n.table {
		v.visit(append(key, lpm.Component(k)), f)
	}
	if n.val != nil {
		f(key)
	}
}

func (n *node) Visit(f UpdateFunc) {
	n.visit(make([]lpm.Component, 0, 16), func(k []lpm.Component) {
		val, found := n.Get(k)
		if found {
			val2, del := f(k, val)
			if !del {
				n.Update(k, val2)
			} else {
				n.Delete(k)
			}
		}
	})
}
