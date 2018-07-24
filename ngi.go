/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package ngi

import (
	"sync"
	"time"

	"./lib/lpm"
	"./lib/ngi"
)

type Ngi struct {
	routeMatcher
	mu sync.RWMutex
	Handler
}

func New() *Ngi {
	NGI := new(Ngi)
	NGI.Handler = HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
		var h Handler
		NGI.mu.RLock()
		val, ok := NGI.Match(i.Name.Components)
		if ok {
			h = val
		}
		NGI.mu.RUnlock()

		if h != nil {
			return h.ServeNGI(w, i)
		}
		return nil
	})
	return NGI
}

func (NGI *Ngi) Use(m Middleware) {
	NGI.Handler = m(NGI.Handler)
}

func (NGI *Ngi) Handle(name string, h Handler, mw ...Middleware) {
	for _, m := range mw {
		h = m(h)
	}
	NGI.mu.Lock()
	NGI.routeMatcher.Update(lpm.NewComponents(name), h)
	NGI.mu.Unlock()
}

func (NGI *Ngi) HandleFunc(name string, h HandlerFunc, mw ...Middleware) {
	NGI.Handle(name, h, mw...)
}

func (NGI *Ngi) Register(w ngi.Sender, key ngi.Key) error {
	var names [][]lpm.Component
	NGI.mu.Lock()
	NGI.routeMatcher.Visit(func(name []lpm.Component, v Handler) (Handler, bool) {
		cpy := make([]lpm.Component, len(name))
		copy(cpy, name)
		names = append(names, cpy)
		return v, false
	})
	NGI.mu.Unlock()

	for _, name := range names {
		err := ngi.SendControl(w, "rib", "register", &ngi.Parameters{
			Name: ngi.Name{Components: name},
		}, key)
		if err != nil {
			return err
		}
	}
	return nil
}

func (NGI *Ngi) Run(w ngi.Sender, ch <-chan *ngi.Interest, key ngi.Key) {
	NGI.Register(w, key)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case i, ok := <-ch:
			if !ok {
				return
			}
			go NGI.ServeNGI(w, i)
		case <-ticker.C:
			go NGI.Register(w, key)
		}
	}
}
