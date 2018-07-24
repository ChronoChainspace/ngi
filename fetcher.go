/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package ngi

import "./lib/ngi"

type Fetcher struct {
	Handler
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		Handler: HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
			d, err := w.SendInterest(i)
			if err != nil {
				return err
			}
			return w.SendData(d)
		}),
	}
}

func (f *Fetcher) Use(m Middleware) {
	f.Handler = m(f.Handler)
}

type collector struct {
	ngi.Sender
	*ngi.Data
}

func (c *collector) SendData(d *ngi.Data) error {
	if c.Data == nil {
		c.Data = d
	}
	return nil
}

func (f *Fetcher) Fetch(remote ngi.Sender, i *ngi.Interest, mw ...Middleware) ([]byte, error) {
	h := f.Handler
	for _, m := range mw {
		h = m(h)
	}
	c := &collector{Sender: remote}
	err := h.ServeNGI(c, i)
	if err != nil {
		return nil, err
	}
	if c.Data == nil {
		return nil, nil
	}
	return c.Content, nil
}
