/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package ngi


import "./lib/ngi"

type Publisher struct {
	ngi.Cache
	mw []Middleware
}

func NewPublisher(cache ngi.Cache) *Publisher {
	return &Publisher{
		Cache: cache,
	}
}

func (p *Publisher) Use(m Middleware) {
	p.mw = append(p.mw, m)
}

func (p *Publisher) Publish(d *ngi.Data, mw ...Middleware) error {
	h := Handler(HandlerFunc(func(w ngi.Sender, _ *ngi.Interest) error {
		return w.SendData(d)
	}))
	for _, m := range p.mw {
		h = m(h)
	}
	for _, m := range mw {
		h = m(h)
	}
	return h.ServeNGI(&cacher{
		CacherOptions: CacherOptions{
			Cache: p.Cache,
		}}, nil)
}