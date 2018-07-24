/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package ngi

import "./lib/ngi"

type Handler interface {
	ServeNGI(ngi.Sender, *ngi.Interest) error
}

type HandlerFunc func(ngi.Sender, *ngi.Interest) error


func (f HandlerFunc) ServeNGI(w ngi.Sender, i *ngi.Interest) error {
	return f(w, i)
}

type Middleware func(Handler) Handler

type Hijacker interface {
	Hijack() ngi.Sender
}
