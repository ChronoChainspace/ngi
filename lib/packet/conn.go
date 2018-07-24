/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package packet

import (
	"io"
	"net"
	"syscall"
	"time"
)

var (
	keepAlive = []byte{0x01}
	shutdown  = []byte{0x02}
)

type conn struct {
	io.Reader
	io.Writer
	io.Closer
	laddr, raddr net.Addr
	closed       chan struct{}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) {
	return f(b)
}

type closerFunc func() error

func (f closerFunc) Close() error {
	return f()
}

func newConn(r io.Reader, w io.Writer, closer io.Closer, laddr, raddr net.Addr) *conn {
	c := &conn{
		Reader: r,
		Writer: w,
		Closer: closer,
		laddr:  laddr,
		raddr:  raddr,
		closed: make(chan struct{}),
	}

	go func() {
		c.Write(keepAlive)
		ticker := time.NewTicker(heartbeatIntv)
		defer ticker.Stop()
		for {
			select {
			case <-c.closed:
				return
			case <-ticker.C:
				c.Write(keepAlive)
			}
		}
	}()
	return c
}

func (c *conn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *conn) Read(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, syscall.EINVAL
	default:
		return c.Reader.Read(b)
	}
}

func (c *conn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, syscall.EINVAL
	default:
		return c.Writer.Write(b)
	}
}

func (c *conn) Close() error {
	c.Write(shutdown)
	close(c.closed)
	return c.Closer.Close()
}

func (c *conn) SetDeadline(time.Time) error      { return nil }
func (c *conn) SetReadDeadline(time.Time) error  { return nil }
func (c *conn) SetWriteDeadline(time.Time) error { return nil }
