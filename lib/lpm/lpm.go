/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

// longest prefix match (LPM)

package lpm

import (
	"net/url"
	"strings"
)

type Component []byte

func NewComponents(s string) (cs []Component) {
	if !strings.HasPrefix(s, "/") {
		return
	}
	s = s[1:]
	if s == "" {
		return
	}
	parts := strings.Split(s, "/")
	cs = make([]Component, len(parts))
	for i := range parts {
		parts[i], _ = url.QueryUnescape(parts[i])
		cs[i] = Component(parts[i])
	}
	return
}

func (c Component) String() string {
	return url.QueryEscape(string(c))
}
