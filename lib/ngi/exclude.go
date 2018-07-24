/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package ngi

import (
	"bytes"
	"../lpm"
	"../tlv"
)

type Interval struct {
	lpm.Component
	Any bool
}

type Exclude []Interval

func (ex Exclude) Match(c lpm.Component) bool {
	for i := len(ex) - 1; i >= 0; i-- {
		cmp := bytes.Compare(ex[i].Component, c)
		if cmp == 0 {
			return true
		}
		if cmp < 0 {
			return ex[i].Any
		}
	}
	return false
}

func (ex *Exclude) UnmarshalBinary(b []byte) error {
	r := tlv.NewReader(bytes.NewReader(b))
	for {
		switch r.Peek() {
		case 19:
			if len(*ex) == 0 {
				*ex = append(*ex, Interval{})
			}
			err := r.Read(&(*ex)[len(*ex)-1].Any, 19)
			if err != nil {
				return err
			}
		case 8:
			var intv Interval
			err := r.Read(&intv.Component, 8)
			if err != nil {
				return err
			}
			*ex = append(*ex, intv)
		case 0:
			return nil
		default:
			return ErrNotSupported
		}
	}
}

func (ex Exclude) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	w := tlv.NewWriter(buf)
	for _, intv := range ex {
		if len(intv.Component) != 0 {
			err := w.Write(intv.Component, 8)
			if err != nil {
				return nil, err
			}
		}
		err := w.Write(intv.Any, 19)
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}
