/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package tlv

import (
	"hash"
	"reflect"
)

func Marshal(v interface{}, t uint64) ([]byte, error) {
	b := make([]byte, MaxSize)
	n, err := writeTLV(b, t, reflect.ValueOf(v), false)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

func Hash(f func() hash.Hash, v interface{}) ([]byte, error) {
	value := reflect.Indirect(reflect.ValueOf(v))
	if value.Kind() != reflect.Struct {
		return nil, ErrNotSupported
	}
	b := make([]byte, MaxSize)
	n, err := writeStruct(b, value, true)
	if err != nil {
		return nil, err
	}
	h := f()
	h.Write(b[:n])
	return h.Sum(nil), nil
}
