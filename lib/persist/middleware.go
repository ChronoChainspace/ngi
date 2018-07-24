/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package persist

import "../../../ngi"

func Cacher(file string) ngi.Middleware {
	c, err := New(file)
	if err != nil {
		panic(err)
	}
	return ngi.RawCacher(&ngi.CacherOptions{
		Cache: c,
	})
}