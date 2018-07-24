/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package ngi

import "../tlv"

func init() {
	tlv.CacheType((*Interest)(nil))
	tlv.CacheType((*Data)(nil))
	tlv.CacheType((*Command)(nil))
	tlv.CacheType((*CommandResponse)(nil))
}
