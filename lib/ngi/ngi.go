/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package ngi

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"hash/crc32"
	"math/rand"

	"../lpm"
	"../tlv"
)

type Interest struct {
	Name      Name      `tlv:"7"`
	Selectors Selectors `tlv:"9?"`
	Nonce     uint64    `tlv:"10"`
	LifeTime  uint64    `tlv:"12?"`
}

type Selectors struct {
	MinComponents             uint64     `tlv:"133?"`
	MaxComponents             uint64     `tlv:"134?"`
	PublisherPublicKeyLocator KeyLocator `tlv:"15?"`
	Exclude                   Exclude    `tlv:"16?"`
	ChildSelector             uint64     `tlv:"17?"`
	MustBeFresh               bool       `tlv:"18?"`
}

func (sel *Selectors) Match(d *Data, interestLen int) bool {
	dataLen := d.Name.Len()
	if sel.MinComponents != 0 && sel.MinComponents > uint64(dataLen) {
		return false
	}
	if sel.MaxComponents != 0 && sel.MaxComponents < uint64(dataLen) {
		return false
	}
	if sel.PublisherPublicKeyLocator.Name.Len() != 0 &&
		sel.PublisherPublicKeyLocator.Name.Compare(d.SignatureInfo.KeyLocator.Name) != 0 {
		return false
	}
	if len(sel.PublisherPublicKeyLocator.Digest) != 0 &&
		!bytes.Equal(sel.PublisherPublicKeyLocator.Digest, d.SignatureInfo.KeyLocator.Digest) {
		return false
	}
	if dataLen > interestLen && sel.Exclude.Match(d.Name.Components[interestLen]) {
		return false
	}
	return true
}

type Data struct {
	Name           Name          `tlv:"7"`
	MetaInfo       MetaInfo      `tlv:"20"`
	Content        []byte        `tlv:"21"`
	SignatureInfo  SignatureInfo `tlv:"22"`
	SignatureValue []byte        `tlv:"23*"`
}

type MetaInfo struct {
	ContentType          uint64       `tlv:"24?"`
	FreshnessPeriod      uint64       `tlv:"25?"`
	FinalBlockID         FinalBlockID `tlv:"26?"`
	CompressionType      uint64       `tlv:"128?"`
	EncryptionType       uint64       `tlv:"129?"`
	EncryptionKeyLocator KeyLocator   `tlv:"130?"`
	EncryptionIV         []byte       `tlv:"131?"`
	CacheControl         uint64       `tlv:"132?"`
}

type FinalBlockID struct {
	Component lpm.Component `tlv:"8"`
}

const (
	CompressionTypeNone uint64 = 0
	CompressionTypeGZIP        = 1
)

const (
	CacheControlPublic  uint64 = 0
	CacheControlNoStore        = 1
	CacheControlPrivate        = 2
)

const (
	EncryptionTypeNone       uint64 = 0
	EncryptionTypeAESWithCTR        = 1
)

type SignatureInfo struct {
	SignatureType  uint64         `tlv:"27"`
	KeyLocator     KeyLocator     `tlv:"28?"`
	ValidityPeriod ValidityPeriod `tlv:"253?"`
}

const (
	SignatureTypeDigestSHA256    uint64 = 0
	SignatureTypeSHA256WithRSA          = 1
	SignatureTypeDigestCRC32C           = 2
	SignatureTypeSHA256WithECDSA        = 3
	SignatureTypeSHA256WithHMAC         = 4
)

type KeyLocator struct {
	Name   Name   `tlv:"7?"`
	Digest []byte `tlv:"29?"`
}

const (
	ISO8601 = "20060102T150405"
)

type ValidityPeriod struct {
	NotBefore string `tlv:"254"`
	NotAfter  string `tlv:"255"`
}

func (i *Interest) WriteTo(w tlv.Writer) error {
	if i.Nonce == 0 {
		i.Nonce = uint64(rand.Uint32())
	}
	return w.Write(i, 5)
}

func (i *Interest) ReadFrom(r tlv.Reader) error {
	return r.Read(i, 5)
}

var (
	castagnoliTable = crc32.MakeTable(crc32.Castagnoli)
)

func NewCRC32C() hash.Hash {
	return crc32.New(castagnoliTable)
}

func (d *Data) WriteTo(w tlv.Writer) error {
	if len(d.SignatureValue) == 0 {
		var f func() hash.Hash
		switch d.SignatureInfo.SignatureType {
		case SignatureTypeDigestSHA256:
			f = sha256.New
		case SignatureTypeDigestCRC32C:
			f = NewCRC32C
		default:
			return ErrNotSupported
		}
		var err error
		d.SignatureValue, err = tlv.Hash(f, d)
		if err != nil {
			return err
		}
	}
	return w.Write(d, 6)
}

func (d *Data) ReadFrom(r tlv.Reader) error {
	return r.Read(d, 6)
}
