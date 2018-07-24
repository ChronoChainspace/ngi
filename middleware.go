/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package ngi

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"./lib/lpm"
	"./lib/ngi"
	"./lib/tlv"
	"github.com/sirupsen/logrus"
)

func signed(d *ngi.Data) bool {
	switch d.SignatureInfo.SignatureType {
	case ngi.SignatureTypeSHA256WithRSA:
	case ngi.SignatureTypeSHA256WithECDSA:
	case ngi.SignatureTypeSHA256WithHMAC:
	default:
		return false
	}
	return len(d.SignatureValue) != 0
}

type cacher struct {
	ngi.Sender
	CacherOptions
}

type CacherOptions struct {
	Cache       ngi.Cache
	Copy        bool
	SkipPrivate bool
}

func (c *cacher) SendData(d *ngi.Data) error {
	switch d.MetaInfo.CacheControl {
	case ngi.CacheControlPrivate:
		if !c.SkipPrivate {
			goto CACHE
		}
	case ngi.CacheControlNoStore:
	default:
		goto CACHE
	}
	if c.Sender == nil {
		return nil
	}
	return c.Sender.SendData(d)
CACHE:
	c.Cache.Add(d)
	if c.Sender == nil {
		return nil
	}
	return copySend(c.Sender, d, c.Copy)
}

func copySend(w ngi.Sender, d *ngi.Data, cpy bool) error {
	if cpy {
		copied := new(ngi.Data)
		err := tlv.Copy(copied, d)
		if err != nil {
			return err
		}
		return w.SendData(copied)
	}
	return w.SendData(d)
}

func (c *cacher) Hijack() ngi.Sender {
	return c.Sender
}

func RawCacher(opt *CacherOptions) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
			d := opt.Cache.Get(i)
			if d == nil {
				return next.ServeNGI(&cacher{Sender: w, CacherOptions: *opt}, i)
			}
			return copySend(w, d, opt.Copy)
		})
	}
}

var Cacher = RawCacher(&CacherOptions{
	Cache: ngi.NewCache(65536),
	Copy:  true,
})

func Logger(next Handler) Handler {
	return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
		before := time.Now()
		defer func() {
			logrus.WithFields(logrus.Fields{
				"elapsed": time.Since(before),
				"name":    i.Name,
			}).Info("interest served")
		}()
		return next.ServeNGI(w, i)
	})
}

type segmentor struct {
	ngi.Sender
	size int
}

func (s *segmentor) SendData(d *ngi.Data) error {
	if signed(d) {
		return s.Sender.SendData(d)
	}
	l := d.Name.Len()
	for i := 0; i == 0 || i*s.size < len(d.Content); i++ {
		end := (i + 1) * s.size
		if end > len(d.Content) {
			end = len(d.Content)
		}
		seg := &ngi.Data{
			Content: d.Content[i*s.size : end],
		}
		segNum := encodeMarkedNum(segmentMarker, uint64(i))
		seg.Name.Components = make([]lpm.Component, l+1)
		copy(seg.Name.Components, d.Name.Components)
		seg.Name.Components[l] = segNum

		seg.MetaInfo = d.MetaInfo
		seg.MetaInfo.FinalBlockID = ngi.FinalBlockID{}
		if end == len(d.Content) {
			seg.MetaInfo.FinalBlockID.Component = segNum
		}

		err := s.Sender.SendData(seg)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *segmentor) Hijack() ngi.Sender {
	return s.Sender
}

func Segmentor(size int) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
			return next.ServeNGI(&segmentor{Sender: w, size: size}, i)
		})
	}
}

type assembler struct {
	ngi.Sender
	Handler
	content []byte
	blockID uint64
}

func (a *assembler) SendData(d *ngi.Data) error {
	l := d.Name.Len()
	if l == 0 {
		return nil
	}
	blockID, err := decodeMarkedNum(segmentMarker, d.Name.Components[l-1])
	if err != nil {
		return a.Sender.SendData(d)
	}
	if blockID != a.blockID {
		return nil
	}
	a.blockID++

	a.content = append(a.content, d.Content...)
	finalBlockID, err := decodeMarkedNum(segmentMarker, d.MetaInfo.FinalBlockID.Component)
	if err == nil && blockID >= finalBlockID {

		assembled := &ngi.Data{
			Name:    ngi.Name{Components: d.Name.Components[:l-1]},
			Content: a.content,
		}

		assembled.MetaInfo = d.MetaInfo
		assembled.MetaInfo.FinalBlockID = ngi.FinalBlockID{}
		if l > 1 {
			assembled.MetaInfo.FinalBlockID.Component = assembled.Name.Components[l-2]
		}

		return a.Sender.SendData(assembled)
	}


	seg := new(ngi.Interest)
	seg.Name.Components = make([]lpm.Component, l)
	copy(seg.Name.Components, d.Name.Components[:l-1])
	seg.Name.Components[l-1] = encodeMarkedNum(segmentMarker, a.blockID)
	return a.ServeNGI(a, seg)
}

func (a *assembler) Hijack() ngi.Sender {
	return a.Sender
}

func Assembler(next Handler) Handler {
	return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
		return next.ServeNGI(&assembler{Sender: w, Handler: next}, i)
	})
}

type checksumVerifier struct {
	ngi.Sender
}

var (
	ErrInvalidChecksum = errors.New("invalid checksum")
)

func (v *checksumVerifier) SendData(d *ngi.Data) error {
	var f func() hash.Hash
	switch d.SignatureInfo.SignatureType {
	case ngi.SignatureTypeDigestSHA256:
		f = sha256.New
	case ngi.SignatureTypeDigestCRC32C:
		f = ngi.NewCRC32C
	default:
		return v.Sender.SendData(d)
	}
	digest, err := tlv.Hash(f, d)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, d.SignatureValue) {
		return ErrInvalidChecksum
	}
	return v.Sender.SendData(d)
}

func (v *checksumVerifier) Hijack() ngi.Sender {
	return v.Sender
}

func ChecksumVerifier(next Handler) Handler {
	return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
		return next.ServeNGI(&checksumVerifier{Sender: w}, i)
	})
}

func FileServer(from, to string) (string, Handler) {
	return from, HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
		content, err := ioutil.ReadFile(to + filepath.Clean(strings.TrimPrefix(i.Name.String(), from)))
		if err != nil {
			return err
		}
		return w.SendData(&ngi.Data{
			Name:    i.Name,
			Content: content,
		})
	})
}

func StaticFile(path string) (string, Handler) {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	d := new(ngi.Data)
	err = d.ReadFrom(tlv.NewReader(base64.NewDecoder(base64.StdEncoding, f)))
	if err != nil {
		panic(err)
	}
	return d.Name.String(), HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
		return w.SendData(d)
	})
}

type encryptor struct {
	pub        []*ngi.RSAKey
	keyLocator ngi.Name
	ngi.Sender
}

func (enc *encryptor) SendData(d *ngi.Data) error {
	if signed(d) {
		return enc.Sender.SendData(d)
	}
	if d.MetaInfo.EncryptionType != ngi.EncryptionTypeNone {
		return enc.Sender.SendData(d)
	}

	l := enc.keyLocator.Len()
	keyName := make([]lpm.Component, l+d.Name.Len()+1)
	copy(keyName, enc.keyLocator.Components)
	keyName[l] = []byte("C-KEY")
	copy(keyName[l+1:], d.Name.Components)

	ckey := make([]byte, 16)
	_, err := rand.Read(ckey)
	if err != nil {
		return err
	}


	d.MetaInfo.EncryptionType = ngi.EncryptionTypeAESWithCTR
	d.MetaInfo.EncryptionKeyLocator.Name.Components = keyName
	d.MetaInfo.EncryptionIV = make([]byte, aes.BlockSize)
	_, err = rand.Read(d.MetaInfo.EncryptionIV)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(ckey)
	if err != nil {
		return err
	}
	cipher.NewCTR(block, d.MetaInfo.EncryptionIV).XORKeyStream(d.Content, d.Content)

	err = enc.Sender.SendData(d)
	if err != nil {
		return err
	}

	for _, pub := range enc.pub {
		keyFor := make([]lpm.Component, len(keyName)+pub.Name.Len()+1)
		copy(keyFor, keyName)
		keyFor[len(keyName)] = []byte("FOR")
		copy(keyFor[len(keyName)+1:], pub.Name.Components)

		dkey := new(ngi.Data)
		dkey.Name.Components = keyFor
		dkey.Content, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &pub.PrivateKey.PublicKey, ckey, nil)
		if err != nil {
			return err
		}
		err := enc.Sender.SendData(dkey)
		if err != nil {
			return err
		}
	}
	return nil
}

func (enc *encryptor) Hijack() ngi.Sender {
	return enc.Sender
}

func Encryptor(keyLocator string, pub ...*ngi.RSAKey) Middleware {
	name := ngi.NewName(keyLocator)
	return func(next Handler) Handler {
		return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
			return next.ServeNGI(&encryptor{
				Sender:     w,
				pub:        pub,
				keyLocator: name,
			}, i)
		})
	}
}

type decryptor struct {
	pri *ngi.RSAKey
	Handler
	ngi.Sender
}

func (dec *decryptor) SendData(d *ngi.Data) error {
	if d.MetaInfo.EncryptionType != ngi.EncryptionTypeAESWithCTR {
		return dec.Sender.SendData(d)
	}
	l := d.MetaInfo.EncryptionKeyLocator.Name.Len()
	keyFor := make([]lpm.Component, l+dec.pri.Name.Len()+1)
	copy(keyFor, d.MetaInfo.EncryptionKeyLocator.Name.Components)
	keyFor[l] = []byte("FOR")
	copy(keyFor[l+1:], dec.pri.Name.Components)

	c := &collector{Sender: dec.Sender}
	err := dec.ServeNGI(c, &ngi.Interest{Name: ngi.Name{Components: keyFor}})
	if err != nil {
		return err
	}
	if c.Data == nil {
		return nil
	}

	ckey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, dec.pri.PrivateKey, c.Data.Content, nil)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(ckey)
	if err != nil {
		return err
	}

	cipher.NewCTR(block, d.MetaInfo.EncryptionIV).XORKeyStream(d.Content, d.Content)
	d.MetaInfo.EncryptionType = ngi.EncryptionTypeNone
	d.MetaInfo.EncryptionKeyLocator = ngi.KeyLocator{}
	d.MetaInfo.EncryptionIV = nil

	return dec.Sender.SendData(d)
}

func (dec *decryptor) Hijack() ngi.Sender {
	return dec.Sender
}

func Decryptor(pri *ngi.RSAKey) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
			return next.ServeNGI(&decryptor{Sender: w, pri: pri, Handler: next}, i)
		})
	}
}

type gzipper struct {
	ngi.Sender
}

func (gz *gzipper) SendData(d *ngi.Data) error {
	if signed(d) {
		return gz.Sender.SendData(d)
	}
	if d.MetaInfo.CompressionType != ngi.CompressionTypeNone {
		return gz.Sender.SendData(d)
	}
	buf := new(bytes.Buffer)
	gzw := gzip.NewWriter(buf)
	_, err := gzw.Write(d.Content)
	if err != nil {
		return err
	}
	err = gzw.Close()
	if err != nil {
		return err
	}

	d.MetaInfo.CompressionType = ngi.CompressionTypeGZIP
	d.Content = buf.Bytes()
	return gz.Sender.SendData(d)
}

func (gz *gzipper) Hijack() ngi.Sender {
	return gz.Sender
}

func Gzipper(next Handler) Handler {
	return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
		return next.ServeNGI(&gzipper{Sender: w}, i)
	})
}

type gunzipper struct {
	ngi.Sender
}

func (gz *gunzipper) SendData(d *ngi.Data) error {
	if d.MetaInfo.CompressionType != ngi.CompressionTypeGZIP {
		return gz.Sender.SendData(d)
	}
	gzr, err := gzip.NewReader(bytes.NewReader(d.Content))
	if err != nil {
		return err
	}
	defer gzr.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(gzr)

	d.MetaInfo.CompressionType = ngi.CompressionTypeNone
	d.Content = buf.Bytes()
	return gz.Sender.SendData(d)
}

func (gz *gunzipper) Hijack() ngi.Sender {
	return gz.Sender
}

func Gunzipper(next Handler) Handler {
	return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
		return next.ServeNGI(&gunzipper{Sender: w}, i)
	})
}

type signer struct {
	ngi.Key
	ngi.Sender
}

func (s *signer) SendData(d *ngi.Data) error {
	if signed(d) {
		return s.Sender.SendData(d)
	}
	err := ngi.SignData(s, d)
	if err != nil {
		return err
	}
	return s.Sender.SendData(d)
}

func (s *signer) Hijack() ngi.Sender {
	return s.Sender
}

func Signer(key ngi.Key) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
			return next.ServeNGI(&signer{Sender: w, Key: key}, i)
		})
	}
}

type VerifyRule struct {
	DataPattern string
	re          *regexp.Regexp

	KeyPattern string
	DataSHA256 string
}

type verifier struct {
	ngi.Sender
	Handler
	rule []*VerifyRule
}

var (
	ErrUntrustedKeyName = errors.New("untrusted key name")
	ErrUntrustedData    = errors.New("untrusted data")
	ErrFetchKey         = errors.New("cannot fetch key")
)

func (v *verifier) verify(d *ngi.Data) error {
	name := d.Name.String()
	keyName := d.SignatureInfo.KeyLocator.Name.String()
	for _, rule := range v.rule {
		if !rule.re.MatchString(name) {
			continue
		}

		if rule.DataSHA256 != "" {
			h := sha256.New()
			err := d.WriteTo(tlv.NewWriter(h))
			if err != nil {
				return err
			}
			if rule.DataSHA256 != fmt.Sprintf("%x", h.Sum(nil)) {
				return ErrInvalidChecksum
			}
			return nil
		}

		if rule.KeyPattern != "" &&
			!regexp.MustCompile(rule.re.ReplaceAllString(name, rule.KeyPattern)).MatchString(keyName) {
			return ErrUntrustedKeyName
		}
		c := &collector{Sender: v.Sender}
		err := v.ServeNGI(c, &ngi.Interest{Name: d.SignatureInfo.KeyLocator.Name})
		if err != nil {
			return err
		}
		if c.Data == nil {

			return ErrFetchKey
		}

		key, err := ngi.CertificateFromData(c.Data)
		if err != nil {

			return err
		}

		err = ngi.VerifyData(key, d)
		if err != nil {
			return err
		}
		return v.verify(c.Data)
	}
	return ErrUntrustedData
}

func (v *verifier) SendData(d *ngi.Data) error {
	name := d.Name.String()
	for _, rule := range v.rule {
		if !rule.re.MatchString(name) {
			continue
		}
		
		err := v.verify(d)
		if err != nil {
			return err
		}
		return v.Sender.SendData(d)
	}
	return v.Sender.SendData(d)
}

func (v *verifier) Hijack() ngi.Sender {
	return v.Sender
}

func Verifier(rule ...*VerifyRule) Middleware {
	for _, r := range rule {
		r.re = regexp.MustCompile(r.DataPattern)
	}
	return func(next Handler) Handler {
		return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
			return next.ServeNGI(&verifier{Sender: w, Handler: next, rule: rule}, i)
		})
	}
}

type versioner struct {
	ngi.Sender
}

func (v *versioner) SendData(d *ngi.Data) error {
	if signed(d) {
		return v.Sender.SendData(d)
	}
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()/1000000))
	d.Name.Components = append(d.Name.Components, timestamp)
	return v.Sender.SendData(d)
}

func (v *versioner) Hijack() ngi.Sender {
	return v.Sender
}

func Versioner(next Handler) Handler {
	return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
		return next.ServeNGI(&versioner{Sender: w}, i)
	})
}

type queuer struct {
	ngi.Sender
	d []*ngi.Data
}

func (q *queuer) SendData(d *ngi.Data) error {
	q.d = append(q.d, d)
	return nil
}

func (q *queuer) Hijack() ngi.Sender {
	return q.Sender
}

func Queuer(next Handler) Handler {
	return HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
		q := &queuer{Sender: w}
		err := next.ServeNGI(q, i)
		if err != nil {
			return err
		}
		for _, d := range q.d {
			err = w.SendData(d)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func Notify(listener, dataName string) ngi.Name {
	return ngi.NewName(fmt.Sprintf("%s/ACK%s", listener, dataName))
}

func Listener(name string, h func(string, ngi.Sender, *ngi.Interest) error) (string, Handler) {
	name += "/ACK"
	return name, HandlerFunc(func(w ngi.Sender, i *ngi.Interest) error {
		return h(strings.TrimPrefix(i.Name.String(), name), w, i)
	})
}
