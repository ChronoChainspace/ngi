/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package ngi

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"../tlv"
)

type HMACKey struct {
	Name
	PrivateKey []byte
}

func (key *HMACKey) Locator() Name {
	return key.Name
}

func (key *HMACKey) Private() ([]byte, error) {
	return key.PrivateKey, nil
}

func (key *HMACKey) Public() ([]byte, error) {
	return key.PrivateKey, nil
}

func (key *HMACKey) SignatureType() uint64 {
	return SignatureTypeSHA256WithHMAC
}

func (key *HMACKey) Sign(v interface{}) ([]byte, error) {
	return tlv.Hash(func() hash.Hash {
		return hmac.New(sha256.New, key.PrivateKey)
	}, v)
}

func (key *HMACKey) Verify(v interface{}, signature []byte) error {
	expectedMAC, err := key.Sign(v)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, expectedMAC) {
		return ErrInvalidSignature
	}
	return nil
}
