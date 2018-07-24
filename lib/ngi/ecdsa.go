/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package ngi

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"

	"../tlv"
)

type ECDSAKey struct {
	Name
	*ecdsa.PrivateKey
}

func (key *ECDSAKey) Locator() Name {
	return key.Name
}

func (key *ECDSAKey) Private() ([]byte, error) {
	return x509.MarshalECPrivateKey(key.PrivateKey)
}

func (key *ECDSAKey) Public() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key.PrivateKey.Public())
}

func (key *ECDSAKey) SignatureType() uint64 {
	return SignatureTypeSHA256WithECDSA
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (key *ECDSAKey) Sign(v interface{}) ([]byte, error) {
	digest, err := tlv.Hash(sha256.New, v)
	if err != nil {
		return nil, err
	}
	var sig ecdsaSignature
	sig.R, sig.S, err = ecdsa.Sign(rand.Reader, key.PrivateKey, digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sig)
}

func (key *ECDSAKey) Verify(v interface{}, signature []byte) error {
	digest, err := tlv.Hash(sha256.New, v)
	if err != nil {
		return err
	}
	var sig ecdsaSignature
	_, err = asn1.Unmarshal(signature, &sig)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(&key.PrivateKey.PublicKey, digest, sig.R, sig.S) {
		return ErrInvalidSignature
	}
	return nil
}
