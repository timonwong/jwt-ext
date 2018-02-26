package jwtext

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/ed25519"
)

const (
	algName = "EdDSA"
)

var (
	SigningMethodEdDSA     jwt.SigningMethod
	ErrEd25519Verification = errors.New("crypto/ed25519: verification error")
)

func init() {
	SigningMethodEdDSA = &SigningMethodEdDSAImpl{}
	jwt.RegisterSigningMethod(algName, func() jwt.SigningMethod {
		return SigningMethodEdDSA
	})
}

type SigningMethodEdDSAImpl struct{}

func (m *SigningMethodEdDSAImpl) Alg() string {
	return algName
}

func (m *SigningMethodEdDSAImpl) Verify(signingString, signature string, key interface{}) error {
	var err error

	// Decode the signature
	var sig []byte
	if sig, err = jwt.DecodeSegment(signature); err != nil {
		return err
	}

	// Get the key
	var edKey ed25519.PublicKey
	switch k := key.(type) {
	case []byte:
		edKey = k
	case ed25519.PublicKey:
		edKey = k
	default:
		return jwt.ErrInvalidKeyType
	}

	// Verify the signature
	if status := ed25519.Verify(edKey, []byte(signingString), sig); status == true {
		return nil
	} else {
		return ErrEd25519Verification
	}
}

func (m *SigningMethodEdDSAImpl) Sign(signingString string, key interface{}) (string, error) {
	// Get the key
	var edKey ed25519.PrivateKey
	switch k := key.(type) {
	case []byte:
		edKey = k
	case ed25519.PrivateKey:
		edKey = k
	default:
		return "", jwt.ErrInvalidKeyType
	}

	sig := ed25519.Sign(edKey, []byte(signingString))
	return jwt.EncodeSegment(sig), nil
}
