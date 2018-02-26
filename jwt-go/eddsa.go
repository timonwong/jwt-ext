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
	// SigningMethodEdDSA is EdDSA signing method.
	SigningMethodEdDSA jwt.SigningMethod

	// ErrEd25519Verification is the error for ed25519 verification error.
	ErrEd25519Verification = errors.New("crypto/ed25519: verification error")
)

func init() {
	SigningMethodEdDSA = &SigningMethodEdDSAImpl{}
	jwt.RegisterSigningMethod(algName, func() jwt.SigningMethod {
		return SigningMethodEdDSA
	})
}

// SigningMethodEdDSAImpl implements the EdDSA singing method using ed25519.
type SigningMethodEdDSAImpl struct{}

// Alg implements jwt.SigningMethod interface.
func (m *SigningMethodEdDSAImpl) Alg() string {
	return algName
}

// Verify implements jwt.SigningMethod interface.
// For this verify method, key must be an ed25519.PublicKey or []byte.
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

	// Check key length to avoid panics inside ed25519
	if len(edKey) != ed25519.PublicKeySize {
		return jwt.ErrInvalidKey
	}

	// Verify the signature
	if ok := ed25519.Verify(edKey, []byte(signingString), sig); ok {
		return nil
	} else {
		return ErrEd25519Verification
	}
}

// Sign implements jwt.SigningMethod interface.
// For this signing method, key must be an ed25519.PrivateKey or []byte.
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

	// Check key length to avoid panics inside ed25519
	if len(edKey) != ed25519.PrivateKeySize {
		return "", jwt.ErrInvalidKey
	}

	sig := ed25519.Sign(edKey, []byte(signingString))
	return jwt.EncodeSegment(sig), nil
}
