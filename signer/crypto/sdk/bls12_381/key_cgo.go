//go:build ((linux && amd64) || (linux && arm64) || (darwin && amd64) || (darwin && arm64) || (windows && amd64)) && bls12381

package bls12_381

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/tmhash"

	bls12381 "github.com/cosmos/crypto/curves/bls12381"
)

// ===============================================================================================
// Private Key
// ===============================================================================================

// PrivKey is a wrapper around the BLS12-381 private key type.
// This wrapper conforms to crypto.PrivKey to allow for the use of the BLS12-381 private key type.

var _ crypto.PrivKey = &PrivKey{}

// NewPrivateKeyFromBytes builds a new key from the given bytes.
func NewPrivateKeyFromBytes(bz []byte) (*PrivKey, error) {
	if len(bz) != PrivKeySize {
		return nil, errors.New("invalid private key size")
	}
	secretKey, err := bls12381.SecretKeyFromBytes(bz)
	if err != nil {
		return nil, err
	}
	return &PrivKey{
		Key: secretKey.Marshal(),
	}, nil
}

// GenPrivKey generates a new key.
func GenPrivKey() (*PrivKey, error) {
	secretKey, err := bls12381.RandKey()
	if err != nil {
		return nil, err
	}
	return &PrivKey{
		Key: secretKey.Marshal(),
	}, nil
}

// Bytes returns the byte representation of the Key.
func (privKey *PrivKey) Bytes() []byte {
	return privKey.Key
}

// PubKey returns the private key's public key.
func (privKey *PrivKey) PubKey() crypto.PubKey {
	secretKey, err := bls12381.SecretKeyFromBytes(privKey.Key)
	if err != nil {
		return nil
	}
	return &PubKey{
		Key: secretKey.PublicKey().Marshal(),
	}
}

// Sign signs the given message.
func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	secretKey, err := bls12381.SecretKeyFromBytes(privKey.Key)
	if err != nil {
		return nil, err
	}

	if len(msg) > MaxMsgLen {
		hash := sha256.Sum256(msg)
		sig := secretKey.Sign(hash[:])
		return sig.Marshal(), nil
	}
	sig := secretKey.Sign(msg)
	return sig.Marshal(), nil
}

// Equals returns true if two keys are equal and false otherwise.
func (privKey *PrivKey) Equals(other crypto.PrivKey) bool {
	otherPrivKey, ok := other.(*PrivKey)
	if !ok {
		return false
	}
	return bytes.Equal(privKey.Bytes(), otherPrivKey.Bytes())
}

// Type returns the key's type.
func (privKey *PrivKey) Type() string {
	return KeyType
}

// ===============================================================================================
// Public Key
// ===============================================================================================

// PubKey is a wrapper around the BLS12-381 public key type.
// This wrapper conforms to crypto.PubKey to allow for the use of the BLS12-381 public key type.

var _ crypto.PubKey = &PubKey{}

// Address returns the address of the key.
func (pubKey *PubKey) Address() crypto.Address {
	if len(pubKey.Key) != PubKeySize {
		panic("pubkey is incorrect size")
	}
	return crypto.Address(tmhash.SumTruncated(pubKey.Bytes()))
}

// Bytes returns the byte representation of the key.
func (pubKey *PubKey) Bytes() []byte {
	return pubKey.Key
}

// VerifySignature verifies the given signature.
func (pubKey *PubKey) VerifySignature(msg, sig []byte) bool {
	if len(sig) != SignatureLength {
		return false
	}

	// 復元した公開鍵を取得
	pubK, err := bls12381.PublicKeyFromBytes(pubKey.Key)
	if err != nil { // invalid pubkey
		return false
	}

	// メッセージのハッシュ処理
	if len(msg) > MaxMsgLen {
		hash := sha256.Sum256(msg)
		msg = hash[:]
	}

	// 署名を復元
	signature, err := bls12381.SignatureFromBytes(sig)
	if err != nil {
		return false
	}

	// 署名の検証
	ok := signature.Verify(pubK, msg)
	return ok
}

// Equals returns true if two public keys are equal.
func (pubKey *PubKey) Equals(other crypto.PubKey) bool {
	otherPubKey, ok := other.(*PubKey)
	if !ok {
		return false
	}
	return bytes.Equal(pubKey.Bytes(), otherPubKey.Bytes())
}

// Type returns the key's type.
func (pubKey *PubKey) Type() string {
	return KeyType
}

// String returns a string representation of the public key.
func (pubKey *PubKey) String() string {
	return fmt.Sprintf("PubKeyBLS12_381{%X}", pubKey.Key)
}
