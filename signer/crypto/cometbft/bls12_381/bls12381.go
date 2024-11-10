//go:build bls12381

package bls12381

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	blst "github.com/supranational/blst/bindings/go"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtjson "github.com/cometbft/cometbft/libs/json"
)

// ===============================================================================================
// Constants
// ===============================================================================================

const (
	// Enabled indicates if this curve is enabled.
	Enabled = true
	// PrivKeySize defines the length of the PrivKey byte array.
	PrivKeySize = 32
	// PubKeySize defines the length of the PubKey byte array.
	PubKeySize = 48 // 圧縮形式の公開鍵サイズ
	// SignatureSize defines the byte length of a BLS signature.
	SignatureSize = 96 // 圧縮形式の署名サイズ
	// KeyType is the string constant for the BLS12-381 algorithm.
	KeyType = "bls12_381"
	// BLS12-381 private key name.
	PrivKeyName = "cometbft/PrivKeyBls12_381"
	// BLS12-381 public key name.
	PubKeyName = "cometbft/PubKeyBls12_381"
)

var (
	// ErrDeserialization is returned when deserialization fails.
	ErrDeserialization = errors.New("bls12381: deserialization error")
	// ErrInfinitePubKey is returned when the public key is infinite. It is part
	// of a more comprehensive subgroup check on the key.
	ErrInfinitePubKey = errors.New("bls12381: pubkey is infinite")
	// ErrInvalidSignature is returned when the signature is invalid.
	ErrInvalidSignature = errors.New("bls12381: invalid signature")

	dstMinSig = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
)

// For minimal-pubkey-size operations.
//
// Changing this to 'minimal-signature-size' would render CometBFT not Ethereum
// compatible.
type (
	blstPublicKey          = blst.P1Affine
	blstSignature          = blst.P2Affine
	blstAggregateSignature = blst.P2Aggregate
	blstAggregatePublicKey = blst.P1Aggregate
)

func init() {
	cmtjson.RegisterType(&PubKey{}, PubKeyName)
	cmtjson.RegisterType(&PrivKey{}, PrivKeyName)
}

// ===============================================================================================
// Private Key
// ===============================================================================================

// PrivKey is a wrapper around the Ethereum BLS12-381 private key type.
// This wrapper conforms to crypto.PrivKey to allow for the use of the Ethereum BLS12-381 private key type.

var _ crypto.PrivKey = (*PrivKey)(nil)

type PrivKey struct {
	sk *blst.SecretKey
}

// GenPrivKeyFromSecret generates a new random key using `secret` for the seed
func GenPrivKeyFromSecret(secret []byte) (*PrivKey, error) {
	if len(secret) != 32 {
		seed := sha256.Sum256(secret) // We need 32 bytes
		secret = seed[:]
	}

	sk := blst.KeyGen(secret)
	return &PrivKey{sk: sk}, nil
}

// NewPrivateKeyFromBytes builds a new key from the given bytes.
func NewPrivateKeyFromBytes(bz []byte) (*PrivKey, error) {
	sk := new(blst.SecretKey).Deserialize(bz)
	if sk == nil {
		return nil, ErrDeserialization
	}
	return &PrivKey{sk: sk}, nil
}

// GenPrivKey generates a new key.
func GenPrivKey() (*PrivKey, error) {
	var ikm [32]byte
	_, err := rand.Read(ikm[:])
	if err != nil {
		return nil, err
	}
	return GenPrivKeyFromSecret(ikm[:])
}

// Bytes returns the byte representation of the Key.
func (privKey *PrivKey) Bytes() []byte {
	return privKey.sk.Serialize()
}

// PubKey returns the private key's public key. If the privkey is not valid it returns a nil value.
func (privKey *PrivKey) PubKey() crypto.PubKey {
	return &PubKey{pk: new(blstPublicKey).From(privKey.sk)}
}

// Type returns the type.
func (PrivKey) Type() string {
	return KeyType
}

// Sign signs the given byte array.
func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	signature := new(blstSignature).Sign(privKey.sk, msg, dstMinSig)
	return signature.Compress(), nil
}

// Equals compares two private keys for equality.
func (privKey *PrivKey) Equals(other crypto.PrivKey) bool {
	if otherPrivKey, ok := other.(*PrivKey); ok {
		return privKey.sk.Equals(otherPrivKey.sk)
	}
	return false
}

// Zeroize clears the private key.
func (privKey *PrivKey) Zeroize() {
	privKey.sk.Zeroize()
}

// MarshalJSON marshals the private key to JSON.
func (privKey *PrivKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(privKey.Bytes())
}

// UnmarshalJSON unmarshals the private key from JSON.
func (privKey *PrivKey) UnmarshalJSON(bz []byte) error {
	var rawBytes []byte
	if err := json.Unmarshal(bz, &rawBytes); err != nil {
		return err
	}
	pk, err := NewPrivateKeyFromBytes(rawBytes)
	if err != nil {
		return err
	}
	privKey.sk = pk.sk
	return nil
}

// ===============================================================================================
// Public Key
// ===============================================================================================

// PubKey is a wrapper around the Ethereum BLS12-381 public key type.
// This wrapper conforms to crypto.PubKey to allow for the use of the Ethereum BLS12-381 public key type.

var _ crypto.PubKey = (*PubKey)(nil)

type PubKey struct {
	pk *blstPublicKey
}

// NewPublicKeyFromBytes returns a new public key from the given bytes.
func NewPublicKeyFromBytes(bz []byte) (*PubKey, error) {
	pk := new(blstPublicKey).Uncompress(bz)
	if pk == nil {
		return nil, ErrDeserialization
	}
	// Subgroup and infinity check
	if !pk.KeyValidate() {
		return nil, ErrInfinitePubKey
	}
	return &PubKey{pk: pk}, nil
}

// Address returns the address of the key.
// The function will panic if the public key is invalid.
func (pubKey *PubKey) Address() crypto.Address {
	return crypto.Address(tmhash.SumTruncated(pubKey.Bytes()))
}

func (pubKey *PubKey) Reset() {
	*pubKey = PubKey{}
}

func (pubKey *PubKey) String() string {
	return fmt.Sprintf("PubKeyBLS12_381{%X}", pubKey.Bytes())
}

func (pubKey *PubKey) ProtoMessage() {}

// VerifySignature verifies the given signature.
func (pubKey *PubKey) VerifySignature(msg, sig []byte) bool {
	signature := new(blstSignature).Uncompress(sig)
	if signature == nil {
		return false
	}

	// Group check signature. Do not check for infinity since an aggregated signature could be infinite.
	if !signature.SigValidate(false) {
		return false
	}

	return signature.Verify(false, pubKey.pk, false, msg, dstMinSig)
}

// Bytes returns the byte format.
func (pubKey *PubKey) Bytes() []byte {
	return pubKey.pk.Compress()
}

// Type returns the key's type.
func (PubKey) Type() string {
	return KeyType
}

// Equals compares two public keys for equality.
func (pubKey *PubKey) Equals(other crypto.PubKey) bool {
	if otherPubKey, ok := other.(*PubKey); ok {
		return pubKey.pk.Equals(otherPubKey.pk)
	}
	return false
}

// MarshalJSON marshals the public key to JSON.
func (pubKey *PubKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(pubKey.Bytes())
}

// UnmarshalJSON unmarshals the public key from JSON.
func (pubKey *PubKey) UnmarshalJSON(bz []byte) error {
	var rawBytes []byte
	if err := json.Unmarshal(bz, &rawBytes); err != nil {
		return err
	}
	pk, err := NewPublicKeyFromBytes(rawBytes)
	if err != nil {
		return err
	}
	pubKey.pk = pk.pk
	return nil
}

// ===============================================================================================
// Batch Verification
// ===============================================================================================

// BatchVerifier implements batch verification for BLS signatures.
type BatchVerifier struct {
	messages   [][]byte
	pubKeys    []*blstPublicKey
	signatures []*blstSignature
}

var _ crypto.BatchVerifier = &BatchVerifier{}

// NewBatchVerifier creates a new BatchVerifier instance.
func NewBatchVerifier() crypto.BatchVerifier {
	return &BatchVerifier{}
}

// Add adds a new public key, message, and signature to the batch.
func (b *BatchVerifier) Add(key crypto.PubKey, msg, signature []byte) error {
	pubKey, ok := key.(*PubKey)
	if !ok {
		return fmt.Errorf("expected *PubKey, got %T", key)
	}

	sig := new(blstSignature).Uncompress(signature)
	if sig == nil {
		return ErrInvalidSignature
	}

	b.messages = append(b.messages, msg)
	b.pubKeys = append(b.pubKeys, pubKey.pk)
	b.signatures = append(b.signatures, sig)
	return nil
}

// Verify performs batch verification of all added signatures.
func (b *BatchVerifier) Verify() (bool, []bool) {
	individualResults := make([]bool, len(b.messages))
	allValid := true
	for i := range b.messages {
		valid := b.signatures[i].Verify(false, b.pubKeys[i], false, b.messages[i], dstMinSig)
		individualResults[i] = valid
		if !valid {
			allValid = false
		}
	}
	return allValid, individualResults
}
