//go:build bls12381

package bls12381_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto"
	bls12381 "github.com/liray-unendlich/horcrux-bls/signer/crypto/cometbft/bls12_381"
)

func TestNewPrivateKeyFromBytes(t *testing.T) {
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()

	privKeyBytes := privKey.Bytes()
	privKey2, err := bls12381.NewPrivateKeyFromBytes(privKeyBytes)
	require.NoError(t, err)
	defer privKey2.Zeroize()

	assert.True(t, privKey.Equals(privKey2))

	_, err = bls12381.NewPrivateKeyFromBytes(crypto.CRandBytes(31))
	assert.Error(t, err)
}

func TestGenPrivKey(t *testing.T) {
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()
	assert.NotNil(t, privKey)
}

func TestGenPrivKeyFromSecret(t *testing.T) {
	secret := []byte("this is my secret")
	privKey, err := bls12381.GenPrivKeyFromSecret(secret)
	require.NoError(t, err)
	assert.NotNil(t, privKey)
}

func TestGenPrivKeyFromSecret_SignVerify(t *testing.T) {
	secret := []byte("this is my secret for priv key")
	priv, err := bls12381.GenPrivKeyFromSecret(secret)
	require.NoError(t, err)
	defer priv.Zeroize()

	msg := []byte("this is my message to sign")
	sig, err := priv.Sign(msg)
	require.NoError(t, err)

	pub := priv.PubKey()
	assert.True(t, pub.VerifySignature(msg, sig), "Signature did not verify")
}

func TestPrivKeyBytes(t *testing.T) {
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()

	privKeyBytes := privKey.Bytes()
	privKey2, err := bls12381.NewPrivateKeyFromBytes(privKeyBytes)
	require.NoError(t, err)
	defer privKey2.Zeroize()

	assert.True(t, privKey.Equals(privKey2))
}

func TestPrivKeyPubKey(t *testing.T) {
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()

	pubKey := privKey.PubKey()
	assert.NotNil(t, pubKey)
}

func TestPrivKeyType(t *testing.T) {
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()

	assert.Equal(t, "bls12_381", privKey.Type())
}

func TestPrivKeySignAndPubKeyVerifySignature(t *testing.T) {
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()

	pubKey := privKey.PubKey()

	msg := crypto.CRandBytes(32)
	sig, err := privKey.Sign(msg)
	require.NoError(t, err)

	assert.True(t, pubKey.VerifySignature(msg, sig))

	// Modify the signature to ensure verification fails
	sig[7] ^= byte(0x01)
	assert.False(t, pubKey.VerifySignature(msg, sig))

	// Sign and verify a longer message
	msg = crypto.CRandBytes(192)
	sig, err = privKey.Sign(msg)
	require.NoError(t, err)
	assert.True(t, pubKey.VerifySignature(msg, sig))
}

func TestPubKey(t *testing.T) {
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()

	pubKey := privKey.PubKey()
	assert.NotNil(t, pubKey)
}

func TestPubKeyType(t *testing.T) {
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()

	pubKey := privKey.PubKey()
	assert.Equal(t, "bls12_381", pubKey.Type())
}

func TestConst(t *testing.T) {
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()

	// Verify private key size
	assert.Equal(t, bls12381.PrivKeySize, len(privKey.Bytes()))

	pubKey := privKey.PubKey()
	// Verify public key size (48 bytes)
	assert.Equal(t, bls12381.PubKeySize, len(pubKey.Bytes()))

	msg := crypto.CRandBytes(32)
	sig, err := privKey.Sign(msg)
	require.NoError(t, err)

	// Verify signature size (96 bytes)
	assert.Equal(t, bls12381.SignatureSize, len(sig))
}

func TestPrivKey_MarshalJSON(t *testing.T) {
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()

	jsonBytes, err := privKey.MarshalJSON()
	require.NoError(t, err)

	privKey2 := new(bls12381.PrivKey)
	err = privKey2.UnmarshalJSON(jsonBytes)
	require.NoError(t, err)
	defer privKey2.Zeroize()

	assert.True(t, privKey.Equals(privKey2))
}

func TestPubKey_MarshalJSON(t *testing.T) {
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()

	pubKeyInterface := privKey.PubKey()

	// Cast to *bls12381.PubKey
	pubKey, ok := pubKeyInterface.(*bls12381.PubKey)
	require.True(t, ok, "failed to cast pubKey to *bls12381.PubKey")

	jsonBytes, err := pubKey.MarshalJSON()
	require.NoError(t, err)

	pubKey2 := new(bls12381.PubKey)
	err = pubKey2.UnmarshalJSON(jsonBytes)
	require.NoError(t, err)

	assert.True(t, pubKey.Equals(pubKey2))
}

func TestPubKey_NewPublicKeyFromInvalidBytes(t *testing.T) {
	// Generate a valid public key
	privKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	defer privKey.Zeroize()

	pubKey := privKey.PubKey().(*bls12381.PubKey)
	pubKeyBytes := pubKey.Bytes()

	testCases := []struct {
		desc        string
		pkBytes     []byte
		expectedErr error
	}{
		{
			desc: "InvalidCompressedPubKey",
			pkBytes: func() []byte {
				// Corrupt the compressed public key bytes
				corruptedBytes := make([]byte, len(pubKeyBytes))
				copy(corruptedBytes, pubKeyBytes)
				corruptedBytes[0] ^= 0xFF
				return corruptedBytes
			}(),
			expectedErr: bls12381.ErrDeserialization,
		},
		{
			desc: "InvalidSubgroupPubKey",
			pkBytes: func() []byte {
				// Modify the last byte to fail subgroup check
				corruptedBytes := make([]byte, len(pubKeyBytes))
				copy(corruptedBytes, pubKeyBytes)
				corruptedBytes[len(corruptedBytes)-1] ^= 0x01
				return corruptedBytes
			}(),
			expectedErr: bls12381.ErrInfinitePubKey,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := bls12381.NewPublicKeyFromBytes(tc.pkBytes)
			require.Equal(t, tc.expectedErr, err)
			t.Log(tc.desc, "NewPublicKeyFromBytes error:", err)
		})
	}
}
