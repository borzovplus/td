package telegram

import (
	"bytes"
	"crypto/aes"
	"crypto/sha1" // #nosec G505
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gotd/ige"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/crypto"
)

func TestEncryptBindTempAuthKeyMessage(t *testing.T) {
	var (
		permKey crypto.Key
		tempKey crypto.Key
	)
	for i := range permKey {
		permKey[i] = byte(i + 1)
		tempKey[i] = byte(255 - i)
	}
	perm := permKey.WithID()
	temp := tempKey.WithID()

	const (
		nonce       = int64(123456789)
		sessionID   = int64(987654321)
		expiresAt   = 1700000000
		payloadSize = 40
	)

	encrypted, err := encryptBindTempAuthKeyMessage(
		bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)),
		perm,
		temp,
		nonce,
		sessionID,
		expiresAt,
	)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(encrypted), 16)

	var msgKey bin.Int128
	copy(msgKey[:], encrypted[:16])

	ciphertext := encrypted[16:]
	require.Zero(t, len(ciphertext)%aes.BlockSize)

	key, iv := crypto.OldKeys(perm.Value, msgKey, crypto.Client)
	block, err := aes.NewCipher(key[:])
	require.NoError(t, err)

	plaintext := make([]byte, len(ciphertext))
	ige.DecryptBlocks(block, iv[:], plaintext, ciphertext)

	payload := plaintext[:payloadSize]
	hash := sha1.Sum(payload) // #nosec G401
	require.Equal(t, hash[4:20], msgKey[:])

	var b bin.Buffer
	b.Buf = payload
	require.NoError(t, b.ConsumeID(bindAuthKeyInnerTypeID))

	gotNonce, err := b.Long()
	require.NoError(t, err)
	require.Equal(t, nonce, gotNonce)

	gotTempID, err := b.Long()
	require.NoError(t, err)
	require.Equal(t, temp.IntID(), gotTempID)

	gotPermID, err := b.Long()
	require.NoError(t, err)
	require.Equal(t, perm.IntID(), gotPermID)

	gotSessionID, err := b.Long()
	require.NoError(t, err)
	require.Equal(t, sessionID, gotSessionID)

	gotExpiresAt, err := b.Int()
	require.NoError(t, err)
	require.Equal(t, expiresAt, gotExpiresAt)
}
