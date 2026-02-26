package telegram

import (
	"context"
	"crypto/aes"
	"crypto/sha1" // #nosec G505
	"io"
	"time"

	"github.com/go-faster/errors"
	"go.uber.org/zap"

	"github.com/gotd/ige"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/crypto"
	"github.com/gotd/td/mtproto"
	"github.com/gotd/td/tg"
)

const (
	bindAuthKeyInnerTypeID   = 0x75a3f765
	defaultTempAuthExpires   = 24 * time.Hour
	defaultTempAuthBindDelay = 15 * time.Second
)

func (c *Client) bindTempAuthKeyAsync(dc int, perm crypto.AuthKey, s mtproto.Session) {
	go func() {
		if err := c.bindTempAuthKeyWithTimeout(dc, perm, s); err != nil {
			c.log.Warn("Failed to bind temporary auth key",
				zap.Int("dc_id", dc),
				zap.String("temp_key_id", s.Key.String()),
				zap.Error(err),
			)
		}
	}()
}

func (c *Client) bindTempAuthKeySync(dc int, perm crypto.AuthKey, s mtproto.Session) error {
	return c.bindTempAuthKeyWithTimeout(dc, perm, s)
}

func (c *Client) bindTempAuthKeyWithTimeout(dc int, perm crypto.AuthKey, s mtproto.Session) error {
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, defaultTempAuthBindDelay)
	defer cancel()

	if err := c.bindTempAuthKey(reqCtx, perm, s.Key, s.ID); err != nil {
		return err
	}

	c.markTempAuthKeyBound(s.Key.ID)
	c.log.Debug("Temporary auth key bound",
		zap.Int("dc_id", dc),
		zap.String("perm_key_id", perm.String()),
		zap.String("temp_key_id", s.Key.String()),
	)
	if err := c.persistBoundTempAuthKey(s); err != nil {
		c.log.Warn("Failed to persist bound temporary auth key",
			zap.Int("dc_id", dc),
			zap.String("temp_key_id", s.Key.String()),
			zap.Error(err),
		)
	}
	return nil
}

func (c *Client) tempAuthExpires() time.Duration {
	if c.tempAuthKeyExpire > 0 {
		return c.tempAuthKeyExpire
	}
	return defaultTempAuthExpires
}

func (c *Client) bindTempAuthKey(ctx context.Context, perm, temp crypto.AuthKey, tempSessionID int64) error {
	nonce, err := crypto.RandInt64(c.rand)
	if err != nil {
		return errors.Wrap(err, "generate nonce")
	}

	expires := c.tempAuthExpires()
	expiresAt := int(c.clock.Now().Add(expires).Unix())

	encrypted, err := encryptBindTempAuthKeyMessage(c.rand, perm, temp, nonce, tempSessionID, expiresAt)
	if err != nil {
		return errors.Wrap(err, "generate encrypted_message")
	}

	ok, err := c.tg.AuthBindTempAuthKey(ctx, &tg.AuthBindTempAuthKeyRequest{
		PermAuthKeyID:    perm.IntID(),
		Nonce:            nonce,
		ExpiresAt:        expiresAt,
		EncryptedMessage: encrypted,
	})
	if tg.IsTempAuthKeyAlreadyBound(err) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "auth.bindTempAuthKey")
	}
	if !ok {
		return errors.New("auth.bindTempAuthKey returned false")
	}

	return nil
}

func encryptBindTempAuthKeyMessage(rand io.Reader, perm, temp crypto.AuthKey, nonce, tempSessionID int64, expiresAt int) ([]byte, error) {
	var dataBuf bin.Buffer
	dataBuf.PutID(bindAuthKeyInnerTypeID)
	dataBuf.PutLong(nonce)
	dataBuf.PutLong(temp.IntID())
	dataBuf.PutLong(perm.IntID())
	dataBuf.PutLong(tempSessionID)
	dataBuf.PutInt(expiresAt)
	data := dataBuf.Buf

	hash := sha1.Sum(data) // #nosec G401
	var msgKey bin.Int128
	copy(msgKey[:], hash[4:20])

	aesKey, aesIV := crypto.OldKeys(perm.Value, msgKey, crypto.Client)

	padded := make([]byte, len(data))
	copy(padded, data)
	if rem := len(padded) % aes.BlockSize; rem != 0 {
		padLen := aes.BlockSize - rem
		pad := make([]byte, padLen)
		if _, err := io.ReadFull(rand, pad); err != nil {
			return nil, errors.Wrap(err, "generate padding")
		}
		padded = append(padded, pad...)
	}

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, errors.Wrap(err, "create aes block")
	}
	encrypted := make([]byte, len(padded))
	ige.EncryptBlocks(block, aesIV[:], encrypted, padded)

	out := make([]byte, len(msgKey)+len(encrypted))
	copy(out, msgKey[:])
	copy(out[len(msgKey):], encrypted)
	return out, nil
}
