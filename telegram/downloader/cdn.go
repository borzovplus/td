package downloader

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"sync"

	"github.com/go-faster/errors"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

// ExpiredTokenError error is returned when Downloader get expired file token for CDN.
// See https://core.telegram.org/constructor/upload.fileCdnRedirect.
type ExpiredTokenError struct {
	*tg.UploadCDNFileReuploadNeeded
}

// Error implements error interface.
func (r *ExpiredTokenError) Error() string {
	return "redirect to master DC for requesting new file token"
}

// cdn is a CDN DC download schema.
// See https://core.telegram.org/cdn#getting-files-from-a-cdn.
type cdn struct {
	cdn      CDN
	client   Client
	pool     *bin.Pool
	redirect *tg.UploadFileCDNRedirect

	mode       cdnMode
	stateMux   sync.RWMutex
	refreshMux sync.Mutex
	master     master
	rev        uint64
}

var _ schema = (*cdn)(nil)

type cdnMode uint8

const (
	modeCDN cdnMode = iota
	modeMaster
)

func (c *cdn) snapshot() (mode cdnMode, redirect *tg.UploadFileCDNRedirect, rev uint64) {
	c.stateMux.RLock()
	defer c.stateMux.RUnlock()
	return c.mode, c.redirect, c.rev
}

func (c *cdn) setRedirect(redirect *tg.UploadFileCDNRedirect) {
	c.stateMux.Lock()
	defer c.stateMux.Unlock()
	c.redirect = redirect
	c.mode = modeCDN
	c.rev++
}

func (c *cdn) setMaster() {
	c.stateMux.Lock()
	defer c.stateMux.Unlock()
	c.mode = modeMaster
	c.rev++
}

func (c *cdn) refreshRedirect(
	ctx context.Context, offset int64, limit int, prevRev uint64,
) (*chunk, error) {
	if limit <= 0 {
		limit = 4 * 1024
	}
	c.refreshMux.Lock()
	defer c.refreshMux.Unlock()

	_, _, currentRev := c.snapshot()
	if currentRev != prevRev {
		return nil, nil
	}

	for {
		masterChunk, err := c.master.Chunk(ctx, offset, limit)
		if flood, waitErr := tgerr.FloodWait(ctx, err); waitErr != nil {
			if flood || tgerr.Is(waitErr, tg.ErrTimeout) {
				continue
			}
			err = waitErr
		}

		if err == nil {
			c.setMaster()
			return &masterChunk, nil
		}

		var redirectErr *RedirectError
		if errors.As(err, &redirectErr) {
			c.setRedirect(redirectErr.Redirect)
			return nil, nil
		}

		return nil, errors.Wrap(err, "refresh CDN redirect")
	}
}

// decrypt decrypts file chunk from Telegram CDN.
// See https://core.telegram.org/cdn#decrypting-files.
func (c *cdn) decrypt(src []byte, offset int64, redirect *tg.UploadFileCDNRedirect) ([]byte, error) {
	block, err := aes.NewCipher(redirect.EncryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "create cipher")
	}

	if block.BlockSize() != len(redirect.EncryptionIv) {
		return nil, errors.Errorf(
			"invalid IV or key length, block size %d != IV %d",
			block.BlockSize(), len(redirect.EncryptionIv),
		)
	}

	// Copy IV to buffer from Pool.
	iv := c.pool.GetSize(len(redirect.EncryptionIv))
	defer c.pool.Put(iv)
	copy(iv.Buf, redirect.EncryptionIv)

	// For IV, it should use the value of encryption_iv, modified in the following manner:
	// for each offset replace the last 4 bytes of the encryption_iv with offset / 16 in big-endian.
	binary.BigEndian.PutUint32(iv.Buf[iv.Len()-4:], uint32(offset/16))

	dst := make([]byte, len(src))
	cipher.NewCTR(block, iv.Buf).XORKeyStream(dst, src)
	return dst, nil
}

func (c *cdn) Chunk(ctx context.Context, offset int64, limit int) (chunk, error) {
	for {
		mode, redirect, rev := c.snapshot()
		if mode == modeMaster {
			r, err := c.master.Chunk(ctx, offset, limit)
			if err == nil {
				return r, nil
			}

			var redirectErr *RedirectError
			if !errors.As(err, &redirectErr) {
				return chunk{}, err
			}
			c.setRedirect(redirectErr.Redirect)
			continue
		}

		if redirect == nil {
			c.setMaster()
			continue
		}

		r, err := c.cdn.UploadGetCDNFile(ctx, &tg.UploadGetCDNFileRequest{
			Offset:    offset,
			Limit:     limit,
			FileToken: redirect.FileToken,
		})
		if err != nil {
			if tgerr.Is(err, "FILE_TOKEN_INVALID", "REQUEST_TOKEN_INVALID") {
				masterChunk, err := c.refreshRedirect(ctx, offset, limit, rev)
				if err != nil {
					return chunk{}, err
				}
				if masterChunk != nil {
					return *masterChunk, nil
				}
				continue
			}
			return chunk{}, err
		}

		switch result := r.(type) {
		case *tg.UploadCDNFile:
			data, err := c.decrypt(result.Bytes, offset, redirect)
			if err != nil {
				return chunk{}, err
			}

			return chunk{
				data: data,
			}, nil
		case *tg.UploadCDNFileReuploadNeeded:
			_, err := c.client.UploadReuploadCDNFile(ctx, &tg.UploadReuploadCDNFileRequest{
				FileToken:    redirect.FileToken,
				RequestToken: result.RequestToken,
			})
			if err != nil {
				if tgerr.Is(err, "FILE_TOKEN_INVALID", "REQUEST_TOKEN_INVALID") {
					masterChunk, err := c.refreshRedirect(ctx, offset, limit, rev)
					if err != nil {
						return chunk{}, err
					}
					if masterChunk != nil {
						return *masterChunk, nil
					}
					continue
				}
				return chunk{}, err
			}
			continue
		default:
			return chunk{}, errors.Errorf("unexpected type %T", r)
		}
	}
}

func (c *cdn) Hashes(ctx context.Context, offset int64) ([]tg.FileHash, error) {
	for {
		mode, redirect, rev := c.snapshot()
		if mode == modeMaster || redirect == nil {
			return c.master.Hashes(ctx, offset)
		}

		hashes, err := c.client.UploadGetCDNFileHashes(ctx, &tg.UploadGetCDNFileHashesRequest{
			FileToken: redirect.FileToken,
			Offset:    offset,
		})
		if err != nil && tgerr.Is(err, "FILE_TOKEN_INVALID", "REQUEST_TOKEN_INVALID") {
			if _, err := c.refreshRedirect(ctx, offset, 4*1024, rev); err != nil {
				return nil, err
			}
			continue
		}
		return hashes, err
	}
}
