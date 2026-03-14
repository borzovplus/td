package downloader

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/go-faster/errors"
	"github.com/stretchr/testify/require"

	"github.com/gotd/td/crypto"
	"github.com/gotd/td/syncio"
	"github.com/gotd/td/testutil"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

type mock struct {
	data      []byte
	hashes    mockHashes
	migrate   bool
	err       bool
	hashesErr bool
	redirect  *tg.UploadFileCDNRedirect

	migrateOnce    atomic.Bool
	reuploadNeeded atomic.Bool
	tokenInvalid   atomic.Bool
	getFileCalls   atomic.Int32
}

var testErr = testutil.TestError()

func (m *mock) getPart(offset int64, limit int) []byte {
	length := len(m.data)
	if offset >= int64(length) {
		return []byte{}
	}

	size := length - int(offset)
	if size > limit {
		size = limit
	}

	r := make([]byte, size)
	copy(r, m.data[offset:])
	return r
}

func (m *mock) UploadGetFile(ctx context.Context, request *tg.UploadGetFileRequest) (tg.UploadFileClass, error) {
	m.getFileCalls.Add(1)
	if m.err {
		return nil, testErr
	}

	if request.GetCDNSupported() && m.migrateOnce.CompareAndSwap(true, false) {
		return m.redirect, nil
	}

	if request.GetCDNSupported() && m.migrate {
		return m.redirect, nil
	}

	return &tg.UploadFile{
		Bytes: m.getPart(request.Offset, request.Limit),
	}, nil
}

func (m *mock) UploadGetFileHashes(ctx context.Context, request *tg.UploadGetFileHashesRequest) ([]tg.FileHash, error) {
	if m.hashesErr {
		return nil, testErr
	}

	return m.hashes.Hashes(ctx, request.Offset)
}

func (m *mock) UploadReuploadCDNFile(ctx context.Context, request *tg.UploadReuploadCDNFileRequest) ([]tg.FileHash, error) {
	if m.err {
		return nil, testErr
	}

	return nil, nil
}

func (m *mock) UploadGetCDNFile(ctx context.Context, request *tg.UploadGetCDNFileRequest) (tg.UploadCDNFileClass, error) {
	if m.err {
		return nil, testErr
	}

	if m.tokenInvalid.CompareAndSwap(true, false) {
		return nil, tgerr.New(400, "FILE_TOKEN_INVALID")
	}

	if m.reuploadNeeded.CompareAndSwap(true, false) {
		return &tg.UploadCDNFileReuploadNeeded{
			RequestToken: []byte{1, 2, 3},
		}, nil
	}

	block, err := aes.NewCipher(m.redirect.EncryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "CDN mock cipher creation")
	}

	iv := make([]byte, len(m.redirect.EncryptionIv))
	copy(iv, m.redirect.EncryptionIv)
	binary.BigEndian.PutUint32(iv[len(iv)-4:], uint32(request.Offset/16))

	part := m.getPart(request.Offset, request.Limit)
	r := make([]byte, len(part))
	cipher.NewCTR(block, iv).XORKeyStream(r, part)
	return &tg.UploadCDNFile{
		Bytes: r,
	}, nil
}

func (m *mock) UploadGetCDNFileHashes(ctx context.Context, request *tg.UploadGetCDNFileHashesRequest) ([]tg.FileHash, error) {
	if m.hashesErr {
		return nil, testErr
	}

	return m.hashes.Hashes(ctx, request.Offset)
}

func (m *mock) UploadGetWebFile(ctx context.Context, request *tg.UploadGetWebFileRequest) (*tg.UploadWebFile, error) {
	if m.err {
		return nil, testErr
	}

	return &tg.UploadWebFile{
		Bytes: m.getPart(int64(request.Offset), request.Limit),
	}, nil
}

type noopCloser struct{}

func (noopCloser) Close() error {
	return nil
}

func (m *mock) CDN(ctx context.Context, dc int, max int64) (CDN, io.Closer, error) {
	return m, noopCloser{}, nil
}

type noCDNClient struct {
	base *mock
}

func (c *noCDNClient) UploadGetFile(ctx context.Context, request *tg.UploadGetFileRequest) (tg.UploadFileClass, error) {
	return c.base.UploadGetFile(ctx, request)
}

func (c *noCDNClient) UploadGetFileHashes(ctx context.Context, request *tg.UploadGetFileHashesRequest) ([]tg.FileHash, error) {
	return c.base.UploadGetFileHashes(ctx, request)
}

func (c *noCDNClient) UploadReuploadCDNFile(ctx context.Context, request *tg.UploadReuploadCDNFileRequest) ([]tg.FileHash, error) {
	return c.base.UploadReuploadCDNFile(ctx, request)
}

func (c *noCDNClient) UploadGetCDNFileHashes(ctx context.Context, request *tg.UploadGetCDNFileHashesRequest) ([]tg.FileHash, error) {
	return c.base.UploadGetCDNFileHashes(ctx, request)
}

func (c *noCDNClient) UploadGetWebFile(ctx context.Context, request *tg.UploadGetWebFileRequest) (*tg.UploadWebFile, error) {
	return c.base.UploadGetWebFile(ctx, request)
}

type nilCDNProvider struct {
	*mock
}

func (c *nilCDNProvider) CDN(ctx context.Context, dc int, max int64) (CDN, io.Closer, error) {
	return nil, noopCloser{}, nil
}

type errCDNProvider struct {
	*mock
	err error
}

func (c *errCDNProvider) CDN(ctx context.Context, dc int, max int64) (CDN, io.Closer, error) {
	return nil, nil, c.err
}

func countHashes(data []byte, partSize int) (r [][]tg.FileHash) {
	actions := data
	batchSize := partSize
	batches := make([][]byte, 0, (len(actions)+batchSize-1)/batchSize)

	for batchSize < len(actions) {
		actions, batches = actions[batchSize:], append(batches, actions[0:batchSize:batchSize])
	}
	batches = append(batches, actions)

	currentRange := make([]tg.FileHash, 0, 10)
	offset := 0
	for _, batch := range batches {
		if len(currentRange) >= 10 {
			r = append(r, currentRange)
			currentRange = make([]tg.FileHash, 0, 10)
		}
		currentRange = append(currentRange, tg.FileHash{
			Offset: int64(offset),
			Limit:  partSize,
			Hash:   crypto.SHA256(batch),
		})
		offset += len(batch)

		if len(batch) < partSize {
			break
		}
	}
	r = append(r, currentRange)
	return
}

func Test_countHashes(t *testing.T) {
	a := require.New(t)
	data := bytes.Repeat([]byte{1, 2, 3, 4, 5}, 10)
	hashes := countHashes(data, 4)

	a.NotEmpty(hashes)
	for _, hashRange := range hashes {
		for _, hash := range hashRange {
			from := hash.Offset
			to := int(hash.Offset) + hash.Limit
			if to > len(data) {
				to = len(data)
			}
			a.Equal(crypto.SHA256(data[from:to]), hash.Hash)
		}
	}
}

func TestDownloader(t *testing.T) {
	ctx := context.Background()

	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatal(err)
	}
	redirect := &tg.UploadFileCDNRedirect{
		DCID:          1,
		FileToken:     []byte{10},
		EncryptionKey: key,
		EncryptionIv:  iv,
	}

	testData := make([]byte, defaultPartSize*2)
	if _, err := io.ReadFull(rand.Reader, testData); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		data        []byte
		migrate     bool
		cdnReupload bool
		cdnTokenErr bool
		err         bool
		hashesErr   bool
	}{
		{"5b", []byte{1, 2, 3, 4, 5}, false, false, false, false, false},
		{strconv.Itoa(len(testData)) + "b", testData, false, false, false, false, false},
		{"Error", []byte{}, false, false, false, true, false},
		{"HashesError", testData, false, false, false, false, true},
		{"Migrate", testData, true, false, false, false, false},
		{"MigrateReupload", testData, true, true, false, false, false},
		{"MigrateTokenInvalid", testData, true, false, true, false, false},
	}
	schemas := []struct {
		name    string
		creator func(c Client) *Builder
	}{
		{"Master", func(c Client) *Builder {
			return NewDownloader().Download(c, nil)
		}},
		{"Web", func(c Client) *Builder {
			return NewDownloader().Web(c, nil)
		}},
	}
	ways := []struct {
		name   string
		action func(b *Builder) ([]byte, error)
	}{
		{"Stream", func(b *Builder) ([]byte, error) {
			output := new(bytes.Buffer)
			_, err := b.Stream(ctx, output)
			return output.Bytes(), err
		}},
		{"Parallel", func(b *Builder) ([]byte, error) {
			output := new(syncio.BufWriterAt)
			_, err := b.WithThreads(runtime.GOMAXPROCS(0)).Parallel(ctx, output)
			return output.Bytes(), err
		}},
		{"Parallel-OneThread", func(b *Builder) ([]byte, error) {
			output := new(syncio.BufWriterAt)
			_, err := b.WithThreads(1).Parallel(ctx, output)
			return output.Bytes(), err
		}},
	}
	options := []struct {
		name   string
		action func(b *Builder) *Builder
	}{
		{"NoVerify", func(b *Builder) *Builder {
			return b.WithVerify(false)
		}},
		{"Verify", func(b *Builder) *Builder {
			return b.WithVerify(true)
		}},
	}

	for _, schema := range schemas {
		t.Run(schema.name, func(t *testing.T) {
			for _, test := range tests {
				// Telegram can't redirect web file downloads.
				if schema.name == "Web" && test.migrate {
					continue
				}
				t.Run(test.name, func(t *testing.T) {
					for _, option := range options {
						// Telegram can't return hashes for web files.
						if schema.name == "Web" && option.name == "Verify" {
							continue
						}

						t.Run(option.name, func(t *testing.T) {
							for _, way := range ways {
								t.Run(way.name, func(t *testing.T) {
									a := require.New(t)
									client := &mock{
										data: test.data,
										hashes: mockHashes{
											ranges: countHashes(test.data, 128*1024),
										},
										migrate:   test.migrate,
										err:       test.err,
										hashesErr: test.hashesErr,
										redirect:  redirect,
									}
									if test.cdnReupload {
										client.reuploadNeeded.Store(true)
									}
									if test.cdnTokenErr {
										client.tokenInvalid.Store(true)
									}

									b := schema.creator(client)
									b = option.action(b)
									data, err := way.action(b)
									shouldErr := test.err || (test.hashesErr && option.name == "Verify")
									if shouldErr {
										a.Error(err)
									} else {
										a.NoError(err)
										a.True(bytes.Equal(test.data, data))
									}
								})
							}
						})
					}
				})
			}
		})
	}
}

func TestDownloader_CDNFallbackWithoutProvider(t *testing.T) {
	ctx := context.Background()
	data := []byte("fallback-without-cdn-provider")

	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatal(err)
	}

	redirect := &tg.UploadFileCDNRedirect{
		DCID:          203,
		FileToken:     []byte{10},
		EncryptionKey: key,
		EncryptionIv:  iv,
	}

	t.Run("NoProvider", func(t *testing.T) {
		m := &mock{
			data:    data,
			migrate: true,
			hashes: mockHashes{
				ranges: countHashes(data, 128*1024),
			},
			redirect: redirect,
		}
		output := new(bytes.Buffer)
		_, err := NewDownloader().Download(&noCDNClient{base: m}, nil).WithVerify(true).Stream(ctx, output)
		require.NoError(t, err)
		require.Equal(t, data, output.Bytes())
		require.EqualValues(t, 1, m.getFileCalls.Load())
	})

	t.Run("NilProvider", func(t *testing.T) {
		m := &mock{
			data:    data,
			migrate: true,
			hashes: mockHashes{
				ranges: countHashes(data, 128*1024),
			},
			redirect: redirect,
		}
		output := new(bytes.Buffer)
		_, err := NewDownloader().Download(&nilCDNProvider{mock: m}, nil).WithVerify(true).Stream(ctx, output)
		require.NoError(t, err)
		require.Equal(t, data, output.Bytes())
	})

	t.Run("ProviderErrorFallback", func(t *testing.T) {
		m := &mock{
			data:    data,
			migrate: true,
			hashes: mockHashes{
				ranges: countHashes(data, 128*1024),
			},
			redirect: redirect,
		}
		output := new(bytes.Buffer)
		_, err := NewDownloader().Download(&errCDNProvider{
			mock: m,
			err:  testErr,
		}, nil).WithVerify(true).Stream(ctx, output)
		require.NoError(t, err)
		require.Equal(t, data, output.Bytes())
	})

	t.Run("ProviderContextError", func(t *testing.T) {
		m := &mock{
			data:    data,
			migrate: true,
			hashes: mockHashes{
				ranges: countHashes(data, 128*1024),
			},
			redirect: redirect,
		}
		output := new(bytes.Buffer)
		_, err := NewDownloader().Download(&errCDNProvider{
			mock: m,
			err:  context.Canceled,
		}, nil).WithVerify(true).Stream(ctx, output)
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("TokenInvalidFallbackToMaster", func(t *testing.T) {
		m := &mock{
			data: data,
			hashes: mockHashes{
				ranges: countHashes(data, 128*1024),
			},
			redirect: redirect,
		}
		m.migrateOnce.Store(true)
		m.tokenInvalid.Store(true)

		output := new(bytes.Buffer)
		_, err := NewDownloader().Download(m, nil).WithVerify(true).Stream(ctx, output)
		require.NoError(t, err)
		require.Equal(t, data, output.Bytes())
	})
}
