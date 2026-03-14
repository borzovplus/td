package downloader

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/go-faster/errors"
	"go.uber.org/multierr"

	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

// Builder is a download builder.
type Builder struct {
	downloader *Downloader

	schema    schema
	hashes    []tg.FileHash
	verify    bool
	verifySet bool
	threads   int
}

func newBuilder(downloader *Downloader, schema schema) *Builder {
	return &Builder{
		schema:     schema,
		threads:    1,
		downloader: downloader,
	}
}

// WithThreads sets downloading goroutines limit.
func (b *Builder) WithThreads(threads int) *Builder {
	if threads > 0 {
		b.threads = threads
	}
	return b
}

// WithVerify sets verify parameter.
// If verify is true, file hashes will be checked
// Verify is true by default for CDN downloads.
func (b *Builder) WithVerify(verify bool) *Builder {
	b.verify = verify
	b.verifySet = true
	return b
}

func (b *Builder) prepare(ctx context.Context) (_ *Builder, closeCDN func() error, err error) {
	m, ok := b.schema.(master)
	if !ok {
		return b, nil, nil
	}
	provider, hasProvider := m.client.(CDNProvider)
	if !hasProvider {
		// Client does not support CDN pools, stick to master DC without probe.
		return b, nil, nil
	}

	prepareMaster := func(allowCDN bool) *Builder {
		clone := *b
		masterSchema := m
		masterSchema.allowCDN = allowCDN
		clone.schema = masterSchema
		clone.hashes = nil
		return &clone
	}

	// Probe first chunk to detect upload.fileCdnRedirect before actual download.
	m.allowCDN = true
	probeLimit := b.downloader.partSize
	if probeLimit <= 0 || probeLimit > 4*1024 {
		probeLimit = 4 * 1024
	}
	var probeErr error
	for {
		_, probeErr = m.Chunk(ctx, 0, probeLimit)

		if flood, waitErr := tgerr.FloodWait(ctx, probeErr); waitErr != nil {
			if flood || tgerr.Is(waitErr, tg.ErrTimeout) {
				continue
			}
			probeErr = waitErr
		}
		break
	}

	if probeErr == nil {
		// Use regular DC for this file to avoid extra redirect handling paths.
		return prepareMaster(false), nil, nil
	}

	var redirectErr *RedirectError
	if !errors.As(probeErr, &redirectErr) {
		return nil, nil, errors.Wrap(probeErr, "probe download schema")
	}

	max := int64(b.threads)
	if max < 1 {
		max = 1
	}

	cdnClient, closer, err := provider.CDN(ctx, redirectErr.Redirect.DCID, max)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, errors.Wrapf(err, "create CDN client for DC %d", redirectErr.Redirect.DCID)
		}
		// CDN startup failed, keep downloading from master DC.
		return prepareMaster(false), nil, nil
	}
	if cdnClient == nil {
		// Defensive fallback for misbehaving provider implementations.
		return prepareMaster(false), nil, nil
	}

	clone := *b
	clone.schema = &cdn{
		cdn:      cdnClient,
		client:   m.client,
		pool:     b.downloader.pool,
		redirect: redirectErr.Redirect,
		mode:     modeCDN,
		master:   m,
	}
	clone.hashes = append([]tg.FileHash(nil), redirectErr.Redirect.FileHashes...)
	if !clone.verifySet {
		clone.verify = true
	}

	if closer != nil {
		closeCDN = closer.Close
	}

	return &clone, closeCDN, nil
}

func (b *Builder) reader() *reader {
	if b.verify {
		return verifiedReader(b.schema, newVerifier(b.schema, b.hashes...))
	}

	return plainReader(b.schema, b.downloader.partSize)
}

// Stream downloads file to given io.Writer.
// NB: in this mode download can't be parallel.
func (b *Builder) Stream(ctx context.Context, output io.Writer) (_ tg.StorageFileTypeClass, err error) {
	prepared, closeCDN, err := b.prepare(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeCDN != nil {
			multierr.AppendInto(&err, closeCDN())
		}
	}()

	return prepared.downloader.stream(ctx, prepared.reader(), output)
}

// Parallel downloads file to given io.WriterAt.
func (b *Builder) Parallel(ctx context.Context, output io.WriterAt) (_ tg.StorageFileTypeClass, err error) {
	prepared, closeCDN, err := b.prepare(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeCDN != nil {
			multierr.AppendInto(&err, closeCDN())
		}
	}()

	return prepared.downloader.parallel(ctx, prepared.reader(), prepared.threads, output)
}

// ToPath downloads file to given path.
func (b *Builder) ToPath(ctx context.Context, path string) (_ tg.StorageFileTypeClass, err error) {
	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		return nil, errors.Wrap(err, "create output file")
	}
	defer func() {
		multierr.AppendInto(&err, f.Close())
	}()

	return b.Parallel(ctx, f)
}
