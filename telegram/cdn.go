package telegram

import (
	"context"
	"crypto/rsa"
	"encoding/pem"

	"github.com/go-faster/errors"

	"github.com/gotd/td/crypto"
	"github.com/gotd/td/exchange"
	"github.com/gotd/td/tg"
)

func parseCDNKeys(keys ...tg.CDNPublicKey) ([]*rsa.PublicKey, error) {
	r := make([]*rsa.PublicKey, 0, len(keys))

	for _, key := range keys {
		block, _ := pem.Decode([]byte(key.PublicKey))
		if block == nil {
			continue
		}

		key, err := crypto.ParseRSA(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "parse RSA from PEM")
		}

		r = append(r, key)
	}

	return r, nil
}

func (c *Client) fetchCDNKeys(ctx context.Context) ([]exchange.PublicKey, error) {
	cfg, err := c.tg.HelpGetCDNConfig(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "help.getCdnConfig")
	}

	rsaKeys, err := parseCDNKeys(cfg.PublicKeys...)
	if err != nil {
		return nil, errors.Wrap(err, "parse CDN public keys")
	}

	r := make([]exchange.PublicKey, 0, len(rsaKeys))
	for _, key := range rsaKeys {
		r = append(r, exchange.PublicKey{RSA: key})
	}
	return r, nil
}

func mergePublicKeys(base, extra []exchange.PublicKey) []exchange.PublicKey {
	if len(extra) == 0 {
		return append([]exchange.PublicKey(nil), base...)
	}

	r := make([]exchange.PublicKey, 0, len(base)+len(extra))
	seen := make(map[int64]struct{}, len(base)+len(extra))

	for _, key := range base {
		fingerprint := key.Fingerprint()
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		r = append(r, key)
	}
	for _, key := range extra {
		fingerprint := key.Fingerprint()
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		r = append(r, key)
	}

	return r
}
