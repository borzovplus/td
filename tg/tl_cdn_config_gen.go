// Code generated by gotdgen, DO NOT EDIT.

package tg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gotd/td/bin"
)

// No-op definition for keeping imports.
var _ = bin.Buffer{}
var _ = context.Background()
var _ = fmt.Stringer(nil)
var _ = strings.Builder{}
var _ = errors.Is

// CdnConfig represents TL type `cdnConfig#5725e40a`.
// Configuration for CDN¹ file downloads.
//
// Links:
//  1) https://core.telegram.org/cdn
//
// See https://core.telegram.org/constructor/cdnConfig for reference.
type CdnConfig struct {
	// Vector of public keys to use only during handshakes to CDN¹ DCs.
	//
	// Links:
	//  1) https://core.telegram.org/cdn
	PublicKeys []CdnPublicKey `tl:"public_keys"`
}

// CdnConfigTypeID is TL type id of CdnConfig.
const CdnConfigTypeID = 0x5725e40a

func (c *CdnConfig) Zero() bool {
	if c == nil {
		return true
	}
	if !(c.PublicKeys == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (c *CdnConfig) String() string {
	if c == nil {
		return "CdnConfig(nil)"
	}
	type Alias CdnConfig
	return fmt.Sprintf("CdnConfig%+v", Alias(*c))
}

// FillFrom fills CdnConfig from given interface.
func (c *CdnConfig) FillFrom(from interface {
	GetPublicKeys() (value []CdnPublicKey)
}) {
	c.PublicKeys = from.GetPublicKeys()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (c *CdnConfig) TypeID() uint32 {
	return CdnConfigTypeID
}

// TypeName returns name of type in TL schema.
func (c *CdnConfig) TypeName() string {
	return "cdnConfig"
}

// Encode implements bin.Encoder.
func (c *CdnConfig) Encode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode cdnConfig#5725e40a as nil")
	}
	b.PutID(CdnConfigTypeID)
	b.PutVectorHeader(len(c.PublicKeys))
	for idx, v := range c.PublicKeys {
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode cdnConfig#5725e40a: field public_keys element with index %d: %w", idx, err)
		}
	}
	return nil
}

// GetPublicKeys returns value of PublicKeys field.
func (c *CdnConfig) GetPublicKeys() (value []CdnPublicKey) {
	return c.PublicKeys
}

// Decode implements bin.Decoder.
func (c *CdnConfig) Decode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode cdnConfig#5725e40a to nil")
	}
	if err := b.ConsumeID(CdnConfigTypeID); err != nil {
		return fmt.Errorf("unable to decode cdnConfig#5725e40a: %w", err)
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode cdnConfig#5725e40a: field public_keys: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			var value CdnPublicKey
			if err := value.Decode(b); err != nil {
				return fmt.Errorf("unable to decode cdnConfig#5725e40a: field public_keys: %w", err)
			}
			c.PublicKeys = append(c.PublicKeys, value)
		}
	}
	return nil
}

// Ensuring interfaces in compile-time for CdnConfig.
var (
	_ bin.Encoder = &CdnConfig{}
	_ bin.Decoder = &CdnConfig{}
)
