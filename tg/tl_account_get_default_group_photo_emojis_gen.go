// Code generated by gotdgen, DO NOT EDIT.

package tg

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"go.uber.org/multierr"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/tdjson"
	"github.com/gotd/td/tdp"
	"github.com/gotd/td/tgerr"
)

// No-op definition for keeping imports.
var (
	_ = bin.Buffer{}
	_ = context.Background()
	_ = fmt.Stringer(nil)
	_ = strings.Builder{}
	_ = errors.Is
	_ = multierr.AppendInto
	_ = sort.Ints
	_ = tdp.Format
	_ = tgerr.Error{}
	_ = tdjson.Encoder{}
)

// AccountGetDefaultGroupPhotoEmojisRequest represents TL type `account.getDefaultGroupPhotoEmojis#915860ae`.
//
// See https://core.telegram.org/method/account.getDefaultGroupPhotoEmojis for reference.
type AccountGetDefaultGroupPhotoEmojisRequest struct {
	// Hash field of AccountGetDefaultGroupPhotoEmojisRequest.
	Hash int64
}

// AccountGetDefaultGroupPhotoEmojisRequestTypeID is TL type id of AccountGetDefaultGroupPhotoEmojisRequest.
const AccountGetDefaultGroupPhotoEmojisRequestTypeID = 0x915860ae

// Ensuring interfaces in compile-time for AccountGetDefaultGroupPhotoEmojisRequest.
var (
	_ bin.Encoder     = &AccountGetDefaultGroupPhotoEmojisRequest{}
	_ bin.Decoder     = &AccountGetDefaultGroupPhotoEmojisRequest{}
	_ bin.BareEncoder = &AccountGetDefaultGroupPhotoEmojisRequest{}
	_ bin.BareDecoder = &AccountGetDefaultGroupPhotoEmojisRequest{}
)

func (g *AccountGetDefaultGroupPhotoEmojisRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Hash == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *AccountGetDefaultGroupPhotoEmojisRequest) String() string {
	if g == nil {
		return "AccountGetDefaultGroupPhotoEmojisRequest(nil)"
	}
	type Alias AccountGetDefaultGroupPhotoEmojisRequest
	return fmt.Sprintf("AccountGetDefaultGroupPhotoEmojisRequest%+v", Alias(*g))
}

// FillFrom fills AccountGetDefaultGroupPhotoEmojisRequest from given interface.
func (g *AccountGetDefaultGroupPhotoEmojisRequest) FillFrom(from interface {
	GetHash() (value int64)
}) {
	g.Hash = from.GetHash()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*AccountGetDefaultGroupPhotoEmojisRequest) TypeID() uint32 {
	return AccountGetDefaultGroupPhotoEmojisRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*AccountGetDefaultGroupPhotoEmojisRequest) TypeName() string {
	return "account.getDefaultGroupPhotoEmojis"
}

// TypeInfo returns info about TL type.
func (g *AccountGetDefaultGroupPhotoEmojisRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "account.getDefaultGroupPhotoEmojis",
		ID:   AccountGetDefaultGroupPhotoEmojisRequestTypeID,
	}
	if g == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Hash",
			SchemaName: "hash",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (g *AccountGetDefaultGroupPhotoEmojisRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode account.getDefaultGroupPhotoEmojis#915860ae as nil")
	}
	b.PutID(AccountGetDefaultGroupPhotoEmojisRequestTypeID)
	return g.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (g *AccountGetDefaultGroupPhotoEmojisRequest) EncodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode account.getDefaultGroupPhotoEmojis#915860ae as nil")
	}
	b.PutLong(g.Hash)
	return nil
}

// Decode implements bin.Decoder.
func (g *AccountGetDefaultGroupPhotoEmojisRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode account.getDefaultGroupPhotoEmojis#915860ae to nil")
	}
	if err := b.ConsumeID(AccountGetDefaultGroupPhotoEmojisRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode account.getDefaultGroupPhotoEmojis#915860ae: %w", err)
	}
	return g.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (g *AccountGetDefaultGroupPhotoEmojisRequest) DecodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode account.getDefaultGroupPhotoEmojis#915860ae to nil")
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode account.getDefaultGroupPhotoEmojis#915860ae: field hash: %w", err)
		}
		g.Hash = value
	}
	return nil
}

// GetHash returns value of Hash field.
func (g *AccountGetDefaultGroupPhotoEmojisRequest) GetHash() (value int64) {
	if g == nil {
		return
	}
	return g.Hash
}

// AccountGetDefaultGroupPhotoEmojis invokes method account.getDefaultGroupPhotoEmojis#915860ae returning error if any.
//
// See https://core.telegram.org/method/account.getDefaultGroupPhotoEmojis for reference.
func (c *Client) AccountGetDefaultGroupPhotoEmojis(ctx context.Context, hash int64) (EmojiListClass, error) {
	var result EmojiListBox

	request := &AccountGetDefaultGroupPhotoEmojisRequest{
		Hash: hash,
	}
	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return result.EmojiList, nil
}