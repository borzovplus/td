// Code generated by gotdgen, DO NOT EDIT.

package tdapi

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

// ClearRecentReactionsRequest represents TL type `clearRecentReactions#4d61c752`.
type ClearRecentReactionsRequest struct {
}

// ClearRecentReactionsRequestTypeID is TL type id of ClearRecentReactionsRequest.
const ClearRecentReactionsRequestTypeID = 0x4d61c752

// Ensuring interfaces in compile-time for ClearRecentReactionsRequest.
var (
	_ bin.Encoder     = &ClearRecentReactionsRequest{}
	_ bin.Decoder     = &ClearRecentReactionsRequest{}
	_ bin.BareEncoder = &ClearRecentReactionsRequest{}
	_ bin.BareDecoder = &ClearRecentReactionsRequest{}
)

func (c *ClearRecentReactionsRequest) Zero() bool {
	if c == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (c *ClearRecentReactionsRequest) String() string {
	if c == nil {
		return "ClearRecentReactionsRequest(nil)"
	}
	type Alias ClearRecentReactionsRequest
	return fmt.Sprintf("ClearRecentReactionsRequest%+v", Alias(*c))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*ClearRecentReactionsRequest) TypeID() uint32 {
	return ClearRecentReactionsRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*ClearRecentReactionsRequest) TypeName() string {
	return "clearRecentReactions"
}

// TypeInfo returns info about TL type.
func (c *ClearRecentReactionsRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "clearRecentReactions",
		ID:   ClearRecentReactionsRequestTypeID,
	}
	if c == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{}
	return typ
}

// Encode implements bin.Encoder.
func (c *ClearRecentReactionsRequest) Encode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode clearRecentReactions#4d61c752 as nil")
	}
	b.PutID(ClearRecentReactionsRequestTypeID)
	return c.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (c *ClearRecentReactionsRequest) EncodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode clearRecentReactions#4d61c752 as nil")
	}
	return nil
}

// Decode implements bin.Decoder.
func (c *ClearRecentReactionsRequest) Decode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode clearRecentReactions#4d61c752 to nil")
	}
	if err := b.ConsumeID(ClearRecentReactionsRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode clearRecentReactions#4d61c752: %w", err)
	}
	return c.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (c *ClearRecentReactionsRequest) DecodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode clearRecentReactions#4d61c752 to nil")
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (c *ClearRecentReactionsRequest) EncodeTDLibJSON(b tdjson.Encoder) error {
	if c == nil {
		return fmt.Errorf("can't encode clearRecentReactions#4d61c752 as nil")
	}
	b.ObjStart()
	b.PutID("clearRecentReactions")
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (c *ClearRecentReactionsRequest) DecodeTDLibJSON(b tdjson.Decoder) error {
	if c == nil {
		return fmt.Errorf("can't decode clearRecentReactions#4d61c752 to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("clearRecentReactions"); err != nil {
				return fmt.Errorf("unable to decode clearRecentReactions#4d61c752: %w", err)
			}
		default:
			return b.Skip()
		}
		return nil
	})
}

// ClearRecentReactions invokes method clearRecentReactions#4d61c752 returning error if any.
func (c *Client) ClearRecentReactions(ctx context.Context) error {
	var ok Ok

	request := &ClearRecentReactionsRequest{}
	if err := c.rpc.Invoke(ctx, request, &ok); err != nil {
		return err
	}
	return nil
}