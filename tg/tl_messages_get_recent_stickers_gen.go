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

// MessagesGetRecentStickersRequest represents TL type `messages.getRecentStickers#5ea192c9`.
// Get recent stickers
//
// See https://core.telegram.org/method/messages.getRecentStickers for reference.
type MessagesGetRecentStickersRequest struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields `tl:"flags"`
	// Get stickers recently attached to photo or video files
	Attached bool `tl:"attached"`
	// Hash for pagination, for more info click here¹
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets#hash-generation
	Hash int `tl:"hash"`
}

// MessagesGetRecentStickersRequestTypeID is TL type id of MessagesGetRecentStickersRequest.
const MessagesGetRecentStickersRequestTypeID = 0x5ea192c9

func (g *MessagesGetRecentStickersRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Flags.Zero()) {
		return false
	}
	if !(g.Attached == false) {
		return false
	}
	if !(g.Hash == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *MessagesGetRecentStickersRequest) String() string {
	if g == nil {
		return "MessagesGetRecentStickersRequest(nil)"
	}
	type Alias MessagesGetRecentStickersRequest
	return fmt.Sprintf("MessagesGetRecentStickersRequest%+v", Alias(*g))
}

// FillFrom fills MessagesGetRecentStickersRequest from given interface.
func (g *MessagesGetRecentStickersRequest) FillFrom(from interface {
	GetAttached() (value bool)
	GetHash() (value int)
}) {
	g.Attached = from.GetAttached()
	g.Hash = from.GetHash()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (g *MessagesGetRecentStickersRequest) TypeID() uint32 {
	return MessagesGetRecentStickersRequestTypeID
}

// TypeName returns name of type in TL schema.
func (g *MessagesGetRecentStickersRequest) TypeName() string {
	return "messages.getRecentStickers"
}

// Encode implements bin.Encoder.
func (g *MessagesGetRecentStickersRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode messages.getRecentStickers#5ea192c9 as nil")
	}
	b.PutID(MessagesGetRecentStickersRequestTypeID)
	if !(g.Attached == false) {
		g.Flags.Set(0)
	}
	if err := g.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.getRecentStickers#5ea192c9: field flags: %w", err)
	}
	b.PutInt(g.Hash)
	return nil
}

// SetAttached sets value of Attached conditional field.
func (g *MessagesGetRecentStickersRequest) SetAttached(value bool) {
	if value {
		g.Flags.Set(0)
		g.Attached = true
	} else {
		g.Flags.Unset(0)
		g.Attached = false
	}
}

// GetAttached returns value of Attached conditional field.
func (g *MessagesGetRecentStickersRequest) GetAttached() (value bool) {
	return g.Flags.Has(0)
}

// GetHash returns value of Hash field.
func (g *MessagesGetRecentStickersRequest) GetHash() (value int) {
	return g.Hash
}

// Decode implements bin.Decoder.
func (g *MessagesGetRecentStickersRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode messages.getRecentStickers#5ea192c9 to nil")
	}
	if err := b.ConsumeID(MessagesGetRecentStickersRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.getRecentStickers#5ea192c9: %w", err)
	}
	{
		if err := g.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode messages.getRecentStickers#5ea192c9: field flags: %w", err)
		}
	}
	g.Attached = g.Flags.Has(0)
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getRecentStickers#5ea192c9: field hash: %w", err)
		}
		g.Hash = value
	}
	return nil
}

// Ensuring interfaces in compile-time for MessagesGetRecentStickersRequest.
var (
	_ bin.Encoder = &MessagesGetRecentStickersRequest{}
	_ bin.Decoder = &MessagesGetRecentStickersRequest{}
)

// MessagesGetRecentStickers invokes method messages.getRecentStickers#5ea192c9 returning error if any.
// Get recent stickers
//
// See https://core.telegram.org/method/messages.getRecentStickers for reference.
func (c *Client) MessagesGetRecentStickers(ctx context.Context, request *MessagesGetRecentStickersRequest) (MessagesRecentStickersClass, error) {
	var result MessagesRecentStickersBox

	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return result.RecentStickers, nil
}
