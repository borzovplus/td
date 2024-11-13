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

// MessagesGetSponsoredMessagesRequest represents TL type `messages.getSponsoredMessages#9bd2f439`.
//
// See https://core.telegram.org/method/messages.getSponsoredMessages for reference.
type MessagesGetSponsoredMessagesRequest struct {
	// Peer field of MessagesGetSponsoredMessagesRequest.
	Peer InputPeerClass
}

// MessagesGetSponsoredMessagesRequestTypeID is TL type id of MessagesGetSponsoredMessagesRequest.
const MessagesGetSponsoredMessagesRequestTypeID = 0x9bd2f439

// Ensuring interfaces in compile-time for MessagesGetSponsoredMessagesRequest.
var (
	_ bin.Encoder     = &MessagesGetSponsoredMessagesRequest{}
	_ bin.Decoder     = &MessagesGetSponsoredMessagesRequest{}
	_ bin.BareEncoder = &MessagesGetSponsoredMessagesRequest{}
	_ bin.BareDecoder = &MessagesGetSponsoredMessagesRequest{}
)

func (g *MessagesGetSponsoredMessagesRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Peer == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *MessagesGetSponsoredMessagesRequest) String() string {
	if g == nil {
		return "MessagesGetSponsoredMessagesRequest(nil)"
	}
	type Alias MessagesGetSponsoredMessagesRequest
	return fmt.Sprintf("MessagesGetSponsoredMessagesRequest%+v", Alias(*g))
}

// FillFrom fills MessagesGetSponsoredMessagesRequest from given interface.
func (g *MessagesGetSponsoredMessagesRequest) FillFrom(from interface {
	GetPeer() (value InputPeerClass)
}) {
	g.Peer = from.GetPeer()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*MessagesGetSponsoredMessagesRequest) TypeID() uint32 {
	return MessagesGetSponsoredMessagesRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*MessagesGetSponsoredMessagesRequest) TypeName() string {
	return "messages.getSponsoredMessages"
}

// TypeInfo returns info about TL type.
func (g *MessagesGetSponsoredMessagesRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "messages.getSponsoredMessages",
		ID:   MessagesGetSponsoredMessagesRequestTypeID,
	}
	if g == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Peer",
			SchemaName: "peer",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (g *MessagesGetSponsoredMessagesRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode messages.getSponsoredMessages#9bd2f439 as nil")
	}
	b.PutID(MessagesGetSponsoredMessagesRequestTypeID)
	return g.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (g *MessagesGetSponsoredMessagesRequest) EncodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode messages.getSponsoredMessages#9bd2f439 as nil")
	}
	if g.Peer == nil {
		return fmt.Errorf("unable to encode messages.getSponsoredMessages#9bd2f439: field peer is nil")
	}
	if err := g.Peer.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.getSponsoredMessages#9bd2f439: field peer: %w", err)
	}
	return nil
}

// Decode implements bin.Decoder.
func (g *MessagesGetSponsoredMessagesRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode messages.getSponsoredMessages#9bd2f439 to nil")
	}
	if err := b.ConsumeID(MessagesGetSponsoredMessagesRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.getSponsoredMessages#9bd2f439: %w", err)
	}
	return g.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (g *MessagesGetSponsoredMessagesRequest) DecodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode messages.getSponsoredMessages#9bd2f439 to nil")
	}
	{
		value, err := DecodeInputPeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.getSponsoredMessages#9bd2f439: field peer: %w", err)
		}
		g.Peer = value
	}
	return nil
}

// GetPeer returns value of Peer field.
func (g *MessagesGetSponsoredMessagesRequest) GetPeer() (value InputPeerClass) {
	if g == nil {
		return
	}
	return g.Peer
}

// MessagesGetSponsoredMessages invokes method messages.getSponsoredMessages#9bd2f439 returning error if any.
//
// See https://core.telegram.org/method/messages.getSponsoredMessages for reference.
func (c *Client) MessagesGetSponsoredMessages(ctx context.Context, peer InputPeerClass) (MessagesSponsoredMessagesClass, error) {
	var result MessagesSponsoredMessagesBox

	request := &MessagesGetSponsoredMessagesRequest{
		Peer: peer,
	}
	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return result.SponsoredMessages, nil
}
