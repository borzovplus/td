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

// MessagesGetUnreadMentionsRequest represents TL type `messages.getUnreadMentions#46578472`.
// Get unread messages where we were mentioned
//
// See https://core.telegram.org/method/messages.getUnreadMentions for reference.
type MessagesGetUnreadMentionsRequest struct {
	// Peer where to look for mentions
	Peer InputPeerClass `tl:"peer"`
	// Offsets for pagination, for more info click here¹
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets
	OffsetID int `tl:"offset_id"`
	// Offsets for pagination, for more info click here¹
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets
	AddOffset int `tl:"add_offset"`
	// Maximum number of results to return, see pagination¹
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets
	Limit int `tl:"limit"`
	// Maximum message ID to return, see pagination¹
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets
	MaxID int `tl:"max_id"`
	// Minimum message ID to return, see pagination¹
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets
	MinID int `tl:"min_id"`
}

// MessagesGetUnreadMentionsRequestTypeID is TL type id of MessagesGetUnreadMentionsRequest.
const MessagesGetUnreadMentionsRequestTypeID = 0x46578472

func (g *MessagesGetUnreadMentionsRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Peer == nil) {
		return false
	}
	if !(g.OffsetID == 0) {
		return false
	}
	if !(g.AddOffset == 0) {
		return false
	}
	if !(g.Limit == 0) {
		return false
	}
	if !(g.MaxID == 0) {
		return false
	}
	if !(g.MinID == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *MessagesGetUnreadMentionsRequest) String() string {
	if g == nil {
		return "MessagesGetUnreadMentionsRequest(nil)"
	}
	type Alias MessagesGetUnreadMentionsRequest
	return fmt.Sprintf("MessagesGetUnreadMentionsRequest%+v", Alias(*g))
}

// FillFrom fills MessagesGetUnreadMentionsRequest from given interface.
func (g *MessagesGetUnreadMentionsRequest) FillFrom(from interface {
	GetPeer() (value InputPeerClass)
	GetOffsetID() (value int)
	GetAddOffset() (value int)
	GetLimit() (value int)
	GetMaxID() (value int)
	GetMinID() (value int)
}) {
	g.Peer = from.GetPeer()
	g.OffsetID = from.GetOffsetID()
	g.AddOffset = from.GetAddOffset()
	g.Limit = from.GetLimit()
	g.MaxID = from.GetMaxID()
	g.MinID = from.GetMinID()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (g *MessagesGetUnreadMentionsRequest) TypeID() uint32 {
	return MessagesGetUnreadMentionsRequestTypeID
}

// TypeName returns name of type in TL schema.
func (g *MessagesGetUnreadMentionsRequest) TypeName() string {
	return "messages.getUnreadMentions"
}

// Encode implements bin.Encoder.
func (g *MessagesGetUnreadMentionsRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode messages.getUnreadMentions#46578472 as nil")
	}
	b.PutID(MessagesGetUnreadMentionsRequestTypeID)
	if g.Peer == nil {
		return fmt.Errorf("unable to encode messages.getUnreadMentions#46578472: field peer is nil")
	}
	if err := g.Peer.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.getUnreadMentions#46578472: field peer: %w", err)
	}
	b.PutInt(g.OffsetID)
	b.PutInt(g.AddOffset)
	b.PutInt(g.Limit)
	b.PutInt(g.MaxID)
	b.PutInt(g.MinID)
	return nil
}

// GetPeer returns value of Peer field.
func (g *MessagesGetUnreadMentionsRequest) GetPeer() (value InputPeerClass) {
	return g.Peer
}

// GetOffsetID returns value of OffsetID field.
func (g *MessagesGetUnreadMentionsRequest) GetOffsetID() (value int) {
	return g.OffsetID
}

// GetAddOffset returns value of AddOffset field.
func (g *MessagesGetUnreadMentionsRequest) GetAddOffset() (value int) {
	return g.AddOffset
}

// GetLimit returns value of Limit field.
func (g *MessagesGetUnreadMentionsRequest) GetLimit() (value int) {
	return g.Limit
}

// GetMaxID returns value of MaxID field.
func (g *MessagesGetUnreadMentionsRequest) GetMaxID() (value int) {
	return g.MaxID
}

// GetMinID returns value of MinID field.
func (g *MessagesGetUnreadMentionsRequest) GetMinID() (value int) {
	return g.MinID
}

// Decode implements bin.Decoder.
func (g *MessagesGetUnreadMentionsRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode messages.getUnreadMentions#46578472 to nil")
	}
	if err := b.ConsumeID(MessagesGetUnreadMentionsRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.getUnreadMentions#46578472: %w", err)
	}
	{
		value, err := DecodeInputPeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.getUnreadMentions#46578472: field peer: %w", err)
		}
		g.Peer = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getUnreadMentions#46578472: field offset_id: %w", err)
		}
		g.OffsetID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getUnreadMentions#46578472: field add_offset: %w", err)
		}
		g.AddOffset = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getUnreadMentions#46578472: field limit: %w", err)
		}
		g.Limit = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getUnreadMentions#46578472: field max_id: %w", err)
		}
		g.MaxID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getUnreadMentions#46578472: field min_id: %w", err)
		}
		g.MinID = value
	}
	return nil
}

// Ensuring interfaces in compile-time for MessagesGetUnreadMentionsRequest.
var (
	_ bin.Encoder = &MessagesGetUnreadMentionsRequest{}
	_ bin.Decoder = &MessagesGetUnreadMentionsRequest{}
)

// MessagesGetUnreadMentions invokes method messages.getUnreadMentions#46578472 returning error if any.
// Get unread messages where we were mentioned
//
// Possible errors:
//  400 CHANNEL_INVALID: The provided channel is invalid
//  400 CHANNEL_PRIVATE: You haven't joined this channel/supergroup
//  400 PEER_ID_INVALID: The provided peer id is invalid
//
// See https://core.telegram.org/method/messages.getUnreadMentions for reference.
func (c *Client) MessagesGetUnreadMentions(ctx context.Context, request *MessagesGetUnreadMentionsRequest) (MessagesMessagesClass, error) {
	var result MessagesMessagesBox

	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return result.Messages, nil
}
