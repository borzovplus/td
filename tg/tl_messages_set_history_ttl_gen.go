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

// MessagesSetHistoryTTLRequest represents TL type `messages.setHistoryTTL#b80e5fe4`.
// Set maximum Time-To-Live of all messages in the specified chat
//
// See https://core.telegram.org/method/messages.setHistoryTTL for reference.
type MessagesSetHistoryTTLRequest struct {
	// The dialog
	Peer InputPeerClass
	// Automatically delete all messages sent in the chat after this many seconds
	Period int
}

// MessagesSetHistoryTTLRequestTypeID is TL type id of MessagesSetHistoryTTLRequest.
const MessagesSetHistoryTTLRequestTypeID = 0xb80e5fe4

// Ensuring interfaces in compile-time for MessagesSetHistoryTTLRequest.
var (
	_ bin.Encoder     = &MessagesSetHistoryTTLRequest{}
	_ bin.Decoder     = &MessagesSetHistoryTTLRequest{}
	_ bin.BareEncoder = &MessagesSetHistoryTTLRequest{}
	_ bin.BareDecoder = &MessagesSetHistoryTTLRequest{}
)

func (s *MessagesSetHistoryTTLRequest) Zero() bool {
	if s == nil {
		return true
	}
	if !(s.Peer == nil) {
		return false
	}
	if !(s.Period == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (s *MessagesSetHistoryTTLRequest) String() string {
	if s == nil {
		return "MessagesSetHistoryTTLRequest(nil)"
	}
	type Alias MessagesSetHistoryTTLRequest
	return fmt.Sprintf("MessagesSetHistoryTTLRequest%+v", Alias(*s))
}

// FillFrom fills MessagesSetHistoryTTLRequest from given interface.
func (s *MessagesSetHistoryTTLRequest) FillFrom(from interface {
	GetPeer() (value InputPeerClass)
	GetPeriod() (value int)
}) {
	s.Peer = from.GetPeer()
	s.Period = from.GetPeriod()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*MessagesSetHistoryTTLRequest) TypeID() uint32 {
	return MessagesSetHistoryTTLRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*MessagesSetHistoryTTLRequest) TypeName() string {
	return "messages.setHistoryTTL"
}

// TypeInfo returns info about TL type.
func (s *MessagesSetHistoryTTLRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "messages.setHistoryTTL",
		ID:   MessagesSetHistoryTTLRequestTypeID,
	}
	if s == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Peer",
			SchemaName: "peer",
		},
		{
			Name:       "Period",
			SchemaName: "period",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (s *MessagesSetHistoryTTLRequest) Encode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode messages.setHistoryTTL#b80e5fe4 as nil")
	}
	b.PutID(MessagesSetHistoryTTLRequestTypeID)
	return s.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (s *MessagesSetHistoryTTLRequest) EncodeBare(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode messages.setHistoryTTL#b80e5fe4 as nil")
	}
	if s.Peer == nil {
		return fmt.Errorf("unable to encode messages.setHistoryTTL#b80e5fe4: field peer is nil")
	}
	if err := s.Peer.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.setHistoryTTL#b80e5fe4: field peer: %w", err)
	}
	b.PutInt(s.Period)
	return nil
}

// Decode implements bin.Decoder.
func (s *MessagesSetHistoryTTLRequest) Decode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode messages.setHistoryTTL#b80e5fe4 to nil")
	}
	if err := b.ConsumeID(MessagesSetHistoryTTLRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.setHistoryTTL#b80e5fe4: %w", err)
	}
	return s.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (s *MessagesSetHistoryTTLRequest) DecodeBare(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode messages.setHistoryTTL#b80e5fe4 to nil")
	}
	{
		value, err := DecodeInputPeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.setHistoryTTL#b80e5fe4: field peer: %w", err)
		}
		s.Peer = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.setHistoryTTL#b80e5fe4: field period: %w", err)
		}
		s.Period = value
	}
	return nil
}

// GetPeer returns value of Peer field.
func (s *MessagesSetHistoryTTLRequest) GetPeer() (value InputPeerClass) {
	if s == nil {
		return
	}
	return s.Peer
}

// GetPeriod returns value of Period field.
func (s *MessagesSetHistoryTTLRequest) GetPeriod() (value int) {
	if s == nil {
		return
	}
	return s.Period
}

// MessagesSetHistoryTTL invokes method messages.setHistoryTTL#b80e5fe4 returning error if any.
// Set maximum Time-To-Live of all messages in the specified chat
//
// Possible errors:
//
//	400 CHAT_NOT_MODIFIED: No changes were made to chat information because the new information you passed is identical to the current information.
//	400 TTL_PERIOD_INVALID: The specified TTL period is invalid.
//
// See https://core.telegram.org/method/messages.setHistoryTTL for reference.
func (c *Client) MessagesSetHistoryTTL(ctx context.Context, request *MessagesSetHistoryTTLRequest) (UpdatesClass, error) {
	var result UpdatesBox

	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return result.Updates, nil
}
