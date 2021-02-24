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

// MessagesForwardMessagesRequest represents TL type `messages.forwardMessages#d9fee60e`.
// Forwards messages by their IDs.
//
// See https://core.telegram.org/method/messages.forwardMessages for reference.
type MessagesForwardMessagesRequest struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields `tl:"flags"`
	// Whether to send messages silently (no notification will be triggered on the destination clients)
	Silent bool `tl:"silent"`
	// Whether to send the message in background
	Background bool `tl:"background"`
	// When forwarding games, whether to include your score in the game
	WithMyScore bool `tl:"with_my_score"`
	// Source of messages
	FromPeer InputPeerClass `tl:"from_peer"`
	// IDs of messages
	ID []int `tl:"id"`
	// Random ID to prevent resending of messages
	RandomID []int64 `tl:"random_id"`
	// Destination peer
	ToPeer InputPeerClass `tl:"to_peer"`
	// Scheduled message date for scheduled messages
	//
	// Use SetScheduleDate and GetScheduleDate helpers.
	ScheduleDate int `tl:"schedule_date"`
}

// MessagesForwardMessagesRequestTypeID is TL type id of MessagesForwardMessagesRequest.
const MessagesForwardMessagesRequestTypeID = 0xd9fee60e

func (f *MessagesForwardMessagesRequest) Zero() bool {
	if f == nil {
		return true
	}
	if !(f.Flags.Zero()) {
		return false
	}
	if !(f.Silent == false) {
		return false
	}
	if !(f.Background == false) {
		return false
	}
	if !(f.WithMyScore == false) {
		return false
	}
	if !(f.FromPeer == nil) {
		return false
	}
	if !(f.ID == nil) {
		return false
	}
	if !(f.RandomID == nil) {
		return false
	}
	if !(f.ToPeer == nil) {
		return false
	}
	if !(f.ScheduleDate == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (f *MessagesForwardMessagesRequest) String() string {
	if f == nil {
		return "MessagesForwardMessagesRequest(nil)"
	}
	type Alias MessagesForwardMessagesRequest
	return fmt.Sprintf("MessagesForwardMessagesRequest%+v", Alias(*f))
}

// FillFrom fills MessagesForwardMessagesRequest from given interface.
func (f *MessagesForwardMessagesRequest) FillFrom(from interface {
	GetSilent() (value bool)
	GetBackground() (value bool)
	GetWithMyScore() (value bool)
	GetFromPeer() (value InputPeerClass)
	GetID() (value []int)
	GetRandomID() (value []int64)
	GetToPeer() (value InputPeerClass)
	GetScheduleDate() (value int, ok bool)
}) {
	f.Silent = from.GetSilent()
	f.Background = from.GetBackground()
	f.WithMyScore = from.GetWithMyScore()
	f.FromPeer = from.GetFromPeer()
	f.ID = from.GetID()
	f.RandomID = from.GetRandomID()
	f.ToPeer = from.GetToPeer()
	if val, ok := from.GetScheduleDate(); ok {
		f.ScheduleDate = val
	}

}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (f *MessagesForwardMessagesRequest) TypeID() uint32 {
	return MessagesForwardMessagesRequestTypeID
}

// TypeName returns name of type in TL schema.
func (f *MessagesForwardMessagesRequest) TypeName() string {
	return "messages.forwardMessages"
}

// Encode implements bin.Encoder.
func (f *MessagesForwardMessagesRequest) Encode(b *bin.Buffer) error {
	if f == nil {
		return fmt.Errorf("can't encode messages.forwardMessages#d9fee60e as nil")
	}
	b.PutID(MessagesForwardMessagesRequestTypeID)
	if !(f.Silent == false) {
		f.Flags.Set(5)
	}
	if !(f.Background == false) {
		f.Flags.Set(6)
	}
	if !(f.WithMyScore == false) {
		f.Flags.Set(8)
	}
	if !(f.ScheduleDate == 0) {
		f.Flags.Set(10)
	}
	if err := f.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.forwardMessages#d9fee60e: field flags: %w", err)
	}
	if f.FromPeer == nil {
		return fmt.Errorf("unable to encode messages.forwardMessages#d9fee60e: field from_peer is nil")
	}
	if err := f.FromPeer.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.forwardMessages#d9fee60e: field from_peer: %w", err)
	}
	b.PutVectorHeader(len(f.ID))
	for _, v := range f.ID {
		b.PutInt(v)
	}
	b.PutVectorHeader(len(f.RandomID))
	for _, v := range f.RandomID {
		b.PutLong(v)
	}
	if f.ToPeer == nil {
		return fmt.Errorf("unable to encode messages.forwardMessages#d9fee60e: field to_peer is nil")
	}
	if err := f.ToPeer.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.forwardMessages#d9fee60e: field to_peer: %w", err)
	}
	if f.Flags.Has(10) {
		b.PutInt(f.ScheduleDate)
	}
	return nil
}

// SetSilent sets value of Silent conditional field.
func (f *MessagesForwardMessagesRequest) SetSilent(value bool) {
	if value {
		f.Flags.Set(5)
		f.Silent = true
	} else {
		f.Flags.Unset(5)
		f.Silent = false
	}
}

// GetSilent returns value of Silent conditional field.
func (f *MessagesForwardMessagesRequest) GetSilent() (value bool) {
	return f.Flags.Has(5)
}

// SetBackground sets value of Background conditional field.
func (f *MessagesForwardMessagesRequest) SetBackground(value bool) {
	if value {
		f.Flags.Set(6)
		f.Background = true
	} else {
		f.Flags.Unset(6)
		f.Background = false
	}
}

// GetBackground returns value of Background conditional field.
func (f *MessagesForwardMessagesRequest) GetBackground() (value bool) {
	return f.Flags.Has(6)
}

// SetWithMyScore sets value of WithMyScore conditional field.
func (f *MessagesForwardMessagesRequest) SetWithMyScore(value bool) {
	if value {
		f.Flags.Set(8)
		f.WithMyScore = true
	} else {
		f.Flags.Unset(8)
		f.WithMyScore = false
	}
}

// GetWithMyScore returns value of WithMyScore conditional field.
func (f *MessagesForwardMessagesRequest) GetWithMyScore() (value bool) {
	return f.Flags.Has(8)
}

// GetFromPeer returns value of FromPeer field.
func (f *MessagesForwardMessagesRequest) GetFromPeer() (value InputPeerClass) {
	return f.FromPeer
}

// GetID returns value of ID field.
func (f *MessagesForwardMessagesRequest) GetID() (value []int) {
	return f.ID
}

// GetRandomID returns value of RandomID field.
func (f *MessagesForwardMessagesRequest) GetRandomID() (value []int64) {
	return f.RandomID
}

// GetToPeer returns value of ToPeer field.
func (f *MessagesForwardMessagesRequest) GetToPeer() (value InputPeerClass) {
	return f.ToPeer
}

// SetScheduleDate sets value of ScheduleDate conditional field.
func (f *MessagesForwardMessagesRequest) SetScheduleDate(value int) {
	f.Flags.Set(10)
	f.ScheduleDate = value
}

// GetScheduleDate returns value of ScheduleDate conditional field and
// boolean which is true if field was set.
func (f *MessagesForwardMessagesRequest) GetScheduleDate() (value int, ok bool) {
	if !f.Flags.Has(10) {
		return value, false
	}
	return f.ScheduleDate, true
}

// Decode implements bin.Decoder.
func (f *MessagesForwardMessagesRequest) Decode(b *bin.Buffer) error {
	if f == nil {
		return fmt.Errorf("can't decode messages.forwardMessages#d9fee60e to nil")
	}
	if err := b.ConsumeID(MessagesForwardMessagesRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.forwardMessages#d9fee60e: %w", err)
	}
	{
		if err := f.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode messages.forwardMessages#d9fee60e: field flags: %w", err)
		}
	}
	f.Silent = f.Flags.Has(5)
	f.Background = f.Flags.Has(6)
	f.WithMyScore = f.Flags.Has(8)
	{
		value, err := DecodeInputPeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.forwardMessages#d9fee60e: field from_peer: %w", err)
		}
		f.FromPeer = value
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode messages.forwardMessages#d9fee60e: field id: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := b.Int()
			if err != nil {
				return fmt.Errorf("unable to decode messages.forwardMessages#d9fee60e: field id: %w", err)
			}
			f.ID = append(f.ID, value)
		}
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode messages.forwardMessages#d9fee60e: field random_id: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := b.Long()
			if err != nil {
				return fmt.Errorf("unable to decode messages.forwardMessages#d9fee60e: field random_id: %w", err)
			}
			f.RandomID = append(f.RandomID, value)
		}
	}
	{
		value, err := DecodeInputPeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.forwardMessages#d9fee60e: field to_peer: %w", err)
		}
		f.ToPeer = value
	}
	if f.Flags.Has(10) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.forwardMessages#d9fee60e: field schedule_date: %w", err)
		}
		f.ScheduleDate = value
	}
	return nil
}

// Ensuring interfaces in compile-time for MessagesForwardMessagesRequest.
var (
	_ bin.Encoder = &MessagesForwardMessagesRequest{}
	_ bin.Decoder = &MessagesForwardMessagesRequest{}
)

// MessagesForwardMessages invokes method messages.forwardMessages#d9fee60e returning error if any.
// Forwards messages by their IDs.
//
// Possible errors:
//  400 BROADCAST_PUBLIC_VOTERS_FORBIDDEN: You can't forward polls with public voters
//  400 CHANNEL_INVALID: The provided channel is invalid
//  400 CHANNEL_PRIVATE: You haven't joined this channel/supergroup
//  400 CHAT_ADMIN_REQUIRED: You must be an admin in this chat to do this
//  400 CHAT_ID_INVALID: The provided chat id is invalid
//  400 CHAT_RESTRICTED: You can't send messages in this chat, you were restricted
//  403 CHAT_SEND_GIFS_FORBIDDEN: You can't send gifs in this chat
//  403 CHAT_SEND_MEDIA_FORBIDDEN: You can't send media in this chat
//  403 CHAT_SEND_POLL_FORBIDDEN: You can't send polls in this chat
//  403 CHAT_SEND_STICKERS_FORBIDDEN: You can't send stickers in this chat.
//  403 CHAT_WRITE_FORBIDDEN: You can't write in this chat
//  400 GROUPED_MEDIA_INVALID: Invalid grouped media
//  400 INPUT_USER_DEACTIVATED: The specified user was deleted
//  400 MEDIA_EMPTY: The provided media object is invalid
//  400 MESSAGE_IDS_EMPTY: No message ids were provided
//  400 MESSAGE_ID_INVALID: The provided message id is invalid
//  400 MSG_ID_INVALID: Invalid message ID provided
//  420 P0NY_FLOODWAIT:
//  400 PEER_ID_INVALID: The provided peer id is invalid
//  400 RANDOM_ID_INVALID: A provided random ID is invalid
//  400 SCHEDULE_TOO_MUCH: There are too many scheduled messages
//  400 SLOWMODE_MULTI_MSGS_DISABLED: Slowmode is enabled, you cannot forward multiple messages to this group.
//  420 SLOWMODE_WAIT_X: Slowmode is enabled in this chat: you must wait for the specified number of seconds before sending another message to the chat.
//  400 USER_BANNED_IN_CHANNEL: You're banned from sending messages in supergroups/channels
//  400 USER_IS_BLOCKED: You were blocked by this user
//  400 USER_IS_BOT: Bots can't send messages to other bots
//  400 YOU_BLOCKED_USER: You blocked this user
//
// See https://core.telegram.org/method/messages.forwardMessages for reference.
// Can be used by bots.
func (c *Client) MessagesForwardMessages(ctx context.Context, request *MessagesForwardMessagesRequest) (UpdatesClass, error) {
	var result UpdatesBox

	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return result.Updates, nil
}
