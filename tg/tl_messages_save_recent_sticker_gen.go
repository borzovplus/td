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

// MessagesSaveRecentStickerRequest represents TL type `messages.saveRecentSticker#392718f8`.
// Add/remove sticker from recent stickers list
//
// See https://core.telegram.org/method/messages.saveRecentSticker for reference.
type MessagesSaveRecentStickerRequest struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields `tl:"flags"`
	// Whether to add/remove stickers recently attached to photo or video files
	Attached bool `tl:"attached"`
	// Sticker
	ID InputDocumentClass `tl:"id"`
	// Whether to save or unsave the sticker
	Unsave bool `tl:"unsave"`
}

// MessagesSaveRecentStickerRequestTypeID is TL type id of MessagesSaveRecentStickerRequest.
const MessagesSaveRecentStickerRequestTypeID = 0x392718f8

func (s *MessagesSaveRecentStickerRequest) Zero() bool {
	if s == nil {
		return true
	}
	if !(s.Flags.Zero()) {
		return false
	}
	if !(s.Attached == false) {
		return false
	}
	if !(s.ID == nil) {
		return false
	}
	if !(s.Unsave == false) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (s *MessagesSaveRecentStickerRequest) String() string {
	if s == nil {
		return "MessagesSaveRecentStickerRequest(nil)"
	}
	type Alias MessagesSaveRecentStickerRequest
	return fmt.Sprintf("MessagesSaveRecentStickerRequest%+v", Alias(*s))
}

// FillFrom fills MessagesSaveRecentStickerRequest from given interface.
func (s *MessagesSaveRecentStickerRequest) FillFrom(from interface {
	GetAttached() (value bool)
	GetID() (value InputDocumentClass)
	GetUnsave() (value bool)
}) {
	s.Attached = from.GetAttached()
	s.ID = from.GetID()
	s.Unsave = from.GetUnsave()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (s *MessagesSaveRecentStickerRequest) TypeID() uint32 {
	return MessagesSaveRecentStickerRequestTypeID
}

// TypeName returns name of type in TL schema.
func (s *MessagesSaveRecentStickerRequest) TypeName() string {
	return "messages.saveRecentSticker"
}

// Encode implements bin.Encoder.
func (s *MessagesSaveRecentStickerRequest) Encode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode messages.saveRecentSticker#392718f8 as nil")
	}
	b.PutID(MessagesSaveRecentStickerRequestTypeID)
	if !(s.Attached == false) {
		s.Flags.Set(0)
	}
	if err := s.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.saveRecentSticker#392718f8: field flags: %w", err)
	}
	if s.ID == nil {
		return fmt.Errorf("unable to encode messages.saveRecentSticker#392718f8: field id is nil")
	}
	if err := s.ID.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.saveRecentSticker#392718f8: field id: %w", err)
	}
	b.PutBool(s.Unsave)
	return nil
}

// SetAttached sets value of Attached conditional field.
func (s *MessagesSaveRecentStickerRequest) SetAttached(value bool) {
	if value {
		s.Flags.Set(0)
		s.Attached = true
	} else {
		s.Flags.Unset(0)
		s.Attached = false
	}
}

// GetAttached returns value of Attached conditional field.
func (s *MessagesSaveRecentStickerRequest) GetAttached() (value bool) {
	return s.Flags.Has(0)
}

// GetID returns value of ID field.
func (s *MessagesSaveRecentStickerRequest) GetID() (value InputDocumentClass) {
	return s.ID
}

// GetIDAsNotEmpty returns mapped value of ID field.
func (s *MessagesSaveRecentStickerRequest) GetIDAsNotEmpty() (*InputDocument, bool) {
	return s.ID.AsNotEmpty()
}

// GetUnsave returns value of Unsave field.
func (s *MessagesSaveRecentStickerRequest) GetUnsave() (value bool) {
	return s.Unsave
}

// Decode implements bin.Decoder.
func (s *MessagesSaveRecentStickerRequest) Decode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode messages.saveRecentSticker#392718f8 to nil")
	}
	if err := b.ConsumeID(MessagesSaveRecentStickerRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.saveRecentSticker#392718f8: %w", err)
	}
	{
		if err := s.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode messages.saveRecentSticker#392718f8: field flags: %w", err)
		}
	}
	s.Attached = s.Flags.Has(0)
	{
		value, err := DecodeInputDocument(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.saveRecentSticker#392718f8: field id: %w", err)
		}
		s.ID = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode messages.saveRecentSticker#392718f8: field unsave: %w", err)
		}
		s.Unsave = value
	}
	return nil
}

// Ensuring interfaces in compile-time for MessagesSaveRecentStickerRequest.
var (
	_ bin.Encoder = &MessagesSaveRecentStickerRequest{}
	_ bin.Decoder = &MessagesSaveRecentStickerRequest{}
)

// MessagesSaveRecentSticker invokes method messages.saveRecentSticker#392718f8 returning error if any.
// Add/remove sticker from recent stickers list
//
// Possible errors:
//  400 STICKER_ID_INVALID: The provided sticker ID is invalid
//
// See https://core.telegram.org/method/messages.saveRecentSticker for reference.
func (c *Client) MessagesSaveRecentSticker(ctx context.Context, request *MessagesSaveRecentStickerRequest) (bool, error) {
	var result BoolBox

	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return false, err
	}
	_, ok := result.Bool.(*BoolTrue)
	return ok, nil
}
