// Code generated by gotdgen, DO NOT EDIT.

package tg

import (
	"context"
	"fmt"

	"github.com/ernado/td/bin"
)

// No-op definition for keeping imports.
var _ = bin.Buffer{}
var _ = context.Background()
var _ = fmt.Stringer(nil)

// UpdatesTooLong represents TL type `updatesTooLong#e317af7e`.
type UpdatesTooLong struct {
}

// UpdatesTooLongTypeID is TL type id of UpdatesTooLong.
const UpdatesTooLongTypeID = 0xe317af7e

// Encode implements bin.Encoder.
func (u *UpdatesTooLong) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode updatesTooLong#e317af7e as nil")
	}
	b.PutID(UpdatesTooLongTypeID)
	return nil
}

// Decode implements bin.Decoder.
func (u *UpdatesTooLong) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode updatesTooLong#e317af7e to nil")
	}
	if err := b.ConsumeID(UpdatesTooLongTypeID); err != nil {
		return fmt.Errorf("unable to decode updatesTooLong#e317af7e: %w", err)
	}
	return nil
}

// construct implements constructor of UpdatesClass.
func (u UpdatesTooLong) construct() UpdatesClass { return &u }

// Ensuring interfaces in compile-time for UpdatesTooLong.
var (
	_ bin.Encoder = &UpdatesTooLong{}
	_ bin.Decoder = &UpdatesTooLong{}

	_ UpdatesClass = &UpdatesTooLong{}
)

// UpdateShortMessage represents TL type `updateShortMessage#2296d2c8`.
type UpdateShortMessage struct {
	// Flags field of UpdateShortMessage.
	Flags bin.Fields
	// Out field of UpdateShortMessage.
	Out bool
	// Mentioned field of UpdateShortMessage.
	Mentioned bool
	// MediaUnread field of UpdateShortMessage.
	MediaUnread bool
	// Silent field of UpdateShortMessage.
	Silent bool
	// ID field of UpdateShortMessage.
	ID int
	// UserID field of UpdateShortMessage.
	UserID int
	// Message field of UpdateShortMessage.
	Message string
	// Pts field of UpdateShortMessage.
	Pts int
	// PtsCount field of UpdateShortMessage.
	PtsCount int
	// Date field of UpdateShortMessage.
	Date int
	// FwdFrom field of UpdateShortMessage.
	//
	// Use SetFwdFrom and GetFwdFrom helpers.
	FwdFrom MessageFwdHeader
	// ViaBotID field of UpdateShortMessage.
	//
	// Use SetViaBotID and GetViaBotID helpers.
	ViaBotID int
	// ReplyTo field of UpdateShortMessage.
	//
	// Use SetReplyTo and GetReplyTo helpers.
	ReplyTo MessageReplyHeader
	// Entities field of UpdateShortMessage.
	//
	// Use SetEntities and GetEntities helpers.
	Entities []MessageEntityClass
}

// UpdateShortMessageTypeID is TL type id of UpdateShortMessage.
const UpdateShortMessageTypeID = 0x2296d2c8

// Encode implements bin.Encoder.
func (u *UpdateShortMessage) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode updateShortMessage#2296d2c8 as nil")
	}
	b.PutID(UpdateShortMessageTypeID)
	if err := u.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode updateShortMessage#2296d2c8: field flags: %w", err)
	}
	b.PutInt(u.ID)
	b.PutInt(u.UserID)
	b.PutString(u.Message)
	b.PutInt(u.Pts)
	b.PutInt(u.PtsCount)
	b.PutInt(u.Date)
	if u.Flags.Has(2) {
		if err := u.FwdFrom.Encode(b); err != nil {
			return fmt.Errorf("unable to encode updateShortMessage#2296d2c8: field fwd_from: %w", err)
		}
	}
	if u.Flags.Has(11) {
		b.PutInt(u.ViaBotID)
	}
	if u.Flags.Has(3) {
		if err := u.ReplyTo.Encode(b); err != nil {
			return fmt.Errorf("unable to encode updateShortMessage#2296d2c8: field reply_to: %w", err)
		}
	}
	if u.Flags.Has(7) {
		b.PutVectorHeader(len(u.Entities))
		for idx, v := range u.Entities {
			if v == nil {
				return fmt.Errorf("unable to encode updateShortMessage#2296d2c8: field entities element with index %d is nil", idx)
			}
			if err := v.Encode(b); err != nil {
				return fmt.Errorf("unable to encode updateShortMessage#2296d2c8: field entities element with index %d: %w", idx, err)
			}
		}
	}
	return nil
}

// SetOut sets value of Out conditional field.
func (u *UpdateShortMessage) SetOut(value bool) {
	if value {
		u.Flags.Set(1)
	} else {
		u.Flags.Unset(1)
	}
}

// SetMentioned sets value of Mentioned conditional field.
func (u *UpdateShortMessage) SetMentioned(value bool) {
	if value {
		u.Flags.Set(4)
	} else {
		u.Flags.Unset(4)
	}
}

// SetMediaUnread sets value of MediaUnread conditional field.
func (u *UpdateShortMessage) SetMediaUnread(value bool) {
	if value {
		u.Flags.Set(5)
	} else {
		u.Flags.Unset(5)
	}
}

// SetSilent sets value of Silent conditional field.
func (u *UpdateShortMessage) SetSilent(value bool) {
	if value {
		u.Flags.Set(13)
	} else {
		u.Flags.Unset(13)
	}
}

// SetFwdFrom sets value of FwdFrom conditional field.
func (u *UpdateShortMessage) SetFwdFrom(value MessageFwdHeader) {
	u.Flags.Set(2)
	u.FwdFrom = value
}

// GetFwdFrom returns value of FwdFrom conditional field and
// boolean which is true if field was set.
func (u *UpdateShortMessage) GetFwdFrom() (value MessageFwdHeader, ok bool) {
	if !u.Flags.Has(2) {
		return value, false
	}
	return u.FwdFrom, true
}

// SetViaBotID sets value of ViaBotID conditional field.
func (u *UpdateShortMessage) SetViaBotID(value int) {
	u.Flags.Set(11)
	u.ViaBotID = value
}

// GetViaBotID returns value of ViaBotID conditional field and
// boolean which is true if field was set.
func (u *UpdateShortMessage) GetViaBotID() (value int, ok bool) {
	if !u.Flags.Has(11) {
		return value, false
	}
	return u.ViaBotID, true
}

// SetReplyTo sets value of ReplyTo conditional field.
func (u *UpdateShortMessage) SetReplyTo(value MessageReplyHeader) {
	u.Flags.Set(3)
	u.ReplyTo = value
}

// GetReplyTo returns value of ReplyTo conditional field and
// boolean which is true if field was set.
func (u *UpdateShortMessage) GetReplyTo() (value MessageReplyHeader, ok bool) {
	if !u.Flags.Has(3) {
		return value, false
	}
	return u.ReplyTo, true
}

// SetEntities sets value of Entities conditional field.
func (u *UpdateShortMessage) SetEntities(value []MessageEntityClass) {
	u.Flags.Set(7)
	u.Entities = value
}

// GetEntities returns value of Entities conditional field and
// boolean which is true if field was set.
func (u *UpdateShortMessage) GetEntities() (value []MessageEntityClass, ok bool) {
	if !u.Flags.Has(7) {
		return value, false
	}
	return u.Entities, true
}

// Decode implements bin.Decoder.
func (u *UpdateShortMessage) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode updateShortMessage#2296d2c8 to nil")
	}
	if err := b.ConsumeID(UpdateShortMessageTypeID); err != nil {
		return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: %w", err)
	}
	{
		if err := u.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field flags: %w", err)
		}
	}
	u.Out = u.Flags.Has(1)
	u.Mentioned = u.Flags.Has(4)
	u.MediaUnread = u.Flags.Has(5)
	u.Silent = u.Flags.Has(13)
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field id: %w", err)
		}
		u.ID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field user_id: %w", err)
		}
		u.UserID = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field message: %w", err)
		}
		u.Message = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field pts: %w", err)
		}
		u.Pts = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field pts_count: %w", err)
		}
		u.PtsCount = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field date: %w", err)
		}
		u.Date = value
	}
	if u.Flags.Has(2) {
		if err := u.FwdFrom.Decode(b); err != nil {
			return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field fwd_from: %w", err)
		}
	}
	if u.Flags.Has(11) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field via_bot_id: %w", err)
		}
		u.ViaBotID = value
	}
	if u.Flags.Has(3) {
		if err := u.ReplyTo.Decode(b); err != nil {
			return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field reply_to: %w", err)
		}
	}
	if u.Flags.Has(7) {
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field entities: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeMessageEntity(b)
			if err != nil {
				return fmt.Errorf("unable to decode updateShortMessage#2296d2c8: field entities: %w", err)
			}
			u.Entities = append(u.Entities, value)
		}
	}
	return nil
}

// construct implements constructor of UpdatesClass.
func (u UpdateShortMessage) construct() UpdatesClass { return &u }

// Ensuring interfaces in compile-time for UpdateShortMessage.
var (
	_ bin.Encoder = &UpdateShortMessage{}
	_ bin.Decoder = &UpdateShortMessage{}

	_ UpdatesClass = &UpdateShortMessage{}
)

// UpdateShortChatMessage represents TL type `updateShortChatMessage#402d5dbb`.
type UpdateShortChatMessage struct {
	// Flags field of UpdateShortChatMessage.
	Flags bin.Fields
	// Out field of UpdateShortChatMessage.
	Out bool
	// Mentioned field of UpdateShortChatMessage.
	Mentioned bool
	// MediaUnread field of UpdateShortChatMessage.
	MediaUnread bool
	// Silent field of UpdateShortChatMessage.
	Silent bool
	// ID field of UpdateShortChatMessage.
	ID int
	// FromID field of UpdateShortChatMessage.
	FromID int
	// ChatID field of UpdateShortChatMessage.
	ChatID int
	// Message field of UpdateShortChatMessage.
	Message string
	// Pts field of UpdateShortChatMessage.
	Pts int
	// PtsCount field of UpdateShortChatMessage.
	PtsCount int
	// Date field of UpdateShortChatMessage.
	Date int
	// FwdFrom field of UpdateShortChatMessage.
	//
	// Use SetFwdFrom and GetFwdFrom helpers.
	FwdFrom MessageFwdHeader
	// ViaBotID field of UpdateShortChatMessage.
	//
	// Use SetViaBotID and GetViaBotID helpers.
	ViaBotID int
	// ReplyTo field of UpdateShortChatMessage.
	//
	// Use SetReplyTo and GetReplyTo helpers.
	ReplyTo MessageReplyHeader
	// Entities field of UpdateShortChatMessage.
	//
	// Use SetEntities and GetEntities helpers.
	Entities []MessageEntityClass
}

// UpdateShortChatMessageTypeID is TL type id of UpdateShortChatMessage.
const UpdateShortChatMessageTypeID = 0x402d5dbb

// Encode implements bin.Encoder.
func (u *UpdateShortChatMessage) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode updateShortChatMessage#402d5dbb as nil")
	}
	b.PutID(UpdateShortChatMessageTypeID)
	if err := u.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode updateShortChatMessage#402d5dbb: field flags: %w", err)
	}
	b.PutInt(u.ID)
	b.PutInt(u.FromID)
	b.PutInt(u.ChatID)
	b.PutString(u.Message)
	b.PutInt(u.Pts)
	b.PutInt(u.PtsCount)
	b.PutInt(u.Date)
	if u.Flags.Has(2) {
		if err := u.FwdFrom.Encode(b); err != nil {
			return fmt.Errorf("unable to encode updateShortChatMessage#402d5dbb: field fwd_from: %w", err)
		}
	}
	if u.Flags.Has(11) {
		b.PutInt(u.ViaBotID)
	}
	if u.Flags.Has(3) {
		if err := u.ReplyTo.Encode(b); err != nil {
			return fmt.Errorf("unable to encode updateShortChatMessage#402d5dbb: field reply_to: %w", err)
		}
	}
	if u.Flags.Has(7) {
		b.PutVectorHeader(len(u.Entities))
		for idx, v := range u.Entities {
			if v == nil {
				return fmt.Errorf("unable to encode updateShortChatMessage#402d5dbb: field entities element with index %d is nil", idx)
			}
			if err := v.Encode(b); err != nil {
				return fmt.Errorf("unable to encode updateShortChatMessage#402d5dbb: field entities element with index %d: %w", idx, err)
			}
		}
	}
	return nil
}

// SetOut sets value of Out conditional field.
func (u *UpdateShortChatMessage) SetOut(value bool) {
	if value {
		u.Flags.Set(1)
	} else {
		u.Flags.Unset(1)
	}
}

// SetMentioned sets value of Mentioned conditional field.
func (u *UpdateShortChatMessage) SetMentioned(value bool) {
	if value {
		u.Flags.Set(4)
	} else {
		u.Flags.Unset(4)
	}
}

// SetMediaUnread sets value of MediaUnread conditional field.
func (u *UpdateShortChatMessage) SetMediaUnread(value bool) {
	if value {
		u.Flags.Set(5)
	} else {
		u.Flags.Unset(5)
	}
}

// SetSilent sets value of Silent conditional field.
func (u *UpdateShortChatMessage) SetSilent(value bool) {
	if value {
		u.Flags.Set(13)
	} else {
		u.Flags.Unset(13)
	}
}

// SetFwdFrom sets value of FwdFrom conditional field.
func (u *UpdateShortChatMessage) SetFwdFrom(value MessageFwdHeader) {
	u.Flags.Set(2)
	u.FwdFrom = value
}

// GetFwdFrom returns value of FwdFrom conditional field and
// boolean which is true if field was set.
func (u *UpdateShortChatMessage) GetFwdFrom() (value MessageFwdHeader, ok bool) {
	if !u.Flags.Has(2) {
		return value, false
	}
	return u.FwdFrom, true
}

// SetViaBotID sets value of ViaBotID conditional field.
func (u *UpdateShortChatMessage) SetViaBotID(value int) {
	u.Flags.Set(11)
	u.ViaBotID = value
}

// GetViaBotID returns value of ViaBotID conditional field and
// boolean which is true if field was set.
func (u *UpdateShortChatMessage) GetViaBotID() (value int, ok bool) {
	if !u.Flags.Has(11) {
		return value, false
	}
	return u.ViaBotID, true
}

// SetReplyTo sets value of ReplyTo conditional field.
func (u *UpdateShortChatMessage) SetReplyTo(value MessageReplyHeader) {
	u.Flags.Set(3)
	u.ReplyTo = value
}

// GetReplyTo returns value of ReplyTo conditional field and
// boolean which is true if field was set.
func (u *UpdateShortChatMessage) GetReplyTo() (value MessageReplyHeader, ok bool) {
	if !u.Flags.Has(3) {
		return value, false
	}
	return u.ReplyTo, true
}

// SetEntities sets value of Entities conditional field.
func (u *UpdateShortChatMessage) SetEntities(value []MessageEntityClass) {
	u.Flags.Set(7)
	u.Entities = value
}

// GetEntities returns value of Entities conditional field and
// boolean which is true if field was set.
func (u *UpdateShortChatMessage) GetEntities() (value []MessageEntityClass, ok bool) {
	if !u.Flags.Has(7) {
		return value, false
	}
	return u.Entities, true
}

// Decode implements bin.Decoder.
func (u *UpdateShortChatMessage) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode updateShortChatMessage#402d5dbb to nil")
	}
	if err := b.ConsumeID(UpdateShortChatMessageTypeID); err != nil {
		return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: %w", err)
	}
	{
		if err := u.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field flags: %w", err)
		}
	}
	u.Out = u.Flags.Has(1)
	u.Mentioned = u.Flags.Has(4)
	u.MediaUnread = u.Flags.Has(5)
	u.Silent = u.Flags.Has(13)
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field id: %w", err)
		}
		u.ID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field from_id: %w", err)
		}
		u.FromID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field chat_id: %w", err)
		}
		u.ChatID = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field message: %w", err)
		}
		u.Message = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field pts: %w", err)
		}
		u.Pts = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field pts_count: %w", err)
		}
		u.PtsCount = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field date: %w", err)
		}
		u.Date = value
	}
	if u.Flags.Has(2) {
		if err := u.FwdFrom.Decode(b); err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field fwd_from: %w", err)
		}
	}
	if u.Flags.Has(11) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field via_bot_id: %w", err)
		}
		u.ViaBotID = value
	}
	if u.Flags.Has(3) {
		if err := u.ReplyTo.Decode(b); err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field reply_to: %w", err)
		}
	}
	if u.Flags.Has(7) {
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field entities: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeMessageEntity(b)
			if err != nil {
				return fmt.Errorf("unable to decode updateShortChatMessage#402d5dbb: field entities: %w", err)
			}
			u.Entities = append(u.Entities, value)
		}
	}
	return nil
}

// construct implements constructor of UpdatesClass.
func (u UpdateShortChatMessage) construct() UpdatesClass { return &u }

// Ensuring interfaces in compile-time for UpdateShortChatMessage.
var (
	_ bin.Encoder = &UpdateShortChatMessage{}
	_ bin.Decoder = &UpdateShortChatMessage{}

	_ UpdatesClass = &UpdateShortChatMessage{}
)

// UpdateShort represents TL type `updateShort#78d4dec1`.
type UpdateShort struct {
	// Update field of UpdateShort.
	Update UpdateClass
	// Date field of UpdateShort.
	Date int
}

// UpdateShortTypeID is TL type id of UpdateShort.
const UpdateShortTypeID = 0x78d4dec1

// Encode implements bin.Encoder.
func (u *UpdateShort) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode updateShort#78d4dec1 as nil")
	}
	b.PutID(UpdateShortTypeID)
	if u.Update == nil {
		return fmt.Errorf("unable to encode updateShort#78d4dec1: field update is nil")
	}
	if err := u.Update.Encode(b); err != nil {
		return fmt.Errorf("unable to encode updateShort#78d4dec1: field update: %w", err)
	}
	b.PutInt(u.Date)
	return nil
}

// Decode implements bin.Decoder.
func (u *UpdateShort) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode updateShort#78d4dec1 to nil")
	}
	if err := b.ConsumeID(UpdateShortTypeID); err != nil {
		return fmt.Errorf("unable to decode updateShort#78d4dec1: %w", err)
	}
	{
		value, err := DecodeUpdate(b)
		if err != nil {
			return fmt.Errorf("unable to decode updateShort#78d4dec1: field update: %w", err)
		}
		u.Update = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShort#78d4dec1: field date: %w", err)
		}
		u.Date = value
	}
	return nil
}

// construct implements constructor of UpdatesClass.
func (u UpdateShort) construct() UpdatesClass { return &u }

// Ensuring interfaces in compile-time for UpdateShort.
var (
	_ bin.Encoder = &UpdateShort{}
	_ bin.Decoder = &UpdateShort{}

	_ UpdatesClass = &UpdateShort{}
)

// UpdatesCombined represents TL type `updatesCombined#725b04c3`.
type UpdatesCombined struct {
	// Updates field of UpdatesCombined.
	Updates []UpdateClass
	// Users field of UpdatesCombined.
	Users []UserClass
	// Chats field of UpdatesCombined.
	Chats []ChatClass
	// Date field of UpdatesCombined.
	Date int
	// SeqStart field of UpdatesCombined.
	SeqStart int
	// Seq field of UpdatesCombined.
	Seq int
}

// UpdatesCombinedTypeID is TL type id of UpdatesCombined.
const UpdatesCombinedTypeID = 0x725b04c3

// Encode implements bin.Encoder.
func (u *UpdatesCombined) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode updatesCombined#725b04c3 as nil")
	}
	b.PutID(UpdatesCombinedTypeID)
	b.PutVectorHeader(len(u.Updates))
	for idx, v := range u.Updates {
		if v == nil {
			return fmt.Errorf("unable to encode updatesCombined#725b04c3: field updates element with index %d is nil", idx)
		}
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode updatesCombined#725b04c3: field updates element with index %d: %w", idx, err)
		}
	}
	b.PutVectorHeader(len(u.Users))
	for idx, v := range u.Users {
		if v == nil {
			return fmt.Errorf("unable to encode updatesCombined#725b04c3: field users element with index %d is nil", idx)
		}
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode updatesCombined#725b04c3: field users element with index %d: %w", idx, err)
		}
	}
	b.PutVectorHeader(len(u.Chats))
	for idx, v := range u.Chats {
		if v == nil {
			return fmt.Errorf("unable to encode updatesCombined#725b04c3: field chats element with index %d is nil", idx)
		}
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode updatesCombined#725b04c3: field chats element with index %d: %w", idx, err)
		}
	}
	b.PutInt(u.Date)
	b.PutInt(u.SeqStart)
	b.PutInt(u.Seq)
	return nil
}

// Decode implements bin.Decoder.
func (u *UpdatesCombined) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode updatesCombined#725b04c3 to nil")
	}
	if err := b.ConsumeID(UpdatesCombinedTypeID); err != nil {
		return fmt.Errorf("unable to decode updatesCombined#725b04c3: %w", err)
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode updatesCombined#725b04c3: field updates: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeUpdate(b)
			if err != nil {
				return fmt.Errorf("unable to decode updatesCombined#725b04c3: field updates: %w", err)
			}
			u.Updates = append(u.Updates, value)
		}
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode updatesCombined#725b04c3: field users: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeUser(b)
			if err != nil {
				return fmt.Errorf("unable to decode updatesCombined#725b04c3: field users: %w", err)
			}
			u.Users = append(u.Users, value)
		}
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode updatesCombined#725b04c3: field chats: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeChat(b)
			if err != nil {
				return fmt.Errorf("unable to decode updatesCombined#725b04c3: field chats: %w", err)
			}
			u.Chats = append(u.Chats, value)
		}
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updatesCombined#725b04c3: field date: %w", err)
		}
		u.Date = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updatesCombined#725b04c3: field seq_start: %w", err)
		}
		u.SeqStart = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updatesCombined#725b04c3: field seq: %w", err)
		}
		u.Seq = value
	}
	return nil
}

// construct implements constructor of UpdatesClass.
func (u UpdatesCombined) construct() UpdatesClass { return &u }

// Ensuring interfaces in compile-time for UpdatesCombined.
var (
	_ bin.Encoder = &UpdatesCombined{}
	_ bin.Decoder = &UpdatesCombined{}

	_ UpdatesClass = &UpdatesCombined{}
)

// Updates represents TL type `updates#74ae4240`.
type Updates struct {
	// Updates field of Updates.
	Updates []UpdateClass
	// Users field of Updates.
	Users []UserClass
	// Chats field of Updates.
	Chats []ChatClass
	// Date field of Updates.
	Date int
	// Seq field of Updates.
	Seq int
}

// UpdatesTypeID is TL type id of Updates.
const UpdatesTypeID = 0x74ae4240

// Encode implements bin.Encoder.
func (u *Updates) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode updates#74ae4240 as nil")
	}
	b.PutID(UpdatesTypeID)
	b.PutVectorHeader(len(u.Updates))
	for idx, v := range u.Updates {
		if v == nil {
			return fmt.Errorf("unable to encode updates#74ae4240: field updates element with index %d is nil", idx)
		}
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode updates#74ae4240: field updates element with index %d: %w", idx, err)
		}
	}
	b.PutVectorHeader(len(u.Users))
	for idx, v := range u.Users {
		if v == nil {
			return fmt.Errorf("unable to encode updates#74ae4240: field users element with index %d is nil", idx)
		}
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode updates#74ae4240: field users element with index %d: %w", idx, err)
		}
	}
	b.PutVectorHeader(len(u.Chats))
	for idx, v := range u.Chats {
		if v == nil {
			return fmt.Errorf("unable to encode updates#74ae4240: field chats element with index %d is nil", idx)
		}
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode updates#74ae4240: field chats element with index %d: %w", idx, err)
		}
	}
	b.PutInt(u.Date)
	b.PutInt(u.Seq)
	return nil
}

// Decode implements bin.Decoder.
func (u *Updates) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode updates#74ae4240 to nil")
	}
	if err := b.ConsumeID(UpdatesTypeID); err != nil {
		return fmt.Errorf("unable to decode updates#74ae4240: %w", err)
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode updates#74ae4240: field updates: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeUpdate(b)
			if err != nil {
				return fmt.Errorf("unable to decode updates#74ae4240: field updates: %w", err)
			}
			u.Updates = append(u.Updates, value)
		}
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode updates#74ae4240: field users: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeUser(b)
			if err != nil {
				return fmt.Errorf("unable to decode updates#74ae4240: field users: %w", err)
			}
			u.Users = append(u.Users, value)
		}
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode updates#74ae4240: field chats: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeChat(b)
			if err != nil {
				return fmt.Errorf("unable to decode updates#74ae4240: field chats: %w", err)
			}
			u.Chats = append(u.Chats, value)
		}
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updates#74ae4240: field date: %w", err)
		}
		u.Date = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updates#74ae4240: field seq: %w", err)
		}
		u.Seq = value
	}
	return nil
}

// construct implements constructor of UpdatesClass.
func (u Updates) construct() UpdatesClass { return &u }

// Ensuring interfaces in compile-time for Updates.
var (
	_ bin.Encoder = &Updates{}
	_ bin.Decoder = &Updates{}

	_ UpdatesClass = &Updates{}
)

// UpdateShortSentMessage represents TL type `updateShortSentMessage#11f1331c`.
type UpdateShortSentMessage struct {
	// Flags field of UpdateShortSentMessage.
	Flags bin.Fields
	// Out field of UpdateShortSentMessage.
	Out bool
	// ID field of UpdateShortSentMessage.
	ID int
	// Pts field of UpdateShortSentMessage.
	Pts int
	// PtsCount field of UpdateShortSentMessage.
	PtsCount int
	// Date field of UpdateShortSentMessage.
	Date int
	// Media field of UpdateShortSentMessage.
	//
	// Use SetMedia and GetMedia helpers.
	Media MessageMediaClass
	// Entities field of UpdateShortSentMessage.
	//
	// Use SetEntities and GetEntities helpers.
	Entities []MessageEntityClass
}

// UpdateShortSentMessageTypeID is TL type id of UpdateShortSentMessage.
const UpdateShortSentMessageTypeID = 0x11f1331c

// Encode implements bin.Encoder.
func (u *UpdateShortSentMessage) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode updateShortSentMessage#11f1331c as nil")
	}
	b.PutID(UpdateShortSentMessageTypeID)
	if err := u.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode updateShortSentMessage#11f1331c: field flags: %w", err)
	}
	b.PutInt(u.ID)
	b.PutInt(u.Pts)
	b.PutInt(u.PtsCount)
	b.PutInt(u.Date)
	if u.Flags.Has(9) {
		if u.Media == nil {
			return fmt.Errorf("unable to encode updateShortSentMessage#11f1331c: field media is nil")
		}
		if err := u.Media.Encode(b); err != nil {
			return fmt.Errorf("unable to encode updateShortSentMessage#11f1331c: field media: %w", err)
		}
	}
	if u.Flags.Has(7) {
		b.PutVectorHeader(len(u.Entities))
		for idx, v := range u.Entities {
			if v == nil {
				return fmt.Errorf("unable to encode updateShortSentMessage#11f1331c: field entities element with index %d is nil", idx)
			}
			if err := v.Encode(b); err != nil {
				return fmt.Errorf("unable to encode updateShortSentMessage#11f1331c: field entities element with index %d: %w", idx, err)
			}
		}
	}
	return nil
}

// SetOut sets value of Out conditional field.
func (u *UpdateShortSentMessage) SetOut(value bool) {
	if value {
		u.Flags.Set(1)
	} else {
		u.Flags.Unset(1)
	}
}

// SetMedia sets value of Media conditional field.
func (u *UpdateShortSentMessage) SetMedia(value MessageMediaClass) {
	u.Flags.Set(9)
	u.Media = value
}

// GetMedia returns value of Media conditional field and
// boolean which is true if field was set.
func (u *UpdateShortSentMessage) GetMedia() (value MessageMediaClass, ok bool) {
	if !u.Flags.Has(9) {
		return value, false
	}
	return u.Media, true
}

// SetEntities sets value of Entities conditional field.
func (u *UpdateShortSentMessage) SetEntities(value []MessageEntityClass) {
	u.Flags.Set(7)
	u.Entities = value
}

// GetEntities returns value of Entities conditional field and
// boolean which is true if field was set.
func (u *UpdateShortSentMessage) GetEntities() (value []MessageEntityClass, ok bool) {
	if !u.Flags.Has(7) {
		return value, false
	}
	return u.Entities, true
}

// Decode implements bin.Decoder.
func (u *UpdateShortSentMessage) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode updateShortSentMessage#11f1331c to nil")
	}
	if err := b.ConsumeID(UpdateShortSentMessageTypeID); err != nil {
		return fmt.Errorf("unable to decode updateShortSentMessage#11f1331c: %w", err)
	}
	{
		if err := u.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode updateShortSentMessage#11f1331c: field flags: %w", err)
		}
	}
	u.Out = u.Flags.Has(1)
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortSentMessage#11f1331c: field id: %w", err)
		}
		u.ID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortSentMessage#11f1331c: field pts: %w", err)
		}
		u.Pts = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortSentMessage#11f1331c: field pts_count: %w", err)
		}
		u.PtsCount = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortSentMessage#11f1331c: field date: %w", err)
		}
		u.Date = value
	}
	if u.Flags.Has(9) {
		value, err := DecodeMessageMedia(b)
		if err != nil {
			return fmt.Errorf("unable to decode updateShortSentMessage#11f1331c: field media: %w", err)
		}
		u.Media = value
	}
	if u.Flags.Has(7) {
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode updateShortSentMessage#11f1331c: field entities: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeMessageEntity(b)
			if err != nil {
				return fmt.Errorf("unable to decode updateShortSentMessage#11f1331c: field entities: %w", err)
			}
			u.Entities = append(u.Entities, value)
		}
	}
	return nil
}

// construct implements constructor of UpdatesClass.
func (u UpdateShortSentMessage) construct() UpdatesClass { return &u }

// Ensuring interfaces in compile-time for UpdateShortSentMessage.
var (
	_ bin.Encoder = &UpdateShortSentMessage{}
	_ bin.Decoder = &UpdateShortSentMessage{}

	_ UpdatesClass = &UpdateShortSentMessage{}
)

// UpdatesClass represents Updates generic type.
//
// Example:
//  g, err := DecodeUpdates(buf)
//  if err != nil {
//      panic(err)
//  }
//  switch v := g.(type) {
//  case *UpdatesTooLong: // updatesTooLong#e317af7e
//  case *UpdateShortMessage: // updateShortMessage#2296d2c8
//  case *UpdateShortChatMessage: // updateShortChatMessage#402d5dbb
//  case *UpdateShort: // updateShort#78d4dec1
//  case *UpdatesCombined: // updatesCombined#725b04c3
//  case *Updates: // updates#74ae4240
//  case *UpdateShortSentMessage: // updateShortSentMessage#11f1331c
//  default: panic(v)
//  }
type UpdatesClass interface {
	bin.Encoder
	bin.Decoder
	construct() UpdatesClass
}

// DecodeUpdates implements binary de-serialization for UpdatesClass.
func DecodeUpdates(buf *bin.Buffer) (UpdatesClass, error) {
	id, err := buf.PeekID()
	if err != nil {
		return nil, err
	}
	switch id {
	case UpdatesTooLongTypeID:
		// Decoding updatesTooLong#e317af7e.
		v := UpdatesTooLong{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UpdatesClass: %w", err)
		}
		return &v, nil
	case UpdateShortMessageTypeID:
		// Decoding updateShortMessage#2296d2c8.
		v := UpdateShortMessage{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UpdatesClass: %w", err)
		}
		return &v, nil
	case UpdateShortChatMessageTypeID:
		// Decoding updateShortChatMessage#402d5dbb.
		v := UpdateShortChatMessage{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UpdatesClass: %w", err)
		}
		return &v, nil
	case UpdateShortTypeID:
		// Decoding updateShort#78d4dec1.
		v := UpdateShort{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UpdatesClass: %w", err)
		}
		return &v, nil
	case UpdatesCombinedTypeID:
		// Decoding updatesCombined#725b04c3.
		v := UpdatesCombined{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UpdatesClass: %w", err)
		}
		return &v, nil
	case UpdatesTypeID:
		// Decoding updates#74ae4240.
		v := Updates{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UpdatesClass: %w", err)
		}
		return &v, nil
	case UpdateShortSentMessageTypeID:
		// Decoding updateShortSentMessage#11f1331c.
		v := UpdateShortSentMessage{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UpdatesClass: %w", err)
		}
		return &v, nil
	default:
		return nil, fmt.Errorf("unable to decode UpdatesClass: %w", bin.NewUnexpectedID(id))
	}
}