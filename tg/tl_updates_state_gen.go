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

// UpdatesState represents TL type `updates.state#a56c2a3e`.
// Updates state.
//
// See https://core.telegram.org/constructor/updates.state for reference.
type UpdatesState struct {
	// Number of events occured in a text box
	Pts int `tl:"pts"`
	// Position in a sequence of updates in secret chats. For further detailes refer to article secret chats¹Parameter was added in eigth layer².
	//
	// Links:
	//  1) https://core.telegram.org/api/end-to-end
	//  2) https://core.telegram.org/api/layers#layer-8
	Qts int `tl:"qts"`
	// Date of condition
	Date int `tl:"date"`
	// Number of sent updates
	Seq int `tl:"seq"`
	// Number of unread messages
	UnreadCount int `tl:"unread_count"`
}

// UpdatesStateTypeID is TL type id of UpdatesState.
const UpdatesStateTypeID = 0xa56c2a3e

func (s *UpdatesState) Zero() bool {
	if s == nil {
		return true
	}
	if !(s.Pts == 0) {
		return false
	}
	if !(s.Qts == 0) {
		return false
	}
	if !(s.Date == 0) {
		return false
	}
	if !(s.Seq == 0) {
		return false
	}
	if !(s.UnreadCount == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (s *UpdatesState) String() string {
	if s == nil {
		return "UpdatesState(nil)"
	}
	type Alias UpdatesState
	return fmt.Sprintf("UpdatesState%+v", Alias(*s))
}

// FillFrom fills UpdatesState from given interface.
func (s *UpdatesState) FillFrom(from interface {
	GetPts() (value int)
	GetQts() (value int)
	GetDate() (value int)
	GetSeq() (value int)
	GetUnreadCount() (value int)
}) {
	s.Pts = from.GetPts()
	s.Qts = from.GetQts()
	s.Date = from.GetDate()
	s.Seq = from.GetSeq()
	s.UnreadCount = from.GetUnreadCount()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (s *UpdatesState) TypeID() uint32 {
	return UpdatesStateTypeID
}

// TypeName returns name of type in TL schema.
func (s *UpdatesState) TypeName() string {
	return "updates.state"
}

// Encode implements bin.Encoder.
func (s *UpdatesState) Encode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode updates.state#a56c2a3e as nil")
	}
	b.PutID(UpdatesStateTypeID)
	b.PutInt(s.Pts)
	b.PutInt(s.Qts)
	b.PutInt(s.Date)
	b.PutInt(s.Seq)
	b.PutInt(s.UnreadCount)
	return nil
}

// GetPts returns value of Pts field.
func (s *UpdatesState) GetPts() (value int) {
	return s.Pts
}

// GetQts returns value of Qts field.
func (s *UpdatesState) GetQts() (value int) {
	return s.Qts
}

// GetDate returns value of Date field.
func (s *UpdatesState) GetDate() (value int) {
	return s.Date
}

// GetSeq returns value of Seq field.
func (s *UpdatesState) GetSeq() (value int) {
	return s.Seq
}

// GetUnreadCount returns value of UnreadCount field.
func (s *UpdatesState) GetUnreadCount() (value int) {
	return s.UnreadCount
}

// Decode implements bin.Decoder.
func (s *UpdatesState) Decode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode updates.state#a56c2a3e to nil")
	}
	if err := b.ConsumeID(UpdatesStateTypeID); err != nil {
		return fmt.Errorf("unable to decode updates.state#a56c2a3e: %w", err)
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updates.state#a56c2a3e: field pts: %w", err)
		}
		s.Pts = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updates.state#a56c2a3e: field qts: %w", err)
		}
		s.Qts = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updates.state#a56c2a3e: field date: %w", err)
		}
		s.Date = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updates.state#a56c2a3e: field seq: %w", err)
		}
		s.Seq = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode updates.state#a56c2a3e: field unread_count: %w", err)
		}
		s.UnreadCount = value
	}
	return nil
}

// Ensuring interfaces in compile-time for UpdatesState.
var (
	_ bin.Encoder = &UpdatesState{}
	_ bin.Decoder = &UpdatesState{}
)
