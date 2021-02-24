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

// PhoneGroupCall represents TL type `phone.groupCall#66ab0bfc`.
//
// See https://core.telegram.org/constructor/phone.groupCall for reference.
type PhoneGroupCall struct {
	// Call field of PhoneGroupCall.
	Call GroupCallClass `tl:"call"`
	// Participants field of PhoneGroupCall.
	Participants []GroupCallParticipant `tl:"participants"`
	// ParticipantsNextOffset field of PhoneGroupCall.
	ParticipantsNextOffset string `tl:"participants_next_offset"`
	// Users field of PhoneGroupCall.
	Users []UserClass `tl:"users"`
}

// PhoneGroupCallTypeID is TL type id of PhoneGroupCall.
const PhoneGroupCallTypeID = 0x66ab0bfc

func (g *PhoneGroupCall) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Call == nil) {
		return false
	}
	if !(g.Participants == nil) {
		return false
	}
	if !(g.ParticipantsNextOffset == "") {
		return false
	}
	if !(g.Users == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *PhoneGroupCall) String() string {
	if g == nil {
		return "PhoneGroupCall(nil)"
	}
	type Alias PhoneGroupCall
	return fmt.Sprintf("PhoneGroupCall%+v", Alias(*g))
}

// FillFrom fills PhoneGroupCall from given interface.
func (g *PhoneGroupCall) FillFrom(from interface {
	GetCall() (value GroupCallClass)
	GetParticipants() (value []GroupCallParticipant)
	GetParticipantsNextOffset() (value string)
	GetUsers() (value []UserClass)
}) {
	g.Call = from.GetCall()
	g.Participants = from.GetParticipants()
	g.ParticipantsNextOffset = from.GetParticipantsNextOffset()
	g.Users = from.GetUsers()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (g *PhoneGroupCall) TypeID() uint32 {
	return PhoneGroupCallTypeID
}

// TypeName returns name of type in TL schema.
func (g *PhoneGroupCall) TypeName() string {
	return "phone.groupCall"
}

// Encode implements bin.Encoder.
func (g *PhoneGroupCall) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode phone.groupCall#66ab0bfc as nil")
	}
	b.PutID(PhoneGroupCallTypeID)
	if g.Call == nil {
		return fmt.Errorf("unable to encode phone.groupCall#66ab0bfc: field call is nil")
	}
	if err := g.Call.Encode(b); err != nil {
		return fmt.Errorf("unable to encode phone.groupCall#66ab0bfc: field call: %w", err)
	}
	b.PutVectorHeader(len(g.Participants))
	for idx, v := range g.Participants {
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode phone.groupCall#66ab0bfc: field participants element with index %d: %w", idx, err)
		}
	}
	b.PutString(g.ParticipantsNextOffset)
	b.PutVectorHeader(len(g.Users))
	for idx, v := range g.Users {
		if v == nil {
			return fmt.Errorf("unable to encode phone.groupCall#66ab0bfc: field users element with index %d is nil", idx)
		}
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode phone.groupCall#66ab0bfc: field users element with index %d: %w", idx, err)
		}
	}
	return nil
}

// GetCall returns value of Call field.
func (g *PhoneGroupCall) GetCall() (value GroupCallClass) {
	return g.Call
}

// GetParticipants returns value of Participants field.
func (g *PhoneGroupCall) GetParticipants() (value []GroupCallParticipant) {
	return g.Participants
}

// GetParticipantsNextOffset returns value of ParticipantsNextOffset field.
func (g *PhoneGroupCall) GetParticipantsNextOffset() (value string) {
	return g.ParticipantsNextOffset
}

// GetUsers returns value of Users field.
func (g *PhoneGroupCall) GetUsers() (value []UserClass) {
	return g.Users
}

// MapUsers returns field Users wrapped in UserClassSlice helper.
func (g *PhoneGroupCall) MapUsers() (value UserClassSlice) {
	return UserClassSlice(g.Users)
}

// Decode implements bin.Decoder.
func (g *PhoneGroupCall) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode phone.groupCall#66ab0bfc to nil")
	}
	if err := b.ConsumeID(PhoneGroupCallTypeID); err != nil {
		return fmt.Errorf("unable to decode phone.groupCall#66ab0bfc: %w", err)
	}
	{
		value, err := DecodeGroupCall(b)
		if err != nil {
			return fmt.Errorf("unable to decode phone.groupCall#66ab0bfc: field call: %w", err)
		}
		g.Call = value
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode phone.groupCall#66ab0bfc: field participants: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			var value GroupCallParticipant
			if err := value.Decode(b); err != nil {
				return fmt.Errorf("unable to decode phone.groupCall#66ab0bfc: field participants: %w", err)
			}
			g.Participants = append(g.Participants, value)
		}
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode phone.groupCall#66ab0bfc: field participants_next_offset: %w", err)
		}
		g.ParticipantsNextOffset = value
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode phone.groupCall#66ab0bfc: field users: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeUser(b)
			if err != nil {
				return fmt.Errorf("unable to decode phone.groupCall#66ab0bfc: field users: %w", err)
			}
			g.Users = append(g.Users, value)
		}
	}
	return nil
}

// Ensuring interfaces in compile-time for PhoneGroupCall.
var (
	_ bin.Encoder = &PhoneGroupCall{}
	_ bin.Decoder = &PhoneGroupCall{}
)
