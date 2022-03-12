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

// SetGroupCallParticipantIsSpeakingRequest represents TL type `setGroupCallParticipantIsSpeaking#3748a1e5`.
type SetGroupCallParticipantIsSpeakingRequest struct {
	// Group call identifier
	GroupCallID int32
	// Group call participant's synchronization audio source identifier, or 0 for the current
	// user
	AudioSource int32
	// Pass true if the user is speaking
	IsSpeaking bool
}

// SetGroupCallParticipantIsSpeakingRequestTypeID is TL type id of SetGroupCallParticipantIsSpeakingRequest.
const SetGroupCallParticipantIsSpeakingRequestTypeID = 0x3748a1e5

// Ensuring interfaces in compile-time for SetGroupCallParticipantIsSpeakingRequest.
var (
	_ bin.Encoder     = &SetGroupCallParticipantIsSpeakingRequest{}
	_ bin.Decoder     = &SetGroupCallParticipantIsSpeakingRequest{}
	_ bin.BareEncoder = &SetGroupCallParticipantIsSpeakingRequest{}
	_ bin.BareDecoder = &SetGroupCallParticipantIsSpeakingRequest{}
)

func (s *SetGroupCallParticipantIsSpeakingRequest) Zero() bool {
	if s == nil {
		return true
	}
	if !(s.GroupCallID == 0) {
		return false
	}
	if !(s.AudioSource == 0) {
		return false
	}
	if !(s.IsSpeaking == false) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (s *SetGroupCallParticipantIsSpeakingRequest) String() string {
	if s == nil {
		return "SetGroupCallParticipantIsSpeakingRequest(nil)"
	}
	type Alias SetGroupCallParticipantIsSpeakingRequest
	return fmt.Sprintf("SetGroupCallParticipantIsSpeakingRequest%+v", Alias(*s))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*SetGroupCallParticipantIsSpeakingRequest) TypeID() uint32 {
	return SetGroupCallParticipantIsSpeakingRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*SetGroupCallParticipantIsSpeakingRequest) TypeName() string {
	return "setGroupCallParticipantIsSpeaking"
}

// TypeInfo returns info about TL type.
func (s *SetGroupCallParticipantIsSpeakingRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "setGroupCallParticipantIsSpeaking",
		ID:   SetGroupCallParticipantIsSpeakingRequestTypeID,
	}
	if s == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "GroupCallID",
			SchemaName: "group_call_id",
		},
		{
			Name:       "AudioSource",
			SchemaName: "audio_source",
		},
		{
			Name:       "IsSpeaking",
			SchemaName: "is_speaking",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (s *SetGroupCallParticipantIsSpeakingRequest) Encode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode setGroupCallParticipantIsSpeaking#3748a1e5 as nil")
	}
	b.PutID(SetGroupCallParticipantIsSpeakingRequestTypeID)
	return s.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (s *SetGroupCallParticipantIsSpeakingRequest) EncodeBare(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode setGroupCallParticipantIsSpeaking#3748a1e5 as nil")
	}
	b.PutInt32(s.GroupCallID)
	b.PutInt32(s.AudioSource)
	b.PutBool(s.IsSpeaking)
	return nil
}

// Decode implements bin.Decoder.
func (s *SetGroupCallParticipantIsSpeakingRequest) Decode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode setGroupCallParticipantIsSpeaking#3748a1e5 to nil")
	}
	if err := b.ConsumeID(SetGroupCallParticipantIsSpeakingRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode setGroupCallParticipantIsSpeaking#3748a1e5: %w", err)
	}
	return s.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (s *SetGroupCallParticipantIsSpeakingRequest) DecodeBare(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode setGroupCallParticipantIsSpeaking#3748a1e5 to nil")
	}
	{
		value, err := b.Int32()
		if err != nil {
			return fmt.Errorf("unable to decode setGroupCallParticipantIsSpeaking#3748a1e5: field group_call_id: %w", err)
		}
		s.GroupCallID = value
	}
	{
		value, err := b.Int32()
		if err != nil {
			return fmt.Errorf("unable to decode setGroupCallParticipantIsSpeaking#3748a1e5: field audio_source: %w", err)
		}
		s.AudioSource = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode setGroupCallParticipantIsSpeaking#3748a1e5: field is_speaking: %w", err)
		}
		s.IsSpeaking = value
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (s *SetGroupCallParticipantIsSpeakingRequest) EncodeTDLibJSON(b tdjson.Encoder) error {
	if s == nil {
		return fmt.Errorf("can't encode setGroupCallParticipantIsSpeaking#3748a1e5 as nil")
	}
	b.ObjStart()
	b.PutID("setGroupCallParticipantIsSpeaking")
	b.Comma()
	b.FieldStart("group_call_id")
	b.PutInt32(s.GroupCallID)
	b.Comma()
	b.FieldStart("audio_source")
	b.PutInt32(s.AudioSource)
	b.Comma()
	b.FieldStart("is_speaking")
	b.PutBool(s.IsSpeaking)
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (s *SetGroupCallParticipantIsSpeakingRequest) DecodeTDLibJSON(b tdjson.Decoder) error {
	if s == nil {
		return fmt.Errorf("can't decode setGroupCallParticipantIsSpeaking#3748a1e5 to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("setGroupCallParticipantIsSpeaking"); err != nil {
				return fmt.Errorf("unable to decode setGroupCallParticipantIsSpeaking#3748a1e5: %w", err)
			}
		case "group_call_id":
			value, err := b.Int32()
			if err != nil {
				return fmt.Errorf("unable to decode setGroupCallParticipantIsSpeaking#3748a1e5: field group_call_id: %w", err)
			}
			s.GroupCallID = value
		case "audio_source":
			value, err := b.Int32()
			if err != nil {
				return fmt.Errorf("unable to decode setGroupCallParticipantIsSpeaking#3748a1e5: field audio_source: %w", err)
			}
			s.AudioSource = value
		case "is_speaking":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode setGroupCallParticipantIsSpeaking#3748a1e5: field is_speaking: %w", err)
			}
			s.IsSpeaking = value
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetGroupCallID returns value of GroupCallID field.
func (s *SetGroupCallParticipantIsSpeakingRequest) GetGroupCallID() (value int32) {
	if s == nil {
		return
	}
	return s.GroupCallID
}

// GetAudioSource returns value of AudioSource field.
func (s *SetGroupCallParticipantIsSpeakingRequest) GetAudioSource() (value int32) {
	if s == nil {
		return
	}
	return s.AudioSource
}

// GetIsSpeaking returns value of IsSpeaking field.
func (s *SetGroupCallParticipantIsSpeakingRequest) GetIsSpeaking() (value bool) {
	if s == nil {
		return
	}
	return s.IsSpeaking
}

// SetGroupCallParticipantIsSpeaking invokes method setGroupCallParticipantIsSpeaking#3748a1e5 returning error if any.
func (c *Client) SetGroupCallParticipantIsSpeaking(ctx context.Context, request *SetGroupCallParticipantIsSpeakingRequest) error {
	var ok Ok

	if err := c.rpc.Invoke(ctx, request, &ok); err != nil {
		return err
	}
	return nil
}
