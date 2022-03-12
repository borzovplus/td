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

// AnimatedEmoji represents TL type `animatedEmoji#93b7fec9`.
type AnimatedEmoji struct {
	// Animated sticker for the emoji
	Sticker Sticker
	// Emoji modifier fitzpatrick type; 0-6; 0 if none
	FitzpatrickType int32
	// File containing the sound to be played when the animated emoji is clicked; may be null
	// The sound is encoded with the Opus codec, and stored inside an OGG container
	Sound File
}

// AnimatedEmojiTypeID is TL type id of AnimatedEmoji.
const AnimatedEmojiTypeID = 0x93b7fec9

// Ensuring interfaces in compile-time for AnimatedEmoji.
var (
	_ bin.Encoder     = &AnimatedEmoji{}
	_ bin.Decoder     = &AnimatedEmoji{}
	_ bin.BareEncoder = &AnimatedEmoji{}
	_ bin.BareDecoder = &AnimatedEmoji{}
)

func (a *AnimatedEmoji) Zero() bool {
	if a == nil {
		return true
	}
	if !(a.Sticker.Zero()) {
		return false
	}
	if !(a.FitzpatrickType == 0) {
		return false
	}
	if !(a.Sound.Zero()) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (a *AnimatedEmoji) String() string {
	if a == nil {
		return "AnimatedEmoji(nil)"
	}
	type Alias AnimatedEmoji
	return fmt.Sprintf("AnimatedEmoji%+v", Alias(*a))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*AnimatedEmoji) TypeID() uint32 {
	return AnimatedEmojiTypeID
}

// TypeName returns name of type in TL schema.
func (*AnimatedEmoji) TypeName() string {
	return "animatedEmoji"
}

// TypeInfo returns info about TL type.
func (a *AnimatedEmoji) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "animatedEmoji",
		ID:   AnimatedEmojiTypeID,
	}
	if a == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Sticker",
			SchemaName: "sticker",
		},
		{
			Name:       "FitzpatrickType",
			SchemaName: "fitzpatrick_type",
		},
		{
			Name:       "Sound",
			SchemaName: "sound",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (a *AnimatedEmoji) Encode(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't encode animatedEmoji#93b7fec9 as nil")
	}
	b.PutID(AnimatedEmojiTypeID)
	return a.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (a *AnimatedEmoji) EncodeBare(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't encode animatedEmoji#93b7fec9 as nil")
	}
	if err := a.Sticker.Encode(b); err != nil {
		return fmt.Errorf("unable to encode animatedEmoji#93b7fec9: field sticker: %w", err)
	}
	b.PutInt32(a.FitzpatrickType)
	if err := a.Sound.Encode(b); err != nil {
		return fmt.Errorf("unable to encode animatedEmoji#93b7fec9: field sound: %w", err)
	}
	return nil
}

// Decode implements bin.Decoder.
func (a *AnimatedEmoji) Decode(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't decode animatedEmoji#93b7fec9 to nil")
	}
	if err := b.ConsumeID(AnimatedEmojiTypeID); err != nil {
		return fmt.Errorf("unable to decode animatedEmoji#93b7fec9: %w", err)
	}
	return a.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (a *AnimatedEmoji) DecodeBare(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't decode animatedEmoji#93b7fec9 to nil")
	}
	{
		if err := a.Sticker.Decode(b); err != nil {
			return fmt.Errorf("unable to decode animatedEmoji#93b7fec9: field sticker: %w", err)
		}
	}
	{
		value, err := b.Int32()
		if err != nil {
			return fmt.Errorf("unable to decode animatedEmoji#93b7fec9: field fitzpatrick_type: %w", err)
		}
		a.FitzpatrickType = value
	}
	{
		if err := a.Sound.Decode(b); err != nil {
			return fmt.Errorf("unable to decode animatedEmoji#93b7fec9: field sound: %w", err)
		}
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (a *AnimatedEmoji) EncodeTDLibJSON(b tdjson.Encoder) error {
	if a == nil {
		return fmt.Errorf("can't encode animatedEmoji#93b7fec9 as nil")
	}
	b.ObjStart()
	b.PutID("animatedEmoji")
	b.Comma()
	b.FieldStart("sticker")
	if err := a.Sticker.EncodeTDLibJSON(b); err != nil {
		return fmt.Errorf("unable to encode animatedEmoji#93b7fec9: field sticker: %w", err)
	}
	b.Comma()
	b.FieldStart("fitzpatrick_type")
	b.PutInt32(a.FitzpatrickType)
	b.Comma()
	b.FieldStart("sound")
	if err := a.Sound.EncodeTDLibJSON(b); err != nil {
		return fmt.Errorf("unable to encode animatedEmoji#93b7fec9: field sound: %w", err)
	}
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (a *AnimatedEmoji) DecodeTDLibJSON(b tdjson.Decoder) error {
	if a == nil {
		return fmt.Errorf("can't decode animatedEmoji#93b7fec9 to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("animatedEmoji"); err != nil {
				return fmt.Errorf("unable to decode animatedEmoji#93b7fec9: %w", err)
			}
		case "sticker":
			if err := a.Sticker.DecodeTDLibJSON(b); err != nil {
				return fmt.Errorf("unable to decode animatedEmoji#93b7fec9: field sticker: %w", err)
			}
		case "fitzpatrick_type":
			value, err := b.Int32()
			if err != nil {
				return fmt.Errorf("unable to decode animatedEmoji#93b7fec9: field fitzpatrick_type: %w", err)
			}
			a.FitzpatrickType = value
		case "sound":
			if err := a.Sound.DecodeTDLibJSON(b); err != nil {
				return fmt.Errorf("unable to decode animatedEmoji#93b7fec9: field sound: %w", err)
			}
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetSticker returns value of Sticker field.
func (a *AnimatedEmoji) GetSticker() (value Sticker) {
	if a == nil {
		return
	}
	return a.Sticker
}

// GetFitzpatrickType returns value of FitzpatrickType field.
func (a *AnimatedEmoji) GetFitzpatrickType() (value int32) {
	if a == nil {
		return
	}
	return a.FitzpatrickType
}

// GetSound returns value of Sound field.
func (a *AnimatedEmoji) GetSound() (value File) {
	if a == nil {
		return
	}
	return a.Sound
}
