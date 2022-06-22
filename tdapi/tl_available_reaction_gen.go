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

// AvailableReaction represents TL type `availableReaction#6963e721`.
type AvailableReaction struct {
	// Text representation of the reaction
	Reaction string
	// True, if Telegram Premium is needed to send the reaction
	NeedsPremium bool
}

// AvailableReactionTypeID is TL type id of AvailableReaction.
const AvailableReactionTypeID = 0x6963e721

// Ensuring interfaces in compile-time for AvailableReaction.
var (
	_ bin.Encoder     = &AvailableReaction{}
	_ bin.Decoder     = &AvailableReaction{}
	_ bin.BareEncoder = &AvailableReaction{}
	_ bin.BareDecoder = &AvailableReaction{}
)

func (a *AvailableReaction) Zero() bool {
	if a == nil {
		return true
	}
	if !(a.Reaction == "") {
		return false
	}
	if !(a.NeedsPremium == false) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (a *AvailableReaction) String() string {
	if a == nil {
		return "AvailableReaction(nil)"
	}
	type Alias AvailableReaction
	return fmt.Sprintf("AvailableReaction%+v", Alias(*a))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*AvailableReaction) TypeID() uint32 {
	return AvailableReactionTypeID
}

// TypeName returns name of type in TL schema.
func (*AvailableReaction) TypeName() string {
	return "availableReaction"
}

// TypeInfo returns info about TL type.
func (a *AvailableReaction) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "availableReaction",
		ID:   AvailableReactionTypeID,
	}
	if a == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Reaction",
			SchemaName: "reaction",
		},
		{
			Name:       "NeedsPremium",
			SchemaName: "needs_premium",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (a *AvailableReaction) Encode(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't encode availableReaction#6963e721 as nil")
	}
	b.PutID(AvailableReactionTypeID)
	return a.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (a *AvailableReaction) EncodeBare(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't encode availableReaction#6963e721 as nil")
	}
	b.PutString(a.Reaction)
	b.PutBool(a.NeedsPremium)
	return nil
}

// Decode implements bin.Decoder.
func (a *AvailableReaction) Decode(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't decode availableReaction#6963e721 to nil")
	}
	if err := b.ConsumeID(AvailableReactionTypeID); err != nil {
		return fmt.Errorf("unable to decode availableReaction#6963e721: %w", err)
	}
	return a.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (a *AvailableReaction) DecodeBare(b *bin.Buffer) error {
	if a == nil {
		return fmt.Errorf("can't decode availableReaction#6963e721 to nil")
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode availableReaction#6963e721: field reaction: %w", err)
		}
		a.Reaction = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode availableReaction#6963e721: field needs_premium: %w", err)
		}
		a.NeedsPremium = value
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (a *AvailableReaction) EncodeTDLibJSON(b tdjson.Encoder) error {
	if a == nil {
		return fmt.Errorf("can't encode availableReaction#6963e721 as nil")
	}
	b.ObjStart()
	b.PutID("availableReaction")
	b.Comma()
	b.FieldStart("reaction")
	b.PutString(a.Reaction)
	b.Comma()
	b.FieldStart("needs_premium")
	b.PutBool(a.NeedsPremium)
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (a *AvailableReaction) DecodeTDLibJSON(b tdjson.Decoder) error {
	if a == nil {
		return fmt.Errorf("can't decode availableReaction#6963e721 to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("availableReaction"); err != nil {
				return fmt.Errorf("unable to decode availableReaction#6963e721: %w", err)
			}
		case "reaction":
			value, err := b.String()
			if err != nil {
				return fmt.Errorf("unable to decode availableReaction#6963e721: field reaction: %w", err)
			}
			a.Reaction = value
		case "needs_premium":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode availableReaction#6963e721: field needs_premium: %w", err)
			}
			a.NeedsPremium = value
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetReaction returns value of Reaction field.
func (a *AvailableReaction) GetReaction() (value string) {
	if a == nil {
		return
	}
	return a.Reaction
}

// GetNeedsPremium returns value of NeedsPremium field.
func (a *AvailableReaction) GetNeedsPremium() (value bool) {
	if a == nil {
		return
	}
	return a.NeedsPremium
}
