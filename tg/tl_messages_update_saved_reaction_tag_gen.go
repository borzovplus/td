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

// MessagesUpdateSavedReactionTagRequest represents TL type `messages.updateSavedReactionTag#60297dec`.
//
// See https://core.telegram.org/method/messages.updateSavedReactionTag for reference.
type MessagesUpdateSavedReactionTagRequest struct {
	// Flags field of MessagesUpdateSavedReactionTagRequest.
	Flags bin.Fields
	// Reaction field of MessagesUpdateSavedReactionTagRequest.
	Reaction ReactionClass
	// Title field of MessagesUpdateSavedReactionTagRequest.
	//
	// Use SetTitle and GetTitle helpers.
	Title string
}

// MessagesUpdateSavedReactionTagRequestTypeID is TL type id of MessagesUpdateSavedReactionTagRequest.
const MessagesUpdateSavedReactionTagRequestTypeID = 0x60297dec

// Ensuring interfaces in compile-time for MessagesUpdateSavedReactionTagRequest.
var (
	_ bin.Encoder     = &MessagesUpdateSavedReactionTagRequest{}
	_ bin.Decoder     = &MessagesUpdateSavedReactionTagRequest{}
	_ bin.BareEncoder = &MessagesUpdateSavedReactionTagRequest{}
	_ bin.BareDecoder = &MessagesUpdateSavedReactionTagRequest{}
)

func (u *MessagesUpdateSavedReactionTagRequest) Zero() bool {
	if u == nil {
		return true
	}
	if !(u.Flags.Zero()) {
		return false
	}
	if !(u.Reaction == nil) {
		return false
	}
	if !(u.Title == "") {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (u *MessagesUpdateSavedReactionTagRequest) String() string {
	if u == nil {
		return "MessagesUpdateSavedReactionTagRequest(nil)"
	}
	type Alias MessagesUpdateSavedReactionTagRequest
	return fmt.Sprintf("MessagesUpdateSavedReactionTagRequest%+v", Alias(*u))
}

// FillFrom fills MessagesUpdateSavedReactionTagRequest from given interface.
func (u *MessagesUpdateSavedReactionTagRequest) FillFrom(from interface {
	GetReaction() (value ReactionClass)
	GetTitle() (value string, ok bool)
}) {
	u.Reaction = from.GetReaction()
	if val, ok := from.GetTitle(); ok {
		u.Title = val
	}

}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*MessagesUpdateSavedReactionTagRequest) TypeID() uint32 {
	return MessagesUpdateSavedReactionTagRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*MessagesUpdateSavedReactionTagRequest) TypeName() string {
	return "messages.updateSavedReactionTag"
}

// TypeInfo returns info about TL type.
func (u *MessagesUpdateSavedReactionTagRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "messages.updateSavedReactionTag",
		ID:   MessagesUpdateSavedReactionTagRequestTypeID,
	}
	if u == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Reaction",
			SchemaName: "reaction",
		},
		{
			Name:       "Title",
			SchemaName: "title",
			Null:       !u.Flags.Has(0),
		},
	}
	return typ
}

// SetFlags sets flags for non-zero fields.
func (u *MessagesUpdateSavedReactionTagRequest) SetFlags() {
	if !(u.Title == "") {
		u.Flags.Set(0)
	}
}

// Encode implements bin.Encoder.
func (u *MessagesUpdateSavedReactionTagRequest) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode messages.updateSavedReactionTag#60297dec as nil")
	}
	b.PutID(MessagesUpdateSavedReactionTagRequestTypeID)
	return u.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (u *MessagesUpdateSavedReactionTagRequest) EncodeBare(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode messages.updateSavedReactionTag#60297dec as nil")
	}
	u.SetFlags()
	if err := u.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.updateSavedReactionTag#60297dec: field flags: %w", err)
	}
	if u.Reaction == nil {
		return fmt.Errorf("unable to encode messages.updateSavedReactionTag#60297dec: field reaction is nil")
	}
	if err := u.Reaction.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.updateSavedReactionTag#60297dec: field reaction: %w", err)
	}
	if u.Flags.Has(0) {
		b.PutString(u.Title)
	}
	return nil
}

// Decode implements bin.Decoder.
func (u *MessagesUpdateSavedReactionTagRequest) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode messages.updateSavedReactionTag#60297dec to nil")
	}
	if err := b.ConsumeID(MessagesUpdateSavedReactionTagRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.updateSavedReactionTag#60297dec: %w", err)
	}
	return u.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (u *MessagesUpdateSavedReactionTagRequest) DecodeBare(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode messages.updateSavedReactionTag#60297dec to nil")
	}
	{
		if err := u.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode messages.updateSavedReactionTag#60297dec: field flags: %w", err)
		}
	}
	{
		value, err := DecodeReaction(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.updateSavedReactionTag#60297dec: field reaction: %w", err)
		}
		u.Reaction = value
	}
	if u.Flags.Has(0) {
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode messages.updateSavedReactionTag#60297dec: field title: %w", err)
		}
		u.Title = value
	}
	return nil
}

// GetReaction returns value of Reaction field.
func (u *MessagesUpdateSavedReactionTagRequest) GetReaction() (value ReactionClass) {
	if u == nil {
		return
	}
	return u.Reaction
}

// SetTitle sets value of Title conditional field.
func (u *MessagesUpdateSavedReactionTagRequest) SetTitle(value string) {
	u.Flags.Set(0)
	u.Title = value
}

// GetTitle returns value of Title conditional field and
// boolean which is true if field was set.
func (u *MessagesUpdateSavedReactionTagRequest) GetTitle() (value string, ok bool) {
	if u == nil {
		return
	}
	if !u.Flags.Has(0) {
		return value, false
	}
	return u.Title, true
}

// MessagesUpdateSavedReactionTag invokes method messages.updateSavedReactionTag#60297dec returning error if any.
//
// See https://core.telegram.org/method/messages.updateSavedReactionTag for reference.
func (c *Client) MessagesUpdateSavedReactionTag(ctx context.Context, request *MessagesUpdateSavedReactionTagRequest) (bool, error) {
	var result BoolBox

	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return false, err
	}
	_, ok := result.Bool.(*BoolTrue)
	return ok, nil
}
