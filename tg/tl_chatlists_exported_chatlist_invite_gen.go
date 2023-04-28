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

// ChatlistsExportedChatlistInvite represents TL type `chatlists.exportedChatlistInvite#10e6e3a6`.
// Info about an exported chat folder deep link »¹.
//
// Links:
//  1. https://core.telegram.org/api/links#chat-folder-links
//
// See https://core.telegram.org/constructor/chatlists.exportedChatlistInvite for reference.
type ChatlistsExportedChatlistInvite struct {
	// Folder ID
	Filter DialogFilterClass
	// The exported chat folder deep link »¹.
	//
	// Links:
	//  1) https://core.telegram.org/api/links#chat-folder-links
	Invite ExportedChatlistInvite
}

// ChatlistsExportedChatlistInviteTypeID is TL type id of ChatlistsExportedChatlistInvite.
const ChatlistsExportedChatlistInviteTypeID = 0x10e6e3a6

// Ensuring interfaces in compile-time for ChatlistsExportedChatlistInvite.
var (
	_ bin.Encoder     = &ChatlistsExportedChatlistInvite{}
	_ bin.Decoder     = &ChatlistsExportedChatlistInvite{}
	_ bin.BareEncoder = &ChatlistsExportedChatlistInvite{}
	_ bin.BareDecoder = &ChatlistsExportedChatlistInvite{}
)

func (e *ChatlistsExportedChatlistInvite) Zero() bool {
	if e == nil {
		return true
	}
	if !(e.Filter == nil) {
		return false
	}
	if !(e.Invite.Zero()) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (e *ChatlistsExportedChatlistInvite) String() string {
	if e == nil {
		return "ChatlistsExportedChatlistInvite(nil)"
	}
	type Alias ChatlistsExportedChatlistInvite
	return fmt.Sprintf("ChatlistsExportedChatlistInvite%+v", Alias(*e))
}

// FillFrom fills ChatlistsExportedChatlistInvite from given interface.
func (e *ChatlistsExportedChatlistInvite) FillFrom(from interface {
	GetFilter() (value DialogFilterClass)
	GetInvite() (value ExportedChatlistInvite)
}) {
	e.Filter = from.GetFilter()
	e.Invite = from.GetInvite()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*ChatlistsExportedChatlistInvite) TypeID() uint32 {
	return ChatlistsExportedChatlistInviteTypeID
}

// TypeName returns name of type in TL schema.
func (*ChatlistsExportedChatlistInvite) TypeName() string {
	return "chatlists.exportedChatlistInvite"
}

// TypeInfo returns info about TL type.
func (e *ChatlistsExportedChatlistInvite) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "chatlists.exportedChatlistInvite",
		ID:   ChatlistsExportedChatlistInviteTypeID,
	}
	if e == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Filter",
			SchemaName: "filter",
		},
		{
			Name:       "Invite",
			SchemaName: "invite",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (e *ChatlistsExportedChatlistInvite) Encode(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't encode chatlists.exportedChatlistInvite#10e6e3a6 as nil")
	}
	b.PutID(ChatlistsExportedChatlistInviteTypeID)
	return e.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (e *ChatlistsExportedChatlistInvite) EncodeBare(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't encode chatlists.exportedChatlistInvite#10e6e3a6 as nil")
	}
	if e.Filter == nil {
		return fmt.Errorf("unable to encode chatlists.exportedChatlistInvite#10e6e3a6: field filter is nil")
	}
	if err := e.Filter.Encode(b); err != nil {
		return fmt.Errorf("unable to encode chatlists.exportedChatlistInvite#10e6e3a6: field filter: %w", err)
	}
	if err := e.Invite.Encode(b); err != nil {
		return fmt.Errorf("unable to encode chatlists.exportedChatlistInvite#10e6e3a6: field invite: %w", err)
	}
	return nil
}

// Decode implements bin.Decoder.
func (e *ChatlistsExportedChatlistInvite) Decode(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't decode chatlists.exportedChatlistInvite#10e6e3a6 to nil")
	}
	if err := b.ConsumeID(ChatlistsExportedChatlistInviteTypeID); err != nil {
		return fmt.Errorf("unable to decode chatlists.exportedChatlistInvite#10e6e3a6: %w", err)
	}
	return e.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (e *ChatlistsExportedChatlistInvite) DecodeBare(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't decode chatlists.exportedChatlistInvite#10e6e3a6 to nil")
	}
	{
		value, err := DecodeDialogFilter(b)
		if err != nil {
			return fmt.Errorf("unable to decode chatlists.exportedChatlistInvite#10e6e3a6: field filter: %w", err)
		}
		e.Filter = value
	}
	{
		if err := e.Invite.Decode(b); err != nil {
			return fmt.Errorf("unable to decode chatlists.exportedChatlistInvite#10e6e3a6: field invite: %w", err)
		}
	}
	return nil
}

// GetFilter returns value of Filter field.
func (e *ChatlistsExportedChatlistInvite) GetFilter() (value DialogFilterClass) {
	if e == nil {
		return
	}
	return e.Filter
}

// GetInvite returns value of Invite field.
func (e *ChatlistsExportedChatlistInvite) GetInvite() (value ExportedChatlistInvite) {
	if e == nil {
		return
	}
	return e.Invite
}