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

// GetChatHistoryRequest represents TL type `getChatHistory#d051927d`.
type GetChatHistoryRequest struct {
	// Chat identifier
	ChatID int64
	// Identifier of the message starting from which history must be fetched; use 0 to get
	// results from the last message
	FromMessageID int64
	// Specify 0 to get results from exactly the from_message_id or a negative offset up to
	// 99 to get additionally some newer messages
	Offset int32
	// The maximum number of messages to be returned; must be positive and can't be greater
	// than 100. If the offset is negative, the limit must be greater than or equal to
	// -offset. For optimal performance, the number of returned messages is chosen by TDLib
	// and can be smaller than the specified limit
	Limit int32
	// Pass true to get only messages that are available without sending network requests
	OnlyLocal bool
}

// GetChatHistoryRequestTypeID is TL type id of GetChatHistoryRequest.
const GetChatHistoryRequestTypeID = 0xd051927d

// Ensuring interfaces in compile-time for GetChatHistoryRequest.
var (
	_ bin.Encoder     = &GetChatHistoryRequest{}
	_ bin.Decoder     = &GetChatHistoryRequest{}
	_ bin.BareEncoder = &GetChatHistoryRequest{}
	_ bin.BareDecoder = &GetChatHistoryRequest{}
)

func (g *GetChatHistoryRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.ChatID == 0) {
		return false
	}
	if !(g.FromMessageID == 0) {
		return false
	}
	if !(g.Offset == 0) {
		return false
	}
	if !(g.Limit == 0) {
		return false
	}
	if !(g.OnlyLocal == false) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *GetChatHistoryRequest) String() string {
	if g == nil {
		return "GetChatHistoryRequest(nil)"
	}
	type Alias GetChatHistoryRequest
	return fmt.Sprintf("GetChatHistoryRequest%+v", Alias(*g))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*GetChatHistoryRequest) TypeID() uint32 {
	return GetChatHistoryRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*GetChatHistoryRequest) TypeName() string {
	return "getChatHistory"
}

// TypeInfo returns info about TL type.
func (g *GetChatHistoryRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "getChatHistory",
		ID:   GetChatHistoryRequestTypeID,
	}
	if g == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "ChatID",
			SchemaName: "chat_id",
		},
		{
			Name:       "FromMessageID",
			SchemaName: "from_message_id",
		},
		{
			Name:       "Offset",
			SchemaName: "offset",
		},
		{
			Name:       "Limit",
			SchemaName: "limit",
		},
		{
			Name:       "OnlyLocal",
			SchemaName: "only_local",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (g *GetChatHistoryRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode getChatHistory#d051927d as nil")
	}
	b.PutID(GetChatHistoryRequestTypeID)
	return g.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (g *GetChatHistoryRequest) EncodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode getChatHistory#d051927d as nil")
	}
	b.PutInt53(g.ChatID)
	b.PutInt53(g.FromMessageID)
	b.PutInt32(g.Offset)
	b.PutInt32(g.Limit)
	b.PutBool(g.OnlyLocal)
	return nil
}

// Decode implements bin.Decoder.
func (g *GetChatHistoryRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode getChatHistory#d051927d to nil")
	}
	if err := b.ConsumeID(GetChatHistoryRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode getChatHistory#d051927d: %w", err)
	}
	return g.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (g *GetChatHistoryRequest) DecodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode getChatHistory#d051927d to nil")
	}
	{
		value, err := b.Int53()
		if err != nil {
			return fmt.Errorf("unable to decode getChatHistory#d051927d: field chat_id: %w", err)
		}
		g.ChatID = value
	}
	{
		value, err := b.Int53()
		if err != nil {
			return fmt.Errorf("unable to decode getChatHistory#d051927d: field from_message_id: %w", err)
		}
		g.FromMessageID = value
	}
	{
		value, err := b.Int32()
		if err != nil {
			return fmt.Errorf("unable to decode getChatHistory#d051927d: field offset: %w", err)
		}
		g.Offset = value
	}
	{
		value, err := b.Int32()
		if err != nil {
			return fmt.Errorf("unable to decode getChatHistory#d051927d: field limit: %w", err)
		}
		g.Limit = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode getChatHistory#d051927d: field only_local: %w", err)
		}
		g.OnlyLocal = value
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (g *GetChatHistoryRequest) EncodeTDLibJSON(b tdjson.Encoder) error {
	if g == nil {
		return fmt.Errorf("can't encode getChatHistory#d051927d as nil")
	}
	b.ObjStart()
	b.PutID("getChatHistory")
	b.Comma()
	b.FieldStart("chat_id")
	b.PutInt53(g.ChatID)
	b.Comma()
	b.FieldStart("from_message_id")
	b.PutInt53(g.FromMessageID)
	b.Comma()
	b.FieldStart("offset")
	b.PutInt32(g.Offset)
	b.Comma()
	b.FieldStart("limit")
	b.PutInt32(g.Limit)
	b.Comma()
	b.FieldStart("only_local")
	b.PutBool(g.OnlyLocal)
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (g *GetChatHistoryRequest) DecodeTDLibJSON(b tdjson.Decoder) error {
	if g == nil {
		return fmt.Errorf("can't decode getChatHistory#d051927d to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("getChatHistory"); err != nil {
				return fmt.Errorf("unable to decode getChatHistory#d051927d: %w", err)
			}
		case "chat_id":
			value, err := b.Int53()
			if err != nil {
				return fmt.Errorf("unable to decode getChatHistory#d051927d: field chat_id: %w", err)
			}
			g.ChatID = value
		case "from_message_id":
			value, err := b.Int53()
			if err != nil {
				return fmt.Errorf("unable to decode getChatHistory#d051927d: field from_message_id: %w", err)
			}
			g.FromMessageID = value
		case "offset":
			value, err := b.Int32()
			if err != nil {
				return fmt.Errorf("unable to decode getChatHistory#d051927d: field offset: %w", err)
			}
			g.Offset = value
		case "limit":
			value, err := b.Int32()
			if err != nil {
				return fmt.Errorf("unable to decode getChatHistory#d051927d: field limit: %w", err)
			}
			g.Limit = value
		case "only_local":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode getChatHistory#d051927d: field only_local: %w", err)
			}
			g.OnlyLocal = value
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetChatID returns value of ChatID field.
func (g *GetChatHistoryRequest) GetChatID() (value int64) {
	if g == nil {
		return
	}
	return g.ChatID
}

// GetFromMessageID returns value of FromMessageID field.
func (g *GetChatHistoryRequest) GetFromMessageID() (value int64) {
	if g == nil {
		return
	}
	return g.FromMessageID
}

// GetOffset returns value of Offset field.
func (g *GetChatHistoryRequest) GetOffset() (value int32) {
	if g == nil {
		return
	}
	return g.Offset
}

// GetLimit returns value of Limit field.
func (g *GetChatHistoryRequest) GetLimit() (value int32) {
	if g == nil {
		return
	}
	return g.Limit
}

// GetOnlyLocal returns value of OnlyLocal field.
func (g *GetChatHistoryRequest) GetOnlyLocal() (value bool) {
	if g == nil {
		return
	}
	return g.OnlyLocal
}

// GetChatHistory invokes method getChatHistory#d051927d returning error if any.
func (c *Client) GetChatHistory(ctx context.Context, request *GetChatHistoryRequest) (*Messages, error) {
	var result Messages

	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
