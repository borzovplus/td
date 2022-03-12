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

// GetVideoChatRtmpURLRequest represents TL type `getVideoChatRtmpUrl#482b1b1f`.
type GetVideoChatRtmpURLRequest struct {
	// Chat identifier
	ChatID int64
}

// GetVideoChatRtmpURLRequestTypeID is TL type id of GetVideoChatRtmpURLRequest.
const GetVideoChatRtmpURLRequestTypeID = 0x482b1b1f

// Ensuring interfaces in compile-time for GetVideoChatRtmpURLRequest.
var (
	_ bin.Encoder     = &GetVideoChatRtmpURLRequest{}
	_ bin.Decoder     = &GetVideoChatRtmpURLRequest{}
	_ bin.BareEncoder = &GetVideoChatRtmpURLRequest{}
	_ bin.BareDecoder = &GetVideoChatRtmpURLRequest{}
)

func (g *GetVideoChatRtmpURLRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.ChatID == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *GetVideoChatRtmpURLRequest) String() string {
	if g == nil {
		return "GetVideoChatRtmpURLRequest(nil)"
	}
	type Alias GetVideoChatRtmpURLRequest
	return fmt.Sprintf("GetVideoChatRtmpURLRequest%+v", Alias(*g))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*GetVideoChatRtmpURLRequest) TypeID() uint32 {
	return GetVideoChatRtmpURLRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*GetVideoChatRtmpURLRequest) TypeName() string {
	return "getVideoChatRtmpUrl"
}

// TypeInfo returns info about TL type.
func (g *GetVideoChatRtmpURLRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "getVideoChatRtmpUrl",
		ID:   GetVideoChatRtmpURLRequestTypeID,
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
	}
	return typ
}

// Encode implements bin.Encoder.
func (g *GetVideoChatRtmpURLRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode getVideoChatRtmpUrl#482b1b1f as nil")
	}
	b.PutID(GetVideoChatRtmpURLRequestTypeID)
	return g.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (g *GetVideoChatRtmpURLRequest) EncodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode getVideoChatRtmpUrl#482b1b1f as nil")
	}
	b.PutInt53(g.ChatID)
	return nil
}

// Decode implements bin.Decoder.
func (g *GetVideoChatRtmpURLRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode getVideoChatRtmpUrl#482b1b1f to nil")
	}
	if err := b.ConsumeID(GetVideoChatRtmpURLRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode getVideoChatRtmpUrl#482b1b1f: %w", err)
	}
	return g.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (g *GetVideoChatRtmpURLRequest) DecodeBare(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode getVideoChatRtmpUrl#482b1b1f to nil")
	}
	{
		value, err := b.Int53()
		if err != nil {
			return fmt.Errorf("unable to decode getVideoChatRtmpUrl#482b1b1f: field chat_id: %w", err)
		}
		g.ChatID = value
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (g *GetVideoChatRtmpURLRequest) EncodeTDLibJSON(b tdjson.Encoder) error {
	if g == nil {
		return fmt.Errorf("can't encode getVideoChatRtmpUrl#482b1b1f as nil")
	}
	b.ObjStart()
	b.PutID("getVideoChatRtmpUrl")
	b.Comma()
	b.FieldStart("chat_id")
	b.PutInt53(g.ChatID)
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (g *GetVideoChatRtmpURLRequest) DecodeTDLibJSON(b tdjson.Decoder) error {
	if g == nil {
		return fmt.Errorf("can't decode getVideoChatRtmpUrl#482b1b1f to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("getVideoChatRtmpUrl"); err != nil {
				return fmt.Errorf("unable to decode getVideoChatRtmpUrl#482b1b1f: %w", err)
			}
		case "chat_id":
			value, err := b.Int53()
			if err != nil {
				return fmt.Errorf("unable to decode getVideoChatRtmpUrl#482b1b1f: field chat_id: %w", err)
			}
			g.ChatID = value
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetChatID returns value of ChatID field.
func (g *GetVideoChatRtmpURLRequest) GetChatID() (value int64) {
	if g == nil {
		return
	}
	return g.ChatID
}

// GetVideoChatRtmpURL invokes method getVideoChatRtmpUrl#482b1b1f returning error if any.
func (c *Client) GetVideoChatRtmpURL(ctx context.Context, chatid int64) (*RtmpURL, error) {
	var result RtmpURL

	request := &GetVideoChatRtmpURLRequest{
		ChatID: chatid,
	}
	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
