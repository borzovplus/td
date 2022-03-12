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

// CreateCallRequest represents TL type `createCall#be282e10`.
type CreateCallRequest struct {
	// Identifier of the user to be called
	UserID int64
	// The call protocols supported by the application
	Protocol CallProtocol
	// Pass true to create a video call
	IsVideo bool
}

// CreateCallRequestTypeID is TL type id of CreateCallRequest.
const CreateCallRequestTypeID = 0xbe282e10

// Ensuring interfaces in compile-time for CreateCallRequest.
var (
	_ bin.Encoder     = &CreateCallRequest{}
	_ bin.Decoder     = &CreateCallRequest{}
	_ bin.BareEncoder = &CreateCallRequest{}
	_ bin.BareDecoder = &CreateCallRequest{}
)

func (c *CreateCallRequest) Zero() bool {
	if c == nil {
		return true
	}
	if !(c.UserID == 0) {
		return false
	}
	if !(c.Protocol.Zero()) {
		return false
	}
	if !(c.IsVideo == false) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (c *CreateCallRequest) String() string {
	if c == nil {
		return "CreateCallRequest(nil)"
	}
	type Alias CreateCallRequest
	return fmt.Sprintf("CreateCallRequest%+v", Alias(*c))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*CreateCallRequest) TypeID() uint32 {
	return CreateCallRequestTypeID
}

// TypeName returns name of type in TL schema.
func (*CreateCallRequest) TypeName() string {
	return "createCall"
}

// TypeInfo returns info about TL type.
func (c *CreateCallRequest) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "createCall",
		ID:   CreateCallRequestTypeID,
	}
	if c == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "UserID",
			SchemaName: "user_id",
		},
		{
			Name:       "Protocol",
			SchemaName: "protocol",
		},
		{
			Name:       "IsVideo",
			SchemaName: "is_video",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (c *CreateCallRequest) Encode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode createCall#be282e10 as nil")
	}
	b.PutID(CreateCallRequestTypeID)
	return c.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (c *CreateCallRequest) EncodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode createCall#be282e10 as nil")
	}
	b.PutInt53(c.UserID)
	if err := c.Protocol.Encode(b); err != nil {
		return fmt.Errorf("unable to encode createCall#be282e10: field protocol: %w", err)
	}
	b.PutBool(c.IsVideo)
	return nil
}

// Decode implements bin.Decoder.
func (c *CreateCallRequest) Decode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode createCall#be282e10 to nil")
	}
	if err := b.ConsumeID(CreateCallRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode createCall#be282e10: %w", err)
	}
	return c.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (c *CreateCallRequest) DecodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode createCall#be282e10 to nil")
	}
	{
		value, err := b.Int53()
		if err != nil {
			return fmt.Errorf("unable to decode createCall#be282e10: field user_id: %w", err)
		}
		c.UserID = value
	}
	{
		if err := c.Protocol.Decode(b); err != nil {
			return fmt.Errorf("unable to decode createCall#be282e10: field protocol: %w", err)
		}
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode createCall#be282e10: field is_video: %w", err)
		}
		c.IsVideo = value
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (c *CreateCallRequest) EncodeTDLibJSON(b tdjson.Encoder) error {
	if c == nil {
		return fmt.Errorf("can't encode createCall#be282e10 as nil")
	}
	b.ObjStart()
	b.PutID("createCall")
	b.Comma()
	b.FieldStart("user_id")
	b.PutInt53(c.UserID)
	b.Comma()
	b.FieldStart("protocol")
	if err := c.Protocol.EncodeTDLibJSON(b); err != nil {
		return fmt.Errorf("unable to encode createCall#be282e10: field protocol: %w", err)
	}
	b.Comma()
	b.FieldStart("is_video")
	b.PutBool(c.IsVideo)
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (c *CreateCallRequest) DecodeTDLibJSON(b tdjson.Decoder) error {
	if c == nil {
		return fmt.Errorf("can't decode createCall#be282e10 to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("createCall"); err != nil {
				return fmt.Errorf("unable to decode createCall#be282e10: %w", err)
			}
		case "user_id":
			value, err := b.Int53()
			if err != nil {
				return fmt.Errorf("unable to decode createCall#be282e10: field user_id: %w", err)
			}
			c.UserID = value
		case "protocol":
			if err := c.Protocol.DecodeTDLibJSON(b); err != nil {
				return fmt.Errorf("unable to decode createCall#be282e10: field protocol: %w", err)
			}
		case "is_video":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode createCall#be282e10: field is_video: %w", err)
			}
			c.IsVideo = value
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetUserID returns value of UserID field.
func (c *CreateCallRequest) GetUserID() (value int64) {
	if c == nil {
		return
	}
	return c.UserID
}

// GetProtocol returns value of Protocol field.
func (c *CreateCallRequest) GetProtocol() (value CallProtocol) {
	if c == nil {
		return
	}
	return c.Protocol
}

// GetIsVideo returns value of IsVideo field.
func (c *CreateCallRequest) GetIsVideo() (value bool) {
	if c == nil {
		return
	}
	return c.IsVideo
}

// CreateCall invokes method createCall#be282e10 returning error if any.
func (c *Client) CreateCall(ctx context.Context, request *CreateCallRequest) (*CallID, error) {
	var result CallID

	if err := c.rpc.Invoke(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
