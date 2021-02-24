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

// MessagesGetInlineBotResultsRequest represents TL type `messages.getInlineBotResults#514e999d`.
// Query an inline bot
//
// See https://core.telegram.org/method/messages.getInlineBotResults for reference.
type MessagesGetInlineBotResultsRequest struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields `tl:"flags"`
	// The bot to query
	Bot InputUserClass `tl:"bot"`
	// The currently opened chat
	Peer InputPeerClass `tl:"peer"`
	// The geolocation, if requested
	//
	// Use SetGeoPoint and GetGeoPoint helpers.
	GeoPoint InputGeoPointClass `tl:"geo_point"`
	// The query
	Query string `tl:"query"`
	// The offset within the results, will be passed directly as-is to the bot.
	Offset string `tl:"offset"`
}

// MessagesGetInlineBotResultsRequestTypeID is TL type id of MessagesGetInlineBotResultsRequest.
const MessagesGetInlineBotResultsRequestTypeID = 0x514e999d

func (g *MessagesGetInlineBotResultsRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Flags.Zero()) {
		return false
	}
	if !(g.Bot == nil) {
		return false
	}
	if !(g.Peer == nil) {
		return false
	}
	if !(g.GeoPoint == nil) {
		return false
	}
	if !(g.Query == "") {
		return false
	}
	if !(g.Offset == "") {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *MessagesGetInlineBotResultsRequest) String() string {
	if g == nil {
		return "MessagesGetInlineBotResultsRequest(nil)"
	}
	type Alias MessagesGetInlineBotResultsRequest
	return fmt.Sprintf("MessagesGetInlineBotResultsRequest%+v", Alias(*g))
}

// FillFrom fills MessagesGetInlineBotResultsRequest from given interface.
func (g *MessagesGetInlineBotResultsRequest) FillFrom(from interface {
	GetBot() (value InputUserClass)
	GetPeer() (value InputPeerClass)
	GetGeoPoint() (value InputGeoPointClass, ok bool)
	GetQuery() (value string)
	GetOffset() (value string)
}) {
	g.Bot = from.GetBot()
	g.Peer = from.GetPeer()
	if val, ok := from.GetGeoPoint(); ok {
		g.GeoPoint = val
	}

	g.Query = from.GetQuery()
	g.Offset = from.GetOffset()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (g *MessagesGetInlineBotResultsRequest) TypeID() uint32 {
	return MessagesGetInlineBotResultsRequestTypeID
}

// TypeName returns name of type in TL schema.
func (g *MessagesGetInlineBotResultsRequest) TypeName() string {
	return "messages.getInlineBotResults"
}

// Encode implements bin.Encoder.
func (g *MessagesGetInlineBotResultsRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode messages.getInlineBotResults#514e999d as nil")
	}
	b.PutID(MessagesGetInlineBotResultsRequestTypeID)
	if !(g.GeoPoint == nil) {
		g.Flags.Set(0)
	}
	if err := g.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.getInlineBotResults#514e999d: field flags: %w", err)
	}
	if g.Bot == nil {
		return fmt.Errorf("unable to encode messages.getInlineBotResults#514e999d: field bot is nil")
	}
	if err := g.Bot.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.getInlineBotResults#514e999d: field bot: %w", err)
	}
	if g.Peer == nil {
		return fmt.Errorf("unable to encode messages.getInlineBotResults#514e999d: field peer is nil")
	}
	if err := g.Peer.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.getInlineBotResults#514e999d: field peer: %w", err)
	}
	if g.Flags.Has(0) {
		if g.GeoPoint == nil {
			return fmt.Errorf("unable to encode messages.getInlineBotResults#514e999d: field geo_point is nil")
		}
		if err := g.GeoPoint.Encode(b); err != nil {
			return fmt.Errorf("unable to encode messages.getInlineBotResults#514e999d: field geo_point: %w", err)
		}
	}
	b.PutString(g.Query)
	b.PutString(g.Offset)
	return nil
}

// GetBot returns value of Bot field.
func (g *MessagesGetInlineBotResultsRequest) GetBot() (value InputUserClass) {
	return g.Bot
}

// GetPeer returns value of Peer field.
func (g *MessagesGetInlineBotResultsRequest) GetPeer() (value InputPeerClass) {
	return g.Peer
}

// SetGeoPoint sets value of GeoPoint conditional field.
func (g *MessagesGetInlineBotResultsRequest) SetGeoPoint(value InputGeoPointClass) {
	g.Flags.Set(0)
	g.GeoPoint = value
}

// GetGeoPoint returns value of GeoPoint conditional field and
// boolean which is true if field was set.
func (g *MessagesGetInlineBotResultsRequest) GetGeoPoint() (value InputGeoPointClass, ok bool) {
	if !g.Flags.Has(0) {
		return value, false
	}
	return g.GeoPoint, true
}

// GetGeoPointAsNotEmpty returns mapped value of GeoPoint conditional field and
// boolean which is true if field was set.
func (g *MessagesGetInlineBotResultsRequest) GetGeoPointAsNotEmpty() (*InputGeoPoint, bool) {
	if value, ok := g.GetGeoPoint(); ok {
		return value.AsNotEmpty()
	}
	return nil, false
}

// GetQuery returns value of Query field.
func (g *MessagesGetInlineBotResultsRequest) GetQuery() (value string) {
	return g.Query
}

// GetOffset returns value of Offset field.
func (g *MessagesGetInlineBotResultsRequest) GetOffset() (value string) {
	return g.Offset
}

// Decode implements bin.Decoder.
func (g *MessagesGetInlineBotResultsRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode messages.getInlineBotResults#514e999d to nil")
	}
	if err := b.ConsumeID(MessagesGetInlineBotResultsRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.getInlineBotResults#514e999d: %w", err)
	}
	{
		if err := g.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode messages.getInlineBotResults#514e999d: field flags: %w", err)
		}
	}
	{
		value, err := DecodeInputUser(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.getInlineBotResults#514e999d: field bot: %w", err)
		}
		g.Bot = value
	}
	{
		value, err := DecodeInputPeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.getInlineBotResults#514e999d: field peer: %w", err)
		}
		g.Peer = value
	}
	if g.Flags.Has(0) {
		value, err := DecodeInputGeoPoint(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.getInlineBotResults#514e999d: field geo_point: %w", err)
		}
		g.GeoPoint = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getInlineBotResults#514e999d: field query: %w", err)
		}
		g.Query = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getInlineBotResults#514e999d: field offset: %w", err)
		}
		g.Offset = value
	}
	return nil
}

// Ensuring interfaces in compile-time for MessagesGetInlineBotResultsRequest.
var (
	_ bin.Encoder = &MessagesGetInlineBotResultsRequest{}
	_ bin.Decoder = &MessagesGetInlineBotResultsRequest{}
)

// MessagesGetInlineBotResults invokes method messages.getInlineBotResults#514e999d returning error if any.
// Query an inline bot
//
// Possible errors:
//  400 BOT_INLINE_DISABLED: This bot can't be used in inline mode
//  400 BOT_INVALID: This is not a valid bot
//  400 BOT_RESPONSE_TIMEOUT: A timeout occurred while fetching data from the bot
//  400 CHANNEL_PRIVATE: You haven't joined this channel/supergroup
//  400 INPUT_USER_DEACTIVATED: The specified user was deleted
//  400 MSG_ID_INVALID: Invalid message ID provided
//  -503 Timeout: Timeout while fetching data
//
// See https://core.telegram.org/method/messages.getInlineBotResults for reference.
func (c *Client) MessagesGetInlineBotResults(ctx context.Context, request *MessagesGetInlineBotResultsRequest) (*MessagesBotResults, error) {
	var result MessagesBotResults

	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
