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

// ChannelsGetAdminLogRequest represents TL type `channels.getAdminLog#33ddf480`.
// Get the admin log of a channel/supergroup¹
//
// Links:
//  1) https://core.telegram.org/api/channel
//
// See https://core.telegram.org/method/channels.getAdminLog for reference.
type ChannelsGetAdminLogRequest struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields `tl:"flags"`
	// Channel
	Channel InputChannelClass `tl:"channel"`
	// Search query, can be empty
	Q string `tl:"q"`
	// Event filter
	//
	// Use SetEventsFilter and GetEventsFilter helpers.
	EventsFilter ChannelAdminLogEventsFilter `tl:"events_filter"`
	// Only show events from these admins
	//
	// Use SetAdmins and GetAdmins helpers.
	Admins []InputUserClass `tl:"admins"`
	// Maximum ID of message to return (see pagination¹)
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets
	MaxID int64 `tl:"max_id"`
	// Minimum ID of message to return (see pagination¹)
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets
	MinID int64 `tl:"min_id"`
	// Maximum number of results to return, see pagination¹
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets
	Limit int `tl:"limit"`
}

// ChannelsGetAdminLogRequestTypeID is TL type id of ChannelsGetAdminLogRequest.
const ChannelsGetAdminLogRequestTypeID = 0x33ddf480

func (g *ChannelsGetAdminLogRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Flags.Zero()) {
		return false
	}
	if !(g.Channel == nil) {
		return false
	}
	if !(g.Q == "") {
		return false
	}
	if !(g.EventsFilter.Zero()) {
		return false
	}
	if !(g.Admins == nil) {
		return false
	}
	if !(g.MaxID == 0) {
		return false
	}
	if !(g.MinID == 0) {
		return false
	}
	if !(g.Limit == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *ChannelsGetAdminLogRequest) String() string {
	if g == nil {
		return "ChannelsGetAdminLogRequest(nil)"
	}
	type Alias ChannelsGetAdminLogRequest
	return fmt.Sprintf("ChannelsGetAdminLogRequest%+v", Alias(*g))
}

// FillFrom fills ChannelsGetAdminLogRequest from given interface.
func (g *ChannelsGetAdminLogRequest) FillFrom(from interface {
	GetChannel() (value InputChannelClass)
	GetQ() (value string)
	GetEventsFilter() (value ChannelAdminLogEventsFilter, ok bool)
	GetAdmins() (value []InputUserClass, ok bool)
	GetMaxID() (value int64)
	GetMinID() (value int64)
	GetLimit() (value int)
}) {
	g.Channel = from.GetChannel()
	g.Q = from.GetQ()
	if val, ok := from.GetEventsFilter(); ok {
		g.EventsFilter = val
	}

	if val, ok := from.GetAdmins(); ok {
		g.Admins = val
	}

	g.MaxID = from.GetMaxID()
	g.MinID = from.GetMinID()
	g.Limit = from.GetLimit()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (g *ChannelsGetAdminLogRequest) TypeID() uint32 {
	return ChannelsGetAdminLogRequestTypeID
}

// TypeName returns name of type in TL schema.
func (g *ChannelsGetAdminLogRequest) TypeName() string {
	return "channels.getAdminLog"
}

// Encode implements bin.Encoder.
func (g *ChannelsGetAdminLogRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode channels.getAdminLog#33ddf480 as nil")
	}
	b.PutID(ChannelsGetAdminLogRequestTypeID)
	if !(g.EventsFilter.Zero()) {
		g.Flags.Set(0)
	}
	if !(g.Admins == nil) {
		g.Flags.Set(1)
	}
	if err := g.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode channels.getAdminLog#33ddf480: field flags: %w", err)
	}
	if g.Channel == nil {
		return fmt.Errorf("unable to encode channels.getAdminLog#33ddf480: field channel is nil")
	}
	if err := g.Channel.Encode(b); err != nil {
		return fmt.Errorf("unable to encode channels.getAdminLog#33ddf480: field channel: %w", err)
	}
	b.PutString(g.Q)
	if g.Flags.Has(0) {
		if err := g.EventsFilter.Encode(b); err != nil {
			return fmt.Errorf("unable to encode channels.getAdminLog#33ddf480: field events_filter: %w", err)
		}
	}
	if g.Flags.Has(1) {
		b.PutVectorHeader(len(g.Admins))
		for idx, v := range g.Admins {
			if v == nil {
				return fmt.Errorf("unable to encode channels.getAdminLog#33ddf480: field admins element with index %d is nil", idx)
			}
			if err := v.Encode(b); err != nil {
				return fmt.Errorf("unable to encode channels.getAdminLog#33ddf480: field admins element with index %d: %w", idx, err)
			}
		}
	}
	b.PutLong(g.MaxID)
	b.PutLong(g.MinID)
	b.PutInt(g.Limit)
	return nil
}

// GetChannel returns value of Channel field.
func (g *ChannelsGetAdminLogRequest) GetChannel() (value InputChannelClass) {
	return g.Channel
}

// GetChannelAsNotEmpty returns mapped value of Channel field.
func (g *ChannelsGetAdminLogRequest) GetChannelAsNotEmpty() (NotEmptyInputChannel, bool) {
	return g.Channel.AsNotEmpty()
}

// GetQ returns value of Q field.
func (g *ChannelsGetAdminLogRequest) GetQ() (value string) {
	return g.Q
}

// SetEventsFilter sets value of EventsFilter conditional field.
func (g *ChannelsGetAdminLogRequest) SetEventsFilter(value ChannelAdminLogEventsFilter) {
	g.Flags.Set(0)
	g.EventsFilter = value
}

// GetEventsFilter returns value of EventsFilter conditional field and
// boolean which is true if field was set.
func (g *ChannelsGetAdminLogRequest) GetEventsFilter() (value ChannelAdminLogEventsFilter, ok bool) {
	if !g.Flags.Has(0) {
		return value, false
	}
	return g.EventsFilter, true
}

// SetAdmins sets value of Admins conditional field.
func (g *ChannelsGetAdminLogRequest) SetAdmins(value []InputUserClass) {
	g.Flags.Set(1)
	g.Admins = value
}

// GetAdmins returns value of Admins conditional field and
// boolean which is true if field was set.
func (g *ChannelsGetAdminLogRequest) GetAdmins() (value []InputUserClass, ok bool) {
	if !g.Flags.Has(1) {
		return value, false
	}
	return g.Admins, true
}

// MapAdmins returns field Admins wrapped in InputUserClassSlice helper.
func (g *ChannelsGetAdminLogRequest) MapAdmins() (value InputUserClassSlice, ok bool) {
	if !g.Flags.Has(1) {
		return value, false
	}
	return InputUserClassSlice(g.Admins), true
}

// GetMaxID returns value of MaxID field.
func (g *ChannelsGetAdminLogRequest) GetMaxID() (value int64) {
	return g.MaxID
}

// GetMinID returns value of MinID field.
func (g *ChannelsGetAdminLogRequest) GetMinID() (value int64) {
	return g.MinID
}

// GetLimit returns value of Limit field.
func (g *ChannelsGetAdminLogRequest) GetLimit() (value int) {
	return g.Limit
}

// Decode implements bin.Decoder.
func (g *ChannelsGetAdminLogRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode channels.getAdminLog#33ddf480 to nil")
	}
	if err := b.ConsumeID(ChannelsGetAdminLogRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode channels.getAdminLog#33ddf480: %w", err)
	}
	{
		if err := g.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode channels.getAdminLog#33ddf480: field flags: %w", err)
		}
	}
	{
		value, err := DecodeInputChannel(b)
		if err != nil {
			return fmt.Errorf("unable to decode channels.getAdminLog#33ddf480: field channel: %w", err)
		}
		g.Channel = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode channels.getAdminLog#33ddf480: field q: %w", err)
		}
		g.Q = value
	}
	if g.Flags.Has(0) {
		if err := g.EventsFilter.Decode(b); err != nil {
			return fmt.Errorf("unable to decode channels.getAdminLog#33ddf480: field events_filter: %w", err)
		}
	}
	if g.Flags.Has(1) {
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode channels.getAdminLog#33ddf480: field admins: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeInputUser(b)
			if err != nil {
				return fmt.Errorf("unable to decode channels.getAdminLog#33ddf480: field admins: %w", err)
			}
			g.Admins = append(g.Admins, value)
		}
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode channels.getAdminLog#33ddf480: field max_id: %w", err)
		}
		g.MaxID = value
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode channels.getAdminLog#33ddf480: field min_id: %w", err)
		}
		g.MinID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode channels.getAdminLog#33ddf480: field limit: %w", err)
		}
		g.Limit = value
	}
	return nil
}

// Ensuring interfaces in compile-time for ChannelsGetAdminLogRequest.
var (
	_ bin.Encoder = &ChannelsGetAdminLogRequest{}
	_ bin.Decoder = &ChannelsGetAdminLogRequest{}
)

// ChannelsGetAdminLog invokes method channels.getAdminLog#33ddf480 returning error if any.
// Get the admin log of a channel/supergroup¹
//
// Links:
//  1) https://core.telegram.org/api/channel
//
// Possible errors:
//  400 CHANNEL_INVALID: The provided channel is invalid
//  400 CHANNEL_PRIVATE: You haven't joined this channel/supergroup
//  400 CHAT_ADMIN_REQUIRED: You must be an admin in this chat to do this
//  403 CHAT_WRITE_FORBIDDEN: You can't write in this chat
//  400 MSG_ID_INVALID: Invalid message ID provided
//
// See https://core.telegram.org/method/channels.getAdminLog for reference.
func (c *Client) ChannelsGetAdminLog(ctx context.Context, request *ChannelsGetAdminLogRequest) (*ChannelsAdminLogResults, error) {
	var result ChannelsAdminLogResults

	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
