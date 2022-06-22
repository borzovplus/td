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

// ChatFilter represents TL type `chatFilter#9a7344af`.
type ChatFilter struct {
	// The title of the filter; 1-12 characters without line feeds
	Title string
	// The chosen icon name for short filter representation. If non-empty, must be one of
	// "All", "Unread", "Unmuted", "Bots", "Channels", "Groups", "Private", "Custom", "Setup"
	// "Cat", "Crown", "Favorite", "Flower", "Game", "Home", "Love", "Mask", "Party",
	// "Sport", "Study", "Trade", "Travel", "Work".
	IconName string
	// The chat identifiers of pinned chats in the filtered chat list. There can be up to
	// GetOption("chat_filter_chosen_chat_count_max") pinned and always included non-secret
	// chats and the same number of secret chats, but the limit can be increased with
	// Telegram Premium
	PinnedChatIDs []int64
	// The chat identifiers of always included chats in the filtered chat list. There can be
	// up to GetOption("chat_filter_chosen_chat_count_max") pinned and always included
	// non-secret chats and the same number of secret chats, but the limit can be increased
	// with Telegram Premium
	IncludedChatIDs []int64
	// The chat identifiers of always excluded chats in the filtered chat list. There can be
	// up to GetOption("chat_filter_chosen_chat_count_max") always excluded non-secret chats
	// and the same number of secret chats, but the limit can be increased with Telegram
	// Premium
	ExcludedChatIDs []int64
	// True, if muted chats need to be excluded
	ExcludeMuted bool
	// True, if read chats need to be excluded
	ExcludeRead bool
	// True, if archived chats need to be excluded
	ExcludeArchived bool
	// True, if contacts need to be included
	IncludeContacts bool
	// True, if non-contact users need to be included
	IncludeNonContacts bool
	// True, if bots need to be included
	IncludeBots bool
	// True, if basic groups and supergroups need to be included
	IncludeGroups bool
	// True, if channels need to be included
	IncludeChannels bool
}

// ChatFilterTypeID is TL type id of ChatFilter.
const ChatFilterTypeID = 0x9a7344af

// Ensuring interfaces in compile-time for ChatFilter.
var (
	_ bin.Encoder     = &ChatFilter{}
	_ bin.Decoder     = &ChatFilter{}
	_ bin.BareEncoder = &ChatFilter{}
	_ bin.BareDecoder = &ChatFilter{}
)

func (c *ChatFilter) Zero() bool {
	if c == nil {
		return true
	}
	if !(c.Title == "") {
		return false
	}
	if !(c.IconName == "") {
		return false
	}
	if !(c.PinnedChatIDs == nil) {
		return false
	}
	if !(c.IncludedChatIDs == nil) {
		return false
	}
	if !(c.ExcludedChatIDs == nil) {
		return false
	}
	if !(c.ExcludeMuted == false) {
		return false
	}
	if !(c.ExcludeRead == false) {
		return false
	}
	if !(c.ExcludeArchived == false) {
		return false
	}
	if !(c.IncludeContacts == false) {
		return false
	}
	if !(c.IncludeNonContacts == false) {
		return false
	}
	if !(c.IncludeBots == false) {
		return false
	}
	if !(c.IncludeGroups == false) {
		return false
	}
	if !(c.IncludeChannels == false) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (c *ChatFilter) String() string {
	if c == nil {
		return "ChatFilter(nil)"
	}
	type Alias ChatFilter
	return fmt.Sprintf("ChatFilter%+v", Alias(*c))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*ChatFilter) TypeID() uint32 {
	return ChatFilterTypeID
}

// TypeName returns name of type in TL schema.
func (*ChatFilter) TypeName() string {
	return "chatFilter"
}

// TypeInfo returns info about TL type.
func (c *ChatFilter) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "chatFilter",
		ID:   ChatFilterTypeID,
	}
	if c == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Title",
			SchemaName: "title",
		},
		{
			Name:       "IconName",
			SchemaName: "icon_name",
		},
		{
			Name:       "PinnedChatIDs",
			SchemaName: "pinned_chat_ids",
		},
		{
			Name:       "IncludedChatIDs",
			SchemaName: "included_chat_ids",
		},
		{
			Name:       "ExcludedChatIDs",
			SchemaName: "excluded_chat_ids",
		},
		{
			Name:       "ExcludeMuted",
			SchemaName: "exclude_muted",
		},
		{
			Name:       "ExcludeRead",
			SchemaName: "exclude_read",
		},
		{
			Name:       "ExcludeArchived",
			SchemaName: "exclude_archived",
		},
		{
			Name:       "IncludeContacts",
			SchemaName: "include_contacts",
		},
		{
			Name:       "IncludeNonContacts",
			SchemaName: "include_non_contacts",
		},
		{
			Name:       "IncludeBots",
			SchemaName: "include_bots",
		},
		{
			Name:       "IncludeGroups",
			SchemaName: "include_groups",
		},
		{
			Name:       "IncludeChannels",
			SchemaName: "include_channels",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (c *ChatFilter) Encode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode chatFilter#9a7344af as nil")
	}
	b.PutID(ChatFilterTypeID)
	return c.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (c *ChatFilter) EncodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode chatFilter#9a7344af as nil")
	}
	b.PutString(c.Title)
	b.PutString(c.IconName)
	b.PutInt(len(c.PinnedChatIDs))
	for _, v := range c.PinnedChatIDs {
		b.PutInt53(v)
	}
	b.PutInt(len(c.IncludedChatIDs))
	for _, v := range c.IncludedChatIDs {
		b.PutInt53(v)
	}
	b.PutInt(len(c.ExcludedChatIDs))
	for _, v := range c.ExcludedChatIDs {
		b.PutInt53(v)
	}
	b.PutBool(c.ExcludeMuted)
	b.PutBool(c.ExcludeRead)
	b.PutBool(c.ExcludeArchived)
	b.PutBool(c.IncludeContacts)
	b.PutBool(c.IncludeNonContacts)
	b.PutBool(c.IncludeBots)
	b.PutBool(c.IncludeGroups)
	b.PutBool(c.IncludeChannels)
	return nil
}

// Decode implements bin.Decoder.
func (c *ChatFilter) Decode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode chatFilter#9a7344af to nil")
	}
	if err := b.ConsumeID(ChatFilterTypeID); err != nil {
		return fmt.Errorf("unable to decode chatFilter#9a7344af: %w", err)
	}
	return c.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (c *ChatFilter) DecodeBare(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode chatFilter#9a7344af to nil")
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field title: %w", err)
		}
		c.Title = value
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field icon_name: %w", err)
		}
		c.IconName = value
	}
	{
		headerLen, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field pinned_chat_ids: %w", err)
		}

		if headerLen > 0 {
			c.PinnedChatIDs = make([]int64, 0, headerLen%bin.PreallocateLimit)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := b.Int53()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field pinned_chat_ids: %w", err)
			}
			c.PinnedChatIDs = append(c.PinnedChatIDs, value)
		}
	}
	{
		headerLen, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field included_chat_ids: %w", err)
		}

		if headerLen > 0 {
			c.IncludedChatIDs = make([]int64, 0, headerLen%bin.PreallocateLimit)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := b.Int53()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field included_chat_ids: %w", err)
			}
			c.IncludedChatIDs = append(c.IncludedChatIDs, value)
		}
	}
	{
		headerLen, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field excluded_chat_ids: %w", err)
		}

		if headerLen > 0 {
			c.ExcludedChatIDs = make([]int64, 0, headerLen%bin.PreallocateLimit)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := b.Int53()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field excluded_chat_ids: %w", err)
			}
			c.ExcludedChatIDs = append(c.ExcludedChatIDs, value)
		}
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field exclude_muted: %w", err)
		}
		c.ExcludeMuted = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field exclude_read: %w", err)
		}
		c.ExcludeRead = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field exclude_archived: %w", err)
		}
		c.ExcludeArchived = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field include_contacts: %w", err)
		}
		c.IncludeContacts = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field include_non_contacts: %w", err)
		}
		c.IncludeNonContacts = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field include_bots: %w", err)
		}
		c.IncludeBots = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field include_groups: %w", err)
		}
		c.IncludeGroups = value
	}
	{
		value, err := b.Bool()
		if err != nil {
			return fmt.Errorf("unable to decode chatFilter#9a7344af: field include_channels: %w", err)
		}
		c.IncludeChannels = value
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (c *ChatFilter) EncodeTDLibJSON(b tdjson.Encoder) error {
	if c == nil {
		return fmt.Errorf("can't encode chatFilter#9a7344af as nil")
	}
	b.ObjStart()
	b.PutID("chatFilter")
	b.Comma()
	b.FieldStart("title")
	b.PutString(c.Title)
	b.Comma()
	b.FieldStart("icon_name")
	b.PutString(c.IconName)
	b.Comma()
	b.FieldStart("pinned_chat_ids")
	b.ArrStart()
	for _, v := range c.PinnedChatIDs {
		b.PutInt53(v)
		b.Comma()
	}
	b.StripComma()
	b.ArrEnd()
	b.Comma()
	b.FieldStart("included_chat_ids")
	b.ArrStart()
	for _, v := range c.IncludedChatIDs {
		b.PutInt53(v)
		b.Comma()
	}
	b.StripComma()
	b.ArrEnd()
	b.Comma()
	b.FieldStart("excluded_chat_ids")
	b.ArrStart()
	for _, v := range c.ExcludedChatIDs {
		b.PutInt53(v)
		b.Comma()
	}
	b.StripComma()
	b.ArrEnd()
	b.Comma()
	b.FieldStart("exclude_muted")
	b.PutBool(c.ExcludeMuted)
	b.Comma()
	b.FieldStart("exclude_read")
	b.PutBool(c.ExcludeRead)
	b.Comma()
	b.FieldStart("exclude_archived")
	b.PutBool(c.ExcludeArchived)
	b.Comma()
	b.FieldStart("include_contacts")
	b.PutBool(c.IncludeContacts)
	b.Comma()
	b.FieldStart("include_non_contacts")
	b.PutBool(c.IncludeNonContacts)
	b.Comma()
	b.FieldStart("include_bots")
	b.PutBool(c.IncludeBots)
	b.Comma()
	b.FieldStart("include_groups")
	b.PutBool(c.IncludeGroups)
	b.Comma()
	b.FieldStart("include_channels")
	b.PutBool(c.IncludeChannels)
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (c *ChatFilter) DecodeTDLibJSON(b tdjson.Decoder) error {
	if c == nil {
		return fmt.Errorf("can't decode chatFilter#9a7344af to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("chatFilter"); err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: %w", err)
			}
		case "title":
			value, err := b.String()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field title: %w", err)
			}
			c.Title = value
		case "icon_name":
			value, err := b.String()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field icon_name: %w", err)
			}
			c.IconName = value
		case "pinned_chat_ids":
			if err := b.Arr(func(b tdjson.Decoder) error {
				value, err := b.Int53()
				if err != nil {
					return fmt.Errorf("unable to decode chatFilter#9a7344af: field pinned_chat_ids: %w", err)
				}
				c.PinnedChatIDs = append(c.PinnedChatIDs, value)
				return nil
			}); err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field pinned_chat_ids: %w", err)
			}
		case "included_chat_ids":
			if err := b.Arr(func(b tdjson.Decoder) error {
				value, err := b.Int53()
				if err != nil {
					return fmt.Errorf("unable to decode chatFilter#9a7344af: field included_chat_ids: %w", err)
				}
				c.IncludedChatIDs = append(c.IncludedChatIDs, value)
				return nil
			}); err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field included_chat_ids: %w", err)
			}
		case "excluded_chat_ids":
			if err := b.Arr(func(b tdjson.Decoder) error {
				value, err := b.Int53()
				if err != nil {
					return fmt.Errorf("unable to decode chatFilter#9a7344af: field excluded_chat_ids: %w", err)
				}
				c.ExcludedChatIDs = append(c.ExcludedChatIDs, value)
				return nil
			}); err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field excluded_chat_ids: %w", err)
			}
		case "exclude_muted":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field exclude_muted: %w", err)
			}
			c.ExcludeMuted = value
		case "exclude_read":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field exclude_read: %w", err)
			}
			c.ExcludeRead = value
		case "exclude_archived":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field exclude_archived: %w", err)
			}
			c.ExcludeArchived = value
		case "include_contacts":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field include_contacts: %w", err)
			}
			c.IncludeContacts = value
		case "include_non_contacts":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field include_non_contacts: %w", err)
			}
			c.IncludeNonContacts = value
		case "include_bots":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field include_bots: %w", err)
			}
			c.IncludeBots = value
		case "include_groups":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field include_groups: %w", err)
			}
			c.IncludeGroups = value
		case "include_channels":
			value, err := b.Bool()
			if err != nil {
				return fmt.Errorf("unable to decode chatFilter#9a7344af: field include_channels: %w", err)
			}
			c.IncludeChannels = value
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetTitle returns value of Title field.
func (c *ChatFilter) GetTitle() (value string) {
	if c == nil {
		return
	}
	return c.Title
}

// GetIconName returns value of IconName field.
func (c *ChatFilter) GetIconName() (value string) {
	if c == nil {
		return
	}
	return c.IconName
}

// GetPinnedChatIDs returns value of PinnedChatIDs field.
func (c *ChatFilter) GetPinnedChatIDs() (value []int64) {
	if c == nil {
		return
	}
	return c.PinnedChatIDs
}

// GetIncludedChatIDs returns value of IncludedChatIDs field.
func (c *ChatFilter) GetIncludedChatIDs() (value []int64) {
	if c == nil {
		return
	}
	return c.IncludedChatIDs
}

// GetExcludedChatIDs returns value of ExcludedChatIDs field.
func (c *ChatFilter) GetExcludedChatIDs() (value []int64) {
	if c == nil {
		return
	}
	return c.ExcludedChatIDs
}

// GetExcludeMuted returns value of ExcludeMuted field.
func (c *ChatFilter) GetExcludeMuted() (value bool) {
	if c == nil {
		return
	}
	return c.ExcludeMuted
}

// GetExcludeRead returns value of ExcludeRead field.
func (c *ChatFilter) GetExcludeRead() (value bool) {
	if c == nil {
		return
	}
	return c.ExcludeRead
}

// GetExcludeArchived returns value of ExcludeArchived field.
func (c *ChatFilter) GetExcludeArchived() (value bool) {
	if c == nil {
		return
	}
	return c.ExcludeArchived
}

// GetIncludeContacts returns value of IncludeContacts field.
func (c *ChatFilter) GetIncludeContacts() (value bool) {
	if c == nil {
		return
	}
	return c.IncludeContacts
}

// GetIncludeNonContacts returns value of IncludeNonContacts field.
func (c *ChatFilter) GetIncludeNonContacts() (value bool) {
	if c == nil {
		return
	}
	return c.IncludeNonContacts
}

// GetIncludeBots returns value of IncludeBots field.
func (c *ChatFilter) GetIncludeBots() (value bool) {
	if c == nil {
		return
	}
	return c.IncludeBots
}

// GetIncludeGroups returns value of IncludeGroups field.
func (c *ChatFilter) GetIncludeGroups() (value bool) {
	if c == nil {
		return
	}
	return c.IncludeGroups
}

// GetIncludeChannels returns value of IncludeChannels field.
func (c *ChatFilter) GetIncludeChannels() (value bool) {
	if c == nil {
		return
	}
	return c.IncludeChannels
}
