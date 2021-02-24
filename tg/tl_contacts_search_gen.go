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

// ContactsSearchRequest represents TL type `contacts.search#11f812d8`.
// Returns users found by username substring.
//
// See https://core.telegram.org/method/contacts.search for reference.
type ContactsSearchRequest struct {
	// Target substring
	Q string `tl:"q"`
	// Maximum number of users to be returned
	Limit int `tl:"limit"`
}

// ContactsSearchRequestTypeID is TL type id of ContactsSearchRequest.
const ContactsSearchRequestTypeID = 0x11f812d8

func (s *ContactsSearchRequest) Zero() bool {
	if s == nil {
		return true
	}
	if !(s.Q == "") {
		return false
	}
	if !(s.Limit == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (s *ContactsSearchRequest) String() string {
	if s == nil {
		return "ContactsSearchRequest(nil)"
	}
	type Alias ContactsSearchRequest
	return fmt.Sprintf("ContactsSearchRequest%+v", Alias(*s))
}

// FillFrom fills ContactsSearchRequest from given interface.
func (s *ContactsSearchRequest) FillFrom(from interface {
	GetQ() (value string)
	GetLimit() (value int)
}) {
	s.Q = from.GetQ()
	s.Limit = from.GetLimit()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (s *ContactsSearchRequest) TypeID() uint32 {
	return ContactsSearchRequestTypeID
}

// TypeName returns name of type in TL schema.
func (s *ContactsSearchRequest) TypeName() string {
	return "contacts.search"
}

// Encode implements bin.Encoder.
func (s *ContactsSearchRequest) Encode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode contacts.search#11f812d8 as nil")
	}
	b.PutID(ContactsSearchRequestTypeID)
	b.PutString(s.Q)
	b.PutInt(s.Limit)
	return nil
}

// GetQ returns value of Q field.
func (s *ContactsSearchRequest) GetQ() (value string) {
	return s.Q
}

// GetLimit returns value of Limit field.
func (s *ContactsSearchRequest) GetLimit() (value int) {
	return s.Limit
}

// Decode implements bin.Decoder.
func (s *ContactsSearchRequest) Decode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode contacts.search#11f812d8 to nil")
	}
	if err := b.ConsumeID(ContactsSearchRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode contacts.search#11f812d8: %w", err)
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode contacts.search#11f812d8: field q: %w", err)
		}
		s.Q = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode contacts.search#11f812d8: field limit: %w", err)
		}
		s.Limit = value
	}
	return nil
}

// Ensuring interfaces in compile-time for ContactsSearchRequest.
var (
	_ bin.Encoder = &ContactsSearchRequest{}
	_ bin.Decoder = &ContactsSearchRequest{}
)

// ContactsSearch invokes method contacts.search#11f812d8 returning error if any.
// Returns users found by username substring.
//
// Possible errors:
//  400 QUERY_TOO_SHORT: The query string is too short
//  400 SEARCH_QUERY_EMPTY: The search query is empty
//
// See https://core.telegram.org/method/contacts.search for reference.
func (c *Client) ContactsSearch(ctx context.Context, request *ContactsSearchRequest) (*ContactsFound, error) {
	var result ContactsFound

	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
