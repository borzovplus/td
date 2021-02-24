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

// ContactsDeleteByPhonesRequest represents TL type `contacts.deleteByPhones#1013fd9e`.
// Delete contacts by phone number
//
// See https://core.telegram.org/method/contacts.deleteByPhones for reference.
type ContactsDeleteByPhonesRequest struct {
	// Phone numbers
	Phones []string `tl:"phones"`
}

// ContactsDeleteByPhonesRequestTypeID is TL type id of ContactsDeleteByPhonesRequest.
const ContactsDeleteByPhonesRequestTypeID = 0x1013fd9e

func (d *ContactsDeleteByPhonesRequest) Zero() bool {
	if d == nil {
		return true
	}
	if !(d.Phones == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (d *ContactsDeleteByPhonesRequest) String() string {
	if d == nil {
		return "ContactsDeleteByPhonesRequest(nil)"
	}
	type Alias ContactsDeleteByPhonesRequest
	return fmt.Sprintf("ContactsDeleteByPhonesRequest%+v", Alias(*d))
}

// FillFrom fills ContactsDeleteByPhonesRequest from given interface.
func (d *ContactsDeleteByPhonesRequest) FillFrom(from interface {
	GetPhones() (value []string)
}) {
	d.Phones = from.GetPhones()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (d *ContactsDeleteByPhonesRequest) TypeID() uint32 {
	return ContactsDeleteByPhonesRequestTypeID
}

// TypeName returns name of type in TL schema.
func (d *ContactsDeleteByPhonesRequest) TypeName() string {
	return "contacts.deleteByPhones"
}

// Encode implements bin.Encoder.
func (d *ContactsDeleteByPhonesRequest) Encode(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't encode contacts.deleteByPhones#1013fd9e as nil")
	}
	b.PutID(ContactsDeleteByPhonesRequestTypeID)
	b.PutVectorHeader(len(d.Phones))
	for _, v := range d.Phones {
		b.PutString(v)
	}
	return nil
}

// GetPhones returns value of Phones field.
func (d *ContactsDeleteByPhonesRequest) GetPhones() (value []string) {
	return d.Phones
}

// Decode implements bin.Decoder.
func (d *ContactsDeleteByPhonesRequest) Decode(b *bin.Buffer) error {
	if d == nil {
		return fmt.Errorf("can't decode contacts.deleteByPhones#1013fd9e to nil")
	}
	if err := b.ConsumeID(ContactsDeleteByPhonesRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode contacts.deleteByPhones#1013fd9e: %w", err)
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode contacts.deleteByPhones#1013fd9e: field phones: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := b.String()
			if err != nil {
				return fmt.Errorf("unable to decode contacts.deleteByPhones#1013fd9e: field phones: %w", err)
			}
			d.Phones = append(d.Phones, value)
		}
	}
	return nil
}

// Ensuring interfaces in compile-time for ContactsDeleteByPhonesRequest.
var (
	_ bin.Encoder = &ContactsDeleteByPhonesRequest{}
	_ bin.Decoder = &ContactsDeleteByPhonesRequest{}
)

// ContactsDeleteByPhones invokes method contacts.deleteByPhones#1013fd9e returning error if any.
// Delete contacts by phone number
//
// See https://core.telegram.org/method/contacts.deleteByPhones for reference.
func (c *Client) ContactsDeleteByPhones(ctx context.Context, phones []string) (bool, error) {
	var result BoolBox

	request := &ContactsDeleteByPhonesRequest{
		Phones: phones,
	}
	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return false, err
	}
	_, ok := result.Bool.(*BoolTrue)
	return ok, nil
}
