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

// LabeledPrice represents TL type `labeledPrice#cb296bf8`.
// This object represents a portion of the price for goods or services.
//
// See https://core.telegram.org/constructor/labeledPrice for reference.
type LabeledPrice struct {
	// Portion label
	Label string `tl:"label"`
	// Price of the product in the smallest units of the currency (integer, not float/double). For example, for a price of US$ 1.45 pass amount = 145. See the exp parameter in currencies.json¹, it shows the number of digits past the decimal point for each currency (2 for the majority of currencies).
	//
	// Links:
	//  1) https://core.telegram.org/bots/payments/currencies.json
	Amount int64 `tl:"amount"`
}

// LabeledPriceTypeID is TL type id of LabeledPrice.
const LabeledPriceTypeID = 0xcb296bf8

func (l *LabeledPrice) Zero() bool {
	if l == nil {
		return true
	}
	if !(l.Label == "") {
		return false
	}
	if !(l.Amount == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (l *LabeledPrice) String() string {
	if l == nil {
		return "LabeledPrice(nil)"
	}
	type Alias LabeledPrice
	return fmt.Sprintf("LabeledPrice%+v", Alias(*l))
}

// FillFrom fills LabeledPrice from given interface.
func (l *LabeledPrice) FillFrom(from interface {
	GetLabel() (value string)
	GetAmount() (value int64)
}) {
	l.Label = from.GetLabel()
	l.Amount = from.GetAmount()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (l *LabeledPrice) TypeID() uint32 {
	return LabeledPriceTypeID
}

// TypeName returns name of type in TL schema.
func (l *LabeledPrice) TypeName() string {
	return "labeledPrice"
}

// Encode implements bin.Encoder.
func (l *LabeledPrice) Encode(b *bin.Buffer) error {
	if l == nil {
		return fmt.Errorf("can't encode labeledPrice#cb296bf8 as nil")
	}
	b.PutID(LabeledPriceTypeID)
	b.PutString(l.Label)
	b.PutLong(l.Amount)
	return nil
}

// GetLabel returns value of Label field.
func (l *LabeledPrice) GetLabel() (value string) {
	return l.Label
}

// GetAmount returns value of Amount field.
func (l *LabeledPrice) GetAmount() (value int64) {
	return l.Amount
}

// Decode implements bin.Decoder.
func (l *LabeledPrice) Decode(b *bin.Buffer) error {
	if l == nil {
		return fmt.Errorf("can't decode labeledPrice#cb296bf8 to nil")
	}
	if err := b.ConsumeID(LabeledPriceTypeID); err != nil {
		return fmt.Errorf("unable to decode labeledPrice#cb296bf8: %w", err)
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode labeledPrice#cb296bf8: field label: %w", err)
		}
		l.Label = value
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode labeledPrice#cb296bf8: field amount: %w", err)
		}
		l.Amount = value
	}
	return nil
}

// Ensuring interfaces in compile-time for LabeledPrice.
var (
	_ bin.Encoder = &LabeledPrice{}
	_ bin.Decoder = &LabeledPrice{}
)
