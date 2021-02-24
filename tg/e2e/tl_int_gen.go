// Code generated by gotdgen, DO NOT EDIT.

package e2e

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

// Int represents TL type `int#a8509bda`.
//
// See https://core.telegram.org/constructor/int for reference.
type Int struct {
}

// IntTypeID is TL type id of Int.
const IntTypeID = 0xa8509bda

func (i *Int) Zero() bool {
	if i == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (i *Int) String() string {
	if i == nil {
		return "Int(nil)"
	}
	type Alias Int
	return fmt.Sprintf("Int%+v", Alias(*i))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (i *Int) TypeID() uint32 {
	return IntTypeID
}

// TypeName returns name of type in TL schema.
func (i *Int) TypeName() string {
	return "int"
}

// Encode implements bin.Encoder.
func (i *Int) Encode(b *bin.Buffer) error {
	if i == nil {
		return fmt.Errorf("can't encode int#a8509bda as nil")
	}
	b.PutID(IntTypeID)
	return nil
}

// Decode implements bin.Decoder.
func (i *Int) Decode(b *bin.Buffer) error {
	if i == nil {
		return fmt.Errorf("can't decode int#a8509bda to nil")
	}
	if err := b.ConsumeID(IntTypeID); err != nil {
		return fmt.Errorf("unable to decode int#a8509bda: %w", err)
	}
	return nil
}

// Ensuring interfaces in compile-time for Int.
var (
	_ bin.Encoder = &Int{}
	_ bin.Decoder = &Int{}
)
