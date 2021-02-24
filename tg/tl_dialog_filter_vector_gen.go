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

// DialogFilterVector is a box for Vector<DialogFilter>
type DialogFilterVector struct {
	// Elements of Vector<DialogFilter>
	Elems []DialogFilter `tl:"Elems"`
}

// DialogFilterVectorTypeID is TL type id of DialogFilterVector.
const DialogFilterVectorTypeID = bin.TypeVector

func (vec *DialogFilterVector) Zero() bool {
	if vec == nil {
		return true
	}
	if !(vec.Elems == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (vec *DialogFilterVector) String() string {
	if vec == nil {
		return "DialogFilterVector(nil)"
	}
	type Alias DialogFilterVector
	return fmt.Sprintf("DialogFilterVector%+v", Alias(*vec))
}

// FillFrom fills DialogFilterVector from given interface.
func (vec *DialogFilterVector) FillFrom(from interface {
	GetElems() (value []DialogFilter)
}) {
	vec.Elems = from.GetElems()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (vec *DialogFilterVector) TypeID() uint32 {
	return DialogFilterVectorTypeID
}

// TypeName returns name of type in TL schema.
func (vec *DialogFilterVector) TypeName() string {
	return ""
}

// Encode implements bin.Encoder.
func (vec *DialogFilterVector) Encode(b *bin.Buffer) error {
	if vec == nil {
		return fmt.Errorf("can't encode Vector<DialogFilter> as nil")
	}
	b.PutVectorHeader(len(vec.Elems))
	for idx, v := range vec.Elems {
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode Vector<DialogFilter>: field Elems element with index %d: %w", idx, err)
		}
	}
	return nil
}

// GetElems returns value of Elems field.
func (vec *DialogFilterVector) GetElems() (value []DialogFilter) {
	return vec.Elems
}

// Decode implements bin.Decoder.
func (vec *DialogFilterVector) Decode(b *bin.Buffer) error {
	if vec == nil {
		return fmt.Errorf("can't decode Vector<DialogFilter> to nil")
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode Vector<DialogFilter>: field Elems: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			var value DialogFilter
			if err := value.Decode(b); err != nil {
				return fmt.Errorf("unable to decode Vector<DialogFilter>: field Elems: %w", err)
			}
			vec.Elems = append(vec.Elems, value)
		}
	}
	return nil
}

// Ensuring interfaces in compile-time for DialogFilterVector.
var (
	_ bin.Encoder = &DialogFilterVector{}
	_ bin.Decoder = &DialogFilterVector{}
)
