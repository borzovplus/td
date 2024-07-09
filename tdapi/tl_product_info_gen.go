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

// ProductInfo represents TL type `productInfo#87e47ca4`.
type ProductInfo struct {
	// Product title
	Title string
	// Contains information about a product that can be paid with invoice
	Description FormattedText
	// Product photo; may be null
	Photo Photo
}

// ProductInfoTypeID is TL type id of ProductInfo.
const ProductInfoTypeID = 0x87e47ca4

// Ensuring interfaces in compile-time for ProductInfo.
var (
	_ bin.Encoder     = &ProductInfo{}
	_ bin.Decoder     = &ProductInfo{}
	_ bin.BareEncoder = &ProductInfo{}
	_ bin.BareDecoder = &ProductInfo{}
)

func (p *ProductInfo) Zero() bool {
	if p == nil {
		return true
	}
	if !(p.Title == "") {
		return false
	}
	if !(p.Description.Zero()) {
		return false
	}
	if !(p.Photo.Zero()) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (p *ProductInfo) String() string {
	if p == nil {
		return "ProductInfo(nil)"
	}
	type Alias ProductInfo
	return fmt.Sprintf("ProductInfo%+v", Alias(*p))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (*ProductInfo) TypeID() uint32 {
	return ProductInfoTypeID
}

// TypeName returns name of type in TL schema.
func (*ProductInfo) TypeName() string {
	return "productInfo"
}

// TypeInfo returns info about TL type.
func (p *ProductInfo) TypeInfo() tdp.Type {
	typ := tdp.Type{
		Name: "productInfo",
		ID:   ProductInfoTypeID,
	}
	if p == nil {
		typ.Null = true
		return typ
	}
	typ.Fields = []tdp.Field{
		{
			Name:       "Title",
			SchemaName: "title",
		},
		{
			Name:       "Description",
			SchemaName: "description",
		},
		{
			Name:       "Photo",
			SchemaName: "photo",
		},
	}
	return typ
}

// Encode implements bin.Encoder.
func (p *ProductInfo) Encode(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't encode productInfo#87e47ca4 as nil")
	}
	b.PutID(ProductInfoTypeID)
	return p.EncodeBare(b)
}

// EncodeBare implements bin.BareEncoder.
func (p *ProductInfo) EncodeBare(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't encode productInfo#87e47ca4 as nil")
	}
	b.PutString(p.Title)
	if err := p.Description.Encode(b); err != nil {
		return fmt.Errorf("unable to encode productInfo#87e47ca4: field description: %w", err)
	}
	if err := p.Photo.Encode(b); err != nil {
		return fmt.Errorf("unable to encode productInfo#87e47ca4: field photo: %w", err)
	}
	return nil
}

// Decode implements bin.Decoder.
func (p *ProductInfo) Decode(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't decode productInfo#87e47ca4 to nil")
	}
	if err := b.ConsumeID(ProductInfoTypeID); err != nil {
		return fmt.Errorf("unable to decode productInfo#87e47ca4: %w", err)
	}
	return p.DecodeBare(b)
}

// DecodeBare implements bin.BareDecoder.
func (p *ProductInfo) DecodeBare(b *bin.Buffer) error {
	if p == nil {
		return fmt.Errorf("can't decode productInfo#87e47ca4 to nil")
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode productInfo#87e47ca4: field title: %w", err)
		}
		p.Title = value
	}
	{
		if err := p.Description.Decode(b); err != nil {
			return fmt.Errorf("unable to decode productInfo#87e47ca4: field description: %w", err)
		}
	}
	{
		if err := p.Photo.Decode(b); err != nil {
			return fmt.Errorf("unable to decode productInfo#87e47ca4: field photo: %w", err)
		}
	}
	return nil
}

// EncodeTDLibJSON implements tdjson.TDLibEncoder.
func (p *ProductInfo) EncodeTDLibJSON(b tdjson.Encoder) error {
	if p == nil {
		return fmt.Errorf("can't encode productInfo#87e47ca4 as nil")
	}
	b.ObjStart()
	b.PutID("productInfo")
	b.Comma()
	b.FieldStart("title")
	b.PutString(p.Title)
	b.Comma()
	b.FieldStart("description")
	if err := p.Description.EncodeTDLibJSON(b); err != nil {
		return fmt.Errorf("unable to encode productInfo#87e47ca4: field description: %w", err)
	}
	b.Comma()
	b.FieldStart("photo")
	if err := p.Photo.EncodeTDLibJSON(b); err != nil {
		return fmt.Errorf("unable to encode productInfo#87e47ca4: field photo: %w", err)
	}
	b.Comma()
	b.StripComma()
	b.ObjEnd()
	return nil
}

// DecodeTDLibJSON implements tdjson.TDLibDecoder.
func (p *ProductInfo) DecodeTDLibJSON(b tdjson.Decoder) error {
	if p == nil {
		return fmt.Errorf("can't decode productInfo#87e47ca4 to nil")
	}

	return b.Obj(func(b tdjson.Decoder, key []byte) error {
		switch string(key) {
		case tdjson.TypeField:
			if err := b.ConsumeID("productInfo"); err != nil {
				return fmt.Errorf("unable to decode productInfo#87e47ca4: %w", err)
			}
		case "title":
			value, err := b.String()
			if err != nil {
				return fmt.Errorf("unable to decode productInfo#87e47ca4: field title: %w", err)
			}
			p.Title = value
		case "description":
			if err := p.Description.DecodeTDLibJSON(b); err != nil {
				return fmt.Errorf("unable to decode productInfo#87e47ca4: field description: %w", err)
			}
		case "photo":
			if err := p.Photo.DecodeTDLibJSON(b); err != nil {
				return fmt.Errorf("unable to decode productInfo#87e47ca4: field photo: %w", err)
			}
		default:
			return b.Skip()
		}
		return nil
	})
}

// GetTitle returns value of Title field.
func (p *ProductInfo) GetTitle() (value string) {
	if p == nil {
		return
	}
	return p.Title
}

// GetDescription returns value of Description field.
func (p *ProductInfo) GetDescription() (value FormattedText) {
	if p == nil {
		return
	}
	return p.Description
}

// GetPhoto returns value of Photo field.
func (p *ProductInfo) GetPhoto() (value Photo) {
	if p == nil {
		return
	}
	return p.Photo
}