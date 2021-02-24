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

// LangpackGetLanguagesRequest represents TL type `langpack.getLanguages#42c6978f`.
// Get information about all languages in a localization pack
//
// See https://core.telegram.org/method/langpack.getLanguages for reference.
type LangpackGetLanguagesRequest struct {
	// Language pack
	LangPack string `tl:"lang_pack"`
}

// LangpackGetLanguagesRequestTypeID is TL type id of LangpackGetLanguagesRequest.
const LangpackGetLanguagesRequestTypeID = 0x42c6978f

func (g *LangpackGetLanguagesRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.LangPack == "") {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *LangpackGetLanguagesRequest) String() string {
	if g == nil {
		return "LangpackGetLanguagesRequest(nil)"
	}
	type Alias LangpackGetLanguagesRequest
	return fmt.Sprintf("LangpackGetLanguagesRequest%+v", Alias(*g))
}

// FillFrom fills LangpackGetLanguagesRequest from given interface.
func (g *LangpackGetLanguagesRequest) FillFrom(from interface {
	GetLangPack() (value string)
}) {
	g.LangPack = from.GetLangPack()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (g *LangpackGetLanguagesRequest) TypeID() uint32 {
	return LangpackGetLanguagesRequestTypeID
}

// TypeName returns name of type in TL schema.
func (g *LangpackGetLanguagesRequest) TypeName() string {
	return "langpack.getLanguages"
}

// Encode implements bin.Encoder.
func (g *LangpackGetLanguagesRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode langpack.getLanguages#42c6978f as nil")
	}
	b.PutID(LangpackGetLanguagesRequestTypeID)
	b.PutString(g.LangPack)
	return nil
}

// GetLangPack returns value of LangPack field.
func (g *LangpackGetLanguagesRequest) GetLangPack() (value string) {
	return g.LangPack
}

// Decode implements bin.Decoder.
func (g *LangpackGetLanguagesRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode langpack.getLanguages#42c6978f to nil")
	}
	if err := b.ConsumeID(LangpackGetLanguagesRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode langpack.getLanguages#42c6978f: %w", err)
	}
	{
		value, err := b.String()
		if err != nil {
			return fmt.Errorf("unable to decode langpack.getLanguages#42c6978f: field lang_pack: %w", err)
		}
		g.LangPack = value
	}
	return nil
}

// Ensuring interfaces in compile-time for LangpackGetLanguagesRequest.
var (
	_ bin.Encoder = &LangpackGetLanguagesRequest{}
	_ bin.Decoder = &LangpackGetLanguagesRequest{}
)

// LangpackGetLanguages invokes method langpack.getLanguages#42c6978f returning error if any.
// Get information about all languages in a localization pack
//
// Possible errors:
//  400 LANG_PACK_INVALID: The provided language pack is invalid
//
// See https://core.telegram.org/method/langpack.getLanguages for reference.
func (c *Client) LangpackGetLanguages(ctx context.Context, langpack string) ([]LangPackLanguage, error) {
	var result LangPackLanguageVector

	request := &LangpackGetLanguagesRequest{
		LangPack: langpack,
	}
	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return result.Elems, nil
}
