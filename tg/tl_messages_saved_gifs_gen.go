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

// MessagesSavedGifsNotModified represents TL type `messages.savedGifsNotModified#e8025ca2`.
// No new saved gifs were found
//
// See https://core.telegram.org/constructor/messages.savedGifsNotModified for reference.
type MessagesSavedGifsNotModified struct {
}

// MessagesSavedGifsNotModifiedTypeID is TL type id of MessagesSavedGifsNotModified.
const MessagesSavedGifsNotModifiedTypeID = 0xe8025ca2

func (s *MessagesSavedGifsNotModified) Zero() bool {
	if s == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (s *MessagesSavedGifsNotModified) String() string {
	if s == nil {
		return "MessagesSavedGifsNotModified(nil)"
	}
	type Alias MessagesSavedGifsNotModified
	return fmt.Sprintf("MessagesSavedGifsNotModified%+v", Alias(*s))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (s *MessagesSavedGifsNotModified) TypeID() uint32 {
	return MessagesSavedGifsNotModifiedTypeID
}

// TypeName returns name of type in TL schema.
func (s *MessagesSavedGifsNotModified) TypeName() string {
	return "messages.savedGifsNotModified"
}

// Encode implements bin.Encoder.
func (s *MessagesSavedGifsNotModified) Encode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode messages.savedGifsNotModified#e8025ca2 as nil")
	}
	b.PutID(MessagesSavedGifsNotModifiedTypeID)
	return nil
}

// Decode implements bin.Decoder.
func (s *MessagesSavedGifsNotModified) Decode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode messages.savedGifsNotModified#e8025ca2 to nil")
	}
	if err := b.ConsumeID(MessagesSavedGifsNotModifiedTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.savedGifsNotModified#e8025ca2: %w", err)
	}
	return nil
}

// construct implements constructor of MessagesSavedGifsClass.
func (s MessagesSavedGifsNotModified) construct() MessagesSavedGifsClass { return &s }

// Ensuring interfaces in compile-time for MessagesSavedGifsNotModified.
var (
	_ bin.Encoder = &MessagesSavedGifsNotModified{}
	_ bin.Decoder = &MessagesSavedGifsNotModified{}

	_ MessagesSavedGifsClass = &MessagesSavedGifsNotModified{}
)

// MessagesSavedGifs represents TL type `messages.savedGifs#2e0709a5`.
// Saved gifs
//
// See https://core.telegram.org/constructor/messages.savedGifs for reference.
type MessagesSavedGifs struct {
	// Hash for pagination, for more info click here¹
	//
	// Links:
	//  1) https://core.telegram.org/api/offsets#hash-generation
	Hash int `tl:"hash"`
	// List of saved gifs
	Gifs []DocumentClass `tl:"gifs"`
}

// MessagesSavedGifsTypeID is TL type id of MessagesSavedGifs.
const MessagesSavedGifsTypeID = 0x2e0709a5

func (s *MessagesSavedGifs) Zero() bool {
	if s == nil {
		return true
	}
	if !(s.Hash == 0) {
		return false
	}
	if !(s.Gifs == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (s *MessagesSavedGifs) String() string {
	if s == nil {
		return "MessagesSavedGifs(nil)"
	}
	type Alias MessagesSavedGifs
	return fmt.Sprintf("MessagesSavedGifs%+v", Alias(*s))
}

// FillFrom fills MessagesSavedGifs from given interface.
func (s *MessagesSavedGifs) FillFrom(from interface {
	GetHash() (value int)
	GetGifs() (value []DocumentClass)
}) {
	s.Hash = from.GetHash()
	s.Gifs = from.GetGifs()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (s *MessagesSavedGifs) TypeID() uint32 {
	return MessagesSavedGifsTypeID
}

// TypeName returns name of type in TL schema.
func (s *MessagesSavedGifs) TypeName() string {
	return "messages.savedGifs"
}

// Encode implements bin.Encoder.
func (s *MessagesSavedGifs) Encode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode messages.savedGifs#2e0709a5 as nil")
	}
	b.PutID(MessagesSavedGifsTypeID)
	b.PutInt(s.Hash)
	b.PutVectorHeader(len(s.Gifs))
	for idx, v := range s.Gifs {
		if v == nil {
			return fmt.Errorf("unable to encode messages.savedGifs#2e0709a5: field gifs element with index %d is nil", idx)
		}
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode messages.savedGifs#2e0709a5: field gifs element with index %d: %w", idx, err)
		}
	}
	return nil
}

// GetHash returns value of Hash field.
func (s *MessagesSavedGifs) GetHash() (value int) {
	return s.Hash
}

// GetGifs returns value of Gifs field.
func (s *MessagesSavedGifs) GetGifs() (value []DocumentClass) {
	return s.Gifs
}

// MapGifs returns field Gifs wrapped in DocumentClassSlice helper.
func (s *MessagesSavedGifs) MapGifs() (value DocumentClassSlice) {
	return DocumentClassSlice(s.Gifs)
}

// Decode implements bin.Decoder.
func (s *MessagesSavedGifs) Decode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode messages.savedGifs#2e0709a5 to nil")
	}
	if err := b.ConsumeID(MessagesSavedGifsTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.savedGifs#2e0709a5: %w", err)
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.savedGifs#2e0709a5: field hash: %w", err)
		}
		s.Hash = value
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode messages.savedGifs#2e0709a5: field gifs: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			value, err := DecodeDocument(b)
			if err != nil {
				return fmt.Errorf("unable to decode messages.savedGifs#2e0709a5: field gifs: %w", err)
			}
			s.Gifs = append(s.Gifs, value)
		}
	}
	return nil
}

// construct implements constructor of MessagesSavedGifsClass.
func (s MessagesSavedGifs) construct() MessagesSavedGifsClass { return &s }

// Ensuring interfaces in compile-time for MessagesSavedGifs.
var (
	_ bin.Encoder = &MessagesSavedGifs{}
	_ bin.Decoder = &MessagesSavedGifs{}

	_ MessagesSavedGifsClass = &MessagesSavedGifs{}
)

// MessagesSavedGifsClass represents messages.SavedGifs generic type.
//
// See https://core.telegram.org/type/messages.SavedGifs for reference.
//
// Example:
//  g, err := tg.DecodeMessagesSavedGifs(buf)
//  if err != nil {
//      panic(err)
//  }
//  switch v := g.(type) {
//  case *tg.MessagesSavedGifsNotModified: // messages.savedGifsNotModified#e8025ca2
//  case *tg.MessagesSavedGifs: // messages.savedGifs#2e0709a5
//  default: panic(v)
//  }
type MessagesSavedGifsClass interface {
	bin.Encoder
	bin.Decoder
	construct() MessagesSavedGifsClass

	// TypeID returns type id in TL schema.
	//
	// See https://core.telegram.org/mtproto/TL-tl#remarks.
	TypeID() uint32
	// TypeName returns name of type in TL schema.
	TypeName() string
	// String implements fmt.Stringer.
	String() string
	// Zero returns true if current object has a zero value.
	Zero() bool

	// AsModified tries to map MessagesSavedGifsClass to MessagesSavedGifs.
	AsModified() (*MessagesSavedGifs, bool)
}

// AsModified tries to map MessagesSavedGifsNotModified to MessagesSavedGifs.
func (s *MessagesSavedGifsNotModified) AsModified() (*MessagesSavedGifs, bool) {
	return nil, false
}

// AsModified tries to map MessagesSavedGifs to MessagesSavedGifs.
func (s *MessagesSavedGifs) AsModified() (*MessagesSavedGifs, bool) {
	return s, true
}

// DecodeMessagesSavedGifs implements binary de-serialization for MessagesSavedGifsClass.
func DecodeMessagesSavedGifs(buf *bin.Buffer) (MessagesSavedGifsClass, error) {
	id, err := buf.PeekID()
	if err != nil {
		return nil, err
	}
	switch id {
	case MessagesSavedGifsNotModifiedTypeID:
		// Decoding messages.savedGifsNotModified#e8025ca2.
		v := MessagesSavedGifsNotModified{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode MessagesSavedGifsClass: %w", err)
		}
		return &v, nil
	case MessagesSavedGifsTypeID:
		// Decoding messages.savedGifs#2e0709a5.
		v := MessagesSavedGifs{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode MessagesSavedGifsClass: %w", err)
		}
		return &v, nil
	default:
		return nil, fmt.Errorf("unable to decode MessagesSavedGifsClass: %w", bin.NewUnexpectedID(id))
	}
}

// MessagesSavedGifs boxes the MessagesSavedGifsClass providing a helper.
type MessagesSavedGifsBox struct {
	SavedGifs MessagesSavedGifsClass
}

// Decode implements bin.Decoder for MessagesSavedGifsBox.
func (b *MessagesSavedGifsBox) Decode(buf *bin.Buffer) error {
	if b == nil {
		return fmt.Errorf("unable to decode MessagesSavedGifsBox to nil")
	}
	v, err := DecodeMessagesSavedGifs(buf)
	if err != nil {
		return fmt.Errorf("unable to decode boxed value: %w", err)
	}
	b.SavedGifs = v
	return nil
}

// Encode implements bin.Encode for MessagesSavedGifsBox.
func (b *MessagesSavedGifsBox) Encode(buf *bin.Buffer) error {
	if b == nil || b.SavedGifs == nil {
		return fmt.Errorf("unable to encode MessagesSavedGifsClass as nil")
	}
	return b.SavedGifs.Encode(buf)
}

// MessagesSavedGifsClassSlice is adapter for slice of MessagesSavedGifsClass.
type MessagesSavedGifsClassSlice []MessagesSavedGifsClass

// AppendOnlyModified appends only Modified constructors to
// given slice.
func (s MessagesSavedGifsClassSlice) AppendOnlyModified(to []*MessagesSavedGifs) []*MessagesSavedGifs {
	for _, elem := range s {
		value, ok := elem.AsModified()
		if !ok {
			continue
		}
		to = append(to, value)
	}

	return to
}

// AsModified returns copy with only Modified constructors.
func (s MessagesSavedGifsClassSlice) AsModified() (to []*MessagesSavedGifs) {
	return s.AppendOnlyModified(to)
}

// FirstAsModified returns first element of slice (if exists).
func (s MessagesSavedGifsClassSlice) FirstAsModified() (v *MessagesSavedGifs, ok bool) {
	value, ok := s.First()
	if !ok {
		return
	}
	return value.AsModified()
}

// LastAsModified returns last element of slice (if exists).
func (s MessagesSavedGifsClassSlice) LastAsModified() (v *MessagesSavedGifs, ok bool) {
	value, ok := s.Last()
	if !ok {
		return
	}
	return value.AsModified()
}

// PopFirstAsModified returns element of slice (if exists).
func (s *MessagesSavedGifsClassSlice) PopFirstAsModified() (v *MessagesSavedGifs, ok bool) {
	value, ok := s.PopFirst()
	if !ok {
		return
	}
	return value.AsModified()
}

// PopAsModified returns element of slice (if exists).
func (s *MessagesSavedGifsClassSlice) PopAsModified() (v *MessagesSavedGifs, ok bool) {
	value, ok := s.Pop()
	if !ok {
		return
	}
	return value.AsModified()
}

// First returns first element of slice (if exists).
func (s MessagesSavedGifsClassSlice) First() (v MessagesSavedGifsClass, ok bool) {
	if len(s) < 1 {
		return
	}
	return s[0], true
}

// Last returns last element of slice (if exists).
func (s MessagesSavedGifsClassSlice) Last() (v MessagesSavedGifsClass, ok bool) {
	if len(s) < 1 {
		return
	}
	return s[len(s)-1], true
}

// PopFirst returns first element of slice (if exists) and deletes it.
func (s *MessagesSavedGifsClassSlice) PopFirst() (v MessagesSavedGifsClass, ok bool) {
	if s == nil || len(*s) < 1 {
		return
	}

	a := *s
	v = a[0]

	// Delete by index from SliceTricks.
	copy(a[0:], a[1:])
	a[len(a)-1] = nil
	a = a[:len(a)-1]
	*s = a

	return v, true
}

// Pop returns last element of slice (if exists) and deletes it.
func (s *MessagesSavedGifsClassSlice) Pop() (v MessagesSavedGifsClass, ok bool) {
	if s == nil || len(*s) < 1 {
		return
	}

	a := *s
	v = a[len(a)-1]
	a = a[:len(a)-1]
	*s = a

	return v, true
}
