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

// ChatPhotoEmpty represents TL type `chatPhotoEmpty#37c1011c`.
// Group photo is not set.
//
// See https://core.telegram.org/constructor/chatPhotoEmpty for reference.
type ChatPhotoEmpty struct {
}

// ChatPhotoEmptyTypeID is TL type id of ChatPhotoEmpty.
const ChatPhotoEmptyTypeID = 0x37c1011c

func (c *ChatPhotoEmpty) Zero() bool {
	if c == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (c *ChatPhotoEmpty) String() string {
	if c == nil {
		return "ChatPhotoEmpty(nil)"
	}
	type Alias ChatPhotoEmpty
	return fmt.Sprintf("ChatPhotoEmpty%+v", Alias(*c))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (c *ChatPhotoEmpty) TypeID() uint32 {
	return ChatPhotoEmptyTypeID
}

// TypeName returns name of type in TL schema.
func (c *ChatPhotoEmpty) TypeName() string {
	return "chatPhotoEmpty"
}

// Encode implements bin.Encoder.
func (c *ChatPhotoEmpty) Encode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode chatPhotoEmpty#37c1011c as nil")
	}
	b.PutID(ChatPhotoEmptyTypeID)
	return nil
}

// Decode implements bin.Decoder.
func (c *ChatPhotoEmpty) Decode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode chatPhotoEmpty#37c1011c to nil")
	}
	if err := b.ConsumeID(ChatPhotoEmptyTypeID); err != nil {
		return fmt.Errorf("unable to decode chatPhotoEmpty#37c1011c: %w", err)
	}
	return nil
}

// construct implements constructor of ChatPhotoClass.
func (c ChatPhotoEmpty) construct() ChatPhotoClass { return &c }

// Ensuring interfaces in compile-time for ChatPhotoEmpty.
var (
	_ bin.Encoder = &ChatPhotoEmpty{}
	_ bin.Decoder = &ChatPhotoEmpty{}

	_ ChatPhotoClass = &ChatPhotoEmpty{}
)

// ChatPhoto represents TL type `chatPhoto#d20b9f3c`.
// Group profile photo.
//
// See https://core.telegram.org/constructor/chatPhoto for reference.
type ChatPhoto struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields `tl:"flags"`
	// Whether the user has an animated profile picture
	HasVideo bool `tl:"has_video"`
	// Location of the file corresponding to the small thumbnail for group profile photo
	PhotoSmall FileLocationToBeDeprecated `tl:"photo_small"`
	// Location of the file corresponding to the small thumbnail for group profile photo
	PhotoBig FileLocationToBeDeprecated `tl:"photo_big"`
	// DC where this photo is stored
	DCID int `tl:"dc_id"`
}

// ChatPhotoTypeID is TL type id of ChatPhoto.
const ChatPhotoTypeID = 0xd20b9f3c

func (c *ChatPhoto) Zero() bool {
	if c == nil {
		return true
	}
	if !(c.Flags.Zero()) {
		return false
	}
	if !(c.HasVideo == false) {
		return false
	}
	if !(c.PhotoSmall.Zero()) {
		return false
	}
	if !(c.PhotoBig.Zero()) {
		return false
	}
	if !(c.DCID == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (c *ChatPhoto) String() string {
	if c == nil {
		return "ChatPhoto(nil)"
	}
	type Alias ChatPhoto
	return fmt.Sprintf("ChatPhoto%+v", Alias(*c))
}

// FillFrom fills ChatPhoto from given interface.
func (c *ChatPhoto) FillFrom(from interface {
	GetHasVideo() (value bool)
	GetPhotoSmall() (value FileLocationToBeDeprecated)
	GetPhotoBig() (value FileLocationToBeDeprecated)
	GetDCID() (value int)
}) {
	c.HasVideo = from.GetHasVideo()
	c.PhotoSmall = from.GetPhotoSmall()
	c.PhotoBig = from.GetPhotoBig()
	c.DCID = from.GetDCID()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (c *ChatPhoto) TypeID() uint32 {
	return ChatPhotoTypeID
}

// TypeName returns name of type in TL schema.
func (c *ChatPhoto) TypeName() string {
	return "chatPhoto"
}

// Encode implements bin.Encoder.
func (c *ChatPhoto) Encode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't encode chatPhoto#d20b9f3c as nil")
	}
	b.PutID(ChatPhotoTypeID)
	if !(c.HasVideo == false) {
		c.Flags.Set(0)
	}
	if err := c.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode chatPhoto#d20b9f3c: field flags: %w", err)
	}
	if err := c.PhotoSmall.Encode(b); err != nil {
		return fmt.Errorf("unable to encode chatPhoto#d20b9f3c: field photo_small: %w", err)
	}
	if err := c.PhotoBig.Encode(b); err != nil {
		return fmt.Errorf("unable to encode chatPhoto#d20b9f3c: field photo_big: %w", err)
	}
	b.PutInt(c.DCID)
	return nil
}

// SetHasVideo sets value of HasVideo conditional field.
func (c *ChatPhoto) SetHasVideo(value bool) {
	if value {
		c.Flags.Set(0)
		c.HasVideo = true
	} else {
		c.Flags.Unset(0)
		c.HasVideo = false
	}
}

// GetHasVideo returns value of HasVideo conditional field.
func (c *ChatPhoto) GetHasVideo() (value bool) {
	return c.Flags.Has(0)
}

// GetPhotoSmall returns value of PhotoSmall field.
func (c *ChatPhoto) GetPhotoSmall() (value FileLocationToBeDeprecated) {
	return c.PhotoSmall
}

// GetPhotoBig returns value of PhotoBig field.
func (c *ChatPhoto) GetPhotoBig() (value FileLocationToBeDeprecated) {
	return c.PhotoBig
}

// GetDCID returns value of DCID field.
func (c *ChatPhoto) GetDCID() (value int) {
	return c.DCID
}

// Decode implements bin.Decoder.
func (c *ChatPhoto) Decode(b *bin.Buffer) error {
	if c == nil {
		return fmt.Errorf("can't decode chatPhoto#d20b9f3c to nil")
	}
	if err := b.ConsumeID(ChatPhotoTypeID); err != nil {
		return fmt.Errorf("unable to decode chatPhoto#d20b9f3c: %w", err)
	}
	{
		if err := c.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode chatPhoto#d20b9f3c: field flags: %w", err)
		}
	}
	c.HasVideo = c.Flags.Has(0)
	{
		if err := c.PhotoSmall.Decode(b); err != nil {
			return fmt.Errorf("unable to decode chatPhoto#d20b9f3c: field photo_small: %w", err)
		}
	}
	{
		if err := c.PhotoBig.Decode(b); err != nil {
			return fmt.Errorf("unable to decode chatPhoto#d20b9f3c: field photo_big: %w", err)
		}
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode chatPhoto#d20b9f3c: field dc_id: %w", err)
		}
		c.DCID = value
	}
	return nil
}

// construct implements constructor of ChatPhotoClass.
func (c ChatPhoto) construct() ChatPhotoClass { return &c }

// Ensuring interfaces in compile-time for ChatPhoto.
var (
	_ bin.Encoder = &ChatPhoto{}
	_ bin.Decoder = &ChatPhoto{}

	_ ChatPhotoClass = &ChatPhoto{}
)

// ChatPhotoClass represents ChatPhoto generic type.
//
// See https://core.telegram.org/type/ChatPhoto for reference.
//
// Example:
//  g, err := tg.DecodeChatPhoto(buf)
//  if err != nil {
//      panic(err)
//  }
//  switch v := g.(type) {
//  case *tg.ChatPhotoEmpty: // chatPhotoEmpty#37c1011c
//  case *tg.ChatPhoto: // chatPhoto#d20b9f3c
//  default: panic(v)
//  }
type ChatPhotoClass interface {
	bin.Encoder
	bin.Decoder
	construct() ChatPhotoClass

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

	// AsNotEmpty tries to map ChatPhotoClass to ChatPhoto.
	AsNotEmpty() (*ChatPhoto, bool)
}

// AsNotEmpty tries to map ChatPhotoEmpty to ChatPhoto.
func (c *ChatPhotoEmpty) AsNotEmpty() (*ChatPhoto, bool) {
	return nil, false
}

// AsNotEmpty tries to map ChatPhoto to ChatPhoto.
func (c *ChatPhoto) AsNotEmpty() (*ChatPhoto, bool) {
	return c, true
}

// DecodeChatPhoto implements binary de-serialization for ChatPhotoClass.
func DecodeChatPhoto(buf *bin.Buffer) (ChatPhotoClass, error) {
	id, err := buf.PeekID()
	if err != nil {
		return nil, err
	}
	switch id {
	case ChatPhotoEmptyTypeID:
		// Decoding chatPhotoEmpty#37c1011c.
		v := ChatPhotoEmpty{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode ChatPhotoClass: %w", err)
		}
		return &v, nil
	case ChatPhotoTypeID:
		// Decoding chatPhoto#d20b9f3c.
		v := ChatPhoto{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode ChatPhotoClass: %w", err)
		}
		return &v, nil
	default:
		return nil, fmt.Errorf("unable to decode ChatPhotoClass: %w", bin.NewUnexpectedID(id))
	}
}

// ChatPhoto boxes the ChatPhotoClass providing a helper.
type ChatPhotoBox struct {
	ChatPhoto ChatPhotoClass
}

// Decode implements bin.Decoder for ChatPhotoBox.
func (b *ChatPhotoBox) Decode(buf *bin.Buffer) error {
	if b == nil {
		return fmt.Errorf("unable to decode ChatPhotoBox to nil")
	}
	v, err := DecodeChatPhoto(buf)
	if err != nil {
		return fmt.Errorf("unable to decode boxed value: %w", err)
	}
	b.ChatPhoto = v
	return nil
}

// Encode implements bin.Encode for ChatPhotoBox.
func (b *ChatPhotoBox) Encode(buf *bin.Buffer) error {
	if b == nil || b.ChatPhoto == nil {
		return fmt.Errorf("unable to encode ChatPhotoClass as nil")
	}
	return b.ChatPhoto.Encode(buf)
}

// ChatPhotoClassSlice is adapter for slice of ChatPhotoClass.
type ChatPhotoClassSlice []ChatPhotoClass

// AppendOnlyNotEmpty appends only NotEmpty constructors to
// given slice.
func (s ChatPhotoClassSlice) AppendOnlyNotEmpty(to []*ChatPhoto) []*ChatPhoto {
	for _, elem := range s {
		value, ok := elem.AsNotEmpty()
		if !ok {
			continue
		}
		to = append(to, value)
	}

	return to
}

// AsNotEmpty returns copy with only NotEmpty constructors.
func (s ChatPhotoClassSlice) AsNotEmpty() (to []*ChatPhoto) {
	return s.AppendOnlyNotEmpty(to)
}

// FirstAsNotEmpty returns first element of slice (if exists).
func (s ChatPhotoClassSlice) FirstAsNotEmpty() (v *ChatPhoto, ok bool) {
	value, ok := s.First()
	if !ok {
		return
	}
	return value.AsNotEmpty()
}

// LastAsNotEmpty returns last element of slice (if exists).
func (s ChatPhotoClassSlice) LastAsNotEmpty() (v *ChatPhoto, ok bool) {
	value, ok := s.Last()
	if !ok {
		return
	}
	return value.AsNotEmpty()
}

// PopFirstAsNotEmpty returns element of slice (if exists).
func (s *ChatPhotoClassSlice) PopFirstAsNotEmpty() (v *ChatPhoto, ok bool) {
	value, ok := s.PopFirst()
	if !ok {
		return
	}
	return value.AsNotEmpty()
}

// PopAsNotEmpty returns element of slice (if exists).
func (s *ChatPhotoClassSlice) PopAsNotEmpty() (v *ChatPhoto, ok bool) {
	value, ok := s.Pop()
	if !ok {
		return
	}
	return value.AsNotEmpty()
}

// First returns first element of slice (if exists).
func (s ChatPhotoClassSlice) First() (v ChatPhotoClass, ok bool) {
	if len(s) < 1 {
		return
	}
	return s[0], true
}

// Last returns last element of slice (if exists).
func (s ChatPhotoClassSlice) Last() (v ChatPhotoClass, ok bool) {
	if len(s) < 1 {
		return
	}
	return s[len(s)-1], true
}

// PopFirst returns first element of slice (if exists) and deletes it.
func (s *ChatPhotoClassSlice) PopFirst() (v ChatPhotoClass, ok bool) {
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
func (s *ChatPhotoClassSlice) Pop() (v ChatPhotoClass, ok bool) {
	if s == nil || len(*s) < 1 {
		return
	}

	a := *s
	v = a[len(a)-1]
	a = a[:len(a)-1]
	*s = a

	return v, true
}
