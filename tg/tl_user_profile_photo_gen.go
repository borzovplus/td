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

// UserProfilePhotoEmpty represents TL type `userProfilePhotoEmpty#4f11bae1`.
// Profile photo has not been set, or was hidden.
//
// See https://core.telegram.org/constructor/userProfilePhotoEmpty for reference.
type UserProfilePhotoEmpty struct {
}

// UserProfilePhotoEmptyTypeID is TL type id of UserProfilePhotoEmpty.
const UserProfilePhotoEmptyTypeID = 0x4f11bae1

func (u *UserProfilePhotoEmpty) Zero() bool {
	if u == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (u *UserProfilePhotoEmpty) String() string {
	if u == nil {
		return "UserProfilePhotoEmpty(nil)"
	}
	type Alias UserProfilePhotoEmpty
	return fmt.Sprintf("UserProfilePhotoEmpty%+v", Alias(*u))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (u *UserProfilePhotoEmpty) TypeID() uint32 {
	return UserProfilePhotoEmptyTypeID
}

// TypeName returns name of type in TL schema.
func (u *UserProfilePhotoEmpty) TypeName() string {
	return "userProfilePhotoEmpty"
}

// Encode implements bin.Encoder.
func (u *UserProfilePhotoEmpty) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode userProfilePhotoEmpty#4f11bae1 as nil")
	}
	b.PutID(UserProfilePhotoEmptyTypeID)
	return nil
}

// Decode implements bin.Decoder.
func (u *UserProfilePhotoEmpty) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode userProfilePhotoEmpty#4f11bae1 to nil")
	}
	if err := b.ConsumeID(UserProfilePhotoEmptyTypeID); err != nil {
		return fmt.Errorf("unable to decode userProfilePhotoEmpty#4f11bae1: %w", err)
	}
	return nil
}

// construct implements constructor of UserProfilePhotoClass.
func (u UserProfilePhotoEmpty) construct() UserProfilePhotoClass { return &u }

// Ensuring interfaces in compile-time for UserProfilePhotoEmpty.
var (
	_ bin.Encoder = &UserProfilePhotoEmpty{}
	_ bin.Decoder = &UserProfilePhotoEmpty{}

	_ UserProfilePhotoClass = &UserProfilePhotoEmpty{}
)

// UserProfilePhoto represents TL type `userProfilePhoto#69d3ab26`.
// User profile photo.
//
// See https://core.telegram.org/constructor/userProfilePhoto for reference.
type UserProfilePhoto struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields `tl:"flags"`
	// Whether an animated profile picture¹ is available for this user
	//
	// Links:
	//  1) https://core.telegram.org/api/files#animated-profile-pictures
	HasVideo bool `tl:"has_video"`
	// Identifier of the respective photoParameter added in Layer 2¹
	//
	// Links:
	//  1) https://core.telegram.org/api/layers#layer-2
	PhotoID int64 `tl:"photo_id"`
	// Location of the file, corresponding to the small profile photo thumbnail
	PhotoSmall FileLocationToBeDeprecated `tl:"photo_small"`
	// Location of the file, corresponding to the big profile photo thumbnail
	PhotoBig FileLocationToBeDeprecated `tl:"photo_big"`
	// DC ID where the photo is stored
	DCID int `tl:"dc_id"`
}

// UserProfilePhotoTypeID is TL type id of UserProfilePhoto.
const UserProfilePhotoTypeID = 0x69d3ab26

func (u *UserProfilePhoto) Zero() bool {
	if u == nil {
		return true
	}
	if !(u.Flags.Zero()) {
		return false
	}
	if !(u.HasVideo == false) {
		return false
	}
	if !(u.PhotoID == 0) {
		return false
	}
	if !(u.PhotoSmall.Zero()) {
		return false
	}
	if !(u.PhotoBig.Zero()) {
		return false
	}
	if !(u.DCID == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (u *UserProfilePhoto) String() string {
	if u == nil {
		return "UserProfilePhoto(nil)"
	}
	type Alias UserProfilePhoto
	return fmt.Sprintf("UserProfilePhoto%+v", Alias(*u))
}

// FillFrom fills UserProfilePhoto from given interface.
func (u *UserProfilePhoto) FillFrom(from interface {
	GetHasVideo() (value bool)
	GetPhotoID() (value int64)
	GetPhotoSmall() (value FileLocationToBeDeprecated)
	GetPhotoBig() (value FileLocationToBeDeprecated)
	GetDCID() (value int)
}) {
	u.HasVideo = from.GetHasVideo()
	u.PhotoID = from.GetPhotoID()
	u.PhotoSmall = from.GetPhotoSmall()
	u.PhotoBig = from.GetPhotoBig()
	u.DCID = from.GetDCID()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (u *UserProfilePhoto) TypeID() uint32 {
	return UserProfilePhotoTypeID
}

// TypeName returns name of type in TL schema.
func (u *UserProfilePhoto) TypeName() string {
	return "userProfilePhoto"
}

// Encode implements bin.Encoder.
func (u *UserProfilePhoto) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode userProfilePhoto#69d3ab26 as nil")
	}
	b.PutID(UserProfilePhotoTypeID)
	if !(u.HasVideo == false) {
		u.Flags.Set(0)
	}
	if err := u.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode userProfilePhoto#69d3ab26: field flags: %w", err)
	}
	b.PutLong(u.PhotoID)
	if err := u.PhotoSmall.Encode(b); err != nil {
		return fmt.Errorf("unable to encode userProfilePhoto#69d3ab26: field photo_small: %w", err)
	}
	if err := u.PhotoBig.Encode(b); err != nil {
		return fmt.Errorf("unable to encode userProfilePhoto#69d3ab26: field photo_big: %w", err)
	}
	b.PutInt(u.DCID)
	return nil
}

// SetHasVideo sets value of HasVideo conditional field.
func (u *UserProfilePhoto) SetHasVideo(value bool) {
	if value {
		u.Flags.Set(0)
		u.HasVideo = true
	} else {
		u.Flags.Unset(0)
		u.HasVideo = false
	}
}

// GetHasVideo returns value of HasVideo conditional field.
func (u *UserProfilePhoto) GetHasVideo() (value bool) {
	return u.Flags.Has(0)
}

// GetPhotoID returns value of PhotoID field.
func (u *UserProfilePhoto) GetPhotoID() (value int64) {
	return u.PhotoID
}

// GetPhotoSmall returns value of PhotoSmall field.
func (u *UserProfilePhoto) GetPhotoSmall() (value FileLocationToBeDeprecated) {
	return u.PhotoSmall
}

// GetPhotoBig returns value of PhotoBig field.
func (u *UserProfilePhoto) GetPhotoBig() (value FileLocationToBeDeprecated) {
	return u.PhotoBig
}

// GetDCID returns value of DCID field.
func (u *UserProfilePhoto) GetDCID() (value int) {
	return u.DCID
}

// Decode implements bin.Decoder.
func (u *UserProfilePhoto) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode userProfilePhoto#69d3ab26 to nil")
	}
	if err := b.ConsumeID(UserProfilePhotoTypeID); err != nil {
		return fmt.Errorf("unable to decode userProfilePhoto#69d3ab26: %w", err)
	}
	{
		if err := u.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode userProfilePhoto#69d3ab26: field flags: %w", err)
		}
	}
	u.HasVideo = u.Flags.Has(0)
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode userProfilePhoto#69d3ab26: field photo_id: %w", err)
		}
		u.PhotoID = value
	}
	{
		if err := u.PhotoSmall.Decode(b); err != nil {
			return fmt.Errorf("unable to decode userProfilePhoto#69d3ab26: field photo_small: %w", err)
		}
	}
	{
		if err := u.PhotoBig.Decode(b); err != nil {
			return fmt.Errorf("unable to decode userProfilePhoto#69d3ab26: field photo_big: %w", err)
		}
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode userProfilePhoto#69d3ab26: field dc_id: %w", err)
		}
		u.DCID = value
	}
	return nil
}

// construct implements constructor of UserProfilePhotoClass.
func (u UserProfilePhoto) construct() UserProfilePhotoClass { return &u }

// Ensuring interfaces in compile-time for UserProfilePhoto.
var (
	_ bin.Encoder = &UserProfilePhoto{}
	_ bin.Decoder = &UserProfilePhoto{}

	_ UserProfilePhotoClass = &UserProfilePhoto{}
)

// UserProfilePhotoClass represents UserProfilePhoto generic type.
//
// See https://core.telegram.org/type/UserProfilePhoto for reference.
//
// Example:
//  g, err := tg.DecodeUserProfilePhoto(buf)
//  if err != nil {
//      panic(err)
//  }
//  switch v := g.(type) {
//  case *tg.UserProfilePhotoEmpty: // userProfilePhotoEmpty#4f11bae1
//  case *tg.UserProfilePhoto: // userProfilePhoto#69d3ab26
//  default: panic(v)
//  }
type UserProfilePhotoClass interface {
	bin.Encoder
	bin.Decoder
	construct() UserProfilePhotoClass

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

	// AsNotEmpty tries to map UserProfilePhotoClass to UserProfilePhoto.
	AsNotEmpty() (*UserProfilePhoto, bool)
}

// AsNotEmpty tries to map UserProfilePhotoEmpty to UserProfilePhoto.
func (u *UserProfilePhotoEmpty) AsNotEmpty() (*UserProfilePhoto, bool) {
	return nil, false
}

// AsNotEmpty tries to map UserProfilePhoto to UserProfilePhoto.
func (u *UserProfilePhoto) AsNotEmpty() (*UserProfilePhoto, bool) {
	return u, true
}

// DecodeUserProfilePhoto implements binary de-serialization for UserProfilePhotoClass.
func DecodeUserProfilePhoto(buf *bin.Buffer) (UserProfilePhotoClass, error) {
	id, err := buf.PeekID()
	if err != nil {
		return nil, err
	}
	switch id {
	case UserProfilePhotoEmptyTypeID:
		// Decoding userProfilePhotoEmpty#4f11bae1.
		v := UserProfilePhotoEmpty{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UserProfilePhotoClass: %w", err)
		}
		return &v, nil
	case UserProfilePhotoTypeID:
		// Decoding userProfilePhoto#69d3ab26.
		v := UserProfilePhoto{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UserProfilePhotoClass: %w", err)
		}
		return &v, nil
	default:
		return nil, fmt.Errorf("unable to decode UserProfilePhotoClass: %w", bin.NewUnexpectedID(id))
	}
}

// UserProfilePhoto boxes the UserProfilePhotoClass providing a helper.
type UserProfilePhotoBox struct {
	UserProfilePhoto UserProfilePhotoClass
}

// Decode implements bin.Decoder for UserProfilePhotoBox.
func (b *UserProfilePhotoBox) Decode(buf *bin.Buffer) error {
	if b == nil {
		return fmt.Errorf("unable to decode UserProfilePhotoBox to nil")
	}
	v, err := DecodeUserProfilePhoto(buf)
	if err != nil {
		return fmt.Errorf("unable to decode boxed value: %w", err)
	}
	b.UserProfilePhoto = v
	return nil
}

// Encode implements bin.Encode for UserProfilePhotoBox.
func (b *UserProfilePhotoBox) Encode(buf *bin.Buffer) error {
	if b == nil || b.UserProfilePhoto == nil {
		return fmt.Errorf("unable to encode UserProfilePhotoClass as nil")
	}
	return b.UserProfilePhoto.Encode(buf)
}

// UserProfilePhotoClassSlice is adapter for slice of UserProfilePhotoClass.
type UserProfilePhotoClassSlice []UserProfilePhotoClass

// AppendOnlyNotEmpty appends only NotEmpty constructors to
// given slice.
func (s UserProfilePhotoClassSlice) AppendOnlyNotEmpty(to []*UserProfilePhoto) []*UserProfilePhoto {
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
func (s UserProfilePhotoClassSlice) AsNotEmpty() (to []*UserProfilePhoto) {
	return s.AppendOnlyNotEmpty(to)
}

// FirstAsNotEmpty returns first element of slice (if exists).
func (s UserProfilePhotoClassSlice) FirstAsNotEmpty() (v *UserProfilePhoto, ok bool) {
	value, ok := s.First()
	if !ok {
		return
	}
	return value.AsNotEmpty()
}

// LastAsNotEmpty returns last element of slice (if exists).
func (s UserProfilePhotoClassSlice) LastAsNotEmpty() (v *UserProfilePhoto, ok bool) {
	value, ok := s.Last()
	if !ok {
		return
	}
	return value.AsNotEmpty()
}

// PopFirstAsNotEmpty returns element of slice (if exists).
func (s *UserProfilePhotoClassSlice) PopFirstAsNotEmpty() (v *UserProfilePhoto, ok bool) {
	value, ok := s.PopFirst()
	if !ok {
		return
	}
	return value.AsNotEmpty()
}

// PopAsNotEmpty returns element of slice (if exists).
func (s *UserProfilePhotoClassSlice) PopAsNotEmpty() (v *UserProfilePhoto, ok bool) {
	value, ok := s.Pop()
	if !ok {
		return
	}
	return value.AsNotEmpty()
}

// First returns first element of slice (if exists).
func (s UserProfilePhotoClassSlice) First() (v UserProfilePhotoClass, ok bool) {
	if len(s) < 1 {
		return
	}
	return s[0], true
}

// Last returns last element of slice (if exists).
func (s UserProfilePhotoClassSlice) Last() (v UserProfilePhotoClass, ok bool) {
	if len(s) < 1 {
		return
	}
	return s[len(s)-1], true
}

// PopFirst returns first element of slice (if exists) and deletes it.
func (s *UserProfilePhotoClassSlice) PopFirst() (v UserProfilePhotoClass, ok bool) {
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
func (s *UserProfilePhotoClassSlice) Pop() (v UserProfilePhotoClass, ok bool) {
	if s == nil || len(*s) < 1 {
		return
	}

	a := *s
	v = a[len(a)-1]
	a = a[:len(a)-1]
	*s = a

	return v, true
}
