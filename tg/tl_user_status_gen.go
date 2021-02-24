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

// UserStatusEmpty represents TL type `userStatusEmpty#9d05049`.
// User status has not been set yet.
//
// See https://core.telegram.org/constructor/userStatusEmpty for reference.
type UserStatusEmpty struct {
}

// UserStatusEmptyTypeID is TL type id of UserStatusEmpty.
const UserStatusEmptyTypeID = 0x9d05049

func (u *UserStatusEmpty) Zero() bool {
	if u == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (u *UserStatusEmpty) String() string {
	if u == nil {
		return "UserStatusEmpty(nil)"
	}
	type Alias UserStatusEmpty
	return fmt.Sprintf("UserStatusEmpty%+v", Alias(*u))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (u *UserStatusEmpty) TypeID() uint32 {
	return UserStatusEmptyTypeID
}

// TypeName returns name of type in TL schema.
func (u *UserStatusEmpty) TypeName() string {
	return "userStatusEmpty"
}

// Encode implements bin.Encoder.
func (u *UserStatusEmpty) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode userStatusEmpty#9d05049 as nil")
	}
	b.PutID(UserStatusEmptyTypeID)
	return nil
}

// Decode implements bin.Decoder.
func (u *UserStatusEmpty) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode userStatusEmpty#9d05049 to nil")
	}
	if err := b.ConsumeID(UserStatusEmptyTypeID); err != nil {
		return fmt.Errorf("unable to decode userStatusEmpty#9d05049: %w", err)
	}
	return nil
}

// construct implements constructor of UserStatusClass.
func (u UserStatusEmpty) construct() UserStatusClass { return &u }

// Ensuring interfaces in compile-time for UserStatusEmpty.
var (
	_ bin.Encoder = &UserStatusEmpty{}
	_ bin.Decoder = &UserStatusEmpty{}

	_ UserStatusClass = &UserStatusEmpty{}
)

// UserStatusOnline represents TL type `userStatusOnline#edb93949`.
// Online status of the user.
//
// See https://core.telegram.org/constructor/userStatusOnline for reference.
type UserStatusOnline struct {
	// Time to expiration of the current online status
	Expires int `tl:"expires"`
}

// UserStatusOnlineTypeID is TL type id of UserStatusOnline.
const UserStatusOnlineTypeID = 0xedb93949

func (u *UserStatusOnline) Zero() bool {
	if u == nil {
		return true
	}
	if !(u.Expires == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (u *UserStatusOnline) String() string {
	if u == nil {
		return "UserStatusOnline(nil)"
	}
	type Alias UserStatusOnline
	return fmt.Sprintf("UserStatusOnline%+v", Alias(*u))
}

// FillFrom fills UserStatusOnline from given interface.
func (u *UserStatusOnline) FillFrom(from interface {
	GetExpires() (value int)
}) {
	u.Expires = from.GetExpires()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (u *UserStatusOnline) TypeID() uint32 {
	return UserStatusOnlineTypeID
}

// TypeName returns name of type in TL schema.
func (u *UserStatusOnline) TypeName() string {
	return "userStatusOnline"
}

// Encode implements bin.Encoder.
func (u *UserStatusOnline) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode userStatusOnline#edb93949 as nil")
	}
	b.PutID(UserStatusOnlineTypeID)
	b.PutInt(u.Expires)
	return nil
}

// GetExpires returns value of Expires field.
func (u *UserStatusOnline) GetExpires() (value int) {
	return u.Expires
}

// Decode implements bin.Decoder.
func (u *UserStatusOnline) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode userStatusOnline#edb93949 to nil")
	}
	if err := b.ConsumeID(UserStatusOnlineTypeID); err != nil {
		return fmt.Errorf("unable to decode userStatusOnline#edb93949: %w", err)
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode userStatusOnline#edb93949: field expires: %w", err)
		}
		u.Expires = value
	}
	return nil
}

// construct implements constructor of UserStatusClass.
func (u UserStatusOnline) construct() UserStatusClass { return &u }

// Ensuring interfaces in compile-time for UserStatusOnline.
var (
	_ bin.Encoder = &UserStatusOnline{}
	_ bin.Decoder = &UserStatusOnline{}

	_ UserStatusClass = &UserStatusOnline{}
)

// UserStatusOffline represents TL type `userStatusOffline#8c703f`.
// The user's offline status.
//
// See https://core.telegram.org/constructor/userStatusOffline for reference.
type UserStatusOffline struct {
	// Time the user was last seen online
	WasOnline int `tl:"was_online"`
}

// UserStatusOfflineTypeID is TL type id of UserStatusOffline.
const UserStatusOfflineTypeID = 0x8c703f

func (u *UserStatusOffline) Zero() bool {
	if u == nil {
		return true
	}
	if !(u.WasOnline == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (u *UserStatusOffline) String() string {
	if u == nil {
		return "UserStatusOffline(nil)"
	}
	type Alias UserStatusOffline
	return fmt.Sprintf("UserStatusOffline%+v", Alias(*u))
}

// FillFrom fills UserStatusOffline from given interface.
func (u *UserStatusOffline) FillFrom(from interface {
	GetWasOnline() (value int)
}) {
	u.WasOnline = from.GetWasOnline()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (u *UserStatusOffline) TypeID() uint32 {
	return UserStatusOfflineTypeID
}

// TypeName returns name of type in TL schema.
func (u *UserStatusOffline) TypeName() string {
	return "userStatusOffline"
}

// Encode implements bin.Encoder.
func (u *UserStatusOffline) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode userStatusOffline#8c703f as nil")
	}
	b.PutID(UserStatusOfflineTypeID)
	b.PutInt(u.WasOnline)
	return nil
}

// GetWasOnline returns value of WasOnline field.
func (u *UserStatusOffline) GetWasOnline() (value int) {
	return u.WasOnline
}

// Decode implements bin.Decoder.
func (u *UserStatusOffline) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode userStatusOffline#8c703f to nil")
	}
	if err := b.ConsumeID(UserStatusOfflineTypeID); err != nil {
		return fmt.Errorf("unable to decode userStatusOffline#8c703f: %w", err)
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode userStatusOffline#8c703f: field was_online: %w", err)
		}
		u.WasOnline = value
	}
	return nil
}

// construct implements constructor of UserStatusClass.
func (u UserStatusOffline) construct() UserStatusClass { return &u }

// Ensuring interfaces in compile-time for UserStatusOffline.
var (
	_ bin.Encoder = &UserStatusOffline{}
	_ bin.Decoder = &UserStatusOffline{}

	_ UserStatusClass = &UserStatusOffline{}
)

// UserStatusRecently represents TL type `userStatusRecently#e26f42f1`.
// Online status: last seen recently
//
// See https://core.telegram.org/constructor/userStatusRecently for reference.
type UserStatusRecently struct {
}

// UserStatusRecentlyTypeID is TL type id of UserStatusRecently.
const UserStatusRecentlyTypeID = 0xe26f42f1

func (u *UserStatusRecently) Zero() bool {
	if u == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (u *UserStatusRecently) String() string {
	if u == nil {
		return "UserStatusRecently(nil)"
	}
	type Alias UserStatusRecently
	return fmt.Sprintf("UserStatusRecently%+v", Alias(*u))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (u *UserStatusRecently) TypeID() uint32 {
	return UserStatusRecentlyTypeID
}

// TypeName returns name of type in TL schema.
func (u *UserStatusRecently) TypeName() string {
	return "userStatusRecently"
}

// Encode implements bin.Encoder.
func (u *UserStatusRecently) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode userStatusRecently#e26f42f1 as nil")
	}
	b.PutID(UserStatusRecentlyTypeID)
	return nil
}

// Decode implements bin.Decoder.
func (u *UserStatusRecently) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode userStatusRecently#e26f42f1 to nil")
	}
	if err := b.ConsumeID(UserStatusRecentlyTypeID); err != nil {
		return fmt.Errorf("unable to decode userStatusRecently#e26f42f1: %w", err)
	}
	return nil
}

// construct implements constructor of UserStatusClass.
func (u UserStatusRecently) construct() UserStatusClass { return &u }

// Ensuring interfaces in compile-time for UserStatusRecently.
var (
	_ bin.Encoder = &UserStatusRecently{}
	_ bin.Decoder = &UserStatusRecently{}

	_ UserStatusClass = &UserStatusRecently{}
)

// UserStatusLastWeek represents TL type `userStatusLastWeek#7bf09fc`.
// Online status: last seen last week
//
// See https://core.telegram.org/constructor/userStatusLastWeek for reference.
type UserStatusLastWeek struct {
}

// UserStatusLastWeekTypeID is TL type id of UserStatusLastWeek.
const UserStatusLastWeekTypeID = 0x7bf09fc

func (u *UserStatusLastWeek) Zero() bool {
	if u == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (u *UserStatusLastWeek) String() string {
	if u == nil {
		return "UserStatusLastWeek(nil)"
	}
	type Alias UserStatusLastWeek
	return fmt.Sprintf("UserStatusLastWeek%+v", Alias(*u))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (u *UserStatusLastWeek) TypeID() uint32 {
	return UserStatusLastWeekTypeID
}

// TypeName returns name of type in TL schema.
func (u *UserStatusLastWeek) TypeName() string {
	return "userStatusLastWeek"
}

// Encode implements bin.Encoder.
func (u *UserStatusLastWeek) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode userStatusLastWeek#7bf09fc as nil")
	}
	b.PutID(UserStatusLastWeekTypeID)
	return nil
}

// Decode implements bin.Decoder.
func (u *UserStatusLastWeek) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode userStatusLastWeek#7bf09fc to nil")
	}
	if err := b.ConsumeID(UserStatusLastWeekTypeID); err != nil {
		return fmt.Errorf("unable to decode userStatusLastWeek#7bf09fc: %w", err)
	}
	return nil
}

// construct implements constructor of UserStatusClass.
func (u UserStatusLastWeek) construct() UserStatusClass { return &u }

// Ensuring interfaces in compile-time for UserStatusLastWeek.
var (
	_ bin.Encoder = &UserStatusLastWeek{}
	_ bin.Decoder = &UserStatusLastWeek{}

	_ UserStatusClass = &UserStatusLastWeek{}
)

// UserStatusLastMonth represents TL type `userStatusLastMonth#77ebc742`.
// Online status: last seen last month
//
// See https://core.telegram.org/constructor/userStatusLastMonth for reference.
type UserStatusLastMonth struct {
}

// UserStatusLastMonthTypeID is TL type id of UserStatusLastMonth.
const UserStatusLastMonthTypeID = 0x77ebc742

func (u *UserStatusLastMonth) Zero() bool {
	if u == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (u *UserStatusLastMonth) String() string {
	if u == nil {
		return "UserStatusLastMonth(nil)"
	}
	type Alias UserStatusLastMonth
	return fmt.Sprintf("UserStatusLastMonth%+v", Alias(*u))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (u *UserStatusLastMonth) TypeID() uint32 {
	return UserStatusLastMonthTypeID
}

// TypeName returns name of type in TL schema.
func (u *UserStatusLastMonth) TypeName() string {
	return "userStatusLastMonth"
}

// Encode implements bin.Encoder.
func (u *UserStatusLastMonth) Encode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't encode userStatusLastMonth#77ebc742 as nil")
	}
	b.PutID(UserStatusLastMonthTypeID)
	return nil
}

// Decode implements bin.Decoder.
func (u *UserStatusLastMonth) Decode(b *bin.Buffer) error {
	if u == nil {
		return fmt.Errorf("can't decode userStatusLastMonth#77ebc742 to nil")
	}
	if err := b.ConsumeID(UserStatusLastMonthTypeID); err != nil {
		return fmt.Errorf("unable to decode userStatusLastMonth#77ebc742: %w", err)
	}
	return nil
}

// construct implements constructor of UserStatusClass.
func (u UserStatusLastMonth) construct() UserStatusClass { return &u }

// Ensuring interfaces in compile-time for UserStatusLastMonth.
var (
	_ bin.Encoder = &UserStatusLastMonth{}
	_ bin.Decoder = &UserStatusLastMonth{}

	_ UserStatusClass = &UserStatusLastMonth{}
)

// UserStatusClass represents UserStatus generic type.
//
// See https://core.telegram.org/type/UserStatus for reference.
//
// Example:
//  g, err := tg.DecodeUserStatus(buf)
//  if err != nil {
//      panic(err)
//  }
//  switch v := g.(type) {
//  case *tg.UserStatusEmpty: // userStatusEmpty#9d05049
//  case *tg.UserStatusOnline: // userStatusOnline#edb93949
//  case *tg.UserStatusOffline: // userStatusOffline#8c703f
//  case *tg.UserStatusRecently: // userStatusRecently#e26f42f1
//  case *tg.UserStatusLastWeek: // userStatusLastWeek#7bf09fc
//  case *tg.UserStatusLastMonth: // userStatusLastMonth#77ebc742
//  default: panic(v)
//  }
type UserStatusClass interface {
	bin.Encoder
	bin.Decoder
	construct() UserStatusClass

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
}

// DecodeUserStatus implements binary de-serialization for UserStatusClass.
func DecodeUserStatus(buf *bin.Buffer) (UserStatusClass, error) {
	id, err := buf.PeekID()
	if err != nil {
		return nil, err
	}
	switch id {
	case UserStatusEmptyTypeID:
		// Decoding userStatusEmpty#9d05049.
		v := UserStatusEmpty{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UserStatusClass: %w", err)
		}
		return &v, nil
	case UserStatusOnlineTypeID:
		// Decoding userStatusOnline#edb93949.
		v := UserStatusOnline{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UserStatusClass: %w", err)
		}
		return &v, nil
	case UserStatusOfflineTypeID:
		// Decoding userStatusOffline#8c703f.
		v := UserStatusOffline{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UserStatusClass: %w", err)
		}
		return &v, nil
	case UserStatusRecentlyTypeID:
		// Decoding userStatusRecently#e26f42f1.
		v := UserStatusRecently{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UserStatusClass: %w", err)
		}
		return &v, nil
	case UserStatusLastWeekTypeID:
		// Decoding userStatusLastWeek#7bf09fc.
		v := UserStatusLastWeek{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UserStatusClass: %w", err)
		}
		return &v, nil
	case UserStatusLastMonthTypeID:
		// Decoding userStatusLastMonth#77ebc742.
		v := UserStatusLastMonth{}
		if err := v.Decode(buf); err != nil {
			return nil, fmt.Errorf("unable to decode UserStatusClass: %w", err)
		}
		return &v, nil
	default:
		return nil, fmt.Errorf("unable to decode UserStatusClass: %w", bin.NewUnexpectedID(id))
	}
}

// UserStatus boxes the UserStatusClass providing a helper.
type UserStatusBox struct {
	UserStatus UserStatusClass
}

// Decode implements bin.Decoder for UserStatusBox.
func (b *UserStatusBox) Decode(buf *bin.Buffer) error {
	if b == nil {
		return fmt.Errorf("unable to decode UserStatusBox to nil")
	}
	v, err := DecodeUserStatus(buf)
	if err != nil {
		return fmt.Errorf("unable to decode boxed value: %w", err)
	}
	b.UserStatus = v
	return nil
}

// Encode implements bin.Encode for UserStatusBox.
func (b *UserStatusBox) Encode(buf *bin.Buffer) error {
	if b == nil || b.UserStatus == nil {
		return fmt.Errorf("unable to encode UserStatusClass as nil")
	}
	return b.UserStatus.Encode(buf)
}

// UserStatusClassSlice is adapter for slice of UserStatusClass.
type UserStatusClassSlice []UserStatusClass

// First returns first element of slice (if exists).
func (s UserStatusClassSlice) First() (v UserStatusClass, ok bool) {
	if len(s) < 1 {
		return
	}
	return s[0], true
}

// Last returns last element of slice (if exists).
func (s UserStatusClassSlice) Last() (v UserStatusClass, ok bool) {
	if len(s) < 1 {
		return
	}
	return s[len(s)-1], true
}

// PopFirst returns first element of slice (if exists) and deletes it.
func (s *UserStatusClassSlice) PopFirst() (v UserStatusClass, ok bool) {
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
func (s *UserStatusClassSlice) Pop() (v UserStatusClass, ok bool) {
	if s == nil || len(*s) < 1 {
		return
	}

	a := *s
	v = a[len(a)-1]
	a = a[:len(a)-1]
	*s = a

	return v, true
}
