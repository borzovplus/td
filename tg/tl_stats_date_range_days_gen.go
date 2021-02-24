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

// StatsDateRangeDays represents TL type `statsDateRangeDays#b637edaf`.
// Channel statistics¹ date range
//
// Links:
//  1) https://core.telegram.org/api/stats
//
// See https://core.telegram.org/constructor/statsDateRangeDays for reference.
type StatsDateRangeDays struct {
	// Initial date
	MinDate int `tl:"min_date"`
	// Final date
	MaxDate int `tl:"max_date"`
}

// StatsDateRangeDaysTypeID is TL type id of StatsDateRangeDays.
const StatsDateRangeDaysTypeID = 0xb637edaf

func (s *StatsDateRangeDays) Zero() bool {
	if s == nil {
		return true
	}
	if !(s.MinDate == 0) {
		return false
	}
	if !(s.MaxDate == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (s *StatsDateRangeDays) String() string {
	if s == nil {
		return "StatsDateRangeDays(nil)"
	}
	type Alias StatsDateRangeDays
	return fmt.Sprintf("StatsDateRangeDays%+v", Alias(*s))
}

// FillFrom fills StatsDateRangeDays from given interface.
func (s *StatsDateRangeDays) FillFrom(from interface {
	GetMinDate() (value int)
	GetMaxDate() (value int)
}) {
	s.MinDate = from.GetMinDate()
	s.MaxDate = from.GetMaxDate()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (s *StatsDateRangeDays) TypeID() uint32 {
	return StatsDateRangeDaysTypeID
}

// TypeName returns name of type in TL schema.
func (s *StatsDateRangeDays) TypeName() string {
	return "statsDateRangeDays"
}

// Encode implements bin.Encoder.
func (s *StatsDateRangeDays) Encode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't encode statsDateRangeDays#b637edaf as nil")
	}
	b.PutID(StatsDateRangeDaysTypeID)
	b.PutInt(s.MinDate)
	b.PutInt(s.MaxDate)
	return nil
}

// GetMinDate returns value of MinDate field.
func (s *StatsDateRangeDays) GetMinDate() (value int) {
	return s.MinDate
}

// GetMaxDate returns value of MaxDate field.
func (s *StatsDateRangeDays) GetMaxDate() (value int) {
	return s.MaxDate
}

// Decode implements bin.Decoder.
func (s *StatsDateRangeDays) Decode(b *bin.Buffer) error {
	if s == nil {
		return fmt.Errorf("can't decode statsDateRangeDays#b637edaf to nil")
	}
	if err := b.ConsumeID(StatsDateRangeDaysTypeID); err != nil {
		return fmt.Errorf("unable to decode statsDateRangeDays#b637edaf: %w", err)
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode statsDateRangeDays#b637edaf: field min_date: %w", err)
		}
		s.MinDate = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode statsDateRangeDays#b637edaf: field max_date: %w", err)
		}
		s.MaxDate = value
	}
	return nil
}

// Ensuring interfaces in compile-time for StatsDateRangeDays.
var (
	_ bin.Encoder = &StatsDateRangeDays{}
	_ bin.Decoder = &StatsDateRangeDays{}
)
