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

// WallPaperSettings represents TL type `wallPaperSettings#5086cf8`.
// Wallpaper settings
//
// See https://core.telegram.org/constructor/wallPaperSettings for reference.
type WallPaperSettings struct {
	// Flags, see TL conditional fields¹
	//
	// Links:
	//  1) https://core.telegram.org/mtproto/TL-combinators#conditional-fields
	Flags bin.Fields `tl:"flags"`
	// If set, the wallpaper must be downscaled to fit in 450x450 square and then box-blurred with radius 12
	Blur bool `tl:"blur"`
	// If set, the background needs to be slightly moved when device is rotated
	Motion bool `tl:"motion"`
	// If set, a PNG pattern is to be combined with the color chosen by the user: the main color of the background in RGB24 format
	//
	// Use SetBackgroundColor and GetBackgroundColor helpers.
	BackgroundColor int `tl:"background_color"`
	// If set, a PNG pattern is to be combined with the first and second background colors (RGB24 format) in a top-bottom gradient
	//
	// Use SetSecondBackgroundColor and GetSecondBackgroundColor helpers.
	SecondBackgroundColor int `tl:"second_background_color"`
	// Intensity of the pattern when it is shown above the main background color, 0-100
	//
	// Use SetIntensity and GetIntensity helpers.
	Intensity int `tl:"intensity"`
	// Clockwise rotation angle of the gradient, in degrees; 0-359. Should be always divisible by 45
	//
	// Use SetRotation and GetRotation helpers.
	Rotation int `tl:"rotation"`
}

// WallPaperSettingsTypeID is TL type id of WallPaperSettings.
const WallPaperSettingsTypeID = 0x5086cf8

func (w *WallPaperSettings) Zero() bool {
	if w == nil {
		return true
	}
	if !(w.Flags.Zero()) {
		return false
	}
	if !(w.Blur == false) {
		return false
	}
	if !(w.Motion == false) {
		return false
	}
	if !(w.BackgroundColor == 0) {
		return false
	}
	if !(w.SecondBackgroundColor == 0) {
		return false
	}
	if !(w.Intensity == 0) {
		return false
	}
	if !(w.Rotation == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (w *WallPaperSettings) String() string {
	if w == nil {
		return "WallPaperSettings(nil)"
	}
	type Alias WallPaperSettings
	return fmt.Sprintf("WallPaperSettings%+v", Alias(*w))
}

// FillFrom fills WallPaperSettings from given interface.
func (w *WallPaperSettings) FillFrom(from interface {
	GetBlur() (value bool)
	GetMotion() (value bool)
	GetBackgroundColor() (value int, ok bool)
	GetSecondBackgroundColor() (value int, ok bool)
	GetIntensity() (value int, ok bool)
	GetRotation() (value int, ok bool)
}) {
	w.Blur = from.GetBlur()
	w.Motion = from.GetMotion()
	if val, ok := from.GetBackgroundColor(); ok {
		w.BackgroundColor = val
	}

	if val, ok := from.GetSecondBackgroundColor(); ok {
		w.SecondBackgroundColor = val
	}

	if val, ok := from.GetIntensity(); ok {
		w.Intensity = val
	}

	if val, ok := from.GetRotation(); ok {
		w.Rotation = val
	}

}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (w *WallPaperSettings) TypeID() uint32 {
	return WallPaperSettingsTypeID
}

// TypeName returns name of type in TL schema.
func (w *WallPaperSettings) TypeName() string {
	return "wallPaperSettings"
}

// Encode implements bin.Encoder.
func (w *WallPaperSettings) Encode(b *bin.Buffer) error {
	if w == nil {
		return fmt.Errorf("can't encode wallPaperSettings#5086cf8 as nil")
	}
	b.PutID(WallPaperSettingsTypeID)
	if !(w.Blur == false) {
		w.Flags.Set(1)
	}
	if !(w.Motion == false) {
		w.Flags.Set(2)
	}
	if !(w.BackgroundColor == 0) {
		w.Flags.Set(0)
	}
	if !(w.SecondBackgroundColor == 0) {
		w.Flags.Set(4)
	}
	if !(w.Intensity == 0) {
		w.Flags.Set(3)
	}
	if !(w.Rotation == 0) {
		w.Flags.Set(4)
	}
	if err := w.Flags.Encode(b); err != nil {
		return fmt.Errorf("unable to encode wallPaperSettings#5086cf8: field flags: %w", err)
	}
	if w.Flags.Has(0) {
		b.PutInt(w.BackgroundColor)
	}
	if w.Flags.Has(4) {
		b.PutInt(w.SecondBackgroundColor)
	}
	if w.Flags.Has(3) {
		b.PutInt(w.Intensity)
	}
	if w.Flags.Has(4) {
		b.PutInt(w.Rotation)
	}
	return nil
}

// SetBlur sets value of Blur conditional field.
func (w *WallPaperSettings) SetBlur(value bool) {
	if value {
		w.Flags.Set(1)
		w.Blur = true
	} else {
		w.Flags.Unset(1)
		w.Blur = false
	}
}

// GetBlur returns value of Blur conditional field.
func (w *WallPaperSettings) GetBlur() (value bool) {
	return w.Flags.Has(1)
}

// SetMotion sets value of Motion conditional field.
func (w *WallPaperSettings) SetMotion(value bool) {
	if value {
		w.Flags.Set(2)
		w.Motion = true
	} else {
		w.Flags.Unset(2)
		w.Motion = false
	}
}

// GetMotion returns value of Motion conditional field.
func (w *WallPaperSettings) GetMotion() (value bool) {
	return w.Flags.Has(2)
}

// SetBackgroundColor sets value of BackgroundColor conditional field.
func (w *WallPaperSettings) SetBackgroundColor(value int) {
	w.Flags.Set(0)
	w.BackgroundColor = value
}

// GetBackgroundColor returns value of BackgroundColor conditional field and
// boolean which is true if field was set.
func (w *WallPaperSettings) GetBackgroundColor() (value int, ok bool) {
	if !w.Flags.Has(0) {
		return value, false
	}
	return w.BackgroundColor, true
}

// SetSecondBackgroundColor sets value of SecondBackgroundColor conditional field.
func (w *WallPaperSettings) SetSecondBackgroundColor(value int) {
	w.Flags.Set(4)
	w.SecondBackgroundColor = value
}

// GetSecondBackgroundColor returns value of SecondBackgroundColor conditional field and
// boolean which is true if field was set.
func (w *WallPaperSettings) GetSecondBackgroundColor() (value int, ok bool) {
	if !w.Flags.Has(4) {
		return value, false
	}
	return w.SecondBackgroundColor, true
}

// SetIntensity sets value of Intensity conditional field.
func (w *WallPaperSettings) SetIntensity(value int) {
	w.Flags.Set(3)
	w.Intensity = value
}

// GetIntensity returns value of Intensity conditional field and
// boolean which is true if field was set.
func (w *WallPaperSettings) GetIntensity() (value int, ok bool) {
	if !w.Flags.Has(3) {
		return value, false
	}
	return w.Intensity, true
}

// SetRotation sets value of Rotation conditional field.
func (w *WallPaperSettings) SetRotation(value int) {
	w.Flags.Set(4)
	w.Rotation = value
}

// GetRotation returns value of Rotation conditional field and
// boolean which is true if field was set.
func (w *WallPaperSettings) GetRotation() (value int, ok bool) {
	if !w.Flags.Has(4) {
		return value, false
	}
	return w.Rotation, true
}

// Decode implements bin.Decoder.
func (w *WallPaperSettings) Decode(b *bin.Buffer) error {
	if w == nil {
		return fmt.Errorf("can't decode wallPaperSettings#5086cf8 to nil")
	}
	if err := b.ConsumeID(WallPaperSettingsTypeID); err != nil {
		return fmt.Errorf("unable to decode wallPaperSettings#5086cf8: %w", err)
	}
	{
		if err := w.Flags.Decode(b); err != nil {
			return fmt.Errorf("unable to decode wallPaperSettings#5086cf8: field flags: %w", err)
		}
	}
	w.Blur = w.Flags.Has(1)
	w.Motion = w.Flags.Has(2)
	if w.Flags.Has(0) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode wallPaperSettings#5086cf8: field background_color: %w", err)
		}
		w.BackgroundColor = value
	}
	if w.Flags.Has(4) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode wallPaperSettings#5086cf8: field second_background_color: %w", err)
		}
		w.SecondBackgroundColor = value
	}
	if w.Flags.Has(3) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode wallPaperSettings#5086cf8: field intensity: %w", err)
		}
		w.Intensity = value
	}
	if w.Flags.Has(4) {
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode wallPaperSettings#5086cf8: field rotation: %w", err)
		}
		w.Rotation = value
	}
	return nil
}

// Ensuring interfaces in compile-time for WallPaperSettings.
var (
	_ bin.Encoder = &WallPaperSettings{}
	_ bin.Decoder = &WallPaperSettings{}
)
