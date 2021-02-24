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

// AccountGetAutoDownloadSettingsRequest represents TL type `account.getAutoDownloadSettings#56da0b3f`.
// Get media autodownload settings
//
// See https://core.telegram.org/method/account.getAutoDownloadSettings for reference.
type AccountGetAutoDownloadSettingsRequest struct {
}

// AccountGetAutoDownloadSettingsRequestTypeID is TL type id of AccountGetAutoDownloadSettingsRequest.
const AccountGetAutoDownloadSettingsRequestTypeID = 0x56da0b3f

func (g *AccountGetAutoDownloadSettingsRequest) Zero() bool {
	if g == nil {
		return true
	}

	return true
}

// String implements fmt.Stringer.
func (g *AccountGetAutoDownloadSettingsRequest) String() string {
	if g == nil {
		return "AccountGetAutoDownloadSettingsRequest(nil)"
	}
	type Alias AccountGetAutoDownloadSettingsRequest
	return fmt.Sprintf("AccountGetAutoDownloadSettingsRequest%+v", Alias(*g))
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (g *AccountGetAutoDownloadSettingsRequest) TypeID() uint32 {
	return AccountGetAutoDownloadSettingsRequestTypeID
}

// TypeName returns name of type in TL schema.
func (g *AccountGetAutoDownloadSettingsRequest) TypeName() string {
	return "account.getAutoDownloadSettings"
}

// Encode implements bin.Encoder.
func (g *AccountGetAutoDownloadSettingsRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode account.getAutoDownloadSettings#56da0b3f as nil")
	}
	b.PutID(AccountGetAutoDownloadSettingsRequestTypeID)
	return nil
}

// Decode implements bin.Decoder.
func (g *AccountGetAutoDownloadSettingsRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode account.getAutoDownloadSettings#56da0b3f to nil")
	}
	if err := b.ConsumeID(AccountGetAutoDownloadSettingsRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode account.getAutoDownloadSettings#56da0b3f: %w", err)
	}
	return nil
}

// Ensuring interfaces in compile-time for AccountGetAutoDownloadSettingsRequest.
var (
	_ bin.Encoder = &AccountGetAutoDownloadSettingsRequest{}
	_ bin.Decoder = &AccountGetAutoDownloadSettingsRequest{}
)

// AccountGetAutoDownloadSettings invokes method account.getAutoDownloadSettings#56da0b3f returning error if any.
// Get media autodownload settings
//
// See https://core.telegram.org/method/account.getAutoDownloadSettings for reference.
func (c *Client) AccountGetAutoDownloadSettings(ctx context.Context) (*AccountAutoDownloadSettings, error) {
	var result AccountAutoDownloadSettings

	request := &AccountGetAutoDownloadSettingsRequest{}
	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
