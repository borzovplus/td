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

// PaymentsGetPaymentReceiptRequest represents TL type `payments.getPaymentReceipt#a092a980`.
// Get payment receipt
//
// See https://core.telegram.org/method/payments.getPaymentReceipt for reference.
type PaymentsGetPaymentReceiptRequest struct {
	// Message ID of receipt
	MsgID int `tl:"msg_id"`
}

// PaymentsGetPaymentReceiptRequestTypeID is TL type id of PaymentsGetPaymentReceiptRequest.
const PaymentsGetPaymentReceiptRequestTypeID = 0xa092a980

func (g *PaymentsGetPaymentReceiptRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.MsgID == 0) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *PaymentsGetPaymentReceiptRequest) String() string {
	if g == nil {
		return "PaymentsGetPaymentReceiptRequest(nil)"
	}
	type Alias PaymentsGetPaymentReceiptRequest
	return fmt.Sprintf("PaymentsGetPaymentReceiptRequest%+v", Alias(*g))
}

// FillFrom fills PaymentsGetPaymentReceiptRequest from given interface.
func (g *PaymentsGetPaymentReceiptRequest) FillFrom(from interface {
	GetMsgID() (value int)
}) {
	g.MsgID = from.GetMsgID()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (g *PaymentsGetPaymentReceiptRequest) TypeID() uint32 {
	return PaymentsGetPaymentReceiptRequestTypeID
}

// TypeName returns name of type in TL schema.
func (g *PaymentsGetPaymentReceiptRequest) TypeName() string {
	return "payments.getPaymentReceipt"
}

// Encode implements bin.Encoder.
func (g *PaymentsGetPaymentReceiptRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode payments.getPaymentReceipt#a092a980 as nil")
	}
	b.PutID(PaymentsGetPaymentReceiptRequestTypeID)
	b.PutInt(g.MsgID)
	return nil
}

// GetMsgID returns value of MsgID field.
func (g *PaymentsGetPaymentReceiptRequest) GetMsgID() (value int) {
	return g.MsgID
}

// Decode implements bin.Decoder.
func (g *PaymentsGetPaymentReceiptRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode payments.getPaymentReceipt#a092a980 to nil")
	}
	if err := b.ConsumeID(PaymentsGetPaymentReceiptRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode payments.getPaymentReceipt#a092a980: %w", err)
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode payments.getPaymentReceipt#a092a980: field msg_id: %w", err)
		}
		g.MsgID = value
	}
	return nil
}

// Ensuring interfaces in compile-time for PaymentsGetPaymentReceiptRequest.
var (
	_ bin.Encoder = &PaymentsGetPaymentReceiptRequest{}
	_ bin.Decoder = &PaymentsGetPaymentReceiptRequest{}
)

// PaymentsGetPaymentReceipt invokes method payments.getPaymentReceipt#a092a980 returning error if any.
// Get payment receipt
//
// Possible errors:
//  400 MESSAGE_ID_INVALID: The provided message id is invalid
//
// See https://core.telegram.org/method/payments.getPaymentReceipt for reference.
func (c *Client) PaymentsGetPaymentReceipt(ctx context.Context, msgid int) (*PaymentsPaymentReceipt, error) {
	var result PaymentsPaymentReceipt

	request := &PaymentsGetPaymentReceiptRequest{
		MsgID: msgid,
	}
	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
