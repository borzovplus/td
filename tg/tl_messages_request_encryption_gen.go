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

// MessagesRequestEncryptionRequest represents TL type `messages.requestEncryption#f64daf43`.
// Sends a request to start a secret chat to the user.
//
// See https://core.telegram.org/method/messages.requestEncryption for reference.
type MessagesRequestEncryptionRequest struct {
	// User ID
	UserID InputUserClass `tl:"user_id"`
	// Unique client request ID required to prevent resending. This also doubles as the chat ID.
	RandomID int `tl:"random_id"`
	// A = g ^ a mod p, see Wikipedia¹
	//
	// Links:
	//  1) https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
	GA []byte `tl:"g_a"`
}

// MessagesRequestEncryptionRequestTypeID is TL type id of MessagesRequestEncryptionRequest.
const MessagesRequestEncryptionRequestTypeID = 0xf64daf43

func (r *MessagesRequestEncryptionRequest) Zero() bool {
	if r == nil {
		return true
	}
	if !(r.UserID == nil) {
		return false
	}
	if !(r.RandomID == 0) {
		return false
	}
	if !(r.GA == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (r *MessagesRequestEncryptionRequest) String() string {
	if r == nil {
		return "MessagesRequestEncryptionRequest(nil)"
	}
	type Alias MessagesRequestEncryptionRequest
	return fmt.Sprintf("MessagesRequestEncryptionRequest%+v", Alias(*r))
}

// FillFrom fills MessagesRequestEncryptionRequest from given interface.
func (r *MessagesRequestEncryptionRequest) FillFrom(from interface {
	GetUserID() (value InputUserClass)
	GetRandomID() (value int)
	GetGA() (value []byte)
}) {
	r.UserID = from.GetUserID()
	r.RandomID = from.GetRandomID()
	r.GA = from.GetGA()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (r *MessagesRequestEncryptionRequest) TypeID() uint32 {
	return MessagesRequestEncryptionRequestTypeID
}

// TypeName returns name of type in TL schema.
func (r *MessagesRequestEncryptionRequest) TypeName() string {
	return "messages.requestEncryption"
}

// Encode implements bin.Encoder.
func (r *MessagesRequestEncryptionRequest) Encode(b *bin.Buffer) error {
	if r == nil {
		return fmt.Errorf("can't encode messages.requestEncryption#f64daf43 as nil")
	}
	b.PutID(MessagesRequestEncryptionRequestTypeID)
	if r.UserID == nil {
		return fmt.Errorf("unable to encode messages.requestEncryption#f64daf43: field user_id is nil")
	}
	if err := r.UserID.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.requestEncryption#f64daf43: field user_id: %w", err)
	}
	b.PutInt(r.RandomID)
	b.PutBytes(r.GA)
	return nil
}

// GetUserID returns value of UserID field.
func (r *MessagesRequestEncryptionRequest) GetUserID() (value InputUserClass) {
	return r.UserID
}

// GetRandomID returns value of RandomID field.
func (r *MessagesRequestEncryptionRequest) GetRandomID() (value int) {
	return r.RandomID
}

// GetGA returns value of GA field.
func (r *MessagesRequestEncryptionRequest) GetGA() (value []byte) {
	return r.GA
}

// Decode implements bin.Decoder.
func (r *MessagesRequestEncryptionRequest) Decode(b *bin.Buffer) error {
	if r == nil {
		return fmt.Errorf("can't decode messages.requestEncryption#f64daf43 to nil")
	}
	if err := b.ConsumeID(MessagesRequestEncryptionRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.requestEncryption#f64daf43: %w", err)
	}
	{
		value, err := DecodeInputUser(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.requestEncryption#f64daf43: field user_id: %w", err)
		}
		r.UserID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.requestEncryption#f64daf43: field random_id: %w", err)
		}
		r.RandomID = value
	}
	{
		value, err := b.Bytes()
		if err != nil {
			return fmt.Errorf("unable to decode messages.requestEncryption#f64daf43: field g_a: %w", err)
		}
		r.GA = value
	}
	return nil
}

// Ensuring interfaces in compile-time for MessagesRequestEncryptionRequest.
var (
	_ bin.Encoder = &MessagesRequestEncryptionRequest{}
	_ bin.Decoder = &MessagesRequestEncryptionRequest{}
)

// MessagesRequestEncryption invokes method messages.requestEncryption#f64daf43 returning error if any.
// Sends a request to start a secret chat to the user.
//
// Possible errors:
//  400 DH_G_A_INVALID: g_a invalid
//  400 USER_ID_INVALID: The provided user ID is invalid
//
// See https://core.telegram.org/method/messages.requestEncryption for reference.
func (c *Client) MessagesRequestEncryption(ctx context.Context, request *MessagesRequestEncryptionRequest) (EncryptedChatClass, error) {
	var result EncryptedChatBox

	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return result.EncryptedChat, nil
}
