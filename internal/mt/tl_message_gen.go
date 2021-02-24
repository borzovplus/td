// Code generated by gotdgen, DO NOT EDIT.

package mt

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

// Message represents TL type `message#5bb8e511`.
type Message struct {
	// MsgID field of Message.
	MsgID int64 `tl:"msg_id"`
	// Seqno field of Message.
	Seqno int `tl:"seqno"`
	// Bytes field of Message.
	Bytes int `tl:"bytes"`
	// Body field of Message.
	Body GzipPacked `tl:"body"`
}

// MessageTypeID is TL type id of Message.
const MessageTypeID = 0x5bb8e511

func (m *Message) Zero() bool {
	if m == nil {
		return true
	}
	if !(m.MsgID == 0) {
		return false
	}
	if !(m.Seqno == 0) {
		return false
	}
	if !(m.Bytes == 0) {
		return false
	}
	if !(m.Body.Zero()) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (m *Message) String() string {
	if m == nil {
		return "Message(nil)"
	}
	type Alias Message
	return fmt.Sprintf("Message%+v", Alias(*m))
}

// FillFrom fills Message from given interface.
func (m *Message) FillFrom(from interface {
	GetMsgID() (value int64)
	GetSeqno() (value int)
	GetBytes() (value int)
	GetBody() (value GzipPacked)
}) {
	m.MsgID = from.GetMsgID()
	m.Seqno = from.GetSeqno()
	m.Bytes = from.GetBytes()
	m.Body = from.GetBody()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (m *Message) TypeID() uint32 {
	return MessageTypeID
}

// TypeName returns name of type in TL schema.
func (m *Message) TypeName() string {
	return "message"
}

// Encode implements bin.Encoder.
func (m *Message) Encode(b *bin.Buffer) error {
	if m == nil {
		return fmt.Errorf("can't encode message#5bb8e511 as nil")
	}
	b.PutID(MessageTypeID)
	b.PutLong(m.MsgID)
	b.PutInt(m.Seqno)
	b.PutInt(m.Bytes)
	if err := m.Body.Encode(b); err != nil {
		return fmt.Errorf("unable to encode message#5bb8e511: field body: %w", err)
	}
	return nil
}

// GetMsgID returns value of MsgID field.
func (m *Message) GetMsgID() (value int64) {
	return m.MsgID
}

// GetSeqno returns value of Seqno field.
func (m *Message) GetSeqno() (value int) {
	return m.Seqno
}

// GetBytes returns value of Bytes field.
func (m *Message) GetBytes() (value int) {
	return m.Bytes
}

// GetBody returns value of Body field.
func (m *Message) GetBody() (value GzipPacked) {
	return m.Body
}

// Decode implements bin.Decoder.
func (m *Message) Decode(b *bin.Buffer) error {
	if m == nil {
		return fmt.Errorf("can't decode message#5bb8e511 to nil")
	}
	if err := b.ConsumeID(MessageTypeID); err != nil {
		return fmt.Errorf("unable to decode message#5bb8e511: %w", err)
	}
	{
		value, err := b.Long()
		if err != nil {
			return fmt.Errorf("unable to decode message#5bb8e511: field msg_id: %w", err)
		}
		m.MsgID = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode message#5bb8e511: field seqno: %w", err)
		}
		m.Seqno = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode message#5bb8e511: field bytes: %w", err)
		}
		m.Bytes = value
	}
	{
		if err := m.Body.Decode(b); err != nil {
			return fmt.Errorf("unable to decode message#5bb8e511: field body: %w", err)
		}
	}
	return nil
}

// Ensuring interfaces in compile-time for Message.
var (
	_ bin.Encoder = &Message{}
	_ bin.Decoder = &Message{}
)
