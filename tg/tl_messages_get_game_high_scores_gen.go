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

// MessagesGetGameHighScoresRequest represents TL type `messages.getGameHighScores#e822649d`.
// Get highscores of a game
//
// See https://core.telegram.org/method/messages.getGameHighScores for reference.
type MessagesGetGameHighScoresRequest struct {
	// Where was the game sent
	Peer InputPeerClass `tl:"peer"`
	// ID of message with game media attachment
	ID int `tl:"id"`
	// Get high scores made by a certain user
	UserID InputUserClass `tl:"user_id"`
}

// MessagesGetGameHighScoresRequestTypeID is TL type id of MessagesGetGameHighScoresRequest.
const MessagesGetGameHighScoresRequestTypeID = 0xe822649d

func (g *MessagesGetGameHighScoresRequest) Zero() bool {
	if g == nil {
		return true
	}
	if !(g.Peer == nil) {
		return false
	}
	if !(g.ID == 0) {
		return false
	}
	if !(g.UserID == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (g *MessagesGetGameHighScoresRequest) String() string {
	if g == nil {
		return "MessagesGetGameHighScoresRequest(nil)"
	}
	type Alias MessagesGetGameHighScoresRequest
	return fmt.Sprintf("MessagesGetGameHighScoresRequest%+v", Alias(*g))
}

// FillFrom fills MessagesGetGameHighScoresRequest from given interface.
func (g *MessagesGetGameHighScoresRequest) FillFrom(from interface {
	GetPeer() (value InputPeerClass)
	GetID() (value int)
	GetUserID() (value InputUserClass)
}) {
	g.Peer = from.GetPeer()
	g.ID = from.GetID()
	g.UserID = from.GetUserID()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (g *MessagesGetGameHighScoresRequest) TypeID() uint32 {
	return MessagesGetGameHighScoresRequestTypeID
}

// TypeName returns name of type in TL schema.
func (g *MessagesGetGameHighScoresRequest) TypeName() string {
	return "messages.getGameHighScores"
}

// Encode implements bin.Encoder.
func (g *MessagesGetGameHighScoresRequest) Encode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't encode messages.getGameHighScores#e822649d as nil")
	}
	b.PutID(MessagesGetGameHighScoresRequestTypeID)
	if g.Peer == nil {
		return fmt.Errorf("unable to encode messages.getGameHighScores#e822649d: field peer is nil")
	}
	if err := g.Peer.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.getGameHighScores#e822649d: field peer: %w", err)
	}
	b.PutInt(g.ID)
	if g.UserID == nil {
		return fmt.Errorf("unable to encode messages.getGameHighScores#e822649d: field user_id is nil")
	}
	if err := g.UserID.Encode(b); err != nil {
		return fmt.Errorf("unable to encode messages.getGameHighScores#e822649d: field user_id: %w", err)
	}
	return nil
}

// GetPeer returns value of Peer field.
func (g *MessagesGetGameHighScoresRequest) GetPeer() (value InputPeerClass) {
	return g.Peer
}

// GetID returns value of ID field.
func (g *MessagesGetGameHighScoresRequest) GetID() (value int) {
	return g.ID
}

// GetUserID returns value of UserID field.
func (g *MessagesGetGameHighScoresRequest) GetUserID() (value InputUserClass) {
	return g.UserID
}

// Decode implements bin.Decoder.
func (g *MessagesGetGameHighScoresRequest) Decode(b *bin.Buffer) error {
	if g == nil {
		return fmt.Errorf("can't decode messages.getGameHighScores#e822649d to nil")
	}
	if err := b.ConsumeID(MessagesGetGameHighScoresRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode messages.getGameHighScores#e822649d: %w", err)
	}
	{
		value, err := DecodeInputPeer(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.getGameHighScores#e822649d: field peer: %w", err)
		}
		g.Peer = value
	}
	{
		value, err := b.Int()
		if err != nil {
			return fmt.Errorf("unable to decode messages.getGameHighScores#e822649d: field id: %w", err)
		}
		g.ID = value
	}
	{
		value, err := DecodeInputUser(b)
		if err != nil {
			return fmt.Errorf("unable to decode messages.getGameHighScores#e822649d: field user_id: %w", err)
		}
		g.UserID = value
	}
	return nil
}

// Ensuring interfaces in compile-time for MessagesGetGameHighScoresRequest.
var (
	_ bin.Encoder = &MessagesGetGameHighScoresRequest{}
	_ bin.Decoder = &MessagesGetGameHighScoresRequest{}
)

// MessagesGetGameHighScores invokes method messages.getGameHighScores#e822649d returning error if any.
// Get highscores of a game
//
// Possible errors:
//  400 MESSAGE_ID_INVALID: The provided message id is invalid
//  400 PEER_ID_INVALID: The provided peer id is invalid
//  400 USER_BOT_REQUIRED: This method can only be called by a bot
//
// See https://core.telegram.org/method/messages.getGameHighScores for reference.
// Can be used by bots.
func (c *Client) MessagesGetGameHighScores(ctx context.Context, request *MessagesGetGameHighScoresRequest) (*MessagesHighScores, error) {
	var result MessagesHighScores

	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
