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

// FoldersEditPeerFoldersRequest represents TL type `folders.editPeerFolders#6847d0ab`.
// Edit peers in peer folder¹
//
// Links:
//  1) https://core.telegram.org/api/folders#peer-folders
//
// See https://core.telegram.org/method/folders.editPeerFolders for reference.
type FoldersEditPeerFoldersRequest struct {
	// New peer list
	FolderPeers []InputFolderPeer `tl:"folder_peers"`
}

// FoldersEditPeerFoldersRequestTypeID is TL type id of FoldersEditPeerFoldersRequest.
const FoldersEditPeerFoldersRequestTypeID = 0x6847d0ab

func (e *FoldersEditPeerFoldersRequest) Zero() bool {
	if e == nil {
		return true
	}
	if !(e.FolderPeers == nil) {
		return false
	}

	return true
}

// String implements fmt.Stringer.
func (e *FoldersEditPeerFoldersRequest) String() string {
	if e == nil {
		return "FoldersEditPeerFoldersRequest(nil)"
	}
	type Alias FoldersEditPeerFoldersRequest
	return fmt.Sprintf("FoldersEditPeerFoldersRequest%+v", Alias(*e))
}

// FillFrom fills FoldersEditPeerFoldersRequest from given interface.
func (e *FoldersEditPeerFoldersRequest) FillFrom(from interface {
	GetFolderPeers() (value []InputFolderPeer)
}) {
	e.FolderPeers = from.GetFolderPeers()
}

// TypeID returns type id in TL schema.
//
// See https://core.telegram.org/mtproto/TL-tl#remarks.
func (e *FoldersEditPeerFoldersRequest) TypeID() uint32 {
	return FoldersEditPeerFoldersRequestTypeID
}

// TypeName returns name of type in TL schema.
func (e *FoldersEditPeerFoldersRequest) TypeName() string {
	return "folders.editPeerFolders"
}

// Encode implements bin.Encoder.
func (e *FoldersEditPeerFoldersRequest) Encode(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't encode folders.editPeerFolders#6847d0ab as nil")
	}
	b.PutID(FoldersEditPeerFoldersRequestTypeID)
	b.PutVectorHeader(len(e.FolderPeers))
	for idx, v := range e.FolderPeers {
		if err := v.Encode(b); err != nil {
			return fmt.Errorf("unable to encode folders.editPeerFolders#6847d0ab: field folder_peers element with index %d: %w", idx, err)
		}
	}
	return nil
}

// GetFolderPeers returns value of FolderPeers field.
func (e *FoldersEditPeerFoldersRequest) GetFolderPeers() (value []InputFolderPeer) {
	return e.FolderPeers
}

// Decode implements bin.Decoder.
func (e *FoldersEditPeerFoldersRequest) Decode(b *bin.Buffer) error {
	if e == nil {
		return fmt.Errorf("can't decode folders.editPeerFolders#6847d0ab to nil")
	}
	if err := b.ConsumeID(FoldersEditPeerFoldersRequestTypeID); err != nil {
		return fmt.Errorf("unable to decode folders.editPeerFolders#6847d0ab: %w", err)
	}
	{
		headerLen, err := b.VectorHeader()
		if err != nil {
			return fmt.Errorf("unable to decode folders.editPeerFolders#6847d0ab: field folder_peers: %w", err)
		}
		for idx := 0; idx < headerLen; idx++ {
			var value InputFolderPeer
			if err := value.Decode(b); err != nil {
				return fmt.Errorf("unable to decode folders.editPeerFolders#6847d0ab: field folder_peers: %w", err)
			}
			e.FolderPeers = append(e.FolderPeers, value)
		}
	}
	return nil
}

// Ensuring interfaces in compile-time for FoldersEditPeerFoldersRequest.
var (
	_ bin.Encoder = &FoldersEditPeerFoldersRequest{}
	_ bin.Decoder = &FoldersEditPeerFoldersRequest{}
)

// FoldersEditPeerFolders invokes method folders.editPeerFolders#6847d0ab returning error if any.
// Edit peers in peer folder¹
//
// Links:
//  1) https://core.telegram.org/api/folders#peer-folders
//
// Possible errors:
//  400 FOLDER_ID_INVALID: Invalid folder ID
//
// See https://core.telegram.org/method/folders.editPeerFolders for reference.
func (c *Client) FoldersEditPeerFolders(ctx context.Context, folderpeers []InputFolderPeer) (UpdatesClass, error) {
	var result UpdatesBox

	request := &FoldersEditPeerFoldersRequest{
		FolderPeers: folderpeers,
	}
	if err := c.rpc.InvokeRaw(ctx, request, &result); err != nil {
		return nil, err
	}
	return result.Updates, nil
}
