package session

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func testStorage(storage Storage) func(t *testing.T) {
	ctx := context.Background()
	loader := Loader{
		Storage: storage,
	}

	return func(t *testing.T) {
		a := require.New(t)

		_, err := loader.Load(ctx)
		a.ErrorIs(err, ErrNotFound)

		data := &Data{
			Config:    Config{},
			DC:        2,
			Addr:      "localhost:8080",
			AuthKey:   bytes.Repeat([]byte{'a'}, 256),
			AuthKeyID: []byte("gotd1337"),
			Salt:      10,
		}
		a.NoError(loader.Save(ctx, data))

		gotData, err := loader.Load(ctx)
		a.NoError(err)
		require.Equal(t, data, gotData)
	}
}

func TestLoader_LoadVersion1(t *testing.T) {
	a := require.New(t)
	ctx := context.Background()
	storage := &StorageMemory{}
	loader := Loader{Storage: storage}

	data := Data{
		Config:    Config{},
		DC:        2,
		Addr:      "localhost:8080",
		AuthKey:   bytes.Repeat([]byte{'a'}, 256),
		AuthKeyID: []byte("gotd1337"),
		Salt:      10,
	}

	raw, err := json.Marshal(struct {
		Version int
		Data    Data
	}{
		Version: sessionVersion1,
		Data:    data,
	})
	a.NoError(err)
	a.NoError(storage.StoreSession(ctx, raw))

	got, err := loader.Load(ctx)
	a.NoError(err)
	a.Equal(&data, got)
}
