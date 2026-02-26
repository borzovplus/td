package telegram

import (
	"context"
	"testing"
	"time"

	"github.com/go-faster/errors"
	"github.com/stretchr/testify/require"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/clock"
	"github.com/gotd/td/crypto"
	"github.com/gotd/td/mtproto"
	"github.com/gotd/td/pool"
	"github.com/gotd/td/session"
	"github.com/gotd/td/tg"
)

func testAuthKey(fill byte) crypto.AuthKey {
	var k crypto.Key
	for i := range k {
		k[i] = fill
	}
	return k.WithID()
}

func TestClient_SaveSessionPersistsTempAuthKey(t *testing.T) {
	ctx := context.Background()
	storage := &session.StorageMemory{}
	client := NewClient(1, "hash", Options{
		UseTempAuthKey:     true,
		TempAuthKeyExpires: time.Hour,
		SessionStorage:     storage,
	})
	client.ctx = ctx

	perm := testAuthKey(1)
	temp := testAuthKey(2)
	client.setPermAuthKey(perm)
	client.markTempAuthKeyBound(temp.ID)

	err := client.saveSession(tg.Config{ThisDC: 2}, mtproto.Session{
		Key:  temp,
		Salt: 777,
	})
	require.NoError(t, err)

	loader := session.Loader{Storage: storage}
	data, err := loader.Load(ctx)
	require.NoError(t, err)
	require.Equal(t, perm.Value[:], data.AuthKey)
	require.Equal(t, perm.ID[:], data.AuthKeyID)
	require.Equal(t, temp.Value[:], data.TempAuthKey)
	require.Equal(t, temp.ID[:], data.TempAuthKeyID)
	require.Greater(t, data.TempAuthExpiresAt, time.Now().Unix())
}

func TestClient_SaveSessionKeepsTempAuthKeyExpiry(t *testing.T) {
	ctx := context.Background()
	storage := &session.StorageMemory{}
	loader := session.Loader{Storage: storage}

	perm := testAuthKey(11)
	temp := testAuthKey(12)
	expiresAt := time.Now().Add(30 * time.Minute).Unix()
	require.NoError(t, loader.Save(ctx, &session.Data{
		DC:                2,
		AuthKey:           perm.Value[:],
		AuthKeyID:         perm.ID[:],
		Salt:              101,
		TempAuthKey:       temp.Value[:],
		TempAuthKeyID:     temp.ID[:],
		TempAuthExpiresAt: expiresAt,
	}))

	client := NewClient(1, "hash", Options{
		UseTempAuthKey:     true,
		TempAuthKeyExpires: time.Hour,
		SessionStorage:     storage,
	})
	client.ctx = ctx
	client.setPermAuthKey(perm)
	client.markTempAuthKeyBound(temp.ID)

	require.NoError(t, client.saveSession(tg.Config{ThisDC: 2}, mtproto.Session{
		Key:  temp,
		Salt: 777,
	}))

	data, err := loader.Load(ctx)
	require.NoError(t, err)
	require.Equal(t, expiresAt, data.TempAuthExpiresAt)
}

func TestClient_SaveSessionSkipsUnboundTempAuthKey(t *testing.T) {
	ctx := context.Background()
	storage := &session.StorageMemory{}
	client := NewClient(1, "hash", Options{
		UseTempAuthKey:     true,
		TempAuthKeyExpires: time.Hour,
		SessionStorage:     storage,
	})
	client.ctx = ctx

	perm := testAuthKey(9)
	temp := testAuthKey(10)
	client.setPermAuthKey(perm)

	err := client.saveSession(tg.Config{ThisDC: 2}, mtproto.Session{
		Key:  temp,
		Salt: 777,
	})
	require.NoError(t, err)

	loader := session.Loader{Storage: storage}
	data, err := loader.Load(ctx)
	require.NoError(t, err)
	require.Nil(t, data.TempAuthKey)
	require.Nil(t, data.TempAuthKeyID)
	require.Zero(t, data.TempAuthExpiresAt)
}

func TestClient_RestoreConnectionUpgradesLegacySessionToTempFlow(t *testing.T) {
	ctx := context.Background()
	storage := &session.StorageMemory{}
	loader := session.Loader{Storage: storage}

	perm := testAuthKey(13)
	require.NoError(t, loader.Save(ctx, &session.Data{
		DC:        2,
		AuthKey:   perm.Value[:],
		AuthKeyID: perm.ID[:],
		Salt:      101,
	}))

	client := NewClient(1, "hash", Options{
		UseTempAuthKey: true,
		SessionStorage: storage,
	})
	require.NoError(t, client.restoreConnection(ctx))

	s := client.session.Load()
	require.True(t, s.AuthKey.Zero())
	require.Zero(t, s.Salt)
	require.Equal(t, perm.ID, client.permAuthKeyValue().ID)
}

func TestClient_RestoreConnectionUsesPersistedTempAuthKey(t *testing.T) {
	ctx := context.Background()
	storage := &session.StorageMemory{}
	loader := session.Loader{Storage: storage}

	perm := testAuthKey(3)
	temp := testAuthKey(4)
	require.NoError(t, loader.Save(ctx, &session.Data{
		DC:                2,
		AuthKey:           perm.Value[:],
		AuthKeyID:         perm.ID[:],
		Salt:              101,
		TempAuthKey:       temp.Value[:],
		TempAuthKeyID:     temp.ID[:],
		TempAuthExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))

	client := NewClient(1, "hash", Options{
		UseTempAuthKey: true,
		SessionStorage: storage,
	})
	require.NoError(t, client.restoreConnection(ctx))

	s := client.session.Load()
	require.Equal(t, temp.ID, s.AuthKey.ID)
	require.Equal(t, int64(101), s.Salt)
	require.Equal(t, perm.ID, client.permAuthKeyValue().ID)
	require.True(t, client.tempAuthKeyBound(temp.ID))
}

func TestClient_OnSessionTempAuthBindStrict(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		client := newTestClient(func(id int64, body bin.Encoder) (bin.Encoder, error) {
			switch body.(type) {
			case *tg.AuthBindTempAuthKeyRequest:
				return &tg.BoolTrue{}, nil
			default:
				return &tg.BoolTrue{}, nil
			}
		})
		client.useTempAuthKey = true
		client.tempAuthKeyExpire = time.Hour
		client.clock = clock.System
		client.setPermAuthKey(testAuthKey(5))
		client.session = pool.NewSyncSession(pool.Session{DC: 2})

		err := client.onSession(tg.Config{ThisDC: 2}, mtproto.Session{
			ID:   10,
			Key:  testAuthKey(6),
			Salt: 10,
		})
		require.NoError(t, err)

		select {
		case <-client.ready.Ready():
		default:
			t.Fatal("expected ready to be signaled")
		}
	})

	t.Run("Failure", func(t *testing.T) {
		client := newTestClient(func(id int64, body bin.Encoder) (bin.Encoder, error) {
			switch body.(type) {
			case *tg.AuthBindTempAuthKeyRequest:
				return nil, errors.New("bind failed")
			default:
				return &tg.BoolTrue{}, nil
			}
		})
		client.useTempAuthKey = true
		client.tempAuthKeyExpire = time.Hour
		client.clock = clock.System
		client.setPermAuthKey(testAuthKey(7))
		client.session = pool.NewSyncSession(pool.Session{DC: 2})

		err := client.onSession(tg.Config{ThisDC: 2}, mtproto.Session{
			ID:   10,
			Key:  testAuthKey(8),
			Salt: 10,
		})
		require.Error(t, err)

		select {
		case <-client.ready.Ready():
			t.Fatal("ready should not be signaled on bind failure")
		default:
		}
	})
}
