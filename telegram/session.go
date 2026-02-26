package telegram

import (
	"context"
	"fmt"

	"github.com/go-faster/errors"
	"go.uber.org/zap"

	"github.com/gotd/td/crypto"
	"github.com/gotd/td/mtproto"
	"github.com/gotd/td/pool"
	"github.com/gotd/td/session"
	"github.com/gotd/td/tg"
)

func (c *Client) restoreConnection(ctx context.Context) error {
	if c.storage == nil {
		return nil
	}

	data, err := c.storage.Load(ctx)
	if errors.Is(err, session.ErrNotFound) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "load")
	}

	// If file does not contain DC ID, so we use DC from options.
	prev := c.session.Load()
	if data.DC == 0 {
		data.DC = prev.DC
	}

	// Restoring persisted auth key.
	var key crypto.AuthKey
	copy(key.Value[:], data.AuthKey)
	copy(key.ID[:], data.AuthKeyID)

	if key.Value.ID() != key.ID {
		return errors.New("corrupted key")
	}

	// Re-initializing connection from persisted state.
	c.log.Info("Connection restored from state",
		zap.String("addr", data.Addr),
		zap.String("key_id", fmt.Sprintf("%x", data.AuthKeyID)),
	)

	c.connMux.Lock()
	runtimeKey := key
	runtimeSalt := data.Salt
	if c.useTempAuthKey {
		// We only persist permanent auth key and derive temporary key on connect.
		c.setPermAuthKey(key)
		runtimeKey = crypto.AuthKey{}
		runtimeSalt = 0
		if temp, ok := c.loadPersistedTempAuthKey(data); ok {
			runtimeKey = temp
			runtimeSalt = data.Salt
			c.markTempAuthKeyBound(temp.ID)
		}
	}
	c.session.Store(pool.Session{
		DC:      data.DC,
		AuthKey: runtimeKey,
		Salt:    runtimeSalt,
	})
	c.conn = c.createPrimaryConn(nil)
	c.connMux.Unlock()

	return nil
}

func (c *Client) saveSession(cfg tg.Config, s mtproto.Session) error {
	if c.storage == nil {
		return nil
	}

	data, err := c.storage.Load(c.ctx)
	if errors.Is(err, session.ErrNotFound) {
		// Initializing new state.
		err = nil
		data = &session.Data{}
	}
	if err != nil {
		return errors.Wrap(err, "load")
	}

	// Updating previous data.
	data.Config = session.ConfigFromTG(cfg)
	persisted := s.Key
	if c.useTempAuthKey {
		prevTempAuthKeyID := append([]byte(nil), data.TempAuthKeyID...)
		prevTempAuthExpiresAt := data.TempAuthExpiresAt
		if key := c.permAuthKeyValue(); !key.Zero() {
			persisted = key
		}
		if persisted.ID != s.Key.ID && c.tempAuthKeyBound(s.Key.ID) {
			expiresAt := c.clock.Now().Add(c.tempAuthExpires()).Unix()
			if prevTempAuthExpiresAt > 0 && len(prevTempAuthKeyID) == len(s.Key.ID) {
				sameTempKey := true
				for i := range s.Key.ID {
					if prevTempAuthKeyID[i] != s.Key.ID[i] {
						sameTempKey = false
						break
					}
				}
				if sameTempKey {
					// Temp key expiry is fixed at bind time, do not extend it on each save.
					expiresAt = prevTempAuthExpiresAt
				}
			}
			data.TempAuthKey = append([]byte(nil), s.Key.Value[:]...)
			data.TempAuthKeyID = append([]byte(nil), s.Key.ID[:]...)
			data.TempAuthExpiresAt = expiresAt
		} else {
			data.TempAuthKey = nil
			data.TempAuthKeyID = nil
			data.TempAuthExpiresAt = 0
		}
	} else {
		data.TempAuthKey = nil
		data.TempAuthKeyID = nil
		data.TempAuthExpiresAt = 0
	}
	data.AuthKey = persisted.Value[:]
	data.AuthKeyID = persisted.ID[:]
	data.DC = cfg.ThisDC
	data.Salt = s.Salt

	if err := c.storage.Save(c.ctx, data); err != nil {
		return errors.Wrap(err, "save")
	}

	c.log.Debug("Data saved",
		zap.String("key_id", fmt.Sprintf("%x", data.AuthKeyID)),
	)
	return nil
}

func (c *Client) onSession(cfg tg.Config, s mtproto.Session) error {
	if c.useTempAuthKey && c.permAuthKeyValue().Zero() {
		// The first authorized session key is permanent.
		c.setPermAuthKey(s.Key)
	}

	c.sessionsMux.Lock()
	c.sessions[cfg.ThisDC] = pool.NewSyncSession(pool.Session{
		DC:      cfg.ThisDC,
		Salt:    s.Salt,
		AuthKey: s.Key,
	})
	c.sessionsMux.Unlock()

	primaryDC := c.session.Load().DC
	// Do not save session for non-primary DC.
	if cfg.ThisDC != 0 && primaryDC != 0 && primaryDC != cfg.ThisDC {
		return nil
	}

	c.connMux.Lock()
	c.session.Store(pool.Session{
		DC:      cfg.ThisDC,
		Salt:    s.Salt,
		AuthKey: s.Key,
	})
	c.cfg.Store(cfg)
	c.connMux.Unlock()

	if c.useTempAuthKey {
		perm := c.permAuthKeyValue()
		if !perm.Zero() && perm.ID != s.Key.ID && !c.tempAuthKeyBound(s.Key.ID) {
			if err := c.bindTempAuthKeySync(cfg.ThisDC, perm, s); err != nil {
				return errors.Wrap(err, "bind temporary auth key")
			}
		}
	}
	c.onReady()

	if err := c.saveSession(cfg, s); err != nil {
		return errors.Wrap(err, "save")
	}

	return nil
}

func (c *Client) loadPersistedTempAuthKey(data *session.Data) (_ crypto.AuthKey, ok bool) {
	if data.TempAuthExpiresAt <= c.clock.Now().Unix() {
		return crypto.AuthKey{}, false
	}

	var key crypto.AuthKey
	if len(data.TempAuthKey) != len(key.Value) || len(data.TempAuthKeyID) != len(key.ID) {
		return crypto.AuthKey{}, false
	}
	copy(key.Value[:], data.TempAuthKey)
	copy(key.ID[:], data.TempAuthKeyID)
	if key.Value.ID() != key.ID {
		return crypto.AuthKey{}, false
	}
	return key, true
}

func (c *Client) persistBoundTempAuthKey(s mtproto.Session) error {
	current := c.session.Load()
	if current.AuthKey.ID != s.Key.ID {
		return nil
	}
	return c.saveSession(c.cfg.Load(), mtproto.Session{
		Key:  s.Key,
		Salt: current.Salt,
	})
}
