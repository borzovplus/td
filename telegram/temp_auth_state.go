package telegram

import "github.com/gotd/td/crypto"

func (c *Client) setPermAuthKey(key crypto.AuthKey) {
	c.tempAuthMux.Lock()
	c.permAuthKey = key
	c.boundTempAuthKey = [8]byte{}
	c.tempAuthMux.Unlock()
}

func (c *Client) permAuthKeyValue() crypto.AuthKey {
	c.tempAuthMux.RLock()
	key := c.permAuthKey
	c.tempAuthMux.RUnlock()
	return key
}

func (c *Client) clearBoundTempAuthKey() {
	c.tempAuthMux.Lock()
	c.boundTempAuthKey = [8]byte{}
	c.tempAuthMux.Unlock()
}

func (c *Client) tempAuthKeyBound(id [8]byte) bool {
	c.tempAuthMux.RLock()
	bound := c.boundTempAuthKey
	c.tempAuthMux.RUnlock()
	return id == bound
}

func (c *Client) markTempAuthKeyBound(id [8]byte) {
	c.tempAuthMux.Lock()
	c.boundTempAuthKey = id
	c.tempAuthMux.Unlock()
}
