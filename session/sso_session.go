package session

import (
	"sync"
	"time"
)

// The number of time before a internalSsoSession object is removed from the storage map.
// Should allow enough time for concurrent calls manipulating on the ssoSession to complete.
const itemExpiryDelay = time.Second * 60

// SsoSession stores information about an active SSO session.
type SsoSession struct {
	IssuedAt         time.Time
	ReauthAfter      time.Time
	ClientSignatures ClientSignatureList
}

type internalSsoSession struct {
	Session  SsoSession
	ExpireAt time.Time
	// Timer to remove `this` from the map, triggered after `itemExpiryDelay` when `this` expires.
	ExpiryTimer *time.Timer
}

// sync.Map from SessionId to internalSsoSession
type SessionMap struct {
	m    map[string]internalSsoSession
	lock sync.RWMutex
}

func (sm *SessionMap) Get(sessionId string) *SsoSession {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	ssi, ok := sm.m[sessionId]
	if !ok {
		return nil
	}

	if ssi.ExpireAt.Before(time.Now()) {
		return nil
	}

	return &ssi.Session
}

func (sm *SessionMap) Set(sessionId string, expireAt time.Time, ssoSession SsoSession) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	ssi, ok := sm.m[sessionId]
	if ok {
		// Cancel timer.
		ssi.ExpiryTimer.Stop()
	}

	ssi = internalSsoSession{
		Session:     ssoSession,
		ExpireAt:    expireAt,
		ExpiryTimer: time.NewTimer(time.Until(expireAt.Add(itemExpiryDelay))),
	}
	go func(timer <-chan time.Time, sessionId string) {
		_, ok := <-timer
		if ok {
			sm.lock.Lock()
			defer sm.lock.Unlock()
			delete(sm.m, sessionId)
		}
	}(ssi.ExpiryTimer.C, sessionId)

	sm.m[sessionId] = ssi
}

func CreateSessionMap() SessionMap {
	return SessionMap{
		m:    make(map[string]internalSsoSession),
		lock: sync.RWMutex{},
	}
}
