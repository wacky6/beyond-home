package session

import (
	"time"
)

// SsoSession stores information about an active SSO session.
type SsoSession struct {
	IssuedAt         time.Time
	ReauthAfter      time.Time
	ClientSignatures ClientSignatureList
}

type SsoSessionInternal struct {
	Session     SsoSession
	ExpiryTimer *time.Timer
}

type SsoAction = int

type SsoManagerChannel = chan interface{}

type SsoSet struct {
	SessionId string
	Session   SsoSession
	ExpireAt  time.Time
	ReplyCh   chan interface{}
}
type SsoGet struct {
	SessionId string
	ReplyCh   chan (*SsoSession)
}

type SessionMap = map[string]SsoSessionInternal

func SessionManager(ch SsoManagerChannel) {
	ssoSessions := SessionMap{}

	for {
		op := <-ch
		switch v := op.(type) {
		case SsoSet:
			internalSession, found := ssoSessions[v.SessionId]
			if found && internalSession.ExpiryTimer != nil {
				internalSession.ExpiryTimer.Stop()
			}

			internalSession = SsoSessionInternal{
				Session:     v.Session,
				ExpiryTimer: time.NewTimer(time.Until(v.ExpireAt)),
			}

			ssoSessions[v.SessionId] = internalSession

			// Setup timeout
			go func(ssoSessions SessionMap, timer <-chan time.Time, sessionId string) {
				_, ok := <-timer
				if ok {
					delete(ssoSessions, v.SessionId)
				}
			}(ssoSessions, internalSession.ExpiryTimer.C, v.SessionId)
			v.ReplyCh <- true
		case SsoGet:
			internalSession, found := ssoSessions[v.SessionId]
			if !found {
				v.ReplyCh <- nil
			} else {
				v.ReplyCh <- &internalSession.Session
			}
		default:
			// No-op.
		}
	}
}
