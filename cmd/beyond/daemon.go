package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/wacky6/beyond-home/auth"
	"github.com/wacky6/beyond-home/session"
	frontend "github.com/wacky6/beyond-home/web"
)

type AuthKey = auth.AuthKey

var opts struct {
	// Default port is 0x10BE
	Port            int           `short:"p" long:"port" default:"4086" description:"Port to listen for nginx auth_request."`
	AuthKeys        string        `short:"k" long:"auth-keys" default:"/etc/beyond-keys" description:"Public key list file for authentication."`
	SsoDomain       string        `short:"d" long:"sso-domain" description:"The domain (and its subdomains) that are authenticated with beyond-home."`
	SsoExpiry       time.Duration `          long:"sso-expiry" default:"720h" description:"If the session hasn't been active for this amount of time, invalidate the SSO session. This triggers a full login audit (e.g. notification) on user's next session. Default is 1 month."`
	AuthExpiry      time.Duration `          long:"auth-expiry" default:"20h" description:"The amount of time before user has to re-authenticate. Should be shorter than --sso-expiry."`
	ChallengeExpiry time.Duration `          long:"challenge-expiry" default:"5m" description:"The amount of time before a challenge expires."`
	Realm           string        `short:"r" long:"realm" default:"be" description:"Scope of SSO, used to distinguish between SSO Cookies."`
	Telegram        string        `short:"t" long:"telegram" default:"" description:"Telegram <token>:<chat_id> to send audit notifications."`
}

var MIME_JSON = mime.TypeByExtension(".json")

const QUERY_REDIRECT = "r"

const HEADER_CONTENT_TYPE = "content-type"
const HEADER_X_FORWARDED_FOR = "x-forwarded-for"
const HEADER_X_FORWARDED_HOST = "x-forwarded-host"
const HEADER_X_FORWARDED_PROTO = "x-forwarded-proto"
const HEADER_ACCEPT_CH = "Accept-CH"

const jwtSecretLength = 32 // Per-runtime jwt secret
const jwtNonceLength = 32  // Per-authuentication nonce length
const sessionIdBytes = 48  // Number of bytes in Session ID

// Per-runtime jwt secret, used to sign and verify challenges sent to client.
var jwtSecret []byte

// Global variables derived from cmdline options.
var ssoCookieName string
var ssoChallengeCookieName string

var sm session.SessionMap = session.CreateSessionMap()

func handleAuthReq(w http.ResponseWriter, req *http.Request) {
	ssoCookie, err := req.Cookie(ssoCookieName)
	if err != nil {
		// SSO Cookie missing.
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	ssoSession := sm.Get(ssoCookie.Value)
	if ssoSession == nil {
		// Cookie is not associated with a session.
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if time.Now().After(ssoSession.ReauthAfter) {
		// Needs to re-authenticate.
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Check signature.
	curSig := session.GenerateSignature(req)
	curSigSimiliarity := ssoSession.ClientSignatures.CalculateSimilarity(curSig)
	if curSigSimiliarity < session.CLIENT_SIGNATURE_VERIFICATION_THRESHOLD {
		// Need to re-authenticate because the client signature isn't similar.
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// TODO: Update client signature to take into account of permanent / semi-permanent relocating
	// NOTE: SignatureLastActiveTime ?

	// Refresh session expiry.
	sm.Set(ssoCookie.Value, time.Now().Add(opts.SsoExpiry), *ssoSession)

	w.WriteHeader(http.StatusNoContent)
}

func refreshChallenge(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set(HEADER_CONTENT_TYPE, MIME_JSON)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"ok": false, "message": "Bad request"}`))
		return
	}

	w.Header().Set(HEADER_CONTENT_TYPE, MIME_JSON)
	if err := generateAndSetChallengeCookie(w, req); err != nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok": true}`))
	}
}

// Writes a challenge cookie with reaponse.
func generateAndSetChallengeCookie(w http.ResponseWriter, req *http.Request) error {
	expireAt := time.Now().Add(opts.ChallengeExpiry)
	http.SetCookie(w, &http.Cookie{
		Name:     ssoChallengeCookieName,
		Value:    auth.GenerateChallenge(jwtSecret, jwtNonceLength, expireAt),
		Path:     "/",
		Expires:  expireAt,
		SameSite: http.SameSiteStrictMode,
		HttpOnly: false, // Client JS needs to read and sign this challenge
		Secure:   true,
	})

	return nil
}

func handleChallengeResponse(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set(HEADER_CONTENT_TYPE, MIME_JSON)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"ok": false, "message": "Bad request"}`))
		return
	}

	// Parse challenge response and get client's signature.
	clientSigBytes, err := auth.ParseChallengeResponse(req.Body)
	if err != nil {
		w.Header().Set(HEADER_CONTENT_TYPE, MIME_JSON)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"ok": false, "message": "Bad request"}`))
		return
	}

	// Get the original challenge.
	challengeCookie, err := req.Cookie(ssoChallengeCookieName)
	var challenge string
	if challengeCookie != nil {
		challenge, err = auth.ParseAndVerifyChallenge(jwtSecret, challengeCookie.Value)
	}

	if err != nil {
		// The challenge sent from client is invalid. Generate a new one so client can retry.
		w.Header().Set(HEADER_CONTENT_TYPE, MIME_JSON)
		if err := generateAndSetChallengeCookie(w, req); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"ok": false, "message": "Internal error"}`))
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"ok": false, code: "CHALLENGE_EXPIRED", "message": "Challenge expired"}`))
		return
	}

	keys, _ := auth.ReadKeys(opts.AuthKeys, nil)
	keyIdx := 0
	verified := false
	for !verified && keyIdx < len(keys) {
		verified = keys[keyIdx].VerifyChallenge([]byte(challenge), *clientSigBytes)
		keyIdx += 1
	}

	if !verified {
		w.Header().Set(HEADER_CONTENT_TYPE, MIME_JSON)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"ok": false, "message": "Failed to authenticate"}`))
		return
	}

	var sessionId string
	var ssoSession *session.SsoSession

	if ssoCookie, _ := req.Cookie(ssoCookieName); ssoCookie != nil {
		ssoSession = sm.Get(ssoCookie.Value)
	}

	if ssoSession == nil {
		// Client is starting a new session.
		sessionIdBytes := make([]byte, sessionIdBytes)
		if _, err := io.ReadFull(rand.Reader, sessionIdBytes); err != nil {
			w.Header().Set(HEADER_CONTENT_TYPE, MIME_JSON)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"ok": false, "code": "TRY_AGAIN", "message": "Failed to generate session id"}`))
			return
		}

		sessionId = base64.StdEncoding.EncodeToString(sessionIdBytes)

		// Trigger login audit.
		// TODO: Send telegram notification.
		log.Printf("TODO: Trigger login audit")
	}

	var clientSignatures session.ClientSignatureList
	if ssoSession == nil {
		clientSignatures = []session.ClientSignature{}
	}

	newSsoSession := session.SsoSession{
		IssuedAt:         time.Now(),
		ReauthAfter:      time.Now().Add(opts.AuthExpiry),
		ClientSignatures: append(clientSignatures, session.GenerateSignature(req)),
	}

	sm.Set(sessionId, time.Now().Add(opts.SsoExpiry), newSsoSession)

	// Clear challenge cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     ssoChallengeCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		SameSite: http.SameSiteStrictMode,
		HttpOnly: false,
		Secure:   true,
	})

	// Set or refresh SSO Cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     ssoCookieName,
		Value:    sessionId,
		Domain:   opts.SsoDomain,
		Expires:  time.Now().Add(opts.SsoExpiry),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set(HEADER_CONTENT_TYPE, MIME_JSON)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok": true}`))
}

func handleIndex(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set(HEADER_CONTENT_TYPE, MIME_JSON)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"ok": false, "message": "Bad request"}`))
		return
	}

	log.Println("handleIndex") // DO NOT SUBMIT: DEBUG

	if req.URL.Query().Has(QUERY_REDIRECT) {
		if err := generateAndSetChallengeCookie(w, req); err != nil {
			// Failed to generate challenge.
			frontend.ServeError(frontend.ErrorServiceUnavailable, w)
			return
		}
	}

	// Send index page.
	w.Header().Set(HEADER_ACCEPT_CH, session.ACCEPTED_CLIENT_HINTS)
	frontend.Serve(w, req)
}

func handleLogOut(w http.ResponseWriter, req *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     ssoCookieName,
		Value:    "",
		Domain:   opts.SsoDomain,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set(HEADER_CONTENT_TYPE, MIME_JSON)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok": true}`))
}

func main() {
	if _, err := flags.Parse(&opts); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// TODO: check SsoDomain is reasonable.

	// Check key files during startup.
	log.Println("Checking keys...")
	writer := log.Writer()
	keys, err := auth.ReadKeys(opts.AuthKeys, &writer)
	if err != nil {
		log.Printf("WARN: can't read key file: %v", err)
	}
	log.Printf("Found %d keys at startup.", len(keys))

	ssoCookieName = fmt.Sprintf("beSso_%s", opts.Realm)
	ssoChallengeCookieName = fmt.Sprintf("beSsoCh_%s", opts.Realm)

	// Generate per-runtime jwt secret.
	jwtSecret = make([]byte, jwtSecretLength)
	if _, err := io.ReadFull(rand.Reader, jwtSecret); err != nil {
		log.Fatal("Can't initialize jwt secret: ", err)
		os.Exit(1)
	}

	http.HandleFunc("/auth_request", handleAuthReq)
	http.HandleFunc("/c", refreshChallenge)
	http.HandleFunc("/r", handleChallengeResponse)
	http.HandleFunc("/logout", handleLogOut)

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			handleIndex(w, req)
		} else {
			frontend.Serve(w, req)
		}
	})

	listenAddr := fmt.Sprintf(":%d", opts.Port)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatal("Can't start server: ", err)
		os.Exit(1)
	}
}
