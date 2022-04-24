package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/golang-jwt/jwt"
)

func (k *AuthKey) VerifyChallenge(challenge []byte, signature []byte) bool {
	switch k.Type {
	case TYPE_ED25519:
		return ed25519.Verify(k.PublicKey, challenge, signature)
	default:
		panic(errors.New("trying to verify an unknown key type"))
	}
}

type ChallengeResponse struct {
	// Base64 signature of challenge
	Signature string `json:"s"`
}

type JwtChallengePayload struct {
	*jwt.StandardClaims
	Challenge string `json:"c"`
}

func GenerateChallenge(secret []byte, nonceLength int, expireAt time.Time) string {
	// Generate a challenge
	nonce := make([]byte, nonceLength)
	io.ReadFull(rand.Reader, nonce)

	jwtStr, _ := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		JwtChallengePayload{
			&jwt.StandardClaims{
				ExpiresAt: expireAt.Unix(),
			},
			base64.StdEncoding.EncodeToString(nonce),
		},
	).SignedString(secret)

	return jwtStr
}

// ParseChallengeResponse returns client's response (signature with their private key) as []byte.
// The returned []byte should be verified by a crypto algorithm.
func ParseChallengeResponse(reader io.ReadCloser) (*[]byte, error) {
	var cr ChallengeResponse
	if err := json.NewDecoder(reader).Decode(&cr); err != nil {
		return nil, fmt.Errorf("can't parse challenge: %w", err)
	}

	crBytes, err := base64.StdEncoding.DecodeString(cr.Signature)
	if err != nil {
		return nil, fmt.Errorf("response is malformed: %w", err)
	}

	return &crBytes, nil
}

func ParseAndVerifyChallenge(secret []byte, jwtStr string) (string, error) {
	token, err := jwt.ParseWithClaims(jwtStr, &JwtChallengePayload{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("bad signing algorithm")
		}
		return secret, nil
	})

	if err != nil {
		return "", fmt.Errorf("malform jwt: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid jwt signature")
	}

	jwtPayload, ok := token.Claims.(*JwtChallengePayload)
	if !ok {
		return "", fmt.Errorf("malform jwt: missing required fields")
	}

	if time.Now().After(time.Unix(jwtPayload.ExpiresAt, 0)) {
		return "", fmt.Errorf("challenge expired")
	}

	return jwtPayload.Challenge, nil
}
