package session

import "net/http"

type ClientSignatureList []ClientSignature

type ClientSignature struct {
	// TODO: define signature
}

// GenerateSignature returns a string that identifies a client device.
func GenerateSignature(req *http.Request) ClientSignature {
	return ClientSignature{}
}

// Threshold for a signature to be considered sufficiently similar with
// existing signatures.
const CLIENT_SIGNATURE_VERIFICATION_THRESHOLD = 0.5

// CalculateSimilarity returns a similarity score between 0-1 between
// `sig` and all other signatures in `ls`.
//
// This score should be used to determine if re-authentication is needed
// when the client makes a request under a different signature (e.g. a
// new IP).
func (ls *ClientSignatureList) CalculateSimilarity(csig ClientSignature) float32 {
	return 1.0
}
