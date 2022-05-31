package session

import (
	"errors"
	"math"
	"net"
	"net/http"
	"strings"
)

type ClientSignatureList []ClientSignature

type ClientSignature struct {
	// Calculated based on heuristics.
	IPNetwork *net.IPNet

	// Client Hint UA Arch.
	Arch string

	// Client Hint UA Platform.
	Platform string

	// Client Hint UA Platform version.
	PlatformVersion string

	// Client Hint UA Device Pixel Ratio.
	DevicePixelRation string

	// JavaScript fingerprint sent with the authentication request.
	JSFingerprint string
}

// List of client hints the signature algorithm checks.
const CH_UA = "Sec-CH-UA"
const CH_UA_FULL_VERSION_LIST = "Sec-CH-UA-Full-Version-List"
const CH_UA_ARCH = "Sec-CH-UA-Arch"
const CH_UA_PLATFORM = "Sec-CH-UA-Platform"
const CH_UA_PLATFORM_VERSION = "Sec-CH-UA-Platform-Version"
const CH_DPR = "Sec-CH-DPR"

// Client JavaScript Fingerprint
const HEADER_JS_FINGERPRINT = "X-Beyond-Home-Fingerprint"

var ACCEPTED_CLIENT_HINTS = strings.Join([]string{
	CH_UA, CH_UA_FULL_VERSION_LIST,
	CH_UA_ARCH, CH_UA_PLATFORM, CH_UA_PLATFORM_VERSION,
	CH_DPR,
}, ", ")

// GenerateSignature returns a string that identifies a client device.
func GenerateSignature(req *http.Request) ClientSignature {
	var ipnet *net.IPNet

	// IP address.
	realIPs := req.Header.Values("X-Forwarded-For")
	if len(realIPs) == 1 {
		addrStr := realIPs[0]
		ipaddr := net.ParseIP(addrStr)
		if ipaddr != nil {
			// Heuristic for IP network detection.
			if len(ipaddr) == net.IPv4len {
				ipnet = &net.IPNet{
					IP:   ipaddr,
					Mask: net.CIDRMask(24, 32),
				}
			} else if len(ipaddr) == net.IPv6len {
				ipnet = &net.IPNet{
					IP:   ipaddr,
					Mask: net.CIDRMask(64, 128)}
			} else {
				panic(errors.New("Unreached"))
			}
		}
	}

	return ClientSignature{
		IPNetwork: ipnet,
	}
}

// Threshold for a signature to be considered sufficiently similar to
// existing signatures.
const CLIENT_SIGNATURE_VERIFICATION_THRESHOLD = 0.65

// CalculateSimilarity returns a similarity score between 0-1 between
// `sig` and all other signatures in `ls`.
//
// This score should be used to determine if re-authentication is needed
// when the client makes a request under a different signature (e.g. a
// new IP).
func (ls *ClientSignatureList) CalculateSimilarity(csig ClientSignature) float64 {
	var maxScore float64 = 0.0

	for _, s := range *ls {
		var sum float64 = 0
		if s.IPNetwork != nil && csig.IPNetwork != nil {
			if s.IPNetwork.IP.Equal(csig.IPNetwork.IP) {
				sum += 0.75
			} else if s.IPNetwork.Contains(csig.IPNetwork.IP) {
				sum += 0.33
			}
		}

		sum = math.Min(sum, 1.0)
		maxScore = math.Max(maxScore, sum)
	}

	return maxScore
}
