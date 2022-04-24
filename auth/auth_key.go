package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/aquilax/truncate"
	"github.com/wacky6/beyond-home/util"
)

type AuthKeyType int

const (
	UNKNOWN = iota
	TYPE_ED25519
)

const (
	TYPE_ID_ED25519 = "ed25519"
)

// AuthKey stores information about a authentication public key.
type AuthKey struct {
	Type      AuthKeyType
	PublicKey []byte
	Identity  string
}

// Parse a AuthKey from a line.
// Format: <type_identifier> <base64_pubkey> <identity> [...options]
//
// Format is intentially different from OpenSSH authorized_keys to avoid
// misuse because BeyondHome authentication is less trustworthy than SSH.
func FromString(line string) (*AuthKey, error) {
	parts := util.RE_SPLIT_SPACES.Split(line, -1)
	if len(parts) < 3 {
		return nil, errors.New("invalid key format")
	}

	key := AuthKey{
		Identity: parts[2],
	}

	switch parts[0] {
	case TYPE_ID_ED25519:
		keyBytes, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, errors.New("bad key value")
		}

		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("bad key length, want: %d, got: %d", ed25519.PublicKeySize, len(keyBytes))
		}

		key.Type = TYPE_ED25519
		key.PublicKey = keyBytes

		return &key, nil
	default:
		return nil, errors.New("bad key type")
	}
}

// Read and return all valid keys stored in `path`.
// If `w` is provided, prints errors encountered during key parsing
// (e.g. invalid keys).
func ReadKeys(path string, w *io.Writer) ([]AuthKey, error) {
	var result []AuthKey
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return result, err
	}

	var lines = util.RE_SPLIT_NEWLINE.Split(string(content), -1)
	for lineNumber, line := range lines {
		var trimmedLine = strings.TrimSpace(line)
		if len(trimmedLine) == 0 {
			continue
		}

		key, err := FromString(trimmedLine)
		if err != nil && w != nil {
			fmt.Fprintf(*w,
				"WARN: invalid key at %s:%d (%s): %v\n",
				path,
				lineNumber+1,
				truncate.Truncate(trimmedLine, 10, "...", truncate.PositionEnd),
				err,
			)
		}

		if key != nil {
			result = append(result, *key)
		}
	}

	return result, nil
}
