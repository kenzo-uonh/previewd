package validate

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// DeliveryHeader carries GitHub's delivery GUID. GitHub does not sign it:
// the HMAC covers the body only. Callers must not trust it beyond ordering
// and must pair it with a content-based replay check.
const DeliveryHeader = "X-GitHub-Delivery"

// ErrDelivery rejects a delivery GUID that is not a canonical UUID version 1.
var ErrDelivery = errors.New("invalid delivery id")

// uuidEpochOffset is the number of 100-nanosecond intervals between the
// UUID epoch (1582-10-15 00:00 UTC) and the Unix epoch.
const uuidEpochOffset = 0x01B21DD213814000

// DeliveryID is a parsed X-GitHub-Delivery header.
type DeliveryID struct {
	// ID is the canonical lower-case form: the replay key.
	ID string
	// Seq is the UUIDv1 timestamp, 100-nanosecond intervals since the UUID
	// epoch: the ordering key of intents for one environment.
	Seq int64
	// Time is Seq as a wall-clock time.
	Time time.Time
}

// ParseDeliveryID accepts only the canonical 8-4-4-4-12 hexadecimal form of
// a UUID with version 1 and the RFC 4122 variant, whose timestamp is after
// the Unix epoch. Anything else (another version, braces, URN prefix,
// missing hyphens) is refused rather than given an arbitrary order.
func ParseDeliveryID(s string) (DeliveryID, error) {
	if len(s) != 36 {
		return DeliveryID{}, fmt.Errorf("%w: length %d, want 36", ErrDelivery, len(s))
	}
	for i := range len(s) {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return DeliveryID{}, fmt.Errorf("%w: %s", ErrDelivery, Quote(s))
			}
		default:
			if !isHex(c) {
				return DeliveryID{}, fmt.Errorf("%w: %s", ErrDelivery, Quote(s))
			}
		}
	}
	id := strings.ToLower(s)
	if id[14] != '1' {
		return DeliveryID{}, fmt.Errorf("%w: version %c, want 1 (time-based)", ErrDelivery, id[14])
	}
	switch id[19] {
	case '8', '9', 'a', 'b':
	default:
		return DeliveryID{}, fmt.Errorf("%w: not an RFC 4122 variant", ErrDelivery)
	}

	// time_low (32 bits) - time_mid (16) - version (4) time_hi (12).
	ticks := hexValue(id[15:18])<<48 | hexValue(id[9:13])<<32 | hexValue(id[0:8])
	if ticks <= uuidEpochOffset {
		return DeliveryID{}, fmt.Errorf("%w: timestamp before 1970", ErrDelivery)
	}
	unix100ns := ticks - uuidEpochOffset
	return DeliveryID{
		ID:   id,
		Seq:  int64(ticks),                                                    // #nosec G115 -- 60-bit value, fits in int64
		Time: time.Unix(int64(unix100ns/1e7), int64(unix100ns%1e7)*100).UTC(), // #nosec G115 -- bounded by the 60-bit timestamp
	}, nil
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// hexValue decodes lower-case hexadecimal already checked by isHex.
func hexValue(s string) uint64 {
	var v uint64
	for i := range len(s) {
		c := s[i]
		v <<= 4
		if c <= '9' {
			v |= uint64(c - '0')
		} else {
			v |= uint64(c-'a') + 10
		}
	}
	return v
}

// SeqAt is t on the scale of DeliveryID.Seq: 100-nanosecond intervals since
// the UUID epoch. A forge whose deliveries carry no time-based ID orders its
// intents by the instant it received them.
func SeqAt(t time.Time) int64 {
	return t.UnixNano()/100 + uuidEpochOffset
}
