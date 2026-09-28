package esim_test

import (
	"errors"
	"math"
	"strconv"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/esim/sgp22"
)

func TestSubjectPublicKeyBitLengthHostBoundary(t *testing.T) {
	if strconv.IntSize != 32 {
		t.Skip("the 32-bit host boundary needs a representable test allocation")
	}
	// X.690 (02/2021) §8.6: the BIT STRING content starts with its
	// unused-bit count. The octets below put the value at MaxInt bits
	// when unused=1, and one bit above MaxInt when unused=0.
	wire := make([]byte, 19+1<<28)
	copy(wire, []byte{
		0x30, 0x84, 0x10, 0x00, 0x00, 0x0d,
		0x30, 0x04, 0x06, 0x02, 0x2a, 0x03,
		0x03, 0x84, 0x10, 0x00, 0x00, 0x01,
	})
	// The header is 18 octets; the first content octet is the unused count.
	wire[18] = 1
	var value sgp22.SubjectPublicKeyInfo
	opts := ber.WithDecodeLimits(ber.DecodeLimits{MaxWork: 1 << 30})
	if err := value.UnmarshalBER(wire, opts); err != nil {
		t.Fatalf("exact boundary rejected: %v", err)
	}
	if value.SubjectPublicKey.BitLength != math.MaxInt {
		t.Fatalf("exact boundary length = %d", value.SubjectPublicKey.BitLength)
	}
	wire[18] = 0
	wire[len(wire)-1] = 1
	if err := value.UnmarshalBER(wire, opts); !errors.Is(err, ber.ErrInvalidValue) {
		t.Fatalf("overflowing BIT STRING accepted: length=%d, err=%v", value.SubjectPublicKey.BitLength, err)
	}
}
