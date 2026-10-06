package validation

import (
	"encoding/hex"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
	"github.com/gomaja/go-asn1/telecom/lte/rrc"
)

type uperValue interface {
	UnmarshalUPER([]byte) error
	MarshalUPER() ([]byte, error)
}

func uperHex(t *testing.T, value uperValue) string {
	t.Helper()
	out, err := value.MarshalUPER()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(out)
}

func replayHex(t *testing.T, value uperValue, text string) {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	if err := value.UnmarshalUPER(data); err != nil {
		t.Fatalf("decoding %s: %v", text, err)
	}
	if got := uperHex(t, value); got != text {
		t.Fatalf("decoded %s, re-encoded %s", text, got)
	}
}

// ITU-T X.691 (02/2021) §19.5 leaves out a DEFAULT component of a simple type
// that holds its default value. The pinned encodings are pycrate 0.7.11's:
// with its default canonical mode it leaves such components out, and with
// ASN1CodecPER.CANONICAL off it sends them, as some senders do. tshark 4.6.8
// dissects the DL-DCCH pair with offsetFreq dB0 and filterCoefficientRSRP and
// RSRQ fc4 absent and present respectively.
func TestDefaultComponentsOmittedAndReplayed(t *testing.T) {
	dB0, fc4 := rrc.QOffsetRangeDB0, rrc.FilterCoefficientFc4

	var measObject rrc.MeasObjectEUTRA
	replayHex(t, &measObject, "0000c808")
	measObject.OffsetFreq = &dB0
	if got := uperHex(t, &measObject); got != "0000c808" {
		t.Errorf("MeasObjectEUTRA with offsetFreq dB0: %s, want 0000c808", got)
	}
	replayHex(t, &measObject, "4000c80bc0")
	if measObject.OffsetFreq == nil || *measObject.OffsetFreq != dB0 {
		t.Errorf("explicit offsetFreq dB0 decoded as %v", measObject.OffsetFreq)
	}
	replayHex(t, &measObject, "4000c80c80") // dB3 is sent

	quantity := rrc.QuantityConfigEUTRA{FilterCoefficientRSRP: &fc4, FilterCoefficientRSRQ: &fc4}
	if got := uperHex(t, &quantity); got != "00" {
		t.Errorf("QuantityConfigEUTRA fc4, fc4: %s, want 00", got)
	}
	replayHex(t, &quantity, "c840")

	var geran rrc.MeasObjectGERAN
	replayHex(t, &geran, "000400")
	zero := rrc.QOffsetRangeInterRAT(0)
	geran.OffsetFreq, geran.NccPermitted = &zero, &runtime.BitString{Bytes: []byte{0xff}, BitLength: 8}
	if got := uperHex(t, &geran); got != "000400" {
		t.Errorf("MeasObjectGERAN at its defaults: %s, want 000400", got)
	}
	replayHex(t, &geran, "600401ffe0")

	const canonical, explicit = "22101080000000320280", "221010800010003202f46420"
	var message rrc.DLDCCHMessage
	replayHex(t, &message, explicit)
	r8 := message.Message.C1.RrcConnectionReconfiguration.CriticalExtensions.C1.RrcConnectionReconfigurationR8
	eutra := r8.MeasConfig.MeasObjectToAddModList[0].MeasObject.MeasObjectEUTRA
	eutra.PERPadding_ = per.FinalPadding{}
	r8.MeasConfig.QuantityConfig.QuantityConfigEUTRA.PERPadding_ = per.FinalPadding{}
	if got := uperHex(t, &message); got != canonical {
		t.Errorf("DL-DCCH without its records: %s, want %s", got, canonical)
	}
	replayHex(t, &message, canonical)

	// Recording the explicit defaults allocates nothing.
	data, _ := hex.DecodeString(explicit)
	plain, _ := hex.DecodeString(canonical)
	explicitAllocations := testing.AllocsPerRun(50, func() { _ = message.UnmarshalUPER(data) })
	plainAllocations := testing.AllocsPerRun(50, func() { _ = message.UnmarshalUPER(plain) })
	if explicitAllocations != plainAllocations+3 {
		t.Errorf("explicit decode allocates %v, without the three components %v: want only their values", explicitAllocations, plainAllocations)
	}
}
