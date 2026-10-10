package validation

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	lterrc "github.com/gomaja/go-asn1/telecom/lte/rrc"
	umtsrrc "github.com/gomaja/go-asn1/telecom/umts/rrc"
)

// SystemInfoListGERAN ::= SEQUENCE (SIZE (1..maxGERAN-SI)) OF OCTET STRING
// (SIZE (1..23)) (3GPP TS 36.331 V19.4.0 §6.3.4). Each element length is a
// 5-bit constrained whole number, length minus 1 (ITU-T X.691 (02/2021)
// §§17.8, 11.9.4.1). pycrate 0.7.11 produces these encodings and refuses
// elements of 0 and 24 octets (go-asn1#117).
func TestSystemInfoListGERANElementSize(t *testing.T) {
	long := bytes.Repeat([]byte{0xab}, 23)
	for _, c := range []struct {
		value lterrc.SystemInfoListGERAN
		hex   string
	}{
		{lterrc.SystemInfoListGERAN{{0x01}}, "000080"},
		{lterrc.SystemInfoListGERAN{{0x01, 0x02}}, "00808100"},
		{lterrc.SystemInfoListGERAN{{0x01}, {0x02}}, "10008008"},
		{lterrc.SystemInfoListGERAN{long}, "0b55d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d580"},
	} {
		wire := mustHex(t, c.hex)
		encoded, err := lterrc.MarshalUPERSystemInfoListGERAN(lterrc.SystemInfoListGERANComplete{Value: c.value})
		if err != nil || !bytes.Equal(encoded, wire) {
			t.Fatalf("encode %x = %x, %v; want %s", c.value, encoded, err, c.hex)
		}
		decoded, err := lterrc.UnmarshalUPERSystemInfoListGERAN(wire)
		if err != nil || !reflect.DeepEqual(decoded.Value, c.value) {
			t.Fatalf("decode %s = %x, %v", c.hex, decoded.Value, err)
		}
		if replay, err := decoded.MarshalUPER(); err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("replay %s = %x, %v", c.hex, replay, err)
		}
	}
	for _, size := range []int{0, 24} {
		value := lterrc.SystemInfoListGERANComplete{Value: lterrc.SystemInfoListGERAN{make([]byte, size)}}
		if encoded, err := lterrc.MarshalUPERSystemInfoListGERAN(value); err == nil {
			t.Fatalf("%d-octet element encoded as %x", size, encoded)
		}
	}
	// A length field of 23 announces a 24-octet element.
	if decoded, err := lterrc.UnmarshalUPERSystemInfoListGERAN(mustHex(t, "0bd5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d580")); err == nil {
		t.Fatalf("24-octet element decoded as %x", decoded.Value)
	}
}

// These contexts use the same element constraint as SystemInfoListGERAN
// (TS 36.331 V19.4.0 §6.3.4). pycrate 0.7.11 independently encodes and
// decodes psi = [01] and CellInfoGERAN-r9.systemInformation-r9 = [01].
func TestSIOrPSIGERANPsiElementSize(t *testing.T) {
	wire := mustHex(t, "800040")
	want := lterrc.SystemInfoListGERAN{{0x01}}
	value := lterrc.NewSIOrPSIGERANPsi(want)
	if encoded, err := value.MarshalUPER(); err != nil || !bytes.Equal(encoded, wire) {
		t.Fatalf("psi encode = %x, %v; want %x", encoded, err, wire)
	}
	var decoded lterrc.SIOrPSIGERAN
	if err := decoded.UnmarshalUPER(wire); err != nil {
		t.Fatal(err)
	}
	if decoded.Choice != lterrc.SIOrPSIGERANChoicePsi || !reflect.DeepEqual(decoded.Psi, want) {
		t.Fatalf("psi value = %+v, want %x", decoded, want)
	}
	if replay, err := decoded.MarshalUPER(); err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("psi replay = %x, %v; want %x", replay, err, wire)
	}
}

// The systemInformation-r9 component references SystemInfoListGERAN's
// element constraint (TS 36.331 V19.4.0 §6.3.4). pycrate 0.7.11 encodes this
// cell with one information octet 01 as ac25000040.
func TestCellInfoGERANR9SystemInformationElementSize(t *testing.T) {
	wire := mustHex(t, "ac25000040")
	want := lterrc.CellInfoGERANR9{
		PhysCellIdR9: lterrc.PhysCellIdGERAN{
			NetworkColourCode:     runtime.BitString{Bytes: []byte{0xa0}, BitLength: 3},
			BaseStationColourCode: runtime.BitString{Bytes: []byte{0x60}, BitLength: 3},
		},
		CarrierFreqR9:       lterrc.CarrierFreqGERAN{Arfcn: 37, BandIndicator: lterrc.BandIndicatorGERANDcs1800},
		SystemInformationR9: lterrc.SystemInfoListGERAN{{0x01}},
	}
	if encoded, err := want.MarshalUPER(); err != nil || !bytes.Equal(encoded, wire) {
		t.Fatalf("CellInfoGERAN-r9 encode = %x, %v; want %x", encoded, err, wire)
	}
	var decoded lterrc.CellInfoGERANR9
	if err := decoded.UnmarshalUPER(wire); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.SystemInformationR9, want.SystemInformationR9) ||
		!reflect.DeepEqual(decoded.PhysCellIdR9.NetworkColourCode, want.PhysCellIdR9.NetworkColourCode) ||
		!reflect.DeepEqual(decoded.PhysCellIdR9.BaseStationColourCode, want.PhysCellIdR9.BaseStationColourCode) ||
		decoded.CarrierFreqR9.Arfcn != want.CarrierFreqR9.Arfcn || decoded.CarrierFreqR9.BandIndicator != want.CarrierFreqR9.BandIndicator {
		t.Fatalf("CellInfoGERAN-r9 value = %+v, want %+v", decoded, want)
	}
	if replay, err := decoded.MarshalUPER(); err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("CellInfoGERAN-r9 replay = %x, %v; want %x", replay, err, wire)
	}
}

// DL-DCCH MobilityFromEUTRACommand-r9 handover to UTRA with an empty
// container and systemInformation si = [00]. Earlier releases decoded si as
// one empty element and still replayed the input. pycrate 0.7.11 and tshark
// 4.6.8 (lte-rrc.dl.dcch) decode si as one element 00.
func TestMobilityFromEUTRACommandGERANSystemInformation(t *testing.T) {
	wire := mustHex(t, "184080000000")
	var message lterrc.DLDCCHMessage
	if err := message.UnmarshalUPER(wire); err != nil {
		t.Fatal(err)
	}
	text, err := json.Marshal(&message)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), `"SystemInformation":{"Choice":1,"Si":["AA=="]}`) {
		t.Fatalf("systemInformation lost its element: %s", text)
	}
	if replay, err := message.MarshalUPER(); err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("replay = %x, %v", replay, err)
	}
}

// IntraFreqMeasQuantity-TDD-sib3List ::= SEQUENCE (SIZE (1..2)) OF
// ENUMERATED { primaryCCPCH-RSCP, timeslotISCP } (3GPP TS 25.331 V19.0.1
// §11.3). Earlier releases generated an enumeration root count of 0 and
// rejected every value. pycrate 0.7.11 and tshark 4.6.8 (rrc.si.sib3) decode
// the SIB3 list as [timeslotISCP, primaryCCPCH-RSCP].
func TestIntraFreqMeasQuantityTDDSib3List(t *testing.T) {
	sib3 := mustHex(t, "848d159cc081063bd511e0")
	var info umtsrrc.SysInfoType3
	if err := info.UnmarshalUPER(sib3); err != nil {
		t.Fatal(err)
	}
	text, err := json.Marshal(&info)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), `"IntraFreqMeasQuantityTDDList":[1,0]`) {
		t.Fatalf("TDD list = %s", text)
	}
	if replay, err := info.MarshalUPER(); err != nil || !bytes.Equal(replay, sib3) {
		t.Fatalf("SIB3 replay = %x, %v", replay, err)
	}

	extension := mustHex(t, "8d")
	var v770 umtsrrc.SysInfoType3V770extIEs
	if err := v770.UnmarshalUPER(extension); err != nil {
		t.Fatal(err)
	}
	support := v770.DeferredMeasurementControlReadingSupport
	if support == nil || support.ModeSpecificInfo == nil || support.ModeSpecificInfo.Tdd == nil ||
		!reflect.DeepEqual(support.ModeSpecificInfo.Tdd.IntraFreqMeasQuantityTDDList, umtsrrc.IntraFreqMeasQuantityTDDSib3List{1}) {
		t.Fatalf("v770 extension = %+v", v770)
	}
	if replay, err := v770.MarshalUPER(); err != nil || !bytes.Equal(replay, extension) {
		t.Fatalf("v770 replay = %x, %v", replay, err)
	}
}

// The exported named-list codecs must retain the two-root enumeration too
// (TS 25.331 V19.0.1 §11.3; X.691 (02/2021) §14). pycrate 0.7.11 encodes
// [timeslotISCP, primaryCCPCH-RSCP] as c0.
func TestNamedIntraFreqMeasQuantityTDDSib3List(t *testing.T) {
	wire := mustHex(t, "c0")
	want := umtsrrc.IntraFreqMeasQuantityTDDSib3List{1, 0}
	encoded, err := umtsrrc.MarshalUPERIntraFreqMeasQuantityTDDSib3List(umtsrrc.IntraFreqMeasQuantityTDDSib3ListComplete{Value: want})
	if err != nil || !bytes.Equal(encoded, wire) {
		t.Fatalf("named TDD list encode = %x, %v; want %x", encoded, err, wire)
	}
	decoded, err := umtsrrc.UnmarshalUPERIntraFreqMeasQuantityTDDSib3List(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Value, want) {
		t.Fatalf("named TDD list = %v, want %v", decoded.Value, want)
	}
	if replay, err := decoded.MarshalUPER(); err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("named TDD list replay = %x, %v; want %x", replay, err, wire)
	}
}
