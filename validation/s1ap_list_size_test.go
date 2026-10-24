package validation

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/s1ap"
	"github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
)

// Synthetic vectors only; expected bytes produced by pycrate 0.7.11 and
// decoded identically by tshark 4.6.8 (TS 36.413 V19.2.0, X.691 (02/2021)
// §§11.5.7.2, 11.9.3.3, 20.6).
const (
	synchronisationSyncHex = "10000000f11000000010"
	synchronisationBaseHex = "1000000000f11000000010"
	synchronisationPDUHex  = "002840320000010081402b4000f1100000001000f11000010000f1100000002000f110000100000000d1400a10000000f11000000010"
)

func synchronisationHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestS1APSynchronisationInformationVector(t *testing.T) {
	cell := runtime.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x10}, BitLength: 28}
	value := s1ap.SynchronisationInformation{AggressoreCGIList: s1ap.IEsECGIList{{PLMNidentity: s1ap.PLMNidentity{0x00, 0xf1, 0x10}, CellID: cell}}}
	got, err := value.MarshalAPER()
	if err != nil || !bytes.Equal(got, synchronisationHex(t, synchronisationSyncHex)) {
		t.Fatalf("MarshalAPER = %x, %v; want %s", got, err, synchronisationSyncHex)
	}
	var decoded s1ap.SynchronisationInformation
	if _, err := decoded.UnmarshalAPER(synchronisationHex(t, synchronisationSyncHex)); err != nil {
		t.Fatalf("UnmarshalAPER(expected): %v", err)
	}
	if len(decoded.AggressoreCGIList) != 1 || !bytes.Equal(decoded.AggressoreCGIList[0].PLMNidentity, []byte{0x00, 0xf1, 0x10}) ||
		decoded.AggressoreCGIList[0].CellID.BitLength != 28 || !bytes.Equal(decoded.AggressoreCGIList[0].CellID.Bytes, cell.Bytes) {
		t.Fatalf("decoded = %+v", decoded)
	}
	again, err := decoded.MarshalAPER()
	if err != nil || !bytes.Equal(again, synchronisationHex(t, synchronisationSyncHex)) {
		t.Fatalf("replay = %x, %v", again, err)
	}
	// The pre-fix two-octet count must not decode to the same value.
	var old s1ap.SynchronisationInformation
	if _, err := old.UnmarshalAPER(synchronisationHex(t, synchronisationBaseHex)); err == nil && len(old.AggressoreCGIList) == 1 &&
		bytes.Equal(old.AggressoreCGIList[0].PLMNidentity, []byte{0x00, 0xf1, 0x10}) {
		t.Fatalf("pre-fix encoding decoded as the expected value: %+v", old)
	}
}

func TestS1APENBConfigurationTransferTypedValues(t *testing.T) {
	wire := synchronisationHex(t, synchronisationPDUHex)
	var pdu s1ap.S1APPDU
	if _, err := pdu.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if again, err := pdu.MarshalAPER(); err != nil || !bytes.Equal(again, wire) {
		t.Fatalf("PDU replay = %x, %v", again, err)
	}
	transfer, ok := pdu.InitiatingMessage.Value.AsENBConfigurationTransfer()
	if !ok || len(transfer.ProtocolIEs) != 1 || transfer.ProtocolIEs[0].Id != 129 {
		t.Fatalf("transfer=%+v", transfer)
	}
	son, ok := transfer.ProtocolIEs[0].Value.AsSONConfigurationTransferECT()
	if !ok || len(son.IEExtensions) != 1 || son.IEExtensions[0].Id != 209 {
		t.Fatalf("SONConfigurationTransfer=%+v", son)
	}
	sync, ok := son.IEExtensions[0].ExtensionValue.AsSynchronisationInformation()
	if !ok || len(sync.AggressoreCGIList) != 1 || !bytes.Equal(sync.AggressoreCGIList[0].PLMNidentity, []byte{0, 0xf1, 0x10}) || sync.AggressoreCGIList[0].CellID.BitLength != 28 || !bytes.Equal(sync.AggressoreCGIList[0].CellID.Bytes, []byte{0, 0, 0, 0x10}) {
		t.Fatalf("SynchronisationInformation=%+v", sync)
	}

	if replay, err := sync.MarshalAPER(); err != nil || !bytes.Equal(replay, synchronisationHex(t, synchronisationSyncHex)) {
		t.Fatalf("extension replay = %x, %v", replay, err)
	}
}

// TS 36.413 V19.2.0 Annex B distinguishes ECGI-List (1..256) from
// ECGIList (1..65535); X.691 (02/2021) §§11.5.7.2, 11.9.3.3, 20.6.
func TestS1APAggressorListBoundary(t *testing.T) {
	cells := make(s1ap.IEsECGIList, 257)
	for i := range cells {
		cells[i] = s1ap.EUTRANCGI{
			PLMNidentity: []byte{0, 0xf1, 0x10},
			CellID:       runtime.BitString{Bytes: []byte{0, 0, 0, 0x10}, BitLength: 28},
		}
	}
	value := s1ap.SynchronisationInformation{AggressoreCGIList: cells[:256]}
	wire, err := value.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	// The list length is one octet, not the two octets used by ECGIList.
	if len(wire) != 1795 || !bytes.Equal(wire[:3], []byte{0x10, 0xff, 0x00}) {
		t.Fatalf("256-entry encoding: length %d, prefix %x", len(wire), wire[:3])
	}
	var decoded s1ap.SynchronisationInformation
	if _, err := decoded.UnmarshalAPER(wire); err != nil || len(decoded.AggressoreCGIList) != 256 {
		t.Fatalf("256-entry decode: %v, count %d", err, len(decoded.AggressoreCGIList))
	}
	if replay, err := decoded.MarshalAPER(); err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("256-entry replay: %v", err)
	}
	value.AggressoreCGIList = cells
	if _, err := value.MarshalAPER(); err == nil {
		t.Fatal("257 aggressor cells accepted")
	}
	large, err := s1ap.NewWarningAreaListCellIDList(s1ap.ECGIList(cells))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := large.MarshalAPER(); err != nil {
		t.Fatalf("the separate ECGIList must accept 257 cells: %v", err)
	}
}

func FuzzS1APSynchronisationInformation(f *testing.F) {
	for _, text := range []string{synchronisationSyncHex, synchronisationBaseHex, "0000"} {
		seed, err := hex.DecodeString(text)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			return
		}
		var value s1ap.SynchronisationInformation
		if _, err := value.UnmarshalAPER(wire); err != nil {
			return
		}
		if len(value.AggressoreCGIList) > 256 {
			t.Fatalf("decoded %d aggressor cells", len(value.AggressoreCGIList))
		}
		if replay, err := value.MarshalAPER(); err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("replay = %x, %v; want %x", replay, err, wire)
		}
	})
}
