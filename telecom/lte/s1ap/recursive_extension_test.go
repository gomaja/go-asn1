package s1ap

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

func dapsResponseInfoListWire(t *testing.T, erabID ERABID, indicator int64) []byte {
	t.Helper()
	itemWire, err := (&DAPSResponseInfoItem{
		ERABID: erabID,
		DAPSResponseInfo: DAPSResponseInfo{
			Dapsresponseindicator: indicator,
		},
	}).MarshalAPER()
	if err != nil {
		t.Fatalf("encoding DAPS response item: %v", err)
	}

	list := per.NewBitBuffer()
	if err := per.EncodeConstrainedWholeNumberAligned(list, 1, 1, MaxnoofERABs); err != nil {
		t.Fatalf("encoding DAPS response list length: %v", err)
	}
	if err := (&ProtocolIEField{
		Id: IdDAPSResponseInfoItem, Criticality: CriticalityIgnore,
		Value: runtime.RawValue{Bytes: itemWire},
	}).MarshalAPERTo(list); err != nil {
		t.Fatalf("encoding DAPS response list item: %v", err)
	}
	return list.Bytes()
}

func TestDecodeProtocolExtensionsRecursiveTargetTransparentContainerDAPS(t *testing.T) {
	// 3GPP TS 36.413 V19.2.0, S1AP-IEs: the typed
	// TargeteNB-ToSourceeNB-TransparentContainer extension set maps ID 318 to
	// DAPSResponseInfoList, whose items use DAPSResponseInfoListIEs.
	raw := dapsResponseInfoListWire(t, 5, 0)
	container := &TargeteNBToSourceeNBTransparentContainer{
		RRCContainer: RRCContainer{0x01},
		IEExtensions: ProtocolExtensionContainer{{
			Id: IdDAPSResponseInfoList, Criticality: CriticalityIgnore,
			ExtensionValue: runtime.RawValue{Bytes: raw},
		}},
	}

	decoded, err := DecodeProtocolExtensionsRecursive(container)
	if err != nil {
		t.Fatalf("recursive DAPS extension decode: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded extensions = %#v, want one", decoded)
	}
	extension := decoded[0]
	if extension.Path != "TargeteNBToSourceeNBTransparentContainer.IEExtensions[0]" ||
		extension.ObjectSet != "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs" {
		t.Errorf("extension context = (%q, %q)", extension.Path, extension.ObjectSet)
	}
	if !bytes.Equal(extension.Field.ExtensionValue.Bytes, raw) {
		t.Errorf("retained extension bytes = %x, want %x", extension.Field.ExtensionValue.Bytes, raw)
	}
	if len(extension.ProtocolIEs) != 1 {
		t.Fatalf("nested DAPS list = %#v, want one item", extension.ProtocolIEs)
	}
	itemNode := extension.ProtocolIEs[0]
	if itemNode.ObjectSet != "DAPSResponseInfoListIEs" || itemNode.Field.Id != IdDAPSResponseInfoItem {
		t.Errorf("nested item context = (%q, %d)", itemNode.ObjectSet, itemNode.Field.Id)
	}
	item, ok := itemNode.Value.(*DAPSResponseInfoItem)
	if !ok {
		t.Fatalf("nested item type = %T, want *DAPSResponseInfoItem", itemNode.Value)
	}
	if item.ERABID != 5 || item.DAPSResponseInfo.Dapsresponseindicator != 0 {
		t.Errorf("decoded DAPS item = %#v, want E-RAB 5 accepted", item)
	}
}

func TestDecodeProtocolExtensionFieldsRecursivePreservesUnknownExtension(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	decoded, err := DecodeProtocolExtensionFieldsRecursive(
		"TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs",
		[]ProtocolExtensionField{{Id: 65532, ExtensionValue: runtime.RawValue{Bytes: raw}}},
	)
	if err != nil {
		t.Fatalf("unknown extension decode: %v", err)
	}
	if len(decoded) != 1 || decoded[0].Value != nil {
		t.Fatalf("unknown extension result = %#v, want one unresolved node", decoded)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, raw) {
		t.Errorf("unknown extension bytes = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, raw)
	}
}

func TestDecodeProtocolExtensionsRecursiveReportsDAPSPath(t *testing.T) {
	container := &TargeteNBToSourceeNBTransparentContainer{
		IEExtensions: ProtocolExtensionContainer{{Id: IdDAPSResponseInfoList}},
	}
	_, err := DecodeProtocolExtensionsRecursive(container)
	if err == nil ||
		!strings.Contains(err.Error(), "TargeteNBToSourceeNBTransparentContainer.IEExtensions[0]") ||
		!strings.Contains(err.Error(), "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs") ||
		!strings.Contains(err.Error(), "extension 318") {
		t.Fatalf("malformed DAPS extension error = %v, want full path, object set, and ID", err)
	}
}

func FuzzDecodeProtocolExtensionFieldsRecursive(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeProtocolExtensionFieldsRecursive(
			"TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs",
			[]ProtocolExtensionField{{
				Id:             IdDAPSResponseInfoList,
				ExtensionValue: runtime.RawValue{Bytes: raw},
			}},
		)
	})
}
