package lppa

import (
	"errors"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s22"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"testing"
)

// Strict decoding rejects nonzero terminal padding (X.691 (02/2021)
// §11.1.4). Fresh encoding retains its preferred extension framing
// (§§19.8–19.9), including below table and procedure bindings.
func TestValueCodecWithoutReplayReachesNestedEncoders(t *testing.T) {
	t.Run("table padding", func(t *testing.T) {
		body := CriticalityDiagnostics{}
		preferred := sliceByteCodecFreshMust(body.MarshalAPER())
		wire := append([]byte(nil), preferred...)
		wire[len(wire)-1] |= 1
		_, _, err := ErrorIndicationIEs().CriticalityDiagnostics().Codec().DecodeAPER(wire)
		if !errors.Is(err, aper.ErrSyntax) {
			t.Fatalf("nonzero embedded padding accepted: %v", err)
		}
	})
	t.Run("named sequence framing and padding", func(t *testing.T) {
		value := int64(1)
		body := NPRSSubframePartB{SIB1NBSubframeTDD: &value}
		preferred := sliceByteCodecFreshMust(body.MarshalAPER())
		*s07.BridgeNPRSSubframePartBFieldExtCount(&body) = 3
		*s07.BridgeNPRSSubframePartBFieldExtPresent(&body) = make([]bool, 4)
		*s07.BridgeNPRSSubframePartBFieldExtData(&body) = make([][]byte, 4)
		wire := sliceByteCodecFreshMust(body.MarshalAPER())
		nPRSSubframePartBCheckCodecFresh(t, NPRSSubframePartBCodec(), wire, preferred)
	})
	t.Run("table list nested framing", func(t *testing.T) {
		item := MeasurementQuantitiesItem{}
		if err := item.SetExtension(0, []byte{0x80}); err != nil {
			t.Fatal(err)
		}
		preferredField := measurementQuantitiesItemIEFieldCodecFreshMust(MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().New(item))
		preferred := sliceByteCodecFreshMust((&MeasurementQuantitiesComplete{Value: MeasurementQuantities{preferredField}}).MarshalAPER())
		*s06.BridgeMeasurementQuantitiesItemFieldExtCount(&item) = 3
		*s06.BridgeMeasurementQuantitiesItemFieldExtPresent(&item) = append(*s06.BridgeMeasurementQuantitiesItemFieldExtPresent(&item), false, false, false)
		*s06.BridgeMeasurementQuantitiesItemFieldExtData(&item) = append(*s06.BridgeMeasurementQuantitiesItemFieldExtData(&item), nil, nil, nil)
		field := measurementQuantitiesItemIEFieldCodecFreshMust(MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().New(item))
		wire := sliceByteCodecFreshMust((&MeasurementQuantitiesComplete{Value: MeasurementQuantities{field}}).MarshalAPER())
		measurementQuantitiesCheckCodecFresh(t, MeasurementQuantitiesCodec(), wire, preferred)
	})
	t.Run("named list nested framing", func(t *testing.T) {
		item := ResultNRItem{}
		if err := item.SetExtension(0, []byte{0x80}); err != nil {
			t.Fatal(err)
		}
		preferred := sliceByteCodecFreshMust((&ResultNRComplete{Value: ResultNR{item}}).MarshalAPER())
		*s19.BridgeResultNRItemFieldExtCount(&item) = 3
		*s19.BridgeResultNRItemFieldExtPresent(&item) = append(*s19.BridgeResultNRItemFieldExtPresent(&item), false, false, false)
		*s19.BridgeResultNRItemFieldExtData(&item) = append(*s19.BridgeResultNRItemFieldExtData(&item), nil, nil, nil)
		wire := sliceByteCodecFreshMust((&ResultNRComplete{Value: ResultNR{item}}).MarshalAPER())
		resultNRCheckCodecFresh(t, ResultNRCodec(), wire, preferred)
	})
	t.Run("initiating procedure", func(t *testing.T) {
		body := ErrorIndication{}
		if err := body.SetExtension(0, []byte{0x80}); err != nil {
			t.Fatal(err)
		}
		preferred := sliceByteCodecFreshMust(body.MarshalAPER())
		*s11.BridgeErrorIndicationFieldExtCount(&body) = 3
		*s11.BridgeErrorIndicationFieldExtPresent(&body) = append(*s11.BridgeErrorIndicationFieldExtPresent(&body), false, false, false)
		*s11.BridgeErrorIndicationFieldExtData(&body) = append(*s11.BridgeErrorIndicationFieldExtData(&body), nil, nil, nil)
		errorIndicationCheckCodecFresh(t, ErrorIndicationProcedure().Initiating().Codec(), sliceByteCodecFreshMust(body.MarshalAPER()), preferred)
	})
	t.Run("successful procedure", func(t *testing.T) {
		body := ECIDMeasurementInitiationResponse{}
		if err := body.SetExtension(0, []byte{0x80}); err != nil {
			t.Fatal(err)
		}
		preferred := sliceByteCodecFreshMust(body.MarshalAPER())
		*s22.BridgeECIDMeasurementInitiationResponseFieldExtCount(&body) = 3
		*s22.BridgeECIDMeasurementInitiationResponseFieldExtPresent(&body) = append(*s22.BridgeECIDMeasurementInitiationResponseFieldExtPresent(&body), false, false, false)
		*s22.BridgeECIDMeasurementInitiationResponseFieldExtData(&body) = append(*s22.BridgeECIDMeasurementInitiationResponseFieldExtData(&body), nil, nil, nil)
		eCIDMeasurementInitiationResponseCheckCodecFresh(t, ECIDMeasurementInitiationProcedure().Successful().Codec(), sliceByteCodecFreshMust(body.MarshalAPER()), preferred)
	})
	t.Run("unsuccessful procedure", func(t *testing.T) {
		body := ECIDMeasurementInitiationFailure{}
		if err := body.SetExtension(0, []byte{0x80}); err != nil {
			t.Fatal(err)
		}
		preferred := sliceByteCodecFreshMust(body.MarshalAPER())
		*s11.BridgeECIDMeasurementInitiationFailureFieldExtCount(&body) = 3
		*s11.BridgeECIDMeasurementInitiationFailureFieldExtPresent(&body) = append(*s11.BridgeECIDMeasurementInitiationFailureFieldExtPresent(&body), false, false, false)
		*s11.BridgeECIDMeasurementInitiationFailureFieldExtData(&body) = append(*s11.BridgeECIDMeasurementInitiationFailureFieldExtData(&body), nil, nil, nil)
		eCIDMeasurementInitiationFailureCheckCodecFresh(t, ECIDMeasurementInitiationProcedure().Unsuccessful().Codec(), sliceByteCodecFreshMust(body.MarshalAPER()), preferred)
	})
}
