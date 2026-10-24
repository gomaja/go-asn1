package lppa

import (
	q11 "errors"
	bridge1 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	bridge3 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	bridge2 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	bridge4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s22"

	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q8 "testing"
)

// Strict decoding rejects nonzero terminal padding (X.691 (02/2021)
// §11.1.4). Fresh encoding retains its preferred extension framing
// (§§19.8–19.9), including below table and procedure bindings.
func TestValueCodecWithoutReplayReachesNestedEncoders(t *q8.T) {
	t.Run("table padding", func(t *q8.T) {
		body := CriticalityDiagnostics{}
		preferred := sliceByteCodecFreshMust(body.MarshalAPER())
		wire := append([]byte(nil), preferred...)
		wire[len(wire)-1] |= 1
		_, _, err := ErrorIndicationIEs().CriticalityDiagnostics().Codec().DecodeAPER(wire)
		if !q11.Is(err, q12.ErrSyntax) {
			t.Fatalf("nonzero embedded padding accepted: %v", err)
		}
	})
	t.Run("named sequence framing and padding", func(t *q8.T) {
		value := int64(1)
		body := NPRSSubframePartB{SIB1NBSubframeTDD: &value}
		preferred := sliceByteCodecFreshMust(body.MarshalAPER())
		*bridge0.BridgeNPRSSubframePartBFieldExtCount(&body) = 3
		*bridge0.BridgeNPRSSubframePartBFieldExtPresent(&body) = make([]bool, 4)
		*bridge0.BridgeNPRSSubframePartBFieldExtData(&body) = make([][]byte, 4)
		wire := sliceByteCodecFreshMust(body.MarshalAPER())
		nPRSSubframePartBCheckCodecFresh(t, NPRSSubframePartBCodec(), wire, preferred)
	})
	t.Run("table list nested framing", func(t *q8.T) {
		item := MeasurementQuantitiesItem{}
		if err := item.SetExtension(0, []byte{0x80}); err != nil {
			t.Fatal(err)
		}
		preferredField := measurementQuantitiesItemIEFieldCodecFreshMust(MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().New(item))
		preferred := sliceByteCodecFreshMust((&MeasurementQuantitiesComplete{Value: MeasurementQuantities{preferredField}}).MarshalAPER())
		*bridge1.BridgeMeasurementQuantitiesItemFieldExtCount(&item) = 3
		*bridge1.BridgeMeasurementQuantitiesItemFieldExtPresent(&item) = append(*bridge1.BridgeMeasurementQuantitiesItemFieldExtPresent(&item), false, false, false)
		*bridge1.BridgeMeasurementQuantitiesItemFieldExtData(&item) = append(*bridge1.BridgeMeasurementQuantitiesItemFieldExtData(&item), nil, nil, nil)
		field := measurementQuantitiesItemIEFieldCodecFreshMust(MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().New(item))
		wire := sliceByteCodecFreshMust((&MeasurementQuantitiesComplete{Value: MeasurementQuantities{field}}).MarshalAPER())
		measurementQuantitiesCheckCodecFresh(t, MeasurementQuantitiesCodec(), wire, preferred)
	})
	t.Run("named list nested framing", func(t *q8.T) {
		item := ResultNRItem{}
		if err := item.SetExtension(0, []byte{0x80}); err != nil {
			t.Fatal(err)
		}
		preferred := sliceByteCodecFreshMust((&ResultNRComplete{Value: ResultNR{item}}).MarshalAPER())
		*bridge2.BridgeResultNRItemFieldExtCount(&item) = 3
		*bridge2.BridgeResultNRItemFieldExtPresent(&item) = append(*bridge2.BridgeResultNRItemFieldExtPresent(&item), false, false, false)
		*bridge2.BridgeResultNRItemFieldExtData(&item) = append(*bridge2.BridgeResultNRItemFieldExtData(&item), nil, nil, nil)
		wire := sliceByteCodecFreshMust((&ResultNRComplete{Value: ResultNR{item}}).MarshalAPER())
		resultNRCheckCodecFresh(t, ResultNRCodec(), wire, preferred)
	})
	t.Run("initiating procedure", func(t *q8.T) {
		body := ErrorIndication{}
		if err := body.SetExtension(0, []byte{0x80}); err != nil {
			t.Fatal(err)
		}
		preferred := sliceByteCodecFreshMust(body.MarshalAPER())
		*bridge3.BridgeErrorIndicationFieldExtCount(&body) = 3
		*bridge3.BridgeErrorIndicationFieldExtPresent(&body) = append(*bridge3.BridgeErrorIndicationFieldExtPresent(&body), false, false, false)
		*bridge3.BridgeErrorIndicationFieldExtData(&body) = append(*bridge3.BridgeErrorIndicationFieldExtData(&body), nil, nil, nil)
		errorIndicationCheckCodecFresh(t, ErrorIndicationProcedure().Initiating().Codec(), sliceByteCodecFreshMust(body.MarshalAPER()), preferred)
	})
	t.Run("successful procedure", func(t *q8.T) {
		body := ECIDMeasurementInitiationResponse{}
		if err := body.SetExtension(0, []byte{0x80}); err != nil {
			t.Fatal(err)
		}
		preferred := sliceByteCodecFreshMust(body.MarshalAPER())
		*bridge4.BridgeECIDMeasurementInitiationResponseFieldExtCount(&body) = 3
		*bridge4.BridgeECIDMeasurementInitiationResponseFieldExtPresent(&body) = append(*bridge4.BridgeECIDMeasurementInitiationResponseFieldExtPresent(&body), false, false, false)
		*bridge4.BridgeECIDMeasurementInitiationResponseFieldExtData(&body) = append(*bridge4.BridgeECIDMeasurementInitiationResponseFieldExtData(&body), nil, nil, nil)
		eCIDMeasurementInitiationResponseCheckCodecFresh(t, ECIDMeasurementInitiationProcedure().Successful().Codec(), sliceByteCodecFreshMust(body.MarshalAPER()), preferred)
	})
	t.Run("unsuccessful procedure", func(t *q8.T) {
		body := ECIDMeasurementInitiationFailure{}
		if err := body.SetExtension(0, []byte{0x80}); err != nil {
			t.Fatal(err)
		}
		preferred := sliceByteCodecFreshMust(body.MarshalAPER())
		*bridge3.BridgeECIDMeasurementInitiationFailureFieldExtCount(&body) = 3
		*bridge3.BridgeECIDMeasurementInitiationFailureFieldExtPresent(&body) = append(*bridge3.BridgeECIDMeasurementInitiationFailureFieldExtPresent(&body), false, false, false)
		*bridge3.BridgeECIDMeasurementInitiationFailureFieldExtData(&body) = append(*bridge3.BridgeECIDMeasurementInitiationFailureFieldExtData(&body), nil, nil, nil)
		eCIDMeasurementInitiationFailureCheckCodecFresh(t, ECIDMeasurementInitiationProcedure().Unsuccessful().Codec(), sliceByteCodecFreshMust(body.MarshalAPER()), preferred)
	})
}
