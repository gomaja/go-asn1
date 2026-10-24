package lppa

import (
	q27 "bytes"
	bridge1 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"

	q30 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q28 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q9 "testing"
)

func causeFreshMust(value Cause,

	err error) Cause {
	if err != nil {
		panic(err)
	}
	return value
}
func errorIndicationFreshInitiating(t *q9.T, binding ErrorIndicationInitiatingBinding, body ErrorIndication,

) LPPAPDU {
	t.Helper()
	message := initiatingMessageFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUInitiatingMessage(message))
}
func errorIndicationFreshMust(value ErrorIndication,

	err error) ErrorIndication {
	if err != nil {
		panic(err)
	}
	return value
}
func privateIEIDFreshMust(value PrivateIEID,

	err error) PrivateIEID {
	if err != nil {
		panic(err)
	}
	return value
}
func privateMessageIEsValuePrivateIEFieldFreshMust(value PrivateMessageIEsValuePrivateIEField, err error) PrivateMessageIEsValuePrivateIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func privateMessageFreshInitiating(t *q9.T, binding PrivateMessageInitiatingBinding, body PrivateMessage,

) LPPAPDU {
	t.Helper()
	message := initiatingMessageFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUInitiatingMessage(message))
}
func privateMessageFreshMust(value PrivateMessage,

	err error) PrivateMessage {
	if err != nil {
		panic(err)
	}
	return value
}
func measurementQuantitiesItemIEFieldFreshMust(value MeasurementQuantitiesItemIEField, err error) MeasurementQuantitiesItemIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementInitiationRequestFreshMust(value ECIDMeasurementInitiationRequest,

	err error) ECIDMeasurementInitiationRequest {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementInitiationRequestIEFieldFreshMust(value ECIDMeasurementInitiationRequestIEField, err error) ECIDMeasurementInitiationRequestIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementInitiationRequestFreshInitiating(t *q9.T, binding ECIDMeasurementInitiationRequestInitiatingBinding, body ECIDMeasurementInitiationRequest,

) LPPAPDU {
	t.Helper()
	message := initiatingMessageFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUInitiatingMessage(message))
}
func eCIDMeasurementInitiationResponseFreshMust(value ECIDMeasurementInitiationResponse,

	err error) ECIDMeasurementInitiationResponse {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementInitiationResponseIEFieldFreshMust(value ECIDMeasurementInitiationResponseIEField, err error) ECIDMeasurementInitiationResponseIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementInitiationResponseFreshSuccessful(t *q9.T, binding ECIDMeasurementInitiationResponseSuccessfulBinding, body ECIDMeasurementInitiationResponse,

) LPPAPDU {
	t.Helper()
	message := successfulOutcomeFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUSuccessfulOutcome(message))
}
func eCIDMeasurementInitiationFailureFreshMust(value ECIDMeasurementInitiationFailure,

	err error) ECIDMeasurementInitiationFailure {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementInitiationFailureIEFieldFreshMust(value ECIDMeasurementInitiationFailureIEField, err error) ECIDMeasurementInitiationFailureIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementInitiationFailureFreshUnsuccessful(t *q9.T, binding ECIDMeasurementInitiationFailureUnsuccessfulBinding, body ECIDMeasurementInitiationFailure,

) LPPAPDU {
	t.Helper()
	message := unsuccessfulOutcomeFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUUnsuccessfulOutcome(message))
}
func eCIDMeasurementFailureIndicationFreshMust(value ECIDMeasurementFailureIndication,

	err error) ECIDMeasurementFailureIndication {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementFailureIndicationIEFieldFreshMust(value ECIDMeasurementFailureIndicationIEField, err error) ECIDMeasurementFailureIndicationIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementFailureIndicationFreshInitiating(t *q9.T, binding ECIDMeasurementFailureIndicationInitiatingBinding, body ECIDMeasurementFailureIndication,

) LPPAPDU {
	t.Helper()
	message := initiatingMessageFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUInitiatingMessage(message))
}
func eCIDMeasurementReportFreshMust(value ECIDMeasurementReport,

	err error) ECIDMeasurementReport {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementReportIEFieldFreshMust(value ECIDMeasurementReportIEField, err error) ECIDMeasurementReportIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementReportFreshInitiating(t *q9.T, binding ECIDMeasurementReportInitiatingBinding, body ECIDMeasurementReport,

) LPPAPDU {
	t.Helper()
	message := initiatingMessageFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUInitiatingMessage(message))
}
func eCIDMeasurementTerminationCommandFreshMust(value ECIDMeasurementTerminationCommand,

	err error) ECIDMeasurementTerminationCommand {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementTerminationCommandIEFieldFreshMust(value ECIDMeasurementTerminationCommandIEField, err error) ECIDMeasurementTerminationCommandIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementTerminationCommandFreshInitiating(t *q9.T, binding ECIDMeasurementTerminationCommandInitiatingBinding, body ECIDMeasurementTerminationCommand,

) LPPAPDU {
	t.Helper()
	message := initiatingMessageFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUInitiatingMessage(message))
}
func oTDOAInformationTypeIEFieldFreshMust(value OTDOAInformationTypeIEField, err error) OTDOAInformationTypeIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func oTDOAInformationRequestFreshMust(value OTDOAInformationRequest,

	err error) OTDOAInformationRequest {
	if err != nil {
		panic(err)
	}
	return value
}
func oTDOAInformationRequestIEFieldFreshMust(value OTDOAInformationRequestIEField, err error) OTDOAInformationRequestIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func oTDOAInformationRequestFreshInitiating(t *q9.T, binding OTDOAInformationRequestInitiatingBinding, body OTDOAInformationRequest,

) LPPAPDU {
	t.Helper()
	message := initiatingMessageFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUInitiatingMessage(message))
}
func oTDOACellInformationItemFreshMust(value OTDOACellInformationItem,

	err error) OTDOACellInformationItem {
	if err != nil {
		panic(err)
	}
	return value
}
func oTDOAInformationResponseFreshMust(value OTDOAInformationResponse,

	err error) OTDOAInformationResponse {
	if err != nil {
		panic(err)
	}
	return value
}
func oTDOAInformationResponseIEFieldFreshMust(value OTDOAInformationResponseIEField, err error) OTDOAInformationResponseIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func oTDOAInformationResponseFreshSuccessful(t *q9.T, binding OTDOAInformationResponseSuccessfulBinding, body OTDOAInformationResponse,

) LPPAPDU {
	t.Helper()
	message := successfulOutcomeFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUSuccessfulOutcome(message))
}
func oTDOAInformationFailureFreshMust(value OTDOAInformationFailure,

	err error) OTDOAInformationFailure {
	if err != nil {
		panic(err)
	}
	return value
}
func oTDOAInformationFailureIEFieldFreshMust(value OTDOAInformationFailureIEField, err error) OTDOAInformationFailureIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func oTDOAInformationFailureFreshUnsuccessful(t *q9.T, binding OTDOAInformationFailureUnsuccessfulBinding, body OTDOAInformationFailure,

) LPPAPDU {
	t.Helper()
	message := unsuccessfulOutcomeFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUUnsuccessfulOutcome(message))
}
func uTDOAInformationRequestFreshInitiating(t *q9.T, binding UTDOAInformationRequestInitiatingBinding, body UTDOAInformationRequest,

) LPPAPDU {
	t.Helper()
	message := initiatingMessageFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUInitiatingMessage(message))
}
func uTDOAInformationRequestFreshMust(value UTDOAInformationRequest,

	err error) UTDOAInformationRequest {
	if err != nil {
		panic(err)
	}
	return value
}
func uTDOAInformationResponseFreshMust(value UTDOAInformationResponse,

	err error) UTDOAInformationResponse {
	if err != nil {
		panic(err)
	}
	return value
}
func uTDOAInformationResponseIEFieldFreshMust(value UTDOAInformationResponseIEField, err error) UTDOAInformationResponseIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func uTDOAInformationResponseFreshSuccessful(t *q9.T, binding UTDOAInformationResponseSuccessfulBinding, body UTDOAInformationResponse,

) LPPAPDU {
	t.Helper()
	message := successfulOutcomeFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUSuccessfulOutcome(message))
}
func uTDOAInformationFailureFreshMust(value UTDOAInformationFailure,

	err error) UTDOAInformationFailure {
	if err != nil {
		panic(err)
	}
	return value
}
func uTDOAInformationFailureIEFieldFreshMust(value UTDOAInformationFailureIEField, err error) UTDOAInformationFailureIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func uTDOAInformationFailureFreshUnsuccessful(t *q9.T, binding UTDOAInformationFailureUnsuccessfulBinding, body UTDOAInformationFailure,

) LPPAPDU {
	t.Helper()
	message := unsuccessfulOutcomeFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUUnsuccessfulOutcome(message))
}
func uTDOAInformationUpdateFreshInitiating(t *q9.T, binding UTDOAInformationUpdateInitiatingBinding, body UTDOAInformationUpdate,

) LPPAPDU {
	t.Helper()
	message := initiatingMessageFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUInitiatingMessage(message))
}
func uTDOAInformationUpdateFreshMust(value UTDOAInformationUpdate,

	err error) UTDOAInformationUpdate {
	if err != nil {
		panic(err)
	}
	return value
}
func assistanceInformationControlFreshInitiating(t *q9.T, binding AssistanceInformationControlInitiatingBinding, body AssistanceInformationControl,

) LPPAPDU {
	t.Helper()
	message := initiatingMessageFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUInitiatingMessage(message))
}
func assistanceInformationControlFreshMust(value AssistanceInformationControl,

	err error) AssistanceInformationControl {
	if err != nil {
		panic(err)
	}
	return value
}
func assistanceInformationFeedbackFreshInitiating(t *q9.T, binding AssistanceInformationFeedbackInitiatingBinding, body AssistanceInformationFeedback,

) LPPAPDU {
	t.Helper()
	message := initiatingMessageFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUInitiatingMessage(message))
}
func assistanceInformationFeedbackFreshMust(value AssistanceInformationFeedback,

	err error) AssistanceInformationFeedback {
	if err != nil {
		panic(err)
	}
	return value
}
func sliceByteCodecFreshMust(value []byte,

	err error) []byte {
	if err != nil {
		panic(err)
	}
	return value
}
func nPRSSubframePartBCheckCodecFresh(t *q9.T, codec NPRSSubframePartBValueCodec, wire, preferred []byte) {
	t.Helper()
	if q27.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, q28.WithoutReplay())
	if err != nil || !q27.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !q27.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Errorf("fresh encoding changed default replay=%x err=%v", replay, err)
	}
}
func measurementQuantitiesItemIEFieldCodecFreshMust(value MeasurementQuantitiesItemIEField, err error) MeasurementQuantitiesItemIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func measurementQuantitiesCheckCodecFresh(t *q9.T, codec MeasurementQuantitiesConcreteValueCodec, wire, preferred []byte) {
	t.Helper()
	if q27.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, q28.WithoutReplay())
	if err != nil || !q27.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !q27.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Errorf("fresh encoding changed default replay=%x err=%v", replay, err)
	}
}
func resultNRCheckCodecFresh(t *q9.T, codec ResultNRValueCodec, wire, preferred []byte) {
	t.Helper()
	if q27.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, q28.WithoutReplay())
	if err != nil || !q27.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !q27.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Errorf("fresh encoding changed default replay=%x err=%v", replay, err)
	}
}
func errorIndicationCheckCodecFresh(t *q9.T, codec ErrorIndicationValueCodec, wire, preferred []byte) {
	t.Helper()
	if q27.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, q28.WithoutReplay())
	if err != nil || !q27.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !q27.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Errorf("fresh encoding changed default replay=%x err=%v", replay, err)
	}
}
func eCIDMeasurementInitiationResponseCheckCodecFresh(t *q9.T, codec ECIDMeasurementInitiationResponseValueCodec, wire, preferred []byte) {
	t.Helper()
	if q27.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, q28.WithoutReplay())
	if err != nil || !q27.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !q27.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Errorf("fresh encoding changed default replay=%x err=%v", replay, err)
	}
}
func eCIDMeasurementInitiationFailureCheckCodecFresh(t *q9.T, codec ECIDMeasurementInitiationFailureValueCodec, wire, preferred []byte) {
	t.Helper()
	if q27.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, q28.WithoutReplay())
	if err != nil || !q27.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !q27.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !q27.Equal(replay, wire) {
		t.Errorf("fresh encoding changed default replay=%x err=%v", replay, err)
	}
}
func errorIndicationIEFieldConsistencyMust(value ErrorIndicationIEField, err error) ErrorIndicationIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func resultNRItemExtIEsExtFieldConsistencyMust(value ResultNRItemExtIEsExtField, err error) ResultNRItemExtIEsExtField {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementInitiationResponseIEFieldConsistencyMust(value ECIDMeasurementInitiationResponseIEField, err error) ECIDMeasurementInitiationResponseIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func eCIDMeasurementInitiationResponseEnvelopeMust(v ECIDMeasurementInitiationResponse,

	err error) ECIDMeasurementInitiationResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func eCIDMeasurementInitiationResponseIEFieldEnvelopeMust(v ECIDMeasurementInitiationResponseIEField, err error) ECIDMeasurementInitiationResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func causeEnvelopeMust(v Cause,

	err error) Cause {
	if err != nil {
		panic(err)
	}
	return v
}
func eCIDMeasurementInitiationFailureEnvelopeMust(v ECIDMeasurementInitiationFailure,

	err error) ECIDMeasurementInitiationFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func eCIDMeasurementInitiationFailureIEFieldEnvelopeMust(v ECIDMeasurementInitiationFailureIEField, err error) ECIDMeasurementInitiationFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func initiatingMessageEnvelopeMust(v InitiatingMessage,

	err error) InitiatingMessage {
	if err != nil {
		panic(err)
	}
	return v
}
func errorIndicationEnvelopeMust(v ErrorIndication,

	err error) ErrorIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func successfulOutcomeEnvelopeMust(v SuccessfulOutcome,

	err error) SuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return v
}
func unsuccessfulOutcomeEnvelopeMust(v UnsuccessfulOutcome,

	err error) UnsuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return v
}
func sliceByteEnvelopeMust(v []byte,

	err error) []byte {
	if err != nil {
		panic(err)
	}
	return v
}
func privateIEIDEnvelopeMust(v PrivateIEID,

	err error) PrivateIEID {
	if err != nil {
		panic(err)
	}
	return v
}
func privateMessageIEsValuePrivateIEFieldEnvelopeMust(v PrivateMessageIEsValuePrivateIEField, err error) PrivateMessageIEsValuePrivateIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func objectIdentifierEnvelopeMust(v q30.ObjectIdentifier,

	err error) q30.ObjectIdentifier {
	if err != nil {
		panic(err)
	}
	return v
}
func errorIndicationIEFieldReplayMust(v ErrorIndicationIEField, err error) ErrorIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func sliceByteReplayMust(v []byte,

	err error) []byte {
	if err != nil {
		panic(err)
	}
	return v
}
func pLMNIdentitySemanticEditRestore(t *q9.T, c PLMNIdentityValueCodec, initial PLMNIdentity,

	edit, restore func(*PLMNIdentity,

	)) {
	t.Helper()
	encoder := *bridge0.BridgePLMNIdentityValueCodecFieldEncode(&c)
	calls := 0
	*bridge0.BridgePLMNIdentityValueCodecFieldEncode(&c) = func(v PLMNIdentity,

		f bool, b *q28.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, f, b)
	}
	wire := sliceByteReplayMust(c.EncodeAPER(pLMNIdentityAPERValueReplayMust(c.New(initial))))
	original := q27.Clone(wire)
	calls = 0
	decoded, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("decode called encoder")
	}
	for i := range wire {
		wire[i] ^= 0xff
	}
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !q27.Equal(got, original) || calls != 0 {
		t.Fatal("original storage borrowed or unchanged encode called encoder")
	}
	edit(&decoded.Value)
	got := sliceByteReplayMust(c.EncodeAPER(decoded))
	want := sliceByteReplayMust(c.EncodeAPER(decoded, q28.WithoutReplay()))
	if q27.Equal(got, original) || !q27.Equal(got, want) {
		t.Fatalf("edited semantics: %x want %x original %x", got, want, original)
	}
	calls = 0
	restore(&decoded.Value)
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !q27.Equal(got, original) || calls != 0 {
		t.Fatal("restored encode called encoder or failed exact replay")
	}
}
func sSIDSemanticEditRestore(t *q9.T, c SSIDValueCodec, initial SSID,

	edit, restore func(*SSID,

	)) {
	t.Helper()
	encoder := *bridge0.BridgeSSIDValueCodecFieldEncode(&c)
	calls := 0
	*bridge0.BridgeSSIDValueCodecFieldEncode(&c) = func(v SSID,

		f bool, b *q28.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, f, b)
	}
	wire := sliceByteReplayMust(c.EncodeAPER(sSIDAPERValueReplayMust(c.New(initial))))
	original := q27.Clone(wire)
	calls = 0
	decoded, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("decode called encoder")
	}
	for i := range wire {
		wire[i] ^= 0xff
	}
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !q27.Equal(got, original) || calls != 0 {
		t.Fatal("original storage borrowed or unchanged encode called encoder")
	}
	edit(&decoded.Value)
	got := sliceByteReplayMust(c.EncodeAPER(decoded))
	want := sliceByteReplayMust(c.EncodeAPER(decoded, q28.WithoutReplay()))
	if q27.Equal(got, original) || !q27.Equal(got, want) {
		t.Fatalf("edited semantics: %x want %x original %x", got, want, original)
	}
	calls = 0
	restore(&decoded.Value)
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !q27.Equal(got, original) || calls != 0 {
		t.Fatal("restored encode called encoder or failed exact replay")
	}
}
func measurementIDSemanticEditRestore(t *q9.T, c MeasurementIDValueCodec, initial MeasurementID,

	edit, restore func(*MeasurementID,

	)) {
	t.Helper()
	encoder := *bridge1.BridgeMeasurementIDValueCodecFieldEncode(&c)
	calls := 0
	*bridge1.BridgeMeasurementIDValueCodecFieldEncode(&c) = func(v MeasurementID,

		f bool, b *q28.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, f, b)
	}
	wire := sliceByteReplayMust(c.EncodeAPER(measurementIDAPERValueReplayMust(c.New(initial))))
	original := q27.Clone(wire)
	calls = 0
	decoded, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("decode called encoder")
	}
	for i := range wire {
		wire[i] ^= 0xff
	}
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !q27.Equal(got, original) || calls != 0 {
		t.Fatal("original storage borrowed or unchanged encode called encoder")
	}
	edit(&decoded.Value)
	got := sliceByteReplayMust(c.EncodeAPER(decoded))
	want := sliceByteReplayMust(c.EncodeAPER(decoded, q28.WithoutReplay()))
	if q27.Equal(got, original) || !q27.Equal(got, want) {
		t.Fatalf("edited semantics: %x want %x original %x", got, want, original)
	}
	calls = 0
	restore(&decoded.Value)
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !q27.Equal(got, original) || calls != 0 {
		t.Fatal("restored encode called encoder or failed exact replay")
	}
}
func eUTRANCellIdentifierSemanticEditRestore(t *q9.T, c EUTRANCellIdentifierValueCodec, initial EUTRANCellIdentifier,

	edit, restore func(*EUTRANCellIdentifier,

	)) {
	t.Helper()
	encoder := *bridge1.BridgeEUTRANCellIdentifierValueCodecFieldEncode(&c)
	calls := 0
	*bridge1.BridgeEUTRANCellIdentifierValueCodecFieldEncode(&c) = func(v EUTRANCellIdentifier,

		f bool, b *q28.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, f, b)
	}
	wire := sliceByteReplayMust(c.EncodeAPER(eUTRANCellIdentifierAPERValueReplayMust(c.New(initial))))
	original := q27.Clone(wire)
	calls = 0
	decoded, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("decode called encoder")
	}
	for i := range wire {
		wire[i] ^= 0xff
	}
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !q27.Equal(got, original) || calls != 0 {
		t.Fatal("original storage borrowed or unchanged encode called encoder")
	}
	edit(&decoded.Value)
	got := sliceByteReplayMust(c.EncodeAPER(decoded))
	want := sliceByteReplayMust(c.EncodeAPER(decoded, q28.WithoutReplay()))
	if q27.Equal(got, original) || !q27.Equal(got, want) {
		t.Fatalf("edited semantics: %x want %x original %x", got, want, original)
	}
	calls = 0
	restore(&decoded.Value)
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !q27.Equal(got, original) || calls != 0 {
		t.Fatal("restored encode called encoder or failed exact replay")
	}
}
func eUTRANCellIdentifierAPERValueReplayMust(v EUTRANCellIdentifierAPERValue, err error) EUTRANCellIdentifierAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func eCIDMeasurementInitiationRequestIEFieldReplayMust(v ECIDMeasurementInitiationRequestIEField, err error) ECIDMeasurementInitiationRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eCIDMeasurementReportIEFieldUnknownBoundaryMust(value ECIDMeasurementReportIEField, err error) ECIDMeasurementReportIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func initiatingMessageFreshMust(value InitiatingMessage,

	err error) InitiatingMessage {
	if err != nil {
		panic(err)
	}
	return value
}
func lPPAPDUFreshMust(value LPPAPDU,

	err error) LPPAPDU {
	if err != nil {
		panic(err)
	}
	return value
}
func successfulOutcomeFreshMust(value SuccessfulOutcome,

	err error) SuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return value
}
func unsuccessfulOutcomeFreshMust(value UnsuccessfulOutcome,

	err error) UnsuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return value
}
func pLMNIdentityAPERValueReplayMust(v PLMNIdentityAPERValue, err error) PLMNIdentityAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func sSIDAPERValueReplayMust(v SSIDAPERValue, err error) SSIDAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func measurementIDAPERValueReplayMust(v MeasurementIDAPERValue, err error) MeasurementIDAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
