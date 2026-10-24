package lppa

import (
	"bytes"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"testing"
)

func causeFreshMust(value Cause,

	err error) Cause {
	if err != nil {
		panic(err)
	}
	return value
}
func errorIndicationFreshInitiating(t *testing.T, binding ErrorIndicationInitiatingBinding, body ErrorIndication,

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
func privateMessageFreshInitiating(t *testing.T, binding PrivateMessageInitiatingBinding, body PrivateMessage,

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
func eCIDMeasurementInitiationRequestFreshInitiating(t *testing.T, binding ECIDMeasurementInitiationRequestInitiatingBinding, body ECIDMeasurementInitiationRequest,

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
func eCIDMeasurementInitiationResponseFreshSuccessful(t *testing.T, binding ECIDMeasurementInitiationResponseSuccessfulBinding, body ECIDMeasurementInitiationResponse,

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
func eCIDMeasurementInitiationFailureFreshUnsuccessful(t *testing.T, binding ECIDMeasurementInitiationFailureUnsuccessfulBinding, body ECIDMeasurementInitiationFailure,

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
func eCIDMeasurementFailureIndicationFreshInitiating(t *testing.T, binding ECIDMeasurementFailureIndicationInitiatingBinding, body ECIDMeasurementFailureIndication,

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
func eCIDMeasurementReportFreshInitiating(t *testing.T, binding ECIDMeasurementReportInitiatingBinding, body ECIDMeasurementReport,

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
func eCIDMeasurementTerminationCommandFreshInitiating(t *testing.T, binding ECIDMeasurementTerminationCommandInitiatingBinding, body ECIDMeasurementTerminationCommand,

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
func oTDOAInformationRequestFreshInitiating(t *testing.T, binding OTDOAInformationRequestInitiatingBinding, body OTDOAInformationRequest,

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
func oTDOAInformationResponseFreshSuccessful(t *testing.T, binding OTDOAInformationResponseSuccessfulBinding, body OTDOAInformationResponse,

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
func oTDOAInformationFailureFreshUnsuccessful(t *testing.T, binding OTDOAInformationFailureUnsuccessfulBinding, body OTDOAInformationFailure,

) LPPAPDU {
	t.Helper()
	message := unsuccessfulOutcomeFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUUnsuccessfulOutcome(message))
}
func uTDOAInformationRequestFreshInitiating(t *testing.T, binding UTDOAInformationRequestInitiatingBinding, body UTDOAInformationRequest,

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
func uTDOAInformationResponseFreshSuccessful(t *testing.T, binding UTDOAInformationResponseSuccessfulBinding, body UTDOAInformationResponse,

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
func uTDOAInformationFailureFreshUnsuccessful(t *testing.T, binding UTDOAInformationFailureUnsuccessfulBinding, body UTDOAInformationFailure,

) LPPAPDU {
	t.Helper()
	message := unsuccessfulOutcomeFreshMust(binding.Build(body, 7))
	return lPPAPDUFreshMust(NewLPPAPDUUnsuccessfulOutcome(message))
}
func uTDOAInformationUpdateFreshInitiating(t *testing.T, binding UTDOAInformationUpdateInitiatingBinding, body UTDOAInformationUpdate,

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
func assistanceInformationControlFreshInitiating(t *testing.T, binding AssistanceInformationControlInitiatingBinding, body AssistanceInformationControl,

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
func assistanceInformationFeedbackFreshInitiating(t *testing.T, binding AssistanceInformationFeedbackInitiatingBinding, body AssistanceInformationFeedback,

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
func nPRSSubframePartBCheckCodecFresh(t *testing.T, codec NPRSSubframePartBValueCodec, wire, preferred []byte) {
	t.Helper()
	if bytes.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, aper.WithoutReplay())
	if err != nil || !bytes.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !bytes.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Errorf("fresh encoding changed default replay=%x err=%v", replay, err)
	}
}
func measurementQuantitiesItemIEFieldCodecFreshMust(value MeasurementQuantitiesItemIEField, err error) MeasurementQuantitiesItemIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func measurementQuantitiesCheckCodecFresh(t *testing.T, codec MeasurementQuantitiesConcreteValueCodec, wire, preferred []byte) {
	t.Helper()
	if bytes.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, aper.WithoutReplay())
	if err != nil || !bytes.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !bytes.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Errorf("fresh encoding changed default replay=%x err=%v", replay, err)
	}
}
func resultNRCheckCodecFresh(t *testing.T, codec ResultNRValueCodec, wire, preferred []byte) {
	t.Helper()
	if bytes.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, aper.WithoutReplay())
	if err != nil || !bytes.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !bytes.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Errorf("fresh encoding changed default replay=%x err=%v", replay, err)
	}
}
func errorIndicationCheckCodecFresh(t *testing.T, codec ErrorIndicationValueCodec, wire, preferred []byte) {
	t.Helper()
	if bytes.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, aper.WithoutReplay())
	if err != nil || !bytes.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !bytes.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Errorf("fresh encoding changed default replay=%x err=%v", replay, err)
	}
}
func eCIDMeasurementInitiationResponseCheckCodecFresh(t *testing.T, codec ECIDMeasurementInitiationResponseValueCodec, wire, preferred []byte) {
	t.Helper()
	if bytes.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, aper.WithoutReplay())
	if err != nil || !bytes.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !bytes.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Errorf("fresh encoding changed default replay=%x err=%v", replay, err)
	}
}
func eCIDMeasurementInitiationFailureCheckCodecFresh(t *testing.T, codec ECIDMeasurementInitiationFailureValueCodec, wire, preferred []byte) {
	t.Helper()
	if bytes.Equal(wire, preferred) {
		t.Fatal("fixture has no nonpreferred representation")
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("default replay=%x err=%v want=%x", replay, err, wire)
	}
	fresh, err := codec.EncodeAPER(decoded, aper.WithoutReplay())
	if err != nil || !bytes.Equal(fresh, preferred) {
		t.Errorf("fresh=%x err=%v want=%x", fresh, err, preferred)
	}
	freshValue, err := codec.EncodeAPER(decoded.WithoutReplay())
	if err != nil || !bytes.Equal(freshValue, preferred) {
		t.Errorf("value.WithoutReplay=%x err=%v want=%x", freshValue, err, preferred)
	}
	replay, err = codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
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
func objectIdentifierEnvelopeMust(v runtime.ObjectIdentifier,

	err error) runtime.ObjectIdentifier {
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
func pLMNIdentitySemanticEditRestore(t *testing.T, c PLMNIdentityValueCodec, initial PLMNIdentity,

	edit, restore func(*PLMNIdentity,

	)) {
	t.Helper()
	encoder := *s01.BridgePLMNIdentityValueCodecFieldEncode(&c)
	calls := 0
	*s01.BridgePLMNIdentityValueCodecFieldEncode(&c) = func(v PLMNIdentity,

		f bool, b *aper.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, f, b)
	}
	wire := sliceByteReplayMust(c.EncodeAPER(pLMNIdentityAPERValueReplayMust(c.New(initial))))
	original := bytes.Clone(wire)
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
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !bytes.Equal(got, original) || calls != 0 {
		t.Fatal("original storage borrowed or unchanged encode called encoder")
	}
	edit(&decoded.Value)
	got := sliceByteReplayMust(c.EncodeAPER(decoded))
	want := sliceByteReplayMust(c.EncodeAPER(decoded, aper.WithoutReplay()))
	if bytes.Equal(got, original) || !bytes.Equal(got, want) {
		t.Fatalf("edited semantics: %x want %x original %x", got, want, original)
	}
	calls = 0
	restore(&decoded.Value)
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !bytes.Equal(got, original) || calls != 0 {
		t.Fatal("restored encode called encoder or failed exact replay")
	}
}
func sSIDSemanticEditRestore(t *testing.T, c SSIDValueCodec, initial SSID,

	edit, restore func(*SSID,

	)) {
	t.Helper()
	encoder := *s01.BridgeSSIDValueCodecFieldEncode(&c)
	calls := 0
	*s01.BridgeSSIDValueCodecFieldEncode(&c) = func(v SSID,

		f bool, b *aper.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, f, b)
	}
	wire := sliceByteReplayMust(c.EncodeAPER(sSIDAPERValueReplayMust(c.New(initial))))
	original := bytes.Clone(wire)
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
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !bytes.Equal(got, original) || calls != 0 {
		t.Fatal("original storage borrowed or unchanged encode called encoder")
	}
	edit(&decoded.Value)
	got := sliceByteReplayMust(c.EncodeAPER(decoded))
	want := sliceByteReplayMust(c.EncodeAPER(decoded, aper.WithoutReplay()))
	if bytes.Equal(got, original) || !bytes.Equal(got, want) {
		t.Fatalf("edited semantics: %x want %x original %x", got, want, original)
	}
	calls = 0
	restore(&decoded.Value)
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !bytes.Equal(got, original) || calls != 0 {
		t.Fatal("restored encode called encoder or failed exact replay")
	}
}
func measurementIDSemanticEditRestore(t *testing.T, c MeasurementIDValueCodec, initial MeasurementID,

	edit, restore func(*MeasurementID,

	)) {
	t.Helper()
	encoder := *s00.BridgeMeasurementIDValueCodecFieldEncode(&c)
	calls := 0
	*s00.BridgeMeasurementIDValueCodecFieldEncode(&c) = func(v MeasurementID,

		f bool, b *aper.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, f, b)
	}
	wire := sliceByteReplayMust(c.EncodeAPER(measurementIDAPERValueReplayMust(c.New(initial))))
	original := bytes.Clone(wire)
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
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !bytes.Equal(got, original) || calls != 0 {
		t.Fatal("original storage borrowed or unchanged encode called encoder")
	}
	edit(&decoded.Value)
	got := sliceByteReplayMust(c.EncodeAPER(decoded))
	want := sliceByteReplayMust(c.EncodeAPER(decoded, aper.WithoutReplay()))
	if bytes.Equal(got, original) || !bytes.Equal(got, want) {
		t.Fatalf("edited semantics: %x want %x original %x", got, want, original)
	}
	calls = 0
	restore(&decoded.Value)
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !bytes.Equal(got, original) || calls != 0 {
		t.Fatal("restored encode called encoder or failed exact replay")
	}
}
func eUTRANCellIdentifierSemanticEditRestore(t *testing.T, c EUTRANCellIdentifierValueCodec, initial EUTRANCellIdentifier,

	edit, restore func(*EUTRANCellIdentifier,

	)) {
	t.Helper()
	encoder := *s00.BridgeEUTRANCellIdentifierValueCodecFieldEncode(&c)
	calls := 0
	*s00.BridgeEUTRANCellIdentifierValueCodecFieldEncode(&c) = func(v EUTRANCellIdentifier,

		f bool, b *aper.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, f, b)
	}
	wire := sliceByteReplayMust(c.EncodeAPER(eUTRANCellIdentifierAPERValueReplayMust(c.New(initial))))
	original := bytes.Clone(wire)
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
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !bytes.Equal(got, original) || calls != 0 {
		t.Fatal("original storage borrowed or unchanged encode called encoder")
	}
	edit(&decoded.Value)
	got := sliceByteReplayMust(c.EncodeAPER(decoded))
	want := sliceByteReplayMust(c.EncodeAPER(decoded, aper.WithoutReplay()))
	if bytes.Equal(got, original) || !bytes.Equal(got, want) {
		t.Fatalf("edited semantics: %x want %x original %x", got, want, original)
	}
	calls = 0
	restore(&decoded.Value)
	if got := sliceByteReplayMust(c.EncodeAPER(decoded)); !bytes.Equal(got, original) || calls != 0 {
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
