// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s57 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s57

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s55 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s55"
	s56 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s56"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func BridgeERABModificationIndicationIEValueCaptureS1APProtocolIEContainer(v *s56.ERABModificationIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModificationIndicationIEValueCompareS1APProtocolIEContainer(v *s56.ERABModificationIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyResponseIEValueCaptureS1APProtocolIEContainer(v *s56.ERABModifyResponseIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyResponseIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyResponseIEValueCompareS1APProtocolIEContainer(v *s56.ERABModifyResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIEContainer(v *s56.ERABReleaseIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseIndicationIEValueCompareS1APProtocolIEContainer(v *s56.ERABReleaseIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEContainer(v *s56.ERABReleaseResponseIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseResponseIEValueCompareS1APProtocolIEContainer(v *s56.ERABReleaseResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupResponseIEValueCaptureS1APProtocolIEContainer(v *s56.ERABSetupResponseIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupResponseIEValueCompareS1APProtocolIEContainer(v *s56.ERABSetupResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEContainer(v *s56.SecondaryRATDataUsageReportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEContainer(v *s56.SecondaryRATDataUsageReportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEContainer(v *s56.UEContextReleaseCompleteIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEContainer(v *s56.UEContextReleaseCompleteIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEContainer(v *s56.UEContextSuspendRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEContainer(v *s56.UEContextSuspendRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(v *s14.V2XServicesAuthorizedExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(v *s14.V2XServicesAuthorizedExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABModificationIndicationUserLocationInformationIEBinding binds UserLocationInformation to the E-RABModificationIndicationIEs object set of TS 36.413.
type ERABModificationIndicationUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s56.UserLocationInformationValueCodec
	inject func(s55.UserLocationInformation,

	) s56.ERABModificationIndicationIEValue

	get func(*s56.ERABModificationIndicationIEValue,

	) (*s55.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationIndicationUserLocationInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABModificationIndicationUserLocationInformationIEBinding) Codec() s56.UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationIndicationUserLocationInformationIEBinding) New(value s55.UserLocationInformation,

) (s56.ERABModificationIndicationIEField, error) {
	if b.inject == nil {
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s56.BridgeUserLocationInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return s56.ERABModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationIndicationUserLocationInformationIEBinding) Get(field *s56.ERABModificationIndicationIEField) (*s55.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyResponseUserLocationInformationIEBinding binds UserLocationInformation to the E-RABModifyResponseIEs object set of TS 36.413.
type ERABModifyResponseUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s56.UserLocationInformationValueCodec
	inject func(s55.UserLocationInformation,

	) s56.ERABModifyResponseIEValue

	get func(*s56.ERABModifyResponseIEValue,

	) (*s55.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyResponseUserLocationInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyResponseUserLocationInformationIEBinding) Codec() s56.UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModifyResponseUserLocationInformationIEBinding) New(value s55.UserLocationInformation,

) (s56.ERABModifyResponseIEField, error) {
	if b.inject == nil {
		return s56.ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s56.ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s56.BridgeUserLocationInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s56.ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s56.ERABModifyResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return s56.ERABModifyResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyResponseUserLocationInformationIEBinding) Get(field *s56.ERABModifyResponseIEField) (*s55.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseIndicationUserLocationInformationIEBinding binds UserLocationInformation to the E-RABReleaseIndicationIEs object set of TS 36.413.
type ERABReleaseIndicationUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s56.UserLocationInformationValueCodec
	inject func(s55.UserLocationInformation,

	) s56.ERABReleaseIndicationIEValue

	get func(*s56.ERABReleaseIndicationIEValue,

	) (*s55.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseIndicationUserLocationInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseIndicationUserLocationInformationIEBinding) Codec() s56.UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABReleaseIndicationUserLocationInformationIEBinding) New(value s55.UserLocationInformation,

) (s56.ERABReleaseIndicationIEField, error) {
	if b.inject == nil {
		return s56.ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s56.ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s56.BridgeUserLocationInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s56.ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s56.ERABReleaseIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return s56.ERABReleaseIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseIndicationUserLocationInformationIEBinding) Get(field *s56.ERABReleaseIndicationIEField) (*s55.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseResponseUserLocationInformationIEBinding binds UserLocationInformation to the E-RABReleaseResponseIEs object set of TS 36.413.
type ERABReleaseResponseUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s56.UserLocationInformationValueCodec
	inject func(s55.UserLocationInformation,

	) s56.ERABReleaseResponseIEValue

	get func(*s56.ERABReleaseResponseIEValue,

	) (*s55.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseResponseUserLocationInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseResponseUserLocationInformationIEBinding) Codec() s56.UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABReleaseResponseUserLocationInformationIEBinding) New(value s55.UserLocationInformation,

) (s56.ERABReleaseResponseIEField, error) {
	if b.inject == nil {
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s56.BridgeUserLocationInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return s56.ERABReleaseResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseResponseUserLocationInformationIEBinding) Get(field *s56.ERABReleaseResponseIEField) (*s55.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupResponseUserLocationInformationIEBinding binds UserLocationInformation to the E-RABSetupResponseIEs object set of TS 36.413.
type ERABSetupResponseUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s56.UserLocationInformationValueCodec
	inject func(s55.UserLocationInformation,

	) s56.ERABSetupResponseIEValue

	get func(*s56.ERABSetupResponseIEValue,

	) (*s55.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupResponseUserLocationInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupResponseUserLocationInformationIEBinding) Codec() s56.UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABSetupResponseUserLocationInformationIEBinding) New(value s55.UserLocationInformation,

) (s56.ERABSetupResponseIEField, error) {
	if b.inject == nil {
		return s56.ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s56.ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s56.BridgeUserLocationInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s56.ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s56.ERABSetupResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return s56.ERABSetupResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupResponseUserLocationInformationIEBinding) Get(field *s56.ERABSetupResponseIEField) (*s55.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SecondaryRATDataUsageReportUserLocationInformationIEBinding binds UserLocationInformation to the SecondaryRATDataUsageReportIEs object set of TS 36.413.
type SecondaryRATDataUsageReportUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s56.UserLocationInformationValueCodec
	inject func(s55.UserLocationInformation,

	) s56.SecondaryRATDataUsageReportIEValue

	get func(*s56.SecondaryRATDataUsageReportIEValue,

	) (*s55.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SecondaryRATDataUsageReportUserLocationInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SecondaryRATDataUsageReportUserLocationInformationIEBinding) Codec() s56.UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SecondaryRATDataUsageReportUserLocationInformationIEBinding) New(value s55.UserLocationInformation,

) (s56.SecondaryRATDataUsageReportIEField, error) {
	if b.inject == nil {
		return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s56.BridgeUserLocationInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return s56.SecondaryRATDataUsageReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SecondaryRATDataUsageReportUserLocationInformationIEBinding) Get(field *s56.SecondaryRATDataUsageReportIEField) (*s55.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseCompleteUserLocationInformationIEBinding binds UserLocationInformation to the UEContextReleaseComplete-IEs object set of TS 36.413.
type UEContextReleaseCompleteUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s56.UserLocationInformationValueCodec
	inject func(s55.UserLocationInformation,

	) s56.UEContextReleaseCompleteIEValue

	get func(*s56.UEContextReleaseCompleteIEValue,

	) (*s55.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteUserLocationInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteUserLocationInformationIEBinding) Codec() s56.UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCompleteUserLocationInformationIEBinding) New(value s55.UserLocationInformation,

) (s56.UEContextReleaseCompleteIEField, error) {
	if b.inject == nil {
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s56.BridgeUserLocationInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Value.New")
	}
	return s56.UEContextReleaseCompleteIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCompleteUserLocationInformationIEBinding) Get(field *s56.UEContextReleaseCompleteIEField) (*s55.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextSuspendRequestUserLocationInformationIEBinding binds UserLocationInformation to the UEContextSuspendRequestIEs object set of TS 36.413.
type UEContextSuspendRequestUserLocationInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s56.UserLocationInformationValueCodec
	inject func(s55.UserLocationInformation,

	) s56.UEContextSuspendRequestIEValue

	get func(*s56.UEContextSuspendRequestIEValue,

	) (*s55.UserLocationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendRequestUserLocationInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendRequestUserLocationInformationIEBinding) Codec() s56.UserLocationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextSuspendRequestUserLocationInformationIEBinding) New(value s55.UserLocationInformation,

) (s56.UEContextSuspendRequestIEField, error) {
	if b.inject == nil {
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s56.BridgeUserLocationInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return s56.UEContextSuspendRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextSuspendRequestUserLocationInformationIEBinding) Get(field *s56.UEContextSuspendRequestIEField) (*s55.UserLocationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationIndicationValueCodec is the concrete ValueCodec[ERABModificationIndication].
type ERABModificationIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationIndication,

		error)
	encode func(ERABModificationIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationIndication, aper.DecodeState,

	) (ERABModificationIndication, aper.Snapshot,

	)
	compare func(ERABModificationIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationIndicationValueCodec) New(value ERABModificationIndication,

) (ERABModificationIndicationAPERValue, error) {
	if c.encode == nil {
		return ERABModificationIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationIndicationValueCodec) EncodeAPER(value ERABModificationIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModificationIndicationValueCodec) encodeBudgetValue(value ERABModificationIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationIndicationValueCodec) encodeChanged(value ERABModificationIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyResponseValueCodec is the concrete ValueCodec[ERABModifyResponse].
type ERABModifyResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyResponse,

		error)
	encode func(ERABModifyResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyResponse, aper.DecodeState,

	) (ERABModifyResponse, aper.Snapshot,

	)
	compare func(ERABModifyResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyResponseValueCodec) New(value ERABModifyResponse,

) (ERABModifyResponseAPERValue, error) {
	if c.encode == nil {
		return ERABModifyResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyResponseValueCodec) EncodeAPER(value ERABModifyResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABModifyResponseValueCodec) encodeBudgetValue(value ERABModifyResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyResponseValueCodec) encodeChanged(value ERABModifyResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseIndicationValueCodec is the concrete ValueCodec[ERABReleaseIndication].
type ERABReleaseIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseIndication,

		error)
	encode func(ERABReleaseIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseIndication, aper.DecodeState,

	) (ERABReleaseIndication, aper.Snapshot,

	)
	compare func(ERABReleaseIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseIndicationValueCodec) New(value ERABReleaseIndication,

) (ERABReleaseIndicationAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseIndicationValueCodec) EncodeAPER(value ERABReleaseIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseIndicationValueCodec) encodeBudgetValue(value ERABReleaseIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseIndicationValueCodec) encodeChanged(value ERABReleaseIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseResponseValueCodec is the concrete ValueCodec[ERABReleaseResponse].
type ERABReleaseResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseResponse,

		error)
	encode func(ERABReleaseResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseResponse, aper.DecodeState,

	) (ERABReleaseResponse, aper.Snapshot,

	)
	compare func(ERABReleaseResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseResponseValueCodec) New(value ERABReleaseResponse,

) (ERABReleaseResponseAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseResponseValueCodec) EncodeAPER(value ERABReleaseResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseResponseValueCodec) encodeBudgetValue(value ERABReleaseResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseResponseValueCodec) encodeChanged(value ERABReleaseResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupResponseValueCodec is the concrete ValueCodec[ERABSetupResponse].
type ERABSetupResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupResponse,

		error)
	encode func(ERABSetupResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupResponse, aper.DecodeState,

	) (ERABSetupResponse, aper.Snapshot,

	)
	compare func(ERABSetupResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupResponseValueCodec) New(value ERABSetupResponse,

) (ERABSetupResponseAPERValue, error) {
	if c.encode == nil {
		return ERABSetupResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupResponseValueCodec) EncodeAPER(value ERABSetupResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupResponseValueCodec) encodeBudgetValue(value ERABSetupResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupResponseValueCodec) encodeChanged(value ERABSetupResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportValueCodec is the concrete ValueCodec[SecondaryRATDataUsageReport].
type SecondaryRATDataUsageReportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReport,

		error)
	encode func(SecondaryRATDataUsageReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReport, aper.DecodeState,

	) (SecondaryRATDataUsageReport, aper.Snapshot,

	)
	compare func(SecondaryRATDataUsageReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportValueCodec) New(value SecondaryRATDataUsageReport,

) (SecondaryRATDataUsageReportAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportValueCodec) EncodeAPER(value SecondaryRATDataUsageReportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecondaryRATDataUsageReportValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportValueCodec) encodeChanged(value SecondaryRATDataUsageReport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCompleteValueCodec is the concrete ValueCodec[UEContextReleaseComplete].
type UEContextReleaseCompleteValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseComplete,

		error)
	encode func(UEContextReleaseComplete,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseComplete, aper.DecodeState,

	) (UEContextReleaseComplete, aper.Snapshot,

	)
	compare func(UEContextReleaseComplete, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCompleteValueCodec) New(value UEContextReleaseComplete,

) (UEContextReleaseCompleteAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCompleteAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCompleteAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCompleteAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCompleteValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCompleteAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCompleteAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCompleteAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCompleteAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCompleteAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCompleteValueCodec) EncodeAPER(value UEContextReleaseCompleteAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextReleaseCompleteValueCodec) encodeBudgetValue(value UEContextReleaseComplete,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCompleteValueCodec) encodeChanged(value UEContextReleaseComplete,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendRequestValueCodec is the concrete ValueCodec[UEContextSuspendRequest].
type UEContextSuspendRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendRequest,

		error)
	encode func(UEContextSuspendRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendRequest, aper.DecodeState,

	) (UEContextSuspendRequest, aper.Snapshot,

	)
	compare func(UEContextSuspendRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendRequestValueCodec) New(value UEContextSuspendRequest,

) (UEContextSuspendRequestAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendRequestValueCodec) EncodeAPER(value UEContextSuspendRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextSuspendRequestValueCodec) encodeBudgetValue(value UEContextSuspendRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendRequestValueCodec) encodeChanged(value UEContextSuspendRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABSetupResponseIEValueValidateS1APIEContainer(fields s56.ERABSetupResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s56.BridgeERABSetupResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s56.BridgeERABSetupResponseIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s56.BridgeERABSetupResponseIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABModifyResponseIEValueValidateS1APIEContainer(fields s56.ERABModifyResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s56.BridgeERABModifyResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s56.BridgeERABModifyResponseIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s56.BridgeERABModifyResponseIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABReleaseResponseIEValueValidateS1APIEContainer(fields s56.ERABReleaseResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s56.BridgeERABReleaseResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s56.BridgeERABReleaseResponseIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s56.BridgeERABReleaseResponseIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABReleaseIndicationIEValueValidateS1APIEContainer(fields s56.ERABReleaseIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s56.BridgeERABReleaseIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s56.BridgeERABReleaseIndicationIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s56.BridgeERABReleaseIndicationIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeUEContextReleaseCompleteIEValueValidateS1APIEContainer(fields s56.UEContextReleaseCompleteIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s56.BridgeUEContextReleaseCompleteIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s56.BridgeUEContextReleaseCompleteIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s56.BridgeUEContextReleaseCompleteIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABModificationIndicationIEValueValidateS1APIEContainer(fields s56.ERABModificationIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s56.BridgeERABModificationIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s56.BridgeERABModificationIndicationIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s56.BridgeERABModificationIndicationIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeUEContextSuspendRequestIEValueValidateS1APIEContainer(fields s56.UEContextSuspendRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s56.BridgeUEContextSuspendRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s56.BridgeUEContextSuspendRequestIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s56.BridgeUEContextSuspendRequestIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeSecondaryRATDataUsageReportIEValueValidateS1APIEContainer(fields s56.SecondaryRATDataUsageReportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s56.BridgeSecondaryRATDataUsageReportIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s56.BridgeSecondaryRATDataUsageReportIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s56.BridgeSecondaryRATDataUsageReportIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeUserLocationInformationExtIEsValueValidateS1APExtensionContainer(fields s25.UserLocationInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s25.UserLocationInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s25.UserLocationInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUserLocationInformationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// ERABModificationIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABModificationIndicationIEs}} codec of TS 36.413.
func ERABModificationIndicationIEValueERABIEContainerListCodec(table s00.ERABModificationIndicationIEValueIETable) s56.ERABModificationIndicationIEValueERABIEContainerListValueCodec {
	codec := ERABModificationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeERABModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABModificationIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABModificationIndicationIEValueERABIEContainerListValueCodec {
		sealed := s56.ERABModificationIndicationIEValueERABIEContainerListValueCodec{}
		*s56.BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABModificationIndicationIEValueERABIEContainerList"
		*s56.BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABModificationIndicationIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABModificationIndicationIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABModificationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModificationIndicationIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModificationIndicationIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModificationIndicationIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABModificationIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABModificationIndicationIEContainerValueCodecFieldEncode(&codec))(s56.ERABModificationIndicationIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABModificationIndicationIEValueERABIEContainerList, options aper.DecodeState) (s56.ERABModificationIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModificationIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABModificationIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModificationIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABModifyResponseIEs}} codec of TS 36.413.
func ERABModifyResponseIEValueERABIEContainerListCodec(table s00.ERABModifyResponseIEValueIETable) s56.ERABModifyResponseIEValueERABIEContainerListValueCodec {
	codec := ERABModifyResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeERABModifyResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABModifyResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABModifyResponseIEValueERABIEContainerListValueCodec {
		sealed := s56.ERABModifyResponseIEValueERABIEContainerListValueCodec{}
		*s56.BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABModifyResponseIEValueERABIEContainerList"
		*s56.BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABModifyResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABModifyResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABModifyResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABModifyResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyResponseIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyResponseIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyResponseIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABModifyResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABModifyResponseIEContainerValueCodecFieldEncode(&codec))(s56.ERABModifyResponseIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABModifyResponseIEValueERABIEContainerList, options aper.DecodeState) (s56.ERABModifyResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABModifyResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABModifyResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABReleaseIndicationIEs}} codec of TS 36.413.
func ERABReleaseIndicationIEValueERABIEContainerListCodec(table s00.ERABReleaseIndicationIEValueIETable) s56.ERABReleaseIndicationIEValueERABIEContainerListValueCodec {
	codec := ERABReleaseIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABReleaseIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABReleaseIndicationIEValueERABIEContainerListValueCodec {
		sealed := s56.ERABReleaseIndicationIEValueERABIEContainerListValueCodec{}
		*s56.BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABReleaseIndicationIEValueERABIEContainerList"
		*s56.BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABReleaseIndicationIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABReleaseIndicationIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABReleaseIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABReleaseIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseIndicationIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseIndicationIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseIndicationIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABReleaseIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldEncode(&codec))(s56.ERABReleaseIndicationIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABReleaseIndicationIEValueERABIEContainerList, options aper.DecodeState) (s56.ERABReleaseIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABReleaseIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABReleaseIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABReleaseResponseIEs}} codec of TS 36.413.
func ERABReleaseResponseIEValueERABIEContainerListCodec(table s00.ERABReleaseResponseIEValueIETable) s56.ERABReleaseResponseIEValueERABIEContainerListValueCodec {
	codec := ERABReleaseResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABReleaseResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABReleaseResponseIEValueERABIEContainerListValueCodec {
		sealed := s56.ERABReleaseResponseIEValueERABIEContainerListValueCodec{}
		*s56.BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABReleaseResponseIEValueERABIEContainerList"
		*s56.BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABReleaseResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABReleaseResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABReleaseResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABReleaseResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseResponseIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseResponseIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseResponseIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABReleaseResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABReleaseResponseIEContainerValueCodecFieldEncode(&codec))(s56.ERABReleaseResponseIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABReleaseResponseIEValueERABIEContainerList, options aper.DecodeState) (s56.ERABReleaseResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABReleaseResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABSetupResponseIEs}} codec of TS 36.413.
func ERABSetupResponseIEValueERABIEContainerListCodec(table s00.ERABSetupResponseIEValueIETable) s56.ERABSetupResponseIEValueERABIEContainerListValueCodec {
	codec := ERABSetupResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeERABSetupResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABSetupResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABSetupResponseIEValueERABIEContainerListValueCodec {
		sealed := s56.ERABSetupResponseIEValueERABIEContainerListValueCodec{}
		*s56.BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABSetupResponseIEValueERABIEContainerList"
		*s56.BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABSetupResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABSetupResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABSetupResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABSetupResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupResponseIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupResponseIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupResponseIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABSetupResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABSetupResponseIEContainerValueCodecFieldEncode(&codec))(s56.ERABSetupResponseIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABSetupResponseIEValueERABIEContainerList, options aper.DecodeState) (s56.ERABSetupResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABSetupResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SecondaryRATDataUsageReportIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{SecondaryRATDataUsageReportIEs}} codec of TS 36.413.
func SecondaryRATDataUsageReportIEValueERABIEContainerListCodec(table s00.SecondaryRATDataUsageReportIEValueIETable) s56.SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec {
	codec := SecondaryRATDataUsageReportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec {
		sealed := s56.SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec{}
		*s56.BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportIEValueERABIEContainerList"
		*s56.BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.SecondaryRATDataUsageReportIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.SecondaryRATDataUsageReportIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.SecondaryRATDataUsageReportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeSecondaryRATDataUsageReportIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "SecondaryRATDataUsageReportIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.SecondaryRATDataUsageReportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldEncode(&codec))(s56.SecondaryRATDataUsageReportIEContainer(value), fresh, budget)
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.SecondaryRATDataUsageReportIEValueERABIEContainerList, options aper.DecodeState) (s56.SecondaryRATDataUsageReportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.SecondaryRATDataUsageReportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextReleaseCompleteIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextReleaseComplete-IEs}} codec of TS 36.413.
func UEContextReleaseCompleteIEValueERABIEContainerListCodec(table s00.UEContextReleaseCompleteIEValueIETable) s56.UEContextReleaseCompleteIEValueERABIEContainerListValueCodec {
	codec := UEContextReleaseCompleteIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.UEContextReleaseCompleteIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.UEContextReleaseCompleteIEValueERABIEContainerListValueCodec {
		sealed := s56.UEContextReleaseCompleteIEValueERABIEContainerListValueCodec{}
		*s56.BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UEContextReleaseCompleteIEValueERABIEContainerList"
		*s56.BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.UEContextReleaseCompleteIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.UEContextReleaseCompleteIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.UEContextReleaseCompleteIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeUEContextReleaseCompleteIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCompleteIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCompleteIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCompleteIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.UEContextReleaseCompleteIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldEncode(&codec))(s56.UEContextReleaseCompleteIEContainer(value), fresh, budget)
		}
		*s56.BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.UEContextReleaseCompleteIEValueERABIEContainerList, options aper.DecodeState) (s56.UEContextReleaseCompleteIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.UEContextReleaseCompleteIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextSuspendRequestIEs}} codec of TS 36.413.
func UEContextSuspendRequestIEValueERABIEContainerListCodec(table s00.UEContextSuspendRequestIEValueIETable) s56.UEContextSuspendRequestIEValueERABIEContainerListValueCodec {
	codec := UEContextSuspendRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.UEContextSuspendRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.UEContextSuspendRequestIEValueERABIEContainerListValueCodec {
		sealed := s56.UEContextSuspendRequestIEValueERABIEContainerListValueCodec{}
		*s56.BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UEContextSuspendRequestIEValueERABIEContainerList"
		*s56.BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.UEContextSuspendRequestIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.UEContextSuspendRequestIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.UEContextSuspendRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeUEContextSuspendRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendRequestIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextSuspendRequestIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendRequestIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.UEContextSuspendRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldEncode(&codec))(s56.UEContextSuspendRequestIEContainer(value), fresh, budget)
		}
		*s56.BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.UEContextSuspendRequestIEValueERABIEContainerList, options aper.DecodeState) (s56.UEContextSuspendRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.UEContextSuspendRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// V2XServicesAuthorizedExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{V2XServicesAuthorized-ExtIEs}} codec of TS 36.413.
func V2XServicesAuthorizedExtIEsValueExtensionFieldTableCodec(table s00.V2XServicesAuthorizedExtIEsValueExtensionTable) s14.V2XServicesAuthorizedExtIEsExtFieldValueCodec {
	if !*s00.BridgeV2XServicesAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s14.V2XServicesAuthorizedExtIEsExtFieldValueCodec{}
	}
	return func() s14.V2XServicesAuthorizedExtIEsExtFieldValueCodec {
		sealed := s14.V2XServicesAuthorizedExtIEsExtFieldValueCodec{}
		*s14.BridgeV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldPath(&sealed) = "V2XServicesAuthorizedExtIEsExtField"
		*s14.BridgeV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.V2XServicesAuthorizedExtIEsExtField, error) {
			var field s14.V2XServicesAuthorizedExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "V2XServicesAuthorizedExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "V2XServicesAuthorizedExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "V2XServicesAuthorizedExtIEsExtField")
			}
			return field, nil
		}
		*s14.BridgeV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s14.V2XServicesAuthorizedExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s14.V2XServicesAuthorizedExtIEsExtField, options aper.DecodeState) (s14.V2XServicesAuthorizedExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s14.BridgeV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s14.V2XServicesAuthorizedExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModificationIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABModificationIndicationIEs}} codec of TS 36.413.
func ERABModificationIndicationIEValueIEFieldTableCodec(table s00.ERABModificationIndicationIEValueIETable) s56.ERABModificationIndicationIEFieldValueCodec {
	if !*s00.BridgeERABModificationIndicationIEValueIETableFieldBound(&table) {
		return s56.ERABModificationIndicationIEFieldValueCodec{}
	}
	return func() s56.ERABModificationIndicationIEFieldValueCodec {
		sealed := s56.ERABModificationIndicationIEFieldValueCodec{}
		*s56.BridgeERABModificationIndicationIEFieldValueCodecFieldPath(&sealed) = "ERABModificationIndicationIEField"
		*s56.BridgeERABModificationIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABModificationIndicationIEField, error) {
			var field s56.ERABModificationIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s56.BridgeERABModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModificationIndicationIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModificationIndicationIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModificationIndicationIEField")
			}
			return field, nil
		}
		*s56.BridgeERABModificationIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s56.ERABModificationIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s56.BridgeERABModificationIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeERABModificationIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s56.ERABModificationIndicationIEField, options aper.DecodeState) (s56.ERABModificationIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModificationIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABModificationIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s56.ERABModificationIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModificationIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABModificationIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABModifyResponseIEs}} codec of TS 36.413.
func ERABModifyResponseIEValueIEFieldTableCodec(table s00.ERABModifyResponseIEValueIETable) s56.ERABModifyResponseIEFieldValueCodec {
	if !*s00.BridgeERABModifyResponseIEValueIETableFieldBound(&table) {
		return s56.ERABModifyResponseIEFieldValueCodec{}
	}
	return func() s56.ERABModifyResponseIEFieldValueCodec {
		sealed := s56.ERABModifyResponseIEFieldValueCodec{}
		*s56.BridgeERABModifyResponseIEFieldValueCodecFieldPath(&sealed) = "ERABModifyResponseIEField"
		*s56.BridgeERABModifyResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABModifyResponseIEField, error) {
			var field s56.ERABModifyResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s56.BridgeERABModifyResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModifyResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModifyResponseIEField")
			}
			return field, nil
		}
		*s56.BridgeERABModifyResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s56.ERABModifyResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s56.BridgeERABModifyResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeERABModifyResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s56.ERABModifyResponseIEField, options aper.DecodeState) (s56.ERABModifyResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABModifyResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s56.ERABModifyResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABModifyResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABReleaseIndicationIEs}} codec of TS 36.413.
func ERABReleaseIndicationIEValueIEFieldTableCodec(table s00.ERABReleaseIndicationIEValueIETable) s56.ERABReleaseIndicationIEFieldValueCodec {
	if !*s00.BridgeERABReleaseIndicationIEValueIETableFieldBound(&table) {
		return s56.ERABReleaseIndicationIEFieldValueCodec{}
	}
	return func() s56.ERABReleaseIndicationIEFieldValueCodec {
		sealed := s56.ERABReleaseIndicationIEFieldValueCodec{}
		*s56.BridgeERABReleaseIndicationIEFieldValueCodecFieldPath(&sealed) = "ERABReleaseIndicationIEField"
		*s56.BridgeERABReleaseIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABReleaseIndicationIEField, error) {
			var field s56.ERABReleaseIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s56.BridgeERABReleaseIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABReleaseIndicationIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseIndicationIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABReleaseIndicationIEField")
			}
			return field, nil
		}
		*s56.BridgeERABReleaseIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s56.ERABReleaseIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s56.BridgeERABReleaseIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeERABReleaseIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s56.ERABReleaseIndicationIEField, options aper.DecodeState) (s56.ERABReleaseIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABReleaseIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s56.ERABReleaseIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABReleaseIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABReleaseResponseIEs}} codec of TS 36.413.
func ERABReleaseResponseIEValueIEFieldTableCodec(table s00.ERABReleaseResponseIEValueIETable) s56.ERABReleaseResponseIEFieldValueCodec {
	if !*s00.BridgeERABReleaseResponseIEValueIETableFieldBound(&table) {
		return s56.ERABReleaseResponseIEFieldValueCodec{}
	}
	return func() s56.ERABReleaseResponseIEFieldValueCodec {
		sealed := s56.ERABReleaseResponseIEFieldValueCodec{}
		*s56.BridgeERABReleaseResponseIEFieldValueCodecFieldPath(&sealed) = "ERABReleaseResponseIEField"
		*s56.BridgeERABReleaseResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABReleaseResponseIEField, error) {
			var field s56.ERABReleaseResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s56.BridgeERABReleaseResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABReleaseResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABReleaseResponseIEField")
			}
			return field, nil
		}
		*s56.BridgeERABReleaseResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s56.ERABReleaseResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s56.BridgeERABReleaseResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeERABReleaseResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s56.ERABReleaseResponseIEField, options aper.DecodeState) (s56.ERABReleaseResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABReleaseResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s56.ERABReleaseResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABReleaseResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABSetupResponseIEs}} codec of TS 36.413.
func ERABSetupResponseIEValueIEFieldTableCodec(table s00.ERABSetupResponseIEValueIETable) s56.ERABSetupResponseIEFieldValueCodec {
	if !*s00.BridgeERABSetupResponseIEValueIETableFieldBound(&table) {
		return s56.ERABSetupResponseIEFieldValueCodec{}
	}
	return func() s56.ERABSetupResponseIEFieldValueCodec {
		sealed := s56.ERABSetupResponseIEFieldValueCodec{}
		*s56.BridgeERABSetupResponseIEFieldValueCodecFieldPath(&sealed) = "ERABSetupResponseIEField"
		*s56.BridgeERABSetupResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABSetupResponseIEField, error) {
			var field s56.ERABSetupResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s56.BridgeERABSetupResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSetupResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSetupResponseIEField")
			}
			return field, nil
		}
		*s56.BridgeERABSetupResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s56.ERABSetupResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s56.BridgeERABSetupResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeERABSetupResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s56.ERABSetupResponseIEField, options aper.DecodeState) (s56.ERABSetupResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABSetupResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s56.ERABSetupResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABSetupResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SecondaryRATDataUsageReportIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{SecondaryRATDataUsageReportIEs}} codec of TS 36.413.
func SecondaryRATDataUsageReportIEValueIEFieldTableCodec(table s00.SecondaryRATDataUsageReportIEValueIETable) s56.SecondaryRATDataUsageReportIEFieldValueCodec {
	if !*s00.BridgeSecondaryRATDataUsageReportIEValueIETableFieldBound(&table) {
		return s56.SecondaryRATDataUsageReportIEFieldValueCodec{}
	}
	return func() s56.SecondaryRATDataUsageReportIEFieldValueCodec {
		sealed := s56.SecondaryRATDataUsageReportIEFieldValueCodec{}
		*s56.BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportIEField"
		*s56.BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.SecondaryRATDataUsageReportIEField, error) {
			var field s56.SecondaryRATDataUsageReportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s56.BridgeSecondaryRATDataUsageReportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "SecondaryRATDataUsageReportIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportIEField")
			}
			return field, nil
		}
		*s56.BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldEncode(&sealed) = func(field s56.SecondaryRATDataUsageReportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s56.BridgeSecondaryRATDataUsageReportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldCapture(&sealed) = func(v s56.SecondaryRATDataUsageReportIEField, options aper.DecodeState) (s56.SecondaryRATDataUsageReportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldCompare(&sealed) = func(v s56.SecondaryRATDataUsageReportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextReleaseCompleteIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextReleaseComplete-IEs}} codec of TS 36.413.
func UEContextReleaseCompleteIEValueIEFieldTableCodec(table s00.UEContextReleaseCompleteIEValueIETable) s56.UEContextReleaseCompleteIEFieldValueCodec {
	if !*s00.BridgeUEContextReleaseCompleteIEValueIETableFieldBound(&table) {
		return s56.UEContextReleaseCompleteIEFieldValueCodec{}
	}
	return func() s56.UEContextReleaseCompleteIEFieldValueCodec {
		sealed := s56.UEContextReleaseCompleteIEFieldValueCodec{}
		*s56.BridgeUEContextReleaseCompleteIEFieldValueCodecFieldPath(&sealed) = "UEContextReleaseCompleteIEField"
		*s56.BridgeUEContextReleaseCompleteIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.UEContextReleaseCompleteIEField, error) {
			var field s56.UEContextReleaseCompleteIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s56.BridgeUEContextReleaseCompleteIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextReleaseCompleteIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCompleteIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextReleaseCompleteIEField")
			}
			return field, nil
		}
		*s56.BridgeUEContextReleaseCompleteIEFieldValueCodecFieldEncode(&sealed) = func(field s56.UEContextReleaseCompleteIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s56.BridgeUEContextReleaseCompleteIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeUEContextReleaseCompleteIEFieldValueCodecFieldCapture(&sealed) = func(v s56.UEContextReleaseCompleteIEField, options aper.DecodeState) (s56.UEContextReleaseCompleteIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeUEContextReleaseCompleteIEFieldValueCodecFieldCompare(&sealed) = func(v s56.UEContextReleaseCompleteIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUEContextReleaseCompleteIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextSuspendRequestIEs}} codec of TS 36.413.
func UEContextSuspendRequestIEValueIEFieldTableCodec(table s00.UEContextSuspendRequestIEValueIETable) s56.UEContextSuspendRequestIEFieldValueCodec {
	if !*s00.BridgeUEContextSuspendRequestIEValueIETableFieldBound(&table) {
		return s56.UEContextSuspendRequestIEFieldValueCodec{}
	}
	return func() s56.UEContextSuspendRequestIEFieldValueCodec {
		sealed := s56.UEContextSuspendRequestIEFieldValueCodec{}
		*s56.BridgeUEContextSuspendRequestIEFieldValueCodecFieldPath(&sealed) = "UEContextSuspendRequestIEField"
		*s56.BridgeUEContextSuspendRequestIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.UEContextSuspendRequestIEField, error) {
			var field s56.UEContextSuspendRequestIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s56.BridgeUEContextSuspendRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextSuspendRequestIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextSuspendRequestIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextSuspendRequestIEField")
			}
			return field, nil
		}
		*s56.BridgeUEContextSuspendRequestIEFieldValueCodecFieldEncode(&sealed) = func(field s56.UEContextSuspendRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s56.BridgeUEContextSuspendRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeUEContextSuspendRequestIEFieldValueCodecFieldCapture(&sealed) = func(v s56.UEContextSuspendRequestIEField, options aper.DecodeState) (s56.UEContextSuspendRequestIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeUEContextSuspendRequestIEFieldValueCodecFieldCompare(&sealed) = func(v s56.UEContextSuspendRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUEContextSuspendRequestIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModificationIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABModificationIndicationIEs}} codec of TS 36.413.
func ERABModificationIndicationIEValueIETableCodec(table s00.ERABModificationIndicationIEValueIETable, bounds aper.ListBounds) s56.ERABModificationIndicationIEContainerValueCodec {
	if !*s00.BridgeERABModificationIndicationIEValueIETableFieldBound(&table) {
		return s56.ERABModificationIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABModificationIndicationIEContainerValueCodec {
		sealed := s56.ERABModificationIndicationIEContainerValueCodec{}
		*s56.BridgeERABModificationIndicationIEContainerValueCodecFieldPath(&sealed) = "ERABModificationIndicationIEContainer"
		*s56.BridgeERABModificationIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABModificationIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABModificationIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABModificationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModificationIndicationIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModificationIndicationIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModificationIndicationIEContainer")
			}
			return fields, nil
		}
		*s56.BridgeERABModificationIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s56.ERABModificationIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s56.BridgeERABModificationIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeERABModificationIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s56.ERABModificationIndicationIEContainer, options aper.DecodeState) (s56.ERABModificationIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModificationIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeERABModificationIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s56.ERABModificationIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModificationIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABModificationIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyResponseIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABModifyResponseIEs}} codec of TS 36.413.
func ERABModifyResponseIEValueIETableCodec(table s00.ERABModifyResponseIEValueIETable, bounds aper.ListBounds) s56.ERABModifyResponseIEContainerValueCodec {
	if !*s00.BridgeERABModifyResponseIEValueIETableFieldBound(&table) {
		return s56.ERABModifyResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABModifyResponseIEContainerValueCodec {
		sealed := s56.ERABModifyResponseIEContainerValueCodec{}
		*s56.BridgeERABModifyResponseIEContainerValueCodecFieldPath(&sealed) = "ERABModifyResponseIEContainer"
		*s56.BridgeERABModifyResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABModifyResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABModifyResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABModifyResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABModifyResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyResponseIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyResponseIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyResponseIEContainer")
			}
			return fields, nil
		}
		*s56.BridgeERABModifyResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s56.ERABModifyResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s56.BridgeERABModifyResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeERABModifyResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s56.ERABModifyResponseIEContainer, options aper.DecodeState) (s56.ERABModifyResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeERABModifyResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s56.ERABModifyResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABModifyResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABReleaseIndicationIEs}} codec of TS 36.413.
func ERABReleaseIndicationIEValueIETableCodec(table s00.ERABReleaseIndicationIEValueIETable, bounds aper.ListBounds) s56.ERABReleaseIndicationIEContainerValueCodec {
	if !*s00.BridgeERABReleaseIndicationIEValueIETableFieldBound(&table) {
		return s56.ERABReleaseIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABReleaseIndicationIEContainerValueCodec {
		sealed := s56.ERABReleaseIndicationIEContainerValueCodec{}
		*s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldPath(&sealed) = "ERABReleaseIndicationIEContainer"
		*s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABReleaseIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABReleaseIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABReleaseIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABReleaseIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseIndicationIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseIndicationIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseIndicationIEContainer")
			}
			return fields, nil
		}
		*s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s56.ERABReleaseIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s56.BridgeERABReleaseIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s56.ERABReleaseIndicationIEContainer, options aper.DecodeState) (s56.ERABReleaseIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s56.ERABReleaseIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseResponseIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABReleaseResponseIEs}} codec of TS 36.413.
func ERABReleaseResponseIEValueIETableCodec(table s00.ERABReleaseResponseIEValueIETable, bounds aper.ListBounds) s56.ERABReleaseResponseIEContainerValueCodec {
	if !*s00.BridgeERABReleaseResponseIEValueIETableFieldBound(&table) {
		return s56.ERABReleaseResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABReleaseResponseIEContainerValueCodec {
		sealed := s56.ERABReleaseResponseIEContainerValueCodec{}
		*s56.BridgeERABReleaseResponseIEContainerValueCodecFieldPath(&sealed) = "ERABReleaseResponseIEContainer"
		*s56.BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABReleaseResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABReleaseResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABReleaseResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABReleaseResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseResponseIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseResponseIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseResponseIEContainer")
			}
			return fields, nil
		}
		*s56.BridgeERABReleaseResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s56.ERABReleaseResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s56.BridgeERABReleaseResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeERABReleaseResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s56.ERABReleaseResponseIEContainer, options aper.DecodeState) (s56.ERABReleaseResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeERABReleaseResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s56.ERABReleaseResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABReleaseResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupResponseIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABSetupResponseIEs}} codec of TS 36.413.
func ERABSetupResponseIEValueIETableCodec(table s00.ERABSetupResponseIEValueIETable, bounds aper.ListBounds) s56.ERABSetupResponseIEContainerValueCodec {
	if !*s00.BridgeERABSetupResponseIEValueIETableFieldBound(&table) {
		return s56.ERABSetupResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABSetupResponseIEContainerValueCodec {
		sealed := s56.ERABSetupResponseIEContainerValueCodec{}
		*s56.BridgeERABSetupResponseIEContainerValueCodecFieldPath(&sealed) = "ERABSetupResponseIEContainer"
		*s56.BridgeERABSetupResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABSetupResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABSetupResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABSetupResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABSetupResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupResponseIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupResponseIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupResponseIEContainer")
			}
			return fields, nil
		}
		*s56.BridgeERABSetupResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s56.ERABSetupResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s56.BridgeERABSetupResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeERABSetupResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s56.ERABSetupResponseIEContainer, options aper.DecodeState) (s56.ERABSetupResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeERABSetupResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s56.ERABSetupResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABSetupResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SecondaryRATDataUsageReportIEValueIETableCodec constructs the ProtocolIE-Container {{SecondaryRATDataUsageReportIEs}} codec of TS 36.413.
func SecondaryRATDataUsageReportIEValueIETableCodec(table s00.SecondaryRATDataUsageReportIEValueIETable, bounds aper.ListBounds) s56.SecondaryRATDataUsageReportIEContainerValueCodec {
	if !*s00.BridgeSecondaryRATDataUsageReportIEValueIETableFieldBound(&table) {
		return s56.SecondaryRATDataUsageReportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s56.SecondaryRATDataUsageReportIEContainerValueCodec {
		sealed := s56.SecondaryRATDataUsageReportIEContainerValueCodec{}
		*s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportIEContainer"
		*s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.SecondaryRATDataUsageReportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.SecondaryRATDataUsageReportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.SecondaryRATDataUsageReportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeSecondaryRATDataUsageReportIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "SecondaryRATDataUsageReportIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportIEContainer")
			}
			return fields, nil
		}
		*s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldEncode(&sealed) = func(fields s56.SecondaryRATDataUsageReportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s56.BridgeSecondaryRATDataUsageReportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldCapture(&sealed) = func(v s56.SecondaryRATDataUsageReportIEContainer, options aper.DecodeState) (s56.SecondaryRATDataUsageReportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldCompare(&sealed) = func(v s56.SecondaryRATDataUsageReportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextReleaseCompleteIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextReleaseComplete-IEs}} codec of TS 36.413.
func UEContextReleaseCompleteIEValueIETableCodec(table s00.UEContextReleaseCompleteIEValueIETable, bounds aper.ListBounds) s56.UEContextReleaseCompleteIEContainerValueCodec {
	if !*s00.BridgeUEContextReleaseCompleteIEValueIETableFieldBound(&table) {
		return s56.UEContextReleaseCompleteIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s56.UEContextReleaseCompleteIEContainerValueCodec {
		sealed := s56.UEContextReleaseCompleteIEContainerValueCodec{}
		*s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldPath(&sealed) = "UEContextReleaseCompleteIEContainer"
		*s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.UEContextReleaseCompleteIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.UEContextReleaseCompleteIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.UEContextReleaseCompleteIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeUEContextReleaseCompleteIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCompleteIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCompleteIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCompleteIEContainer")
			}
			return fields, nil
		}
		*s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldEncode(&sealed) = func(fields s56.UEContextReleaseCompleteIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s56.BridgeUEContextReleaseCompleteIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldCapture(&sealed) = func(v s56.UEContextReleaseCompleteIEContainer, options aper.DecodeState) (s56.UEContextReleaseCompleteIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldCompare(&sealed) = func(v s56.UEContextReleaseCompleteIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendRequestIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextSuspendRequestIEs}} codec of TS 36.413.
func UEContextSuspendRequestIEValueIETableCodec(table s00.UEContextSuspendRequestIEValueIETable, bounds aper.ListBounds) s56.UEContextSuspendRequestIEContainerValueCodec {
	if !*s00.BridgeUEContextSuspendRequestIEValueIETableFieldBound(&table) {
		return s56.UEContextSuspendRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s56.UEContextSuspendRequestIEContainerValueCodec {
		sealed := s56.UEContextSuspendRequestIEContainerValueCodec{}
		*s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldPath(&sealed) = "UEContextSuspendRequestIEContainer"
		*s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.UEContextSuspendRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.UEContextSuspendRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.UEContextSuspendRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeUEContextSuspendRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendRequestIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextSuspendRequestIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendRequestIEContainer")
			}
			return fields, nil
		}
		*s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s56.UEContextSuspendRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s56.BridgeUEContextSuspendRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s56.UEContextSuspendRequestIEContainer, options aper.DecodeState) (s56.UEContextSuspendRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s56.UEContextSuspendRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABModificationIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABModificationIndicationIEs}} codec of TS 36.413.
func ERABModificationIndicationIEValueProtocolErrorIEContainerListCodec(table s00.ERABModificationIndicationIEValueIETable) s56.ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABModificationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeERABModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s56.ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s56.BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABModificationIndicationIEValueProtocolErrorIEContainerList"
		*s56.BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABModificationIndicationIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABModificationIndicationIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABModificationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModificationIndicationIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModificationIndicationIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModificationIndicationIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABModificationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABModificationIndicationIEContainerValueCodecFieldEncode(&codec))(s56.ERABModificationIndicationIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABModificationIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s56.ERABModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModificationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABModificationIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModificationIndicationIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABModifyResponseIEs}} codec of TS 36.413.
func ERABModifyResponseIEValueProtocolErrorIEContainerListCodec(table s00.ERABModifyResponseIEValueIETable) s56.ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABModifyResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeERABModifyResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s56.ERABModifyResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s56.BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABModifyResponseIEValueProtocolErrorIEContainerList"
		*s56.BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABModifyResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABModifyResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABModifyResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABModifyResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyResponseIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyResponseIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyResponseIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABModifyResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABModifyResponseIEContainerValueCodecFieldEncode(&codec))(s56.ERABModifyResponseIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABModifyResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s56.ERABModifyResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABModifyResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABModifyResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABReleaseIndicationIEs}} codec of TS 36.413.
func ERABReleaseIndicationIEValueProtocolErrorIEContainerListCodec(table s00.ERABReleaseIndicationIEValueIETable) s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABReleaseIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s56.BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABReleaseIndicationIEValueProtocolErrorIEContainerList"
		*s56.BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABReleaseIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABReleaseIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseIndicationIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseIndicationIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseIndicationIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldEncode(&codec))(s56.ERABReleaseIndicationIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseIndicationIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABReleaseIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABReleaseResponseIEs}} codec of TS 36.413.
func ERABReleaseResponseIEValueProtocolErrorIEContainerListCodec(table s00.ERABReleaseResponseIEValueIETable) s56.ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABReleaseResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s56.ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s56.BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABReleaseResponseIEValueProtocolErrorIEContainerList"
		*s56.BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABReleaseResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABReleaseResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABReleaseResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABReleaseResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseResponseIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseResponseIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseResponseIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABReleaseResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABReleaseResponseIEContainerValueCodecFieldEncode(&codec))(s56.ERABReleaseResponseIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABReleaseResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s56.ERABReleaseResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABReleaseResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABSetupResponseIEs}} codec of TS 36.413.
func ERABSetupResponseIEValueProtocolErrorIEContainerListCodec(table s00.ERABSetupResponseIEValueIETable) s56.ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABSetupResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeERABSetupResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s56.ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s56.BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABSetupResponseIEValueProtocolErrorIEContainerList"
		*s56.BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABSetupResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABSetupResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABSetupResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABSetupResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupResponseIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupResponseIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupResponseIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABSetupResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABSetupResponseIEContainerValueCodecFieldEncode(&codec))(s56.ERABSetupResponseIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABSetupResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s56.ERABSetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABSetupResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{SecondaryRATDataUsageReportIEs}} codec of TS 36.413.
func SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListCodec(table s00.SecondaryRATDataUsageReportIEValueIETable) s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec {
	codec := SecondaryRATDataUsageReportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec{}
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList"
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.SecondaryRATDataUsageReportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeSecondaryRATDataUsageReportIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldEncode(&codec))(s56.SecondaryRATDataUsageReportIEContainer(value), fresh, budget)
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextReleaseCompleteIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextReleaseComplete-IEs}} codec of TS 36.413.
func UEContextReleaseCompleteIEValueProtocolErrorIEContainerListCodec(table s00.UEContextReleaseCompleteIEValueIETable) s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextReleaseCompleteIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec{}
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UEContextReleaseCompleteIEValueProtocolErrorIEContainerList"
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.UEContextReleaseCompleteIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeUEContextReleaseCompleteIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCompleteIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCompleteIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCompleteIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldEncode(&codec))(s56.UEContextReleaseCompleteIEContainer(value), fresh, budget)
		}
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextSuspendRequestIEs}} codec of TS 36.413.
func UEContextSuspendRequestIEValueProtocolErrorIEContainerListCodec(table s00.UEContextSuspendRequestIEValueIETable) s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextSuspendRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s56.BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UEContextSuspendRequestIEValueProtocolErrorIEContainerList"
		*s56.BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.UEContextSuspendRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeUEContextSuspendRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendRequestIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextSuspendRequestIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendRequestIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldEncode(&codec))(s56.UEContextSuspendRequestIEContainer(value), fresh, budget)
		}
		*s56.BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s56.BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModificationIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABModificationIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABModificationIndicationIEValueProtocolIEContainerListCodec(table s00.ERABModificationIndicationIEValueIETable, bounds aper.ListBounds) s56.ERABModificationIndicationIEValueProtocolIEContainerListValueCodec {
	codec := ERABModificationIndicationIEValueIETableCodec(table, bounds)
	if *s56.BridgeERABModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABModificationIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABModificationIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s56.ERABModificationIndicationIEValueProtocolIEContainerListValueCodec{}
		*s56.BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABModificationIndicationIEValueProtocolIEContainerList"
		*s56.BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABModificationIndicationIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABModificationIndicationIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABModificationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModificationIndicationIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModificationIndicationIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModificationIndicationIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABModificationIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABModificationIndicationIEContainerValueCodecFieldEncode(&codec))(s56.ERABModificationIndicationIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABModificationIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s56.ERABModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModificationIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABModificationIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABModificationIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABModifyResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABModifyResponseIEValueProtocolIEContainerListCodec(table s00.ERABModifyResponseIEValueIETable, bounds aper.ListBounds) s56.ERABModifyResponseIEValueProtocolIEContainerListValueCodec {
	codec := ERABModifyResponseIEValueIETableCodec(table, bounds)
	if *s56.BridgeERABModifyResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABModifyResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABModifyResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s56.ERABModifyResponseIEValueProtocolIEContainerListValueCodec{}
		*s56.BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABModifyResponseIEValueProtocolIEContainerList"
		*s56.BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABModifyResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABModifyResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABModifyResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABModifyResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyResponseIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyResponseIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyResponseIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABModifyResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABModifyResponseIEContainerValueCodecFieldEncode(&codec))(s56.ERABModifyResponseIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABModifyResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s56.ERABModifyResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABModifyResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABModifyResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABModifyResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABReleaseIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABReleaseIndicationIEValueProtocolIEContainerListCodec(table s00.ERABReleaseIndicationIEValueIETable, bounds aper.ListBounds) s56.ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec {
	codec := ERABReleaseIndicationIEValueIETableCodec(table, bounds)
	if *s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s56.ERABReleaseIndicationIEValueProtocolIEContainerListValueCodec{}
		*s56.BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABReleaseIndicationIEValueProtocolIEContainerList"
		*s56.BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABReleaseIndicationIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABReleaseIndicationIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABReleaseIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABReleaseIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseIndicationIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseIndicationIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseIndicationIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABReleaseIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABReleaseIndicationIEContainerValueCodecFieldEncode(&codec))(s56.ERABReleaseIndicationIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABReleaseIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s56.ERABReleaseIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABReleaseIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABReleaseIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABReleaseIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABReleaseResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABReleaseResponseIEValueProtocolIEContainerListCodec(table s00.ERABReleaseResponseIEValueIETable, bounds aper.ListBounds) s56.ERABReleaseResponseIEValueProtocolIEContainerListValueCodec {
	codec := ERABReleaseResponseIEValueIETableCodec(table, bounds)
	if *s56.BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABReleaseResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABReleaseResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s56.ERABReleaseResponseIEValueProtocolIEContainerListValueCodec{}
		*s56.BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABReleaseResponseIEValueProtocolIEContainerList"
		*s56.BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABReleaseResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABReleaseResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABReleaseResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABReleaseResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseResponseIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseResponseIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseResponseIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABReleaseResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABReleaseResponseIEContainerValueCodecFieldEncode(&codec))(s56.ERABReleaseResponseIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABReleaseResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s56.ERABReleaseResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABReleaseResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABReleaseResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {E-RABSetupResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ERABSetupResponseIEValueProtocolIEContainerListCodec(table s00.ERABSetupResponseIEValueIETable, bounds aper.ListBounds) s56.ERABSetupResponseIEValueProtocolIEContainerListValueCodec {
	codec := ERABSetupResponseIEValueIETableCodec(table, bounds)
	if *s56.BridgeERABSetupResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.ERABSetupResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s56.ERABSetupResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s56.ERABSetupResponseIEValueProtocolIEContainerListValueCodec{}
		*s56.BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ERABSetupResponseIEValueProtocolIEContainerList"
		*s56.BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.ERABSetupResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.ERABSetupResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.ERABSetupResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeERABSetupResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupResponseIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupResponseIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupResponseIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.ERABSetupResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeERABSetupResponseIEContainerValueCodecFieldEncode(&codec))(s56.ERABSetupResponseIEContainer(value), fresh, budget)
		}
		*s56.BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.ERABSetupResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s56.ERABSetupResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s56.BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.ERABSetupResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABSetupResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// SecondaryRATDataUsageReportIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {SecondaryRATDataUsageReportIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func SecondaryRATDataUsageReportIEValueProtocolIEContainerListCodec(table s00.SecondaryRATDataUsageReportIEValueIETable, bounds aper.ListBounds) s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec {
	codec := SecondaryRATDataUsageReportIEValueIETableCodec(table, bounds)
	if *s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec {
		sealed := s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec{}
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportIEValueProtocolIEContainerList"
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.SecondaryRATDataUsageReportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeSecondaryRATDataUsageReportIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "SecondaryRATDataUsageReportIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldEncode(&codec))(s56.SecondaryRATDataUsageReportIEContainer(value), fresh, budget)
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, options aper.DecodeState) (s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextReleaseCompleteIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextReleaseComplete-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextReleaseCompleteIEValueProtocolIEContainerListCodec(table s00.UEContextReleaseCompleteIEValueIETable, bounds aper.ListBounds) s56.UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec {
	codec := UEContextReleaseCompleteIEValueIETableCodec(table, bounds)
	if *s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s56.UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec {
		sealed := s56.UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec{}
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UEContextReleaseCompleteIEValueProtocolIEContainerList"
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.UEContextReleaseCompleteIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.UEContextReleaseCompleteIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.UEContextReleaseCompleteIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeUEContextReleaseCompleteIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCompleteIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCompleteIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCompleteIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.UEContextReleaseCompleteIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldEncode(&codec))(s56.UEContextReleaseCompleteIEContainer(value), fresh, budget)
		}
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.UEContextReleaseCompleteIEValueProtocolIEContainerList, options aper.DecodeState) (s56.UEContextReleaseCompleteIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.UEContextReleaseCompleteIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextSuspendRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextSuspendRequestIEValueProtocolIEContainerListCodec(table s00.UEContextSuspendRequestIEValueIETable, bounds aper.ListBounds) s56.UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec {
	codec := UEContextSuspendRequestIEValueIETableCodec(table, bounds)
	if *s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s56.UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s56.UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s56.UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec{}
		*s56.BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UEContextSuspendRequestIEValueProtocolIEContainerList"
		*s56.BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s56.UEContextSuspendRequestIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s56.UEContextSuspendRequestIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s56.UEContextSuspendRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s56.BridgeUEContextSuspendRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendRequestIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextSuspendRequestIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendRequestIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s56.BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s56.UEContextSuspendRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s56.BridgeUEContextSuspendRequestIEContainerValueCodecFieldEncode(&codec))(s56.UEContextSuspendRequestIEContainer(value), fresh, budget)
		}
		*s56.BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s56.UEContextSuspendRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s56.UEContextSuspendRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s56.BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s56.UEContextSuspendRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// eRABModificationIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABModificationIndicationIEValue].
type ERABModificationIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s56.ERABModificationIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s56.ERABModificationIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABModificationIndicationIEValueCaptureS1APProtocolIEField(v *s56.ERABModificationIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s56.BridgeERABModificationIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s56.BridgeERABModificationIndicationIEFieldFieldReplay(v), *s56.BridgeERABModificationIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeERABModificationIndicationIEValueCompareS1APProtocolIEField(v *s56.ERABModificationIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s56.BridgeERABModificationIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s56.BridgeERABModificationIndicationIEFieldFieldReplay(v), *s56.BridgeERABModificationIndicationIEFieldFieldWithoutReplay(v))
}

// eRABModifyResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABModifyResponseIEValue].
type ERABModifyResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s56.ERABModifyResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s56.ERABModifyResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABModifyResponseIEValueCaptureS1APProtocolIEField(v *s56.ERABModifyResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s56.BridgeERABModifyResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s56.BridgeERABModifyResponseIEFieldFieldReplay(v), *s56.BridgeERABModifyResponseIEFieldFieldWithoutReplay(v))
}
func BridgeERABModifyResponseIEValueCompareS1APProtocolIEField(v *s56.ERABModifyResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s56.BridgeERABModifyResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s56.BridgeERABModifyResponseIEFieldFieldReplay(v), *s56.BridgeERABModifyResponseIEFieldFieldWithoutReplay(v))
}

// eRABReleaseIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABReleaseIndicationIEValue].
type ERABReleaseIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s56.ERABReleaseIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s56.ERABReleaseIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIEField(v *s56.ERABReleaseIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s56.BridgeERABReleaseIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s56.BridgeERABReleaseIndicationIEFieldFieldReplay(v), *s56.BridgeERABReleaseIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeERABReleaseIndicationIEValueCompareS1APProtocolIEField(v *s56.ERABReleaseIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s56.BridgeERABReleaseIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s56.BridgeERABReleaseIndicationIEFieldFieldReplay(v), *s56.BridgeERABReleaseIndicationIEFieldFieldWithoutReplay(v))
}

// eRABReleaseResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABReleaseResponseIEValue].
type ERABReleaseResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s56.ERABReleaseResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s56.ERABReleaseResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEField(v *s56.ERABReleaseResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s56.BridgeERABReleaseResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s56.BridgeERABReleaseResponseIEFieldFieldReplay(v), *s56.BridgeERABReleaseResponseIEFieldFieldWithoutReplay(v))
}
func BridgeERABReleaseResponseIEValueCompareS1APProtocolIEField(v *s56.ERABReleaseResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s56.BridgeERABReleaseResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s56.BridgeERABReleaseResponseIEFieldFieldReplay(v), *s56.BridgeERABReleaseResponseIEFieldFieldWithoutReplay(v))
}

// eRABSetupResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABSetupResponseIEValue].
type ERABSetupResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s56.ERABSetupResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s56.ERABSetupResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABSetupResponseIEValueCaptureS1APProtocolIEField(v *s56.ERABSetupResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s56.BridgeERABSetupResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s56.BridgeERABSetupResponseIEFieldFieldReplay(v), *s56.BridgeERABSetupResponseIEFieldFieldWithoutReplay(v))
}
func BridgeERABSetupResponseIEValueCompareS1APProtocolIEField(v *s56.ERABSetupResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s56.BridgeERABSetupResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s56.BridgeERABSetupResponseIEFieldFieldReplay(v), *s56.BridgeERABSetupResponseIEFieldFieldWithoutReplay(v))
}

// secondaryRATDataUsageReportIEValueProtocolOpenValue is the concrete protocolOpenValue[SecondaryRATDataUsageReportIEValue].
type SecondaryRATDataUsageReportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s56.SecondaryRATDataUsageReportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s56.SecondaryRATDataUsageReportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEField(v *s56.SecondaryRATDataUsageReportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s56.BridgeSecondaryRATDataUsageReportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s56.BridgeSecondaryRATDataUsageReportIEFieldFieldReplay(v), *s56.BridgeSecondaryRATDataUsageReportIEFieldFieldWithoutReplay(v))
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEField(v *s56.SecondaryRATDataUsageReportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s56.BridgeSecondaryRATDataUsageReportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s56.BridgeSecondaryRATDataUsageReportIEFieldFieldReplay(v), *s56.BridgeSecondaryRATDataUsageReportIEFieldFieldWithoutReplay(v))
}

// uEContextReleaseCompleteIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextReleaseCompleteIEValue].
type UEContextReleaseCompleteIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s56.UEContextReleaseCompleteIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s56.UEContextReleaseCompleteIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEField(v *s56.UEContextReleaseCompleteIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s56.BridgeUEContextReleaseCompleteIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s56.BridgeUEContextReleaseCompleteIEFieldFieldReplay(v), *s56.BridgeUEContextReleaseCompleteIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEField(v *s56.UEContextReleaseCompleteIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s56.BridgeUEContextReleaseCompleteIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s56.BridgeUEContextReleaseCompleteIEFieldFieldReplay(v), *s56.BridgeUEContextReleaseCompleteIEFieldFieldWithoutReplay(v))
}

// uEContextSuspendRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextSuspendRequestIEValue].
type UEContextSuspendRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s56.UEContextSuspendRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s56.UEContextSuspendRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEField(v *s56.UEContextSuspendRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s56.BridgeUEContextSuspendRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s56.BridgeUEContextSuspendRequestIEFieldFieldReplay(v), *s56.BridgeUEContextSuspendRequestIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEField(v *s56.UEContextSuspendRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s56.BridgeUEContextSuspendRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s56.BridgeUEContextSuspendRequestIEFieldFieldReplay(v), *s56.BridgeUEContextSuspendRequestIEFieldFieldWithoutReplay(v))
}

// userLocationInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UserLocationInformationExtIEsValue].
type UserLocationInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s25.UserLocationInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s25.UserLocationInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(v *s14.V2XServicesAuthorizedExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeV2XServicesAuthorizedExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s14.BridgeV2XServicesAuthorizedExtIEsExtFieldFieldReplay(v), *s14.BridgeV2XServicesAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionField(v *s14.V2XServicesAuthorizedExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeV2XServicesAuthorizedExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s14.BridgeV2XServicesAuthorizedExtIEsExtFieldFieldReplay(v), *s14.BridgeV2XServicesAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}

// ERABModificationIndicationAPERValue is the concrete APERValue[ERABModificationIndication].
type ERABModificationIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABModificationIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationIndicationAPERValue) WithoutReplay() ERABModificationIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyResponseAPERValue is the concrete APERValue[ERABModifyResponse].
type ERABModifyResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABModifyResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyResponseAPERValue) WithoutReplay() ERABModifyResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseIndicationAPERValue is the concrete APERValue[ERABReleaseIndication].
type ERABReleaseIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABReleaseIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseIndicationAPERValue) WithoutReplay() ERABReleaseIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseResponseAPERValue is the concrete APERValue[ERABReleaseResponse].
type ERABReleaseResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABReleaseResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseResponseAPERValue) WithoutReplay() ERABReleaseResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupResponseAPERValue is the concrete APERValue[ERABSetupResponse].
type ERABSetupResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABSetupResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupResponseAPERValue) WithoutReplay() ERABSetupResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportAPERValue is the concrete APERValue[SecondaryRATDataUsageReport].
type SecondaryRATDataUsageReportAPERValue struct {
	context s00.BridgeCodecContext
	Value   SecondaryRATDataUsageReport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportAPERValue) WithoutReplay() SecondaryRATDataUsageReportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCompleteAPERValue is the concrete APERValue[UEContextReleaseComplete].
type UEContextReleaseCompleteAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextReleaseComplete

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCompleteAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCompleteAPERValue) WithoutReplay() UEContextReleaseCompleteAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendRequestAPERValue is the concrete APERValue[UEContextSuspendRequest].
type UEContextSuspendRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextSuspendRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendRequestAPERValue) WithoutReplay() UEContextSuspendRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeUserLocationInformationExtIEsValueValidateS1APIEContainer(fields s25.UserLocationInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s25.BridgeUserLocationInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s25.BridgeUserLocationInformationExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s25.BridgeUserLocationInformationExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeERABModificationIndicationIEValueCaptureS1APERABIEContainerList(v *s56.ERABModificationIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModificationIndicationIEValueCompareS1APERABIEContainerList(v *s56.ERABModificationIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyResponseIEValueCaptureS1APERABIEContainerList(v *s56.ERABModifyResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyResponseIEValueCompareS1APERABIEContainerList(v *s56.ERABModifyResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseIndicationIEValueCaptureS1APERABIEContainerList(v *s56.ERABReleaseIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseIndicationIEValueCompareS1APERABIEContainerList(v *s56.ERABReleaseIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseResponseIEValueCaptureS1APERABIEContainerList(v *s56.ERABReleaseResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseResponseIEValueCompareS1APERABIEContainerList(v *s56.ERABReleaseResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupResponseIEValueCaptureS1APERABIEContainerList(v *s56.ERABSetupResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupResponseIEValueCompareS1APERABIEContainerList(v *s56.ERABSetupResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APERABIEContainerList(v *s56.SecondaryRATDataUsageReportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APERABIEContainerList(v *s56.SecondaryRATDataUsageReportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextReleaseCompleteIEValueCaptureS1APERABIEContainerList(v *s56.UEContextReleaseCompleteIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APERABIEContainerList(v *s56.UEContextReleaseCompleteIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendRequestIEValueCaptureS1APERABIEContainerList(v *s56.UEContextSuspendRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendRequestIEValueCompareS1APERABIEContainerList(v *s56.UEContextSuspendRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModificationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s56.ERABModificationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModificationIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s56.ERABModificationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s56.ERABModifyResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s56.ERABModifyResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s56.ERABReleaseIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s56.ERABReleaseResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s56.ERABReleaseResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s56.ERABSetupResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s56.ERABSetupResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolErrorIEContainerList(v *s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolErrorIEContainerList(v *s56.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolErrorIEContainerList(v *s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolErrorIEContainerList(v *s56.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s56.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModificationIndicationIEValueCaptureS1APProtocolIEContainerList(v *s56.ERABModificationIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModificationIndicationIEValueCompareS1APProtocolIEContainerList(v *s56.ERABModificationIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModificationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyResponseIEValueCaptureS1APProtocolIEContainerList(v *s56.ERABModifyResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyResponseIEValueCompareS1APProtocolIEContainerList(v *s56.ERABModifyResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABModifyResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIEContainerList(v *s56.ERABReleaseIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseIndicationIEValueCompareS1APProtocolIEContainerList(v *s56.ERABReleaseIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEContainerList(v *s56.ERABReleaseResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseResponseIEValueCompareS1APProtocolIEContainerList(v *s56.ERABReleaseResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABReleaseResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupResponseIEValueCaptureS1APProtocolIEContainerList(v *s56.ERABSetupResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupResponseIEValueCompareS1APProtocolIEContainerList(v *s56.ERABSetupResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABSetupResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEContainerList(v *s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEContainerList(v *s56.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEContainerList(v *s56.UEContextReleaseCompleteIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEContainerList(v *s56.UEContextReleaseCompleteIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEContainerList(v *s56.UEContextSuspendRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEContainerList(v *s56.UEContextSuspendRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModificationIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s56.ERABModificationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModificationIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABModificationIndicationIEValueCompareS1APProtocolIESingleContainer(v *s56.ERABModificationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModificationIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyResponseIEValueCaptureS1APProtocolIESingleContainer(v *s56.ERABModifyResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABModifyResponseIEValueCompareS1APProtocolIESingleContainer(v *s56.ERABModifyResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s56.ERABReleaseIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABReleaseIndicationIEValueCompareS1APProtocolIESingleContainer(v *s56.ERABReleaseIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseResponseIEValueCaptureS1APProtocolIESingleContainer(v *s56.ERABReleaseResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABReleaseResponseIEValueCompareS1APProtocolIESingleContainer(v *s56.ERABReleaseResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupResponseIEValueCaptureS1APProtocolIESingleContainer(v *s56.ERABSetupResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABSetupResponseIEValueCompareS1APProtocolIESingleContainer(v *s56.ERABSetupResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIESingleContainer(v *s56.SecondaryRATDataUsageReportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIESingleContainer(v *s56.SecondaryRATDataUsageReportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIESingleContainer(v *s56.UEContextReleaseCompleteIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIESingleContainer(v *s56.UEContextReleaseCompleteIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIESingleContainer(v *s56.UEContextSuspendRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIESingleContainer(v *s56.UEContextSuspendRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABModificationIndication(v *ERABModificationIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModificationIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABModificationIndication(v *ERABModificationIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModificationIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABModifyResponse(v *ERABModifyResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABModifyResponse(v *ERABModifyResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABModifyResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABReleaseIndication(v *ERABReleaseIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABReleaseIndication(v *ERABReleaseIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABReleaseResponse(v *ERABReleaseResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABReleaseResponse(v *ERABReleaseResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABReleaseResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABSetupResponse(v *ERABSetupResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABSetupResponse(v *ERABSetupResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSecondaryRATDataUsageReport(v *SecondaryRATDataUsageReport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSecondaryRATDataUsageReport(v *SecondaryRATDataUsageReport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextReleaseComplete(v *UEContextReleaseComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextReleaseComplete(v *UEContextReleaseComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextSuspendRequest(v *UEContextSuspendRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextSuspendRequest(v *UEContextSuspendRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APV2XServicesAuthorized(v *V2XServicesAuthorized, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.VehicleUE == nil)
		if v.VehicleUE != nil {
			s00.BridgeCaptureS1APVehicleUE(v.VehicleUE, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.PedestrianUE == nil)
		if v.PedestrianUE != nil {
			s00.BridgeCaptureS1APPedestrianUE(v.PedestrianUE, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APV2XServicesAuthorized(v *V2XServicesAuthorized, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.VehicleUE == nil)
		if v.VehicleUE != nil {
			s08.BridgeCompareS1APVehicleUE(v.VehicleUE, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.PedestrianUE == nil)
		if v.PedestrianUE != nil {
			s02.BridgeCompareS1APPedestrianUE(v.PedestrianUE, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// V2XServicesAuthorized represents the ASN.1 type V2XServicesAuthorized (SEQUENCE).
type V2XServicesAuthorized struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	VehicleUE         *s00.VehicleUE                              `asn1:"tag:0,context,implicit,optional" json:"VehicleUE,omitempty"`
	PedestrianUE      *s00.PedestrianUE                           `asn1:"tag:1,context,implicit,optional" json:"PedestrianUE,omitempty"`
	IEExtensions      s14.V2XServicesAuthorizedExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                        `asn1:"-" json:"-"`
	extCount          int64                                       `asn1:"-" json:"-"`
	extPresent        []bool                                      `asn1:"-" json:"-"`
	extData           [][]byte                                    `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes V2XServicesAuthorized to APER format.
func (v *V2XServicesAuthorized) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *V2XServicesAuthorized) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.VehicleUE != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.PedestrianUE != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.VehicleUE != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.VehicleUE), 2, true); err != nil {
			return fmt.Errorf("encoding vehicleUE: %w", err)
		}
	}
	if v.PedestrianUE != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.PedestrianUE), 2, true); err != nil {
			return fmt.Errorf("encoding pedestrianUE: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s14.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes V2XServicesAuthorized from APER format.
func (v *V2XServicesAuthorized) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *V2XServicesAuthorized) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "V2XServicesAuthorized")
	}
	bb.EnterComponent("V2XServicesAuthorized")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "V2XServicesAuthorized")
	}
	padding, err := aper.CaptureFinalBits(bb, "V2XServicesAuthorized")
	if err != nil {
		return runtime.WrapDecodePath(err, "V2XServicesAuthorized")
	}
	v.perPadding = padding
	return nil
}
func (v *V2XServicesAuthorized) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = V2XServicesAuthorized{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_vehicleue, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_pedestrianue, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_vehicleue {
		val_vehicleue, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "VehicleUE"})
		if err != nil {
			return runtime.WrapDecodePath(err, "VehicleUE")
		}
		tmp_vehicleue := s00.VehicleUE(val_vehicleue)
		if err := aper.ChargeValue(bb, tmp_vehicleue); err != nil {
			return err
		}
		v.VehicleUE = (*s00.VehicleUE)(bb.OwnInt64(int64(tmp_vehicleue)))

	}
	if opt_pedestrianue {
		val_pedestrianue, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PedestrianUE"})
		if err != nil {
			return runtime.WrapDecodePath(err, "PedestrianUE")
		}
		tmp_pedestrianue := s00.PedestrianUE(val_pedestrianue)
		if err := aper.ChargeValue(bb, tmp_pedestrianue); err != nil {
			return err
		}
		v.PedestrianUE = (*s00.PedestrianUE)(bb.OwnInt64(int64(tmp_pedestrianue)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s14.V2XServicesAuthorizedExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s14.V2XServicesAuthorizedExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s14.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *V2XServicesAuthorized) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "V2XServicesAuthorized", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "V2XServicesAuthorized", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v V2XServicesAuthorized) WithoutReplay() V2XServicesAuthorized {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero V2XServicesAuthorized
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *V2XServicesAuthorized) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *V2XServicesAuthorized) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("V2XServicesAuthorized.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("V2XServicesAuthorized.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *V2XServicesAuthorized) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("V2XServicesAuthorized.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("V2XServicesAuthorized.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *V2XServicesAuthorized) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "V2XServicesAuthorized")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *V2XServicesAuthorized) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "V2XServicesAuthorized")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APV2XServicesAuthorized(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "V2XServicesAuthorized")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "V2XServicesAuthorized")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *V2XServicesAuthorized) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "V2XServicesAuthorized")
}
func (v *V2XServicesAuthorized) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "V2XServicesAuthorized")
}
func (v *V2XServicesAuthorized) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APV2XServicesAuthorized(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *V2XServicesAuthorized) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *V2XServicesAuthorized) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *V2XServicesAuthorized) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "V2XServicesAuthorized")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded V2XServicesAuthorized
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APV2XServicesAuthorized(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = V2XServicesAuthorized{}
		return report, aper.OperationError(err, "V2XServicesAuthorized")
	}
	*v = decoded
	return report, aper.OperationError(nil, "V2XServicesAuthorized")
}

// ERABSetupResponse represents the ASN.1 type E-RABSetupResponse (SEQUENCE).
type ERABSetupResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s56.ERABSetupResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                             `asn1:"-" json:"-"`
	extCount         int64                            `asn1:"-" json:"-"`
	extPresent       []bool                           `asn1:"-" json:"-"`
	extData          [][]byte                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ERABModifyResponse represents the ASN.1 type E-RABModifyResponse (SEQUENCE).
type ERABModifyResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s56.ERABModifyResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                              `asn1:"-" json:"-"`
	extCount         int64                             `asn1:"-" json:"-"`
	extPresent       []bool                            `asn1:"-" json:"-"`
	extData          [][]byte                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ERABReleaseResponse represents the ASN.1 type E-RABReleaseResponse (SEQUENCE).
type ERABReleaseResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s56.ERABReleaseResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                               `asn1:"-" json:"-"`
	extCount         int64                              `asn1:"-" json:"-"`
	extPresent       []bool                             `asn1:"-" json:"-"`
	extData          [][]byte                           `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ERABReleaseIndication represents the ASN.1 type E-RABReleaseIndication (SEQUENCE).
type ERABReleaseIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s56.ERABReleaseIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                 `asn1:"-" json:"-"`
	extCount         int64                                `asn1:"-" json:"-"`
	extPresent       []bool                               `asn1:"-" json:"-"`
	extData          [][]byte                             `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextReleaseComplete represents the ASN.1 type UEContextReleaseComplete (SEQUENCE).
type UEContextReleaseComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s56.UEContextReleaseCompleteIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ERABModificationIndication represents the ASN.1 type E-RABModificationIndication (SEQUENCE).
type ERABModificationIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s56.ERABModificationIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                      `asn1:"-" json:"-"`
	extCount         int64                                     `asn1:"-" json:"-"`
	extPresent       []bool                                    `asn1:"-" json:"-"`
	extData          [][]byte                                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextSuspendRequest represents the ASN.1 type UEContextSuspendRequest (SEQUENCE).
type UEContextSuspendRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s56.UEContextSuspendRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                   `asn1:"-" json:"-"`
	extCount         int64                                  `asn1:"-" json:"-"`
	extPresent       []bool                                 `asn1:"-" json:"-"`
	extData          [][]byte                               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SecondaryRATDataUsageReport represents the ASN.1 type SecondaryRATDataUsageReport (SEQUENCE).
type SecondaryRATDataUsageReport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s56.SecondaryRATDataUsageReportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                       `asn1:"-" json:"-"`
	extCount         int64                                      `asn1:"-" json:"-"`
	extPresent       []bool                                     `asn1:"-" json:"-"`
	extData          [][]byte                                   `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ERABSetupResponse to APER format.
func (v *ERABSetupResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABSetupResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s56.BridgeERABSetupResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ERABSetupResponse from APER format.
func (v *ERABSetupResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ERABSetupResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupResponse")
	}
	bb.EnterComponent("ERABSetupResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABSetupResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupResponse")
	}
	v.perPadding = padding
	return nil
}
func (v *ERABSetupResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupResponse{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s56.ERABSetupResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s56.ERABSetupResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s56.BridgeERABSetupResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes ERABModifyResponse to APER format.
func (v *ERABModifyResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABModifyResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s56.BridgeERABModifyResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ERABModifyResponse from APER format.
func (v *ERABModifyResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ERABModifyResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyResponse")
	}
	bb.EnterComponent("ERABModifyResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABModifyResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyResponse")
	}
	v.perPadding = padding
	return nil
}
func (v *ERABModifyResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyResponse{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s56.ERABModifyResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s56.ERABModifyResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s56.BridgeERABModifyResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes ERABReleaseResponse to APER format.
func (v *ERABReleaseResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABReleaseResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s56.BridgeERABReleaseResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ERABReleaseResponse from APER format.
func (v *ERABReleaseResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ERABReleaseResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseResponse")
	}
	bb.EnterComponent("ERABReleaseResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABReleaseResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseResponse")
	}
	v.perPadding = padding
	return nil
}
func (v *ERABReleaseResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABReleaseResponse{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s56.ERABReleaseResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s56.ERABReleaseResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s56.BridgeERABReleaseResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes ERABReleaseIndication to APER format.
func (v *ERABReleaseIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABReleaseIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s56.BridgeERABReleaseIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ERABReleaseIndication from APER format.
func (v *ERABReleaseIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ERABReleaseIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseIndication")
	}
	bb.EnterComponent("ERABReleaseIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABReleaseIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseIndication")
	}
	v.perPadding = padding
	return nil
}
func (v *ERABReleaseIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABReleaseIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s56.ERABReleaseIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s56.ERABReleaseIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s56.BridgeERABReleaseIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes UEContextReleaseComplete to APER format.
func (v *UEContextReleaseComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextReleaseComplete) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s56.BridgeUEContextReleaseCompleteIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes UEContextReleaseComplete from APER format.
func (v *UEContextReleaseComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UEContextReleaseComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseComplete")
	}
	bb.EnterComponent("UEContextReleaseComplete")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseComplete")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextReleaseComplete")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseComplete")
	}
	v.perPadding = padding
	return nil
}
func (v *UEContextReleaseComplete) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextReleaseComplete{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s56.UEContextReleaseCompleteIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s56.UEContextReleaseCompleteIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s56.BridgeUEContextReleaseCompleteIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes ERABModificationIndication to APER format.
func (v *ERABModificationIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABModificationIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s56.BridgeERABModificationIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ERABModificationIndication from APER format.
func (v *ERABModificationIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ERABModificationIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABModificationIndication")
	}
	bb.EnterComponent("ERABModificationIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModificationIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABModificationIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABModificationIndication")
	}
	v.perPadding = padding
	return nil
}
func (v *ERABModificationIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModificationIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s56.ERABModificationIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s56.ERABModificationIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s56.BridgeERABModificationIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes UEContextSuspendRequest to APER format.
func (v *UEContextSuspendRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextSuspendRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s56.BridgeUEContextSuspendRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes UEContextSuspendRequest from APER format.
func (v *UEContextSuspendRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UEContextSuspendRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendRequest")
	}
	bb.EnterComponent("UEContextSuspendRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextSuspendRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendRequest")
	}
	v.perPadding = padding
	return nil
}
func (v *UEContextSuspendRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextSuspendRequest{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s56.UEContextSuspendRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s56.UEContextSuspendRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s56.BridgeUEContextSuspendRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes SecondaryRATDataUsageReport to APER format.
func (v *SecondaryRATDataUsageReport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SecondaryRATDataUsageReport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s56.BridgeSecondaryRATDataUsageReportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes SecondaryRATDataUsageReport from APER format.
func (v *SecondaryRATDataUsageReport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *SecondaryRATDataUsageReport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReport")
	}
	bb.EnterComponent("SecondaryRATDataUsageReport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReport")
	}
	padding, err := aper.CaptureFinalBits(bb, "SecondaryRATDataUsageReport")
	if err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReport")
	}
	v.perPadding = padding
	return nil
}
func (v *SecondaryRATDataUsageReport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecondaryRATDataUsageReport{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s56.SecondaryRATDataUsageReportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s56.SecondaryRATDataUsageReportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s56.BridgeSecondaryRATDataUsageReportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABModificationIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABModificationIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABModificationIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABModificationIndication) WithoutReplay() ERABModificationIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABModificationIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABModifyResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABModifyResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABModifyResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABModifyResponse) WithoutReplay() ERABModifyResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABModifyResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABReleaseIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABReleaseIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABReleaseIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABReleaseIndication) WithoutReplay() ERABReleaseIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABReleaseIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABReleaseResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABReleaseResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABReleaseResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABReleaseResponse) WithoutReplay() ERABReleaseResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABReleaseResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABSetupResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABSetupResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABSetupResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABSetupResponse) WithoutReplay() ERABSetupResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABSetupResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SecondaryRATDataUsageReport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SecondaryRATDataUsageReport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SecondaryRATDataUsageReport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SecondaryRATDataUsageReport) WithoutReplay() SecondaryRATDataUsageReport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SecondaryRATDataUsageReport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextReleaseComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextReleaseComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextReleaseComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextReleaseComplete) WithoutReplay() UEContextReleaseComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextReleaseComplete
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextSuspendRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextSuspendRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextSuspendRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextSuspendRequest) WithoutReplay() UEContextSuspendRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextSuspendRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ERABModificationIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABModificationIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModificationIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModificationIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABModificationIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModificationIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModificationIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABModifyResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABModifyResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModifyResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModifyResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABModifyResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModifyResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModifyResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABReleaseIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABReleaseIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABReleaseIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABReleaseIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABReleaseIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABReleaseIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABReleaseIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABReleaseResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABReleaseResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABReleaseResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABReleaseResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABReleaseResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABReleaseResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABReleaseResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABSetupResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABSetupResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSetupResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSetupResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABSetupResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSetupResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSetupResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SecondaryRATDataUsageReport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SecondaryRATDataUsageReport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecondaryRATDataUsageReport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecondaryRATDataUsageReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SecondaryRATDataUsageReport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecondaryRATDataUsageReport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecondaryRATDataUsageReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextReleaseComplete) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextReleaseComplete) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseComplete.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseComplete.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextReleaseComplete) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseComplete.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseComplete.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextSuspendRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextSuspendRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextSuspendRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextSuspendRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextSuspendRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextSuspendRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextSuspendRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABModificationIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABModificationIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABModificationIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABModificationIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABModificationIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABModificationIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABModificationIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABModificationIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABModificationIndication")
}
func (v *ERABModificationIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABModificationIndication")
}
func (v *ERABModificationIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABModificationIndication(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *ERABModificationIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABModificationIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABModifyResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABModifyResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABModifyResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABModifyResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABModifyResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABModifyResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABModifyResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABModifyResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABModifyResponse")
}
func (v *ERABModifyResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABModifyResponse")
}
func (v *ERABModifyResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABModifyResponse(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *ERABModifyResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABModifyResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABReleaseIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABReleaseIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABReleaseIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABReleaseIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABReleaseIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABReleaseIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABReleaseIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABReleaseIndication")
}
func (v *ERABReleaseIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABReleaseIndication")
}
func (v *ERABReleaseIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABReleaseIndication(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *ERABReleaseIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABReleaseIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABReleaseResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABReleaseResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABReleaseResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABReleaseResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABReleaseResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABReleaseResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABReleaseResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABReleaseResponse")
}
func (v *ERABReleaseResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABReleaseResponse")
}
func (v *ERABReleaseResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABReleaseResponse(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *ERABReleaseResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABReleaseResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABSetupResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABSetupResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABSetupResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABSetupResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABSetupResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABSetupResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABSetupResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABSetupResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABSetupResponse")
}
func (v *ERABSetupResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABSetupResponse")
}
func (v *ERABSetupResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABSetupResponse(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *ERABSetupResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABSetupResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SecondaryRATDataUsageReport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SecondaryRATDataUsageReport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SecondaryRATDataUsageReport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSecondaryRATDataUsageReport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SecondaryRATDataUsageReport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SecondaryRATDataUsageReport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SecondaryRATDataUsageReport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SecondaryRATDataUsageReport")
}
func (v *SecondaryRATDataUsageReport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SecondaryRATDataUsageReport")
}
func (v *SecondaryRATDataUsageReport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSecondaryRATDataUsageReport(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *SecondaryRATDataUsageReport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SecondaryRATDataUsageReport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UEContextReleaseComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextReleaseComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextReleaseComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextReleaseComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextReleaseComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextReleaseComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextReleaseComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextReleaseComplete")
}
func (v *UEContextReleaseComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextReleaseComplete")
}
func (v *UEContextReleaseComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextReleaseComplete(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *UEContextReleaseComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextReleaseComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UEContextSuspendRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextSuspendRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextSuspendRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextSuspendRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextSuspendRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextSuspendRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextSuspendRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextSuspendRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextSuspendRequest")
}
func (v *UEContextSuspendRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextSuspendRequest")
}
func (v *UEContextSuspendRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextSuspendRequest(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *UEContextSuspendRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextSuspendRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABModificationIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABModificationIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABModificationIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABModificationIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABModificationIndication{}
		return report, aper.OperationError(err, "ERABModificationIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABModificationIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABModifyResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABModifyResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABModifyResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABModifyResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABModifyResponse{}
		return report, aper.OperationError(err, "ERABModifyResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABModifyResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABReleaseIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABReleaseIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABReleaseIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABReleaseIndication{}
		return report, aper.OperationError(err, "ERABReleaseIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABReleaseIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABReleaseResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABReleaseResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABReleaseResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABReleaseResponse{}
		return report, aper.OperationError(err, "ERABReleaseResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABReleaseResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABSetupResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABSetupResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABSetupResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABSetupResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABSetupResponse{}
		return report, aper.OperationError(err, "ERABSetupResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABSetupResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SecondaryRATDataUsageReport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SecondaryRATDataUsageReport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SecondaryRATDataUsageReport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSecondaryRATDataUsageReport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SecondaryRATDataUsageReport{}
		return report, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SecondaryRATDataUsageReport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextReleaseComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextReleaseComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextReleaseComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextReleaseComplete{}
		return report, aper.OperationError(err, "UEContextReleaseComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextReleaseComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextSuspendRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextSuspendRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextSuspendRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextSuspendRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextSuspendRequest{}
		return report, aper.OperationError(err, "UEContextSuspendRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextSuspendRequest")
}

type ERABModificationIndicationIETable struct{}

func ERABModificationIndicationIEs() ERABModificationIndicationIETable {
	return ERABModificationIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of ERABModificationIndicationIETable.
func (ERABModificationIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABModificationIndicationIETable.
func (ERABModificationIndicationIETable) Table() s00.ERABModificationIndicationIEValueIETable {
	return func() s00.ERABModificationIndicationIEValueIETable {
		sealed := s00.ERABModificationIndicationIEValueIETable{}
		*s00.BridgeERABModificationIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) MMEUES1APID() s56.ERABModificationIndicationMMEUES1APIDIEBinding {
	return func() s56.ERABModificationIndicationMMEUES1APIDIEBinding {
		sealed := s56.ERABModificationIndicationMMEUES1APIDIEBinding{}
		*s56.BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s56.BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s56.ERABModificationIndicationIEValue
				decoded, err := s56.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s56.ERABModificationIndicationIEValue {
					sealed := s56.ERABModificationIndicationIEValue{}
					*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s56.BridgeERABModificationIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APMMEUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s56.ERABModificationIndicationIEValue {
			return func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeERABModificationIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.ERABModificationIndicationIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) ENBUES1APID() s56.ERABModificationIndicationENBUES1APIDIEBinding {
	return func() s56.ERABModificationIndicationENBUES1APIDIEBinding {
		sealed := s56.ERABModificationIndicationENBUES1APIDIEBinding{}
		*s56.BridgeERABModificationIndicationENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s56.BridgeERABModificationIndicationENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s56.ERABModificationIndicationIEValue
				decoded, err := s56.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s56.ERABModificationIndicationIEValue {
					sealed := s56.ERABModificationIndicationIEValue{}
					*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s56.BridgeERABModificationIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.ENBUES1APID, options aper.DecodeState) (s00.ENBUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APENBUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.ENBUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APENBUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s00.BridgeENBUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModificationIndicationENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s56.ERABModificationIndicationIEValue {
			return func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeERABModificationIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModificationIndicationENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.ERABModificationIndicationIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoERABToBeModifiedListBearerModInd() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(199), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedListBearerModInd"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-E-RABToBeModifiedListBearerModInd"}}}
}

// ERABToBeModifiedListBearerModInd returns the typed binding for the ERABToBeModifiedListBearerModInd row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) ERABToBeModifiedListBearerModInd() s56.ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding {
	return func() s56.ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding {
		sealed := s56.ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding{}
		*s56.BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldInfo(&sealed) = t.infoERABToBeModifiedListBearerModInd()
		*s56.BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldCodec(&sealed) = func() s20.ERABToBeModifiedListBearerModIndValueCodec {
			sealed := s20.ERABToBeModifiedListBearerModIndValueCodec{}
			*s20.BridgeERABToBeModifiedListBearerModIndValueCodecFieldPath(&sealed) = "ERABToBeModifiedListBearerModInd"
			*s20.BridgeERABToBeModifiedListBearerModIndValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeModifiedListBearerModInd, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s20.ERABToBeModifiedListBearerModInd
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABToBeModifiedListBearerModInd")
				var zero s56.ERABModificationIndicationIEValue
				decoded, err := s56.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(199), raw)
				if err != nil {
					var empty s20.ERABToBeModifiedListBearerModInd
					return empty, runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModInd")
				}
				value, ok := decoded.AsERABToBeModifiedListBearerModInd()
				if !ok {
					var empty s20.ERABToBeModifiedListBearerModInd
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-E-RABToBeModifiedListBearerModInd: no selected value")
				}
				return *value, nil
			}
			*s20.BridgeERABToBeModifiedListBearerModIndValueCodecFieldEncode(&sealed) = func(value s20.ERABToBeModifiedListBearerModInd, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s56.ERABModificationIndicationIEValue {
					sealed := s56.ERABModificationIndicationIEValue{}
					*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(199)
					*s56.BridgeERABModificationIndicationIEValueFieldRowERABToBeModifiedListBearerModInd(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s20.BridgeERABToBeModifiedListBearerModIndValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeModifiedListBearerModInd, options aper.DecodeState) (s20.ERABToBeModifiedListBearerModInd, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s29.BridgeCaptureS1APERABToBeModifiedListBearerModInd(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s20.BridgeERABToBeModifiedListBearerModIndValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeModifiedListBearerModInd, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s29.BridgeCompareS1APERABToBeModifiedListBearerModInd(&v,
					&s,
				)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s20.BridgeERABToBeModifiedListBearerModIndValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeModifiedListBearerModInd"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldInject(&sealed) = func(value s20.ERABToBeModifiedListBearerModInd) s56.ERABModificationIndicationIEValue {
			return func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(199)
				*s56.BridgeERABModificationIndicationIEValueFieldRowERABToBeModifiedListBearerModInd(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldGet(&sealed) = func(value *s56.ERABModificationIndicationIEValue) (*s20.ERABToBeModifiedListBearerModInd, bool) {
			return value.AsERABToBeModifiedListBearerModInd()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoERABNotToBeModifiedListBearerModInd() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(201), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABNotToBeModifiedListBearerModInd"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-E-RABNotToBeModifiedListBearerModInd"}}}
}

// ERABNotToBeModifiedListBearerModInd returns the typed binding for the ERABNotToBeModifiedListBearerModInd row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) ERABNotToBeModifiedListBearerModInd() s56.ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding {
	return func() s56.ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding {
		sealed := s56.ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding{}
		*s56.BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldInfo(&sealed) = t.infoERABNotToBeModifiedListBearerModInd()
		*s56.BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldCodec(&sealed) = func() s19.ERABNotToBeModifiedListBearerModIndValueCodec {
			sealed := s19.ERABNotToBeModifiedListBearerModIndValueCodec{}
			*s19.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldPath(&sealed) = "ERABNotToBeModifiedListBearerModInd"
			*s19.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABNotToBeModifiedListBearerModInd, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.ERABNotToBeModifiedListBearerModInd
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABNotToBeModifiedListBearerModInd")
				var zero s56.ERABModificationIndicationIEValue
				decoded, err := s56.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(201), raw)
				if err != nil {
					var empty s19.ERABNotToBeModifiedListBearerModInd
					return empty, runtime.WrapDecodePath(err, "ERABNotToBeModifiedListBearerModInd")
				}
				value, ok := decoded.AsERABNotToBeModifiedListBearerModInd()
				if !ok {
					var empty s19.ERABNotToBeModifiedListBearerModInd
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-E-RABNotToBeModifiedListBearerModInd: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldEncode(&sealed) = func(value s19.ERABNotToBeModifiedListBearerModInd, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s56.ERABModificationIndicationIEValue {
					sealed := s56.ERABModificationIndicationIEValue{}
					*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(201)
					*s56.BridgeERABModificationIndicationIEValueFieldRowERABNotToBeModifiedListBearerModInd(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldCapture(&sealed) = func(v s19.ERABNotToBeModifiedListBearerModInd, options aper.DecodeState) (s19.ERABNotToBeModifiedListBearerModInd, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s29.BridgeCaptureS1APERABNotToBeModifiedListBearerModInd(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root

			}
			*s19.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldCompare(&sealed) = func(v s19.ERABNotToBeModifiedListBearerModInd, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s29.BridgeCompareS1APERABNotToBeModifiedListBearerModInd(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABNotToBeModifiedListBearerModInd"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldInject(&sealed) = func(value s19.ERABNotToBeModifiedListBearerModInd) s56.ERABModificationIndicationIEValue {
			return func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(201)
				*s56.BridgeERABModificationIndicationIEValueFieldRowERABNotToBeModifiedListBearerModInd(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldGet(&sealed) = func(value *s56.ERABModificationIndicationIEValue) (*s19.ERABNotToBeModifiedListBearerModInd, bool) {
			return value.AsERABNotToBeModifiedListBearerModInd()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoCSGMembershipInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(226), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "CSGMembershipInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-CSGMembershipInfo"}}}
}

// CSGMembershipInfo returns the typed binding for the CSGMembershipInfo row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) CSGMembershipInfo() s56.ERABModificationIndicationCSGMembershipInfoIEBinding {
	return func() s56.ERABModificationIndicationCSGMembershipInfoIEBinding {
		sealed := s56.ERABModificationIndicationCSGMembershipInfoIEBinding{}
		*s56.BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldInfo(&sealed) = t.infoCSGMembershipInfo()
		*s56.BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldCodec(&sealed) = func() s17.CSGMembershipInfoValueCodec {
			sealed := s17.CSGMembershipInfoValueCodec{}
			*s17.BridgeCSGMembershipInfoValueCodecFieldPath(&sealed) = "CSGMembershipInfo"
			*s17.BridgeCSGMembershipInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CSGMembershipInfo, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s17.CSGMembershipInfo
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CSGMembershipInfo")
				var zero s56.ERABModificationIndicationIEValue
				decoded, err := s56.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(226), raw)
				if err != nil {
					var empty s17.CSGMembershipInfo
					return empty, runtime.WrapDecodePath(err, "CSGMembershipInfo")
				}
				value, ok := decoded.AsCSGMembershipInfo()
				if !ok {
					var empty s17.CSGMembershipInfo
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-CSGMembershipInfo: no selected value")
				}
				return *value, nil
			}
			*s17.BridgeCSGMembershipInfoValueCodecFieldEncode(&sealed) = func(value s17.CSGMembershipInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s56.ERABModificationIndicationIEValue {
					sealed := s56.ERABModificationIndicationIEValue{}
					*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(226)
					*s56.BridgeERABModificationIndicationIEValueFieldRowCSGMembershipInfo(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s17.BridgeCSGMembershipInfoValueCodecFieldCapture(&sealed) = func(v s17.CSGMembershipInfo, options aper.DecodeState) (s17.CSGMembershipInfo, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s17.BridgeCaptureS1APCSGMembershipInfo(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v,
					root

			}
			*s17.BridgeCSGMembershipInfoValueCodecFieldCompare(&sealed) = func(v s17.CSGMembershipInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s17.BridgeCompareS1APCSGMembershipInfo(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s17.BridgeCSGMembershipInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGMembershipInfo"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldInject(&sealed) = func(value s17.CSGMembershipInfo) s56.ERABModificationIndicationIEValue {
			return func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(226)
				*s56.BridgeERABModificationIndicationIEValueFieldRowCSGMembershipInfo(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldGet(&sealed) = func(value *s56.ERABModificationIndicationIEValue) (*s17.CSGMembershipInfo, bool) {
			return value.AsCSGMembershipInfo()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoTunnelInformationForBBF() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(176), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TunnelInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-Tunnel-Information-for-BBF"}}}
}

// TunnelInformationForBBF returns the typed binding for the TunnelInformationForBBF row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) TunnelInformationForBBF() s56.ERABModificationIndicationTunnelInformationIEBinding {
	return func() s56.ERABModificationIndicationTunnelInformationIEBinding {
		sealed := s56.ERABModificationIndicationTunnelInformationIEBinding{}
		*s56.BridgeERABModificationIndicationTunnelInformationIEBindingFieldInfo(&sealed) = t.infoTunnelInformationForBBF()
		*s56.BridgeERABModificationIndicationTunnelInformationIEBindingFieldCodec(&sealed) = func() s44.TunnelInformationValueCodec {
			sealed := s44.TunnelInformationValueCodec{}
			*s44.BridgeTunnelInformationValueCodecFieldPath(&sealed) = "TunnelInformation"
			*s44.BridgeTunnelInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s44.TunnelInformation, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s44.TunnelInformation
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TunnelInformation")
				var zero s56.ERABModificationIndicationIEValue
				decoded, err := s56.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(176), raw)
				if err != nil {
					var empty s44.TunnelInformation
					return empty, runtime.WrapDecodePath(err, "TunnelInformation")
				}
				value, ok := decoded.AsTunnelInformationForBBF()
				if !ok {
					var empty s44.TunnelInformation
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-Tunnel-Information-for-BBF: no selected value")
				}
				return *value, nil
			}
			*s44.BridgeTunnelInformationValueCodecFieldEncode(&sealed) = func(value s44.TunnelInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s56.ERABModificationIndicationIEValue {
					sealed := s56.ERABModificationIndicationIEValue{}
					*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
					*s56.BridgeERABModificationIndicationIEValueFieldRowTunnelInformationForBBF(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s44.BridgeTunnelInformationValueCodecFieldCapture(&sealed) = func(v s44.TunnelInformation, options aper.DecodeState) (s44.TunnelInformation, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s44.BridgeCaptureS1APTunnelInformation(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v,
					root

			}
			*s44.BridgeTunnelInformationValueCodecFieldCompare(&sealed) = func(v s44.TunnelInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s44.BridgeCompareS1APTunnelInformation(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s44.BridgeTunnelInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TunnelInformation"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModificationIndicationTunnelInformationIEBindingFieldInject(&sealed) = func(value s44.TunnelInformation) s56.ERABModificationIndicationIEValue {
			return func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
				*s56.BridgeERABModificationIndicationIEValueFieldRowTunnelInformationForBBF(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModificationIndicationTunnelInformationIEBindingFieldGet(&sealed) = func(value *s56.ERABModificationIndicationIEValue) (*s44.TunnelInformation, bool) {
			return value.AsTunnelInformationForBBF()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) SecondaryRATDataUsageReportList() s56.ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding {
	return func() s56.ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding {
		sealed := s56.ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding{}
		*s56.BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldInfo(&sealed) = t.infoSecondaryRATDataUsageReportList()
		*s56.BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldCodec(&sealed) = func() s36.SecondaryRATDataUsageReportListValueCodec {
			sealed := s36.SecondaryRATDataUsageReportListValueCodec{}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
				var zero s56.ERABModificationIndicationIEValue
				decoded, err := s56.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(264), raw)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
				}
				value, ok := decoded.AsSecondaryRATDataUsageReportList()
				if !ok {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-SecondaryRATDataUsageReportList: no selected value")
				}
				return *value, nil
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s36.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s56.ERABModificationIndicationIEValue {
					sealed := s56.ERABModificationIndicationIEValue{}
					*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
					*s56.BridgeERABModificationIndicationIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s36.SecondaryRATDataUsageReportList, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s36.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s36.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s36.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldInject(&sealed) = func(value s36.SecondaryRATDataUsageReportList) s56.ERABModificationIndicationIEValue {
			return func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeERABModificationIndicationIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldGet(&sealed) = func(value *s56.ERABModificationIndicationIEValue) (*s36.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}
		return sealed
	}()
}
func (ERABModificationIndicationIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModificationIndicationIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) UserLocationInformation() ERABModificationIndicationUserLocationInformationIEBinding {
	return ERABModificationIndicationUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: func() s56.UserLocationInformationValueCodec {
		sealed := s56.UserLocationInformationValueCodec{}
		*s56.BridgeUserLocationInformationValueCodecFieldPath(&sealed) = "UserLocationInformation"
		*s56.BridgeUserLocationInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s55.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero s56.ERABModificationIndicationIEValue
			decoded, err := s56.BridgeERABModificationIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s55.UserLocationInformation
				return empty, fmt.Errorf("binding E-RABModificationIndicationIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		}
		*s56.BridgeUserLocationInformationValueCodecFieldEncode(&sealed) = func(value s55.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s56.BridgeERABModificationIndicationIEValueMethodEncodeFresh((func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABModificationIndicationIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCapture(&sealed) = func(v s55.UserLocationInformation, options aper.DecodeState) (s55.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s55.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCompare(&sealed) = func(v s55.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s55.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUserLocationInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s55.UserLocationInformation) s56.ERABModificationIndicationIEValue {
			return func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABModificationIndicationIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s56.ERABModificationIndicationIEValue) (*s55.UserLocationInformation, bool) {
			return value.AsUserLocationInformation()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABModificationIndicationIETable.
func (t ERABModificationIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s56.ERABModificationIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(199):
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeModifiedListBearerModInd requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(201):
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABNotToBeModifiedListBearerModInd requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(226):
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(176):
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Tunnel-Information-for-BBF requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return s56.ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s56.ERABModificationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s56.ERABModificationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return s56.ERABModificationIndicationIEField{Id: id, Criticality: criticality, Value: func() s56.ERABModificationIndicationIEValue {
			sealed := s56.ERABModificationIndicationIEValue{}
			*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = id
			*s56.BridgeERABModificationIndicationIEValueFieldOpaque(&sealed) = opaque
			*s56.BridgeERABModificationIndicationIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABModifyResponseIETable struct{}

func ERABModifyResponseIEs() ERABModifyResponseIETable { return ERABModifyResponseIETable{} }

// ID returns the ASN.1 object-set identity of ERABModifyResponseIETable.
func (ERABModifyResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABModifyResponseIETable.
func (ERABModifyResponseIETable) Table() s00.ERABModifyResponseIEValueIETable {
	return func() s00.ERABModifyResponseIEValueIETable {
		sealed := s00.ERABModifyResponseIEValueIETable{}
		*s00.BridgeERABModifyResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABModifyResponseIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) MMEUES1APID() s56.ERABModifyResponseMMEUES1APIDIEBinding {
	return func() s56.ERABModifyResponseMMEUES1APIDIEBinding {
		sealed := s56.ERABModifyResponseMMEUES1APIDIEBinding{}
		*s56.BridgeERABModifyResponseMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s56.BridgeERABModifyResponseMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s56.ERABModifyResponseIEValue
				decoded, err := s56.BridgeERABModifyResponseIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModifyResponseIEValueMethodEncodeFresh((func() s56.ERABModifyResponseIEValue {
					sealed := s56.ERABModifyResponseIEValue{}
					*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s56.BridgeERABModifyResponseIEValueFieldRowMMEUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APMMEUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModifyResponseMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s56.ERABModifyResponseIEValue {
			return func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeERABModifyResponseIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModifyResponseMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.ERABModifyResponseIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }
		return sealed
	}()
}
func (ERABModifyResponseIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) ENBUES1APID() s56.ERABModifyResponseENBUES1APIDIEBinding {
	return func() s56.ERABModifyResponseENBUES1APIDIEBinding {
		sealed := s56.ERABModifyResponseENBUES1APIDIEBinding{}
		*s56.BridgeERABModifyResponseENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s56.BridgeERABModifyResponseENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s56.ERABModifyResponseIEValue
				decoded, err := s56.BridgeERABModifyResponseIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModifyResponseIEValueMethodEncodeFresh((func() s56.ERABModifyResponseIEValue {
					sealed := s56.ERABModifyResponseIEValue{}
					*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s56.BridgeERABModifyResponseIEValueFieldRowENBUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.ENBUES1APID, options aper.DecodeState) (s00.ENBUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APENBUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.ENBUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APENBUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s00.BridgeENBUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModifyResponseENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s56.ERABModifyResponseIEValue {
			return func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeERABModifyResponseIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModifyResponseENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.ERABModifyResponseIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }
		return sealed
	}()
}
func (ERABModifyResponseIETable) infoERABModifyListBearerModRes() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(31), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyListBearerModRes"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-E-RABModifyListBearerModRes"}}}
}

// ERABModifyListBearerModRes returns the typed binding for the ERABModifyListBearerModRes row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) ERABModifyListBearerModRes() s56.ERABModifyResponseERABModifyListBearerModResIEBinding {
	return func() s56.ERABModifyResponseERABModifyListBearerModResIEBinding {
		sealed := s56.ERABModifyResponseERABModifyListBearerModResIEBinding{}
		*s56.BridgeERABModifyResponseERABModifyListBearerModResIEBindingFieldInfo(&sealed) = t.infoERABModifyListBearerModRes()
		*s56.BridgeERABModifyResponseERABModifyListBearerModResIEBindingFieldCodec(&sealed) = func() s19.ERABModifyListBearerModResValueCodec {
			sealed := s19.ERABModifyListBearerModResValueCodec{}
			*s19.BridgeERABModifyListBearerModResValueCodecFieldPath(&sealed) = "ERABModifyListBearerModRes"
			*s19.BridgeERABModifyListBearerModResValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABModifyListBearerModRes, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.ERABModifyListBearerModRes
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABModifyListBearerModRes")
				var zero s56.ERABModifyResponseIEValue
				decoded, err := s56.BridgeERABModifyResponseIEValueMethodDecode(zero, s00.ProtocolIEID(31), raw)
				if err != nil {
					var empty s19.ERABModifyListBearerModRes
					return empty, runtime.WrapDecodePath(err, "ERABModifyListBearerModRes")
				}
				value, ok := decoded.AsERABModifyListBearerModRes()
				if !ok {
					var empty s19.ERABModifyListBearerModRes
					return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-E-RABModifyListBearerModRes: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeERABModifyListBearerModResValueCodecFieldEncode(&sealed) = func(value s19.ERABModifyListBearerModRes, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModifyResponseIEValueMethodEncodeFresh((func() s56.ERABModifyResponseIEValue {
					sealed := s56.ERABModifyResponseIEValue{}
					*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(31)
					*s56.BridgeERABModifyResponseIEValueFieldRowERABModifyListBearerModRes(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeERABModifyListBearerModResValueCodecFieldCapture(&sealed) = func(v s19.ERABModifyListBearerModRes, options aper.DecodeState) (s19.ERABModifyListBearerModRes, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s29.BridgeCaptureS1APERABModifyListBearerModRes(&v, &s)
				var root aper.Snapshot
				s.End(
					f, &root, false)
				return v, root
			}
			*s19.BridgeERABModifyListBearerModResValueCodecFieldCompare(&sealed) = func(v s19.ERABModifyListBearerModRes, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s29.BridgeCompareS1APERABModifyListBearerModRes(&v, &s)
				s.End(f,
					root,

					false)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeERABModifyListBearerModResValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABModifyListBearerModRes"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModifyResponseERABModifyListBearerModResIEBindingFieldInject(&sealed) = func(value s19.ERABModifyListBearerModRes) s56.ERABModifyResponseIEValue {
			return func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(31)
				*s56.BridgeERABModifyResponseIEValueFieldRowERABModifyListBearerModRes(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModifyResponseERABModifyListBearerModResIEBindingFieldGet(&sealed) = func(value *s56.ERABModifyResponseIEValue) (*s19.ERABModifyListBearerModRes, bool) {
			return value.AsERABModifyListBearerModRes()
		}
		return sealed
	}()
}
func (ERABModifyResponseIETable) infoERABFailedToModifyList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(32), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-E-RABFailedToModifyList"}}}
}

// ERABFailedToModifyList returns the typed binding for the ERABFailedToModifyList row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) ERABFailedToModifyList() s56.ERABModifyResponseERABListIEBinding {
	return func() s56.ERABModifyResponseERABListIEBinding {
		sealed := s56.ERABModifyResponseERABListIEBinding{}
		*s56.BridgeERABModifyResponseERABListIEBindingFieldInfo(&sealed) = t.infoERABFailedToModifyList()
		*s56.BridgeERABModifyResponseERABListIEBindingFieldCodec(&sealed) = func() s19.ERABListValueCodec {
			sealed := s19.ERABListValueCodec{}
			*s19.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
			*s19.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.ERABList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABList")
				var zero s56.ERABModifyResponseIEValue
				decoded, err := s56.BridgeERABModifyResponseIEValueMethodDecode(zero, s00.ProtocolIEID(32), raw)
				if err != nil {
					var empty s19.ERABList
					return empty, runtime.WrapDecodePath(err, "ERABList")
				}
				value, ok := decoded.AsERABFailedToModifyList()
				if !ok {
					var empty s19.ERABList
					return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-E-RABFailedToModifyList: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s19.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModifyResponseIEValueMethodEncodeFresh((func() s56.ERABModifyResponseIEValue {
					sealed := s56.ERABModifyResponseIEValue{}
					*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(32)
					*s56.BridgeERABModifyResponseIEValueFieldRowERABFailedToModifyList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s19.ERABList, options aper.DecodeState) (s19.ERABList, aper.Snapshot) {
				s := aper.SemanticCaptureFor(
					options)
				f := s.Begin()
				s29.BridgeCaptureS1APERABList(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s19.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s19.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s29.BridgeCompareS1APERABList(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModifyResponseERABListIEBindingFieldInject(&sealed) = func(value s19.ERABList) s56.ERABModifyResponseIEValue {
			return func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(32)
				*s56.BridgeERABModifyResponseIEValueFieldRowERABFailedToModifyList(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModifyResponseERABListIEBindingFieldGet(&sealed) = func(value *s56.ERABModifyResponseIEValue) (*s19.ERABList, bool) {
			return value.AsERABFailedToModifyList()
		}
		return sealed
	}()
}
func (ERABModifyResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) CriticalityDiagnostics() s56.ERABModifyResponseCriticalityDiagnosticsIEBinding {
	return func() s56.ERABModifyResponseCriticalityDiagnosticsIEBinding {
		sealed := s56.ERABModifyResponseCriticalityDiagnosticsIEBinding{}
		*s56.BridgeERABModifyResponseCriticalityDiagnosticsIEBindingFieldInfo(&sealed) = t.infoCriticalityDiagnostics()
		*s56.BridgeERABModifyResponseCriticalityDiagnosticsIEBindingFieldCodec(&sealed) = func() s26.CriticalityDiagnosticsValueCodec {
			sealed := s26.CriticalityDiagnosticsValueCodec{}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
				var zero s56.ERABModifyResponseIEValue
				decoded, err := s56.BridgeERABModifyResponseIEValueMethodDecode(zero, s00.ProtocolIEID(58), raw)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
				}
				value, ok := decoded.AsCriticalityDiagnostics()
				if !ok {
					var empty s26.CriticalityDiagnostics
					return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-CriticalityDiagnostics: no selected value")
				}
				return *value, nil
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModifyResponseIEValueMethodEncodeFresh((func() s56.ERABModifyResponseIEValue {
					sealed := s56.ERABModifyResponseIEValue{}
					*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
					*s56.BridgeERABModifyResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModifyResponseCriticalityDiagnosticsIEBindingFieldInject(&sealed) = func(value s26.CriticalityDiagnostics) s56.ERABModifyResponseIEValue {
			return func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s56.BridgeERABModifyResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModifyResponseCriticalityDiagnosticsIEBindingFieldGet(&sealed) = func(value *s56.ERABModifyResponseIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}
		return sealed
	}()
}
func (ERABModifyResponseIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) SecondaryRATDataUsageReportList() s56.ERABModifyResponseSecondaryRATDataUsageReportListIEBinding {
	return func() s56.ERABModifyResponseSecondaryRATDataUsageReportListIEBinding {
		sealed := s56.ERABModifyResponseSecondaryRATDataUsageReportListIEBinding{}
		*s56.BridgeERABModifyResponseSecondaryRATDataUsageReportListIEBindingFieldInfo(&sealed) = t.infoSecondaryRATDataUsageReportList()
		*s56.BridgeERABModifyResponseSecondaryRATDataUsageReportListIEBindingFieldCodec(&sealed) = func() s36.SecondaryRATDataUsageReportListValueCodec {
			sealed := s36.SecondaryRATDataUsageReportListValueCodec{}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
				var zero s56.ERABModifyResponseIEValue
				decoded, err := s56.BridgeERABModifyResponseIEValueMethodDecode(zero, s00.ProtocolIEID(264), raw)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
				}
				value, ok := decoded.AsSecondaryRATDataUsageReportList()
				if !ok {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-SecondaryRATDataUsageReportList: no selected value")
				}
				return *value, nil
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s36.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABModifyResponseIEValueMethodEncodeFresh((func() s56.ERABModifyResponseIEValue {
					sealed := s56.ERABModifyResponseIEValue{}
					*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
					*s56.BridgeERABModifyResponseIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s36.SecondaryRATDataUsageReportList, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s36.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s36.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s36.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABModifyResponseSecondaryRATDataUsageReportListIEBindingFieldInject(&sealed) = func(value s36.SecondaryRATDataUsageReportList) s56.ERABModifyResponseIEValue {
			return func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeERABModifyResponseIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABModifyResponseSecondaryRATDataUsageReportListIEBindingFieldGet(&sealed) = func(value *s56.ERABModifyResponseIEValue) (*s36.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}
		return sealed
	}()
}
func (ERABModifyResponseIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyResponseIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyResponseIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) UserLocationInformation() ERABModifyResponseUserLocationInformationIEBinding {
	return ERABModifyResponseUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: func() s56.UserLocationInformationValueCodec {
		sealed := s56.UserLocationInformationValueCodec{}
		*s56.BridgeUserLocationInformationValueCodecFieldPath(&sealed) = "UserLocationInformation"
		*s56.BridgeUserLocationInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s55.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero s56.ERABModifyResponseIEValue
			decoded, err := s56.BridgeERABModifyResponseIEValueMethodDecode(zero, s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s55.UserLocationInformation
				return empty, fmt.Errorf("binding E-RABModifyResponseIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		}
		*s56.BridgeUserLocationInformationValueCodecFieldEncode(&sealed) = func(value s55.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s56.BridgeERABModifyResponseIEValueMethodEncodeFresh((func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABModifyResponseIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCapture(&sealed) = func(v s55.UserLocationInformation, options aper.DecodeState) (s55.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s55.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCompare(&sealed) = func(v s55.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s55.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUserLocationInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s55.UserLocationInformation) s56.ERABModifyResponseIEValue {
			return func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABModifyResponseIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s56.ERABModifyResponseIEValue) (*s55.UserLocationInformation, bool) {
			return value.AsUserLocationInformation()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABModifyResponseIETable.
func (t ERABModifyResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s56.ERABModifyResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s56.ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s56.ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s56.ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(31):
		return s56.ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABModifyListBearerModRes requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(32):
		return s56.ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABFailedToModifyList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return s56.ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return s56.ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return s56.ERABModifyResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s56.ERABModifyResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s56.ERABModifyResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return s56.ERABModifyResponseIEField{Id: id, Criticality: criticality, Value: func() s56.ERABModifyResponseIEValue {
			sealed := s56.ERABModifyResponseIEValue{}
			*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = id
			*s56.BridgeERABModifyResponseIEValueFieldOpaque(&sealed) = opaque
			*s56.BridgeERABModifyResponseIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABReleaseIndicationIETable struct{}

func ERABReleaseIndicationIEs() ERABReleaseIndicationIETable { return ERABReleaseIndicationIETable{} }

// ID returns the ASN.1 object-set identity of ERABReleaseIndicationIETable.
func (ERABReleaseIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABReleaseIndicationIETable.
func (ERABReleaseIndicationIETable) Table() s00.ERABReleaseIndicationIEValueIETable {
	return func() s00.ERABReleaseIndicationIEValueIETable {
		sealed := s00.ERABReleaseIndicationIEValueIETable{}
		*s00.BridgeERABReleaseIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABReleaseIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) MMEUES1APID() s56.ERABReleaseIndicationMMEUES1APIDIEBinding {
	return func() s56.ERABReleaseIndicationMMEUES1APIDIEBinding {
		sealed := s56.ERABReleaseIndicationMMEUES1APIDIEBinding{}
		*s56.BridgeERABReleaseIndicationMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s56.BridgeERABReleaseIndicationMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s56.ERABReleaseIndicationIEValue
				decoded, err := s56.BridgeERABReleaseIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding E-RABReleaseIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABReleaseIndicationIEValueMethodEncodeFresh((func() s56.ERABReleaseIndicationIEValue {
					sealed := s56.ERABReleaseIndicationIEValue{}
					*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s56.BridgeERABReleaseIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APMMEUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABReleaseIndicationMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s56.ERABReleaseIndicationIEValue {
			return func() s56.ERABReleaseIndicationIEValue {
				sealed := s56.ERABReleaseIndicationIEValue{}
				*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeERABReleaseIndicationIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABReleaseIndicationMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.ERABReleaseIndicationIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }
		return sealed
	}()
}
func (ERABReleaseIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) ENBUES1APID() s56.ERABReleaseIndicationENBUES1APIDIEBinding {
	return func() s56.ERABReleaseIndicationENBUES1APIDIEBinding {
		sealed := s56.ERABReleaseIndicationENBUES1APIDIEBinding{}
		*s56.BridgeERABReleaseIndicationENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s56.BridgeERABReleaseIndicationENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s56.ERABReleaseIndicationIEValue
				decoded, err := s56.BridgeERABReleaseIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding E-RABReleaseIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABReleaseIndicationIEValueMethodEncodeFresh((func() s56.ERABReleaseIndicationIEValue {
					sealed := s56.ERABReleaseIndicationIEValue{}
					*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s56.BridgeERABReleaseIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.ENBUES1APID, options aper.DecodeState) (s00.ENBUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APENBUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.ENBUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APENBUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s00.BridgeENBUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABReleaseIndicationENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s56.ERABReleaseIndicationIEValue {
			return func() s56.ERABReleaseIndicationIEValue {
				sealed := s56.ERABReleaseIndicationIEValue{}
				*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeERABReleaseIndicationIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABReleaseIndicationENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.ERABReleaseIndicationIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }
		return sealed
	}()
}
func (ERABReleaseIndicationIETable) infoERABReleasedList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseIndicationIEs().ID(), ID: s00.ProtocolIEID(110), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs", Row: "id-E-RABReleasedList"}}}
}

// ERABReleasedList returns the typed binding for the ERABReleasedList row of ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) ERABReleasedList() s56.ERABReleaseIndicationERABListIEBinding {
	return func() s56.ERABReleaseIndicationERABListIEBinding {
		sealed := s56.ERABReleaseIndicationERABListIEBinding{}
		*s56.BridgeERABReleaseIndicationERABListIEBindingFieldInfo(&sealed) = t.infoERABReleasedList()
		*s56.BridgeERABReleaseIndicationERABListIEBindingFieldCodec(&sealed) = func() s19.ERABListValueCodec {
			sealed := s19.ERABListValueCodec{}
			*s19.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
			*s19.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.ERABList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABList")
				var zero s56.ERABReleaseIndicationIEValue
				decoded, err := s56.BridgeERABReleaseIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(110), raw)
				if err != nil {
					var empty s19.ERABList
					return empty, runtime.WrapDecodePath(err, "ERABList")
				}
				value, ok := decoded.AsERABReleasedList()
				if !ok {
					var empty s19.ERABList
					return empty, fmt.Errorf("binding E-RABReleaseIndicationIEs.id-E-RABReleasedList: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s19.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABReleaseIndicationIEValueMethodEncodeFresh((func() s56.ERABReleaseIndicationIEValue {
					sealed := s56.ERABReleaseIndicationIEValue{}
					*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(110)
					*s56.BridgeERABReleaseIndicationIEValueFieldRowERABReleasedList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s19.ERABList, options aper.DecodeState) (s19.ERABList, aper.Snapshot) {
				s := aper.SemanticCaptureFor(
					options)
				f := s.Begin()
				s29.BridgeCaptureS1APERABList(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s19.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s19.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s29.BridgeCompareS1APERABList(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABReleaseIndicationERABListIEBindingFieldInject(&sealed) = func(value s19.ERABList) s56.ERABReleaseIndicationIEValue {
			return func() s56.ERABReleaseIndicationIEValue {
				sealed := s56.ERABReleaseIndicationIEValue{}
				*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(110)
				*s56.BridgeERABReleaseIndicationIEValueFieldRowERABReleasedList(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABReleaseIndicationERABListIEBindingFieldGet(&sealed) = func(value *s56.ERABReleaseIndicationIEValue) (*s19.ERABList, bool) {
			return value.AsERABReleasedList()
		}
		return sealed
	}()
}
func (ERABReleaseIndicationIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseIndicationIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) UserLocationInformation() ERABReleaseIndicationUserLocationInformationIEBinding {
	return ERABReleaseIndicationUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: func() s56.UserLocationInformationValueCodec {
		sealed := s56.UserLocationInformationValueCodec{}
		*s56.BridgeUserLocationInformationValueCodecFieldPath(&sealed) = "UserLocationInformation"
		*s56.BridgeUserLocationInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s55.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero s56.ERABReleaseIndicationIEValue
			decoded, err := s56.BridgeERABReleaseIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s55.UserLocationInformation
				return empty, fmt.Errorf("binding E-RABReleaseIndicationIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		}
		*s56.BridgeUserLocationInformationValueCodecFieldEncode(&sealed) = func(value s55.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s56.BridgeERABReleaseIndicationIEValueMethodEncodeFresh((func() s56.ERABReleaseIndicationIEValue {
				sealed := s56.ERABReleaseIndicationIEValue{}
				*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABReleaseIndicationIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCapture(&sealed) = func(v s55.UserLocationInformation, options aper.DecodeState) (s55.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s55.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCompare(&sealed) = func(v s55.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s55.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUserLocationInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s55.UserLocationInformation) s56.ERABReleaseIndicationIEValue {
			return func() s56.ERABReleaseIndicationIEValue {
				sealed := s56.ERABReleaseIndicationIEValue{}
				*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABReleaseIndicationIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s56.ERABReleaseIndicationIEValue) (*s55.UserLocationInformation, bool) {
			return value.AsUserLocationInformation()
		}}
}
func (ERABReleaseIndicationIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseIndicationIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseIndicationIEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) SecondaryRATDataUsageReportList() s56.ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding {
	return func() s56.ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding {
		sealed := s56.ERABReleaseIndicationSecondaryRATDataUsageReportListIEBinding{}
		*s56.BridgeERABReleaseIndicationSecondaryRATDataUsageReportListIEBindingFieldInfo(&sealed) = t.infoSecondaryRATDataUsageReportList()
		*s56.BridgeERABReleaseIndicationSecondaryRATDataUsageReportListIEBindingFieldCodec(&sealed) = func() s36.SecondaryRATDataUsageReportListValueCodec {
			sealed := s36.SecondaryRATDataUsageReportListValueCodec{}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
				var zero s56.ERABReleaseIndicationIEValue
				decoded, err := s56.BridgeERABReleaseIndicationIEValueMethodDecode(zero, s00.ProtocolIEID(264), raw)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
				}
				value, ok := decoded.AsSecondaryRATDataUsageReportList()
				if !ok {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, fmt.Errorf("binding E-RABReleaseIndicationIEs.id-SecondaryRATDataUsageReportList: no selected value")
				}
				return *value, nil
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s36.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABReleaseIndicationIEValueMethodEncodeFresh((func() s56.ERABReleaseIndicationIEValue {
					sealed := s56.ERABReleaseIndicationIEValue{}
					*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
					*s56.BridgeERABReleaseIndicationIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s36.SecondaryRATDataUsageReportList, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s36.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s36.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s36.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABReleaseIndicationSecondaryRATDataUsageReportListIEBindingFieldInject(&sealed) = func(value s36.SecondaryRATDataUsageReportList) s56.ERABReleaseIndicationIEValue {
			return func() s56.ERABReleaseIndicationIEValue {
				sealed := s56.ERABReleaseIndicationIEValue{}
				*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeERABReleaseIndicationIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABReleaseIndicationSecondaryRATDataUsageReportListIEBindingFieldGet(&sealed) = func(value *s56.ERABReleaseIndicationIEValue) (*s36.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABReleaseIndicationIETable.
func (t ERABReleaseIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s56.ERABReleaseIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s56.ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s56.ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s56.ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(110):
		return s56.ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABReleasedList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return s56.ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return s56.ERABReleaseIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s56.ERABReleaseIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s56.ERABReleaseIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return s56.ERABReleaseIndicationIEField{Id: id, Criticality: criticality, Value: func() s56.ERABReleaseIndicationIEValue {
			sealed := s56.ERABReleaseIndicationIEValue{}
			*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = id
			*s56.BridgeERABReleaseIndicationIEValueFieldOpaque(&sealed) = opaque
			*s56.BridgeERABReleaseIndicationIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABReleaseResponseIETable struct{}

func ERABReleaseResponseIEs() ERABReleaseResponseIETable { return ERABReleaseResponseIETable{} }

// ID returns the ASN.1 object-set identity of ERABReleaseResponseIETable.
func (ERABReleaseResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABReleaseResponseIETable.
func (ERABReleaseResponseIETable) Table() s00.ERABReleaseResponseIEValueIETable {
	return func() s00.ERABReleaseResponseIEValueIETable {
		sealed := s00.ERABReleaseResponseIEValueIETable{}
		*s00.BridgeERABReleaseResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABReleaseResponseIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) MMEUES1APID() s56.ERABReleaseResponseMMEUES1APIDIEBinding {
	return func() s56.ERABReleaseResponseMMEUES1APIDIEBinding {
		sealed := s56.ERABReleaseResponseMMEUES1APIDIEBinding{}
		*s56.BridgeERABReleaseResponseMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s56.BridgeERABReleaseResponseMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s56.ERABReleaseResponseIEValue
				decoded, err := s56.BridgeERABReleaseResponseIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABReleaseResponseIEValueMethodEncodeFresh((func() s56.ERABReleaseResponseIEValue {
					sealed := s56.ERABReleaseResponseIEValue{}
					*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s56.BridgeERABReleaseResponseIEValueFieldRowMMEUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APMMEUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABReleaseResponseMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s56.ERABReleaseResponseIEValue {
			return func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeERABReleaseResponseIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABReleaseResponseMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.ERABReleaseResponseIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }
		return sealed
	}()
}
func (ERABReleaseResponseIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) ENBUES1APID() s56.ERABReleaseResponseENBUES1APIDIEBinding {
	return func() s56.ERABReleaseResponseENBUES1APIDIEBinding {
		sealed := s56.ERABReleaseResponseENBUES1APIDIEBinding{}
		*s56.BridgeERABReleaseResponseENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s56.BridgeERABReleaseResponseENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s56.ERABReleaseResponseIEValue
				decoded, err := s56.BridgeERABReleaseResponseIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABReleaseResponseIEValueMethodEncodeFresh((func() s56.ERABReleaseResponseIEValue {
					sealed := s56.ERABReleaseResponseIEValue{}
					*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s56.BridgeERABReleaseResponseIEValueFieldRowENBUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.ENBUES1APID, options aper.DecodeState) (s00.ENBUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APENBUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.ENBUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APENBUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s00.BridgeENBUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABReleaseResponseENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s56.ERABReleaseResponseIEValue {
			return func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeERABReleaseResponseIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABReleaseResponseENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.ERABReleaseResponseIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }
		return sealed
	}()
}
func (ERABReleaseResponseIETable) infoERABReleaseListBearerRelComp() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(69), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseListBearerRelComp"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-E-RABReleaseListBearerRelComp"}}}
}

// ERABReleaseListBearerRelComp returns the typed binding for the ERABReleaseListBearerRelComp row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) ERABReleaseListBearerRelComp() s56.ERABReleaseResponseERABReleaseListBearerRelCompIEBinding {
	return func() s56.ERABReleaseResponseERABReleaseListBearerRelCompIEBinding {
		sealed := s56.ERABReleaseResponseERABReleaseListBearerRelCompIEBinding{}
		*s56.BridgeERABReleaseResponseERABReleaseListBearerRelCompIEBindingFieldInfo(&sealed) = t.infoERABReleaseListBearerRelComp()
		*s56.BridgeERABReleaseResponseERABReleaseListBearerRelCompIEBindingFieldCodec(&sealed) = func() s19.ERABReleaseListBearerRelCompValueCodec {
			sealed := s19.ERABReleaseListBearerRelCompValueCodec{}
			*s19.BridgeERABReleaseListBearerRelCompValueCodecFieldPath(&sealed) = "ERABReleaseListBearerRelComp"
			*s19.BridgeERABReleaseListBearerRelCompValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABReleaseListBearerRelComp, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.ERABReleaseListBearerRelComp
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABReleaseListBearerRelComp")
				var zero s56.ERABReleaseResponseIEValue
				decoded, err := s56.BridgeERABReleaseResponseIEValueMethodDecode(zero, s00.ProtocolIEID(69), raw)
				if err != nil {
					var empty s19.ERABReleaseListBearerRelComp
					return empty, runtime.WrapDecodePath(err, "ERABReleaseListBearerRelComp")
				}
				value, ok := decoded.AsERABReleaseListBearerRelComp()
				if !ok {
					var empty s19.ERABReleaseListBearerRelComp
					return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-E-RABReleaseListBearerRelComp: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeERABReleaseListBearerRelCompValueCodecFieldEncode(&sealed) = func(value s19.ERABReleaseListBearerRelComp, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABReleaseResponseIEValueMethodEncodeFresh((func() s56.ERABReleaseResponseIEValue {
					sealed := s56.ERABReleaseResponseIEValue{}
					*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(69)
					*s56.BridgeERABReleaseResponseIEValueFieldRowERABReleaseListBearerRelComp(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeERABReleaseListBearerRelCompValueCodecFieldCapture(&sealed) = func(v s19.ERABReleaseListBearerRelComp, options aper.DecodeState) (s19.ERABReleaseListBearerRelComp, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s29.BridgeCaptureS1APERABReleaseListBearerRelComp(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s19.BridgeERABReleaseListBearerRelCompValueCodecFieldCompare(&sealed) = func(v s19.ERABReleaseListBearerRelComp, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.
					Begin()
				s29.BridgeCompareS1APERABReleaseListBearerRelComp(&v, &s)
				s.End(
					f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeERABReleaseListBearerRelCompValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABReleaseListBearerRelComp"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABReleaseResponseERABReleaseListBearerRelCompIEBindingFieldInject(&sealed) = func(value s19.ERABReleaseListBearerRelComp) s56.ERABReleaseResponseIEValue {
			return func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(69)
				*s56.BridgeERABReleaseResponseIEValueFieldRowERABReleaseListBearerRelComp(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABReleaseResponseERABReleaseListBearerRelCompIEBindingFieldGet(&sealed) = func(value *s56.ERABReleaseResponseIEValue) (*s19.ERABReleaseListBearerRelComp, bool) {
			return value.AsERABReleaseListBearerRelComp()
		}
		return sealed
	}()
}
func (ERABReleaseResponseIETable) infoERABFailedToReleaseList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(34), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-E-RABFailedToReleaseList"}}}
}

// ERABFailedToReleaseList returns the typed binding for the ERABFailedToReleaseList row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) ERABFailedToReleaseList() s56.ERABReleaseResponseERABListIEBinding {
	return func() s56.ERABReleaseResponseERABListIEBinding {
		sealed := s56.ERABReleaseResponseERABListIEBinding{}
		*s56.BridgeERABReleaseResponseERABListIEBindingFieldInfo(&sealed) = t.infoERABFailedToReleaseList()
		*s56.BridgeERABReleaseResponseERABListIEBindingFieldCodec(&sealed) = func() s19.ERABListValueCodec {
			sealed := s19.ERABListValueCodec{}
			*s19.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
			*s19.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.ERABList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABList")
				var zero s56.ERABReleaseResponseIEValue
				decoded, err := s56.BridgeERABReleaseResponseIEValueMethodDecode(zero, s00.ProtocolIEID(34), raw)
				if err != nil {
					var empty s19.ERABList
					return empty, runtime.WrapDecodePath(err, "ERABList")
				}
				value, ok := decoded.AsERABFailedToReleaseList()
				if !ok {
					var empty s19.ERABList
					return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-E-RABFailedToReleaseList: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s19.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABReleaseResponseIEValueMethodEncodeFresh((func() s56.ERABReleaseResponseIEValue {
					sealed := s56.ERABReleaseResponseIEValue{}
					*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(34)
					*s56.BridgeERABReleaseResponseIEValueFieldRowERABFailedToReleaseList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s19.ERABList, options aper.DecodeState) (s19.ERABList, aper.Snapshot) {
				s := aper.SemanticCaptureFor(
					options)
				f := s.Begin()
				s29.BridgeCaptureS1APERABList(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s19.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s19.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s29.BridgeCompareS1APERABList(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABReleaseResponseERABListIEBindingFieldInject(&sealed) = func(value s19.ERABList) s56.ERABReleaseResponseIEValue {
			return func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(34)
				*s56.BridgeERABReleaseResponseIEValueFieldRowERABFailedToReleaseList(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABReleaseResponseERABListIEBindingFieldGet(&sealed) = func(value *s56.ERABReleaseResponseIEValue) (*s19.ERABList, bool) {
			return value.AsERABFailedToReleaseList()
		}
		return sealed
	}()
}
func (ERABReleaseResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) CriticalityDiagnostics() s56.ERABReleaseResponseCriticalityDiagnosticsIEBinding {
	return func() s56.ERABReleaseResponseCriticalityDiagnosticsIEBinding {
		sealed := s56.ERABReleaseResponseCriticalityDiagnosticsIEBinding{}
		*s56.BridgeERABReleaseResponseCriticalityDiagnosticsIEBindingFieldInfo(&sealed) = t.infoCriticalityDiagnostics()
		*s56.BridgeERABReleaseResponseCriticalityDiagnosticsIEBindingFieldCodec(&sealed) = func() s26.CriticalityDiagnosticsValueCodec {
			sealed := s26.CriticalityDiagnosticsValueCodec{}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
				var zero s56.ERABReleaseResponseIEValue
				decoded, err := s56.BridgeERABReleaseResponseIEValueMethodDecode(zero, s00.ProtocolIEID(58), raw)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
				}
				value, ok := decoded.AsCriticalityDiagnostics()
				if !ok {
					var empty s26.CriticalityDiagnostics
					return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-CriticalityDiagnostics: no selected value")
				}
				return *value, nil
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABReleaseResponseIEValueMethodEncodeFresh((func() s56.ERABReleaseResponseIEValue {
					sealed := s56.ERABReleaseResponseIEValue{}
					*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
					*s56.BridgeERABReleaseResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABReleaseResponseCriticalityDiagnosticsIEBindingFieldInject(&sealed) = func(value s26.CriticalityDiagnostics) s56.ERABReleaseResponseIEValue {
			return func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s56.BridgeERABReleaseResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABReleaseResponseCriticalityDiagnosticsIEBindingFieldGet(&sealed) = func(value *s56.ERABReleaseResponseIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}
		return sealed
	}()
}
func (ERABReleaseResponseIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) UserLocationInformation() ERABReleaseResponseUserLocationInformationIEBinding {
	return ERABReleaseResponseUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: func() s56.UserLocationInformationValueCodec {
		sealed := s56.UserLocationInformationValueCodec{}
		*s56.BridgeUserLocationInformationValueCodecFieldPath(&sealed) = "UserLocationInformation"
		*s56.BridgeUserLocationInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s55.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero s56.ERABReleaseResponseIEValue
			decoded, err := s56.BridgeERABReleaseResponseIEValueMethodDecode(zero, s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s55.UserLocationInformation
				return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		}
		*s56.BridgeUserLocationInformationValueCodecFieldEncode(&sealed) = func(value s55.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s56.BridgeERABReleaseResponseIEValueMethodEncodeFresh((func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABReleaseResponseIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCapture(&sealed) = func(v s55.UserLocationInformation, options aper.DecodeState) (s55.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s55.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCompare(&sealed) = func(v s55.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s55.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUserLocationInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s55.UserLocationInformation) s56.ERABReleaseResponseIEValue {
			return func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABReleaseResponseIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s56.ERABReleaseResponseIEValue) (*s55.UserLocationInformation, bool) {
			return value.AsUserLocationInformation()
		}}
}
func (ERABReleaseResponseIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseResponseIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseResponseIEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) SecondaryRATDataUsageReportList() s56.ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding {
	return func() s56.ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding {
		sealed := s56.ERABReleaseResponseSecondaryRATDataUsageReportListIEBinding{}
		*s56.BridgeERABReleaseResponseSecondaryRATDataUsageReportListIEBindingFieldInfo(&sealed) = t.infoSecondaryRATDataUsageReportList()
		*s56.BridgeERABReleaseResponseSecondaryRATDataUsageReportListIEBindingFieldCodec(&sealed) = func() s36.SecondaryRATDataUsageReportListValueCodec {
			sealed := s36.SecondaryRATDataUsageReportListValueCodec{}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
				var zero s56.ERABReleaseResponseIEValue
				decoded, err := s56.BridgeERABReleaseResponseIEValueMethodDecode(zero, s00.ProtocolIEID(264), raw)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
				}
				value, ok := decoded.AsSecondaryRATDataUsageReportList()
				if !ok {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, fmt.Errorf("binding E-RABReleaseResponseIEs.id-SecondaryRATDataUsageReportList: no selected value")
				}
				return *value, nil
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s36.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABReleaseResponseIEValueMethodEncodeFresh((func() s56.ERABReleaseResponseIEValue {
					sealed := s56.ERABReleaseResponseIEValue{}
					*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
					*s56.BridgeERABReleaseResponseIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s36.SecondaryRATDataUsageReportList, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s36.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s36.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s36.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABReleaseResponseSecondaryRATDataUsageReportListIEBindingFieldInject(&sealed) = func(value s36.SecondaryRATDataUsageReportList) s56.ERABReleaseResponseIEValue {
			return func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeERABReleaseResponseIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABReleaseResponseSecondaryRATDataUsageReportListIEBindingFieldGet(&sealed) = func(value *s56.ERABReleaseResponseIEValue) (*s36.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABReleaseResponseIETable.
func (t ERABReleaseResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s56.ERABReleaseResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(69):
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABReleaseListBearerRelComp requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(34):
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABFailedToReleaseList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return s56.ERABReleaseResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s56.ERABReleaseResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s56.ERABReleaseResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return s56.ERABReleaseResponseIEField{Id: id, Criticality: criticality, Value: func() s56.ERABReleaseResponseIEValue {
			sealed := s56.ERABReleaseResponseIEValue{}
			*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = id
			*s56.BridgeERABReleaseResponseIEValueFieldOpaque(&sealed) = opaque
			*s56.BridgeERABReleaseResponseIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABSetupResponseIETable struct{}

func ERABSetupResponseIEs() ERABSetupResponseIETable { return ERABSetupResponseIETable{} }

// ID returns the ASN.1 object-set identity of ERABSetupResponseIETable.
func (ERABSetupResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABSetupResponseIETable.
func (ERABSetupResponseIETable) Table() s00.ERABSetupResponseIEValueIETable {
	return func() s00.ERABSetupResponseIEValueIETable {
		sealed := s00.ERABSetupResponseIEValueIETable{}
		*s00.BridgeERABSetupResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABSetupResponseIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) MMEUES1APID() s56.ERABSetupResponseMMEUES1APIDIEBinding {
	return func() s56.ERABSetupResponseMMEUES1APIDIEBinding {
		sealed := s56.ERABSetupResponseMMEUES1APIDIEBinding{}
		*s56.BridgeERABSetupResponseMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s56.BridgeERABSetupResponseMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s56.ERABSetupResponseIEValue
				decoded, err := s56.BridgeERABSetupResponseIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABSetupResponseIEValueMethodEncodeFresh((func() s56.ERABSetupResponseIEValue {
					sealed := s56.ERABSetupResponseIEValue{}
					*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s56.BridgeERABSetupResponseIEValueFieldRowMMEUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APMMEUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABSetupResponseMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s56.ERABSetupResponseIEValue {
			return func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeERABSetupResponseIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABSetupResponseMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.ERABSetupResponseIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }
		return sealed
	}()
}
func (ERABSetupResponseIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) ENBUES1APID() s56.ERABSetupResponseENBUES1APIDIEBinding {
	return func() s56.ERABSetupResponseENBUES1APIDIEBinding {
		sealed := s56.ERABSetupResponseENBUES1APIDIEBinding{}
		*s56.BridgeERABSetupResponseENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s56.BridgeERABSetupResponseENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s56.ERABSetupResponseIEValue
				decoded, err := s56.BridgeERABSetupResponseIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABSetupResponseIEValueMethodEncodeFresh((func() s56.ERABSetupResponseIEValue {
					sealed := s56.ERABSetupResponseIEValue{}
					*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s56.BridgeERABSetupResponseIEValueFieldRowENBUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.ENBUES1APID, options aper.DecodeState) (s00.ENBUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APENBUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.ENBUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APENBUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s00.BridgeENBUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABSetupResponseENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s56.ERABSetupResponseIEValue {
			return func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeERABSetupResponseIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABSetupResponseENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.ERABSetupResponseIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }
		return sealed
	}()
}
func (ERABSetupResponseIETable) infoERABSetupListBearerSURes() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(28), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupListBearerSURes"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-E-RABSetupListBearerSURes"}}}
}

// ERABSetupListBearerSURes returns the typed binding for the ERABSetupListBearerSURes row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) ERABSetupListBearerSURes() s56.ERABSetupResponseERABSetupListBearerSUResIEBinding {
	return func() s56.ERABSetupResponseERABSetupListBearerSUResIEBinding {
		sealed := s56.ERABSetupResponseERABSetupListBearerSUResIEBinding{}
		*s56.BridgeERABSetupResponseERABSetupListBearerSUResIEBindingFieldInfo(&sealed) = t.infoERABSetupListBearerSURes()
		*s56.BridgeERABSetupResponseERABSetupListBearerSUResIEBindingFieldCodec(&sealed) = func() s20.ERABSetupListBearerSUResValueCodec {
			sealed := s20.ERABSetupListBearerSUResValueCodec{}
			*s20.BridgeERABSetupListBearerSUResValueCodecFieldPath(&sealed) = "ERABSetupListBearerSURes"
			*s20.BridgeERABSetupListBearerSUResValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABSetupListBearerSURes, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s20.ERABSetupListBearerSURes
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABSetupListBearerSURes")
				var zero s56.ERABSetupResponseIEValue
				decoded, err := s56.BridgeERABSetupResponseIEValueMethodDecode(zero, s00.ProtocolIEID(28), raw)
				if err != nil {
					var empty s20.ERABSetupListBearerSURes
					return empty, runtime.WrapDecodePath(err, "ERABSetupListBearerSURes")
				}
				value, ok := decoded.AsERABSetupListBearerSURes()
				if !ok {
					var empty s20.ERABSetupListBearerSURes
					return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-E-RABSetupListBearerSURes: no selected value")
				}
				return *value, nil
			}
			*s20.BridgeERABSetupListBearerSUResValueCodecFieldEncode(&sealed) = func(value s20.ERABSetupListBearerSURes, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABSetupResponseIEValueMethodEncodeFresh((func() s56.ERABSetupResponseIEValue {
					sealed := s56.ERABSetupResponseIEValue{}
					*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(28)
					*s56.BridgeERABSetupResponseIEValueFieldRowERABSetupListBearerSURes(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s20.BridgeERABSetupListBearerSUResValueCodecFieldCapture(&sealed) = func(v s20.ERABSetupListBearerSURes, options aper.DecodeState) (s20.ERABSetupListBearerSURes, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s29.BridgeCaptureS1APERABSetupListBearerSURes(&v, &s)
				var root aper.Snapshot
				s.End(f, &root,

					false)
				return v, root
			}
			*s20.BridgeERABSetupListBearerSUResValueCodecFieldCompare(&sealed) = func(v s20.ERABSetupListBearerSURes, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s29.BridgeCompareS1APERABSetupListBearerSURes(&v, &s)
				s.End(f, root,

					false,
				)
				return s.Plan(), s.BudgetValue()
			}
			*s20.BridgeERABSetupListBearerSUResValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABSetupListBearerSURes"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABSetupResponseERABSetupListBearerSUResIEBindingFieldInject(&sealed) = func(value s20.ERABSetupListBearerSURes) s56.ERABSetupResponseIEValue {
			return func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(28)
				*s56.BridgeERABSetupResponseIEValueFieldRowERABSetupListBearerSURes(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABSetupResponseERABSetupListBearerSUResIEBindingFieldGet(&sealed) = func(value *s56.ERABSetupResponseIEValue) (*s20.ERABSetupListBearerSURes, bool) {
			return value.AsERABSetupListBearerSURes()
		}
		return sealed
	}()
}
func (ERABSetupResponseIETable) infoERABFailedToSetupListBearerSURes() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(29), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-E-RABFailedToSetupListBearerSURes"}}}
}

// ERABFailedToSetupListBearerSURes returns the typed binding for the ERABFailedToSetupListBearerSURes row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) ERABFailedToSetupListBearerSURes() s56.ERABSetupResponseERABListIEBinding {
	return func() s56.ERABSetupResponseERABListIEBinding {
		sealed := s56.ERABSetupResponseERABListIEBinding{}
		*s56.BridgeERABSetupResponseERABListIEBindingFieldInfo(&sealed) = t.infoERABFailedToSetupListBearerSURes()
		*s56.BridgeERABSetupResponseERABListIEBindingFieldCodec(&sealed) = func() s19.ERABListValueCodec {
			sealed := s19.ERABListValueCodec{}
			*s19.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
			*s19.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.ERABList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABList")
				var zero s56.ERABSetupResponseIEValue
				decoded, err := s56.BridgeERABSetupResponseIEValueMethodDecode(zero, s00.ProtocolIEID(29), raw)
				if err != nil {
					var empty s19.ERABList
					return empty, runtime.WrapDecodePath(err, "ERABList")
				}
				value, ok := decoded.AsERABFailedToSetupListBearerSURes()
				if !ok {
					var empty s19.ERABList
					return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-E-RABFailedToSetupListBearerSURes: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s19.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABSetupResponseIEValueMethodEncodeFresh((func() s56.ERABSetupResponseIEValue {
					sealed := s56.ERABSetupResponseIEValue{}
					*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(29)
					*s56.BridgeERABSetupResponseIEValueFieldRowERABFailedToSetupListBearerSURes(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s19.ERABList, options aper.DecodeState) (s19.ERABList, aper.Snapshot) {
				s := aper.SemanticCaptureFor(
					options)
				f := s.Begin()
				s29.BridgeCaptureS1APERABList(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s19.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s19.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s29.BridgeCompareS1APERABList(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABSetupResponseERABListIEBindingFieldInject(&sealed) = func(value s19.ERABList) s56.ERABSetupResponseIEValue {
			return func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(29)
				*s56.BridgeERABSetupResponseIEValueFieldRowERABFailedToSetupListBearerSURes(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABSetupResponseERABListIEBindingFieldGet(&sealed) = func(value *s56.ERABSetupResponseIEValue) (*s19.ERABList, bool) {
			return value.AsERABFailedToSetupListBearerSURes()
		}
		return sealed
	}()
}
func (ERABSetupResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) CriticalityDiagnostics() s56.ERABSetupResponseCriticalityDiagnosticsIEBinding {
	return func() s56.ERABSetupResponseCriticalityDiagnosticsIEBinding {
		sealed := s56.ERABSetupResponseCriticalityDiagnosticsIEBinding{}
		*s56.BridgeERABSetupResponseCriticalityDiagnosticsIEBindingFieldInfo(&sealed) = t.infoCriticalityDiagnostics()
		*s56.BridgeERABSetupResponseCriticalityDiagnosticsIEBindingFieldCodec(&sealed) = func() s26.CriticalityDiagnosticsValueCodec {
			sealed := s26.CriticalityDiagnosticsValueCodec{}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
				var zero s56.ERABSetupResponseIEValue
				decoded, err := s56.BridgeERABSetupResponseIEValueMethodDecode(zero, s00.ProtocolIEID(58), raw)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
				}
				value, ok := decoded.AsCriticalityDiagnostics()
				if !ok {
					var empty s26.CriticalityDiagnostics
					return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-CriticalityDiagnostics: no selected value")
				}
				return *value, nil
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeERABSetupResponseIEValueMethodEncodeFresh((func() s56.ERABSetupResponseIEValue {
					sealed := s56.ERABSetupResponseIEValue{}
					*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
					*s56.BridgeERABSetupResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeERABSetupResponseCriticalityDiagnosticsIEBindingFieldInject(&sealed) = func(value s26.CriticalityDiagnostics) s56.ERABSetupResponseIEValue {
			return func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s56.BridgeERABSetupResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeERABSetupResponseCriticalityDiagnosticsIEBindingFieldGet(&sealed) = func(value *s56.ERABSetupResponseIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}
		return sealed
	}()
}
func (ERABSetupResponseIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupResponseIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupResponseIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) UserLocationInformation() ERABSetupResponseUserLocationInformationIEBinding {
	return ERABSetupResponseUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: func() s56.UserLocationInformationValueCodec {
		sealed := s56.UserLocationInformationValueCodec{}
		*s56.BridgeUserLocationInformationValueCodecFieldPath(&sealed) = "UserLocationInformation"
		*s56.BridgeUserLocationInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s55.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero s56.ERABSetupResponseIEValue
			decoded, err := s56.BridgeERABSetupResponseIEValueMethodDecode(zero, s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s55.UserLocationInformation
				return empty, fmt.Errorf("binding E-RABSetupResponseIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		}
		*s56.BridgeUserLocationInformationValueCodecFieldEncode(&sealed) = func(value s55.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s56.BridgeERABSetupResponseIEValueMethodEncodeFresh((func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABSetupResponseIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCapture(&sealed) = func(v s55.UserLocationInformation, options aper.DecodeState) (s55.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s55.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCompare(&sealed) = func(v s55.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s55.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUserLocationInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s55.UserLocationInformation) s56.ERABSetupResponseIEValue {
			return func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABSetupResponseIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s56.ERABSetupResponseIEValue) (*s55.UserLocationInformation, bool) {
			return value.AsUserLocationInformation()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABSetupResponseIETable.
func (t ERABSetupResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s56.ERABSetupResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s56.ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s56.ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s56.ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(28):
		return s56.ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABSetupListBearerSURes requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(29):
		return s56.ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABFailedToSetupListBearerSURes requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return s56.ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return s56.ERABSetupResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s56.ERABSetupResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s56.ERABSetupResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return s56.ERABSetupResponseIEField{Id: id, Criticality: criticality, Value: func() s56.ERABSetupResponseIEValue {
			sealed := s56.ERABSetupResponseIEValue{}
			*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = id
			*s56.BridgeERABSetupResponseIEValueFieldOpaque(&sealed) = opaque
			*s56.BridgeERABSetupResponseIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type SecondaryRATDataUsageReportIETable struct{}

func SecondaryRATDataUsageReportIEs() SecondaryRATDataUsageReportIETable {
	return SecondaryRATDataUsageReportIETable{}
}

// ID returns the ASN.1 object-set identity of SecondaryRATDataUsageReportIETable.
func (SecondaryRATDataUsageReportIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SecondaryRATDataUsageReportIETable.
func (SecondaryRATDataUsageReportIETable) Table() s00.SecondaryRATDataUsageReportIEValueIETable {
	return func() s00.SecondaryRATDataUsageReportIEValueIETable {
		sealed := s00.SecondaryRATDataUsageReportIEValueIETable{}
		*s00.BridgeSecondaryRATDataUsageReportIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (SecondaryRATDataUsageReportIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) MMEUES1APID() s56.SecondaryRATDataUsageReportMMEUES1APIDIEBinding {
	return func() s56.SecondaryRATDataUsageReportMMEUES1APIDIEBinding {
		sealed := s56.SecondaryRATDataUsageReportMMEUES1APIDIEBinding{}
		*s56.BridgeSecondaryRATDataUsageReportMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s56.BridgeSecondaryRATDataUsageReportMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s56.SecondaryRATDataUsageReportIEValue
				decoded, err := s56.BridgeSecondaryRATDataUsageReportIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeSecondaryRATDataUsageReportIEValueMethodEncodeFresh((func() s56.SecondaryRATDataUsageReportIEValue {
					sealed := s56.SecondaryRATDataUsageReportIEValue{}
					*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowMMEUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APMMEUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeSecondaryRATDataUsageReportMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s56.SecondaryRATDataUsageReportIEValue {
			return func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeSecondaryRATDataUsageReportMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.SecondaryRATDataUsageReportIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}
		return sealed
	}()
}
func (SecondaryRATDataUsageReportIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) ENBUES1APID() s56.SecondaryRATDataUsageReportENBUES1APIDIEBinding {
	return func() s56.SecondaryRATDataUsageReportENBUES1APIDIEBinding {
		sealed := s56.SecondaryRATDataUsageReportENBUES1APIDIEBinding{}
		*s56.BridgeSecondaryRATDataUsageReportENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s56.BridgeSecondaryRATDataUsageReportENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s56.SecondaryRATDataUsageReportIEValue
				decoded, err := s56.BridgeSecondaryRATDataUsageReportIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeSecondaryRATDataUsageReportIEValueMethodEncodeFresh((func() s56.SecondaryRATDataUsageReportIEValue {
					sealed := s56.SecondaryRATDataUsageReportIEValue{}
					*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowENBUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.ENBUES1APID, options aper.DecodeState) (s00.ENBUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APENBUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.ENBUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APENBUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s00.BridgeENBUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeSecondaryRATDataUsageReportENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s56.SecondaryRATDataUsageReportIEValue {
			return func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeSecondaryRATDataUsageReportENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.SecondaryRATDataUsageReportIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}
		return sealed
	}()
}
func (SecondaryRATDataUsageReportIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) SecondaryRATDataUsageReportList() s56.SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding {
	return func() s56.SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding {
		sealed := s56.SecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBinding{}
		*s56.BridgeSecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBindingFieldInfo(&sealed) = t.infoSecondaryRATDataUsageReportList()
		*s56.BridgeSecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBindingFieldCodec(&sealed) = func() s36.SecondaryRATDataUsageReportListValueCodec {
			sealed := s36.SecondaryRATDataUsageReportListValueCodec{}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
				var zero s56.SecondaryRATDataUsageReportIEValue
				decoded, err := s56.BridgeSecondaryRATDataUsageReportIEValueMethodDecode(zero, s00.ProtocolIEID(264), raw)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
				}
				value, ok := decoded.AsSecondaryRATDataUsageReportList()
				if !ok {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-SecondaryRATDataUsageReportList: no selected value")
				}
				return *value, nil
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s36.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeSecondaryRATDataUsageReportIEValueMethodEncodeFresh((func() s56.SecondaryRATDataUsageReportIEValue {
					sealed := s56.SecondaryRATDataUsageReportIEValue{}
					*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
					*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s36.SecondaryRATDataUsageReportList, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s36.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s36.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s36.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeSecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBindingFieldInject(&sealed) = func(value s36.SecondaryRATDataUsageReportList) s56.SecondaryRATDataUsageReportIEValue {
			return func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeSecondaryRATDataUsageReportSecondaryRATDataUsageReportListIEBindingFieldGet(&sealed) = func(value *s56.SecondaryRATDataUsageReportIEValue) (*s36.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}
		return sealed
	}()
}
func (SecondaryRATDataUsageReportIETable) infoHandoverFlag() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(266), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverFlag"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-HandoverFlag"}}}
}

// HandoverFlag returns the typed binding for the HandoverFlag row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) HandoverFlag() s56.SecondaryRATDataUsageReportHandoverFlagIEBinding {
	return func() s56.SecondaryRATDataUsageReportHandoverFlagIEBinding {
		sealed := s56.SecondaryRATDataUsageReportHandoverFlagIEBinding{}
		*s56.BridgeSecondaryRATDataUsageReportHandoverFlagIEBindingFieldInfo(&sealed) = t.infoHandoverFlag()
		*s56.BridgeSecondaryRATDataUsageReportHandoverFlagIEBindingFieldCodec(&sealed) = func() s01.HandoverFlagValueCodec {
			sealed := s01.HandoverFlagValueCodec{}
			*s01.BridgeHandoverFlagValueCodecFieldPath(&sealed) = "HandoverFlag"
			*s01.BridgeHandoverFlagValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HandoverFlag, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.HandoverFlag
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("HandoverFlag")
				var zero s56.SecondaryRATDataUsageReportIEValue
				decoded, err := s56.BridgeSecondaryRATDataUsageReportIEValueMethodDecode(zero, s00.ProtocolIEID(266), raw)
				if err != nil {
					var empty s00.HandoverFlag
					return empty, runtime.WrapDecodePath(err, "HandoverFlag")
				}
				value, ok := decoded.AsHandoverFlag()
				if !ok {
					var empty s00.HandoverFlag
					return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-HandoverFlag: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeHandoverFlagValueCodecFieldEncode(&sealed) = func(value s00.HandoverFlag, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeSecondaryRATDataUsageReportIEValueMethodEncodeFresh((func() s56.SecondaryRATDataUsageReportIEValue {
					sealed := s56.SecondaryRATDataUsageReportIEValue{}
					*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(266)
					*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowHandoverFlag(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeHandoverFlagValueCodecFieldCapture(&sealed) = func(v s00.HandoverFlag, options aper.DecodeState) (s00.HandoverFlag, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APHandoverFlag(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeHandoverFlagValueCodecFieldCompare(&sealed) = func(v s00.HandoverFlag, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APHandoverFlag(&v, &s)
				s.End(f, root, false)
				return s.Plan(),
					s.
						BudgetValue()
			}
			*s01.BridgeHandoverFlagValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverFlag"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeSecondaryRATDataUsageReportHandoverFlagIEBindingFieldInject(&sealed) = func(value s00.HandoverFlag) s56.SecondaryRATDataUsageReportIEValue {
			return func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(266)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowHandoverFlag(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeSecondaryRATDataUsageReportHandoverFlagIEBindingFieldGet(&sealed) = func(value *s56.SecondaryRATDataUsageReportIEValue) (*s00.HandoverFlag, bool) {
			return value.AsHandoverFlag()
		}
		return sealed
	}()
}
func (SecondaryRATDataUsageReportIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) UserLocationInformation() SecondaryRATDataUsageReportUserLocationInformationIEBinding {
	return SecondaryRATDataUsageReportUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: func() s56.UserLocationInformationValueCodec {
		sealed := s56.UserLocationInformationValueCodec{}
		*s56.BridgeUserLocationInformationValueCodecFieldPath(&sealed) = "UserLocationInformation"
		*s56.BridgeUserLocationInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s55.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero s56.SecondaryRATDataUsageReportIEValue
			decoded, err := s56.BridgeSecondaryRATDataUsageReportIEValueMethodDecode(zero, s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s55.UserLocationInformation
				return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		}
		*s56.BridgeUserLocationInformationValueCodecFieldEncode(&sealed) = func(value s55.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s56.BridgeSecondaryRATDataUsageReportIEValueMethodEncodeFresh((func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCapture(&sealed) = func(v s55.UserLocationInformation, options aper.DecodeState) (s55.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s55.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCompare(&sealed) = func(v s55.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s55.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUserLocationInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s55.UserLocationInformation) s56.SecondaryRATDataUsageReportIEValue {
			return func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s56.SecondaryRATDataUsageReportIEValue) (*s55.UserLocationInformation, bool) {
			return value.AsUserLocationInformation()
		}}
}
func (SecondaryRATDataUsageReportIETable) infoTimeSinceSecondaryNodeRelease() s00.FieldInfo {
	return s00.FieldInfo{Table: SecondaryRATDataUsageReportIEs().ID(), ID: s00.ProtocolIEID(297), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeSinceSecondaryNodeRelease"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "SecondaryRATDataUsageReportIEs", Row: "id-TimeSinceSecondaryNodeRelease"}}}
}

// TimeSinceSecondaryNodeRelease returns the typed binding for the TimeSinceSecondaryNodeRelease row of SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) TimeSinceSecondaryNodeRelease() s56.SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding {
	return func() s56.SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding {
		sealed := s56.SecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBinding{}
		*s56.BridgeSecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBindingFieldInfo(&sealed) = t.infoTimeSinceSecondaryNodeRelease()
		*s56.BridgeSecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBindingFieldCodec(&sealed) = func() s02.TimeSinceSecondaryNodeReleaseValueCodec {
			sealed := s02.TimeSinceSecondaryNodeReleaseValueCodec{}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldPath(&sealed) = "TimeSinceSecondaryNodeRelease"
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.TimeSinceSecondaryNodeRelease
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TimeSinceSecondaryNodeRelease")
				var zero s56.SecondaryRATDataUsageReportIEValue
				decoded, err := s56.BridgeSecondaryRATDataUsageReportIEValueMethodDecode(zero, s00.ProtocolIEID(297), raw)
				if err != nil {
					var empty s00.TimeSinceSecondaryNodeRelease
					return empty, runtime.WrapDecodePath(err, "TimeSinceSecondaryNodeRelease")
				}
				value, ok := decoded.AsTimeSinceSecondaryNodeRelease()
				if !ok {
					var empty s00.TimeSinceSecondaryNodeRelease
					return empty, fmt.Errorf("binding SecondaryRATDataUsageReportIEs.id-TimeSinceSecondaryNodeRelease: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldEncode(&sealed) = func(value s00.TimeSinceSecondaryNodeRelease, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeSecondaryRATDataUsageReportIEValueMethodEncodeFresh((func() s56.SecondaryRATDataUsageReportIEValue {
					sealed := s56.SecondaryRATDataUsageReportIEValue{}
					*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
					*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCapture(&sealed) = func(v s00.TimeSinceSecondaryNodeRelease, options aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APTimeSinceSecondaryNodeRelease(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCompare(&sealed) = func(v s00.TimeSinceSecondaryNodeRelease, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f :=
					s.Begin()
				s08.BridgeCompareS1APTimeSinceSecondaryNodeRelease(&v, &s)
				s.
					End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeSinceSecondaryNodeRelease"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeSecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBindingFieldInject(&sealed) = func(value s00.TimeSinceSecondaryNodeRelease) s56.SecondaryRATDataUsageReportIEValue {
			return func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeSecondaryRATDataUsageReportTimeSinceSecondaryNodeReleaseIEBindingFieldGet(&sealed) = func(value *s56.SecondaryRATDataUsageReportIEValue) (*s00.TimeSinceSecondaryNodeRelease, bool) {
			return value.AsTimeSinceSecondaryNodeRelease()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SecondaryRATDataUsageReportIETable.
func (t SecondaryRATDataUsageReportIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s56.SecondaryRATDataUsageReportIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(266):
		return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-HandoverFlag requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(297):
		return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeSinceSecondaryNodeRelease requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s56.SecondaryRATDataUsageReportIEField{}, aper.OperationError(err, "Opaque")
		}
		return s56.SecondaryRATDataUsageReportIEField{Id: id, Criticality: criticality, Value: func() s56.SecondaryRATDataUsageReportIEValue {
			sealed := s56.SecondaryRATDataUsageReportIEValue{}
			*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = id
			*s56.BridgeSecondaryRATDataUsageReportIEValueFieldOpaque(&sealed) = opaque
			*s56.BridgeSecondaryRATDataUsageReportIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextReleaseCompleteIETable struct{}

func UEContextReleaseCompleteIEs() UEContextReleaseCompleteIETable {
	return UEContextReleaseCompleteIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextReleaseCompleteIETable.
func (UEContextReleaseCompleteIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextReleaseCompleteIETable.
func (UEContextReleaseCompleteIETable) Table() s00.UEContextReleaseCompleteIEValueIETable {
	return func() s00.UEContextReleaseCompleteIEValueIETable {
		sealed := s00.UEContextReleaseCompleteIEValueIETable{}
		*s00.BridgeUEContextReleaseCompleteIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextReleaseCompleteIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) MMEUES1APID() s56.UEContextReleaseCompleteMMEUES1APIDIEBinding {
	return func() s56.UEContextReleaseCompleteMMEUES1APIDIEBinding {
		sealed := s56.UEContextReleaseCompleteMMEUES1APIDIEBinding{}
		*s56.BridgeUEContextReleaseCompleteMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s56.BridgeUEContextReleaseCompleteMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s56.UEContextReleaseCompleteIEValue
				decoded, err := s56.BridgeUEContextReleaseCompleteIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextReleaseCompleteIEValueMethodEncodeFresh((func() s56.UEContextReleaseCompleteIEValue {
					sealed := s56.UEContextReleaseCompleteIEValue{}
					*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s56.BridgeUEContextReleaseCompleteIEValueFieldRowMMEUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APMMEUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextReleaseCompleteMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s56.UEContextReleaseCompleteIEValue {
			return func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextReleaseCompleteMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.UEContextReleaseCompleteIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}
		return sealed
	}()
}
func (UEContextReleaseCompleteIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) ENBUES1APID() s56.UEContextReleaseCompleteENBUES1APIDIEBinding {
	return func() s56.UEContextReleaseCompleteENBUES1APIDIEBinding {
		sealed := s56.UEContextReleaseCompleteENBUES1APIDIEBinding{}
		*s56.BridgeUEContextReleaseCompleteENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s56.BridgeUEContextReleaseCompleteENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s56.UEContextReleaseCompleteIEValue
				decoded, err := s56.BridgeUEContextReleaseCompleteIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextReleaseCompleteIEValueMethodEncodeFresh((func() s56.UEContextReleaseCompleteIEValue {
					sealed := s56.UEContextReleaseCompleteIEValue{}
					*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s56.BridgeUEContextReleaseCompleteIEValueFieldRowENBUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.ENBUES1APID, options aper.DecodeState) (s00.ENBUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APENBUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.ENBUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APENBUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s00.BridgeENBUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextReleaseCompleteENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s56.UEContextReleaseCompleteIEValue {
			return func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextReleaseCompleteENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.UEContextReleaseCompleteIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}
		return sealed
	}()
}
func (UEContextReleaseCompleteIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) CriticalityDiagnostics() s56.UEContextReleaseCompleteCriticalityDiagnosticsIEBinding {
	return func() s56.UEContextReleaseCompleteCriticalityDiagnosticsIEBinding {
		sealed := s56.UEContextReleaseCompleteCriticalityDiagnosticsIEBinding{}
		*s56.BridgeUEContextReleaseCompleteCriticalityDiagnosticsIEBindingFieldInfo(&sealed) = t.infoCriticalityDiagnostics()
		*s56.BridgeUEContextReleaseCompleteCriticalityDiagnosticsIEBindingFieldCodec(&sealed) = func() s26.CriticalityDiagnosticsValueCodec {
			sealed := s26.CriticalityDiagnosticsValueCodec{}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
				var zero s56.UEContextReleaseCompleteIEValue
				decoded, err := s56.BridgeUEContextReleaseCompleteIEValueMethodDecode(zero, s00.ProtocolIEID(58), raw)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
				}
				value, ok := decoded.AsCriticalityDiagnostics()
				if !ok {
					var empty s26.CriticalityDiagnostics
					return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-CriticalityDiagnostics: no selected value")
				}
				return *value, nil
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextReleaseCompleteIEValueMethodEncodeFresh((func() s56.UEContextReleaseCompleteIEValue {
					sealed := s56.UEContextReleaseCompleteIEValue{}
					*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
					*s56.BridgeUEContextReleaseCompleteIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextReleaseCompleteCriticalityDiagnosticsIEBindingFieldInject(&sealed) = func(value s26.CriticalityDiagnostics) s56.UEContextReleaseCompleteIEValue {
			return func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextReleaseCompleteCriticalityDiagnosticsIEBindingFieldGet(&sealed) = func(value *s56.UEContextReleaseCompleteIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}
		return sealed
	}()
}
func (UEContextReleaseCompleteIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) UserLocationInformation() UEContextReleaseCompleteUserLocationInformationIEBinding {
	return UEContextReleaseCompleteUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: func() s56.UserLocationInformationValueCodec {
		sealed := s56.UserLocationInformationValueCodec{}
		*s56.BridgeUserLocationInformationValueCodecFieldPath(&sealed) = "UserLocationInformation"
		*s56.BridgeUserLocationInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s55.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero s56.UEContextReleaseCompleteIEValue
			decoded, err := s56.BridgeUEContextReleaseCompleteIEValueMethodDecode(zero, s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s55.UserLocationInformation
				return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		}
		*s56.BridgeUserLocationInformationValueCodecFieldEncode(&sealed) = func(value s55.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s56.BridgeUEContextReleaseCompleteIEValueMethodEncodeFresh((func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCapture(&sealed) = func(v s55.UserLocationInformation, options aper.DecodeState) (s55.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s55.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCompare(&sealed) = func(v s55.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s55.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUserLocationInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s55.UserLocationInformation) s56.UEContextReleaseCompleteIEValue {
			return func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s56.UEContextReleaseCompleteIEValue) (*s55.UserLocationInformation, bool) {
			return value.AsUserLocationInformation()
		}}
}
func (UEContextReleaseCompleteIETable) infoInformationOnRecommendedCellsAndENBsForPaging() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(213), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "InformationOnRecommendedCellsAndENBsForPaging"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-InformationOnRecommendedCellsAndENBsForPaging"}}}
}

// InformationOnRecommendedCellsAndENBsForPaging returns the typed binding for the InformationOnRecommendedCellsAndENBsForPaging row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) InformationOnRecommendedCellsAndENBsForPaging() s56.UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding {
	return func() s56.UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding {
		sealed := s56.UEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBinding{}
		*s56.BridgeUEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldInfo(&sealed) = t.infoInformationOnRecommendedCellsAndENBsForPaging()
		*s56.BridgeUEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldCodec(&sealed) = func() s42.InformationOnRecommendedCellsAndENBsForPagingValueCodec {
			sealed := s42.InformationOnRecommendedCellsAndENBsForPagingValueCodec{}
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldPath(&sealed) = "InformationOnRecommendedCellsAndENBsForPaging"
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s42.InformationOnRecommendedCellsAndENBsForPaging, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s42.InformationOnRecommendedCellsAndENBsForPaging
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("InformationOnRecommendedCellsAndENBsForPaging")
				var zero s56.UEContextReleaseCompleteIEValue
				decoded, err := s56.BridgeUEContextReleaseCompleteIEValueMethodDecode(zero, s00.ProtocolIEID(213), raw)
				if err != nil {
					var empty s42.InformationOnRecommendedCellsAndENBsForPaging
					return empty, runtime.WrapDecodePath(err, "InformationOnRecommendedCellsAndENBsForPaging")
				}
				value, ok := decoded.AsInformationOnRecommendedCellsAndENBsForPaging()
				if !ok {
					var empty s42.InformationOnRecommendedCellsAndENBsForPaging
					return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-InformationOnRecommendedCellsAndENBsForPaging: no selected value")
				}
				return *value, nil
			}
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldEncode(&sealed) = func(value s42.InformationOnRecommendedCellsAndENBsForPaging, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextReleaseCompleteIEValueMethodEncodeFresh((func() s56.UEContextReleaseCompleteIEValue {
					sealed := s56.UEContextReleaseCompleteIEValue{}
					*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(213)
					*s56.BridgeUEContextReleaseCompleteIEValueFieldRowInformationOnRecommendedCellsAndENBsForPaging(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldCapture(&sealed) = func(v s42.InformationOnRecommendedCellsAndENBsForPaging, options aper.DecodeState) (s42.InformationOnRecommendedCellsAndENBsForPaging, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s42.BridgeCaptureS1APInformationOnRecommendedCellsAndENBsForPaging(&v, &s)
				var root aper.Snapshot
				s.
					End(f, &root, false)
				return v, root
			}
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldCompare(&sealed) = func(v s42.InformationOnRecommendedCellsAndENBsForPaging, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(
					root, budget)
				f := s.Begin()
				s42.BridgeCompareS1APInformationOnRecommendedCellsAndENBsForPaging(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InformationOnRecommendedCellsAndENBsForPaging"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldInject(&sealed) = func(value s42.InformationOnRecommendedCellsAndENBsForPaging) s56.UEContextReleaseCompleteIEValue {
			return func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(213)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowInformationOnRecommendedCellsAndENBsForPaging(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextReleaseCompleteInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldGet(&sealed) = func(value *s56.UEContextReleaseCompleteIEValue) (*s42.InformationOnRecommendedCellsAndENBsForPaging, bool) {
			return value.AsInformationOnRecommendedCellsAndENBsForPaging()
		}
		return sealed
	}()
}
func (UEContextReleaseCompleteIETable) infoCellIdentifierAndCELevelForCECapableUEs() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(212), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellIdentifierAndCELevelForCECapableUEs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-CellIdentifierAndCELevelForCECapableUEs"}}}
}

// CellIdentifierAndCELevelForCECapableUEs returns the typed binding for the CellIdentifierAndCELevelForCECapableUEs row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) CellIdentifierAndCELevelForCECapableUEs() s56.UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding {
	return func() s56.UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding {
		sealed := s56.UEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBinding{}
		*s56.BridgeUEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBindingFieldInfo(&sealed) = t.infoCellIdentifierAndCELevelForCECapableUEs()
		*s56.BridgeUEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBindingFieldCodec(&sealed) = func() s20.CellIdentifierAndCELevelForCECapableUEsValueCodec {
			sealed := s20.CellIdentifierAndCELevelForCECapableUEsValueCodec{}
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldPath(&sealed) = "CellIdentifierAndCELevelForCECapableUEs"
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CellIdentifierAndCELevelForCECapableUEs, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s20.CellIdentifierAndCELevelForCECapableUEs
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CellIdentifierAndCELevelForCECapableUEs")
				var zero s56.UEContextReleaseCompleteIEValue
				decoded, err := s56.BridgeUEContextReleaseCompleteIEValueMethodDecode(zero, s00.ProtocolIEID(212), raw)
				if err != nil {
					var empty s20.CellIdentifierAndCELevelForCECapableUEs
					return empty, runtime.WrapDecodePath(err, "CellIdentifierAndCELevelForCECapableUEs")
				}
				value, ok := decoded.AsCellIdentifierAndCELevelForCECapableUEs()
				if !ok {
					var empty s20.CellIdentifierAndCELevelForCECapableUEs
					return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-CellIdentifierAndCELevelForCECapableUEs: no selected value")
				}
				return *value, nil
			}
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldEncode(&sealed) = func(value s20.CellIdentifierAndCELevelForCECapableUEs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextReleaseCompleteIEValueMethodEncodeFresh((func() s56.UEContextReleaseCompleteIEValue {
					sealed := s56.UEContextReleaseCompleteIEValue{}
					*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(212)
					*s56.BridgeUEContextReleaseCompleteIEValueFieldRowCellIdentifierAndCELevelForCECapableUEs(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldCapture(&sealed) = func(v s20.CellIdentifierAndCELevelForCECapableUEs, options aper.DecodeState) (s20.CellIdentifierAndCELevelForCECapableUEs, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s20.BridgeCaptureS1APCellIdentifierAndCELevelForCECapableUEs(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldCompare(&sealed) = func(v s20.CellIdentifierAndCELevelForCECapableUEs, root aper.Snapshot, budget aper.DecodeBudget,
			) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s20.BridgeCompareS1APCellIdentifierAndCELevelForCECapableUEs(&v, &s)
				s.End(f, root, false)
				return s.Plan(),
					s.
						BudgetValue()
			}
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIdentifierAndCELevelForCECapableUEs"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBindingFieldInject(&sealed) = func(value s20.CellIdentifierAndCELevelForCECapableUEs) s56.UEContextReleaseCompleteIEValue {
			return func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(212)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowCellIdentifierAndCELevelForCECapableUEs(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextReleaseCompleteCellIdentifierAndCELevelForCECapableUEsIEBindingFieldGet(&sealed) = func(value *s56.UEContextReleaseCompleteIEValue) (*s20.CellIdentifierAndCELevelForCECapableUEs, bool) {
			return value.AsCellIdentifierAndCELevelForCECapableUEs()
		}
		return sealed
	}()
}
func (UEContextReleaseCompleteIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) SecondaryRATDataUsageReportList() s56.UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding {
	return func() s56.UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding {
		sealed := s56.UEContextReleaseCompleteSecondaryRATDataUsageReportListIEBinding{}
		*s56.BridgeUEContextReleaseCompleteSecondaryRATDataUsageReportListIEBindingFieldInfo(&sealed) = t.infoSecondaryRATDataUsageReportList()
		*s56.BridgeUEContextReleaseCompleteSecondaryRATDataUsageReportListIEBindingFieldCodec(&sealed) = func() s36.SecondaryRATDataUsageReportListValueCodec {
			sealed := s36.SecondaryRATDataUsageReportListValueCodec{}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
				var zero s56.UEContextReleaseCompleteIEValue
				decoded, err := s56.BridgeUEContextReleaseCompleteIEValueMethodDecode(zero, s00.ProtocolIEID(264), raw)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
				}
				value, ok := decoded.AsSecondaryRATDataUsageReportList()
				if !ok {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-SecondaryRATDataUsageReportList: no selected value")
				}
				return *value, nil
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s36.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextReleaseCompleteIEValueMethodEncodeFresh((func() s56.UEContextReleaseCompleteIEValue {
					sealed := s56.UEContextReleaseCompleteIEValue{}
					*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
					*s56.BridgeUEContextReleaseCompleteIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s36.SecondaryRATDataUsageReportList, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s36.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s36.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s36.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextReleaseCompleteSecondaryRATDataUsageReportListIEBindingFieldInject(&sealed) = func(value s36.SecondaryRATDataUsageReportList) s56.UEContextReleaseCompleteIEValue {
			return func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextReleaseCompleteSecondaryRATDataUsageReportListIEBindingFieldGet(&sealed) = func(value *s56.UEContextReleaseCompleteIEValue) (*s36.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}
		return sealed
	}()
}
func (UEContextReleaseCompleteIETable) infoTimeSinceSecondaryNodeRelease() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCompleteIEs().ID(), ID: s00.ProtocolIEID(297), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeSinceSecondaryNodeRelease"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseComplete-IEs", Row: "id-TimeSinceSecondaryNodeRelease"}}}
}

// TimeSinceSecondaryNodeRelease returns the typed binding for the TimeSinceSecondaryNodeRelease row of UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) TimeSinceSecondaryNodeRelease() s56.UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding {
	return func() s56.UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding {
		sealed := s56.UEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBinding{}
		*s56.BridgeUEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBindingFieldInfo(&sealed) = t.infoTimeSinceSecondaryNodeRelease()
		*s56.BridgeUEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBindingFieldCodec(&sealed) = func() s02.TimeSinceSecondaryNodeReleaseValueCodec {
			sealed := s02.TimeSinceSecondaryNodeReleaseValueCodec{}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldPath(&sealed) = "TimeSinceSecondaryNodeRelease"
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.TimeSinceSecondaryNodeRelease
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TimeSinceSecondaryNodeRelease")
				var zero s56.UEContextReleaseCompleteIEValue
				decoded, err := s56.BridgeUEContextReleaseCompleteIEValueMethodDecode(zero, s00.ProtocolIEID(297), raw)
				if err != nil {
					var empty s00.TimeSinceSecondaryNodeRelease
					return empty, runtime.WrapDecodePath(err, "TimeSinceSecondaryNodeRelease")
				}
				value, ok := decoded.AsTimeSinceSecondaryNodeRelease()
				if !ok {
					var empty s00.TimeSinceSecondaryNodeRelease
					return empty, fmt.Errorf("binding UEContextReleaseComplete-IEs.id-TimeSinceSecondaryNodeRelease: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldEncode(&sealed) = func(value s00.TimeSinceSecondaryNodeRelease, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextReleaseCompleteIEValueMethodEncodeFresh((func() s56.UEContextReleaseCompleteIEValue {
					sealed := s56.UEContextReleaseCompleteIEValue{}
					*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
					*s56.BridgeUEContextReleaseCompleteIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCapture(&sealed) = func(v s00.TimeSinceSecondaryNodeRelease, options aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APTimeSinceSecondaryNodeRelease(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCompare(&sealed) = func(v s00.TimeSinceSecondaryNodeRelease, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f :=
					s.Begin()
				s08.BridgeCompareS1APTimeSinceSecondaryNodeRelease(&v, &s)
				s.
					End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeSinceSecondaryNodeRelease"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBindingFieldInject(&sealed) = func(value s00.TimeSinceSecondaryNodeRelease) s56.UEContextReleaseCompleteIEValue {
			return func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextReleaseCompleteTimeSinceSecondaryNodeReleaseIEBindingFieldGet(&sealed) = func(value *s56.UEContextReleaseCompleteIEValue) (*s00.TimeSinceSecondaryNodeRelease, bool) {
			return value.AsTimeSinceSecondaryNodeRelease()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextReleaseCompleteIETable.
func (t UEContextReleaseCompleteIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s56.UEContextReleaseCompleteIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(213):
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-InformationOnRecommendedCellsAndENBsForPaging requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(212):
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-CellIdentifierAndCELevelForCECapableUEs requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(297):
		return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeSinceSecondaryNodeRelease requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s56.UEContextReleaseCompleteIEField{}, aper.OperationError(err, "Opaque")
		}
		return s56.UEContextReleaseCompleteIEField{Id: id, Criticality: criticality, Value: func() s56.UEContextReleaseCompleteIEValue {
			sealed := s56.UEContextReleaseCompleteIEValue{}
			*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = id
			*s56.BridgeUEContextReleaseCompleteIEValueFieldOpaque(&sealed) = opaque
			*s56.BridgeUEContextReleaseCompleteIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextSuspendRequestIETable struct{}

func UEContextSuspendRequestIEs() UEContextSuspendRequestIETable {
	return UEContextSuspendRequestIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextSuspendRequestIETable.
func (UEContextSuspendRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextSuspendRequestIETable.
func (UEContextSuspendRequestIETable) Table() s00.UEContextSuspendRequestIEValueIETable {
	return func() s00.UEContextSuspendRequestIEValueIETable {
		sealed := s00.UEContextSuspendRequestIEValueIETable{}
		*s00.BridgeUEContextSuspendRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextSuspendRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendRequestIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UEContextSuspendRequestIETable.
func (t UEContextSuspendRequestIETable) MMEUES1APID() s56.UEContextSuspendRequestMMEUES1APIDIEBinding {
	return func() s56.UEContextSuspendRequestMMEUES1APIDIEBinding {
		sealed := s56.UEContextSuspendRequestMMEUES1APIDIEBinding{}
		*s56.BridgeUEContextSuspendRequestMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s56.BridgeUEContextSuspendRequestMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s56.UEContextSuspendRequestIEValue
				decoded, err := s56.BridgeUEContextSuspendRequestIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding UEContextSuspendRequestIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextSuspendRequestIEValueMethodEncodeFresh((func() s56.UEContextSuspendRequestIEValue {
					sealed := s56.UEContextSuspendRequestIEValue{}
					*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s56.BridgeUEContextSuspendRequestIEValueFieldRowMMEUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APMMEUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextSuspendRequestMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s56.UEContextSuspendRequestIEValue {
			return func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextSuspendRequestMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.UEContextSuspendRequestIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}
		return sealed
	}()
}
func (UEContextSuspendRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendRequestIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UEContextSuspendRequestIETable.
func (t UEContextSuspendRequestIETable) ENBUES1APID() s56.UEContextSuspendRequestENBUES1APIDIEBinding {
	return func() s56.UEContextSuspendRequestENBUES1APIDIEBinding {
		sealed := s56.UEContextSuspendRequestENBUES1APIDIEBinding{}
		*s56.BridgeUEContextSuspendRequestENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s56.BridgeUEContextSuspendRequestENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s56.UEContextSuspendRequestIEValue
				decoded, err := s56.BridgeUEContextSuspendRequestIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding UEContextSuspendRequestIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextSuspendRequestIEValueMethodEncodeFresh((func() s56.UEContextSuspendRequestIEValue {
					sealed := s56.UEContextSuspendRequestIEValue{}
					*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s56.BridgeUEContextSuspendRequestIEValueFieldRowENBUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.ENBUES1APID, options aper.DecodeState) (s00.ENBUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APENBUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeENBUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.ENBUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APENBUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s00.BridgeENBUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextSuspendRequestENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s56.UEContextSuspendRequestIEValue {
			return func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextSuspendRequestENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s56.UEContextSuspendRequestIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}
		return sealed
	}()
}
func (UEContextSuspendRequestIETable) infoInformationOnRecommendedCellsAndENBsForPaging() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendRequestIEs().ID(), ID: s00.ProtocolIEID(213), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "InformationOnRecommendedCellsAndENBsForPaging"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendRequestIEs", Row: "id-InformationOnRecommendedCellsAndENBsForPaging"}}}
}

// InformationOnRecommendedCellsAndENBsForPaging returns the typed binding for the InformationOnRecommendedCellsAndENBsForPaging row of UEContextSuspendRequestIETable.
func (t UEContextSuspendRequestIETable) InformationOnRecommendedCellsAndENBsForPaging() s56.UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding {
	return func() s56.UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding {
		sealed := s56.UEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBinding{}
		*s56.BridgeUEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldInfo(&sealed) = t.infoInformationOnRecommendedCellsAndENBsForPaging()
		*s56.BridgeUEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldCodec(&sealed) = func() s42.InformationOnRecommendedCellsAndENBsForPagingValueCodec {
			sealed := s42.InformationOnRecommendedCellsAndENBsForPagingValueCodec{}
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldPath(&sealed) = "InformationOnRecommendedCellsAndENBsForPaging"
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s42.InformationOnRecommendedCellsAndENBsForPaging, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s42.InformationOnRecommendedCellsAndENBsForPaging
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("InformationOnRecommendedCellsAndENBsForPaging")
				var zero s56.UEContextSuspendRequestIEValue
				decoded, err := s56.BridgeUEContextSuspendRequestIEValueMethodDecode(zero, s00.ProtocolIEID(213), raw)
				if err != nil {
					var empty s42.InformationOnRecommendedCellsAndENBsForPaging
					return empty, runtime.WrapDecodePath(err, "InformationOnRecommendedCellsAndENBsForPaging")
				}
				value, ok := decoded.AsInformationOnRecommendedCellsAndENBsForPaging()
				if !ok {
					var empty s42.InformationOnRecommendedCellsAndENBsForPaging
					return empty, fmt.Errorf("binding UEContextSuspendRequestIEs.id-InformationOnRecommendedCellsAndENBsForPaging: no selected value")
				}
				return *value, nil
			}
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldEncode(&sealed) = func(value s42.InformationOnRecommendedCellsAndENBsForPaging, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextSuspendRequestIEValueMethodEncodeFresh((func() s56.UEContextSuspendRequestIEValue {
					sealed := s56.UEContextSuspendRequestIEValue{}
					*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(213)
					*s56.BridgeUEContextSuspendRequestIEValueFieldRowInformationOnRecommendedCellsAndENBsForPaging(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldCapture(&sealed) = func(v s42.InformationOnRecommendedCellsAndENBsForPaging, options aper.DecodeState) (s42.InformationOnRecommendedCellsAndENBsForPaging, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s42.BridgeCaptureS1APInformationOnRecommendedCellsAndENBsForPaging(&v, &s)
				var root aper.Snapshot
				s.
					End(f, &root, false)
				return v, root
			}
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldCompare(&sealed) = func(v s42.InformationOnRecommendedCellsAndENBsForPaging, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(
					root, budget)
				f := s.Begin()
				s42.BridgeCompareS1APInformationOnRecommendedCellsAndENBsForPaging(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s42.BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InformationOnRecommendedCellsAndENBsForPaging"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldInject(&sealed) = func(value s42.InformationOnRecommendedCellsAndENBsForPaging) s56.UEContextSuspendRequestIEValue {
			return func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(213)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowInformationOnRecommendedCellsAndENBsForPaging(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextSuspendRequestInformationOnRecommendedCellsAndENBsForPagingIEBindingFieldGet(&sealed) = func(value *s56.UEContextSuspendRequestIEValue) (*s42.InformationOnRecommendedCellsAndENBsForPaging, bool) {
			return value.AsInformationOnRecommendedCellsAndENBsForPaging()
		}
		return sealed
	}()
}
func (UEContextSuspendRequestIETable) infoCellIdentifierAndCELevelForCECapableUEs() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendRequestIEs().ID(), ID: s00.ProtocolIEID(212), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellIdentifierAndCELevelForCECapableUEs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendRequestIEs", Row: "id-CellIdentifierAndCELevelForCECapableUEs"}}}
}

// CellIdentifierAndCELevelForCECapableUEs returns the typed binding for the CellIdentifierAndCELevelForCECapableUEs row of UEContextSuspendRequestIETable.
func (t UEContextSuspendRequestIETable) CellIdentifierAndCELevelForCECapableUEs() s56.UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding {
	return func() s56.UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding {
		sealed := s56.UEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBinding{}
		*s56.BridgeUEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBindingFieldInfo(&sealed) = t.infoCellIdentifierAndCELevelForCECapableUEs()
		*s56.BridgeUEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBindingFieldCodec(&sealed) = func() s20.CellIdentifierAndCELevelForCECapableUEsValueCodec {
			sealed := s20.CellIdentifierAndCELevelForCECapableUEsValueCodec{}
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldPath(&sealed) = "CellIdentifierAndCELevelForCECapableUEs"
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CellIdentifierAndCELevelForCECapableUEs, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s20.CellIdentifierAndCELevelForCECapableUEs
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CellIdentifierAndCELevelForCECapableUEs")
				var zero s56.UEContextSuspendRequestIEValue
				decoded, err := s56.BridgeUEContextSuspendRequestIEValueMethodDecode(zero, s00.ProtocolIEID(212), raw)
				if err != nil {
					var empty s20.CellIdentifierAndCELevelForCECapableUEs
					return empty, runtime.WrapDecodePath(err, "CellIdentifierAndCELevelForCECapableUEs")
				}
				value, ok := decoded.AsCellIdentifierAndCELevelForCECapableUEs()
				if !ok {
					var empty s20.CellIdentifierAndCELevelForCECapableUEs
					return empty, fmt.Errorf("binding UEContextSuspendRequestIEs.id-CellIdentifierAndCELevelForCECapableUEs: no selected value")
				}
				return *value, nil
			}
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldEncode(&sealed) = func(value s20.CellIdentifierAndCELevelForCECapableUEs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextSuspendRequestIEValueMethodEncodeFresh((func() s56.UEContextSuspendRequestIEValue {
					sealed := s56.UEContextSuspendRequestIEValue{}
					*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(212)
					*s56.BridgeUEContextSuspendRequestIEValueFieldRowCellIdentifierAndCELevelForCECapableUEs(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldCapture(&sealed) = func(v s20.CellIdentifierAndCELevelForCECapableUEs, options aper.DecodeState) (s20.CellIdentifierAndCELevelForCECapableUEs, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s20.BridgeCaptureS1APCellIdentifierAndCELevelForCECapableUEs(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldCompare(&sealed) = func(v s20.CellIdentifierAndCELevelForCECapableUEs, root aper.Snapshot, budget aper.DecodeBudget,
			) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s20.BridgeCompareS1APCellIdentifierAndCELevelForCECapableUEs(&v, &s)
				s.End(f, root, false)
				return s.Plan(),
					s.
						BudgetValue()
			}
			*s20.BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIdentifierAndCELevelForCECapableUEs"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBindingFieldInject(&sealed) = func(value s20.CellIdentifierAndCELevelForCECapableUEs) s56.UEContextSuspendRequestIEValue {
			return func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(212)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowCellIdentifierAndCELevelForCECapableUEs(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextSuspendRequestCellIdentifierAndCELevelForCECapableUEsIEBindingFieldGet(&sealed) = func(value *s56.UEContextSuspendRequestIEValue) (*s20.CellIdentifierAndCELevelForCECapableUEs, bool) {
			return value.AsCellIdentifierAndCELevelForCECapableUEs()
		}
		return sealed
	}()
}
func (UEContextSuspendRequestIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendRequestIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendRequestIEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}

// SecondaryRATDataUsageReportList returns the typed binding for the SecondaryRATDataUsageReportList row of UEContextSuspendRequestIETable.
func (t UEContextSuspendRequestIETable) SecondaryRATDataUsageReportList() s56.UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding {
	return func() s56.UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding {
		sealed := s56.UEContextSuspendRequestSecondaryRATDataUsageReportListIEBinding{}
		*s56.BridgeUEContextSuspendRequestSecondaryRATDataUsageReportListIEBindingFieldInfo(&sealed) = t.infoSecondaryRATDataUsageReportList()
		*s56.BridgeUEContextSuspendRequestSecondaryRATDataUsageReportListIEBindingFieldCodec(&sealed) = func() s36.SecondaryRATDataUsageReportListValueCodec {
			sealed := s36.SecondaryRATDataUsageReportListValueCodec{}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecondaryRATDataUsageReportList")
				var zero s56.UEContextSuspendRequestIEValue
				decoded, err := s56.BridgeUEContextSuspendRequestIEValueMethodDecode(zero, s00.ProtocolIEID(264), raw)
				if err != nil {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
				}
				value, ok := decoded.AsSecondaryRATDataUsageReportList()
				if !ok {
					var empty s36.SecondaryRATDataUsageReportList
					return empty, fmt.Errorf("binding UEContextSuspendRequestIEs.id-SecondaryRATDataUsageReportList: no selected value")
				}
				return *value, nil
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s36.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextSuspendRequestIEValueMethodEncodeFresh((func() s56.UEContextSuspendRequestIEValue {
					sealed := s56.UEContextSuspendRequestIEValue{}
					*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
					*s56.BridgeUEContextSuspendRequestIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s36.SecondaryRATDataUsageReportList, options aper.DecodeState) (s36.SecondaryRATDataUsageReportList, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s36.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s36.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s36.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s36.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextSuspendRequestSecondaryRATDataUsageReportListIEBindingFieldInject(&sealed) = func(value s36.SecondaryRATDataUsageReportList) s56.UEContextSuspendRequestIEValue {
			return func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextSuspendRequestSecondaryRATDataUsageReportListIEBindingFieldGet(&sealed) = func(value *s56.UEContextSuspendRequestIEValue) (*s36.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}
		return sealed
	}()
}
func (UEContextSuspendRequestIETable) infoUserLocationInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendRequestIEs().ID(), ID: s00.ProtocolIEID(189), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendRequestIEs", Row: "id-UserLocationInformation"}}}
}

// UserLocationInformation returns the typed binding for the UserLocationInformation row of UEContextSuspendRequestIETable.
func (t UEContextSuspendRequestIETable) UserLocationInformation() UEContextSuspendRequestUserLocationInformationIEBinding {
	return UEContextSuspendRequestUserLocationInformationIEBinding{info: t.infoUserLocationInformation(), codec: func() s56.UserLocationInformationValueCodec {
		sealed := s56.UserLocationInformationValueCodec{}
		*s56.BridgeUserLocationInformationValueCodecFieldPath(&sealed) = "UserLocationInformation"
		*s56.BridgeUserLocationInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s55.UserLocationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UserLocationInformation")
			var zero s56.UEContextSuspendRequestIEValue
			decoded, err := s56.BridgeUEContextSuspendRequestIEValueMethodDecode(zero, s00.ProtocolIEID(189), raw)
			if err != nil {
				var empty s55.UserLocationInformation
				return empty, runtime.WrapDecodePath(err, "UserLocationInformation")
			}
			value, ok := decoded.AsUserLocationInformation()
			if !ok {
				var empty s55.UserLocationInformation
				return empty, fmt.Errorf("binding UEContextSuspendRequestIEs.id-UserLocationInformation: no selected value")
			}
			return *value, nil
		}
		*s56.BridgeUserLocationInformationValueCodecFieldEncode(&sealed) = func(value s55.UserLocationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s56.BridgeUEContextSuspendRequestIEValueMethodEncodeFresh((func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCapture(&sealed) = func(v s55.UserLocationInformation, options aper.DecodeState) (s55.UserLocationInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s55.BridgeCaptureS1APUserLocationInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s56.BridgeUserLocationInformationValueCodecFieldCompare(&sealed) = func(v s55.UserLocationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s55.BridgeCompareS1APUserLocationInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s56.BridgeUserLocationInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UserLocationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s55.UserLocationInformation) s56.UEContextSuspendRequestIEValue {
			return func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowUserLocationInformation(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s56.UEContextSuspendRequestIEValue) (*s55.UserLocationInformation, bool) {
			return value.AsUserLocationInformation()
		}}
}
func (UEContextSuspendRequestIETable) infoTimeSinceSecondaryNodeRelease() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextSuspendRequestIEs().ID(), ID: s00.ProtocolIEID(297), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeSinceSecondaryNodeRelease"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextSuspendRequestIEs", Row: "id-TimeSinceSecondaryNodeRelease"}}}
}

// TimeSinceSecondaryNodeRelease returns the typed binding for the TimeSinceSecondaryNodeRelease row of UEContextSuspendRequestIETable.
func (t UEContextSuspendRequestIETable) TimeSinceSecondaryNodeRelease() s56.UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding {
	return func() s56.UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding {
		sealed := s56.UEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBinding{}
		*s56.BridgeUEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBindingFieldInfo(&sealed) = t.infoTimeSinceSecondaryNodeRelease()
		*s56.BridgeUEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBindingFieldCodec(&sealed) = func() s02.TimeSinceSecondaryNodeReleaseValueCodec {
			sealed := s02.TimeSinceSecondaryNodeReleaseValueCodec{}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldPath(&sealed) = "TimeSinceSecondaryNodeRelease"
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.TimeSinceSecondaryNodeRelease
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TimeSinceSecondaryNodeRelease")
				var zero s56.UEContextSuspendRequestIEValue
				decoded, err := s56.BridgeUEContextSuspendRequestIEValueMethodDecode(zero, s00.ProtocolIEID(297), raw)
				if err != nil {
					var empty s00.TimeSinceSecondaryNodeRelease
					return empty, runtime.WrapDecodePath(err, "TimeSinceSecondaryNodeRelease")
				}
				value, ok := decoded.AsTimeSinceSecondaryNodeRelease()
				if !ok {
					var empty s00.TimeSinceSecondaryNodeRelease
					return empty, fmt.Errorf("binding UEContextSuspendRequestIEs.id-TimeSinceSecondaryNodeRelease: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldEncode(&sealed) = func(value s00.TimeSinceSecondaryNodeRelease, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s56.BridgeUEContextSuspendRequestIEValueMethodEncodeFresh((func() s56.UEContextSuspendRequestIEValue {
					sealed := s56.UEContextSuspendRequestIEValue{}
					*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
					*s56.BridgeUEContextSuspendRequestIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCapture(&sealed) = func(v s00.TimeSinceSecondaryNodeRelease, options aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APTimeSinceSecondaryNodeRelease(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCompare(&sealed) = func(v s00.TimeSinceSecondaryNodeRelease, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f :=
					s.Begin()
				s08.BridgeCompareS1APTimeSinceSecondaryNodeRelease(&v, &s)
				s.
					End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s02.BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeSinceSecondaryNodeRelease"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s56.BridgeUEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBindingFieldInject(&sealed) = func(value s00.TimeSinceSecondaryNodeRelease) s56.UEContextSuspendRequestIEValue {
			return func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = &value
				return sealed
			}()
		}
		*s56.BridgeUEContextSuspendRequestTimeSinceSecondaryNodeReleaseIEBindingFieldGet(&sealed) = func(value *s56.UEContextSuspendRequestIEValue) (*s00.TimeSinceSecondaryNodeRelease, bool) {
			return value.AsTimeSinceSecondaryNodeRelease()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextSuspendRequestIETable.
func (t UEContextSuspendRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s56.UEContextSuspendRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(213):
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-InformationOnRecommendedCellsAndENBsForPaging requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(212):
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CellIdentifierAndCELevelForCECapableUEs requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(189):
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UserLocationInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(297):
		return s56.UEContextSuspendRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeSinceSecondaryNodeRelease requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s56.UEContextSuspendRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s56.UEContextSuspendRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return s56.UEContextSuspendRequestIEField{Id: id, Criticality: criticality, Value: func() s56.UEContextSuspendRequestIEValue {
			sealed := s56.UEContextSuspendRequestIEValue{}
			*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = id
			*s56.BridgeUEContextSuspendRequestIEValueFieldOpaque(&sealed) = opaque
			*s56.BridgeUEContextSuspendRequestIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

// CSGMembershipInfoCodec binds the complete APER value type.
func CSGMembershipInfoCodec() s17.CSGMembershipInfoValueCodec {
	return ERABModificationIndicationIEs().CSGMembershipInfo().Codec()
}

// CellIdentifierAndCELevelForCECapableUEsCodec binds the complete APER value type.
func CellIdentifierAndCELevelForCECapableUEsCodec() s20.CellIdentifierAndCELevelForCECapableUEsValueCodec {
	return UEContextReleaseCompleteIEs().CellIdentifierAndCELevelForCECapableUEs().Codec()
}

// ERABModifyListBearerModResCodec binds the complete APER value type.
func ERABModifyListBearerModResCodec() s19.ERABModifyListBearerModResValueCodec {
	return ERABModifyResponseIEs().ERABModifyListBearerModRes().Codec()
}

// ERABNotToBeModifiedListBearerModIndCodec binds the complete APER value type.
func ERABNotToBeModifiedListBearerModIndCodec() s19.ERABNotToBeModifiedListBearerModIndValueCodec {
	return ERABModificationIndicationIEs().ERABNotToBeModifiedListBearerModInd().Codec()
}

// ERABReleaseListBearerRelCompCodec binds the complete APER value type.
func ERABReleaseListBearerRelCompCodec() s19.ERABReleaseListBearerRelCompValueCodec {
	return ERABReleaseResponseIEs().ERABReleaseListBearerRelComp().Codec()
}

// ERABSetupListBearerSUResCodec binds the complete APER value type.
func ERABSetupListBearerSUResCodec() s20.ERABSetupListBearerSUResValueCodec {
	return ERABSetupResponseIEs().ERABSetupListBearerSURes().Codec()
}

// ERABToBeModifiedListBearerModIndCodec binds the complete APER value type.
func ERABToBeModifiedListBearerModIndCodec() s20.ERABToBeModifiedListBearerModIndValueCodec {
	return ERABModificationIndicationIEs().ERABToBeModifiedListBearerModInd().Codec()
}

// HandoverFlagCodec binds the complete APER value type.
func HandoverFlagCodec() s01.HandoverFlagValueCodec {
	return SecondaryRATDataUsageReportIEs().HandoverFlag().Codec()
}

// InformationOnRecommendedCellsAndENBsForPagingCodec binds the complete APER value type.
func InformationOnRecommendedCellsAndENBsForPagingCodec() s42.InformationOnRecommendedCellsAndENBsForPagingValueCodec {
	return UEContextReleaseCompleteIEs().InformationOnRecommendedCellsAndENBsForPaging().Codec()
}

// SecondaryRATDataUsageReportListCodec binds the complete APER value type.
func SecondaryRATDataUsageReportListCodec() s36.SecondaryRATDataUsageReportListValueCodec {
	return ERABModificationIndicationIEs().SecondaryRATDataUsageReportList().Codec()
}

// TimeSinceSecondaryNodeReleaseCodec binds the complete APER value type.
func TimeSinceSecondaryNodeReleaseCodec() s02.TimeSinceSecondaryNodeReleaseValueCodec {
	return SecondaryRATDataUsageReportIEs().TimeSinceSecondaryNodeRelease().Codec()
}

// TunnelInformationCodec binds the complete APER value type.
func TunnelInformationCodec() s44.TunnelInformationValueCodec {
	return ERABModificationIndicationIEs().TunnelInformationForBBF().Codec()
}

// UserLocationInformationCodec binds the complete APER value type.
func UserLocationInformationCodec() s56.UserLocationInformationValueCodec {
	return ERABModificationIndicationIEs().UserLocationInformation().Codec()
}
func BridgeERABModificationIndicationFieldPerPadding(v *ERABModificationIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABModificationIndicationFieldReceived(v *ERABModificationIndication) *bool {
	return &v.received
}
func BridgeERABModificationIndicationFieldReceivedAbsolute(v *ERABModificationIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeERABModificationIndicationFieldReceivedBytes(v *ERABModificationIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABModificationIndicationFieldReceivedLocation(v *ERABModificationIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABModificationIndicationMethodMarshalAPERBudget(v *ERABModificationIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABModificationIndicationMethodUnmarshalAPERFrom(v *ERABModificationIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModificationIndicationMethodUnmarshalAPERWithOptions(v *ERABModificationIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABModificationIndicationValueCodecFieldCapture(v *ERABModificationIndicationValueCodec) *func(ERABModificationIndication, aper.DecodeState) (ERABModificationIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationIndicationValueCodecFieldCompare(v *ERABModificationIndicationValueCodec) *func(ERABModificationIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationIndicationValueCodecFieldContext(v *ERABModificationIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationIndicationValueCodecFieldDecode(v *ERABModificationIndicationValueCodec) *func([]byte, aper.DecodeState) (ERABModificationIndication, error) {
	return &v.decode
}
func BridgeERABModificationIndicationValueCodecFieldEncode(v *ERABModificationIndicationValueCodec) *func(ERABModificationIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationIndicationValueCodecFieldPath(v *ERABModificationIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyResponseFieldPerPadding(v *ERABModifyResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABModifyResponseFieldReceived(v *ERABModifyResponse) *bool { return &v.received }
func BridgeERABModifyResponseFieldReceivedAbsolute(v *ERABModifyResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeERABModifyResponseFieldReceivedBytes(v *ERABModifyResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABModifyResponseFieldReceivedLocation(v *ERABModifyResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABModifyResponseMethodMarshalAPERBudget(v *ERABModifyResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABModifyResponseMethodUnmarshalAPERFrom(v *ERABModifyResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModifyResponseMethodUnmarshalAPERWithOptions(v *ERABModifyResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABModifyResponseValueCodecFieldCapture(v *ERABModifyResponseValueCodec) *func(ERABModifyResponse, aper.DecodeState) (ERABModifyResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyResponseValueCodecFieldCompare(v *ERABModifyResponseValueCodec) *func(ERABModifyResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyResponseValueCodecFieldContext(v *ERABModifyResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseValueCodecFieldDecode(v *ERABModifyResponseValueCodec) *func([]byte, aper.DecodeState) (ERABModifyResponse, error) {
	return &v.decode
}
func BridgeERABModifyResponseValueCodecFieldEncode(v *ERABModifyResponseValueCodec) *func(ERABModifyResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyResponseValueCodecFieldPath(v *ERABModifyResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseIndicationFieldPerPadding(v *ERABReleaseIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABReleaseIndicationFieldReceived(v *ERABReleaseIndication) *bool { return &v.received }
func BridgeERABReleaseIndicationFieldReceivedAbsolute(v *ERABReleaseIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeERABReleaseIndicationFieldReceivedBytes(v *ERABReleaseIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABReleaseIndicationFieldReceivedLocation(v *ERABReleaseIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABReleaseIndicationMethodMarshalAPERBudget(v *ERABReleaseIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABReleaseIndicationMethodUnmarshalAPERFrom(v *ERABReleaseIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABReleaseIndicationMethodUnmarshalAPERWithOptions(v *ERABReleaseIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABReleaseIndicationValueCodecFieldCapture(v *ERABReleaseIndicationValueCodec) *func(ERABReleaseIndication, aper.DecodeState) (ERABReleaseIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseIndicationValueCodecFieldCompare(v *ERABReleaseIndicationValueCodec) *func(ERABReleaseIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseIndicationValueCodecFieldContext(v *ERABReleaseIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseIndicationValueCodecFieldDecode(v *ERABReleaseIndicationValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseIndication, error) {
	return &v.decode
}
func BridgeERABReleaseIndicationValueCodecFieldEncode(v *ERABReleaseIndicationValueCodec) *func(ERABReleaseIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseIndicationValueCodecFieldPath(v *ERABReleaseIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseResponseFieldPerPadding(v *ERABReleaseResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABReleaseResponseFieldReceived(v *ERABReleaseResponse) *bool { return &v.received }
func BridgeERABReleaseResponseFieldReceivedAbsolute(v *ERABReleaseResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeERABReleaseResponseFieldReceivedBytes(v *ERABReleaseResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABReleaseResponseFieldReceivedLocation(v *ERABReleaseResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABReleaseResponseMethodMarshalAPERBudget(v *ERABReleaseResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABReleaseResponseMethodUnmarshalAPERFrom(v *ERABReleaseResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABReleaseResponseMethodUnmarshalAPERWithOptions(v *ERABReleaseResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABReleaseResponseValueCodecFieldCapture(v *ERABReleaseResponseValueCodec) *func(ERABReleaseResponse, aper.DecodeState) (ERABReleaseResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseResponseValueCodecFieldCompare(v *ERABReleaseResponseValueCodec) *func(ERABReleaseResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseResponseValueCodecFieldContext(v *ERABReleaseResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseValueCodecFieldDecode(v *ERABReleaseResponseValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseResponse, error) {
	return &v.decode
}
func BridgeERABReleaseResponseValueCodecFieldEncode(v *ERABReleaseResponseValueCodec) *func(ERABReleaseResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseResponseValueCodecFieldPath(v *ERABReleaseResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupResponseFieldPerPadding(v *ERABSetupResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABSetupResponseFieldReceived(v *ERABSetupResponse) *bool { return &v.received }
func BridgeERABSetupResponseFieldReceivedAbsolute(v *ERABSetupResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeERABSetupResponseFieldReceivedBytes(v *ERABSetupResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABSetupResponseFieldReceivedLocation(v *ERABSetupResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABSetupResponseMethodMarshalAPERBudget(v *ERABSetupResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABSetupResponseMethodUnmarshalAPERFrom(v *ERABSetupResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSetupResponseMethodUnmarshalAPERWithOptions(v *ERABSetupResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABSetupResponseValueCodecFieldCapture(v *ERABSetupResponseValueCodec) *func(ERABSetupResponse, aper.DecodeState) (ERABSetupResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupResponseValueCodecFieldCompare(v *ERABSetupResponseValueCodec) *func(ERABSetupResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupResponseValueCodecFieldContext(v *ERABSetupResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseValueCodecFieldDecode(v *ERABSetupResponseValueCodec) *func([]byte, aper.DecodeState) (ERABSetupResponse, error) {
	return &v.decode
}
func BridgeERABSetupResponseValueCodecFieldEncode(v *ERABSetupResponseValueCodec) *func(ERABSetupResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupResponseValueCodecFieldPath(v *ERABSetupResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportFieldPerPadding(v *SecondaryRATDataUsageReport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSecondaryRATDataUsageReportFieldReceived(v *SecondaryRATDataUsageReport) *bool {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportFieldReceivedAbsolute(v *SecondaryRATDataUsageReport) *bool {
	return &v.receivedAbsolute
}
func BridgeSecondaryRATDataUsageReportFieldReceivedBytes(v *SecondaryRATDataUsageReport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSecondaryRATDataUsageReportFieldReceivedLocation(v *SecondaryRATDataUsageReport) *aper.Location {
	return &v.receivedLocation
}
func BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(v *SecondaryRATDataUsageReport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSecondaryRATDataUsageReportMethodUnmarshalAPERFrom(v *SecondaryRATDataUsageReport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecondaryRATDataUsageReportMethodUnmarshalAPERWithOptions(v *SecondaryRATDataUsageReport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldCapture(v *SecondaryRATDataUsageReportValueCodec) *func(SecondaryRATDataUsageReport, aper.DecodeState) (SecondaryRATDataUsageReport, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldCompare(v *SecondaryRATDataUsageReportValueCodec) *func(SecondaryRATDataUsageReport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldContext(v *SecondaryRATDataUsageReportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldDecode(v *SecondaryRATDataUsageReportValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReport, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldEncode(v *SecondaryRATDataUsageReportValueCodec) *func(SecondaryRATDataUsageReport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldPath(v *SecondaryRATDataUsageReportValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCompleteFieldPerPadding(v *UEContextReleaseComplete) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextReleaseCompleteFieldReceived(v *UEContextReleaseComplete) *bool {
	return &v.received
}
func BridgeUEContextReleaseCompleteFieldReceivedAbsolute(v *UEContextReleaseComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextReleaseCompleteFieldReceivedBytes(v *UEContextReleaseComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextReleaseCompleteFieldReceivedLocation(v *UEContextReleaseComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(v *UEContextReleaseComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextReleaseCompleteMethodUnmarshalAPERFrom(v *UEContextReleaseComplete, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextReleaseCompleteMethodUnmarshalAPERWithOptions(v *UEContextReleaseComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextReleaseCompleteValueCodecFieldCapture(v *UEContextReleaseCompleteValueCodec) *func(UEContextReleaseComplete, aper.DecodeState) (UEContextReleaseComplete, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCompleteValueCodecFieldCompare(v *UEContextReleaseCompleteValueCodec) *func(UEContextReleaseComplete, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCompleteValueCodecFieldContext(v *UEContextReleaseCompleteValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteValueCodecFieldDecode(v *UEContextReleaseCompleteValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseComplete, error) {
	return &v.decode
}
func BridgeUEContextReleaseCompleteValueCodecFieldEncode(v *UEContextReleaseCompleteValueCodec) *func(UEContextReleaseComplete, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCompleteValueCodecFieldPath(v *UEContextReleaseCompleteValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendRequestFieldPerPadding(v *UEContextSuspendRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextSuspendRequestFieldReceived(v *UEContextSuspendRequest) *bool { return &v.received }
func BridgeUEContextSuspendRequestFieldReceivedAbsolute(v *UEContextSuspendRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextSuspendRequestFieldReceivedBytes(v *UEContextSuspendRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextSuspendRequestFieldReceivedLocation(v *UEContextSuspendRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextSuspendRequestMethodMarshalAPERBudget(v *UEContextSuspendRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextSuspendRequestMethodUnmarshalAPERFrom(v *UEContextSuspendRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextSuspendRequestMethodUnmarshalAPERWithOptions(v *UEContextSuspendRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextSuspendRequestValueCodecFieldCapture(v *UEContextSuspendRequestValueCodec) *func(UEContextSuspendRequest, aper.DecodeState) (UEContextSuspendRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendRequestValueCodecFieldCompare(v *UEContextSuspendRequestValueCodec) *func(UEContextSuspendRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendRequestValueCodecFieldContext(v *UEContextSuspendRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestValueCodecFieldDecode(v *UEContextSuspendRequestValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendRequest, error) {
	return &v.decode
}
func BridgeUEContextSuspendRequestValueCodecFieldEncode(v *UEContextSuspendRequestValueCodec) *func(UEContextSuspendRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendRequestValueCodecFieldPath(v *UEContextSuspendRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeV2XServicesAuthorizedFieldPerPadding(v *V2XServicesAuthorized) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeV2XServicesAuthorizedFieldReceived(v *V2XServicesAuthorized) *bool { return &v.received }
func BridgeV2XServicesAuthorizedFieldReceivedBytes(v *V2XServicesAuthorized) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeV2XServicesAuthorizedFieldReceivedLocation(v *V2XServicesAuthorized) *aper.Location {
	return &v.receivedLocation
}
func BridgeV2XServicesAuthorizedMethodMarshalAPERBudget(v *V2XServicesAuthorized, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeV2XServicesAuthorizedMethodUnmarshalAPERFrom(v *V2XServicesAuthorized, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
