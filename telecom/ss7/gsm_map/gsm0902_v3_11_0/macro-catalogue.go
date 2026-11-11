// Code generated from native Q.773 (11/1988) Annex A macro bindings. DO NOT EDIT.

package gsm0902_v3_11_0

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// MacroType binds a native NamedType to its statically typed generated codec.
// It does not replace a source type with an opaque wire container.
type MacroType struct {
	Module, ASN1Name, GoName string
	decode                   func([]byte, ...ber.DecodeOption) (any, error)
	encode                   func(any, ...ber.EncodeOption) ([]byte, error)
}

func (t *MacroType) DecodeBER(data []byte, opts ...ber.DecodeOption) (any, error) {
	if t == nil {
		return nil, ber.ErrInvalidCodec
	}
	return t.decode(data, opts...)
}
func (t *MacroType) EncodeBER(value any, opts ...ber.EncodeOption) ([]byte, error) {
	if t == nil {
		return nil, ber.ErrInvalidCodec
	}
	return t.encode(value, opts...)
}
func newMacroType[T any](module, name, goName string, codec ValueCodec[T]) *MacroType {
	return &MacroType{Module: module, ASN1Name: name, GoName: goName, decode: func(data []byte, opts ...ber.DecodeOption) (any, error) {
		v, err := codec.DecodeBER(data, opts...)
		if err != nil {
			return nil, err
		}
		return v, nil
	}, encode: func(value any, opts ...ber.EncodeOption) ([]byte, error) {
		v, ok := value.(T)
		if !ok {
			return nil, fmt.Errorf("%w: native macro role expects %s.%s", ber.ErrInvalidValue, module, name)
		}
		return codec.EncodeBER(v, opts...)
	}}
}

// MacroReference retains the original ERRORS or LINKED reference family.
type MacroReference struct {
	Module, Name, DefinitionModule, Definition string
	IsValue                                    bool
}

// MacroOperation preserves absent, empty and typed RESULT independently.
type MacroOperation struct {
	Name, Definition, Module                    string
	Code                                        int64
	Argument, Result                            *MacroType
	ResultPresent, ErrorsPresent, LinkedPresent bool
	Errors, Linked                              []MacroReference
}
type MacroError struct {
	Name, Definition, Module string
	Code                     int64
	Parameter                *MacroType
}

func buildMacroOperation0() MacroOperation {
	return MacroOperation{Name: "activateSS", Definition: "ActivateSS", Module: "MAP-Operations", Code: 12, Argument: newMacroType("MAP-Operations", "ActivateSS.argument", "ActivateSSArgument", ActivateSSArgumentCodec()), Result: newMacroType("MAP-DataTypes", "SS-Information", "SSInformation", SSInformationCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "NegativePasswordCheck", DefinitionModule: "MAP-Errors", Definition: "NegativePasswordCheck", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSS-Operation", DefinitionModule: "MAP-Errors", Definition: "IllegalSS-Operation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-ErrorStatus", DefinitionModule: "MAP-Errors", Definition: "SS-ErrorStatus", IsValue: false}, {Module: "MAP-Errors", Name: "SS-NotAvailable", DefinitionModule: "MAP-Errors", Definition: "SS-NotAvailable", IsValue: false}, {Module: "MAP-Errors", Name: "SS-SubscriptionViolation", DefinitionModule: "MAP-Errors", Definition: "SS-SubscriptionViolation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-Incompatibility", DefinitionModule: "MAP-Errors", Definition: "SS-Incompatibility", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}}, Linked: nil}
}
func buildMacroOperation1() MacroOperation {
	return MacroOperation{Name: "activateTraceMode", Definition: "ActivateTraceMode", Module: "MAP-Operations", Code: 50, Argument: newMacroType("MAP-Operations", "ActivateTraceMode.argument", "ActivateTraceModeArgument", ActivateTraceModeArgumentCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "TracingBufferFull", DefinitionModule: "MAP-Errors", Definition: "TracingBufferFull", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation2() MacroOperation {
	return MacroOperation{Name: "alertServiceCentre", Definition: "AlertServiceCentre", Module: "MAP-Operations", Code: 49, Argument: newMacroType("MAP-Operations", "AlertServiceCentre.argument", "AlertServiceCentreArgument", AlertServiceCentreArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation3() MacroOperation {
	return MacroOperation{Name: "allocateHandoverNumber", Definition: "AllocateHandoverNumber", Module: "MAP-Operations", Code: 31, Argument: nil, Result: nil, ResultPresent: false, ErrorsPresent: true, LinkedPresent: true, Errors: []MacroReference{{Module: "MAP-Errors", Name: "NoHandoverNumberAvailable", DefinitionModule: "MAP-Errors", Definition: "NoHandoverNumberAvailable", IsValue: false}}, Linked: []MacroReference{{Module: "MAP-Operations", Name: "SendHandoverReport", DefinitionModule: "MAP-Operations", Definition: "SendHandoverReport", IsValue: false}}}
}
func buildMacroOperation4() MacroOperation {
	return MacroOperation{Name: "attachIMSI", Definition: "AttachIMSI", Module: "MAP-Operations", Code: 6, Argument: newMacroType("MAP-DataTypes", "SubscriberId", "SubscriberId", SubscriberIdCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalMS", DefinitionModule: "MAP-Errors", Definition: "IllegalMS", IsValue: false}, {Module: "MAP-Errors", Name: "RoamingNotAllowed", DefinitionModule: "MAP-Errors", Definition: "RoamingNotAllowed", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation5() MacroOperation {
	return MacroOperation{Name: "authenticate", Definition: "Authenticate", Module: "MAP-Operations", Code: 39, Argument: newMacroType("MAP-Operations", "Authenticate.argument", "AuthenticateArgument", AuthenticateArgumentCodec()), Result: newMacroType("MAP-DataTypes", "Sres", "Sres", SresCodec()), ResultPresent: true, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation6() MacroOperation {
	return MacroOperation{Name: "beginSubscriberActivity", Definition: "BeginSubscriberActivity", Module: "MAP-Operations", Code: 54, Argument: newMacroType("MAP-Operations", "BeginSubscriberActivity.argument", "BeginSubscriberActivityArgument", BeginSubscriberActivityArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation7() MacroOperation {
	return MacroOperation{Name: "cancelLocation", Definition: "CancelLocation", Module: "MAP-Operations", Code: 3, Argument: newMacroType("MAP-Operations", "CancelLocation.argument", "CancelLocationArgument", CancelLocationArgumentCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation8() MacroOperation {
	return MacroOperation{Name: "checkIMEI", Definition: "CheckIMEI", Module: "MAP-Operations", Code: 43, Argument: newMacroType("MAP-DataTypes", "IMEI", "IMEI", IMEICodec()), Result: newMacroType("MAP-DataTypes", "EquipStatus", "EquipStatus", EquipStatusCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownEquipment", DefinitionModule: "MAP-Errors", Definition: "UnknownEquipment", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation9() MacroOperation {
	return MacroOperation{Name: "completeCall", Definition: "CompleteCall", Module: "MAP-Operations", Code: 23, Argument: newMacroType("MAP-Operations", "CompleteCall.argument", "CompleteCallArgument", CompleteCallArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "NoSubscriberReply", DefinitionModule: "MAP-Errors", Definition: "NoSubscriberReply", IsValue: false}, {Module: "MAP-Errors", Name: "RadioCongestion", DefinitionModule: "MAP-Errors", Definition: "RadioCongestion", IsValue: false}, {Module: "MAP-Errors", Name: "BusySubscriber", DefinitionModule: "MAP-Errors", Definition: "BusySubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation10() MacroOperation {
	return MacroOperation{Name: "connectToFollowingAddress", Definition: "ConnectToFollowingAddress", Module: "MAP-Operations", Code: 24, Argument: newMacroType("MAP-Operations", "ConnectToFollowingAddress.argument", "ConnectToFollowingAddressArgument", ConnectToFollowingAddressArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation11() MacroOperation {
	return MacroOperation{Name: "deactivateSS", Definition: "DeactivateSS", Module: "MAP-Operations", Code: 13, Argument: newMacroType("MAP-Operations", "DeactivateSS.argument", "DeactivateSSArgument", DeactivateSSArgumentCodec()), Result: newMacroType("MAP-DataTypes", "SS-Information", "SSInformation", SSInformationCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSS-Operation", DefinitionModule: "MAP-Errors", Definition: "IllegalSS-Operation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-ErrorStatus", DefinitionModule: "MAP-Errors", Definition: "SS-ErrorStatus", IsValue: false}, {Module: "MAP-Errors", Name: "SS-SubscriptionViolation", DefinitionModule: "MAP-Errors", Definition: "SS-SubscriptionViolation", IsValue: false}, {Module: "MAP-Errors", Name: "NegativePasswordCheck", DefinitionModule: "MAP-Errors", Definition: "NegativePasswordCheck", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}}, Linked: nil}
}
func buildMacroOperation12() MacroOperation {
	return MacroOperation{Name: "deactivateTraceMode", Definition: "DeactivateTraceMode", Module: "MAP-Operations", Code: 51, Argument: newMacroType("MAP-Operations", "DeactivateTraceMode.argument", "DeactivateTraceModeArgument", DeactivateTraceModeArgumentCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation13() MacroOperation {
	return MacroOperation{Name: "deleteSubscriberData", Definition: "DeleteSubscriberData", Module: "MAP-Operations", Code: 8, Argument: newMacroType("MAP-Operations", "DeleteSubscriberData.argument", "DeleteSubscriberDataArgument", DeleteSubscriberDataArgumentCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation14() MacroOperation {
	return MacroOperation{Name: "detachIMSI", Definition: "DetachIMSI", Module: "MAP-Operations", Code: 5, Argument: newMacroType("MAP-DataTypes", "SubscriberId", "SubscriberId", SubscriberIdCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation15() MacroOperation {
	return MacroOperation{Name: "eraseSS", Definition: "EraseSS", Module: "MAP-Operations", Code: 11, Argument: newMacroType("MAP-Operations", "EraseSS.argument", "EraseSSArgument", EraseSSArgumentCodec()), Result: newMacroType("MAP-DataTypes", "SS-Information", "SSInformation", SSInformationCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "NegativePasswordCheck", DefinitionModule: "MAP-Errors", Definition: "NegativePasswordCheck", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSS-Operation", DefinitionModule: "MAP-Errors", Definition: "IllegalSS-Operation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-ErrorStatus", DefinitionModule: "MAP-Errors", Definition: "SS-ErrorStatus", IsValue: false}, {Module: "MAP-Errors", Name: "SS-SubscriptionViolation", DefinitionModule: "MAP-Errors", Definition: "SS-SubscriptionViolation", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}}, Linked: nil}
}
func buildMacroOperation16() MacroOperation {
	return MacroOperation{Name: "forwardAccessSignalling", Definition: "ForwardAccessSignalling", Module: "MAP-Operations", Code: 34, Argument: newMacroType("MAP-DataTypes", "ExternalSignalInfo", "ExternalSignalInfo", ExternalSignalInfoCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation17() MacroOperation {
	return MacroOperation{Name: "forwardCheckSsIndication", Definition: "ForwardCheckSsIndication", Module: "MAP-Operations", Code: 38, Argument: nil, Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation18() MacroOperation {
	return MacroOperation{Name: "forwardNewTMSI", Definition: "ForwardNewTMSI", Module: "MAP-Operations", Code: 41, Argument: newMacroType("MAP-DataTypes", "TMSI", "TMSI", TMSICodec()), Result: nil, ResultPresent: true, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation19() MacroOperation {
	return MacroOperation{Name: "forwardShortMessage", Definition: "ForwardShortMessage", Module: "MAP-Operations", Code: 46, Argument: newMacroType("MAP-Operations", "ForwardShortMessage.argument", "ForwardShortMessageArgument", ForwardShortMessageArgumentCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalMS", DefinitionModule: "MAP-Errors", Definition: "IllegalMS", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "SM-DeliveryFailure", DefinitionModule: "MAP-Errors", Definition: "SM-DeliveryFailure", IsValue: false}}, Linked: nil}
}
func buildMacroOperation20() MacroOperation {
	return MacroOperation{Name: "forwardSsNotification", Definition: "ForwardSsNotification", Module: "MAP-Operations", Code: 16, Argument: newMacroType("MAP-Operations", "ForwardSsNotification.argument", "ForwardSsNotificationArgument", ForwardSsNotificationArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation21() MacroOperation {
	return MacroOperation{Name: "getPassword", Definition: "GetPassword", Module: "MAP-Operations", Code: 18, Argument: newMacroType("MAP-DataTypes", "GuidanceInfo", "GuidanceInfo", GuidanceInfoCodec()), Result: newMacroType("MAP-DataTypes", "Password", "Password", PasswordCodec()), ResultPresent: true, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation22() MacroOperation {
	return MacroOperation{Name: "insertSubscriberData", Definition: "InsertSubscriberData", Module: "MAP-Operations", Code: 7, Argument: newMacroType("MAP-Operations", "InsertSubscriberData.argument", "InsertSubscriberDataArgument", InsertSubscriberDataArgumentCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation23() MacroOperation {
	return MacroOperation{Name: "interrogateSS", Definition: "InterrogateSS", Module: "MAP-Operations", Code: 14, Argument: newMacroType("MAP-Operations", "InterrogateSS.argument", "InterrogateSSArgument", InterrogateSSArgumentCodec()), Result: newMacroType("MAP-Operations", "InterrogateSS.result", "InterrogateSSResult", InterrogateSSResultCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "NegativePasswordCheck", DefinitionModule: "MAP-Errors", Definition: "NegativePasswordCheck", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSS-Operation", DefinitionModule: "MAP-Errors", Definition: "IllegalSS-Operation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-NotAvailable", DefinitionModule: "MAP-Errors", Definition: "SS-NotAvailable", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}}, Linked: nil}
}
func buildMacroOperation24() MacroOperation {
	return MacroOperation{Name: "invokeSS", Definition: "InvokeSS", Module: "MAP-Operations", Code: 15, Argument: newMacroType("MAP-Operations", "InvokeSS.argument", "InvokeSSArgument", InvokeSSArgumentCodec()), Result: newMacroType("MAP-DataTypes", "CUG-Interlock", "CUGInterlock", CUGInterlockCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "IllegalSS-Operation", DefinitionModule: "MAP-Errors", Definition: "IllegalSS-Operation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-ErrorStatus", DefinitionModule: "MAP-Errors", Definition: "SS-ErrorStatus", IsValue: false}, {Module: "MAP-Errors", Name: "SS-NotAvailable", DefinitionModule: "MAP-Errors", Definition: "SS-NotAvailable", IsValue: false}, {Module: "MAP-Errors", Name: "SS-SubscriptionViolation", DefinitionModule: "MAP-Errors", Definition: "SS-SubscriptionViolation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-Incompatibility", DefinitionModule: "MAP-Errors", Definition: "SS-Incompatibility", IsValue: false}, {Module: "MAP-Errors", Name: "CUG-Reject", DefinitionModule: "MAP-Errors", Definition: "CUG-Reject", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}}, Linked: nil}
}
func buildMacroOperation25() MacroOperation {
	return MacroOperation{Name: "noteInternalHandover", Definition: "NoteInternalHandover", Module: "MAP-Operations", Code: 35, Argument: newMacroType("MAP-Operations", "NoteInternalHandover.argument", "NoteInternalHandoverArgument", NoteInternalHandoverArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation26() MacroOperation {
	return MacroOperation{Name: "noteMSPresent", Definition: "NoteMSPresent", Module: "MAP-Operations", Code: 48, Argument: newMacroType("MAP-DataTypes", "IMSI", "IMSI", IMSICodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation27() MacroOperation {
	return MacroOperation{Name: "page", Definition: "Page", Module: "MAP-Operations", Code: 26, Argument: newMacroType("MAP-Operations", "Page.argument", "PageArgument", PageArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownLocArea", DefinitionModule: "MAP-Errors", Definition: "UnknownLocArea", IsValue: false}, {Module: "MAP-Errors", Name: "BusySubscriber", DefinitionModule: "MAP-Errors", Definition: "BusySubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation28() MacroOperation {
	return MacroOperation{Name: "performHandover", Definition: "PerformHandover", Module: "MAP-Operations", Code: 28, Argument: newMacroType("MAP-Operations", "PerformHandover.argument", "PerformHandoverArgument", PerformHandoverArgumentCodec()), Result: newMacroType("MAP-Operations", "PerformHandover.result", "PerformHandoverResult", PerformHandoverResultCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownBaseStation", DefinitionModule: "MAP-Errors", Definition: "UnknownBaseStation", IsValue: false}, {Module: "MAP-Errors", Name: "InvalidTargetBaseStation", DefinitionModule: "MAP-Errors", Definition: "InvalidTargetBaseStation", IsValue: false}, {Module: "MAP-Errors", Name: "NoRadioResourceAvailable", DefinitionModule: "MAP-Errors", Definition: "NoRadioResourceAvailable", IsValue: false}, {Module: "MAP-Errors", Name: "NoHandoverNumberAvailable", DefinitionModule: "MAP-Errors", Definition: "NoHandoverNumberAvailable", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation29() MacroOperation {
	return MacroOperation{Name: "performSubsequentHandover", Definition: "PerformSubsequentHandover", Module: "MAP-Operations", Code: 30, Argument: newMacroType("MAP-Operations", "PerformSubsequentHandover.argument", "PerformSubsequentHandoverArgument", PerformSubsequentHandoverArgumentCodec()), Result: newMacroType("MAP-DataTypes", "ExternalSignalInfo", "ExternalSignalInfo", ExternalSignalInfoCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownBaseStation", DefinitionModule: "MAP-Errors", Definition: "UnknownBaseStation", IsValue: false}, {Module: "MAP-Errors", Name: "InvalidTargetBaseStation", DefinitionModule: "MAP-Errors", Definition: "InvalidTargetBaseStation", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownMSC", DefinitionModule: "MAP-Errors", Definition: "UnknownMSC", IsValue: false}, {Module: "MAP-Errors", Name: "SubsequentHandoverFailure", DefinitionModule: "MAP-Errors", Definition: "SubsequentHandoverFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation30() MacroOperation {
	return MacroOperation{Name: "processAccessRequest", Definition: "ProcessAccessRequest", Module: "MAP-Operations", Code: 53, Argument: newMacroType("MAP-Operations", "ProcessAccessRequest.argument", "ProcessAccessRequestArgument", ProcessAccessRequestArgumentCodec()), Result: newMacroType("MAP-Operations", "ProcessAccessRequest.result", "ProcessAccessRequestResult", ProcessAccessRequestResultCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "IllegalMS", DefinitionModule: "MAP-Errors", Definition: "IllegalMS", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation31() MacroOperation {
	return MacroOperation{Name: "processAccessSignalling", Definition: "ProcessAccessSignalling", Module: "MAP-Operations", Code: 33, Argument: newMacroType("MAP-DataTypes", "ExternalSignalInfo", "ExternalSignalInfo", ExternalSignalInfoCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation32() MacroOperation {
	return MacroOperation{Name: "processCallWaiting", Definition: "ProcessCallWaiting", Module: "MAP-Operations", Code: 25, Argument: nil, Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation33() MacroOperation {
	return MacroOperation{Name: "processUnstructuredSsData", Definition: "ProcessUnstructuredSsData", Module: "MAP-Operations", Code: 19, Argument: newMacroType("MAP-DataTypes", "SS-UserData", "SSUserData", SSUserDataCodec()), Result: newMacroType("MAP-DataTypes", "SS-UserData", "SSUserData", SSUserDataCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}}, Linked: nil}
}
func buildMacroOperation34() MacroOperation {
	return MacroOperation{Name: "provideIMSi", Definition: "ProvideIMSI", Module: "MAP-Operations", Code: 40, Argument: nil, Result: newMacroType("MAP-DataTypes", "IMSI", "IMSI", IMSICodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}}, Linked: nil}
}
func buildMacroOperation35() MacroOperation {
	return MacroOperation{Name: "provideRoamingNumber", Definition: "ProvideRoamingNumber", Module: "MAP-Operations", Code: 4, Argument: newMacroType("MAP-Operations", "ProvideRoamingNumber.argument", "ProvideRoamingNumberArgument", ProvideRoamingNumberArgumentCodec()), Result: newMacroType("MAP-DataTypes", "IsdnAddressString", "IsdnAddressString", IsdnAddressStringCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "NoRoamingNumberAvailable", DefinitionModule: "MAP-Errors", Definition: "NoRoamingNumberAvailable", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation36() MacroOperation {
	return MacroOperation{Name: "registerChargingInformation", Definition: "RegisterChargingInformation", Module: "MAP-Operations", Code: 36, Argument: newMacroType("MAP-Operations", "RegisterChargingInformation.argument", "RegisterChargingInformationArgument", RegisterChargingInformationArgumentCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation37() MacroOperation {
	return MacroOperation{Name: "registerPassword", Definition: "RegisterPassword", Module: "MAP-Operations", Code: 17, Argument: newMacroType("MAP-DataTypes", "SS-Code", "SSCode", SSCodeCodec()), Result: newMacroType("MAP-DataTypes", "Password", "Password", PasswordCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: true, Errors: []MacroReference{{Module: "MAP-Errors", Name: "NegativePasswordCheck", DefinitionModule: "MAP-Errors", Definition: "NegativePasswordCheck", IsValue: false}, {Module: "MAP-Errors", Name: "PasswordRegistrationFailure", DefinitionModule: "MAP-Errors", Definition: "PasswordRegistrationFailure", IsValue: false}, {Module: "MAP-Errors", Name: "SS-SubscriptionViolation", DefinitionModule: "MAP-Errors", Definition: "SS-SubscriptionViolation", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}}, Linked: []MacroReference{{Module: "MAP-Operations", Name: "GetPassword", DefinitionModule: "MAP-Operations", Definition: "GetPassword", IsValue: false}}}
}
func buildMacroOperation38() MacroOperation {
	return MacroOperation{Name: "registerSS", Definition: "RegisterSS", Module: "MAP-Operations", Code: 10, Argument: newMacroType("MAP-Operations", "RegisterSS.argument", "RegisterSSArgument", RegisterSSArgumentCodec()), Result: newMacroType("MAP-DataTypes", "SS-Information", "SSInformation", SSInformationCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSS-Operation", DefinitionModule: "MAP-Errors", Definition: "IllegalSS-Operation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-ErrorStatus", DefinitionModule: "MAP-Errors", Definition: "SS-ErrorStatus", IsValue: false}, {Module: "MAP-Errors", Name: "SS-NotAvailable", DefinitionModule: "MAP-Errors", Definition: "SS-NotAvailable", IsValue: false}, {Module: "MAP-Errors", Name: "BearerServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "BearerServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "TeleServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "TeleServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "SS-SubscriptionViolation", DefinitionModule: "MAP-Errors", Definition: "SS-SubscriptionViolation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-Incompatibility", DefinitionModule: "MAP-Errors", Definition: "SS-Incompatibility", IsValue: false}, {Module: "MAP-Errors", Name: "NegativePasswordCheck", DefinitionModule: "MAP-Errors", Definition: "NegativePasswordCheck", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}}, Linked: nil}
}
func buildMacroOperation39() MacroOperation {
	return MacroOperation{Name: "reset", Definition: "Reset", Module: "MAP-Operations", Code: 37, Argument: newMacroType("MAP-Operations", "Reset.argument", "ResetArgument", ResetArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation40() MacroOperation {
	return MacroOperation{Name: "searchForMobileSubscriber", Definition: "SearchForMobileSubscriber", Module: "MAP-Operations", Code: 27, Argument: newMacroType("MAP-Operations", "SearchForMobileSubscriber.argument", "SearchForMobileSubscriberArgument", SearchForMobileSubscriberArgumentCodec()), Result: newMacroType("MAP-DataTypes", "LocAreaId", "LocAreaId", LocAreaIdCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "BusySubscriber", DefinitionModule: "MAP-Errors", Definition: "BusySubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation41() MacroOperation {
	return MacroOperation{Name: "sendEndSignal", Definition: "SendEndSignal", Module: "MAP-Operations", Code: 29, Argument: nil, Result: nil, ResultPresent: true, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation42() MacroOperation {
	return MacroOperation{Name: "sendHandoverReport", Definition: "SendHandoverReport", Module: "MAP-Operations", Code: 32, Argument: newMacroType("MAP-DataTypes", "IsdnAddressString", "IsdnAddressString", IsdnAddressStringCodec()), Result: nil, ResultPresent: true, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation43() MacroOperation {
	return MacroOperation{Name: "sendInfoForIncomingCall", Definition: "SendInfoForIncomingCall", Module: "MAP-Operations", Code: 20, Argument: newMacroType("MAP-Operations", "SendInfoForIncomingCall.argument", "SendInfoForIncomingCallArgument", SendInfoForIncomingCallArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: true, LinkedPresent: true, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnallocatedRoamingNumber", DefinitionModule: "MAP-Errors", Definition: "UnallocatedRoamingNumber", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "ImpossibleCallCompletion", DefinitionModule: "MAP-Errors", Definition: "ImpossibleCallCompletion", IsValue: false}, {Module: "MAP-Errors", Name: "ForwardingViolation", DefinitionModule: "MAP-Errors", Definition: "ForwardingViolation", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}}, Linked: []MacroReference{{Module: "MAP-Operations", Name: "CompleteCall", DefinitionModule: "MAP-Operations", Definition: "CompleteCall", IsValue: false}, {Module: "MAP-Operations", Name: "ProcessCallWaiting", DefinitionModule: "MAP-Operations", Definition: "ProcessCallWaiting", IsValue: false}, {Module: "MAP-Operations", Name: "ConnectToFollowingAddress", DefinitionModule: "MAP-Operations", Definition: "ConnectToFollowingAddress", IsValue: false}}}
}
func buildMacroOperation44() MacroOperation {
	return MacroOperation{Name: "sendInfoForOutgoingCall", Definition: "SendInfoForOutgoingCall", Module: "MAP-Operations", Code: 21, Argument: newMacroType("MAP-Operations", "SendInfoForOutgoingCall.argument", "SendInfoForOutgoingCallArgument", SendInfoForOutgoingCallArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: true, LinkedPresent: true, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "BearerServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "BearerServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "TeleServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "TeleServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}, {Module: "MAP-Errors", Name: "CUG-Reject", DefinitionModule: "MAP-Errors", Definition: "CUG-Reject", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}}, Linked: []MacroReference{{Module: "MAP-Operations", Name: "CompleteCall", DefinitionModule: "MAP-Operations", Definition: "CompleteCall", IsValue: false}}}
}
func buildMacroOperation45() MacroOperation {
	return MacroOperation{Name: "sendParameters", Definition: "SendParameters", Module: "MAP-Operations", Code: 9, Argument: newMacroType("MAP-Operations", "SendParameters.argument", "SendParametersArgument", SendParametersArgumentCodec()), Result: newMacroType("MAP-DataTypes", "SentParameters", "SentParameters", SentParametersCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation46() MacroOperation {
	return MacroOperation{Name: "sendRoutingInfoForSM", Definition: "SendRoutingInfoForSM", Module: "MAP-Operations", Code: 45, Argument: newMacroType("MAP-Operations", "SendRoutingInfoForSM.argument", "SendRoutingInfoForSMArgument", SendRoutingInfoForSMArgumentCodec()), Result: newMacroType("MAP-Operations", "SendRoutingInfoForSM.result", "SendRoutingInfoForSMResult", SendRoutingInfoForSMResultCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}, {Module: "MAP-Errors", Name: "CUG-Reject", DefinitionModule: "MAP-Errors", Definition: "CUG-Reject", IsValue: false}, {Module: "MAP-Errors", Name: "TeleServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "TeleServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation47() MacroOperation {
	return MacroOperation{Name: "sendRoutingInformation", Definition: "SendRoutingInformation", Module: "MAP-Operations", Code: 22, Argument: newMacroType("MAP-Operations", "SendRoutingInformation.argument", "SendRoutingInformationArgument", SendRoutingInformationArgumentCodec()), Result: newMacroType("MAP-Operations", "SendRoutingInformation.result", "SendRoutingInformationResult", SendRoutingInformationResultCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}, {Module: "MAP-Errors", Name: "CUG-Reject", DefinitionModule: "MAP-Errors", Definition: "CUG-Reject", IsValue: false}, {Module: "MAP-Errors", Name: "BearerServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "BearerServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "TeleServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "TeleServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "ForwardingViolation", DefinitionModule: "MAP-Errors", Definition: "ForwardingViolation", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation48() MacroOperation {
	return MacroOperation{Name: "setCipheringMode", Definition: "SetCipheringMode", Module: "MAP-Operations", Code: 42, Argument: newMacroType("MAP-Operations", "SetCipheringMode.argument", "SetCipheringModeArgument", SetCipheringModeArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation49() MacroOperation {
	return MacroOperation{Name: "setMessageWaitingData", Definition: "SetMessageWaitingData", Module: "MAP-Operations", Code: 47, Argument: newMacroType("MAP-Operations", "SetMessageWaitingData.argument", "SetMessageWaitingDataArgument", SetMessageWaitingDataArgumentCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "MessageWaitingListFull", DefinitionModule: "MAP-Errors", Definition: "MessageWaitingListFull", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation50() MacroOperation {
	return MacroOperation{Name: "traceSubscriberActivity", Definition: "TraceSubscriberActivity", Module: "MAP-Operations", Code: 52, Argument: newMacroType("MAP-Operations", "TraceSubscriberActivity.argument", "TraceSubscriberActivityArgument", TraceSubscriberActivityArgumentCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation51() MacroOperation {
	return MacroOperation{Name: "updateLocation", Definition: "UpdateLocation", Module: "MAP-Operations", Code: 2, Argument: newMacroType("MAP-Operations", "UpdateLocation.argument", "UpdateLocationArgument", UpdateLocationArgumentCodec()), Result: newMacroType("MAP-DataTypes", "IsdnAddressString", "IsdnAddressString", IsdnAddressStringCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "RoamingNotAllowed", DefinitionModule: "MAP-Errors", Definition: "RoamingNotAllowed", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation52() MacroOperation {
	return MacroOperation{Name: "updateLocationArea", Definition: "UpdateLocationArea", Module: "MAP-Operations", Code: 1, Argument: newMacroType("MAP-Operations", "UpdateLocationArea.argument", "UpdateLocationAreaArgument", UpdateLocationAreaArgumentCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownLocArea", DefinitionModule: "MAP-Errors", Definition: "UnknownLocArea", IsValue: false}, {Module: "MAP-Errors", Name: "RoamingNotAllowed", DefinitionModule: "MAP-Errors", Definition: "RoamingNotAllowed", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalMS", DefinitionModule: "MAP-Errors", Definition: "IllegalMS", IsValue: false}, {Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func MacroOperations() []MacroOperation {
	return []MacroOperation{
		buildMacroOperation0(),
		buildMacroOperation1(),
		buildMacroOperation2(),
		buildMacroOperation3(),
		buildMacroOperation4(),
		buildMacroOperation5(),
		buildMacroOperation6(),
		buildMacroOperation7(),
		buildMacroOperation8(),
		buildMacroOperation9(),
		buildMacroOperation10(),
		buildMacroOperation11(),
		buildMacroOperation12(),
		buildMacroOperation13(),
		buildMacroOperation14(),
		buildMacroOperation15(),
		buildMacroOperation16(),
		buildMacroOperation17(),
		buildMacroOperation18(),
		buildMacroOperation19(),
		buildMacroOperation20(),
		buildMacroOperation21(),
		buildMacroOperation22(),
		buildMacroOperation23(),
		buildMacroOperation24(),
		buildMacroOperation25(),
		buildMacroOperation26(),
		buildMacroOperation27(),
		buildMacroOperation28(),
		buildMacroOperation29(),
		buildMacroOperation30(),
		buildMacroOperation31(),
		buildMacroOperation32(),
		buildMacroOperation33(),
		buildMacroOperation34(),
		buildMacroOperation35(),
		buildMacroOperation36(),
		buildMacroOperation37(),
		buildMacroOperation38(),
		buildMacroOperation39(),
		buildMacroOperation40(),
		buildMacroOperation41(),
		buildMacroOperation42(),
		buildMacroOperation43(),
		buildMacroOperation44(),
		buildMacroOperation45(),
		buildMacroOperation46(),
		buildMacroOperation47(),
		buildMacroOperation48(),
		buildMacroOperation49(),
		buildMacroOperation50(),
		buildMacroOperation51(),
		buildMacroOperation52(),
	}
}

// LookupMacroOperation returns detached metadata and builds only the requested entry.
func LookupMacroOperation(code int64) (MacroOperation, bool) {
	switch code {
	case 12:
		return buildMacroOperation0(), true
	case 50:
		return buildMacroOperation1(), true
	case 49:
		return buildMacroOperation2(), true
	case 31:
		return buildMacroOperation3(), true
	case 6:
		return buildMacroOperation4(), true
	case 39:
		return buildMacroOperation5(), true
	case 54:
		return buildMacroOperation6(), true
	case 3:
		return buildMacroOperation7(), true
	case 43:
		return buildMacroOperation8(), true
	case 23:
		return buildMacroOperation9(), true
	case 24:
		return buildMacroOperation10(), true
	case 13:
		return buildMacroOperation11(), true
	case 51:
		return buildMacroOperation12(), true
	case 8:
		return buildMacroOperation13(), true
	case 5:
		return buildMacroOperation14(), true
	case 11:
		return buildMacroOperation15(), true
	case 34:
		return buildMacroOperation16(), true
	case 38:
		return buildMacroOperation17(), true
	case 41:
		return buildMacroOperation18(), true
	case 46:
		return buildMacroOperation19(), true
	case 16:
		return buildMacroOperation20(), true
	case 18:
		return buildMacroOperation21(), true
	case 7:
		return buildMacroOperation22(), true
	case 14:
		return buildMacroOperation23(), true
	case 15:
		return buildMacroOperation24(), true
	case 35:
		return buildMacroOperation25(), true
	case 48:
		return buildMacroOperation26(), true
	case 26:
		return buildMacroOperation27(), true
	case 28:
		return buildMacroOperation28(), true
	case 30:
		return buildMacroOperation29(), true
	case 53:
		return buildMacroOperation30(), true
	case 33:
		return buildMacroOperation31(), true
	case 25:
		return buildMacroOperation32(), true
	case 19:
		return buildMacroOperation33(), true
	case 40:
		return buildMacroOperation34(), true
	case 4:
		return buildMacroOperation35(), true
	case 36:
		return buildMacroOperation36(), true
	case 17:
		return buildMacroOperation37(), true
	case 10:
		return buildMacroOperation38(), true
	case 37:
		return buildMacroOperation39(), true
	case 27:
		return buildMacroOperation40(), true
	case 29:
		return buildMacroOperation41(), true
	case 32:
		return buildMacroOperation42(), true
	case 20:
		return buildMacroOperation43(), true
	case 21:
		return buildMacroOperation44(), true
	case 9:
		return buildMacroOperation45(), true
	case 45:
		return buildMacroOperation46(), true
	case 22:
		return buildMacroOperation47(), true
	case 42:
		return buildMacroOperation48(), true
	case 47:
		return buildMacroOperation49(), true
	case 52:
		return buildMacroOperation50(), true
	case 2:
		return buildMacroOperation51(), true
	case 1:
		return buildMacroOperation52(), true
	}
	return MacroOperation{}, false
}
func buildMacroError0() MacroError {
	return MacroError{Name: "absentSubscriber", Definition: "AbsentSubscriber", Module: "MAP-Errors", Code: 27, Parameter: newMacroType("", "BOOLEAN", "bool", primitiveValueCodec[bool]("MAP-Errors.AbsentSubscriber", "parameter", nil, func(data []byte, opts ...ber.DecodeOption) (bool, int, error) {
		v, _, n, err := ber.DecodeBoolean(data, opts...)
		return v, n, err
	}, func(v bool, _ bool) ([]byte, error) { return ber.EncodeBoolean(v), nil }, nil))}
}
func buildMacroError1() MacroError {
	return MacroError{Name: "bearerServiceNotProvisioned", Definition: "BearerServiceNotProvisioned", Module: "MAP-Errors", Code: 10, Parameter: nil}
}
func buildMacroError2() MacroError {
	return MacroError{Name: "busySubscriber", Definition: "BusySubscriber", Module: "MAP-Errors", Code: 28, Parameter: nil}
}
func buildMacroError3() MacroError {
	return MacroError{Name: "callBarred", Definition: "CallBarred", Module: "MAP-Errors", Code: 13, Parameter: newMacroType("MAP-Errors", "CallBarred.parameter", "CallBarredParameter", CallBarredParameterCodec())}
}
func buildMacroError4() MacroError {
	return MacroError{Name: "cug-Reject", Definition: "CUG-Reject", Module: "MAP-Errors", Code: 15, Parameter: newMacroType("MAP-Errors", "CUG-Reject.parameter", "CUGRejectParameter", CUGRejectParameterCodec())}
}
func buildMacroError5() MacroError {
	return MacroError{Name: "dataMissing", Definition: "DataMissing", Module: "MAP-Errors", Code: 35, Parameter: nil}
}
func buildMacroError6() MacroError {
	return MacroError{Name: "facilityNotSupported", Definition: "FacilityNotSupported", Module: "MAP-Errors", Code: 21, Parameter: nil}
}
func buildMacroError7() MacroError {
	return MacroError{Name: "forwardingViolation", Definition: "ForwardingViolation", Module: "MAP-Errors", Code: 14, Parameter: nil}
}
func buildMacroError8() MacroError {
	return MacroError{Name: "illegalMS", Definition: "IllegalMS", Module: "MAP-Errors", Code: 9, Parameter: nil}
}
func buildMacroError9() MacroError {
	return MacroError{Name: "illegalSS-Operation", Definition: "IllegalSS-Operation", Module: "MAP-Errors", Code: 16, Parameter: nil}
}
func buildMacroError10() MacroError {
	return MacroError{Name: "impossibleCallCompletion", Definition: "ImpossibleCallCompletion", Module: "MAP-Errors", Code: 31, Parameter: newMacroType("MAP-DataTypes", "SS-CodeList", "SSCodeList", SSCodeListCodec())}
}
func buildMacroError11() MacroError {
	return MacroError{Name: "insufficientBearerCapabilities", Definition: "InsufficientBearerCapabilities", Module: "MAP-Errors", Code: 12, Parameter: nil}
}
func buildMacroError12() MacroError {
	return MacroError{Name: "invalidTargetBaseStation", Definition: "InvalidTargetBaseStation", Module: "MAP-Errors", Code: 23, Parameter: nil}
}
func buildMacroError13() MacroError {
	return MacroError{Name: "messageWaitingListFull", Definition: "MessageWaitingListFull", Module: "MAP-Errors", Code: 33, Parameter: nil}
}
func buildMacroError14() MacroError {
	return MacroError{Name: "negativePasswordCheck", Definition: "NegativePasswordCheck", Module: "MAP-Errors", Code: 38, Parameter: nil}
}
func buildMacroError15() MacroError {
	return MacroError{Name: "noHandoverNumberAvailable", Definition: "NoHandoverNumberAvailable", Module: "MAP-Errors", Code: 25, Parameter: nil}
}
func buildMacroError16() MacroError {
	return MacroError{Name: "noRadioResourceAvailable", Definition: "NoRadioResourceAvailable", Module: "MAP-Errors", Code: 24, Parameter: nil}
}
func buildMacroError17() MacroError {
	return MacroError{Name: "noRoamingNumberAvailable", Definition: "NoRoamingNumberAvailable", Module: "MAP-Errors", Code: 39, Parameter: nil}
}
func buildMacroError18() MacroError {
	return MacroError{Name: "noSubscriberReply", Definition: "NoSubscriberReply", Module: "MAP-Errors", Code: 29, Parameter: nil}
}
func buildMacroError19() MacroError {
	return MacroError{Name: "passwordRegistrationFailure", Definition: "PasswordRegistrationFailure", Module: "MAP-Errors", Code: 37, Parameter: newMacroType("MAP-Errors", "PasswordRegistrationFailure.parameter", "PasswordRegistrationFailureParameter", PasswordRegistrationFailureParameterCodec())}
}
func buildMacroError20() MacroError {
	return MacroError{Name: "radioCongestion", Definition: "RadioCongestion", Module: "MAP-Errors", Code: 30, Parameter: nil}
}
func buildMacroError21() MacroError {
	return MacroError{Name: "roamingNotAllowed", Definition: "RoamingNotAllowed", Module: "MAP-Errors", Code: 8, Parameter: nil}
}
func buildMacroError22() MacroError {
	return MacroError{Name: "sm-DeliveryFailure", Definition: "SM-DeliveryFailure", Module: "MAP-Errors", Code: 32, Parameter: newMacroType("MAP-Errors", "SM-DeliveryFailure.parameter", "SMDeliveryFailureParameter", SMDeliveryFailureParameterCodec())}
}
func buildMacroError23() MacroError {
	return MacroError{Name: "ss-ErrorStatus", Definition: "SS-ErrorStatus", Module: "MAP-Errors", Code: 17, Parameter: newMacroType("MAP-DataTypes", "SS-Status", "SSStatus", SSStatusCodec())}
}
func buildMacroError24() MacroError {
	return MacroError{Name: "ss-Incompatibility", Definition: "SS-Incompatibility", Module: "MAP-Errors", Code: 20, Parameter: newMacroType("MAP-Errors", "SS-Incompatibility.parameter", "SSIncompatibilityParameter", SSIncompatibilityParameterCodec())}
}
func buildMacroError25() MacroError {
	return MacroError{Name: "ss-NotAvailable", Definition: "SS-NotAvailable", Module: "MAP-Errors", Code: 18, Parameter: nil}
}
func buildMacroError26() MacroError {
	return MacroError{Name: "ss-SubscriptionViolation", Definition: "SS-SubscriptionViolation", Module: "MAP-Errors", Code: 19, Parameter: newMacroType("MAP-DataTypes", "SS-SubscriptionOption", "SSSubscriptionOption", SSSubscriptionOptionCodec())}
}
func buildMacroError27() MacroError {
	return MacroError{Name: "subsequentHandoverFailure", Definition: "SubsequentHandoverFailure", Module: "MAP-Errors", Code: 26, Parameter: nil}
}
func buildMacroError28() MacroError {
	return MacroError{Name: "systemFailure", Definition: "SystemFailure", Module: "MAP-Errors", Code: 34, Parameter: newMacroType("MAP-DataTypes", "NetworkResource", "NetworkResource", NetworkResourceCodec())}
}
func buildMacroError29() MacroError {
	return MacroError{Name: "teleServiceNotProvisioned", Definition: "TeleServiceNotProvisioned", Module: "MAP-Errors", Code: 11, Parameter: nil}
}
func buildMacroError30() MacroError {
	return MacroError{Name: "tracingBufferFull", Definition: "TracingBufferFull", Module: "MAP-Errors", Code: 40, Parameter: nil}
}
func buildMacroError31() MacroError {
	return MacroError{Name: "unallocatedRoamingNumber", Definition: "UnallocatedRoamingNumber", Module: "MAP-Errors", Code: 6, Parameter: nil}
}
func buildMacroError32() MacroError {
	return MacroError{Name: "unexpectedDataValue", Definition: "UnexpectedDataValue", Module: "MAP-Errors", Code: 36, Parameter: nil}
}
func buildMacroError33() MacroError {
	return MacroError{Name: "unidentifiedSubscriber", Definition: "UnidentifiedSubscriber", Module: "MAP-Errors", Code: 5, Parameter: nil}
}
func buildMacroError34() MacroError {
	return MacroError{Name: "unknownBaseStation", Definition: "UnknownBaseStation", Module: "MAP-Errors", Code: 2, Parameter: nil}
}
func buildMacroError35() MacroError {
	return MacroError{Name: "unknownEquipment", Definition: "UnknownEquipment", Module: "MAP-Errors", Code: 7, Parameter: nil}
}
func buildMacroError36() MacroError {
	return MacroError{Name: "unknownLocArea", Definition: "UnknownLocArea", Module: "MAP-Errors", Code: 4, Parameter: nil}
}
func buildMacroError37() MacroError {
	return MacroError{Name: "unknownMSC", Definition: "UnknownMSC", Module: "MAP-Errors", Code: 3, Parameter: nil}
}
func buildMacroError38() MacroError {
	return MacroError{Name: "unknownSubscriber", Definition: "UnknownSubscriber", Module: "MAP-Errors", Code: 1, Parameter: nil}
}
func MacroErrors() []MacroError {
	return []MacroError{
		buildMacroError0(),
		buildMacroError1(),
		buildMacroError2(),
		buildMacroError3(),
		buildMacroError4(),
		buildMacroError5(),
		buildMacroError6(),
		buildMacroError7(),
		buildMacroError8(),
		buildMacroError9(),
		buildMacroError10(),
		buildMacroError11(),
		buildMacroError12(),
		buildMacroError13(),
		buildMacroError14(),
		buildMacroError15(),
		buildMacroError16(),
		buildMacroError17(),
		buildMacroError18(),
		buildMacroError19(),
		buildMacroError20(),
		buildMacroError21(),
		buildMacroError22(),
		buildMacroError23(),
		buildMacroError24(),
		buildMacroError25(),
		buildMacroError26(),
		buildMacroError27(),
		buildMacroError28(),
		buildMacroError29(),
		buildMacroError30(),
		buildMacroError31(),
		buildMacroError32(),
		buildMacroError33(),
		buildMacroError34(),
		buildMacroError35(),
		buildMacroError36(),
		buildMacroError37(),
		buildMacroError38(),
	}
}

// LookupMacroError returns detached metadata and builds only the requested entry.
func LookupMacroError(code int64) (MacroError, bool) {
	switch code {
	case 27:
		return buildMacroError0(), true
	case 10:
		return buildMacroError1(), true
	case 28:
		return buildMacroError2(), true
	case 13:
		return buildMacroError3(), true
	case 15:
		return buildMacroError4(), true
	case 35:
		return buildMacroError5(), true
	case 21:
		return buildMacroError6(), true
	case 14:
		return buildMacroError7(), true
	case 9:
		return buildMacroError8(), true
	case 16:
		return buildMacroError9(), true
	case 31:
		return buildMacroError10(), true
	case 12:
		return buildMacroError11(), true
	case 23:
		return buildMacroError12(), true
	case 33:
		return buildMacroError13(), true
	case 38:
		return buildMacroError14(), true
	case 25:
		return buildMacroError15(), true
	case 24:
		return buildMacroError16(), true
	case 39:
		return buildMacroError17(), true
	case 29:
		return buildMacroError18(), true
	case 37:
		return buildMacroError19(), true
	case 30:
		return buildMacroError20(), true
	case 8:
		return buildMacroError21(), true
	case 32:
		return buildMacroError22(), true
	case 17:
		return buildMacroError23(), true
	case 20:
		return buildMacroError24(), true
	case 18:
		return buildMacroError25(), true
	case 19:
		return buildMacroError26(), true
	case 26:
		return buildMacroError27(), true
	case 34:
		return buildMacroError28(), true
	case 11:
		return buildMacroError29(), true
	case 40:
		return buildMacroError30(), true
	case 6:
		return buildMacroError31(), true
	case 36:
		return buildMacroError32(), true
	case 5:
		return buildMacroError33(), true
	case 2:
		return buildMacroError34(), true
	case 7:
		return buildMacroError35(), true
	case 4:
		return buildMacroError36(), true
	case 3:
		return buildMacroError37(), true
	case 1:
		return buildMacroError38(), true
	}
	return MacroError{}, false
}

// UnassignedMacroOperation is a declared OPERATION without a code assignment.
type UnassignedMacroOperation struct {
	Module, Name                                string
	Argument, Result                            *MacroType
	ResultPresent, ErrorsPresent, LinkedPresent bool
	Errors, Linked                              []MacroReference
}

// UnassignedMacroOperations retains source declarations without dispatch.
// GSM 09.02 V3.11.0 §6.5; Q.773 (11/1988) Annex A.
func UnassignedMacroOperations() []UnassignedMacroOperation {
	return []UnassignedMacroOperation{
		{Module: "MAP-Operations", Name: "DeregisterMobileSubscriber", Argument: newMacroType("MAP-DataTypes", "IMSI", "IMSI", IMSICodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil},
	}
}
