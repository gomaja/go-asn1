// Code generated from native Q.773 (06/1997) §3.1 macro bindings. DO NOT EDIT.

package gsm0902_v4_19_1

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
	return MacroOperation{Name: "activateSS", Definition: "ActivateSS", Module: "MAP-SupplementaryServiceOperations", Code: 12, Argument: newMacroType("MAP-SS-DataTypes", "SS-ForBS-Code", "SSForBSCode", SSForBSCodeCodec()), Result: newMacroType("MAP-SS-DataTypes", "SS-Info", "SSInfo", SSInfoCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "BearerServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "BearerServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "TeleserviceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "TeleserviceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSS-Operation", DefinitionModule: "MAP-Errors", Definition: "IllegalSS-Operation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-ErrorStatus", DefinitionModule: "MAP-Errors", Definition: "SS-ErrorStatus", IsValue: false}, {Module: "MAP-Errors", Name: "SS-SubscriptionViolation", DefinitionModule: "MAP-Errors", Definition: "SS-SubscriptionViolation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-Incompatibility", DefinitionModule: "MAP-Errors", Definition: "SS-Incompatibility", IsValue: false}, {Module: "MAP-Errors", Name: "NegativePW-Check", DefinitionModule: "MAP-Errors", Definition: "NegativePW-Check", IsValue: false}, {Module: "MAP-Errors", Name: "NumberOfPW-AttemptsViolation", DefinitionModule: "MAP-Errors", Definition: "NumberOfPW-AttemptsViolation", IsValue: false}}, Linked: nil}
}
func buildMacroOperation1() MacroOperation {
	return MacroOperation{Name: "activateTraceMode", Definition: "ActivateTraceMode", Module: "MAP-OperationAndMaintenanceOperations", Code: 50, Argument: newMacroType("MAP-OM-DataTypes", "ActivateTraceModeArg", "ActivateTraceModeArg", ActivateTraceModeArgCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "TracingBufferFull", DefinitionModule: "MAP-Errors", Definition: "TracingBufferFull", IsValue: false}}, Linked: nil}
}
func buildMacroOperation2() MacroOperation {
	return MacroOperation{Name: "alertServiceCentre", Definition: "AlertServiceCentre", Module: "MAP-ShortMessageServiceOperations", Code: 64, Argument: newMacroType("MAP-SM-DataTypes", "AlertServiceCentreArg", "AlertServiceCentreArg", AlertServiceCentreArgCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation3() MacroOperation {
	return MacroOperation{Name: "alertServiceCentreWithoutResult", Definition: "AlertServiceCentreWithoutResult", Module: "MAP-ShortMessageServiceOperations", Code: 49, Argument: newMacroType("MAP-SM-DataTypes", "AlertServiceCentreArg", "AlertServiceCentreArg", AlertServiceCentreArgCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation4() MacroOperation {
	return MacroOperation{Name: "beginSubscriberActivity", Definition: "BeginSubscriberActivity", Module: "MAP-SupplementaryServiceOperations", Code: 54, Argument: newMacroType("MAP-SS-DataTypes", "BeginSubscriberActivityArg", "BeginSubscriberActivityArg", BeginSubscriberActivityArgCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation5() MacroOperation {
	return MacroOperation{Name: "cancelLocation", Definition: "CancelLocation", Module: "MAP-MobileServiceOperations", Code: 3, Argument: newMacroType("MAP-MS-DataTypes", "CancelLocationArg", "CancelLocationArg", CancelLocationArgCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}}, Linked: nil}
}
func buildMacroOperation6() MacroOperation {
	return MacroOperation{Name: "checkIMEI", Definition: "CheckIMEI", Module: "MAP-MobileServiceOperations", Code: 43, Argument: newMacroType("MAP-CommonDataTypes", "IMEI", "IMEI", IMEICodec()), Result: newMacroType("MAP-MS-DataTypes", "EquipmentStatus", "EquipmentStatus", EquipmentStatusCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownEquipment", DefinitionModule: "MAP-Errors", Definition: "UnknownEquipment", IsValue: false}}, Linked: nil}
}
func buildMacroOperation7() MacroOperation {
	return MacroOperation{Name: "deactivateSS", Definition: "DeactivateSS", Module: "MAP-SupplementaryServiceOperations", Code: 13, Argument: newMacroType("MAP-SS-DataTypes", "SS-ForBS-Code", "SSForBSCode", SSForBSCodeCodec()), Result: newMacroType("MAP-SS-DataTypes", "SS-Info", "SSInfo", SSInfoCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "BearerServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "BearerServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "TeleserviceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "TeleserviceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSS-Operation", DefinitionModule: "MAP-Errors", Definition: "IllegalSS-Operation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-ErrorStatus", DefinitionModule: "MAP-Errors", Definition: "SS-ErrorStatus", IsValue: false}, {Module: "MAP-Errors", Name: "SS-SubscriptionViolation", DefinitionModule: "MAP-Errors", Definition: "SS-SubscriptionViolation", IsValue: false}, {Module: "MAP-Errors", Name: "NegativePW-Check", DefinitionModule: "MAP-Errors", Definition: "NegativePW-Check", IsValue: false}, {Module: "MAP-Errors", Name: "NumberOfPW-AttemptsViolation", DefinitionModule: "MAP-Errors", Definition: "NumberOfPW-AttemptsViolation", IsValue: false}}, Linked: nil}
}
func buildMacroOperation8() MacroOperation {
	return MacroOperation{Name: "deactivateTraceMode", Definition: "DeactivateTraceMode", Module: "MAP-OperationAndMaintenanceOperations", Code: 51, Argument: newMacroType("MAP-OM-DataTypes", "DeactivateTraceModeArg", "DeactivateTraceModeArg", DeactivateTraceModeArgCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}}, Linked: nil}
}
func buildMacroOperation9() MacroOperation {
	return MacroOperation{Name: "deleteSubscriberData", Definition: "DeleteSubscriberData", Module: "MAP-MobileServiceOperations", Code: 8, Argument: newMacroType("MAP-MS-DataTypes", "DeleteSubscriberDataArg", "DeleteSubscriberDataArg", DeleteSubscriberDataArgCodec()), Result: newMacroType("MAP-MS-DataTypes", "DeleteSubscriberDataRes", "DeleteSubscriberDataRes", DeleteSubscriberDataResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}}, Linked: nil}
}
func buildMacroOperation10() MacroOperation {
	return MacroOperation{Name: "eraseSS", Definition: "EraseSS", Module: "MAP-SupplementaryServiceOperations", Code: 11, Argument: newMacroType("MAP-SS-DataTypes", "SS-ForBS-Code", "SSForBSCode", SSForBSCodeCodec()), Result: newMacroType("MAP-SS-DataTypes", "SS-Info", "SSInfo", SSInfoCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "BearerServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "BearerServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "TeleserviceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "TeleserviceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSS-Operation", DefinitionModule: "MAP-Errors", Definition: "IllegalSS-Operation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-ErrorStatus", DefinitionModule: "MAP-Errors", Definition: "SS-ErrorStatus", IsValue: false}, {Module: "MAP-Errors", Name: "SS-SubscriptionViolation", DefinitionModule: "MAP-Errors", Definition: "SS-SubscriptionViolation", IsValue: false}}, Linked: nil}
}
func buildMacroOperation11() MacroOperation {
	return MacroOperation{Name: "forwardAccessSignalling", Definition: "ForwardAccessSignalling", Module: "MAP-MobileServiceOperations", Code: 34, Argument: newMacroType("MAP-CommonDataTypes", "ExternalSignalInfo", "ExternalSignalInfo", ExternalSignalInfoCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation12() MacroOperation {
	return MacroOperation{Name: "forwardCheckSS-Indication", Definition: "ForwardCheckSS-Indication", Module: "MAP-MobileServiceOperations", Code: 38, Argument: nil, Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation13() MacroOperation {
	return MacroOperation{Name: "forwardSM", Definition: "ForwardSM", Module: "MAP-ShortMessageServiceOperations", Code: 46, Argument: newMacroType("MAP-SM-DataTypes", "ForwardSM-Arg", "ForwardSMArg", ForwardSMArgCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSubscriber", DefinitionModule: "MAP-Errors", Definition: "IllegalSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalEquipment", DefinitionModule: "MAP-Errors", Definition: "IllegalEquipment", IsValue: false}, {Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "SubscriberBusyForMT-SMS", DefinitionModule: "MAP-Errors", Definition: "SubscriberBusyForMT-SMS", IsValue: false}, {Module: "MAP-Errors", Name: "SM-DeliveryFailure", DefinitionModule: "MAP-Errors", Definition: "SM-DeliveryFailure", IsValue: false}}, Linked: nil}
}
func buildMacroOperation14() MacroOperation {
	return MacroOperation{Name: "getPassword", Definition: "GetPassword", Module: "MAP-SupplementaryServiceOperations", Code: 18, Argument: newMacroType("MAP-SS-DataTypes", "GuidanceInfo", "GuidanceInfo", GuidanceInfoCodec()), Result: newMacroType("MAP-SS-DataTypes", "Password", "Password", PasswordCodec()), ResultPresent: true, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation15() MacroOperation {
	return MacroOperation{Name: "informServiceCentre", Definition: "InformServiceCentre", Module: "MAP-ShortMessageServiceOperations", Code: 63, Argument: newMacroType("MAP-SM-DataTypes", "InformServiceCentreArg", "InformServiceCentreArg", InformServiceCentreArgCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation16() MacroOperation {
	return MacroOperation{Name: "insertSubscriberData", Definition: "InsertSubscriberData", Module: "MAP-MobileServiceOperations", Code: 7, Argument: newMacroType("MAP-MS-DataTypes", "InsertSubscriberDataArg", "InsertSubscriberDataArg", InsertSubscriberDataArgCodec()), Result: newMacroType("MAP-MS-DataTypes", "InsertSubscriberDataRes", "InsertSubscriberDataRes", InsertSubscriberDataResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}}, Linked: nil}
}
func buildMacroOperation17() MacroOperation {
	return MacroOperation{Name: "interrogateSS", Definition: "InterrogateSS", Module: "MAP-SupplementaryServiceOperations", Code: 14, Argument: newMacroType("MAP-SS-DataTypes", "SS-ForBS-Code", "SSForBSCode", SSForBSCodeCodec()), Result: newMacroType("MAP-SS-DataTypes", "InterrogateSS-Res", "InterrogateSSRes", InterrogateSSResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "BearerServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "BearerServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "TeleserviceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "TeleserviceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSS-Operation", DefinitionModule: "MAP-Errors", Definition: "IllegalSS-Operation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-NotAvailable", DefinitionModule: "MAP-Errors", Definition: "SS-NotAvailable", IsValue: false}}, Linked: nil}
}
func buildMacroOperation18() MacroOperation {
	return MacroOperation{Name: "noteInternalHandover", Definition: "NoteInternalHandover", Module: "MAP-OperationAndMaintenanceOperations", Code: 35, Argument: newMacroType("MAP-OM-DataTypes", "NoteInternalHO-Arg", "NoteInternalHOArg", NoteInternalHOArgCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation19() MacroOperation {
	return MacroOperation{Name: "noteSubscriberPresent", Definition: "NoteSubscriberPresent", Module: "MAP-ShortMessageServiceOperations", Code: 48, Argument: newMacroType("MAP-CommonDataTypes", "IMSI", "IMSI", IMSICodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation20() MacroOperation {
	return MacroOperation{Name: "performHandover", Definition: "PerformHandover", Module: "MAP-MobileServiceOperations", Code: 28, Argument: newMacroType("MAP-MS-DataTypes", "PerformHO-Arg", "PerformHOArg", PerformHOArgCodec()), Result: newMacroType("MAP-MS-DataTypes", "PerformHO-Res", "PerformHORes", PerformHOResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownBaseStation", DefinitionModule: "MAP-Errors", Definition: "UnknownBaseStation", IsValue: false}, {Module: "MAP-Errors", Name: "InvalidTargetBaseStation", DefinitionModule: "MAP-Errors", Definition: "InvalidTargetBaseStation", IsValue: false}, {Module: "MAP-Errors", Name: "NoRadioResourceAvailable", DefinitionModule: "MAP-Errors", Definition: "NoRadioResourceAvailable", IsValue: false}, {Module: "MAP-Errors", Name: "NoHandoverNumberAvailable", DefinitionModule: "MAP-Errors", Definition: "NoHandoverNumberAvailable", IsValue: false}}, Linked: nil}
}
func buildMacroOperation21() MacroOperation {
	return MacroOperation{Name: "performSubsequentHandover", Definition: "PerformSubsequentHandover", Module: "MAP-MobileServiceOperations", Code: 30, Argument: newMacroType("MAP-MS-DataTypes", "PerformSubsequentHO-Arg", "PerformSubsequentHOArg", PerformSubsequentHOArgCodec()), Result: newMacroType("MAP-CommonDataTypes", "ExternalSignalInfo", "ExternalSignalInfo", ExternalSignalInfoCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownBaseStation", DefinitionModule: "MAP-Errors", Definition: "UnknownBaseStation", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownMSC", DefinitionModule: "MAP-Errors", Definition: "UnknownMSC", IsValue: false}, {Module: "MAP-Errors", Name: "InvalidTargetBaseStation", DefinitionModule: "MAP-Errors", Definition: "InvalidTargetBaseStation", IsValue: false}, {Module: "MAP-Errors", Name: "SubsequentHandoverFailure", DefinitionModule: "MAP-Errors", Definition: "SubsequentHandoverFailure", IsValue: false}}, Linked: nil}
}
func buildMacroOperation22() MacroOperation {
	return MacroOperation{Name: "prepareHandover", Definition: "PrepareHandover", Module: "MAP-MobileServiceOperations", Code: 68, Argument: newMacroType("MAP-MS-DataTypes", "PrepareHO-Arg", "PrepareHOArg", PrepareHOArgCodec()), Result: newMacroType("MAP-MS-DataTypes", "PrepareHO-Res", "PrepareHORes", PrepareHOResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "NoHandoverNumberAvailable", DefinitionModule: "MAP-Errors", Definition: "NoHandoverNumberAvailable", IsValue: false}}, Linked: nil}
}
func buildMacroOperation23() MacroOperation {
	return MacroOperation{Name: "prepareSubsequentHandover", Definition: "PrepareSubsequentHandover", Module: "MAP-MobileServiceOperations", Code: 69, Argument: newMacroType("MAP-MS-DataTypes", "PrepareSubsequentHO-Arg", "PrepareSubsequentHOArg", PrepareSubsequentHOArgCodec()), Result: newMacroType("MAP-CommonDataTypes", "ExternalSignalInfo", "ExternalSignalInfo", ExternalSignalInfoCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownMSC", DefinitionModule: "MAP-Errors", Definition: "UnknownMSC", IsValue: false}, {Module: "MAP-Errors", Name: "SubsequentHandoverFailure", DefinitionModule: "MAP-Errors", Definition: "SubsequentHandoverFailure", IsValue: false}}, Linked: nil}
}
func buildMacroOperation24() MacroOperation {
	return MacroOperation{Name: "processAccessSignalling", Definition: "ProcessAccessSignalling", Module: "MAP-MobileServiceOperations", Code: 33, Argument: newMacroType("MAP-CommonDataTypes", "ExternalSignalInfo", "ExternalSignalInfo", ExternalSignalInfoCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation25() MacroOperation {
	return MacroOperation{Name: "processUnstructuredSS-Data", Definition: "ProcessUnstructuredSS-Data", Module: "MAP-SupplementaryServiceOperations", Code: 19, Argument: newMacroType("MAP-SS-DataTypes", "SS-UserData", "SSUserData", SSUserDataCodec()), Result: newMacroType("MAP-SS-DataTypes", "SS-UserData", "SSUserData", SSUserDataCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}}, Linked: nil}
}
func buildMacroOperation26() MacroOperation {
	return MacroOperation{Name: "processUnstructuredSS-Request", Definition: "ProcessUnstructuredSS-Request", Module: "MAP-SupplementaryServiceOperations", Code: 59, Argument: newMacroType("MAP-SS-DataTypes", "USSD-Arg", "USSDArg", USSDArgCodec()), Result: newMacroType("MAP-SS-DataTypes", "USSD-Res", "USSDRes", USSDResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownAlphabet", DefinitionModule: "MAP-Errors", Definition: "UnknownAlphabet", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}}, Linked: nil}
}
func buildMacroOperation27() MacroOperation {
	return MacroOperation{Name: "provideRoamingNumber", Definition: "ProvideRoamingNumber", Module: "MAP-CallHandlingOperations", Code: 4, Argument: newMacroType("MAP-CH-DataTypes", "ProvideRoamingNumberArg", "ProvideRoamingNumberArg", ProvideRoamingNumberArgCodec()), Result: newMacroType("MAP-CommonDataTypes", "ISDN-AddressString", "ISDNAddressString", ISDNAddressStringCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "NoRoamingNumberAvailable", DefinitionModule: "MAP-Errors", Definition: "NoRoamingNumberAvailable", IsValue: false}}, Linked: nil}
}
func buildMacroOperation28() MacroOperation {
	return MacroOperation{Name: "purgeMS", Definition: "PurgeMS", Module: "MAP-MobileServiceOperations", Code: 67, Argument: newMacroType("MAP-MS-DataTypes", "PurgeMS-Arg", "PurgeMSArg", PurgeMSArgCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation29() MacroOperation {
	return MacroOperation{Name: "readyForSM", Definition: "ReadyForSM", Module: "MAP-ShortMessageServiceOperations", Code: 66, Argument: newMacroType("MAP-SM-DataTypes", "ReadyForSM-Arg", "ReadyForSMArg", ReadyForSMArgCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}}, Linked: nil}
}
func buildMacroOperation30() MacroOperation {
	return MacroOperation{Name: "registerPassword", Definition: "RegisterPassword", Module: "MAP-SupplementaryServiceOperations", Code: 17, Argument: newMacroType("MAP-SS-Code", "SS-Code", "SSCode", SSCodeCodec()), Result: newMacroType("MAP-SS-DataTypes", "Password", "Password", PasswordCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: true, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}, {Module: "MAP-Errors", Name: "SS-SubscriptionViolation", DefinitionModule: "MAP-Errors", Definition: "SS-SubscriptionViolation", IsValue: false}, {Module: "MAP-Errors", Name: "PW-RegistrationFailure", DefinitionModule: "MAP-Errors", Definition: "PW-RegistrationFailure", IsValue: false}, {Module: "MAP-Errors", Name: "NegativePW-Check", DefinitionModule: "MAP-Errors", Definition: "NegativePW-Check", IsValue: false}, {Module: "MAP-Errors", Name: "NumberOfPW-AttemptsViolation", DefinitionModule: "MAP-Errors", Definition: "NumberOfPW-AttemptsViolation", IsValue: false}}, Linked: []MacroReference{{Module: "MAP-SupplementaryServiceOperations", Name: "GetPassword", DefinitionModule: "MAP-SupplementaryServiceOperations", Definition: "GetPassword", IsValue: false}}}
}
func buildMacroOperation31() MacroOperation {
	return MacroOperation{Name: "registerSS", Definition: "RegisterSS", Module: "MAP-SupplementaryServiceOperations", Code: 10, Argument: newMacroType("MAP-SS-DataTypes", "RegisterSS-Arg", "RegisterSSArg", RegisterSSArgCodec()), Result: newMacroType("MAP-SS-DataTypes", "SS-Info", "SSInfo", SSInfoCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "BearerServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "BearerServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "TeleserviceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "TeleserviceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSS-Operation", DefinitionModule: "MAP-Errors", Definition: "IllegalSS-Operation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-ErrorStatus", DefinitionModule: "MAP-Errors", Definition: "SS-ErrorStatus", IsValue: false}, {Module: "MAP-Errors", Name: "SS-SubscriptionViolation", DefinitionModule: "MAP-Errors", Definition: "SS-SubscriptionViolation", IsValue: false}, {Module: "MAP-Errors", Name: "SS-Incompatibility", DefinitionModule: "MAP-Errors", Definition: "SS-Incompatibility", IsValue: false}}, Linked: nil}
}
func buildMacroOperation32() MacroOperation {
	return MacroOperation{Name: "reportSM-DeliveryStatus", Definition: "ReportSM-DeliveryStatus", Module: "MAP-ShortMessageServiceOperations", Code: 47, Argument: newMacroType("MAP-SM-DataTypes", "ReportSM-DeliveryStatusArg", "ReportSMDeliveryStatusArg", ReportSMDeliveryStatusArgCodec()), Result: newMacroType("MAP-CommonDataTypes", "ISDN-AddressString", "ISDNAddressString", ISDNAddressStringCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "MessageWaitingListFull", DefinitionModule: "MAP-Errors", Definition: "MessageWaitingListFull", IsValue: false}}, Linked: nil}
}
func buildMacroOperation33() MacroOperation {
	return MacroOperation{Name: "reset", Definition: "Reset", Module: "MAP-MobileServiceOperations", Code: 37, Argument: newMacroType("MAP-MS-DataTypes", "ResetArg", "ResetArg", ResetArgCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation34() MacroOperation {
	return MacroOperation{Name: "restoreData", Definition: "RestoreData", Module: "MAP-MobileServiceOperations", Code: 57, Argument: newMacroType("MAP-MS-DataTypes", "RestoreDataArg", "RestoreDataArg", RestoreDataArgCodec()), Result: newMacroType("MAP-MS-DataTypes", "RestoreDataRes", "RestoreDataRes", RestoreDataResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}}, Linked: nil}
}
func buildMacroOperation35() MacroOperation {
	return MacroOperation{Name: "sendAuthenticationInfo", Definition: "SendAuthenticationInfo", Module: "MAP-MobileServiceOperations", Code: 56, Argument: newMacroType("MAP-MS-DataTypes", "SendAuthenticationInfoArg", "SendAuthenticationInfoArg", SendAuthenticationInfoArgCodec()), Result: newMacroType("MAP-MS-DataTypes", "SendAuthenticationInfoRes", "SendAuthenticationInfoRes", SendAuthenticationInfoResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}}, Linked: nil}
}
func buildMacroOperation36() MacroOperation {
	return MacroOperation{Name: "sendEndSignal", Definition: "SendEndSignal", Module: "MAP-MobileServiceOperations", Code: 29, Argument: newMacroType("MAP-CommonDataTypes", "ExternalSignalInfo", "ExternalSignalInfo", ExternalSignalInfoCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation37() MacroOperation {
	return MacroOperation{Name: "sendIMSI", Definition: "SendIMSI", Module: "MAP-OperationAndMaintenanceOperations", Code: 58, Argument: newMacroType("MAP-CommonDataTypes", "ISDN-AddressString", "ISDNAddressString", ISDNAddressStringCodec()), Result: newMacroType("MAP-CommonDataTypes", "IMSI", "IMSI", IMSICodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}}, Linked: nil}
}
func buildMacroOperation38() MacroOperation {
	return MacroOperation{Name: "sendIdentification", Definition: "SendIdentification", Module: "MAP-MobileServiceOperations", Code: 55, Argument: newMacroType("MAP-CommonDataTypes", "TMSI", "TMSI", TMSICodec()), Result: newMacroType("MAP-MS-DataTypes", "SendIdentificationRes", "SendIdentificationRes", SendIdentificationResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}}, Linked: nil}
}
func buildMacroOperation39() MacroOperation {
	return MacroOperation{Name: "sendParameters", Definition: "SendParameters", Module: "MAP-MobileServiceOperations", Code: 9, Argument: newMacroType("MAP-MS-DataTypes", "SendParametersArg", "SendParametersArg", SendParametersArgCodec()), Result: newMacroType("MAP-MS-DataTypes", "SentParameterList", "SentParameterList", SentParameterListCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "UnidentifiedSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnidentifiedSubscriber", IsValue: false}}, Linked: nil}
}
func buildMacroOperation40() MacroOperation {
	return MacroOperation{Name: "sendRoutingInfo", Definition: "SendRoutingInfo", Module: "MAP-CallHandlingOperations", Code: 22, Argument: newMacroType("MAP-CH-DataTypes", "SendRoutingInfoArg", "SendRoutingInfoArg", SendRoutingInfoArgCodec()), Result: newMacroType("MAP-CH-DataTypes", "SendRoutingInfoRes", "SendRoutingInfoRes", SendRoutingInfoResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "NumberChanged", DefinitionModule: "MAP-Errors", Definition: "NumberChanged", IsValue: false}, {Module: "MAP-Errors", Name: "BearerServiceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "BearerServiceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "TeleserviceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "TeleserviceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}, {Module: "MAP-Errors", Name: "CUG-Reject", DefinitionModule: "MAP-Errors", Definition: "CUG-Reject", IsValue: false}, {Module: "MAP-Errors", Name: "ForwardingViolation", DefinitionModule: "MAP-Errors", Definition: "ForwardingViolation", IsValue: false}}, Linked: nil}
}
func buildMacroOperation41() MacroOperation {
	return MacroOperation{Name: "sendRoutingInfoForSM", Definition: "SendRoutingInfoForSM", Module: "MAP-ShortMessageServiceOperations", Code: 45, Argument: newMacroType("MAP-SM-DataTypes", "RoutingInfoForSM-Arg", "RoutingInfoForSMArg", RoutingInfoForSMArgCodec()), Result: newMacroType("MAP-SM-DataTypes", "RoutingInfoForSM-Res", "RoutingInfoForSMRes", RoutingInfoForSMResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "FacilityNotSupported", DefinitionModule: "MAP-Errors", Definition: "FacilityNotSupported", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "TeleserviceNotProvisioned", DefinitionModule: "MAP-Errors", Definition: "TeleserviceNotProvisioned", IsValue: false}, {Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "CallBarred", DefinitionModule: "MAP-Errors", Definition: "CallBarred", IsValue: false}}, Linked: nil}
}
func buildMacroOperation42() MacroOperation {
	return MacroOperation{Name: "traceSubscriberActivity", Definition: "TraceSubscriberActivity", Module: "MAP-OperationAndMaintenanceOperations", Code: 52, Argument: newMacroType("MAP-OM-DataTypes", "TraceSubscriberActivityArg", "TraceSubscriberActivityArg", TraceSubscriberActivityArgCodec()), Result: nil, ResultPresent: false, ErrorsPresent: false, LinkedPresent: false, Errors: nil, Linked: nil}
}
func buildMacroOperation43() MacroOperation {
	return MacroOperation{Name: "unstructuredSS-Notify", Definition: "UnstructuredSS-Notify", Module: "MAP-SupplementaryServiceOperations", Code: 61, Argument: newMacroType("MAP-SS-DataTypes", "USSD-Arg", "USSDArg", USSDArgCodec()), Result: nil, ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSubscriber", DefinitionModule: "MAP-Errors", Definition: "IllegalSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalEquipment", DefinitionModule: "MAP-Errors", Definition: "IllegalEquipment", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownAlphabet", DefinitionModule: "MAP-Errors", Definition: "UnknownAlphabet", IsValue: false}, {Module: "MAP-Errors", Name: "USSD-Busy", DefinitionModule: "MAP-Errors", Definition: "USSD-Busy", IsValue: false}}, Linked: nil}
}
func buildMacroOperation44() MacroOperation {
	return MacroOperation{Name: "unstructuredSS-Request", Definition: "UnstructuredSS-Request", Module: "MAP-SupplementaryServiceOperations", Code: 60, Argument: newMacroType("MAP-SS-DataTypes", "USSD-Arg", "USSDArg", USSDArgCodec()), Result: newMacroType("MAP-SS-DataTypes", "USSD-Res", "USSDRes", USSDResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "AbsentSubscriber", DefinitionModule: "MAP-Errors", Definition: "AbsentSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalSubscriber", DefinitionModule: "MAP-Errors", Definition: "IllegalSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "IllegalEquipment", DefinitionModule: "MAP-Errors", Definition: "IllegalEquipment", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownAlphabet", DefinitionModule: "MAP-Errors", Definition: "UnknownAlphabet", IsValue: false}, {Module: "MAP-Errors", Name: "USSD-Busy", DefinitionModule: "MAP-Errors", Definition: "USSD-Busy", IsValue: false}}, Linked: nil}
}
func buildMacroOperation45() MacroOperation {
	return MacroOperation{Name: "updateLocation", Definition: "UpdateLocation", Module: "MAP-MobileServiceOperations", Code: 2, Argument: newMacroType("MAP-MS-DataTypes", "UpdateLocationArg", "UpdateLocationArg", UpdateLocationArgCodec()), Result: newMacroType("MAP-MS-DataTypes", "UpdateLocationRes", "UpdateLocationRes", UpdateLocationResCodec()), ResultPresent: true, ErrorsPresent: true, LinkedPresent: false, Errors: []MacroReference{{Module: "MAP-Errors", Name: "SystemFailure", DefinitionModule: "MAP-Errors", Definition: "SystemFailure", IsValue: false}, {Module: "MAP-Errors", Name: "DataMissing", DefinitionModule: "MAP-Errors", Definition: "DataMissing", IsValue: false}, {Module: "MAP-Errors", Name: "UnexpectedDataValue", DefinitionModule: "MAP-Errors", Definition: "UnexpectedDataValue", IsValue: false}, {Module: "MAP-Errors", Name: "UnknownSubscriber", DefinitionModule: "MAP-Errors", Definition: "UnknownSubscriber", IsValue: false}, {Module: "MAP-Errors", Name: "RoamingNotAllowed", DefinitionModule: "MAP-Errors", Definition: "RoamingNotAllowed", IsValue: false}}, Linked: nil}
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
	}
}

// LookupMacroOperation returns detached metadata and builds only the requested entry.
func LookupMacroOperation(code int64) (MacroOperation, bool) {
	switch code {
	case 12:
		return buildMacroOperation0(), true
	case 50:
		return buildMacroOperation1(), true
	case 64:
		return buildMacroOperation2(), true
	case 49:
		return buildMacroOperation3(), true
	case 54:
		return buildMacroOperation4(), true
	case 3:
		return buildMacroOperation5(), true
	case 43:
		return buildMacroOperation6(), true
	case 13:
		return buildMacroOperation7(), true
	case 51:
		return buildMacroOperation8(), true
	case 8:
		return buildMacroOperation9(), true
	case 11:
		return buildMacroOperation10(), true
	case 34:
		return buildMacroOperation11(), true
	case 38:
		return buildMacroOperation12(), true
	case 46:
		return buildMacroOperation13(), true
	case 18:
		return buildMacroOperation14(), true
	case 63:
		return buildMacroOperation15(), true
	case 7:
		return buildMacroOperation16(), true
	case 14:
		return buildMacroOperation17(), true
	case 35:
		return buildMacroOperation18(), true
	case 48:
		return buildMacroOperation19(), true
	case 28:
		return buildMacroOperation20(), true
	case 30:
		return buildMacroOperation21(), true
	case 68:
		return buildMacroOperation22(), true
	case 69:
		return buildMacroOperation23(), true
	case 33:
		return buildMacroOperation24(), true
	case 19:
		return buildMacroOperation25(), true
	case 59:
		return buildMacroOperation26(), true
	case 4:
		return buildMacroOperation27(), true
	case 67:
		return buildMacroOperation28(), true
	case 66:
		return buildMacroOperation29(), true
	case 17:
		return buildMacroOperation30(), true
	case 10:
		return buildMacroOperation31(), true
	case 47:
		return buildMacroOperation32(), true
	case 37:
		return buildMacroOperation33(), true
	case 57:
		return buildMacroOperation34(), true
	case 56:
		return buildMacroOperation35(), true
	case 29:
		return buildMacroOperation36(), true
	case 58:
		return buildMacroOperation37(), true
	case 55:
		return buildMacroOperation38(), true
	case 9:
		return buildMacroOperation39(), true
	case 22:
		return buildMacroOperation40(), true
	case 45:
		return buildMacroOperation41(), true
	case 52:
		return buildMacroOperation42(), true
	case 61:
		return buildMacroOperation43(), true
	case 60:
		return buildMacroOperation44(), true
	case 2:
		return buildMacroOperation45(), true
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
	return MacroError{Name: "callBarred", Definition: "CallBarred", Module: "MAP-Errors", Code: 13, Parameter: newMacroType("MAP-ER-DataTypes", "CallBarringCause", "CallBarringCause", CallBarringCauseCodec())}
}
func buildMacroError3() MacroError {
	return MacroError{Name: "cug-Reject", Definition: "CUG-Reject", Module: "MAP-Errors", Code: 15, Parameter: newMacroType("MAP-ER-DataTypes", "CUG-RejectCause", "CUGRejectCause", CUGRejectCauseCodec())}
}
func buildMacroError4() MacroError {
	return MacroError{Name: "dataMissing", Definition: "DataMissing", Module: "MAP-Errors", Code: 35, Parameter: nil}
}
func buildMacroError5() MacroError {
	return MacroError{Name: "facilityNotSupported", Definition: "FacilityNotSupported", Module: "MAP-Errors", Code: 21, Parameter: nil}
}
func buildMacroError6() MacroError {
	return MacroError{Name: "forwardingViolation", Definition: "ForwardingViolation", Module: "MAP-Errors", Code: 14, Parameter: nil}
}
func buildMacroError7() MacroError {
	return MacroError{Name: "illegalEquipment", Definition: "IllegalEquipment", Module: "MAP-Errors", Code: 12, Parameter: nil}
}
func buildMacroError8() MacroError {
	return MacroError{Name: "illegalSS-Operation", Definition: "IllegalSS-Operation", Module: "MAP-Errors", Code: 16, Parameter: nil}
}
func buildMacroError9() MacroError {
	return MacroError{Name: "illegalSubscriber", Definition: "IllegalSubscriber", Module: "MAP-Errors", Code: 9, Parameter: nil}
}
func buildMacroError10() MacroError {
	return MacroError{Name: "invalidTargetBaseStation", Definition: "InvalidTargetBaseStation", Module: "MAP-Errors", Code: 23, Parameter: nil}
}
func buildMacroError11() MacroError {
	return MacroError{Name: "messageWaitingListFull", Definition: "MessageWaitingListFull", Module: "MAP-Errors", Code: 33, Parameter: nil}
}
func buildMacroError12() MacroError {
	return MacroError{Name: "negativePW-Check", Definition: "NegativePW-Check", Module: "MAP-Errors", Code: 38, Parameter: nil}
}
func buildMacroError13() MacroError {
	return MacroError{Name: "noHandoverNumberAvailable", Definition: "NoHandoverNumberAvailable", Module: "MAP-Errors", Code: 25, Parameter: nil}
}
func buildMacroError14() MacroError {
	return MacroError{Name: "noRadioResourceAvailable", Definition: "NoRadioResourceAvailable", Module: "MAP-Errors", Code: 24, Parameter: nil}
}
func buildMacroError15() MacroError {
	return MacroError{Name: "noRoamingNumberAvailable", Definition: "NoRoamingNumberAvailable", Module: "MAP-Errors", Code: 39, Parameter: nil}
}
func buildMacroError16() MacroError {
	return MacroError{Name: "numberChanged", Definition: "NumberChanged", Module: "MAP-Errors", Code: 44, Parameter: nil}
}
func buildMacroError17() MacroError {
	return MacroError{Name: "numberOfPW-AttemptsViolation", Definition: "NumberOfPW-AttemptsViolation", Module: "MAP-Errors", Code: 43, Parameter: nil}
}
func buildMacroError18() MacroError {
	return MacroError{Name: "pw-RegistrationFailure", Definition: "PW-RegistrationFailure", Module: "MAP-Errors", Code: 37, Parameter: newMacroType("MAP-ER-DataTypes", "PW-RegistrationFailureCause", "PWRegistrationFailureCause", PWRegistrationFailureCauseCodec())}
}
func buildMacroError19() MacroError {
	return MacroError{Name: "roamingNotAllowed", Definition: "RoamingNotAllowed", Module: "MAP-Errors", Code: 8, Parameter: newMacroType("MAP-ER-DataTypes", "RoamingNotAllowedCause", "RoamingNotAllowedCause", RoamingNotAllowedCauseCodec())}
}
func buildMacroError20() MacroError {
	return MacroError{Name: "sm-DeliveryFailure", Definition: "SM-DeliveryFailure", Module: "MAP-Errors", Code: 32, Parameter: newMacroType("MAP-ER-DataTypes", "SM-DeliveryFailureCause", "SMDeliveryFailureCause", SMDeliveryFailureCauseCodec())}
}
func buildMacroError21() MacroError {
	return MacroError{Name: "ss-ErrorStatus", Definition: "SS-ErrorStatus", Module: "MAP-Errors", Code: 17, Parameter: newMacroType("MAP-SS-DataTypes", "SS-Status", "SSStatus", SSStatusCodec())}
}
func buildMacroError22() MacroError {
	return MacroError{Name: "ss-Incompatibility", Definition: "SS-Incompatibility", Module: "MAP-Errors", Code: 20, Parameter: newMacroType("MAP-ER-DataTypes", "SS-IncompatibilityCause", "SSIncompatibilityCause", SSIncompatibilityCauseCodec())}
}
func buildMacroError23() MacroError {
	return MacroError{Name: "ss-NotAvailable", Definition: "SS-NotAvailable", Module: "MAP-Errors", Code: 18, Parameter: nil}
}
func buildMacroError24() MacroError {
	return MacroError{Name: "ss-SubscriptionViolation", Definition: "SS-SubscriptionViolation", Module: "MAP-Errors", Code: 19, Parameter: newMacroType("MAP-SS-DataTypes", "SS-SubscriptionOption", "SSSubscriptionOption", SSSubscriptionOptionCodec())}
}
func buildMacroError25() MacroError {
	return MacroError{Name: "subscriberBusyForMT-SMS", Definition: "SubscriberBusyForMT-SMS", Module: "MAP-Errors", Code: 31, Parameter: nil}
}
func buildMacroError26() MacroError {
	return MacroError{Name: "subsequentHandoverFailure", Definition: "SubsequentHandoverFailure", Module: "MAP-Errors", Code: 26, Parameter: nil}
}
func buildMacroError27() MacroError {
	return MacroError{Name: "systemFailure", Definition: "SystemFailure", Module: "MAP-Errors", Code: 34, Parameter: newMacroType("MAP-CommonDataTypes", "NetworkResource", "NetworkResource", NetworkResourceCodec())}
}
func buildMacroError28() MacroError {
	return MacroError{Name: "teleserviceNotProvisioned", Definition: "TeleserviceNotProvisioned", Module: "MAP-Errors", Code: 11, Parameter: nil}
}
func buildMacroError29() MacroError {
	return MacroError{Name: "tracingBufferFull", Definition: "TracingBufferFull", Module: "MAP-Errors", Code: 40, Parameter: nil}
}
func buildMacroError30() MacroError {
	return MacroError{Name: "unexpectedDataValue", Definition: "UnexpectedDataValue", Module: "MAP-Errors", Code: 36, Parameter: nil}
}
func buildMacroError31() MacroError {
	return MacroError{Name: "unidentifiedSubscriber", Definition: "UnidentifiedSubscriber", Module: "MAP-Errors", Code: 5, Parameter: nil}
}
func buildMacroError32() MacroError {
	return MacroError{Name: "unknownAlphabet", Definition: "UnknownAlphabet", Module: "MAP-Errors", Code: 71, Parameter: nil}
}
func buildMacroError33() MacroError {
	return MacroError{Name: "unknownBaseStation", Definition: "UnknownBaseStation", Module: "MAP-Errors", Code: 2, Parameter: nil}
}
func buildMacroError34() MacroError {
	return MacroError{Name: "unknownEquipment", Definition: "UnknownEquipment", Module: "MAP-Errors", Code: 7, Parameter: nil}
}
func buildMacroError35() MacroError {
	return MacroError{Name: "unknownMSC", Definition: "UnknownMSC", Module: "MAP-Errors", Code: 3, Parameter: nil}
}
func buildMacroError36() MacroError {
	return MacroError{Name: "unknownSubscriber", Definition: "UnknownSubscriber", Module: "MAP-Errors", Code: 1, Parameter: nil}
}
func buildMacroError37() MacroError {
	return MacroError{Name: "ussd-Busy", Definition: "USSD-Busy", Module: "MAP-Errors", Code: 72, Parameter: nil}
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
	}
}

// LookupMacroError returns detached metadata and builds only the requested entry.
func LookupMacroError(code int64) (MacroError, bool) {
	switch code {
	case 27:
		return buildMacroError0(), true
	case 10:
		return buildMacroError1(), true
	case 13:
		return buildMacroError2(), true
	case 15:
		return buildMacroError3(), true
	case 35:
		return buildMacroError4(), true
	case 21:
		return buildMacroError5(), true
	case 14:
		return buildMacroError6(), true
	case 12:
		return buildMacroError7(), true
	case 16:
		return buildMacroError8(), true
	case 9:
		return buildMacroError9(), true
	case 23:
		return buildMacroError10(), true
	case 33:
		return buildMacroError11(), true
	case 38:
		return buildMacroError12(), true
	case 25:
		return buildMacroError13(), true
	case 24:
		return buildMacroError14(), true
	case 39:
		return buildMacroError15(), true
	case 44:
		return buildMacroError16(), true
	case 43:
		return buildMacroError17(), true
	case 37:
		return buildMacroError18(), true
	case 8:
		return buildMacroError19(), true
	case 32:
		return buildMacroError20(), true
	case 17:
		return buildMacroError21(), true
	case 20:
		return buildMacroError22(), true
	case 18:
		return buildMacroError23(), true
	case 19:
		return buildMacroError24(), true
	case 31:
		return buildMacroError25(), true
	case 26:
		return buildMacroError26(), true
	case 34:
		return buildMacroError27(), true
	case 11:
		return buildMacroError28(), true
	case 40:
		return buildMacroError29(), true
	case 36:
		return buildMacroError30(), true
	case 5:
		return buildMacroError31(), true
	case 71:
		return buildMacroError32(), true
	case 2:
		return buildMacroError33(), true
	case 7:
		return buildMacroError34(), true
	case 3:
		return buildMacroError35(), true
	case 1:
		return buildMacroError36(), true
	case 72:
		return buildMacroError37(), true
	}
	return MacroError{}, false
}
