// Code generated from ASN.1 module "DummyMAP". DO NOT EDIT.

package gsm_map

import (
	"fmt"
	"math/big"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

const (

	// MaxNumOfSentParameter is the integer constant for MaxNumOfSentParameter.
	MaxNumOfSentParameter int64 = 6
)

// AccessTypeId returns the OID value for AccessTypeId.
func AccessTypeId() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 12, 2, 1107, 3, 66, 1, 1}
}

// AccessTypeNotAllowedId returns the OID value for AccessTypeNotAllowedId.
func AccessTypeNotAllowedId() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 12, 2, 1107, 3, 66, 1, 2}
}

// Component choice constants.
const (
	ComponentChoiceInvoke              = 1
	ComponentChoiceReturnResultLast    = 2
	ComponentChoiceReturnError         = 3
	ComponentChoiceReject              = 4
	ComponentChoiceReturnResultNotLast = 5
)

// Component represents the ASN.1 CHOICE type Component.
type Component struct {
	Choice              int
	Invoke              *DumInvoke       `json:"Invoke,omitempty"`
	ReturnResultLast    *DumReturnResult `json:"ReturnResultLast,omitempty"`
	ReturnError         *DumReturnError  `json:"ReturnError,omitempty"`
	Reject              *DumReject       `json:"Reject,omitempty"`
	ReturnResultNotLast *DumReturnResult `json:"ReturnResultNotLast,omitempty"`
}

// NewComponentInvoke creates a Component with the invoke alternative.
func NewComponentInvoke(v DumInvoke) Component {
	return Component{
		Choice: ComponentChoiceInvoke,
		Invoke: &v,
	}
}

// NewComponentReturnResultLast creates a Component with the returnResultLast alternative.
func NewComponentReturnResultLast(v DumReturnResult) Component {
	return Component{
		Choice:           ComponentChoiceReturnResultLast,
		ReturnResultLast: &v,
	}
}

// NewComponentReturnError creates a Component with the returnError alternative.
func NewComponentReturnError(v DumReturnError) Component {
	return Component{
		Choice:      ComponentChoiceReturnError,
		ReturnError: &v,
	}
}

// NewComponentReject creates a Component with the reject alternative.
func NewComponentReject(v DumReject) Component {
	return Component{
		Choice: ComponentChoiceReject,
		Reject: &v,
	}
}

// NewComponentReturnResultNotLast creates a Component with the returnResultNotLast alternative.
func NewComponentReturnResultNotLast(v DumReturnResult) Component {
	return Component{
		Choice:              ComponentChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// DumInvoke represents the ASN.1 type DumInvoke (SEQUENCE).
type DumInvoke struct {
	InvokeID        InvokeIdType      `asn1:""`
	LinkedID        *InvokeIdType     `asn1:"tag:0,context,implicit,optional" json:"LinkedID,omitempty"`
	OpCode          MAPOPERATION      `asn1:""`
	Invokeparameter *runtime.RawValue `asn1:",optional" json:"Invokeparameter,omitempty" asn1c:"raw-preserve"`
}

// asn1c:raw-preserve
// InvokeParameter represents the ASN.1 type InvokeParameter (ANY).
type InvokeParameter = runtime.RawValue

// DumReturnResult represents the ASN.1 type DumReturnResult (SEQUENCE).
type DumReturnResult struct {
	InvokeID     InvokeIdType              `asn1:""`
	Resultretres *ReturnResultResultretres `asn1:",optional" json:"Resultretres,omitempty"`
}

// asn1c:raw-preserve
// ReturnResultParameter represents the ASN.1 type ReturnResultParameter (ANY).
type ReturnResultParameter = runtime.RawValue

// DumReturnError represents the ASN.1 type DumReturnError (SEQUENCE).
type DumReturnError struct {
	InvokeID  InvokeIdType      `asn1:""`
	ErrorCode MAPERROR          `asn1:""`
	Parameter *runtime.RawValue `asn1:",optional" json:"Parameter,omitempty" asn1c:"raw-preserve"`
}

// asn1c:raw-preserve
// ReturnErrorParameter represents the ASN.1 type ReturnErrorParameter (ANY).
type ReturnErrorParameter = runtime.RawValue

// DumReject represents the ASN.1 type DumReject (SEQUENCE).
type DumReject struct {
	InvokeIDRej RejectInvokeIDRej `asn1:""`
	Problem     DumRejectProblem  `asn1:""`
}

// InvokeIdType represents the ASN.1 type InvokeIdType (INTEGER).
type InvokeIdType = int64

// MAPOPERATION choice constants.
const (
	MAPOPERATIONChoiceLocalValue  = 1
	MAPOPERATIONChoiceGlobalValue = 2
)

// MAPOPERATION represents the ASN.1 CHOICE type MAPOPERATION.
type MAPOPERATION struct {
	Choice      int
	LocalValue  *OperationLocalvalue     `json:"LocalValue,omitempty"`
	GlobalValue runtime.ObjectIdentifier `json:"GlobalValue,omitempty"`
}

// NewMAPOPERATIONLocalValue creates a MAPOPERATION with the localValue alternative.
func NewMAPOPERATIONLocalValue(v OperationLocalvalue) MAPOPERATION {
	return MAPOPERATION{
		Choice:     MAPOPERATIONChoiceLocalValue,
		LocalValue: &v,
	}
}

// NewMAPOPERATIONGlobalValue creates a MAPOPERATION with the globalValue alternative.
func NewMAPOPERATIONGlobalValue(v runtime.ObjectIdentifier) MAPOPERATION {
	return MAPOPERATION{
		Choice:      MAPOPERATIONChoiceGlobalValue,
		GlobalValue: v,
	}
}

// NewMAPOPERATIONLocalValueInt64 creates a MAPOPERATION localValue alternative from an int64 code.
func NewMAPOPERATIONLocalValueInt64(v int64) MAPOPERATION {
	var local OperationLocalvalue
	if err := local.UnmarshalText([]byte(fmt.Sprintf("%d", v))); err != nil {
		panic(err)
	}
	return NewMAPOPERATIONLocalValue(local)
}

// LocalCode returns the localValue code when this MAPOPERATION carries an int64 localValue alternative.
func (v MAPOPERATION) LocalCode() (int64, bool) {
	if v.Choice != MAPOPERATIONChoiceLocalValue || v.LocalValue == nil {
		return 0, false
	}
	return v.LocalValue.AsInt64()
}

// GSMMAPOperationLocalvalue represents the arbitrary-width ASN.1 INTEGER type GSMMAPOperationLocalvalue with named numbers.
type GSMMAPOperationLocalvalue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	GSMMAPOperationLocalvalueUpdateLocationDecimal                   = "2"
	GSMMAPOperationLocalvalueUpdateLocation                          = 2
	GSMMAPOperationLocalvalueCancelLocationDecimal                   = "3"
	GSMMAPOperationLocalvalueCancelLocation                          = 3
	GSMMAPOperationLocalvalueProvideRoamingNumberDecimal             = "4"
	GSMMAPOperationLocalvalueProvideRoamingNumber                    = 4
	GSMMAPOperationLocalvalueNoteSubscriberDataModifiedDecimal       = "5"
	GSMMAPOperationLocalvalueNoteSubscriberDataModified              = 5
	GSMMAPOperationLocalvalueResumeCallHandlingDecimal               = "6"
	GSMMAPOperationLocalvalueResumeCallHandling                      = 6
	GSMMAPOperationLocalvalueInsertSubscriberDataDecimal             = "7"
	GSMMAPOperationLocalvalueInsertSubscriberData                    = 7
	GSMMAPOperationLocalvalueDeleteSubscriberDataDecimal             = "8"
	GSMMAPOperationLocalvalueDeleteSubscriberData                    = 8
	GSMMAPOperationLocalvalueSendParametersDecimal                   = "9"
	GSMMAPOperationLocalvalueSendParameters                          = 9
	GSMMAPOperationLocalvalueRegisterSSDecimal                       = "10"
	GSMMAPOperationLocalvalueRegisterSS                              = 10
	GSMMAPOperationLocalvalueEraseSSDecimal                          = "11"
	GSMMAPOperationLocalvalueEraseSS                                 = 11
	GSMMAPOperationLocalvalueActivateSSDecimal                       = "12"
	GSMMAPOperationLocalvalueActivateSS                              = 12
	GSMMAPOperationLocalvalueDeactivateSSDecimal                     = "13"
	GSMMAPOperationLocalvalueDeactivateSS                            = 13
	GSMMAPOperationLocalvalueInterrogateSSDecimal                    = "14"
	GSMMAPOperationLocalvalueInterrogateSS                           = 14
	GSMMAPOperationLocalvalueAuthenticationFailureReportDecimal      = "15"
	GSMMAPOperationLocalvalueAuthenticationFailureReport             = 15
	GSMMAPOperationLocalvalueNotifySSDecimal                         = "16"
	GSMMAPOperationLocalvalueNotifySS                                = 16
	GSMMAPOperationLocalvalueRegisterPasswordDecimal                 = "17"
	GSMMAPOperationLocalvalueRegisterPassword                        = 17
	GSMMAPOperationLocalvalueGetPasswordDecimal                      = "18"
	GSMMAPOperationLocalvalueGetPassword                             = 18
	GSMMAPOperationLocalvalueProcessUnstructuredSSDataDecimal        = "19"
	GSMMAPOperationLocalvalueProcessUnstructuredSSData               = 19
	GSMMAPOperationLocalvalueReleaseResourcesDecimal                 = "20"
	GSMMAPOperationLocalvalueReleaseResources                        = 20
	GSMMAPOperationLocalvalueMtForwardSMVGCSDecimal                  = "21"
	GSMMAPOperationLocalvalueMtForwardSMVGCS                         = 21
	GSMMAPOperationLocalvalueSendRoutingInfoDecimal                  = "22"
	GSMMAPOperationLocalvalueSendRoutingInfo                         = 22
	GSMMAPOperationLocalvalueUpdateGprsLocationDecimal               = "23"
	GSMMAPOperationLocalvalueUpdateGprsLocation                      = 23
	GSMMAPOperationLocalvalueSendRoutingInfoForGprsDecimal           = "24"
	GSMMAPOperationLocalvalueSendRoutingInfoForGprs                  = 24
	GSMMAPOperationLocalvalueFailureReportDecimal                    = "25"
	GSMMAPOperationLocalvalueFailureReport                           = 25
	GSMMAPOperationLocalvalueNoteMsPresentForGprsDecimal             = "26"
	GSMMAPOperationLocalvalueNoteMsPresentForGprs                    = 26
	GSMMAPOperationLocalvaluePerformHandoverDecimal                  = "28"
	GSMMAPOperationLocalvaluePerformHandover                         = 28
	GSMMAPOperationLocalvalueSendEndSignalDecimal                    = "29"
	GSMMAPOperationLocalvalueSendEndSignal                           = 29
	GSMMAPOperationLocalvaluePerformSubsequentHandoverDecimal        = "30"
	GSMMAPOperationLocalvaluePerformSubsequentHandover               = 30
	GSMMAPOperationLocalvalueProvideSIWFSNumberDecimal               = "31"
	GSMMAPOperationLocalvalueProvideSIWFSNumber                      = 31
	GSMMAPOperationLocalvalueSIWFSSignallingModifyDecimal            = "32"
	GSMMAPOperationLocalvalueSIWFSSignallingModify                   = 32
	GSMMAPOperationLocalvalueProcessAccessSignallingDecimal          = "33"
	GSMMAPOperationLocalvalueProcessAccessSignalling                 = 33
	GSMMAPOperationLocalvalueForwardAccessSignallingDecimal          = "34"
	GSMMAPOperationLocalvalueForwardAccessSignalling                 = 34
	GSMMAPOperationLocalvalueNoteInternalHandoverDecimal             = "35"
	GSMMAPOperationLocalvalueNoteInternalHandover                    = 35
	GSMMAPOperationLocalvalueCancelVcsgLocationDecimal               = "36"
	GSMMAPOperationLocalvalueCancelVcsgLocation                      = 36
	GSMMAPOperationLocalvalueResetDecimal                            = "37"
	GSMMAPOperationLocalvalueReset                                   = 37
	GSMMAPOperationLocalvalueForwardCheckSSDecimal                   = "38"
	GSMMAPOperationLocalvalueForwardCheckSS                          = 38
	GSMMAPOperationLocalvaluePrepareGroupCallDecimal                 = "39"
	GSMMAPOperationLocalvaluePrepareGroupCall                        = 39
	GSMMAPOperationLocalvalueSendGroupCallEndSignalDecimal           = "40"
	GSMMAPOperationLocalvalueSendGroupCallEndSignal                  = 40
	GSMMAPOperationLocalvalueProcessGroupCallSignallingDecimal       = "41"
	GSMMAPOperationLocalvalueProcessGroupCallSignalling              = 41
	GSMMAPOperationLocalvalueForwardGroupCallSignallingDecimal       = "42"
	GSMMAPOperationLocalvalueForwardGroupCallSignalling              = 42
	GSMMAPOperationLocalvalueCheckIMEIDecimal                        = "43"
	GSMMAPOperationLocalvalueCheckIMEI                               = 43
	GSMMAPOperationLocalvalueMtForwardSMDecimal                      = "44"
	GSMMAPOperationLocalvalueMtForwardSM                             = 44
	GSMMAPOperationLocalvalueSendRoutingInfoForSMDecimal             = "45"
	GSMMAPOperationLocalvalueSendRoutingInfoForSM                    = 45
	GSMMAPOperationLocalvalueMoForwardSMDecimal                      = "46"
	GSMMAPOperationLocalvalueMoForwardSM                             = 46
	GSMMAPOperationLocalvalueReportSMDeliveryStatusDecimal           = "47"
	GSMMAPOperationLocalvalueReportSMDeliveryStatus                  = 47
	GSMMAPOperationLocalvalueNoteSubscriberPresentDecimal            = "48"
	GSMMAPOperationLocalvalueNoteSubscriberPresent                   = 48
	GSMMAPOperationLocalvalueAlertServiceCentreWithoutResultDecimal  = "49"
	GSMMAPOperationLocalvalueAlertServiceCentreWithoutResult         = 49
	GSMMAPOperationLocalvalueActivateTraceModeDecimal                = "50"
	GSMMAPOperationLocalvalueActivateTraceMode                       = 50
	GSMMAPOperationLocalvalueDeactivateTraceModeDecimal              = "51"
	GSMMAPOperationLocalvalueDeactivateTraceMode                     = 51
	GSMMAPOperationLocalvalueTraceSubscriberActivityDecimal          = "52"
	GSMMAPOperationLocalvalueTraceSubscriberActivity                 = 52
	GSMMAPOperationLocalvalueUpdateVcsgLocationDecimal               = "53"
	GSMMAPOperationLocalvalueUpdateVcsgLocation                      = 53
	GSMMAPOperationLocalvalueBeginSubscriberActivityDecimal          = "54"
	GSMMAPOperationLocalvalueBeginSubscriberActivity                 = 54
	GSMMAPOperationLocalvalueSendIdentificationDecimal               = "55"
	GSMMAPOperationLocalvalueSendIdentification                      = 55
	GSMMAPOperationLocalvalueSendAuthenticationInfoDecimal           = "56"
	GSMMAPOperationLocalvalueSendAuthenticationInfo                  = 56
	GSMMAPOperationLocalvalueRestoreDataDecimal                      = "57"
	GSMMAPOperationLocalvalueRestoreData                             = 57
	GSMMAPOperationLocalvalueSendIMSIDecimal                         = "58"
	GSMMAPOperationLocalvalueSendIMSI                                = 58
	GSMMAPOperationLocalvalueProcessUnstructuredSSRequestDecimal     = "59"
	GSMMAPOperationLocalvalueProcessUnstructuredSSRequest            = 59
	GSMMAPOperationLocalvalueUnstructuredSSRequestDecimal            = "60"
	GSMMAPOperationLocalvalueUnstructuredSSRequest                   = 60
	GSMMAPOperationLocalvalueUnstructuredSSNotifyDecimal             = "61"
	GSMMAPOperationLocalvalueUnstructuredSSNotify                    = 61
	GSMMAPOperationLocalvalueAnyTimeSubscriptionInterrogationDecimal = "62"
	GSMMAPOperationLocalvalueAnyTimeSubscriptionInterrogation        = 62
	GSMMAPOperationLocalvalueInformServiceCentreDecimal              = "63"
	GSMMAPOperationLocalvalueInformServiceCentre                     = 63
	GSMMAPOperationLocalvalueAlertServiceCentreDecimal               = "64"
	GSMMAPOperationLocalvalueAlertServiceCentre                      = 64
	GSMMAPOperationLocalvalueAnyTimeModificationDecimal              = "65"
	GSMMAPOperationLocalvalueAnyTimeModification                     = 65
	GSMMAPOperationLocalvalueReadyForSMDecimal                       = "66"
	GSMMAPOperationLocalvalueReadyForSM                              = 66
	GSMMAPOperationLocalvaluePurgeMSDecimal                          = "67"
	GSMMAPOperationLocalvaluePurgeMS                                 = 67
	GSMMAPOperationLocalvaluePrepareHandoverDecimal                  = "68"
	GSMMAPOperationLocalvaluePrepareHandover                         = 68
	GSMMAPOperationLocalvaluePrepareSubsequentHandoverDecimal        = "69"
	GSMMAPOperationLocalvaluePrepareSubsequentHandover               = 69
	GSMMAPOperationLocalvalueProvideSubscriberInfoDecimal            = "70"
	GSMMAPOperationLocalvalueProvideSubscriberInfo                   = 70
	GSMMAPOperationLocalvalueAnyTimeInterrogationDecimal             = "71"
	GSMMAPOperationLocalvalueAnyTimeInterrogation                    = 71
	GSMMAPOperationLocalvalueSsInvocationNotificationDecimal         = "72"
	GSMMAPOperationLocalvalueSsInvocationNotification                = 72
	GSMMAPOperationLocalvalueSetReportingStateDecimal                = "73"
	GSMMAPOperationLocalvalueSetReportingState                       = 73
	GSMMAPOperationLocalvalueStatusReportDecimal                     = "74"
	GSMMAPOperationLocalvalueStatusReport                            = 74
	GSMMAPOperationLocalvalueRemoteUserFreeDecimal                   = "75"
	GSMMAPOperationLocalvalueRemoteUserFree                          = 75
	GSMMAPOperationLocalvalueRegisterCCEntryDecimal                  = "76"
	GSMMAPOperationLocalvalueRegisterCCEntry                         = 76
	GSMMAPOperationLocalvalueEraseCCEntryDecimal                     = "77"
	GSMMAPOperationLocalvalueEraseCCEntry                            = 77
	GSMMAPOperationLocalvalueSecureTransportClass1Decimal            = "78"
	GSMMAPOperationLocalvalueSecureTransportClass1                   = 78
	GSMMAPOperationLocalvalueSecureTransportClass2Decimal            = "79"
	GSMMAPOperationLocalvalueSecureTransportClass2                   = 79
	GSMMAPOperationLocalvalueSecureTransportClass3Decimal            = "80"
	GSMMAPOperationLocalvalueSecureTransportClass3                   = 80
	GSMMAPOperationLocalvalueSecureTransportClass4Decimal            = "81"
	GSMMAPOperationLocalvalueSecureTransportClass4                   = 81
	GSMMAPOperationLocalvalueProvideSubscriberLocationDecimal        = "83"
	GSMMAPOperationLocalvalueProvideSubscriberLocation               = 83
	GSMMAPOperationLocalvalueSendGroupCallInfoDecimal                = "84"
	GSMMAPOperationLocalvalueSendGroupCallInfo                       = 84
	GSMMAPOperationLocalvalueSendRoutingInfoForLCSDecimal            = "85"
	GSMMAPOperationLocalvalueSendRoutingInfoForLCS                   = 85
	GSMMAPOperationLocalvalueSubscriberLocationReportDecimal         = "86"
	GSMMAPOperationLocalvalueSubscriberLocationReport                = 86
	GSMMAPOperationLocalvalueIstAlertDecimal                         = "87"
	GSMMAPOperationLocalvalueIstAlert                                = 87
	GSMMAPOperationLocalvalueIstCommandDecimal                       = "88"
	GSMMAPOperationLocalvalueIstCommand                              = 88
	GSMMAPOperationLocalvalueNoteMMEventDecimal                      = "89"
	GSMMAPOperationLocalvalueNoteMMEvent                             = 89
	GSMMAPOperationLocalvalueLcsPeriodicLocationCancellationDecimal  = "109"
	GSMMAPOperationLocalvalueLcsPeriodicLocationCancellation         = 109
	GSMMAPOperationLocalvalueLcsLocationUpdateDecimal                = "110"
	GSMMAPOperationLocalvalueLcsLocationUpdate                       = 110
	GSMMAPOperationLocalvalueLcsPeriodicLocationRequestDecimal       = "111"
	GSMMAPOperationLocalvalueLcsPeriodicLocationRequest              = 111
	GSMMAPOperationLocalvalueLcsAreaEventCancellationDecimal         = "112"
	GSMMAPOperationLocalvalueLcsAreaEventCancellation                = 112
	GSMMAPOperationLocalvalueLcsAreaEventReportDecimal               = "113"
	GSMMAPOperationLocalvalueLcsAreaEventReport                      = 113
	GSMMAPOperationLocalvalueLcsAreaEventRequestDecimal              = "114"
	GSMMAPOperationLocalvalueLcsAreaEventRequest                     = 114
	GSMMAPOperationLocalvalueLcsMOLRDecimal                          = "115"
	GSMMAPOperationLocalvalueLcsMOLR                                 = 115
	GSMMAPOperationLocalvalueLcsLocationNotificationDecimal          = "116"
	GSMMAPOperationLocalvalueLcsLocationNotification                 = 116
	GSMMAPOperationLocalvalueCallDeflectionDecimal                   = "117"
	GSMMAPOperationLocalvalueCallDeflection                          = 117
	GSMMAPOperationLocalvalueUserUserServiceDecimal                  = "118"
	GSMMAPOperationLocalvalueUserUserService                         = 118
	GSMMAPOperationLocalvalueAccessRegisterCCEntryDecimal            = "119"
	GSMMAPOperationLocalvalueAccessRegisterCCEntry                   = 119
	GSMMAPOperationLocalvalueForwardCUGInfoDecimal                   = "120"
	GSMMAPOperationLocalvalueForwardCUGInfo                          = 120
	GSMMAPOperationLocalvalueSplitMPTYDecimal                        = "121"
	GSMMAPOperationLocalvalueSplitMPTY                               = 121
	GSMMAPOperationLocalvalueRetrieveMPTYDecimal                     = "122"
	GSMMAPOperationLocalvalueRetrieveMPTY                            = 122
	GSMMAPOperationLocalvalueHoldMPTYDecimal                         = "123"
	GSMMAPOperationLocalvalueHoldMPTY                                = 123
	GSMMAPOperationLocalvalueBuildMPTYDecimal                        = "124"
	GSMMAPOperationLocalvalueBuildMPTY                               = 124
	GSMMAPOperationLocalvalueForwardChargeAdviceDecimal              = "125"
	GSMMAPOperationLocalvalueForwardChargeAdvice                     = 125
	GSMMAPOperationLocalvalueExplicitCTDecimal                       = "126"
	GSMMAPOperationLocalvalueExplicitCT                              = 126
)

// NewGSMMAPOperationLocalvalue returns an immutable GSMMAPOperationLocalvalue containing value.
func NewGSMMAPOperationLocalvalue(value *big.Int) GSMMAPOperationLocalvalue {
	return GSMMAPOperationLocalvalue{value: runtime.CloneBigInt(value)}
}

// NewGSMMAPOperationLocalvalueInt64 returns a GSMMAPOperationLocalvalue containing value.
func NewGSMMAPOperationLocalvalueInt64(value int64) GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(big.NewInt(value))
}

// GSMMAPOperationLocalvalueUpdateLocationValue returns the named value updateLocation.
func GSMMAPOperationLocalvalueUpdateLocationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueUpdateLocationDecimal))
}

// GSMMAPOperationLocalvalueCancelLocationValue returns the named value cancelLocation.
func GSMMAPOperationLocalvalueCancelLocationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueCancelLocationDecimal))
}

// GSMMAPOperationLocalvalueProvideRoamingNumberValue returns the named value provideRoamingNumber.
func GSMMAPOperationLocalvalueProvideRoamingNumberValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueProvideRoamingNumberDecimal))
}

// GSMMAPOperationLocalvalueNoteSubscriberDataModifiedValue returns the named value noteSubscriberDataModified.
func GSMMAPOperationLocalvalueNoteSubscriberDataModifiedValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueNoteSubscriberDataModifiedDecimal))
}

// GSMMAPOperationLocalvalueResumeCallHandlingValue returns the named value resumeCallHandling.
func GSMMAPOperationLocalvalueResumeCallHandlingValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueResumeCallHandlingDecimal))
}

// GSMMAPOperationLocalvalueInsertSubscriberDataValue returns the named value insertSubscriberData.
func GSMMAPOperationLocalvalueInsertSubscriberDataValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueInsertSubscriberDataDecimal))
}

// GSMMAPOperationLocalvalueDeleteSubscriberDataValue returns the named value deleteSubscriberData.
func GSMMAPOperationLocalvalueDeleteSubscriberDataValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueDeleteSubscriberDataDecimal))
}

// GSMMAPOperationLocalvalueSendParametersValue returns the named value sendParameters.
func GSMMAPOperationLocalvalueSendParametersValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSendParametersDecimal))
}

// GSMMAPOperationLocalvalueRegisterSSValue returns the named value registerSS.
func GSMMAPOperationLocalvalueRegisterSSValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueRegisterSSDecimal))
}

// GSMMAPOperationLocalvalueEraseSSValue returns the named value eraseSS.
func GSMMAPOperationLocalvalueEraseSSValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueEraseSSDecimal))
}

// GSMMAPOperationLocalvalueActivateSSValue returns the named value activateSS.
func GSMMAPOperationLocalvalueActivateSSValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueActivateSSDecimal))
}

// GSMMAPOperationLocalvalueDeactivateSSValue returns the named value deactivateSS.
func GSMMAPOperationLocalvalueDeactivateSSValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueDeactivateSSDecimal))
}

// GSMMAPOperationLocalvalueInterrogateSSValue returns the named value interrogateSS.
func GSMMAPOperationLocalvalueInterrogateSSValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueInterrogateSSDecimal))
}

// GSMMAPOperationLocalvalueAuthenticationFailureReportValue returns the named value authenticationFailureReport.
func GSMMAPOperationLocalvalueAuthenticationFailureReportValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueAuthenticationFailureReportDecimal))
}

// GSMMAPOperationLocalvalueNotifySSValue returns the named value notifySS.
func GSMMAPOperationLocalvalueNotifySSValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueNotifySSDecimal))
}

// GSMMAPOperationLocalvalueRegisterPasswordValue returns the named value registerPassword.
func GSMMAPOperationLocalvalueRegisterPasswordValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueRegisterPasswordDecimal))
}

// GSMMAPOperationLocalvalueGetPasswordValue returns the named value getPassword.
func GSMMAPOperationLocalvalueGetPasswordValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueGetPasswordDecimal))
}

// GSMMAPOperationLocalvalueProcessUnstructuredSSDataValue returns the named value processUnstructuredSS-Data.
func GSMMAPOperationLocalvalueProcessUnstructuredSSDataValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueProcessUnstructuredSSDataDecimal))
}

// GSMMAPOperationLocalvalueReleaseResourcesValue returns the named value releaseResources.
func GSMMAPOperationLocalvalueReleaseResourcesValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueReleaseResourcesDecimal))
}

// GSMMAPOperationLocalvalueMtForwardSMVGCSValue returns the named value mt-ForwardSM-VGCS.
func GSMMAPOperationLocalvalueMtForwardSMVGCSValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueMtForwardSMVGCSDecimal))
}

// GSMMAPOperationLocalvalueSendRoutingInfoValue returns the named value sendRoutingInfo.
func GSMMAPOperationLocalvalueSendRoutingInfoValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSendRoutingInfoDecimal))
}

// GSMMAPOperationLocalvalueUpdateGprsLocationValue returns the named value updateGprsLocation.
func GSMMAPOperationLocalvalueUpdateGprsLocationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueUpdateGprsLocationDecimal))
}

// GSMMAPOperationLocalvalueSendRoutingInfoForGprsValue returns the named value sendRoutingInfoForGprs.
func GSMMAPOperationLocalvalueSendRoutingInfoForGprsValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSendRoutingInfoForGprsDecimal))
}

// GSMMAPOperationLocalvalueFailureReportValue returns the named value failureReport.
func GSMMAPOperationLocalvalueFailureReportValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueFailureReportDecimal))
}

// GSMMAPOperationLocalvalueNoteMsPresentForGprsValue returns the named value noteMsPresentForGprs.
func GSMMAPOperationLocalvalueNoteMsPresentForGprsValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueNoteMsPresentForGprsDecimal))
}

// GSMMAPOperationLocalvaluePerformHandoverValue returns the named value performHandover.
func GSMMAPOperationLocalvaluePerformHandoverValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvaluePerformHandoverDecimal))
}

// GSMMAPOperationLocalvalueSendEndSignalValue returns the named value sendEndSignal.
func GSMMAPOperationLocalvalueSendEndSignalValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSendEndSignalDecimal))
}

// GSMMAPOperationLocalvaluePerformSubsequentHandoverValue returns the named value performSubsequentHandover.
func GSMMAPOperationLocalvaluePerformSubsequentHandoverValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvaluePerformSubsequentHandoverDecimal))
}

// GSMMAPOperationLocalvalueProvideSIWFSNumberValue returns the named value provideSIWFSNumber.
func GSMMAPOperationLocalvalueProvideSIWFSNumberValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueProvideSIWFSNumberDecimal))
}

// GSMMAPOperationLocalvalueSIWFSSignallingModifyValue returns the named value sIWFSSignallingModify.
func GSMMAPOperationLocalvalueSIWFSSignallingModifyValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSIWFSSignallingModifyDecimal))
}

// GSMMAPOperationLocalvalueProcessAccessSignallingValue returns the named value processAccessSignalling.
func GSMMAPOperationLocalvalueProcessAccessSignallingValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueProcessAccessSignallingDecimal))
}

// GSMMAPOperationLocalvalueForwardAccessSignallingValue returns the named value forwardAccessSignalling.
func GSMMAPOperationLocalvalueForwardAccessSignallingValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueForwardAccessSignallingDecimal))
}

// GSMMAPOperationLocalvalueNoteInternalHandoverValue returns the named value noteInternalHandover.
func GSMMAPOperationLocalvalueNoteInternalHandoverValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueNoteInternalHandoverDecimal))
}

// GSMMAPOperationLocalvalueCancelVcsgLocationValue returns the named value cancelVcsgLocation.
func GSMMAPOperationLocalvalueCancelVcsgLocationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueCancelVcsgLocationDecimal))
}

// GSMMAPOperationLocalvalueResetValue returns the named value reset.
func GSMMAPOperationLocalvalueResetValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueResetDecimal))
}

// GSMMAPOperationLocalvalueForwardCheckSSValue returns the named value forwardCheckSS.
func GSMMAPOperationLocalvalueForwardCheckSSValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueForwardCheckSSDecimal))
}

// GSMMAPOperationLocalvaluePrepareGroupCallValue returns the named value prepareGroupCall.
func GSMMAPOperationLocalvaluePrepareGroupCallValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvaluePrepareGroupCallDecimal))
}

// GSMMAPOperationLocalvalueSendGroupCallEndSignalValue returns the named value sendGroupCallEndSignal.
func GSMMAPOperationLocalvalueSendGroupCallEndSignalValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSendGroupCallEndSignalDecimal))
}

// GSMMAPOperationLocalvalueProcessGroupCallSignallingValue returns the named value processGroupCallSignalling.
func GSMMAPOperationLocalvalueProcessGroupCallSignallingValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueProcessGroupCallSignallingDecimal))
}

// GSMMAPOperationLocalvalueForwardGroupCallSignallingValue returns the named value forwardGroupCallSignalling.
func GSMMAPOperationLocalvalueForwardGroupCallSignallingValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueForwardGroupCallSignallingDecimal))
}

// GSMMAPOperationLocalvalueCheckIMEIValue returns the named value checkIMEI.
func GSMMAPOperationLocalvalueCheckIMEIValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueCheckIMEIDecimal))
}

// GSMMAPOperationLocalvalueMtForwardSMValue returns the named value mt-forwardSM.
func GSMMAPOperationLocalvalueMtForwardSMValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueMtForwardSMDecimal))
}

// GSMMAPOperationLocalvalueSendRoutingInfoForSMValue returns the named value sendRoutingInfoForSM.
func GSMMAPOperationLocalvalueSendRoutingInfoForSMValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSendRoutingInfoForSMDecimal))
}

// GSMMAPOperationLocalvalueMoForwardSMValue returns the named value mo-forwardSM.
func GSMMAPOperationLocalvalueMoForwardSMValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueMoForwardSMDecimal))
}

// GSMMAPOperationLocalvalueReportSMDeliveryStatusValue returns the named value reportSM-DeliveryStatus.
func GSMMAPOperationLocalvalueReportSMDeliveryStatusValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueReportSMDeliveryStatusDecimal))
}

// GSMMAPOperationLocalvalueNoteSubscriberPresentValue returns the named value noteSubscriberPresent.
func GSMMAPOperationLocalvalueNoteSubscriberPresentValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueNoteSubscriberPresentDecimal))
}

// GSMMAPOperationLocalvalueAlertServiceCentreWithoutResultValue returns the named value alertServiceCentreWithoutResult.
func GSMMAPOperationLocalvalueAlertServiceCentreWithoutResultValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueAlertServiceCentreWithoutResultDecimal))
}

// GSMMAPOperationLocalvalueActivateTraceModeValue returns the named value activateTraceMode.
func GSMMAPOperationLocalvalueActivateTraceModeValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueActivateTraceModeDecimal))
}

// GSMMAPOperationLocalvalueDeactivateTraceModeValue returns the named value deactivateTraceMode.
func GSMMAPOperationLocalvalueDeactivateTraceModeValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueDeactivateTraceModeDecimal))
}

// GSMMAPOperationLocalvalueTraceSubscriberActivityValue returns the named value traceSubscriberActivity.
func GSMMAPOperationLocalvalueTraceSubscriberActivityValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueTraceSubscriberActivityDecimal))
}

// GSMMAPOperationLocalvalueUpdateVcsgLocationValue returns the named value updateVcsgLocation.
func GSMMAPOperationLocalvalueUpdateVcsgLocationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueUpdateVcsgLocationDecimal))
}

// GSMMAPOperationLocalvalueBeginSubscriberActivityValue returns the named value beginSubscriberActivity.
func GSMMAPOperationLocalvalueBeginSubscriberActivityValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueBeginSubscriberActivityDecimal))
}

// GSMMAPOperationLocalvalueSendIdentificationValue returns the named value sendIdentification.
func GSMMAPOperationLocalvalueSendIdentificationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSendIdentificationDecimal))
}

// GSMMAPOperationLocalvalueSendAuthenticationInfoValue returns the named value sendAuthenticationInfo.
func GSMMAPOperationLocalvalueSendAuthenticationInfoValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSendAuthenticationInfoDecimal))
}

// GSMMAPOperationLocalvalueRestoreDataValue returns the named value restoreData.
func GSMMAPOperationLocalvalueRestoreDataValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueRestoreDataDecimal))
}

// GSMMAPOperationLocalvalueSendIMSIValue returns the named value sendIMSI.
func GSMMAPOperationLocalvalueSendIMSIValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSendIMSIDecimal))
}

// GSMMAPOperationLocalvalueProcessUnstructuredSSRequestValue returns the named value processUnstructuredSS-Request.
func GSMMAPOperationLocalvalueProcessUnstructuredSSRequestValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueProcessUnstructuredSSRequestDecimal))
}

// GSMMAPOperationLocalvalueUnstructuredSSRequestValue returns the named value unstructuredSS-Request.
func GSMMAPOperationLocalvalueUnstructuredSSRequestValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueUnstructuredSSRequestDecimal))
}

// GSMMAPOperationLocalvalueUnstructuredSSNotifyValue returns the named value unstructuredSS-Notify.
func GSMMAPOperationLocalvalueUnstructuredSSNotifyValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueUnstructuredSSNotifyDecimal))
}

// GSMMAPOperationLocalvalueAnyTimeSubscriptionInterrogationValue returns the named value anyTimeSubscriptionInterrogation.
func GSMMAPOperationLocalvalueAnyTimeSubscriptionInterrogationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueAnyTimeSubscriptionInterrogationDecimal))
}

// GSMMAPOperationLocalvalueInformServiceCentreValue returns the named value informServiceCentre.
func GSMMAPOperationLocalvalueInformServiceCentreValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueInformServiceCentreDecimal))
}

// GSMMAPOperationLocalvalueAlertServiceCentreValue returns the named value alertServiceCentre.
func GSMMAPOperationLocalvalueAlertServiceCentreValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueAlertServiceCentreDecimal))
}

// GSMMAPOperationLocalvalueAnyTimeModificationValue returns the named value anyTimeModification.
func GSMMAPOperationLocalvalueAnyTimeModificationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueAnyTimeModificationDecimal))
}

// GSMMAPOperationLocalvalueReadyForSMValue returns the named value readyForSM.
func GSMMAPOperationLocalvalueReadyForSMValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueReadyForSMDecimal))
}

// GSMMAPOperationLocalvaluePurgeMSValue returns the named value purgeMS.
func GSMMAPOperationLocalvaluePurgeMSValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvaluePurgeMSDecimal))
}

// GSMMAPOperationLocalvaluePrepareHandoverValue returns the named value prepareHandover.
func GSMMAPOperationLocalvaluePrepareHandoverValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvaluePrepareHandoverDecimal))
}

// GSMMAPOperationLocalvaluePrepareSubsequentHandoverValue returns the named value prepareSubsequentHandover.
func GSMMAPOperationLocalvaluePrepareSubsequentHandoverValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvaluePrepareSubsequentHandoverDecimal))
}

// GSMMAPOperationLocalvalueProvideSubscriberInfoValue returns the named value provideSubscriberInfo.
func GSMMAPOperationLocalvalueProvideSubscriberInfoValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueProvideSubscriberInfoDecimal))
}

// GSMMAPOperationLocalvalueAnyTimeInterrogationValue returns the named value anyTimeInterrogation.
func GSMMAPOperationLocalvalueAnyTimeInterrogationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueAnyTimeInterrogationDecimal))
}

// GSMMAPOperationLocalvalueSsInvocationNotificationValue returns the named value ss-InvocationNotification.
func GSMMAPOperationLocalvalueSsInvocationNotificationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSsInvocationNotificationDecimal))
}

// GSMMAPOperationLocalvalueSetReportingStateValue returns the named value setReportingState.
func GSMMAPOperationLocalvalueSetReportingStateValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSetReportingStateDecimal))
}

// GSMMAPOperationLocalvalueStatusReportValue returns the named value statusReport.
func GSMMAPOperationLocalvalueStatusReportValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueStatusReportDecimal))
}

// GSMMAPOperationLocalvalueRemoteUserFreeValue returns the named value remoteUserFree.
func GSMMAPOperationLocalvalueRemoteUserFreeValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueRemoteUserFreeDecimal))
}

// GSMMAPOperationLocalvalueRegisterCCEntryValue returns the named value registerCC-Entry.
func GSMMAPOperationLocalvalueRegisterCCEntryValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueRegisterCCEntryDecimal))
}

// GSMMAPOperationLocalvalueEraseCCEntryValue returns the named value eraseCC-Entry.
func GSMMAPOperationLocalvalueEraseCCEntryValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueEraseCCEntryDecimal))
}

// GSMMAPOperationLocalvalueSecureTransportClass1Value returns the named value secureTransportClass1.
func GSMMAPOperationLocalvalueSecureTransportClass1Value() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSecureTransportClass1Decimal))
}

// GSMMAPOperationLocalvalueSecureTransportClass2Value returns the named value secureTransportClass2.
func GSMMAPOperationLocalvalueSecureTransportClass2Value() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSecureTransportClass2Decimal))
}

// GSMMAPOperationLocalvalueSecureTransportClass3Value returns the named value secureTransportClass3.
func GSMMAPOperationLocalvalueSecureTransportClass3Value() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSecureTransportClass3Decimal))
}

// GSMMAPOperationLocalvalueSecureTransportClass4Value returns the named value secureTransportClass4.
func GSMMAPOperationLocalvalueSecureTransportClass4Value() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSecureTransportClass4Decimal))
}

// GSMMAPOperationLocalvalueProvideSubscriberLocationValue returns the named value provideSubscriberLocation.
func GSMMAPOperationLocalvalueProvideSubscriberLocationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueProvideSubscriberLocationDecimal))
}

// GSMMAPOperationLocalvalueSendGroupCallInfoValue returns the named value sendGroupCallInfo.
func GSMMAPOperationLocalvalueSendGroupCallInfoValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSendGroupCallInfoDecimal))
}

// GSMMAPOperationLocalvalueSendRoutingInfoForLCSValue returns the named value sendRoutingInfoForLCS.
func GSMMAPOperationLocalvalueSendRoutingInfoForLCSValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSendRoutingInfoForLCSDecimal))
}

// GSMMAPOperationLocalvalueSubscriberLocationReportValue returns the named value subscriberLocationReport.
func GSMMAPOperationLocalvalueSubscriberLocationReportValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSubscriberLocationReportDecimal))
}

// GSMMAPOperationLocalvalueIstAlertValue returns the named value ist-Alert.
func GSMMAPOperationLocalvalueIstAlertValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueIstAlertDecimal))
}

// GSMMAPOperationLocalvalueIstCommandValue returns the named value ist-Command.
func GSMMAPOperationLocalvalueIstCommandValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueIstCommandDecimal))
}

// GSMMAPOperationLocalvalueNoteMMEventValue returns the named value noteMM-Event.
func GSMMAPOperationLocalvalueNoteMMEventValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueNoteMMEventDecimal))
}

// GSMMAPOperationLocalvalueLcsPeriodicLocationCancellationValue returns the named value lcs-PeriodicLocationCancellation.
func GSMMAPOperationLocalvalueLcsPeriodicLocationCancellationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueLcsPeriodicLocationCancellationDecimal))
}

// GSMMAPOperationLocalvalueLcsLocationUpdateValue returns the named value lcs-LocationUpdate.
func GSMMAPOperationLocalvalueLcsLocationUpdateValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueLcsLocationUpdateDecimal))
}

// GSMMAPOperationLocalvalueLcsPeriodicLocationRequestValue returns the named value lcs-PeriodicLocationRequest.
func GSMMAPOperationLocalvalueLcsPeriodicLocationRequestValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueLcsPeriodicLocationRequestDecimal))
}

// GSMMAPOperationLocalvalueLcsAreaEventCancellationValue returns the named value lcs-AreaEventCancellation.
func GSMMAPOperationLocalvalueLcsAreaEventCancellationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueLcsAreaEventCancellationDecimal))
}

// GSMMAPOperationLocalvalueLcsAreaEventReportValue returns the named value lcs-AreaEventReport.
func GSMMAPOperationLocalvalueLcsAreaEventReportValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueLcsAreaEventReportDecimal))
}

// GSMMAPOperationLocalvalueLcsAreaEventRequestValue returns the named value lcs-AreaEventRequest.
func GSMMAPOperationLocalvalueLcsAreaEventRequestValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueLcsAreaEventRequestDecimal))
}

// GSMMAPOperationLocalvalueLcsMOLRValue returns the named value lcs-MOLR.
func GSMMAPOperationLocalvalueLcsMOLRValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueLcsMOLRDecimal))
}

// GSMMAPOperationLocalvalueLcsLocationNotificationValue returns the named value lcs-LocationNotification.
func GSMMAPOperationLocalvalueLcsLocationNotificationValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueLcsLocationNotificationDecimal))
}

// GSMMAPOperationLocalvalueCallDeflectionValue returns the named value callDeflection.
func GSMMAPOperationLocalvalueCallDeflectionValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueCallDeflectionDecimal))
}

// GSMMAPOperationLocalvalueUserUserServiceValue returns the named value userUserService.
func GSMMAPOperationLocalvalueUserUserServiceValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueUserUserServiceDecimal))
}

// GSMMAPOperationLocalvalueAccessRegisterCCEntryValue returns the named value accessRegisterCCEntry.
func GSMMAPOperationLocalvalueAccessRegisterCCEntryValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueAccessRegisterCCEntryDecimal))
}

// GSMMAPOperationLocalvalueForwardCUGInfoValue returns the named value forwardCUG-Info.
func GSMMAPOperationLocalvalueForwardCUGInfoValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueForwardCUGInfoDecimal))
}

// GSMMAPOperationLocalvalueSplitMPTYValue returns the named value splitMPTY.
func GSMMAPOperationLocalvalueSplitMPTYValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueSplitMPTYDecimal))
}

// GSMMAPOperationLocalvalueRetrieveMPTYValue returns the named value retrieveMPTY.
func GSMMAPOperationLocalvalueRetrieveMPTYValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueRetrieveMPTYDecimal))
}

// GSMMAPOperationLocalvalueHoldMPTYValue returns the named value holdMPTY.
func GSMMAPOperationLocalvalueHoldMPTYValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueHoldMPTYDecimal))
}

// GSMMAPOperationLocalvalueBuildMPTYValue returns the named value buildMPTY.
func GSMMAPOperationLocalvalueBuildMPTYValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueBuildMPTYDecimal))
}

// GSMMAPOperationLocalvalueForwardChargeAdviceValue returns the named value forwardChargeAdvice.
func GSMMAPOperationLocalvalueForwardChargeAdviceValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueForwardChargeAdviceDecimal))
}

// GSMMAPOperationLocalvalueExplicitCTValue returns the named value explicitCT.
func GSMMAPOperationLocalvalueExplicitCTValue() GSMMAPOperationLocalvalue {
	return NewGSMMAPOperationLocalvalue(runtime.MustParseBigIntDecimal(GSMMAPOperationLocalvalueExplicitCTDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v GSMMAPOperationLocalvalue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v GSMMAPOperationLocalvalue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v GSMMAPOperationLocalvalue) Name() (string, bool) {
	switch v.BigInt().String() {
	case GSMMAPOperationLocalvalueUpdateLocationDecimal:
		return "updateLocation", true
	case GSMMAPOperationLocalvalueCancelLocationDecimal:
		return "cancelLocation", true
	case GSMMAPOperationLocalvalueProvideRoamingNumberDecimal:
		return "provideRoamingNumber", true
	case GSMMAPOperationLocalvalueNoteSubscriberDataModifiedDecimal:
		return "noteSubscriberDataModified", true
	case GSMMAPOperationLocalvalueResumeCallHandlingDecimal:
		return "resumeCallHandling", true
	case GSMMAPOperationLocalvalueInsertSubscriberDataDecimal:
		return "insertSubscriberData", true
	case GSMMAPOperationLocalvalueDeleteSubscriberDataDecimal:
		return "deleteSubscriberData", true
	case GSMMAPOperationLocalvalueSendParametersDecimal:
		return "sendParameters", true
	case GSMMAPOperationLocalvalueRegisterSSDecimal:
		return "registerSS", true
	case GSMMAPOperationLocalvalueEraseSSDecimal:
		return "eraseSS", true
	case GSMMAPOperationLocalvalueActivateSSDecimal:
		return "activateSS", true
	case GSMMAPOperationLocalvalueDeactivateSSDecimal:
		return "deactivateSS", true
	case GSMMAPOperationLocalvalueInterrogateSSDecimal:
		return "interrogateSS", true
	case GSMMAPOperationLocalvalueAuthenticationFailureReportDecimal:
		return "authenticationFailureReport", true
	case GSMMAPOperationLocalvalueNotifySSDecimal:
		return "notifySS", true
	case GSMMAPOperationLocalvalueRegisterPasswordDecimal:
		return "registerPassword", true
	case GSMMAPOperationLocalvalueGetPasswordDecimal:
		return "getPassword", true
	case GSMMAPOperationLocalvalueProcessUnstructuredSSDataDecimal:
		return "processUnstructuredSS-Data", true
	case GSMMAPOperationLocalvalueReleaseResourcesDecimal:
		return "releaseResources", true
	case GSMMAPOperationLocalvalueMtForwardSMVGCSDecimal:
		return "mt-ForwardSM-VGCS", true
	case GSMMAPOperationLocalvalueSendRoutingInfoDecimal:
		return "sendRoutingInfo", true
	case GSMMAPOperationLocalvalueUpdateGprsLocationDecimal:
		return "updateGprsLocation", true
	case GSMMAPOperationLocalvalueSendRoutingInfoForGprsDecimal:
		return "sendRoutingInfoForGprs", true
	case GSMMAPOperationLocalvalueFailureReportDecimal:
		return "failureReport", true
	case GSMMAPOperationLocalvalueNoteMsPresentForGprsDecimal:
		return "noteMsPresentForGprs", true
	case GSMMAPOperationLocalvaluePerformHandoverDecimal:
		return "performHandover", true
	case GSMMAPOperationLocalvalueSendEndSignalDecimal:
		return "sendEndSignal", true
	case GSMMAPOperationLocalvaluePerformSubsequentHandoverDecimal:
		return "performSubsequentHandover", true
	case GSMMAPOperationLocalvalueProvideSIWFSNumberDecimal:
		return "provideSIWFSNumber", true
	case GSMMAPOperationLocalvalueSIWFSSignallingModifyDecimal:
		return "sIWFSSignallingModify", true
	case GSMMAPOperationLocalvalueProcessAccessSignallingDecimal:
		return "processAccessSignalling", true
	case GSMMAPOperationLocalvalueForwardAccessSignallingDecimal:
		return "forwardAccessSignalling", true
	case GSMMAPOperationLocalvalueNoteInternalHandoverDecimal:
		return "noteInternalHandover", true
	case GSMMAPOperationLocalvalueCancelVcsgLocationDecimal:
		return "cancelVcsgLocation", true
	case GSMMAPOperationLocalvalueResetDecimal:
		return "reset", true
	case GSMMAPOperationLocalvalueForwardCheckSSDecimal:
		return "forwardCheckSS", true
	case GSMMAPOperationLocalvaluePrepareGroupCallDecimal:
		return "prepareGroupCall", true
	case GSMMAPOperationLocalvalueSendGroupCallEndSignalDecimal:
		return "sendGroupCallEndSignal", true
	case GSMMAPOperationLocalvalueProcessGroupCallSignallingDecimal:
		return "processGroupCallSignalling", true
	case GSMMAPOperationLocalvalueForwardGroupCallSignallingDecimal:
		return "forwardGroupCallSignalling", true
	case GSMMAPOperationLocalvalueCheckIMEIDecimal:
		return "checkIMEI", true
	case GSMMAPOperationLocalvalueMtForwardSMDecimal:
		return "mt-forwardSM", true
	case GSMMAPOperationLocalvalueSendRoutingInfoForSMDecimal:
		return "sendRoutingInfoForSM", true
	case GSMMAPOperationLocalvalueMoForwardSMDecimal:
		return "mo-forwardSM", true
	case GSMMAPOperationLocalvalueReportSMDeliveryStatusDecimal:
		return "reportSM-DeliveryStatus", true
	case GSMMAPOperationLocalvalueNoteSubscriberPresentDecimal:
		return "noteSubscriberPresent", true
	case GSMMAPOperationLocalvalueAlertServiceCentreWithoutResultDecimal:
		return "alertServiceCentreWithoutResult", true
	case GSMMAPOperationLocalvalueActivateTraceModeDecimal:
		return "activateTraceMode", true
	case GSMMAPOperationLocalvalueDeactivateTraceModeDecimal:
		return "deactivateTraceMode", true
	case GSMMAPOperationLocalvalueTraceSubscriberActivityDecimal:
		return "traceSubscriberActivity", true
	case GSMMAPOperationLocalvalueUpdateVcsgLocationDecimal:
		return "updateVcsgLocation", true
	case GSMMAPOperationLocalvalueBeginSubscriberActivityDecimal:
		return "beginSubscriberActivity", true
	case GSMMAPOperationLocalvalueSendIdentificationDecimal:
		return "sendIdentification", true
	case GSMMAPOperationLocalvalueSendAuthenticationInfoDecimal:
		return "sendAuthenticationInfo", true
	case GSMMAPOperationLocalvalueRestoreDataDecimal:
		return "restoreData", true
	case GSMMAPOperationLocalvalueSendIMSIDecimal:
		return "sendIMSI", true
	case GSMMAPOperationLocalvalueProcessUnstructuredSSRequestDecimal:
		return "processUnstructuredSS-Request", true
	case GSMMAPOperationLocalvalueUnstructuredSSRequestDecimal:
		return "unstructuredSS-Request", true
	case GSMMAPOperationLocalvalueUnstructuredSSNotifyDecimal:
		return "unstructuredSS-Notify", true
	case GSMMAPOperationLocalvalueAnyTimeSubscriptionInterrogationDecimal:
		return "anyTimeSubscriptionInterrogation", true
	case GSMMAPOperationLocalvalueInformServiceCentreDecimal:
		return "informServiceCentre", true
	case GSMMAPOperationLocalvalueAlertServiceCentreDecimal:
		return "alertServiceCentre", true
	case GSMMAPOperationLocalvalueAnyTimeModificationDecimal:
		return "anyTimeModification", true
	case GSMMAPOperationLocalvalueReadyForSMDecimal:
		return "readyForSM", true
	case GSMMAPOperationLocalvaluePurgeMSDecimal:
		return "purgeMS", true
	case GSMMAPOperationLocalvaluePrepareHandoverDecimal:
		return "prepareHandover", true
	case GSMMAPOperationLocalvaluePrepareSubsequentHandoverDecimal:
		return "prepareSubsequentHandover", true
	case GSMMAPOperationLocalvalueProvideSubscriberInfoDecimal:
		return "provideSubscriberInfo", true
	case GSMMAPOperationLocalvalueAnyTimeInterrogationDecimal:
		return "anyTimeInterrogation", true
	case GSMMAPOperationLocalvalueSsInvocationNotificationDecimal:
		return "ss-InvocationNotification", true
	case GSMMAPOperationLocalvalueSetReportingStateDecimal:
		return "setReportingState", true
	case GSMMAPOperationLocalvalueStatusReportDecimal:
		return "statusReport", true
	case GSMMAPOperationLocalvalueRemoteUserFreeDecimal:
		return "remoteUserFree", true
	case GSMMAPOperationLocalvalueRegisterCCEntryDecimal:
		return "registerCC-Entry", true
	case GSMMAPOperationLocalvalueEraseCCEntryDecimal:
		return "eraseCC-Entry", true
	case GSMMAPOperationLocalvalueSecureTransportClass1Decimal:
		return "secureTransportClass1", true
	case GSMMAPOperationLocalvalueSecureTransportClass2Decimal:
		return "secureTransportClass2", true
	case GSMMAPOperationLocalvalueSecureTransportClass3Decimal:
		return "secureTransportClass3", true
	case GSMMAPOperationLocalvalueSecureTransportClass4Decimal:
		return "secureTransportClass4", true
	case GSMMAPOperationLocalvalueProvideSubscriberLocationDecimal:
		return "provideSubscriberLocation", true
	case GSMMAPOperationLocalvalueSendGroupCallInfoDecimal:
		return "sendGroupCallInfo", true
	case GSMMAPOperationLocalvalueSendRoutingInfoForLCSDecimal:
		return "sendRoutingInfoForLCS", true
	case GSMMAPOperationLocalvalueSubscriberLocationReportDecimal:
		return "subscriberLocationReport", true
	case GSMMAPOperationLocalvalueIstAlertDecimal:
		return "ist-Alert", true
	case GSMMAPOperationLocalvalueIstCommandDecimal:
		return "ist-Command", true
	case GSMMAPOperationLocalvalueNoteMMEventDecimal:
		return "noteMM-Event", true
	case GSMMAPOperationLocalvalueLcsPeriodicLocationCancellationDecimal:
		return "lcs-PeriodicLocationCancellation", true
	case GSMMAPOperationLocalvalueLcsLocationUpdateDecimal:
		return "lcs-LocationUpdate", true
	case GSMMAPOperationLocalvalueLcsPeriodicLocationRequestDecimal:
		return "lcs-PeriodicLocationRequest", true
	case GSMMAPOperationLocalvalueLcsAreaEventCancellationDecimal:
		return "lcs-AreaEventCancellation", true
	case GSMMAPOperationLocalvalueLcsAreaEventReportDecimal:
		return "lcs-AreaEventReport", true
	case GSMMAPOperationLocalvalueLcsAreaEventRequestDecimal:
		return "lcs-AreaEventRequest", true
	case GSMMAPOperationLocalvalueLcsMOLRDecimal:
		return "lcs-MOLR", true
	case GSMMAPOperationLocalvalueLcsLocationNotificationDecimal:
		return "lcs-LocationNotification", true
	case GSMMAPOperationLocalvalueCallDeflectionDecimal:
		return "callDeflection", true
	case GSMMAPOperationLocalvalueUserUserServiceDecimal:
		return "userUserService", true
	case GSMMAPOperationLocalvalueAccessRegisterCCEntryDecimal:
		return "accessRegisterCCEntry", true
	case GSMMAPOperationLocalvalueForwardCUGInfoDecimal:
		return "forwardCUG-Info", true
	case GSMMAPOperationLocalvalueSplitMPTYDecimal:
		return "splitMPTY", true
	case GSMMAPOperationLocalvalueRetrieveMPTYDecimal:
		return "retrieveMPTY", true
	case GSMMAPOperationLocalvalueHoldMPTYDecimal:
		return "holdMPTY", true
	case GSMMAPOperationLocalvalueBuildMPTYDecimal:
		return "buildMPTY", true
	case GSMMAPOperationLocalvalueForwardChargeAdviceDecimal:
		return "forwardChargeAdvice", true
	case GSMMAPOperationLocalvalueExplicitCTDecimal:
		return "explicitCT", true
	default:
		return "", false
	}
}

func (v GSMMAPOperationLocalvalue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v GSMMAPOperationLocalvalue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *GSMMAPOperationLocalvalue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal GSMMAPOperationLocalvalue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewGSMMAPOperationLocalvalue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v GSMMAPOperationLocalvalue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *GSMMAPOperationLocalvalue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal GSMMAPOperationLocalvalue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewGSMMAPOperationLocalvalue(value)
	return nil
}

// OperationLocalvalue represents the arbitrary-width ASN.1 INTEGER type OperationLocalvalue with named numbers.
type OperationLocalvalue struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	OperationLocalvalueUpdateLocationDecimal                   = "2"
	OperationLocalvalueUpdateLocation                          = 2
	OperationLocalvalueCancelLocationDecimal                   = "3"
	OperationLocalvalueCancelLocation                          = 3
	OperationLocalvalueProvideRoamingNumberDecimal             = "4"
	OperationLocalvalueProvideRoamingNumber                    = 4
	OperationLocalvalueNoteSubscriberDataModifiedDecimal       = "5"
	OperationLocalvalueNoteSubscriberDataModified              = 5
	OperationLocalvalueResumeCallHandlingDecimal               = "6"
	OperationLocalvalueResumeCallHandling                      = 6
	OperationLocalvalueInsertSubscriberDataDecimal             = "7"
	OperationLocalvalueInsertSubscriberData                    = 7
	OperationLocalvalueDeleteSubscriberDataDecimal             = "8"
	OperationLocalvalueDeleteSubscriberData                    = 8
	OperationLocalvalueSendParametersDecimal                   = "9"
	OperationLocalvalueSendParameters                          = 9
	OperationLocalvalueRegisterSSDecimal                       = "10"
	OperationLocalvalueRegisterSS                              = 10
	OperationLocalvalueEraseSSDecimal                          = "11"
	OperationLocalvalueEraseSS                                 = 11
	OperationLocalvalueActivateSSDecimal                       = "12"
	OperationLocalvalueActivateSS                              = 12
	OperationLocalvalueDeactivateSSDecimal                     = "13"
	OperationLocalvalueDeactivateSS                            = 13
	OperationLocalvalueInterrogateSSDecimal                    = "14"
	OperationLocalvalueInterrogateSS                           = 14
	OperationLocalvalueAuthenticationFailureReportDecimal      = "15"
	OperationLocalvalueAuthenticationFailureReport             = 15
	OperationLocalvalueNotifySSDecimal                         = "16"
	OperationLocalvalueNotifySS                                = 16
	OperationLocalvalueRegisterPasswordDecimal                 = "17"
	OperationLocalvalueRegisterPassword                        = 17
	OperationLocalvalueGetPasswordDecimal                      = "18"
	OperationLocalvalueGetPassword                             = 18
	OperationLocalvalueProcessUnstructuredSSDataDecimal        = "19"
	OperationLocalvalueProcessUnstructuredSSData               = 19
	OperationLocalvalueReleaseResourcesDecimal                 = "20"
	OperationLocalvalueReleaseResources                        = 20
	OperationLocalvalueMtForwardSMVGCSDecimal                  = "21"
	OperationLocalvalueMtForwardSMVGCS                         = 21
	OperationLocalvalueSendRoutingInfoDecimal                  = "22"
	OperationLocalvalueSendRoutingInfo                         = 22
	OperationLocalvalueUpdateGprsLocationDecimal               = "23"
	OperationLocalvalueUpdateGprsLocation                      = 23
	OperationLocalvalueSendRoutingInfoForGprsDecimal           = "24"
	OperationLocalvalueSendRoutingInfoForGprs                  = 24
	OperationLocalvalueFailureReportDecimal                    = "25"
	OperationLocalvalueFailureReport                           = 25
	OperationLocalvalueNoteMsPresentForGprsDecimal             = "26"
	OperationLocalvalueNoteMsPresentForGprs                    = 26
	OperationLocalvaluePerformHandoverDecimal                  = "28"
	OperationLocalvaluePerformHandover                         = 28
	OperationLocalvalueSendEndSignalDecimal                    = "29"
	OperationLocalvalueSendEndSignal                           = 29
	OperationLocalvaluePerformSubsequentHandoverDecimal        = "30"
	OperationLocalvaluePerformSubsequentHandover               = 30
	OperationLocalvalueProvideSIWFSNumberDecimal               = "31"
	OperationLocalvalueProvideSIWFSNumber                      = 31
	OperationLocalvalueSIWFSSignallingModifyDecimal            = "32"
	OperationLocalvalueSIWFSSignallingModify                   = 32
	OperationLocalvalueProcessAccessSignallingDecimal          = "33"
	OperationLocalvalueProcessAccessSignalling                 = 33
	OperationLocalvalueForwardAccessSignallingDecimal          = "34"
	OperationLocalvalueForwardAccessSignalling                 = 34
	OperationLocalvalueNoteInternalHandoverDecimal             = "35"
	OperationLocalvalueNoteInternalHandover                    = 35
	OperationLocalvalueCancelVcsgLocationDecimal               = "36"
	OperationLocalvalueCancelVcsgLocation                      = 36
	OperationLocalvalueResetDecimal                            = "37"
	OperationLocalvalueReset                                   = 37
	OperationLocalvalueForwardCheckSSDecimal                   = "38"
	OperationLocalvalueForwardCheckSS                          = 38
	OperationLocalvaluePrepareGroupCallDecimal                 = "39"
	OperationLocalvaluePrepareGroupCall                        = 39
	OperationLocalvalueSendGroupCallEndSignalDecimal           = "40"
	OperationLocalvalueSendGroupCallEndSignal                  = 40
	OperationLocalvalueProcessGroupCallSignallingDecimal       = "41"
	OperationLocalvalueProcessGroupCallSignalling              = 41
	OperationLocalvalueForwardGroupCallSignallingDecimal       = "42"
	OperationLocalvalueForwardGroupCallSignalling              = 42
	OperationLocalvalueCheckIMEIDecimal                        = "43"
	OperationLocalvalueCheckIMEI                               = 43
	OperationLocalvalueMtForwardSMDecimal                      = "44"
	OperationLocalvalueMtForwardSM                             = 44
	OperationLocalvalueSendRoutingInfoForSMDecimal             = "45"
	OperationLocalvalueSendRoutingInfoForSM                    = 45
	OperationLocalvalueMoForwardSMDecimal                      = "46"
	OperationLocalvalueMoForwardSM                             = 46
	OperationLocalvalueReportSMDeliveryStatusDecimal           = "47"
	OperationLocalvalueReportSMDeliveryStatus                  = 47
	OperationLocalvalueNoteSubscriberPresentDecimal            = "48"
	OperationLocalvalueNoteSubscriberPresent                   = 48
	OperationLocalvalueAlertServiceCentreWithoutResultDecimal  = "49"
	OperationLocalvalueAlertServiceCentreWithoutResult         = 49
	OperationLocalvalueActivateTraceModeDecimal                = "50"
	OperationLocalvalueActivateTraceMode                       = 50
	OperationLocalvalueDeactivateTraceModeDecimal              = "51"
	OperationLocalvalueDeactivateTraceMode                     = 51
	OperationLocalvalueTraceSubscriberActivityDecimal          = "52"
	OperationLocalvalueTraceSubscriberActivity                 = 52
	OperationLocalvalueUpdateVcsgLocationDecimal               = "53"
	OperationLocalvalueUpdateVcsgLocation                      = 53
	OperationLocalvalueBeginSubscriberActivityDecimal          = "54"
	OperationLocalvalueBeginSubscriberActivity                 = 54
	OperationLocalvalueSendIdentificationDecimal               = "55"
	OperationLocalvalueSendIdentification                      = 55
	OperationLocalvalueSendAuthenticationInfoDecimal           = "56"
	OperationLocalvalueSendAuthenticationInfo                  = 56
	OperationLocalvalueRestoreDataDecimal                      = "57"
	OperationLocalvalueRestoreData                             = 57
	OperationLocalvalueSendIMSIDecimal                         = "58"
	OperationLocalvalueSendIMSI                                = 58
	OperationLocalvalueProcessUnstructuredSSRequestDecimal     = "59"
	OperationLocalvalueProcessUnstructuredSSRequest            = 59
	OperationLocalvalueUnstructuredSSRequestDecimal            = "60"
	OperationLocalvalueUnstructuredSSRequest                   = 60
	OperationLocalvalueUnstructuredSSNotifyDecimal             = "61"
	OperationLocalvalueUnstructuredSSNotify                    = 61
	OperationLocalvalueAnyTimeSubscriptionInterrogationDecimal = "62"
	OperationLocalvalueAnyTimeSubscriptionInterrogation        = 62
	OperationLocalvalueInformServiceCentreDecimal              = "63"
	OperationLocalvalueInformServiceCentre                     = 63
	OperationLocalvalueAlertServiceCentreDecimal               = "64"
	OperationLocalvalueAlertServiceCentre                      = 64
	OperationLocalvalueAnyTimeModificationDecimal              = "65"
	OperationLocalvalueAnyTimeModification                     = 65
	OperationLocalvalueReadyForSMDecimal                       = "66"
	OperationLocalvalueReadyForSM                              = 66
	OperationLocalvaluePurgeMSDecimal                          = "67"
	OperationLocalvaluePurgeMS                                 = 67
	OperationLocalvaluePrepareHandoverDecimal                  = "68"
	OperationLocalvaluePrepareHandover                         = 68
	OperationLocalvaluePrepareSubsequentHandoverDecimal        = "69"
	OperationLocalvaluePrepareSubsequentHandover               = 69
	OperationLocalvalueProvideSubscriberInfoDecimal            = "70"
	OperationLocalvalueProvideSubscriberInfo                   = 70
	OperationLocalvalueAnyTimeInterrogationDecimal             = "71"
	OperationLocalvalueAnyTimeInterrogation                    = 71
	OperationLocalvalueSsInvocationNotificationDecimal         = "72"
	OperationLocalvalueSsInvocationNotification                = 72
	OperationLocalvalueSetReportingStateDecimal                = "73"
	OperationLocalvalueSetReportingState                       = 73
	OperationLocalvalueStatusReportDecimal                     = "74"
	OperationLocalvalueStatusReport                            = 74
	OperationLocalvalueRemoteUserFreeDecimal                   = "75"
	OperationLocalvalueRemoteUserFree                          = 75
	OperationLocalvalueRegisterCCEntryDecimal                  = "76"
	OperationLocalvalueRegisterCCEntry                         = 76
	OperationLocalvalueEraseCCEntryDecimal                     = "77"
	OperationLocalvalueEraseCCEntry                            = 77
	OperationLocalvalueSecureTransportClass1Decimal            = "78"
	OperationLocalvalueSecureTransportClass1                   = 78
	OperationLocalvalueSecureTransportClass2Decimal            = "79"
	OperationLocalvalueSecureTransportClass2                   = 79
	OperationLocalvalueSecureTransportClass3Decimal            = "80"
	OperationLocalvalueSecureTransportClass3                   = 80
	OperationLocalvalueSecureTransportClass4Decimal            = "81"
	OperationLocalvalueSecureTransportClass4                   = 81
	OperationLocalvalueProvideSubscriberLocationDecimal        = "83"
	OperationLocalvalueProvideSubscriberLocation               = 83
	OperationLocalvalueSendGroupCallInfoDecimal                = "84"
	OperationLocalvalueSendGroupCallInfo                       = 84
	OperationLocalvalueSendRoutingInfoForLCSDecimal            = "85"
	OperationLocalvalueSendRoutingInfoForLCS                   = 85
	OperationLocalvalueSubscriberLocationReportDecimal         = "86"
	OperationLocalvalueSubscriberLocationReport                = 86
	OperationLocalvalueIstAlertDecimal                         = "87"
	OperationLocalvalueIstAlert                                = 87
	OperationLocalvalueIstCommandDecimal                       = "88"
	OperationLocalvalueIstCommand                              = 88
	OperationLocalvalueNoteMMEventDecimal                      = "89"
	OperationLocalvalueNoteMMEvent                             = 89
	OperationLocalvalueLcsPeriodicLocationCancellationDecimal  = "109"
	OperationLocalvalueLcsPeriodicLocationCancellation         = 109
	OperationLocalvalueLcsLocationUpdateDecimal                = "110"
	OperationLocalvalueLcsLocationUpdate                       = 110
	OperationLocalvalueLcsPeriodicLocationRequestDecimal       = "111"
	OperationLocalvalueLcsPeriodicLocationRequest              = 111
	OperationLocalvalueLcsAreaEventCancellationDecimal         = "112"
	OperationLocalvalueLcsAreaEventCancellation                = 112
	OperationLocalvalueLcsAreaEventReportDecimal               = "113"
	OperationLocalvalueLcsAreaEventReport                      = 113
	OperationLocalvalueLcsAreaEventRequestDecimal              = "114"
	OperationLocalvalueLcsAreaEventRequest                     = 114
	OperationLocalvalueLcsMOLRDecimal                          = "115"
	OperationLocalvalueLcsMOLR                                 = 115
	OperationLocalvalueLcsLocationNotificationDecimal          = "116"
	OperationLocalvalueLcsLocationNotification                 = 116
	OperationLocalvalueCallDeflectionDecimal                   = "117"
	OperationLocalvalueCallDeflection                          = 117
	OperationLocalvalueUserUserServiceDecimal                  = "118"
	OperationLocalvalueUserUserService                         = 118
	OperationLocalvalueAccessRegisterCCEntryDecimal            = "119"
	OperationLocalvalueAccessRegisterCCEntry                   = 119
	OperationLocalvalueForwardCUGInfoDecimal                   = "120"
	OperationLocalvalueForwardCUGInfo                          = 120
	OperationLocalvalueSplitMPTYDecimal                        = "121"
	OperationLocalvalueSplitMPTY                               = 121
	OperationLocalvalueRetrieveMPTYDecimal                     = "122"
	OperationLocalvalueRetrieveMPTY                            = 122
	OperationLocalvalueHoldMPTYDecimal                         = "123"
	OperationLocalvalueHoldMPTY                                = 123
	OperationLocalvalueBuildMPTYDecimal                        = "124"
	OperationLocalvalueBuildMPTY                               = 124
	OperationLocalvalueForwardChargeAdviceDecimal              = "125"
	OperationLocalvalueForwardChargeAdvice                     = 125
	OperationLocalvalueExplicitCTDecimal                       = "126"
	OperationLocalvalueExplicitCT                              = 126
)

// NewOperationLocalvalue returns an immutable OperationLocalvalue containing value.
func NewOperationLocalvalue(value *big.Int) OperationLocalvalue {
	return OperationLocalvalue{value: runtime.CloneBigInt(value)}
}

// NewOperationLocalvalueInt64 returns a OperationLocalvalue containing value.
func NewOperationLocalvalueInt64(value int64) OperationLocalvalue {
	return NewOperationLocalvalue(big.NewInt(value))
}

// OperationLocalvalueUpdateLocationValue returns the named value updateLocation.
func OperationLocalvalueUpdateLocationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueUpdateLocationDecimal))
}

// OperationLocalvalueCancelLocationValue returns the named value cancelLocation.
func OperationLocalvalueCancelLocationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueCancelLocationDecimal))
}

// OperationLocalvalueProvideRoamingNumberValue returns the named value provideRoamingNumber.
func OperationLocalvalueProvideRoamingNumberValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueProvideRoamingNumberDecimal))
}

// OperationLocalvalueNoteSubscriberDataModifiedValue returns the named value noteSubscriberDataModified.
func OperationLocalvalueNoteSubscriberDataModifiedValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueNoteSubscriberDataModifiedDecimal))
}

// OperationLocalvalueResumeCallHandlingValue returns the named value resumeCallHandling.
func OperationLocalvalueResumeCallHandlingValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueResumeCallHandlingDecimal))
}

// OperationLocalvalueInsertSubscriberDataValue returns the named value insertSubscriberData.
func OperationLocalvalueInsertSubscriberDataValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueInsertSubscriberDataDecimal))
}

// OperationLocalvalueDeleteSubscriberDataValue returns the named value deleteSubscriberData.
func OperationLocalvalueDeleteSubscriberDataValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueDeleteSubscriberDataDecimal))
}

// OperationLocalvalueSendParametersValue returns the named value sendParameters.
func OperationLocalvalueSendParametersValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSendParametersDecimal))
}

// OperationLocalvalueRegisterSSValue returns the named value registerSS.
func OperationLocalvalueRegisterSSValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueRegisterSSDecimal))
}

// OperationLocalvalueEraseSSValue returns the named value eraseSS.
func OperationLocalvalueEraseSSValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueEraseSSDecimal))
}

// OperationLocalvalueActivateSSValue returns the named value activateSS.
func OperationLocalvalueActivateSSValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueActivateSSDecimal))
}

// OperationLocalvalueDeactivateSSValue returns the named value deactivateSS.
func OperationLocalvalueDeactivateSSValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueDeactivateSSDecimal))
}

// OperationLocalvalueInterrogateSSValue returns the named value interrogateSS.
func OperationLocalvalueInterrogateSSValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueInterrogateSSDecimal))
}

// OperationLocalvalueAuthenticationFailureReportValue returns the named value authenticationFailureReport.
func OperationLocalvalueAuthenticationFailureReportValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueAuthenticationFailureReportDecimal))
}

// OperationLocalvalueNotifySSValue returns the named value notifySS.
func OperationLocalvalueNotifySSValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueNotifySSDecimal))
}

// OperationLocalvalueRegisterPasswordValue returns the named value registerPassword.
func OperationLocalvalueRegisterPasswordValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueRegisterPasswordDecimal))
}

// OperationLocalvalueGetPasswordValue returns the named value getPassword.
func OperationLocalvalueGetPasswordValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueGetPasswordDecimal))
}

// OperationLocalvalueProcessUnstructuredSSDataValue returns the named value processUnstructuredSS-Data.
func OperationLocalvalueProcessUnstructuredSSDataValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueProcessUnstructuredSSDataDecimal))
}

// OperationLocalvalueReleaseResourcesValue returns the named value releaseResources.
func OperationLocalvalueReleaseResourcesValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueReleaseResourcesDecimal))
}

// OperationLocalvalueMtForwardSMVGCSValue returns the named value mt-ForwardSM-VGCS.
func OperationLocalvalueMtForwardSMVGCSValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueMtForwardSMVGCSDecimal))
}

// OperationLocalvalueSendRoutingInfoValue returns the named value sendRoutingInfo.
func OperationLocalvalueSendRoutingInfoValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSendRoutingInfoDecimal))
}

// OperationLocalvalueUpdateGprsLocationValue returns the named value updateGprsLocation.
func OperationLocalvalueUpdateGprsLocationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueUpdateGprsLocationDecimal))
}

// OperationLocalvalueSendRoutingInfoForGprsValue returns the named value sendRoutingInfoForGprs.
func OperationLocalvalueSendRoutingInfoForGprsValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSendRoutingInfoForGprsDecimal))
}

// OperationLocalvalueFailureReportValue returns the named value failureReport.
func OperationLocalvalueFailureReportValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueFailureReportDecimal))
}

// OperationLocalvalueNoteMsPresentForGprsValue returns the named value noteMsPresentForGprs.
func OperationLocalvalueNoteMsPresentForGprsValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueNoteMsPresentForGprsDecimal))
}

// OperationLocalvaluePerformHandoverValue returns the named value performHandover.
func OperationLocalvaluePerformHandoverValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvaluePerformHandoverDecimal))
}

// OperationLocalvalueSendEndSignalValue returns the named value sendEndSignal.
func OperationLocalvalueSendEndSignalValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSendEndSignalDecimal))
}

// OperationLocalvaluePerformSubsequentHandoverValue returns the named value performSubsequentHandover.
func OperationLocalvaluePerformSubsequentHandoverValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvaluePerformSubsequentHandoverDecimal))
}

// OperationLocalvalueProvideSIWFSNumberValue returns the named value provideSIWFSNumber.
func OperationLocalvalueProvideSIWFSNumberValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueProvideSIWFSNumberDecimal))
}

// OperationLocalvalueSIWFSSignallingModifyValue returns the named value sIWFSSignallingModify.
func OperationLocalvalueSIWFSSignallingModifyValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSIWFSSignallingModifyDecimal))
}

// OperationLocalvalueProcessAccessSignallingValue returns the named value processAccessSignalling.
func OperationLocalvalueProcessAccessSignallingValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueProcessAccessSignallingDecimal))
}

// OperationLocalvalueForwardAccessSignallingValue returns the named value forwardAccessSignalling.
func OperationLocalvalueForwardAccessSignallingValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueForwardAccessSignallingDecimal))
}

// OperationLocalvalueNoteInternalHandoverValue returns the named value noteInternalHandover.
func OperationLocalvalueNoteInternalHandoverValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueNoteInternalHandoverDecimal))
}

// OperationLocalvalueCancelVcsgLocationValue returns the named value cancelVcsgLocation.
func OperationLocalvalueCancelVcsgLocationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueCancelVcsgLocationDecimal))
}

// OperationLocalvalueResetValue returns the named value reset.
func OperationLocalvalueResetValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueResetDecimal))
}

// OperationLocalvalueForwardCheckSSValue returns the named value forwardCheckSS.
func OperationLocalvalueForwardCheckSSValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueForwardCheckSSDecimal))
}

// OperationLocalvaluePrepareGroupCallValue returns the named value prepareGroupCall.
func OperationLocalvaluePrepareGroupCallValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvaluePrepareGroupCallDecimal))
}

// OperationLocalvalueSendGroupCallEndSignalValue returns the named value sendGroupCallEndSignal.
func OperationLocalvalueSendGroupCallEndSignalValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSendGroupCallEndSignalDecimal))
}

// OperationLocalvalueProcessGroupCallSignallingValue returns the named value processGroupCallSignalling.
func OperationLocalvalueProcessGroupCallSignallingValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueProcessGroupCallSignallingDecimal))
}

// OperationLocalvalueForwardGroupCallSignallingValue returns the named value forwardGroupCallSignalling.
func OperationLocalvalueForwardGroupCallSignallingValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueForwardGroupCallSignallingDecimal))
}

// OperationLocalvalueCheckIMEIValue returns the named value checkIMEI.
func OperationLocalvalueCheckIMEIValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueCheckIMEIDecimal))
}

// OperationLocalvalueMtForwardSMValue returns the named value mt-forwardSM.
func OperationLocalvalueMtForwardSMValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueMtForwardSMDecimal))
}

// OperationLocalvalueSendRoutingInfoForSMValue returns the named value sendRoutingInfoForSM.
func OperationLocalvalueSendRoutingInfoForSMValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSendRoutingInfoForSMDecimal))
}

// OperationLocalvalueMoForwardSMValue returns the named value mo-forwardSM.
func OperationLocalvalueMoForwardSMValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueMoForwardSMDecimal))
}

// OperationLocalvalueReportSMDeliveryStatusValue returns the named value reportSM-DeliveryStatus.
func OperationLocalvalueReportSMDeliveryStatusValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueReportSMDeliveryStatusDecimal))
}

// OperationLocalvalueNoteSubscriberPresentValue returns the named value noteSubscriberPresent.
func OperationLocalvalueNoteSubscriberPresentValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueNoteSubscriberPresentDecimal))
}

// OperationLocalvalueAlertServiceCentreWithoutResultValue returns the named value alertServiceCentreWithoutResult.
func OperationLocalvalueAlertServiceCentreWithoutResultValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueAlertServiceCentreWithoutResultDecimal))
}

// OperationLocalvalueActivateTraceModeValue returns the named value activateTraceMode.
func OperationLocalvalueActivateTraceModeValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueActivateTraceModeDecimal))
}

// OperationLocalvalueDeactivateTraceModeValue returns the named value deactivateTraceMode.
func OperationLocalvalueDeactivateTraceModeValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueDeactivateTraceModeDecimal))
}

// OperationLocalvalueTraceSubscriberActivityValue returns the named value traceSubscriberActivity.
func OperationLocalvalueTraceSubscriberActivityValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueTraceSubscriberActivityDecimal))
}

// OperationLocalvalueUpdateVcsgLocationValue returns the named value updateVcsgLocation.
func OperationLocalvalueUpdateVcsgLocationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueUpdateVcsgLocationDecimal))
}

// OperationLocalvalueBeginSubscriberActivityValue returns the named value beginSubscriberActivity.
func OperationLocalvalueBeginSubscriberActivityValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueBeginSubscriberActivityDecimal))
}

// OperationLocalvalueSendIdentificationValue returns the named value sendIdentification.
func OperationLocalvalueSendIdentificationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSendIdentificationDecimal))
}

// OperationLocalvalueSendAuthenticationInfoValue returns the named value sendAuthenticationInfo.
func OperationLocalvalueSendAuthenticationInfoValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSendAuthenticationInfoDecimal))
}

// OperationLocalvalueRestoreDataValue returns the named value restoreData.
func OperationLocalvalueRestoreDataValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueRestoreDataDecimal))
}

// OperationLocalvalueSendIMSIValue returns the named value sendIMSI.
func OperationLocalvalueSendIMSIValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSendIMSIDecimal))
}

// OperationLocalvalueProcessUnstructuredSSRequestValue returns the named value processUnstructuredSS-Request.
func OperationLocalvalueProcessUnstructuredSSRequestValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueProcessUnstructuredSSRequestDecimal))
}

// OperationLocalvalueUnstructuredSSRequestValue returns the named value unstructuredSS-Request.
func OperationLocalvalueUnstructuredSSRequestValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueUnstructuredSSRequestDecimal))
}

// OperationLocalvalueUnstructuredSSNotifyValue returns the named value unstructuredSS-Notify.
func OperationLocalvalueUnstructuredSSNotifyValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueUnstructuredSSNotifyDecimal))
}

// OperationLocalvalueAnyTimeSubscriptionInterrogationValue returns the named value anyTimeSubscriptionInterrogation.
func OperationLocalvalueAnyTimeSubscriptionInterrogationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueAnyTimeSubscriptionInterrogationDecimal))
}

// OperationLocalvalueInformServiceCentreValue returns the named value informServiceCentre.
func OperationLocalvalueInformServiceCentreValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueInformServiceCentreDecimal))
}

// OperationLocalvalueAlertServiceCentreValue returns the named value alertServiceCentre.
func OperationLocalvalueAlertServiceCentreValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueAlertServiceCentreDecimal))
}

// OperationLocalvalueAnyTimeModificationValue returns the named value anyTimeModification.
func OperationLocalvalueAnyTimeModificationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueAnyTimeModificationDecimal))
}

// OperationLocalvalueReadyForSMValue returns the named value readyForSM.
func OperationLocalvalueReadyForSMValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueReadyForSMDecimal))
}

// OperationLocalvaluePurgeMSValue returns the named value purgeMS.
func OperationLocalvaluePurgeMSValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvaluePurgeMSDecimal))
}

// OperationLocalvaluePrepareHandoverValue returns the named value prepareHandover.
func OperationLocalvaluePrepareHandoverValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvaluePrepareHandoverDecimal))
}

// OperationLocalvaluePrepareSubsequentHandoverValue returns the named value prepareSubsequentHandover.
func OperationLocalvaluePrepareSubsequentHandoverValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvaluePrepareSubsequentHandoverDecimal))
}

// OperationLocalvalueProvideSubscriberInfoValue returns the named value provideSubscriberInfo.
func OperationLocalvalueProvideSubscriberInfoValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueProvideSubscriberInfoDecimal))
}

// OperationLocalvalueAnyTimeInterrogationValue returns the named value anyTimeInterrogation.
func OperationLocalvalueAnyTimeInterrogationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueAnyTimeInterrogationDecimal))
}

// OperationLocalvalueSsInvocationNotificationValue returns the named value ss-InvocationNotification.
func OperationLocalvalueSsInvocationNotificationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSsInvocationNotificationDecimal))
}

// OperationLocalvalueSetReportingStateValue returns the named value setReportingState.
func OperationLocalvalueSetReportingStateValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSetReportingStateDecimal))
}

// OperationLocalvalueStatusReportValue returns the named value statusReport.
func OperationLocalvalueStatusReportValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueStatusReportDecimal))
}

// OperationLocalvalueRemoteUserFreeValue returns the named value remoteUserFree.
func OperationLocalvalueRemoteUserFreeValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueRemoteUserFreeDecimal))
}

// OperationLocalvalueRegisterCCEntryValue returns the named value registerCC-Entry.
func OperationLocalvalueRegisterCCEntryValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueRegisterCCEntryDecimal))
}

// OperationLocalvalueEraseCCEntryValue returns the named value eraseCC-Entry.
func OperationLocalvalueEraseCCEntryValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueEraseCCEntryDecimal))
}

// OperationLocalvalueSecureTransportClass1Value returns the named value secureTransportClass1.
func OperationLocalvalueSecureTransportClass1Value() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSecureTransportClass1Decimal))
}

// OperationLocalvalueSecureTransportClass2Value returns the named value secureTransportClass2.
func OperationLocalvalueSecureTransportClass2Value() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSecureTransportClass2Decimal))
}

// OperationLocalvalueSecureTransportClass3Value returns the named value secureTransportClass3.
func OperationLocalvalueSecureTransportClass3Value() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSecureTransportClass3Decimal))
}

// OperationLocalvalueSecureTransportClass4Value returns the named value secureTransportClass4.
func OperationLocalvalueSecureTransportClass4Value() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSecureTransportClass4Decimal))
}

// OperationLocalvalueProvideSubscriberLocationValue returns the named value provideSubscriberLocation.
func OperationLocalvalueProvideSubscriberLocationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueProvideSubscriberLocationDecimal))
}

// OperationLocalvalueSendGroupCallInfoValue returns the named value sendGroupCallInfo.
func OperationLocalvalueSendGroupCallInfoValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSendGroupCallInfoDecimal))
}

// OperationLocalvalueSendRoutingInfoForLCSValue returns the named value sendRoutingInfoForLCS.
func OperationLocalvalueSendRoutingInfoForLCSValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSendRoutingInfoForLCSDecimal))
}

// OperationLocalvalueSubscriberLocationReportValue returns the named value subscriberLocationReport.
func OperationLocalvalueSubscriberLocationReportValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSubscriberLocationReportDecimal))
}

// OperationLocalvalueIstAlertValue returns the named value ist-Alert.
func OperationLocalvalueIstAlertValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueIstAlertDecimal))
}

// OperationLocalvalueIstCommandValue returns the named value ist-Command.
func OperationLocalvalueIstCommandValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueIstCommandDecimal))
}

// OperationLocalvalueNoteMMEventValue returns the named value noteMM-Event.
func OperationLocalvalueNoteMMEventValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueNoteMMEventDecimal))
}

// OperationLocalvalueLcsPeriodicLocationCancellationValue returns the named value lcs-PeriodicLocationCancellation.
func OperationLocalvalueLcsPeriodicLocationCancellationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueLcsPeriodicLocationCancellationDecimal))
}

// OperationLocalvalueLcsLocationUpdateValue returns the named value lcs-LocationUpdate.
func OperationLocalvalueLcsLocationUpdateValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueLcsLocationUpdateDecimal))
}

// OperationLocalvalueLcsPeriodicLocationRequestValue returns the named value lcs-PeriodicLocationRequest.
func OperationLocalvalueLcsPeriodicLocationRequestValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueLcsPeriodicLocationRequestDecimal))
}

// OperationLocalvalueLcsAreaEventCancellationValue returns the named value lcs-AreaEventCancellation.
func OperationLocalvalueLcsAreaEventCancellationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueLcsAreaEventCancellationDecimal))
}

// OperationLocalvalueLcsAreaEventReportValue returns the named value lcs-AreaEventReport.
func OperationLocalvalueLcsAreaEventReportValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueLcsAreaEventReportDecimal))
}

// OperationLocalvalueLcsAreaEventRequestValue returns the named value lcs-AreaEventRequest.
func OperationLocalvalueLcsAreaEventRequestValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueLcsAreaEventRequestDecimal))
}

// OperationLocalvalueLcsMOLRValue returns the named value lcs-MOLR.
func OperationLocalvalueLcsMOLRValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueLcsMOLRDecimal))
}

// OperationLocalvalueLcsLocationNotificationValue returns the named value lcs-LocationNotification.
func OperationLocalvalueLcsLocationNotificationValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueLcsLocationNotificationDecimal))
}

// OperationLocalvalueCallDeflectionValue returns the named value callDeflection.
func OperationLocalvalueCallDeflectionValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueCallDeflectionDecimal))
}

// OperationLocalvalueUserUserServiceValue returns the named value userUserService.
func OperationLocalvalueUserUserServiceValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueUserUserServiceDecimal))
}

// OperationLocalvalueAccessRegisterCCEntryValue returns the named value accessRegisterCCEntry.
func OperationLocalvalueAccessRegisterCCEntryValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueAccessRegisterCCEntryDecimal))
}

// OperationLocalvalueForwardCUGInfoValue returns the named value forwardCUG-Info.
func OperationLocalvalueForwardCUGInfoValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueForwardCUGInfoDecimal))
}

// OperationLocalvalueSplitMPTYValue returns the named value splitMPTY.
func OperationLocalvalueSplitMPTYValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueSplitMPTYDecimal))
}

// OperationLocalvalueRetrieveMPTYValue returns the named value retrieveMPTY.
func OperationLocalvalueRetrieveMPTYValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueRetrieveMPTYDecimal))
}

// OperationLocalvalueHoldMPTYValue returns the named value holdMPTY.
func OperationLocalvalueHoldMPTYValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueHoldMPTYDecimal))
}

// OperationLocalvalueBuildMPTYValue returns the named value buildMPTY.
func OperationLocalvalueBuildMPTYValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueBuildMPTYDecimal))
}

// OperationLocalvalueForwardChargeAdviceValue returns the named value forwardChargeAdvice.
func OperationLocalvalueForwardChargeAdviceValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueForwardChargeAdviceDecimal))
}

// OperationLocalvalueExplicitCTValue returns the named value explicitCT.
func OperationLocalvalueExplicitCTValue() OperationLocalvalue {
	return NewOperationLocalvalue(runtime.MustParseBigIntDecimal(OperationLocalvalueExplicitCTDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v OperationLocalvalue) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v OperationLocalvalue) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v OperationLocalvalue) Name() (string, bool) {
	switch v.BigInt().String() {
	case OperationLocalvalueUpdateLocationDecimal:
		return "updateLocation", true
	case OperationLocalvalueCancelLocationDecimal:
		return "cancelLocation", true
	case OperationLocalvalueProvideRoamingNumberDecimal:
		return "provideRoamingNumber", true
	case OperationLocalvalueNoteSubscriberDataModifiedDecimal:
		return "noteSubscriberDataModified", true
	case OperationLocalvalueResumeCallHandlingDecimal:
		return "resumeCallHandling", true
	case OperationLocalvalueInsertSubscriberDataDecimal:
		return "insertSubscriberData", true
	case OperationLocalvalueDeleteSubscriberDataDecimal:
		return "deleteSubscriberData", true
	case OperationLocalvalueSendParametersDecimal:
		return "sendParameters", true
	case OperationLocalvalueRegisterSSDecimal:
		return "registerSS", true
	case OperationLocalvalueEraseSSDecimal:
		return "eraseSS", true
	case OperationLocalvalueActivateSSDecimal:
		return "activateSS", true
	case OperationLocalvalueDeactivateSSDecimal:
		return "deactivateSS", true
	case OperationLocalvalueInterrogateSSDecimal:
		return "interrogateSS", true
	case OperationLocalvalueAuthenticationFailureReportDecimal:
		return "authenticationFailureReport", true
	case OperationLocalvalueNotifySSDecimal:
		return "notifySS", true
	case OperationLocalvalueRegisterPasswordDecimal:
		return "registerPassword", true
	case OperationLocalvalueGetPasswordDecimal:
		return "getPassword", true
	case OperationLocalvalueProcessUnstructuredSSDataDecimal:
		return "processUnstructuredSS-Data", true
	case OperationLocalvalueReleaseResourcesDecimal:
		return "releaseResources", true
	case OperationLocalvalueMtForwardSMVGCSDecimal:
		return "mt-ForwardSM-VGCS", true
	case OperationLocalvalueSendRoutingInfoDecimal:
		return "sendRoutingInfo", true
	case OperationLocalvalueUpdateGprsLocationDecimal:
		return "updateGprsLocation", true
	case OperationLocalvalueSendRoutingInfoForGprsDecimal:
		return "sendRoutingInfoForGprs", true
	case OperationLocalvalueFailureReportDecimal:
		return "failureReport", true
	case OperationLocalvalueNoteMsPresentForGprsDecimal:
		return "noteMsPresentForGprs", true
	case OperationLocalvaluePerformHandoverDecimal:
		return "performHandover", true
	case OperationLocalvalueSendEndSignalDecimal:
		return "sendEndSignal", true
	case OperationLocalvaluePerformSubsequentHandoverDecimal:
		return "performSubsequentHandover", true
	case OperationLocalvalueProvideSIWFSNumberDecimal:
		return "provideSIWFSNumber", true
	case OperationLocalvalueSIWFSSignallingModifyDecimal:
		return "sIWFSSignallingModify", true
	case OperationLocalvalueProcessAccessSignallingDecimal:
		return "processAccessSignalling", true
	case OperationLocalvalueForwardAccessSignallingDecimal:
		return "forwardAccessSignalling", true
	case OperationLocalvalueNoteInternalHandoverDecimal:
		return "noteInternalHandover", true
	case OperationLocalvalueCancelVcsgLocationDecimal:
		return "cancelVcsgLocation", true
	case OperationLocalvalueResetDecimal:
		return "reset", true
	case OperationLocalvalueForwardCheckSSDecimal:
		return "forwardCheckSS", true
	case OperationLocalvaluePrepareGroupCallDecimal:
		return "prepareGroupCall", true
	case OperationLocalvalueSendGroupCallEndSignalDecimal:
		return "sendGroupCallEndSignal", true
	case OperationLocalvalueProcessGroupCallSignallingDecimal:
		return "processGroupCallSignalling", true
	case OperationLocalvalueForwardGroupCallSignallingDecimal:
		return "forwardGroupCallSignalling", true
	case OperationLocalvalueCheckIMEIDecimal:
		return "checkIMEI", true
	case OperationLocalvalueMtForwardSMDecimal:
		return "mt-forwardSM", true
	case OperationLocalvalueSendRoutingInfoForSMDecimal:
		return "sendRoutingInfoForSM", true
	case OperationLocalvalueMoForwardSMDecimal:
		return "mo-forwardSM", true
	case OperationLocalvalueReportSMDeliveryStatusDecimal:
		return "reportSM-DeliveryStatus", true
	case OperationLocalvalueNoteSubscriberPresentDecimal:
		return "noteSubscriberPresent", true
	case OperationLocalvalueAlertServiceCentreWithoutResultDecimal:
		return "alertServiceCentreWithoutResult", true
	case OperationLocalvalueActivateTraceModeDecimal:
		return "activateTraceMode", true
	case OperationLocalvalueDeactivateTraceModeDecimal:
		return "deactivateTraceMode", true
	case OperationLocalvalueTraceSubscriberActivityDecimal:
		return "traceSubscriberActivity", true
	case OperationLocalvalueUpdateVcsgLocationDecimal:
		return "updateVcsgLocation", true
	case OperationLocalvalueBeginSubscriberActivityDecimal:
		return "beginSubscriberActivity", true
	case OperationLocalvalueSendIdentificationDecimal:
		return "sendIdentification", true
	case OperationLocalvalueSendAuthenticationInfoDecimal:
		return "sendAuthenticationInfo", true
	case OperationLocalvalueRestoreDataDecimal:
		return "restoreData", true
	case OperationLocalvalueSendIMSIDecimal:
		return "sendIMSI", true
	case OperationLocalvalueProcessUnstructuredSSRequestDecimal:
		return "processUnstructuredSS-Request", true
	case OperationLocalvalueUnstructuredSSRequestDecimal:
		return "unstructuredSS-Request", true
	case OperationLocalvalueUnstructuredSSNotifyDecimal:
		return "unstructuredSS-Notify", true
	case OperationLocalvalueAnyTimeSubscriptionInterrogationDecimal:
		return "anyTimeSubscriptionInterrogation", true
	case OperationLocalvalueInformServiceCentreDecimal:
		return "informServiceCentre", true
	case OperationLocalvalueAlertServiceCentreDecimal:
		return "alertServiceCentre", true
	case OperationLocalvalueAnyTimeModificationDecimal:
		return "anyTimeModification", true
	case OperationLocalvalueReadyForSMDecimal:
		return "readyForSM", true
	case OperationLocalvaluePurgeMSDecimal:
		return "purgeMS", true
	case OperationLocalvaluePrepareHandoverDecimal:
		return "prepareHandover", true
	case OperationLocalvaluePrepareSubsequentHandoverDecimal:
		return "prepareSubsequentHandover", true
	case OperationLocalvalueProvideSubscriberInfoDecimal:
		return "provideSubscriberInfo", true
	case OperationLocalvalueAnyTimeInterrogationDecimal:
		return "anyTimeInterrogation", true
	case OperationLocalvalueSsInvocationNotificationDecimal:
		return "ss-InvocationNotification", true
	case OperationLocalvalueSetReportingStateDecimal:
		return "setReportingState", true
	case OperationLocalvalueStatusReportDecimal:
		return "statusReport", true
	case OperationLocalvalueRemoteUserFreeDecimal:
		return "remoteUserFree", true
	case OperationLocalvalueRegisterCCEntryDecimal:
		return "registerCC-Entry", true
	case OperationLocalvalueEraseCCEntryDecimal:
		return "eraseCC-Entry", true
	case OperationLocalvalueSecureTransportClass1Decimal:
		return "secureTransportClass1", true
	case OperationLocalvalueSecureTransportClass2Decimal:
		return "secureTransportClass2", true
	case OperationLocalvalueSecureTransportClass3Decimal:
		return "secureTransportClass3", true
	case OperationLocalvalueSecureTransportClass4Decimal:
		return "secureTransportClass4", true
	case OperationLocalvalueProvideSubscriberLocationDecimal:
		return "provideSubscriberLocation", true
	case OperationLocalvalueSendGroupCallInfoDecimal:
		return "sendGroupCallInfo", true
	case OperationLocalvalueSendRoutingInfoForLCSDecimal:
		return "sendRoutingInfoForLCS", true
	case OperationLocalvalueSubscriberLocationReportDecimal:
		return "subscriberLocationReport", true
	case OperationLocalvalueIstAlertDecimal:
		return "ist-Alert", true
	case OperationLocalvalueIstCommandDecimal:
		return "ist-Command", true
	case OperationLocalvalueNoteMMEventDecimal:
		return "noteMM-Event", true
	case OperationLocalvalueLcsPeriodicLocationCancellationDecimal:
		return "lcs-PeriodicLocationCancellation", true
	case OperationLocalvalueLcsLocationUpdateDecimal:
		return "lcs-LocationUpdate", true
	case OperationLocalvalueLcsPeriodicLocationRequestDecimal:
		return "lcs-PeriodicLocationRequest", true
	case OperationLocalvalueLcsAreaEventCancellationDecimal:
		return "lcs-AreaEventCancellation", true
	case OperationLocalvalueLcsAreaEventReportDecimal:
		return "lcs-AreaEventReport", true
	case OperationLocalvalueLcsAreaEventRequestDecimal:
		return "lcs-AreaEventRequest", true
	case OperationLocalvalueLcsMOLRDecimal:
		return "lcs-MOLR", true
	case OperationLocalvalueLcsLocationNotificationDecimal:
		return "lcs-LocationNotification", true
	case OperationLocalvalueCallDeflectionDecimal:
		return "callDeflection", true
	case OperationLocalvalueUserUserServiceDecimal:
		return "userUserService", true
	case OperationLocalvalueAccessRegisterCCEntryDecimal:
		return "accessRegisterCCEntry", true
	case OperationLocalvalueForwardCUGInfoDecimal:
		return "forwardCUG-Info", true
	case OperationLocalvalueSplitMPTYDecimal:
		return "splitMPTY", true
	case OperationLocalvalueRetrieveMPTYDecimal:
		return "retrieveMPTY", true
	case OperationLocalvalueHoldMPTYDecimal:
		return "holdMPTY", true
	case OperationLocalvalueBuildMPTYDecimal:
		return "buildMPTY", true
	case OperationLocalvalueForwardChargeAdviceDecimal:
		return "forwardChargeAdvice", true
	case OperationLocalvalueExplicitCTDecimal:
		return "explicitCT", true
	default:
		return "", false
	}
}

func (v OperationLocalvalue) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v OperationLocalvalue) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *OperationLocalvalue) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal OperationLocalvalue into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewOperationLocalvalue(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v OperationLocalvalue) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *OperationLocalvalue) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal OperationLocalvalue into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewOperationLocalvalue(value)
	return nil
}

// MAPERROR choice constants.
const (
	MAPERRORChoiceLocalValue  = 1
	MAPERRORChoiceGlobalValue = 2
)

// MAPERROR represents the ASN.1 CHOICE type MAPERROR.
type MAPERROR struct {
	Choice      int
	LocalValue  *LocalErrorcode          `json:"LocalValue,omitempty"`
	GlobalValue runtime.ObjectIdentifier `json:"GlobalValue,omitempty"`
}

// NewMAPERRORLocalValue creates a MAPERROR with the localValue alternative.
func NewMAPERRORLocalValue(v LocalErrorcode) MAPERROR {
	return MAPERROR{
		Choice:     MAPERRORChoiceLocalValue,
		LocalValue: &v,
	}
}

// NewMAPERRORGlobalValue creates a MAPERROR with the globalValue alternative.
func NewMAPERRORGlobalValue(v runtime.ObjectIdentifier) MAPERROR {
	return MAPERROR{
		Choice:      MAPERRORChoiceGlobalValue,
		GlobalValue: v,
	}
}

// NewMAPERRORLocalValueInt64 creates a MAPERROR localValue alternative from an int64 code.
func NewMAPERRORLocalValueInt64(v int64) MAPERROR {
	var local LocalErrorcode
	if err := local.UnmarshalText([]byte(fmt.Sprintf("%d", v))); err != nil {
		panic(err)
	}
	return NewMAPERRORLocalValue(local)
}

// LocalCode returns the localValue code when this MAPERROR carries an int64 localValue alternative.
func (v MAPERROR) LocalCode() (int64, bool) {
	if v.Choice != MAPERRORChoiceLocalValue || v.LocalValue == nil {
		return 0, false
	}
	return v.LocalValue.AsInt64()
}

// GSMMAPLocalErrorcode represents the arbitrary-width ASN.1 INTEGER type GSMMAPLocalErrorcode with named numbers.
type GSMMAPLocalErrorcode struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	GSMMAPLocalErrorcodeUnknownSubscriberDecimal              = "1"
	GSMMAPLocalErrorcodeUnknownSubscriber                     = 1
	GSMMAPLocalErrorcodeUnknownBaseStationDecimal             = "2"
	GSMMAPLocalErrorcodeUnknownBaseStation                    = 2
	GSMMAPLocalErrorcodeUnknownMSCDecimal                     = "3"
	GSMMAPLocalErrorcodeUnknownMSC                            = 3
	GSMMAPLocalErrorcodeSecureTransportErrorDecimal           = "4"
	GSMMAPLocalErrorcodeSecureTransportError                  = 4
	GSMMAPLocalErrorcodeUnidentifiedSubscriberDecimal         = "5"
	GSMMAPLocalErrorcodeUnidentifiedSubscriber                = 5
	GSMMAPLocalErrorcodeAbsentSubscriberSMDecimal             = "6"
	GSMMAPLocalErrorcodeAbsentSubscriberSM                    = 6
	GSMMAPLocalErrorcodeUnknownEquipmentDecimal               = "7"
	GSMMAPLocalErrorcodeUnknownEquipment                      = 7
	GSMMAPLocalErrorcodeRoamingNotAllowedDecimal              = "8"
	GSMMAPLocalErrorcodeRoamingNotAllowed                     = 8
	GSMMAPLocalErrorcodeIllegalSubscriberDecimal              = "9"
	GSMMAPLocalErrorcodeIllegalSubscriber                     = 9
	GSMMAPLocalErrorcodeBearerServiceNotProvisionedDecimal    = "10"
	GSMMAPLocalErrorcodeBearerServiceNotProvisioned           = 10
	GSMMAPLocalErrorcodeTeleserviceNotProvisionedDecimal      = "11"
	GSMMAPLocalErrorcodeTeleserviceNotProvisioned             = 11
	GSMMAPLocalErrorcodeIllegalEquipmentDecimal               = "12"
	GSMMAPLocalErrorcodeIllegalEquipment                      = 12
	GSMMAPLocalErrorcodeCallBarredDecimal                     = "13"
	GSMMAPLocalErrorcodeCallBarred                            = 13
	GSMMAPLocalErrorcodeForwardingViolationDecimal            = "14"
	GSMMAPLocalErrorcodeForwardingViolation                   = 14
	GSMMAPLocalErrorcodeCugRejectDecimal                      = "15"
	GSMMAPLocalErrorcodeCugReject                             = 15
	GSMMAPLocalErrorcodeIllegalSSOperationDecimal             = "16"
	GSMMAPLocalErrorcodeIllegalSSOperation                    = 16
	GSMMAPLocalErrorcodeSsErrorStatusDecimal                  = "17"
	GSMMAPLocalErrorcodeSsErrorStatus                         = 17
	GSMMAPLocalErrorcodeSsNotAvailableDecimal                 = "18"
	GSMMAPLocalErrorcodeSsNotAvailable                        = 18
	GSMMAPLocalErrorcodeSsSubscriptionViolationDecimal        = "19"
	GSMMAPLocalErrorcodeSsSubscriptionViolation               = 19
	GSMMAPLocalErrorcodeSsIncompatibilityDecimal              = "20"
	GSMMAPLocalErrorcodeSsIncompatibility                     = 20
	GSMMAPLocalErrorcodeFacilityNotSupportedDecimal           = "21"
	GSMMAPLocalErrorcodeFacilityNotSupported                  = 21
	GSMMAPLocalErrorcodeOngoingGroupCallDecimal               = "22"
	GSMMAPLocalErrorcodeOngoingGroupCall                      = 22
	GSMMAPLocalErrorcodeInvalidTargetBaseStationDecimal       = "23"
	GSMMAPLocalErrorcodeInvalidTargetBaseStation              = 23
	GSMMAPLocalErrorcodeNoRadioResourceAvailableDecimal       = "24"
	GSMMAPLocalErrorcodeNoRadioResourceAvailable              = 24
	GSMMAPLocalErrorcodeNoHandoverNumberAvailableDecimal      = "25"
	GSMMAPLocalErrorcodeNoHandoverNumberAvailable             = 25
	GSMMAPLocalErrorcodeSubsequentHandoverFailureDecimal      = "26"
	GSMMAPLocalErrorcodeSubsequentHandoverFailure             = 26
	GSMMAPLocalErrorcodeAbsentSubscriberDecimal               = "27"
	GSMMAPLocalErrorcodeAbsentSubscriber                      = 27
	GSMMAPLocalErrorcodeIncompatibleTerminalDecimal           = "28"
	GSMMAPLocalErrorcodeIncompatibleTerminal                  = 28
	GSMMAPLocalErrorcodeShortTermDenialDecimal                = "29"
	GSMMAPLocalErrorcodeShortTermDenial                       = 29
	GSMMAPLocalErrorcodeLongTermDenialDecimal                 = "30"
	GSMMAPLocalErrorcodeLongTermDenial                        = 30
	GSMMAPLocalErrorcodeSubscriberBusyForMTSMSDecimal         = "31"
	GSMMAPLocalErrorcodeSubscriberBusyForMTSMS                = 31
	GSMMAPLocalErrorcodeSmDeliveryFailureDecimal              = "32"
	GSMMAPLocalErrorcodeSmDeliveryFailure                     = 32
	GSMMAPLocalErrorcodeMessageWaitingListFullDecimal         = "33"
	GSMMAPLocalErrorcodeMessageWaitingListFull                = 33
	GSMMAPLocalErrorcodeSystemFailureDecimal                  = "34"
	GSMMAPLocalErrorcodeSystemFailure                         = 34
	GSMMAPLocalErrorcodeDataMissingDecimal                    = "35"
	GSMMAPLocalErrorcodeDataMissing                           = 35
	GSMMAPLocalErrorcodeUnexpectedDataValueDecimal            = "36"
	GSMMAPLocalErrorcodeUnexpectedDataValue                   = 36
	GSMMAPLocalErrorcodePwRegistrationFailureDecimal          = "37"
	GSMMAPLocalErrorcodePwRegistrationFailure                 = 37
	GSMMAPLocalErrorcodeNegativePWCheckDecimal                = "38"
	GSMMAPLocalErrorcodeNegativePWCheck                       = 38
	GSMMAPLocalErrorcodeNoRoamingNumberAvailableDecimal       = "39"
	GSMMAPLocalErrorcodeNoRoamingNumberAvailable              = 39
	GSMMAPLocalErrorcodeTracingBufferFullDecimal              = "40"
	GSMMAPLocalErrorcodeTracingBufferFull                     = 40
	GSMMAPLocalErrorcodeTargetCellOutsideGroupCallAreaDecimal = "42"
	GSMMAPLocalErrorcodeTargetCellOutsideGroupCallArea        = 42
	GSMMAPLocalErrorcodeNumberOfPWAttemptsViolationDecimal    = "43"
	GSMMAPLocalErrorcodeNumberOfPWAttemptsViolation           = 43
	GSMMAPLocalErrorcodeNumberChangedDecimal                  = "44"
	GSMMAPLocalErrorcodeNumberChanged                         = 44
	GSMMAPLocalErrorcodeBusySubscriberDecimal                 = "45"
	GSMMAPLocalErrorcodeBusySubscriber                        = 45
	GSMMAPLocalErrorcodeNoSubscriberReplyDecimal              = "46"
	GSMMAPLocalErrorcodeNoSubscriberReply                     = 46
	GSMMAPLocalErrorcodeForwardingFailedDecimal               = "47"
	GSMMAPLocalErrorcodeForwardingFailed                      = 47
	GSMMAPLocalErrorcodeOrNotAllowedDecimal                   = "48"
	GSMMAPLocalErrorcodeOrNotAllowed                          = 48
	GSMMAPLocalErrorcodeAtiNotAllowedDecimal                  = "49"
	GSMMAPLocalErrorcodeAtiNotAllowed                         = 49
	GSMMAPLocalErrorcodeNoGroupCallNumberAvailableDecimal     = "50"
	GSMMAPLocalErrorcodeNoGroupCallNumberAvailable            = 50
	GSMMAPLocalErrorcodeResourceLimitationDecimal             = "51"
	GSMMAPLocalErrorcodeResourceLimitation                    = 51
	GSMMAPLocalErrorcodeUnauthorizedRequestingNetworkDecimal  = "52"
	GSMMAPLocalErrorcodeUnauthorizedRequestingNetwork         = 52
	GSMMAPLocalErrorcodeUnauthorizedLCSClientDecimal          = "53"
	GSMMAPLocalErrorcodeUnauthorizedLCSClient                 = 53
	GSMMAPLocalErrorcodePositionMethodFailureDecimal          = "54"
	GSMMAPLocalErrorcodePositionMethodFailure                 = 54
	GSMMAPLocalErrorcodeUnknownOrUnreachableLCSClientDecimal  = "58"
	GSMMAPLocalErrorcodeUnknownOrUnreachableLCSClient         = 58
	GSMMAPLocalErrorcodeMmEventNotSupportedDecimal            = "59"
	GSMMAPLocalErrorcodeMmEventNotSupported                   = 59
	GSMMAPLocalErrorcodeAtsiNotAllowedDecimal                 = "60"
	GSMMAPLocalErrorcodeAtsiNotAllowed                        = 60
	GSMMAPLocalErrorcodeAtmNotAllowedDecimal                  = "61"
	GSMMAPLocalErrorcodeAtmNotAllowed                         = 61
	GSMMAPLocalErrorcodeInformationNotAvailableDecimal        = "62"
	GSMMAPLocalErrorcodeInformationNotAvailable               = 62
	GSMMAPLocalErrorcodeUnknownAlphabetDecimal                = "71"
	GSMMAPLocalErrorcodeUnknownAlphabet                       = 71
	GSMMAPLocalErrorcodeUssdBusyDecimal                       = "72"
	GSMMAPLocalErrorcodeUssdBusy                              = 72
)

// NewGSMMAPLocalErrorcode returns an immutable GSMMAPLocalErrorcode containing value.
func NewGSMMAPLocalErrorcode(value *big.Int) GSMMAPLocalErrorcode {
	return GSMMAPLocalErrorcode{value: runtime.CloneBigInt(value)}
}

// NewGSMMAPLocalErrorcodeInt64 returns a GSMMAPLocalErrorcode containing value.
func NewGSMMAPLocalErrorcodeInt64(value int64) GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(big.NewInt(value))
}

// GSMMAPLocalErrorcodeUnknownSubscriberValue returns the named value unknownSubscriber.
func GSMMAPLocalErrorcodeUnknownSubscriberValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeUnknownSubscriberDecimal))
}

// GSMMAPLocalErrorcodeUnknownBaseStationValue returns the named value unknownBaseStation.
func GSMMAPLocalErrorcodeUnknownBaseStationValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeUnknownBaseStationDecimal))
}

// GSMMAPLocalErrorcodeUnknownMSCValue returns the named value unknownMSC.
func GSMMAPLocalErrorcodeUnknownMSCValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeUnknownMSCDecimal))
}

// GSMMAPLocalErrorcodeSecureTransportErrorValue returns the named value secureTransportError.
func GSMMAPLocalErrorcodeSecureTransportErrorValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeSecureTransportErrorDecimal))
}

// GSMMAPLocalErrorcodeUnidentifiedSubscriberValue returns the named value unidentifiedSubscriber.
func GSMMAPLocalErrorcodeUnidentifiedSubscriberValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeUnidentifiedSubscriberDecimal))
}

// GSMMAPLocalErrorcodeAbsentSubscriberSMValue returns the named value absentSubscriberSM.
func GSMMAPLocalErrorcodeAbsentSubscriberSMValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeAbsentSubscriberSMDecimal))
}

// GSMMAPLocalErrorcodeUnknownEquipmentValue returns the named value unknownEquipment.
func GSMMAPLocalErrorcodeUnknownEquipmentValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeUnknownEquipmentDecimal))
}

// GSMMAPLocalErrorcodeRoamingNotAllowedValue returns the named value roamingNotAllowed.
func GSMMAPLocalErrorcodeRoamingNotAllowedValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeRoamingNotAllowedDecimal))
}

// GSMMAPLocalErrorcodeIllegalSubscriberValue returns the named value illegalSubscriber.
func GSMMAPLocalErrorcodeIllegalSubscriberValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeIllegalSubscriberDecimal))
}

// GSMMAPLocalErrorcodeBearerServiceNotProvisionedValue returns the named value bearerServiceNotProvisioned.
func GSMMAPLocalErrorcodeBearerServiceNotProvisionedValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeBearerServiceNotProvisionedDecimal))
}

// GSMMAPLocalErrorcodeTeleserviceNotProvisionedValue returns the named value teleserviceNotProvisioned.
func GSMMAPLocalErrorcodeTeleserviceNotProvisionedValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeTeleserviceNotProvisionedDecimal))
}

// GSMMAPLocalErrorcodeIllegalEquipmentValue returns the named value illegalEquipment.
func GSMMAPLocalErrorcodeIllegalEquipmentValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeIllegalEquipmentDecimal))
}

// GSMMAPLocalErrorcodeCallBarredValue returns the named value callBarred.
func GSMMAPLocalErrorcodeCallBarredValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeCallBarredDecimal))
}

// GSMMAPLocalErrorcodeForwardingViolationValue returns the named value forwardingViolation.
func GSMMAPLocalErrorcodeForwardingViolationValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeForwardingViolationDecimal))
}

// GSMMAPLocalErrorcodeCugRejectValue returns the named value cug-Reject.
func GSMMAPLocalErrorcodeCugRejectValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeCugRejectDecimal))
}

// GSMMAPLocalErrorcodeIllegalSSOperationValue returns the named value illegalSS-Operation.
func GSMMAPLocalErrorcodeIllegalSSOperationValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeIllegalSSOperationDecimal))
}

// GSMMAPLocalErrorcodeSsErrorStatusValue returns the named value ss-ErrorStatus.
func GSMMAPLocalErrorcodeSsErrorStatusValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeSsErrorStatusDecimal))
}

// GSMMAPLocalErrorcodeSsNotAvailableValue returns the named value ss-NotAvailable.
func GSMMAPLocalErrorcodeSsNotAvailableValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeSsNotAvailableDecimal))
}

// GSMMAPLocalErrorcodeSsSubscriptionViolationValue returns the named value ss-SubscriptionViolation.
func GSMMAPLocalErrorcodeSsSubscriptionViolationValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeSsSubscriptionViolationDecimal))
}

// GSMMAPLocalErrorcodeSsIncompatibilityValue returns the named value ss-Incompatibility.
func GSMMAPLocalErrorcodeSsIncompatibilityValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeSsIncompatibilityDecimal))
}

// GSMMAPLocalErrorcodeFacilityNotSupportedValue returns the named value facilityNotSupported.
func GSMMAPLocalErrorcodeFacilityNotSupportedValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeFacilityNotSupportedDecimal))
}

// GSMMAPLocalErrorcodeOngoingGroupCallValue returns the named value ongoingGroupCall.
func GSMMAPLocalErrorcodeOngoingGroupCallValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeOngoingGroupCallDecimal))
}

// GSMMAPLocalErrorcodeInvalidTargetBaseStationValue returns the named value invalidTargetBaseStation.
func GSMMAPLocalErrorcodeInvalidTargetBaseStationValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeInvalidTargetBaseStationDecimal))
}

// GSMMAPLocalErrorcodeNoRadioResourceAvailableValue returns the named value noRadioResourceAvailable.
func GSMMAPLocalErrorcodeNoRadioResourceAvailableValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeNoRadioResourceAvailableDecimal))
}

// GSMMAPLocalErrorcodeNoHandoverNumberAvailableValue returns the named value noHandoverNumberAvailable.
func GSMMAPLocalErrorcodeNoHandoverNumberAvailableValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeNoHandoverNumberAvailableDecimal))
}

// GSMMAPLocalErrorcodeSubsequentHandoverFailureValue returns the named value subsequentHandoverFailure.
func GSMMAPLocalErrorcodeSubsequentHandoverFailureValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeSubsequentHandoverFailureDecimal))
}

// GSMMAPLocalErrorcodeAbsentSubscriberValue returns the named value absentSubscriber.
func GSMMAPLocalErrorcodeAbsentSubscriberValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeAbsentSubscriberDecimal))
}

// GSMMAPLocalErrorcodeIncompatibleTerminalValue returns the named value incompatibleTerminal.
func GSMMAPLocalErrorcodeIncompatibleTerminalValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeIncompatibleTerminalDecimal))
}

// GSMMAPLocalErrorcodeShortTermDenialValue returns the named value shortTermDenial.
func GSMMAPLocalErrorcodeShortTermDenialValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeShortTermDenialDecimal))
}

// GSMMAPLocalErrorcodeLongTermDenialValue returns the named value longTermDenial.
func GSMMAPLocalErrorcodeLongTermDenialValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeLongTermDenialDecimal))
}

// GSMMAPLocalErrorcodeSubscriberBusyForMTSMSValue returns the named value subscriberBusyForMT-SMS.
func GSMMAPLocalErrorcodeSubscriberBusyForMTSMSValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeSubscriberBusyForMTSMSDecimal))
}

// GSMMAPLocalErrorcodeSmDeliveryFailureValue returns the named value sm-DeliveryFailure.
func GSMMAPLocalErrorcodeSmDeliveryFailureValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeSmDeliveryFailureDecimal))
}

// GSMMAPLocalErrorcodeMessageWaitingListFullValue returns the named value messageWaitingListFull.
func GSMMAPLocalErrorcodeMessageWaitingListFullValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeMessageWaitingListFullDecimal))
}

// GSMMAPLocalErrorcodeSystemFailureValue returns the named value systemFailure.
func GSMMAPLocalErrorcodeSystemFailureValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeSystemFailureDecimal))
}

// GSMMAPLocalErrorcodeDataMissingValue returns the named value dataMissing.
func GSMMAPLocalErrorcodeDataMissingValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeDataMissingDecimal))
}

// GSMMAPLocalErrorcodeUnexpectedDataValueValue returns the named value unexpectedDataValue.
func GSMMAPLocalErrorcodeUnexpectedDataValueValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeUnexpectedDataValueDecimal))
}

// GSMMAPLocalErrorcodePwRegistrationFailureValue returns the named value pw-RegistrationFailure.
func GSMMAPLocalErrorcodePwRegistrationFailureValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodePwRegistrationFailureDecimal))
}

// GSMMAPLocalErrorcodeNegativePWCheckValue returns the named value negativePW-Check.
func GSMMAPLocalErrorcodeNegativePWCheckValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeNegativePWCheckDecimal))
}

// GSMMAPLocalErrorcodeNoRoamingNumberAvailableValue returns the named value noRoamingNumberAvailable.
func GSMMAPLocalErrorcodeNoRoamingNumberAvailableValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeNoRoamingNumberAvailableDecimal))
}

// GSMMAPLocalErrorcodeTracingBufferFullValue returns the named value tracingBufferFull.
func GSMMAPLocalErrorcodeTracingBufferFullValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeTracingBufferFullDecimal))
}

// GSMMAPLocalErrorcodeTargetCellOutsideGroupCallAreaValue returns the named value targetCellOutsideGroupCallArea.
func GSMMAPLocalErrorcodeTargetCellOutsideGroupCallAreaValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeTargetCellOutsideGroupCallAreaDecimal))
}

// GSMMAPLocalErrorcodeNumberOfPWAttemptsViolationValue returns the named value numberOfPW-AttemptsViolation.
func GSMMAPLocalErrorcodeNumberOfPWAttemptsViolationValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeNumberOfPWAttemptsViolationDecimal))
}

// GSMMAPLocalErrorcodeNumberChangedValue returns the named value numberChanged.
func GSMMAPLocalErrorcodeNumberChangedValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeNumberChangedDecimal))
}

// GSMMAPLocalErrorcodeBusySubscriberValue returns the named value busySubscriber.
func GSMMAPLocalErrorcodeBusySubscriberValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeBusySubscriberDecimal))
}

// GSMMAPLocalErrorcodeNoSubscriberReplyValue returns the named value noSubscriberReply.
func GSMMAPLocalErrorcodeNoSubscriberReplyValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeNoSubscriberReplyDecimal))
}

// GSMMAPLocalErrorcodeForwardingFailedValue returns the named value forwardingFailed.
func GSMMAPLocalErrorcodeForwardingFailedValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeForwardingFailedDecimal))
}

// GSMMAPLocalErrorcodeOrNotAllowedValue returns the named value or-NotAllowed.
func GSMMAPLocalErrorcodeOrNotAllowedValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeOrNotAllowedDecimal))
}

// GSMMAPLocalErrorcodeAtiNotAllowedValue returns the named value ati-NotAllowed.
func GSMMAPLocalErrorcodeAtiNotAllowedValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeAtiNotAllowedDecimal))
}

// GSMMAPLocalErrorcodeNoGroupCallNumberAvailableValue returns the named value noGroupCallNumberAvailable.
func GSMMAPLocalErrorcodeNoGroupCallNumberAvailableValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeNoGroupCallNumberAvailableDecimal))
}

// GSMMAPLocalErrorcodeResourceLimitationValue returns the named value resourceLimitation.
func GSMMAPLocalErrorcodeResourceLimitationValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeResourceLimitationDecimal))
}

// GSMMAPLocalErrorcodeUnauthorizedRequestingNetworkValue returns the named value unauthorizedRequestingNetwork.
func GSMMAPLocalErrorcodeUnauthorizedRequestingNetworkValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeUnauthorizedRequestingNetworkDecimal))
}

// GSMMAPLocalErrorcodeUnauthorizedLCSClientValue returns the named value unauthorizedLCSClient.
func GSMMAPLocalErrorcodeUnauthorizedLCSClientValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeUnauthorizedLCSClientDecimal))
}

// GSMMAPLocalErrorcodePositionMethodFailureValue returns the named value positionMethodFailure.
func GSMMAPLocalErrorcodePositionMethodFailureValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodePositionMethodFailureDecimal))
}

// GSMMAPLocalErrorcodeUnknownOrUnreachableLCSClientValue returns the named value unknownOrUnreachableLCSClient.
func GSMMAPLocalErrorcodeUnknownOrUnreachableLCSClientValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeUnknownOrUnreachableLCSClientDecimal))
}

// GSMMAPLocalErrorcodeMmEventNotSupportedValue returns the named value mm-EventNotSupported.
func GSMMAPLocalErrorcodeMmEventNotSupportedValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeMmEventNotSupportedDecimal))
}

// GSMMAPLocalErrorcodeAtsiNotAllowedValue returns the named value atsi-NotAllowed.
func GSMMAPLocalErrorcodeAtsiNotAllowedValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeAtsiNotAllowedDecimal))
}

// GSMMAPLocalErrorcodeAtmNotAllowedValue returns the named value atm-NotAllowed.
func GSMMAPLocalErrorcodeAtmNotAllowedValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeAtmNotAllowedDecimal))
}

// GSMMAPLocalErrorcodeInformationNotAvailableValue returns the named value informationNotAvailable.
func GSMMAPLocalErrorcodeInformationNotAvailableValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeInformationNotAvailableDecimal))
}

// GSMMAPLocalErrorcodeUnknownAlphabetValue returns the named value unknownAlphabet.
func GSMMAPLocalErrorcodeUnknownAlphabetValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeUnknownAlphabetDecimal))
}

// GSMMAPLocalErrorcodeUssdBusyValue returns the named value ussd-Busy.
func GSMMAPLocalErrorcodeUssdBusyValue() GSMMAPLocalErrorcode {
	return NewGSMMAPLocalErrorcode(runtime.MustParseBigIntDecimal(GSMMAPLocalErrorcodeUssdBusyDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v GSMMAPLocalErrorcode) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v GSMMAPLocalErrorcode) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v GSMMAPLocalErrorcode) Name() (string, bool) {
	switch v.BigInt().String() {
	case GSMMAPLocalErrorcodeUnknownSubscriberDecimal:
		return "unknownSubscriber", true
	case GSMMAPLocalErrorcodeUnknownBaseStationDecimal:
		return "unknownBaseStation", true
	case GSMMAPLocalErrorcodeUnknownMSCDecimal:
		return "unknownMSC", true
	case GSMMAPLocalErrorcodeSecureTransportErrorDecimal:
		return "secureTransportError", true
	case GSMMAPLocalErrorcodeUnidentifiedSubscriberDecimal:
		return "unidentifiedSubscriber", true
	case GSMMAPLocalErrorcodeAbsentSubscriberSMDecimal:
		return "absentSubscriberSM", true
	case GSMMAPLocalErrorcodeUnknownEquipmentDecimal:
		return "unknownEquipment", true
	case GSMMAPLocalErrorcodeRoamingNotAllowedDecimal:
		return "roamingNotAllowed", true
	case GSMMAPLocalErrorcodeIllegalSubscriberDecimal:
		return "illegalSubscriber", true
	case GSMMAPLocalErrorcodeBearerServiceNotProvisionedDecimal:
		return "bearerServiceNotProvisioned", true
	case GSMMAPLocalErrorcodeTeleserviceNotProvisionedDecimal:
		return "teleserviceNotProvisioned", true
	case GSMMAPLocalErrorcodeIllegalEquipmentDecimal:
		return "illegalEquipment", true
	case GSMMAPLocalErrorcodeCallBarredDecimal:
		return "callBarred", true
	case GSMMAPLocalErrorcodeForwardingViolationDecimal:
		return "forwardingViolation", true
	case GSMMAPLocalErrorcodeCugRejectDecimal:
		return "cug-Reject", true
	case GSMMAPLocalErrorcodeIllegalSSOperationDecimal:
		return "illegalSS-Operation", true
	case GSMMAPLocalErrorcodeSsErrorStatusDecimal:
		return "ss-ErrorStatus", true
	case GSMMAPLocalErrorcodeSsNotAvailableDecimal:
		return "ss-NotAvailable", true
	case GSMMAPLocalErrorcodeSsSubscriptionViolationDecimal:
		return "ss-SubscriptionViolation", true
	case GSMMAPLocalErrorcodeSsIncompatibilityDecimal:
		return "ss-Incompatibility", true
	case GSMMAPLocalErrorcodeFacilityNotSupportedDecimal:
		return "facilityNotSupported", true
	case GSMMAPLocalErrorcodeOngoingGroupCallDecimal:
		return "ongoingGroupCall", true
	case GSMMAPLocalErrorcodeInvalidTargetBaseStationDecimal:
		return "invalidTargetBaseStation", true
	case GSMMAPLocalErrorcodeNoRadioResourceAvailableDecimal:
		return "noRadioResourceAvailable", true
	case GSMMAPLocalErrorcodeNoHandoverNumberAvailableDecimal:
		return "noHandoverNumberAvailable", true
	case GSMMAPLocalErrorcodeSubsequentHandoverFailureDecimal:
		return "subsequentHandoverFailure", true
	case GSMMAPLocalErrorcodeAbsentSubscriberDecimal:
		return "absentSubscriber", true
	case GSMMAPLocalErrorcodeIncompatibleTerminalDecimal:
		return "incompatibleTerminal", true
	case GSMMAPLocalErrorcodeShortTermDenialDecimal:
		return "shortTermDenial", true
	case GSMMAPLocalErrorcodeLongTermDenialDecimal:
		return "longTermDenial", true
	case GSMMAPLocalErrorcodeSubscriberBusyForMTSMSDecimal:
		return "subscriberBusyForMT-SMS", true
	case GSMMAPLocalErrorcodeSmDeliveryFailureDecimal:
		return "sm-DeliveryFailure", true
	case GSMMAPLocalErrorcodeMessageWaitingListFullDecimal:
		return "messageWaitingListFull", true
	case GSMMAPLocalErrorcodeSystemFailureDecimal:
		return "systemFailure", true
	case GSMMAPLocalErrorcodeDataMissingDecimal:
		return "dataMissing", true
	case GSMMAPLocalErrorcodeUnexpectedDataValueDecimal:
		return "unexpectedDataValue", true
	case GSMMAPLocalErrorcodePwRegistrationFailureDecimal:
		return "pw-RegistrationFailure", true
	case GSMMAPLocalErrorcodeNegativePWCheckDecimal:
		return "negativePW-Check", true
	case GSMMAPLocalErrorcodeNoRoamingNumberAvailableDecimal:
		return "noRoamingNumberAvailable", true
	case GSMMAPLocalErrorcodeTracingBufferFullDecimal:
		return "tracingBufferFull", true
	case GSMMAPLocalErrorcodeTargetCellOutsideGroupCallAreaDecimal:
		return "targetCellOutsideGroupCallArea", true
	case GSMMAPLocalErrorcodeNumberOfPWAttemptsViolationDecimal:
		return "numberOfPW-AttemptsViolation", true
	case GSMMAPLocalErrorcodeNumberChangedDecimal:
		return "numberChanged", true
	case GSMMAPLocalErrorcodeBusySubscriberDecimal:
		return "busySubscriber", true
	case GSMMAPLocalErrorcodeNoSubscriberReplyDecimal:
		return "noSubscriberReply", true
	case GSMMAPLocalErrorcodeForwardingFailedDecimal:
		return "forwardingFailed", true
	case GSMMAPLocalErrorcodeOrNotAllowedDecimal:
		return "or-NotAllowed", true
	case GSMMAPLocalErrorcodeAtiNotAllowedDecimal:
		return "ati-NotAllowed", true
	case GSMMAPLocalErrorcodeNoGroupCallNumberAvailableDecimal:
		return "noGroupCallNumberAvailable", true
	case GSMMAPLocalErrorcodeResourceLimitationDecimal:
		return "resourceLimitation", true
	case GSMMAPLocalErrorcodeUnauthorizedRequestingNetworkDecimal:
		return "unauthorizedRequestingNetwork", true
	case GSMMAPLocalErrorcodeUnauthorizedLCSClientDecimal:
		return "unauthorizedLCSClient", true
	case GSMMAPLocalErrorcodePositionMethodFailureDecimal:
		return "positionMethodFailure", true
	case GSMMAPLocalErrorcodeUnknownOrUnreachableLCSClientDecimal:
		return "unknownOrUnreachableLCSClient", true
	case GSMMAPLocalErrorcodeMmEventNotSupportedDecimal:
		return "mm-EventNotSupported", true
	case GSMMAPLocalErrorcodeAtsiNotAllowedDecimal:
		return "atsi-NotAllowed", true
	case GSMMAPLocalErrorcodeAtmNotAllowedDecimal:
		return "atm-NotAllowed", true
	case GSMMAPLocalErrorcodeInformationNotAvailableDecimal:
		return "informationNotAvailable", true
	case GSMMAPLocalErrorcodeUnknownAlphabetDecimal:
		return "unknownAlphabet", true
	case GSMMAPLocalErrorcodeUssdBusyDecimal:
		return "ussd-Busy", true
	default:
		return "", false
	}
}

func (v GSMMAPLocalErrorcode) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v GSMMAPLocalErrorcode) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *GSMMAPLocalErrorcode) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal GSMMAPLocalErrorcode into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewGSMMAPLocalErrorcode(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v GSMMAPLocalErrorcode) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *GSMMAPLocalErrorcode) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal GSMMAPLocalErrorcode into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewGSMMAPLocalErrorcode(value)
	return nil
}

// LocalErrorcode represents the arbitrary-width ASN.1 INTEGER type LocalErrorcode with named numbers.
type LocalErrorcode struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	LocalErrorcodeUnknownSubscriberDecimal              = "1"
	LocalErrorcodeUnknownSubscriber                     = 1
	LocalErrorcodeUnknownBaseStationDecimal             = "2"
	LocalErrorcodeUnknownBaseStation                    = 2
	LocalErrorcodeUnknownMSCDecimal                     = "3"
	LocalErrorcodeUnknownMSC                            = 3
	LocalErrorcodeSecureTransportErrorDecimal           = "4"
	LocalErrorcodeSecureTransportError                  = 4
	LocalErrorcodeUnidentifiedSubscriberDecimal         = "5"
	LocalErrorcodeUnidentifiedSubscriber                = 5
	LocalErrorcodeAbsentSubscriberSMDecimal             = "6"
	LocalErrorcodeAbsentSubscriberSM                    = 6
	LocalErrorcodeUnknownEquipmentDecimal               = "7"
	LocalErrorcodeUnknownEquipment                      = 7
	LocalErrorcodeRoamingNotAllowedDecimal              = "8"
	LocalErrorcodeRoamingNotAllowed                     = 8
	LocalErrorcodeIllegalSubscriberDecimal              = "9"
	LocalErrorcodeIllegalSubscriber                     = 9
	LocalErrorcodeBearerServiceNotProvisionedDecimal    = "10"
	LocalErrorcodeBearerServiceNotProvisioned           = 10
	LocalErrorcodeTeleserviceNotProvisionedDecimal      = "11"
	LocalErrorcodeTeleserviceNotProvisioned             = 11
	LocalErrorcodeIllegalEquipmentDecimal               = "12"
	LocalErrorcodeIllegalEquipment                      = 12
	LocalErrorcodeCallBarredDecimal                     = "13"
	LocalErrorcodeCallBarred                            = 13
	LocalErrorcodeForwardingViolationDecimal            = "14"
	LocalErrorcodeForwardingViolation                   = 14
	LocalErrorcodeCugRejectDecimal                      = "15"
	LocalErrorcodeCugReject                             = 15
	LocalErrorcodeIllegalSSOperationDecimal             = "16"
	LocalErrorcodeIllegalSSOperation                    = 16
	LocalErrorcodeSsErrorStatusDecimal                  = "17"
	LocalErrorcodeSsErrorStatus                         = 17
	LocalErrorcodeSsNotAvailableDecimal                 = "18"
	LocalErrorcodeSsNotAvailable                        = 18
	LocalErrorcodeSsSubscriptionViolationDecimal        = "19"
	LocalErrorcodeSsSubscriptionViolation               = 19
	LocalErrorcodeSsIncompatibilityDecimal              = "20"
	LocalErrorcodeSsIncompatibility                     = 20
	LocalErrorcodeFacilityNotSupportedDecimal           = "21"
	LocalErrorcodeFacilityNotSupported                  = 21
	LocalErrorcodeOngoingGroupCallDecimal               = "22"
	LocalErrorcodeOngoingGroupCall                      = 22
	LocalErrorcodeInvalidTargetBaseStationDecimal       = "23"
	LocalErrorcodeInvalidTargetBaseStation              = 23
	LocalErrorcodeNoRadioResourceAvailableDecimal       = "24"
	LocalErrorcodeNoRadioResourceAvailable              = 24
	LocalErrorcodeNoHandoverNumberAvailableDecimal      = "25"
	LocalErrorcodeNoHandoverNumberAvailable             = 25
	LocalErrorcodeSubsequentHandoverFailureDecimal      = "26"
	LocalErrorcodeSubsequentHandoverFailure             = 26
	LocalErrorcodeAbsentSubscriberDecimal               = "27"
	LocalErrorcodeAbsentSubscriber                      = 27
	LocalErrorcodeIncompatibleTerminalDecimal           = "28"
	LocalErrorcodeIncompatibleTerminal                  = 28
	LocalErrorcodeShortTermDenialDecimal                = "29"
	LocalErrorcodeShortTermDenial                       = 29
	LocalErrorcodeLongTermDenialDecimal                 = "30"
	LocalErrorcodeLongTermDenial                        = 30
	LocalErrorcodeSubscriberBusyForMTSMSDecimal         = "31"
	LocalErrorcodeSubscriberBusyForMTSMS                = 31
	LocalErrorcodeSmDeliveryFailureDecimal              = "32"
	LocalErrorcodeSmDeliveryFailure                     = 32
	LocalErrorcodeMessageWaitingListFullDecimal         = "33"
	LocalErrorcodeMessageWaitingListFull                = 33
	LocalErrorcodeSystemFailureDecimal                  = "34"
	LocalErrorcodeSystemFailure                         = 34
	LocalErrorcodeDataMissingDecimal                    = "35"
	LocalErrorcodeDataMissing                           = 35
	LocalErrorcodeUnexpectedDataValueDecimal            = "36"
	LocalErrorcodeUnexpectedDataValue                   = 36
	LocalErrorcodePwRegistrationFailureDecimal          = "37"
	LocalErrorcodePwRegistrationFailure                 = 37
	LocalErrorcodeNegativePWCheckDecimal                = "38"
	LocalErrorcodeNegativePWCheck                       = 38
	LocalErrorcodeNoRoamingNumberAvailableDecimal       = "39"
	LocalErrorcodeNoRoamingNumberAvailable              = 39
	LocalErrorcodeTracingBufferFullDecimal              = "40"
	LocalErrorcodeTracingBufferFull                     = 40
	LocalErrorcodeTargetCellOutsideGroupCallAreaDecimal = "42"
	LocalErrorcodeTargetCellOutsideGroupCallArea        = 42
	LocalErrorcodeNumberOfPWAttemptsViolationDecimal    = "43"
	LocalErrorcodeNumberOfPWAttemptsViolation           = 43
	LocalErrorcodeNumberChangedDecimal                  = "44"
	LocalErrorcodeNumberChanged                         = 44
	LocalErrorcodeBusySubscriberDecimal                 = "45"
	LocalErrorcodeBusySubscriber                        = 45
	LocalErrorcodeNoSubscriberReplyDecimal              = "46"
	LocalErrorcodeNoSubscriberReply                     = 46
	LocalErrorcodeForwardingFailedDecimal               = "47"
	LocalErrorcodeForwardingFailed                      = 47
	LocalErrorcodeOrNotAllowedDecimal                   = "48"
	LocalErrorcodeOrNotAllowed                          = 48
	LocalErrorcodeAtiNotAllowedDecimal                  = "49"
	LocalErrorcodeAtiNotAllowed                         = 49
	LocalErrorcodeNoGroupCallNumberAvailableDecimal     = "50"
	LocalErrorcodeNoGroupCallNumberAvailable            = 50
	LocalErrorcodeResourceLimitationDecimal             = "51"
	LocalErrorcodeResourceLimitation                    = 51
	LocalErrorcodeUnauthorizedRequestingNetworkDecimal  = "52"
	LocalErrorcodeUnauthorizedRequestingNetwork         = 52
	LocalErrorcodeUnauthorizedLCSClientDecimal          = "53"
	LocalErrorcodeUnauthorizedLCSClient                 = 53
	LocalErrorcodePositionMethodFailureDecimal          = "54"
	LocalErrorcodePositionMethodFailure                 = 54
	LocalErrorcodeUnknownOrUnreachableLCSClientDecimal  = "58"
	LocalErrorcodeUnknownOrUnreachableLCSClient         = 58
	LocalErrorcodeMmEventNotSupportedDecimal            = "59"
	LocalErrorcodeMmEventNotSupported                   = 59
	LocalErrorcodeAtsiNotAllowedDecimal                 = "60"
	LocalErrorcodeAtsiNotAllowed                        = 60
	LocalErrorcodeAtmNotAllowedDecimal                  = "61"
	LocalErrorcodeAtmNotAllowed                         = 61
	LocalErrorcodeInformationNotAvailableDecimal        = "62"
	LocalErrorcodeInformationNotAvailable               = 62
	LocalErrorcodeUnknownAlphabetDecimal                = "71"
	LocalErrorcodeUnknownAlphabet                       = 71
	LocalErrorcodeUssdBusyDecimal                       = "72"
	LocalErrorcodeUssdBusy                              = 72
)

// NewLocalErrorcode returns an immutable LocalErrorcode containing value.
func NewLocalErrorcode(value *big.Int) LocalErrorcode {
	return LocalErrorcode{value: runtime.CloneBigInt(value)}
}

// NewLocalErrorcodeInt64 returns a LocalErrorcode containing value.
func NewLocalErrorcodeInt64(value int64) LocalErrorcode {
	return NewLocalErrorcode(big.NewInt(value))
}

// LocalErrorcodeUnknownSubscriberValue returns the named value unknownSubscriber.
func LocalErrorcodeUnknownSubscriberValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeUnknownSubscriberDecimal))
}

// LocalErrorcodeUnknownBaseStationValue returns the named value unknownBaseStation.
func LocalErrorcodeUnknownBaseStationValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeUnknownBaseStationDecimal))
}

// LocalErrorcodeUnknownMSCValue returns the named value unknownMSC.
func LocalErrorcodeUnknownMSCValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeUnknownMSCDecimal))
}

// LocalErrorcodeSecureTransportErrorValue returns the named value secureTransportError.
func LocalErrorcodeSecureTransportErrorValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeSecureTransportErrorDecimal))
}

// LocalErrorcodeUnidentifiedSubscriberValue returns the named value unidentifiedSubscriber.
func LocalErrorcodeUnidentifiedSubscriberValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeUnidentifiedSubscriberDecimal))
}

// LocalErrorcodeAbsentSubscriberSMValue returns the named value absentSubscriberSM.
func LocalErrorcodeAbsentSubscriberSMValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeAbsentSubscriberSMDecimal))
}

// LocalErrorcodeUnknownEquipmentValue returns the named value unknownEquipment.
func LocalErrorcodeUnknownEquipmentValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeUnknownEquipmentDecimal))
}

// LocalErrorcodeRoamingNotAllowedValue returns the named value roamingNotAllowed.
func LocalErrorcodeRoamingNotAllowedValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeRoamingNotAllowedDecimal))
}

// LocalErrorcodeIllegalSubscriberValue returns the named value illegalSubscriber.
func LocalErrorcodeIllegalSubscriberValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeIllegalSubscriberDecimal))
}

// LocalErrorcodeBearerServiceNotProvisionedValue returns the named value bearerServiceNotProvisioned.
func LocalErrorcodeBearerServiceNotProvisionedValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeBearerServiceNotProvisionedDecimal))
}

// LocalErrorcodeTeleserviceNotProvisionedValue returns the named value teleserviceNotProvisioned.
func LocalErrorcodeTeleserviceNotProvisionedValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeTeleserviceNotProvisionedDecimal))
}

// LocalErrorcodeIllegalEquipmentValue returns the named value illegalEquipment.
func LocalErrorcodeIllegalEquipmentValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeIllegalEquipmentDecimal))
}

// LocalErrorcodeCallBarredValue returns the named value callBarred.
func LocalErrorcodeCallBarredValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeCallBarredDecimal))
}

// LocalErrorcodeForwardingViolationValue returns the named value forwardingViolation.
func LocalErrorcodeForwardingViolationValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeForwardingViolationDecimal))
}

// LocalErrorcodeCugRejectValue returns the named value cug-Reject.
func LocalErrorcodeCugRejectValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeCugRejectDecimal))
}

// LocalErrorcodeIllegalSSOperationValue returns the named value illegalSS-Operation.
func LocalErrorcodeIllegalSSOperationValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeIllegalSSOperationDecimal))
}

// LocalErrorcodeSsErrorStatusValue returns the named value ss-ErrorStatus.
func LocalErrorcodeSsErrorStatusValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeSsErrorStatusDecimal))
}

// LocalErrorcodeSsNotAvailableValue returns the named value ss-NotAvailable.
func LocalErrorcodeSsNotAvailableValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeSsNotAvailableDecimal))
}

// LocalErrorcodeSsSubscriptionViolationValue returns the named value ss-SubscriptionViolation.
func LocalErrorcodeSsSubscriptionViolationValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeSsSubscriptionViolationDecimal))
}

// LocalErrorcodeSsIncompatibilityValue returns the named value ss-Incompatibility.
func LocalErrorcodeSsIncompatibilityValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeSsIncompatibilityDecimal))
}

// LocalErrorcodeFacilityNotSupportedValue returns the named value facilityNotSupported.
func LocalErrorcodeFacilityNotSupportedValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeFacilityNotSupportedDecimal))
}

// LocalErrorcodeOngoingGroupCallValue returns the named value ongoingGroupCall.
func LocalErrorcodeOngoingGroupCallValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeOngoingGroupCallDecimal))
}

// LocalErrorcodeInvalidTargetBaseStationValue returns the named value invalidTargetBaseStation.
func LocalErrorcodeInvalidTargetBaseStationValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeInvalidTargetBaseStationDecimal))
}

// LocalErrorcodeNoRadioResourceAvailableValue returns the named value noRadioResourceAvailable.
func LocalErrorcodeNoRadioResourceAvailableValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeNoRadioResourceAvailableDecimal))
}

// LocalErrorcodeNoHandoverNumberAvailableValue returns the named value noHandoverNumberAvailable.
func LocalErrorcodeNoHandoverNumberAvailableValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeNoHandoverNumberAvailableDecimal))
}

// LocalErrorcodeSubsequentHandoverFailureValue returns the named value subsequentHandoverFailure.
func LocalErrorcodeSubsequentHandoverFailureValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeSubsequentHandoverFailureDecimal))
}

// LocalErrorcodeAbsentSubscriberValue returns the named value absentSubscriber.
func LocalErrorcodeAbsentSubscriberValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeAbsentSubscriberDecimal))
}

// LocalErrorcodeIncompatibleTerminalValue returns the named value incompatibleTerminal.
func LocalErrorcodeIncompatibleTerminalValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeIncompatibleTerminalDecimal))
}

// LocalErrorcodeShortTermDenialValue returns the named value shortTermDenial.
func LocalErrorcodeShortTermDenialValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeShortTermDenialDecimal))
}

// LocalErrorcodeLongTermDenialValue returns the named value longTermDenial.
func LocalErrorcodeLongTermDenialValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeLongTermDenialDecimal))
}

// LocalErrorcodeSubscriberBusyForMTSMSValue returns the named value subscriberBusyForMT-SMS.
func LocalErrorcodeSubscriberBusyForMTSMSValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeSubscriberBusyForMTSMSDecimal))
}

// LocalErrorcodeSmDeliveryFailureValue returns the named value sm-DeliveryFailure.
func LocalErrorcodeSmDeliveryFailureValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeSmDeliveryFailureDecimal))
}

// LocalErrorcodeMessageWaitingListFullValue returns the named value messageWaitingListFull.
func LocalErrorcodeMessageWaitingListFullValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeMessageWaitingListFullDecimal))
}

// LocalErrorcodeSystemFailureValue returns the named value systemFailure.
func LocalErrorcodeSystemFailureValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeSystemFailureDecimal))
}

// LocalErrorcodeDataMissingValue returns the named value dataMissing.
func LocalErrorcodeDataMissingValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeDataMissingDecimal))
}

// LocalErrorcodeUnexpectedDataValueValue returns the named value unexpectedDataValue.
func LocalErrorcodeUnexpectedDataValueValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeUnexpectedDataValueDecimal))
}

// LocalErrorcodePwRegistrationFailureValue returns the named value pw-RegistrationFailure.
func LocalErrorcodePwRegistrationFailureValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodePwRegistrationFailureDecimal))
}

// LocalErrorcodeNegativePWCheckValue returns the named value negativePW-Check.
func LocalErrorcodeNegativePWCheckValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeNegativePWCheckDecimal))
}

// LocalErrorcodeNoRoamingNumberAvailableValue returns the named value noRoamingNumberAvailable.
func LocalErrorcodeNoRoamingNumberAvailableValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeNoRoamingNumberAvailableDecimal))
}

// LocalErrorcodeTracingBufferFullValue returns the named value tracingBufferFull.
func LocalErrorcodeTracingBufferFullValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeTracingBufferFullDecimal))
}

// LocalErrorcodeTargetCellOutsideGroupCallAreaValue returns the named value targetCellOutsideGroupCallArea.
func LocalErrorcodeTargetCellOutsideGroupCallAreaValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeTargetCellOutsideGroupCallAreaDecimal))
}

// LocalErrorcodeNumberOfPWAttemptsViolationValue returns the named value numberOfPW-AttemptsViolation.
func LocalErrorcodeNumberOfPWAttemptsViolationValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeNumberOfPWAttemptsViolationDecimal))
}

// LocalErrorcodeNumberChangedValue returns the named value numberChanged.
func LocalErrorcodeNumberChangedValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeNumberChangedDecimal))
}

// LocalErrorcodeBusySubscriberValue returns the named value busySubscriber.
func LocalErrorcodeBusySubscriberValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeBusySubscriberDecimal))
}

// LocalErrorcodeNoSubscriberReplyValue returns the named value noSubscriberReply.
func LocalErrorcodeNoSubscriberReplyValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeNoSubscriberReplyDecimal))
}

// LocalErrorcodeForwardingFailedValue returns the named value forwardingFailed.
func LocalErrorcodeForwardingFailedValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeForwardingFailedDecimal))
}

// LocalErrorcodeOrNotAllowedValue returns the named value or-NotAllowed.
func LocalErrorcodeOrNotAllowedValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeOrNotAllowedDecimal))
}

// LocalErrorcodeAtiNotAllowedValue returns the named value ati-NotAllowed.
func LocalErrorcodeAtiNotAllowedValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeAtiNotAllowedDecimal))
}

// LocalErrorcodeNoGroupCallNumberAvailableValue returns the named value noGroupCallNumberAvailable.
func LocalErrorcodeNoGroupCallNumberAvailableValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeNoGroupCallNumberAvailableDecimal))
}

// LocalErrorcodeResourceLimitationValue returns the named value resourceLimitation.
func LocalErrorcodeResourceLimitationValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeResourceLimitationDecimal))
}

// LocalErrorcodeUnauthorizedRequestingNetworkValue returns the named value unauthorizedRequestingNetwork.
func LocalErrorcodeUnauthorizedRequestingNetworkValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeUnauthorizedRequestingNetworkDecimal))
}

// LocalErrorcodeUnauthorizedLCSClientValue returns the named value unauthorizedLCSClient.
func LocalErrorcodeUnauthorizedLCSClientValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeUnauthorizedLCSClientDecimal))
}

// LocalErrorcodePositionMethodFailureValue returns the named value positionMethodFailure.
func LocalErrorcodePositionMethodFailureValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodePositionMethodFailureDecimal))
}

// LocalErrorcodeUnknownOrUnreachableLCSClientValue returns the named value unknownOrUnreachableLCSClient.
func LocalErrorcodeUnknownOrUnreachableLCSClientValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeUnknownOrUnreachableLCSClientDecimal))
}

// LocalErrorcodeMmEventNotSupportedValue returns the named value mm-EventNotSupported.
func LocalErrorcodeMmEventNotSupportedValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeMmEventNotSupportedDecimal))
}

// LocalErrorcodeAtsiNotAllowedValue returns the named value atsi-NotAllowed.
func LocalErrorcodeAtsiNotAllowedValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeAtsiNotAllowedDecimal))
}

// LocalErrorcodeAtmNotAllowedValue returns the named value atm-NotAllowed.
func LocalErrorcodeAtmNotAllowedValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeAtmNotAllowedDecimal))
}

// LocalErrorcodeInformationNotAvailableValue returns the named value informationNotAvailable.
func LocalErrorcodeInformationNotAvailableValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeInformationNotAvailableDecimal))
}

// LocalErrorcodeUnknownAlphabetValue returns the named value unknownAlphabet.
func LocalErrorcodeUnknownAlphabetValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeUnknownAlphabetDecimal))
}

// LocalErrorcodeUssdBusyValue returns the named value ussd-Busy.
func LocalErrorcodeUssdBusyValue() LocalErrorcode {
	return NewLocalErrorcode(runtime.MustParseBigIntDecimal(LocalErrorcodeUssdBusyDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v LocalErrorcode) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v LocalErrorcode) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v LocalErrorcode) Name() (string, bool) {
	switch v.BigInt().String() {
	case LocalErrorcodeUnknownSubscriberDecimal:
		return "unknownSubscriber", true
	case LocalErrorcodeUnknownBaseStationDecimal:
		return "unknownBaseStation", true
	case LocalErrorcodeUnknownMSCDecimal:
		return "unknownMSC", true
	case LocalErrorcodeSecureTransportErrorDecimal:
		return "secureTransportError", true
	case LocalErrorcodeUnidentifiedSubscriberDecimal:
		return "unidentifiedSubscriber", true
	case LocalErrorcodeAbsentSubscriberSMDecimal:
		return "absentSubscriberSM", true
	case LocalErrorcodeUnknownEquipmentDecimal:
		return "unknownEquipment", true
	case LocalErrorcodeRoamingNotAllowedDecimal:
		return "roamingNotAllowed", true
	case LocalErrorcodeIllegalSubscriberDecimal:
		return "illegalSubscriber", true
	case LocalErrorcodeBearerServiceNotProvisionedDecimal:
		return "bearerServiceNotProvisioned", true
	case LocalErrorcodeTeleserviceNotProvisionedDecimal:
		return "teleserviceNotProvisioned", true
	case LocalErrorcodeIllegalEquipmentDecimal:
		return "illegalEquipment", true
	case LocalErrorcodeCallBarredDecimal:
		return "callBarred", true
	case LocalErrorcodeForwardingViolationDecimal:
		return "forwardingViolation", true
	case LocalErrorcodeCugRejectDecimal:
		return "cug-Reject", true
	case LocalErrorcodeIllegalSSOperationDecimal:
		return "illegalSS-Operation", true
	case LocalErrorcodeSsErrorStatusDecimal:
		return "ss-ErrorStatus", true
	case LocalErrorcodeSsNotAvailableDecimal:
		return "ss-NotAvailable", true
	case LocalErrorcodeSsSubscriptionViolationDecimal:
		return "ss-SubscriptionViolation", true
	case LocalErrorcodeSsIncompatibilityDecimal:
		return "ss-Incompatibility", true
	case LocalErrorcodeFacilityNotSupportedDecimal:
		return "facilityNotSupported", true
	case LocalErrorcodeOngoingGroupCallDecimal:
		return "ongoingGroupCall", true
	case LocalErrorcodeInvalidTargetBaseStationDecimal:
		return "invalidTargetBaseStation", true
	case LocalErrorcodeNoRadioResourceAvailableDecimal:
		return "noRadioResourceAvailable", true
	case LocalErrorcodeNoHandoverNumberAvailableDecimal:
		return "noHandoverNumberAvailable", true
	case LocalErrorcodeSubsequentHandoverFailureDecimal:
		return "subsequentHandoverFailure", true
	case LocalErrorcodeAbsentSubscriberDecimal:
		return "absentSubscriber", true
	case LocalErrorcodeIncompatibleTerminalDecimal:
		return "incompatibleTerminal", true
	case LocalErrorcodeShortTermDenialDecimal:
		return "shortTermDenial", true
	case LocalErrorcodeLongTermDenialDecimal:
		return "longTermDenial", true
	case LocalErrorcodeSubscriberBusyForMTSMSDecimal:
		return "subscriberBusyForMT-SMS", true
	case LocalErrorcodeSmDeliveryFailureDecimal:
		return "sm-DeliveryFailure", true
	case LocalErrorcodeMessageWaitingListFullDecimal:
		return "messageWaitingListFull", true
	case LocalErrorcodeSystemFailureDecimal:
		return "systemFailure", true
	case LocalErrorcodeDataMissingDecimal:
		return "dataMissing", true
	case LocalErrorcodeUnexpectedDataValueDecimal:
		return "unexpectedDataValue", true
	case LocalErrorcodePwRegistrationFailureDecimal:
		return "pw-RegistrationFailure", true
	case LocalErrorcodeNegativePWCheckDecimal:
		return "negativePW-Check", true
	case LocalErrorcodeNoRoamingNumberAvailableDecimal:
		return "noRoamingNumberAvailable", true
	case LocalErrorcodeTracingBufferFullDecimal:
		return "tracingBufferFull", true
	case LocalErrorcodeTargetCellOutsideGroupCallAreaDecimal:
		return "targetCellOutsideGroupCallArea", true
	case LocalErrorcodeNumberOfPWAttemptsViolationDecimal:
		return "numberOfPW-AttemptsViolation", true
	case LocalErrorcodeNumberChangedDecimal:
		return "numberChanged", true
	case LocalErrorcodeBusySubscriberDecimal:
		return "busySubscriber", true
	case LocalErrorcodeNoSubscriberReplyDecimal:
		return "noSubscriberReply", true
	case LocalErrorcodeForwardingFailedDecimal:
		return "forwardingFailed", true
	case LocalErrorcodeOrNotAllowedDecimal:
		return "or-NotAllowed", true
	case LocalErrorcodeAtiNotAllowedDecimal:
		return "ati-NotAllowed", true
	case LocalErrorcodeNoGroupCallNumberAvailableDecimal:
		return "noGroupCallNumberAvailable", true
	case LocalErrorcodeResourceLimitationDecimal:
		return "resourceLimitation", true
	case LocalErrorcodeUnauthorizedRequestingNetworkDecimal:
		return "unauthorizedRequestingNetwork", true
	case LocalErrorcodeUnauthorizedLCSClientDecimal:
		return "unauthorizedLCSClient", true
	case LocalErrorcodePositionMethodFailureDecimal:
		return "positionMethodFailure", true
	case LocalErrorcodeUnknownOrUnreachableLCSClientDecimal:
		return "unknownOrUnreachableLCSClient", true
	case LocalErrorcodeMmEventNotSupportedDecimal:
		return "mm-EventNotSupported", true
	case LocalErrorcodeAtsiNotAllowedDecimal:
		return "atsi-NotAllowed", true
	case LocalErrorcodeAtmNotAllowedDecimal:
		return "atm-NotAllowed", true
	case LocalErrorcodeInformationNotAvailableDecimal:
		return "informationNotAvailable", true
	case LocalErrorcodeUnknownAlphabetDecimal:
		return "unknownAlphabet", true
	case LocalErrorcodeUssdBusyDecimal:
		return "ussd-Busy", true
	default:
		return "", false
	}
}

func (v LocalErrorcode) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v LocalErrorcode) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *LocalErrorcode) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal LocalErrorcode into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewLocalErrorcode(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v LocalErrorcode) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *LocalErrorcode) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal LocalErrorcode into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewLocalErrorcode(value)
	return nil
}

// DumGeneralProblem represents the arbitrary-width ASN.1 INTEGER type DumGeneralProblem with named numbers.
type DumGeneralProblem struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	DumGeneralProblemUnrecognizedComponentDecimal    = "0"
	DumGeneralProblemUnrecognizedComponent           = 0
	DumGeneralProblemMistypedComponentDecimal        = "1"
	DumGeneralProblemMistypedComponent               = 1
	DumGeneralProblemBadlyStructuredComponentDecimal = "2"
	DumGeneralProblemBadlyStructuredComponent        = 2
)

// NewDumGeneralProblem returns an immutable DumGeneralProblem containing value.
func NewDumGeneralProblem(value *big.Int) DumGeneralProblem {
	return DumGeneralProblem{value: runtime.CloneBigInt(value)}
}

// NewDumGeneralProblemInt64 returns a DumGeneralProblem containing value.
func NewDumGeneralProblemInt64(value int64) DumGeneralProblem {
	return NewDumGeneralProblem(big.NewInt(value))
}

// DumGeneralProblemUnrecognizedComponentValue returns the named value unrecognizedComponent.
func DumGeneralProblemUnrecognizedComponentValue() DumGeneralProblem {
	return NewDumGeneralProblem(runtime.MustParseBigIntDecimal(DumGeneralProblemUnrecognizedComponentDecimal))
}

// DumGeneralProblemMistypedComponentValue returns the named value mistypedComponent.
func DumGeneralProblemMistypedComponentValue() DumGeneralProblem {
	return NewDumGeneralProblem(runtime.MustParseBigIntDecimal(DumGeneralProblemMistypedComponentDecimal))
}

// DumGeneralProblemBadlyStructuredComponentValue returns the named value badlyStructuredComponent.
func DumGeneralProblemBadlyStructuredComponentValue() DumGeneralProblem {
	return NewDumGeneralProblem(runtime.MustParseBigIntDecimal(DumGeneralProblemBadlyStructuredComponentDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v DumGeneralProblem) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v DumGeneralProblem) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v DumGeneralProblem) Name() (string, bool) {
	switch v.BigInt().String() {
	case DumGeneralProblemUnrecognizedComponentDecimal:
		return "unrecognizedComponent", true
	case DumGeneralProblemMistypedComponentDecimal:
		return "mistypedComponent", true
	case DumGeneralProblemBadlyStructuredComponentDecimal:
		return "badlyStructuredComponent", true
	default:
		return "", false
	}
}

func (v DumGeneralProblem) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v DumGeneralProblem) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *DumGeneralProblem) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DumGeneralProblem into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewDumGeneralProblem(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v DumGeneralProblem) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *DumGeneralProblem) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DumGeneralProblem into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewDumGeneralProblem(value)
	return nil
}

// DumInvokeProblem represents the arbitrary-width ASN.1 INTEGER type DumInvokeProblem with named numbers.
type DumInvokeProblem struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	DumInvokeProblemDuplicateInvokeIDDecimal         = "0"
	DumInvokeProblemDuplicateInvokeID                = 0
	DumInvokeProblemUnrecognizedOperationDecimal     = "1"
	DumInvokeProblemUnrecognizedOperation            = 1
	DumInvokeProblemMistypedParameterDecimal         = "2"
	DumInvokeProblemMistypedParameter                = 2
	DumInvokeProblemResourceLimitationDecimal        = "3"
	DumInvokeProblemResourceLimitation               = 3
	DumInvokeProblemInitiatingReleaseDecimal         = "4"
	DumInvokeProblemInitiatingRelease                = 4
	DumInvokeProblemUnrecognizedLinkedIDDecimal      = "5"
	DumInvokeProblemUnrecognizedLinkedID             = 5
	DumInvokeProblemLinkedResponseUnexpectedDecimal  = "6"
	DumInvokeProblemLinkedResponseUnexpected         = 6
	DumInvokeProblemUnexpectedLinkedOperationDecimal = "7"
	DumInvokeProblemUnexpectedLinkedOperation        = 7
)

// NewDumInvokeProblem returns an immutable DumInvokeProblem containing value.
func NewDumInvokeProblem(value *big.Int) DumInvokeProblem {
	return DumInvokeProblem{value: runtime.CloneBigInt(value)}
}

// NewDumInvokeProblemInt64 returns a DumInvokeProblem containing value.
func NewDumInvokeProblemInt64(value int64) DumInvokeProblem {
	return NewDumInvokeProblem(big.NewInt(value))
}

// DumInvokeProblemDuplicateInvokeIDValue returns the named value duplicateInvokeID.
func DumInvokeProblemDuplicateInvokeIDValue() DumInvokeProblem {
	return NewDumInvokeProblem(runtime.MustParseBigIntDecimal(DumInvokeProblemDuplicateInvokeIDDecimal))
}

// DumInvokeProblemUnrecognizedOperationValue returns the named value unrecognizedOperation.
func DumInvokeProblemUnrecognizedOperationValue() DumInvokeProblem {
	return NewDumInvokeProblem(runtime.MustParseBigIntDecimal(DumInvokeProblemUnrecognizedOperationDecimal))
}

// DumInvokeProblemMistypedParameterValue returns the named value mistypedParameter.
func DumInvokeProblemMistypedParameterValue() DumInvokeProblem {
	return NewDumInvokeProblem(runtime.MustParseBigIntDecimal(DumInvokeProblemMistypedParameterDecimal))
}

// DumInvokeProblemResourceLimitationValue returns the named value resourceLimitation.
func DumInvokeProblemResourceLimitationValue() DumInvokeProblem {
	return NewDumInvokeProblem(runtime.MustParseBigIntDecimal(DumInvokeProblemResourceLimitationDecimal))
}

// DumInvokeProblemInitiatingReleaseValue returns the named value initiatingRelease.
func DumInvokeProblemInitiatingReleaseValue() DumInvokeProblem {
	return NewDumInvokeProblem(runtime.MustParseBigIntDecimal(DumInvokeProblemInitiatingReleaseDecimal))
}

// DumInvokeProblemUnrecognizedLinkedIDValue returns the named value unrecognizedLinkedID.
func DumInvokeProblemUnrecognizedLinkedIDValue() DumInvokeProblem {
	return NewDumInvokeProblem(runtime.MustParseBigIntDecimal(DumInvokeProblemUnrecognizedLinkedIDDecimal))
}

// DumInvokeProblemLinkedResponseUnexpectedValue returns the named value linkedResponseUnexpected.
func DumInvokeProblemLinkedResponseUnexpectedValue() DumInvokeProblem {
	return NewDumInvokeProblem(runtime.MustParseBigIntDecimal(DumInvokeProblemLinkedResponseUnexpectedDecimal))
}

// DumInvokeProblemUnexpectedLinkedOperationValue returns the named value unexpectedLinkedOperation.
func DumInvokeProblemUnexpectedLinkedOperationValue() DumInvokeProblem {
	return NewDumInvokeProblem(runtime.MustParseBigIntDecimal(DumInvokeProblemUnexpectedLinkedOperationDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v DumInvokeProblem) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v DumInvokeProblem) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v DumInvokeProblem) Name() (string, bool) {
	switch v.BigInt().String() {
	case DumInvokeProblemDuplicateInvokeIDDecimal:
		return "duplicateInvokeID", true
	case DumInvokeProblemUnrecognizedOperationDecimal:
		return "unrecognizedOperation", true
	case DumInvokeProblemMistypedParameterDecimal:
		return "mistypedParameter", true
	case DumInvokeProblemResourceLimitationDecimal:
		return "resourceLimitation", true
	case DumInvokeProblemInitiatingReleaseDecimal:
		return "initiatingRelease", true
	case DumInvokeProblemUnrecognizedLinkedIDDecimal:
		return "unrecognizedLinkedID", true
	case DumInvokeProblemLinkedResponseUnexpectedDecimal:
		return "linkedResponseUnexpected", true
	case DumInvokeProblemUnexpectedLinkedOperationDecimal:
		return "unexpectedLinkedOperation", true
	default:
		return "", false
	}
}

func (v DumInvokeProblem) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v DumInvokeProblem) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *DumInvokeProblem) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DumInvokeProblem into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewDumInvokeProblem(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v DumInvokeProblem) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *DumInvokeProblem) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DumInvokeProblem into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewDumInvokeProblem(value)
	return nil
}

// DumReturnResultProblem represents the arbitrary-width ASN.1 INTEGER type DumReturnResultProblem with named numbers.
type DumReturnResultProblem struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	DumReturnResultProblemUnrecognizedInvokeIDDecimal   = "0"
	DumReturnResultProblemUnrecognizedInvokeID          = 0
	DumReturnResultProblemReturnResultUnexpectedDecimal = "1"
	DumReturnResultProblemReturnResultUnexpected        = 1
	DumReturnResultProblemMistypedParameterDecimal      = "2"
	DumReturnResultProblemMistypedParameter             = 2
)

// NewDumReturnResultProblem returns an immutable DumReturnResultProblem containing value.
func NewDumReturnResultProblem(value *big.Int) DumReturnResultProblem {
	return DumReturnResultProblem{value: runtime.CloneBigInt(value)}
}

// NewDumReturnResultProblemInt64 returns a DumReturnResultProblem containing value.
func NewDumReturnResultProblemInt64(value int64) DumReturnResultProblem {
	return NewDumReturnResultProblem(big.NewInt(value))
}

// DumReturnResultProblemUnrecognizedInvokeIDValue returns the named value unrecognizedInvokeID.
func DumReturnResultProblemUnrecognizedInvokeIDValue() DumReturnResultProblem {
	return NewDumReturnResultProblem(runtime.MustParseBigIntDecimal(DumReturnResultProblemUnrecognizedInvokeIDDecimal))
}

// DumReturnResultProblemReturnResultUnexpectedValue returns the named value returnResultUnexpected.
func DumReturnResultProblemReturnResultUnexpectedValue() DumReturnResultProblem {
	return NewDumReturnResultProblem(runtime.MustParseBigIntDecimal(DumReturnResultProblemReturnResultUnexpectedDecimal))
}

// DumReturnResultProblemMistypedParameterValue returns the named value mistypedParameter.
func DumReturnResultProblemMistypedParameterValue() DumReturnResultProblem {
	return NewDumReturnResultProblem(runtime.MustParseBigIntDecimal(DumReturnResultProblemMistypedParameterDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v DumReturnResultProblem) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v DumReturnResultProblem) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v DumReturnResultProblem) Name() (string, bool) {
	switch v.BigInt().String() {
	case DumReturnResultProblemUnrecognizedInvokeIDDecimal:
		return "unrecognizedInvokeID", true
	case DumReturnResultProblemReturnResultUnexpectedDecimal:
		return "returnResultUnexpected", true
	case DumReturnResultProblemMistypedParameterDecimal:
		return "mistypedParameter", true
	default:
		return "", false
	}
}

func (v DumReturnResultProblem) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v DumReturnResultProblem) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *DumReturnResultProblem) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DumReturnResultProblem into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewDumReturnResultProblem(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v DumReturnResultProblem) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *DumReturnResultProblem) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DumReturnResultProblem into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewDumReturnResultProblem(value)
	return nil
}

// DumReturnErrorProblem represents the arbitrary-width ASN.1 INTEGER type DumReturnErrorProblem with named numbers.
type DumReturnErrorProblem struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	DumReturnErrorProblemUnrecognizedInvokeIDDecimal  = "0"
	DumReturnErrorProblemUnrecognizedInvokeID         = 0
	DumReturnErrorProblemReturnErrorUnexpectedDecimal = "1"
	DumReturnErrorProblemReturnErrorUnexpected        = 1
	DumReturnErrorProblemUnrecognizedErrorDecimal     = "2"
	DumReturnErrorProblemUnrecognizedError            = 2
	DumReturnErrorProblemUnexpectedErrorDecimal       = "3"
	DumReturnErrorProblemUnexpectedError              = 3
	DumReturnErrorProblemMistypedParameterDecimal     = "4"
	DumReturnErrorProblemMistypedParameter            = 4
)

// NewDumReturnErrorProblem returns an immutable DumReturnErrorProblem containing value.
func NewDumReturnErrorProblem(value *big.Int) DumReturnErrorProblem {
	return DumReturnErrorProblem{value: runtime.CloneBigInt(value)}
}

// NewDumReturnErrorProblemInt64 returns a DumReturnErrorProblem containing value.
func NewDumReturnErrorProblemInt64(value int64) DumReturnErrorProblem {
	return NewDumReturnErrorProblem(big.NewInt(value))
}

// DumReturnErrorProblemUnrecognizedInvokeIDValue returns the named value unrecognizedInvokeID.
func DumReturnErrorProblemUnrecognizedInvokeIDValue() DumReturnErrorProblem {
	return NewDumReturnErrorProblem(runtime.MustParseBigIntDecimal(DumReturnErrorProblemUnrecognizedInvokeIDDecimal))
}

// DumReturnErrorProblemReturnErrorUnexpectedValue returns the named value returnErrorUnexpected.
func DumReturnErrorProblemReturnErrorUnexpectedValue() DumReturnErrorProblem {
	return NewDumReturnErrorProblem(runtime.MustParseBigIntDecimal(DumReturnErrorProblemReturnErrorUnexpectedDecimal))
}

// DumReturnErrorProblemUnrecognizedErrorValue returns the named value unrecognizedError.
func DumReturnErrorProblemUnrecognizedErrorValue() DumReturnErrorProblem {
	return NewDumReturnErrorProblem(runtime.MustParseBigIntDecimal(DumReturnErrorProblemUnrecognizedErrorDecimal))
}

// DumReturnErrorProblemUnexpectedErrorValue returns the named value unexpectedError.
func DumReturnErrorProblemUnexpectedErrorValue() DumReturnErrorProblem {
	return NewDumReturnErrorProblem(runtime.MustParseBigIntDecimal(DumReturnErrorProblemUnexpectedErrorDecimal))
}

// DumReturnErrorProblemMistypedParameterValue returns the named value mistypedParameter.
func DumReturnErrorProblemMistypedParameterValue() DumReturnErrorProblem {
	return NewDumReturnErrorProblem(runtime.MustParseBigIntDecimal(DumReturnErrorProblemMistypedParameterDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v DumReturnErrorProblem) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v DumReturnErrorProblem) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v DumReturnErrorProblem) Name() (string, bool) {
	switch v.BigInt().String() {
	case DumReturnErrorProblemUnrecognizedInvokeIDDecimal:
		return "unrecognizedInvokeID", true
	case DumReturnErrorProblemReturnErrorUnexpectedDecimal:
		return "returnErrorUnexpected", true
	case DumReturnErrorProblemUnrecognizedErrorDecimal:
		return "unrecognizedError", true
	case DumReturnErrorProblemUnexpectedErrorDecimal:
		return "unexpectedError", true
	case DumReturnErrorProblemMistypedParameterDecimal:
		return "mistypedParameter", true
	default:
		return "", false
	}
}

func (v DumReturnErrorProblem) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v DumReturnErrorProblem) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *DumReturnErrorProblem) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DumReturnErrorProblem into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewDumReturnErrorProblem(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v DumReturnErrorProblem) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *DumReturnErrorProblem) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal DumReturnErrorProblem into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewDumReturnErrorProblem(value)
	return nil
}

// BssAPDU represents the ASN.1 type BssAPDU (SEQUENCE).
type BssAPDU struct {
	ProtocolId         CommonDataTypesProtocolId             `asn1:""`
	SignalInfo         CommonDataTypesSignalInfo             `asn1:""`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// ProvideSIWFSNumberArg represents the ASN.1 type ProvideSIWFSNumberArg (SEQUENCE).
type ProvideSIWFSNumberArg struct {
	GsmBearerCapability     CommonDataTypesExternalSignalInfo     `asn1:"tag:0,context,implicit"`
	IsdnBearerCapability    CommonDataTypesExternalSignalInfo     `asn1:"tag:1,context,implicit"`
	CallDirection           CallDirection                         `asn1:"tag:2,context,implicit"`
	BSubscriberAddress      CommonDataTypesISDNAddressString      `asn1:"tag:3,context,implicit"`
	ChosenChannel           CommonDataTypesExternalSignalInfo     `asn1:"tag:4,context,implicit"`
	LowerLayerCompatibility *CommonDataTypesExternalSignalInfo    `asn1:"tag:5,context,implicit,optional" json:"LowerLayerCompatibility,omitempty"`
	HighLayerCompatibility  *CommonDataTypesExternalSignalInfo    `asn1:"tag:6,context,implicit,optional" json:"HighLayerCompatibility,omitempty"`
	ExtensionContainer      *ExtensionDataTypesExtensionContainer `asn1:"tag:7,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                                 `asn1:"-" json:"-"`
	ExtPresent_             []bool                                `asn1:"-" json:"-"`
	ExtData_                [][]byte                              `asn1:"-" json:"-"`
}

// ProvideSIWFSNumberRes represents the ASN.1 type ProvideSIWFSNumberRes (SEQUENCE).
type ProvideSIWFSNumberRes struct {
	SIWFSNumber        CommonDataTypesISDNAddressString      `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CallDirection represents the ASN.1 type CallDirection (OCTET_STRING).
type CallDirection = []byte

// DumPurgeMSArgV2 represents the ASN.1 type DumPurgeMSArgV2 (SEQUENCE).
type DumPurgeMSArgV2 struct {
	Imsi        CommonDataTypesIMSI               `asn1:""`
	VlrNumber   *CommonDataTypesISDNAddressString `asn1:",optional" json:"VlrNumber,omitempty"`
	ExtCount_   int64                             `asn1:"-" json:"-"`
	ExtPresent_ []bool                            `asn1:"-" json:"-"`
	ExtData_    [][]byte                          `asn1:"-" json:"-"`
}

// PrepareHOArgOld represents the ASN.1 type PrepareHOArgOld (SEQUENCE).
type PrepareHOArgOld struct {
	TargetCellId        *CommonDataTypesGlobalCellId `asn1:",optional" json:"TargetCellId,omitempty"`
	HoNumberNotRequired *struct{}                    `asn1:",optional" json:"HoNumberNotRequired,omitempty"`
	BssAPDU             *BssAPDU                     `asn1:",optional" json:"BssAPDU,omitempty"`
	ExtCount_           int64                        `asn1:"-" json:"-"`
	ExtPresent_         []bool                       `asn1:"-" json:"-"`
	ExtData_            [][]byte                     `asn1:"-" json:"-"`
}

// PrepareHOResOld represents the ASN.1 type PrepareHOResOld (SEQUENCE).
type PrepareHOResOld struct {
	HandoverNumber *CommonDataTypesISDNAddressString `asn1:",optional" json:"HandoverNumber,omitempty"`
	BssAPDU        *BssAPDU                          `asn1:",optional" json:"BssAPDU,omitempty"`
	ExtCount_      int64                             `asn1:"-" json:"-"`
	ExtPresent_    []bool                            `asn1:"-" json:"-"`
	ExtData_       [][]byte                          `asn1:"-" json:"-"`
}

// DumSendAuthenticationInfoResOld represents the ASN.1 type DumSendAuthenticationInfoResOld (SEQUENCE_OF).
type DumSendAuthenticationInfoResOld = []DumSendAuthenticationInfoResOldElem

// DumRAND represents the ASN.1 type DumRAND (OCTET_STRING).
type DumRAND = []byte

// DumSRES represents the ASN.1 type DumSRES (OCTET_STRING).
type DumSRES = []byte

// DumKc represents the ASN.1 type DumKc (OCTET_STRING).
type DumKc = []byte

// DumSendIdentificationResV2 represents the ASN.1 type DumSendIdentificationResV2 (SEQUENCE).
type DumSendIdentificationResV2 struct {
	Imsi              *CommonDataTypesIMSI `asn1:",optional" json:"Imsi,omitempty"`
	TripletList       TripletListold       `asn1:",optional" json:"TripletList,omitempty"`
	TripletListIndef_ bool                 `asn1:"-" json:"-"`
	ExtCount_         int64                `asn1:"-" json:"-"`
	ExtPresent_       []bool               `asn1:"-" json:"-"`
	ExtData_          [][]byte             `asn1:"-" json:"-"`
}

// TripletListold represents the ASN.1 type TripletListold (SEQUENCE_OF).
type TripletListold = []AuthenticationTripletV2

// AuthenticationTripletV2 represents the ASN.1 type AuthenticationTripletV2 (SEQUENCE).
type AuthenticationTripletV2 struct {
	Rand        DumRAND  `asn1:""`
	Sres        DumSRES  `asn1:""`
	Kc          DumKc    `asn1:""`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// SIWFSSignallingModifyArg represents the ASN.1 type SIWFSSignallingModifyArg (SEQUENCE).
type SIWFSSignallingModifyArg struct {
	ChannelType        *CommonDataTypesExternalSignalInfo    `asn1:"tag:0,context,implicit,optional" json:"ChannelType,omitempty"`
	ChosenChannel      *CommonDataTypesExternalSignalInfo    `asn1:"tag:1,context,implicit,optional" json:"ChosenChannel,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// SIWFSSignallingModifyRes represents the ASN.1 type SIWFSSignallingModifyRes (SEQUENCE).
type SIWFSSignallingModifyRes struct {
	ChannelType        *CommonDataTypesExternalSignalInfo    `asn1:"tag:0,context,implicit,optional" json:"ChannelType,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// NewPassword represents the ASN.1 type NewPassword (NumericString).
type NewPassword = string

// GetPasswordArg represents the ASN.1 ENUMERATED type GetPasswordArg.
type GetPasswordArg int64

const (
	GetPasswordArgEnterPW         GetPasswordArg = 0
	GetPasswordArgEnterNewPW      GetPasswordArg = 1
	GetPasswordArgEnterNewPWAgain GetPasswordArg = 2
)

func (v GetPasswordArg) String() string {
	switch v {
	case GetPasswordArgEnterPW:
		return "enterPW"
	case GetPasswordArgEnterNewPW:
		return "enterNewPW"
	case GetPasswordArgEnterNewPWAgain:
		return "enterNewPW-Again"
	default:
		return "unknown"
	}
}

// CurrentPassword represents the ASN.1 type CurrentPassword (NumericString).
type CurrentPassword = string

// SecureTransportArg represents the ASN.1 type SecureTransportArg (SEQUENCE).
type SecureTransportArg struct {
	SecurityHeader   SecurityHeader    `asn1:""`
	ProtectedPayload *ProtectedPayload `asn1:",optional" json:"ProtectedPayload,omitempty"`
}

// SecureTransportErrorParam represents the ASN.1 type SecureTransportErrorParam (SEQUENCE).
type SecureTransportErrorParam struct {
	SecurityHeader   SecurityHeader    `asn1:""`
	ProtectedPayload *ProtectedPayload `asn1:",optional" json:"ProtectedPayload,omitempty"`
}

// SecureTransportRes represents the ASN.1 type SecureTransportRes (SEQUENCE).
type SecureTransportRes struct {
	SecurityHeader   SecurityHeader    `asn1:""`
	ProtectedPayload *ProtectedPayload `asn1:",optional" json:"ProtectedPayload,omitempty"`
}

// SecurityHeader represents the ASN.1 type SecurityHeader (SEQUENCE).
type SecurityHeader struct {
	SecurityParametersIndex     SecurityParametersIndex     `asn1:""`
	OriginalComponentIdentifier OriginalComponentIdentifier `asn1:""`
	InitialisationVector        *InitialisationVector       `asn1:",optional" json:"InitialisationVector,omitempty"`
	ExtCount_                   int64                       `asn1:"-" json:"-"`
	ExtPresent_                 []bool                      `asn1:"-" json:"-"`
	ExtData_                    [][]byte                    `asn1:"-" json:"-"`
}

// ProtectedPayload represents the ASN.1 type ProtectedPayload (OCTET_STRING).
type ProtectedPayload = []byte

// SecurityParametersIndex represents the ASN.1 type SecurityParametersIndex (OCTET_STRING).
type SecurityParametersIndex = []byte

// InitialisationVector represents the ASN.1 type InitialisationVector (OCTET_STRING).
type InitialisationVector = []byte

// OriginalComponentIdentifier choice constants.
const (
	OriginalComponentIdentifierChoiceOperationCode = 1
	OriginalComponentIdentifierChoiceErrorCode     = 2
	OriginalComponentIdentifierChoiceUserInfo      = 3
)

// OriginalComponentIdentifier represents the ASN.1 CHOICE type OriginalComponentIdentifier.
type OriginalComponentIdentifier struct {
	Choice        int
	OperationCode *OperationCode `json:"OperationCode,omitempty"`
	ErrorCode     *ErrorCode     `json:"ErrorCode,omitempty"`
	UserInfo      *struct{}      `json:"UserInfo,omitempty"`
}

// NewOriginalComponentIdentifierOperationCode creates a OriginalComponentIdentifier with the operationCode alternative.
func NewOriginalComponentIdentifierOperationCode(v OperationCode) OriginalComponentIdentifier {
	return OriginalComponentIdentifier{
		Choice:        OriginalComponentIdentifierChoiceOperationCode,
		OperationCode: &v,
	}
}

// NewOriginalComponentIdentifierErrorCode creates a OriginalComponentIdentifier with the errorCode alternative.
func NewOriginalComponentIdentifierErrorCode(v ErrorCode) OriginalComponentIdentifier {
	return OriginalComponentIdentifier{
		Choice:    OriginalComponentIdentifierChoiceErrorCode,
		ErrorCode: &v,
	}
}

// NewOriginalComponentIdentifierUserInfo creates a OriginalComponentIdentifier with the userInfo alternative.
func NewOriginalComponentIdentifierUserInfo(v struct{}) OriginalComponentIdentifier {
	return OriginalComponentIdentifier{
		Choice:   OriginalComponentIdentifierChoiceUserInfo,
		UserInfo: &v,
	}
}

// OperationCode choice constants.
const (
	OperationCodeChoiceLocalValue  = 1
	OperationCodeChoiceGlobalValue = 2
)

// OperationCode represents the ASN.1 CHOICE type OperationCode.
type OperationCode struct {
	Choice      int
	LocalValue  *big.Int                 `json:"LocalValue,omitempty"`
	GlobalValue runtime.ObjectIdentifier `json:"GlobalValue,omitempty"`
}

// NewOperationCodeLocalValue creates a OperationCode with the localValue alternative.
func NewOperationCodeLocalValue(v *big.Int) OperationCode {
	return OperationCode{
		Choice:     OperationCodeChoiceLocalValue,
		LocalValue: v,
	}
}

// NewOperationCodeGlobalValue creates a OperationCode with the globalValue alternative.
func NewOperationCodeGlobalValue(v runtime.ObjectIdentifier) OperationCode {
	return OperationCode{
		Choice:      OperationCodeChoiceGlobalValue,
		GlobalValue: v,
	}
}

// NewOperationCodeLocalValueInt64 creates a OperationCode localValue alternative from an int64 code.
func NewOperationCodeLocalValueInt64(v int64) OperationCode {
	return NewOperationCodeLocalValue(big.NewInt(v))
}

// LocalCode returns the localValue code when this OperationCode carries a localValue alternative.
func (v OperationCode) LocalCode() (int64, bool) {
	if v.Choice != OperationCodeChoiceLocalValue || v.LocalValue == nil || !v.LocalValue.IsInt64() {
		return 0, false
	}
	return v.LocalValue.Int64(), true
}

// ErrorCode choice constants.
const (
	ErrorCodeChoiceLocalValue  = 1
	ErrorCodeChoiceGlobalValue = 2
)

// ErrorCode represents the ASN.1 CHOICE type ErrorCode.
type ErrorCode struct {
	Choice      int
	LocalValue  *big.Int                 `json:"LocalValue,omitempty"`
	GlobalValue runtime.ObjectIdentifier `json:"GlobalValue,omitempty"`
}

// NewErrorCodeLocalValue creates a ErrorCode with the localValue alternative.
func NewErrorCodeLocalValue(v *big.Int) ErrorCode {
	return ErrorCode{
		Choice:     ErrorCodeChoiceLocalValue,
		LocalValue: v,
	}
}

// NewErrorCodeGlobalValue creates a ErrorCode with the globalValue alternative.
func NewErrorCodeGlobalValue(v runtime.ObjectIdentifier) ErrorCode {
	return ErrorCode{
		Choice:      ErrorCodeChoiceGlobalValue,
		GlobalValue: v,
	}
}

// NewErrorCodeLocalValueInt64 creates a ErrorCode localValue alternative from an int64 code.
func NewErrorCodeLocalValueInt64(v int64) ErrorCode {
	return NewErrorCodeLocalValue(big.NewInt(v))
}

// LocalCode returns the localValue code when this ErrorCode carries a localValue alternative.
func (v ErrorCode) LocalCode() (int64, bool) {
	if v.Choice != ErrorCodeChoiceLocalValue || v.LocalValue == nil || !v.LocalValue.IsInt64() {
		return 0, false
	}
	return v.LocalValue.Int64(), true
}

// PlmnContainer represents the ASN.1 type PlmnContainer (SEQUENCE).
type PlmnContainer struct {
	Msisdn               *CommonDataTypesISDNAddressString `asn1:"tag:0,context,implicit,optional" json:"Msisdn,omitempty"`
	Category             *DumCategory                      `asn1:"tag:1,context,implicit,optional" json:"Category,omitempty"`
	BasicService         *CommonDataTypesBasicServiceCode  `asn1:",optional" json:"BasicService,omitempty"`
	OperatorSSCode       PlmnContainerOperatorSSCode       `asn1:"tag:4,context,implicit,optional" json:"OperatorSSCode,omitempty"`
	OperatorSSCodeIndef_ bool                              `asn1:"-" json:"-"`
	ExtCount_            int64                             `asn1:"-" json:"-"`
	ExtPresent_          []bool                            `asn1:"-" json:"-"`
	ExtData_             [][]byte                          `asn1:"-" json:"-"`
}

// DumCategory represents the ASN.1 type DumCategory (OCTET_STRING).
type DumCategory = []byte

// ForwardSMArg represents the ASN.1 type ForwardSMArg (SEQUENCE).
type ForwardSMArg struct {
	SmRPDA             SMRPDAold                 `asn1:""`
	SmRPOA             SMRPOAold                 `asn1:""`
	SmRPUI             CommonDataTypesSignalInfo `asn1:""`
	MoreMessagesToSend *struct{}                 `asn1:",optional" json:"MoreMessagesToSend,omitempty"`
	ExtCount_          int64                     `asn1:"-" json:"-"`
	ExtPresent_        []bool                    `asn1:"-" json:"-"`
	ExtData_           [][]byte                  `asn1:"-" json:"-"`
}

// SMRPDAold choice constants.
const (
	SMRPDAoldChoiceImsi                   = 1
	SMRPDAoldChoiceLmsi                   = 2
	SMRPDAoldChoiceServiceCentreAddressDA = 3
	SMRPDAoldChoiceNoSMRPDA               = 4
)

// SMRPDAold represents the ASN.1 CHOICE type SMRPDAold.
type SMRPDAold struct {
	Choice                 int
	Imsi                   *CommonDataTypesIMSI          `json:"Imsi,omitempty"`
	Lmsi                   *CommonDataTypesLMSI          `json:"Lmsi,omitempty"`
	ServiceCentreAddressDA *CommonDataTypesAddressString `json:"ServiceCentreAddressDA,omitempty"`
	NoSMRPDA               *struct{}                     `json:"NoSMRPDA,omitempty"`
}

// NewSMRPDAoldImsi creates a SMRPDAold with the imsi alternative.
func NewSMRPDAoldImsi(v CommonDataTypesIMSI) SMRPDAold {
	return SMRPDAold{
		Choice: SMRPDAoldChoiceImsi,
		Imsi:   &v,
	}
}

// NewSMRPDAoldLmsi creates a SMRPDAold with the lmsi alternative.
func NewSMRPDAoldLmsi(v CommonDataTypesLMSI) SMRPDAold {
	return SMRPDAold{
		Choice: SMRPDAoldChoiceLmsi,
		Lmsi:   &v,
	}
}

// NewSMRPDAoldServiceCentreAddressDA creates a SMRPDAold with the serviceCentreAddressDA alternative.
func NewSMRPDAoldServiceCentreAddressDA(v CommonDataTypesAddressString) SMRPDAold {
	return SMRPDAold{
		Choice:                 SMRPDAoldChoiceServiceCentreAddressDA,
		ServiceCentreAddressDA: &v,
	}
}

// NewSMRPDAoldNoSMRPDA creates a SMRPDAold with the noSM-RP-DA alternative.
func NewSMRPDAoldNoSMRPDA(v struct{}) SMRPDAold {
	return SMRPDAold{
		Choice:   SMRPDAoldChoiceNoSMRPDA,
		NoSMRPDA: &v,
	}
}

// SMRPOAold choice constants.
const (
	SMRPOAoldChoiceMsisdn                 = 1
	SMRPOAoldChoiceServiceCentreAddressOA = 2
	SMRPOAoldChoiceNoSMRPOA               = 3
)

// SMRPOAold represents the ASN.1 CHOICE type SMRPOAold.
type SMRPOAold struct {
	Choice                 int
	Msisdn                 *CommonDataTypesISDNAddressString `json:"Msisdn,omitempty"`
	ServiceCentreAddressOA *CommonDataTypesAddressString     `json:"ServiceCentreAddressOA,omitempty"`
	NoSMRPOA               *struct{}                         `json:"NoSMRPOA,omitempty"`
}

// NewSMRPOAoldMsisdn creates a SMRPOAold with the msisdn alternative.
func NewSMRPOAoldMsisdn(v CommonDataTypesISDNAddressString) SMRPOAold {
	return SMRPOAold{
		Choice: SMRPOAoldChoiceMsisdn,
		Msisdn: &v,
	}
}

// NewSMRPOAoldServiceCentreAddressOA creates a SMRPOAold with the serviceCentreAddressOA alternative.
func NewSMRPOAoldServiceCentreAddressOA(v CommonDataTypesAddressString) SMRPOAold {
	return SMRPOAold{
		Choice:                 SMRPOAoldChoiceServiceCentreAddressOA,
		ServiceCentreAddressOA: &v,
	}
}

// NewSMRPOAoldNoSMRPOA creates a SMRPOAold with the noSM-RP-OA alternative.
func NewSMRPOAoldNoSMRPOA(v struct{}) SMRPOAold {
	return SMRPOAold{
		Choice:   SMRPOAoldChoiceNoSMRPOA,
		NoSMRPOA: &v,
	}
}

// SendRoutingInfoArgV2 represents the ASN.1 type SendRoutingInfoArgV2 (SEQUENCE).
type SendRoutingInfoArgV2 struct {
	Msisdn             CommonDataTypesISDNAddressString   `asn1:"tag:0,context,implicit"`
	CugCheckInfo       *CHCUGCheckInfo                    `asn1:"tag:1,context,implicit,optional" json:"CugCheckInfo,omitempty"`
	NumberOfForwarding *CHNumberOfForwarding              `asn1:"tag:2,context,implicit,optional" json:"NumberOfForwarding,omitempty"`
	NetworkSignalInfo  *CommonDataTypesExternalSignalInfo `asn1:"tag:10,context,implicit,optional" json:"NetworkSignalInfo,omitempty"`
	ExtCount_          int64                              `asn1:"-" json:"-"`
	ExtPresent_        []bool                             `asn1:"-" json:"-"`
	ExtData_           [][]byte                           `asn1:"-" json:"-"`
}

// SendRoutingInfoResV2 represents the ASN.1 type SendRoutingInfoResV2 (SEQUENCE).
type SendRoutingInfoResV2 struct {
	Imsi         CommonDataTypesIMSI `asn1:""`
	RoutingInfo  CHRoutingInfo       `asn1:""`
	CugCheckInfo *CHCUGCheckInfo     `asn1:",optional" json:"CugCheckInfo,omitempty"`
	ExtCount_    int64               `asn1:"-" json:"-"`
	ExtPresent_  []bool              `asn1:"-" json:"-"`
	ExtData_     [][]byte            `asn1:"-" json:"-"`
}

// BeginSubscriberActivityArg represents the ASN.1 type BeginSubscriberActivityArg (SEQUENCE).
type BeginSubscriberActivityArg struct {
	Imsi                    CommonDataTypesIMSI              `asn1:""`
	OriginatingEntityNumber CommonDataTypesISDNAddressString `asn1:""`
	Msisdn                  *CommonDataTypesAddressString    `asn1:"tag:28,private,implicit,optional" json:"Msisdn,omitempty"`
	ExtCount_               int64                            `asn1:"-" json:"-"`
	ExtPresent_             []bool                           `asn1:"-" json:"-"`
	ExtData_                [][]byte                         `asn1:"-" json:"-"`
}

// RoutingInfoForSMArgV1 represents the ASN.1 type RoutingInfoForSMArgV1 (SEQUENCE).
type RoutingInfoForSMArgV1 struct {
	Msisdn               CommonDataTypesISDNAddressString `asn1:"tag:0,context,implicit"`
	SmRPPRI              bool                             `asn1:"tag:1,context,implicit"`
	SmRPPRIRaw_          byte                             `asn1:"-" json:"-"`
	ServiceCentreAddress CommonDataTypesAddressString     `asn1:"tag:2,context,implicit"`
	CugInterlock         *CUGInterlock3                   `asn1:"tag:3,context,implicit,optional" json:"CugInterlock,omitempty"`
	TeleserviceCode      *TSTeleserviceCode               `asn1:"tag:5,context,implicit,optional" json:"TeleserviceCode,omitempty"`
	Imsi                 *CommonDataTypesIMSI             `asn1:"tag:12,context,implicit,optional" json:"Imsi,omitempty"`
	ExtCount_            int64                            `asn1:"-" json:"-"`
	ExtPresent_          []bool                           `asn1:"-" json:"-"`
	ExtData_             [][]byte                         `asn1:"-" json:"-"`
}

// RoutingInfoForSMResV2 represents the ASN.1 type RoutingInfoForSMResV2 (SEQUENCE).
type RoutingInfoForSMResV2 struct {
	Imsi                 CommonDataTypesIMSI    `asn1:""`
	LocationInfoWithLMSI LocationInfoWithLMSIv2 `asn1:"tag:0,context,implicit"`
	MwdSet               *bool                  `asn1:"tag:2,context,implicit,optional" json:"MwdSet,omitempty"`
	MwdSetRaw_           byte                   `asn1:"-" json:"-"`
	ExtCount_            int64                  `asn1:"-" json:"-"`
	ExtPresent_          []bool                 `asn1:"-" json:"-"`
	ExtData_             [][]byte               `asn1:"-" json:"-"`
}

// LocationInfoWithLMSIv2 represents the ASN.1 type LocationInfoWithLMSIv2 (SEQUENCE).
type LocationInfoWithLMSIv2 struct {
	LocationInfo LocationInfo         `asn1:""`
	Lmsi         *CommonDataTypesLMSI `asn1:",optional" json:"Lmsi,omitempty"`
	ExtCount_    int64                `asn1:"-" json:"-"`
	ExtPresent_  []bool               `asn1:"-" json:"-"`
	ExtData_     [][]byte             `asn1:"-" json:"-"`
}

// LocationInfo choice constants.
const (
	LocationInfoChoiceRoamingNumber = 1
	LocationInfoChoiceMscNumber     = 2
)

// LocationInfo represents the ASN.1 CHOICE type LocationInfo.
type LocationInfo struct {
	Choice        int
	RoamingNumber *CommonDataTypesISDNAddressString `json:"RoamingNumber,omitempty"`
	MscNumber     *CommonDataTypesISDNAddressString `json:"MscNumber,omitempty"`
}

// NewLocationInfoRoamingNumber creates a LocationInfo with the roamingNumber alternative.
func NewLocationInfoRoamingNumber(v CommonDataTypesISDNAddressString) LocationInfo {
	return LocationInfo{
		Choice:        LocationInfoChoiceRoamingNumber,
		RoamingNumber: &v,
	}
}

// NewLocationInfoMscNumber creates a LocationInfo with the msc-Number alternative.
func NewLocationInfoMscNumber(v CommonDataTypesISDNAddressString) LocationInfo {
	return LocationInfo{
		Choice:    LocationInfoChoiceMscNumber,
		MscNumber: &v,
	}
}

// Ki represents the ASN.1 type Ki (OCTET_STRING).
type Ki = []byte

// SendParametersArg represents the ASN.1 type SendParametersArg (SEQUENCE).
type SendParametersArg struct {
	SubscriberId               CommonDataTypesSubscriberId `asn1:""`
	RequestParameterList       RequestParameterList        `asn1:""`
	RequestParameterListIndef_ bool                        `asn1:"-" json:"-"`
}

// RequestParameter represents the ASN.1 ENUMERATED type RequestParameter.
type RequestParameter int64

const (
	RequestParameterRequestIMSI              RequestParameter = 0
	RequestParameterRequestAuthenticationSet RequestParameter = 1
	RequestParameterRequestSubscriberData    RequestParameter = 2
	RequestParameterRequestKi                RequestParameter = 4
)

func (v RequestParameter) String() string {
	switch v {
	case RequestParameterRequestIMSI:
		return "requestIMSI"
	case RequestParameterRequestAuthenticationSet:
		return "requestAuthenticationSet"
	case RequestParameterRequestSubscriberData:
		return "requestSubscriberData"
	case RequestParameterRequestKi:
		return "requestKi"
	default:
		return "unknown"
	}
}

// RequestParameterList represents the ASN.1 type RequestParameterList (SEQUENCE_OF).
type RequestParameterList = []RequestParameter

// SentParameter choice constants.
const (
	SentParameterChoiceImsi              = 1
	SentParameterChoiceAuthenticationSet = 2
	SentParameterChoiceSubscriberData    = 3
	SentParameterChoiceKi                = 4
)

// SentParameter represents the ASN.1 CHOICE type SentParameter.
type SentParameter struct {
	Choice            int
	Imsi              *CommonDataTypesIMSI      `json:"Imsi,omitempty"`
	AuthenticationSet *AuthenticationSetListOld `json:"AuthenticationSet,omitempty"`
	SubscriberData    *SubscriberData3          `json:"SubscriberData,omitempty"`
	Ki                *Ki                       `json:"Ki,omitempty"`
}

// NewSentParameterImsi creates a SentParameter with the imsi alternative.
func NewSentParameterImsi(v CommonDataTypesIMSI) SentParameter {
	return SentParameter{
		Choice: SentParameterChoiceImsi,
		Imsi:   &v,
	}
}

// NewSentParameterAuthenticationSet creates a SentParameter with the authenticationSet alternative.
func NewSentParameterAuthenticationSet(v AuthenticationSetListOld) SentParameter {
	return SentParameter{
		Choice:            SentParameterChoiceAuthenticationSet,
		AuthenticationSet: &v,
	}
}

// NewSentParameterSubscriberData creates a SentParameter with the subscriberData alternative.
func NewSentParameterSubscriberData(v SubscriberData3) SentParameter {
	return SentParameter{
		Choice:         SentParameterChoiceSubscriberData,
		SubscriberData: &v,
	}
}

// NewSentParameterKi creates a SentParameter with the ki alternative.
func NewSentParameterKi(v Ki) SentParameter {
	return SentParameter{
		Choice: SentParameterChoiceKi,
		Ki:     &v,
	}
}

// AuthenticationSetListOld choice constants.
const (
	AuthenticationSetListOldChoiceTripletList    = 1
	AuthenticationSetListOldChoiceQuintupletList = 2
)

// AuthenticationSetListOld represents the ASN.1 CHOICE type AuthenticationSetListOld.
type AuthenticationSetListOld struct {
	Choice         int
	TripletList    TripletList3    `json:"TripletList,omitempty"`
	QuintupletList QuintupletList3 `json:"QuintupletList,omitempty"`
}

// NewAuthenticationSetListOldTripletList creates a AuthenticationSetListOld with the tripletList alternative.
func NewAuthenticationSetListOldTripletList(v TripletList3) AuthenticationSetListOld {
	return AuthenticationSetListOld{
		Choice:      AuthenticationSetListOldChoiceTripletList,
		TripletList: v,
	}
}

// NewAuthenticationSetListOldQuintupletList creates a AuthenticationSetListOld with the quintupletList alternative.
func NewAuthenticationSetListOldQuintupletList(v QuintupletList3) AuthenticationSetListOld {
	return AuthenticationSetListOld{
		Choice:         AuthenticationSetListOldChoiceQuintupletList,
		QuintupletList: v,
	}
}

// SentParameterList represents the ASN.1 type SentParameterList (SEQUENCE_OF).
type SentParameterList = []SentParameter

// ResetArgV2 represents the ASN.1 type ResetArgV2 (SEQUENCE).
type ResetArgV2 struct {
	NetworkResource *CommonDataTypesNetworkResource  `asn1:",optional" json:"NetworkResource,omitempty"`
	HlrNumber       CommonDataTypesISDNAddressString `asn1:""`
	HlrList         CommonDataTypesHLRList           `asn1:",optional" json:"HlrList,omitempty"`
	HlrListIndef_   bool                             `asn1:"-" json:"-"`
	ExtCount_       int64                            `asn1:"-" json:"-"`
	ExtPresent_     []bool                           `asn1:"-" json:"-"`
	ExtData_        [][]byte                         `asn1:"-" json:"-"`
}

// ReturnResultResultretres represents the ASN.1 type ReturnResultResultretres (SEQUENCE).
type ReturnResultResultretres struct {
	OpCode          MAPOPERATION      `asn1:""`
	Returnparameter *runtime.RawValue `asn1:",optional" json:"Returnparameter,omitempty" asn1c:"raw-preserve"`
}

// RejectInvokeIDRej choice constants.
const (
	RejectInvokeIDRejChoiceDerivable    = 1
	RejectInvokeIDRejChoiceNotDerivable = 2
)

// RejectInvokeIDRej represents the ASN.1 CHOICE type RejectInvokeIDRej.
type RejectInvokeIDRej struct {
	Choice       int
	Derivable    *InvokeIdType `json:"Derivable,omitempty"`
	NotDerivable *struct{}     `json:"NotDerivable,omitempty"`
}

// NewRejectInvokeIDRejDerivable creates a RejectInvokeIDRej with the derivable alternative.
func NewRejectInvokeIDRejDerivable(v InvokeIdType) RejectInvokeIDRej {
	return RejectInvokeIDRej{
		Choice:    RejectInvokeIDRejChoiceDerivable,
		Derivable: &v,
	}
}

// NewRejectInvokeIDRejNotDerivable creates a RejectInvokeIDRej with the not-derivable alternative.
func NewRejectInvokeIDRejNotDerivable(v struct{}) RejectInvokeIDRej {
	return RejectInvokeIDRej{
		Choice:       RejectInvokeIDRejChoiceNotDerivable,
		NotDerivable: &v,
	}
}

// DumRejectProblem choice constants.
const (
	DumRejectProblemChoiceGeneralProblem      = 1
	DumRejectProblemChoiceInvokeProblem       = 2
	DumRejectProblemChoiceReturnResultProblem = 3
	DumRejectProblemChoiceReturnErrorProblem  = 4
)

// DumRejectProblem represents the ASN.1 CHOICE type DumRejectProblem.
type DumRejectProblem struct {
	Choice              int
	GeneralProblem      *DumGeneralProblem      `json:"GeneralProblem,omitempty"`
	InvokeProblem       *DumInvokeProblem       `json:"InvokeProblem,omitempty"`
	ReturnResultProblem *DumReturnResultProblem `json:"ReturnResultProblem,omitempty"`
	ReturnErrorProblem  *DumReturnErrorProblem  `json:"ReturnErrorProblem,omitempty"`
}

// NewDumRejectProblemGeneralProblem creates a DumRejectProblem with the generalProblem alternative.
func NewDumRejectProblemGeneralProblem(v DumGeneralProblem) DumRejectProblem {
	return DumRejectProblem{
		Choice:         DumRejectProblemChoiceGeneralProblem,
		GeneralProblem: &v,
	}
}

// NewDumRejectProblemInvokeProblem creates a DumRejectProblem with the invokeProblem alternative.
func NewDumRejectProblemInvokeProblem(v DumInvokeProblem) DumRejectProblem {
	return DumRejectProblem{
		Choice:        DumRejectProblemChoiceInvokeProblem,
		InvokeProblem: &v,
	}
}

// NewDumRejectProblemReturnResultProblem creates a DumRejectProblem with the returnResultProblem alternative.
func NewDumRejectProblemReturnResultProblem(v DumReturnResultProblem) DumRejectProblem {
	return DumRejectProblem{
		Choice:              DumRejectProblemChoiceReturnResultProblem,
		ReturnResultProblem: &v,
	}
}

// NewDumRejectProblemReturnErrorProblem creates a DumRejectProblem with the returnErrorProblem alternative.
func NewDumRejectProblemReturnErrorProblem(v DumReturnErrorProblem) DumRejectProblem {
	return DumRejectProblem{
		Choice:             DumRejectProblemChoiceReturnErrorProblem,
		ReturnErrorProblem: &v,
	}
}

// DumSendAuthenticationInfoResOldElem represents the ASN.1 type DumSendAuthenticationInfoResOldElem (SEQUENCE).
type DumSendAuthenticationInfoResOldElem struct {
	Rand        DumRAND  `asn1:""`
	Sres        DumSRES  `asn1:""`
	Kc          DumKc    `asn1:""`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// PlmnContainerOperatorSSCode represents the ASN.1 type PlmnContainerOperatorSSCode (SEQUENCE_OF).
type PlmnContainerOperatorSSCode = [][]byte

// MarshalBER encodes Component to BER format.
func (v *Component) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ComponentChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice Component: invoke is nil")
		}
		enc_0, err := v.Invoke.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_0)
		return enc_0, nil
	case ComponentChoiceReturnResultLast:
		if v.ReturnResultLast == nil {
			return nil, fmt.Errorf("choice Component: returnResultLast is nil")
		}
		enc_1, err := v.ReturnResultLast.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultLast: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_1)
		return enc_1, nil
	case ComponentChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice Component: returnError is nil")
		}
		enc_2, err := v.ReturnError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	case ComponentChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice Component: reject is nil")
		}
		enc_3, err := v.Reject.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_3)
		return enc_3, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("choice Component: returnResultNotLast is nil")
		}
		enc_4, err := v.ReturnResultNotLast.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", err)
		}
		enc_4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_4)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Component", v.Choice)
	}
}

// MarshalDER encodes Component to DER format.
func (v *Component) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ComponentChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice Component: invoke is nil")
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_0)
		return enc_der_0, nil
	case ComponentChoiceReturnResultLast:
		if v.ReturnResultLast == nil {
			return nil, fmt.Errorf("choice Component: returnResultLast is nil")
		}
		enc_der_1, err := v.ReturnResultLast.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultLast: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_der_1)
		return enc_der_1, nil
	case ComponentChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice Component: returnError is nil")
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_der_2)
		return enc_der_2, nil
	case ComponentChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice Component: reject is nil")
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_der_3)
		return enc_der_3, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("choice Component: returnResultNotLast is nil")
		}
		enc_der_4, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", err)
		}
		enc_der_4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_der_4)
		return enc_der_4, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes Component from BER/DER format.
func (v *Component) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Component CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Component: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Component CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Component", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = ComponentChoiceInvoke
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding invoke: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec DumInvoke
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding invoke: %w", unmErr)
		}
		v.Invoke = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ComponentChoiceReturnResultLast
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResultLast: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec DumReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnResultLast: %w", unmErr)
		}
		v.ReturnResultLast = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = ComponentChoiceReturnError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec DumReturnError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnError: %w", unmErr)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = ComponentChoiceReject
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding reject: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec DumReject
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding reject: %w", unmErr)
		}
		v.Reject = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
		v.Choice = ComponentChoiceReturnResultNotLast
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResultNotLast: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec DumReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnResultNotLast: %w", unmErr)
		}
		v.ReturnResultNotLast = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Component CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes DumInvoke to BER format.
func (v *DumInvoke) MarshalBER() ([]byte, error) {
	var children []byte
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	if v.LinkedID != nil {
		enc_linkedid := ber.EncodeInteger(int64(*v.LinkedID))
		enc_linkedid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_linkedid)
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.OpCode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding opCode: %w", err)
	}
	children = append(children, enc_opcode...)
	if v.Invokeparameter != nil {
		enc_invokeparameter := v.Invokeparameter.Bytes
		children = append(children, enc_invokeparameter...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DumInvoke to DER format.
func (v *DumInvoke) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DumInvoke from BER/DER format.
func (v *DumInvoke) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DumInvoke SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DumInvoke", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeID
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeID")
	}
	val_invokeid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding invokeID: %w", err)
	}
	v.InvokeID = InvokeIdType(val_invokeid)
	offset += n
	// Decode linkedID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_linkedid, rawVal_linkedid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding linkedID: %w", err)
				}
				decVal_linkedid, intErr := ber.DecodeIntegerValue(rawVal_linkedid)
				if intErr != nil {
					return fmt.Errorf("decoding linkedID: %w", intErr)
				}
				tmp_linkedid := InvokeIdType(decVal_linkedid)
				v.LinkedID = &tmp_linkedid
				offset += n_linkedid
			}
		}
	}
	// Decode opCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opCode")
	}
	// Decode nested CHOICE (MAPOPERATION)
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:])
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opCode: %w", tlvErr_opcode)
	}
	if unmErr := v.OpCode.UnmarshalBER(content[offset : offset+n_opcode]); unmErr != nil {
		return fmt.Errorf("decoding opCode: %w", unmErr)
	}
	offset += n_opcode
	// Decode invokeparameter
	if offset < len(content) {
		_, n_invokeparameter, _, tlvErr_invokeparameter := ber.DecodeTLV(content[offset:])
		if tlvErr_invokeparameter != nil {
			return fmt.Errorf("decoding invokeparameter: %w", tlvErr_invokeparameter)
		}
		tmp_invokeparameter := runtime.RawValue{Bytes: content[offset : offset+n_invokeparameter]}
		v.Invokeparameter = &tmp_invokeparameter
		offset += n_invokeparameter
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DumInvoke", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes DumReturnResult to BER format.
func (v *DumReturnResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	if v.Resultretres != nil {
		enc_resultretres, err := v.Resultretres.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding resultretres: %w", err)
		}
		children = append(children, enc_resultretres...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DumReturnResult to DER format.
func (v *DumReturnResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DumReturnResult from BER/DER format.
func (v *DumReturnResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DumReturnResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DumReturnResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeID
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeID")
	}
	val_invokeid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding invokeID: %w", err)
	}
	v.InvokeID = InvokeIdType(val_invokeid)
	offset += n
	// Decode resultretres
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ReturnResultResultretres)
				_, n_resultretres, _, tlvErr_resultretres := ber.DecodeTLV(content[offset:])
				if tlvErr_resultretres != nil {
					return fmt.Errorf("decoding resultretres: %w", tlvErr_resultretres)
				}
				var dec_resultretres ReturnResultResultretres
				if unmErr := dec_resultretres.UnmarshalBER(content[offset : offset+n_resultretres]); unmErr != nil {
					return fmt.Errorf("decoding resultretres: %w", unmErr)
				}
				v.Resultretres = &dec_resultretres
				offset += n_resultretres
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DumReturnResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes DumReturnError to BER format.
func (v *DumReturnError) MarshalBER() ([]byte, error) {
	var children []byte
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	enc_errorcode, err := v.ErrorCode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding errorCode: %w", err)
	}
	children = append(children, enc_errorcode...)
	if v.Parameter != nil {
		enc_parameter := v.Parameter.Bytes
		children = append(children, enc_parameter...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DumReturnError to DER format.
func (v *DumReturnError) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DumReturnError from BER/DER format.
func (v *DumReturnError) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DumReturnError SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DumReturnError", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeID
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeID")
	}
	val_invokeid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding invokeID: %w", err)
	}
	v.InvokeID = InvokeIdType(val_invokeid)
	offset += n
	// Decode errorCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field errorCode")
	}
	// Decode nested CHOICE (MAPERROR)
	_, n_errorcode, _, tlvErr_errorcode := ber.DecodeTLV(content[offset:])
	if tlvErr_errorcode != nil {
		return fmt.Errorf("decoding errorCode: %w", tlvErr_errorcode)
	}
	if unmErr := v.ErrorCode.UnmarshalBER(content[offset : offset+n_errorcode]); unmErr != nil {
		return fmt.Errorf("decoding errorCode: %w", unmErr)
	}
	offset += n_errorcode
	// Decode parameter
	if offset < len(content) {
		_, n_parameter, _, tlvErr_parameter := ber.DecodeTLV(content[offset:])
		if tlvErr_parameter != nil {
			return fmt.Errorf("decoding parameter: %w", tlvErr_parameter)
		}
		tmp_parameter := runtime.RawValue{Bytes: content[offset : offset+n_parameter]}
		v.Parameter = &tmp_parameter
		offset += n_parameter
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DumReturnError", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes DumReject to BER format.
func (v *DumReject) MarshalBER() ([]byte, error) {
	var children []byte
	enc_invokeidrej, err := v.InvokeIDRej.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding invokeIDRej: %w", err)
	}
	children = append(children, enc_invokeidrej...)
	enc_problem, err := v.Problem.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding problem: %w", err)
	}
	children = append(children, enc_problem...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DumReject to DER format.
func (v *DumReject) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DumReject from BER/DER format.
func (v *DumReject) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DumReject SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DumReject", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeIDRej
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeIDRej")
	}
	// Decode nested CHOICE (RejectInvokeIDRej)
	_, n_invokeidrej, _, tlvErr_invokeidrej := ber.DecodeTLV(content[offset:])
	if tlvErr_invokeidrej != nil {
		return fmt.Errorf("decoding invokeIDRej: %w", tlvErr_invokeidrej)
	}
	if unmErr := v.InvokeIDRej.UnmarshalBER(content[offset : offset+n_invokeidrej]); unmErr != nil {
		return fmt.Errorf("decoding invokeIDRej: %w", unmErr)
	}
	offset += n_invokeidrej
	// Decode problem
	if offset >= len(content) {
		return fmt.Errorf("missing required field problem")
	}
	// Decode nested CHOICE (DumRejectProblem)
	_, n_problem, _, tlvErr_problem := ber.DecodeTLV(content[offset:])
	if tlvErr_problem != nil {
		return fmt.Errorf("decoding problem: %w", tlvErr_problem)
	}
	if unmErr := v.Problem.UnmarshalBER(content[offset : offset+n_problem]); unmErr != nil {
		return fmt.Errorf("decoding problem: %w", unmErr)
	}
	offset += n_problem
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DumReject", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes MAPOPERATION to BER format.
func (v *MAPOPERATION) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case MAPOPERATIONChoiceLocalValue:
		if v.LocalValue == nil {
			return nil, fmt.Errorf("choice MAPOPERATION: localValue is nil")
		}
		enc_0 := ber.EncodeBigInt(v.LocalValue.BigInt())
		return enc_0, nil
	case MAPOPERATIONChoiceGlobalValue:
		enc_1 := ber.EncodeObjectIdentifier([]uint64(v.GlobalValue))
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for MAPOPERATION", v.Choice)
	}
}

// MarshalDER encodes MAPOPERATION to DER format.
func (v *MAPOPERATION) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes MAPOPERATION from BER/DER format.
func (v *MAPOPERATION) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for MAPOPERATION CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for MAPOPERATION: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding MAPOPERATION CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPOPERATION", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = MAPOPERATIONChoiceLocalValue
		decVal, _, intErr := ber.DecodeBigInt(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		var named_localvalue OperationLocalvalue
		if namedErr := named_localvalue.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding localValue: %w", namedErr)
		}
		v.LocalValue = &named_localvalue
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 {
		v.Choice = MAPOPERATIONChoiceGlobalValue
		decVal, _, oidErr := ber.DecodeObjectIdentifier(choiceData)
		if oidErr != nil {
			return fmt.Errorf("decoding globalValue: %w", oidErr)
		}
		tmp := runtime.ObjectIdentifier(decVal)
		v.GlobalValue = tmp
	} else {
		return fmt.Errorf("unknown tag %s for MAPOPERATION CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes MAPERROR to BER format.
func (v *MAPERROR) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case MAPERRORChoiceLocalValue:
		if v.LocalValue == nil {
			return nil, fmt.Errorf("choice MAPERROR: localValue is nil")
		}
		enc_0 := ber.EncodeBigInt(v.LocalValue.BigInt())
		return enc_0, nil
	case MAPERRORChoiceGlobalValue:
		enc_1 := ber.EncodeObjectIdentifier([]uint64(v.GlobalValue))
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for MAPERROR", v.Choice)
	}
}

// MarshalDER encodes MAPERROR to DER format.
func (v *MAPERROR) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes MAPERROR from BER/DER format.
func (v *MAPERROR) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for MAPERROR CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for MAPERROR: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding MAPERROR CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPERROR", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = MAPERRORChoiceLocalValue
		decVal, _, intErr := ber.DecodeBigInt(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		var named_localvalue LocalErrorcode
		if namedErr := named_localvalue.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding localValue: %w", namedErr)
		}
		v.LocalValue = &named_localvalue
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 {
		v.Choice = MAPERRORChoiceGlobalValue
		decVal, _, oidErr := ber.DecodeObjectIdentifier(choiceData)
		if oidErr != nil {
			return fmt.Errorf("decoding globalValue: %w", oidErr)
		}
		tmp := runtime.ObjectIdentifier(decVal)
		v.GlobalValue = tmp
	} else {
		return fmt.Errorf("unknown tag %s for MAPERROR CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes BssAPDU to BER format.
func (v *BssAPDU) MarshalBER() ([]byte, error) {
	var children []byte
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes BssAPDU to DER format.
func (v *BssAPDU) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes BssAPDU from BER/DER format.
func (v *BssAPDU) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding BssAPDU SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BssAPDU", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field protocolId")
	}
	val_protocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding protocolId: %w", err)
	}
	v.ProtocolId = CommonDataTypesProtocolId(val_protocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = CommonDataTypesSignalInfo(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "BssAPDU", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProvideSIWFSNumberArg to BER format.
func (v *ProvideSIWFSNumberArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", err)
	}
	enc_gsmbearercapability = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_gsmbearercapability)
	children = append(children, enc_gsmbearercapability...)
	enc_isdnbearercapability, err := v.IsdnBearerCapability.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding isdn-BearerCapability: %w", err)
	}
	enc_isdnbearercapability = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_isdnbearercapability)
	children = append(children, enc_isdnbearercapability...)
	enc_calldirection := ber.EncodeOctetString([]byte(v.CallDirection))
	enc_calldirection = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_calldirection)
	children = append(children, enc_calldirection...)
	enc_bsubscriberaddress := ber.EncodeOctetString([]byte(v.BSubscriberAddress))
	enc_bsubscriberaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_bsubscriberaddress)
	children = append(children, enc_bsubscriberaddress...)
	enc_chosenchannel, err := v.ChosenChannel.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding chosenChannel: %w", err)
	}
	enc_chosenchannel = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_chosenchannel)
	children = append(children, enc_chosenchannel...)
	if v.LowerLayerCompatibility != nil {
		enc_lowerlayercompatibility, err := v.LowerLayerCompatibility.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding lowerLayerCompatibility: %w", err)
		}
		enc_lowerlayercompatibility = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_lowerlayercompatibility)
		children = append(children, enc_lowerlayercompatibility...)
	}
	if v.HighLayerCompatibility != nil {
		enc_highlayercompatibility, err := v.HighLayerCompatibility.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding highLayerCompatibility: %w", err)
		}
		enc_highlayercompatibility = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_highlayercompatibility)
		children = append(children, enc_highlayercompatibility...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ProvideSIWFSNumberArg to DER format.
func (v *ProvideSIWFSNumberArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProvideSIWFSNumberArg from BER/DER format.
func (v *ProvideSIWFSNumberArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProvideSIWFSNumberArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideSIWFSNumberArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode gsm-BearerCapability
	if offset >= len(content) {
		return fmt.Errorf("missing required field gsm-BearerCapability")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for gsm-BearerCapability, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_gsmbearercapability, rawVal_gsmbearercapability, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding gsm-BearerCapability: %w", err)
	}
	reconstructed_gsmbearercapability := ber.EncodeSequence(rawVal_gsmbearercapability)
	if unmErr := v.GsmBearerCapability.UnmarshalBER(reconstructed_gsmbearercapability); unmErr != nil {
		return fmt.Errorf("decoding gsm-BearerCapability: %w", unmErr)
	}
	offset += n_gsmbearercapability
	// Decode isdn-BearerCapability
	if offset >= len(content) {
		return fmt.Errorf("missing required field isdn-BearerCapability")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for isdn-BearerCapability, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_isdnbearercapability, rawVal_isdnbearercapability, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding isdn-BearerCapability: %w", err)
	}
	reconstructed_isdnbearercapability := ber.EncodeSequence(rawVal_isdnbearercapability)
	if unmErr := v.IsdnBearerCapability.UnmarshalBER(reconstructed_isdnbearercapability); unmErr != nil {
		return fmt.Errorf("decoding isdn-BearerCapability: %w", unmErr)
	}
	offset += n_isdnbearercapability
	// Decode call-Direction
	if offset >= len(content) {
		return fmt.Errorf("missing required field call-Direction")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for call-Direction, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_calldirection, rawVal_calldirection, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding call-Direction: %w", err)
	}
	v.CallDirection = CallDirection(rawVal_calldirection)
	offset += n_calldirection
	// Decode b-Subscriber-Address
	if offset >= len(content) {
		return fmt.Errorf("missing required field b-Subscriber-Address")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for b-Subscriber-Address, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_bsubscriberaddress, rawVal_bsubscriberaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding b-Subscriber-Address: %w", err)
	}
	v.BSubscriberAddress = CommonDataTypesISDNAddressString(rawVal_bsubscriberaddress)
	offset += n_bsubscriberaddress
	// Decode chosenChannel
	if offset >= len(content) {
		return fmt.Errorf("missing required field chosenChannel")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for chosenChannel, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	_, n_chosenchannel, rawVal_chosenchannel, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding chosenChannel: %w", err)
	}
	reconstructed_chosenchannel := ber.EncodeSequence(rawVal_chosenchannel)
	if unmErr := v.ChosenChannel.UnmarshalBER(reconstructed_chosenchannel); unmErr != nil {
		return fmt.Errorf("decoding chosenChannel: %w", unmErr)
	}
	offset += n_chosenchannel
	// Decode lowerLayerCompatibility
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_lowerlayercompatibility, rawVal_lowerlayercompatibility, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lowerLayerCompatibility: %w", err)
				}
				reconstructed_lowerlayercompatibility := ber.EncodeSequence(rawVal_lowerlayercompatibility)
				var dec_lowerlayercompatibility CommonDataTypesExternalSignalInfo
				if unmErr := dec_lowerlayercompatibility.UnmarshalBER(reconstructed_lowerlayercompatibility); unmErr != nil {
					return fmt.Errorf("decoding lowerLayerCompatibility: %w", unmErr)
				}
				v.LowerLayerCompatibility = &dec_lowerlayercompatibility
				offset += n_lowerlayercompatibility
			}
		}
	}
	// Decode highLayerCompatibility
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_highlayercompatibility, rawVal_highlayercompatibility, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding highLayerCompatibility: %w", err)
				}
				reconstructed_highlayercompatibility := ber.EncodeSequence(rawVal_highlayercompatibility)
				var dec_highlayercompatibility CommonDataTypesExternalSignalInfo
				if unmErr := dec_highlayercompatibility.UnmarshalBER(reconstructed_highlayercompatibility); unmErr != nil {
					return fmt.Errorf("decoding highLayerCompatibility: %w", unmErr)
				}
				v.HighLayerCompatibility = &dec_highlayercompatibility
				offset += n_highlayercompatibility
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProvideSIWFSNumberArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProvideSIWFSNumberRes to BER format.
func (v *ProvideSIWFSNumberRes) MarshalBER() ([]byte, error) {
	var children []byte
	enc_siwfsnumber := ber.EncodeOctetString([]byte(v.SIWFSNumber))
	enc_siwfsnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_siwfsnumber)
	children = append(children, enc_siwfsnumber...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ProvideSIWFSNumberRes to DER format.
func (v *ProvideSIWFSNumberRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProvideSIWFSNumberRes from BER/DER format.
func (v *ProvideSIWFSNumberRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProvideSIWFSNumberRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideSIWFSNumberRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sIWFSNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field sIWFSNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for sIWFSNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_siwfsnumber, rawVal_siwfsnumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sIWFSNumber: %w", err)
	}
	v.SIWFSNumber = CommonDataTypesISDNAddressString(rawVal_siwfsnumber)
	offset += n_siwfsnumber
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProvideSIWFSNumberRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DumPurgeMSArgV2 to BER format.
func (v *DumPurgeMSArgV2) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	children = append(children, enc_imsi...)
	if v.VlrNumber != nil {
		enc_vlrnumber := ber.EncodeOctetString([]byte(*v.VlrNumber))
		children = append(children, enc_vlrnumber...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DumPurgeMSArgV2 to DER format.
func (v *DumPurgeMSArgV2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DumPurgeMSArgV2 from BER/DER format.
func (v *DumPurgeMSArgV2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DumPurgeMSArgV2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DumPurgeMSArgV2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	val_imsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(val_imsi)
	offset += n
	// Decode vlr-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_vlrnumber, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding vlr-Number: %w", err)
				}
				tmp_vlrnumber := CommonDataTypesISDNAddressString(val_vlrnumber)
				v.VlrNumber = &tmp_vlrnumber
				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DumPurgeMSArgV2", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PrepareHOArgOld to BER format.
func (v *PrepareHOArgOld) MarshalBER() ([]byte, error) {
	var children []byte
	if v.TargetCellId != nil {
		enc_targetcellid := ber.EncodeOctetString([]byte(*v.TargetCellId))
		children = append(children, enc_targetcellid...)
	}
	if v.HoNumberNotRequired != nil {
		enc_honumbernotrequired := ber.EncodeNull()
		children = append(children, enc_honumbernotrequired...)
	}
	if v.BssAPDU != nil {
		enc_bssapdu, err := v.BssAPDU.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding bss-APDU: %w", err)
		}
		children = append(children, enc_bssapdu...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PrepareHOArgOld to DER format.
func (v *PrepareHOArgOld) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PrepareHOArgOld from BER/DER format.
func (v *PrepareHOArgOld) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PrepareHOArgOld SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareHOArgOld", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode targetCellId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_targetcellid, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding targetCellId: %w", err)
				}
				tmp_targetcellid := CommonDataTypesGlobalCellId(val_targetcellid)
				v.TargetCellId = &tmp_targetcellid
				offset += n
			}
		}
	}
	// Decode ho-NumberNotRequired
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ho-NumberNotRequired: %w", err)
				}
				v.HoNumberNotRequired = &struct{}{}
				offset += n
			}
		}
	}
	// Decode bss-APDU
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (BssAPDU)
				_, n_bssapdu, _, tlvErr_bssapdu := ber.DecodeTLV(content[offset:])
				if tlvErr_bssapdu != nil {
					return fmt.Errorf("decoding bss-APDU: %w", tlvErr_bssapdu)
				}
				var dec_bssapdu BssAPDU
				if unmErr := dec_bssapdu.UnmarshalBER(content[offset : offset+n_bssapdu]); unmErr != nil {
					return fmt.Errorf("decoding bss-APDU: %w", unmErr)
				}
				v.BssAPDU = &dec_bssapdu
				offset += n_bssapdu
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareHOArgOld", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PrepareHOResOld to BER format.
func (v *PrepareHOResOld) MarshalBER() ([]byte, error) {
	var children []byte
	if v.HandoverNumber != nil {
		enc_handovernumber := ber.EncodeOctetString([]byte(*v.HandoverNumber))
		children = append(children, enc_handovernumber...)
	}
	if v.BssAPDU != nil {
		enc_bssapdu, err := v.BssAPDU.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding bss-APDU: %w", err)
		}
		children = append(children, enc_bssapdu...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PrepareHOResOld to DER format.
func (v *PrepareHOResOld) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PrepareHOResOld from BER/DER format.
func (v *PrepareHOResOld) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PrepareHOResOld SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareHOResOld", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode handoverNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_handovernumber, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding handoverNumber: %w", err)
				}
				tmp_handovernumber := CommonDataTypesISDNAddressString(val_handovernumber)
				v.HandoverNumber = &tmp_handovernumber
				offset += n
			}
		}
	}
	// Decode bss-APDU
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (BssAPDU)
				_, n_bssapdu, _, tlvErr_bssapdu := ber.DecodeTLV(content[offset:])
				if tlvErr_bssapdu != nil {
					return fmt.Errorf("decoding bss-APDU: %w", tlvErr_bssapdu)
				}
				var dec_bssapdu BssAPDU
				if unmErr := dec_bssapdu.UnmarshalBER(content[offset : offset+n_bssapdu]); unmErr != nil {
					return fmt.Errorf("decoding bss-APDU: %w", unmErr)
				}
				v.BssAPDU = &dec_bssapdu
				offset += n_bssapdu
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareHOResOld", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERDumSendAuthenticationInfoResOld encodes a DumSendAuthenticationInfoResOld list to BER.
func MarshalBERDumSendAuthenticationInfoResOld(list DumSendAuthenticationInfoResOld) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERDumSendAuthenticationInfoResOld decodes a DumSendAuthenticationInfoResOld list from BER.
func UnmarshalBERDumSendAuthenticationInfoResOld(data []byte) (DumSendAuthenticationInfoResOld, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding DumSendAuthenticationInfoResOld: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "DumSendAuthenticationInfoResOld", Cause: ber.ErrExtraData}
	}
	var result DumSendAuthenticationInfoResOld
	offset := 0
	for offset < len(content) {
		var elem DumSendAuthenticationInfoResOldElem
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes DumSendIdentificationResV2 to BER format.
func (v *DumSendIdentificationResV2) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		children = append(children, enc_imsi...)
	}
	if v.TripletList != nil {
		enc_tripletlist, err := MarshalBERTripletListold(v.TripletList)
		if err != nil {
			return nil, fmt.Errorf("encoding tripletList: %w", err)
		}
		children = append(children, enc_tripletlist...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DumSendIdentificationResV2 to DER format.
func (v *DumSendIdentificationResV2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.TripletListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes DumSendIdentificationResV2 from BER/DER format.
func (v *DumSendIdentificationResV2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DumSendIdentificationResV2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DumSendIdentificationResV2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_imsi, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := CommonDataTypesIMSI(val_imsi)
				v.Imsi = &tmp_imsi
				offset += n
			}
		}
	}
	// Decode tripletList
	v.TripletListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (TripletListold)
				_, n_tripletlist, _, tlvErr_tripletlist := ber.DecodeTLV(content[offset:])
				if tlvErr_tripletlist != nil {
					return fmt.Errorf("decoding tripletList: %w", tlvErr_tripletlist)
				}
				tlv_tripletlist := content[offset : offset+n_tripletlist]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_tripletlist)
					if tagSz_ < len(tlv_tripletlist) && tlv_tripletlist[tagSz_] == 0x80 {
						v.TripletListIndef_ = true
					}
				}
				dec_tripletlist, unmErr := UnmarshalBERTripletListold(tlv_tripletlist)
				if unmErr != nil {
					return fmt.Errorf("decoding tripletList: %w", unmErr)
				}
				v.TripletList = dec_tripletlist
				offset += n_tripletlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DumSendIdentificationResV2", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERTripletListold encodes a TripletListold list to BER.
func MarshalBERTripletListold(list TripletListold) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERTripletListold decodes a TripletListold list from BER.
func UnmarshalBERTripletListold(data []byte) (TripletListold, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding TripletListold: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TripletListold", Cause: ber.ErrExtraData}
	}
	var result TripletListold
	offset := 0
	for offset < len(content) {
		var elem AuthenticationTripletV2
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes AuthenticationTripletV2 to BER format.
func (v *AuthenticationTripletV2) MarshalBER() ([]byte, error) {
	var children []byte
	enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	children = append(children, enc_rand...)
	enc_sres := ber.EncodeOctetString([]byte(v.Sres))
	children = append(children, enc_sres...)
	enc_kc := ber.EncodeOctetString([]byte(v.Kc))
	children = append(children, enc_kc...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AuthenticationTripletV2 to DER format.
func (v *AuthenticationTripletV2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticationTripletV2 from BER/DER format.
func (v *AuthenticationTripletV2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AuthenticationTripletV2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticationTripletV2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode rand
	if offset >= len(content) {
		return fmt.Errorf("missing required field rand")
	}
	val_rand, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding rand: %w", err)
	}
	v.Rand = DumRAND(val_rand)
	offset += n
	// Decode sres
	if offset >= len(content) {
		return fmt.Errorf("missing required field sres")
	}
	val_sres, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sres: %w", err)
	}
	v.Sres = DumSRES(val_sres)
	offset += n
	// Decode kc
	if offset >= len(content) {
		return fmt.Errorf("missing required field kc")
	}
	val_kc, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding kc: %w", err)
	}
	v.Kc = DumKc(val_kc)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AuthenticationTripletV2", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SIWFSSignallingModifyArg to BER format.
func (v *SIWFSSignallingModifyArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ChannelType != nil {
		enc_channeltype, err := v.ChannelType.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding channelType: %w", err)
		}
		enc_channeltype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_channeltype)
		children = append(children, enc_channeltype...)
	}
	if v.ChosenChannel != nil {
		enc_chosenchannel, err := v.ChosenChannel.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding chosenChannel: %w", err)
		}
		enc_chosenchannel = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_chosenchannel)
		children = append(children, enc_chosenchannel...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SIWFSSignallingModifyArg to DER format.
func (v *SIWFSSignallingModifyArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SIWFSSignallingModifyArg from BER/DER format.
func (v *SIWFSSignallingModifyArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SIWFSSignallingModifyArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SIWFSSignallingModifyArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode channelType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_channeltype, rawVal_channeltype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding channelType: %w", err)
				}
				reconstructed_channeltype := ber.EncodeSequence(rawVal_channeltype)
				var dec_channeltype CommonDataTypesExternalSignalInfo
				if unmErr := dec_channeltype.UnmarshalBER(reconstructed_channeltype); unmErr != nil {
					return fmt.Errorf("decoding channelType: %w", unmErr)
				}
				v.ChannelType = &dec_channeltype
				offset += n_channeltype
			}
		}
	}
	// Decode chosenChannel
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_chosenchannel, rawVal_chosenchannel, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding chosenChannel: %w", err)
				}
				reconstructed_chosenchannel := ber.EncodeSequence(rawVal_chosenchannel)
				var dec_chosenchannel CommonDataTypesExternalSignalInfo
				if unmErr := dec_chosenchannel.UnmarshalBER(reconstructed_chosenchannel); unmErr != nil {
					return fmt.Errorf("decoding chosenChannel: %w", unmErr)
				}
				v.ChosenChannel = &dec_chosenchannel
				offset += n_chosenchannel
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SIWFSSignallingModifyArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SIWFSSignallingModifyRes to BER format.
func (v *SIWFSSignallingModifyRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ChannelType != nil {
		enc_channeltype, err := v.ChannelType.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding channelType: %w", err)
		}
		enc_channeltype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_channeltype)
		children = append(children, enc_channeltype...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SIWFSSignallingModifyRes to DER format.
func (v *SIWFSSignallingModifyRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SIWFSSignallingModifyRes from BER/DER format.
func (v *SIWFSSignallingModifyRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SIWFSSignallingModifyRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SIWFSSignallingModifyRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode channelType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_channeltype, rawVal_channeltype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding channelType: %w", err)
				}
				reconstructed_channeltype := ber.EncodeSequence(rawVal_channeltype)
				var dec_channeltype CommonDataTypesExternalSignalInfo
				if unmErr := dec_channeltype.UnmarshalBER(reconstructed_channeltype); unmErr != nil {
					return fmt.Errorf("decoding channelType: %w", unmErr)
				}
				v.ChannelType = &dec_channeltype
				offset += n_channeltype
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SIWFSSignallingModifyRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SecureTransportArg to BER format.
func (v *SecureTransportArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_securityheader, err := v.SecurityHeader.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding securityHeader: %w", err)
	}
	children = append(children, enc_securityheader...)
	if v.ProtectedPayload != nil {
		enc_protectedpayload := ber.EncodeOctetString([]byte(*v.ProtectedPayload))
		children = append(children, enc_protectedpayload...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SecureTransportArg to DER format.
func (v *SecureTransportArg) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SecureTransportArg from BER/DER format.
func (v *SecureTransportArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SecureTransportArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SecureTransportArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode securityHeader
	if offset >= len(content) {
		return fmt.Errorf("missing required field securityHeader")
	}
	// Decode nested SEQUENCE (SecurityHeader)
	_, n_securityheader, _, tlvErr_securityheader := ber.DecodeTLV(content[offset:])
	if tlvErr_securityheader != nil {
		return fmt.Errorf("decoding securityHeader: %w", tlvErr_securityheader)
	}
	if unmErr := v.SecurityHeader.UnmarshalBER(content[offset : offset+n_securityheader]); unmErr != nil {
		return fmt.Errorf("decoding securityHeader: %w", unmErr)
	}
	offset += n_securityheader
	// Decode protectedPayload
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_protectedpayload, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding protectedPayload: %w", err)
				}
				tmp_protectedpayload := ProtectedPayload(val_protectedpayload)
				v.ProtectedPayload = &tmp_protectedpayload
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SecureTransportArg", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SecureTransportErrorParam to BER format.
func (v *SecureTransportErrorParam) MarshalBER() ([]byte, error) {
	var children []byte
	enc_securityheader, err := v.SecurityHeader.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding securityHeader: %w", err)
	}
	children = append(children, enc_securityheader...)
	if v.ProtectedPayload != nil {
		enc_protectedpayload := ber.EncodeOctetString([]byte(*v.ProtectedPayload))
		children = append(children, enc_protectedpayload...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SecureTransportErrorParam to DER format.
func (v *SecureTransportErrorParam) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SecureTransportErrorParam from BER/DER format.
func (v *SecureTransportErrorParam) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SecureTransportErrorParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SecureTransportErrorParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode securityHeader
	if offset >= len(content) {
		return fmt.Errorf("missing required field securityHeader")
	}
	// Decode nested SEQUENCE (SecurityHeader)
	_, n_securityheader, _, tlvErr_securityheader := ber.DecodeTLV(content[offset:])
	if tlvErr_securityheader != nil {
		return fmt.Errorf("decoding securityHeader: %w", tlvErr_securityheader)
	}
	if unmErr := v.SecurityHeader.UnmarshalBER(content[offset : offset+n_securityheader]); unmErr != nil {
		return fmt.Errorf("decoding securityHeader: %w", unmErr)
	}
	offset += n_securityheader
	// Decode protectedPayload
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_protectedpayload, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding protectedPayload: %w", err)
				}
				tmp_protectedpayload := ProtectedPayload(val_protectedpayload)
				v.ProtectedPayload = &tmp_protectedpayload
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SecureTransportErrorParam", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SecureTransportRes to BER format.
func (v *SecureTransportRes) MarshalBER() ([]byte, error) {
	var children []byte
	enc_securityheader, err := v.SecurityHeader.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding securityHeader: %w", err)
	}
	children = append(children, enc_securityheader...)
	if v.ProtectedPayload != nil {
		enc_protectedpayload := ber.EncodeOctetString([]byte(*v.ProtectedPayload))
		children = append(children, enc_protectedpayload...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SecureTransportRes to DER format.
func (v *SecureTransportRes) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SecureTransportRes from BER/DER format.
func (v *SecureTransportRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SecureTransportRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SecureTransportRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode securityHeader
	if offset >= len(content) {
		return fmt.Errorf("missing required field securityHeader")
	}
	// Decode nested SEQUENCE (SecurityHeader)
	_, n_securityheader, _, tlvErr_securityheader := ber.DecodeTLV(content[offset:])
	if tlvErr_securityheader != nil {
		return fmt.Errorf("decoding securityHeader: %w", tlvErr_securityheader)
	}
	if unmErr := v.SecurityHeader.UnmarshalBER(content[offset : offset+n_securityheader]); unmErr != nil {
		return fmt.Errorf("decoding securityHeader: %w", unmErr)
	}
	offset += n_securityheader
	// Decode protectedPayload
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_protectedpayload, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding protectedPayload: %w", err)
				}
				tmp_protectedpayload := ProtectedPayload(val_protectedpayload)
				v.ProtectedPayload = &tmp_protectedpayload
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SecureTransportRes", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SecurityHeader to BER format.
func (v *SecurityHeader) MarshalBER() ([]byte, error) {
	var children []byte
	enc_securityparametersindex := ber.EncodeOctetString([]byte(v.SecurityParametersIndex))
	children = append(children, enc_securityparametersindex...)
	enc_originalcomponentidentifier, err := v.OriginalComponentIdentifier.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding originalComponentIdentifier: %w", err)
	}
	children = append(children, enc_originalcomponentidentifier...)
	if v.InitialisationVector != nil {
		enc_initialisationvector := ber.EncodeOctetString([]byte(*v.InitialisationVector))
		children = append(children, enc_initialisationvector...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SecurityHeader to DER format.
func (v *SecurityHeader) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SecurityHeader from BER/DER format.
func (v *SecurityHeader) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SecurityHeader SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SecurityHeader", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode securityParametersIndex
	if offset >= len(content) {
		return fmt.Errorf("missing required field securityParametersIndex")
	}
	val_securityparametersindex, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding securityParametersIndex: %w", err)
	}
	v.SecurityParametersIndex = SecurityParametersIndex(val_securityparametersindex)
	offset += n
	// Decode originalComponentIdentifier
	if offset >= len(content) {
		return fmt.Errorf("missing required field originalComponentIdentifier")
	}
	// Decode nested CHOICE (OriginalComponentIdentifier)
	_, n_originalcomponentidentifier, _, tlvErr_originalcomponentidentifier := ber.DecodeTLV(content[offset:])
	if tlvErr_originalcomponentidentifier != nil {
		return fmt.Errorf("decoding originalComponentIdentifier: %w", tlvErr_originalcomponentidentifier)
	}
	if unmErr := v.OriginalComponentIdentifier.UnmarshalBER(content[offset : offset+n_originalcomponentidentifier]); unmErr != nil {
		return fmt.Errorf("decoding originalComponentIdentifier: %w", unmErr)
	}
	offset += n_originalcomponentidentifier
	// Decode initialisationVector
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_initialisationvector, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding initialisationVector: %w", err)
				}
				tmp_initialisationvector := InitialisationVector(val_initialisationvector)
				v.InitialisationVector = &tmp_initialisationvector
				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SecurityHeader", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OriginalComponentIdentifier to BER format.
func (v *OriginalComponentIdentifier) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case OriginalComponentIdentifierChoiceOperationCode:
		if v.OperationCode == nil {
			return nil, fmt.Errorf("choice OriginalComponentIdentifier: operationCode is nil")
		}
		enc_0, err := v.OperationCode.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding operationCode: %w", err)
		}
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		return enc_0, nil
	case OriginalComponentIdentifierChoiceErrorCode:
		if v.ErrorCode == nil {
			return nil, fmt.Errorf("choice OriginalComponentIdentifier: errorCode is nil")
		}
		enc_1, err := v.ErrorCode.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding errorCode: %w", err)
		}
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		return enc_1, nil
	case OriginalComponentIdentifierChoiceUserInfo:
		enc_2 := ber.EncodeNull()
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for OriginalComponentIdentifier", v.Choice)
	}
}

// MarshalDER encodes OriginalComponentIdentifier to DER format.
func (v *OriginalComponentIdentifier) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case OriginalComponentIdentifierChoiceOperationCode:
		if v.OperationCode == nil {
			return nil, fmt.Errorf("choice OriginalComponentIdentifier: operationCode is nil")
		}
		enc_der_0, err := v.OperationCode.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding operationCode: %w", err)
		}
		enc_der_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_0)
		return enc_der_0, nil
	case OriginalComponentIdentifierChoiceErrorCode:
		if v.ErrorCode == nil {
			return nil, fmt.Errorf("choice OriginalComponentIdentifier: errorCode is nil")
		}
		enc_der_1, err := v.ErrorCode.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding errorCode: %w", err)
		}
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes OriginalComponentIdentifier from BER/DER format.
func (v *OriginalComponentIdentifier) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for OriginalComponentIdentifier CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for OriginalComponentIdentifier: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding OriginalComponentIdentifier CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "OriginalComponentIdentifier", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = OriginalComponentIdentifierChoiceOperationCode
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding operationCode: %w", tlvErr)
		}
		var dec OperationCode
		if unmErr := dec.UnmarshalBER(innerData); unmErr != nil {
			return fmt.Errorf("decoding operationCode: %w", unmErr)
		}
		v.OperationCode = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = OriginalComponentIdentifierChoiceErrorCode
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding errorCode: %w", tlvErr)
		}
		var dec ErrorCode
		if unmErr := dec.UnmarshalBER(innerData); unmErr != nil {
			return fmt.Errorf("decoding errorCode: %w", unmErr)
		}
		v.ErrorCode = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = OriginalComponentIdentifierChoiceUserInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding userInfo: %w", tlvErr)
		}
		_ = rawVal // NULL has no content
		v.UserInfo = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for OriginalComponentIdentifier CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes OperationCode to BER format.
func (v *OperationCode) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case OperationCodeChoiceLocalValue:
		if v.LocalValue == nil {
			return nil, fmt.Errorf("choice OperationCode: localValue is nil")
		}
		enc_0 := ber.EncodeBigInt(v.LocalValue)
		return enc_0, nil
	case OperationCodeChoiceGlobalValue:
		enc_1 := ber.EncodeObjectIdentifier([]uint64(v.GlobalValue))
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for OperationCode", v.Choice)
	}
}

// MarshalDER encodes OperationCode to DER format.
func (v *OperationCode) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes OperationCode from BER/DER format.
func (v *OperationCode) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for OperationCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for OperationCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding OperationCode CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "OperationCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = OperationCodeChoiceLocalValue
		decVal, _, intErr := ber.DecodeBigInt(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		v.LocalValue = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 {
		v.Choice = OperationCodeChoiceGlobalValue
		decVal, _, oidErr := ber.DecodeObjectIdentifier(choiceData)
		if oidErr != nil {
			return fmt.Errorf("decoding globalValue: %w", oidErr)
		}
		tmp := runtime.ObjectIdentifier(decVal)
		v.GlobalValue = tmp
	} else {
		return fmt.Errorf("unknown tag %s for OperationCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ErrorCode to BER format.
func (v *ErrorCode) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ErrorCodeChoiceLocalValue:
		if v.LocalValue == nil {
			return nil, fmt.Errorf("choice ErrorCode: localValue is nil")
		}
		enc_0 := ber.EncodeBigInt(v.LocalValue)
		return enc_0, nil
	case ErrorCodeChoiceGlobalValue:
		enc_1 := ber.EncodeObjectIdentifier([]uint64(v.GlobalValue))
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ErrorCode", v.Choice)
	}
}

// MarshalDER encodes ErrorCode to DER format.
func (v *ErrorCode) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes ErrorCode from BER/DER format.
func (v *ErrorCode) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ErrorCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ErrorCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ErrorCode CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ErrorCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = ErrorCodeChoiceLocalValue
		decVal, _, intErr := ber.DecodeBigInt(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		v.LocalValue = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 {
		v.Choice = ErrorCodeChoiceGlobalValue
		decVal, _, oidErr := ber.DecodeObjectIdentifier(choiceData)
		if oidErr != nil {
			return fmt.Errorf("decoding globalValue: %w", oidErr)
		}
		tmp := runtime.ObjectIdentifier(decVal)
		v.GlobalValue = tmp
	} else {
		return fmt.Errorf("unknown tag %s for ErrorCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes PlmnContainer to BER format.
func (v *PlmnContainer) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_msisdn)
		children = append(children, enc_msisdn...)
	}
	if v.Category != nil {
		enc_category := ber.EncodeOctetString([]byte(*v.Category))
		enc_category = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_category)
		children = append(children, enc_category...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.OperatorSSCode != nil {
		enc_operatorsscode, err := MarshalBERPlmnContainerOperatorSSCode(v.OperatorSSCode)
		if err != nil {
			return nil, fmt.Errorf("encoding operatorSS-Code: %w", err)
		}
		if v.OperatorSSCodeIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_operatorsscode)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_operatorsscode = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, seqContent_)
		} else {
			enc_operatorsscode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_operatorsscode)
		}
		children = append(children, enc_operatorsscode...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 2, Constructed: true}, children), nil
}

// MarshalDER encodes PlmnContainer to DER format.
func (v *PlmnContainer) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.OperatorSSCodeIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes PlmnContainer from BER/DER format.
func (v *PlmnContainer) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding PlmnContainer: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 2 || !decodedTag.Constructed {
		return fmt.Errorf("decoding PlmnContainer: %w: expected tag [PRIVATE 2], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PlmnContainer", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				tmp_msisdn := CommonDataTypesISDNAddressString(rawVal_msisdn)
				v.Msisdn = &tmp_msisdn
				offset += n_msisdn
			}
		}
	}
	// Decode category
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_category, rawVal_category, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding category: %w", err)
				}
				tmp_category := DumCategory(rawVal_category)
				v.Category = &tmp_category
				offset += n_category
			}
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (CommonDataTypesBasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice CommonDataTypesBasicServiceCode
				if unmErr := dec_basicservice.UnmarshalBER(content[offset : offset+n_basicservice]); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				offset += n_basicservice
			}
		}
	}
	// Decode operatorSS-Code
	v.OperatorSSCodeIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_operatorsscode, rawVal_operatorsscode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding operatorSS-Code: %w", err)
				}
				reconstructed_operatorsscode := ber.EncodeSequence(rawVal_operatorsscode)
				dec_operatorsscode, unmErr := UnmarshalBERPlmnContainerOperatorSSCode(reconstructed_operatorsscode)
				if unmErr != nil {
					return fmt.Errorf("decoding operatorSS-Code: %w", unmErr)
				}
				v.OperatorSSCode = dec_operatorsscode
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OperatorSSCodeIndef_ = true
					}
				}
				offset += n_operatorsscode
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PlmnContainer", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ForwardSMArg to BER format.
func (v *ForwardSMArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-DA: %w", err)
	}
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-OA: %w", err)
	}
	children = append(children, enc_smrpoa...)
	enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	children = append(children, enc_smrpui...)
	if v.MoreMessagesToSend != nil {
		enc_moremessagestosend := ber.EncodeNull()
		children = append(children, enc_moremessagestosend...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ForwardSMArg to DER format.
func (v *ForwardSMArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ForwardSMArg from BER/DER format.
func (v *ForwardSMArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardSMArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-DA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-DA")
	}
	// Decode nested CHOICE (SMRPDAold)
	_, n_smrpda, _, tlvErr_smrpda := ber.DecodeTLV(content[offset:])
	if tlvErr_smrpda != nil {
		return fmt.Errorf("decoding sm-RP-DA: %w", tlvErr_smrpda)
	}
	if unmErr := v.SmRPDA.UnmarshalBER(content[offset : offset+n_smrpda]); unmErr != nil {
		return fmt.Errorf("decoding sm-RP-DA: %w", unmErr)
	}
	offset += n_smrpda
	// Decode sm-RP-OA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-OA")
	}
	// Decode nested CHOICE (SMRPOAold)
	_, n_smrpoa, _, tlvErr_smrpoa := ber.DecodeTLV(content[offset:])
	if tlvErr_smrpoa != nil {
		return fmt.Errorf("decoding sm-RP-OA: %w", tlvErr_smrpoa)
	}
	if unmErr := v.SmRPOA.UnmarshalBER(content[offset : offset+n_smrpoa]); unmErr != nil {
		return fmt.Errorf("decoding sm-RP-OA: %w", unmErr)
	}
	offset += n_smrpoa
	// Decode sm-RP-UI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-UI")
	}
	val_smrpui, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sm-RP-UI: %w", err)
	}
	v.SmRPUI = CommonDataTypesSignalInfo(val_smrpui)
	offset += n
	// Decode moreMessagesToSend
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding moreMessagesToSend: %w", err)
				}
				v.MoreMessagesToSend = &struct{}{}
				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardSMArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMRPDAold to BER format.
func (v *SMRPDAold) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SMRPDAoldChoiceImsi:
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case SMRPDAoldChoiceLmsi:
		enc_1 := ber.EncodeOctetString([]byte(*v.Lmsi))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	case SMRPDAoldChoiceServiceCentreAddressDA:
		enc_2 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressDA))
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_2)
		return enc_2, nil
	case SMRPDAoldChoiceNoSMRPDA:
		enc_3 := ber.EncodeNull()
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMRPDAold", v.Choice)
	}
}

// MarshalDER encodes SMRPDAold to DER format.
func (v *SMRPDAold) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes SMRPDAold from BER/DER format.
func (v *SMRPDAold) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMRPDAold CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMRPDAold: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SMRPDAold CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRPDAold", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SMRPDAoldChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := CommonDataTypesIMSI(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMRPDAoldChoiceLmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding lmsi: %w", tlvErr)
		}
		tmp := CommonDataTypesLMSI(rawVal)
		v.Lmsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPDAoldChoiceServiceCentreAddressDA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressDA: %w", tlvErr)
		}
		tmp := CommonDataTypesAddressString(rawVal)
		v.ServiceCentreAddressDA = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
		v.Choice = SMRPDAoldChoiceNoSMRPDA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding noSM-RP-DA: %w", tlvErr)
		}
		_ = rawVal // NULL has no content
		v.NoSMRPDA = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for SMRPDAold CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SMRPOAold to BER format.
func (v *SMRPOAold) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SMRPOAoldChoiceMsisdn:
		enc_0 := ber.EncodeOctetString([]byte(*v.Msisdn))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_0)
		return enc_0, nil
	case SMRPOAoldChoiceServiceCentreAddressOA:
		enc_1 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressOA))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_1)
		return enc_1, nil
	case SMRPOAoldChoiceNoSMRPOA:
		enc_2 := ber.EncodeNull()
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMRPOAold", v.Choice)
	}
}

// MarshalDER encodes SMRPOAold to DER format.
func (v *SMRPOAold) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes SMRPOAold from BER/DER format.
func (v *SMRPOAold) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMRPOAold CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMRPOAold: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SMRPOAold CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRPOAold", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SMRPOAoldChoiceMsisdn
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msisdn: %w", tlvErr)
		}
		tmp := CommonDataTypesISDNAddressString(rawVal)
		v.Msisdn = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPOAoldChoiceServiceCentreAddressOA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressOA: %w", tlvErr)
		}
		tmp := CommonDataTypesAddressString(rawVal)
		v.ServiceCentreAddressOA = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
		v.Choice = SMRPOAoldChoiceNoSMRPOA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding noSM-RP-OA: %w", tlvErr)
		}
		_ = rawVal // NULL has no content
		v.NoSMRPOA = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for SMRPOAold CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SendRoutingInfoArgV2 to BER format.
func (v *SendRoutingInfoArgV2) MarshalBER() ([]byte, error) {
	var children []byte
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_msisdn)
	children = append(children, enc_msisdn...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		enc_cugcheckinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_cugcheckinfo)
		children = append(children, enc_cugcheckinfo...)
	}
	if v.NumberOfForwarding != nil {
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		enc_numberofforwarding = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_numberofforwarding)
		children = append(children, enc_numberofforwarding...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", err)
		}
		enc_networksignalinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_networksignalinfo)
		children = append(children, enc_networksignalinfo...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SendRoutingInfoArgV2 to DER format.
func (v *SendRoutingInfoArgV2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SendRoutingInfoArgV2 from BER/DER format.
func (v *SendRoutingInfoArgV2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SendRoutingInfoArgV2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInfoArgV2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("missing required field msisdn")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for msisdn, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	v.Msisdn = CommonDataTypesISDNAddressString(rawVal_msisdn)
	offset += n_msisdn
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", err)
				}
				reconstructed_cugcheckinfo := ber.EncodeSequence(rawVal_cugcheckinfo)
				var dec_cugcheckinfo CHCUGCheckInfo
				if unmErr := dec_cugcheckinfo.UnmarshalBER(reconstructed_cugcheckinfo); unmErr != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", unmErr)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				offset += n_cugcheckinfo
			}
		}
	}
	// Decode numberOfForwarding
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_numberofforwarding, rawVal_numberofforwarding, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding numberOfForwarding: %w", err)
				}
				decVal_numberofforwarding, intErr := ber.DecodeIntegerValue(rawVal_numberofforwarding)
				if intErr != nil {
					return fmt.Errorf("decoding numberOfForwarding: %w", intErr)
				}
				tmp_numberofforwarding := CHNumberOfForwarding(decVal_numberofforwarding)
				v.NumberOfForwarding = &tmp_numberofforwarding
				offset += n_numberofforwarding
			}
		}
	}
	// Decode networkSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				_, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkSignalInfo: %w", err)
				}
				reconstructed_networksignalinfo := ber.EncodeSequence(rawVal_networksignalinfo)
				var dec_networksignalinfo CommonDataTypesExternalSignalInfo
				if unmErr := dec_networksignalinfo.UnmarshalBER(reconstructed_networksignalinfo); unmErr != nil {
					return fmt.Errorf("decoding networkSignalInfo: %w", unmErr)
				}
				v.NetworkSignalInfo = &dec_networksignalinfo
				offset += n_networksignalinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoArgV2", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SendRoutingInfoResV2 to BER format.
func (v *SendRoutingInfoResV2) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	children = append(children, enc_imsi...)
	enc_routinginfo, err := v.RoutingInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding routingInfo: %w", err)
	}
	children = append(children, enc_routinginfo...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		children = append(children, enc_cugcheckinfo...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SendRoutingInfoResV2 to DER format.
func (v *SendRoutingInfoResV2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SendRoutingInfoResV2 from BER/DER format.
func (v *SendRoutingInfoResV2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SendRoutingInfoResV2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInfoResV2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	val_imsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(val_imsi)
	offset += n
	// Decode routingInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field routingInfo")
	}
	// Decode nested CHOICE (CHRoutingInfo)
	_, n_routinginfo, _, tlvErr_routinginfo := ber.DecodeTLV(content[offset:])
	if tlvErr_routinginfo != nil {
		return fmt.Errorf("decoding routingInfo: %w", tlvErr_routinginfo)
	}
	if unmErr := v.RoutingInfo.UnmarshalBER(content[offset : offset+n_routinginfo]); unmErr != nil {
		return fmt.Errorf("decoding routingInfo: %w", unmErr)
	}
	offset += n_routinginfo
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (CHCUGCheckInfo)
				_, n_cugcheckinfo, _, tlvErr_cugcheckinfo := ber.DecodeTLV(content[offset:])
				if tlvErr_cugcheckinfo != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", tlvErr_cugcheckinfo)
				}
				var dec_cugcheckinfo CHCUGCheckInfo
				if unmErr := dec_cugcheckinfo.UnmarshalBER(content[offset : offset+n_cugcheckinfo]); unmErr != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", unmErr)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				offset += n_cugcheckinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoResV2", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes BeginSubscriberActivityArg to BER format.
func (v *BeginSubscriberActivityArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	children = append(children, enc_imsi...)
	enc_originatingentitynumber := ber.EncodeOctetString([]byte(v.OriginatingEntityNumber))
	children = append(children, enc_originatingentitynumber...)
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 28, false, enc_msisdn)
		children = append(children, enc_msisdn...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes BeginSubscriberActivityArg to DER format.
func (v *BeginSubscriberActivityArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes BeginSubscriberActivityArg from BER/DER format.
func (v *BeginSubscriberActivityArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding BeginSubscriberActivityArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BeginSubscriberActivityArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	val_imsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(val_imsi)
	offset += n
	// Decode originatingEntityNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field originatingEntityNumber")
	}
	val_originatingentitynumber, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding originatingEntityNumber: %w", err)
	}
	v.OriginatingEntityNumber = CommonDataTypesISDNAddressString(val_originatingentitynumber)
	offset += n
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassPrivate && peekTag.Number == 28 {
				_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				tmp_msisdn := CommonDataTypesAddressString(rawVal_msisdn)
				v.Msisdn = &tmp_msisdn
				offset += n_msisdn
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "BeginSubscriberActivityArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RoutingInfoForSMArgV1 to BER format.
func (v *RoutingInfoForSMArgV1) MarshalBER() ([]byte, error) {
	var children []byte
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_msisdn)
	children = append(children, enc_msisdn...)
	var enc_smrppri []byte
	if v.SmRPPRIRaw_ != 0 {
		enc_smrppri = ber.EncodeBooleanRaw(v.SmRPPRIRaw_)
	} else {
		enc_smrppri = ber.EncodeBoolean(v.SmRPPRI)
	}
	enc_smrppri = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_smrppri)
	children = append(children, enc_smrppri...)
	enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	enc_servicecentreaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_servicecentreaddress)
	children = append(children, enc_servicecentreaddress...)
	if v.CugInterlock != nil {
		enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
		enc_cuginterlock = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_cuginterlock)
		children = append(children, enc_cuginterlock...)
	}
	if v.TeleserviceCode != nil {
		enc_teleservicecode := ber.EncodeOctetString([]byte(*v.TeleserviceCode))
		enc_teleservicecode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_teleservicecode)
		children = append(children, enc_teleservicecode...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes RoutingInfoForSMArgV1 to DER format.
func (v *RoutingInfoForSMArgV1) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RoutingInfoForSMArgV1 from BER/DER format.
func (v *RoutingInfoForSMArgV1) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RoutingInfoForSMArgV1 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfoForSMArgV1", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("missing required field msisdn")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for msisdn, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	v.Msisdn = CommonDataTypesISDNAddressString(rawVal_msisdn)
	offset += n_msisdn
	// Decode sm-RP-PRI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-PRI")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for sm-RP-PRI, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_smrppri, rawVal_smrppri, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sm-RP-PRI: %w", err)
	}
	decVal_smrppri, boolErr := ber.DecodeBooleanValue(rawVal_smrppri)
	if boolErr != nil {
		return fmt.Errorf("decoding sm-RP-PRI: %w", boolErr)
	}
	if len(rawVal_smrppri) == 1 {
		v.SmRPPRIRaw_ = rawVal_smrppri[0]
	}
	v.SmRPPRI = decVal_smrppri
	offset += n_smrppri
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceCentreAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for serviceCentreAddress, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_servicecentreaddress, rawVal_servicecentreaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serviceCentreAddress: %w", err)
	}
	v.ServiceCentreAddress = CommonDataTypesAddressString(rawVal_servicecentreaddress)
	offset += n_servicecentreaddress
	// Decode cug-Interlock
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_cuginterlock, rawVal_cuginterlock, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-Interlock: %w", err)
				}
				tmp_cuginterlock := CUGInterlock3(rawVal_cuginterlock)
				v.CugInterlock = &tmp_cuginterlock
				offset += n_cuginterlock
			}
		}
	}
	// Decode teleserviceCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_teleservicecode, rawVal_teleservicecode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding teleserviceCode: %w", err)
				}
				tmp_teleservicecode := TSTeleserviceCode(rawVal_teleservicecode)
				v.TeleserviceCode = &tmp_teleservicecode
				offset += n_teleservicecode
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := CommonDataTypesIMSI(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMArgV1", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RoutingInfoForSMResV2 to BER format.
func (v *RoutingInfoForSMResV2) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	children = append(children, enc_imsi...)
	enc_locationinfowithlmsi, err := v.LocationInfoWithLMSI.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding locationInfoWithLMSI: %w", err)
	}
	enc_locationinfowithlmsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_locationinfowithlmsi)
	children = append(children, enc_locationinfowithlmsi...)
	if v.MwdSet != nil {
		var enc_mwdset []byte
		if v.MwdSetRaw_ != 0 {
			enc_mwdset = ber.EncodeBooleanRaw(v.MwdSetRaw_)
		} else {
			enc_mwdset = ber.EncodeBoolean(*v.MwdSet)
		}
		enc_mwdset = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_mwdset)
		children = append(children, enc_mwdset...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes RoutingInfoForSMResV2 to DER format.
func (v *RoutingInfoForSMResV2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RoutingInfoForSMResV2 from BER/DER format.
func (v *RoutingInfoForSMResV2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RoutingInfoForSMResV2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfoForSMResV2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	val_imsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(val_imsi)
	offset += n
	// Decode locationInfoWithLMSI
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationInfoWithLMSI")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for locationInfoWithLMSI, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_locationinfowithlmsi, rawVal_locationinfowithlmsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding locationInfoWithLMSI: %w", err)
	}
	reconstructed_locationinfowithlmsi := ber.EncodeSequence(rawVal_locationinfowithlmsi)
	if unmErr := v.LocationInfoWithLMSI.UnmarshalBER(reconstructed_locationinfowithlmsi); unmErr != nil {
		return fmt.Errorf("decoding locationInfoWithLMSI: %w", unmErr)
	}
	offset += n_locationinfowithlmsi
	// Decode mwd-Set
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_mwdset, rawVal_mwdset, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mwd-Set: %w", err)
				}
				decVal_mwdset, boolErr := ber.DecodeBooleanValue(rawVal_mwdset)
				if boolErr != nil {
					return fmt.Errorf("decoding mwd-Set: %w", boolErr)
				}
				if len(rawVal_mwdset) == 1 {
					v.MwdSetRaw_ = rawVal_mwdset[0]
				}
				v.MwdSet = &decVal_mwdset
				offset += n_mwdset
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMResV2", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LocationInfoWithLMSIv2 to BER format.
func (v *LocationInfoWithLMSIv2) MarshalBER() ([]byte, error) {
	var children []byte
	enc_locationinfo, err := v.LocationInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding locationInfo: %w", err)
	}
	children = append(children, enc_locationinfo...)
	if v.Lmsi != nil {
		enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		children = append(children, enc_lmsi...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes LocationInfoWithLMSIv2 to DER format.
func (v *LocationInfoWithLMSIv2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LocationInfoWithLMSIv2 from BER/DER format.
func (v *LocationInfoWithLMSIv2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LocationInfoWithLMSIv2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LocationInfoWithLMSIv2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationInfo")
	}
	// Decode nested CHOICE (LocationInfo)
	_, n_locationinfo, _, tlvErr_locationinfo := ber.DecodeTLV(content[offset:])
	if tlvErr_locationinfo != nil {
		return fmt.Errorf("decoding locationInfo: %w", tlvErr_locationinfo)
	}
	if unmErr := v.LocationInfo.UnmarshalBER(content[offset : offset+n_locationinfo]); unmErr != nil {
		return fmt.Errorf("decoding locationInfo: %w", unmErr)
	}
	offset += n_locationinfo
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_lmsi, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lmsi: %w", err)
				}
				tmp_lmsi := CommonDataTypesLMSI(val_lmsi)
				v.Lmsi = &tmp_lmsi
				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LocationInfoWithLMSIv2", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LocationInfo to BER format.
func (v *LocationInfo) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case LocationInfoChoiceRoamingNumber:
		enc_0 := ber.EncodeOctetString([]byte(*v.RoamingNumber))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case LocationInfoChoiceMscNumber:
		enc_1 := ber.EncodeOctetString([]byte(*v.MscNumber))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for LocationInfo", v.Choice)
	}
}

// MarshalDER encodes LocationInfo to DER format.
func (v *LocationInfo) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes LocationInfo from BER/DER format.
func (v *LocationInfo) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for LocationInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for LocationInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding LocationInfo CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "LocationInfo", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = LocationInfoChoiceRoamingNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding roamingNumber: %w", tlvErr)
		}
		tmp := CommonDataTypesISDNAddressString(rawVal)
		v.RoamingNumber = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = LocationInfoChoiceMscNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msc-Number: %w", tlvErr)
		}
		tmp := CommonDataTypesISDNAddressString(rawVal)
		v.MscNumber = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for LocationInfo CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SendParametersArg to BER format.
func (v *SendParametersArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_subscriberid, err := v.SubscriberId.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding subscriberId: %w", err)
	}
	children = append(children, enc_subscriberid...)
	enc_requestparameterlist, err := MarshalBERRequestParameterList(v.RequestParameterList)
	if err != nil {
		return nil, fmt.Errorf("encoding requestParameterList: %w", err)
	}
	children = append(children, enc_requestparameterlist...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SendParametersArg to DER format.
func (v *SendParametersArg) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.RequestParameterListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes SendParametersArg from BER/DER format.
func (v *SendParametersArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SendParametersArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendParametersArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode subscriberId
	if offset >= len(content) {
		return fmt.Errorf("missing required field subscriberId")
	}
	// Decode nested CHOICE (CommonDataTypesSubscriberId)
	_, n_subscriberid, _, tlvErr_subscriberid := ber.DecodeTLV(content[offset:])
	if tlvErr_subscriberid != nil {
		return fmt.Errorf("decoding subscriberId: %w", tlvErr_subscriberid)
	}
	if unmErr := v.SubscriberId.UnmarshalBER(content[offset : offset+n_subscriberid]); unmErr != nil {
		return fmt.Errorf("decoding subscriberId: %w", unmErr)
	}
	offset += n_subscriberid
	// Decode requestParameterList
	if offset >= len(content) {
		return fmt.Errorf("missing required field requestParameterList")
	}
	v.RequestParameterListIndef_ = false
	// Decode nested SEQUENCE_OF (RequestParameterList)
	_, n_requestparameterlist, _, tlvErr_requestparameterlist := ber.DecodeTLV(content[offset:])
	if tlvErr_requestparameterlist != nil {
		return fmt.Errorf("decoding requestParameterList: %w", tlvErr_requestparameterlist)
	}
	tlv_requestparameterlist := content[offset : offset+n_requestparameterlist]
	{
		_, tagSz_, _ := ber.DecodeTag(tlv_requestparameterlist)
		if tagSz_ < len(tlv_requestparameterlist) && tlv_requestparameterlist[tagSz_] == 0x80 {
			v.RequestParameterListIndef_ = true
		}
	}
	dec_requestparameterlist, unmErr := UnmarshalBERRequestParameterList(tlv_requestparameterlist)
	if unmErr != nil {
		return fmt.Errorf("decoding requestParameterList: %w", unmErr)
	}
	v.RequestParameterList = dec_requestparameterlist
	offset += n_requestparameterlist
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SendParametersArg", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERRequestParameterList encodes a RequestParameterList list to BER.
func MarshalBERRequestParameterList(list RequestParameterList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeEnumerated(int64(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERRequestParameterList decodes a RequestParameterList list from BER.
func UnmarshalBERRequestParameterList(data []byte) (RequestParameterList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RequestParameterList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RequestParameterList", Cause: ber.ErrExtraData}
	}
	var result RequestParameterList
	offset := 0
	for offset < len(content) {
		val, n, intErr := ber.DecodeInteger(content[offset:])
		if intErr != nil {
			return nil, fmt.Errorf("decoding element: %w", intErr)
		}
		result = append(result, RequestParameter(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes SentParameter to BER format.
func (v *SentParameter) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SentParameterChoiceImsi:
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case SentParameterChoiceAuthenticationSet:
		if v.AuthenticationSet == nil {
			return nil, fmt.Errorf("choice SentParameter: authenticationSet is nil")
		}
		enc_1, err := v.AuthenticationSet.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticationSet: %w", err)
		}
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		return enc_1, nil
	case SentParameterChoiceSubscriberData:
		if v.SubscriberData == nil {
			return nil, fmt.Errorf("choice SentParameter: subscriberData is nil")
		}
		enc_2, err := v.SubscriberData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding subscriberData: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_2)
		return enc_2, nil
	case SentParameterChoiceKi:
		enc_3 := ber.EncodeOctetString([]byte(*v.Ki))
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SentParameter", v.Choice)
	}
}

// MarshalDER encodes SentParameter to DER format.
func (v *SentParameter) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case SentParameterChoiceAuthenticationSet:
		if v.AuthenticationSet == nil {
			return nil, fmt.Errorf("choice SentParameter: authenticationSet is nil")
		}
		enc_der_1, err := v.AuthenticationSet.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticationSet: %w", err)
		}
		enc_der_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		return enc_der_1, nil
	case SentParameterChoiceSubscriberData:
		if v.SubscriberData == nil {
			return nil, fmt.Errorf("choice SentParameter: subscriberData is nil")
		}
		enc_der_2, err := v.SubscriberData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding subscriberData: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_der_2)
		return enc_der_2, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes SentParameter from BER/DER format.
func (v *SentParameter) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SentParameter CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SentParameter: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SentParameter CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SentParameter", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SentParameterChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := CommonDataTypesIMSI(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SentParameterChoiceAuthenticationSet
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticationSet: %w", tlvErr)
		}
		var dec AuthenticationSetListOld
		if unmErr := dec.UnmarshalBER(innerData); unmErr != nil {
			return fmt.Errorf("decoding authenticationSet: %w", unmErr)
		}
		v.AuthenticationSet = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SentParameterChoiceSubscriberData
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding subscriberData: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SubscriberData3
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding subscriberData: %w", unmErr)
		}
		v.SubscriberData = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SentParameterChoiceKi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ki: %w", tlvErr)
		}
		tmp := Ki(rawVal)
		v.Ki = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SentParameter CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AuthenticationSetListOld to BER format.
func (v *AuthenticationSetListOld) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AuthenticationSetListOldChoiceTripletList:
		if v.TripletList == nil {
			return nil, fmt.Errorf("choice AuthenticationSetListOld: tripletList is nil")
		}
		enc_0, err := MarshalBERTripletList3(v.TripletList)
		if err != nil {
			return nil, fmt.Errorf("encoding tripletList: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case AuthenticationSetListOldChoiceQuintupletList:
		if v.QuintupletList == nil {
			return nil, fmt.Errorf("choice AuthenticationSetListOld: quintupletList is nil")
		}
		enc_1, err := MarshalBERQuintupletList3(v.QuintupletList)
		if err != nil {
			return nil, fmt.Errorf("encoding quintupletList: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AuthenticationSetListOld", v.Choice)
	}
}

// MarshalDER encodes AuthenticationSetListOld to DER format.
func (v *AuthenticationSetListOld) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes AuthenticationSetListOld from BER/DER format.
func (v *AuthenticationSetListOld) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AuthenticationSetListOld CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AuthenticationSetListOld: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AuthenticationSetListOld CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticationSetListOld", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = AuthenticationSetListOldChoiceTripletList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding tripletList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERTripletList3(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding tripletList: %w", unmErr)
		}
		v.TripletList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = AuthenticationSetListOldChoiceQuintupletList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding quintupletList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERQuintupletList3(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding quintupletList: %w", unmErr)
		}
		v.QuintupletList = dec
	} else {
		return fmt.Errorf("unknown tag %s for AuthenticationSetListOld CHOICE", peekTag)
	}
	return nil
}

// MarshalBERSentParameterList encodes a SentParameterList list to BER.
func MarshalBERSentParameterList(list SentParameterList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSentParameterList decodes a SentParameterList list from BER.
func UnmarshalBERSentParameterList(data []byte) (SentParameterList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SentParameterList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SentParameterList", Cause: ber.ErrExtraData}
	}
	var result SentParameterList
	offset := 0
	for offset < len(content) {
		var elem SentParameter
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes ResetArgV2 to BER format.
func (v *ResetArgV2) MarshalBER() ([]byte, error) {
	var children []byte
	if v.NetworkResource != nil {
		enc_networkresource := ber.EncodeEnumerated(int64(*v.NetworkResource))
		children = append(children, enc_networkresource...)
	}
	enc_hlrnumber := ber.EncodeOctetString([]byte(v.HlrNumber))
	children = append(children, enc_hlrnumber...)
	if v.HlrList != nil {
		enc_hlrlist, err := MarshalBERCommonDataTypesHLRList(v.HlrList)
		if err != nil {
			return nil, fmt.Errorf("encoding hlr-List: %w", err)
		}
		children = append(children, enc_hlrlist...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ResetArgV2 to DER format.
func (v *ResetArgV2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.HlrListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes ResetArgV2 from BER/DER format.
func (v *ResetArgV2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ResetArgV2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ResetArgV2", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode networkResource
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_networkresource, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkResource: %w", err)
				}
				tmp_networkresource := CommonDataTypesNetworkResource(val_networkresource)
				v.NetworkResource = &tmp_networkresource
				offset += n
			}
		}
	}
	// Decode hlr-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field hlr-Number")
	}
	val_hlrnumber, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding hlr-Number: %w", err)
	}
	v.HlrNumber = CommonDataTypesISDNAddressString(val_hlrnumber)
	offset += n
	// Decode hlr-List
	v.HlrListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (CommonDataTypesHLRList)
				_, n_hlrlist, _, tlvErr_hlrlist := ber.DecodeTLV(content[offset:])
				if tlvErr_hlrlist != nil {
					return fmt.Errorf("decoding hlr-List: %w", tlvErr_hlrlist)
				}
				tlv_hlrlist := content[offset : offset+n_hlrlist]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_hlrlist)
					if tagSz_ < len(tlv_hlrlist) && tlv_hlrlist[tagSz_] == 0x80 {
						v.HlrListIndef_ = true
					}
				}
				dec_hlrlist, unmErr := UnmarshalBERCommonDataTypesHLRList(tlv_hlrlist)
				if unmErr != nil {
					return fmt.Errorf("decoding hlr-List: %w", unmErr)
				}
				v.HlrList = dec_hlrlist
				offset += n_hlrlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ResetArgV2", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ReturnResultResultretres to BER format.
func (v *ReturnResultResultretres) MarshalBER() ([]byte, error) {
	var children []byte
	enc_opcode, err := v.OpCode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding opCode: %w", err)
	}
	children = append(children, enc_opcode...)
	if v.Returnparameter != nil {
		enc_returnparameter := v.Returnparameter.Bytes
		children = append(children, enc_returnparameter...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ReturnResultResultretres to DER format.
func (v *ReturnResultResultretres) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ReturnResultResultretres from BER/DER format.
func (v *ReturnResultResultretres) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReturnResultResultretres SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnResultResultretres", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opCode")
	}
	// Decode nested CHOICE (MAPOPERATION)
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:])
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opCode: %w", tlvErr_opcode)
	}
	if unmErr := v.OpCode.UnmarshalBER(content[offset : offset+n_opcode]); unmErr != nil {
		return fmt.Errorf("decoding opCode: %w", unmErr)
	}
	offset += n_opcode
	// Decode returnparameter
	if offset < len(content) {
		_, n_returnparameter, _, tlvErr_returnparameter := ber.DecodeTLV(content[offset:])
		if tlvErr_returnparameter != nil {
			return fmt.Errorf("decoding returnparameter: %w", tlvErr_returnparameter)
		}
		tmp_returnparameter := runtime.RawValue{Bytes: content[offset : offset+n_returnparameter]}
		v.Returnparameter = &tmp_returnparameter
		offset += n_returnparameter
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnResultResultretres", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RejectInvokeIDRej to BER format.
func (v *RejectInvokeIDRej) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case RejectInvokeIDRejChoiceDerivable:
		if v.Derivable == nil {
			return nil, fmt.Errorf("choice RejectInvokeIDRej: derivable is nil")
		}
		enc_0 := ber.EncodeInteger(int64(*v.Derivable))
		return enc_0, nil
	case RejectInvokeIDRejChoiceNotDerivable:
		enc_1 := ber.EncodeNull()
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RejectInvokeIDRej", v.Choice)
	}
}

// MarshalDER encodes RejectInvokeIDRej to DER format.
func (v *RejectInvokeIDRej) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes RejectInvokeIDRej from BER/DER format.
func (v *RejectInvokeIDRej) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for RejectInvokeIDRej CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RejectInvokeIDRej: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding RejectInvokeIDRej CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RejectInvokeIDRej", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = RejectInvokeIDRejChoiceDerivable
		decVal, _, intErr := ber.DecodeInteger(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding derivable: %w", intErr)
		}
		tmp := InvokeIdType(decVal)
		v.Derivable = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
		v.Choice = RejectInvokeIDRejChoiceNotDerivable
		_, nullErr := ber.DecodeNull(choiceData)
		if nullErr != nil {
			return fmt.Errorf("decoding not-derivable: %w", nullErr)
		}
	} else {
		return fmt.Errorf("unknown tag %s for RejectInvokeIDRej CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes DumRejectProblem to BER format.
func (v *DumRejectProblem) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case DumRejectProblemChoiceGeneralProblem:
		if v.GeneralProblem == nil {
			return nil, fmt.Errorf("choice DumRejectProblem: generalProblem is nil")
		}
		enc_0 := ber.EncodeBigInt(v.GeneralProblem.BigInt())
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case DumRejectProblemChoiceInvokeProblem:
		if v.InvokeProblem == nil {
			return nil, fmt.Errorf("choice DumRejectProblem: invokeProblem is nil")
		}
		enc_1 := ber.EncodeBigInt(v.InvokeProblem.BigInt())
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	case DumRejectProblemChoiceReturnResultProblem:
		if v.ReturnResultProblem == nil {
			return nil, fmt.Errorf("choice DumRejectProblem: returnResultProblem is nil")
		}
		enc_2 := ber.EncodeBigInt(v.ReturnResultProblem.BigInt())
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_2)
		return enc_2, nil
	case DumRejectProblemChoiceReturnErrorProblem:
		if v.ReturnErrorProblem == nil {
			return nil, fmt.Errorf("choice DumRejectProblem: returnErrorProblem is nil")
		}
		enc_3 := ber.EncodeBigInt(v.ReturnErrorProblem.BigInt())
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DumRejectProblem", v.Choice)
	}
}

// MarshalDER encodes DumRejectProblem to DER format.
func (v *DumRejectProblem) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes DumRejectProblem from BER/DER format.
func (v *DumRejectProblem) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for DumRejectProblem CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DumRejectProblem: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding DumRejectProblem CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DumRejectProblem", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = DumRejectProblemChoiceGeneralProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding generalProblem: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding generalProblem: %w", intErr)
		}
		var named_generalproblem DumGeneralProblem
		if namedErr := named_generalproblem.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding generalProblem: %w", namedErr)
		}
		v.GeneralProblem = &named_generalproblem
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = DumRejectProblemChoiceInvokeProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding invokeProblem: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding invokeProblem: %w", intErr)
		}
		var named_invokeproblem DumInvokeProblem
		if namedErr := named_invokeproblem.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding invokeProblem: %w", namedErr)
		}
		v.InvokeProblem = &named_invokeproblem
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = DumRejectProblemChoiceReturnResultProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResultProblem: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding returnResultProblem: %w", intErr)
		}
		var named_returnresultproblem DumReturnResultProblem
		if namedErr := named_returnresultproblem.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding returnResultProblem: %w", namedErr)
		}
		v.ReturnResultProblem = &named_returnresultproblem
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = DumRejectProblemChoiceReturnErrorProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnErrorProblem: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding returnErrorProblem: %w", intErr)
		}
		var named_returnerrorproblem DumReturnErrorProblem
		if namedErr := named_returnerrorproblem.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding returnErrorProblem: %w", namedErr)
		}
		v.ReturnErrorProblem = &named_returnerrorproblem
	} else {
		return fmt.Errorf("unknown tag %s for DumRejectProblem CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes DumSendAuthenticationInfoResOldElem to BER format.
func (v *DumSendAuthenticationInfoResOldElem) MarshalBER() ([]byte, error) {
	var children []byte
	enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	children = append(children, enc_rand...)
	enc_sres := ber.EncodeOctetString([]byte(v.Sres))
	children = append(children, enc_sres...)
	enc_kc := ber.EncodeOctetString([]byte(v.Kc))
	children = append(children, enc_kc...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DumSendAuthenticationInfoResOldElem to DER format.
func (v *DumSendAuthenticationInfoResOldElem) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DumSendAuthenticationInfoResOldElem from BER/DER format.
func (v *DumSendAuthenticationInfoResOldElem) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DumSendAuthenticationInfoResOldElem SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DumSendAuthenticationInfoResOldElem", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode rand
	if offset >= len(content) {
		return fmt.Errorf("missing required field rand")
	}
	val_rand, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding rand: %w", err)
	}
	v.Rand = DumRAND(val_rand)
	offset += n
	// Decode sres
	if offset >= len(content) {
		return fmt.Errorf("missing required field sres")
	}
	val_sres, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sres: %w", err)
	}
	v.Sres = DumSRES(val_sres)
	offset += n
	// Decode kc
	if offset >= len(content) {
		return fmt.Errorf("missing required field kc")
	}
	val_kc, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding kc: %w", err)
	}
	v.Kc = DumKc(val_kc)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DumSendAuthenticationInfoResOldElem", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERPlmnContainerOperatorSSCode encodes a PlmnContainerOperatorSSCode list to BER.
func MarshalBERPlmnContainerOperatorSSCode(list PlmnContainerOperatorSSCode) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString(elem)...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERPlmnContainerOperatorSSCode decodes a PlmnContainerOperatorSSCode list from BER.
func UnmarshalBERPlmnContainerOperatorSSCode(data []byte) (PlmnContainerOperatorSSCode, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding PlmnContainerOperatorSSCode: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PlmnContainerOperatorSSCode", Cause: ber.ErrExtraData}
	}
	var result PlmnContainerOperatorSSCode
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, val)
		offset += n
	}
	return result, nil
}
