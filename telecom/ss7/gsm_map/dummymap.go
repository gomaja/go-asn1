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

	// MaxNumOfSentParameter is the integer constant for maxNumOfSentParameter.
	MaxNumOfSentParameter int64 = 6
)

// AccessTypeId returns the OID value for accessType-id.
func AccessTypeId() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 12, 2, 1107, 3, 66, 1, 1}
}

// AccessTypeNotAllowedId returns the OID value for accessTypeNotAllowed-id.
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
	berOriginal_        []byte           `json:"-"`
	berSnapshot_        []byte           `json:"-"`
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

// DumInvoke represents the ASN.1 type Invoke (SEQUENCE).
type DumInvoke struct {
	InvokeID        InvokeIdType      `asn1:""`
	LinkedID        *InvokeIdType     `asn1:"tag:0,context,implicit,optional" json:"LinkedID,omitempty"`
	OpCode          MAPOPERATION      `asn1:""`
	Invokeparameter *runtime.RawValue `asn1:",optional" json:"Invokeparameter,omitempty" asn1c:"raw-preserve"`
	berOriginal_    []byte            `asn1:"-" json:"-"`
	berSnapshot_    []byte            `asn1:"-" json:"-"`
}

// asn1c:raw-preserve
// InvokeParameter represents the ASN.1 type InvokeParameter (ANY).
type InvokeParameter = runtime.RawValue

// DumReturnResult represents the ASN.1 type ReturnResult (SEQUENCE).
type DumReturnResult struct {
	InvokeID     InvokeIdType              `asn1:""`
	Resultretres *ReturnResultResultretres `asn1:",optional" json:"Resultretres,omitempty"`
	berOriginal_ []byte                    `asn1:"-" json:"-"`
	berSnapshot_ []byte                    `asn1:"-" json:"-"`
}

// asn1c:raw-preserve
// ReturnResultParameter represents the ASN.1 type ReturnResultParameter (ANY).
type ReturnResultParameter = runtime.RawValue

// DumReturnError represents the ASN.1 type ReturnError (SEQUENCE).
type DumReturnError struct {
	InvokeID     InvokeIdType      `asn1:""`
	ErrorCode    MAPERROR          `asn1:""`
	Parameter    *runtime.RawValue `asn1:",optional" json:"Parameter,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte            `asn1:"-" json:"-"`
	berSnapshot_ []byte            `asn1:"-" json:"-"`
}

// asn1c:raw-preserve
// ReturnErrorParameter represents the ASN.1 type ReturnErrorParameter (ANY).
type ReturnErrorParameter = runtime.RawValue

// DumReject represents the ASN.1 type Reject (SEQUENCE).
type DumReject struct {
	InvokeIDRej  RejectInvokeIDRej `asn1:""`
	Problem      DumRejectProblem  `asn1:""`
	berOriginal_ []byte            `asn1:"-" json:"-"`
	berSnapshot_ []byte            `asn1:"-" json:"-"`
}

// InvokeIdType represents the ASN.1 type InvokeIdType (INTEGER).
type InvokeIdType = int64

// MAPOPERATION choice constants.
const (
	MAPOPERATIONChoiceLocalValue  = 1
	MAPOPERATIONChoiceGlobalValue = 2
)

// MAPOPERATION represents the ASN.1 CHOICE type MAP-OPERATION.
type MAPOPERATION struct {
	Choice       int
	berOriginal_ []byte                   `json:"-"`
	berSnapshot_ []byte                   `json:"-"`
	LocalValue   *OperationLocalvalue     `json:"LocalValue,omitempty"`
	GlobalValue  runtime.ObjectIdentifier `json:"GlobalValue,omitzero"`
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
	if err := local.UnmarshalText(fmt.Appendf(nil, "%d", v)); err != nil {
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

// MAPERROR represents the ASN.1 CHOICE type MAP-ERROR.
type MAPERROR struct {
	Choice       int
	berOriginal_ []byte                   `json:"-"`
	berSnapshot_ []byte                   `json:"-"`
	LocalValue   *LocalErrorcode          `json:"LocalValue,omitempty"`
	GlobalValue  runtime.ObjectIdentifier `json:"GlobalValue,omitzero"`
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
	if err := local.UnmarshalText(fmt.Appendf(nil, "%d", v)); err != nil {
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

// DumGeneralProblem represents the arbitrary-width ASN.1 INTEGER type GeneralProblem with named numbers.
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

// DumInvokeProblem represents the arbitrary-width ASN.1 INTEGER type InvokeProblem with named numbers.
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

// DumReturnResultProblem represents the arbitrary-width ASN.1 INTEGER type ReturnResultProblem with named numbers.
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

// DumReturnErrorProblem represents the arbitrary-width ASN.1 INTEGER type ReturnErrorProblem with named numbers.
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

// BssAPDU represents the ASN.1 type Bss-APDU (SEQUENCE).
type BssAPDU struct {
	ProtocolId         CommonDataTypesProtocolId             `asn1:""`
	SignalInfo         CommonDataTypesSignalInfo             `asn1:""`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
	berOriginal_       []byte                                `asn1:"-" json:"-"`
	berSnapshot_       []byte                                `asn1:"-" json:"-"`
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
	berOriginal_            []byte                                `asn1:"-" json:"-"`
	berSnapshot_            []byte                                `asn1:"-" json:"-"`
}

// ProvideSIWFSNumberRes represents the ASN.1 type ProvideSIWFSNumberRes (SEQUENCE).
type ProvideSIWFSNumberRes struct {
	SIWFSNumber        CommonDataTypesISDNAddressString      `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
	berOriginal_       []byte                                `asn1:"-" json:"-"`
	berSnapshot_       []byte                                `asn1:"-" json:"-"`
}

// CallDirection represents the ASN.1 type CallDirection (OCTET_STRING).
type CallDirection = []byte

// DumPurgeMSArgV2 represents the ASN.1 type PurgeMSArgV2 (SEQUENCE).
type DumPurgeMSArgV2 struct {
	Imsi         CommonDataTypesIMSI               `asn1:""`
	VlrNumber    *CommonDataTypesISDNAddressString `asn1:",optional" json:"VlrNumber,omitempty"`
	ExtCount_    int64                             `asn1:"-" json:"-"`
	ExtPresent_  []bool                            `asn1:"-" json:"-"`
	ExtData_     [][]byte                          `asn1:"-" json:"-"`
	berOriginal_ []byte                            `asn1:"-" json:"-"`
	berSnapshot_ []byte                            `asn1:"-" json:"-"`
}

// PrepareHOArgOld represents the ASN.1 type PrepareHO-ArgOld (SEQUENCE).
type PrepareHOArgOld struct {
	TargetCellId        *CommonDataTypesGlobalCellId `asn1:",optional" json:"TargetCellId,omitempty"`
	HoNumberNotRequired *struct{}                    `asn1:",optional" json:"HoNumberNotRequired,omitempty"`
	BssAPDU             *BssAPDU                     `asn1:",optional" json:"BssAPDU,omitempty"`
	ExtCount_           int64                        `asn1:"-" json:"-"`
	ExtPresent_         []bool                       `asn1:"-" json:"-"`
	ExtData_            [][]byte                     `asn1:"-" json:"-"`
	berOriginal_        []byte                       `asn1:"-" json:"-"`
	berSnapshot_        []byte                       `asn1:"-" json:"-"`
}

// PrepareHOResOld represents the ASN.1 type PrepareHO-ResOld (SEQUENCE).
type PrepareHOResOld struct {
	HandoverNumber *CommonDataTypesISDNAddressString `asn1:",optional" json:"HandoverNumber,omitempty"`
	BssAPDU        *BssAPDU                          `asn1:",optional" json:"BssAPDU,omitempty"`
	ExtCount_      int64                             `asn1:"-" json:"-"`
	ExtPresent_    []bool                            `asn1:"-" json:"-"`
	ExtData_       [][]byte                          `asn1:"-" json:"-"`
	berOriginal_   []byte                            `asn1:"-" json:"-"`
	berSnapshot_   []byte                            `asn1:"-" json:"-"`
}

// DumSendAuthenticationInfoResOld represents the ASN.1 type SendAuthenticationInfoResOld (SEQUENCE_OF).
type DumSendAuthenticationInfoResOld struct {
	Values       []DumSendAuthenticationInfoResOldElem `json:"Values"`
	berOriginal_ []byte                                `json:"-"`
	berSnapshot_ []byte                                `json:"-"`
}

// DumRAND represents the ASN.1 type RAND (OCTET_STRING).
type DumRAND = []byte

// DumSRES represents the ASN.1 type SRES (OCTET_STRING).
type DumSRES = []byte

// DumKc represents the ASN.1 type Kc (OCTET_STRING).
type DumKc = []byte

// DumSendIdentificationResV2 represents the ASN.1 type SendIdentificationResV2 (SEQUENCE).
type DumSendIdentificationResV2 struct {
	Imsi              *CommonDataTypesIMSI `asn1:",optional" json:"Imsi,omitempty"`
	TripletList       *TripletListold      `asn1:",optional" json:"TripletList,omitempty"`
	TripletListIndef_ bool                 `asn1:"-" json:"-"`
	ExtCount_         int64                `asn1:"-" json:"-"`
	ExtPresent_       []bool               `asn1:"-" json:"-"`
	ExtData_          [][]byte             `asn1:"-" json:"-"`
	berOriginal_      []byte               `asn1:"-" json:"-"`
	berSnapshot_      []byte               `asn1:"-" json:"-"`
}

// TripletListold represents the ASN.1 type TripletListold (SEQUENCE_OF).
type TripletListold struct {
	Values       []AuthenticationTripletV2 `json:"Values"`
	berOriginal_ []byte                    `json:"-"`
	berSnapshot_ []byte                    `json:"-"`
}

// AuthenticationTripletV2 represents the ASN.1 type AuthenticationTriplet-v2 (SEQUENCE).
type AuthenticationTripletV2 struct {
	Rand         DumRAND  `asn1:""`
	Sres         DumSRES  `asn1:""`
	Kc           DumKc    `asn1:""`
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// SIWFSSignallingModifyArg represents the ASN.1 type SIWFSSignallingModifyArg (SEQUENCE).
type SIWFSSignallingModifyArg struct {
	ChannelType        *CommonDataTypesExternalSignalInfo    `asn1:"tag:0,context,implicit,optional" json:"ChannelType,omitempty"`
	ChosenChannel      *CommonDataTypesExternalSignalInfo    `asn1:"tag:1,context,implicit,optional" json:"ChosenChannel,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
	berOriginal_       []byte                                `asn1:"-" json:"-"`
	berSnapshot_       []byte                                `asn1:"-" json:"-"`
}

// SIWFSSignallingModifyRes represents the ASN.1 type SIWFSSignallingModifyRes (SEQUENCE).
type SIWFSSignallingModifyRes struct {
	ChannelType        *CommonDataTypesExternalSignalInfo    `asn1:"tag:0,context,implicit,optional" json:"ChannelType,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
	berOriginal_       []byte                                `asn1:"-" json:"-"`
	berSnapshot_       []byte                                `asn1:"-" json:"-"`
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
	berOriginal_     []byte            `asn1:"-" json:"-"`
	berSnapshot_     []byte            `asn1:"-" json:"-"`
}

// SecureTransportErrorParam represents the ASN.1 type SecureTransportErrorParam (SEQUENCE).
type SecureTransportErrorParam struct {
	SecurityHeader   SecurityHeader    `asn1:""`
	ProtectedPayload *ProtectedPayload `asn1:",optional" json:"ProtectedPayload,omitempty"`
	berOriginal_     []byte            `asn1:"-" json:"-"`
	berSnapshot_     []byte            `asn1:"-" json:"-"`
}

// SecureTransportRes represents the ASN.1 type SecureTransportRes (SEQUENCE).
type SecureTransportRes struct {
	SecurityHeader   SecurityHeader    `asn1:""`
	ProtectedPayload *ProtectedPayload `asn1:",optional" json:"ProtectedPayload,omitempty"`
	berOriginal_     []byte            `asn1:"-" json:"-"`
	berSnapshot_     []byte            `asn1:"-" json:"-"`
}

// SecurityHeader represents the ASN.1 type SecurityHeader (SEQUENCE).
type SecurityHeader struct {
	SecurityParametersIndex     SecurityParametersIndex     `asn1:""`
	OriginalComponentIdentifier OriginalComponentIdentifier `asn1:""`
	InitialisationVector        *InitialisationVector       `asn1:",optional" json:"InitialisationVector,omitempty"`
	ExtCount_                   int64                       `asn1:"-" json:"-"`
	ExtPresent_                 []bool                      `asn1:"-" json:"-"`
	ExtData_                    [][]byte                    `asn1:"-" json:"-"`
	berOriginal_                []byte                      `asn1:"-" json:"-"`
	berSnapshot_                []byte                      `asn1:"-" json:"-"`
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
	berOriginal_  []byte         `json:"-"`
	berSnapshot_  []byte         `json:"-"`
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
	Choice       int
	berOriginal_ []byte                   `json:"-"`
	berSnapshot_ []byte                   `json:"-"`
	LocalValue   *big.Int                 `json:"LocalValue,omitempty"`
	GlobalValue  runtime.ObjectIdentifier `json:"GlobalValue,omitzero"`
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
	Choice       int
	berOriginal_ []byte                   `json:"-"`
	berSnapshot_ []byte                   `json:"-"`
	LocalValue   *big.Int                 `json:"LocalValue,omitempty"`
	GlobalValue  runtime.ObjectIdentifier `json:"GlobalValue,omitzero"`
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
	OperatorSSCode       *PlmnContainerOperatorSSCode      `asn1:"tag:4,context,implicit,optional" json:"OperatorSSCode,omitempty"`
	OperatorSSCodeIndef_ bool                              `asn1:"-" json:"-"`
	ExtCount_            int64                             `asn1:"-" json:"-"`
	ExtPresent_          []bool                            `asn1:"-" json:"-"`
	ExtData_             [][]byte                          `asn1:"-" json:"-"`
	berOriginal_         []byte                            `asn1:"-" json:"-"`
	berSnapshot_         []byte                            `asn1:"-" json:"-"`
}

// DumCategory represents the ASN.1 type Category (OCTET_STRING).
type DumCategory = []byte

// ForwardSMArg represents the ASN.1 type ForwardSM-Arg (SEQUENCE).
type ForwardSMArg struct {
	SmRPDA             SMRPDAold                 `asn1:""`
	SmRPOA             SMRPOAold                 `asn1:""`
	SmRPUI             CommonDataTypesSignalInfo `asn1:""`
	MoreMessagesToSend *struct{}                 `asn1:",optional" json:"MoreMessagesToSend,omitempty"`
	ExtCount_          int64                     `asn1:"-" json:"-"`
	ExtPresent_        []bool                    `asn1:"-" json:"-"`
	ExtData_           [][]byte                  `asn1:"-" json:"-"`
	berOriginal_       []byte                    `asn1:"-" json:"-"`
	berSnapshot_       []byte                    `asn1:"-" json:"-"`
}

// SMRPDAold choice constants.
const (
	SMRPDAoldChoiceImsi                   = 1
	SMRPDAoldChoiceLmsi                   = 2
	SMRPDAoldChoiceServiceCentreAddressDA = 3
	SMRPDAoldChoiceNoSMRPDA               = 4
)

// SMRPDAold represents the ASN.1 CHOICE type SM-RP-DAold.
type SMRPDAold struct {
	Choice                 int
	berOriginal_           []byte                        `json:"-"`
	berSnapshot_           []byte                        `json:"-"`
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

// SMRPOAold represents the ASN.1 CHOICE type SM-RP-OAold.
type SMRPOAold struct {
	Choice                 int
	berOriginal_           []byte                            `json:"-"`
	berSnapshot_           []byte                            `json:"-"`
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
	berOriginal_       []byte                             `asn1:"-" json:"-"`
	berSnapshot_       []byte                             `asn1:"-" json:"-"`
}

// SendRoutingInfoResV2 represents the ASN.1 type SendRoutingInfoResV2 (SEQUENCE).
type SendRoutingInfoResV2 struct {
	Imsi         CommonDataTypesIMSI `asn1:""`
	RoutingInfo  CHRoutingInfo       `asn1:""`
	CugCheckInfo *CHCUGCheckInfo     `asn1:",optional" json:"CugCheckInfo,omitempty"`
	ExtCount_    int64               `asn1:"-" json:"-"`
	ExtPresent_  []bool              `asn1:"-" json:"-"`
	ExtData_     [][]byte            `asn1:"-" json:"-"`
	berOriginal_ []byte              `asn1:"-" json:"-"`
	berSnapshot_ []byte              `asn1:"-" json:"-"`
}

// BeginSubscriberActivityArg represents the ASN.1 type BeginSubscriberActivityArg (SEQUENCE).
type BeginSubscriberActivityArg struct {
	Imsi                    CommonDataTypesIMSI              `asn1:""`
	OriginatingEntityNumber CommonDataTypesISDNAddressString `asn1:""`
	Msisdn                  *CommonDataTypesAddressString    `asn1:"tag:28,private,implicit,optional" json:"Msisdn,omitempty"`
	ExtCount_               int64                            `asn1:"-" json:"-"`
	ExtPresent_             []bool                           `asn1:"-" json:"-"`
	ExtData_                [][]byte                         `asn1:"-" json:"-"`
	berOriginal_            []byte                           `asn1:"-" json:"-"`
	berSnapshot_            []byte                           `asn1:"-" json:"-"`
}

// RoutingInfoForSMArgV1 represents the ASN.1 type RoutingInfoForSM-ArgV1 (SEQUENCE).
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
	berOriginal_         []byte                           `asn1:"-" json:"-"`
	berSnapshot_         []byte                           `asn1:"-" json:"-"`
}

// RoutingInfoForSMResV2 represents the ASN.1 type RoutingInfoForSM-ResV2 (SEQUENCE).
type RoutingInfoForSMResV2 struct {
	Imsi                 CommonDataTypesIMSI    `asn1:""`
	LocationInfoWithLMSI LocationInfoWithLMSIv2 `asn1:"tag:0,context,implicit"`
	MwdSet               *bool                  `asn1:"tag:2,context,implicit,optional" json:"MwdSet,omitempty"`
	MwdSetRaw_           byte                   `asn1:"-" json:"-"`
	ExtCount_            int64                  `asn1:"-" json:"-"`
	ExtPresent_          []bool                 `asn1:"-" json:"-"`
	ExtData_             [][]byte               `asn1:"-" json:"-"`
	berOriginal_         []byte                 `asn1:"-" json:"-"`
	berSnapshot_         []byte                 `asn1:"-" json:"-"`
}

// LocationInfoWithLMSIv2 represents the ASN.1 type LocationInfoWithLMSIv2 (SEQUENCE).
type LocationInfoWithLMSIv2 struct {
	LocationInfo LocationInfo         `asn1:""`
	Lmsi         *CommonDataTypesLMSI `asn1:",optional" json:"Lmsi,omitempty"`
	ExtCount_    int64                `asn1:"-" json:"-"`
	ExtPresent_  []bool               `asn1:"-" json:"-"`
	ExtData_     [][]byte             `asn1:"-" json:"-"`
	berOriginal_ []byte               `asn1:"-" json:"-"`
	berSnapshot_ []byte               `asn1:"-" json:"-"`
}

// LocationInfo choice constants.
const (
	LocationInfoChoiceRoamingNumber = 1
	LocationInfoChoiceMscNumber     = 2
)

// LocationInfo represents the ASN.1 CHOICE type LocationInfo.
type LocationInfo struct {
	Choice        int
	berOriginal_  []byte                            `json:"-"`
	berSnapshot_  []byte                            `json:"-"`
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
	RequestParameterList       *RequestParameterList       `asn1:""`
	RequestParameterListIndef_ bool                        `asn1:"-" json:"-"`
	berOriginal_               []byte                      `asn1:"-" json:"-"`
	berSnapshot_               []byte                      `asn1:"-" json:"-"`
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
type RequestParameterList struct {
	Values       []RequestParameter `json:"Values"`
	berOriginal_ []byte             `json:"-"`
	berSnapshot_ []byte             `json:"-"`
}

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
	berOriginal_      []byte                    `json:"-"`
	berSnapshot_      []byte                    `json:"-"`
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
	berOriginal_   []byte           `json:"-"`
	berSnapshot_   []byte           `json:"-"`
	TripletList    *TripletList3    `json:"TripletList,omitempty"`
	QuintupletList *QuintupletList3 `json:"QuintupletList,omitempty"`
}

// NewAuthenticationSetListOldTripletList creates a AuthenticationSetListOld with the tripletList alternative.
func NewAuthenticationSetListOldTripletList(v *TripletList3) AuthenticationSetListOld {
	return AuthenticationSetListOld{
		Choice:      AuthenticationSetListOldChoiceTripletList,
		TripletList: v,
	}
}

// NewAuthenticationSetListOldQuintupletList creates a AuthenticationSetListOld with the quintupletList alternative.
func NewAuthenticationSetListOldQuintupletList(v *QuintupletList3) AuthenticationSetListOld {
	return AuthenticationSetListOld{
		Choice:         AuthenticationSetListOldChoiceQuintupletList,
		QuintupletList: v,
	}
}

// SentParameterList represents the ASN.1 type SentParameterList (SEQUENCE_OF).
type SentParameterList struct {
	Values       []SentParameter `json:"Values"`
	berOriginal_ []byte          `json:"-"`
	berSnapshot_ []byte          `json:"-"`
}

// ResetArgV2 represents the ASN.1 type ResetArgV2 (SEQUENCE).
type ResetArgV2 struct {
	NetworkResource *CommonDataTypesNetworkResource  `asn1:",optional" json:"NetworkResource,omitempty"`
	HlrNumber       CommonDataTypesISDNAddressString `asn1:""`
	HlrList         *CommonDataTypesHLRList          `asn1:",optional" json:"HlrList,omitempty"`
	HlrListIndef_   bool                             `asn1:"-" json:"-"`
	ExtCount_       int64                            `asn1:"-" json:"-"`
	ExtPresent_     []bool                           `asn1:"-" json:"-"`
	ExtData_        [][]byte                         `asn1:"-" json:"-"`
	berOriginal_    []byte                           `asn1:"-" json:"-"`
	berSnapshot_    []byte                           `asn1:"-" json:"-"`
}

// ReturnResultResultretres represents the ASN.1 type ReturnResult-resultretres (SEQUENCE).
type ReturnResultResultretres struct {
	OpCode          MAPOPERATION      `asn1:""`
	Returnparameter *runtime.RawValue `asn1:",optional" json:"Returnparameter,omitempty" asn1c:"raw-preserve"`
	berOriginal_    []byte            `asn1:"-" json:"-"`
	berSnapshot_    []byte            `asn1:"-" json:"-"`
}

// RejectInvokeIDRej choice constants.
const (
	RejectInvokeIDRejChoiceDerivable    = 1
	RejectInvokeIDRejChoiceNotDerivable = 2
)

// RejectInvokeIDRej represents the ASN.1 CHOICE type Reject-invokeIDRej.
type RejectInvokeIDRej struct {
	Choice       int
	berOriginal_ []byte        `json:"-"`
	berSnapshot_ []byte        `json:"-"`
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

// DumRejectProblem represents the ASN.1 CHOICE type Reject-problem.
type DumRejectProblem struct {
	Choice              int
	berOriginal_        []byte                  `json:"-"`
	berSnapshot_        []byte                  `json:"-"`
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

// DumSendAuthenticationInfoResOldElem represents the ASN.1 type SendAuthenticationInfoResOld-Elem (SEQUENCE).
type DumSendAuthenticationInfoResOldElem struct {
	Rand         DumRAND  `asn1:""`
	Sres         DumSRES  `asn1:""`
	Kc           DumKc    `asn1:""`
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// PlmnContainerOperatorSSCode represents the ASN.1 type PlmnContainer-operatorSS-Code (SEQUENCE_OF).
type PlmnContainerOperatorSSCode struct {
	Values       [][]byte `json:"Values"`
	berOriginal_ []byte   `json:"-"`
	berSnapshot_ []byte   `json:"-"`
}

// MarshalBER encodes Component to BER format.
func (v *Component) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Component receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Component) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ComponentChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice Component: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding invoke: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ComponentChoiceReturnResultLast:
		if v.ReturnResultLast == nil {
			return nil, fmt.Errorf("%w: choice Component: returnResultLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultLast")...)
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultLast: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding returnResultLast: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case ComponentChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice Component: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding returnError: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case ComponentChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice Component: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding reject: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice Component: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_4, err := v.ReturnResultNotLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", err)
		}
		retagged_enc_4, tagErr_enc_4 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_4)
		if tagErr_enc_4 != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", tagErr_enc_4)
		}
		enc_4 = retagged_enc_4
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Component", v.Choice)
	}
}

// MarshalDER encodes Component to DER format.
func (v *Component) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Component receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ComponentChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice Component: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding invoke: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding invoke as DER: %w", derErr)
		}
		return enc_der_0, nil
	case ComponentChoiceReturnResultLast:
		if v.ReturnResultLast == nil {
			return nil, fmt.Errorf("%w: choice Component: returnResultLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultLast.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultLast: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding returnResultLast: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding returnResultLast as DER: %w", derErr)
		}
		return enc_der_1, nil
	case ComponentChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice Component: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, fmt.Errorf("encoding returnError: %w", tagErr_enc_der_2)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding returnError as DER: %w", derErr)
		}
		return enc_der_2, nil
	case ComponentChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice Component: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, fmt.Errorf("encoding reject: %w", tagErr_enc_der_3)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, fmt.Errorf("encoding reject as DER: %w", derErr)
		}
		return enc_der_3, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice Component: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_4, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", err)
		}
		retagged_enc_der_4, tagErr_enc_der_4 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_4)
		if tagErr_enc_der_4 != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", tagErr_enc_der_4)
		}
		enc_der_4 = retagged_enc_der_4
		if derErr := ber.ValidateDEREncodedElement(enc_der_4); derErr != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast as DER: %w", derErr)
		}
		return enc_der_4, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Component as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Component from BER/DER format.
func (v *Component) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Component destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = Component{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Component CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Component: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding Component CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Component", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ComponentChoiceInvoke
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding invoke: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec DumInvoke
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return fmt.Errorf("decoding invoke: %w", unmErr)
		}
		v.Invoke = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ComponentChoiceReturnResultLast
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResultLast: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec DumReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultLast")...); unmErr != nil {
			return fmt.Errorf("decoding returnResultLast: %w", unmErr)
		}
		v.ReturnResultLast = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ComponentChoiceReturnError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnError: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec DumReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return fmt.Errorf("decoding returnError: %w", unmErr)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ComponentChoiceReject
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding reject: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec DumReject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return fmt.Errorf("decoding reject: %w", unmErr)
		}
		v.Reject = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = ComponentChoiceReturnResultNotLast
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResultNotLast: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec DumReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultNotLast")...); unmErr != nil {
			return fmt.Errorf("decoding returnResultNotLast: %w", unmErr)
		}
		v.ReturnResultNotLast = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Component CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes DumInvoke to BER format.
func (v *DumInvoke) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DumInvoke receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DumInvoke) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.InvokeID) >= -128 && int64(v.InvokeID) <= 127) {
		if constraintErr := ber.CheckEncodedValue(opts, "invokeID", "(-128..127)", fmt.Sprint(int64(v.InvokeID))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	if v.LinkedID != nil {
		if !(int64(*v.LinkedID) >= -128 && int64(*v.LinkedID) <= 127) {
			if constraintErr := ber.CheckEncodedValue(opts, "linkedID", "(-128..127)", fmt.Sprint(int64(*v.LinkedID))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_linkedid := ber.EncodeInteger(int64(*v.LinkedID))
		retagged_enc_linkedid, tagErr_enc_linkedid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_linkedid)
		if tagErr_enc_linkedid != nil {
			return nil, fmt.Errorf("encoding linkedID: %w", tagErr_enc_linkedid)
		}
		enc_linkedid = retagged_enc_linkedid
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.OpCode.MarshalBER(ber.ChildEncodeOptions(opts, "opCode")...)
	if err != nil {
		return nil, fmt.Errorf("encoding opCode: %w", err)
	}
	children = append(children, enc_opcode...)
	if v.Invokeparameter != nil {
		enc_invokeparameter := v.Invokeparameter.Bytes
		children = append(children, enc_invokeparameter...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DumInvoke to DER format.
func (v *DumInvoke) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DumInvoke receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.InvokeID) >= -128 && int64(v.InvokeID) <= 127) {
		if constraintErr := ber.CheckEncodedValue(nil, "invokeID", "(-128..127)", fmt.Sprint(int64(v.InvokeID))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	if v.LinkedID != nil {
		if !(int64(*v.LinkedID) >= -128 && int64(*v.LinkedID) <= 127) {
			if constraintErr := ber.CheckEncodedValue(nil, "linkedID", "(-128..127)", fmt.Sprint(int64(*v.LinkedID))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_linkedid := ber.EncodeInteger(int64(*v.LinkedID))
		retagged_enc_linkedid, tagErr_enc_linkedid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_linkedid)
		if tagErr_enc_linkedid != nil {
			return nil, fmt.Errorf("encoding linkedID: %w", tagErr_enc_linkedid)
		}
		enc_linkedid = retagged_enc_linkedid
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.OpCode.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding opCode: %w", err)
	}
	children = append(children, enc_opcode...)
	if v.Invokeparameter != nil {
		enc_invokeparameter := v.Invokeparameter.Bytes
		children = append(children, enc_invokeparameter...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DumInvoke as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DumInvoke from BER/DER format.
func (v *DumInvoke) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DumInvoke destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DumInvoke{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	val_invokeid, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding invokeID: %w", err)
	}
	v.InvokeID = InvokeIdType(val_invokeid)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.InvokeID) >= -128 && int64(v.InvokeID) <= 127) {
		if constraintErr := ber.CheckDecodedValue(opts, "invokeID", "(-128..127)", fmt.Sprint(int64(v.InvokeID))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode linkedID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_linkedid, n_linkedid, rawVal_linkedid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding linkedID: %w", err)
				}
				if decodedTag_linkedid.Class != tag.ClassContextSpecific || decodedTag_linkedid.Number != 0 || decodedTag_linkedid.Constructed != false {
					return fmt.Errorf("decoding linkedID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_linkedid)
				}
				decVal_linkedid, intErr := ber.DecodeIntegerValue(rawVal_linkedid)
				if intErr != nil {
					return fmt.Errorf("decoding linkedID: %w", intErr)
				}
				tmp_linkedid := InvokeIdType(decVal_linkedid)
				v.LinkedID = &tmp_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
				if !(int64(*v.LinkedID) >= -128 && int64(*v.LinkedID) <= 127) {
					if constraintErr := ber.CheckDecodedValue(opts, "linkedID", "(-128..127)", fmt.Sprint(int64(*v.LinkedID))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode opCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opCode")
	}
	// Decode nested CHOICE (MAPOPERATION)
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opCode: %w", tlvErr_opcode)
	}
	if offset < 0 || offset >
		len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.OpCode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opCode")...); unmErr != nil {
		return fmt.Errorf("decoding opCode: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_opcode
	// Decode invokeparameter
	if offset < len(content) {
		_, n_invokeparameter, _, tlvErr_invokeparameter := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeparameter != nil {
			return fmt.Errorf("decoding invokeparameter: %w", tlvErr_invokeparameter)
		}
		if offset < 0 || offset >
			len(content) || n_invokeparameter < 0 || n_invokeparameter >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_invokeparameter := runtime.RawValue{Bytes: content[offset : offset+n_invokeparameter]}
		v.Invokeparameter = &tmp_invokeparameter
		if offset < 0 || offset >
			len(content) || n_invokeparameter < 0 || n_invokeparameter >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeparameter
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DumInvoke", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes DumReturnResult to BER format.
func (v *DumReturnResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DumReturnResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DumReturnResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.InvokeID) >= -128 && int64(v.InvokeID) <= 127) {
		if constraintErr := ber.CheckEncodedValue(opts, "invokeID", "(-128..127)", fmt.Sprint(int64(v.InvokeID))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	if v.Resultretres != nil {
		enc_resultretres, err := v.Resultretres.MarshalBER(ber.ChildEncodeOptions(opts, "resultretres")...)
		if err != nil {
			return nil, fmt.Errorf("encoding resultretres: %w", err)
		}
		children = append(children, enc_resultretres...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DumReturnResult to DER format.
func (v *DumReturnResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DumReturnResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.InvokeID) >= -128 && int64(v.InvokeID) <= 127) {
		if constraintErr := ber.CheckEncodedValue(nil, "invokeID", "(-128..127)", fmt.Sprint(int64(v.InvokeID))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	if v.Resultretres != nil {
		enc_resultretres, err := v.Resultretres.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding resultretres: %w", err)
		}
		children = append(children, enc_resultretres...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DumReturnResult as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DumReturnResult from BER/DER format.
func (v *DumReturnResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DumReturnResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DumReturnResult{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	val_invokeid, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding invokeID: %w", err)
	}
	v.InvokeID = InvokeIdType(val_invokeid)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.InvokeID) >= -128 && int64(v.InvokeID) <= 127) {
		if constraintErr := ber.CheckDecodedValue(opts, "invokeID", "(-128..127)", fmt.Sprint(int64(v.InvokeID))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode resultretres
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ReturnResultResultretres)
				_, n_resultretres, _, tlvErr_resultretres := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_resultretres != nil {
					return fmt.Errorf("decoding resultretres: %w", tlvErr_resultretres)
				}
				var dec_resultretres ReturnResultResultretres
				if offset < 0 || offset >
					len(content) || n_resultretres < 0 || n_resultretres > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_resultretres.UnmarshalBER(content[offset:offset+n_resultretres], ber.ChildDecodeOptions(opts, "resultretres")...); unmErr != nil {
					return fmt.Errorf("decoding resultretres: %w", unmErr)
				}
				v.Resultretres = &dec_resultretres
				if offset < 0 || offset >
					len(content) || n_resultretres < 0 || n_resultretres > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
func (v *DumReturnError) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DumReturnError receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DumReturnError) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.InvokeID) >= -128 && int64(v.InvokeID) <= 127) {
		if constraintErr := ber.CheckEncodedValue(opts, "invokeID", "(-128..127)", fmt.Sprint(int64(v.InvokeID))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	enc_errorcode, err := v.ErrorCode.MarshalBER(ber.ChildEncodeOptions(opts, "errorCode")...)
	if err != nil {
		return nil, fmt.Errorf("encoding errorCode: %w", err)
	}
	children = append(children, enc_errorcode...)
	if v.Parameter != nil {
		enc_parameter := v.Parameter.Bytes
		children = append(children, enc_parameter...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DumReturnError to DER format.
func (v *DumReturnError) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DumReturnError receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.InvokeID) >= -128 && int64(v.InvokeID) <= 127) {
		if constraintErr := ber.CheckEncodedValue(nil, "invokeID", "(-128..127)", fmt.Sprint(int64(v.InvokeID))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	enc_errorcode, err := v.ErrorCode.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding errorCode: %w", err)
	}
	children = append(children, enc_errorcode...)
	if v.Parameter != nil {
		enc_parameter := v.Parameter.Bytes
		children = append(children, enc_parameter...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DumReturnError as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DumReturnError from BER/DER format.
func (v *DumReturnError) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DumReturnError destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DumReturnError{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	val_invokeid, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding invokeID: %w", err)
	}
	v.InvokeID = InvokeIdType(val_invokeid)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.InvokeID) >= -128 && int64(v.InvokeID) <= 127) {
		if constraintErr := ber.CheckDecodedValue(opts, "invokeID", "(-128..127)", fmt.Sprint(int64(v.InvokeID))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode errorCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field errorCode")
	}
	// Decode nested CHOICE (MAPERROR)
	_, n_errorcode, _, tlvErr_errorcode := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_errorcode != nil {
		return fmt.Errorf("decoding errorCode: %w", tlvErr_errorcode)
	}
	if offset < 0 || offset >
		len(content) || n_errorcode < 0 || n_errorcode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.ErrorCode.UnmarshalBER(content[offset:offset+n_errorcode], ber.ChildDecodeOptions(opts, "errorCode")...); unmErr != nil {
		return fmt.Errorf("decoding errorCode: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_errorcode < 0 || n_errorcode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_errorcode
	// Decode parameter
	if offset < len(content) {
		_, n_parameter, _, tlvErr_parameter := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_parameter != nil {
			return fmt.Errorf("decoding parameter: %w", tlvErr_parameter)
		}
		if offset < 0 || offset >
			len(content) || n_parameter < 0 || n_parameter > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_parameter := runtime.RawValue{Bytes: content[offset : offset+n_parameter]}
		v.Parameter = &tmp_parameter
		if offset < 0 || offset >
			len(content) || n_parameter < 0 || n_parameter > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_parameter
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DumReturnError", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes DumReject to BER format.
func (v *DumReject) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DumReject receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DumReject) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeidrej, err := v.InvokeIDRej.MarshalBER(ber.ChildEncodeOptions(opts, "invokeIDRej")...)
	if err != nil {
		return nil, fmt.Errorf("encoding invokeIDRej: %w", err)
	}
	children = append(children, enc_invokeidrej...)
	enc_problem, err := v.Problem.MarshalBER(ber.ChildEncodeOptions(opts, "problem")...)
	if err != nil {
		return nil, fmt.Errorf("encoding problem: %w", err)
	}
	children = append(children, enc_problem...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DumReject to DER format.
func (v *DumReject) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DumReject receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeidrej, err := v.InvokeIDRej.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding invokeIDRej: %w", err)
	}
	children = append(children, enc_invokeidrej...)
	enc_problem, err := v.Problem.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding problem: %w", err)
	}
	children = append(children, enc_problem...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DumReject as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DumReject from BER/DER format.
func (v *DumReject) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DumReject destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DumReject{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	_, n_invokeidrej, _, tlvErr_invokeidrej := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_invokeidrej != nil {
		return fmt.Errorf("decoding invokeIDRej: %w", tlvErr_invokeidrej)
	}
	if offset > len(content) || n_invokeidrej < 0 || n_invokeidrej > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.InvokeIDRej.UnmarshalBER(content[offset:offset+n_invokeidrej], ber.ChildDecodeOptions(opts, "invokeIDRej")...); unmErr != nil {
		return fmt.Errorf("decoding invokeIDRej: %w", unmErr)
	}
	if offset > len(content) || n_invokeidrej < 0 || n_invokeidrej > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_invokeidrej
	// Decode problem
	if offset >= len(content) {
		return fmt.Errorf("missing required field problem")
	}
	// Decode nested CHOICE (DumRejectProblem)
	_, n_problem, _, tlvErr_problem := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_problem != nil {
		return fmt.Errorf("decoding problem: %w", tlvErr_problem)
	}
	if offset < 0 || offset >
		len(content) || n_problem < 0 || n_problem > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.Problem.UnmarshalBER(content[offset:offset+n_problem], ber.ChildDecodeOptions(opts, "problem")...); unmErr != nil {
		return fmt.Errorf("decoding problem: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_problem < 0 || n_problem > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_problem
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DumReject", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes MAPOPERATION to BER format.
func (v *MAPOPERATION) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: MAPOPERATION receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MAPOPERATION) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case MAPOPERATIONChoiceLocalValue:
		if v.LocalValue == nil {
			return nil, fmt.Errorf("%w: choice MAPOPERATION: localValue is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.LocalValue.BigInt())
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding localValue: %w", encodeErr_enc_0)
		}
		return enc_0, nil
	case MAPOPERATIONChoiceGlobalValue:
		enc_1, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.GlobalValue))
		if oidErr != nil {
			return nil, fmt.Errorf("encoding globalValue: %w", oidErr)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for MAPOPERATION", v.Choice)
	}
}

// MarshalDER encodes MAPOPERATION to DER format.
func (v *MAPOPERATION) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MAPOPERATION receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MAPOPERATION as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MAPOPERATION from BER/DER format.
func (v *MAPOPERATION) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MAPOPERATION destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MAPOPERATION{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for MAPOPERATION CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for MAPOPERATION: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding MAPOPERATION CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPOPERATION", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = MAPOPERATIONChoiceLocalValue
		decVal, _, intErr := ber.DecodeBigInt(choiceData, opts...)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		var named_localvalue OperationLocalvalue
		if namedErr := named_localvalue.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding localValue: %w", namedErr)
		}
		v.LocalValue = &named_localvalue
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 && peekTag.Constructed == false {
		v.Choice = MAPOPERATIONChoiceGlobalValue
		decVal, _, oidErr := ber.DecodeObjectIdentifier(choiceData, opts...)
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
func (v *MAPERROR) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: MAPERROR receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MAPERROR) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case MAPERRORChoiceLocalValue:
		if v.LocalValue == nil {
			return nil, fmt.Errorf("%w: choice MAPERROR: localValue is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.LocalValue.BigInt())
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding localValue: %w", encodeErr_enc_0)
		}
		return enc_0, nil
	case MAPERRORChoiceGlobalValue:
		enc_1, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.GlobalValue))
		if oidErr != nil {
			return nil, fmt.Errorf("encoding globalValue: %w", oidErr)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for MAPERROR", v.Choice)
	}
}

// MarshalDER encodes MAPERROR to DER format.
func (v *MAPERROR) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MAPERROR receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MAPERROR as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MAPERROR from BER/DER format.
func (v *MAPERROR) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MAPERROR destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MAPERROR{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for MAPERROR CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for MAPERROR: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding MAPERROR CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPERROR", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = MAPERRORChoiceLocalValue
		decVal, _, intErr := ber.DecodeBigInt(choiceData, opts...)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		var named_localvalue LocalErrorcode
		if namedErr := named_localvalue.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return fmt.Errorf("decoding localValue: %w", namedErr)
		}
		v.LocalValue = &named_localvalue
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 && peekTag.Constructed == false {
		v.Choice = MAPERRORChoiceGlobalValue
		decVal, _, oidErr := ber.DecodeObjectIdentifier(choiceData, opts...)
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
func (v *BssAPDU) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BssAPDU receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BssAPDU) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := ber.CheckEncodedValue(opts, "protocolId", "ENUMERATED {1, 2, 3, 4}", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes BssAPDU to DER format.
func (v *BssAPDU) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BssAPDU receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := ber.CheckEncodedValue(nil, "protocolId", "ENUMERATED {1, 2, 3, 4}", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(nil, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BssAPDU as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BssAPDU from BER/DER format.
func (v *BssAPDU) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BssAPDU destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = BssAPDU{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	val_protocolid, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding protocolId: %w", err)
	}
	v.ProtocolId = CommonDataTypesProtocolId(val_protocolid)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := ber.CheckDecodedValue(opts, "protocolId", "ENUMERATED {1, 2, 3, 4}", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = CommonDataTypesSignalInfo(val_signalinfo)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckDecodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "BssAPDU", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "BssAPDU", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProvideSIWFSNumberArg to BER format.
func (v *ProvideSIWFSNumberArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ProvideSIWFSNumberArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ProvideSIWFSNumberArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalBER(ber.ChildEncodeOptions(opts, "gsm-BearerCapability")...)
	if err != nil {
		return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", err)
	}
	retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_gsmbearercapability)
	if tagErr_enc_gsmbearercapability != nil {
		return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", tagErr_enc_gsmbearercapability)
	}
	enc_gsmbearercapability = retagged_enc_gsmbearercapability
	children = append(children, enc_gsmbearercapability...)
	enc_isdnbearercapability, err := v.IsdnBearerCapability.MarshalBER(ber.ChildEncodeOptions(opts, "isdn-BearerCapability")...)
	if err != nil {
		return nil, fmt.Errorf("encoding isdn-BearerCapability: %w", err)
	}
	retagged_enc_isdnbearercapability, tagErr_enc_isdnbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_isdnbearercapability)
	if tagErr_enc_isdnbearercapability != nil {
		return nil, fmt.Errorf("encoding isdn-BearerCapability: %w", tagErr_enc_isdnbearercapability)
	}
	enc_isdnbearercapability = retagged_enc_isdnbearercapability
	children = append(children, enc_isdnbearercapability...)
	if len(v.CallDirection) < 1 || len(v.CallDirection) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "call-Direction", "SIZE (1)", len(v.CallDirection)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_calldirection, encodeErr_enc_calldirection := ber.EncodeOctetString([]byte(v.CallDirection))
	if encodeErr_enc_calldirection != nil {
		return nil, fmt.Errorf("encoding call-Direction: %w", encodeErr_enc_calldirection)
	}
	retagged_enc_calldirection, tagErr_enc_calldirection := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_calldirection)
	if tagErr_enc_calldirection != nil {
		return nil, fmt.Errorf("encoding call-Direction: %w", tagErr_enc_calldirection)
	}
	enc_calldirection = retagged_enc_calldirection
	children = append(children, enc_calldirection...)
	if len(v.BSubscriberAddress) < 1 || len(v.BSubscriberAddress) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "b-Subscriber-Address", "SIZE (1..9)", len(v.BSubscriberAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.BSubscriberAddress) < 1 || len(v.BSubscriberAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "b-Subscriber-Address", "SIZE (1..20)", len(v.BSubscriberAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_bsubscriberaddress, encodeErr_enc_bsubscriberaddress := ber.EncodeOctetString([]byte(v.BSubscriberAddress))
	if encodeErr_enc_bsubscriberaddress != nil {
		return nil, fmt.Errorf("encoding b-Subscriber-Address: %w", encodeErr_enc_bsubscriberaddress)
	}
	retagged_enc_bsubscriberaddress, tagErr_enc_bsubscriberaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_bsubscriberaddress)
	if tagErr_enc_bsubscriberaddress != nil {
		return nil, fmt.Errorf("encoding b-Subscriber-Address: %w", tagErr_enc_bsubscriberaddress)
	}
	enc_bsubscriberaddress = retagged_enc_bsubscriberaddress
	children = append(children, enc_bsubscriberaddress...)
	enc_chosenchannel, err := v.ChosenChannel.MarshalBER(ber.ChildEncodeOptions(opts, "chosenChannel")...)
	if err != nil {
		return nil, fmt.Errorf("encoding chosenChannel: %w", err)
	}
	retagged_enc_chosenchannel, tagErr_enc_chosenchannel := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_chosenchannel)
	if tagErr_enc_chosenchannel != nil {
		return nil, fmt.Errorf("encoding chosenChannel: %w", tagErr_enc_chosenchannel)
	}
	enc_chosenchannel = retagged_enc_chosenchannel
	children = append(children, enc_chosenchannel...)
	if v.LowerLayerCompatibility != nil {
		enc_lowerlayercompatibility, err := v.LowerLayerCompatibility.MarshalBER(ber.ChildEncodeOptions(opts, "lowerLayerCompatibility")...)
		if err != nil {
			return nil, fmt.Errorf("encoding lowerLayerCompatibility: %w", err)
		}
		retagged_enc_lowerlayercompatibility, tagErr_enc_lowerlayercompatibility := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lowerlayercompatibility)
		if tagErr_enc_lowerlayercompatibility != nil {
			return nil, fmt.Errorf("encoding lowerLayerCompatibility: %w", tagErr_enc_lowerlayercompatibility)
		}
		enc_lowerlayercompatibility = retagged_enc_lowerlayercompatibility
		children = append(children, enc_lowerlayercompatibility...)
	}
	if v.HighLayerCompatibility != nil {
		enc_highlayercompatibility, err := v.HighLayerCompatibility.MarshalBER(ber.ChildEncodeOptions(opts, "highLayerCompatibility")...)
		if err != nil {
			return nil, fmt.Errorf("encoding highLayerCompatibility: %w", err)
		}
		retagged_enc_highlayercompatibility, tagErr_enc_highlayercompatibility := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_highlayercompatibility)
		if tagErr_enc_highlayercompatibility != nil {
			return nil, fmt.Errorf("encoding highLayerCompatibility: %w", tagErr_enc_highlayercompatibility)
		}
		enc_highlayercompatibility = retagged_enc_highlayercompatibility
		children = append(children, enc_highlayercompatibility...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ProvideSIWFSNumberArg to DER format.
func (v *ProvideSIWFSNumberArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ProvideSIWFSNumberArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", err)
	}
	retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_gsmbearercapability)
	if tagErr_enc_gsmbearercapability != nil {
		return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", tagErr_enc_gsmbearercapability)
	}
	enc_gsmbearercapability = retagged_enc_gsmbearercapability
	children = append(children, enc_gsmbearercapability...)
	enc_isdnbearercapability, err := v.IsdnBearerCapability.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding isdn-BearerCapability: %w", err)
	}
	retagged_enc_isdnbearercapability, tagErr_enc_isdnbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_isdnbearercapability)
	if tagErr_enc_isdnbearercapability != nil {
		return nil, fmt.Errorf("encoding isdn-BearerCapability: %w", tagErr_enc_isdnbearercapability)
	}
	enc_isdnbearercapability = retagged_enc_isdnbearercapability
	children = append(children, enc_isdnbearercapability...)
	if len(v.CallDirection) < 1 || len(v.CallDirection) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "call-Direction", "SIZE (1)", len(v.CallDirection)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_calldirection, encodeErr_enc_calldirection := ber.EncodeOctetString([]byte(v.CallDirection))
	if encodeErr_enc_calldirection != nil {
		return nil, fmt.Errorf("encoding call-Direction: %w", encodeErr_enc_calldirection)
	}
	retagged_enc_calldirection, tagErr_enc_calldirection := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_calldirection)
	if tagErr_enc_calldirection != nil {
		return nil, fmt.Errorf("encoding call-Direction: %w", tagErr_enc_calldirection)
	}
	enc_calldirection = retagged_enc_calldirection
	children = append(children, enc_calldirection...)
	if len(v.BSubscriberAddress) < 1 || len(v.BSubscriberAddress) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "b-Subscriber-Address", "SIZE (1..9)", len(v.BSubscriberAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.BSubscriberAddress) < 1 || len(v.BSubscriberAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "b-Subscriber-Address", "SIZE (1..20)", len(v.BSubscriberAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_bsubscriberaddress, encodeErr_enc_bsubscriberaddress := ber.EncodeOctetString([]byte(v.BSubscriberAddress))
	if encodeErr_enc_bsubscriberaddress != nil {
		return nil, fmt.Errorf("encoding b-Subscriber-Address: %w", encodeErr_enc_bsubscriberaddress)
	}
	retagged_enc_bsubscriberaddress, tagErr_enc_bsubscriberaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_bsubscriberaddress)
	if tagErr_enc_bsubscriberaddress != nil {
		return nil, fmt.Errorf("encoding b-Subscriber-Address: %w", tagErr_enc_bsubscriberaddress)
	}
	enc_bsubscriberaddress = retagged_enc_bsubscriberaddress
	children = append(children, enc_bsubscriberaddress...)
	enc_chosenchannel, err := v.ChosenChannel.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding chosenChannel: %w", err)
	}
	retagged_enc_chosenchannel, tagErr_enc_chosenchannel := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_chosenchannel)
	if tagErr_enc_chosenchannel != nil {
		return nil, fmt.Errorf("encoding chosenChannel: %w", tagErr_enc_chosenchannel)
	}
	enc_chosenchannel = retagged_enc_chosenchannel
	children = append(children, enc_chosenchannel...)
	if v.LowerLayerCompatibility != nil {
		enc_lowerlayercompatibility, err := v.LowerLayerCompatibility.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding lowerLayerCompatibility: %w", err)
		}
		retagged_enc_lowerlayercompatibility, tagErr_enc_lowerlayercompatibility := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lowerlayercompatibility)
		if tagErr_enc_lowerlayercompatibility != nil {
			return nil, fmt.Errorf("encoding lowerLayerCompatibility: %w", tagErr_enc_lowerlayercompatibility)
		}
		enc_lowerlayercompatibility = retagged_enc_lowerlayercompatibility
		children = append(children, enc_lowerlayercompatibility...)
	}
	if v.HighLayerCompatibility != nil {
		enc_highlayercompatibility, err := v.HighLayerCompatibility.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding highLayerCompatibility: %w", err)
		}
		retagged_enc_highlayercompatibility, tagErr_enc_highlayercompatibility := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_highlayercompatibility)
		if tagErr_enc_highlayercompatibility != nil {
			return nil, fmt.Errorf("encoding highLayerCompatibility: %w", tagErr_enc_highlayercompatibility)
		}
		enc_highlayercompatibility = retagged_enc_highlayercompatibility
		children = append(children, enc_highlayercompatibility...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ProvideSIWFSNumberArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ProvideSIWFSNumberArg from BER/DER format.
func (v *ProvideSIWFSNumberArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ProvideSIWFSNumberArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ProvideSIWFSNumberArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	decodedTag_gsmbearercapability, n_gsmbearercapability, rawVal_gsmbearercapability, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding gsm-BearerCapability: %w", err)
	}
	if decodedTag_gsmbearercapability.Class != tag.ClassContextSpecific || decodedTag_gsmbearercapability.Number != 0 || decodedTag_gsmbearercapability.Constructed != true {
		return fmt.Errorf("decoding gsm-BearerCapability: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gsmbearercapability)
	}
	reconstructed_gsmbearercapability, reconstructionErr_gsmbearercapability := ber.EncodeSequence(rawVal_gsmbearercapability)
	if reconstructionErr_gsmbearercapability != nil {
		return fmt.Errorf("decoding gsm-BearerCapability: %w", reconstructionErr_gsmbearercapability)
	}
	if unmErr := v.GsmBearerCapability.UnmarshalBER(reconstructed_gsmbearercapability, ber.ChildDecodeOptions(opts, "gsm-BearerCapability")...); unmErr != nil {
		return fmt.Errorf("decoding gsm-BearerCapability: %w", unmErr)
	}
	if offset > len(content) || n_gsmbearercapability < 0 || n_gsmbearercapability > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
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
	decodedTag_isdnbearercapability, n_isdnbearercapability, rawVal_isdnbearercapability, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding isdn-BearerCapability: %w", err)
	}
	if decodedTag_isdnbearercapability.Class != tag.ClassContextSpecific || decodedTag_isdnbearercapability.Number != 1 || decodedTag_isdnbearercapability.Constructed != true {
		return fmt.Errorf("decoding isdn-BearerCapability: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_isdnbearercapability)
	}
	reconstructed_isdnbearercapability, reconstructionErr_isdnbearercapability := ber.EncodeSequence(rawVal_isdnbearercapability)
	if reconstructionErr_isdnbearercapability != nil {
		return fmt.Errorf("decoding isdn-BearerCapability: %w", reconstructionErr_isdnbearercapability)
	}
	if unmErr := v.IsdnBearerCapability.UnmarshalBER(reconstructed_isdnbearercapability, ber.ChildDecodeOptions(opts, "isdn-BearerCapability")...); unmErr != nil {
		return fmt.Errorf("decoding isdn-BearerCapability: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_isdnbearercapability < 0 || n_isdnbearercapability >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
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
	decodedTag_calldirection, n_calldirection, rawVal_calldirection, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding call-Direction: %w", err)
	}
	if decodedTag_calldirection.Class != tag.ClassContextSpecific || decodedTag_calldirection.Number != 2 {
		return fmt.Errorf("decoding call-Direction: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_calldirection)
	}
	decVal_calldirection, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_calldirection.Constructed, rawVal_calldirection, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding call-Direction: %w", octetErr)
	}
	v.CallDirection = CallDirection(decVal_calldirection)
	if offset < 0 || offset >
		len(content) || n_calldirection < 0 || n_calldirection > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_calldirection
	if len(v.CallDirection) < 1 || len(v.CallDirection) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "call-Direction", "SIZE (1)", len(v.CallDirection)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode b-Subscriber-Address
	if offset >= len(content) {
		return fmt.Errorf("missing required field b-Subscriber-Address")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for b-Subscriber-Address, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	decodedTag_bsubscriberaddress, n_bsubscriberaddress, rawVal_bsubscriberaddress, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding b-Subscriber-Address: %w", err)
	}
	if decodedTag_bsubscriberaddress.Class != tag.ClassContextSpecific || decodedTag_bsubscriberaddress.Number != 3 {
		return fmt.Errorf("decoding b-Subscriber-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bsubscriberaddress)
	}
	decVal_bsubscriberaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_bsubscriberaddress.Constructed, rawVal_bsubscriberaddress, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding b-Subscriber-Address: %w", octetErr)
	}
	v.BSubscriberAddress = CommonDataTypesISDNAddressString(decVal_bsubscriberaddress)
	if offset < 0 || offset >
		len(content) || n_bsubscriberaddress < 0 || n_bsubscriberaddress >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_bsubscriberaddress
	if len(v.BSubscriberAddress) < 1 || len(v.BSubscriberAddress) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "b-Subscriber-Address", "SIZE (1..9)", len(v.BSubscriberAddress)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.BSubscriberAddress) < 1 || len(v.BSubscriberAddress) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "b-Subscriber-Address", "SIZE (1..20)", len(v.BSubscriberAddress)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode chosenChannel
	if offset >= len(content) {
		return fmt.Errorf("missing required field chosenChannel")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for chosenChannel, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	decodedTag_chosenchannel, n_chosenchannel, rawVal_chosenchannel, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding chosenChannel: %w", err)
	}
	if decodedTag_chosenchannel.Class != tag.ClassContextSpecific || decodedTag_chosenchannel.Number != 4 || decodedTag_chosenchannel.Constructed != true {
		return fmt.Errorf("decoding chosenChannel: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_chosenchannel)
	}
	reconstructed_chosenchannel, reconstructionErr_chosenchannel := ber.EncodeSequence(rawVal_chosenchannel)
	if reconstructionErr_chosenchannel != nil {
		return fmt.Errorf("decoding chosenChannel: %w", reconstructionErr_chosenchannel)
	}
	if unmErr := v.ChosenChannel.UnmarshalBER(reconstructed_chosenchannel, ber.ChildDecodeOptions(opts, "chosenChannel")...); unmErr != nil {
		return fmt.Errorf("decoding chosenChannel: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_chosenchannel < 0 || n_chosenchannel > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_chosenchannel
	// Decode lowerLayerCompatibility
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_lowerlayercompatibility, n_lowerlayercompatibility, rawVal_lowerlayercompatibility, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lowerLayerCompatibility: %w", err)
				}
				if decodedTag_lowerlayercompatibility.Class != tag.ClassContextSpecific || decodedTag_lowerlayercompatibility.Number != 5 || decodedTag_lowerlayercompatibility.Constructed != true {
					return fmt.Errorf("decoding lowerLayerCompatibility: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lowerlayercompatibility)
				}
				reconstructed_lowerlayercompatibility, reconstructionErr_lowerlayercompatibility := ber.EncodeSequence(rawVal_lowerlayercompatibility)
				if reconstructionErr_lowerlayercompatibility != nil {
					return fmt.Errorf("decoding lowerLayerCompatibility: %w", reconstructionErr_lowerlayercompatibility)
				}
				var dec_lowerlayercompatibility CommonDataTypesExternalSignalInfo
				if unmErr := dec_lowerlayercompatibility.UnmarshalBER(reconstructed_lowerlayercompatibility, ber.ChildDecodeOptions(opts, "lowerLayerCompatibility")...); unmErr != nil {
					return fmt.Errorf("decoding lowerLayerCompatibility: %w", unmErr)
				}
				v.LowerLayerCompatibility = &dec_lowerlayercompatibility
				if offset < 0 || offset >
					len(content) || n_lowerlayercompatibility < 0 || n_lowerlayercompatibility >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lowerlayercompatibility
			}
		}
	}
	// Decode highLayerCompatibility
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_highlayercompatibility, n_highlayercompatibility, rawVal_highlayercompatibility, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding highLayerCompatibility: %w", err)
				}
				if decodedTag_highlayercompatibility.Class != tag.ClassContextSpecific || decodedTag_highlayercompatibility.Number != 6 || decodedTag_highlayercompatibility.Constructed != true {
					return fmt.Errorf("decoding highLayerCompatibility: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_highlayercompatibility)
				}
				reconstructed_highlayercompatibility, reconstructionErr_highlayercompatibility := ber.EncodeSequence(rawVal_highlayercompatibility)
				if reconstructionErr_highlayercompatibility != nil {
					return fmt.Errorf("decoding highLayerCompatibility: %w", reconstructionErr_highlayercompatibility)
				}
				var dec_highlayercompatibility CommonDataTypesExternalSignalInfo
				if unmErr := dec_highlayercompatibility.UnmarshalBER(reconstructed_highlayercompatibility, ber.ChildDecodeOptions(opts, "highLayerCompatibility")...); unmErr != nil {
					return fmt.Errorf("decoding highLayerCompatibility: %w", unmErr)
				}
				v.HighLayerCompatibility = &dec_highlayercompatibility
				if offset < 0 || offset >
					len(content) || n_highlayercompatibility < 0 || n_highlayercompatibility >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_highlayercompatibility
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 7 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProvideSIWFSNumberArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ProvideSIWFSNumberArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProvideSIWFSNumberRes to BER format.
func (v *ProvideSIWFSNumberRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ProvideSIWFSNumberRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ProvideSIWFSNumberRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SIWFSNumber) < 1 || len(v.SIWFSNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "sIWFSNumber", "SIZE (1..9)", len(v.SIWFSNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.SIWFSNumber) < 1 || len(v.SIWFSNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "sIWFSNumber", "SIZE (1..20)", len(v.SIWFSNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_siwfsnumber, encodeErr_enc_siwfsnumber := ber.EncodeOctetString([]byte(v.SIWFSNumber))
	if encodeErr_enc_siwfsnumber != nil {
		return nil, fmt.Errorf("encoding sIWFSNumber: %w", encodeErr_enc_siwfsnumber)
	}
	retagged_enc_siwfsnumber, tagErr_enc_siwfsnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_siwfsnumber)
	if tagErr_enc_siwfsnumber != nil {
		return nil, fmt.Errorf("encoding sIWFSNumber: %w", tagErr_enc_siwfsnumber)
	}
	enc_siwfsnumber = retagged_enc_siwfsnumber
	children = append(children, enc_siwfsnumber...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ProvideSIWFSNumberRes to DER format.
func (v *ProvideSIWFSNumberRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ProvideSIWFSNumberRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SIWFSNumber) < 1 || len(v.SIWFSNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "sIWFSNumber", "SIZE (1..9)", len(v.SIWFSNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.SIWFSNumber) < 1 || len(v.SIWFSNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "sIWFSNumber", "SIZE (1..20)", len(v.SIWFSNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_siwfsnumber, encodeErr_enc_siwfsnumber := ber.EncodeOctetString([]byte(v.SIWFSNumber))
	if encodeErr_enc_siwfsnumber != nil {
		return nil, fmt.Errorf("encoding sIWFSNumber: %w", encodeErr_enc_siwfsnumber)
	}
	retagged_enc_siwfsnumber, tagErr_enc_siwfsnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_siwfsnumber)
	if tagErr_enc_siwfsnumber != nil {
		return nil, fmt.Errorf("encoding sIWFSNumber: %w", tagErr_enc_siwfsnumber)
	}
	enc_siwfsnumber = retagged_enc_siwfsnumber
	children = append(children, enc_siwfsnumber...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ProvideSIWFSNumberRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ProvideSIWFSNumberRes from BER/DER format.
func (v *ProvideSIWFSNumberRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ProvideSIWFSNumberRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ProvideSIWFSNumberRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	decodedTag_siwfsnumber, n_siwfsnumber, rawVal_siwfsnumber, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding sIWFSNumber: %w", err)
	}
	if decodedTag_siwfsnumber.Class != tag.ClassContextSpecific || decodedTag_siwfsnumber.Number != 0 {
		return fmt.Errorf("decoding sIWFSNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_siwfsnumber)
	}
	decVal_siwfsnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_siwfsnumber.Constructed, rawVal_siwfsnumber, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding sIWFSNumber: %w", octetErr)
	}
	v.SIWFSNumber = CommonDataTypesISDNAddressString(decVal_siwfsnumber)
	if offset > len(content) || n_siwfsnumber < 0 || n_siwfsnumber > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_siwfsnumber
	if len(v.SIWFSNumber) < 1 || len(v.SIWFSNumber) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "sIWFSNumber", "SIZE (1..9)", len(v.SIWFSNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.SIWFSNumber) < 1 || len(v.SIWFSNumber) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "sIWFSNumber", "SIZE (1..20)", len(v.SIWFSNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProvideSIWFSNumberRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ProvideSIWFSNumberRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DumPurgeMSArgV2 to BER format.
func (v *DumPurgeMSArgV2) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DumPurgeMSArgV2 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DumPurgeMSArgV2) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	children = append(children, enc_imsi...)
	if v.VlrNumber != nil {
		if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "vlr-Number", "SIZE (1..9)", len(*v.VlrNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "vlr-Number", "SIZE (1..20)", len(*v.VlrNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vlrnumber, encodeErr_enc_vlrnumber := ber.EncodeOctetString([]byte(*v.VlrNumber))
		if encodeErr_enc_vlrnumber != nil {
			return nil, fmt.Errorf("encoding vlr-Number: %w", encodeErr_enc_vlrnumber)
		}
		children = append(children, enc_vlrnumber...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DumPurgeMSArgV2 to DER format.
func (v *DumPurgeMSArgV2) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DumPurgeMSArgV2 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	children = append(children, enc_imsi...)
	if v.VlrNumber != nil {
		if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "vlr-Number", "SIZE (1..9)", len(*v.VlrNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "vlr-Number", "SIZE (1..20)", len(*v.VlrNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vlrnumber, encodeErr_enc_vlrnumber := ber.EncodeOctetString([]byte(*v.VlrNumber))
		if encodeErr_enc_vlrnumber != nil {
			return nil, fmt.Errorf("encoding vlr-Number: %w", encodeErr_enc_vlrnumber)
		}
		children = append(children, enc_vlrnumber...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DumPurgeMSArgV2 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DumPurgeMSArgV2 from BER/DER format.
func (v *DumPurgeMSArgV2) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DumPurgeMSArgV2 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DumPurgeMSArgV2{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(val_imsi)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode vlr-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_vlrnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding vlr-Number: %w", err)
				}
				tmp_vlrnumber := CommonDataTypesISDNAddressString(val_vlrnumber)
				v.VlrNumber = &tmp_vlrnumber
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "vlr-Number", "SIZE (1..9)", len(*v.VlrNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "vlr-Number", "SIZE (1..20)", len(*v.VlrNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DumPurgeMSArgV2", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "DumPurgeMSArgV2", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PrepareHOArgOld to BER format.
func (v *PrepareHOArgOld) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareHOArgOld receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PrepareHOArgOld) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.TargetCellId != nil {
		if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(*v.TargetCellId))
		if encodeErr_enc_targetcellid != nil {
			return nil, fmt.Errorf("encoding targetCellId: %w", encodeErr_enc_targetcellid)
		}
		children = append(children, enc_targetcellid...)
	}
	if v.HoNumberNotRequired != nil {
		enc_honumbernotrequired := ber.EncodeNull()
		children = append(children, enc_honumbernotrequired...)
	}
	if v.BssAPDU != nil {
		enc_bssapdu, err := v.BssAPDU.MarshalBER(ber.ChildEncodeOptions(opts, "bss-APDU")...)
		if err != nil {
			return nil, fmt.Errorf("encoding bss-APDU: %w", err)
		}
		children = append(children, enc_bssapdu...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PrepareHOArgOld to DER format.
func (v *PrepareHOArgOld) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareHOArgOld receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.TargetCellId != nil {
		if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(*v.TargetCellId))
		if encodeErr_enc_targetcellid != nil {
			return nil, fmt.Errorf("encoding targetCellId: %w", encodeErr_enc_targetcellid)
		}
		children = append(children, enc_targetcellid...)
	}
	if v.HoNumberNotRequired != nil {
		enc_honumbernotrequired := ber.EncodeNull()
		children = append(children, enc_honumbernotrequired...)
	}
	if v.BssAPDU != nil {
		enc_bssapdu, err := v.BssAPDU.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding bss-APDU: %w", err)
		}
		children = append(children, enc_bssapdu...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PrepareHOArgOld as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrepareHOArgOld from BER/DER format.
func (v *PrepareHOArgOld) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PrepareHOArgOld destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PrepareHOArgOld{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
				val_targetcellid, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding targetCellId: %w", err)
				}
				tmp_targetcellid := CommonDataTypesGlobalCellId(val_targetcellid)
				v.TargetCellId = &tmp_targetcellid
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
					if constraintErr := ber.CheckDecodedLength(opts, "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ho-NumberNotRequired
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ho-NumberNotRequired: %w", err)
				}
				v.HoNumberNotRequired = &struct{}{}
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
				_, n_bssapdu, _, tlvErr_bssapdu := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_bssapdu != nil {
					return fmt.Errorf("decoding bss-APDU: %w", tlvErr_bssapdu)
				}
				var dec_bssapdu BssAPDU
				if offset < 0 || offset >
					len(content) || n_bssapdu < 0 || n_bssapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_bssapdu.UnmarshalBER(content[offset:offset+n_bssapdu], ber.ChildDecodeOptions(opts, "bss-APDU")...); unmErr != nil {
					return fmt.Errorf("decoding bss-APDU: %w", unmErr)
				}
				v.BssAPDU = &dec_bssapdu
				if offset < 0 || offset >
					len(content) || n_bssapdu < 0 || n_bssapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bssapdu
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareHOArgOld", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "PrepareHOArgOld", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PrepareHOResOld to BER format.
func (v *PrepareHOResOld) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareHOResOld receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PrepareHOResOld) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.HandoverNumber != nil {
		if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "handoverNumber", "SIZE (1..9)", len(*v.HandoverNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "handoverNumber", "SIZE (1..20)", len(*v.HandoverNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_handovernumber, encodeErr_enc_handovernumber := ber.EncodeOctetString([]byte(*v.HandoverNumber))
		if encodeErr_enc_handovernumber != nil {
			return nil, fmt.Errorf("encoding handoverNumber: %w", encodeErr_enc_handovernumber)
		}
		children = append(children, enc_handovernumber...)
	}
	if v.BssAPDU != nil {
		enc_bssapdu, err := v.BssAPDU.MarshalBER(ber.ChildEncodeOptions(opts, "bss-APDU")...)
		if err != nil {
			return nil, fmt.Errorf("encoding bss-APDU: %w", err)
		}
		children = append(children, enc_bssapdu...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PrepareHOResOld to DER format.
func (v *PrepareHOResOld) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareHOResOld receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.HandoverNumber != nil {
		if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "handoverNumber", "SIZE (1..9)", len(*v.HandoverNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "handoverNumber", "SIZE (1..20)", len(*v.HandoverNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_handovernumber, encodeErr_enc_handovernumber := ber.EncodeOctetString([]byte(*v.HandoverNumber))
		if encodeErr_enc_handovernumber != nil {
			return nil, fmt.Errorf("encoding handoverNumber: %w", encodeErr_enc_handovernumber)
		}
		children = append(children, enc_handovernumber...)
	}
	if v.BssAPDU != nil {
		enc_bssapdu, err := v.BssAPDU.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding bss-APDU: %w", err)
		}
		children = append(children, enc_bssapdu...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PrepareHOResOld as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrepareHOResOld from BER/DER format.
func (v *PrepareHOResOld) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PrepareHOResOld destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PrepareHOResOld{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
				val_handovernumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding handoverNumber: %w", err)
				}
				tmp_handovernumber := CommonDataTypesISDNAddressString(val_handovernumber)
				v.HandoverNumber = &tmp_handovernumber
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "handoverNumber", "SIZE (1..9)", len(*v.HandoverNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.HandoverNumber) < 1 || len(*v.HandoverNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "handoverNumber", "SIZE (1..20)", len(*v.HandoverNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode bss-APDU
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (BssAPDU)
				_, n_bssapdu, _, tlvErr_bssapdu := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_bssapdu != nil {
					return fmt.Errorf("decoding bss-APDU: %w", tlvErr_bssapdu)
				}
				var dec_bssapdu BssAPDU
				if offset < 0 || offset >
					len(content) || n_bssapdu < 0 || n_bssapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_bssapdu.UnmarshalBER(content[offset:offset+n_bssapdu], ber.ChildDecodeOptions(opts, "bss-APDU")...); unmErr != nil {
					return fmt.Errorf("decoding bss-APDU: %w", unmErr)
				}
				v.BssAPDU = &dec_bssapdu
				if offset < 0 || offset >
					len(content) || n_bssapdu < 0 || n_bssapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bssapdu
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareHOResOld", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "PrepareHOResOld", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERDumSendAuthenticationInfoResOld encodes a DumSendAuthenticationInfoResOld list to BER.
func MarshalBERDumSendAuthenticationInfoResOld(collection *DumSendAuthenticationInfoResOld, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERDumSendAuthenticationInfoResOld(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERDumSendAuthenticationInfoResOld(collection *DumSendAuthenticationInfoResOld, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedLength(opts, "DumSendAuthenticationInfoResOld", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERDumSendAuthenticationInfoResOld encodes a DumSendAuthenticationInfoResOld list to DER.
func MarshalDERDumSendAuthenticationInfoResOld(collection *DumSendAuthenticationInfoResOld) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedLength(nil, "DumSendAuthenticationInfoResOld", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DumSendAuthenticationInfoResOld as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERDumSendAuthenticationInfoResOld decodes a DumSendAuthenticationInfoResOld list from BER.
func UnmarshalBERDumSendAuthenticationInfoResOld(data []byte, opts ...ber.DecodeOption) (returnValue *DumSendAuthenticationInfoResOld, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding DumSendAuthenticationInfoResOld: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "DumSendAuthenticationInfoResOld", Cause: ber.ErrExtraData}
	}
	var result []DumSendAuthenticationInfoResOldElem
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem DumSendAuthenticationInfoResOldElem
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 5 {
		if constraintErr := ber.CheckDecodedLength(opts, "DumSendAuthenticationInfoResOld", "SIZE (1..5)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &DumSendAuthenticationInfoResOld{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERDumSendAuthenticationInfoResOld(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes DumSendIdentificationResV2 to BER format.
func (v *DumSendIdentificationResV2) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DumSendIdentificationResV2 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DumSendIdentificationResV2) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		children = append(children, enc_imsi...)
	}
	if v.TripletList != nil {
		if len((v.TripletList).Values) < 1 || len((v.TripletList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "tripletList", "SIZE (1..5)", len((v.TripletList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tripletlist, err := MarshalBERTripletListold(v.TripletList, ber.ChildEncodeOptions(opts, "tripletList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding tripletList: %w", err)
		}
		children = append(children, enc_tripletlist...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DumSendIdentificationResV2 to DER format.
func (v *DumSendIdentificationResV2) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DumSendIdentificationResV2 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		children = append(children, enc_imsi...)
	}
	if v.TripletList != nil {
		if len((v.TripletList).Values) < 1 || len((v.TripletList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, "tripletList", "SIZE (1..5)", len((v.TripletList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tripletlist, err := MarshalDERTripletListold(v.TripletList)
		if err != nil {
			return nil, fmt.Errorf("encoding tripletList: %w", err)
		}
		children = append(children, enc_tripletlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DumSendIdentificationResV2 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DumSendIdentificationResV2 from BER/DER format.
func (v *DumSendIdentificationResV2) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DumSendIdentificationResV2 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DumSendIdentificationResV2{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
				val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := CommonDataTypesIMSI(val_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
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
				_, n_tripletlist, _, tlvErr_tripletlist := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_tripletlist != nil {
					return fmt.Errorf("decoding tripletList: %w", tlvErr_tripletlist)
				}
				if offset < 0 || offset >
					len(content) || n_tripletlist < 0 || n_tripletlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_tripletlist := content[offset : offset+n_tripletlist]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_tripletlist)
					if tagSz_ < len(tlv_tripletlist) && tlv_tripletlist[tagSz_] == 0x80 {
						v.TripletListIndef_ = true
					}
				}
				dec_tripletlist, unmErr := UnmarshalBERTripletListold(tlv_tripletlist, ber.ChildDecodeOptions(opts, "tripletList")...)
				if unmErr != nil {
					return fmt.Errorf("decoding tripletList: %w", unmErr)
				}
				v.TripletList = dec_tripletlist
				if offset < 0 || offset >
					len(content) || n_tripletlist < 0 || n_tripletlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tripletlist
				if len((v.TripletList).Values) < 1 || len((v.TripletList).Values) > 5 {
					if constraintErr := ber.CheckDecodedLength(opts, "tripletList", "SIZE (1..5)", len((v.TripletList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DumSendIdentificationResV2", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "DumSendIdentificationResV2", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERTripletListold encodes a TripletListold list to BER.
func MarshalBERTripletListold(collection *TripletListold, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERTripletListold(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERTripletListold(collection *TripletListold, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedLength(opts, "TripletListold", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERTripletListold encodes a TripletListold list to DER.
func MarshalDERTripletListold(collection *TripletListold) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedLength(nil, "TripletListold", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TripletListold as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERTripletListold decodes a TripletListold list from BER.
func UnmarshalBERTripletListold(data []byte, opts ...ber.DecodeOption) (returnValue *TripletListold, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding TripletListold: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TripletListold", Cause: ber.ErrExtraData}
	}
	var result []AuthenticationTripletV2
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem AuthenticationTripletV2
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 5 {
		if constraintErr := ber.CheckDecodedLength(opts, "TripletListold", "SIZE (1..5)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &TripletListold{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERTripletListold(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes AuthenticationTripletV2 to BER format.
func (v *AuthenticationTripletV2) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AuthenticationTripletV2 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AuthenticationTripletV2) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := ber.CheckEncodedLength(opts, "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_rand, encodeErr_enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	if encodeErr_enc_rand != nil {
		return nil, fmt.Errorf("encoding rand: %w", encodeErr_enc_rand)
	}
	children = append(children, enc_rand...)
	if len(v.Sres) < 4 || len(v.Sres) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sres, encodeErr_enc_sres := ber.EncodeOctetString([]byte(v.Sres))
	if encodeErr_enc_sres != nil {
		return nil, fmt.Errorf("encoding sres: %w", encodeErr_enc_sres)
	}
	children = append(children, enc_sres...)
	if len(v.Kc) < 8 || len(v.Kc) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(v.Kc))
	if encodeErr_enc_kc != nil {
		return nil, fmt.Errorf("encoding kc: %w", encodeErr_enc_kc)
	}
	children = append(children, enc_kc...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AuthenticationTripletV2 to DER format.
func (v *AuthenticationTripletV2) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AuthenticationTripletV2 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := ber.CheckEncodedLength(nil, "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_rand, encodeErr_enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	if encodeErr_enc_rand != nil {
		return nil, fmt.Errorf("encoding rand: %w", encodeErr_enc_rand)
	}
	children = append(children, enc_rand...)
	if len(v.Sres) < 4 || len(v.Sres) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sres, encodeErr_enc_sres := ber.EncodeOctetString([]byte(v.Sres))
	if encodeErr_enc_sres != nil {
		return nil, fmt.Errorf("encoding sres: %w", encodeErr_enc_sres)
	}
	children = append(children, enc_sres...)
	if len(v.Kc) < 8 || len(v.Kc) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(v.Kc))
	if encodeErr_enc_kc != nil {
		return nil, fmt.Errorf("encoding kc: %w", encodeErr_enc_kc)
	}
	children = append(children, enc_kc...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AuthenticationTripletV2 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AuthenticationTripletV2 from BER/DER format.
func (v *AuthenticationTripletV2) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AuthenticationTripletV2 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AuthenticationTripletV2{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	val_rand, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding rand: %w", err)
	}
	v.Rand = DumRAND(val_rand)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := ber.CheckDecodedLength(opts, "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode sres
	if offset >= len(content) {
		return fmt.Errorf("missing required field sres")
	}
	val_sres, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding sres: %w", err)
	}
	v.Sres = DumSRES(val_sres)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Sres) < 4 || len(v.Sres) > 4 {
		if constraintErr := ber.CheckDecodedLength(opts, "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode kc
	if offset >= len(content) {
		return fmt.Errorf("missing required field kc")
	}
	val_kc, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding kc: %w", err)
	}
	v.Kc = DumKc(val_kc)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Kc) < 8 || len(v.Kc) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AuthenticationTripletV2", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SIWFSSignallingModifyArg to BER format.
func (v *SIWFSSignallingModifyArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SIWFSSignallingModifyArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SIWFSSignallingModifyArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ChannelType != nil {
		enc_channeltype, err := v.ChannelType.MarshalBER(ber.ChildEncodeOptions(opts, "channelType")...)
		if err != nil {
			return nil, fmt.Errorf("encoding channelType: %w", err)
		}
		retagged_enc_channeltype, tagErr_enc_channeltype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_channeltype)
		if tagErr_enc_channeltype != nil {
			return nil, fmt.Errorf("encoding channelType: %w", tagErr_enc_channeltype)
		}
		enc_channeltype = retagged_enc_channeltype
		children = append(children, enc_channeltype...)
	}
	if v.ChosenChannel != nil {
		enc_chosenchannel, err := v.ChosenChannel.MarshalBER(ber.ChildEncodeOptions(opts, "chosenChannel")...)
		if err != nil {
			return nil, fmt.Errorf("encoding chosenChannel: %w", err)
		}
		retagged_enc_chosenchannel, tagErr_enc_chosenchannel := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_chosenchannel)
		if tagErr_enc_chosenchannel != nil {
			return nil, fmt.Errorf("encoding chosenChannel: %w", tagErr_enc_chosenchannel)
		}
		enc_chosenchannel = retagged_enc_chosenchannel
		children = append(children, enc_chosenchannel...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SIWFSSignallingModifyArg to DER format.
func (v *SIWFSSignallingModifyArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SIWFSSignallingModifyArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ChannelType != nil {
		enc_channeltype, err := v.ChannelType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding channelType: %w", err)
		}
		retagged_enc_channeltype, tagErr_enc_channeltype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_channeltype)
		if tagErr_enc_channeltype != nil {
			return nil, fmt.Errorf("encoding channelType: %w", tagErr_enc_channeltype)
		}
		enc_channeltype = retagged_enc_channeltype
		children = append(children, enc_channeltype...)
	}
	if v.ChosenChannel != nil {
		enc_chosenchannel, err := v.ChosenChannel.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding chosenChannel: %w", err)
		}
		retagged_enc_chosenchannel, tagErr_enc_chosenchannel := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_chosenchannel)
		if tagErr_enc_chosenchannel != nil {
			return nil, fmt.Errorf("encoding chosenChannel: %w", tagErr_enc_chosenchannel)
		}
		enc_chosenchannel = retagged_enc_chosenchannel
		children = append(children, enc_chosenchannel...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SIWFSSignallingModifyArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SIWFSSignallingModifyArg from BER/DER format.
func (v *SIWFSSignallingModifyArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SIWFSSignallingModifyArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SIWFSSignallingModifyArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
				decodedTag_channeltype, n_channeltype, rawVal_channeltype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding channelType: %w", err)
				}
				if decodedTag_channeltype.Class != tag.ClassContextSpecific || decodedTag_channeltype.Number != 0 || decodedTag_channeltype.Constructed != true {
					return fmt.Errorf("decoding channelType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_channeltype)
				}
				reconstructed_channeltype, reconstructionErr_channeltype := ber.EncodeSequence(rawVal_channeltype)
				if reconstructionErr_channeltype != nil {
					return fmt.Errorf("decoding channelType: %w", reconstructionErr_channeltype)
				}
				var dec_channeltype CommonDataTypesExternalSignalInfo
				if unmErr := dec_channeltype.UnmarshalBER(reconstructed_channeltype, ber.ChildDecodeOptions(opts, "channelType")...); unmErr != nil {
					return fmt.Errorf("decoding channelType: %w", unmErr)
				}
				v.ChannelType = &dec_channeltype
				if offset > len(content) || n_channeltype < 0 || n_channeltype > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_channeltype
			}
		}
	}
	// Decode chosenChannel
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_chosenchannel, n_chosenchannel, rawVal_chosenchannel, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding chosenChannel: %w", err)
				}
				if decodedTag_chosenchannel.Class != tag.ClassContextSpecific || decodedTag_chosenchannel.Number != 1 || decodedTag_chosenchannel.Constructed != true {
					return fmt.Errorf("decoding chosenChannel: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_chosenchannel)
				}
				reconstructed_chosenchannel, reconstructionErr_chosenchannel := ber.EncodeSequence(rawVal_chosenchannel)
				if reconstructionErr_chosenchannel != nil {
					return fmt.Errorf("decoding chosenChannel: %w", reconstructionErr_chosenchannel)
				}
				var dec_chosenchannel CommonDataTypesExternalSignalInfo
				if unmErr := dec_chosenchannel.UnmarshalBER(reconstructed_chosenchannel, ber.ChildDecodeOptions(opts, "chosenChannel")...); unmErr != nil {
					return fmt.Errorf("decoding chosenChannel: %w", unmErr)
				}
				v.ChosenChannel = &dec_chosenchannel
				if offset < 0 || offset >
					len(content) || n_chosenchannel < 0 || n_chosenchannel > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_chosenchannel
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 2 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SIWFSSignallingModifyArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SIWFSSignallingModifyArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SIWFSSignallingModifyRes to BER format.
func (v *SIWFSSignallingModifyRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SIWFSSignallingModifyRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SIWFSSignallingModifyRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ChannelType != nil {
		enc_channeltype, err := v.ChannelType.MarshalBER(ber.ChildEncodeOptions(opts, "channelType")...)
		if err != nil {
			return nil, fmt.Errorf("encoding channelType: %w", err)
		}
		retagged_enc_channeltype, tagErr_enc_channeltype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_channeltype)
		if tagErr_enc_channeltype != nil {
			return nil, fmt.Errorf("encoding channelType: %w", tagErr_enc_channeltype)
		}
		enc_channeltype = retagged_enc_channeltype
		children = append(children, enc_channeltype...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SIWFSSignallingModifyRes to DER format.
func (v *SIWFSSignallingModifyRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SIWFSSignallingModifyRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ChannelType != nil {
		enc_channeltype, err := v.ChannelType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding channelType: %w", err)
		}
		retagged_enc_channeltype, tagErr_enc_channeltype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_channeltype)
		if tagErr_enc_channeltype != nil {
			return nil, fmt.Errorf("encoding channelType: %w", tagErr_enc_channeltype)
		}
		enc_channeltype = retagged_enc_channeltype
		children = append(children, enc_channeltype...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SIWFSSignallingModifyRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SIWFSSignallingModifyRes from BER/DER format.
func (v *SIWFSSignallingModifyRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SIWFSSignallingModifyRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SIWFSSignallingModifyRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
				decodedTag_channeltype, n_channeltype, rawVal_channeltype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding channelType: %w", err)
				}
				if decodedTag_channeltype.Class != tag.ClassContextSpecific || decodedTag_channeltype.Number != 0 || decodedTag_channeltype.Constructed != true {
					return fmt.Errorf("decoding channelType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_channeltype)
				}
				reconstructed_channeltype, reconstructionErr_channeltype := ber.EncodeSequence(rawVal_channeltype)
				if reconstructionErr_channeltype != nil {
					return fmt.Errorf("decoding channelType: %w", reconstructionErr_channeltype)
				}
				var dec_channeltype CommonDataTypesExternalSignalInfo
				if unmErr := dec_channeltype.UnmarshalBER(reconstructed_channeltype, ber.ChildDecodeOptions(opts, "channelType")...); unmErr != nil {
					return fmt.Errorf("decoding channelType: %w", unmErr)
				}
				v.ChannelType = &dec_channeltype
				if offset > len(content) || n_channeltype < 0 || n_channeltype > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_channeltype
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SIWFSSignallingModifyRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SIWFSSignallingModifyRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SecureTransportArg to BER format.
func (v *SecureTransportArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SecureTransportArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SecureTransportArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_securityheader, err := v.SecurityHeader.MarshalBER(ber.ChildEncodeOptions(opts, "securityHeader")...)
	if err != nil {
		return nil, fmt.Errorf("encoding securityHeader: %w", err)
	}
	children = append(children, enc_securityheader...)
	if v.ProtectedPayload != nil {
		if len(*v.ProtectedPayload) < 1 || len(*v.ProtectedPayload) > 3438 {
			if constraintErr := ber.CheckEncodedLength(opts, "protectedPayload", "SIZE (1..3438)", len(*v.ProtectedPayload)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_protectedpayload, encodeErr_enc_protectedpayload := ber.EncodeOctetString([]byte(*v.ProtectedPayload))
		if encodeErr_enc_protectedpayload != nil {
			return nil, fmt.Errorf("encoding protectedPayload: %w", encodeErr_enc_protectedpayload)
		}
		children = append(children, enc_protectedpayload...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SecureTransportArg to DER format.
func (v *SecureTransportArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SecureTransportArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_securityheader, err := v.SecurityHeader.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding securityHeader: %w", err)
	}
	children = append(children, enc_securityheader...)
	if v.ProtectedPayload != nil {
		if len(*v.ProtectedPayload) < 1 || len(*v.ProtectedPayload) > 3438 {
			if constraintErr := ber.CheckEncodedLength(nil, "protectedPayload", "SIZE (1..3438)", len(*v.ProtectedPayload)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_protectedpayload, encodeErr_enc_protectedpayload := ber.EncodeOctetString([]byte(*v.ProtectedPayload))
		if encodeErr_enc_protectedpayload != nil {
			return nil, fmt.Errorf("encoding protectedPayload: %w", encodeErr_enc_protectedpayload)
		}
		children = append(children, enc_protectedpayload...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SecureTransportArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SecureTransportArg from BER/DER format.
func (v *SecureTransportArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SecureTransportArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SecureTransportArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	_, n_securityheader, _, tlvErr_securityheader := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_securityheader != nil {
		return fmt.Errorf("decoding securityHeader: %w", tlvErr_securityheader)
	}
	if offset > len(content) || n_securityheader < 0 || n_securityheader > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.SecurityHeader.UnmarshalBER(content[offset:offset+n_securityheader], ber.ChildDecodeOptions(opts, "securityHeader")...); unmErr != nil {
		return fmt.Errorf("decoding securityHeader: %w", unmErr)
	}
	if offset > len(content) || n_securityheader < 0 || n_securityheader > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_securityheader
	// Decode protectedPayload
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_protectedpayload, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding protectedPayload: %w", err)
				}
				tmp_protectedpayload := ProtectedPayload(val_protectedpayload)
				v.ProtectedPayload = &tmp_protectedpayload
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.ProtectedPayload) < 1 || len(*v.ProtectedPayload) > 3438 {
					if constraintErr := ber.CheckDecodedLength(opts, "protectedPayload", "SIZE (1..3438)", len(*v.ProtectedPayload)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SecureTransportArg", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SecureTransportErrorParam to BER format.
func (v *SecureTransportErrorParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SecureTransportErrorParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SecureTransportErrorParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_securityheader, err := v.SecurityHeader.MarshalBER(ber.ChildEncodeOptions(opts, "securityHeader")...)
	if err != nil {
		return nil, fmt.Errorf("encoding securityHeader: %w", err)
	}
	children = append(children, enc_securityheader...)
	if v.ProtectedPayload != nil {
		if len(*v.ProtectedPayload) < 1 || len(*v.ProtectedPayload) > 3438 {
			if constraintErr := ber.CheckEncodedLength(opts, "protectedPayload", "SIZE (1..3438)", len(*v.ProtectedPayload)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_protectedpayload, encodeErr_enc_protectedpayload := ber.EncodeOctetString([]byte(*v.ProtectedPayload))
		if encodeErr_enc_protectedpayload != nil {
			return nil, fmt.Errorf("encoding protectedPayload: %w", encodeErr_enc_protectedpayload)
		}
		children = append(children, enc_protectedpayload...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SecureTransportErrorParam to DER format.
func (v *SecureTransportErrorParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SecureTransportErrorParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_securityheader, err := v.SecurityHeader.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding securityHeader: %w", err)
	}
	children = append(children, enc_securityheader...)
	if v.ProtectedPayload != nil {
		if len(*v.ProtectedPayload) < 1 || len(*v.ProtectedPayload) > 3438 {
			if constraintErr := ber.CheckEncodedLength(nil, "protectedPayload", "SIZE (1..3438)", len(*v.ProtectedPayload)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_protectedpayload, encodeErr_enc_protectedpayload := ber.EncodeOctetString([]byte(*v.ProtectedPayload))
		if encodeErr_enc_protectedpayload != nil {
			return nil, fmt.Errorf("encoding protectedPayload: %w", encodeErr_enc_protectedpayload)
		}
		children = append(children, enc_protectedpayload...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SecureTransportErrorParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SecureTransportErrorParam from BER/DER format.
func (v *SecureTransportErrorParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SecureTransportErrorParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SecureTransportErrorParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	_, n_securityheader, _, tlvErr_securityheader := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_securityheader != nil {
		return fmt.Errorf("decoding securityHeader: %w", tlvErr_securityheader)
	}
	if offset > len(content) || n_securityheader < 0 || n_securityheader > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.SecurityHeader.UnmarshalBER(content[offset:offset+n_securityheader], ber.ChildDecodeOptions(opts, "securityHeader")...); unmErr != nil {
		return fmt.Errorf("decoding securityHeader: %w", unmErr)
	}
	if offset > len(content) || n_securityheader < 0 || n_securityheader > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_securityheader
	// Decode protectedPayload
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_protectedpayload, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding protectedPayload: %w", err)
				}
				tmp_protectedpayload := ProtectedPayload(val_protectedpayload)
				v.ProtectedPayload = &tmp_protectedpayload
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.ProtectedPayload) < 1 || len(*v.ProtectedPayload) > 3438 {
					if constraintErr := ber.CheckDecodedLength(opts, "protectedPayload", "SIZE (1..3438)", len(*v.ProtectedPayload)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SecureTransportErrorParam", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SecureTransportRes to BER format.
func (v *SecureTransportRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SecureTransportRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SecureTransportRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_securityheader, err := v.SecurityHeader.MarshalBER(ber.ChildEncodeOptions(opts, "securityHeader")...)
	if err != nil {
		return nil, fmt.Errorf("encoding securityHeader: %w", err)
	}
	children = append(children, enc_securityheader...)
	if v.ProtectedPayload != nil {
		if len(*v.ProtectedPayload) < 1 || len(*v.ProtectedPayload) > 3438 {
			if constraintErr := ber.CheckEncodedLength(opts, "protectedPayload", "SIZE (1..3438)", len(*v.ProtectedPayload)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_protectedpayload, encodeErr_enc_protectedpayload := ber.EncodeOctetString([]byte(*v.ProtectedPayload))
		if encodeErr_enc_protectedpayload != nil {
			return nil, fmt.Errorf("encoding protectedPayload: %w", encodeErr_enc_protectedpayload)
		}
		children = append(children, enc_protectedpayload...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SecureTransportRes to DER format.
func (v *SecureTransportRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SecureTransportRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_securityheader, err := v.SecurityHeader.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding securityHeader: %w", err)
	}
	children = append(children, enc_securityheader...)
	if v.ProtectedPayload != nil {
		if len(*v.ProtectedPayload) < 1 || len(*v.ProtectedPayload) > 3438 {
			if constraintErr := ber.CheckEncodedLength(nil, "protectedPayload", "SIZE (1..3438)", len(*v.ProtectedPayload)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_protectedpayload, encodeErr_enc_protectedpayload := ber.EncodeOctetString([]byte(*v.ProtectedPayload))
		if encodeErr_enc_protectedpayload != nil {
			return nil, fmt.Errorf("encoding protectedPayload: %w", encodeErr_enc_protectedpayload)
		}
		children = append(children, enc_protectedpayload...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SecureTransportRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SecureTransportRes from BER/DER format.
func (v *SecureTransportRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SecureTransportRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SecureTransportRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	_, n_securityheader, _, tlvErr_securityheader := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_securityheader != nil {
		return fmt.Errorf("decoding securityHeader: %w", tlvErr_securityheader)
	}
	if offset > len(content) || n_securityheader < 0 || n_securityheader > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.SecurityHeader.UnmarshalBER(content[offset:offset+n_securityheader], ber.ChildDecodeOptions(opts, "securityHeader")...); unmErr != nil {
		return fmt.Errorf("decoding securityHeader: %w", unmErr)
	}
	if offset > len(content) || n_securityheader < 0 || n_securityheader > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_securityheader
	// Decode protectedPayload
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_protectedpayload, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding protectedPayload: %w", err)
				}
				tmp_protectedpayload := ProtectedPayload(val_protectedpayload)
				v.ProtectedPayload = &tmp_protectedpayload
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.ProtectedPayload) < 1 || len(*v.ProtectedPayload) > 3438 {
					if constraintErr := ber.CheckDecodedLength(opts, "protectedPayload", "SIZE (1..3438)", len(*v.ProtectedPayload)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SecureTransportRes", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SecurityHeader to BER format.
func (v *SecurityHeader) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SecurityHeader receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SecurityHeader) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SecurityParametersIndex) < 4 || len(v.SecurityParametersIndex) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "securityParametersIndex", "SIZE (4)", len(v.SecurityParametersIndex)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_securityparametersindex, encodeErr_enc_securityparametersindex := ber.EncodeOctetString([]byte(v.SecurityParametersIndex))
	if encodeErr_enc_securityparametersindex != nil {
		return nil, fmt.Errorf("encoding securityParametersIndex: %w", encodeErr_enc_securityparametersindex)
	}
	children = append(children, enc_securityparametersindex...)
	enc_originalcomponentidentifier, err := v.OriginalComponentIdentifier.MarshalBER(ber.ChildEncodeOptions(opts, "originalComponentIdentifier")...)
	if err != nil {
		return nil, fmt.Errorf("encoding originalComponentIdentifier: %w", err)
	}
	children = append(children, enc_originalcomponentidentifier...)
	if v.InitialisationVector != nil {
		if len(*v.InitialisationVector) < 14 || len(*v.InitialisationVector) > 14 {
			if constraintErr := ber.CheckEncodedLength(opts, "initialisationVector", "SIZE (14)", len(*v.InitialisationVector)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_initialisationvector, encodeErr_enc_initialisationvector := ber.EncodeOctetString([]byte(*v.InitialisationVector))
		if encodeErr_enc_initialisationvector != nil {
			return nil, fmt.Errorf("encoding initialisationVector: %w", encodeErr_enc_initialisationvector)
		}
		children = append(children, enc_initialisationvector...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SecurityHeader to DER format.
func (v *SecurityHeader) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SecurityHeader receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SecurityParametersIndex) < 4 || len(v.SecurityParametersIndex) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "securityParametersIndex", "SIZE (4)", len(v.SecurityParametersIndex)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_securityparametersindex, encodeErr_enc_securityparametersindex := ber.EncodeOctetString([]byte(v.SecurityParametersIndex))
	if encodeErr_enc_securityparametersindex != nil {
		return nil, fmt.Errorf("encoding securityParametersIndex: %w", encodeErr_enc_securityparametersindex)
	}
	children = append(children, enc_securityparametersindex...)
	enc_originalcomponentidentifier, err := v.OriginalComponentIdentifier.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding originalComponentIdentifier: %w", err)
	}
	children = append(children, enc_originalcomponentidentifier...)
	if v.InitialisationVector != nil {
		if len(*v.InitialisationVector) < 14 || len(*v.InitialisationVector) > 14 {
			if constraintErr := ber.CheckEncodedLength(nil, "initialisationVector", "SIZE (14)", len(*v.InitialisationVector)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_initialisationvector, encodeErr_enc_initialisationvector := ber.EncodeOctetString([]byte(*v.InitialisationVector))
		if encodeErr_enc_initialisationvector != nil {
			return nil, fmt.Errorf("encoding initialisationVector: %w", encodeErr_enc_initialisationvector)
		}
		children = append(children, enc_initialisationvector...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SecurityHeader as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SecurityHeader from BER/DER format.
func (v *SecurityHeader) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SecurityHeader destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SecurityHeader{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	val_securityparametersindex, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding securityParametersIndex: %w", err)
	}
	v.SecurityParametersIndex = SecurityParametersIndex(val_securityparametersindex)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SecurityParametersIndex) < 4 || len(v.SecurityParametersIndex) > 4 {
		if constraintErr := ber.CheckDecodedLength(opts, "securityParametersIndex", "SIZE (4)", len(v.SecurityParametersIndex)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode originalComponentIdentifier
	if offset >= len(content) {
		return fmt.Errorf("missing required field originalComponentIdentifier")
	}
	// Decode nested CHOICE (OriginalComponentIdentifier)
	_, n_originalcomponentidentifier, _, tlvErr_originalcomponentidentifier := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_originalcomponentidentifier != nil {
		return fmt.Errorf("decoding originalComponentIdentifier: %w", tlvErr_originalcomponentidentifier)
	}
	if offset < 0 || offset >
		len(content) || n_originalcomponentidentifier < 0 || n_originalcomponentidentifier >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.OriginalComponentIdentifier.UnmarshalBER(content[offset:offset+n_originalcomponentidentifier], ber.ChildDecodeOptions(opts, "originalComponentIdentifier")...); unmErr != nil {
		return fmt.Errorf("decoding originalComponentIdentifier: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_originalcomponentidentifier < 0 || n_originalcomponentidentifier >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_originalcomponentidentifier
	// Decode initialisationVector
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_initialisationvector, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding initialisationVector: %w", err)
				}
				tmp_initialisationvector := InitialisationVector(val_initialisationvector)
				v.InitialisationVector = &tmp_initialisationvector
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.InitialisationVector) < 14 || len(*v.InitialisationVector) > 14 {
					if constraintErr := ber.CheckDecodedLength(opts, "initialisationVector", "SIZE (14)", len(*v.InitialisationVector)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SecurityHeader", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SecurityHeader", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OriginalComponentIdentifier to BER format.
func (v *OriginalComponentIdentifier) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OriginalComponentIdentifier receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OriginalComponentIdentifier) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case OriginalComponentIdentifierChoiceOperationCode:
		if v.OperationCode == nil {
			return nil, fmt.Errorf("%w: choice OriginalComponentIdentifier: operationCode is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.OperationCode.MarshalBER(ber.ChildEncodeOptions(opts, "operationCode")...)
		if err != nil {
			return nil, fmt.Errorf("encoding operationCode: %w", err)
		}
		{
			var encodeErr error
			enc_0, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding operationCode: %w", encodeErr)
			}
		}
		return enc_0, nil
	case OriginalComponentIdentifierChoiceErrorCode:
		if v.ErrorCode == nil {
			return nil, fmt.Errorf("%w: choice OriginalComponentIdentifier: errorCode is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ErrorCode.MarshalBER(ber.ChildEncodeOptions(opts, "errorCode")...)
		if err != nil {
			return nil, fmt.Errorf("encoding errorCode: %w", err)
		}
		{
			var encodeErr error
			enc_1, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding errorCode: %w", encodeErr)
			}
		}
		return enc_1, nil
	case OriginalComponentIdentifierChoiceUserInfo:
		enc_2 := ber.EncodeNull()
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding userInfo: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for OriginalComponentIdentifier", v.Choice)
	}
}

// MarshalDER encodes OriginalComponentIdentifier to DER format.
func (v *OriginalComponentIdentifier) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OriginalComponentIdentifier receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case OriginalComponentIdentifierChoiceOperationCode:
		if v.OperationCode == nil {
			return nil, fmt.Errorf("%w: choice OriginalComponentIdentifier: operationCode is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.OperationCode.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding operationCode: %w", err)
		}
		{
			var encodeErr error
			enc_der_0, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_0)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding operationCode: %w", encodeErr)
			}
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding operationCode as DER: %w", derErr)
		}
		return enc_der_0, nil
	case OriginalComponentIdentifierChoiceErrorCode:
		if v.ErrorCode == nil {
			return nil, fmt.Errorf("%w: choice OriginalComponentIdentifier: errorCode is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ErrorCode.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding errorCode: %w", err)
		}
		{
			var encodeErr error
			enc_der_1, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding errorCode: %w", encodeErr)
			}
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding errorCode as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding OriginalComponentIdentifier as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OriginalComponentIdentifier from BER/DER format.
func (v *OriginalComponentIdentifier) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OriginalComponentIdentifier destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = OriginalComponentIdentifier{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for OriginalComponentIdentifier CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for OriginalComponentIdentifier: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding OriginalComponentIdentifier CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "OriginalComponentIdentifier", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = OriginalComponentIdentifierChoiceOperationCode
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding operationCode: %w", tlvErr)
		}
		_, innerUsed, _, innerErr := ber.DecodeTLV(innerData, opts...)
		if innerErr != nil {
			return fmt.Errorf("decoding operationCode: %w", innerErr)
		}
		if innerUsed != len(innerData) {
			return fmt.Errorf("decoding operationCode: %w", ber.ErrExtraData)
		}
		var dec OperationCode
		if unmErr := dec.UnmarshalBER(innerData, ber.ChildDecodeOptions(opts, "operationCode")...); unmErr != nil {
			return fmt.Errorf("decoding operationCode: %w", unmErr)
		}
		v.OperationCode = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = OriginalComponentIdentifierChoiceErrorCode
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding errorCode: %w", tlvErr)
		}
		_, innerUsed, _, innerErr := ber.DecodeTLV(innerData, opts...)
		if innerErr != nil {
			return fmt.Errorf("decoding errorCode: %w", innerErr)
		}
		if innerUsed != len(innerData) {
			return fmt.Errorf("decoding errorCode: %w", ber.ErrExtraData)
		}
		var dec ErrorCode
		if unmErr := dec.UnmarshalBER(innerData, ber.ChildDecodeOptions(opts, "errorCode")...); unmErr != nil {
			return fmt.Errorf("decoding errorCode: %w", unmErr)
		}
		v.ErrorCode = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = OriginalComponentIdentifierChoiceUserInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding userInfo: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding userInfo: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.UserInfo = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for OriginalComponentIdentifier CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes OperationCode to BER format.
func (v *OperationCode) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OperationCode receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OperationCode) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case OperationCodeChoiceLocalValue:
		if v.LocalValue == nil {
			return nil, fmt.Errorf("%w: choice OperationCode: localValue is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.LocalValue)
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding localValue: %w", encodeErr_enc_0)
		}
		return enc_0, nil
	case OperationCodeChoiceGlobalValue:
		enc_1, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.GlobalValue))
		if oidErr != nil {
			return nil, fmt.Errorf("encoding globalValue: %w", oidErr)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for OperationCode", v.Choice)
	}
}

// MarshalDER encodes OperationCode to DER format.
func (v *OperationCode) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OperationCode receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding OperationCode as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OperationCode from BER/DER format.
func (v *OperationCode) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OperationCode destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = OperationCode{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for OperationCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for OperationCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding OperationCode CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "OperationCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = OperationCodeChoiceLocalValue
		decVal, _, intErr := ber.DecodeBigInt(choiceData, opts...)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		v.LocalValue = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 && peekTag.Constructed == false {
		v.Choice = OperationCodeChoiceGlobalValue
		decVal, _, oidErr := ber.DecodeObjectIdentifier(choiceData, opts...)
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
func (v *ErrorCode) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ErrorCode receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ErrorCode) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ErrorCodeChoiceLocalValue:
		if v.LocalValue == nil {
			return nil, fmt.Errorf("%w: choice ErrorCode: localValue is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.LocalValue)
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding localValue: %w", encodeErr_enc_0)
		}
		return enc_0, nil
	case ErrorCodeChoiceGlobalValue:
		enc_1, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.GlobalValue))
		if oidErr != nil {
			return nil, fmt.Errorf("encoding globalValue: %w", oidErr)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ErrorCode", v.Choice)
	}
}

// MarshalDER encodes ErrorCode to DER format.
func (v *ErrorCode) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ErrorCode receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ErrorCode as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ErrorCode from BER/DER format.
func (v *ErrorCode) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ErrorCode destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ErrorCode{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ErrorCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ErrorCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding ErrorCode CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ErrorCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = ErrorCodeChoiceLocalValue
		decVal, _, intErr := ber.DecodeBigInt(choiceData, opts...)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		v.LocalValue = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 && peekTag.Constructed == false {
		v.Choice = ErrorCodeChoiceGlobalValue
		decVal, _, oidErr := ber.DecodeObjectIdentifier(choiceData, opts...)
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
func (v *PlmnContainer) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PlmnContainer receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PlmnContainer) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, fmt.Errorf("encoding category: %w", encodeErr_enc_category)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_category)
		if tagErr_enc_category != nil {
			return nil, fmt.Errorf("encoding category: %w", tagErr_enc_category)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(ber.ChildEncodeOptions(opts, "basicService")...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.OperatorSSCode != nil {
		if len((v.OperatorSSCode).Values) < 1 || len((v.OperatorSSCode).Values) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "operatorSS-Code", "SIZE (1..16)", len((v.OperatorSSCode).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_operatorsscode, err := MarshalBERPlmnContainerOperatorSSCode(v.OperatorSSCode, ber.ChildEncodeOptions(opts, "operatorSS-Code")...)
		if err != nil {
			return nil, fmt.Errorf("encoding operatorSS-Code: %w", err)
		}
		if v.OperatorSSCodeIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_operatorsscode)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_operatorsscode, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding operatorSS-Code: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_operatorsscode, tagErr_enc_operatorsscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_operatorsscode)
			if tagErr_enc_operatorsscode != nil {
				return nil, fmt.Errorf("encoding operatorSS-Code: %w", tagErr_enc_operatorsscode)
			}
			enc_operatorsscode = retagged_enc_operatorsscode
		}
		children = append(children, enc_operatorsscode...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 2, Constructed: true}, children)
}

// MarshalDER encodes PlmnContainer to DER format.
func (v *PlmnContainer) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PlmnContainer receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, fmt.Errorf("encoding category: %w", encodeErr_enc_category)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_category)
		if tagErr_enc_category != nil {
			return nil, fmt.Errorf("encoding category: %w", tagErr_enc_category)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.OperatorSSCode != nil {
		if len((v.OperatorSSCode).Values) < 1 || len((v.OperatorSSCode).Values) > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "operatorSS-Code", "SIZE (1..16)", len((v.OperatorSSCode).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_operatorsscode, err := MarshalDERPlmnContainerOperatorSSCode(v.OperatorSSCode)
		if err != nil {
			return nil, fmt.Errorf("encoding operatorSS-Code: %w", err)
		}
		retagged_enc_operatorsscode, tagErr_enc_operatorsscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_operatorsscode)
		if tagErr_enc_operatorsscode != nil {
			return nil, fmt.Errorf("encoding operatorSS-Code: %w", tagErr_enc_operatorsscode)
		}
		enc_operatorsscode = retagged_enc_operatorsscode
		children = append(children, enc_operatorsscode...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 2, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding PlmnContainer: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PlmnContainer as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PlmnContainer from BER/DER format.
func (v *PlmnContainer) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PlmnContainer destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PlmnContainer{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
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
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
					return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding msisdn: %w", octetErr)
				}
				tmp_msisdn := CommonDataTypesISDNAddressString(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset > len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode category
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_category, n_category, rawVal_category, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding category: %w", err)
				}
				if decodedTag_category.Class != tag.ClassContextSpecific || decodedTag_category.Number != 1 {
					return fmt.Errorf("decoding category: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_category)
				}
				decVal_category, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_category.Constructed, rawVal_category, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding category: %w", octetErr)
				}
				tmp_category := DumCategory(decVal_category)
				v.Category = &tmp_category
				if offset < 0 || offset >
					len(content) || n_category < 0 || n_category > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_category
				if len(*v.Category) < 1 || len(*v.Category) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (CommonDataTypesBasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice CommonDataTypesBasicServiceCode
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
				decodedTag_operatorsscode, n_operatorsscode, rawVal_operatorsscode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding operatorSS-Code: %w", err)
				}
				if decodedTag_operatorsscode.Class != tag.ClassContextSpecific || decodedTag_operatorsscode.Number != 4 || decodedTag_operatorsscode.Constructed != true {
					return fmt.Errorf("decoding operatorSS-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_operatorsscode)
				}
				reconstructed_operatorsscode, reconstructionErr_operatorsscode := ber.EncodeSequence(rawVal_operatorsscode)
				if reconstructionErr_operatorsscode != nil {
					return fmt.Errorf("decoding operatorSS-Code: %w", reconstructionErr_operatorsscode)
				}
				dec_operatorsscode, unmErr := UnmarshalBERPlmnContainerOperatorSSCode(reconstructed_operatorsscode, ber.ChildDecodeOptions(opts, "operatorSS-Code")...)
				if unmErr != nil {
					return fmt.Errorf("decoding operatorSS-Code: %w", unmErr)
				}
				v.OperatorSSCode = dec_operatorsscode
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OperatorSSCodeIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_operatorsscode < 0 || n_operatorsscode >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_operatorsscode
				if len((v.OperatorSSCode).Values) < 1 || len((v.OperatorSSCode).Values) > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "operatorSS-Code", "SIZE (1..16)", len((v.OperatorSSCode).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PlmnContainer", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "PlmnContainer", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ForwardSMArg to BER format.
func (v *ForwardSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardSMArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ForwardSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalBER(ber.ChildEncodeOptions(opts, "sm-RP-DA")...)
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-DA: %w", err)
	}
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalBER(ber.ChildEncodeOptions(opts, "sm-RP-OA")...)
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-OA: %w", err)
	}
	children = append(children, enc_smrpoa...)
	if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
		if constraintErr := ber.CheckEncodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, fmt.Errorf("encoding sm-RP-UI: %w", encodeErr_enc_smrpui)
	}
	children = append(children, enc_smrpui...)
	if v.MoreMessagesToSend != nil {
		enc_moremessagestosend := ber.EncodeNull()
		children = append(children, enc_moremessagestosend...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ForwardSMArg to DER format.
func (v *ForwardSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardSMArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-DA: %w", err)
	}
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-OA: %w", err)
	}
	children = append(children, enc_smrpoa...)
	if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
		if constraintErr := ber.CheckEncodedLength(nil, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, fmt.Errorf("encoding sm-RP-UI: %w", encodeErr_enc_smrpui)
	}
	children = append(children, enc_smrpui...)
	if v.MoreMessagesToSend != nil {
		enc_moremessagestosend := ber.EncodeNull()
		children = append(children, enc_moremessagestosend...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ForwardSMArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardSMArg from BER/DER format.
func (v *ForwardSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ForwardSMArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ForwardSMArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	_, n_smrpda, _, tlvErr_smrpda := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_smrpda != nil {
		return fmt.Errorf("decoding sm-RP-DA: %w", tlvErr_smrpda)
	}
	if offset > len(content) || n_smrpda < 0 || n_smrpda > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.SmRPDA.UnmarshalBER(content[offset:offset+n_smrpda], ber.ChildDecodeOptions(opts, "sm-RP-DA")...); unmErr != nil {
		return fmt.Errorf("decoding sm-RP-DA: %w", unmErr)
	}
	if offset > len(content) || n_smrpda < 0 || n_smrpda > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_smrpda
	// Decode sm-RP-OA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-OA")
	}
	// Decode nested CHOICE (SMRPOAold)
	_, n_smrpoa, _, tlvErr_smrpoa := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_smrpoa != nil {
		return fmt.Errorf("decoding sm-RP-OA: %w", tlvErr_smrpoa)
	}
	if offset < 0 || offset >
		len(content) || n_smrpoa < 0 || n_smrpoa > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.SmRPOA.UnmarshalBER(content[offset:offset+n_smrpoa], ber.ChildDecodeOptions(opts, "sm-RP-OA")...); unmErr != nil {
		return fmt.Errorf("decoding sm-RP-OA: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_smrpoa < 0 || n_smrpoa > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_smrpoa
	// Decode sm-RP-UI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-UI")
	}
	val_smrpui, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding sm-RP-UI: %w", err)
	}
	v.SmRPUI = CommonDataTypesSignalInfo(val_smrpui)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
		if constraintErr := ber.CheckDecodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode moreMessagesToSend
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding moreMessagesToSend: %w", err)
				}
				v.MoreMessagesToSend = &struct{}{}
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardSMArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ForwardSMArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMRPDAold to BER format.
func (v *SMRPDAold) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMRPDAold receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SMRPDAold) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SMRPDAoldChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SMRPDAold: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_0)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMRPDAoldChoiceLmsi:
		if v.Lmsi == nil {
			return nil, fmt.Errorf("%w: choice SMRPDAold: lmsi is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", encodeErr_enc_1)
		}
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMRPDAoldChoiceServiceCentreAddressDA:
		if v.ServiceCentreAddressDA == nil {
			return nil, fmt.Errorf("%w: choice SMRPDAold: serviceCentreAddressDA is nil", ber.ErrInvalidValue)
		}
		enc_2, encodeErr_enc_2 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressDA))
		if encodeErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding serviceCentreAddressDA: %w", encodeErr_enc_2)
		}
		if len(*v.ServiceCentreAddressDA) < 1 || len(*v.ServiceCentreAddressDA) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "serviceCentreAddressDA", "SIZE (1..20)", len(*v.ServiceCentreAddressDA)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding serviceCentreAddressDA: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SMRPDAoldChoiceNoSMRPDA:
		enc_3 := ber.EncodeNull()
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding noSM-RP-DA: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMRPDAold", v.Choice)
	}
}

// MarshalDER encodes SMRPDAold to DER format.
func (v *SMRPDAold) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMRPDAold receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMRPDAold as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMRPDAold from BER/DER format.
func (v *SMRPDAold) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMRPDAold destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SMRPDAold{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMRPDAold CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMRPDAold: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SMRPDAold CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRPDAold", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SMRPDAoldChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding imsi: %w", octetErr)
		}
		tmp := CommonDataTypesIMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMRPDAoldChoiceLmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding lmsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding lmsi: %w", octetErr)
		}
		tmp := CommonDataTypesLMSI(decVal)
		v.Lmsi = &tmp
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPDAoldChoiceServiceCentreAddressDA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressDA: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressDA: %w", octetErr)
		}
		tmp := CommonDataTypesAddressString(decVal)
		v.ServiceCentreAddressDA = &tmp
		if len(*v.ServiceCentreAddressDA) < 1 || len(*v.ServiceCentreAddressDA) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "serviceCentreAddressDA", "SIZE (1..20)", len(*v.ServiceCentreAddressDA)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMRPDAoldChoiceNoSMRPDA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding noSM-RP-DA: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding noSM-RP-DA: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.NoSMRPDA = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for SMRPDAold CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SMRPOAold to BER format.
func (v *SMRPOAold) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMRPOAold receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SMRPOAold) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SMRPOAoldChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("%w: choice SMRPOAold: msisdn is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_0)
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMRPOAoldChoiceServiceCentreAddressOA:
		if v.ServiceCentreAddressOA == nil {
			return nil, fmt.Errorf("%w: choice SMRPOAold: serviceCentreAddressOA is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressOA))
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding serviceCentreAddressOA: %w", encodeErr_enc_1)
		}
		if len(*v.ServiceCentreAddressOA) < 1 || len(*v.ServiceCentreAddressOA) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "serviceCentreAddressOA", "SIZE (1..20)", len(*v.ServiceCentreAddressOA)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding serviceCentreAddressOA: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMRPOAoldChoiceNoSMRPOA:
		enc_2 := ber.EncodeNull()
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding noSM-RP-OA: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMRPOAold", v.Choice)
	}
}

// MarshalDER encodes SMRPOAold to DER format.
func (v *SMRPOAold) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMRPOAold receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMRPOAold as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMRPOAold from BER/DER format.
func (v *SMRPOAold) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMRPOAold destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SMRPOAold{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMRPOAold CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMRPOAold: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SMRPOAold CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRPOAold", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SMRPOAoldChoiceMsisdn
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding msisdn: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding msisdn: %w", octetErr)
		}
		tmp := CommonDataTypesISDNAddressString(decVal)
		v.Msisdn = &tmp
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPOAoldChoiceServiceCentreAddressOA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressOA: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressOA: %w", octetErr)
		}
		tmp := CommonDataTypesAddressString(decVal)
		v.ServiceCentreAddressOA = &tmp
		if len(*v.ServiceCentreAddressOA) < 1 || len(*v.ServiceCentreAddressOA) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "serviceCentreAddressOA", "SIZE (1..20)", len(*v.ServiceCentreAddressOA)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMRPOAoldChoiceNoSMRPOA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding noSM-RP-OA: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding noSM-RP-OA: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.NoSMRPOA = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for SMRPOAold CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SendRoutingInfoArgV2 to BER format.
func (v *SendRoutingInfoArgV2) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoArgV2 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SendRoutingInfoArgV2) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER(ber.ChildEncodeOptions(opts, "cug-CheckInfo")...)
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", tagErr_enc_cugcheckinfo)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.NumberOfForwarding != nil {
		if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
			if constraintErr := ber.CheckEncodedValue(opts, "numberOfForwarding", "(1..5)", fmt.Sprint(int64(*v.NumberOfForwarding))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		retagged_enc_numberofforwarding, tagErr_enc_numberofforwarding := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_numberofforwarding)
		if tagErr_enc_numberofforwarding != nil {
			return nil, fmt.Errorf("encoding numberOfForwarding: %w", tagErr_enc_numberofforwarding)
		}
		enc_numberofforwarding = retagged_enc_numberofforwarding
		children = append(children, enc_numberofforwarding...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER(ber.ChildEncodeOptions(opts, "networkSignalInfo")...)
		if err != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", err)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", tagErr_enc_networksignalinfo)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		children = append(children, enc_networksignalinfo...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SendRoutingInfoArgV2 to DER format.
func (v *SendRoutingInfoArgV2) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoArgV2 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", tagErr_enc_cugcheckinfo)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.NumberOfForwarding != nil {
		if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
			if constraintErr := ber.CheckEncodedValue(nil, "numberOfForwarding", "(1..5)", fmt.Sprint(int64(*v.NumberOfForwarding))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		retagged_enc_numberofforwarding, tagErr_enc_numberofforwarding := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_numberofforwarding)
		if tagErr_enc_numberofforwarding != nil {
			return nil, fmt.Errorf("encoding numberOfForwarding: %w", tagErr_enc_numberofforwarding)
		}
		enc_numberofforwarding = retagged_enc_numberofforwarding
		children = append(children, enc_numberofforwarding...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", err)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", tagErr_enc_networksignalinfo)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		children = append(children, enc_networksignalinfo...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SendRoutingInfoArgV2 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SendRoutingInfoArgV2 from BER/DER format.
func (v *SendRoutingInfoArgV2) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SendRoutingInfoArgV2 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SendRoutingInfoArgV2{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
		return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
	}
	decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding msisdn: %w", octetErr)
	}
	v.Msisdn = CommonDataTypesISDNAddressString(decVal_msisdn)
	if offset > len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_msisdn
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_cugcheckinfo, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", err)
				}
				if decodedTag_cugcheckinfo.Class != tag.ClassContextSpecific || decodedTag_cugcheckinfo.Number != 1 || decodedTag_cugcheckinfo.Constructed != true {
					return fmt.Errorf("decoding cug-CheckInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugcheckinfo)
				}
				reconstructed_cugcheckinfo, reconstructionErr_cugcheckinfo := ber.EncodeSequence(rawVal_cugcheckinfo)
				if reconstructionErr_cugcheckinfo != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", reconstructionErr_cugcheckinfo)
				}
				var dec_cugcheckinfo CHCUGCheckInfo
				if unmErr := dec_cugcheckinfo.UnmarshalBER(reconstructed_cugcheckinfo, ber.ChildDecodeOptions(opts, "cug-CheckInfo")...); unmErr != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", unmErr)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugcheckinfo
			}
		}
	}
	// Decode numberOfForwarding
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_numberofforwarding, n_numberofforwarding, rawVal_numberofforwarding, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding numberOfForwarding: %w", err)
				}
				if decodedTag_numberofforwarding.Class != tag.ClassContextSpecific || decodedTag_numberofforwarding.Number != 2 || decodedTag_numberofforwarding.Constructed != false {
					return fmt.Errorf("decoding numberOfForwarding: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_numberofforwarding)
				}
				decVal_numberofforwarding, intErr := ber.DecodeIntegerValue(rawVal_numberofforwarding)
				if intErr != nil {
					return fmt.Errorf("decoding numberOfForwarding: %w", intErr)
				}
				tmp_numberofforwarding := CHNumberOfForwarding(decVal_numberofforwarding)
				v.NumberOfForwarding = &tmp_numberofforwarding
				if offset < 0 || offset >
					len(content) || n_numberofforwarding < 0 || n_numberofforwarding >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_numberofforwarding
				if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
					if constraintErr := ber.CheckDecodedValue(opts, "numberOfForwarding", "(1..5)", fmt.Sprint(int64(*v.NumberOfForwarding))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode networkSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_networksignalinfo, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding networkSignalInfo: %w", err)
				}
				if decodedTag_networksignalinfo.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo.Number != 10 || decodedTag_networksignalinfo.Constructed != true {
					return fmt.Errorf("decoding networkSignalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo)
				}
				reconstructed_networksignalinfo, reconstructionErr_networksignalinfo := ber.EncodeSequence(rawVal_networksignalinfo)
				if reconstructionErr_networksignalinfo != nil {
					return fmt.Errorf("decoding networkSignalInfo: %w", reconstructionErr_networksignalinfo)
				}
				var dec_networksignalinfo CommonDataTypesExternalSignalInfo
				if unmErr := dec_networksignalinfo.UnmarshalBER(reconstructed_networksignalinfo, ber.ChildDecodeOptions(opts, "networkSignalInfo")...); unmErr != nil {
					return fmt.Errorf("decoding networkSignalInfo: %w", unmErr)
				}
				v.NetworkSignalInfo = &dec_networksignalinfo
				if offset < 0 || offset >
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_networksignalinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoArgV2", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoArgV2", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SendRoutingInfoResV2 to BER format.
func (v *SendRoutingInfoResV2) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoResV2 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SendRoutingInfoResV2) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	children = append(children, enc_imsi...)
	enc_routinginfo, err := v.RoutingInfo.MarshalBER(ber.ChildEncodeOptions(opts, "routingInfo")...)
	if err != nil {
		return nil, fmt.Errorf("encoding routingInfo: %w", err)
	}
	children = append(children, enc_routinginfo...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER(ber.ChildEncodeOptions(opts, "cug-CheckInfo")...)
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		children = append(children, enc_cugcheckinfo...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SendRoutingInfoResV2 to DER format.
func (v *SendRoutingInfoResV2) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoResV2 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	children = append(children, enc_imsi...)
	enc_routinginfo, err := v.RoutingInfo.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding routingInfo: %w", err)
	}
	children = append(children, enc_routinginfo...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		children = append(children, enc_cugcheckinfo...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SendRoutingInfoResV2 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SendRoutingInfoResV2 from BER/DER format.
func (v *SendRoutingInfoResV2) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SendRoutingInfoResV2 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SendRoutingInfoResV2{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(val_imsi)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode routingInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field routingInfo")
	}
	// Decode nested CHOICE (CHRoutingInfo)
	_, n_routinginfo, _, tlvErr_routinginfo := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_routinginfo != nil {
		return fmt.Errorf("decoding routingInfo: %w", tlvErr_routinginfo)
	}
	if offset < 0 || offset >
		len(content) || n_routinginfo < 0 || n_routinginfo > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.RoutingInfo.UnmarshalBER(content[offset:offset+n_routinginfo], ber.ChildDecodeOptions(opts, "routingInfo")...); unmErr != nil {
		return fmt.Errorf("decoding routingInfo: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_routinginfo < 0 || n_routinginfo > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_routinginfo
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (CHCUGCheckInfo)
				_, n_cugcheckinfo, _, tlvErr_cugcheckinfo := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_cugcheckinfo != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", tlvErr_cugcheckinfo)
				}
				var dec_cugcheckinfo CHCUGCheckInfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_cugcheckinfo.UnmarshalBER(content[offset:offset+n_cugcheckinfo], ber.ChildDecodeOptions(opts, "cug-CheckInfo")...); unmErr != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", unmErr)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugcheckinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoResV2", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoResV2", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes BeginSubscriberActivityArg to BER format.
func (v *BeginSubscriberActivityArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BeginSubscriberActivityArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BeginSubscriberActivityArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	children = append(children, enc_imsi...)
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "originatingEntityNumber", "SIZE (1..9)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_originatingentitynumber, encodeErr_enc_originatingentitynumber := ber.EncodeOctetString([]byte(v.OriginatingEntityNumber))
	if encodeErr_enc_originatingentitynumber != nil {
		return nil, fmt.Errorf("encoding originatingEntityNumber: %w", encodeErr_enc_originatingentitynumber)
	}
	children = append(children, enc_originatingentitynumber...)
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 28, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes BeginSubscriberActivityArg to DER format.
func (v *BeginSubscriberActivityArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BeginSubscriberActivityArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	children = append(children, enc_imsi...)
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "originatingEntityNumber", "SIZE (1..9)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_originatingentitynumber, encodeErr_enc_originatingentitynumber := ber.EncodeOctetString([]byte(v.OriginatingEntityNumber))
	if encodeErr_enc_originatingentitynumber != nil {
		return nil, fmt.Errorf("encoding originatingEntityNumber: %w", encodeErr_enc_originatingentitynumber)
	}
	children = append(children, enc_originatingentitynumber...)
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 28, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BeginSubscriberActivityArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BeginSubscriberActivityArg from BER/DER format.
func (v *BeginSubscriberActivityArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BeginSubscriberActivityArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = BeginSubscriberActivityArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(val_imsi)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode originatingEntityNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field originatingEntityNumber")
	}
	val_originatingentitynumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding originatingEntityNumber: %w", err)
	}
	v.OriginatingEntityNumber = CommonDataTypesISDNAddressString(val_originatingentitynumber)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "originatingEntityNumber", "SIZE (1..9)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassPrivate && peekTag.Number == 28 {
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassPrivate || decodedTag_msisdn.Number != 28 {
					return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding msisdn: %w", octetErr)
				}
				tmp_msisdn := CommonDataTypesAddressString(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "BeginSubscriberActivityArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassPrivate && peekTag.Number == 28) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "BeginSubscriberActivityArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RoutingInfoForSMArgV1 to BER format.
func (v *RoutingInfoForSMArgV1) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMArgV1 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RoutingInfoForSMArgV1) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	var enc_smrppri []byte
	if v.SmRPPRIRaw_ != 0 {
		enc_smrppri = ber.EncodeBooleanRaw(v.SmRPPRIRaw_)
	} else {
		enc_smrppri = ber.EncodeBoolean(v.SmRPPRI)
	}
	retagged_enc_smrppri, tagErr_enc_smrppri := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smrppri)
	if tagErr_enc_smrppri != nil {
		return nil, fmt.Errorf("encoding sm-RP-PRI: %w", tagErr_enc_smrppri)
	}
	enc_smrppri = retagged_enc_smrppri
	children = append(children, enc_smrppri...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, fmt.Errorf("encoding serviceCentreAddress: %w", encodeErr_enc_servicecentreaddress)
	}
	retagged_enc_servicecentreaddress, tagErr_enc_servicecentreaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicecentreaddress)
	if tagErr_enc_servicecentreaddress != nil {
		return nil, fmt.Errorf("encoding serviceCentreAddress: %w", tagErr_enc_servicecentreaddress)
	}
	enc_servicecentreaddress = retagged_enc_servicecentreaddress
	children = append(children, enc_servicecentreaddress...)
	if v.CugInterlock != nil {
		if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
		if encodeErr_enc_cuginterlock != nil {
			return nil, fmt.Errorf("encoding cug-Interlock: %w", encodeErr_enc_cuginterlock)
		}
		retagged_enc_cuginterlock, tagErr_enc_cuginterlock := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_cuginterlock)
		if tagErr_enc_cuginterlock != nil {
			return nil, fmt.Errorf("encoding cug-Interlock: %w", tagErr_enc_cuginterlock)
		}
		enc_cuginterlock = retagged_enc_cuginterlock
		children = append(children, enc_cuginterlock...)
	}
	if v.TeleserviceCode != nil {
		if len(*v.TeleserviceCode) < 1 || len(*v.TeleserviceCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "teleserviceCode", "SIZE (1)", len(*v.TeleserviceCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicecode, encodeErr_enc_teleservicecode := ber.EncodeOctetString([]byte(*v.TeleserviceCode))
		if encodeErr_enc_teleservicecode != nil {
			return nil, fmt.Errorf("encoding teleserviceCode: %w", encodeErr_enc_teleservicecode)
		}
		retagged_enc_teleservicecode, tagErr_enc_teleservicecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_teleservicecode)
		if tagErr_enc_teleservicecode != nil {
			return nil, fmt.Errorf("encoding teleserviceCode: %w", tagErr_enc_teleservicecode)
		}
		enc_teleservicecode = retagged_enc_teleservicecode
		children = append(children, enc_teleservicecode...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes RoutingInfoForSMArgV1 to DER format.
func (v *RoutingInfoForSMArgV1) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMArgV1 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	enc_smrppri := ber.EncodeBoolean(v.SmRPPRI)
	retagged_enc_smrppri, tagErr_enc_smrppri := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smrppri)
	if tagErr_enc_smrppri != nil {
		return nil, fmt.Errorf("encoding sm-RP-PRI: %w", tagErr_enc_smrppri)
	}
	enc_smrppri = retagged_enc_smrppri
	children = append(children, enc_smrppri...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, fmt.Errorf("encoding serviceCentreAddress: %w", encodeErr_enc_servicecentreaddress)
	}
	retagged_enc_servicecentreaddress, tagErr_enc_servicecentreaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicecentreaddress)
	if tagErr_enc_servicecentreaddress != nil {
		return nil, fmt.Errorf("encoding serviceCentreAddress: %w", tagErr_enc_servicecentreaddress)
	}
	enc_servicecentreaddress = retagged_enc_servicecentreaddress
	children = append(children, enc_servicecentreaddress...)
	if v.CugInterlock != nil {
		if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
		if encodeErr_enc_cuginterlock != nil {
			return nil, fmt.Errorf("encoding cug-Interlock: %w", encodeErr_enc_cuginterlock)
		}
		retagged_enc_cuginterlock, tagErr_enc_cuginterlock := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_cuginterlock)
		if tagErr_enc_cuginterlock != nil {
			return nil, fmt.Errorf("encoding cug-Interlock: %w", tagErr_enc_cuginterlock)
		}
		enc_cuginterlock = retagged_enc_cuginterlock
		children = append(children, enc_cuginterlock...)
	}
	if v.TeleserviceCode != nil {
		if len(*v.TeleserviceCode) < 1 || len(*v.TeleserviceCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "teleserviceCode", "SIZE (1)", len(*v.TeleserviceCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicecode, encodeErr_enc_teleservicecode := ber.EncodeOctetString([]byte(*v.TeleserviceCode))
		if encodeErr_enc_teleservicecode != nil {
			return nil, fmt.Errorf("encoding teleserviceCode: %w", encodeErr_enc_teleservicecode)
		}
		retagged_enc_teleservicecode, tagErr_enc_teleservicecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_teleservicecode)
		if tagErr_enc_teleservicecode != nil {
			return nil, fmt.Errorf("encoding teleserviceCode: %w", tagErr_enc_teleservicecode)
		}
		enc_teleservicecode = retagged_enc_teleservicecode
		children = append(children, enc_teleservicecode...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoutingInfoForSMArgV1 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoutingInfoForSMArgV1 from BER/DER format.
func (v *RoutingInfoForSMArgV1) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RoutingInfoForSMArgV1 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RoutingInfoForSMArgV1{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
		return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
	}
	decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding msisdn: %w", octetErr)
	}
	v.Msisdn = CommonDataTypesISDNAddressString(decVal_msisdn)
	if offset > len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_msisdn
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode sm-RP-PRI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-PRI")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for sm-RP-PRI, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_smrppri, n_smrppri, rawVal_smrppri, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding sm-RP-PRI: %w", err)
	}
	if decodedTag_smrppri.Class != tag.ClassContextSpecific || decodedTag_smrppri.Number != 1 || decodedTag_smrppri.Constructed != false {
		return fmt.Errorf("decoding sm-RP-PRI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smrppri)
	}
	decVal_smrppri, boolErr := ber.DecodeBooleanValue(rawVal_smrppri)
	if boolErr != nil {
		return fmt.Errorf("decoding sm-RP-PRI: %w", boolErr)
	}
	if len(rawVal_smrppri) == 1 && rawVal_smrppri[0] != 0 && rawVal_smrppri[0] != 0xff {
		ber.MarkBERNonCanonical(opts)
	}
	if len(rawVal_smrppri) == 1 {
		v.SmRPPRIRaw_ = rawVal_smrppri[0]
	}
	v.SmRPPRI = decVal_smrppri
	if offset < 0 || offset >
		len(content) || n_smrppri < 0 || n_smrppri > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

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
	decodedTag_servicecentreaddress, n_servicecentreaddress, rawVal_servicecentreaddress, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding serviceCentreAddress: %w", err)
	}
	if decodedTag_servicecentreaddress.Class != tag.ClassContextSpecific || decodedTag_servicecentreaddress.Number != 2 {
		return fmt.Errorf("decoding serviceCentreAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servicecentreaddress)
	}
	decVal_servicecentreaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_servicecentreaddress.Constructed, rawVal_servicecentreaddress, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding serviceCentreAddress: %w", octetErr)
	}
	v.ServiceCentreAddress = CommonDataTypesAddressString(decVal_servicecentreaddress)
	if offset < 0 || offset >
		len(content) || n_servicecentreaddress < 0 || n_servicecentreaddress >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_servicecentreaddress
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode cug-Interlock
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_cuginterlock, n_cuginterlock, rawVal_cuginterlock, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cug-Interlock: %w", err)
				}
				if decodedTag_cuginterlock.Class != tag.ClassContextSpecific || decodedTag_cuginterlock.Number != 3 {
					return fmt.Errorf("decoding cug-Interlock: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cuginterlock)
				}
				decVal_cuginterlock, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cuginterlock.Constructed, rawVal_cuginterlock, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding cug-Interlock: %w", octetErr)
				}
				tmp_cuginterlock := CUGInterlock3(decVal_cuginterlock)
				v.CugInterlock = &tmp_cuginterlock
				if offset < 0 || offset >
					len(content) || n_cuginterlock < 0 || n_cuginterlock > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cuginterlock
				if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode teleserviceCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_teleservicecode, n_teleservicecode, rawVal_teleservicecode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding teleserviceCode: %w", err)
				}
				if decodedTag_teleservicecode.Class != tag.ClassContextSpecific || decodedTag_teleservicecode.Number != 5 {
					return fmt.Errorf("decoding teleserviceCode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_teleservicecode)
				}
				decVal_teleservicecode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_teleservicecode.Constructed, rawVal_teleservicecode, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding teleserviceCode: %w", octetErr)
				}
				tmp_teleservicecode := TSTeleserviceCode(decVal_teleservicecode)
				v.TeleserviceCode = &tmp_teleservicecode
				if offset < 0 || offset >
					len(content) || n_teleservicecode < 0 || n_teleservicecode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_teleservicecode
				if len(*v.TeleserviceCode) < 1 || len(*v.TeleserviceCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "teleserviceCode", "SIZE (1)", len(*v.TeleserviceCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 12 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding imsi: %w", octetErr)
				}
				tmp_imsi := CommonDataTypesIMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMArgV1", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMArgV1", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RoutingInfoForSMResV2 to BER format.
func (v *RoutingInfoForSMResV2) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMResV2 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RoutingInfoForSMResV2) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	children = append(children, enc_imsi...)
	enc_locationinfowithlmsi, err := v.LocationInfoWithLMSI.MarshalBER(ber.ChildEncodeOptions(opts, "locationInfoWithLMSI")...)
	if err != nil {
		return nil, fmt.Errorf("encoding locationInfoWithLMSI: %w", err)
	}
	retagged_enc_locationinfowithlmsi, tagErr_enc_locationinfowithlmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationinfowithlmsi)
	if tagErr_enc_locationinfowithlmsi != nil {
		return nil, fmt.Errorf("encoding locationInfoWithLMSI: %w", tagErr_enc_locationinfowithlmsi)
	}
	enc_locationinfowithlmsi = retagged_enc_locationinfowithlmsi
	children = append(children, enc_locationinfowithlmsi...)
	if v.MwdSet != nil {
		var enc_mwdset []byte
		if v.MwdSetRaw_ != 0 {
			enc_mwdset = ber.EncodeBooleanRaw(v.MwdSetRaw_)
		} else {
			enc_mwdset = ber.EncodeBoolean(*v.MwdSet)
		}
		retagged_enc_mwdset, tagErr_enc_mwdset := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_mwdset)
		if tagErr_enc_mwdset != nil {
			return nil, fmt.Errorf("encoding mwd-Set: %w", tagErr_enc_mwdset)
		}
		enc_mwdset = retagged_enc_mwdset
		children = append(children, enc_mwdset...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes RoutingInfoForSMResV2 to DER format.
func (v *RoutingInfoForSMResV2) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMResV2 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	children = append(children, enc_imsi...)
	enc_locationinfowithlmsi, err := v.LocationInfoWithLMSI.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding locationInfoWithLMSI: %w", err)
	}
	retagged_enc_locationinfowithlmsi, tagErr_enc_locationinfowithlmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationinfowithlmsi)
	if tagErr_enc_locationinfowithlmsi != nil {
		return nil, fmt.Errorf("encoding locationInfoWithLMSI: %w", tagErr_enc_locationinfowithlmsi)
	}
	enc_locationinfowithlmsi = retagged_enc_locationinfowithlmsi
	children = append(children, enc_locationinfowithlmsi...)
	if v.MwdSet != nil {
		enc_mwdset := ber.EncodeBoolean(*v.MwdSet)
		retagged_enc_mwdset, tagErr_enc_mwdset := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_mwdset)
		if tagErr_enc_mwdset != nil {
			return nil, fmt.Errorf("encoding mwd-Set: %w", tagErr_enc_mwdset)
		}
		enc_mwdset = retagged_enc_mwdset
		children = append(children, enc_mwdset...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoutingInfoForSMResV2 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoutingInfoForSMResV2 from BER/DER format.
func (v *RoutingInfoForSMResV2) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RoutingInfoForSMResV2 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RoutingInfoForSMResV2{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(val_imsi)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode locationInfoWithLMSI
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationInfoWithLMSI")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for locationInfoWithLMSI, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_locationinfowithlmsi, n_locationinfowithlmsi, rawVal_locationinfowithlmsi, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding locationInfoWithLMSI: %w", err)
	}
	if decodedTag_locationinfowithlmsi.Class != tag.ClassContextSpecific || decodedTag_locationinfowithlmsi.Number != 0 || decodedTag_locationinfowithlmsi.Constructed != true {
		return fmt.Errorf("decoding locationInfoWithLMSI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationinfowithlmsi)
	}
	reconstructed_locationinfowithlmsi, reconstructionErr_locationinfowithlmsi := ber.EncodeSequence(rawVal_locationinfowithlmsi)
	if reconstructionErr_locationinfowithlmsi != nil {
		return fmt.Errorf("decoding locationInfoWithLMSI: %w", reconstructionErr_locationinfowithlmsi)
	}
	if unmErr := v.LocationInfoWithLMSI.UnmarshalBER(reconstructed_locationinfowithlmsi, ber.ChildDecodeOptions(opts, "locationInfoWithLMSI")...); unmErr != nil {
		return fmt.Errorf("decoding locationInfoWithLMSI: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_locationinfowithlmsi < 0 || n_locationinfowithlmsi >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_locationinfowithlmsi
	// Decode mwd-Set
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_mwdset, n_mwdset, rawVal_mwdset, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mwd-Set: %w", err)
				}
				if decodedTag_mwdset.Class != tag.ClassContextSpecific || decodedTag_mwdset.Number != 2 || decodedTag_mwdset.Constructed != false {
					return fmt.Errorf("decoding mwd-Set: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mwdset)
				}
				decVal_mwdset, boolErr := ber.DecodeBooleanValue(rawVal_mwdset)
				if boolErr != nil {
					return fmt.Errorf("decoding mwd-Set: %w", boolErr)
				}
				if len(rawVal_mwdset) == 1 && rawVal_mwdset[0] != 0 && rawVal_mwdset[0] != 0xff {
					ber.MarkBERNonCanonical(opts)
				}
				if len(rawVal_mwdset) == 1 {
					v.MwdSetRaw_ = rawVal_mwdset[0]
				}
				v.MwdSet = &decVal_mwdset
				if offset < 0 || offset >
					len(content) || n_mwdset < 0 || n_mwdset > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mwdset
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMResV2", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMResV2", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LocationInfoWithLMSIv2 to BER format.
func (v *LocationInfoWithLMSIv2) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LocationInfoWithLMSIv2 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LocationInfoWithLMSIv2) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_locationinfo, err := v.LocationInfo.MarshalBER(ber.ChildEncodeOptions(opts, "locationInfo")...)
	if err != nil {
		return nil, fmt.Errorf("encoding locationInfo: %w", err)
	}
	children = append(children, enc_locationinfo...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", encodeErr_enc_lmsi)
		}
		children = append(children, enc_lmsi...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes LocationInfoWithLMSIv2 to DER format.
func (v *LocationInfoWithLMSIv2) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LocationInfoWithLMSIv2 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_locationinfo, err := v.LocationInfo.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding locationInfo: %w", err)
	}
	children = append(children, enc_locationinfo...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", encodeErr_enc_lmsi)
		}
		children = append(children, enc_lmsi...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding LocationInfoWithLMSIv2 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LocationInfoWithLMSIv2 from BER/DER format.
func (v *LocationInfoWithLMSIv2) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LocationInfoWithLMSIv2 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LocationInfoWithLMSIv2{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	_, n_locationinfo, _, tlvErr_locationinfo := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_locationinfo != nil {
		return fmt.Errorf("decoding locationInfo: %w", tlvErr_locationinfo)
	}
	if offset > len(content) || n_locationinfo < 0 || n_locationinfo > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.LocationInfo.UnmarshalBER(content[offset:offset+n_locationinfo], ber.ChildDecodeOptions(opts, "locationInfo")...); unmErr != nil {
		return fmt.Errorf("decoding locationInfo: %w", unmErr)
	}
	if offset > len(content) || n_locationinfo < 0 || n_locationinfo > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_locationinfo
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_lmsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lmsi: %w", err)
				}
				tmp_lmsi := CommonDataTypesLMSI(val_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LocationInfoWithLMSIv2", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LocationInfoWithLMSIv2", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LocationInfo to BER format.
func (v *LocationInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LocationInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LocationInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case LocationInfoChoiceRoamingNumber:
		if v.RoamingNumber == nil {
			return nil, fmt.Errorf("%w: choice LocationInfo: roamingNumber is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.RoamingNumber))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding roamingNumber: %w", encodeErr_enc_0)
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "roamingNumber", "SIZE (1..9)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding roamingNumber: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case LocationInfoChoiceMscNumber:
		if v.MscNumber == nil {
			return nil, fmt.Errorf("%w: choice LocationInfo: msc-Number is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.MscNumber))
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding msc-Number: %w", encodeErr_enc_1)
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding msc-Number: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for LocationInfo", v.Choice)
	}
}

// MarshalDER encodes LocationInfo to DER format.
func (v *LocationInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LocationInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding LocationInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LocationInfo from BER/DER format.
func (v *LocationInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LocationInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LocationInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for LocationInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for LocationInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding LocationInfo CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "LocationInfo", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = LocationInfoChoiceRoamingNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding roamingNumber: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding roamingNumber: %w", octetErr)
		}
		tmp := CommonDataTypesISDNAddressString(decVal)
		v.RoamingNumber = &tmp
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "roamingNumber", "SIZE (1..9)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = LocationInfoChoiceMscNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding msc-Number: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding msc-Number: %w", octetErr)
		}
		tmp := CommonDataTypesISDNAddressString(decVal)
		v.MscNumber = &tmp
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for LocationInfo CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SendParametersArg to BER format.
func (v *SendParametersArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SendParametersArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SendParametersArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_subscriberid, err := v.SubscriberId.MarshalBER(ber.ChildEncodeOptions(opts, "subscriberId")...)
	if err != nil {
		return nil, fmt.Errorf("encoding subscriberId: %w", err)
	}
	children = append(children, enc_subscriberid...)
	if v.RequestParameterList == nil {
		return nil, fmt.Errorf("encoding requestParameterList: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.RequestParameterList).Values) < 1 || len((v.RequestParameterList).Values) > 2 {
		if constraintErr := ber.CheckEncodedLength(opts, "requestParameterList", "SIZE (1..2)", len((v.RequestParameterList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_requestparameterlist, err := MarshalBERRequestParameterList(v.RequestParameterList, ber.ChildEncodeOptions(opts, "requestParameterList")...)
	if err != nil {
		return nil, fmt.Errorf("encoding requestParameterList: %w", err)
	}
	children = append(children, enc_requestparameterlist...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SendParametersArg to DER format.
func (v *SendParametersArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendParametersArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_subscriberid, err := v.SubscriberId.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding subscriberId: %w", err)
	}
	children = append(children, enc_subscriberid...)
	if v.RequestParameterList == nil {
		return nil, fmt.Errorf("encoding requestParameterList: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.RequestParameterList).Values) < 1 || len((v.RequestParameterList).Values) > 2 {
		if constraintErr := ber.CheckEncodedLength(nil, "requestParameterList", "SIZE (1..2)", len((v.RequestParameterList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_requestparameterlist, err := MarshalDERRequestParameterList(v.RequestParameterList)
	if err != nil {
		return nil, fmt.Errorf("encoding requestParameterList: %w", err)
	}
	children = append(children, enc_requestparameterlist...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SendParametersArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SendParametersArg from BER/DER format.
func (v *SendParametersArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SendParametersArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SendParametersArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	_, n_subscriberid, _, tlvErr_subscriberid := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_subscriberid != nil {
		return fmt.Errorf("decoding subscriberId: %w", tlvErr_subscriberid)
	}
	if offset > len(content) || n_subscriberid < 0 || n_subscriberid > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.SubscriberId.UnmarshalBER(content[offset:offset+n_subscriberid], ber.ChildDecodeOptions(opts, "subscriberId")...); unmErr != nil {
		return fmt.Errorf("decoding subscriberId: %w", unmErr)
	}
	if offset > len(content) || n_subscriberid < 0 || n_subscriberid > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_subscriberid
	// Decode requestParameterList
	if offset >= len(content) {
		return fmt.Errorf("missing required field requestParameterList")
	}
	v.RequestParameterListIndef_ = false
	// Decode nested SEQUENCE_OF (RequestParameterList)
	_, n_requestparameterlist, _, tlvErr_requestparameterlist := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_requestparameterlist != nil {
		return fmt.Errorf("decoding requestParameterList: %w", tlvErr_requestparameterlist)
	}
	if offset < 0 || offset >
		len(content) || n_requestparameterlist < 0 || n_requestparameterlist >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	tlv_requestparameterlist := content[offset : offset+n_requestparameterlist]
	{
		_, tagSz_, _ := ber.DecodeTag(tlv_requestparameterlist)
		if tagSz_ < len(tlv_requestparameterlist) && tlv_requestparameterlist[tagSz_] == 0x80 {
			v.RequestParameterListIndef_ = true
		}
	}
	dec_requestparameterlist, unmErr := UnmarshalBERRequestParameterList(tlv_requestparameterlist, ber.ChildDecodeOptions(opts, "requestParameterList")...)
	if unmErr != nil {
		return fmt.Errorf("decoding requestParameterList: %w", unmErr)
	}
	v.RequestParameterList = dec_requestparameterlist
	if offset < 0 || offset >
		len(content) || n_requestparameterlist < 0 || n_requestparameterlist >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_requestparameterlist
	if len((v.RequestParameterList).Values) < 1 || len((v.RequestParameterList).Values) > 2 {
		if constraintErr := ber.CheckDecodedLength(opts, "requestParameterList", "SIZE (1..2)", len((v.RequestParameterList).Values)); constraintErr != nil {
			return constraintErr
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SendParametersArg", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERRequestParameterList encodes a RequestParameterList list to BER.
func MarshalBERRequestParameterList(collection *RequestParameterList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERRequestParameterList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERRequestParameterList(collection *RequestParameterList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 2 {
		if constraintErr := ber.CheckEncodedLength(opts, "RequestParameterList", "SIZE (1..2)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if int64(elem) != 0 && int64(elem) != 1 && int64(elem) != 2 && int64(elem) != 4 {
			if constraintErr := ber.CheckEncodedValue(opts, fmt.Sprintf("element[%d]", elemIndex), "ENUMERATED {0, 1, 2, 4}", fmt.Sprint(int64(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ber.EncodeEnumerated(int64(elem))...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERRequestParameterList encodes a RequestParameterList list to DER.
func MarshalDERRequestParameterList(collection *RequestParameterList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 2 {
		if constraintErr := ber.CheckEncodedLength(nil, "RequestParameterList", "SIZE (1..2)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if int64(elem) != 0 && int64(elem) != 1 && int64(elem) != 2 && int64(elem) != 4 {
			if constraintErr := ber.CheckEncodedValue(nil, fmt.Sprintf("element[%d]", elemIndex), "ENUMERATED {0, 1, 2, 4}", fmt.Sprint(int64(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ber.EncodeEnumerated(int64(elem))...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RequestParameterList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERRequestParameterList decodes a RequestParameterList list from BER.
func UnmarshalBERRequestParameterList(data []byte, opts ...ber.DecodeOption) (returnValue *RequestParameterList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding RequestParameterList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RequestParameterList", Cause: ber.ErrExtraData}
	}
	var result []RequestParameter
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, intErr := ber.DecodeEnumerated(elementData, opts...)
		if intErr != nil {
			return nil, fmt.Errorf("decoding element: %w", intErr)
		}
		if val != 0 && val != 1 && val != 2 && val != 4 {
			if constraintErr := ber.CheckDecodedValue(opts, fmt.Sprintf("element[%d]", len(result)), "ENUMERATED {0, 1, 2, 4}", fmt.Sprint(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, RequestParameter(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 2 {
		if constraintErr := ber.CheckDecodedLength(opts, "RequestParameterList", "SIZE (1..2)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &RequestParameterList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERRequestParameterList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes SentParameter to BER format.
func (v *SentParameter) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SentParameter receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SentParameter) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SentParameterChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_0)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SentParameterChoiceAuthenticationSet:
		if v.AuthenticationSet == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: authenticationSet is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.AuthenticationSet.MarshalBER(ber.ChildEncodeOptions(opts, "authenticationSet")...)
		if err != nil {
			return nil, fmt.Errorf("encoding authenticationSet: %w", err)
		}
		{
			var encodeErr error
			enc_1, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding authenticationSet: %w", encodeErr)
			}
		}
		return enc_1, nil
	case SentParameterChoiceSubscriberData:
		if v.SubscriberData == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: subscriberData is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.SubscriberData.MarshalBER(ber.ChildEncodeOptions(opts, "subscriberData")...)
		if err != nil {
			return nil, fmt.Errorf("encoding subscriberData: %w", err)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding subscriberData: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SentParameterChoiceKi:
		if v.Ki == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: ki is nil", ber.ErrInvalidValue)
		}
		enc_3, encodeErr_enc_3 := ber.EncodeOctetString([]byte(*v.Ki))
		if encodeErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding ki: %w", encodeErr_enc_3)
		}
		if len(*v.Ki) < 16 || len(*v.Ki) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "ki", "SIZE (16)", len(*v.Ki)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding ki: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SentParameter", v.Choice)
	}
}

// MarshalDER encodes SentParameter to DER format.
func (v *SentParameter) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SentParameter receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SentParameterChoiceAuthenticationSet:
		if v.AuthenticationSet == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: authenticationSet is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.AuthenticationSet.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding authenticationSet: %w", err)
		}
		{
			var encodeErr error
			enc_der_1, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding authenticationSet: %w", encodeErr)
			}
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding authenticationSet as DER: %w", derErr)
		}
		return enc_der_1, nil
	case SentParameterChoiceSubscriberData:
		if v.SubscriberData == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: subscriberData is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.SubscriberData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding subscriberData: %w", err)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, fmt.Errorf("encoding subscriberData: %w", tagErr_enc_der_2)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding subscriberData as DER: %w", derErr)
		}
		return enc_der_2, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SentParameter as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SentParameter from BER/DER format.
func (v *SentParameter) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SentParameter destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SentParameter{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SentParameter CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SentParameter: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SentParameter CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SentParameter", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SentParameterChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding imsi: %w", octetErr)
		}
		tmp := CommonDataTypesIMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = SentParameterChoiceAuthenticationSet
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding authenticationSet: %w", tlvErr)
		}
		_, innerUsed, _, innerErr := ber.DecodeTLV(innerData, opts...)
		if innerErr != nil {
			return fmt.Errorf("decoding authenticationSet: %w", innerErr)
		}
		if innerUsed != len(innerData) {
			return fmt.Errorf("decoding authenticationSet: %w", ber.ErrExtraData)
		}
		var dec AuthenticationSetListOld
		if unmErr := dec.UnmarshalBER(innerData, ber.ChildDecodeOptions(opts, "authenticationSet")...); unmErr != nil {
			return fmt.Errorf("decoding authenticationSet: %w", unmErr)
		}
		v.AuthenticationSet = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = SentParameterChoiceSubscriberData
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding subscriberData: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec SubscriberData3
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "subscriberData")...); unmErr != nil {
			return fmt.Errorf("decoding subscriberData: %w", unmErr)
		}
		v.SubscriberData = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SentParameterChoiceKi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding ki: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding ki: %w", octetErr)
		}
		tmp := Ki(decVal)
		v.Ki = &tmp
		if len(*v.Ki) < 16 || len(*v.Ki) > 16 {
			if constraintErr := ber.CheckDecodedLength(opts, "ki", "SIZE (16)", len(*v.Ki)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for SentParameter CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AuthenticationSetListOld to BER format.
func (v *AuthenticationSetListOld) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AuthenticationSetListOld receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AuthenticationSetListOld) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case AuthenticationSetListOldChoiceTripletList:
		enc_0, err := MarshalBERTripletList3(v.TripletList, ber.ChildEncodeOptions(opts, "tripletList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding tripletList: %w", err)
		}
		if len((v.TripletList).Values) < 1 || len((v.TripletList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "tripletList", "SIZE (1..5)", len((v.TripletList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding tripletList: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case AuthenticationSetListOldChoiceQuintupletList:
		enc_1, err := MarshalBERQuintupletList3(v.QuintupletList, ber.ChildEncodeOptions(opts, "quintupletList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding quintupletList: %w", err)
		}
		if len((v.QuintupletList).Values) < 1 || len((v.QuintupletList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "quintupletList", "SIZE (1..5)", len((v.QuintupletList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding quintupletList: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AuthenticationSetListOld", v.Choice)
	}
}

// MarshalDER encodes AuthenticationSetListOld to DER format.
func (v *AuthenticationSetListOld) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AuthenticationSetListOld receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case AuthenticationSetListOldChoiceTripletList:
		enc_der_0, err := MarshalDERTripletList3(v.TripletList)
		if err != nil {
			return nil, fmt.Errorf("encoding tripletList: %w", err)
		}
		if len((v.TripletList).Values) < 1 || len((v.TripletList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, "tripletList", "SIZE (1..5)", len((v.TripletList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding tripletList: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding tripletList as DER: %w", derErr)
		}
		return enc_der_0, nil
	case AuthenticationSetListOldChoiceQuintupletList:
		enc_der_1, err := MarshalDERQuintupletList3(v.QuintupletList)
		if err != nil {
			return nil, fmt.Errorf("encoding quintupletList: %w", err)
		}
		if len((v.QuintupletList).Values) < 1 || len((v.QuintupletList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, "quintupletList", "SIZE (1..5)", len((v.QuintupletList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding quintupletList: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding quintupletList as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AuthenticationSetListOld as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AuthenticationSetListOld from BER/DER format.
func (v *AuthenticationSetListOld) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AuthenticationSetListOld destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AuthenticationSetListOld{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for AuthenticationSetListOld CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AuthenticationSetListOld: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding AuthenticationSetListOld CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticationSetListOld", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = AuthenticationSetListOldChoiceTripletList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding tripletList: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERTripletList3(reconstructed, ber.ChildDecodeOptions(opts, "tripletList")...)
		if unmErr != nil {
			return fmt.Errorf("decoding tripletList: %w", unmErr)
		}
		v.TripletList = dec
		if len((v.TripletList).Values) < 1 || len((v.TripletList).Values) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "tripletList", "SIZE (1..5)", len((v.TripletList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = AuthenticationSetListOldChoiceQuintupletList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding quintupletList: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERQuintupletList3(reconstructed, ber.ChildDecodeOptions(opts, "quintupletList")...)
		if unmErr != nil {
			return fmt.Errorf("decoding quintupletList: %w", unmErr)
		}
		v.QuintupletList = dec
		if len((v.QuintupletList).Values) < 1 || len((v.QuintupletList).Values) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "quintupletList", "SIZE (1..5)", len((v.QuintupletList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for AuthenticationSetListOld CHOICE", peekTag)
	}
	return nil
}

// MarshalBERSentParameterList encodes a SentParameterList list to BER.
func MarshalBERSentParameterList(collection *SentParameterList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERSentParameterList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERSentParameterList(collection *SentParameterList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 6 {
		if constraintErr := ber.CheckEncodedLength(opts, "SentParameterList", "SIZE (1..6)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERSentParameterList encodes a SentParameterList list to DER.
func MarshalDERSentParameterList(collection *SentParameterList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 6 {
		if constraintErr := ber.CheckEncodedLength(nil, "SentParameterList", "SIZE (1..6)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SentParameterList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERSentParameterList decodes a SentParameterList list from BER.
func UnmarshalBERSentParameterList(data []byte, opts ...ber.DecodeOption) (returnValue *SentParameterList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding SentParameterList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SentParameterList", Cause: ber.ErrExtraData}
	}
	var result []SentParameter
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem SentParameter
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 6 {
		if constraintErr := ber.CheckDecodedLength(opts, "SentParameterList", "SIZE (1..6)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SentParameterList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERSentParameterList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes ResetArgV2 to BER format.
func (v *ResetArgV2) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ResetArgV2 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ResetArgV2) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.NetworkResource != nil {
		if int64(*v.NetworkResource) != 0 && int64(*v.NetworkResource) != 1 && int64(*v.NetworkResource) != 2 && int64(*v.NetworkResource) != 3 && int64(*v.NetworkResource) != 4 && int64(*v.NetworkResource) != 5 && int64(*v.NetworkResource) != 6 && int64(*v.NetworkResource) != 7 {
			if constraintErr := ber.CheckEncodedValue(opts, "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.NetworkResource))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_networkresource := ber.EncodeEnumerated(int64(*v.NetworkResource))
		children = append(children, enc_networkresource...)
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_hlrnumber, encodeErr_enc_hlrnumber := ber.EncodeOctetString([]byte(v.HlrNumber))
	if encodeErr_enc_hlrnumber != nil {
		return nil, fmt.Errorf("encoding hlr-Number: %w", encodeErr_enc_hlrnumber)
	}
	children = append(children, enc_hlrnumber...)
	if v.HlrList != nil {
		if len((v.HlrList).Values) < 1 || len((v.HlrList).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(opts, "hlr-List", "SIZE (1..50)", len((v.HlrList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hlrlist, err := MarshalBERCommonDataTypesHLRList(v.HlrList, ber.ChildEncodeOptions(opts, "hlr-List")...)
		if err != nil {
			return nil, fmt.Errorf("encoding hlr-List: %w", err)
		}
		children = append(children, enc_hlrlist...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ResetArgV2 to DER format.
func (v *ResetArgV2) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ResetArgV2 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.NetworkResource != nil {
		if int64(*v.NetworkResource) != 0 && int64(*v.NetworkResource) != 1 && int64(*v.NetworkResource) != 2 && int64(*v.NetworkResource) != 3 && int64(*v.NetworkResource) != 4 && int64(*v.NetworkResource) != 5 && int64(*v.NetworkResource) != 6 && int64(*v.NetworkResource) != 7 {
			if constraintErr := ber.CheckEncodedValue(nil, "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.NetworkResource))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_networkresource := ber.EncodeEnumerated(int64(*v.NetworkResource))
		children = append(children, enc_networkresource...)
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_hlrnumber, encodeErr_enc_hlrnumber := ber.EncodeOctetString([]byte(v.HlrNumber))
	if encodeErr_enc_hlrnumber != nil {
		return nil, fmt.Errorf("encoding hlr-Number: %w", encodeErr_enc_hlrnumber)
	}
	children = append(children, enc_hlrnumber...)
	if v.HlrList != nil {
		if len((v.HlrList).Values) < 1 || len((v.HlrList).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(nil, "hlr-List", "SIZE (1..50)", len((v.HlrList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hlrlist, err := MarshalDERCommonDataTypesHLRList(v.HlrList)
		if err != nil {
			return nil, fmt.Errorf("encoding hlr-List: %w", err)
		}
		children = append(children, enc_hlrlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ResetArgV2 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ResetArgV2 from BER/DER format.
func (v *ResetArgV2) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ResetArgV2 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ResetArgV2{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
				val_networkresource, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding networkResource: %w", err)
				}
				tmp_networkresource := CommonDataTypesNetworkResource(val_networkresource)
				v.NetworkResource = &tmp_networkresource
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if int64(*v.NetworkResource) != 0 && int64(*v.NetworkResource) != 1 && int64(*v.NetworkResource) != 2 && int64(*v.NetworkResource) != 3 && int64(*v.NetworkResource) != 4 && int64(*v.NetworkResource) != 5 && int64(*v.NetworkResource) != 6 && int64(*v.NetworkResource) != 7 {
					if constraintErr := ber.CheckDecodedValue(opts, "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.NetworkResource))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode hlr-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field hlr-Number")
	}
	val_hlrnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding hlr-Number: %w", err)
	}
	v.HlrNumber = CommonDataTypesISDNAddressString(val_hlrnumber)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "hlr-Number", "SIZE (1..9)", len(v.HlrNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.HlrNumber) < 1 || len(v.HlrNumber) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "hlr-Number", "SIZE (1..20)", len(v.HlrNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode hlr-List
	v.HlrListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (CommonDataTypesHLRList)
				_, n_hlrlist, _, tlvErr_hlrlist := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_hlrlist != nil {
					return fmt.Errorf("decoding hlr-List: %w", tlvErr_hlrlist)
				}
				if offset < 0 || offset >
					len(content) || n_hlrlist < 0 || n_hlrlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_hlrlist := content[offset : offset+n_hlrlist]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_hlrlist)
					if tagSz_ < len(tlv_hlrlist) && tlv_hlrlist[tagSz_] == 0x80 {
						v.HlrListIndef_ = true
					}
				}
				dec_hlrlist, unmErr := UnmarshalBERCommonDataTypesHLRList(tlv_hlrlist, ber.ChildDecodeOptions(opts, "hlr-List")...)
				if unmErr != nil {
					return fmt.Errorf("decoding hlr-List: %w", unmErr)
				}
				v.HlrList = dec_hlrlist
				if offset < 0 || offset >
					len(content) || n_hlrlist < 0 || n_hlrlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hlrlist
				if len((v.HlrList).Values) < 1 || len((v.HlrList).Values) > 50 {
					if constraintErr := ber.CheckDecodedLength(opts, "hlr-List", "SIZE (1..50)", len((v.HlrList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ResetArgV2", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ResetArgV2", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ReturnResultResultretres to BER format.
func (v *ReturnResultResultretres) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResultResultretres receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ReturnResultResultretres) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.OpCode.MarshalBER(ber.ChildEncodeOptions(opts, "opCode")...)
	if err != nil {
		return nil, fmt.Errorf("encoding opCode: %w", err)
	}
	children = append(children, enc_opcode...)
	if v.Returnparameter != nil {
		enc_returnparameter := v.Returnparameter.Bytes
		children = append(children, enc_returnparameter...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ReturnResultResultretres to DER format.
func (v *ReturnResultResultretres) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReturnResultResultretres receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.OpCode.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding opCode: %w", err)
	}
	children = append(children, enc_opcode...)
	if v.Returnparameter != nil {
		enc_returnparameter := v.Returnparameter.Bytes
		children = append(children, enc_returnparameter...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ReturnResultResultretres as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReturnResultResultretres from BER/DER format.
func (v *ReturnResultResultretres) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ReturnResultResultretres destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ReturnResultResultretres{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opCode: %w", tlvErr_opcode)
	}
	if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.OpCode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opCode")...); unmErr != nil {
		return fmt.Errorf("decoding opCode: %w", unmErr)
	}
	if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_opcode
	// Decode returnparameter
	if offset < len(content) {
		_, n_returnparameter, _, tlvErr_returnparameter := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_returnparameter != nil {
			return fmt.Errorf("decoding returnparameter: %w", tlvErr_returnparameter)
		}
		if offset < 0 || offset >
			len(content) || n_returnparameter < 0 || n_returnparameter > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_returnparameter := runtime.RawValue{Bytes: content[offset : offset+n_returnparameter]}
		v.Returnparameter = &tmp_returnparameter
		if offset < 0 || offset >
			len(content) || n_returnparameter < 0 || n_returnparameter > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_returnparameter
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnResultResultretres", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RejectInvokeIDRej to BER format.
func (v *RejectInvokeIDRej) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: RejectInvokeIDRej receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RejectInvokeIDRej) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case RejectInvokeIDRejChoiceDerivable:
		if v.Derivable == nil {
			return nil, fmt.Errorf("%w: choice RejectInvokeIDRej: derivable is nil", ber.ErrInvalidValue)
		}
		enc_0 := ber.EncodeInteger(int64(*v.Derivable))
		if !(int64(*v.Derivable) >= -128 && int64(*v.Derivable) <= 127) {
			if constraintErr := ber.CheckEncodedValue(opts, "derivable", "(-128..127)", fmt.Sprint(int64(*v.Derivable))); constraintErr != nil {
				return nil, constraintErr
			}
		}
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
	if v == nil {
		return nil, fmt.Errorf("%w: RejectInvokeIDRej receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RejectInvokeIDRej as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RejectInvokeIDRej from BER/DER format.
func (v *RejectInvokeIDRej) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RejectInvokeIDRej destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RejectInvokeIDRej{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for RejectInvokeIDRej CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RejectInvokeIDRej: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding RejectInvokeIDRej CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RejectInvokeIDRej", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = RejectInvokeIDRejChoiceDerivable
		decVal, _, intErr := ber.DecodeInteger(choiceData, opts...)
		if intErr != nil {
			return fmt.Errorf("decoding derivable: %w", intErr)
		}
		tmp := InvokeIdType(decVal)
		v.Derivable = &tmp
		if !(int64(*v.Derivable) >= -128 && int64(*v.Derivable) <= 127) {
			if constraintErr := ber.CheckDecodedValue(opts, "derivable", "(-128..127)", fmt.Sprint(int64(*v.Derivable))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = RejectInvokeIDRejChoiceNotDerivable
		_, nullErr := ber.DecodeNull(choiceData, opts...)
		if nullErr != nil {
			return fmt.Errorf("decoding not-derivable: %w", nullErr)
		}
	} else {
		return fmt.Errorf("unknown tag %s for RejectInvokeIDRej CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes DumRejectProblem to BER format.
func (v *DumRejectProblem) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DumRejectProblem receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DumRejectProblem) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case DumRejectProblemChoiceGeneralProblem:
		if v.GeneralProblem == nil {
			return nil, fmt.Errorf("%w: choice DumRejectProblem: generalProblem is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.GeneralProblem.BigInt())
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding generalProblem: %w", encodeErr_enc_0)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding generalProblem: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case DumRejectProblemChoiceInvokeProblem:
		if v.InvokeProblem == nil {
			return nil, fmt.Errorf("%w: choice DumRejectProblem: invokeProblem is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeBigInt(v.InvokeProblem.BigInt())
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding invokeProblem: %w", encodeErr_enc_1)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding invokeProblem: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case DumRejectProblemChoiceReturnResultProblem:
		if v.ReturnResultProblem == nil {
			return nil, fmt.Errorf("%w: choice DumRejectProblem: returnResultProblem is nil", ber.ErrInvalidValue)
		}
		enc_2, encodeErr_enc_2 := ber.EncodeBigInt(v.ReturnResultProblem.BigInt())
		if encodeErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding returnResultProblem: %w", encodeErr_enc_2)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding returnResultProblem: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case DumRejectProblemChoiceReturnErrorProblem:
		if v.ReturnErrorProblem == nil {
			return nil, fmt.Errorf("%w: choice DumRejectProblem: returnErrorProblem is nil", ber.ErrInvalidValue)
		}
		enc_3, encodeErr_enc_3 := ber.EncodeBigInt(v.ReturnErrorProblem.BigInt())
		if encodeErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding returnErrorProblem: %w", encodeErr_enc_3)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding returnErrorProblem: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DumRejectProblem", v.Choice)
	}
}

// MarshalDER encodes DumRejectProblem to DER format.
func (v *DumRejectProblem) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DumRejectProblem receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DumRejectProblem as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DumRejectProblem from BER/DER format.
func (v *DumRejectProblem) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DumRejectProblem destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DumRejectProblem{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for DumRejectProblem CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DumRejectProblem: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding DumRejectProblem CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DumRejectProblem", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = DumRejectProblemChoiceGeneralProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = DumRejectProblemChoiceInvokeProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = DumRejectProblemChoiceReturnResultProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == false {
		v.Choice = DumRejectProblemChoiceReturnErrorProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
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
func (v *DumSendAuthenticationInfoResOldElem) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DumSendAuthenticationInfoResOldElem receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DumSendAuthenticationInfoResOldElem) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := ber.CheckEncodedLength(opts, "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_rand, encodeErr_enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	if encodeErr_enc_rand != nil {
		return nil, fmt.Errorf("encoding rand: %w", encodeErr_enc_rand)
	}
	children = append(children, enc_rand...)
	if len(v.Sres) < 4 || len(v.Sres) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sres, encodeErr_enc_sres := ber.EncodeOctetString([]byte(v.Sres))
	if encodeErr_enc_sres != nil {
		return nil, fmt.Errorf("encoding sres: %w", encodeErr_enc_sres)
	}
	children = append(children, enc_sres...)
	if len(v.Kc) < 8 || len(v.Kc) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(v.Kc))
	if encodeErr_enc_kc != nil {
		return nil, fmt.Errorf("encoding kc: %w", encodeErr_enc_kc)
	}
	children = append(children, enc_kc...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DumSendAuthenticationInfoResOldElem to DER format.
func (v *DumSendAuthenticationInfoResOldElem) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DumSendAuthenticationInfoResOldElem receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := ber.CheckEncodedLength(nil, "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_rand, encodeErr_enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	if encodeErr_enc_rand != nil {
		return nil, fmt.Errorf("encoding rand: %w", encodeErr_enc_rand)
	}
	children = append(children, enc_rand...)
	if len(v.Sres) < 4 || len(v.Sres) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sres, encodeErr_enc_sres := ber.EncodeOctetString([]byte(v.Sres))
	if encodeErr_enc_sres != nil {
		return nil, fmt.Errorf("encoding sres: %w", encodeErr_enc_sres)
	}
	children = append(children, enc_sres...)
	if len(v.Kc) < 8 || len(v.Kc) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(v.Kc))
	if encodeErr_enc_kc != nil {
		return nil, fmt.Errorf("encoding kc: %w", encodeErr_enc_kc)
	}
	children = append(children, enc_kc...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DumSendAuthenticationInfoResOldElem as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DumSendAuthenticationInfoResOldElem from BER/DER format.
func (v *DumSendAuthenticationInfoResOldElem) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DumSendAuthenticationInfoResOldElem destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DumSendAuthenticationInfoResOldElem{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
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
	val_rand, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding rand: %w", err)
	}
	v.Rand = DumRAND(val_rand)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := ber.CheckDecodedLength(opts, "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode sres
	if offset >= len(content) {
		return fmt.Errorf("missing required field sres")
	}
	val_sres, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding sres: %w", err)
	}
	v.Sres = DumSRES(val_sres)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Sres) < 4 || len(v.Sres) > 4 {
		if constraintErr := ber.CheckDecodedLength(opts, "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode kc
	if offset >= len(content) {
		return fmt.Errorf("missing required field kc")
	}
	val_kc, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding kc: %w", err)
	}
	v.Kc = DumKc(val_kc)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Kc) < 8 || len(v.Kc) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DumSendAuthenticationInfoResOldElem", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERPlmnContainerOperatorSSCode encodes a PlmnContainerOperatorSSCode list to BER.
func MarshalBERPlmnContainerOperatorSSCode(collection *PlmnContainerOperatorSSCode, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERPlmnContainerOperatorSSCode(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERPlmnContainerOperatorSSCode(collection *PlmnContainerOperatorSSCode, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 16 {
		if constraintErr := ber.CheckEncodedLength(opts, "PlmnContainerOperatorSSCode", "SIZE (1..16)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString(elem)
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERPlmnContainerOperatorSSCode encodes a PlmnContainerOperatorSSCode list to DER.
func MarshalDERPlmnContainerOperatorSSCode(collection *PlmnContainerOperatorSSCode) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 16 {
		if constraintErr := ber.CheckEncodedLength(nil, "PlmnContainerOperatorSSCode", "SIZE (1..16)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString(elem)
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PlmnContainerOperatorSSCode as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERPlmnContainerOperatorSSCode decodes a PlmnContainerOperatorSSCode list from BER.
func UnmarshalBERPlmnContainerOperatorSSCode(data []byte, opts ...ber.DecodeOption) (returnValue *PlmnContainerOperatorSSCode, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding PlmnContainerOperatorSSCode: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PlmnContainerOperatorSSCode", Cause: ber.ErrExtraData}
	}
	var result [][]byte
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 1 || len(val) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, val)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 16 {
		if constraintErr := ber.CheckDecodedLength(opts, "PlmnContainerOperatorSSCode", "SIZE (1..16)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &PlmnContainerOperatorSSCode{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERPlmnContainerOperatorSSCode(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}
