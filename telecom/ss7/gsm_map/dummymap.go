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
	Invokeparameter *runtime.RawValue `asn1:",optional" json:"Invokeparameter,omitempty"`
}

// InvokeParameter represents the ASN.1 type InvokeParameter (ANY).
type InvokeParameter = runtime.RawValue

// DumReturnResult represents the ASN.1 type DumReturnResult (SEQUENCE).
type DumReturnResult struct {
	InvokeID     InvokeIdType              `asn1:""`
	Resultretres *ReturnResultResultretres `asn1:",optional" json:"Resultretres,omitempty"`
}

// ReturnResultParameter represents the ASN.1 type ReturnResultParameter (ANY).
type ReturnResultParameter = runtime.RawValue

// DumReturnError represents the ASN.1 type DumReturnError (SEQUENCE).
type DumReturnError struct {
	InvokeID  InvokeIdType      `asn1:""`
	ErrorCode MAPERROR          `asn1:""`
	Parameter *runtime.RawValue `asn1:",optional" json:"Parameter,omitempty"`
}

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

// MAPOPERATION represents the ASN.1 CHOICE type MAP-OPERATION.
type MAPOPERATION struct {
	Choice      int
	LocalValue  *OperationLocalvalue     `json:"LocalValue,omitempty"`
	GlobalValue runtime.ObjectIdentifier `json:"GlobalValue,omitempty"`
}

// NewMAPOPERATIONLocalValue creates a MAP-OPERATION with the localValue alternative.
func NewMAPOPERATIONLocalValue(v OperationLocalvalue) MAPOPERATION {
	return MAPOPERATION{
		Choice:     MAPOPERATIONChoiceLocalValue,
		LocalValue: &v,
	}
}

// NewMAPOPERATIONGlobalValue creates a MAP-OPERATION with the globalValue alternative.
func NewMAPOPERATIONGlobalValue(v runtime.ObjectIdentifier) MAPOPERATION {
	return MAPOPERATION{
		Choice:      MAPOPERATIONChoiceGlobalValue,
		GlobalValue: v,
	}
}

// GSMMAPOperationLocalvalue represents the ASN.1 INTEGER type GSMMAPOperationLocalvalue with named numbers.
type GSMMAPOperationLocalvalue = int64

const (
	GSMMAPOperationLocalvalueUpdateLocation                   GSMMAPOperationLocalvalue = 2
	GSMMAPOperationLocalvalueCancelLocation                   GSMMAPOperationLocalvalue = 3
	GSMMAPOperationLocalvalueProvideRoamingNumber             GSMMAPOperationLocalvalue = 4
	GSMMAPOperationLocalvalueNoteSubscriberDataModified       GSMMAPOperationLocalvalue = 5
	GSMMAPOperationLocalvalueResumeCallHandling               GSMMAPOperationLocalvalue = 6
	GSMMAPOperationLocalvalueInsertSubscriberData             GSMMAPOperationLocalvalue = 7
	GSMMAPOperationLocalvalueDeleteSubscriberData             GSMMAPOperationLocalvalue = 8
	GSMMAPOperationLocalvalueSendParameters                   GSMMAPOperationLocalvalue = 9
	GSMMAPOperationLocalvalueRegisterSS                       GSMMAPOperationLocalvalue = 10
	GSMMAPOperationLocalvalueEraseSS                          GSMMAPOperationLocalvalue = 11
	GSMMAPOperationLocalvalueActivateSS                       GSMMAPOperationLocalvalue = 12
	GSMMAPOperationLocalvalueDeactivateSS                     GSMMAPOperationLocalvalue = 13
	GSMMAPOperationLocalvalueInterrogateSS                    GSMMAPOperationLocalvalue = 14
	GSMMAPOperationLocalvalueAuthenticationFailureReport      GSMMAPOperationLocalvalue = 15
	GSMMAPOperationLocalvalueNotifySS                         GSMMAPOperationLocalvalue = 16
	GSMMAPOperationLocalvalueRegisterPassword                 GSMMAPOperationLocalvalue = 17
	GSMMAPOperationLocalvalueGetPassword                      GSMMAPOperationLocalvalue = 18
	GSMMAPOperationLocalvalueProcessUnstructuredSSData        GSMMAPOperationLocalvalue = 19
	GSMMAPOperationLocalvalueReleaseResources                 GSMMAPOperationLocalvalue = 20
	GSMMAPOperationLocalvalueMtForwardSMVGCS                  GSMMAPOperationLocalvalue = 21
	GSMMAPOperationLocalvalueSendRoutingInfo                  GSMMAPOperationLocalvalue = 22
	GSMMAPOperationLocalvalueUpdateGprsLocation               GSMMAPOperationLocalvalue = 23
	GSMMAPOperationLocalvalueSendRoutingInfoForGprs           GSMMAPOperationLocalvalue = 24
	GSMMAPOperationLocalvalueFailureReport                    GSMMAPOperationLocalvalue = 25
	GSMMAPOperationLocalvalueNoteMsPresentForGprs             GSMMAPOperationLocalvalue = 26
	GSMMAPOperationLocalvalueUnAllocated                      GSMMAPOperationLocalvalue = 27
	GSMMAPOperationLocalvaluePerformHandover                  GSMMAPOperationLocalvalue = 28
	GSMMAPOperationLocalvalueSendEndSignal                    GSMMAPOperationLocalvalue = 29
	GSMMAPOperationLocalvaluePerformSubsequentHandover        GSMMAPOperationLocalvalue = 30
	GSMMAPOperationLocalvalueProvideSIWFSNumber               GSMMAPOperationLocalvalue = 31
	GSMMAPOperationLocalvalueSIWFSSignallingModify            GSMMAPOperationLocalvalue = 32
	GSMMAPOperationLocalvalueProcessAccessSignalling          GSMMAPOperationLocalvalue = 33
	GSMMAPOperationLocalvalueForwardAccessSignalling          GSMMAPOperationLocalvalue = 34
	GSMMAPOperationLocalvalueNoteInternalHandover             GSMMAPOperationLocalvalue = 35
	GSMMAPOperationLocalvalueCancelVcsgLocation               GSMMAPOperationLocalvalue = 36
	GSMMAPOperationLocalvalueReset                            GSMMAPOperationLocalvalue = 37
	GSMMAPOperationLocalvalueForwardCheckSS                   GSMMAPOperationLocalvalue = 38
	GSMMAPOperationLocalvaluePrepareGroupCall                 GSMMAPOperationLocalvalue = 39
	GSMMAPOperationLocalvalueSendGroupCallEndSignal           GSMMAPOperationLocalvalue = 40
	GSMMAPOperationLocalvalueProcessGroupCallSignalling       GSMMAPOperationLocalvalue = 41
	GSMMAPOperationLocalvalueForwardGroupCallSignalling       GSMMAPOperationLocalvalue = 42
	GSMMAPOperationLocalvalueCheckIMEI                        GSMMAPOperationLocalvalue = 43
	GSMMAPOperationLocalvalueMtForwardSM                      GSMMAPOperationLocalvalue = 44
	GSMMAPOperationLocalvalueSendRoutingInfoForSM             GSMMAPOperationLocalvalue = 45
	GSMMAPOperationLocalvalueMoForwardSM                      GSMMAPOperationLocalvalue = 46
	GSMMAPOperationLocalvalueReportSMDeliveryStatus           GSMMAPOperationLocalvalue = 47
	GSMMAPOperationLocalvalueNoteSubscriberPresent            GSMMAPOperationLocalvalue = 48
	GSMMAPOperationLocalvalueAlertServiceCentreWithoutResult  GSMMAPOperationLocalvalue = 49
	GSMMAPOperationLocalvalueActivateTraceMode                GSMMAPOperationLocalvalue = 50
	GSMMAPOperationLocalvalueDeactivateTraceMode              GSMMAPOperationLocalvalue = 51
	GSMMAPOperationLocalvalueTraceSubscriberActivity          GSMMAPOperationLocalvalue = 52
	GSMMAPOperationLocalvalueUpdateVcsgLocation               GSMMAPOperationLocalvalue = 53
	GSMMAPOperationLocalvalueBeginSubscriberActivity          GSMMAPOperationLocalvalue = 54
	GSMMAPOperationLocalvalueSendIdentification               GSMMAPOperationLocalvalue = 55
	GSMMAPOperationLocalvalueSendAuthenticationInfo           GSMMAPOperationLocalvalue = 56
	GSMMAPOperationLocalvalueRestoreData                      GSMMAPOperationLocalvalue = 57
	GSMMAPOperationLocalvalueSendIMSI                         GSMMAPOperationLocalvalue = 58
	GSMMAPOperationLocalvalueProcessUnstructuredSSRequest     GSMMAPOperationLocalvalue = 59
	GSMMAPOperationLocalvalueUnstructuredSSRequest            GSMMAPOperationLocalvalue = 60
	GSMMAPOperationLocalvalueUnstructuredSSNotify             GSMMAPOperationLocalvalue = 61
	GSMMAPOperationLocalvalueAnyTimeSubscriptionInterrogation GSMMAPOperationLocalvalue = 62
	GSMMAPOperationLocalvalueInformServiceCentre              GSMMAPOperationLocalvalue = 63
	GSMMAPOperationLocalvalueAlertServiceCentre               GSMMAPOperationLocalvalue = 64
	GSMMAPOperationLocalvalueAnyTimeModification              GSMMAPOperationLocalvalue = 65
	GSMMAPOperationLocalvalueReadyForSM                       GSMMAPOperationLocalvalue = 66
	GSMMAPOperationLocalvaluePurgeMS                          GSMMAPOperationLocalvalue = 67
	GSMMAPOperationLocalvaluePrepareHandover                  GSMMAPOperationLocalvalue = 68
	GSMMAPOperationLocalvaluePrepareSubsequentHandover        GSMMAPOperationLocalvalue = 69
	GSMMAPOperationLocalvalueProvideSubscriberInfo            GSMMAPOperationLocalvalue = 70
	GSMMAPOperationLocalvalueAnyTimeInterrogation             GSMMAPOperationLocalvalue = 71
	GSMMAPOperationLocalvalueSsInvocationNotification         GSMMAPOperationLocalvalue = 72
	GSMMAPOperationLocalvalueSetReportingState                GSMMAPOperationLocalvalue = 73
	GSMMAPOperationLocalvalueStatusReport                     GSMMAPOperationLocalvalue = 74
	GSMMAPOperationLocalvalueRemoteUserFree                   GSMMAPOperationLocalvalue = 75
	GSMMAPOperationLocalvalueRegisterCCEntry                  GSMMAPOperationLocalvalue = 76
	GSMMAPOperationLocalvalueEraseCCEntry                     GSMMAPOperationLocalvalue = 77
	GSMMAPOperationLocalvalueSecureTransportClass1            GSMMAPOperationLocalvalue = 78
	GSMMAPOperationLocalvalueSecureTransportClass2            GSMMAPOperationLocalvalue = 79
	GSMMAPOperationLocalvalueSecureTransportClass3            GSMMAPOperationLocalvalue = 80
	GSMMAPOperationLocalvalueSecureTransportClass4            GSMMAPOperationLocalvalue = 81
	GSMMAPOperationLocalvalueUnAllocated82                    GSMMAPOperationLocalvalue = 82
	GSMMAPOperationLocalvalueProvideSubscriberLocation        GSMMAPOperationLocalvalue = 83
	GSMMAPOperationLocalvalueSendGroupCallInfo                GSMMAPOperationLocalvalue = 84
	GSMMAPOperationLocalvalueSendRoutingInfoForLCS            GSMMAPOperationLocalvalue = 85
	GSMMAPOperationLocalvalueSubscriberLocationReport         GSMMAPOperationLocalvalue = 86
	GSMMAPOperationLocalvalueIstAlert                         GSMMAPOperationLocalvalue = 87
	GSMMAPOperationLocalvalueIstCommand                       GSMMAPOperationLocalvalue = 88
	GSMMAPOperationLocalvalueNoteMMEvent                      GSMMAPOperationLocalvalue = 89
	GSMMAPOperationLocalvalueUnAllocated90                    GSMMAPOperationLocalvalue = 90
	GSMMAPOperationLocalvalueUnAllocated91                    GSMMAPOperationLocalvalue = 91
	GSMMAPOperationLocalvalueUnAllocated92                    GSMMAPOperationLocalvalue = 92
	GSMMAPOperationLocalvalueUnAllocated93                    GSMMAPOperationLocalvalue = 93
	GSMMAPOperationLocalvalueUnAllocated94                    GSMMAPOperationLocalvalue = 94
	GSMMAPOperationLocalvalueUnAllocated95                    GSMMAPOperationLocalvalue = 95
	GSMMAPOperationLocalvalueUnAllocated96                    GSMMAPOperationLocalvalue = 96
	GSMMAPOperationLocalvalueUnAllocated97                    GSMMAPOperationLocalvalue = 97
	GSMMAPOperationLocalvalueUnAllocated98                    GSMMAPOperationLocalvalue = 98
	GSMMAPOperationLocalvalueUnAllocated99                    GSMMAPOperationLocalvalue = 99
	GSMMAPOperationLocalvalueUnAllocated100                   GSMMAPOperationLocalvalue = 100
	GSMMAPOperationLocalvalueUnAllocated101                   GSMMAPOperationLocalvalue = 101
	GSMMAPOperationLocalvalueUnAllocated102                   GSMMAPOperationLocalvalue = 102
	GSMMAPOperationLocalvalueUnAllocated103                   GSMMAPOperationLocalvalue = 103
	GSMMAPOperationLocalvalueUnAllocated104                   GSMMAPOperationLocalvalue = 104
	GSMMAPOperationLocalvalueUnAllocated105                   GSMMAPOperationLocalvalue = 105
	GSMMAPOperationLocalvalueUnAllocated106                   GSMMAPOperationLocalvalue = 106
	GSMMAPOperationLocalvalueUnAllocated107                   GSMMAPOperationLocalvalue = 107
	GSMMAPOperationLocalvalueUnAllocated108                   GSMMAPOperationLocalvalue = 108
	GSMMAPOperationLocalvalueLcsPeriodicLocationCancellation  GSMMAPOperationLocalvalue = 109
	GSMMAPOperationLocalvalueLcsLocationUpdate                GSMMAPOperationLocalvalue = 110
	GSMMAPOperationLocalvalueLcsPeriodicLocationRequest       GSMMAPOperationLocalvalue = 111
	GSMMAPOperationLocalvalueLcsAreaEventCancellation         GSMMAPOperationLocalvalue = 112
	GSMMAPOperationLocalvalueLcsAreaEventReport               GSMMAPOperationLocalvalue = 113
	GSMMAPOperationLocalvalueLcsAreaEventRequest              GSMMAPOperationLocalvalue = 114
	GSMMAPOperationLocalvalueLcsMOLR                          GSMMAPOperationLocalvalue = 115
	GSMMAPOperationLocalvalueLcsLocationNotification          GSMMAPOperationLocalvalue = 116
	GSMMAPOperationLocalvalueCallDeflection                   GSMMAPOperationLocalvalue = 117
	GSMMAPOperationLocalvalueUserUserService                  GSMMAPOperationLocalvalue = 118
	GSMMAPOperationLocalvalueAccessRegisterCCEntry            GSMMAPOperationLocalvalue = 119
	GSMMAPOperationLocalvalueForwardCUGInfo                   GSMMAPOperationLocalvalue = 120
	GSMMAPOperationLocalvalueSplitMPTY                        GSMMAPOperationLocalvalue = 121
	GSMMAPOperationLocalvalueRetrieveMPTY                     GSMMAPOperationLocalvalue = 122
	GSMMAPOperationLocalvalueHoldMPTY                         GSMMAPOperationLocalvalue = 123
	GSMMAPOperationLocalvalueBuildMPTY                        GSMMAPOperationLocalvalue = 124
	GSMMAPOperationLocalvalueForwardChargeAdvice              GSMMAPOperationLocalvalue = 125
	GSMMAPOperationLocalvalueExplicitCT                       GSMMAPOperationLocalvalue = 126
)

// OperationLocalvalue represents the ASN.1 type OperationLocalvalue (INTEGER).
type OperationLocalvalue = GSMMAPOperationLocalvalue

// MAPERROR choice constants.
const (
	MAPERRORChoiceLocalValue  = 1
	MAPERRORChoiceGlobalValue = 2
)

// MAPERROR represents the ASN.1 CHOICE type MAP-ERROR.
type MAPERROR struct {
	Choice      int
	LocalValue  *LocalErrorcode          `json:"LocalValue,omitempty"`
	GlobalValue runtime.ObjectIdentifier `json:"GlobalValue,omitempty"`
}

// NewMAPERRORLocalValue creates a MAP-ERROR with the localValue alternative.
func NewMAPERRORLocalValue(v LocalErrorcode) MAPERROR {
	return MAPERROR{
		Choice:     MAPERRORChoiceLocalValue,
		LocalValue: &v,
	}
}

// NewMAPERRORGlobalValue creates a MAP-ERROR with the globalValue alternative.
func NewMAPERRORGlobalValue(v runtime.ObjectIdentifier) MAPERROR {
	return MAPERROR{
		Choice:      MAPERRORChoiceGlobalValue,
		GlobalValue: v,
	}
}

// GSMMAPLocalErrorcode represents the ASN.1 INTEGER type GSMMAPLocalErrorcode with named numbers.
type GSMMAPLocalErrorcode = int64

const (
	GSMMAPLocalErrorcodeUnknownSubscriber              GSMMAPLocalErrorcode = 1
	GSMMAPLocalErrorcodeUnknownBaseStation             GSMMAPLocalErrorcode = 2
	GSMMAPLocalErrorcodeUnknownMSC                     GSMMAPLocalErrorcode = 3
	GSMMAPLocalErrorcodeSecureTransportError           GSMMAPLocalErrorcode = 4
	GSMMAPLocalErrorcodeUnidentifiedSubscriber         GSMMAPLocalErrorcode = 5
	GSMMAPLocalErrorcodeAbsentSubscriberSM             GSMMAPLocalErrorcode = 6
	GSMMAPLocalErrorcodeUnknownEquipment               GSMMAPLocalErrorcode = 7
	GSMMAPLocalErrorcodeRoamingNotAllowed              GSMMAPLocalErrorcode = 8
	GSMMAPLocalErrorcodeIllegalSubscriber              GSMMAPLocalErrorcode = 9
	GSMMAPLocalErrorcodeBearerServiceNotProvisioned    GSMMAPLocalErrorcode = 10
	GSMMAPLocalErrorcodeTeleserviceNotProvisioned      GSMMAPLocalErrorcode = 11
	GSMMAPLocalErrorcodeIllegalEquipment               GSMMAPLocalErrorcode = 12
	GSMMAPLocalErrorcodeCallBarred                     GSMMAPLocalErrorcode = 13
	GSMMAPLocalErrorcodeForwardingViolation            GSMMAPLocalErrorcode = 14
	GSMMAPLocalErrorcodeCugReject                      GSMMAPLocalErrorcode = 15
	GSMMAPLocalErrorcodeIllegalSSOperation             GSMMAPLocalErrorcode = 16
	GSMMAPLocalErrorcodeSsErrorStatus                  GSMMAPLocalErrorcode = 17
	GSMMAPLocalErrorcodeSsNotAvailable                 GSMMAPLocalErrorcode = 18
	GSMMAPLocalErrorcodeSsSubscriptionViolation        GSMMAPLocalErrorcode = 19
	GSMMAPLocalErrorcodeSsIncompatibility              GSMMAPLocalErrorcode = 20
	GSMMAPLocalErrorcodeFacilityNotSupported           GSMMAPLocalErrorcode = 21
	GSMMAPLocalErrorcodeOngoingGroupCall               GSMMAPLocalErrorcode = 22
	GSMMAPLocalErrorcodeInvalidTargetBaseStation       GSMMAPLocalErrorcode = 23
	GSMMAPLocalErrorcodeNoRadioResourceAvailable       GSMMAPLocalErrorcode = 24
	GSMMAPLocalErrorcodeNoHandoverNumberAvailable      GSMMAPLocalErrorcode = 25
	GSMMAPLocalErrorcodeSubsequentHandoverFailure      GSMMAPLocalErrorcode = 26
	GSMMAPLocalErrorcodeAbsentSubscriber               GSMMAPLocalErrorcode = 27
	GSMMAPLocalErrorcodeIncompatibleTerminal           GSMMAPLocalErrorcode = 28
	GSMMAPLocalErrorcodeShortTermDenial                GSMMAPLocalErrorcode = 29
	GSMMAPLocalErrorcodeLongTermDenial                 GSMMAPLocalErrorcode = 30
	GSMMAPLocalErrorcodeSubscriberBusyForMTSMS         GSMMAPLocalErrorcode = 31
	GSMMAPLocalErrorcodeSmDeliveryFailure              GSMMAPLocalErrorcode = 32
	GSMMAPLocalErrorcodeMessageWaitingListFull         GSMMAPLocalErrorcode = 33
	GSMMAPLocalErrorcodeSystemFailure                  GSMMAPLocalErrorcode = 34
	GSMMAPLocalErrorcodeDataMissing                    GSMMAPLocalErrorcode = 35
	GSMMAPLocalErrorcodeUnexpectedDataValue            GSMMAPLocalErrorcode = 36
	GSMMAPLocalErrorcodePwRegistrationFailure          GSMMAPLocalErrorcode = 37
	GSMMAPLocalErrorcodeNegativePWCheck                GSMMAPLocalErrorcode = 38
	GSMMAPLocalErrorcodeNoRoamingNumberAvailable       GSMMAPLocalErrorcode = 39
	GSMMAPLocalErrorcodeTracingBufferFull              GSMMAPLocalErrorcode = 40
	GSMMAPLocalErrorcodeTargetCellOutsideGroupCallArea GSMMAPLocalErrorcode = 42
	GSMMAPLocalErrorcodeNumberOfPWAttemptsViolation    GSMMAPLocalErrorcode = 43
	GSMMAPLocalErrorcodeNumberChanged                  GSMMAPLocalErrorcode = 44
	GSMMAPLocalErrorcodeBusySubscriber                 GSMMAPLocalErrorcode = 45
	GSMMAPLocalErrorcodeNoSubscriberReply              GSMMAPLocalErrorcode = 46
	GSMMAPLocalErrorcodeForwardingFailed               GSMMAPLocalErrorcode = 47
	GSMMAPLocalErrorcodeOrNotAllowed                   GSMMAPLocalErrorcode = 48
	GSMMAPLocalErrorcodeAtiNotAllowed                  GSMMAPLocalErrorcode = 49
	GSMMAPLocalErrorcodeNoGroupCallNumberAvailable     GSMMAPLocalErrorcode = 50
	GSMMAPLocalErrorcodeResourceLimitation             GSMMAPLocalErrorcode = 51
	GSMMAPLocalErrorcodeUnauthorizedRequestingNetwork  GSMMAPLocalErrorcode = 52
	GSMMAPLocalErrorcodeUnauthorizedLCSClient          GSMMAPLocalErrorcode = 53
	GSMMAPLocalErrorcodePositionMethodFailure          GSMMAPLocalErrorcode = 54
	GSMMAPLocalErrorcodeUnknownOrUnreachableLCSClient  GSMMAPLocalErrorcode = 58
	GSMMAPLocalErrorcodeMmEventNotSupported            GSMMAPLocalErrorcode = 59
	GSMMAPLocalErrorcodeAtsiNotAllowed                 GSMMAPLocalErrorcode = 60
	GSMMAPLocalErrorcodeAtmNotAllowed                  GSMMAPLocalErrorcode = 61
	GSMMAPLocalErrorcodeInformationNotAvailable        GSMMAPLocalErrorcode = 62
	GSMMAPLocalErrorcodeUnknownAlphabet                GSMMAPLocalErrorcode = 71
	GSMMAPLocalErrorcodeUssdBusy                       GSMMAPLocalErrorcode = 72
)

// LocalErrorcode represents the ASN.1 type LocalErrorcode (INTEGER).
type LocalErrorcode = GSMMAPLocalErrorcode

// DumGeneralProblem represents the ASN.1 INTEGER type DumGeneralProblem with named numbers.
type DumGeneralProblem = int64

const (
	DumGeneralProblemUnrecognizedComponent    DumGeneralProblem = 0
	DumGeneralProblemMistypedComponent        DumGeneralProblem = 1
	DumGeneralProblemBadlyStructuredComponent DumGeneralProblem = 2
)

// DumInvokeProblem represents the ASN.1 INTEGER type DumInvokeProblem with named numbers.
type DumInvokeProblem = int64

const (
	DumInvokeProblemDuplicateInvokeID         DumInvokeProblem = 0
	DumInvokeProblemUnrecognizedOperation     DumInvokeProblem = 1
	DumInvokeProblemMistypedParameter         DumInvokeProblem = 2
	DumInvokeProblemResourceLimitation        DumInvokeProblem = 3
	DumInvokeProblemInitiatingRelease         DumInvokeProblem = 4
	DumInvokeProblemUnrecognizedLinkedID      DumInvokeProblem = 5
	DumInvokeProblemLinkedResponseUnexpected  DumInvokeProblem = 6
	DumInvokeProblemUnexpectedLinkedOperation DumInvokeProblem = 7
)

// DumReturnResultProblem represents the ASN.1 INTEGER type DumReturnResultProblem with named numbers.
type DumReturnResultProblem = int64

const (
	DumReturnResultProblemUnrecognizedInvokeID   DumReturnResultProblem = 0
	DumReturnResultProblemReturnResultUnexpected DumReturnResultProblem = 1
	DumReturnResultProblemMistypedParameter      DumReturnResultProblem = 2
)

// DumReturnErrorProblem represents the ASN.1 INTEGER type DumReturnErrorProblem with named numbers.
type DumReturnErrorProblem = int64

const (
	DumReturnErrorProblemUnrecognizedInvokeID  DumReturnErrorProblem = 0
	DumReturnErrorProblemReturnErrorUnexpected DumReturnErrorProblem = 1
	DumReturnErrorProblemUnrecognizedError     DumReturnErrorProblem = 2
	DumReturnErrorProblemUnexpectedError       DumReturnErrorProblem = 3
	DumReturnErrorProblemMistypedParameter     DumReturnErrorProblem = 4
)

// BssAPDU represents the ASN.1 type Bss-APDU (SEQUENCE).
type BssAPDU struct {
	ProtocolId         ProtocolId          `asn1:""`
	SignalInfo         SignalInfo          `asn1:""`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// ProvideSIWFSNumberArg represents the ASN.1 type ProvideSIWFSNumberArg (SEQUENCE).
type ProvideSIWFSNumberArg struct {
	GsmBearerCapability     ExternalSignalInfo  `asn1:"tag:0,context,implicit"`
	IsdnBearerCapability    ExternalSignalInfo  `asn1:"tag:1,context,implicit"`
	CallDirection           CallDirection       `asn1:"tag:2,context,implicit"`
	BSubscriberAddress      ISDNAddressString   `asn1:"tag:3,context,implicit"`
	ChosenChannel           ExternalSignalInfo  `asn1:"tag:4,context,implicit"`
	LowerLayerCompatibility *ExternalSignalInfo `asn1:"tag:5,context,implicit,optional" json:"LowerLayerCompatibility,omitempty"`
	HighLayerCompatibility  *ExternalSignalInfo `asn1:"tag:6,context,implicit,optional" json:"HighLayerCompatibility,omitempty"`
	ExtensionContainer      *ExtensionContainer `asn1:"tag:7,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64               `asn1:"-" json:"-"`
	ExtPresent_             []bool              `asn1:"-" json:"-"`
	ExtData_                [][]byte            `asn1:"-" json:"-"`
}

// ProvideSIWFSNumberRes represents the ASN.1 type ProvideSIWFSNumberRes (SEQUENCE).
type ProvideSIWFSNumberRes struct {
	SIWFSNumber        ISDNAddressString   `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// CallDirection represents the ASN.1 type CallDirection (OCTET_STRING).
type CallDirection = []byte

// PurgeMSArgV2 represents the ASN.1 type PurgeMSArgV2 (SEQUENCE).
type PurgeMSArgV2 struct {
	Imsi        IMSI               `asn1:""`
	VlrNumber   *ISDNAddressString `asn1:",optional" json:"VlrNumber,omitempty"`
	ExtCount_   int64              `asn1:"-" json:"-"`
	ExtPresent_ []bool             `asn1:"-" json:"-"`
	ExtData_    [][]byte           `asn1:"-" json:"-"`
}

// PrepareHOArgOld represents the ASN.1 type PrepareHO-ArgOld (SEQUENCE).
type PrepareHOArgOld struct {
	TargetCellId        *GlobalCellId `asn1:",optional" json:"TargetCellId,omitempty"`
	HoNumberNotRequired *struct{}     `asn1:",optional" json:"HoNumberNotRequired,omitempty"`
	BssAPDU             *BssAPDU      `asn1:",optional" json:"BssAPDU,omitempty"`
	ExtCount_           int64         `asn1:"-" json:"-"`
	ExtPresent_         []bool        `asn1:"-" json:"-"`
	ExtData_            [][]byte      `asn1:"-" json:"-"`
}

// PrepareHOResOld represents the ASN.1 type PrepareHO-ResOld (SEQUENCE).
type PrepareHOResOld struct {
	HandoverNumber *ISDNAddressString `asn1:",optional" json:"HandoverNumber,omitempty"`
	BssAPDU        *BssAPDU           `asn1:",optional" json:"BssAPDU,omitempty"`
	ExtCount_      int64              `asn1:"-" json:"-"`
	ExtPresent_    []bool             `asn1:"-" json:"-"`
	ExtData_       [][]byte           `asn1:"-" json:"-"`
}

// SendAuthenticationInfoResOld represents the ASN.1 type SendAuthenticationInfoResOld (SEQUENCE_OF).
type SendAuthenticationInfoResOld = []SendAuthenticationInfoResOldElem

// DumRAND represents the ASN.1 type DumRAND (OCTET_STRING).
type DumRAND = []byte

// DumSRES represents the ASN.1 type DumSRES (OCTET_STRING).
type DumSRES = []byte

// DumKc represents the ASN.1 type DumKc (OCTET_STRING).
type DumKc = []byte

// SendIdentificationResV2 represents the ASN.1 type SendIdentificationResV2 (SEQUENCE).
type SendIdentificationResV2 struct {
	Imsi              *IMSI          `asn1:",optional" json:"Imsi,omitempty"`
	TripletList       TripletListold `asn1:",optional" json:"TripletList,omitempty"`
	TripletListIndef_ bool           `asn1:"-" json:"-"`
	ExtCount_         int64          `asn1:"-" json:"-"`
	ExtPresent_       []bool         `asn1:"-" json:"-"`
	ExtData_          [][]byte       `asn1:"-" json:"-"`
}

// TripletListold represents the ASN.1 type TripletListold (SEQUENCE_OF).
type TripletListold = []AuthenticationTripletV2

// AuthenticationTripletV2 represents the ASN.1 type AuthenticationTriplet-v2 (SEQUENCE).
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
	ChannelType        *ExternalSignalInfo `asn1:"tag:0,context,implicit,optional" json:"ChannelType,omitempty"`
	ChosenChannel      *ExternalSignalInfo `asn1:"tag:1,context,implicit,optional" json:"ChosenChannel,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// SIWFSSignallingModifyRes represents the ASN.1 type SIWFSSignallingModifyRes (SEQUENCE).
type SIWFSSignallingModifyRes struct {
	ChannelType        *ExternalSignalInfo `asn1:"tag:0,context,implicit,optional" json:"ChannelType,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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

// PlmnContainer represents the ASN.1 type PlmnContainer (SEQUENCE).
type PlmnContainer struct {
	Msisdn               *ISDNAddressString          `asn1:"tag:0,context,implicit,optional" json:"Msisdn,omitempty"`
	Category             *DumCategory                `asn1:"tag:1,context,implicit,optional" json:"Category,omitempty"`
	BasicService         *BasicServiceCode           `asn1:",optional" json:"BasicService,omitempty"`
	OperatorSSCode       PlmnContainerOperatorSSCode `asn1:"tag:4,context,implicit,optional" json:"OperatorSSCode,omitempty"`
	OperatorSSCodeIndef_ bool                        `asn1:"-" json:"-"`
	ExtCount_            int64                       `asn1:"-" json:"-"`
	ExtPresent_          []bool                      `asn1:"-" json:"-"`
	ExtData_             [][]byte                    `asn1:"-" json:"-"`
}

// DumCategory represents the ASN.1 type DumCategory (OCTET_STRING).
type DumCategory = []byte

// ForwardSMArg represents the ASN.1 type ForwardSM-Arg (SEQUENCE).
type ForwardSMArg struct {
	SmRPDA             SMRPDAold  `asn1:""`
	SmRPOA             SMRPOAold  `asn1:""`
	SmRPUI             SignalInfo `asn1:""`
	MoreMessagesToSend *struct{}  `asn1:",optional" json:"MoreMessagesToSend,omitempty"`
	ExtCount_          int64      `asn1:"-" json:"-"`
	ExtPresent_        []bool     `asn1:"-" json:"-"`
	ExtData_           [][]byte   `asn1:"-" json:"-"`
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
	Imsi                   *IMSI          `json:"Imsi,omitempty"`
	Lmsi                   *LMSI          `json:"Lmsi,omitempty"`
	ServiceCentreAddressDA *AddressString `json:"ServiceCentreAddressDA,omitempty"`
	NoSMRPDA               *struct{}      `json:"NoSMRPDA,omitempty"`
}

// NewSMRPDAoldImsi creates a SM-RP-DAold with the imsi alternative.
func NewSMRPDAoldImsi(v IMSI) SMRPDAold {
	return SMRPDAold{
		Choice: SMRPDAoldChoiceImsi,
		Imsi:   &v,
	}
}

// NewSMRPDAoldLmsi creates a SM-RP-DAold with the lmsi alternative.
func NewSMRPDAoldLmsi(v LMSI) SMRPDAold {
	return SMRPDAold{
		Choice: SMRPDAoldChoiceLmsi,
		Lmsi:   &v,
	}
}

// NewSMRPDAoldServiceCentreAddressDA creates a SM-RP-DAold with the serviceCentreAddressDA alternative.
func NewSMRPDAoldServiceCentreAddressDA(v AddressString) SMRPDAold {
	return SMRPDAold{
		Choice:                 SMRPDAoldChoiceServiceCentreAddressDA,
		ServiceCentreAddressDA: &v,
	}
}

// NewSMRPDAoldNoSMRPDA creates a SM-RP-DAold with the noSM-RP-DA alternative.
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
	Msisdn                 *ISDNAddressString `json:"Msisdn,omitempty"`
	ServiceCentreAddressOA *AddressString     `json:"ServiceCentreAddressOA,omitempty"`
	NoSMRPOA               *struct{}          `json:"NoSMRPOA,omitempty"`
}

// NewSMRPOAoldMsisdn creates a SM-RP-OAold with the msisdn alternative.
func NewSMRPOAoldMsisdn(v ISDNAddressString) SMRPOAold {
	return SMRPOAold{
		Choice: SMRPOAoldChoiceMsisdn,
		Msisdn: &v,
	}
}

// NewSMRPOAoldServiceCentreAddressOA creates a SM-RP-OAold with the serviceCentreAddressOA alternative.
func NewSMRPOAoldServiceCentreAddressOA(v AddressString) SMRPOAold {
	return SMRPOAold{
		Choice:                 SMRPOAoldChoiceServiceCentreAddressOA,
		ServiceCentreAddressOA: &v,
	}
}

// NewSMRPOAoldNoSMRPOA creates a SM-RP-OAold with the noSM-RP-OA alternative.
func NewSMRPOAoldNoSMRPOA(v struct{}) SMRPOAold {
	return SMRPOAold{
		Choice:   SMRPOAoldChoiceNoSMRPOA,
		NoSMRPOA: &v,
	}
}

// SendRoutingInfoArgV2 represents the ASN.1 type SendRoutingInfoArgV2 (SEQUENCE).
type SendRoutingInfoArgV2 struct {
	Msisdn             ISDNAddressString   `asn1:"tag:0,context,implicit"`
	CugCheckInfo       *CUGCheckInfo       `asn1:"tag:1,context,implicit,optional" json:"CugCheckInfo,omitempty"`
	NumberOfForwarding *NumberOfForwarding `asn1:"tag:2,context,implicit,optional" json:"NumberOfForwarding,omitempty"`
	NetworkSignalInfo  *ExternalSignalInfo `asn1:"tag:10,context,implicit,optional" json:"NetworkSignalInfo,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// SendRoutingInfoResV2 represents the ASN.1 type SendRoutingInfoResV2 (SEQUENCE).
type SendRoutingInfoResV2 struct {
	Imsi         IMSI          `asn1:""`
	RoutingInfo  RoutingInfo   `asn1:""`
	CugCheckInfo *CUGCheckInfo `asn1:",optional" json:"CugCheckInfo,omitempty"`
	ExtCount_    int64         `asn1:"-" json:"-"`
	ExtPresent_  []bool        `asn1:"-" json:"-"`
	ExtData_     [][]byte      `asn1:"-" json:"-"`
}

// BeginSubscriberActivityArg represents the ASN.1 type BeginSubscriberActivityArg (SEQUENCE).
type BeginSubscriberActivityArg struct {
	Imsi                    IMSI              `asn1:""`
	OriginatingEntityNumber ISDNAddressString `asn1:""`
	Msisdn                  *AddressString    `asn1:"tag:28,private,implicit,optional" json:"Msisdn,omitempty"`
	ExtCount_               int64             `asn1:"-" json:"-"`
	ExtPresent_             []bool            `asn1:"-" json:"-"`
	ExtData_                [][]byte          `asn1:"-" json:"-"`
}

// RoutingInfoForSMArgV1 represents the ASN.1 type RoutingInfoForSM-ArgV1 (SEQUENCE).
type RoutingInfoForSMArgV1 struct {
	Msisdn               ISDNAddressString `asn1:"tag:0,context,implicit"`
	SmRPPRI              bool              `asn1:"tag:1,context,implicit"`
	SmRPPRIRaw_          byte              `asn1:"-" json:"-"`
	ServiceCentreAddress AddressString     `asn1:"tag:2,context,implicit"`
	CugInterlock         *CUGInterlock     `asn1:"tag:3,context,implicit,optional" json:"CugInterlock,omitempty"`
	TeleserviceCode      *TeleserviceCode  `asn1:"tag:5,context,implicit,optional" json:"TeleserviceCode,omitempty"`
	Imsi                 *IMSI             `asn1:"tag:12,context,implicit,optional" json:"Imsi,omitempty"`
	ExtCount_            int64             `asn1:"-" json:"-"`
	ExtPresent_          []bool            `asn1:"-" json:"-"`
	ExtData_             [][]byte          `asn1:"-" json:"-"`
}

// RoutingInfoForSMResV2 represents the ASN.1 type RoutingInfoForSM-ResV2 (SEQUENCE).
type RoutingInfoForSMResV2 struct {
	Imsi                 IMSI                   `asn1:""`
	LocationInfoWithLMSI LocationInfoWithLMSIv2 `asn1:"tag:0,context,implicit"`
	MwdSet               *bool                  `asn1:"tag:2,context,implicit,optional" json:"MwdSet,omitempty"`
	MwdSetRaw_           byte                   `asn1:"-" json:"-"`
	ExtCount_            int64                  `asn1:"-" json:"-"`
	ExtPresent_          []bool                 `asn1:"-" json:"-"`
	ExtData_             [][]byte               `asn1:"-" json:"-"`
}

// LocationInfoWithLMSIv2 represents the ASN.1 type LocationInfoWithLMSIv2 (SEQUENCE).
type LocationInfoWithLMSIv2 struct {
	LocationInfo LocationInfo `asn1:""`
	Lmsi         *LMSI        `asn1:",optional" json:"Lmsi,omitempty"`
	ExtCount_    int64        `asn1:"-" json:"-"`
	ExtPresent_  []bool       `asn1:"-" json:"-"`
	ExtData_     [][]byte     `asn1:"-" json:"-"`
}

// LocationInfo choice constants.
const (
	LocationInfoChoiceRoamingNumber = 1
	LocationInfoChoiceMscNumber     = 2
)

// LocationInfo represents the ASN.1 CHOICE type LocationInfo.
type LocationInfo struct {
	Choice        int
	RoamingNumber *ISDNAddressString `json:"RoamingNumber,omitempty"`
	MscNumber     *ISDNAddressString `json:"MscNumber,omitempty"`
}

// NewLocationInfoRoamingNumber creates a LocationInfo with the roamingNumber alternative.
func NewLocationInfoRoamingNumber(v ISDNAddressString) LocationInfo {
	return LocationInfo{
		Choice:        LocationInfoChoiceRoamingNumber,
		RoamingNumber: &v,
	}
}

// NewLocationInfoMscNumber creates a LocationInfo with the msc-Number alternative.
func NewLocationInfoMscNumber(v ISDNAddressString) LocationInfo {
	return LocationInfo{
		Choice:    LocationInfoChoiceMscNumber,
		MscNumber: &v,
	}
}

// Ki represents the ASN.1 type Ki (OCTET_STRING).
type Ki = []byte

// SendParametersArg represents the ASN.1 type SendParametersArg (SEQUENCE).
type SendParametersArg struct {
	SubscriberId               SubscriberId         `asn1:""`
	RequestParameterList       RequestParameterList `asn1:""`
	RequestParameterListIndef_ bool                 `asn1:"-" json:"-"`
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
	Imsi              *IMSI                     `json:"Imsi,omitempty"`
	AuthenticationSet *AuthenticationSetListOld `json:"AuthenticationSet,omitempty"`
	SubscriberData    *SubscriberData           `json:"SubscriberData,omitempty"`
	Ki                *Ki                       `json:"Ki,omitempty"`
}

// NewSentParameterImsi creates a SentParameter with the imsi alternative.
func NewSentParameterImsi(v IMSI) SentParameter {
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
func NewSentParameterSubscriberData(v SubscriberData) SentParameter {
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
	TripletList    TripletList    `json:"TripletList,omitempty"`
	QuintupletList QuintupletList `json:"QuintupletList,omitempty"`
}

// NewAuthenticationSetListOldTripletList creates a AuthenticationSetListOld with the tripletList alternative.
func NewAuthenticationSetListOldTripletList(v TripletList) AuthenticationSetListOld {
	return AuthenticationSetListOld{
		Choice:      AuthenticationSetListOldChoiceTripletList,
		TripletList: v,
	}
}

// NewAuthenticationSetListOldQuintupletList creates a AuthenticationSetListOld with the quintupletList alternative.
func NewAuthenticationSetListOldQuintupletList(v QuintupletList) AuthenticationSetListOld {
	return AuthenticationSetListOld{
		Choice:         AuthenticationSetListOldChoiceQuintupletList,
		QuintupletList: v,
	}
}

// SentParameterList represents the ASN.1 type SentParameterList (SEQUENCE_OF).
type SentParameterList = []SentParameter

// ResetArgV2 represents the ASN.1 type ResetArgV2 (SEQUENCE).
type ResetArgV2 struct {
	NetworkResource *NetworkResource  `asn1:",optional" json:"NetworkResource,omitempty"`
	HlrNumber       ISDNAddressString `asn1:""`
	HlrList         HLRList           `asn1:",optional" json:"HlrList,omitempty"`
	HlrListIndef_   bool              `asn1:"-" json:"-"`
	ExtCount_       int64             `asn1:"-" json:"-"`
	ExtPresent_     []bool            `asn1:"-" json:"-"`
	ExtData_        [][]byte          `asn1:"-" json:"-"`
}

// ReturnResultResultretres represents the ASN.1 type ReturnResult-resultretres (SEQUENCE).
type ReturnResultResultretres struct {
	OpCode          MAPOPERATION      `asn1:""`
	Returnparameter *runtime.RawValue `asn1:",optional" json:"Returnparameter,omitempty"`
}

// RejectInvokeIDRej choice constants.
const (
	RejectInvokeIDRejChoiceDerivable    = 1
	RejectInvokeIDRejChoiceNotDerivable = 2
)

// RejectInvokeIDRej represents the ASN.1 CHOICE type Reject-invokeIDRej.
type RejectInvokeIDRej struct {
	Choice       int
	Derivable    *InvokeIdType `json:"Derivable,omitempty"`
	NotDerivable *struct{}     `json:"NotDerivable,omitempty"`
}

// NewRejectInvokeIDRejDerivable creates a Reject-invokeIDRej with the derivable alternative.
func NewRejectInvokeIDRejDerivable(v InvokeIdType) RejectInvokeIDRej {
	return RejectInvokeIDRej{
		Choice:    RejectInvokeIDRejChoiceDerivable,
		Derivable: &v,
	}
}

// NewRejectInvokeIDRejNotDerivable creates a Reject-invokeIDRej with the not-derivable alternative.
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

// SendAuthenticationInfoResOldElem represents the ASN.1 type SendAuthenticationInfoResOld-Elem (SEQUENCE).
type SendAuthenticationInfoResOldElem struct {
	Rand        DumRAND  `asn1:""`
	Sres        DumSRES  `asn1:""`
	Kc          DumKc    `asn1:""`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// PlmnContainerOperatorSSCode represents the ASN.1 type PlmnContainer-operatorSS-Code (SEQUENCE_OF).
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
		enc_0 := ber.EncodeInteger(int64(*v.LocalValue))
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
		decVal, _, intErr := ber.DecodeInteger(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		tmp := OperationLocalvalue(decVal)
		v.LocalValue = &tmp
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
		enc_0 := ber.EncodeInteger(int64(*v.LocalValue))
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
		decVal, _, intErr := ber.DecodeInteger(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		tmp := LocalErrorcode(decVal)
		v.LocalValue = &tmp
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
	v.ProtocolId = ProtocolId(val_protocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
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
	v.BSubscriberAddress = ISDNAddressString(rawVal_bsubscriberaddress)
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
				var dec_lowerlayercompatibility ExternalSignalInfo
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
				var dec_highlayercompatibility ExternalSignalInfo
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
				var dec_extensioncontainer ExtensionContainer
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
	v.SIWFSNumber = ISDNAddressString(rawVal_siwfsnumber)
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
				var dec_extensioncontainer ExtensionContainer
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

// MarshalBER encodes PurgeMSArgV2 to BER format.
func (v *PurgeMSArgV2) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes PurgeMSArgV2 to DER format.
func (v *PurgeMSArgV2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PurgeMSArgV2 from BER/DER format.
func (v *PurgeMSArgV2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PurgeMSArgV2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PurgeMSArgV2", Cause: ber.ErrExtraData}
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
	v.Imsi = IMSI(val_imsi)
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
				tmp_vlrnumber := ISDNAddressString(val_vlrnumber)
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
			return &ber.DecodeError{Offset: offset, TypeName: "PurgeMSArgV2", Cause: extErr_}
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
				tmp_targetcellid := GlobalCellId(val_targetcellid)
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
				tmp_handovernumber := ISDNAddressString(val_handovernumber)
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

// MarshalBERSendAuthenticationInfoResOld encodes a SendAuthenticationInfoResOld list to BER.
func MarshalBERSendAuthenticationInfoResOld(list SendAuthenticationInfoResOld) ([]byte, error) {
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

// UnmarshalBERSendAuthenticationInfoResOld decodes a SendAuthenticationInfoResOld list from BER.
func UnmarshalBERSendAuthenticationInfoResOld(data []byte) (SendAuthenticationInfoResOld, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SendAuthenticationInfoResOld: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SendAuthenticationInfoResOld", Cause: ber.ErrExtraData}
	}
	var result SendAuthenticationInfoResOld
	offset := 0
	for offset < len(content) {
		var elem SendAuthenticationInfoResOldElem
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

// MarshalBER encodes SendIdentificationResV2 to BER format.
func (v *SendIdentificationResV2) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SendIdentificationResV2 to DER format.
func (v *SendIdentificationResV2) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SendIdentificationResV2 from BER/DER format.
func (v *SendIdentificationResV2) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SendIdentificationResV2 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendIdentificationResV2", Cause: ber.ErrExtraData}
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
				tmp_imsi := IMSI(val_imsi)
				v.Imsi = &tmp_imsi
				offset += n
			}
		}
	}
	// Decode tripletList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (TripletListold)
				_, n_tripletlist, _, tlvErr_tripletlist := ber.DecodeTLV(content[offset:])
				if tlvErr_tripletlist != nil {
					return fmt.Errorf("decoding tripletList: %w", tlvErr_tripletlist)
				}
				dec_tripletlist, unmErr := UnmarshalBERTripletListold(content[offset : offset+n_tripletlist])
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
			return &ber.DecodeError{Offset: offset, TypeName: "SendIdentificationResV2", Cause: extErr_}
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
				var dec_channeltype ExternalSignalInfo
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
				var dec_chosenchannel ExternalSignalInfo
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
				var dec_extensioncontainer ExtensionContainer
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
				var dec_channeltype ExternalSignalInfo
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
				var dec_extensioncontainer ExtensionContainer
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
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
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
				tmp_msisdn := ISDNAddressString(rawVal_msisdn)
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
				// Decode nested CHOICE (BasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode
				if unmErr := dec_basicservice.UnmarshalBER(content[offset : offset+n_basicservice]); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				offset += n_basicservice
			}
		}
	}
	// Decode operatorSS-Code
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
	v.SmRPUI = SignalInfo(val_smrpui)
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
		tmp := IMSI(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMRPDAoldChoiceLmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding lmsi: %w", tlvErr)
		}
		tmp := LMSI(rawVal)
		v.Lmsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPDAoldChoiceServiceCentreAddressDA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressDA: %w", tlvErr)
		}
		tmp := AddressString(rawVal)
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
		tmp := ISDNAddressString(rawVal)
		v.Msisdn = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPOAoldChoiceServiceCentreAddressOA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressOA: %w", tlvErr)
		}
		tmp := AddressString(rawVal)
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
	v.Msisdn = ISDNAddressString(rawVal_msisdn)
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
				var dec_cugcheckinfo CUGCheckInfo
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
				tmp_numberofforwarding := NumberOfForwarding(decVal_numberofforwarding)
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
				var dec_networksignalinfo ExternalSignalInfo
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
	v.Imsi = IMSI(val_imsi)
	offset += n
	// Decode routingInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field routingInfo")
	}
	// Decode nested CHOICE (RoutingInfo)
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
				// Decode nested SEQUENCE (CUGCheckInfo)
				_, n_cugcheckinfo, _, tlvErr_cugcheckinfo := ber.DecodeTLV(content[offset:])
				if tlvErr_cugcheckinfo != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", tlvErr_cugcheckinfo)
				}
				var dec_cugcheckinfo CUGCheckInfo
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
	v.Imsi = IMSI(val_imsi)
	offset += n
	// Decode originatingEntityNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field originatingEntityNumber")
	}
	val_originatingentitynumber, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding originatingEntityNumber: %w", err)
	}
	v.OriginatingEntityNumber = ISDNAddressString(val_originatingentitynumber)
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
				tmp_msisdn := AddressString(rawVal_msisdn)
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
	v.Msisdn = ISDNAddressString(rawVal_msisdn)
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
	v.ServiceCentreAddress = AddressString(rawVal_servicecentreaddress)
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
				tmp_cuginterlock := CUGInterlock(rawVal_cuginterlock)
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
				tmp_teleservicecode := TeleserviceCode(rawVal_teleservicecode)
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
				tmp_imsi := IMSI(rawVal_imsi)
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
	v.Imsi = IMSI(val_imsi)
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
				tmp_lmsi := LMSI(val_lmsi)
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
		tmp := ISDNAddressString(rawVal)
		v.RoamingNumber = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = LocationInfoChoiceMscNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msc-Number: %w", tlvErr)
		}
		tmp := ISDNAddressString(rawVal)
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
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
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
	// Decode nested CHOICE (SubscriberId)
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
	// Decode nested SEQUENCE_OF (RequestParameterList)
	_, n_requestparameterlist, _, tlvErr_requestparameterlist := ber.DecodeTLV(content[offset:])
	if tlvErr_requestparameterlist != nil {
		return fmt.Errorf("decoding requestParameterList: %w", tlvErr_requestparameterlist)
	}
	dec_requestparameterlist, unmErr := UnmarshalBERRequestParameterList(content[offset : offset+n_requestparameterlist])
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
		tmp := IMSI(rawVal)
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
		var dec SubscriberData
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
		enc_0, err := MarshalBERTripletList(v.TripletList)
		if err != nil {
			return nil, fmt.Errorf("encoding tripletList: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case AuthenticationSetListOldChoiceQuintupletList:
		if v.QuintupletList == nil {
			return nil, fmt.Errorf("choice AuthenticationSetListOld: quintupletList is nil")
		}
		enc_1, err := MarshalBERQuintupletList(v.QuintupletList)
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
		dec, unmErr := UnmarshalBERTripletList(reconstructed)
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
		dec, unmErr := UnmarshalBERQuintupletList(reconstructed)
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
		enc_hlrlist, err := MarshalBERHLRList(v.HlrList)
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
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
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
				tmp_networkresource := NetworkResource(val_networkresource)
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
	v.HlrNumber = ISDNAddressString(val_hlrnumber)
	offset += n
	// Decode hlr-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (HLRList)
				_, n_hlrlist, _, tlvErr_hlrlist := ber.DecodeTLV(content[offset:])
				if tlvErr_hlrlist != nil {
					return fmt.Errorf("decoding hlr-List: %w", tlvErr_hlrlist)
				}
				dec_hlrlist, unmErr := UnmarshalBERHLRList(content[offset : offset+n_hlrlist])
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
		enc_0 := ber.EncodeInteger(int64(*v.GeneralProblem))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case DumRejectProblemChoiceInvokeProblem:
		if v.InvokeProblem == nil {
			return nil, fmt.Errorf("choice DumRejectProblem: invokeProblem is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.InvokeProblem))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	case DumRejectProblemChoiceReturnResultProblem:
		if v.ReturnResultProblem == nil {
			return nil, fmt.Errorf("choice DumRejectProblem: returnResultProblem is nil")
		}
		enc_2 := ber.EncodeInteger(int64(*v.ReturnResultProblem))
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_2)
		return enc_2, nil
	case DumRejectProblemChoiceReturnErrorProblem:
		if v.ReturnErrorProblem == nil {
			return nil, fmt.Errorf("choice DumRejectProblem: returnErrorProblem is nil")
		}
		enc_3 := ber.EncodeInteger(int64(*v.ReturnErrorProblem))
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
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding generalProblem: %w", intErr)
		}
		tmp := DumGeneralProblem(decVal)
		v.GeneralProblem = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = DumRejectProblemChoiceInvokeProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding invokeProblem: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding invokeProblem: %w", intErr)
		}
		tmp := DumInvokeProblem(decVal)
		v.InvokeProblem = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = DumRejectProblemChoiceReturnResultProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResultProblem: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding returnResultProblem: %w", intErr)
		}
		tmp := DumReturnResultProblem(decVal)
		v.ReturnResultProblem = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = DumRejectProblemChoiceReturnErrorProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnErrorProblem: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding returnErrorProblem: %w", intErr)
		}
		tmp := DumReturnErrorProblem(decVal)
		v.ReturnErrorProblem = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for DumRejectProblem CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SendAuthenticationInfoResOldElem to BER format.
func (v *SendAuthenticationInfoResOldElem) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SendAuthenticationInfoResOldElem to DER format.
func (v *SendAuthenticationInfoResOldElem) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SendAuthenticationInfoResOldElem from BER/DER format.
func (v *SendAuthenticationInfoResOldElem) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SendAuthenticationInfoResOldElem SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendAuthenticationInfoResOldElem", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "SendAuthenticationInfoResOldElem", Cause: extErr_}
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
