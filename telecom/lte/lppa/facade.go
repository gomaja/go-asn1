// Code generated from the pinned LPPa source closure. DO NOT EDIT.

package lppa

import (
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q31 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q25 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q16 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q26 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	q30 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q19 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q18 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	q29 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	q22 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	q20 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	q24 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	q21 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	q17 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s22"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s24"
	q27 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q23 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q28 "math/big"
)

type APERValue[T any] = q4.APERValue[T]
type AddOTDOACellInformation = q5.AddOTDOACellInformation

// AddOTDOACellInformationAPERValue is the concrete APERValue[AddOTDOACellInformation].
type AddOTDOACellInformationAPERValue = q5.AddOTDOACellInformationAPERValue

// AddOTDOACellInformationCodec binds the complete source value type.
var AddOTDOACellInformationCodec func() AddOTDOACellInformationValueCodec = q6.AddOTDOACellInformationCodec

// AddOTDOACellInformationComplete carries a complete AddOTDOACellInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AddOTDOACellInformationComplete = q6.AddOTDOACellInformationComplete

// AddOTDOACellInformationValueCodec is the concrete ValueCodec[AddOTDOACellInformation].
type AddOTDOACellInformationValueCodec = q5.AddOTDOACellInformationValueCodec
type AddOTDOACells = q5.AddOTDOACells

// AddOTDOACellsAPERValue is the concrete APERValue[AddOTDOACells].
type AddOTDOACellsAPERValue = q5.AddOTDOACellsAPERValue

// AddOTDOACellsCodec binds the complete APER value type.
var AddOTDOACellsCodec func() AddOTDOACellsValueCodec = q7.AddOTDOACellsCodec

// AddOTDOACellsComplete carries a complete AddOTDOACells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AddOTDOACellsComplete = q6.AddOTDOACellsComplete

// AddOTDOACellsElem represents the ASN.1 type Add-OTDOACells-Elem (SEQUENCE).
type AddOTDOACellsElem = q5.AddOTDOACellsElem

// AddOTDOACellsElemAPERValue is the concrete APERValue[AddOTDOACellsElem].
type AddOTDOACellsElemAPERValue = q5.AddOTDOACellsElemAPERValue

// AddOTDOACellsElemCodec binds the complete source value type.
var AddOTDOACellsElemCodec func() AddOTDOACellsElemValueCodec = q5.AddOTDOACellsElemCodec

// AddOTDOACellsElemValueCodec is the concrete ValueCodec[AddOTDOACellsElem].
type AddOTDOACellsElemValueCodec = q5.AddOTDOACellsElemValueCodec
type AddOTDOACellsExtIETable = q8.AddOTDOACellsExtIETable

var AddOTDOACellsExtIEs func() AddOTDOACellsExtIETable = q8.AddOTDOACellsExtIEs

// AddOTDOACellsExtIEsExtContainer is the concrete ProtocolExtensionContainer[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsExtContainer = q8.AddOTDOACellsExtIEsExtContainer

// AddOTDOACellsExtIEsExtField is the concrete ProtocolExtensionField[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsExtField = q8.AddOTDOACellsExtIEsExtField

// AddOTDOACellsExtIEsIEContainer is the concrete ProtocolIEContainer[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsIEContainer = q8.AddOTDOACellsExtIEsIEContainer

// AddOTDOACellsExtIEsIEField is the concrete ProtocolIEField[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsIEField = q8.AddOTDOACellsExtIEsIEField
type AddOTDOACellsExtIEsValue = q9.AddOTDOACellsExtIEsValue

// AddOTDOACellsValueCodec is the concrete ValueCodec[AddOTDOACells].
type AddOTDOACellsValueCodec = q5.AddOTDOACellsValueCodec

// AssistanceInformation represents the ASN.1 type Assistance-Information (SEQUENCE).
type AssistanceInformation = q10.AssistanceInformation

// AssistanceInformationAPERValue is the concrete APERValue[AssistanceInformation].
type AssistanceInformationAPERValue = q10.AssistanceInformationAPERValue

// AssistanceInformationCodec binds the complete APER value type.
var AssistanceInformationCodec func() AssistanceInformationValueCodec = q10.AssistanceInformationCodec

// AssistanceInformationControl represents the ASN.1 type AssistanceInformationControl (SEQUENCE).
type AssistanceInformationControl = q5.AssistanceInformationControl

// AssistanceInformationControlAPERValue is the concrete APERValue[AssistanceInformationControl].
type AssistanceInformationControlAPERValue = q5.AssistanceInformationControlAPERValue

// AssistanceInformationControlAssistanceInformationIEBinding is the concrete IEBinding[AssistanceInformation, AssistanceInformationControlIEValue].
type AssistanceInformationControlAssistanceInformationIEBinding = q10.AssistanceInformationControlAssistanceInformationIEBinding

// AssistanceInformationControlBroadcastIEBinding is the concrete IEBinding[Broadcast, AssistanceInformationControlIEValue].
type AssistanceInformationControlBroadcastIEBinding = q10.AssistanceInformationControlBroadcastIEBinding

// AssistanceInformationControlCodec binds the complete APER value type.
var AssistanceInformationControlCodec func() AssistanceInformationControlValueCodec = q11.AssistanceInformationControlCodec

type AssistanceInformationControlDescriptor = q11.AssistanceInformationControlDescriptor

// AssistanceInformationControlIEContainer is the concrete ProtocolIEContainer[AssistanceInformationControlIEValue].
type AssistanceInformationControlIEContainer = q10.AssistanceInformationControlIEContainer

// AssistanceInformationControlIEField is the concrete ProtocolIEField[AssistanceInformationControlIEValue].
type AssistanceInformationControlIEField = q10.AssistanceInformationControlIEField
type AssistanceInformationControlIETable = q10.AssistanceInformationControlIETable
type AssistanceInformationControlIEValue = q10.AssistanceInformationControlIEValue

var AssistanceInformationControlIEs func() AssistanceInformationControlIETable = q10.AssistanceInformationControlIEs

// AssistanceInformationControlInitiatingBinding is the concrete InitiatingBinding[AssistanceInformationControl].
type AssistanceInformationControlInitiatingBinding = q12.AssistanceInformationControlInitiatingBinding

var AssistanceInformationControlProcedure func() AssistanceInformationControlDescriptor = q11.AssistanceInformationControlProcedure

// AssistanceInformationControlValueCodec is the concrete ValueCodec[AssistanceInformationControl].
type AssistanceInformationControlValueCodec = q5.AssistanceInformationControlValueCodec
type AssistanceInformationExtIETable = q8.AssistanceInformationExtIETable

var AssistanceInformationExtIEs func() AssistanceInformationExtIETable = q8.AssistanceInformationExtIEs

// AssistanceInformationExtIEsExtContainer is the concrete ProtocolExtensionContainer[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsExtContainer = q8.AssistanceInformationExtIEsExtContainer

// AssistanceInformationExtIEsExtField is the concrete ProtocolExtensionField[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsExtField = q8.AssistanceInformationExtIEsExtField

// AssistanceInformationExtIEsIEContainer is the concrete ProtocolIEContainer[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsIEContainer = q8.AssistanceInformationExtIEsIEContainer

// AssistanceInformationExtIEsIEField is the concrete ProtocolIEField[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsIEField = q8.AssistanceInformationExtIEsIEField
type AssistanceInformationExtIEsValue = q9.AssistanceInformationExtIEsValue
type AssistanceInformationFailureList = q13.AssistanceInformationFailureList

// AssistanceInformationFailureListAPERValue is the concrete APERValue[AssistanceInformationFailureList].
type AssistanceInformationFailureListAPERValue = q13.AssistanceInformationFailureListAPERValue

// AssistanceInformationFailureListCodec binds the complete APER value type.
var AssistanceInformationFailureListCodec func() AssistanceInformationFailureListValueCodec = q6.AssistanceInformationFailureListCodec

// AssistanceInformationFailureListComplete carries a complete AssistanceInformationFailureList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AssistanceInformationFailureListComplete = q6.AssistanceInformationFailureListComplete

// AssistanceInformationFailureListElem represents the ASN.1 type AssistanceInformationFailureList-Elem (SEQUENCE).
type AssistanceInformationFailureListElem = q13.AssistanceInformationFailureListElem

// AssistanceInformationFailureListElemAPERValue is the concrete APERValue[AssistanceInformationFailureListElem].
type AssistanceInformationFailureListElemAPERValue = q13.AssistanceInformationFailureListElemAPERValue

// AssistanceInformationFailureListElemCodec binds the complete source value type.
var AssistanceInformationFailureListElemCodec func() AssistanceInformationFailureListElemValueCodec = q13.AssistanceInformationFailureListElemCodec

// AssistanceInformationFailureListElemValueCodec is the concrete ValueCodec[AssistanceInformationFailureListElem].
type AssistanceInformationFailureListElemValueCodec = q13.AssistanceInformationFailureListElemValueCodec
type AssistanceInformationFailureListExtIETable = q8.AssistanceInformationFailureListExtIETable

var AssistanceInformationFailureListExtIEs func() AssistanceInformationFailureListExtIETable = q8.AssistanceInformationFailureListExtIEs

// AssistanceInformationFailureListExtIEsExtContainer is the concrete ProtocolExtensionContainer[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsExtContainer = q8.AssistanceInformationFailureListExtIEsExtContainer

// AssistanceInformationFailureListExtIEsExtField is the concrete ProtocolExtensionField[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsExtField = q8.AssistanceInformationFailureListExtIEsExtField

// AssistanceInformationFailureListExtIEsIEContainer is the concrete ProtocolIEContainer[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsIEContainer = q8.AssistanceInformationFailureListExtIEsIEContainer

// AssistanceInformationFailureListExtIEsIEField is the concrete ProtocolIEField[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsIEField = q8.AssistanceInformationFailureListExtIEsIEField
type AssistanceInformationFailureListExtIEsValue = q9.AssistanceInformationFailureListExtIEsValue

// AssistanceInformationFailureListValueCodec is the concrete ValueCodec[AssistanceInformationFailureList].
type AssistanceInformationFailureListValueCodec = q13.AssistanceInformationFailureListValueCodec

// AssistanceInformationFeedback represents the ASN.1 type AssistanceInformationFeedback (SEQUENCE).
type AssistanceInformationFeedback = q6.AssistanceInformationFeedback

// AssistanceInformationFeedbackAPERValue is the concrete APERValue[AssistanceInformationFeedback].
type AssistanceInformationFeedbackAPERValue = q6.AssistanceInformationFeedbackAPERValue

// AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding is the concrete IEBinding[AssistanceInformationFailureList, AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding = q6.AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding

// AssistanceInformationFeedbackCodec binds the complete APER value type.
var AssistanceInformationFeedbackCodec func() AssistanceInformationFeedbackValueCodec = q4.AssistanceInformationFeedbackCodec

// AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding = q6.AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding
type AssistanceInformationFeedbackDescriptor = q4.AssistanceInformationFeedbackDescriptor

// AssistanceInformationFeedbackIEContainer is the concrete ProtocolIEContainer[AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackIEContainer = q6.AssistanceInformationFeedbackIEContainer

// AssistanceInformationFeedbackIEField is the concrete ProtocolIEField[AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackIEField = q6.AssistanceInformationFeedbackIEField
type AssistanceInformationFeedbackIETable = q6.AssistanceInformationFeedbackIETable
type AssistanceInformationFeedbackIEValue = q6.AssistanceInformationFeedbackIEValue

var AssistanceInformationFeedbackIEs func() AssistanceInformationFeedbackIETable = q6.AssistanceInformationFeedbackIEs

// AssistanceInformationFeedbackInitiatingBinding is the concrete InitiatingBinding[AssistanceInformationFeedback].
type AssistanceInformationFeedbackInitiatingBinding = q12.AssistanceInformationFeedbackInitiatingBinding

var AssistanceInformationFeedbackProcedure func() AssistanceInformationFeedbackDescriptor = q4.AssistanceInformationFeedbackProcedure

// AssistanceInformationFeedbackValueCodec is the concrete ValueCodec[AssistanceInformationFeedback].
type AssistanceInformationFeedbackValueCodec = q6.AssistanceInformationFeedbackValueCodec

// AssistanceInformationMetaData represents the ASN.1 type AssistanceInformationMetaData (SEQUENCE).
type AssistanceInformationMetaData = q13.AssistanceInformationMetaData

// AssistanceInformationMetaDataAPERValue is the concrete APERValue[AssistanceInformationMetaData].
type AssistanceInformationMetaDataAPERValue = q13.AssistanceInformationMetaDataAPERValue

// AssistanceInformationMetaDataCodec binds the complete source value type.
var AssistanceInformationMetaDataCodec func() AssistanceInformationMetaDataValueCodec = q13.AssistanceInformationMetaDataCodec

type AssistanceInformationMetaDataExtIETable = q8.AssistanceInformationMetaDataExtIETable

var AssistanceInformationMetaDataExtIEs func() AssistanceInformationMetaDataExtIETable = q8.AssistanceInformationMetaDataExtIEs

// AssistanceInformationMetaDataExtIEsExtContainer is the concrete ProtocolExtensionContainer[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsExtContainer = q8.AssistanceInformationMetaDataExtIEsExtContainer

// AssistanceInformationMetaDataExtIEsExtField is the concrete ProtocolExtensionField[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsExtField = q8.AssistanceInformationMetaDataExtIEsExtField

// AssistanceInformationMetaDataExtIEsIEContainer is the concrete ProtocolIEContainer[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsIEContainer = q8.AssistanceInformationMetaDataExtIEsIEContainer

// AssistanceInformationMetaDataExtIEsIEField is the concrete ProtocolIEField[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsIEField = q8.AssistanceInformationMetaDataExtIEsIEField
type AssistanceInformationMetaDataExtIEsValue = q9.AssistanceInformationMetaDataExtIEsValue

// AssistanceInformationMetaDataValueCodec is the concrete ValueCodec[AssistanceInformationMetaData].
type AssistanceInformationMetaDataValueCodec = q13.AssistanceInformationMetaDataValueCodec

// AssistanceInformationValueCodec is the concrete ValueCodec[AssistanceInformation].
type AssistanceInformationValueCodec = q10.AssistanceInformationValueCodec

// BCCH represents the ASN.1 type BCCH (INTEGER).
type BCCH = q14.BCCH

// BCCHAPERValue is the concrete APERValue[BCCH].
type BCCHAPERValue = q14.BCCHAPERValue

// BCCHCodec binds the complete source value type.
var BCCHCodec func() BCCHValueCodec = q9.BCCHCodec

// BCCHValueCodec is the concrete ValueCodec[BCCH].
type BCCHValueCodec = q14.BCCHValueCodec

// BSSID represents the ASN.1 type BSSID (OCTET_STRING).
type BSSID = q14.BSSID

// BSSIDAPERValue is the concrete APERValue[BSSID].
type BSSIDAPERValue = q14.BSSIDAPERValue

// BSSIDCodec binds the complete source value type.
var BSSIDCodec func() BSSIDValueCodec = q9.BSSIDCodec

// BSSIDValueCodec is the concrete ValueCodec[BSSID].
type BSSIDValueCodec = q14.BSSIDValueCodec

// BitmapsforNPRS represents the ASN.1 CHOICE type BitmapsforNPRS.
type BitmapsforNPRS = q13.BitmapsforNPRS

// BitmapsforNPRSAPERValue is the concrete APERValue[BitmapsforNPRS].
type BitmapsforNPRSAPERValue = q13.BitmapsforNPRSAPERValue

// BitmapsforNPRS choice constants.
const BitmapsforNPRSChoiceForty = q14.BitmapsforNPRSChoiceForty

// BitmapsforNPRS choice constants.
const BitmapsforNPRSChoiceFortyTdd = q14.BitmapsforNPRSChoiceFortyTdd

// BitmapsforNPRS choice constants.
const BitmapsforNPRSChoiceTen = q14.BitmapsforNPRSChoiceTen

// BitmapsforNPRS choice constants.
const BitmapsforNPRSChoiceTenTdd = q14.BitmapsforNPRSChoiceTenTdd

// BitmapsforNPRSCodec binds the complete source value type.
var BitmapsforNPRSCodec func() BitmapsforNPRSValueCodec = q13.BitmapsforNPRSCodec

// BitmapsforNPRSValueCodec is the concrete ValueCodec[BitmapsforNPRS].
type BitmapsforNPRSValueCodec = q13.BitmapsforNPRSValueCodec

// Broadcast represents the ASN.1 ENUMERATED type Broadcast.
type Broadcast = q14.Broadcast

// BroadcastAPERValue is the concrete APERValue[Broadcast].
type BroadcastAPERValue = q14.BroadcastAPERValue

// BroadcastCodec binds the complete APER value type.
var BroadcastCodec func() BroadcastValueCodec = q10.BroadcastCodec

// BroadcastPeriodicity represents the ASN.1 ENUMERATED type BroadcastPeriodicity.
type BroadcastPeriodicity = q14.BroadcastPeriodicity

// BroadcastPeriodicityAPERValue is the concrete APERValue[BroadcastPeriodicity].
type BroadcastPeriodicityAPERValue = q14.BroadcastPeriodicityAPERValue

// BroadcastPeriodicityCodec binds the complete source value type.
var BroadcastPeriodicityCodec func() BroadcastPeriodicityValueCodec = q9.BroadcastPeriodicityCodec

const BroadcastPeriodicityMs1280 = q14.BroadcastPeriodicityMs1280
const BroadcastPeriodicityMs160 = q14.BroadcastPeriodicityMs160
const BroadcastPeriodicityMs2560 = q14.BroadcastPeriodicityMs2560
const BroadcastPeriodicityMs320 = q14.BroadcastPeriodicityMs320
const BroadcastPeriodicityMs5120 = q14.BroadcastPeriodicityMs5120
const BroadcastPeriodicityMs640 = q14.BroadcastPeriodicityMs640
const BroadcastPeriodicityMs80 = q14.BroadcastPeriodicityMs80

// BroadcastPeriodicityValueCodec is the concrete ValueCodec[BroadcastPeriodicity].
type BroadcastPeriodicityValueCodec = q14.BroadcastPeriodicityValueCodec

const BroadcastStart = q14.BroadcastStart
const BroadcastStop = q14.BroadcastStop

// BroadcastValueCodec is the concrete ValueCodec[Broadcast].
type BroadcastValueCodec = q14.BroadcastValueCodec
type BuildError = q15.BuildError

// CPLength represents the ASN.1 ENUMERATED type CPLength.
type CPLength = q14.CPLength

// CPLengthAPERValue is the concrete APERValue[CPLength].
type CPLengthAPERValue = q14.CPLengthAPERValue

// CPLengthCodec binds the complete source value type.
var CPLengthCodec func() CPLengthValueCodec = q9.CPLengthCodec

const CPLengthExtended = q14.CPLengthExtended
const CPLengthNormal = q14.CPLengthNormal

// CPLengthValueCodec is the concrete ValueCodec[CPLength].
type CPLengthValueCodec = q14.CPLengthValueCodec

// Cause represents the ASN.1 CHOICE type Cause.
type Cause = q13.Cause

// CauseAPERValue is the concrete APERValue[Cause].
type CauseAPERValue = q13.CauseAPERValue

// Cause choice constants.
const CauseChoiceMisc = q14.CauseChoiceMisc

// Cause choice constants.
const CauseChoiceProtocol = q14.CauseChoiceProtocol

// Cause choice constants.
const CauseChoiceRadioNetwork = q14.CauseChoiceRadioNetwork

// CauseCodec binds the complete APER value type.
var CauseCodec func() CauseValueCodec = q16.CauseCodec

// CauseMisc represents the ASN.1 ENUMERATED type CauseMisc.
type CauseMisc = q14.CauseMisc

// CauseMiscAPERValue is the concrete APERValue[CauseMisc].
type CauseMiscAPERValue = q14.CauseMiscAPERValue

// CauseMiscCodec binds the complete source value type.
var CauseMiscCodec func() CauseMiscValueCodec = q9.CauseMiscCodec

const CauseMiscUnspecified = q14.CauseMiscUnspecified

// CauseMiscValueCodec is the concrete ValueCodec[CauseMisc].
type CauseMiscValueCodec = q14.CauseMiscValueCodec

// CauseProtocol represents the ASN.1 ENUMERATED type CauseProtocol.
type CauseProtocol = q14.CauseProtocol

// CauseProtocolAPERValue is the concrete APERValue[CauseProtocol].
type CauseProtocolAPERValue = q14.CauseProtocolAPERValue

const CauseProtocolAbstractSyntaxErrorFalselyConstructedMessage = q14.CauseProtocolAbstractSyntaxErrorFalselyConstructedMessage
const CauseProtocolAbstractSyntaxErrorIgnoreAndNotify = q14.CauseProtocolAbstractSyntaxErrorIgnoreAndNotify
const CauseProtocolAbstractSyntaxErrorReject = q14.CauseProtocolAbstractSyntaxErrorReject

// CauseProtocolCodec binds the complete source value type.
var CauseProtocolCodec func() CauseProtocolValueCodec = q9.CauseProtocolCodec

const CauseProtocolMessageNotCompatibleWithReceiverState = q14.CauseProtocolMessageNotCompatibleWithReceiverState
const CauseProtocolSemanticError = q14.CauseProtocolSemanticError
const CauseProtocolTransferSyntaxError = q14.CauseProtocolTransferSyntaxError
const CauseProtocolUnspecified = q14.CauseProtocolUnspecified

// CauseProtocolValueCodec is the concrete ValueCodec[CauseProtocol].
type CauseProtocolValueCodec = q14.CauseProtocolValueCodec

// CauseRadioNetwork represents the ASN.1 ENUMERATED type CauseRadioNetwork.
type CauseRadioNetwork = q14.CauseRadioNetwork

// CauseRadioNetworkAPERValue is the concrete APERValue[CauseRadioNetwork].
type CauseRadioNetworkAPERValue = q14.CauseRadioNetworkAPERValue

// CauseRadioNetworkCodec binds the complete source value type.
var CauseRadioNetworkCodec func() CauseRadioNetworkValueCodec = q9.CauseRadioNetworkCodec

const CauseRadioNetworkRequestedItemNotSupported = q14.CauseRadioNetworkRequestedItemNotSupported
const CauseRadioNetworkRequestedItemTemporarilyNotAvailable = q14.CauseRadioNetworkRequestedItemTemporarilyNotAvailable
const CauseRadioNetworkUnspecified = q14.CauseRadioNetworkUnspecified

// CauseRadioNetworkValueCodec is the concrete ValueCodec[CauseRadioNetwork].
type CauseRadioNetworkValueCodec = q14.CauseRadioNetworkValueCodec

// CauseValueCodec is the concrete ValueCodec[Cause].
type CauseValueCodec = q13.CauseValueCodec

// CellPortionID represents the ASN.1 type Cell-Portion-ID (INTEGER).
type CellPortionID = q14.CellPortionID

// CellPortionIDAPERValue is the concrete APERValue[CellPortionID].
type CellPortionIDAPERValue = q14.CellPortionIDAPERValue

// CellPortionIDCodec binds the complete APER value type.
var CellPortionIDCodec func() CellPortionIDValueCodec = q17.CellPortionIDCodec

// CellPortionIDValueCodec is the concrete ValueCodec[CellPortionID].
type CellPortionIDValueCodec = q14.CellPortionIDValueCodec

// Criticality represents the ASN.1 ENUMERATED type Criticality.
type Criticality = q14.Criticality

// CriticalityAPERValue is the concrete APERValue[Criticality].
type CriticalityAPERValue = q14.CriticalityAPERValue

// CriticalityCodec binds the complete source value type.
var CriticalityCodec func() CriticalityValueCodec = q9.CriticalityCodec

// CriticalityDiagnostics represents the ASN.1 type CriticalityDiagnostics (SEQUENCE).
type CriticalityDiagnostics = q15.CriticalityDiagnostics

// CriticalityDiagnosticsAPERValue is the concrete APERValue[CriticalityDiagnostics].
type CriticalityDiagnosticsAPERValue = q15.CriticalityDiagnosticsAPERValue

// CriticalityDiagnosticsCodec binds the complete APER value type.
var CriticalityDiagnosticsCodec func() CriticalityDiagnosticsValueCodec = q6.CriticalityDiagnosticsCodec

type CriticalityDiagnosticsExtIETable = q8.CriticalityDiagnosticsExtIETable

var CriticalityDiagnosticsExtIEs func() CriticalityDiagnosticsExtIETable = q8.CriticalityDiagnosticsExtIEs

// CriticalityDiagnosticsExtIEsExtContainer is the concrete ProtocolExtensionContainer[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsExtContainer = q8.CriticalityDiagnosticsExtIEsExtContainer

// CriticalityDiagnosticsExtIEsExtField is the concrete ProtocolExtensionField[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsExtField = q8.CriticalityDiagnosticsExtIEsExtField

// CriticalityDiagnosticsExtIEsIEContainer is the concrete ProtocolIEContainer[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsIEContainer = q8.CriticalityDiagnosticsExtIEsIEContainer

// CriticalityDiagnosticsExtIEsIEField is the concrete ProtocolIEField[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsIEField = q8.CriticalityDiagnosticsExtIEsIEField
type CriticalityDiagnosticsExtIEsValue = q9.CriticalityDiagnosticsExtIEsValue
type CriticalityDiagnosticsIEList = q13.CriticalityDiagnosticsIEList

// CriticalityDiagnosticsIEListAPERValue is the concrete APERValue[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListAPERValue = q13.CriticalityDiagnosticsIEListAPERValue

// CriticalityDiagnosticsIEListCodec binds the complete source value type.
var CriticalityDiagnosticsIEListCodec func() CriticalityDiagnosticsIEListValueCodec = q6.CriticalityDiagnosticsIEListCodec

// CriticalityDiagnosticsIEListComplete carries a complete CriticalityDiagnosticsIEList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CriticalityDiagnosticsIEListComplete = q6.CriticalityDiagnosticsIEListComplete

// CriticalityDiagnosticsIEListElem represents the ASN.1 type CriticalityDiagnostics-IE-List-Elem (SEQUENCE).
type CriticalityDiagnosticsIEListElem = q13.CriticalityDiagnosticsIEListElem

// CriticalityDiagnosticsIEListElemAPERValue is the concrete APERValue[CriticalityDiagnosticsIEListElem].
type CriticalityDiagnosticsIEListElemAPERValue = q13.CriticalityDiagnosticsIEListElemAPERValue

// CriticalityDiagnosticsIEListElemCodec binds the complete source value type.
var CriticalityDiagnosticsIEListElemCodec func() CriticalityDiagnosticsIEListElemValueCodec = q13.CriticalityDiagnosticsIEListElemCodec

// CriticalityDiagnosticsIEListElemValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEListElem].
type CriticalityDiagnosticsIEListElemValueCodec = q13.CriticalityDiagnosticsIEListElemValueCodec
type CriticalityDiagnosticsIEListExtIETable = q8.CriticalityDiagnosticsIEListExtIETable

var CriticalityDiagnosticsIEListExtIEs func() CriticalityDiagnosticsIEListExtIETable = q8.CriticalityDiagnosticsIEListExtIEs

// CriticalityDiagnosticsIEListExtIEsExtContainer is the concrete ProtocolExtensionContainer[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsExtContainer = q8.CriticalityDiagnosticsIEListExtIEsExtContainer

// CriticalityDiagnosticsIEListExtIEsExtField is the concrete ProtocolExtensionField[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsExtField = q8.CriticalityDiagnosticsIEListExtIEsExtField

// CriticalityDiagnosticsIEListExtIEsIEContainer is the concrete ProtocolIEContainer[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsIEContainer = q8.CriticalityDiagnosticsIEListExtIEsIEContainer

// CriticalityDiagnosticsIEListExtIEsIEField is the concrete ProtocolIEField[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsIEField = q8.CriticalityDiagnosticsIEListExtIEsIEField
type CriticalityDiagnosticsIEListExtIEsValue = q9.CriticalityDiagnosticsIEListExtIEsValue

// CriticalityDiagnosticsIEListValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListValueCodec = q13.CriticalityDiagnosticsIEListValueCodec

// CriticalityDiagnosticsValueCodec is the concrete ValueCodec[CriticalityDiagnostics].
type CriticalityDiagnosticsValueCodec = q15.CriticalityDiagnosticsValueCodec

const CriticalityIgnore = q14.CriticalityIgnore
const CriticalityNotify = q14.CriticalityNotify
const CriticalityReject = q14.CriticalityReject

// CriticalityValueCodec is the concrete ValueCodec[Criticality].
type CriticalityValueCodec = q14.CriticalityValueCodec

// DLBandwidth represents the ASN.1 ENUMERATED type DL-Bandwidth.
type DLBandwidth = q14.DLBandwidth

// DLBandwidthAPERValue is the concrete APERValue[DLBandwidth].
type DLBandwidthAPERValue = q14.DLBandwidthAPERValue

const DLBandwidthBw100 = q14.DLBandwidthBw100
const DLBandwidthBw15 = q14.DLBandwidthBw15
const DLBandwidthBw25 = q14.DLBandwidthBw25
const DLBandwidthBw50 = q14.DLBandwidthBw50
const DLBandwidthBw6 = q14.DLBandwidthBw6
const DLBandwidthBw75 = q14.DLBandwidthBw75

// DLBandwidthCodec binds the complete source value type.
var DLBandwidthCodec func() DLBandwidthValueCodec = q9.DLBandwidthCodec

// DLBandwidthValueCodec is the concrete ValueCodec[DLBandwidth].
type DLBandwidthValueCodec = q14.DLBandwidthValueCodec
type DecodePayload[T any] = q4.DecodePayload[T]
type DeferredCondition = q14.DeferredCondition

// EARFCN represents the ASN.1 type EARFCN (INTEGER).
type EARFCN = q14.EARFCN

// EARFCNAPERValue is the concrete APERValue[EARFCN].
type EARFCNAPERValue = q14.EARFCNAPERValue

// EARFCNCodec binds the complete source value type.
var EARFCNCodec func() EARFCNValueCodec = q9.EARFCNCodec

// EARFCNValueCodec is the concrete ValueCodec[EARFCN].
type EARFCNValueCodec = q14.EARFCNValueCodec

// ECGI represents the ASN.1 type ECGI (SEQUENCE).
type ECGI = q13.ECGI

// ECGIAPERValue is the concrete APERValue[ECGI].
type ECGIAPERValue = q13.ECGIAPERValue

// ECGICodec binds the complete source value type.
var ECGICodec func() ECGIValueCodec = q13.ECGICodec

type ECGIExtIETable = q8.ECGIExtIETable

var ECGIExtIEs func() ECGIExtIETable = q8.ECGIExtIEs

// ECGIExtIEsExtContainer is the concrete ProtocolExtensionContainer[ECGIExtIEsValue].
type ECGIExtIEsExtContainer = q8.ECGIExtIEsExtContainer

// ECGIExtIEsExtField is the concrete ProtocolExtensionField[ECGIExtIEsValue].
type ECGIExtIEsExtField = q8.ECGIExtIEsExtField

// ECGIExtIEsIEContainer is the concrete ProtocolIEContainer[ECGIExtIEsValue].
type ECGIExtIEsIEContainer = q8.ECGIExtIEsIEContainer

// ECGIExtIEsIEField is the concrete ProtocolIEField[ECGIExtIEsValue].
type ECGIExtIEsIEField = q8.ECGIExtIEsIEField
type ECGIExtIEsValue = q9.ECGIExtIEsValue

// ECGIValueCodec is the concrete ValueCodec[ECGI].
type ECGIValueCodec = q13.ECGIValueCodec

// ECIDMeasurementFailureIndication represents the ASN.1 type E-CIDMeasurementFailureIndication (SEQUENCE).
type ECIDMeasurementFailureIndication = q18.ECIDMeasurementFailureIndication

// ECIDMeasurementFailureIndicationAPERValue is the concrete APERValue[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationAPERValue = q18.ECIDMeasurementFailureIndicationAPERValue

// ECIDMeasurementFailureIndicationCauseIEBinding is the concrete IEBinding[Cause, ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationCauseIEBinding = q16.ECIDMeasurementFailureIndicationCauseIEBinding

// ECIDMeasurementFailureIndicationCodec binds the complete APER value type.
var ECIDMeasurementFailureIndicationCodec func() ECIDMeasurementFailureIndicationValueCodec = q4.ECIDMeasurementFailureIndicationCodec

type ECIDMeasurementFailureIndicationDescriptor = q4.ECIDMeasurementFailureIndicationDescriptor

// ECIDMeasurementFailureIndicationIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationIEContainer = q16.ECIDMeasurementFailureIndicationIEContainer

// ECIDMeasurementFailureIndicationIEField is the concrete ProtocolIEField[ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationIEField = q16.ECIDMeasurementFailureIndicationIEField
type ECIDMeasurementFailureIndicationIETable = q16.ECIDMeasurementFailureIndicationIETable
type ECIDMeasurementFailureIndicationIEValue = q16.ECIDMeasurementFailureIndicationIEValue

var ECIDMeasurementFailureIndicationIEs func() ECIDMeasurementFailureIndicationIETable = q16.ECIDMeasurementFailureIndicationIEs

// ECIDMeasurementFailureIndicationInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationInitiatingBinding = q12.ECIDMeasurementFailureIndicationInitiatingBinding

// ECIDMeasurementFailureIndicationMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationMeasurementIDIEBinding = q16.ECIDMeasurementFailureIndicationMeasurementIDIEBinding

var ECIDMeasurementFailureIndicationProcedure func() ECIDMeasurementFailureIndicationDescriptor = q4.ECIDMeasurementFailureIndicationProcedure

// ECIDMeasurementFailureIndicationValueCodec is the concrete ValueCodec[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationValueCodec = q18.ECIDMeasurementFailureIndicationValueCodec
type ECIDMeasurementInitiationDescriptor = q11.ECIDMeasurementInitiationDescriptor

// ECIDMeasurementInitiationFailure represents the ASN.1 type E-CIDMeasurementInitiationFailure (SEQUENCE).
type ECIDMeasurementInitiationFailure = q18.ECIDMeasurementInitiationFailure

// ECIDMeasurementInitiationFailureAPERValue is the concrete APERValue[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureAPERValue = q18.ECIDMeasurementInitiationFailureAPERValue

// ECIDMeasurementInitiationFailureCauseIEBinding is the concrete IEBinding[Cause, ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureCauseIEBinding = q15.ECIDMeasurementInitiationFailureCauseIEBinding

// ECIDMeasurementInitiationFailureCodec binds the complete APER value type.
var ECIDMeasurementInitiationFailureCodec func() ECIDMeasurementInitiationFailureValueCodec = q11.ECIDMeasurementInitiationFailureCodec

// ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding = q15.ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding

// ECIDMeasurementInitiationFailureIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureIEContainer = q15.ECIDMeasurementInitiationFailureIEContainer

// ECIDMeasurementInitiationFailureIEField is the concrete ProtocolIEField[ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureIEField = q15.ECIDMeasurementInitiationFailureIEField
type ECIDMeasurementInitiationFailureIETable = q19.ECIDMeasurementInitiationFailureIETable
type ECIDMeasurementInitiationFailureIEValue = q15.ECIDMeasurementInitiationFailureIEValue

var ECIDMeasurementInitiationFailureIEs func() ECIDMeasurementInitiationFailureIETable = q19.ECIDMeasurementInitiationFailureIEs

// ECIDMeasurementInitiationFailureMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureMeasurementIDIEBinding = q19.ECIDMeasurementInitiationFailureMeasurementIDIEBinding

// ECIDMeasurementInitiationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureUnsuccessfulBinding = q20.ECIDMeasurementInitiationFailureUnsuccessfulBinding

// ECIDMeasurementInitiationFailureValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureValueCodec = q18.ECIDMeasurementInitiationFailureValueCodec

var ECIDMeasurementInitiationProcedure func() ECIDMeasurementInitiationDescriptor = q11.ECIDMeasurementInitiationProcedure

// ECIDMeasurementInitiationRequest represents the ASN.1 type E-CIDMeasurementInitiationRequest (SEQUENCE).
type ECIDMeasurementInitiationRequest = q12.ECIDMeasurementInitiationRequest

// ECIDMeasurementInitiationRequestAPERValue is the concrete APERValue[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestAPERValue = q12.ECIDMeasurementInitiationRequestAPERValue

// ECIDMeasurementInitiationRequestCodec binds the complete APER value type.
var ECIDMeasurementInitiationRequestCodec func() ECIDMeasurementInitiationRequestValueCodec = q11.ECIDMeasurementInitiationRequestCodec

// ECIDMeasurementInitiationRequestIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestIEContainer = q12.ECIDMeasurementInitiationRequestIEContainer

// ECIDMeasurementInitiationRequestIEField is the concrete ProtocolIEField[ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestIEField = q12.ECIDMeasurementInitiationRequestIEField
type ECIDMeasurementInitiationRequestIETable = q12.ECIDMeasurementInitiationRequestIETable
type ECIDMeasurementInitiationRequestIEValue = q21.ECIDMeasurementInitiationRequestIEValue

var ECIDMeasurementInitiationRequestIEs func() ECIDMeasurementInitiationRequestIETable = q12.ECIDMeasurementInitiationRequestIEs

// ECIDMeasurementInitiationRequestInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestInitiatingBinding = q12.ECIDMeasurementInitiationRequestInitiatingBinding

// ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding is the concrete IEBinding[InterRATMeasurementQuantities, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding = q12.ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding

// ECIDMeasurementInitiationRequestMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestMeasurementIDIEBinding = q12.ECIDMeasurementInitiationRequestMeasurementIDIEBinding

// ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding is the concrete IEBinding[MeasurementPeriodicity, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding = q12.ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding

// ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding is the concrete IEBinding[MeasurementQuantities, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding = q12.ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding

// ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding is the concrete IEBinding[ReportCharacteristics, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding = q12.ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding

// ECIDMeasurementInitiationRequestValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestValueCodec = q12.ECIDMeasurementInitiationRequestValueCodec

// ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding is the concrete IEBinding[WLANMeasurementQuantities, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding = q12.ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding

// ECIDMeasurementInitiationResponse represents the ASN.1 type E-CIDMeasurementInitiationResponse (SEQUENCE).
type ECIDMeasurementInitiationResponse = q17.ECIDMeasurementInitiationResponse

// ECIDMeasurementInitiationResponseAPERValue is the concrete APERValue[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseAPERValue = q17.ECIDMeasurementInitiationResponseAPERValue

// ECIDMeasurementInitiationResponseCellPortionIDIEBinding is the concrete IEBinding[CellPortionID, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseCellPortionIDIEBinding = q17.ECIDMeasurementInitiationResponseCellPortionIDIEBinding

// ECIDMeasurementInitiationResponseCodec binds the complete APER value type.
var ECIDMeasurementInitiationResponseCodec func() ECIDMeasurementInitiationResponseValueCodec = q11.ECIDMeasurementInitiationResponseCodec

// ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding = q17.ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding

// ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding is the concrete IEBinding[ECIDMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding = q17.ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding

// ECIDMeasurementInitiationResponseIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseIEContainer = q17.ECIDMeasurementInitiationResponseIEContainer

// ECIDMeasurementInitiationResponseIEField is the concrete ProtocolIEField[ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseIEField = q17.ECIDMeasurementInitiationResponseIEField
type ECIDMeasurementInitiationResponseIETable = q17.ECIDMeasurementInitiationResponseIETable
type ECIDMeasurementInitiationResponseIEValue = q17.ECIDMeasurementInitiationResponseIEValue

var ECIDMeasurementInitiationResponseIEs func() ECIDMeasurementInitiationResponseIETable = q17.ECIDMeasurementInitiationResponseIEs

// ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding is the concrete IEBinding[InterRATMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding = q17.ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding

// ECIDMeasurementInitiationResponseMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseMeasurementIDIEBinding = q17.ECIDMeasurementInitiationResponseMeasurementIDIEBinding

// ECIDMeasurementInitiationResponseSuccessfulBinding is the concrete SuccessfulBinding[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseSuccessfulBinding = q4.ECIDMeasurementInitiationResponseSuccessfulBinding

// ECIDMeasurementInitiationResponseValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseValueCodec = q17.ECIDMeasurementInitiationResponseValueCodec

// ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding is the concrete IEBinding[WLANMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding = q17.ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding

// ECIDMeasurementReport represents the ASN.1 type E-CIDMeasurementReport (SEQUENCE).
type ECIDMeasurementReport = q22.ECIDMeasurementReport

// ECIDMeasurementReportAPERValue is the concrete APERValue[ECIDMeasurementReport].
type ECIDMeasurementReportAPERValue = q22.ECIDMeasurementReportAPERValue

// ECIDMeasurementReportCellPortionIDIEBinding is the concrete IEBinding[CellPortionID, ECIDMeasurementReportIEValue].
type ECIDMeasurementReportCellPortionIDIEBinding = q22.ECIDMeasurementReportCellPortionIDIEBinding

// ECIDMeasurementReportCodec binds the complete APER value type.
var ECIDMeasurementReportCodec func() ECIDMeasurementReportValueCodec = q4.ECIDMeasurementReportCodec

type ECIDMeasurementReportDescriptor = q4.ECIDMeasurementReportDescriptor

// ECIDMeasurementReportECIDMeasurementResultIEBinding is the concrete IEBinding[ECIDMeasurementResult, ECIDMeasurementReportIEValue].
type ECIDMeasurementReportECIDMeasurementResultIEBinding = q22.ECIDMeasurementReportECIDMeasurementResultIEBinding

// ECIDMeasurementReportIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementReportIEValue].
type ECIDMeasurementReportIEContainer = q22.ECIDMeasurementReportIEContainer

// ECIDMeasurementReportIEField is the concrete ProtocolIEField[ECIDMeasurementReportIEValue].
type ECIDMeasurementReportIEField = q22.ECIDMeasurementReportIEField
type ECIDMeasurementReportIETable = q22.ECIDMeasurementReportIETable
type ECIDMeasurementReportIEValue = q22.ECIDMeasurementReportIEValue

var ECIDMeasurementReportIEs func() ECIDMeasurementReportIETable = q22.ECIDMeasurementReportIEs

// ECIDMeasurementReportInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementReport].
type ECIDMeasurementReportInitiatingBinding = q12.ECIDMeasurementReportInitiatingBinding

// ECIDMeasurementReportMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementReportIEValue].
type ECIDMeasurementReportMeasurementIDIEBinding = q22.ECIDMeasurementReportMeasurementIDIEBinding

var ECIDMeasurementReportProcedure func() ECIDMeasurementReportDescriptor = q4.ECIDMeasurementReportProcedure

// ECIDMeasurementReportValueCodec is the concrete ValueCodec[ECIDMeasurementReport].
type ECIDMeasurementReportValueCodec = q22.ECIDMeasurementReportValueCodec

// ECIDMeasurementResult represents the ASN.1 type E-CID-MeasurementResult (SEQUENCE).
type ECIDMeasurementResult = q22.ECIDMeasurementResult

// ECIDMeasurementResultAPERValue is the concrete APERValue[ECIDMeasurementResult].
type ECIDMeasurementResultAPERValue = q22.ECIDMeasurementResultAPERValue

// ECIDMeasurementResultCodec binds the complete APER value type.
var ECIDMeasurementResultCodec func() ECIDMeasurementResultValueCodec = q17.ECIDMeasurementResultCodec

// ECIDMeasurementResultValueCodec is the concrete ValueCodec[ECIDMeasurementResult].
type ECIDMeasurementResultValueCodec = q22.ECIDMeasurementResultValueCodec

// ECIDMeasurementTerminationCommand represents the ASN.1 type E-CIDMeasurementTerminationCommand (SEQUENCE).
type ECIDMeasurementTerminationCommand = q16.ECIDMeasurementTerminationCommand

// ECIDMeasurementTerminationCommandAPERValue is the concrete APERValue[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandAPERValue = q16.ECIDMeasurementTerminationCommandAPERValue

// ECIDMeasurementTerminationCommandCodec binds the complete APER value type.
var ECIDMeasurementTerminationCommandCodec func() ECIDMeasurementTerminationCommandValueCodec = q4.ECIDMeasurementTerminationCommandCodec

// ECIDMeasurementTerminationCommandIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementTerminationCommandIEValue].
type ECIDMeasurementTerminationCommandIEContainer = q8.ECIDMeasurementTerminationCommandIEContainer

// ECIDMeasurementTerminationCommandIEField is the concrete ProtocolIEField[ECIDMeasurementTerminationCommandIEValue].
type ECIDMeasurementTerminationCommandIEField = q8.ECIDMeasurementTerminationCommandIEField
type ECIDMeasurementTerminationCommandIETable = q8.ECIDMeasurementTerminationCommandIETable
type ECIDMeasurementTerminationCommandIEValue = q9.ECIDMeasurementTerminationCommandIEValue

var ECIDMeasurementTerminationCommandIEs func() ECIDMeasurementTerminationCommandIETable = q8.ECIDMeasurementTerminationCommandIEs

// ECIDMeasurementTerminationCommandInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandInitiatingBinding = q12.ECIDMeasurementTerminationCommandInitiatingBinding

// ECIDMeasurementTerminationCommandMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementTerminationCommandIEValue].
type ECIDMeasurementTerminationCommandMeasurementIDIEBinding = q8.ECIDMeasurementTerminationCommandMeasurementIDIEBinding

// ECIDMeasurementTerminationCommandValueCodec is the concrete ValueCodec[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandValueCodec = q16.ECIDMeasurementTerminationCommandValueCodec
type ECIDMeasurementTerminationDescriptor = q4.ECIDMeasurementTerminationDescriptor

var ECIDMeasurementTerminationProcedure func() ECIDMeasurementTerminationDescriptor = q4.ECIDMeasurementTerminationProcedure

// EUTRANAccessPointPosition represents the ASN.1 type E-UTRANAccessPointPosition (SEQUENCE).
type EUTRANAccessPointPosition = q16.EUTRANAccessPointPosition

// EUTRANAccessPointPositionAPERValue is the concrete APERValue[EUTRANAccessPointPosition].
type EUTRANAccessPointPositionAPERValue = q16.EUTRANAccessPointPositionAPERValue

// EUTRANAccessPointPositionCodec binds the complete source value type.
var EUTRANAccessPointPositionCodec func() EUTRANAccessPointPositionValueCodec = q16.EUTRANAccessPointPositionCodec

// EUTRANAccessPointPositionValueCodec is the concrete ValueCodec[EUTRANAccessPointPosition].
type EUTRANAccessPointPositionValueCodec = q16.EUTRANAccessPointPositionValueCodec

// EUTRANCellIdentifier represents the ASN.1 type EUTRANCellIdentifier (BIT_STRING).
type EUTRANCellIdentifier = q14.EUTRANCellIdentifier

// EUTRANCellIdentifierAPERValue is the concrete APERValue[EUTRANCellIdentifier].
type EUTRANCellIdentifierAPERValue = q14.EUTRANCellIdentifierAPERValue

// EUTRANCellIdentifierCodec binds the complete source value type.
var EUTRANCellIdentifierCodec func() EUTRANCellIdentifierValueCodec = q9.EUTRANCellIdentifierCodec

// EUTRANCellIdentifierValueCodec is the concrete ValueCodec[EUTRANCellIdentifier].
type EUTRANCellIdentifierValueCodec = q14.EUTRANCellIdentifierValueCodec
type EncodePayload[T any] = q4.EncodePayload[T]

// ErrorIndication represents the ASN.1 type ErrorIndication (SEQUENCE).
type ErrorIndication = q18.ErrorIndication

// ErrorIndicationAPERValue is the concrete APERValue[ErrorIndication].
type ErrorIndicationAPERValue = q18.ErrorIndicationAPERValue

// ErrorIndicationCauseIEBinding is the concrete IEBinding[Cause, ErrorIndicationIEValue].
type ErrorIndicationCauseIEBinding = q19.ErrorIndicationCauseIEBinding

// ErrorIndicationCodec binds the complete APER value type.
var ErrorIndicationCodec func() ErrorIndicationValueCodec = q4.ErrorIndicationCodec

// ErrorIndicationCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ErrorIndicationIEValue].
type ErrorIndicationCriticalityDiagnosticsIEBinding = q19.ErrorIndicationCriticalityDiagnosticsIEBinding
type ErrorIndicationDescriptor = q4.ErrorIndicationDescriptor

// ErrorIndicationIEContainer is the concrete ProtocolIEContainer[ErrorIndicationIEValue].
type ErrorIndicationIEContainer = q19.ErrorIndicationIEContainer

// ErrorIndicationIEField is the concrete ProtocolIEField[ErrorIndicationIEValue].
type ErrorIndicationIEField = q19.ErrorIndicationIEField
type ErrorIndicationIETable = q19.ErrorIndicationIETable
type ErrorIndicationIEValue = q19.ErrorIndicationIEValue

var ErrorIndicationIEs func() ErrorIndicationIETable = q19.ErrorIndicationIEs

// ErrorIndicationInitiatingBinding is the concrete InitiatingBinding[ErrorIndication].
type ErrorIndicationInitiatingBinding = q12.ErrorIndicationInitiatingBinding

var ErrorIndicationProcedure func() ErrorIndicationDescriptor = q4.ErrorIndicationProcedure

// ErrorIndicationValueCodec is the concrete ValueCodec[ErrorIndication].
type ErrorIndicationValueCodec = q18.ErrorIndicationValueCodec
type ExtensionBinding[T any, V q4.ProtocolOpenValueConstraint[V]] = q4.ExtensionBinding[T, V]
type FieldInfo = q14.FieldInfo

// HESSID represents the ASN.1 type HESSID (OCTET_STRING).
type HESSID = q14.HESSID

// HESSIDAPERValue is the concrete APERValue[HESSID].
type HESSIDAPERValue = q14.HESSIDAPERValue

// HESSIDCodec binds the complete source value type.
var HESSIDCodec func() HESSIDValueCodec = q9.HESSIDCodec

// HESSIDValueCodec is the concrete ValueCodec[HESSID].
type HESSIDValueCodec = q14.HESSIDValueCodec
type IEBinding[T any, V q4.ProtocolOpenValueConstraint[V]] = q4.IEBinding[T, V]

// IdAddOTDOACells is the integer constant for id-AddOTDOACells.
const IdAddOTDOACells = q14.IdAddOTDOACells

// IdAssistanceInformation is the integer constant for id-Assistance-Information.
const IdAssistanceInformation = q14.IdAssistanceInformation

// IdAssistanceInformationControl is the integer constant for id-assistanceInformationControl.
const IdAssistanceInformationControl = q14.IdAssistanceInformationControl

// IdAssistanceInformationFailureList is the integer constant for id-AssistanceInformationFailureList.
const IdAssistanceInformationFailureList = q14.IdAssistanceInformationFailureList

// IdAssistanceInformationFeedback is the integer constant for id-assistanceInformationFeedback.
const IdAssistanceInformationFeedback = q14.IdAssistanceInformationFeedback

// IdBroadcast is the integer constant for id-Broadcast.
const IdBroadcast = q14.IdBroadcast

// IdCause is the integer constant for id-Cause.
const IdCause = q14.IdCause

// IdCellPortionID is the integer constant for id-Cell-Portion-ID.
const IdCellPortionID = q14.IdCellPortionID

// IdCriticalityDiagnostics is the integer constant for id-CriticalityDiagnostics.
const IdCriticalityDiagnostics = q14.IdCriticalityDiagnostics

// IdECIDMeasurementFailureIndication is the integer constant for id-e-CIDMeasurementFailureIndication.
const IdECIDMeasurementFailureIndication = q14.IdECIDMeasurementFailureIndication

// IdECIDMeasurementInitiation is the integer constant for id-e-CIDMeasurementInitiation.
const IdECIDMeasurementInitiation = q14.IdECIDMeasurementInitiation

// IdECIDMeasurementReport is the integer constant for id-e-CIDMeasurementReport.
const IdECIDMeasurementReport = q14.IdECIDMeasurementReport

// IdECIDMeasurementResult is the integer constant for id-E-CID-MeasurementResult.
const IdECIDMeasurementResult = q14.IdECIDMeasurementResult

// IdECIDMeasurementTermination is the integer constant for id-e-CIDMeasurementTermination.
const IdECIDMeasurementTermination = q14.IdECIDMeasurementTermination

// IdENBUEMeasurementID is the integer constant for id-eNB-UE-Measurement-ID.
const IdENBUEMeasurementID = q14.IdENBUEMeasurementID

// IdESMLCUEMeasurementID is the integer constant for id-E-SMLC-UE-Measurement-ID.
const IdESMLCUEMeasurementID = q14.IdESMLCUEMeasurementID

// IdErrorIndication is the integer constant for id-errorIndication.
const IdErrorIndication = q14.IdErrorIndication

// IdInterRATMeasurementQuantities is the integer constant for id-InterRATMeasurementQuantities.
const IdInterRATMeasurementQuantities = q14.IdInterRATMeasurementQuantities

// IdInterRATMeasurementQuantitiesItem is the integer constant for id-InterRATMeasurementQuantities-Item.
const IdInterRATMeasurementQuantitiesItem = q14.IdInterRATMeasurementQuantitiesItem

// IdInterRATMeasurementResult is the integer constant for id-InterRATMeasurementResult.
const IdInterRATMeasurementResult = q14.IdInterRATMeasurementResult

// IdMeasurementPeriodicity is the integer constant for id-MeasurementPeriodicity.
const IdMeasurementPeriodicity = q14.IdMeasurementPeriodicity

// IdMeasurementQuantities is the integer constant for id-MeasurementQuantities.
const IdMeasurementQuantities = q14.IdMeasurementQuantities

// IdMeasurementQuantitiesItem is the integer constant for id-MeasurementQuantities-Item.
const IdMeasurementQuantitiesItem = q14.IdMeasurementQuantitiesItem

// IdNRCGI is the integer constant for id-NR-CGI.
const IdNRCGI = q14.IdNRCGI

// IdOTDOACells is the integer constant for id-OTDOACells.
const IdOTDOACells = q14.IdOTDOACells

// IdOTDOAInformationExchange is the integer constant for id-oTDOAInformationExchange.
const IdOTDOAInformationExchange = q14.IdOTDOAInformationExchange

// IdOTDOAInformationTypeGroup is the integer constant for id-OTDOA-Information-Type-Group.
const IdOTDOAInformationTypeGroup = q14.IdOTDOAInformationTypeGroup

// IdOTDOAInformationTypeItem is the integer constant for id-OTDOA-Information-Type-Item.
const IdOTDOAInformationTypeItem = q14.IdOTDOAInformationTypeItem

// IdPrivateMessage is the integer constant for id-privateMessage.
const IdPrivateMessage = q14.IdPrivateMessage

// IdReportCharacteristics is the integer constant for id-ReportCharacteristics.
const IdReportCharacteristics = q14.IdReportCharacteristics

// IdRequestedSRSTransmissionCharacteristics is the integer constant for id-RequestedSRSTransmissionCharacteristics.
const IdRequestedSRSTransmissionCharacteristics = q14.IdRequestedSRSTransmissionCharacteristics

// IdResultsPerSSBIndexItem is the integer constant for id-ResultsPerSSB-Index-Item.
const IdResultsPerSSBIndexItem = q14.IdResultsPerSSBIndexItem

// IdResultsPerSSBIndexList is the integer constant for id-ResultsPerSSB-Index-List.
const IdResultsPerSSBIndexList = q14.IdResultsPerSSBIndexList

// IdULConfiguration is the integer constant for id-ULConfiguration.
const IdULConfiguration = q14.IdULConfiguration

// IdUTDOAInformationExchange is the integer constant for id-uTDOAInformationExchange.
const IdUTDOAInformationExchange = q14.IdUTDOAInformationExchange

// IdUTDOAInformationUpdate is the integer constant for id-uTDOAInformationUpdate.
const IdUTDOAInformationUpdate = q14.IdUTDOAInformationUpdate

// IdWLANMeasurementQuantities is the integer constant for id-WLANMeasurementQuantities.
const IdWLANMeasurementQuantities = q14.IdWLANMeasurementQuantities

// IdWLANMeasurementQuantitiesItem is the integer constant for id-WLANMeasurementQuantities-Item.
const IdWLANMeasurementQuantitiesItem = q14.IdWLANMeasurementQuantitiesItem

// IdWLANMeasurementResult is the integer constant for id-WLANMeasurementResult.
const IdWLANMeasurementResult = q14.IdWLANMeasurementResult

type InitiatingBinding[T any] = q4.InitiatingBinding[T]

// InitiatingMessage represents the ASN.1 type InitiatingMessage (SEQUENCE).
type InitiatingMessage = q12.InitiatingMessage

// InitiatingMessageAPERValue is the concrete APERValue[InitiatingMessage].
type InitiatingMessageAPERValue = q12.InitiatingMessageAPERValue

// InitiatingMessageCodec binds the complete source value type.
var InitiatingMessageCodec func() InitiatingMessageValueCodec = q12.InitiatingMessageCodec

// InitiatingMessageValueCodec is the concrete ValueCodec[InitiatingMessage].
type InitiatingMessageValueCodec = q12.InitiatingMessageValueCodec

var InitiatingReason func(code ProcedureCode) q23.OpaqueReason = q14.InitiatingReason

type InitiatingValue = q12.InitiatingValue

// InterRATMeasuredResultsValue represents the ASN.1 CHOICE type InterRATMeasuredResultsValue.
type InterRATMeasuredResultsValue = q24.InterRATMeasuredResultsValue

// InterRATMeasuredResultsValueAPERValue is the concrete APERValue[InterRATMeasuredResultsValue].
type InterRATMeasuredResultsValueAPERValue = q21.InterRATMeasuredResultsValueAPERValue

// InterRATMeasuredResultsValue choice constants.
const InterRATMeasuredResultsValueChoiceResultGERAN = q14.InterRATMeasuredResultsValueChoiceResultGERAN

// InterRATMeasuredResultsValue choice constants.
const InterRATMeasuredResultsValueChoiceResultNR = q14.InterRATMeasuredResultsValueChoiceResultNR

// InterRATMeasuredResultsValue choice constants.
const InterRATMeasuredResultsValueChoiceResultUTRAN = q14.InterRATMeasuredResultsValueChoiceResultUTRAN

// InterRATMeasuredResultsValueCodec binds the complete source value type.
var InterRATMeasuredResultsValueCodec func() InterRATMeasuredResultsValueValueCodec = q21.InterRATMeasuredResultsValueCodec

// InterRATMeasuredResultsValueValueCodec is the concrete ValueCodec[InterRATMeasuredResultsValue].
type InterRATMeasuredResultsValueValueCodec = q21.InterRATMeasuredResultsValueValueCodec
type InterRATMeasurementQuantities = q16.InterRATMeasurementQuantities

// InterRATMeasurementQuantitiesAPERValue is the concrete APERValue[InterRATMeasurementQuantities].
type InterRATMeasurementQuantitiesAPERValue = q16.InterRATMeasurementQuantitiesAPERValue

// InterRATMeasurementQuantitiesCodec binds the complete APER value type.
var InterRATMeasurementQuantitiesCodec func() InterRATMeasurementQuantitiesConcreteValueCodec = q12.InterRATMeasurementQuantitiesCodec

// InterRATMeasurementQuantitiesComplete carries a complete InterRATMeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type InterRATMeasurementQuantitiesComplete = q6.InterRATMeasurementQuantitiesComplete

// InterRATMeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[InterRATMeasurementQuantities].
type InterRATMeasurementQuantitiesConcreteValueCodec = q16.InterRATMeasurementQuantitiesConcreteValueCodec

// InterRATMeasurementQuantitiesItem represents the ASN.1 type InterRATMeasurementQuantities-Item (SEQUENCE).
type InterRATMeasurementQuantitiesItem = q16.InterRATMeasurementQuantitiesItem

// InterRATMeasurementQuantitiesItemAPERValue is the concrete APERValue[InterRATMeasurementQuantitiesItem].
type InterRATMeasurementQuantitiesItemAPERValue = q16.InterRATMeasurementQuantitiesItemAPERValue

// InterRATMeasurementQuantitiesItemCodec binds the complete APER value type.
var InterRATMeasurementQuantitiesItemCodec func() InterRATMeasurementQuantitiesItemValueCodec = q16.InterRATMeasurementQuantitiesItemCodec

// InterRATMeasurementQuantitiesItemIEContainer is the concrete ProtocolIEContainer[InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemIEContainer = q16.InterRATMeasurementQuantitiesItemIEContainer

// InterRATMeasurementQuantitiesItemIEField is the concrete ProtocolIEField[InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemIEField = q16.InterRATMeasurementQuantitiesItemIEField
type InterRATMeasurementQuantitiesItemIETable = q16.InterRATMeasurementQuantitiesItemIETable
type InterRATMeasurementQuantitiesItemIEValue = q16.InterRATMeasurementQuantitiesItemIEValue

// InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer = q16.InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer

var InterRATMeasurementQuantitiesItemIEs func() InterRATMeasurementQuantitiesItemIETable = q16.InterRATMeasurementQuantitiesItemIEs

// InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding is the concrete IEBinding[InterRATMeasurementQuantitiesItem, InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding = q16.InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding

// InterRATMeasurementQuantitiesItemValueCodec is the concrete ValueCodec[InterRATMeasurementQuantitiesItem].
type InterRATMeasurementQuantitiesItemValueCodec = q16.InterRATMeasurementQuantitiesItemValueCodec

// InterRATMeasurementQuantitiesValue represents the ASN.1 ENUMERATED type InterRATMeasurementQuantitiesValue.
type InterRATMeasurementQuantitiesValue = q14.InterRATMeasurementQuantitiesValue

// InterRATMeasurementQuantitiesValueAPERValue is the concrete APERValue[InterRATMeasurementQuantitiesValue].
type InterRATMeasurementQuantitiesValueAPERValue = q14.InterRATMeasurementQuantitiesValueAPERValue

// InterRATMeasurementQuantitiesValueCodec binds the complete source value type.
var InterRATMeasurementQuantitiesValueCodec func() InterRATMeasurementQuantitiesValueValueCodec = q9.InterRATMeasurementQuantitiesValueCodec

type InterRATMeasurementQuantitiesValueExtIETable = q8.InterRATMeasurementQuantitiesValueExtIETable

var InterRATMeasurementQuantitiesValueExtIEs func() InterRATMeasurementQuantitiesValueExtIETable = q8.InterRATMeasurementQuantitiesValueExtIEs

// InterRATMeasurementQuantitiesValueExtIEsExtContainer is the concrete ProtocolExtensionContainer[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsExtContainer = q8.InterRATMeasurementQuantitiesValueExtIEsExtContainer

// InterRATMeasurementQuantitiesValueExtIEsExtField is the concrete ProtocolExtensionField[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsExtField = q8.InterRATMeasurementQuantitiesValueExtIEsExtField

// InterRATMeasurementQuantitiesValueExtIEsIEContainer is the concrete ProtocolIEContainer[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsIEContainer = q8.InterRATMeasurementQuantitiesValueExtIEsIEContainer

// InterRATMeasurementQuantitiesValueExtIEsIEField is the concrete ProtocolIEField[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsIEField = q8.InterRATMeasurementQuantitiesValueExtIEsIEField
type InterRATMeasurementQuantitiesValueExtIEsValue = q9.InterRATMeasurementQuantitiesValueExtIEsValue

const InterRATMeasurementQuantitiesValueGeran = q14.InterRATMeasurementQuantitiesValueGeran
const InterRATMeasurementQuantitiesValueNr = q14.InterRATMeasurementQuantitiesValueNr
const InterRATMeasurementQuantitiesValueUtran = q14.InterRATMeasurementQuantitiesValueUtran

// InterRATMeasurementQuantitiesValueValueCodec is the concrete ValueCodec[InterRATMeasurementQuantitiesValue].
type InterRATMeasurementQuantitiesValueValueCodec = q14.InterRATMeasurementQuantitiesValueValueCodec
type InterRATMeasurementResult = q21.InterRATMeasurementResult

// InterRATMeasurementResultAPERValue is the concrete APERValue[InterRATMeasurementResult].
type InterRATMeasurementResultAPERValue = q21.InterRATMeasurementResultAPERValue

// InterRATMeasurementResultCodec binds the complete APER value type.
var InterRATMeasurementResultCodec func() InterRATMeasurementResultValueCodec = q17.InterRATMeasurementResultCodec

// InterRATMeasurementResultComplete carries a complete InterRATMeasurementResult encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type InterRATMeasurementResultComplete = q21.InterRATMeasurementResultComplete

// InterRATMeasurementResultValueCodec is the concrete ValueCodec[InterRATMeasurementResult].
type InterRATMeasurementResultValueCodec = q21.InterRATMeasurementResultValueCodec

// LPPAPDU represents the ASN.1 CHOICE type LPPA-PDU.
type LPPAPDU = q4.LPPAPDU

// LPPAPDUAPERValue is the concrete APERValue[LPPAPDU].
type LPPAPDUAPERValue = q4.LPPAPDUAPERValue

// LPPAPDU choice constants.
const LPPAPDUChoiceInitiatingMessage = q14.LPPAPDUChoiceInitiatingMessage

// LPPAPDU choice constants.
const LPPAPDUChoiceSuccessfulOutcome = q14.LPPAPDUChoiceSuccessfulOutcome

// LPPAPDU choice constants.
const LPPAPDUChoiceUnsuccessfulOutcome = q14.LPPAPDUChoiceUnsuccessfulOutcome

// LPPAPDUCodec binds the complete source value type.
var LPPAPDUCodec func() LPPAPDUValueCodec = q4.LPPAPDUCodec

// LPPAPDUValueCodec is the concrete ValueCodec[LPPAPDU].
type LPPAPDUValueCodec = q4.LPPAPDUValueCodec

// LPPATransactionID represents the ASN.1 type LPPATransactionID (INTEGER).
type LPPATransactionID = q14.LPPATransactionID

// LPPATransactionIDAPERValue is the concrete APERValue[LPPATransactionID].
type LPPATransactionIDAPERValue = q14.LPPATransactionIDAPERValue

// LPPATransactionIDCodec binds the complete source value type.
var LPPATransactionIDCodec func() LPPATransactionIDValueCodec = q25.LPPATransactionIDCodec

// LPPATransactionIDValueCodec is the concrete ValueCodec[LPPATransactionID].
type LPPATransactionIDValueCodec = q14.LPPATransactionIDValueCodec
type MBSFNsubframeConfiguration = q15.MBSFNsubframeConfiguration

// MBSFNsubframeConfigurationAPERValue is the concrete APERValue[MBSFNsubframeConfiguration].
type MBSFNsubframeConfigurationAPERValue = q15.MBSFNsubframeConfigurationAPERValue

// MBSFNsubframeConfigurationCodec binds the complete source value type.
var MBSFNsubframeConfigurationCodec func() MBSFNsubframeConfigurationConcreteValueCodec = q7.MBSFNsubframeConfigurationCodec

// MBSFNsubframeConfigurationComplete carries a complete MBSFNsubframeConfiguration encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MBSFNsubframeConfigurationComplete = q7.MBSFNsubframeConfigurationComplete

// MBSFNsubframeConfigurationConcreteValueCodec is the concrete ValueCodec[MBSFNsubframeConfiguration].
type MBSFNsubframeConfigurationConcreteValueCodec = q15.MBSFNsubframeConfigurationConcreteValueCodec

// MBSFNsubframeConfigurationValue represents the ASN.1 type MBSFNsubframeConfigurationValue (SEQUENCE).
type MBSFNsubframeConfigurationValue = q15.MBSFNsubframeConfigurationValue

// MBSFNsubframeConfigurationValueAPERValue is the concrete APERValue[MBSFNsubframeConfigurationValue].
type MBSFNsubframeConfigurationValueAPERValue = q15.MBSFNsubframeConfigurationValueAPERValue

// MBSFNsubframeConfigurationValueCodec binds the complete source value type.
var MBSFNsubframeConfigurationValueCodec func() MBSFNsubframeConfigurationValueValueCodec = q15.MBSFNsubframeConfigurationValueCodec

// MBSFNsubframeConfigurationValueValueCodec is the concrete ValueCodec[MBSFNsubframeConfigurationValue].
type MBSFNsubframeConfigurationValueValueCodec = q15.MBSFNsubframeConfigurationValueValueCodec

// MarshalAPERAddOTDOACellInformation encodes a complete named list.
var MarshalAPERAddOTDOACellInformation func(v AddOTDOACellInformationComplete, options ...q23.EncodeOption) ([]byte, error) = q6.MarshalAPERAddOTDOACellInformation

// MarshalAPERAddOTDOACells encodes a complete named list.
var MarshalAPERAddOTDOACells func(v AddOTDOACellsComplete, options ...q23.EncodeOption) ([]byte, error) = q6.MarshalAPERAddOTDOACells

// MarshalAPERAssistanceInformationFailureList encodes a complete named list.
var MarshalAPERAssistanceInformationFailureList func(v AssistanceInformationFailureListComplete, options ...q23.EncodeOption) ([]byte, error) = q6.MarshalAPERAssistanceInformationFailureList

// MarshalAPERCriticalityDiagnosticsIEList encodes a complete named list.
var MarshalAPERCriticalityDiagnosticsIEList func(v CriticalityDiagnosticsIEListComplete, options ...q23.EncodeOption) ([]byte, error) = q6.MarshalAPERCriticalityDiagnosticsIEList

// MarshalAPERInterRATMeasurementQuantities encodes a complete named list.
var MarshalAPERInterRATMeasurementQuantities func(v InterRATMeasurementQuantitiesComplete, options ...q23.EncodeOption) ([]byte, error) = q6.MarshalAPERInterRATMeasurementQuantities

// MarshalAPERInterRATMeasurementResult encodes a complete named list.
var MarshalAPERInterRATMeasurementResult func(v InterRATMeasurementResultComplete, options ...q23.EncodeOption) ([]byte, error) = q21.MarshalAPERInterRATMeasurementResult

// MarshalAPERMBSFNsubframeConfiguration encodes a complete named list.
var MarshalAPERMBSFNsubframeConfiguration func(v MBSFNsubframeConfigurationComplete, options ...q23.EncodeOption) ([]byte, error) = q7.MarshalAPERMBSFNsubframeConfiguration

// MarshalAPERMeasuredResults encodes a complete named list.
var MarshalAPERMeasuredResults func(v MeasuredResultsComplete, options ...q23.EncodeOption) ([]byte, error) = q7.MarshalAPERMeasuredResults

// MarshalAPERMeasurementQuantities encodes a complete named list.
var MarshalAPERMeasurementQuantities func(v MeasurementQuantitiesComplete, options ...q23.EncodeOption) ([]byte, error) = q7.MarshalAPERMeasurementQuantities

// MarshalAPEROTDOACellInformation encodes a complete named list.
var MarshalAPEROTDOACellInformation func(v OTDOACellInformationComplete, options ...q23.EncodeOption) ([]byte, error) = q7.MarshalAPEROTDOACellInformation

// MarshalAPEROTDOACells encodes a complete named list.
var MarshalAPEROTDOACells func(v OTDOACellsComplete, options ...q23.EncodeOption) ([]byte, error) = q7.MarshalAPEROTDOACells

// MarshalAPEROTDOAInformationType encodes a complete named list.
var MarshalAPEROTDOAInformationType func(v OTDOAInformationTypeComplete, options ...q23.EncodeOption) ([]byte, error) = q7.MarshalAPEROTDOAInformationType

// MarshalAPERPRSFrequencyHoppingConfigurationBandPositions encodes a complete named list.
var MarshalAPERPRSFrequencyHoppingConfigurationBandPositions func(v PRSFrequencyHoppingConfigurationBandPositionsComplete, options ...q23.EncodeOption) ([]byte, error) = q24.MarshalAPERPRSFrequencyHoppingConfigurationBandPositions

// MarshalAPERPosSIBSegments encodes a complete named list.
var MarshalAPERPosSIBSegments func(v PosSIBSegmentsComplete, options ...q23.EncodeOption) ([]byte, error) = q24.MarshalAPERPosSIBSegments

// MarshalAPERPosSIBs encodes a complete named list.
var MarshalAPERPosSIBs func(v PosSIBsComplete, options ...q23.EncodeOption) ([]byte, error) = q24.MarshalAPERPosSIBs

// MarshalAPERResultGERAN encodes a complete named list.
var MarshalAPERResultGERAN func(v ResultGERANComplete, options ...q23.EncodeOption) ([]byte, error) = q24.MarshalAPERResultGERAN

// MarshalAPERResultNR encodes a complete named list.
var MarshalAPERResultNR func(v ResultNRComplete, options ...q23.EncodeOption) ([]byte, error) = q21.MarshalAPERResultNR

// MarshalAPERResultRSRP encodes a complete named list.
var MarshalAPERResultRSRP func(v ResultRSRPComplete, options ...q23.EncodeOption) ([]byte, error) = q24.MarshalAPERResultRSRP

// MarshalAPERResultRSRQ encodes a complete named list.
var MarshalAPERResultRSRQ func(v ResultRSRQComplete, options ...q23.EncodeOption) ([]byte, error) = q24.MarshalAPERResultRSRQ

// MarshalAPERResultUTRAN encodes a complete named list.
var MarshalAPERResultUTRAN func(v ResultUTRANComplete, options ...q23.EncodeOption) ([]byte, error) = q24.MarshalAPERResultUTRAN

// MarshalAPERResultsPerSSBIndexList encodes a complete named list.
var MarshalAPERResultsPerSSBIndexList func(v ResultsPerSSBIndexListComplete, options ...q23.EncodeOption) ([]byte, error) = q24.MarshalAPERResultsPerSSBIndexList

// MarshalAPERSRSConfigurationForAllCells encodes a complete named list.
var MarshalAPERSRSConfigurationForAllCells func(v SRSConfigurationForAllCellsComplete, options ...q23.EncodeOption) ([]byte, error) = q21.MarshalAPERSRSConfigurationForAllCells

// MarshalAPERSystemInformation encodes a complete named list.
var MarshalAPERSystemInformation func(v SystemInformationComplete, options ...q23.EncodeOption) ([]byte, error) = q21.MarshalAPERSystemInformation

// MarshalAPERWLANChannelList encodes a complete named list.
var MarshalAPERWLANChannelList func(v WLANChannelListComplete, options ...q23.EncodeOption) ([]byte, error) = q21.MarshalAPERWLANChannelList

// MarshalAPERWLANMeasurementQuantities encodes a complete named list.
var MarshalAPERWLANMeasurementQuantities func(v WLANMeasurementQuantitiesComplete, options ...q23.EncodeOption) ([]byte, error) = q12.MarshalAPERWLANMeasurementQuantities

// MarshalAPERWLANMeasurementResult encodes a complete named list.
var MarshalAPERWLANMeasurementResult func(v WLANMeasurementResultComplete, options ...q23.EncodeOption) ([]byte, error) = q17.MarshalAPERWLANMeasurementResult

// MaxCellReport is the integer constant for maxCellReport.
const MaxCellReport = q14.MaxCellReport

// MaxCellineNB is the integer constant for maxCellineNB.
const MaxCellineNB = q14.MaxCellineNB

// MaxCellineNBExt is the integer constant for maxCellineNB-ext.
const MaxCellineNBExt = q14.MaxCellineNBExt

// MaxGERANMeas is the integer constant for maxGERANMeas.
const MaxGERANMeas = q14.MaxGERANMeas

// MaxMBSFNAllocations is the integer constant for maxMBSFN-Allocations.
const MaxMBSFNAllocations = q14.MaxMBSFNAllocations

// MaxNRmeas is the integer constant for maxNRmeas.
const MaxNRmeas = q14.MaxNRmeas

// MaxNoMeas is the integer constant for maxNoMeas.
const MaxNoMeas = q14.MaxNoMeas

// MaxNrOfErrors is the integer constant for maxNrOfErrors.
const MaxNrOfErrors = q14.MaxNrOfErrors

// MaxNrOfPosSIBs is the integer constant for maxNrOfPosSIBs.
const MaxNrOfPosSIBs = q14.MaxNrOfPosSIBs

// MaxNrOfPosSImessage is the integer constant for maxNrOfPosSImessage.
const MaxNrOfPosSImessage = q14.MaxNrOfPosSImessage

// MaxNrOfSegments is the integer constant for maxNrOfSegments.
const MaxNrOfSegments = q14.MaxNrOfSegments

// MaxPrivateIEs is the integer constant for maxPrivateIEs.
const MaxPrivateIEs = q14.MaxPrivateIEs

// MaxProtocolExtensions is the integer constant for maxProtocolExtensions.
const MaxProtocolExtensions = q14.MaxProtocolExtensions

// MaxProtocolIEs is the integer constant for maxProtocolIEs.
const MaxProtocolIEs = q14.MaxProtocolIEs

// MaxResultsPerSSBIndex is the integer constant for maxResultsPerSSBIndex.
const MaxResultsPerSSBIndex = q14.MaxResultsPerSSBIndex

// MaxServCell is the integer constant for maxServCell.
const MaxServCell = q14.MaxServCell

// MaxUTRANMeas is the integer constant for maxUTRANMeas.
const MaxUTRANMeas = q14.MaxUTRANMeas

// MaxWLANchannels is the integer constant for maxWLANchannels.
const MaxWLANchannels = q14.MaxWLANchannels

// MaxnoAssistInfoFailureListItems is the integer constant for maxnoAssistInfoFailureListItems.
const MaxnoAssistInfoFailureListItems = q14.MaxnoAssistInfoFailureListItems

// MaxnoFreqHoppingBandsMinusOne is the integer constant for maxnoFreqHoppingBandsMinusOne.
const MaxnoFreqHoppingBandsMinusOne = q14.MaxnoFreqHoppingBandsMinusOne

// MaxnoOTDOAtypes is the integer constant for maxnoOTDOAtypes.
const MaxnoOTDOAtypes = q14.MaxnoOTDOAtypes

type MeasuredResults = q22.MeasuredResults

// MeasuredResultsAPERValue is the concrete APERValue[MeasuredResults].
type MeasuredResultsAPERValue = q22.MeasuredResultsAPERValue

// MeasuredResultsCodec binds the complete source value type.
var MeasuredResultsCodec func() MeasuredResultsConcreteValueCodec = q7.MeasuredResultsCodec

// MeasuredResultsComplete carries a complete MeasuredResults encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MeasuredResultsComplete = q7.MeasuredResultsComplete

// MeasuredResultsConcreteValueCodec is the concrete ValueCodec[MeasuredResults].
type MeasuredResultsConcreteValueCodec = q22.MeasuredResultsConcreteValueCodec

// MeasuredResultsValue represents the ASN.1 CHOICE type MeasuredResultsValue.
type MeasuredResultsValue = q22.MeasuredResultsValue

// MeasuredResultsValueAPERValue is the concrete APERValue[MeasuredResultsValue].
type MeasuredResultsValueAPERValue = q22.MeasuredResultsValueAPERValue

// MeasuredResultsValue choice constants.
const MeasuredResultsValueChoiceResultRSRP = q14.MeasuredResultsValueChoiceResultRSRP

// MeasuredResultsValue choice constants.
const MeasuredResultsValueChoiceResultRSRQ = q14.MeasuredResultsValueChoiceResultRSRQ

// MeasuredResultsValue choice constants.
const MeasuredResultsValueChoiceValueAngleOfArrival = q14.MeasuredResultsValueChoiceValueAngleOfArrival

// MeasuredResultsValue choice constants.
const MeasuredResultsValueChoiceValueTimingAdvanceType1 = q14.MeasuredResultsValueChoiceValueTimingAdvanceType1

// MeasuredResultsValue choice constants.
const MeasuredResultsValueChoiceValueTimingAdvanceType2 = q14.MeasuredResultsValueChoiceValueTimingAdvanceType2

// MeasuredResultsValueCodec binds the complete source value type.
var MeasuredResultsValueCodec func() MeasuredResultsValueValueCodec = q22.MeasuredResultsValueCodec

// MeasuredResultsValueValueCodec is the concrete ValueCodec[MeasuredResultsValue].
type MeasuredResultsValueValueCodec = q22.MeasuredResultsValueValueCodec

// MeasurementID represents the ASN.1 type Measurement-ID (INTEGER).
type MeasurementID = q14.MeasurementID

// MeasurementIDAPERValue is the concrete APERValue[MeasurementID].
type MeasurementIDAPERValue = q14.MeasurementIDAPERValue

// MeasurementIDCodec binds the complete APER value type.
var MeasurementIDCodec func() MeasurementIDValueCodec = q16.MeasurementIDCodec

// MeasurementIDValueCodec is the concrete ValueCodec[MeasurementID].
type MeasurementIDValueCodec = q14.MeasurementIDValueCodec

// MeasurementPeriodicity represents the ASN.1 ENUMERATED type MeasurementPeriodicity.
type MeasurementPeriodicity = q14.MeasurementPeriodicity

// MeasurementPeriodicityAPERValue is the concrete APERValue[MeasurementPeriodicity].
type MeasurementPeriodicityAPERValue = q14.MeasurementPeriodicityAPERValue

// MeasurementPeriodicityCodec binds the complete APER value type.
var MeasurementPeriodicityCodec func() MeasurementPeriodicityValueCodec = q12.MeasurementPeriodicityCodec

const MeasurementPeriodicityMin1 = q14.MeasurementPeriodicityMin1
const MeasurementPeriodicityMin12 = q14.MeasurementPeriodicityMin12
const MeasurementPeriodicityMin30 = q14.MeasurementPeriodicityMin30
const MeasurementPeriodicityMin6 = q14.MeasurementPeriodicityMin6
const MeasurementPeriodicityMin60 = q14.MeasurementPeriodicityMin60
const MeasurementPeriodicityMs1024 = q14.MeasurementPeriodicityMs1024
const MeasurementPeriodicityMs10240 = q14.MeasurementPeriodicityMs10240
const MeasurementPeriodicityMs120 = q14.MeasurementPeriodicityMs120
const MeasurementPeriodicityMs2048 = q14.MeasurementPeriodicityMs2048
const MeasurementPeriodicityMs240 = q14.MeasurementPeriodicityMs240
const MeasurementPeriodicityMs480 = q14.MeasurementPeriodicityMs480
const MeasurementPeriodicityMs5120 = q14.MeasurementPeriodicityMs5120
const MeasurementPeriodicityMs640 = q14.MeasurementPeriodicityMs640

// MeasurementPeriodicityValueCodec is the concrete ValueCodec[MeasurementPeriodicity].
type MeasurementPeriodicityValueCodec = q14.MeasurementPeriodicityValueCodec
type MeasurementQuantities = q16.MeasurementQuantities

// MeasurementQuantitiesAPERValue is the concrete APERValue[MeasurementQuantities].
type MeasurementQuantitiesAPERValue = q16.MeasurementQuantitiesAPERValue

// MeasurementQuantitiesCodec binds the complete APER value type.
var MeasurementQuantitiesCodec func() MeasurementQuantitiesConcreteValueCodec = q12.MeasurementQuantitiesCodec

// MeasurementQuantitiesComplete carries a complete MeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MeasurementQuantitiesComplete = q7.MeasurementQuantitiesComplete

// MeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[MeasurementQuantities].
type MeasurementQuantitiesConcreteValueCodec = q16.MeasurementQuantitiesConcreteValueCodec

// MeasurementQuantitiesItem represents the ASN.1 type MeasurementQuantities-Item (SEQUENCE).
type MeasurementQuantitiesItem = q16.MeasurementQuantitiesItem

// MeasurementQuantitiesItemAPERValue is the concrete APERValue[MeasurementQuantitiesItem].
type MeasurementQuantitiesItemAPERValue = q16.MeasurementQuantitiesItemAPERValue

// MeasurementQuantitiesItemCodec binds the complete APER value type.
var MeasurementQuantitiesItemCodec func() MeasurementQuantitiesItemValueCodec = q26.MeasurementQuantitiesItemCodec

// MeasurementQuantitiesItemIEContainer is the concrete ProtocolIEContainer[MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemIEContainer = q16.MeasurementQuantitiesItemIEContainer

// MeasurementQuantitiesItemIEField is the concrete ProtocolIEField[MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemIEField = q16.MeasurementQuantitiesItemIEField
type MeasurementQuantitiesItemIETable = q26.MeasurementQuantitiesItemIETable
type MeasurementQuantitiesItemIEValue = q16.MeasurementQuantitiesItemIEValue

// MeasurementQuantitiesItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemIEValueProtocolIESingleContainer = q16.MeasurementQuantitiesItemIEValueProtocolIESingleContainer

var MeasurementQuantitiesItemIEs func() MeasurementQuantitiesItemIETable = q26.MeasurementQuantitiesItemIEs

// MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding is the concrete IEBinding[MeasurementQuantitiesItem, MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding = q16.MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding

// MeasurementQuantitiesItemValueCodec is the concrete ValueCodec[MeasurementQuantitiesItem].
type MeasurementQuantitiesItemValueCodec = q16.MeasurementQuantitiesItemValueCodec

// MeasurementQuantitiesValue represents the ASN.1 ENUMERATED type MeasurementQuantitiesValue.
type MeasurementQuantitiesValue = q14.MeasurementQuantitiesValue

// MeasurementQuantitiesValueAPERValue is the concrete APERValue[MeasurementQuantitiesValue].
type MeasurementQuantitiesValueAPERValue = q14.MeasurementQuantitiesValueAPERValue

const MeasurementQuantitiesValueAngleOfArrival = q14.MeasurementQuantitiesValueAngleOfArrival
const MeasurementQuantitiesValueCellID = q14.MeasurementQuantitiesValueCellID

// MeasurementQuantitiesValueCodec binds the complete source value type.
var MeasurementQuantitiesValueCodec func() MeasurementQuantitiesValueValueCodec = q9.MeasurementQuantitiesValueCodec

type MeasurementQuantitiesValueExtIETable = q25.MeasurementQuantitiesValueExtIETable

var MeasurementQuantitiesValueExtIEs func() MeasurementQuantitiesValueExtIETable = q25.MeasurementQuantitiesValueExtIEs

// MeasurementQuantitiesValueExtIEsExtContainer is the concrete ProtocolExtensionContainer[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsExtContainer = q25.MeasurementQuantitiesValueExtIEsExtContainer

// MeasurementQuantitiesValueExtIEsExtField is the concrete ProtocolExtensionField[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsExtField = q25.MeasurementQuantitiesValueExtIEsExtField

// MeasurementQuantitiesValueExtIEsIEContainer is the concrete ProtocolIEContainer[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsIEContainer = q25.MeasurementQuantitiesValueExtIEsIEContainer

// MeasurementQuantitiesValueExtIEsIEField is the concrete ProtocolIEField[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsIEField = q25.MeasurementQuantitiesValueExtIEsIEField
type MeasurementQuantitiesValueExtIEsValue = q9.MeasurementQuantitiesValueExtIEsValue

const MeasurementQuantitiesValueRSRP = q14.MeasurementQuantitiesValueRSRP
const MeasurementQuantitiesValueRSRQ = q14.MeasurementQuantitiesValueRSRQ
const MeasurementQuantitiesValueTimingAdvanceType1 = q14.MeasurementQuantitiesValueTimingAdvanceType1
const MeasurementQuantitiesValueTimingAdvanceType2 = q14.MeasurementQuantitiesValueTimingAdvanceType2

// MeasurementQuantitiesValueValueCodec is the concrete ValueCodec[MeasurementQuantitiesValue].
type MeasurementQuantitiesValueValueCodec = q14.MeasurementQuantitiesValueValueCodec

const MissingMandatory = q14.MissingMandatory

// NPRSConfiguration represents the ASN.1 type NPRSConfiguration (SEQUENCE).
type NPRSConfiguration = q26.NPRSConfiguration

// NPRSConfigurationAPERValue is the concrete APERValue[NPRSConfiguration].
type NPRSConfigurationAPERValue = q26.NPRSConfigurationAPERValue

// NPRSConfigurationCodec binds the complete source value type.
var NPRSConfigurationCodec func() NPRSConfigurationValueCodec = q26.NPRSConfigurationCodec

// NPRSConfigurationValueCodec is the concrete ValueCodec[NPRSConfiguration].
type NPRSConfigurationValueCodec = q26.NPRSConfigurationValueCodec

// NPRSMutingConfiguration represents the ASN.1 CHOICE type NPRSMutingConfiguration.
type NPRSMutingConfiguration = q26.NPRSMutingConfiguration

// NPRSMutingConfigurationAPERValue is the concrete APERValue[NPRSMutingConfiguration].
type NPRSMutingConfigurationAPERValue = q26.NPRSMutingConfigurationAPERValue

// NPRSMutingConfiguration choice constants.
const NPRSMutingConfigurationChoiceEight = q14.NPRSMutingConfigurationChoiceEight

// NPRSMutingConfiguration choice constants.
const NPRSMutingConfigurationChoiceFour = q14.NPRSMutingConfigurationChoiceFour

// NPRSMutingConfiguration choice constants.
const NPRSMutingConfigurationChoiceSixteen = q14.NPRSMutingConfigurationChoiceSixteen

// NPRSMutingConfiguration choice constants.
const NPRSMutingConfigurationChoiceTwo = q14.NPRSMutingConfigurationChoiceTwo

// NPRSMutingConfigurationCodec binds the complete source value type.
var NPRSMutingConfigurationCodec func() NPRSMutingConfigurationValueCodec = q26.NPRSMutingConfigurationCodec

// NPRSMutingConfigurationValueCodec is the concrete ValueCodec[NPRSMutingConfiguration].
type NPRSMutingConfigurationValueCodec = q26.NPRSMutingConfigurationValueCodec

// NPRSSequenceInfo represents the ASN.1 type NPRSSequenceInfo (INTEGER).
type NPRSSequenceInfo = q14.NPRSSequenceInfo

// NPRSSequenceInfoAPERValue is the concrete APERValue[NPRSSequenceInfo].
type NPRSSequenceInfoAPERValue = q14.NPRSSequenceInfoAPERValue

// NPRSSequenceInfoCodec binds the complete source value type.
var NPRSSequenceInfoCodec func() NPRSSequenceInfoValueCodec = q9.NPRSSequenceInfoCodec

// NPRSSequenceInfoValueCodec is the concrete ValueCodec[NPRSSequenceInfo].
type NPRSSequenceInfoValueCodec = q14.NPRSSequenceInfoValueCodec

// NPRSSubframePartA represents the ASN.1 type NPRSSubframePartA (SEQUENCE).
type NPRSSubframePartA = q26.NPRSSubframePartA

// NPRSSubframePartAAPERValue is the concrete APERValue[NPRSSubframePartA].
type NPRSSubframePartAAPERValue = q26.NPRSSubframePartAAPERValue

// NPRSSubframePartACodec binds the complete source value type.
var NPRSSubframePartACodec func() NPRSSubframePartAValueCodec = q26.NPRSSubframePartACodec

// NPRSSubframePartAValueCodec is the concrete ValueCodec[NPRSSubframePartA].
type NPRSSubframePartAValueCodec = q26.NPRSSubframePartAValueCodec

// NPRSSubframePartB represents the ASN.1 type NPRSSubframePartB (SEQUENCE).
type NPRSSubframePartB = q26.NPRSSubframePartB

// NPRSSubframePartBAPERValue is the concrete APERValue[NPRSSubframePartB].
type NPRSSubframePartBAPERValue = q26.NPRSSubframePartBAPERValue

// NPRSSubframePartBCodec binds the complete source value type.
var NPRSSubframePartBCodec func() NPRSSubframePartBValueCodec = q26.NPRSSubframePartBCodec

// NPRSSubframePartBValueCodec is the concrete ValueCodec[NPRSSubframePartB].
type NPRSSubframePartBValueCodec = q26.NPRSSubframePartBValueCodec

// NRARFCN represents the ASN.1 type NRARFCN (INTEGER).
type NRARFCN = q14.NRARFCN

// NRARFCNAPERValue is the concrete APERValue[NRARFCN].
type NRARFCNAPERValue = q14.NRARFCNAPERValue

// NRARFCNCodec binds the complete source value type.
var NRARFCNCodec func() NRARFCNValueCodec = q25.NRARFCNCodec

// NRARFCNValueCodec is the concrete ValueCodec[NRARFCN].
type NRARFCNValueCodec = q14.NRARFCNValueCodec

// NRCGI represents the ASN.1 type NR-CGI (SEQUENCE).
type NRCGI = q26.NRCGI

// NRCGIAPERValue is the concrete APERValue[NRCGI].
type NRCGIAPERValue = q26.NRCGIAPERValue

// NRCGICodec binds the complete APER value type.
var NRCGICodec func() NRCGIValueCodec = q24.NRCGICodec

type NRCGIExtIETable = q25.NRCGIExtIETable

var NRCGIExtIEs func() NRCGIExtIETable = q25.NRCGIExtIEs

// NRCGIExtIEsExtContainer is the concrete ProtocolExtensionContainer[NRCGIExtIEsValue].
type NRCGIExtIEsExtContainer = q25.NRCGIExtIEsExtContainer

// NRCGIExtIEsExtField is the concrete ProtocolExtensionField[NRCGIExtIEsValue].
type NRCGIExtIEsExtField = q25.NRCGIExtIEsExtField

// NRCGIExtIEsIEContainer is the concrete ProtocolIEContainer[NRCGIExtIEsValue].
type NRCGIExtIEsIEContainer = q25.NRCGIExtIEsIEContainer

// NRCGIExtIEsIEField is the concrete ProtocolIEField[NRCGIExtIEsValue].
type NRCGIExtIEsIEField = q25.NRCGIExtIEsIEField
type NRCGIExtIEsValue = q9.NRCGIExtIEsValue

// NRCGIValueCodec is the concrete ValueCodec[NRCGI].
type NRCGIValueCodec = q26.NRCGIValueCodec

// NRCellIdentity represents the ASN.1 type NRCellIdentity (BIT_STRING).
type NRCellIdentity = q14.NRCellIdentity

// NRCellIdentityAPERValue is the concrete APERValue[NRCellIdentity].
type NRCellIdentityAPERValue = q14.NRCellIdentityAPERValue

// NRCellIdentityCodec binds the complete source value type.
var NRCellIdentityCodec func() NRCellIdentityValueCodec = q9.NRCellIdentityCodec

// NRCellIdentityValueCodec is the concrete ValueCodec[NRCellIdentity].
type NRCellIdentityValueCodec = q14.NRCellIdentityValueCodec

// NRPCI represents the ASN.1 type NRPCI (INTEGER).
type NRPCI = q14.NRPCI

// NRPCIAPERValue is the concrete APERValue[NRPCI].
type NRPCIAPERValue = q14.NRPCIAPERValue

// NRPCICodec binds the complete source value type.
var NRPCICodec func() NRPCIValueCodec = q25.NRPCICodec

// NRPCIValueCodec is the concrete ValueCodec[NRPCI].
type NRPCIValueCodec = q14.NRPCIValueCodec

// NarrowBandIndex represents the ASN.1 type NarrowBandIndex (INTEGER).
type NarrowBandIndex = q14.NarrowBandIndex

// NarrowBandIndexAPERValue is the concrete APERValue[NarrowBandIndex].
type NarrowBandIndexAPERValue = q14.NarrowBandIndexAPERValue

// NarrowBandIndexCodec binds the complete source value type.
var NarrowBandIndexCodec func() NarrowBandIndexValueCodec = q9.NarrowBandIndexCodec

// NarrowBandIndexValueCodec is the concrete ValueCodec[NarrowBandIndex].
type NarrowBandIndexValueCodec = q14.NarrowBandIndexValueCodec

var NewAssistanceInformationControl func(fields AssistanceInformationControlIEContainer, options ...q23.BuildOption) (AssistanceInformationControl, error) = q11.NewAssistanceInformationControl
var NewAssistanceInformationFeedback func(fields AssistanceInformationFeedbackIEContainer, options ...q23.BuildOption) (AssistanceInformationFeedback, error) = q4.NewAssistanceInformationFeedback

// NewBitmapsforNPRSForty constructs a checked complete value.
var NewBitmapsforNPRSForty func(v q27.BitString, options ...q23.BuildOption) (BitmapsforNPRS, error) = q18.NewBitmapsforNPRSForty

// NewBitmapsforNPRSFortyTdd constructs a checked complete value.
var NewBitmapsforNPRSFortyTdd func(v q27.BitString, options ...q23.BuildOption) (BitmapsforNPRS, error) = q18.NewBitmapsforNPRSFortyTdd

// NewBitmapsforNPRSTen constructs a checked complete value.
var NewBitmapsforNPRSTen func(v q27.BitString, options ...q23.BuildOption) (BitmapsforNPRS, error) = q18.NewBitmapsforNPRSTen

// NewBitmapsforNPRSTenTdd constructs a checked complete value.
var NewBitmapsforNPRSTenTdd func(v q27.BitString, options ...q23.BuildOption) (BitmapsforNPRS, error) = q18.NewBitmapsforNPRSTenTdd

// NewBitmapsforNPRSUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewBitmapsforNPRSUnknownExtension func(index uint64, contents []byte, options ...q23.BuildOption) (BitmapsforNPRS, error) = q26.NewBitmapsforNPRSUnknownExtension

// NewCauseMisc constructs a checked complete value.
var NewCauseMisc func(v CauseMisc, options ...q23.BuildOption) (Cause, error) = q18.NewCauseMisc

// NewCauseProtocol constructs a checked complete value.
var NewCauseProtocol func(v CauseProtocol, options ...q23.BuildOption) (Cause, error) = q18.NewCauseProtocol

// NewCauseRadioNetwork constructs a checked complete value.
var NewCauseRadioNetwork func(v CauseRadioNetwork, options ...q23.BuildOption) (Cause, error) = q18.NewCauseRadioNetwork

// NewCauseUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewCauseUnknownExtension func(index uint64, contents []byte, options ...q23.BuildOption) (Cause, error) = q26.NewCauseUnknownExtension
var NewECIDMeasurementFailureIndication func(fields ECIDMeasurementFailureIndicationIEContainer, options ...q23.BuildOption) (ECIDMeasurementFailureIndication, error) = q4.NewECIDMeasurementFailureIndication
var NewECIDMeasurementInitiationFailure func(fields ECIDMeasurementInitiationFailureIEContainer, options ...q23.BuildOption) (ECIDMeasurementInitiationFailure, error) = q4.NewECIDMeasurementInitiationFailure
var NewECIDMeasurementInitiationRequest func(fields ECIDMeasurementInitiationRequestIEContainer, options ...q23.BuildOption) (ECIDMeasurementInitiationRequest, error) = q11.NewECIDMeasurementInitiationRequest
var NewECIDMeasurementInitiationResponse func(fields ECIDMeasurementInitiationResponseIEContainer, options ...q23.BuildOption) (ECIDMeasurementInitiationResponse, error) = q11.NewECIDMeasurementInitiationResponse
var NewECIDMeasurementReport func(fields ECIDMeasurementReportIEContainer, options ...q23.BuildOption) (ECIDMeasurementReport, error) = q4.NewECIDMeasurementReport
var NewECIDMeasurementTerminationCommand func(fields ECIDMeasurementTerminationCommandIEContainer, options ...q23.BuildOption) (ECIDMeasurementTerminationCommand, error) = q4.NewECIDMeasurementTerminationCommand
var NewErrorIndication func(fields ErrorIndicationIEContainer, options ...q23.BuildOption) (ErrorIndication, error) = q4.NewErrorIndication

// NewInterRATMeasuredResultsValueResultGERAN constructs a checked complete value.
var NewInterRATMeasuredResultsValueResultGERAN func(v ResultGERAN, options ...q23.BuildOption) (InterRATMeasuredResultsValue, error) = q21.NewInterRATMeasuredResultsValueResultGERAN

// NewInterRATMeasuredResultsValueResultNR constructs a checked complete value.
var NewInterRATMeasuredResultsValueResultNR func(v ResultNR, options ...q23.BuildOption) (InterRATMeasuredResultsValue, error) = q21.NewInterRATMeasuredResultsValueResultNR

// NewInterRATMeasuredResultsValueResultUTRAN constructs a checked complete value.
var NewInterRATMeasuredResultsValueResultUTRAN func(v ResultUTRAN, options ...q23.BuildOption) (InterRATMeasuredResultsValue, error) = q21.NewInterRATMeasuredResultsValueResultUTRAN

// NewInterRATMeasuredResultsValueUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewInterRATMeasuredResultsValueUnknownExtension func(index uint64, contents []byte, options ...q23.BuildOption) (InterRATMeasuredResultsValue, error) = q21.NewInterRATMeasuredResultsValueUnknownExtension

// NewLPPAPDUInitiatingMessage constructs and validates a complete LPPa message.
var NewLPPAPDUInitiatingMessage func(v InitiatingMessage, options ...q23.BuildOption) (LPPAPDU, error) = q11.NewLPPAPDUInitiatingMessage

// NewLPPAPDUSuccessfulOutcome constructs and validates a complete LPPa message.
var NewLPPAPDUSuccessfulOutcome func(v SuccessfulOutcome, options ...q23.BuildOption) (LPPAPDU, error) = q11.NewLPPAPDUSuccessfulOutcome

// NewLPPAPDUUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewLPPAPDUUnknownExtension func(index uint64, contents []byte, options ...q23.BuildOption) (LPPAPDU, error) = q4.NewLPPAPDUUnknownExtension

// NewLPPAPDUUnsuccessfulOutcome constructs and validates a complete LPPa message.
var NewLPPAPDUUnsuccessfulOutcome func(v UnsuccessfulOutcome, options ...q23.BuildOption) (LPPAPDU, error) = q11.NewLPPAPDUUnsuccessfulOutcome

// NewMeasuredResultsValueResultRSRP constructs a checked complete value.
var NewMeasuredResultsValueResultRSRP func(v ResultRSRP, options ...q23.BuildOption) (MeasuredResultsValue, error) = q22.NewMeasuredResultsValueResultRSRP

// NewMeasuredResultsValueResultRSRQ constructs a checked complete value.
var NewMeasuredResultsValueResultRSRQ func(v ResultRSRQ, options ...q23.BuildOption) (MeasuredResultsValue, error) = q22.NewMeasuredResultsValueResultRSRQ

// NewMeasuredResultsValueUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewMeasuredResultsValueUnknownExtension func(index uint64, contents []byte, options ...q23.BuildOption) (MeasuredResultsValue, error) = q22.NewMeasuredResultsValueUnknownExtension

// NewMeasuredResultsValueValueAngleOfArrival constructs a checked complete value.
var NewMeasuredResultsValueValueAngleOfArrival func(v int64, options ...q23.BuildOption) (MeasuredResultsValue, error) = q22.NewMeasuredResultsValueValueAngleOfArrival

// NewMeasuredResultsValueValueTimingAdvanceType1 constructs a checked complete value.
var NewMeasuredResultsValueValueTimingAdvanceType1 func(v int64, options ...q23.BuildOption) (MeasuredResultsValue, error) = q22.NewMeasuredResultsValueValueTimingAdvanceType1

// NewMeasuredResultsValueValueTimingAdvanceType2 constructs a checked complete value.
var NewMeasuredResultsValueValueTimingAdvanceType2 func(v int64, options ...q23.BuildOption) (MeasuredResultsValue, error) = q22.NewMeasuredResultsValueValueTimingAdvanceType2

// NewNPRSMutingConfigurationEight constructs a checked complete value.
var NewNPRSMutingConfigurationEight func(v q27.BitString, options ...q23.BuildOption) (NPRSMutingConfiguration, error) = q18.NewNPRSMutingConfigurationEight

// NewNPRSMutingConfigurationFour constructs a checked complete value.
var NewNPRSMutingConfigurationFour func(v q27.BitString, options ...q23.BuildOption) (NPRSMutingConfiguration, error) = q18.NewNPRSMutingConfigurationFour

// NewNPRSMutingConfigurationSixteen constructs a checked complete value.
var NewNPRSMutingConfigurationSixteen func(v q27.BitString, options ...q23.BuildOption) (NPRSMutingConfiguration, error) = q18.NewNPRSMutingConfigurationSixteen

// NewNPRSMutingConfigurationTwo constructs a checked complete value.
var NewNPRSMutingConfigurationTwo func(v q27.BitString, options ...q23.BuildOption) (NPRSMutingConfiguration, error) = q18.NewNPRSMutingConfigurationTwo

// NewNPRSMutingConfigurationUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewNPRSMutingConfigurationUnknownExtension func(index uint64, contents []byte, options ...q23.BuildOption) (NPRSMutingConfiguration, error) = q26.NewNPRSMutingConfigurationUnknownExtension

// NewOTDOACellInformationItemCPLength constructs a checked complete value.
var NewOTDOACellInformationItemCPLength func(v CPLength, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemCPLength

// NewOTDOACellInformationItemCellId constructs a checked complete value.
var NewOTDOACellInformationItemCellId func(v ECGI, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemCellId

// NewOTDOACellInformationItemCrsCPlength constructs a checked complete value.
var NewOTDOACellInformationItemCrsCPlength func(v CPLength, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemCrsCPlength

// NewOTDOACellInformationItemDLBandwidth constructs a checked complete value.
var NewOTDOACellInformationItemDLBandwidth func(v DLBandwidth, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemDLBandwidth

// NewOTDOACellInformationItemEARFCN constructs a checked complete value.
var NewOTDOACellInformationItemEARFCN func(v EARFCN, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemEARFCN

// NewOTDOACellInformationItemEUTRANAccessPointPosition constructs a checked complete value.
var NewOTDOACellInformationItemEUTRANAccessPointPosition func(v EUTRANAccessPointPosition, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemEUTRANAccessPointPosition

// NewOTDOACellInformationItemMBSFNsubframeConfiguration constructs a checked complete value.
var NewOTDOACellInformationItemMBSFNsubframeConfiguration func(v MBSFNsubframeConfiguration, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemMBSFNsubframeConfiguration

// NewOTDOACellInformationItemNPRSConfiguration constructs a checked complete value.
var NewOTDOACellInformationItemNPRSConfiguration func(v NPRSConfiguration, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemNPRSConfiguration

// NewOTDOACellInformationItemNPRSID constructs a checked complete value.
var NewOTDOACellInformationItemNPRSID func(v *q28.Int, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemNPRSID

// NewOTDOACellInformationItemNPRSSequenceInfo constructs a checked complete value.
var NewOTDOACellInformationItemNPRSSequenceInfo func(v NPRSSequenceInfo, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemNPRSSequenceInfo

// NewOTDOACellInformationItemNPRSType2 constructs a checked complete value.
var NewOTDOACellInformationItemNPRSType2 func(v NPRSConfiguration, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemNPRSType2

// NewOTDOACellInformationItemNumberOfAntennaPorts constructs a checked complete value.
var NewOTDOACellInformationItemNumberOfAntennaPorts func(v NumberOfAntennaPorts, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemNumberOfAntennaPorts

// NewOTDOACellInformationItemNumberOfDlFrames constructs a checked complete value.
var NewOTDOACellInformationItemNumberOfDlFrames func(v NumberOfDlFrames, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemNumberOfDlFrames

// NewOTDOACellInformationItemNumberOfDlFramesExtended constructs a checked complete value.
var NewOTDOACellInformationItemNumberOfDlFramesExtended func(v NumberOfDlFramesExtended, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemNumberOfDlFramesExtended

// NewOTDOACellInformationItemOffsetNBChanneltoEARFCN constructs a checked complete value.
var NewOTDOACellInformationItemOffsetNBChanneltoEARFCN func(v OffsetNBChanneltoEARFCN, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemOffsetNBChanneltoEARFCN

// NewOTDOACellInformationItemOperationModeInfo constructs a checked complete value.
var NewOTDOACellInformationItemOperationModeInfo func(v OperationModeInfo, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemOperationModeInfo

// NewOTDOACellInformationItemPCI constructs a checked complete value.
var NewOTDOACellInformationItemPCI func(v PCI, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemPCI

// NewOTDOACellInformationItemPRSBandwidth constructs a checked complete value.
var NewOTDOACellInformationItemPRSBandwidth func(v PRSBandwidth, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemPRSBandwidth

// NewOTDOACellInformationItemPRSConfigurationIndex constructs a checked complete value.
var NewOTDOACellInformationItemPRSConfigurationIndex func(v PRSConfigurationIndex, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemPRSConfigurationIndex

// NewOTDOACellInformationItemPRSFreqHoppingConfig constructs a checked complete value.
var NewOTDOACellInformationItemPRSFreqHoppingConfig func(v PRSFrequencyHoppingConfiguration, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemPRSFreqHoppingConfig

// NewOTDOACellInformationItemPRSMutingConfiguration constructs a checked complete value.
var NewOTDOACellInformationItemPRSMutingConfiguration func(v PRSMutingConfiguration, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemPRSMutingConfiguration

// NewOTDOACellInformationItemPRSOccasionGroup constructs a checked complete value.
var NewOTDOACellInformationItemPRSOccasionGroup func(v PRSOccasionGroup, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemPRSOccasionGroup

// NewOTDOACellInformationItemPrsid constructs a checked complete value.
var NewOTDOACellInformationItemPrsid func(v PRSID, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemPrsid

// NewOTDOACellInformationItemRepetitionNumberofSIB1NB constructs a checked complete value.
var NewOTDOACellInformationItemRepetitionNumberofSIB1NB func(v RepetitionNumberofSIB1NB, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemRepetitionNumberofSIB1NB

// NewOTDOACellInformationItemSFNInitialisationTime constructs a checked complete value.
var NewOTDOACellInformationItemSFNInitialisationTime func(v SFNInitialisationTime, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemSFNInitialisationTime

// NewOTDOACellInformationItemTAC constructs a checked complete value.
var NewOTDOACellInformationItemTAC func(v TAC, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemTAC

// NewOTDOACellInformationItemTddConfiguration constructs a checked complete value.
var NewOTDOACellInformationItemTddConfiguration func(v TDDConfiguration, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemTddConfiguration

// NewOTDOACellInformationItemTpType constructs a checked complete value.
var NewOTDOACellInformationItemTpType func(v TPType, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemTpType

// NewOTDOACellInformationItemTpid constructs a checked complete value.
var NewOTDOACellInformationItemTpid func(v TPID, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q20.NewOTDOACellInformationItemTpid

// NewOTDOACellInformationItemUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewOTDOACellInformationItemUnknownExtension func(index uint64, contents []byte, options ...q23.BuildOption) (OTDOACellInformationItem, error) = q5.NewOTDOACellInformationItemUnknownExtension
var NewOTDOAInformationFailure func(fields OTDOAInformationFailureIEContainer, options ...q23.BuildOption) (OTDOAInformationFailure, error) = q4.NewOTDOAInformationFailure
var NewOTDOAInformationRequest func(fields OTDOAInformationRequestIEContainer, options ...q23.BuildOption) (OTDOAInformationRequest, error) = q4.NewOTDOAInformationRequest
var NewOTDOAInformationResponse func(fields OTDOAInformationResponseIEContainer, options ...q23.BuildOption) (OTDOAInformationResponse, error) = q11.NewOTDOAInformationResponse
var NewOpaqueInitiatingMessage func(code ProcedureCode, criticality Criticality, transactionID LPPATransactionID, data []byte) (InitiatingMessage, error) = q12.NewOpaqueInitiatingMessage
var NewOpaqueSuccessfulOutcome func(code ProcedureCode, criticality Criticality, transactionID LPPATransactionID, data []byte) (SuccessfulOutcome, error) = q4.NewOpaqueSuccessfulOutcome
var NewOpaqueUnsuccessfulOutcome func(code ProcedureCode, criticality Criticality, transactionID LPPATransactionID, data []byte) (UnsuccessfulOutcome, error) = q20.NewOpaqueUnsuccessfulOutcome

// NewPRSMutingConfigurationEight constructs a checked complete value.
var NewPRSMutingConfigurationEight func(v q27.BitString, options ...q23.BuildOption) (PRSMutingConfiguration, error) = q18.NewPRSMutingConfigurationEight

// NewPRSMutingConfigurationFiveHundredAndTwelve constructs a checked complete value.
var NewPRSMutingConfigurationFiveHundredAndTwelve func(v q27.BitString, options ...q23.BuildOption) (PRSMutingConfiguration, error) = q18.NewPRSMutingConfigurationFiveHundredAndTwelve

// NewPRSMutingConfigurationFour constructs a checked complete value.
var NewPRSMutingConfigurationFour func(v q27.BitString, options ...q23.BuildOption) (PRSMutingConfiguration, error) = q29.NewPRSMutingConfigurationFour

// NewPRSMutingConfigurationOneHundredAndTwentyEight constructs a checked complete value.
var NewPRSMutingConfigurationOneHundredAndTwentyEight func(v q27.BitString, options ...q23.BuildOption) (PRSMutingConfiguration, error) = q29.NewPRSMutingConfigurationOneHundredAndTwentyEight

// NewPRSMutingConfigurationOneThousandAndTwentyFour constructs a checked complete value.
var NewPRSMutingConfigurationOneThousandAndTwentyFour func(v q27.BitString, options ...q23.BuildOption) (PRSMutingConfiguration, error) = q29.NewPRSMutingConfigurationOneThousandAndTwentyFour

// NewPRSMutingConfigurationSixteen constructs a checked complete value.
var NewPRSMutingConfigurationSixteen func(v q27.BitString, options ...q23.BuildOption) (PRSMutingConfiguration, error) = q29.NewPRSMutingConfigurationSixteen

// NewPRSMutingConfigurationSixtyFour constructs a checked complete value.
var NewPRSMutingConfigurationSixtyFour func(v q27.BitString, options ...q23.BuildOption) (PRSMutingConfiguration, error) = q29.NewPRSMutingConfigurationSixtyFour

// NewPRSMutingConfigurationThirtyTwo constructs a checked complete value.
var NewPRSMutingConfigurationThirtyTwo func(v q27.BitString, options ...q23.BuildOption) (PRSMutingConfiguration, error) = q29.NewPRSMutingConfigurationThirtyTwo

// NewPRSMutingConfigurationTwo constructs a checked complete value.
var NewPRSMutingConfigurationTwo func(v q27.BitString, options ...q23.BuildOption) (PRSMutingConfiguration, error) = q29.NewPRSMutingConfigurationTwo

// NewPRSMutingConfigurationTwoHundredAndFiftySix constructs a checked complete value.
var NewPRSMutingConfigurationTwoHundredAndFiftySix func(v q27.BitString, options ...q23.BuildOption) (PRSMutingConfiguration, error) = q29.NewPRSMutingConfigurationTwoHundredAndFiftySix

// NewPRSMutingConfigurationUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewPRSMutingConfigurationUnknownExtension func(index uint64, contents []byte, options ...q23.BuildOption) (PRSMutingConfiguration, error) = q30.NewPRSMutingConfigurationUnknownExtension

type NewPayloadCodec[T any] = q4.NewPayloadCodec[T]

// NewPrivateIEIDGlobal constructs a checked complete value.
var NewPrivateIEIDGlobal func(v q27.ObjectIdentifier, options ...q23.BuildOption) (PrivateIEID, error) = q29.NewPrivateIEIDGlobal

// NewPrivateIEIDLocal constructs a checked complete value.
var NewPrivateIEIDLocal func(v int64, options ...q23.BuildOption) (PrivateIEID, error) = q29.NewPrivateIEIDLocal
var NewPrivateMessage func(fields PrivateMessageIEsValuePrivateIEContainer, options ...q23.BuildOption) (PrivateMessage, error) = q21.NewPrivateMessage

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD constructs a checked complete value.
var NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD func(v PhysCellIDUTRAFDD, options ...q23.BuildOption) (ResultUTRANItemPhysCellIDUTRAN, error) = q29.NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD constructs a checked complete value.
var NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD func(v PhysCellIDUTRATDD, options ...q23.BuildOption) (ResultUTRANItemPhysCellIDUTRAN, error) = q29.NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD

// NewSubframeallocationFourFrames constructs a checked complete value.
var NewSubframeallocationFourFrames func(v q27.BitString, options ...q23.BuildOption) (Subframeallocation, error) = q29.NewSubframeallocationFourFrames

// NewSubframeallocationOneFrame constructs a checked complete value.
var NewSubframeallocationOneFrame func(v q27.BitString, options ...q23.BuildOption) (Subframeallocation, error) = q29.NewSubframeallocationOneFrame
var NewUTDOAInformationFailure func(fields UTDOAInformationFailureIEContainer, options ...q23.BuildOption) (UTDOAInformationFailure, error) = q11.NewUTDOAInformationFailure
var NewUTDOAInformationRequest func(fields UTDOAInformationRequestIEContainer, options ...q23.BuildOption) (UTDOAInformationRequest, error) = q11.NewUTDOAInformationRequest
var NewUTDOAInformationResponse func(fields UTDOAInformationResponseIEContainer, options ...q23.BuildOption) (UTDOAInformationResponse, error) = q11.NewUTDOAInformationResponse
var NewUTDOAInformationUpdate func(fields UTDOAInformationUpdateIEContainer, options ...q23.BuildOption) (UTDOAInformationUpdate, error) = q11.NewUTDOAInformationUpdate

const NotAllowed = q14.NotAllowed

// NumberOfAntennaPorts represents the ASN.1 ENUMERATED type NumberOfAntennaPorts.
type NumberOfAntennaPorts = q14.NumberOfAntennaPorts

// NumberOfAntennaPortsAPERValue is the concrete APERValue[NumberOfAntennaPorts].
type NumberOfAntennaPortsAPERValue = q14.NumberOfAntennaPortsAPERValue

// NumberOfAntennaPortsCodec binds the complete source value type.
var NumberOfAntennaPortsCodec func() NumberOfAntennaPortsValueCodec = q9.NumberOfAntennaPortsCodec

const NumberOfAntennaPortsN1OrN2 = q14.NumberOfAntennaPortsN1OrN2
const NumberOfAntennaPortsN4 = q14.NumberOfAntennaPortsN4

// NumberOfAntennaPortsValueCodec is the concrete ValueCodec[NumberOfAntennaPorts].
type NumberOfAntennaPortsValueCodec = q14.NumberOfAntennaPortsValueCodec

// NumberOfDlFrames represents the ASN.1 ENUMERATED type NumberOfDlFrames.
type NumberOfDlFrames = q14.NumberOfDlFrames

// NumberOfDlFramesAPERValue is the concrete APERValue[NumberOfDlFrames].
type NumberOfDlFramesAPERValue = q14.NumberOfDlFramesAPERValue

// NumberOfDlFramesCodec binds the complete source value type.
var NumberOfDlFramesCodec func() NumberOfDlFramesValueCodec = q9.NumberOfDlFramesCodec

// NumberOfDlFramesExtended represents the ASN.1 type NumberOfDlFrames-Extended (INTEGER).
type NumberOfDlFramesExtended = q14.NumberOfDlFramesExtended

// NumberOfDlFramesExtendedAPERValue is the concrete APERValue[NumberOfDlFramesExtended].
type NumberOfDlFramesExtendedAPERValue = q14.NumberOfDlFramesExtendedAPERValue

// NumberOfDlFramesExtendedCodec binds the complete source value type.
var NumberOfDlFramesExtendedCodec func() NumberOfDlFramesExtendedValueCodec = q9.NumberOfDlFramesExtendedCodec

// NumberOfDlFramesExtendedValueCodec is the concrete ValueCodec[NumberOfDlFramesExtended].
type NumberOfDlFramesExtendedValueCodec = q14.NumberOfDlFramesExtendedValueCodec

const NumberOfDlFramesSf1 = q14.NumberOfDlFramesSf1
const NumberOfDlFramesSf2 = q14.NumberOfDlFramesSf2
const NumberOfDlFramesSf4 = q14.NumberOfDlFramesSf4
const NumberOfDlFramesSf6 = q14.NumberOfDlFramesSf6

// NumberOfDlFramesValueCodec is the concrete ValueCodec[NumberOfDlFrames].
type NumberOfDlFramesValueCodec = q14.NumberOfDlFramesValueCodec

// NumberOfFrequencyHoppingBands represents the ASN.1 ENUMERATED type NumberOfFrequencyHoppingBands.
type NumberOfFrequencyHoppingBands = q14.NumberOfFrequencyHoppingBands

// NumberOfFrequencyHoppingBandsAPERValue is the concrete APERValue[NumberOfFrequencyHoppingBands].
type NumberOfFrequencyHoppingBandsAPERValue = q31.NumberOfFrequencyHoppingBandsAPERValue

// NumberOfFrequencyHoppingBandsCodec binds the complete source value type.
var NumberOfFrequencyHoppingBandsCodec func() NumberOfFrequencyHoppingBandsValueCodec = q9.NumberOfFrequencyHoppingBandsCodec

const NumberOfFrequencyHoppingBandsFourbands = q14.NumberOfFrequencyHoppingBandsFourbands
const NumberOfFrequencyHoppingBandsTwobands = q14.NumberOfFrequencyHoppingBandsTwobands

// NumberOfFrequencyHoppingBandsValueCodec is the concrete ValueCodec[NumberOfFrequencyHoppingBands].
type NumberOfFrequencyHoppingBandsValueCodec = q31.NumberOfFrequencyHoppingBandsValueCodec
type OTDOACellInformation = q5.OTDOACellInformation

// OTDOACellInformationAPERValue is the concrete APERValue[OTDOACellInformation].
type OTDOACellInformationAPERValue = q5.OTDOACellInformationAPERValue

// OTDOACellInformationCodec binds the complete source value type.
var OTDOACellInformationCodec func() OTDOACellInformationValueCodec = q7.OTDOACellInformationCodec

// OTDOACellInformationComplete carries a complete OTDOACellInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOACellInformationComplete = q7.OTDOACellInformationComplete

// OTDOACellInformationItem represents the ASN.1 CHOICE type OTDOACell-Information-Item.
type OTDOACellInformationItem = q5.OTDOACellInformationItem

// OTDOACellInformationItemAPERValue is the concrete APERValue[OTDOACellInformationItem].
type OTDOACellInformationItemAPERValue = q5.OTDOACellInformationItemAPERValue

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceCPLength = q14.OTDOACellInformationItemChoiceCPLength

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceCellId = q14.OTDOACellInformationItemChoiceCellId

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceCrsCPlength = q14.OTDOACellInformationItemChoiceCrsCPlength

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceDLBandwidth = q14.OTDOACellInformationItemChoiceDLBandwidth

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceEARFCN = q14.OTDOACellInformationItemChoiceEARFCN

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceEUTRANAccessPointPosition = q14.OTDOACellInformationItemChoiceEUTRANAccessPointPosition

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceMBSFNsubframeConfiguration = q14.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNPRSConfiguration = q14.OTDOACellInformationItemChoiceNPRSConfiguration

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNPRSID = q14.OTDOACellInformationItemChoiceNPRSID

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNPRSSequenceInfo = q14.OTDOACellInformationItemChoiceNPRSSequenceInfo

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNPRSType2 = q14.OTDOACellInformationItemChoiceNPRSType2

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNumberOfAntennaPorts = q14.OTDOACellInformationItemChoiceNumberOfAntennaPorts

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNumberOfDlFrames = q14.OTDOACellInformationItemChoiceNumberOfDlFrames

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNumberOfDlFramesExtended = q14.OTDOACellInformationItemChoiceNumberOfDlFramesExtended

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN = q14.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceOperationModeInfo = q14.OTDOACellInformationItemChoiceOperationModeInfo

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePCI = q14.OTDOACellInformationItemChoicePCI

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePRSBandwidth = q14.OTDOACellInformationItemChoicePRSBandwidth

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePRSConfigurationIndex = q14.OTDOACellInformationItemChoicePRSConfigurationIndex

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePRSFreqHoppingConfig = q14.OTDOACellInformationItemChoicePRSFreqHoppingConfig

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePRSMutingConfiguration = q14.OTDOACellInformationItemChoicePRSMutingConfiguration

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePRSOccasionGroup = q14.OTDOACellInformationItemChoicePRSOccasionGroup

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePrsid = q14.OTDOACellInformationItemChoicePrsid

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB = q14.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceSFNInitialisationTime = q14.OTDOACellInformationItemChoiceSFNInitialisationTime

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceTAC = q14.OTDOACellInformationItemChoiceTAC

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceTddConfiguration = q14.OTDOACellInformationItemChoiceTddConfiguration

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceTpType = q14.OTDOACellInformationItemChoiceTpType

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceTpid = q14.OTDOACellInformationItemChoiceTpid

// OTDOACellInformationItemCodec binds the complete source value type.
var OTDOACellInformationItemCodec func() OTDOACellInformationItemValueCodec = q5.OTDOACellInformationItemCodec

// OTDOACellInformationItemValueCodec is the concrete ValueCodec[OTDOACellInformationItem].
type OTDOACellInformationItemValueCodec = q5.OTDOACellInformationItemValueCodec

// OTDOACellInformationValueCodec is the concrete ValueCodec[OTDOACellInformation].
type OTDOACellInformationValueCodec = q5.OTDOACellInformationValueCodec
type OTDOACells = q20.OTDOACells

// OTDOACellsAPERValue is the concrete APERValue[OTDOACells].
type OTDOACellsAPERValue = q20.OTDOACellsAPERValue

// OTDOACellsCodec binds the complete APER value type.
var OTDOACellsCodec func() OTDOACellsValueCodec = q7.OTDOACellsCodec

// OTDOACellsComplete carries a complete OTDOACells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOACellsComplete = q7.OTDOACellsComplete

// OTDOACellsElem represents the ASN.1 type OTDOACells-Elem (SEQUENCE).
type OTDOACellsElem = q20.OTDOACellsElem

// OTDOACellsElemAPERValue is the concrete APERValue[OTDOACellsElem].
type OTDOACellsElemAPERValue = q20.OTDOACellsElemAPERValue

// OTDOACellsElemCodec binds the complete source value type.
var OTDOACellsElemCodec func() OTDOACellsElemValueCodec = q20.OTDOACellsElemCodec

// OTDOACellsElemValueCodec is the concrete ValueCodec[OTDOACellsElem].
type OTDOACellsElemValueCodec = q20.OTDOACellsElemValueCodec
type OTDOACellsExtIETable = q25.OTDOACellsExtIETable

var OTDOACellsExtIEs func() OTDOACellsExtIETable = q25.OTDOACellsExtIEs

// OTDOACellsExtIEsExtContainer is the concrete ProtocolExtensionContainer[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsExtContainer = q25.OTDOACellsExtIEsExtContainer

// OTDOACellsExtIEsExtField is the concrete ProtocolExtensionField[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsExtField = q25.OTDOACellsExtIEsExtField

// OTDOACellsExtIEsIEContainer is the concrete ProtocolIEContainer[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsIEContainer = q25.OTDOACellsExtIEsIEContainer

// OTDOACellsExtIEsIEField is the concrete ProtocolIEField[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsIEField = q25.OTDOACellsExtIEsIEField
type OTDOACellsExtIEsValue = q9.OTDOACellsExtIEsValue

// OTDOACellsValueCodec is the concrete ValueCodec[OTDOACells].
type OTDOACellsValueCodec = q20.OTDOACellsValueCodec
type OTDOAInformationExchangeDescriptor = q11.OTDOAInformationExchangeDescriptor

var OTDOAInformationExchangeProcedure func() OTDOAInformationExchangeDescriptor = q11.OTDOAInformationExchangeProcedure

// OTDOAInformationFailure represents the ASN.1 type OTDOAInformationFailure (SEQUENCE).
type OTDOAInformationFailure = q29.OTDOAInformationFailure

// OTDOAInformationFailureAPERValue is the concrete APERValue[OTDOAInformationFailure].
type OTDOAInformationFailureAPERValue = q29.OTDOAInformationFailureAPERValue

// OTDOAInformationFailureCauseIEBinding is the concrete IEBinding[Cause, OTDOAInformationFailureIEValue].
type OTDOAInformationFailureCauseIEBinding = q19.OTDOAInformationFailureCauseIEBinding

// OTDOAInformationFailureCodec binds the complete APER value type.
var OTDOAInformationFailureCodec func() OTDOAInformationFailureValueCodec = q11.OTDOAInformationFailureCodec

// OTDOAInformationFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, OTDOAInformationFailureIEValue].
type OTDOAInformationFailureCriticalityDiagnosticsIEBinding = q19.OTDOAInformationFailureCriticalityDiagnosticsIEBinding

// OTDOAInformationFailureIEContainer is the concrete ProtocolIEContainer[OTDOAInformationFailureIEValue].
type OTDOAInformationFailureIEContainer = q19.OTDOAInformationFailureIEContainer

// OTDOAInformationFailureIEField is the concrete ProtocolIEField[OTDOAInformationFailureIEValue].
type OTDOAInformationFailureIEField = q19.OTDOAInformationFailureIEField
type OTDOAInformationFailureIETable = q19.OTDOAInformationFailureIETable
type OTDOAInformationFailureIEValue = q19.OTDOAInformationFailureIEValue

var OTDOAInformationFailureIEs func() OTDOAInformationFailureIETable = q19.OTDOAInformationFailureIEs

// OTDOAInformationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[OTDOAInformationFailure].
type OTDOAInformationFailureUnsuccessfulBinding = q20.OTDOAInformationFailureUnsuccessfulBinding

// OTDOAInformationFailureValueCodec is the concrete ValueCodec[OTDOAInformationFailure].
type OTDOAInformationFailureValueCodec = q29.OTDOAInformationFailureValueCodec

// OTDOAInformationItem represents the ASN.1 ENUMERATED type OTDOA-Information-Item.
type OTDOAInformationItem = q14.OTDOAInformationItem

// OTDOAInformationItemAPERValue is the concrete APERValue[OTDOAInformationItem].
type OTDOAInformationItemAPERValue = q31.OTDOAInformationItemAPERValue

const OTDOAInformationItemCellid = q14.OTDOAInformationItemCellid

// OTDOAInformationItemCodec binds the complete source value type.
var OTDOAInformationItemCodec func() OTDOAInformationItemValueCodec = q9.OTDOAInformationItemCodec

const OTDOAInformationItemCpLength = q14.OTDOAInformationItemCpLength
const OTDOAInformationItemCrsCPlength = q14.OTDOAInformationItemCrsCPlength
const OTDOAInformationItemDlBandwidth = q14.OTDOAInformationItemDlBandwidth
const OTDOAInformationItemEUTRANAccessPointPosition = q14.OTDOAInformationItemEUTRANAccessPointPosition
const OTDOAInformationItemEarfcn = q14.OTDOAInformationItemEarfcn
const OTDOAInformationItemMBSFNsubframeConfiguration = q14.OTDOAInformationItemMBSFNsubframeConfiguration
const OTDOAInformationItemMultipleprsConfigurationsperCell = q14.OTDOAInformationItemMultipleprsConfigurationsperCell
const OTDOAInformationItemNPRSConfiguration = q14.OTDOAInformationItemNPRSConfiguration
const OTDOAInformationItemNPRSID = q14.OTDOAInformationItemNPRSID
const OTDOAInformationItemNPRSSequenceInfo = q14.OTDOAInformationItemNPRSSequenceInfo
const OTDOAInformationItemNPRSType2 = q14.OTDOAInformationItemNPRSType2
const OTDOAInformationItemNoAntennaPorts = q14.OTDOAInformationItemNoAntennaPorts
const OTDOAInformationItemNoDlFrames = q14.OTDOAInformationItemNoDlFrames
const OTDOAInformationItemOffsetNBChannelNumbertoEARFCN = q14.OTDOAInformationItemOffsetNBChannelNumbertoEARFCN
const OTDOAInformationItemOperationModeInfo = q14.OTDOAInformationItemOperationModeInfo
const OTDOAInformationItemPci = q14.OTDOAInformationItemPci
const OTDOAInformationItemPrsBandwidth = q14.OTDOAInformationItemPrsBandwidth
const OTDOAInformationItemPrsConfigIndex = q14.OTDOAInformationItemPrsConfigIndex
const OTDOAInformationItemPrsFrequencyHoppingConfiguration = q14.OTDOAInformationItemPrsFrequencyHoppingConfiguration
const OTDOAInformationItemPrsOccasionGroup = q14.OTDOAInformationItemPrsOccasionGroup
const OTDOAInformationItemPrsid = q14.OTDOAInformationItemPrsid
const OTDOAInformationItemPrsmutingconfiguration = q14.OTDOAInformationItemPrsmutingconfiguration
const OTDOAInformationItemRepetitionNumberofSIB1NB = q14.OTDOAInformationItemRepetitionNumberofSIB1NB
const OTDOAInformationItemSFNInitTime = q14.OTDOAInformationItemSFNInitTime
const OTDOAInformationItemTac = q14.OTDOAInformationItemTac
const OTDOAInformationItemTddConfig = q14.OTDOAInformationItemTddConfig
const OTDOAInformationItemTpType = q14.OTDOAInformationItemTpType
const OTDOAInformationItemTpid = q14.OTDOAInformationItemTpid

// OTDOAInformationItemValueCodec is the concrete ValueCodec[OTDOAInformationItem].
type OTDOAInformationItemValueCodec = q31.OTDOAInformationItemValueCodec

// OTDOAInformationRequest represents the ASN.1 type OTDOAInformationRequest (SEQUENCE).
type OTDOAInformationRequest = q7.OTDOAInformationRequest

// OTDOAInformationRequestAPERValue is the concrete APERValue[OTDOAInformationRequest].
type OTDOAInformationRequestAPERValue = q7.OTDOAInformationRequestAPERValue

// OTDOAInformationRequestCodec binds the complete APER value type.
var OTDOAInformationRequestCodec func() OTDOAInformationRequestValueCodec = q11.OTDOAInformationRequestCodec

// OTDOAInformationRequestIEContainer is the concrete ProtocolIEContainer[OTDOAInformationRequestIEValue].
type OTDOAInformationRequestIEContainer = q7.OTDOAInformationRequestIEContainer

// OTDOAInformationRequestIEField is the concrete ProtocolIEField[OTDOAInformationRequestIEValue].
type OTDOAInformationRequestIEField = q7.OTDOAInformationRequestIEField
type OTDOAInformationRequestIETable = q7.OTDOAInformationRequestIETable
type OTDOAInformationRequestIEValue = q7.OTDOAInformationRequestIEValue

var OTDOAInformationRequestIEs func() OTDOAInformationRequestIETable = q7.OTDOAInformationRequestIEs

// OTDOAInformationRequestInitiatingBinding is the concrete InitiatingBinding[OTDOAInformationRequest].
type OTDOAInformationRequestInitiatingBinding = q12.OTDOAInformationRequestInitiatingBinding

// OTDOAInformationRequestOTDOAInformationTypeIEBinding is the concrete IEBinding[OTDOAInformationType, OTDOAInformationRequestIEValue].
type OTDOAInformationRequestOTDOAInformationTypeIEBinding = q7.OTDOAInformationRequestOTDOAInformationTypeIEBinding

// OTDOAInformationRequestValueCodec is the concrete ValueCodec[OTDOAInformationRequest].
type OTDOAInformationRequestValueCodec = q7.OTDOAInformationRequestValueCodec

// OTDOAInformationResponse represents the ASN.1 type OTDOAInformationResponse (SEQUENCE).
type OTDOAInformationResponse = q7.OTDOAInformationResponse

// OTDOAInformationResponseAPERValue is the concrete APERValue[OTDOAInformationResponse].
type OTDOAInformationResponseAPERValue = q7.OTDOAInformationResponseAPERValue

// OTDOAInformationResponseAddOTDOACellsIEBinding is the concrete IEBinding[AddOTDOACells, OTDOAInformationResponseIEValue].
type OTDOAInformationResponseAddOTDOACellsIEBinding = q7.OTDOAInformationResponseAddOTDOACellsIEBinding

// OTDOAInformationResponseCodec binds the complete APER value type.
var OTDOAInformationResponseCodec func() OTDOAInformationResponseValueCodec = q11.OTDOAInformationResponseCodec

// OTDOAInformationResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, OTDOAInformationResponseIEValue].
type OTDOAInformationResponseCriticalityDiagnosticsIEBinding = q7.OTDOAInformationResponseCriticalityDiagnosticsIEBinding

// OTDOAInformationResponseIEContainer is the concrete ProtocolIEContainer[OTDOAInformationResponseIEValue].
type OTDOAInformationResponseIEContainer = q7.OTDOAInformationResponseIEContainer

// OTDOAInformationResponseIEField is the concrete ProtocolIEField[OTDOAInformationResponseIEValue].
type OTDOAInformationResponseIEField = q7.OTDOAInformationResponseIEField
type OTDOAInformationResponseIETable = q7.OTDOAInformationResponseIETable
type OTDOAInformationResponseIEValue = q7.OTDOAInformationResponseIEValue

var OTDOAInformationResponseIEs func() OTDOAInformationResponseIETable = q7.OTDOAInformationResponseIEs

// OTDOAInformationResponseOTDOACellsIEBinding is the concrete IEBinding[OTDOACells, OTDOAInformationResponseIEValue].
type OTDOAInformationResponseOTDOACellsIEBinding = q7.OTDOAInformationResponseOTDOACellsIEBinding

// OTDOAInformationResponseSuccessfulBinding is the concrete SuccessfulBinding[OTDOAInformationResponse].
type OTDOAInformationResponseSuccessfulBinding = q4.OTDOAInformationResponseSuccessfulBinding

// OTDOAInformationResponseValueCodec is the concrete ValueCodec[OTDOAInformationResponse].
type OTDOAInformationResponseValueCodec = q7.OTDOAInformationResponseValueCodec
type OTDOAInformationType = q26.OTDOAInformationType

// OTDOAInformationTypeAPERValue is the concrete APERValue[OTDOAInformationType].
type OTDOAInformationTypeAPERValue = q26.OTDOAInformationTypeAPERValue

// OTDOAInformationTypeCodec binds the complete APER value type.
var OTDOAInformationTypeCodec func() OTDOAInformationTypeValueCodec = q7.OTDOAInformationTypeCodec

// OTDOAInformationTypeComplete carries a complete OTDOAInformationType encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOAInformationTypeComplete = q7.OTDOAInformationTypeComplete

// OTDOAInformationTypeIEContainer is the concrete ProtocolIEContainer[OTDOAInformationTypeIEValue].
type OTDOAInformationTypeIEContainer = q26.OTDOAInformationTypeIEContainer

// OTDOAInformationTypeIEField is the concrete ProtocolIEField[OTDOAInformationTypeIEValue].
type OTDOAInformationTypeIEField = q26.OTDOAInformationTypeIEField
type OTDOAInformationTypeIETable = q26.OTDOAInformationTypeIETable
type OTDOAInformationTypeIEValue = q26.OTDOAInformationTypeIEValue

// OTDOAInformationTypeIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[OTDOAInformationTypeIEValue].
type OTDOAInformationTypeIEValueProtocolIESingleContainer = q26.OTDOAInformationTypeIEValueProtocolIESingleContainer

var OTDOAInformationTypeIEs func() OTDOAInformationTypeIETable = q26.OTDOAInformationTypeIEs

// OTDOAInformationTypeItem represents the ASN.1 type OTDOA-Information-Type-Item (SEQUENCE).
type OTDOAInformationTypeItem = q26.OTDOAInformationTypeItem

// OTDOAInformationTypeItemAPERValue is the concrete APERValue[OTDOAInformationTypeItem].
type OTDOAInformationTypeItemAPERValue = q26.OTDOAInformationTypeItemAPERValue

// OTDOAInformationTypeItemCodec binds the complete APER value type.
var OTDOAInformationTypeItemCodec func() OTDOAInformationTypeItemValueCodec = q26.OTDOAInformationTypeItemCodec

type OTDOAInformationTypeItemExtIETable = q25.OTDOAInformationTypeItemExtIETable

var OTDOAInformationTypeItemExtIEs func() OTDOAInformationTypeItemExtIETable = q25.OTDOAInformationTypeItemExtIEs

// OTDOAInformationTypeItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsExtContainer = q25.OTDOAInformationTypeItemExtIEsExtContainer

// OTDOAInformationTypeItemExtIEsExtField is the concrete ProtocolExtensionField[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsExtField = q25.OTDOAInformationTypeItemExtIEsExtField

// OTDOAInformationTypeItemExtIEsIEContainer is the concrete ProtocolIEContainer[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsIEContainer = q25.OTDOAInformationTypeItemExtIEsIEContainer

// OTDOAInformationTypeItemExtIEsIEField is the concrete ProtocolIEField[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsIEField = q25.OTDOAInformationTypeItemExtIEsIEField
type OTDOAInformationTypeItemExtIEsValue = q9.OTDOAInformationTypeItemExtIEsValue

// OTDOAInformationTypeItemValueCodec is the concrete ValueCodec[OTDOAInformationTypeItem].
type OTDOAInformationTypeItemValueCodec = q26.OTDOAInformationTypeItemValueCodec

// OTDOAInformationTypeOTDOAInformationTypeItemIEBinding is the concrete IEBinding[OTDOAInformationTypeItem, OTDOAInformationTypeIEValue].
type OTDOAInformationTypeOTDOAInformationTypeItemIEBinding = q26.OTDOAInformationTypeOTDOAInformationTypeItemIEBinding

// OTDOAInformationTypeValueCodec is the concrete ValueCodec[OTDOAInformationType].
type OTDOAInformationTypeValueCodec = q26.OTDOAInformationTypeValueCodec

// OffsetNBChanneltoEARFCN represents the ASN.1 ENUMERATED type OffsetNBChanneltoEARFCN.
type OffsetNBChanneltoEARFCN = q14.OffsetNBChanneltoEARFCN

// OffsetNBChanneltoEARFCNAPERValue is the concrete APERValue[OffsetNBChanneltoEARFCN].
type OffsetNBChanneltoEARFCNAPERValue = q31.OffsetNBChanneltoEARFCNAPERValue

// OffsetNBChanneltoEARFCNCodec binds the complete source value type.
var OffsetNBChanneltoEARFCNCodec func() OffsetNBChanneltoEARFCNValueCodec = q9.OffsetNBChanneltoEARFCNCodec

const OffsetNBChanneltoEARFCNEight = q14.OffsetNBChanneltoEARFCNEight
const OffsetNBChanneltoEARFCNFive = q14.OffsetNBChanneltoEARFCNFive
const OffsetNBChanneltoEARFCNFour = q14.OffsetNBChanneltoEARFCNFour
const OffsetNBChanneltoEARFCNMinusEight = q14.OffsetNBChanneltoEARFCNMinusEight
const OffsetNBChanneltoEARFCNMinusFive = q14.OffsetNBChanneltoEARFCNMinusFive
const OffsetNBChanneltoEARFCNMinusFour = q14.OffsetNBChanneltoEARFCNMinusFour
const OffsetNBChanneltoEARFCNMinusNine = q14.OffsetNBChanneltoEARFCNMinusNine
const OffsetNBChanneltoEARFCNMinusOne = q14.OffsetNBChanneltoEARFCNMinusOne
const OffsetNBChanneltoEARFCNMinusSeven = q14.OffsetNBChanneltoEARFCNMinusSeven
const OffsetNBChanneltoEARFCNMinusSix = q14.OffsetNBChanneltoEARFCNMinusSix
const OffsetNBChanneltoEARFCNMinusTen = q14.OffsetNBChanneltoEARFCNMinusTen
const OffsetNBChanneltoEARFCNMinusThree = q14.OffsetNBChanneltoEARFCNMinusThree
const OffsetNBChanneltoEARFCNMinusTwo = q14.OffsetNBChanneltoEARFCNMinusTwo
const OffsetNBChanneltoEARFCNMinusZeroDotFive = q14.OffsetNBChanneltoEARFCNMinusZeroDotFive
const OffsetNBChanneltoEARFCNNine = q14.OffsetNBChanneltoEARFCNNine
const OffsetNBChanneltoEARFCNOne = q14.OffsetNBChanneltoEARFCNOne
const OffsetNBChanneltoEARFCNSeven = q14.OffsetNBChanneltoEARFCNSeven
const OffsetNBChanneltoEARFCNSix = q14.OffsetNBChanneltoEARFCNSix
const OffsetNBChanneltoEARFCNThree = q14.OffsetNBChanneltoEARFCNThree
const OffsetNBChanneltoEARFCNTwo = q14.OffsetNBChanneltoEARFCNTwo

// OffsetNBChanneltoEARFCNValueCodec is the concrete ValueCodec[OffsetNBChanneltoEARFCN].
type OffsetNBChanneltoEARFCNValueCodec = q31.OffsetNBChanneltoEARFCNValueCodec

const OffsetNBChanneltoEARFCNZero = q14.OffsetNBChanneltoEARFCNZero

// OperationModeInfo represents the ASN.1 ENUMERATED type OperationModeInfo.
type OperationModeInfo = q14.OperationModeInfo

// OperationModeInfoAPERValue is the concrete APERValue[OperationModeInfo].
type OperationModeInfoAPERValue = q31.OperationModeInfoAPERValue

// OperationModeInfoCodec binds the complete source value type.
var OperationModeInfoCodec func() OperationModeInfoValueCodec = q9.OperationModeInfoCodec

const OperationModeInfoGuardband = q14.OperationModeInfoGuardband
const OperationModeInfoInband = q14.OperationModeInfoInband
const OperationModeInfoStandalone = q14.OperationModeInfoStandalone

// OperationModeInfoValueCodec is the concrete ValueCodec[OperationModeInfo].
type OperationModeInfoValueCodec = q31.OperationModeInfoValueCodec

// Outcome represents the ASN.1 ENUMERATED type Outcome.
type Outcome = q14.Outcome

// OutcomeAPERValue is the concrete APERValue[Outcome].
type OutcomeAPERValue = q31.OutcomeAPERValue

// OutcomeCodec binds the complete source value type.
var OutcomeCodec func() OutcomeValueCodec = q9.OutcomeCodec

const OutcomeFailed = q14.OutcomeFailed

// OutcomeValueCodec is the concrete ValueCodec[Outcome].
type OutcomeValueCodec = q31.OutcomeValueCodec

// PCI represents the ASN.1 type PCI (INTEGER).
type PCI = q14.PCI

// PCIAPERValue is the concrete APERValue[PCI].
type PCIAPERValue = q31.PCIAPERValue

// PCICodec binds the complete source value type.
var PCICodec func() PCIValueCodec = q9.PCICodec

// PCIValueCodec is the concrete ValueCodec[PCI].
type PCIValueCodec = q31.PCIValueCodec

// PLMNIdentity represents the ASN.1 type PLMN-Identity (OCTET_STRING).
type PLMNIdentity = q14.PLMNIdentity

// PLMNIdentityAPERValue is the concrete APERValue[PLMNIdentity].
type PLMNIdentityAPERValue = q31.PLMNIdentityAPERValue

// PLMNIdentityCodec binds the complete source value type.
var PLMNIdentityCodec func() PLMNIdentityValueCodec = q9.PLMNIdentityCodec

// PLMNIdentityValueCodec is the concrete ValueCodec[PLMNIdentity].
type PLMNIdentityValueCodec = q31.PLMNIdentityValueCodec

// PRSBandwidth represents the ASN.1 ENUMERATED type PRS-Bandwidth.
type PRSBandwidth = q14.PRSBandwidth

// PRSBandwidthAPERValue is the concrete APERValue[PRSBandwidth].
type PRSBandwidthAPERValue = q31.PRSBandwidthAPERValue

const PRSBandwidthBw100 = q14.PRSBandwidthBw100
const PRSBandwidthBw15 = q14.PRSBandwidthBw15
const PRSBandwidthBw25 = q14.PRSBandwidthBw25
const PRSBandwidthBw50 = q14.PRSBandwidthBw50
const PRSBandwidthBw6 = q14.PRSBandwidthBw6
const PRSBandwidthBw75 = q14.PRSBandwidthBw75

// PRSBandwidthCodec binds the complete source value type.
var PRSBandwidthCodec func() PRSBandwidthValueCodec = q9.PRSBandwidthCodec

// PRSBandwidthValueCodec is the concrete ValueCodec[PRSBandwidth].
type PRSBandwidthValueCodec = q31.PRSBandwidthValueCodec

// PRSConfigurationIndex represents the ASN.1 type PRS-Configuration-Index (INTEGER).
type PRSConfigurationIndex = q14.PRSConfigurationIndex

// PRSConfigurationIndexAPERValue is the concrete APERValue[PRSConfigurationIndex].
type PRSConfigurationIndexAPERValue = q31.PRSConfigurationIndexAPERValue

// PRSConfigurationIndexCodec binds the complete source value type.
var PRSConfigurationIndexCodec func() PRSConfigurationIndexValueCodec = q9.PRSConfigurationIndexCodec

// PRSConfigurationIndexValueCodec is the concrete ValueCodec[PRSConfigurationIndex].
type PRSConfigurationIndexValueCodec = q31.PRSConfigurationIndexValueCodec

// PRSFrequencyHoppingConfiguration represents the ASN.1 type PRSFrequencyHoppingConfiguration (SEQUENCE).
type PRSFrequencyHoppingConfiguration = q30.PRSFrequencyHoppingConfiguration

// PRSFrequencyHoppingConfigurationAPERValue is the concrete APERValue[PRSFrequencyHoppingConfiguration].
type PRSFrequencyHoppingConfigurationAPERValue = q30.PRSFrequencyHoppingConfigurationAPERValue
type PRSFrequencyHoppingConfigurationBandPositions = q14.PRSFrequencyHoppingConfigurationBandPositions

// PRSFrequencyHoppingConfigurationBandPositionsAPERValue is the concrete APERValue[PRSFrequencyHoppingConfigurationBandPositions].
type PRSFrequencyHoppingConfigurationBandPositionsAPERValue = q31.PRSFrequencyHoppingConfigurationBandPositionsAPERValue

// PRSFrequencyHoppingConfigurationBandPositionsCodec binds the complete source value type.
var PRSFrequencyHoppingConfigurationBandPositionsCodec func() PRSFrequencyHoppingConfigurationBandPositionsValueCodec = q24.PRSFrequencyHoppingConfigurationBandPositionsCodec

// PRSFrequencyHoppingConfigurationBandPositionsComplete carries a complete PRSFrequencyHoppingConfigurationBandPositions encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PRSFrequencyHoppingConfigurationBandPositionsComplete = q24.PRSFrequencyHoppingConfigurationBandPositionsComplete

// PRSFrequencyHoppingConfigurationBandPositionsValueCodec is the concrete ValueCodec[PRSFrequencyHoppingConfigurationBandPositions].
type PRSFrequencyHoppingConfigurationBandPositionsValueCodec = q31.PRSFrequencyHoppingConfigurationBandPositionsValueCodec

// PRSFrequencyHoppingConfigurationCodec binds the complete source value type.
var PRSFrequencyHoppingConfigurationCodec func() PRSFrequencyHoppingConfigurationValueCodec = q30.PRSFrequencyHoppingConfigurationCodec

type PRSFrequencyHoppingConfigurationItemIETable = q25.PRSFrequencyHoppingConfigurationItemIETable

var PRSFrequencyHoppingConfigurationItemIEs func() PRSFrequencyHoppingConfigurationItemIETable = q25.PRSFrequencyHoppingConfigurationItemIEs

// PRSFrequencyHoppingConfigurationItemIEsExtContainer is the concrete ProtocolExtensionContainer[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsExtContainer = q25.PRSFrequencyHoppingConfigurationItemIEsExtContainer

// PRSFrequencyHoppingConfigurationItemIEsExtField is the concrete ProtocolExtensionField[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsExtField = q25.PRSFrequencyHoppingConfigurationItemIEsExtField

// PRSFrequencyHoppingConfigurationItemIEsIEContainer is the concrete ProtocolIEContainer[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsIEContainer = q25.PRSFrequencyHoppingConfigurationItemIEsIEContainer

// PRSFrequencyHoppingConfigurationItemIEsIEField is the concrete ProtocolIEField[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsIEField = q25.PRSFrequencyHoppingConfigurationItemIEsIEField
type PRSFrequencyHoppingConfigurationItemIEsValue = q9.PRSFrequencyHoppingConfigurationItemIEsValue

// PRSFrequencyHoppingConfigurationValueCodec is the concrete ValueCodec[PRSFrequencyHoppingConfiguration].
type PRSFrequencyHoppingConfigurationValueCodec = q30.PRSFrequencyHoppingConfigurationValueCodec

// PRSID represents the ASN.1 type PRS-ID (INTEGER).
type PRSID = q14.PRSID

// PRSIDAPERValue is the concrete APERValue[PRSID].
type PRSIDAPERValue = q31.PRSIDAPERValue

// PRSIDCodec binds the complete source value type.
var PRSIDCodec func() PRSIDValueCodec = q9.PRSIDCodec

// PRSIDValueCodec is the concrete ValueCodec[PRSID].
type PRSIDValueCodec = q31.PRSIDValueCodec

// PRSMutingConfiguration represents the ASN.1 CHOICE type PRSMutingConfiguration.
type PRSMutingConfiguration = q30.PRSMutingConfiguration

// PRSMutingConfigurationAPERValue is the concrete APERValue[PRSMutingConfiguration].
type PRSMutingConfigurationAPERValue = q30.PRSMutingConfigurationAPERValue

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceEight = q14.PRSMutingConfigurationChoiceEight

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceFiveHundredAndTwelve = q14.PRSMutingConfigurationChoiceFiveHundredAndTwelve

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceFour = q14.PRSMutingConfigurationChoiceFour

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceOneHundredAndTwentyEight = q14.PRSMutingConfigurationChoiceOneHundredAndTwentyEight

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceOneThousandAndTwentyFour = q14.PRSMutingConfigurationChoiceOneThousandAndTwentyFour

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceSixteen = q14.PRSMutingConfigurationChoiceSixteen

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceSixtyFour = q14.PRSMutingConfigurationChoiceSixtyFour

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceThirtyTwo = q14.PRSMutingConfigurationChoiceThirtyTwo

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceTwo = q14.PRSMutingConfigurationChoiceTwo

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceTwoHundredAndFiftySix = q14.PRSMutingConfigurationChoiceTwoHundredAndFiftySix

// PRSMutingConfigurationCodec binds the complete source value type.
var PRSMutingConfigurationCodec func() PRSMutingConfigurationValueCodec = q30.PRSMutingConfigurationCodec

// PRSMutingConfigurationValueCodec is the concrete ValueCodec[PRSMutingConfiguration].
type PRSMutingConfigurationValueCodec = q30.PRSMutingConfigurationValueCodec

// PRSOccasionGroup represents the ASN.1 ENUMERATED type PRSOccasionGroup.
type PRSOccasionGroup = q14.PRSOccasionGroup

// PRSOccasionGroupAPERValue is the concrete APERValue[PRSOccasionGroup].
type PRSOccasionGroupAPERValue = q31.PRSOccasionGroupAPERValue

// PRSOccasionGroupCodec binds the complete source value type.
var PRSOccasionGroupCodec func() PRSOccasionGroupValueCodec = q9.PRSOccasionGroupCodec

const PRSOccasionGroupOg128 = q14.PRSOccasionGroupOg128
const PRSOccasionGroupOg16 = q14.PRSOccasionGroupOg16
const PRSOccasionGroupOg2 = q14.PRSOccasionGroupOg2
const PRSOccasionGroupOg32 = q14.PRSOccasionGroupOg32
const PRSOccasionGroupOg4 = q14.PRSOccasionGroupOg4
const PRSOccasionGroupOg64 = q14.PRSOccasionGroupOg64
const PRSOccasionGroupOg8 = q14.PRSOccasionGroupOg8

// PRSOccasionGroupValueCodec is the concrete ValueCodec[PRSOccasionGroup].
type PRSOccasionGroupValueCodec = q31.PRSOccasionGroupValueCodec

// PayloadCodec owns a typed foreign decoder and encoder. The callbacks must
// enforce the foreign schema and consume a complete value.
type PayloadCodec[T any] = q4.PayloadCodec[T]
type PayloadDeviation = q14.PayloadDeviation

// PayloadLimits bound a single call across a foreign byte boundary.
// Zero fields select finite defaults; the foreign callback applies its own
// schema and work/depth accounting.
type PayloadLimits = q14.PayloadLimits
type PayloadReport = q14.PayloadReport

// PhysCellIDGERAN represents the ASN.1 type PhysCellIDGERAN (INTEGER).
type PhysCellIDGERAN = q14.PhysCellIDGERAN

// PhysCellIDGERANAPERValue is the concrete APERValue[PhysCellIDGERAN].
type PhysCellIDGERANAPERValue = q31.PhysCellIDGERANAPERValue

// PhysCellIDGERANCodec binds the complete source value type.
var PhysCellIDGERANCodec func() PhysCellIDGERANValueCodec = q9.PhysCellIDGERANCodec

// PhysCellIDGERANValueCodec is the concrete ValueCodec[PhysCellIDGERAN].
type PhysCellIDGERANValueCodec = q31.PhysCellIDGERANValueCodec

// PhysCellIDUTRAFDD represents the ASN.1 type PhysCellIDUTRA-FDD (INTEGER).
type PhysCellIDUTRAFDD = q14.PhysCellIDUTRAFDD

// PhysCellIDUTRAFDDAPERValue is the concrete APERValue[PhysCellIDUTRAFDD].
type PhysCellIDUTRAFDDAPERValue = q31.PhysCellIDUTRAFDDAPERValue

// PhysCellIDUTRAFDDCodec binds the complete source value type.
var PhysCellIDUTRAFDDCodec func() PhysCellIDUTRAFDDValueCodec = q9.PhysCellIDUTRAFDDCodec

// PhysCellIDUTRAFDDValueCodec is the concrete ValueCodec[PhysCellIDUTRAFDD].
type PhysCellIDUTRAFDDValueCodec = q31.PhysCellIDUTRAFDDValueCodec

// PhysCellIDUTRATDD represents the ASN.1 type PhysCellIDUTRA-TDD (INTEGER).
type PhysCellIDUTRATDD = q14.PhysCellIDUTRATDD

// PhysCellIDUTRATDDAPERValue is the concrete APERValue[PhysCellIDUTRATDD].
type PhysCellIDUTRATDDAPERValue = q31.PhysCellIDUTRATDDAPERValue

// PhysCellIDUTRATDDCodec binds the complete source value type.
var PhysCellIDUTRATDDCodec func() PhysCellIDUTRATDDValueCodec = q9.PhysCellIDUTRATDDCodec

// PhysCellIDUTRATDDValueCodec is the concrete ValueCodec[PhysCellIDUTRATDD].
type PhysCellIDUTRATDDValueCodec = q31.PhysCellIDUTRATDDValueCodec
type PosSIBSegments = q30.PosSIBSegments

// PosSIBSegmentsAPERValue is the concrete APERValue[PosSIBSegments].
type PosSIBSegmentsAPERValue = q30.PosSIBSegmentsAPERValue

// PosSIBSegmentsCodec binds the complete source value type.
var PosSIBSegmentsCodec func() PosSIBSegmentsValueCodec = q24.PosSIBSegmentsCodec

// PosSIBSegmentsComplete carries a complete PosSIBSegments encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PosSIBSegmentsComplete = q24.PosSIBSegmentsComplete

// PosSIBSegmentsElem represents the ASN.1 type PosSIB-Segments-Elem (SEQUENCE).
type PosSIBSegmentsElem = q30.PosSIBSegmentsElem

// PosSIBSegmentsElemAPERValue is the concrete APERValue[PosSIBSegmentsElem].
type PosSIBSegmentsElemAPERValue = q30.PosSIBSegmentsElemAPERValue

// PosSIBSegmentsElemCodec binds the complete source value type.
var PosSIBSegmentsElemCodec func() PosSIBSegmentsElemValueCodec = q30.PosSIBSegmentsElemCodec

// PosSIBSegmentsElemValueCodec is the concrete ValueCodec[PosSIBSegmentsElem].
type PosSIBSegmentsElemValueCodec = q30.PosSIBSegmentsElemValueCodec
type PosSIBSegmentsExtIETable = q25.PosSIBSegmentsExtIETable

var PosSIBSegmentsExtIEs func() PosSIBSegmentsExtIETable = q25.PosSIBSegmentsExtIEs

// PosSIBSegmentsExtIEsExtContainer is the concrete ProtocolExtensionContainer[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsExtContainer = q25.PosSIBSegmentsExtIEsExtContainer

// PosSIBSegmentsExtIEsExtField is the concrete ProtocolExtensionField[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsExtField = q25.PosSIBSegmentsExtIEsExtField

// PosSIBSegmentsExtIEsIEContainer is the concrete ProtocolIEContainer[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsIEContainer = q25.PosSIBSegmentsExtIEsIEContainer

// PosSIBSegmentsExtIEsIEField is the concrete ProtocolIEField[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsIEField = q25.PosSIBSegmentsExtIEsIEField
type PosSIBSegmentsExtIEsValue = q9.PosSIBSegmentsExtIEsValue

// PosSIBSegmentsValueCodec is the concrete ValueCodec[PosSIBSegments].
type PosSIBSegmentsValueCodec = q30.PosSIBSegmentsValueCodec

// PosSIBType represents the ASN.1 ENUMERATED type PosSIB-Type.
type PosSIBType = q14.PosSIBType

// PosSIBTypeAPERValue is the concrete APERValue[PosSIBType].
type PosSIBTypeAPERValue = q31.PosSIBTypeAPERValue

// PosSIBTypeCodec binds the complete source value type.
var PosSIBTypeCodec func() PosSIBTypeValueCodec = q9.PosSIBTypeCodec

const PosSIBTypePosSibType11 = q14.PosSIBTypePosSibType11
const PosSIBTypePosSibType12 = q14.PosSIBTypePosSibType12
const PosSIBTypePosSibType13 = q14.PosSIBTypePosSibType13
const PosSIBTypePosSibType14 = q14.PosSIBTypePosSibType14
const PosSIBTypePosSibType15 = q14.PosSIBTypePosSibType15
const PosSIBTypePosSibType16 = q14.PosSIBTypePosSibType16
const PosSIBTypePosSibType17 = q14.PosSIBTypePosSibType17
const PosSIBTypePosSibType21 = q14.PosSIBTypePosSibType21
const PosSIBTypePosSibType210 = q14.PosSIBTypePosSibType210
const PosSIBTypePosSibType211 = q14.PosSIBTypePosSibType211
const PosSIBTypePosSibType212 = q14.PosSIBTypePosSibType212
const PosSIBTypePosSibType213 = q14.PosSIBTypePosSibType213
const PosSIBTypePosSibType214 = q14.PosSIBTypePosSibType214
const PosSIBTypePosSibType215 = q14.PosSIBTypePosSibType215
const PosSIBTypePosSibType216 = q14.PosSIBTypePosSibType216
const PosSIBTypePosSibType217 = q14.PosSIBTypePosSibType217
const PosSIBTypePosSibType218 = q14.PosSIBTypePosSibType218
const PosSIBTypePosSibType219 = q14.PosSIBTypePosSibType219
const PosSIBTypePosSibType22 = q14.PosSIBTypePosSibType22
const PosSIBTypePosSibType224 = q14.PosSIBTypePosSibType224
const PosSIBTypePosSibType225 = q14.PosSIBTypePosSibType225
const PosSIBTypePosSibType23 = q14.PosSIBTypePosSibType23
const PosSIBTypePosSibType24 = q14.PosSIBTypePosSibType24
const PosSIBTypePosSibType25 = q14.PosSIBTypePosSibType25
const PosSIBTypePosSibType26 = q14.PosSIBTypePosSibType26
const PosSIBTypePosSibType27 = q14.PosSIBTypePosSibType27
const PosSIBTypePosSibType28 = q14.PosSIBTypePosSibType28
const PosSIBTypePosSibType29 = q14.PosSIBTypePosSibType29
const PosSIBTypePosSibType31 = q14.PosSIBTypePosSibType31
const PosSIBTypePosSibType41 = q14.PosSIBTypePosSibType41
const PosSIBTypePosSibType51 = q14.PosSIBTypePosSibType51

// PosSIBTypeValueCodec is the concrete ValueCodec[PosSIBType].
type PosSIBTypeValueCodec = q31.PosSIBTypeValueCodec
type PosSIBs = q19.PosSIBs

// PosSIBsAPERValue is the concrete APERValue[PosSIBs].
type PosSIBsAPERValue = q19.PosSIBsAPERValue

// PosSIBsCodec binds the complete source value type.
var PosSIBsCodec func() PosSIBsValueCodec = q24.PosSIBsCodec

// PosSIBsComplete carries a complete PosSIBs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PosSIBsComplete = q24.PosSIBsComplete

// PosSIBsElem represents the ASN.1 type PosSIBs-Elem (SEQUENCE).
type PosSIBsElem = q19.PosSIBsElem

// PosSIBsElemAPERValue is the concrete APERValue[PosSIBsElem].
type PosSIBsElemAPERValue = q19.PosSIBsElemAPERValue

// PosSIBsElemCodec binds the complete source value type.
var PosSIBsElemCodec func() PosSIBsElemValueCodec = q19.PosSIBsElemCodec

// PosSIBsElemValueCodec is the concrete ValueCodec[PosSIBsElem].
type PosSIBsElemValueCodec = q19.PosSIBsElemValueCodec
type PosSIBsExtIETable = q25.PosSIBsExtIETable

var PosSIBsExtIEs func() PosSIBsExtIETable = q25.PosSIBsExtIEs

// PosSIBsExtIEsExtContainer is the concrete ProtocolExtensionContainer[PosSIBsExtIEsValue].
type PosSIBsExtIEsExtContainer = q25.PosSIBsExtIEsExtContainer

// PosSIBsExtIEsExtField is the concrete ProtocolExtensionField[PosSIBsExtIEsValue].
type PosSIBsExtIEsExtField = q25.PosSIBsExtIEsExtField

// PosSIBsExtIEsIEContainer is the concrete ProtocolIEContainer[PosSIBsExtIEsValue].
type PosSIBsExtIEsIEContainer = q25.PosSIBsExtIEsIEContainer

// PosSIBsExtIEsIEField is the concrete ProtocolIEField[PosSIBsExtIEsValue].
type PosSIBsExtIEsIEField = q25.PosSIBsExtIEsIEField
type PosSIBsExtIEsValue = q8.PosSIBsExtIEsValue

// PosSIBsValueCodec is the concrete ValueCodec[PosSIBs].
type PosSIBsValueCodec = q19.PosSIBsValueCodec

// Presence represents the ASN.1 ENUMERATED type Presence.
type Presence = q14.Presence

// PresenceAPERValue is the concrete APERValue[Presence].
type PresenceAPERValue = q31.PresenceAPERValue

// PresenceCodec binds the complete source value type.
var PresenceCodec func() PresenceValueCodec = q9.PresenceCodec

const PresenceConditional = q14.PresenceConditional
const PresenceMandatory = q14.PresenceMandatory
const PresenceOptional = q14.PresenceOptional

// PresenceValueCodec is the concrete ValueCodec[Presence].
type PresenceValueCodec = q31.PresenceValueCodec
type PrivateIEContainer[V q4.ProtocolPrivateValueConstraint[V]] = q4.PrivateIEContainer[V]
type PrivateIEField[V q4.ProtocolPrivateValueConstraint[V]] = q4.PrivateIEField[V]

// PrivateIEID represents the ASN.1 CHOICE type PrivateIE-ID.
type PrivateIEID = q30.PrivateIEID

// PrivateIEIDAPERValue is the concrete APERValue[PrivateIEID].
type PrivateIEIDAPERValue = q30.PrivateIEIDAPERValue

// PrivateIEID choice constants.
const PrivateIEIDChoiceGlobal = q14.PrivateIEIDChoiceGlobal

// PrivateIEID choice constants.
const PrivateIEIDChoiceLocal = q14.PrivateIEIDChoiceLocal

// PrivateIEIDCodec binds the complete source value type.
var PrivateIEIDCodec func() PrivateIEIDValueCodec = q30.PrivateIEIDCodec

// PrivateIEIDValueCodec is the concrete ValueCodec[PrivateIEID].
type PrivateIEIDValueCodec = q30.PrivateIEIDValueCodec

// PrivateMessage represents the ASN.1 type PrivateMessage (SEQUENCE).
type PrivateMessage = q29.PrivateMessage

// PrivateMessageAPERValue is the concrete APERValue[PrivateMessage].
type PrivateMessageAPERValue = q29.PrivateMessageAPERValue

// PrivateMessageCodec binds the complete APER value type.
var PrivateMessageCodec func() PrivateMessageValueCodec = q12.PrivateMessageCodec

type PrivateMessageDescriptor = q12.PrivateMessageDescriptor
type PrivateMessageIETable = q30.PrivateMessageIETable

var PrivateMessageIEs func() PrivateMessageIETable = q30.PrivateMessageIEs

type PrivateMessageIEsValue = q30.PrivateMessageIEsValue

// PrivateMessageIEsValuePrivateIEContainer is the concrete PrivateIEContainer[PrivateMessageIEsValue].
type PrivateMessageIEsValuePrivateIEContainer = q30.PrivateMessageIEsValuePrivateIEContainer

// PrivateMessageIEsValuePrivateIEField is the concrete PrivateIEField[PrivateMessageIEsValue].
type PrivateMessageIEsValuePrivateIEField = q30.PrivateMessageIEsValuePrivateIEField

// PrivateMessageInitiatingBinding is the concrete InitiatingBinding[PrivateMessage].
type PrivateMessageInitiatingBinding = q12.PrivateMessageInitiatingBinding

var PrivateMessageProcedure func() PrivateMessageDescriptor = q12.PrivateMessageProcedure

// PrivateMessageValueCodec is the concrete ValueCodec[PrivateMessage].
type PrivateMessageValueCodec = q29.PrivateMessageValueCodec

// ProcedureCode represents the ASN.1 type ProcedureCode (INTEGER).
type ProcedureCode = q14.ProcedureCode

// ProcedureCodeAPERValue is the concrete APERValue[ProcedureCode].
type ProcedureCodeAPERValue = q31.ProcedureCodeAPERValue

// ProcedureCodeCodec binds the complete source value type.
var ProcedureCodeCodec func() ProcedureCodeValueCodec = q25.ProcedureCodeCodec

// ProcedureCodeValueCodec is the concrete ValueCodec[ProcedureCode].
type ProcedureCodeValueCodec = q31.ProcedureCodeValueCodec
type ProcedureInfo = q14.ProcedureInfo
type ProtocolExtensionContainer[V q4.ProtocolOpenValueConstraint[V]] = q4.ProtocolExtensionContainer[V]
type ProtocolExtensionField[V q4.ProtocolOpenValueConstraint[V]] = q4.ProtocolExtensionField[V]
type ProtocolIEContainer[V q4.ProtocolOpenValueConstraint[V]] = q4.ProtocolIEContainer[V]
type ProtocolIEContainerList[V q4.ProtocolOpenValueConstraint[V]] = q4.ProtocolIEContainerList[V]
type ProtocolIEContainerPair[A q4.ProtocolOpenValueConstraint[A], B q4.ProtocolOpenValueConstraint[B]] = q4.ProtocolIEContainerPair[A, B]
type ProtocolIEContainerPairList[A q4.ProtocolOpenValueConstraint[A], B q4.ProtocolOpenValueConstraint[B]] = q4.ProtocolIEContainerPairList[A, B]
type ProtocolIEField[V q4.ProtocolOpenValueConstraint[V]] = q4.ProtocolIEField[V]
type ProtocolIEFieldPair[A q4.ProtocolOpenValueConstraint[A], B q4.ProtocolOpenValueConstraint[B]] = q4.ProtocolIEFieldPair[A, B]

// ProtocolIEID represents the ASN.1 type ProtocolIE-ID (INTEGER).
type ProtocolIEID = q14.ProtocolIEID

// ProtocolIEIDAPERValue is the concrete APERValue[ProtocolIEID].
type ProtocolIEIDAPERValue = q31.ProtocolIEIDAPERValue

// ProtocolIEIDCodec binds the complete source value type.
var ProtocolIEIDCodec func() ProtocolIEIDValueCodec = q25.ProtocolIEIDCodec

// ProtocolIEIDValueCodec is the concrete ValueCodec[ProtocolIEID].
type ProtocolIEIDValueCodec = q31.ProtocolIEIDValueCodec
type ProtocolIESingleContainer[V q4.ProtocolOpenValueConstraint[V]] = q4.ProtocolIESingleContainer[V]

// RSSI represents the ASN.1 type RSSI (INTEGER).
type RSSI = q14.RSSI

// RSSIAPERValue is the concrete APERValue[RSSI].
type RSSIAPERValue = q31.RSSIAPERValue

// RSSICodec binds the complete source value type.
var RSSICodec func() RSSIValueCodec = q8.RSSICodec

// RSSIValueCodec is the concrete ValueCodec[RSSI].
type RSSIValueCodec = q31.RSSIValueCodec

const RepeatedIE = q14.RepeatedIE

// RepetitionNumberofSIB1NB represents the ASN.1 ENUMERATED type RepetitionNumberofSIB1-NB.
type RepetitionNumberofSIB1NB = q14.RepetitionNumberofSIB1NB

// RepetitionNumberofSIB1NBAPERValue is the concrete APERValue[RepetitionNumberofSIB1NB].
type RepetitionNumberofSIB1NBAPERValue = q31.RepetitionNumberofSIB1NBAPERValue

// RepetitionNumberofSIB1NBCodec binds the complete source value type.
var RepetitionNumberofSIB1NBCodec func() RepetitionNumberofSIB1NBValueCodec = q8.RepetitionNumberofSIB1NBCodec

const RepetitionNumberofSIB1NBR16 = q14.RepetitionNumberofSIB1NBR16
const RepetitionNumberofSIB1NBR4 = q14.RepetitionNumberofSIB1NBR4
const RepetitionNumberofSIB1NBR8 = q14.RepetitionNumberofSIB1NBR8

// RepetitionNumberofSIB1NBValueCodec is the concrete ValueCodec[RepetitionNumberofSIB1NB].
type RepetitionNumberofSIB1NBValueCodec = q31.RepetitionNumberofSIB1NBValueCodec

// ReportCharacteristics represents the ASN.1 ENUMERATED type ReportCharacteristics.
type ReportCharacteristics = q14.ReportCharacteristics

// ReportCharacteristicsAPERValue is the concrete APERValue[ReportCharacteristics].
type ReportCharacteristicsAPERValue = q31.ReportCharacteristicsAPERValue

// ReportCharacteristicsCodec binds the complete APER value type.
var ReportCharacteristicsCodec func() ReportCharacteristicsValueCodec = q12.ReportCharacteristicsCodec

const ReportCharacteristicsOnDemand = q14.ReportCharacteristicsOnDemand
const ReportCharacteristicsPeriodic = q14.ReportCharacteristicsPeriodic

// ReportCharacteristicsValueCodec is the concrete ValueCodec[ReportCharacteristics].
type ReportCharacteristicsValueCodec = q31.ReportCharacteristicsValueCodec

// RequestedSRSTransmissionCharacteristics represents the ASN.1 type RequestedSRSTransmissionCharacteristics (SEQUENCE).
type RequestedSRSTransmissionCharacteristics = q30.RequestedSRSTransmissionCharacteristics

// RequestedSRSTransmissionCharacteristicsAPERValue is the concrete APERValue[RequestedSRSTransmissionCharacteristics].
type RequestedSRSTransmissionCharacteristicsAPERValue = q30.RequestedSRSTransmissionCharacteristicsAPERValue

// RequestedSRSTransmissionCharacteristicsCodec binds the complete APER value type.
var RequestedSRSTransmissionCharacteristicsCodec func() RequestedSRSTransmissionCharacteristicsValueCodec = q15.RequestedSRSTransmissionCharacteristicsCodec

// RequestedSRSTransmissionCharacteristicsValueCodec is the concrete ValueCodec[RequestedSRSTransmissionCharacteristics].
type RequestedSRSTransmissionCharacteristicsValueCodec = q30.RequestedSRSTransmissionCharacteristicsValueCodec
type ResultGERAN = q29.ResultGERAN

// ResultGERANAPERValue is the concrete APERValue[ResultGERAN].
type ResultGERANAPERValue = q29.ResultGERANAPERValue

// ResultGERANCodec binds the complete source value type.
var ResultGERANCodec func() ResultGERANValueCodec = q24.ResultGERANCodec

// ResultGERANComplete carries a complete ResultGERAN encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultGERANComplete = q24.ResultGERANComplete

// ResultGERANItem represents the ASN.1 type ResultGERAN-Item (SEQUENCE).
type ResultGERANItem = q29.ResultGERANItem

// ResultGERANItemAPERValue is the concrete APERValue[ResultGERANItem].
type ResultGERANItemAPERValue = q29.ResultGERANItemAPERValue

// ResultGERANItemCodec binds the complete source value type.
var ResultGERANItemCodec func() ResultGERANItemValueCodec = q29.ResultGERANItemCodec

type ResultGERANItemExtIETable = q25.ResultGERANItemExtIETable

var ResultGERANItemExtIEs func() ResultGERANItemExtIETable = q25.ResultGERANItemExtIEs

// ResultGERANItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsExtContainer = q25.ResultGERANItemExtIEsExtContainer

// ResultGERANItemExtIEsExtField is the concrete ProtocolExtensionField[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsExtField = q25.ResultGERANItemExtIEsExtField

// ResultGERANItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsIEContainer = q25.ResultGERANItemExtIEsIEContainer

// ResultGERANItemExtIEsIEField is the concrete ProtocolIEField[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsIEField = q25.ResultGERANItemExtIEsIEField
type ResultGERANItemExtIEsValue = q8.ResultGERANItemExtIEsValue

// ResultGERANItemValueCodec is the concrete ValueCodec[ResultGERANItem].
type ResultGERANItemValueCodec = q29.ResultGERANItemValueCodec

// ResultGERANValueCodec is the concrete ValueCodec[ResultGERAN].
type ResultGERANValueCodec = q29.ResultGERANValueCodec
type ResultNR = q24.ResultNR

// ResultNRAPERValue is the concrete APERValue[ResultNR].
type ResultNRAPERValue = q24.ResultNRAPERValue

// ResultNRCodec binds the complete source value type.
var ResultNRCodec func() ResultNRValueCodec = q21.ResultNRCodec

// ResultNRComplete carries a complete ResultNR encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultNRComplete = q21.ResultNRComplete

// ResultNRItem represents the ASN.1 type ResultNR-Item (SEQUENCE).
type ResultNRItem = q24.ResultNRItem

// ResultNRItemAPERValue is the concrete APERValue[ResultNRItem].
type ResultNRItemAPERValue = q24.ResultNRItemAPERValue

// ResultNRItemCodec binds the complete source value type.
var ResultNRItemCodec func() ResultNRItemValueCodec = q24.ResultNRItemCodec

type ResultNRItemExtIETable = q24.ResultNRItemExtIETable

var ResultNRItemExtIEs func() ResultNRItemExtIETable = q24.ResultNRItemExtIEs

// ResultNRItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsExtContainer = q24.ResultNRItemExtIEsExtContainer

// ResultNRItemExtIEsExtField is the concrete ProtocolExtensionField[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsExtField = q24.ResultNRItemExtIEsExtField

// ResultNRItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsIEContainer = q24.ResultNRItemExtIEsIEContainer

// ResultNRItemExtIEsIEField is the concrete ProtocolIEField[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsIEField = q24.ResultNRItemExtIEsIEField

// ResultNRItemExtIEsNRCGIExtBinding is the concrete ExtensionBinding[NRCGI, ResultNRItemExtIEsValue].
type ResultNRItemExtIEsNRCGIExtBinding = q24.ResultNRItemExtIEsNRCGIExtBinding

// ResultNRItemExtIEsResultsPerSSBIndexListExtBinding is the concrete ExtensionBinding[ResultsPerSSBIndexList, ResultNRItemExtIEsValue].
type ResultNRItemExtIEsResultsPerSSBIndexListExtBinding = q24.ResultNRItemExtIEsResultsPerSSBIndexListExtBinding
type ResultNRItemExtIEsValue = q24.ResultNRItemExtIEsValue

// ResultNRItemValueCodec is the concrete ValueCodec[ResultNRItem].
type ResultNRItemValueCodec = q24.ResultNRItemValueCodec

// ResultNRValueCodec is the concrete ValueCodec[ResultNR].
type ResultNRValueCodec = q24.ResultNRValueCodec
type ResultRSRP = q29.ResultRSRP

// ResultRSRPAPERValue is the concrete APERValue[ResultRSRP].
type ResultRSRPAPERValue = q29.ResultRSRPAPERValue

// ResultRSRPCodec binds the complete source value type.
var ResultRSRPCodec func() ResultRSRPValueCodec = q24.ResultRSRPCodec

// ResultRSRPComplete carries a complete ResultRSRP encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultRSRPComplete = q24.ResultRSRPComplete

// ResultRSRPItem represents the ASN.1 type ResultRSRP-Item (SEQUENCE).
type ResultRSRPItem = q29.ResultRSRPItem

// ResultRSRPItemAPERValue is the concrete APERValue[ResultRSRPItem].
type ResultRSRPItemAPERValue = q29.ResultRSRPItemAPERValue

// ResultRSRPItemCodec binds the complete source value type.
var ResultRSRPItemCodec func() ResultRSRPItemValueCodec = q29.ResultRSRPItemCodec

type ResultRSRPItemExtIETable = q25.ResultRSRPItemExtIETable

var ResultRSRPItemExtIEs func() ResultRSRPItemExtIETable = q25.ResultRSRPItemExtIEs

// ResultRSRPItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsExtContainer = q25.ResultRSRPItemExtIEsExtContainer

// ResultRSRPItemExtIEsExtField is the concrete ProtocolExtensionField[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsExtField = q25.ResultRSRPItemExtIEsExtField

// ResultRSRPItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsIEContainer = q25.ResultRSRPItemExtIEsIEContainer

// ResultRSRPItemExtIEsIEField is the concrete ProtocolIEField[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsIEField = q25.ResultRSRPItemExtIEsIEField
type ResultRSRPItemExtIEsValue = q8.ResultRSRPItemExtIEsValue

// ResultRSRPItemValueCodec is the concrete ValueCodec[ResultRSRPItem].
type ResultRSRPItemValueCodec = q29.ResultRSRPItemValueCodec

// ResultRSRPValueCodec is the concrete ValueCodec[ResultRSRP].
type ResultRSRPValueCodec = q29.ResultRSRPValueCodec
type ResultRSRQ = q22.ResultRSRQ

// ResultRSRQAPERValue is the concrete APERValue[ResultRSRQ].
type ResultRSRQAPERValue = q22.ResultRSRQAPERValue

// ResultRSRQCodec binds the complete source value type.
var ResultRSRQCodec func() ResultRSRQValueCodec = q24.ResultRSRQCodec

// ResultRSRQComplete carries a complete ResultRSRQ encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultRSRQComplete = q24.ResultRSRQComplete

// ResultRSRQItem represents the ASN.1 type ResultRSRQ-Item (SEQUENCE).
type ResultRSRQItem = q22.ResultRSRQItem

// ResultRSRQItemAPERValue is the concrete APERValue[ResultRSRQItem].
type ResultRSRQItemAPERValue = q22.ResultRSRQItemAPERValue

// ResultRSRQItemCodec binds the complete source value type.
var ResultRSRQItemCodec func() ResultRSRQItemValueCodec = q22.ResultRSRQItemCodec

type ResultRSRQItemExtIETable = q25.ResultRSRQItemExtIETable

var ResultRSRQItemExtIEs func() ResultRSRQItemExtIETable = q25.ResultRSRQItemExtIEs

// ResultRSRQItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsExtContainer = q25.ResultRSRQItemExtIEsExtContainer

// ResultRSRQItemExtIEsExtField is the concrete ProtocolExtensionField[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsExtField = q25.ResultRSRQItemExtIEsExtField

// ResultRSRQItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsIEContainer = q25.ResultRSRQItemExtIEsIEContainer

// ResultRSRQItemExtIEsIEField is the concrete ProtocolIEField[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsIEField = q25.ResultRSRQItemExtIEsIEField
type ResultRSRQItemExtIEsValue = q8.ResultRSRQItemExtIEsValue

// ResultRSRQItemValueCodec is the concrete ValueCodec[ResultRSRQItem].
type ResultRSRQItemValueCodec = q22.ResultRSRQItemValueCodec

// ResultRSRQValueCodec is the concrete ValueCodec[ResultRSRQ].
type ResultRSRQValueCodec = q22.ResultRSRQValueCodec
type ResultUTRAN = q10.ResultUTRAN

// ResultUTRANAPERValue is the concrete APERValue[ResultUTRAN].
type ResultUTRANAPERValue = q10.ResultUTRANAPERValue

// ResultUTRANCodec binds the complete source value type.
var ResultUTRANCodec func() ResultUTRANValueCodec = q24.ResultUTRANCodec

// ResultUTRANComplete carries a complete ResultUTRAN encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultUTRANComplete = q24.ResultUTRANComplete

// ResultUTRANItem represents the ASN.1 type ResultUTRAN-Item (SEQUENCE).
type ResultUTRANItem = q10.ResultUTRANItem

// ResultUTRANItemAPERValue is the concrete APERValue[ResultUTRANItem].
type ResultUTRANItemAPERValue = q10.ResultUTRANItemAPERValue

// ResultUTRANItemCodec binds the complete source value type.
var ResultUTRANItemCodec func() ResultUTRANItemValueCodec = q10.ResultUTRANItemCodec

type ResultUTRANItemExtIETable = q25.ResultUTRANItemExtIETable

var ResultUTRANItemExtIEs func() ResultUTRANItemExtIETable = q25.ResultUTRANItemExtIEs

// ResultUTRANItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsExtContainer = q25.ResultUTRANItemExtIEsExtContainer

// ResultUTRANItemExtIEsExtField is the concrete ProtocolExtensionField[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsExtField = q25.ResultUTRANItemExtIEsExtField

// ResultUTRANItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsIEContainer = q25.ResultUTRANItemExtIEsIEContainer

// ResultUTRANItemExtIEsIEField is the concrete ProtocolIEField[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsIEField = q25.ResultUTRANItemExtIEsIEField
type ResultUTRANItemExtIEsValue = q8.ResultUTRANItemExtIEsValue

// ResultUTRANItemPhysCellIDUTRAN represents the ASN.1 CHOICE type ResultUTRAN-Item-physCellIDUTRAN.
type ResultUTRANItemPhysCellIDUTRAN = q30.ResultUTRANItemPhysCellIDUTRAN

// ResultUTRANItemPhysCellIDUTRANAPERValue is the concrete APERValue[ResultUTRANItemPhysCellIDUTRAN].
type ResultUTRANItemPhysCellIDUTRANAPERValue = q30.ResultUTRANItemPhysCellIDUTRANAPERValue

// ResultUTRANItemPhysCellIDUTRAN choice constants.
const ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD = q14.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD

// ResultUTRANItemPhysCellIDUTRAN choice constants.
const ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD = q14.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD

// ResultUTRANItemPhysCellIDUTRANCodec binds the complete source value type.
var ResultUTRANItemPhysCellIDUTRANCodec func() ResultUTRANItemPhysCellIDUTRANValueCodec = q30.ResultUTRANItemPhysCellIDUTRANCodec

// ResultUTRANItemPhysCellIDUTRANValueCodec is the concrete ValueCodec[ResultUTRANItemPhysCellIDUTRAN].
type ResultUTRANItemPhysCellIDUTRANValueCodec = q30.ResultUTRANItemPhysCellIDUTRANValueCodec

// ResultUTRANItemValueCodec is the concrete ValueCodec[ResultUTRANItem].
type ResultUTRANItemValueCodec = q10.ResultUTRANItemValueCodec

// ResultUTRANValueCodec is the concrete ValueCodec[ResultUTRAN].
type ResultUTRANValueCodec = q10.ResultUTRANValueCodec

// ResultsPerSSBIndexItem represents the ASN.1 type ResultsPerSSB-Index-Item (SEQUENCE).
type ResultsPerSSBIndexItem = q10.ResultsPerSSBIndexItem

// ResultsPerSSBIndexItemAPERValue is the concrete APERValue[ResultsPerSSBIndexItem].
type ResultsPerSSBIndexItemAPERValue = q10.ResultsPerSSBIndexItemAPERValue

// ResultsPerSSBIndexItemCodec binds the complete source value type.
var ResultsPerSSBIndexItemCodec func() ResultsPerSSBIndexItemValueCodec = q10.ResultsPerSSBIndexItemCodec

type ResultsPerSSBIndexItemExtIETable = q25.ResultsPerSSBIndexItemExtIETable

var ResultsPerSSBIndexItemExtIEs func() ResultsPerSSBIndexItemExtIETable = q25.ResultsPerSSBIndexItemExtIEs

// ResultsPerSSBIndexItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsExtContainer = q25.ResultsPerSSBIndexItemExtIEsExtContainer

// ResultsPerSSBIndexItemExtIEsExtField is the concrete ProtocolExtensionField[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsExtField = q25.ResultsPerSSBIndexItemExtIEsExtField

// ResultsPerSSBIndexItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsIEContainer = q25.ResultsPerSSBIndexItemExtIEsIEContainer

// ResultsPerSSBIndexItemExtIEsIEField is the concrete ProtocolIEField[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsIEField = q25.ResultsPerSSBIndexItemExtIEsIEField
type ResultsPerSSBIndexItemExtIEsValue = q8.ResultsPerSSBIndexItemExtIEsValue

// ResultsPerSSBIndexItemValueCodec is the concrete ValueCodec[ResultsPerSSBIndexItem].
type ResultsPerSSBIndexItemValueCodec = q10.ResultsPerSSBIndexItemValueCodec
type ResultsPerSSBIndexList = q10.ResultsPerSSBIndexList

// ResultsPerSSBIndexListAPERValue is the concrete APERValue[ResultsPerSSBIndexList].
type ResultsPerSSBIndexListAPERValue = q10.ResultsPerSSBIndexListAPERValue

// ResultsPerSSBIndexListCodec binds the complete APER value type.
var ResultsPerSSBIndexListCodec func() ResultsPerSSBIndexListValueCodec = q24.ResultsPerSSBIndexListCodec

// ResultsPerSSBIndexListComplete carries a complete ResultsPerSSBIndexList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultsPerSSBIndexListComplete = q24.ResultsPerSSBIndexListComplete

// ResultsPerSSBIndexListValueCodec is the concrete ValueCodec[ResultsPerSSBIndexList].
type ResultsPerSSBIndexListValueCodec = q10.ResultsPerSSBIndexListValueCodec

// SFNInitialisationTime represents the ASN.1 type SFNInitialisationTime (BIT_STRING).
type SFNInitialisationTime = q14.SFNInitialisationTime

// SFNInitialisationTimeAPERValue is the concrete APERValue[SFNInitialisationTime].
type SFNInitialisationTimeAPERValue = q31.SFNInitialisationTimeAPERValue

// SFNInitialisationTimeCodec binds the complete source value type.
var SFNInitialisationTimeCodec func() SFNInitialisationTimeValueCodec = q8.SFNInitialisationTimeCodec

// SFNInitialisationTimeValueCodec is the concrete ValueCodec[SFNInitialisationTime].
type SFNInitialisationTimeValueCodec = q31.SFNInitialisationTimeValueCodec
type SRSConfigurationForAllCells = q15.SRSConfigurationForAllCells

// SRSConfigurationForAllCellsAPERValue is the concrete APERValue[SRSConfigurationForAllCells].
type SRSConfigurationForAllCellsAPERValue = q15.SRSConfigurationForAllCellsAPERValue

// SRSConfigurationForAllCellsCodec binds the complete source value type.
var SRSConfigurationForAllCellsCodec func() SRSConfigurationForAllCellsValueCodec = q21.SRSConfigurationForAllCellsCodec

// SRSConfigurationForAllCellsComplete carries a complete SRSConfigurationForAllCells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SRSConfigurationForAllCellsComplete = q21.SRSConfigurationForAllCellsComplete

// SRSConfigurationForAllCellsValueCodec is the concrete ValueCodec[SRSConfigurationForAllCells].
type SRSConfigurationForAllCellsValueCodec = q15.SRSConfigurationForAllCellsValueCodec

// SRSConfigurationForOneCell represents the ASN.1 type SRSConfigurationForOneCell (SEQUENCE).
type SRSConfigurationForOneCell = q15.SRSConfigurationForOneCell

// SRSConfigurationForOneCellAPERValue is the concrete APERValue[SRSConfigurationForOneCell].
type SRSConfigurationForOneCellAPERValue = q15.SRSConfigurationForOneCellAPERValue

// SRSConfigurationForOneCellCodec binds the complete source value type.
var SRSConfigurationForOneCellCodec func() SRSConfigurationForOneCellValueCodec = q15.SRSConfigurationForOneCellCodec

// SRSConfigurationForOneCellValueCodec is the concrete ValueCodec[SRSConfigurationForOneCell].
type SRSConfigurationForOneCellValueCodec = q15.SRSConfigurationForOneCellValueCodec

// SSBIndex represents the ASN.1 type SSB-Index (INTEGER).
type SSBIndex = q14.SSBIndex

// SSBIndexAPERValue is the concrete APERValue[SSBIndex].
type SSBIndexAPERValue = q31.SSBIndexAPERValue

// SSBIndexCodec binds the complete source value type.
var SSBIndexCodec func() SSBIndexValueCodec = q25.SSBIndexCodec

// SSBIndexValueCodec is the concrete ValueCodec[SSBIndex].
type SSBIndexValueCodec = q31.SSBIndexValueCodec

// SSID represents the ASN.1 type SSID (OCTET_STRING).
type SSID = q14.SSID

// SSIDAPERValue is the concrete APERValue[SSID].
type SSIDAPERValue = q31.SSIDAPERValue

// SSIDCodec binds the complete source value type.
var SSIDCodec func() SSIDValueCodec = q8.SSIDCodec

// SSIDValueCodec is the concrete ValueCodec[SSID].
type SSIDValueCodec = q31.SSIDValueCodec

// SSNRRSRP represents the ASN.1 type SS-NRRSRP (INTEGER).
type SSNRRSRP = q14.SSNRRSRP

// SSNRRSRPAPERValue is the concrete APERValue[SSNRRSRP].
type SSNRRSRPAPERValue = q31.SSNRRSRPAPERValue

// SSNRRSRPCodec binds the complete source value type.
var SSNRRSRPCodec func() SSNRRSRPValueCodec = q25.SSNRRSRPCodec

// SSNRRSRPValueCodec is the concrete ValueCodec[SSNRRSRP].
type SSNRRSRPValueCodec = q31.SSNRRSRPValueCodec

// SSNRRSRQ represents the ASN.1 type SS-NRRSRQ (INTEGER).
type SSNRRSRQ = q14.SSNRRSRQ

// SSNRRSRQAPERValue is the concrete APERValue[SSNRRSRQ].
type SSNRRSRQAPERValue = q31.SSNRRSRQAPERValue

// SSNRRSRQCodec binds the complete source value type.
var SSNRRSRQCodec func() SSNRRSRQValueCodec = q25.SSNRRSRQCodec

// SSNRRSRQValueCodec is the concrete ValueCodec[SSNRRSRQ].
type SSNRRSRQValueCodec = q31.SSNRRSRQValueCodec

// Subframeallocation represents the ASN.1 CHOICE type Subframeallocation.
type Subframeallocation = q15.Subframeallocation

// SubframeallocationAPERValue is the concrete APERValue[Subframeallocation].
type SubframeallocationAPERValue = q15.SubframeallocationAPERValue

// Subframeallocation choice constants.
const SubframeallocationChoiceFourFrames = q14.SubframeallocationChoiceFourFrames

// Subframeallocation choice constants.
const SubframeallocationChoiceOneFrame = q14.SubframeallocationChoiceOneFrame

// SubframeallocationCodec binds the complete source value type.
var SubframeallocationCodec func() SubframeallocationValueCodec = q15.SubframeallocationCodec

// SubframeallocationValueCodec is the concrete ValueCodec[Subframeallocation].
type SubframeallocationValueCodec = q15.SubframeallocationValueCodec
type SuccessfulBinding[T any] = q4.SuccessfulBinding[T]

// SuccessfulOutcome represents the ASN.1 type SuccessfulOutcome (SEQUENCE).
type SuccessfulOutcome = q17.SuccessfulOutcome

// SuccessfulOutcomeAPERValue is the concrete APERValue[SuccessfulOutcome].
type SuccessfulOutcomeAPERValue = q4.SuccessfulOutcomeAPERValue

// SuccessfulOutcomeCodec binds the complete source value type.
var SuccessfulOutcomeCodec func() SuccessfulOutcomeValueCodec = q4.SuccessfulOutcomeCodec

// SuccessfulOutcomeValueCodec is the concrete ValueCodec[SuccessfulOutcome].
type SuccessfulOutcomeValueCodec = q4.SuccessfulOutcomeValueCodec

var SuccessfulReason func(code ProcedureCode) q23.OpaqueReason = q14.SuccessfulReason

type SuccessfulValue = q17.SuccessfulValue
type SystemInformation = q10.SystemInformation

// SystemInformationAPERValue is the concrete APERValue[SystemInformation].
type SystemInformationAPERValue = q10.SystemInformationAPERValue

// SystemInformationCodec binds the complete source value type.
var SystemInformationCodec func() SystemInformationValueCodec = q21.SystemInformationCodec

// SystemInformationComplete carries a complete SystemInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SystemInformationComplete = q21.SystemInformationComplete

// SystemInformationElem represents the ASN.1 type SystemInformation-Elem (SEQUENCE).
type SystemInformationElem = q10.SystemInformationElem

// SystemInformationElemAPERValue is the concrete APERValue[SystemInformationElem].
type SystemInformationElemAPERValue = q10.SystemInformationElemAPERValue

// SystemInformationElemCodec binds the complete source value type.
var SystemInformationElemCodec func() SystemInformationElemValueCodec = q10.SystemInformationElemCodec

// SystemInformationElemValueCodec is the concrete ValueCodec[SystemInformationElem].
type SystemInformationElemValueCodec = q10.SystemInformationElemValueCodec
type SystemInformationExtIETable = q25.SystemInformationExtIETable

var SystemInformationExtIEs func() SystemInformationExtIETable = q25.SystemInformationExtIEs

// SystemInformationExtIEsExtContainer is the concrete ProtocolExtensionContainer[SystemInformationExtIEsValue].
type SystemInformationExtIEsExtContainer = q25.SystemInformationExtIEsExtContainer

// SystemInformationExtIEsExtField is the concrete ProtocolExtensionField[SystemInformationExtIEsValue].
type SystemInformationExtIEsExtField = q25.SystemInformationExtIEsExtField

// SystemInformationExtIEsIEContainer is the concrete ProtocolIEContainer[SystemInformationExtIEsValue].
type SystemInformationExtIEsIEContainer = q25.SystemInformationExtIEsIEContainer

// SystemInformationExtIEsIEField is the concrete ProtocolIEField[SystemInformationExtIEsValue].
type SystemInformationExtIEsIEField = q25.SystemInformationExtIEsIEField
type SystemInformationExtIEsValue = q8.SystemInformationExtIEsValue

// SystemInformationValueCodec is the concrete ValueCodec[SystemInformation].
type SystemInformationValueCodec = q10.SystemInformationValueCodec

// TAC represents the ASN.1 type TAC (OCTET_STRING).
type TAC = q14.TAC

// TACAPERValue is the concrete APERValue[TAC].
type TACAPERValue = q31.TACAPERValue

// TACCodec binds the complete source value type.
var TACCodec func() TACValueCodec = q8.TACCodec

// TACValueCodec is the concrete ValueCodec[TAC].
type TACValueCodec = q31.TACValueCodec

// TDDConfiguration represents the ASN.1 type TDDConfiguration (SEQUENCE).
type TDDConfiguration = q5.TDDConfiguration

// TDDConfigurationAPERValue is the concrete APERValue[TDDConfiguration].
type TDDConfigurationAPERValue = q5.TDDConfigurationAPERValue

// TDDConfigurationCodec binds the complete source value type.
var TDDConfigurationCodec func() TDDConfigurationValueCodec = q5.TDDConfigurationCodec

type TDDConfigurationExtIETable = q25.TDDConfigurationExtIETable

var TDDConfigurationExtIEs func() TDDConfigurationExtIETable = q25.TDDConfigurationExtIEs

// TDDConfigurationExtIEsExtContainer is the concrete ProtocolExtensionContainer[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsExtContainer = q25.TDDConfigurationExtIEsExtContainer

// TDDConfigurationExtIEsExtField is the concrete ProtocolExtensionField[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsExtField = q25.TDDConfigurationExtIEsExtField

// TDDConfigurationExtIEsIEContainer is the concrete ProtocolIEContainer[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsIEContainer = q25.TDDConfigurationExtIEsIEContainer

// TDDConfigurationExtIEsIEField is the concrete ProtocolIEField[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsIEField = q25.TDDConfigurationExtIEsIEField
type TDDConfigurationExtIEsValue = q8.TDDConfigurationExtIEsValue

// TDDConfigurationValueCodec is the concrete ValueCodec[TDDConfiguration].
type TDDConfigurationValueCodec = q5.TDDConfigurationValueCodec

// TPID represents the ASN.1 type TP-ID (INTEGER).
type TPID = q14.TPID

// TPIDAPERValue is the concrete APERValue[TPID].
type TPIDAPERValue = q31.TPIDAPERValue

// TPIDCodec binds the complete source value type.
var TPIDCodec func() TPIDValueCodec = q8.TPIDCodec

// TPIDValueCodec is the concrete ValueCodec[TPID].
type TPIDValueCodec = q31.TPIDValueCodec

// TPType represents the ASN.1 ENUMERATED type TP-Type.
type TPType = q14.TPType

// TPTypeAPERValue is the concrete APERValue[TPType].
type TPTypeAPERValue = q31.TPTypeAPERValue

// TPTypeCodec binds the complete source value type.
var TPTypeCodec func() TPTypeValueCodec = q8.TPTypeCodec

const TPTypePrsOnlyTp = q14.TPTypePrsOnlyTp

// TPTypeValueCodec is the concrete ValueCodec[TPType].
type TPTypeValueCodec = q31.TPTypeValueCodec
type TableID = q14.TableID

// TriggeringMessage represents the ASN.1 ENUMERATED type TriggeringMessage.
type TriggeringMessage = q14.TriggeringMessage

// TriggeringMessageAPERValue is the concrete APERValue[TriggeringMessage].
type TriggeringMessageAPERValue = q31.TriggeringMessageAPERValue

// TriggeringMessageCodec binds the complete source value type.
var TriggeringMessageCodec func() TriggeringMessageValueCodec = q8.TriggeringMessageCodec

const TriggeringMessageInitiatingMessage = q14.TriggeringMessageInitiatingMessage
const TriggeringMessageSuccessfulOutcome = q14.TriggeringMessageSuccessfulOutcome
const TriggeringMessageUnsuccessfulOutcome = q14.TriggeringMessageUnsuccessfulOutcome

// TriggeringMessageValueCodec is the concrete ValueCodec[TriggeringMessage].
type TriggeringMessageValueCodec = q31.TriggeringMessageValueCodec
type TypeID = q14.TypeID

// TypeOfError represents the ASN.1 ENUMERATED type TypeOfError.
type TypeOfError = q14.TypeOfError

// TypeOfErrorAPERValue is the concrete APERValue[TypeOfError].
type TypeOfErrorAPERValue = q31.TypeOfErrorAPERValue

// TypeOfErrorCodec binds the complete source value type.
var TypeOfErrorCodec func() TypeOfErrorValueCodec = q8.TypeOfErrorCodec

const TypeOfErrorMissing = q14.TypeOfErrorMissing
const TypeOfErrorNotUnderstood = q14.TypeOfErrorNotUnderstood

// TypeOfErrorValueCodec is the concrete ValueCodec[TypeOfError].
type TypeOfErrorValueCodec = q31.TypeOfErrorValueCodec

// UARFCN represents the ASN.1 type UARFCN (INTEGER).
type UARFCN = q14.UARFCN

// UARFCNAPERValue is the concrete APERValue[UARFCN].
type UARFCNAPERValue = q31.UARFCNAPERValue

// UARFCNCodec binds the complete source value type.
var UARFCNCodec func() UARFCNValueCodec = q8.UARFCNCodec

// UARFCNValueCodec is the concrete ValueCodec[UARFCN].
type UARFCNValueCodec = q31.UARFCNValueCodec

// ULConfiguration represents the ASN.1 type ULConfiguration (SEQUENCE).
type ULConfiguration = q19.ULConfiguration

// ULConfigurationAPERValue is the concrete APERValue[ULConfiguration].
type ULConfigurationAPERValue = q19.ULConfigurationAPERValue

// ULConfigurationCodec binds the complete APER value type.
var ULConfigurationCodec func() ULConfigurationValueCodec = q19.ULConfigurationCodec

// ULConfigurationValueCodec is the concrete ValueCodec[ULConfiguration].
type ULConfigurationValueCodec = q19.ULConfigurationValueCodec
type UTDOAInformationExchangeDescriptor = q11.UTDOAInformationExchangeDescriptor

var UTDOAInformationExchangeProcedure func() UTDOAInformationExchangeDescriptor = q11.UTDOAInformationExchangeProcedure

// UTDOAInformationFailure represents the ASN.1 type UTDOAInformationFailure (SEQUENCE).
type UTDOAInformationFailure = q20.UTDOAInformationFailure

// UTDOAInformationFailureAPERValue is the concrete APERValue[UTDOAInformationFailure].
type UTDOAInformationFailureAPERValue = q20.UTDOAInformationFailureAPERValue

// UTDOAInformationFailureCauseIEBinding is the concrete IEBinding[Cause, UTDOAInformationFailureIEValue].
type UTDOAInformationFailureCauseIEBinding = q19.UTDOAInformationFailureCauseIEBinding

// UTDOAInformationFailureCodec binds the complete APER value type.
var UTDOAInformationFailureCodec func() UTDOAInformationFailureValueCodec = q11.UTDOAInformationFailureCodec

// UTDOAInformationFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UTDOAInformationFailureIEValue].
type UTDOAInformationFailureCriticalityDiagnosticsIEBinding = q19.UTDOAInformationFailureCriticalityDiagnosticsIEBinding

// UTDOAInformationFailureIEContainer is the concrete ProtocolIEContainer[UTDOAInformationFailureIEValue].
type UTDOAInformationFailureIEContainer = q19.UTDOAInformationFailureIEContainer

// UTDOAInformationFailureIEField is the concrete ProtocolIEField[UTDOAInformationFailureIEValue].
type UTDOAInformationFailureIEField = q19.UTDOAInformationFailureIEField
type UTDOAInformationFailureIETable = q19.UTDOAInformationFailureIETable
type UTDOAInformationFailureIEValue = q19.UTDOAInformationFailureIEValue

var UTDOAInformationFailureIEs func() UTDOAInformationFailureIETable = q19.UTDOAInformationFailureIEs

// UTDOAInformationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[UTDOAInformationFailure].
type UTDOAInformationFailureUnsuccessfulBinding = q20.UTDOAInformationFailureUnsuccessfulBinding

// UTDOAInformationFailureValueCodec is the concrete ValueCodec[UTDOAInformationFailure].
type UTDOAInformationFailureValueCodec = q20.UTDOAInformationFailureValueCodec

// UTDOAInformationRequest represents the ASN.1 type UTDOAInformationRequest (SEQUENCE).
type UTDOAInformationRequest = q20.UTDOAInformationRequest

// UTDOAInformationRequestAPERValue is the concrete APERValue[UTDOAInformationRequest].
type UTDOAInformationRequestAPERValue = q20.UTDOAInformationRequestAPERValue

// UTDOAInformationRequestCodec binds the complete APER value type.
var UTDOAInformationRequestCodec func() UTDOAInformationRequestValueCodec = q11.UTDOAInformationRequestCodec

// UTDOAInformationRequestIEContainer is the concrete ProtocolIEContainer[UTDOAInformationRequestIEValue].
type UTDOAInformationRequestIEContainer = q15.UTDOAInformationRequestIEContainer

// UTDOAInformationRequestIEField is the concrete ProtocolIEField[UTDOAInformationRequestIEValue].
type UTDOAInformationRequestIEField = q15.UTDOAInformationRequestIEField
type UTDOAInformationRequestIETable = q15.UTDOAInformationRequestIETable
type UTDOAInformationRequestIEValue = q15.UTDOAInformationRequestIEValue

var UTDOAInformationRequestIEs func() UTDOAInformationRequestIETable = q15.UTDOAInformationRequestIEs

// UTDOAInformationRequestInitiatingBinding is the concrete InitiatingBinding[UTDOAInformationRequest].
type UTDOAInformationRequestInitiatingBinding = q12.UTDOAInformationRequestInitiatingBinding

// UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding is the concrete IEBinding[RequestedSRSTransmissionCharacteristics, UTDOAInformationRequestIEValue].
type UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding = q15.UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding

// UTDOAInformationRequestValueCodec is the concrete ValueCodec[UTDOAInformationRequest].
type UTDOAInformationRequestValueCodec = q20.UTDOAInformationRequestValueCodec

// UTDOAInformationResponse represents the ASN.1 type UTDOAInformationResponse (SEQUENCE).
type UTDOAInformationResponse = q6.UTDOAInformationResponse

// UTDOAInformationResponseAPERValue is the concrete APERValue[UTDOAInformationResponse].
type UTDOAInformationResponseAPERValue = q6.UTDOAInformationResponseAPERValue

// UTDOAInformationResponseCodec binds the complete APER value type.
var UTDOAInformationResponseCodec func() UTDOAInformationResponseValueCodec = q11.UTDOAInformationResponseCodec

// UTDOAInformationResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UTDOAInformationResponseIEValue].
type UTDOAInformationResponseCriticalityDiagnosticsIEBinding = q19.UTDOAInformationResponseCriticalityDiagnosticsIEBinding

// UTDOAInformationResponseIEContainer is the concrete ProtocolIEContainer[UTDOAInformationResponseIEValue].
type UTDOAInformationResponseIEContainer = q19.UTDOAInformationResponseIEContainer

// UTDOAInformationResponseIEField is the concrete ProtocolIEField[UTDOAInformationResponseIEValue].
type UTDOAInformationResponseIEField = q19.UTDOAInformationResponseIEField
type UTDOAInformationResponseIETable = q19.UTDOAInformationResponseIETable
type UTDOAInformationResponseIEValue = q19.UTDOAInformationResponseIEValue

var UTDOAInformationResponseIEs func() UTDOAInformationResponseIETable = q19.UTDOAInformationResponseIEs

// UTDOAInformationResponseSuccessfulBinding is the concrete SuccessfulBinding[UTDOAInformationResponse].
type UTDOAInformationResponseSuccessfulBinding = q4.UTDOAInformationResponseSuccessfulBinding

// UTDOAInformationResponseULConfigurationIEBinding is the concrete IEBinding[ULConfiguration, UTDOAInformationResponseIEValue].
type UTDOAInformationResponseULConfigurationIEBinding = q19.UTDOAInformationResponseULConfigurationIEBinding

// UTDOAInformationResponseValueCodec is the concrete ValueCodec[UTDOAInformationResponse].
type UTDOAInformationResponseValueCodec = q6.UTDOAInformationResponseValueCodec

// UTDOAInformationUpdate represents the ASN.1 type UTDOAInformationUpdate (SEQUENCE).
type UTDOAInformationUpdate = q6.UTDOAInformationUpdate

// UTDOAInformationUpdateAPERValue is the concrete APERValue[UTDOAInformationUpdate].
type UTDOAInformationUpdateAPERValue = q6.UTDOAInformationUpdateAPERValue

// UTDOAInformationUpdateCodec binds the complete APER value type.
var UTDOAInformationUpdateCodec func() UTDOAInformationUpdateValueCodec = q11.UTDOAInformationUpdateCodec

type UTDOAInformationUpdateDescriptor = q11.UTDOAInformationUpdateDescriptor

// UTDOAInformationUpdateIEContainer is the concrete ProtocolIEContainer[UTDOAInformationUpdateIEValue].
type UTDOAInformationUpdateIEContainer = q18.UTDOAInformationUpdateIEContainer

// UTDOAInformationUpdateIEField is the concrete ProtocolIEField[UTDOAInformationUpdateIEValue].
type UTDOAInformationUpdateIEField = q18.UTDOAInformationUpdateIEField
type UTDOAInformationUpdateIETable = q18.UTDOAInformationUpdateIETable
type UTDOAInformationUpdateIEValue = q18.UTDOAInformationUpdateIEValue

var UTDOAInformationUpdateIEs func() UTDOAInformationUpdateIETable = q18.UTDOAInformationUpdateIEs

// UTDOAInformationUpdateInitiatingBinding is the concrete InitiatingBinding[UTDOAInformationUpdate].
type UTDOAInformationUpdateInitiatingBinding = q12.UTDOAInformationUpdateInitiatingBinding

var UTDOAInformationUpdateProcedure func() UTDOAInformationUpdateDescriptor = q11.UTDOAInformationUpdateProcedure

// UTDOAInformationUpdateULConfigurationIEBinding is the concrete IEBinding[ULConfiguration, UTDOAInformationUpdateIEValue].
type UTDOAInformationUpdateULConfigurationIEBinding = q18.UTDOAInformationUpdateULConfigurationIEBinding

// UTDOAInformationUpdateValueCodec is the concrete ValueCodec[UTDOAInformationUpdate].
type UTDOAInformationUpdateValueCodec = q6.UTDOAInformationUpdateValueCodec

// UTRAEcN0 represents the ASN.1 type UTRA-EcN0 (INTEGER).
type UTRAEcN0 = q14.UTRAEcN0

// UTRAEcN0APERValue is the concrete APERValue[UTRAEcN0].
type UTRAEcN0APERValue = q31.UTRAEcN0APERValue

// UTRAEcN0Codec binds the complete source value type.
var UTRAEcN0Codec func() UTRAEcN0ValueCodec = q8.UTRAEcN0Codec

// UTRAEcN0ValueCodec is the concrete ValueCodec[UTRAEcN0].
type UTRAEcN0ValueCodec = q31.UTRAEcN0ValueCodec

// UTRARSCP represents the ASN.1 type UTRA-RSCP (INTEGER).
type UTRARSCP = q14.UTRARSCP

// UTRARSCPAPERValue is the concrete APERValue[UTRARSCP].
type UTRARSCPAPERValue = q31.UTRARSCPAPERValue

// UTRARSCPCodec binds the complete source value type.
var UTRARSCPCodec func() UTRARSCPValueCodec = q8.UTRARSCPCodec

// UTRARSCPValueCodec is the concrete ValueCodec[UTRARSCP].
type UTRARSCPValueCodec = q31.UTRARSCPValueCodec

const UnavailableOutcome = q14.UnavailableOutcome
const UnknownProcedure = q14.UnknownProcedure

// UnmarshalAPERAddOTDOACellInformation decodes a complete named list.
var UnmarshalAPERAddOTDOACellInformation func(data []byte, options ...q23.DecodeOption) (AddOTDOACellInformationComplete, q23.DecodeReport, error) = q6.UnmarshalAPERAddOTDOACellInformation

// UnmarshalAPERAddOTDOACells decodes a complete named list.
var UnmarshalAPERAddOTDOACells func(data []byte, options ...q23.DecodeOption) (AddOTDOACellsComplete, q23.DecodeReport, error) = q6.UnmarshalAPERAddOTDOACells

// UnmarshalAPERAssistanceInformationFailureList decodes a complete named list.
var UnmarshalAPERAssistanceInformationFailureList func(data []byte, options ...q23.DecodeOption) (AssistanceInformationFailureListComplete, q23.DecodeReport, error) = q6.UnmarshalAPERAssistanceInformationFailureList

// UnmarshalAPERCriticalityDiagnosticsIEList decodes a complete named list.
var UnmarshalAPERCriticalityDiagnosticsIEList func(data []byte, options ...q23.DecodeOption) (CriticalityDiagnosticsIEListComplete, q23.DecodeReport, error) = q6.UnmarshalAPERCriticalityDiagnosticsIEList

// UnmarshalAPERInterRATMeasurementQuantities decodes a complete named list.
var UnmarshalAPERInterRATMeasurementQuantities func(data []byte, options ...q23.DecodeOption) (InterRATMeasurementQuantitiesComplete, q23.DecodeReport, error) = q6.UnmarshalAPERInterRATMeasurementQuantities

// UnmarshalAPERInterRATMeasurementResult decodes a complete named list.
var UnmarshalAPERInterRATMeasurementResult func(data []byte, options ...q23.DecodeOption) (InterRATMeasurementResultComplete, q23.DecodeReport, error) = q21.UnmarshalAPERInterRATMeasurementResult

// UnmarshalAPERMBSFNsubframeConfiguration decodes a complete named list.
var UnmarshalAPERMBSFNsubframeConfiguration func(data []byte, options ...q23.DecodeOption) (MBSFNsubframeConfigurationComplete, q23.DecodeReport, error) = q7.UnmarshalAPERMBSFNsubframeConfiguration

// UnmarshalAPERMeasuredResults decodes a complete named list.
var UnmarshalAPERMeasuredResults func(data []byte, options ...q23.DecodeOption) (MeasuredResultsComplete, q23.DecodeReport, error) = q7.UnmarshalAPERMeasuredResults

// UnmarshalAPERMeasurementQuantities decodes a complete named list.
var UnmarshalAPERMeasurementQuantities func(data []byte, options ...q23.DecodeOption) (MeasurementQuantitiesComplete, q23.DecodeReport, error) = q7.UnmarshalAPERMeasurementQuantities

// UnmarshalAPEROTDOACellInformation decodes a complete named list.
var UnmarshalAPEROTDOACellInformation func(data []byte, options ...q23.DecodeOption) (OTDOACellInformationComplete, q23.DecodeReport, error) = q7.UnmarshalAPEROTDOACellInformation

// UnmarshalAPEROTDOACells decodes a complete named list.
var UnmarshalAPEROTDOACells func(data []byte, options ...q23.DecodeOption) (OTDOACellsComplete, q23.DecodeReport, error) = q7.UnmarshalAPEROTDOACells

// UnmarshalAPEROTDOAInformationType decodes a complete named list.
var UnmarshalAPEROTDOAInformationType func(data []byte, options ...q23.DecodeOption) (OTDOAInformationTypeComplete, q23.DecodeReport, error) = q7.UnmarshalAPEROTDOAInformationType

// UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions decodes a complete named list.
var UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions func(data []byte, options ...q23.DecodeOption) (PRSFrequencyHoppingConfigurationBandPositionsComplete, q23.DecodeReport, error) = q24.UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions

// UnmarshalAPERPosSIBSegments decodes a complete named list.
var UnmarshalAPERPosSIBSegments func(data []byte, options ...q23.DecodeOption) (PosSIBSegmentsComplete, q23.DecodeReport, error) = q24.UnmarshalAPERPosSIBSegments

// UnmarshalAPERPosSIBs decodes a complete named list.
var UnmarshalAPERPosSIBs func(data []byte, options ...q23.DecodeOption) (PosSIBsComplete, q23.DecodeReport, error) = q24.UnmarshalAPERPosSIBs

// UnmarshalAPERResultGERAN decodes a complete named list.
var UnmarshalAPERResultGERAN func(data []byte, options ...q23.DecodeOption) (ResultGERANComplete, q23.DecodeReport, error) = q24.UnmarshalAPERResultGERAN

// UnmarshalAPERResultNR decodes a complete named list.
var UnmarshalAPERResultNR func(data []byte, options ...q23.DecodeOption) (ResultNRComplete, q23.DecodeReport, error) = q21.UnmarshalAPERResultNR

// UnmarshalAPERResultRSRP decodes a complete named list.
var UnmarshalAPERResultRSRP func(data []byte, options ...q23.DecodeOption) (ResultRSRPComplete, q23.DecodeReport, error) = q24.UnmarshalAPERResultRSRP

// UnmarshalAPERResultRSRQ decodes a complete named list.
var UnmarshalAPERResultRSRQ func(data []byte, options ...q23.DecodeOption) (ResultRSRQComplete, q23.DecodeReport, error) = q24.UnmarshalAPERResultRSRQ

// UnmarshalAPERResultUTRAN decodes a complete named list.
var UnmarshalAPERResultUTRAN func(data []byte, options ...q23.DecodeOption) (ResultUTRANComplete, q23.DecodeReport, error) = q24.UnmarshalAPERResultUTRAN

// UnmarshalAPERResultsPerSSBIndexList decodes a complete named list.
var UnmarshalAPERResultsPerSSBIndexList func(data []byte, options ...q23.DecodeOption) (ResultsPerSSBIndexListComplete, q23.DecodeReport, error) = q24.UnmarshalAPERResultsPerSSBIndexList

// UnmarshalAPERSRSConfigurationForAllCells decodes a complete named list.
var UnmarshalAPERSRSConfigurationForAllCells func(data []byte, options ...q23.DecodeOption) (SRSConfigurationForAllCellsComplete, q23.DecodeReport, error) = q21.UnmarshalAPERSRSConfigurationForAllCells

// UnmarshalAPERSystemInformation decodes a complete named list.
var UnmarshalAPERSystemInformation func(data []byte, options ...q23.DecodeOption) (SystemInformationComplete, q23.DecodeReport, error) = q21.UnmarshalAPERSystemInformation

// UnmarshalAPERWLANChannelList decodes a complete named list.
var UnmarshalAPERWLANChannelList func(data []byte, options ...q23.DecodeOption) (WLANChannelListComplete, q23.DecodeReport, error) = q21.UnmarshalAPERWLANChannelList

// UnmarshalAPERWLANMeasurementQuantities decodes a complete named list.
var UnmarshalAPERWLANMeasurementQuantities func(data []byte, options ...q23.DecodeOption) (WLANMeasurementQuantitiesComplete, q23.DecodeReport, error) = q12.UnmarshalAPERWLANMeasurementQuantities

// UnmarshalAPERWLANMeasurementResult decodes a complete named list.
var UnmarshalAPERWLANMeasurementResult func(data []byte, options ...q23.DecodeOption) (WLANMeasurementResultComplete, q23.DecodeReport, error) = q17.UnmarshalAPERWLANMeasurementResult

type UnsuccessfulBinding[T any] = q4.UnsuccessfulBinding[T]

// UnsuccessfulOutcome represents the ASN.1 type UnsuccessfulOutcome (SEQUENCE).
type UnsuccessfulOutcome = q20.UnsuccessfulOutcome

// UnsuccessfulOutcomeAPERValue is the concrete APERValue[UnsuccessfulOutcome].
type UnsuccessfulOutcomeAPERValue = q20.UnsuccessfulOutcomeAPERValue

// UnsuccessfulOutcomeCodec binds the complete source value type.
var UnsuccessfulOutcomeCodec func() UnsuccessfulOutcomeValueCodec = q20.UnsuccessfulOutcomeCodec

// UnsuccessfulOutcomeValueCodec is the concrete ValueCodec[UnsuccessfulOutcome].
type UnsuccessfulOutcomeValueCodec = q20.UnsuccessfulOutcomeValueCodec

var UnsuccessfulReason func(code ProcedureCode) q23.OpaqueReason = q14.UnsuccessfulReason

type UnsuccessfulValue = q20.UnsuccessfulValue

var ValidateAssistanceInformationControl func(v *AssistanceInformationControl, options ...q23.ValidationOption) (ValidationReport, error) = q11.ValidateAssistanceInformationControl
var ValidateAssistanceInformationFeedback func(v *AssistanceInformationFeedback, options ...q23.ValidationOption) (ValidationReport, error) = q4.ValidateAssistanceInformationFeedback
var ValidateECIDMeasurementFailureIndication func(v *ECIDMeasurementFailureIndication, options ...q23.ValidationOption) (ValidationReport, error) = q4.ValidateECIDMeasurementFailureIndication
var ValidateECIDMeasurementInitiationFailure func(v *ECIDMeasurementInitiationFailure, options ...q23.ValidationOption) (ValidationReport, error) = q4.ValidateECIDMeasurementInitiationFailure
var ValidateECIDMeasurementInitiationRequest func(v *ECIDMeasurementInitiationRequest, options ...q23.ValidationOption) (ValidationReport, error) = q11.ValidateECIDMeasurementInitiationRequest
var ValidateECIDMeasurementInitiationResponse func(v *ECIDMeasurementInitiationResponse, options ...q23.ValidationOption) (ValidationReport, error) = q11.ValidateECIDMeasurementInitiationResponse
var ValidateECIDMeasurementReport func(v *ECIDMeasurementReport, options ...q23.ValidationOption) (ValidationReport, error) = q4.ValidateECIDMeasurementReport
var ValidateECIDMeasurementTerminationCommand func(v *ECIDMeasurementTerminationCommand, options ...q23.ValidationOption) (ValidationReport, error) = q4.ValidateECIDMeasurementTerminationCommand
var ValidateErrorIndication func(v *ErrorIndication, options ...q23.ValidationOption) (ValidationReport, error) = q4.ValidateErrorIndication
var ValidateMessage func(v *LPPAPDU, options ...q23.ValidationOption) (ValidationReport, error) = q11.ValidateMessage
var ValidateOTDOAInformationFailure func(v *OTDOAInformationFailure, options ...q23.ValidationOption) (ValidationReport, error) = q4.ValidateOTDOAInformationFailure
var ValidateOTDOAInformationRequest func(v *OTDOAInformationRequest, options ...q23.ValidationOption) (ValidationReport, error) = q4.ValidateOTDOAInformationRequest
var ValidateOTDOAInformationResponse func(v *OTDOAInformationResponse, options ...q23.ValidationOption) (ValidationReport, error) = q11.ValidateOTDOAInformationResponse
var ValidatePrivateMessage func(v *PrivateMessage, options ...q23.ValidationOption) (ValidationReport, error) = q21.ValidatePrivateMessage
var ValidateUTDOAInformationFailure func(v *UTDOAInformationFailure, options ...q23.ValidationOption) (ValidationReport, error) = q11.ValidateUTDOAInformationFailure
var ValidateUTDOAInformationRequest func(v *UTDOAInformationRequest, options ...q23.ValidationOption) (ValidationReport, error) = q11.ValidateUTDOAInformationRequest
var ValidateUTDOAInformationResponse func(v *UTDOAInformationResponse, options ...q23.ValidationOption) (ValidationReport, error) = q11.ValidateUTDOAInformationResponse
var ValidateUTDOAInformationUpdate func(v *UTDOAInformationUpdate, options ...q23.ValidationOption) (ValidationReport, error) = q11.ValidateUTDOAInformationUpdate

type ValidationCode = q14.ValidationCode
type ValidationIssue = q15.ValidationIssue
type ValidationReport = q15.ValidationReport
type ValidationSeverity = q14.ValidationSeverity

const ValidationSeverityError = q14.ValidationSeverityError
const ValidationSeverityInformational = q14.ValidationSeverityInformational
const ValidationSeverityUnrecognized = q14.ValidationSeverityUnrecognized

// ValueCodec binds one source value type to its complete APER encoding.
type ValueCodec[T any] = q4.ValueCodec[T]

const ValueIDMismatch = q14.ValueIDMismatch

// ValueRSRP represents the ASN.1 type ValueRSRP (INTEGER).
type ValueRSRP = q14.ValueRSRP

// ValueRSRPAPERValue is the concrete APERValue[ValueRSRP].
type ValueRSRPAPERValue = q31.ValueRSRPAPERValue

// ValueRSRPCodec binds the complete source value type.
var ValueRSRPCodec func() ValueRSRPValueCodec = q8.ValueRSRPCodec

// ValueRSRPValueCodec is the concrete ValueCodec[ValueRSRP].
type ValueRSRPValueCodec = q31.ValueRSRPValueCodec

// ValueRSRQ represents the ASN.1 type ValueRSRQ (INTEGER).
type ValueRSRQ = q14.ValueRSRQ

// ValueRSRQAPERValue is the concrete APERValue[ValueRSRQ].
type ValueRSRQAPERValue = q31.ValueRSRQAPERValue

// ValueRSRQCodec binds the complete source value type.
var ValueRSRQCodec func() ValueRSRQValueCodec = q8.ValueRSRQCodec

// ValueRSRQValueCodec is the concrete ValueCodec[ValueRSRQ].
type ValueRSRQValueCodec = q31.ValueRSRQValueCodec

// WLANBand represents the ASN.1 ENUMERATED type WLANBand.
type WLANBand = q14.WLANBand

// WLANBandAPERValue is the concrete APERValue[WLANBand].
type WLANBandAPERValue = q31.WLANBandAPERValue

const WLANBandBand2dot4 = q14.WLANBandBand2dot4
const WLANBandBand5 = q14.WLANBandBand5

// WLANBandCodec binds the complete source value type.
var WLANBandCodec func() WLANBandValueCodec = q8.WLANBandCodec

// WLANBandValueCodec is the concrete ValueCodec[WLANBand].
type WLANBandValueCodec = q31.WLANBandValueCodec

// WLANChannel represents the ASN.1 type WLANChannel (INTEGER).
type WLANChannel = q14.WLANChannel

// WLANChannelAPERValue is the concrete APERValue[WLANChannel].
type WLANChannelAPERValue = q31.WLANChannelAPERValue

// WLANChannelCodec binds the complete source value type.
var WLANChannelCodec func() WLANChannelValueCodec = q25.WLANChannelCodec

type WLANChannelList = q14.WLANChannelList

// WLANChannelListAPERValue is the concrete APERValue[WLANChannelList].
type WLANChannelListAPERValue = q31.WLANChannelListAPERValue

// WLANChannelListCodec binds the complete source value type.
var WLANChannelListCodec func() WLANChannelListValueCodec = q21.WLANChannelListCodec

// WLANChannelListComplete carries a complete WLANChannelList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANChannelListComplete = q21.WLANChannelListComplete

// WLANChannelListValueCodec is the concrete ValueCodec[WLANChannelList].
type WLANChannelListValueCodec = q31.WLANChannelListValueCodec

// WLANChannelValueCodec is the concrete ValueCodec[WLANChannel].
type WLANChannelValueCodec = q31.WLANChannelValueCodec

// WLANCountryCode represents the ASN.1 ENUMERATED type WLANCountryCode.
type WLANCountryCode = q14.WLANCountryCode

// WLANCountryCodeAPERValue is the concrete APERValue[WLANCountryCode].
type WLANCountryCodeAPERValue = q31.WLANCountryCodeAPERValue

// WLANCountryCodeCodec binds the complete source value type.
var WLANCountryCodeCodec func() WLANCountryCodeValueCodec = q8.WLANCountryCodeCodec

const WLANCountryCodeEurope = q14.WLANCountryCodeEurope
const WLANCountryCodeGlobal = q14.WLANCountryCodeGlobal
const WLANCountryCodeJapan = q14.WLANCountryCodeJapan
const WLANCountryCodeUnitedStates = q14.WLANCountryCodeUnitedStates

// WLANCountryCodeValueCodec is the concrete ValueCodec[WLANCountryCode].
type WLANCountryCodeValueCodec = q9.WLANCountryCodeValueCodec
type WLANMeasurementQuantities = q21.WLANMeasurementQuantities

// WLANMeasurementQuantitiesAPERValue is the concrete APERValue[WLANMeasurementQuantities].
type WLANMeasurementQuantitiesAPERValue = q21.WLANMeasurementQuantitiesAPERValue

// WLANMeasurementQuantitiesCodec binds the complete APER value type.
var WLANMeasurementQuantitiesCodec func() WLANMeasurementQuantitiesConcreteValueCodec = q12.WLANMeasurementQuantitiesCodec

// WLANMeasurementQuantitiesComplete carries a complete WLANMeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasurementQuantitiesComplete = q21.WLANMeasurementQuantitiesComplete

// WLANMeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[WLANMeasurementQuantities].
type WLANMeasurementQuantitiesConcreteValueCodec = q21.WLANMeasurementQuantitiesConcreteValueCodec

// WLANMeasurementQuantitiesItem represents the ASN.1 type WLANMeasurementQuantities-Item (SEQUENCE).
type WLANMeasurementQuantitiesItem = q21.WLANMeasurementQuantitiesItem

// WLANMeasurementQuantitiesItemAPERValue is the concrete APERValue[WLANMeasurementQuantitiesItem].
type WLANMeasurementQuantitiesItemAPERValue = q21.WLANMeasurementQuantitiesItemAPERValue

// WLANMeasurementQuantitiesItemCodec binds the complete APER value type.
var WLANMeasurementQuantitiesItemCodec func() WLANMeasurementQuantitiesItemValueCodec = q21.WLANMeasurementQuantitiesItemCodec

// WLANMeasurementQuantitiesItemIEContainer is the concrete ProtocolIEContainer[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEContainer = q21.WLANMeasurementQuantitiesItemIEContainer

// WLANMeasurementQuantitiesItemIEField is the concrete ProtocolIEField[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEField = q21.WLANMeasurementQuantitiesItemIEField
type WLANMeasurementQuantitiesItemIETable = q21.WLANMeasurementQuantitiesItemIETable
type WLANMeasurementQuantitiesItemIEValue = q21.WLANMeasurementQuantitiesItemIEValue

// WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer = q21.WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer

var WLANMeasurementQuantitiesItemIEs func() WLANMeasurementQuantitiesItemIETable = q21.WLANMeasurementQuantitiesItemIEs

// WLANMeasurementQuantitiesItemValueCodec is the concrete ValueCodec[WLANMeasurementQuantitiesItem].
type WLANMeasurementQuantitiesItemValueCodec = q21.WLANMeasurementQuantitiesItemValueCodec

// WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding is the concrete IEBinding[WLANMeasurementQuantitiesItem, WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding = q21.WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding

// WLANMeasurementQuantitiesValue represents the ASN.1 ENUMERATED type WLANMeasurementQuantitiesValue.
type WLANMeasurementQuantitiesValue = q14.WLANMeasurementQuantitiesValue

// WLANMeasurementQuantitiesValueAPERValue is the concrete APERValue[WLANMeasurementQuantitiesValue].
type WLANMeasurementQuantitiesValueAPERValue = q9.WLANMeasurementQuantitiesValueAPERValue

// WLANMeasurementQuantitiesValueCodec binds the complete source value type.
var WLANMeasurementQuantitiesValueCodec func() WLANMeasurementQuantitiesValueValueCodec = q8.WLANMeasurementQuantitiesValueCodec

type WLANMeasurementQuantitiesValueExtIETable = q25.WLANMeasurementQuantitiesValueExtIETable

var WLANMeasurementQuantitiesValueExtIEs func() WLANMeasurementQuantitiesValueExtIETable = q25.WLANMeasurementQuantitiesValueExtIEs

// WLANMeasurementQuantitiesValueExtIEsExtContainer is the concrete ProtocolExtensionContainer[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsExtContainer = q25.WLANMeasurementQuantitiesValueExtIEsExtContainer

// WLANMeasurementQuantitiesValueExtIEsExtField is the concrete ProtocolExtensionField[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsExtField = q25.WLANMeasurementQuantitiesValueExtIEsExtField

// WLANMeasurementQuantitiesValueExtIEsIEContainer is the concrete ProtocolIEContainer[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsIEContainer = q25.WLANMeasurementQuantitiesValueExtIEsIEContainer

// WLANMeasurementQuantitiesValueExtIEsIEField is the concrete ProtocolIEField[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsIEField = q25.WLANMeasurementQuantitiesValueExtIEsIEField
type WLANMeasurementQuantitiesValueExtIEsValue = q8.WLANMeasurementQuantitiesValueExtIEsValue

// WLANMeasurementQuantitiesValueValueCodec is the concrete ValueCodec[WLANMeasurementQuantitiesValue].
type WLANMeasurementQuantitiesValueValueCodec = q9.WLANMeasurementQuantitiesValueValueCodec

const WLANMeasurementQuantitiesValueWlan = q14.WLANMeasurementQuantitiesValueWlan

type WLANMeasurementResult = q17.WLANMeasurementResult

// WLANMeasurementResultAPERValue is the concrete APERValue[WLANMeasurementResult].
type WLANMeasurementResultAPERValue = q17.WLANMeasurementResultAPERValue

// WLANMeasurementResultCodec binds the complete APER value type.
var WLANMeasurementResultCodec func() WLANMeasurementResultValueCodec = q17.WLANMeasurementResultCodec

// WLANMeasurementResultComplete carries a complete WLANMeasurementResult encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasurementResultComplete = q17.WLANMeasurementResultComplete

// WLANMeasurementResultItem represents the ASN.1 type WLANMeasurementResult-Item (SEQUENCE).
type WLANMeasurementResultItem = q17.WLANMeasurementResultItem

// WLANMeasurementResultItemAPERValue is the concrete APERValue[WLANMeasurementResultItem].
type WLANMeasurementResultItemAPERValue = q17.WLANMeasurementResultItemAPERValue

// WLANMeasurementResultItemCodec binds the complete source value type.
var WLANMeasurementResultItemCodec func() WLANMeasurementResultItemValueCodec = q17.WLANMeasurementResultItemCodec

type WLANMeasurementResultItemExtIETable = q25.WLANMeasurementResultItemExtIETable

var WLANMeasurementResultItemExtIEs func() WLANMeasurementResultItemExtIETable = q25.WLANMeasurementResultItemExtIEs

// WLANMeasurementResultItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsExtContainer = q25.WLANMeasurementResultItemExtIEsExtContainer

// WLANMeasurementResultItemExtIEsExtField is the concrete ProtocolExtensionField[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsExtField = q25.WLANMeasurementResultItemExtIEsExtField

// WLANMeasurementResultItemExtIEsIEContainer is the concrete ProtocolIEContainer[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsIEContainer = q25.WLANMeasurementResultItemExtIEsIEContainer

// WLANMeasurementResultItemExtIEsIEField is the concrete ProtocolIEField[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsIEField = q25.WLANMeasurementResultItemExtIEsIEField
type WLANMeasurementResultItemExtIEsValue = q8.WLANMeasurementResultItemExtIEsValue

// WLANMeasurementResultItemValueCodec is the concrete ValueCodec[WLANMeasurementResultItem].
type WLANMeasurementResultItemValueCodec = q17.WLANMeasurementResultItemValueCodec

// WLANMeasurementResultValueCodec is the concrete ValueCodec[WLANMeasurementResult].
type WLANMeasurementResultValueCodec = q17.WLANMeasurementResultValueCodec

// WLANOperatingClass represents the ASN.1 type WLANOperatingClass (INTEGER).
type WLANOperatingClass = q14.WLANOperatingClass

// WLANOperatingClassAPERValue is the concrete APERValue[WLANOperatingClass].
type WLANOperatingClassAPERValue = q9.WLANOperatingClassAPERValue

// WLANOperatingClassCodec binds the complete source value type.
var WLANOperatingClassCodec func() WLANOperatingClassValueCodec = q25.WLANOperatingClassCodec

// WLANOperatingClassValueCodec is the concrete ValueCodec[WLANOperatingClass].
type WLANOperatingClassValueCodec = q9.WLANOperatingClassValueCodec

// WLANRSSI represents the ASN.1 type WLAN-RSSI (INTEGER).
type WLANRSSI = q14.WLANRSSI

// WLANRSSIAPERValue is the concrete APERValue[WLANRSSI].
type WLANRSSIAPERValue = q9.WLANRSSIAPERValue

// WLANRSSICodec binds the complete source value type.
var WLANRSSICodec func() WLANRSSIValueCodec = q8.WLANRSSICodec

// WLANRSSIValueCodec is the concrete ValueCodec[WLANRSSI].
type WLANRSSIValueCodec = q9.WLANRSSIValueCodec

const WrongCriticality = q14.WrongCriticality
const WrongOrder = q14.WrongOrder
