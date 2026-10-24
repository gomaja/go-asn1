// Code generated from the pinned LPPa source closure. DO NOT EDIT.

package lppa

import (
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s22"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s24"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"math/big"
)

type APERValue[T any] = s23.APERValue[T]
type AddOTDOACellInformation = s15.AddOTDOACellInformation

// AddOTDOACellInformationAPERValue is the concrete APERValue[AddOTDOACellInformation].
type AddOTDOACellInformationAPERValue = s15.AddOTDOACellInformationAPERValue

// AddOTDOACellInformationCodec binds the complete source value type.
var AddOTDOACellInformationCodec func() AddOTDOACellInformationValueCodec = s17.AddOTDOACellInformationCodec

// AddOTDOACellInformationComplete carries a complete AddOTDOACellInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AddOTDOACellInformationComplete = s17.AddOTDOACellInformationComplete

// AddOTDOACellInformationValueCodec is the concrete ValueCodec[AddOTDOACellInformation].
type AddOTDOACellInformationValueCodec = s15.AddOTDOACellInformationValueCodec
type AddOTDOACells = s15.AddOTDOACells

// AddOTDOACellsAPERValue is the concrete APERValue[AddOTDOACells].
type AddOTDOACellsAPERValue = s15.AddOTDOACellsAPERValue

// AddOTDOACellsCodec binds the complete APER value type.
var AddOTDOACellsCodec func() AddOTDOACellsValueCodec = s18.AddOTDOACellsCodec

// AddOTDOACellsComplete carries a complete AddOTDOACells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AddOTDOACellsComplete = s17.AddOTDOACellsComplete

// AddOTDOACellsElem represents the ASN.1 type Add-OTDOACells-Elem (SEQUENCE).
type AddOTDOACellsElem = s15.AddOTDOACellsElem

// AddOTDOACellsElemAPERValue is the concrete APERValue[AddOTDOACellsElem].
type AddOTDOACellsElemAPERValue = s15.AddOTDOACellsElemAPERValue

// AddOTDOACellsElemCodec binds the complete source value type.
var AddOTDOACellsElemCodec func() AddOTDOACellsElemValueCodec = s15.AddOTDOACellsElemCodec

// AddOTDOACellsElemValueCodec is the concrete ValueCodec[AddOTDOACellsElem].
type AddOTDOACellsElemValueCodec = s15.AddOTDOACellsElemValueCodec
type AddOTDOACellsExtIETable = s03.AddOTDOACellsExtIETable

var AddOTDOACellsExtIEs func() AddOTDOACellsExtIETable = s03.AddOTDOACellsExtIEs

// AddOTDOACellsExtIEsExtContainer is the concrete ProtocolExtensionContainer[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsExtContainer = s03.AddOTDOACellsExtIEsExtContainer

// AddOTDOACellsExtIEsExtField is the concrete ProtocolExtensionField[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsExtField = s03.AddOTDOACellsExtIEsExtField

// AddOTDOACellsExtIEsIEContainer is the concrete ProtocolIEContainer[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsIEContainer = s03.AddOTDOACellsExtIEsIEContainer

// AddOTDOACellsExtIEsIEField is the concrete ProtocolIEField[AddOTDOACellsExtIEsValue].
type AddOTDOACellsExtIEsIEField = s03.AddOTDOACellsExtIEsIEField
type AddOTDOACellsExtIEsValue = s02.AddOTDOACellsExtIEsValue

// AddOTDOACellsValueCodec is the concrete ValueCodec[AddOTDOACells].
type AddOTDOACellsValueCodec = s15.AddOTDOACellsValueCodec

// AssistanceInformation represents the ASN.1 type Assistance-Information (SEQUENCE).
type AssistanceInformation = s14.AssistanceInformation

// AssistanceInformationAPERValue is the concrete APERValue[AssistanceInformation].
type AssistanceInformationAPERValue = s14.AssistanceInformationAPERValue

// AssistanceInformationCodec binds the complete APER value type.
var AssistanceInformationCodec func() AssistanceInformationValueCodec = s14.AssistanceInformationCodec

// AssistanceInformationControl represents the ASN.1 type AssistanceInformationControl (SEQUENCE).
type AssistanceInformationControl = s15.AssistanceInformationControl

// AssistanceInformationControlAPERValue is the concrete APERValue[AssistanceInformationControl].
type AssistanceInformationControlAPERValue = s15.AssistanceInformationControlAPERValue

// AssistanceInformationControlAssistanceInformationIEBinding is the concrete IEBinding[AssistanceInformation, AssistanceInformationControlIEValue].
type AssistanceInformationControlAssistanceInformationIEBinding = s14.AssistanceInformationControlAssistanceInformationIEBinding

// AssistanceInformationControlBroadcastIEBinding is the concrete IEBinding[Broadcast, AssistanceInformationControlIEValue].
type AssistanceInformationControlBroadcastIEBinding = s14.AssistanceInformationControlBroadcastIEBinding

// AssistanceInformationControlCodec binds the complete APER value type.
var AssistanceInformationControlCodec func() AssistanceInformationControlValueCodec = s24.AssistanceInformationControlCodec

type AssistanceInformationControlDescriptor = s24.AssistanceInformationControlDescriptor

// AssistanceInformationControlIEContainer is the concrete ProtocolIEContainer[AssistanceInformationControlIEValue].
type AssistanceInformationControlIEContainer = s14.AssistanceInformationControlIEContainer

// AssistanceInformationControlIEField is the concrete ProtocolIEField[AssistanceInformationControlIEValue].
type AssistanceInformationControlIEField = s14.AssistanceInformationControlIEField
type AssistanceInformationControlIETable = s14.AssistanceInformationControlIETable
type AssistanceInformationControlIEValue = s14.AssistanceInformationControlIEValue

var AssistanceInformationControlIEs func() AssistanceInformationControlIETable = s14.AssistanceInformationControlIEs

// AssistanceInformationControlInitiatingBinding is the concrete InitiatingBinding[AssistanceInformationControl].
type AssistanceInformationControlInitiatingBinding = s21.AssistanceInformationControlInitiatingBinding

var AssistanceInformationControlProcedure func() AssistanceInformationControlDescriptor = s24.AssistanceInformationControlProcedure

// AssistanceInformationControlValueCodec is the concrete ValueCodec[AssistanceInformationControl].
type AssistanceInformationControlValueCodec = s15.AssistanceInformationControlValueCodec
type AssistanceInformationExtIETable = s03.AssistanceInformationExtIETable

var AssistanceInformationExtIEs func() AssistanceInformationExtIETable = s03.AssistanceInformationExtIEs

// AssistanceInformationExtIEsExtContainer is the concrete ProtocolExtensionContainer[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsExtContainer = s03.AssistanceInformationExtIEsExtContainer

// AssistanceInformationExtIEsExtField is the concrete ProtocolExtensionField[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsExtField = s03.AssistanceInformationExtIEsExtField

// AssistanceInformationExtIEsIEContainer is the concrete ProtocolIEContainer[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsIEContainer = s03.AssistanceInformationExtIEsIEContainer

// AssistanceInformationExtIEsIEField is the concrete ProtocolIEField[AssistanceInformationExtIEsValue].
type AssistanceInformationExtIEsIEField = s03.AssistanceInformationExtIEsIEField
type AssistanceInformationExtIEsValue = s02.AssistanceInformationExtIEsValue
type AssistanceInformationFailureList = s05.AssistanceInformationFailureList

// AssistanceInformationFailureListAPERValue is the concrete APERValue[AssistanceInformationFailureList].
type AssistanceInformationFailureListAPERValue = s05.AssistanceInformationFailureListAPERValue

// AssistanceInformationFailureListCodec binds the complete APER value type.
var AssistanceInformationFailureListCodec func() AssistanceInformationFailureListValueCodec = s17.AssistanceInformationFailureListCodec

// AssistanceInformationFailureListComplete carries a complete AssistanceInformationFailureList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AssistanceInformationFailureListComplete = s17.AssistanceInformationFailureListComplete

// AssistanceInformationFailureListElem represents the ASN.1 type AssistanceInformationFailureList-Elem (SEQUENCE).
type AssistanceInformationFailureListElem = s05.AssistanceInformationFailureListElem

// AssistanceInformationFailureListElemAPERValue is the concrete APERValue[AssistanceInformationFailureListElem].
type AssistanceInformationFailureListElemAPERValue = s05.AssistanceInformationFailureListElemAPERValue

// AssistanceInformationFailureListElemCodec binds the complete source value type.
var AssistanceInformationFailureListElemCodec func() AssistanceInformationFailureListElemValueCodec = s05.AssistanceInformationFailureListElemCodec

// AssistanceInformationFailureListElemValueCodec is the concrete ValueCodec[AssistanceInformationFailureListElem].
type AssistanceInformationFailureListElemValueCodec = s05.AssistanceInformationFailureListElemValueCodec
type AssistanceInformationFailureListExtIETable = s03.AssistanceInformationFailureListExtIETable

var AssistanceInformationFailureListExtIEs func() AssistanceInformationFailureListExtIETable = s03.AssistanceInformationFailureListExtIEs

// AssistanceInformationFailureListExtIEsExtContainer is the concrete ProtocolExtensionContainer[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsExtContainer = s03.AssistanceInformationFailureListExtIEsExtContainer

// AssistanceInformationFailureListExtIEsExtField is the concrete ProtocolExtensionField[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsExtField = s03.AssistanceInformationFailureListExtIEsExtField

// AssistanceInformationFailureListExtIEsIEContainer is the concrete ProtocolIEContainer[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsIEContainer = s03.AssistanceInformationFailureListExtIEsIEContainer

// AssistanceInformationFailureListExtIEsIEField is the concrete ProtocolIEField[AssistanceInformationFailureListExtIEsValue].
type AssistanceInformationFailureListExtIEsIEField = s03.AssistanceInformationFailureListExtIEsIEField
type AssistanceInformationFailureListExtIEsValue = s02.AssistanceInformationFailureListExtIEsValue

// AssistanceInformationFailureListValueCodec is the concrete ValueCodec[AssistanceInformationFailureList].
type AssistanceInformationFailureListValueCodec = s05.AssistanceInformationFailureListValueCodec

// AssistanceInformationFeedback represents the ASN.1 type AssistanceInformationFeedback (SEQUENCE).
type AssistanceInformationFeedback = s17.AssistanceInformationFeedback

// AssistanceInformationFeedbackAPERValue is the concrete APERValue[AssistanceInformationFeedback].
type AssistanceInformationFeedbackAPERValue = s17.AssistanceInformationFeedbackAPERValue

// AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding is the concrete IEBinding[AssistanceInformationFailureList, AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding = s17.AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding

// AssistanceInformationFeedbackCodec binds the complete APER value type.
var AssistanceInformationFeedbackCodec func() AssistanceInformationFeedbackValueCodec = s23.AssistanceInformationFeedbackCodec

// AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding = s17.AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding
type AssistanceInformationFeedbackDescriptor = s23.AssistanceInformationFeedbackDescriptor

// AssistanceInformationFeedbackIEContainer is the concrete ProtocolIEContainer[AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackIEContainer = s17.AssistanceInformationFeedbackIEContainer

// AssistanceInformationFeedbackIEField is the concrete ProtocolIEField[AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackIEField = s17.AssistanceInformationFeedbackIEField
type AssistanceInformationFeedbackIETable = s17.AssistanceInformationFeedbackIETable
type AssistanceInformationFeedbackIEValue = s17.AssistanceInformationFeedbackIEValue

var AssistanceInformationFeedbackIEs func() AssistanceInformationFeedbackIETable = s17.AssistanceInformationFeedbackIEs

// AssistanceInformationFeedbackInitiatingBinding is the concrete InitiatingBinding[AssistanceInformationFeedback].
type AssistanceInformationFeedbackInitiatingBinding = s21.AssistanceInformationFeedbackInitiatingBinding

var AssistanceInformationFeedbackProcedure func() AssistanceInformationFeedbackDescriptor = s23.AssistanceInformationFeedbackProcedure

// AssistanceInformationFeedbackValueCodec is the concrete ValueCodec[AssistanceInformationFeedback].
type AssistanceInformationFeedbackValueCodec = s17.AssistanceInformationFeedbackValueCodec

// AssistanceInformationMetaData represents the ASN.1 type AssistanceInformationMetaData (SEQUENCE).
type AssistanceInformationMetaData = s05.AssistanceInformationMetaData

// AssistanceInformationMetaDataAPERValue is the concrete APERValue[AssistanceInformationMetaData].
type AssistanceInformationMetaDataAPERValue = s05.AssistanceInformationMetaDataAPERValue

// AssistanceInformationMetaDataCodec binds the complete source value type.
var AssistanceInformationMetaDataCodec func() AssistanceInformationMetaDataValueCodec = s05.AssistanceInformationMetaDataCodec

type AssistanceInformationMetaDataExtIETable = s03.AssistanceInformationMetaDataExtIETable

var AssistanceInformationMetaDataExtIEs func() AssistanceInformationMetaDataExtIETable = s03.AssistanceInformationMetaDataExtIEs

// AssistanceInformationMetaDataExtIEsExtContainer is the concrete ProtocolExtensionContainer[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsExtContainer = s03.AssistanceInformationMetaDataExtIEsExtContainer

// AssistanceInformationMetaDataExtIEsExtField is the concrete ProtocolExtensionField[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsExtField = s03.AssistanceInformationMetaDataExtIEsExtField

// AssistanceInformationMetaDataExtIEsIEContainer is the concrete ProtocolIEContainer[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsIEContainer = s03.AssistanceInformationMetaDataExtIEsIEContainer

// AssistanceInformationMetaDataExtIEsIEField is the concrete ProtocolIEField[AssistanceInformationMetaDataExtIEsValue].
type AssistanceInformationMetaDataExtIEsIEField = s03.AssistanceInformationMetaDataExtIEsIEField
type AssistanceInformationMetaDataExtIEsValue = s02.AssistanceInformationMetaDataExtIEsValue

// AssistanceInformationMetaDataValueCodec is the concrete ValueCodec[AssistanceInformationMetaData].
type AssistanceInformationMetaDataValueCodec = s05.AssistanceInformationMetaDataValueCodec

// AssistanceInformationValueCodec is the concrete ValueCodec[AssistanceInformation].
type AssistanceInformationValueCodec = s14.AssistanceInformationValueCodec

// BCCH represents the ASN.1 type BCCH (INTEGER).
type BCCH = s00.BCCH

// BCCHAPERValue is the concrete APERValue[BCCH].
type BCCHAPERValue = s00.BCCHAPERValue

// BCCHCodec binds the complete source value type.
var BCCHCodec func() BCCHValueCodec = s02.BCCHCodec

// BCCHValueCodec is the concrete ValueCodec[BCCH].
type BCCHValueCodec = s00.BCCHValueCodec

// BSSID represents the ASN.1 type BSSID (OCTET_STRING).
type BSSID = s00.BSSID

// BSSIDAPERValue is the concrete APERValue[BSSID].
type BSSIDAPERValue = s00.BSSIDAPERValue

// BSSIDCodec binds the complete source value type.
var BSSIDCodec func() BSSIDValueCodec = s02.BSSIDCodec

// BSSIDValueCodec is the concrete ValueCodec[BSSID].
type BSSIDValueCodec = s00.BSSIDValueCodec

// BitmapsforNPRS represents the ASN.1 CHOICE type BitmapsforNPRS.
type BitmapsforNPRS = s05.BitmapsforNPRS

// BitmapsforNPRSAPERValue is the concrete APERValue[BitmapsforNPRS].
type BitmapsforNPRSAPERValue = s05.BitmapsforNPRSAPERValue

// BitmapsforNPRS choice constants.
const BitmapsforNPRSChoiceForty = s00.BitmapsforNPRSChoiceForty

// BitmapsforNPRS choice constants.
const BitmapsforNPRSChoiceFortyTdd = s00.BitmapsforNPRSChoiceFortyTdd

// BitmapsforNPRS choice constants.
const BitmapsforNPRSChoiceTen = s00.BitmapsforNPRSChoiceTen

// BitmapsforNPRS choice constants.
const BitmapsforNPRSChoiceTenTdd = s00.BitmapsforNPRSChoiceTenTdd

// BitmapsforNPRSCodec binds the complete source value type.
var BitmapsforNPRSCodec func() BitmapsforNPRSValueCodec = s05.BitmapsforNPRSCodec

// BitmapsforNPRSValueCodec is the concrete ValueCodec[BitmapsforNPRS].
type BitmapsforNPRSValueCodec = s05.BitmapsforNPRSValueCodec

// Broadcast represents the ASN.1 ENUMERATED type Broadcast.
type Broadcast = s00.Broadcast

// BroadcastAPERValue is the concrete APERValue[Broadcast].
type BroadcastAPERValue = s00.BroadcastAPERValue

// BroadcastCodec binds the complete APER value type.
var BroadcastCodec func() BroadcastValueCodec = s14.BroadcastCodec

// BroadcastPeriodicity represents the ASN.1 ENUMERATED type BroadcastPeriodicity.
type BroadcastPeriodicity = s00.BroadcastPeriodicity

// BroadcastPeriodicityAPERValue is the concrete APERValue[BroadcastPeriodicity].
type BroadcastPeriodicityAPERValue = s00.BroadcastPeriodicityAPERValue

// BroadcastPeriodicityCodec binds the complete source value type.
var BroadcastPeriodicityCodec func() BroadcastPeriodicityValueCodec = s02.BroadcastPeriodicityCodec

const BroadcastPeriodicityMs1280 = s00.BroadcastPeriodicityMs1280
const BroadcastPeriodicityMs160 = s00.BroadcastPeriodicityMs160
const BroadcastPeriodicityMs2560 = s00.BroadcastPeriodicityMs2560
const BroadcastPeriodicityMs320 = s00.BroadcastPeriodicityMs320
const BroadcastPeriodicityMs5120 = s00.BroadcastPeriodicityMs5120
const BroadcastPeriodicityMs640 = s00.BroadcastPeriodicityMs640
const BroadcastPeriodicityMs80 = s00.BroadcastPeriodicityMs80

// BroadcastPeriodicityValueCodec is the concrete ValueCodec[BroadcastPeriodicity].
type BroadcastPeriodicityValueCodec = s00.BroadcastPeriodicityValueCodec

const BroadcastStart = s00.BroadcastStart
const BroadcastStop = s00.BroadcastStop

// BroadcastValueCodec is the concrete ValueCodec[Broadcast].
type BroadcastValueCodec = s00.BroadcastValueCodec
type BuildError = s09.BuildError

// CPLength represents the ASN.1 ENUMERATED type CPLength.
type CPLength = s00.CPLength

// CPLengthAPERValue is the concrete APERValue[CPLength].
type CPLengthAPERValue = s00.CPLengthAPERValue

// CPLengthCodec binds the complete source value type.
var CPLengthCodec func() CPLengthValueCodec = s02.CPLengthCodec

const CPLengthExtended = s00.CPLengthExtended
const CPLengthNormal = s00.CPLengthNormal

// CPLengthValueCodec is the concrete ValueCodec[CPLength].
type CPLengthValueCodec = s00.CPLengthValueCodec

// Cause represents the ASN.1 CHOICE type Cause.
type Cause = s05.Cause

// CauseAPERValue is the concrete APERValue[Cause].
type CauseAPERValue = s05.CauseAPERValue

// Cause choice constants.
const CauseChoiceMisc = s00.CauseChoiceMisc

// Cause choice constants.
const CauseChoiceProtocol = s00.CauseChoiceProtocol

// Cause choice constants.
const CauseChoiceRadioNetwork = s00.CauseChoiceRadioNetwork

// CauseCodec binds the complete APER value type.
var CauseCodec func() CauseValueCodec = s06.CauseCodec

// CauseMisc represents the ASN.1 ENUMERATED type CauseMisc.
type CauseMisc = s00.CauseMisc

// CauseMiscAPERValue is the concrete APERValue[CauseMisc].
type CauseMiscAPERValue = s00.CauseMiscAPERValue

// CauseMiscCodec binds the complete source value type.
var CauseMiscCodec func() CauseMiscValueCodec = s02.CauseMiscCodec

const CauseMiscUnspecified = s00.CauseMiscUnspecified

// CauseMiscValueCodec is the concrete ValueCodec[CauseMisc].
type CauseMiscValueCodec = s00.CauseMiscValueCodec

// CauseProtocol represents the ASN.1 ENUMERATED type CauseProtocol.
type CauseProtocol = s00.CauseProtocol

// CauseProtocolAPERValue is the concrete APERValue[CauseProtocol].
type CauseProtocolAPERValue = s00.CauseProtocolAPERValue

const CauseProtocolAbstractSyntaxErrorFalselyConstructedMessage = s00.CauseProtocolAbstractSyntaxErrorFalselyConstructedMessage
const CauseProtocolAbstractSyntaxErrorIgnoreAndNotify = s00.CauseProtocolAbstractSyntaxErrorIgnoreAndNotify
const CauseProtocolAbstractSyntaxErrorReject = s00.CauseProtocolAbstractSyntaxErrorReject

// CauseProtocolCodec binds the complete source value type.
var CauseProtocolCodec func() CauseProtocolValueCodec = s02.CauseProtocolCodec

const CauseProtocolMessageNotCompatibleWithReceiverState = s00.CauseProtocolMessageNotCompatibleWithReceiverState
const CauseProtocolSemanticError = s00.CauseProtocolSemanticError
const CauseProtocolTransferSyntaxError = s00.CauseProtocolTransferSyntaxError
const CauseProtocolUnspecified = s00.CauseProtocolUnspecified

// CauseProtocolValueCodec is the concrete ValueCodec[CauseProtocol].
type CauseProtocolValueCodec = s00.CauseProtocolValueCodec

// CauseRadioNetwork represents the ASN.1 ENUMERATED type CauseRadioNetwork.
type CauseRadioNetwork = s00.CauseRadioNetwork

// CauseRadioNetworkAPERValue is the concrete APERValue[CauseRadioNetwork].
type CauseRadioNetworkAPERValue = s00.CauseRadioNetworkAPERValue

// CauseRadioNetworkCodec binds the complete source value type.
var CauseRadioNetworkCodec func() CauseRadioNetworkValueCodec = s02.CauseRadioNetworkCodec

const CauseRadioNetworkRequestedItemNotSupported = s00.CauseRadioNetworkRequestedItemNotSupported
const CauseRadioNetworkRequestedItemTemporarilyNotAvailable = s00.CauseRadioNetworkRequestedItemTemporarilyNotAvailable
const CauseRadioNetworkUnspecified = s00.CauseRadioNetworkUnspecified

// CauseRadioNetworkValueCodec is the concrete ValueCodec[CauseRadioNetwork].
type CauseRadioNetworkValueCodec = s00.CauseRadioNetworkValueCodec

// CauseValueCodec is the concrete ValueCodec[Cause].
type CauseValueCodec = s05.CauseValueCodec

// CellPortionID represents the ASN.1 type Cell-Portion-ID (INTEGER).
type CellPortionID = s00.CellPortionID

// CellPortionIDAPERValue is the concrete APERValue[CellPortionID].
type CellPortionIDAPERValue = s00.CellPortionIDAPERValue

// CellPortionIDCodec binds the complete APER value type.
var CellPortionIDCodec func() CellPortionIDValueCodec = s22.CellPortionIDCodec

// CellPortionIDValueCodec is the concrete ValueCodec[CellPortionID].
type CellPortionIDValueCodec = s00.CellPortionIDValueCodec

// Criticality represents the ASN.1 ENUMERATED type Criticality.
type Criticality = s00.Criticality

// CriticalityAPERValue is the concrete APERValue[Criticality].
type CriticalityAPERValue = s00.CriticalityAPERValue

// CriticalityCodec binds the complete source value type.
var CriticalityCodec func() CriticalityValueCodec = s02.CriticalityCodec

// CriticalityDiagnostics represents the ASN.1 type CriticalityDiagnostics (SEQUENCE).
type CriticalityDiagnostics = s09.CriticalityDiagnostics

// CriticalityDiagnosticsAPERValue is the concrete APERValue[CriticalityDiagnostics].
type CriticalityDiagnosticsAPERValue = s09.CriticalityDiagnosticsAPERValue

// CriticalityDiagnosticsCodec binds the complete APER value type.
var CriticalityDiagnosticsCodec func() CriticalityDiagnosticsValueCodec = s17.CriticalityDiagnosticsCodec

type CriticalityDiagnosticsExtIETable = s03.CriticalityDiagnosticsExtIETable

var CriticalityDiagnosticsExtIEs func() CriticalityDiagnosticsExtIETable = s03.CriticalityDiagnosticsExtIEs

// CriticalityDiagnosticsExtIEsExtContainer is the concrete ProtocolExtensionContainer[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsExtContainer = s03.CriticalityDiagnosticsExtIEsExtContainer

// CriticalityDiagnosticsExtIEsExtField is the concrete ProtocolExtensionField[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsExtField = s03.CriticalityDiagnosticsExtIEsExtField

// CriticalityDiagnosticsExtIEsIEContainer is the concrete ProtocolIEContainer[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsIEContainer = s03.CriticalityDiagnosticsExtIEsIEContainer

// CriticalityDiagnosticsExtIEsIEField is the concrete ProtocolIEField[CriticalityDiagnosticsExtIEsValue].
type CriticalityDiagnosticsExtIEsIEField = s03.CriticalityDiagnosticsExtIEsIEField
type CriticalityDiagnosticsExtIEsValue = s02.CriticalityDiagnosticsExtIEsValue
type CriticalityDiagnosticsIEList = s05.CriticalityDiagnosticsIEList

// CriticalityDiagnosticsIEListAPERValue is the concrete APERValue[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListAPERValue = s05.CriticalityDiagnosticsIEListAPERValue

// CriticalityDiagnosticsIEListCodec binds the complete source value type.
var CriticalityDiagnosticsIEListCodec func() CriticalityDiagnosticsIEListValueCodec = s17.CriticalityDiagnosticsIEListCodec

// CriticalityDiagnosticsIEListComplete carries a complete CriticalityDiagnosticsIEList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CriticalityDiagnosticsIEListComplete = s17.CriticalityDiagnosticsIEListComplete

// CriticalityDiagnosticsIEListElem represents the ASN.1 type CriticalityDiagnostics-IE-List-Elem (SEQUENCE).
type CriticalityDiagnosticsIEListElem = s05.CriticalityDiagnosticsIEListElem

// CriticalityDiagnosticsIEListElemAPERValue is the concrete APERValue[CriticalityDiagnosticsIEListElem].
type CriticalityDiagnosticsIEListElemAPERValue = s05.CriticalityDiagnosticsIEListElemAPERValue

// CriticalityDiagnosticsIEListElemCodec binds the complete source value type.
var CriticalityDiagnosticsIEListElemCodec func() CriticalityDiagnosticsIEListElemValueCodec = s05.CriticalityDiagnosticsIEListElemCodec

// CriticalityDiagnosticsIEListElemValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEListElem].
type CriticalityDiagnosticsIEListElemValueCodec = s05.CriticalityDiagnosticsIEListElemValueCodec
type CriticalityDiagnosticsIEListExtIETable = s03.CriticalityDiagnosticsIEListExtIETable

var CriticalityDiagnosticsIEListExtIEs func() CriticalityDiagnosticsIEListExtIETable = s03.CriticalityDiagnosticsIEListExtIEs

// CriticalityDiagnosticsIEListExtIEsExtContainer is the concrete ProtocolExtensionContainer[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsExtContainer = s03.CriticalityDiagnosticsIEListExtIEsExtContainer

// CriticalityDiagnosticsIEListExtIEsExtField is the concrete ProtocolExtensionField[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsExtField = s03.CriticalityDiagnosticsIEListExtIEsExtField

// CriticalityDiagnosticsIEListExtIEsIEContainer is the concrete ProtocolIEContainer[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsIEContainer = s03.CriticalityDiagnosticsIEListExtIEsIEContainer

// CriticalityDiagnosticsIEListExtIEsIEField is the concrete ProtocolIEField[CriticalityDiagnosticsIEListExtIEsValue].
type CriticalityDiagnosticsIEListExtIEsIEField = s03.CriticalityDiagnosticsIEListExtIEsIEField
type CriticalityDiagnosticsIEListExtIEsValue = s02.CriticalityDiagnosticsIEListExtIEsValue

// CriticalityDiagnosticsIEListValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListValueCodec = s05.CriticalityDiagnosticsIEListValueCodec

// CriticalityDiagnosticsValueCodec is the concrete ValueCodec[CriticalityDiagnostics].
type CriticalityDiagnosticsValueCodec = s09.CriticalityDiagnosticsValueCodec

const CriticalityIgnore = s00.CriticalityIgnore
const CriticalityNotify = s00.CriticalityNotify
const CriticalityReject = s00.CriticalityReject

// CriticalityValueCodec is the concrete ValueCodec[Criticality].
type CriticalityValueCodec = s00.CriticalityValueCodec

// DLBandwidth represents the ASN.1 ENUMERATED type DL-Bandwidth.
type DLBandwidth = s00.DLBandwidth

// DLBandwidthAPERValue is the concrete APERValue[DLBandwidth].
type DLBandwidthAPERValue = s00.DLBandwidthAPERValue

const DLBandwidthBw100 = s00.DLBandwidthBw100
const DLBandwidthBw15 = s00.DLBandwidthBw15
const DLBandwidthBw25 = s00.DLBandwidthBw25
const DLBandwidthBw50 = s00.DLBandwidthBw50
const DLBandwidthBw6 = s00.DLBandwidthBw6
const DLBandwidthBw75 = s00.DLBandwidthBw75

// DLBandwidthCodec binds the complete source value type.
var DLBandwidthCodec func() DLBandwidthValueCodec = s02.DLBandwidthCodec

// DLBandwidthValueCodec is the concrete ValueCodec[DLBandwidth].
type DLBandwidthValueCodec = s00.DLBandwidthValueCodec
type DecodePayload[T any] = s23.DecodePayload[T]
type DeferredCondition = s00.DeferredCondition

// EARFCN represents the ASN.1 type EARFCN (INTEGER).
type EARFCN = s00.EARFCN

// EARFCNAPERValue is the concrete APERValue[EARFCN].
type EARFCNAPERValue = s00.EARFCNAPERValue

// EARFCNCodec binds the complete source value type.
var EARFCNCodec func() EARFCNValueCodec = s02.EARFCNCodec

// EARFCNValueCodec is the concrete ValueCodec[EARFCN].
type EARFCNValueCodec = s00.EARFCNValueCodec

// ECGI represents the ASN.1 type ECGI (SEQUENCE).
type ECGI = s05.ECGI

// ECGIAPERValue is the concrete APERValue[ECGI].
type ECGIAPERValue = s05.ECGIAPERValue

// ECGICodec binds the complete source value type.
var ECGICodec func() ECGIValueCodec = s05.ECGICodec

type ECGIExtIETable = s03.ECGIExtIETable

var ECGIExtIEs func() ECGIExtIETable = s03.ECGIExtIEs

// ECGIExtIEsExtContainer is the concrete ProtocolExtensionContainer[ECGIExtIEsValue].
type ECGIExtIEsExtContainer = s03.ECGIExtIEsExtContainer

// ECGIExtIEsExtField is the concrete ProtocolExtensionField[ECGIExtIEsValue].
type ECGIExtIEsExtField = s03.ECGIExtIEsExtField

// ECGIExtIEsIEContainer is the concrete ProtocolIEContainer[ECGIExtIEsValue].
type ECGIExtIEsIEContainer = s03.ECGIExtIEsIEContainer

// ECGIExtIEsIEField is the concrete ProtocolIEField[ECGIExtIEsValue].
type ECGIExtIEsIEField = s03.ECGIExtIEsIEField
type ECGIExtIEsValue = s02.ECGIExtIEsValue

// ECGIValueCodec is the concrete ValueCodec[ECGI].
type ECGIValueCodec = s05.ECGIValueCodec

// ECIDMeasurementFailureIndication represents the ASN.1 type E-CIDMeasurementFailureIndication (SEQUENCE).
type ECIDMeasurementFailureIndication = s11.ECIDMeasurementFailureIndication

// ECIDMeasurementFailureIndicationAPERValue is the concrete APERValue[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationAPERValue = s11.ECIDMeasurementFailureIndicationAPERValue

// ECIDMeasurementFailureIndicationCauseIEBinding is the concrete IEBinding[Cause, ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationCauseIEBinding = s06.ECIDMeasurementFailureIndicationCauseIEBinding

// ECIDMeasurementFailureIndicationCodec binds the complete APER value type.
var ECIDMeasurementFailureIndicationCodec func() ECIDMeasurementFailureIndicationValueCodec = s23.ECIDMeasurementFailureIndicationCodec

type ECIDMeasurementFailureIndicationDescriptor = s23.ECIDMeasurementFailureIndicationDescriptor

// ECIDMeasurementFailureIndicationIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationIEContainer = s06.ECIDMeasurementFailureIndicationIEContainer

// ECIDMeasurementFailureIndicationIEField is the concrete ProtocolIEField[ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationIEField = s06.ECIDMeasurementFailureIndicationIEField
type ECIDMeasurementFailureIndicationIETable = s06.ECIDMeasurementFailureIndicationIETable
type ECIDMeasurementFailureIndicationIEValue = s06.ECIDMeasurementFailureIndicationIEValue

var ECIDMeasurementFailureIndicationIEs func() ECIDMeasurementFailureIndicationIETable = s06.ECIDMeasurementFailureIndicationIEs

// ECIDMeasurementFailureIndicationInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationInitiatingBinding = s21.ECIDMeasurementFailureIndicationInitiatingBinding

// ECIDMeasurementFailureIndicationMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationMeasurementIDIEBinding = s06.ECIDMeasurementFailureIndicationMeasurementIDIEBinding

var ECIDMeasurementFailureIndicationProcedure func() ECIDMeasurementFailureIndicationDescriptor = s23.ECIDMeasurementFailureIndicationProcedure

// ECIDMeasurementFailureIndicationValueCodec is the concrete ValueCodec[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationValueCodec = s11.ECIDMeasurementFailureIndicationValueCodec
type ECIDMeasurementInitiationDescriptor = s24.ECIDMeasurementInitiationDescriptor

// ECIDMeasurementInitiationFailure represents the ASN.1 type E-CIDMeasurementInitiationFailure (SEQUENCE).
type ECIDMeasurementInitiationFailure = s11.ECIDMeasurementInitiationFailure

// ECIDMeasurementInitiationFailureAPERValue is the concrete APERValue[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureAPERValue = s11.ECIDMeasurementInitiationFailureAPERValue

// ECIDMeasurementInitiationFailureCauseIEBinding is the concrete IEBinding[Cause, ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureCauseIEBinding = s09.ECIDMeasurementInitiationFailureCauseIEBinding

// ECIDMeasurementInitiationFailureCodec binds the complete APER value type.
var ECIDMeasurementInitiationFailureCodec func() ECIDMeasurementInitiationFailureValueCodec = s24.ECIDMeasurementInitiationFailureCodec

// ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding = s09.ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding

// ECIDMeasurementInitiationFailureIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureIEContainer = s09.ECIDMeasurementInitiationFailureIEContainer

// ECIDMeasurementInitiationFailureIEField is the concrete ProtocolIEField[ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureIEField = s09.ECIDMeasurementInitiationFailureIEField
type ECIDMeasurementInitiationFailureIETable = s10.ECIDMeasurementInitiationFailureIETable
type ECIDMeasurementInitiationFailureIEValue = s09.ECIDMeasurementInitiationFailureIEValue

var ECIDMeasurementInitiationFailureIEs func() ECIDMeasurementInitiationFailureIETable = s10.ECIDMeasurementInitiationFailureIEs

// ECIDMeasurementInitiationFailureMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureMeasurementIDIEBinding = s10.ECIDMeasurementInitiationFailureMeasurementIDIEBinding

// ECIDMeasurementInitiationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureUnsuccessfulBinding = s16.ECIDMeasurementInitiationFailureUnsuccessfulBinding

// ECIDMeasurementInitiationFailureValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureValueCodec = s11.ECIDMeasurementInitiationFailureValueCodec

var ECIDMeasurementInitiationProcedure func() ECIDMeasurementInitiationDescriptor = s24.ECIDMeasurementInitiationProcedure

// ECIDMeasurementInitiationRequest represents the ASN.1 type E-CIDMeasurementInitiationRequest (SEQUENCE).
type ECIDMeasurementInitiationRequest = s21.ECIDMeasurementInitiationRequest

// ECIDMeasurementInitiationRequestAPERValue is the concrete APERValue[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestAPERValue = s21.ECIDMeasurementInitiationRequestAPERValue

// ECIDMeasurementInitiationRequestCodec binds the complete APER value type.
var ECIDMeasurementInitiationRequestCodec func() ECIDMeasurementInitiationRequestValueCodec = s24.ECIDMeasurementInitiationRequestCodec

// ECIDMeasurementInitiationRequestIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestIEContainer = s21.ECIDMeasurementInitiationRequestIEContainer

// ECIDMeasurementInitiationRequestIEField is the concrete ProtocolIEField[ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestIEField = s21.ECIDMeasurementInitiationRequestIEField
type ECIDMeasurementInitiationRequestIETable = s21.ECIDMeasurementInitiationRequestIETable
type ECIDMeasurementInitiationRequestIEValue = s20.ECIDMeasurementInitiationRequestIEValue

var ECIDMeasurementInitiationRequestIEs func() ECIDMeasurementInitiationRequestIETable = s21.ECIDMeasurementInitiationRequestIEs

// ECIDMeasurementInitiationRequestInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestInitiatingBinding = s21.ECIDMeasurementInitiationRequestInitiatingBinding

// ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding is the concrete IEBinding[InterRATMeasurementQuantities, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding = s21.ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding

// ECIDMeasurementInitiationRequestMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestMeasurementIDIEBinding = s21.ECIDMeasurementInitiationRequestMeasurementIDIEBinding

// ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding is the concrete IEBinding[MeasurementPeriodicity, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding = s21.ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding

// ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding is the concrete IEBinding[MeasurementQuantities, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding = s21.ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding

// ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding is the concrete IEBinding[ReportCharacteristics, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding = s21.ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding

// ECIDMeasurementInitiationRequestValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestValueCodec = s21.ECIDMeasurementInitiationRequestValueCodec

// ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding is the concrete IEBinding[WLANMeasurementQuantities, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding = s21.ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding

// ECIDMeasurementInitiationResponse represents the ASN.1 type E-CIDMeasurementInitiationResponse (SEQUENCE).
type ECIDMeasurementInitiationResponse = s22.ECIDMeasurementInitiationResponse

// ECIDMeasurementInitiationResponseAPERValue is the concrete APERValue[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseAPERValue = s22.ECIDMeasurementInitiationResponseAPERValue

// ECIDMeasurementInitiationResponseCellPortionIDIEBinding is the concrete IEBinding[CellPortionID, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseCellPortionIDIEBinding = s22.ECIDMeasurementInitiationResponseCellPortionIDIEBinding

// ECIDMeasurementInitiationResponseCodec binds the complete APER value type.
var ECIDMeasurementInitiationResponseCodec func() ECIDMeasurementInitiationResponseValueCodec = s24.ECIDMeasurementInitiationResponseCodec

// ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding = s22.ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding

// ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding is the concrete IEBinding[ECIDMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding = s22.ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding

// ECIDMeasurementInitiationResponseIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseIEContainer = s22.ECIDMeasurementInitiationResponseIEContainer

// ECIDMeasurementInitiationResponseIEField is the concrete ProtocolIEField[ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseIEField = s22.ECIDMeasurementInitiationResponseIEField
type ECIDMeasurementInitiationResponseIETable = s22.ECIDMeasurementInitiationResponseIETable
type ECIDMeasurementInitiationResponseIEValue = s22.ECIDMeasurementInitiationResponseIEValue

var ECIDMeasurementInitiationResponseIEs func() ECIDMeasurementInitiationResponseIETable = s22.ECIDMeasurementInitiationResponseIEs

// ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding is the concrete IEBinding[InterRATMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding = s22.ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding

// ECIDMeasurementInitiationResponseMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseMeasurementIDIEBinding = s22.ECIDMeasurementInitiationResponseMeasurementIDIEBinding

// ECIDMeasurementInitiationResponseSuccessfulBinding is the concrete SuccessfulBinding[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseSuccessfulBinding = s23.ECIDMeasurementInitiationResponseSuccessfulBinding

// ECIDMeasurementInitiationResponseValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseValueCodec = s22.ECIDMeasurementInitiationResponseValueCodec

// ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding is the concrete IEBinding[WLANMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding = s22.ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding

// ECIDMeasurementReport represents the ASN.1 type E-CIDMeasurementReport (SEQUENCE).
type ECIDMeasurementReport = s13.ECIDMeasurementReport

// ECIDMeasurementReportAPERValue is the concrete APERValue[ECIDMeasurementReport].
type ECIDMeasurementReportAPERValue = s13.ECIDMeasurementReportAPERValue

// ECIDMeasurementReportCellPortionIDIEBinding is the concrete IEBinding[CellPortionID, ECIDMeasurementReportIEValue].
type ECIDMeasurementReportCellPortionIDIEBinding = s13.ECIDMeasurementReportCellPortionIDIEBinding

// ECIDMeasurementReportCodec binds the complete APER value type.
var ECIDMeasurementReportCodec func() ECIDMeasurementReportValueCodec = s23.ECIDMeasurementReportCodec

type ECIDMeasurementReportDescriptor = s23.ECIDMeasurementReportDescriptor

// ECIDMeasurementReportECIDMeasurementResultIEBinding is the concrete IEBinding[ECIDMeasurementResult, ECIDMeasurementReportIEValue].
type ECIDMeasurementReportECIDMeasurementResultIEBinding = s13.ECIDMeasurementReportECIDMeasurementResultIEBinding

// ECIDMeasurementReportIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementReportIEValue].
type ECIDMeasurementReportIEContainer = s13.ECIDMeasurementReportIEContainer

// ECIDMeasurementReportIEField is the concrete ProtocolIEField[ECIDMeasurementReportIEValue].
type ECIDMeasurementReportIEField = s13.ECIDMeasurementReportIEField
type ECIDMeasurementReportIETable = s13.ECIDMeasurementReportIETable
type ECIDMeasurementReportIEValue = s13.ECIDMeasurementReportIEValue

var ECIDMeasurementReportIEs func() ECIDMeasurementReportIETable = s13.ECIDMeasurementReportIEs

// ECIDMeasurementReportInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementReport].
type ECIDMeasurementReportInitiatingBinding = s21.ECIDMeasurementReportInitiatingBinding

// ECIDMeasurementReportMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementReportIEValue].
type ECIDMeasurementReportMeasurementIDIEBinding = s13.ECIDMeasurementReportMeasurementIDIEBinding

var ECIDMeasurementReportProcedure func() ECIDMeasurementReportDescriptor = s23.ECIDMeasurementReportProcedure

// ECIDMeasurementReportValueCodec is the concrete ValueCodec[ECIDMeasurementReport].
type ECIDMeasurementReportValueCodec = s13.ECIDMeasurementReportValueCodec

// ECIDMeasurementResult represents the ASN.1 type E-CID-MeasurementResult (SEQUENCE).
type ECIDMeasurementResult = s13.ECIDMeasurementResult

// ECIDMeasurementResultAPERValue is the concrete APERValue[ECIDMeasurementResult].
type ECIDMeasurementResultAPERValue = s13.ECIDMeasurementResultAPERValue

// ECIDMeasurementResultCodec binds the complete APER value type.
var ECIDMeasurementResultCodec func() ECIDMeasurementResultValueCodec = s22.ECIDMeasurementResultCodec

// ECIDMeasurementResultValueCodec is the concrete ValueCodec[ECIDMeasurementResult].
type ECIDMeasurementResultValueCodec = s13.ECIDMeasurementResultValueCodec

// ECIDMeasurementTerminationCommand represents the ASN.1 type E-CIDMeasurementTerminationCommand (SEQUENCE).
type ECIDMeasurementTerminationCommand = s06.ECIDMeasurementTerminationCommand

// ECIDMeasurementTerminationCommandAPERValue is the concrete APERValue[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandAPERValue = s06.ECIDMeasurementTerminationCommandAPERValue

// ECIDMeasurementTerminationCommandCodec binds the complete APER value type.
var ECIDMeasurementTerminationCommandCodec func() ECIDMeasurementTerminationCommandValueCodec = s23.ECIDMeasurementTerminationCommandCodec

// ECIDMeasurementTerminationCommandIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementTerminationCommandIEValue].
type ECIDMeasurementTerminationCommandIEContainer = s03.ECIDMeasurementTerminationCommandIEContainer

// ECIDMeasurementTerminationCommandIEField is the concrete ProtocolIEField[ECIDMeasurementTerminationCommandIEValue].
type ECIDMeasurementTerminationCommandIEField = s03.ECIDMeasurementTerminationCommandIEField
type ECIDMeasurementTerminationCommandIETable = s03.ECIDMeasurementTerminationCommandIETable
type ECIDMeasurementTerminationCommandIEValue = s02.ECIDMeasurementTerminationCommandIEValue

var ECIDMeasurementTerminationCommandIEs func() ECIDMeasurementTerminationCommandIETable = s03.ECIDMeasurementTerminationCommandIEs

// ECIDMeasurementTerminationCommandInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandInitiatingBinding = s21.ECIDMeasurementTerminationCommandInitiatingBinding

// ECIDMeasurementTerminationCommandMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementTerminationCommandIEValue].
type ECIDMeasurementTerminationCommandMeasurementIDIEBinding = s03.ECIDMeasurementTerminationCommandMeasurementIDIEBinding

// ECIDMeasurementTerminationCommandValueCodec is the concrete ValueCodec[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandValueCodec = s06.ECIDMeasurementTerminationCommandValueCodec
type ECIDMeasurementTerminationDescriptor = s23.ECIDMeasurementTerminationDescriptor

var ECIDMeasurementTerminationProcedure func() ECIDMeasurementTerminationDescriptor = s23.ECIDMeasurementTerminationProcedure

// EUTRANAccessPointPosition represents the ASN.1 type E-UTRANAccessPointPosition (SEQUENCE).
type EUTRANAccessPointPosition = s06.EUTRANAccessPointPosition

// EUTRANAccessPointPositionAPERValue is the concrete APERValue[EUTRANAccessPointPosition].
type EUTRANAccessPointPositionAPERValue = s06.EUTRANAccessPointPositionAPERValue

// EUTRANAccessPointPositionCodec binds the complete source value type.
var EUTRANAccessPointPositionCodec func() EUTRANAccessPointPositionValueCodec = s06.EUTRANAccessPointPositionCodec

// EUTRANAccessPointPositionValueCodec is the concrete ValueCodec[EUTRANAccessPointPosition].
type EUTRANAccessPointPositionValueCodec = s06.EUTRANAccessPointPositionValueCodec

// EUTRANCellIdentifier represents the ASN.1 type EUTRANCellIdentifier (BIT_STRING).
type EUTRANCellIdentifier = s00.EUTRANCellIdentifier

// EUTRANCellIdentifierAPERValue is the concrete APERValue[EUTRANCellIdentifier].
type EUTRANCellIdentifierAPERValue = s00.EUTRANCellIdentifierAPERValue

// EUTRANCellIdentifierCodec binds the complete source value type.
var EUTRANCellIdentifierCodec func() EUTRANCellIdentifierValueCodec = s02.EUTRANCellIdentifierCodec

// EUTRANCellIdentifierValueCodec is the concrete ValueCodec[EUTRANCellIdentifier].
type EUTRANCellIdentifierValueCodec = s00.EUTRANCellIdentifierValueCodec
type EncodePayload[T any] = s23.EncodePayload[T]

// ErrorIndication represents the ASN.1 type ErrorIndication (SEQUENCE).
type ErrorIndication = s11.ErrorIndication

// ErrorIndicationAPERValue is the concrete APERValue[ErrorIndication].
type ErrorIndicationAPERValue = s11.ErrorIndicationAPERValue

// ErrorIndicationCauseIEBinding is the concrete IEBinding[Cause, ErrorIndicationIEValue].
type ErrorIndicationCauseIEBinding = s10.ErrorIndicationCauseIEBinding

// ErrorIndicationCodec binds the complete APER value type.
var ErrorIndicationCodec func() ErrorIndicationValueCodec = s23.ErrorIndicationCodec

// ErrorIndicationCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ErrorIndicationIEValue].
type ErrorIndicationCriticalityDiagnosticsIEBinding = s10.ErrorIndicationCriticalityDiagnosticsIEBinding
type ErrorIndicationDescriptor = s23.ErrorIndicationDescriptor

// ErrorIndicationIEContainer is the concrete ProtocolIEContainer[ErrorIndicationIEValue].
type ErrorIndicationIEContainer = s10.ErrorIndicationIEContainer

// ErrorIndicationIEField is the concrete ProtocolIEField[ErrorIndicationIEValue].
type ErrorIndicationIEField = s10.ErrorIndicationIEField
type ErrorIndicationIETable = s10.ErrorIndicationIETable
type ErrorIndicationIEValue = s10.ErrorIndicationIEValue

var ErrorIndicationIEs func() ErrorIndicationIETable = s10.ErrorIndicationIEs

// ErrorIndicationInitiatingBinding is the concrete InitiatingBinding[ErrorIndication].
type ErrorIndicationInitiatingBinding = s21.ErrorIndicationInitiatingBinding

var ErrorIndicationProcedure func() ErrorIndicationDescriptor = s23.ErrorIndicationProcedure

// ErrorIndicationValueCodec is the concrete ValueCodec[ErrorIndication].
type ErrorIndicationValueCodec = s11.ErrorIndicationValueCodec
type ExtensionBinding[T any, V s23.ProtocolOpenValueConstraint[V]] = s23.ExtensionBinding[T, V]
type FieldInfo = s00.FieldInfo

// HESSID represents the ASN.1 type HESSID (OCTET_STRING).
type HESSID = s00.HESSID

// HESSIDAPERValue is the concrete APERValue[HESSID].
type HESSIDAPERValue = s00.HESSIDAPERValue

// HESSIDCodec binds the complete source value type.
var HESSIDCodec func() HESSIDValueCodec = s02.HESSIDCodec

// HESSIDValueCodec is the concrete ValueCodec[HESSID].
type HESSIDValueCodec = s00.HESSIDValueCodec
type IEBinding[T any, V s23.ProtocolOpenValueConstraint[V]] = s23.IEBinding[T, V]

// IdAddOTDOACells is the integer constant for id-AddOTDOACells.
const IdAddOTDOACells = s00.IdAddOTDOACells

// IdAssistanceInformation is the integer constant for id-Assistance-Information.
const IdAssistanceInformation = s00.IdAssistanceInformation

// IdAssistanceInformationControl is the integer constant for id-assistanceInformationControl.
const IdAssistanceInformationControl = s00.IdAssistanceInformationControl

// IdAssistanceInformationFailureList is the integer constant for id-AssistanceInformationFailureList.
const IdAssistanceInformationFailureList = s00.IdAssistanceInformationFailureList

// IdAssistanceInformationFeedback is the integer constant for id-assistanceInformationFeedback.
const IdAssistanceInformationFeedback = s00.IdAssistanceInformationFeedback

// IdBroadcast is the integer constant for id-Broadcast.
const IdBroadcast = s00.IdBroadcast

// IdCause is the integer constant for id-Cause.
const IdCause = s00.IdCause

// IdCellPortionID is the integer constant for id-Cell-Portion-ID.
const IdCellPortionID = s00.IdCellPortionID

// IdCriticalityDiagnostics is the integer constant for id-CriticalityDiagnostics.
const IdCriticalityDiagnostics = s00.IdCriticalityDiagnostics

// IdECIDMeasurementFailureIndication is the integer constant for id-e-CIDMeasurementFailureIndication.
const IdECIDMeasurementFailureIndication = s00.IdECIDMeasurementFailureIndication

// IdECIDMeasurementInitiation is the integer constant for id-e-CIDMeasurementInitiation.
const IdECIDMeasurementInitiation = s00.IdECIDMeasurementInitiation

// IdECIDMeasurementReport is the integer constant for id-e-CIDMeasurementReport.
const IdECIDMeasurementReport = s00.IdECIDMeasurementReport

// IdECIDMeasurementResult is the integer constant for id-E-CID-MeasurementResult.
const IdECIDMeasurementResult = s00.IdECIDMeasurementResult

// IdECIDMeasurementTermination is the integer constant for id-e-CIDMeasurementTermination.
const IdECIDMeasurementTermination = s00.IdECIDMeasurementTermination

// IdENBUEMeasurementID is the integer constant for id-eNB-UE-Measurement-ID.
const IdENBUEMeasurementID = s00.IdENBUEMeasurementID

// IdESMLCUEMeasurementID is the integer constant for id-E-SMLC-UE-Measurement-ID.
const IdESMLCUEMeasurementID = s00.IdESMLCUEMeasurementID

// IdErrorIndication is the integer constant for id-errorIndication.
const IdErrorIndication = s00.IdErrorIndication

// IdInterRATMeasurementQuantities is the integer constant for id-InterRATMeasurementQuantities.
const IdInterRATMeasurementQuantities = s00.IdInterRATMeasurementQuantities

// IdInterRATMeasurementQuantitiesItem is the integer constant for id-InterRATMeasurementQuantities-Item.
const IdInterRATMeasurementQuantitiesItem = s00.IdInterRATMeasurementQuantitiesItem

// IdInterRATMeasurementResult is the integer constant for id-InterRATMeasurementResult.
const IdInterRATMeasurementResult = s00.IdInterRATMeasurementResult

// IdMeasurementPeriodicity is the integer constant for id-MeasurementPeriodicity.
const IdMeasurementPeriodicity = s00.IdMeasurementPeriodicity

// IdMeasurementQuantities is the integer constant for id-MeasurementQuantities.
const IdMeasurementQuantities = s00.IdMeasurementQuantities

// IdMeasurementQuantitiesItem is the integer constant for id-MeasurementQuantities-Item.
const IdMeasurementQuantitiesItem = s00.IdMeasurementQuantitiesItem

// IdNRCGI is the integer constant for id-NR-CGI.
const IdNRCGI = s00.IdNRCGI

// IdOTDOACells is the integer constant for id-OTDOACells.
const IdOTDOACells = s00.IdOTDOACells

// IdOTDOAInformationExchange is the integer constant for id-oTDOAInformationExchange.
const IdOTDOAInformationExchange = s00.IdOTDOAInformationExchange

// IdOTDOAInformationTypeGroup is the integer constant for id-OTDOA-Information-Type-Group.
const IdOTDOAInformationTypeGroup = s00.IdOTDOAInformationTypeGroup

// IdOTDOAInformationTypeItem is the integer constant for id-OTDOA-Information-Type-Item.
const IdOTDOAInformationTypeItem = s00.IdOTDOAInformationTypeItem

// IdPrivateMessage is the integer constant for id-privateMessage.
const IdPrivateMessage = s00.IdPrivateMessage

// IdReportCharacteristics is the integer constant for id-ReportCharacteristics.
const IdReportCharacteristics = s00.IdReportCharacteristics

// IdRequestedSRSTransmissionCharacteristics is the integer constant for id-RequestedSRSTransmissionCharacteristics.
const IdRequestedSRSTransmissionCharacteristics = s00.IdRequestedSRSTransmissionCharacteristics

// IdResultsPerSSBIndexItem is the integer constant for id-ResultsPerSSB-Index-Item.
const IdResultsPerSSBIndexItem = s00.IdResultsPerSSBIndexItem

// IdResultsPerSSBIndexList is the integer constant for id-ResultsPerSSB-Index-List.
const IdResultsPerSSBIndexList = s00.IdResultsPerSSBIndexList

// IdULConfiguration is the integer constant for id-ULConfiguration.
const IdULConfiguration = s00.IdULConfiguration

// IdUTDOAInformationExchange is the integer constant for id-uTDOAInformationExchange.
const IdUTDOAInformationExchange = s00.IdUTDOAInformationExchange

// IdUTDOAInformationUpdate is the integer constant for id-uTDOAInformationUpdate.
const IdUTDOAInformationUpdate = s00.IdUTDOAInformationUpdate

// IdWLANMeasurementQuantities is the integer constant for id-WLANMeasurementQuantities.
const IdWLANMeasurementQuantities = s00.IdWLANMeasurementQuantities

// IdWLANMeasurementQuantitiesItem is the integer constant for id-WLANMeasurementQuantities-Item.
const IdWLANMeasurementQuantitiesItem = s00.IdWLANMeasurementQuantitiesItem

// IdWLANMeasurementResult is the integer constant for id-WLANMeasurementResult.
const IdWLANMeasurementResult = s00.IdWLANMeasurementResult

type InitiatingBinding[T any] = s23.InitiatingBinding[T]

// InitiatingMessage represents the ASN.1 type InitiatingMessage (SEQUENCE).
type InitiatingMessage = s21.InitiatingMessage

// InitiatingMessageAPERValue is the concrete APERValue[InitiatingMessage].
type InitiatingMessageAPERValue = s21.InitiatingMessageAPERValue

// InitiatingMessageCodec binds the complete source value type.
var InitiatingMessageCodec func() InitiatingMessageValueCodec = s21.InitiatingMessageCodec

// InitiatingMessageValueCodec is the concrete ValueCodec[InitiatingMessage].
type InitiatingMessageValueCodec = s21.InitiatingMessageValueCodec

var InitiatingReason func(code ProcedureCode) aper.OpaqueReason = s00.InitiatingReason

type InitiatingValue = s21.InitiatingValue

// InterRATMeasuredResultsValue represents the ASN.1 CHOICE type InterRATMeasuredResultsValue.
type InterRATMeasuredResultsValue = s19.InterRATMeasuredResultsValue

// InterRATMeasuredResultsValueAPERValue is the concrete APERValue[InterRATMeasuredResultsValue].
type InterRATMeasuredResultsValueAPERValue = s20.InterRATMeasuredResultsValueAPERValue

// InterRATMeasuredResultsValue choice constants.
const InterRATMeasuredResultsValueChoiceResultGERAN = s00.InterRATMeasuredResultsValueChoiceResultGERAN

// InterRATMeasuredResultsValue choice constants.
const InterRATMeasuredResultsValueChoiceResultNR = s00.InterRATMeasuredResultsValueChoiceResultNR

// InterRATMeasuredResultsValue choice constants.
const InterRATMeasuredResultsValueChoiceResultUTRAN = s00.InterRATMeasuredResultsValueChoiceResultUTRAN

// InterRATMeasuredResultsValueCodec binds the complete source value type.
var InterRATMeasuredResultsValueCodec func() InterRATMeasuredResultsValueValueCodec = s20.InterRATMeasuredResultsValueCodec

// InterRATMeasuredResultsValueValueCodec is the concrete ValueCodec[InterRATMeasuredResultsValue].
type InterRATMeasuredResultsValueValueCodec = s20.InterRATMeasuredResultsValueValueCodec
type InterRATMeasurementQuantities = s06.InterRATMeasurementQuantities

// InterRATMeasurementQuantitiesAPERValue is the concrete APERValue[InterRATMeasurementQuantities].
type InterRATMeasurementQuantitiesAPERValue = s06.InterRATMeasurementQuantitiesAPERValue

// InterRATMeasurementQuantitiesCodec binds the complete APER value type.
var InterRATMeasurementQuantitiesCodec func() InterRATMeasurementQuantitiesConcreteValueCodec = s21.InterRATMeasurementQuantitiesCodec

// InterRATMeasurementQuantitiesComplete carries a complete InterRATMeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type InterRATMeasurementQuantitiesComplete = s17.InterRATMeasurementQuantitiesComplete

// InterRATMeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[InterRATMeasurementQuantities].
type InterRATMeasurementQuantitiesConcreteValueCodec = s06.InterRATMeasurementQuantitiesConcreteValueCodec

// InterRATMeasurementQuantitiesItem represents the ASN.1 type InterRATMeasurementQuantities-Item (SEQUENCE).
type InterRATMeasurementQuantitiesItem = s06.InterRATMeasurementQuantitiesItem

// InterRATMeasurementQuantitiesItemAPERValue is the concrete APERValue[InterRATMeasurementQuantitiesItem].
type InterRATMeasurementQuantitiesItemAPERValue = s06.InterRATMeasurementQuantitiesItemAPERValue

// InterRATMeasurementQuantitiesItemCodec binds the complete APER value type.
var InterRATMeasurementQuantitiesItemCodec func() InterRATMeasurementQuantitiesItemValueCodec = s06.InterRATMeasurementQuantitiesItemCodec

// InterRATMeasurementQuantitiesItemIEContainer is the concrete ProtocolIEContainer[InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemIEContainer = s06.InterRATMeasurementQuantitiesItemIEContainer

// InterRATMeasurementQuantitiesItemIEField is the concrete ProtocolIEField[InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemIEField = s06.InterRATMeasurementQuantitiesItemIEField
type InterRATMeasurementQuantitiesItemIETable = s06.InterRATMeasurementQuantitiesItemIETable
type InterRATMeasurementQuantitiesItemIEValue = s06.InterRATMeasurementQuantitiesItemIEValue

// InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer = s06.InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer

var InterRATMeasurementQuantitiesItemIEs func() InterRATMeasurementQuantitiesItemIETable = s06.InterRATMeasurementQuantitiesItemIEs

// InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding is the concrete IEBinding[InterRATMeasurementQuantitiesItem, InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding = s06.InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding

// InterRATMeasurementQuantitiesItemValueCodec is the concrete ValueCodec[InterRATMeasurementQuantitiesItem].
type InterRATMeasurementQuantitiesItemValueCodec = s06.InterRATMeasurementQuantitiesItemValueCodec

// InterRATMeasurementQuantitiesValue represents the ASN.1 ENUMERATED type InterRATMeasurementQuantitiesValue.
type InterRATMeasurementQuantitiesValue = s00.InterRATMeasurementQuantitiesValue

// InterRATMeasurementQuantitiesValueAPERValue is the concrete APERValue[InterRATMeasurementQuantitiesValue].
type InterRATMeasurementQuantitiesValueAPERValue = s00.InterRATMeasurementQuantitiesValueAPERValue

// InterRATMeasurementQuantitiesValueCodec binds the complete source value type.
var InterRATMeasurementQuantitiesValueCodec func() InterRATMeasurementQuantitiesValueValueCodec = s02.InterRATMeasurementQuantitiesValueCodec

type InterRATMeasurementQuantitiesValueExtIETable = s03.InterRATMeasurementQuantitiesValueExtIETable

var InterRATMeasurementQuantitiesValueExtIEs func() InterRATMeasurementQuantitiesValueExtIETable = s03.InterRATMeasurementQuantitiesValueExtIEs

// InterRATMeasurementQuantitiesValueExtIEsExtContainer is the concrete ProtocolExtensionContainer[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsExtContainer = s03.InterRATMeasurementQuantitiesValueExtIEsExtContainer

// InterRATMeasurementQuantitiesValueExtIEsExtField is the concrete ProtocolExtensionField[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsExtField = s03.InterRATMeasurementQuantitiesValueExtIEsExtField

// InterRATMeasurementQuantitiesValueExtIEsIEContainer is the concrete ProtocolIEContainer[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsIEContainer = s03.InterRATMeasurementQuantitiesValueExtIEsIEContainer

// InterRATMeasurementQuantitiesValueExtIEsIEField is the concrete ProtocolIEField[InterRATMeasurementQuantitiesValueExtIEsValue].
type InterRATMeasurementQuantitiesValueExtIEsIEField = s03.InterRATMeasurementQuantitiesValueExtIEsIEField
type InterRATMeasurementQuantitiesValueExtIEsValue = s02.InterRATMeasurementQuantitiesValueExtIEsValue

const InterRATMeasurementQuantitiesValueGeran = s00.InterRATMeasurementQuantitiesValueGeran
const InterRATMeasurementQuantitiesValueNr = s00.InterRATMeasurementQuantitiesValueNr
const InterRATMeasurementQuantitiesValueUtran = s00.InterRATMeasurementQuantitiesValueUtran

// InterRATMeasurementQuantitiesValueValueCodec is the concrete ValueCodec[InterRATMeasurementQuantitiesValue].
type InterRATMeasurementQuantitiesValueValueCodec = s00.InterRATMeasurementQuantitiesValueValueCodec
type InterRATMeasurementResult = s20.InterRATMeasurementResult

// InterRATMeasurementResultAPERValue is the concrete APERValue[InterRATMeasurementResult].
type InterRATMeasurementResultAPERValue = s20.InterRATMeasurementResultAPERValue

// InterRATMeasurementResultCodec binds the complete APER value type.
var InterRATMeasurementResultCodec func() InterRATMeasurementResultValueCodec = s22.InterRATMeasurementResultCodec

// InterRATMeasurementResultComplete carries a complete InterRATMeasurementResult encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type InterRATMeasurementResultComplete = s20.InterRATMeasurementResultComplete

// InterRATMeasurementResultValueCodec is the concrete ValueCodec[InterRATMeasurementResult].
type InterRATMeasurementResultValueCodec = s20.InterRATMeasurementResultValueCodec

// LPPAPDU represents the ASN.1 CHOICE type LPPA-PDU.
type LPPAPDU = s23.LPPAPDU

// LPPAPDUAPERValue is the concrete APERValue[LPPAPDU].
type LPPAPDUAPERValue = s23.LPPAPDUAPERValue

// LPPAPDU choice constants.
const LPPAPDUChoiceInitiatingMessage = s00.LPPAPDUChoiceInitiatingMessage

// LPPAPDU choice constants.
const LPPAPDUChoiceSuccessfulOutcome = s00.LPPAPDUChoiceSuccessfulOutcome

// LPPAPDU choice constants.
const LPPAPDUChoiceUnsuccessfulOutcome = s00.LPPAPDUChoiceUnsuccessfulOutcome

// LPPAPDUCodec binds the complete source value type.
var LPPAPDUCodec func() LPPAPDUValueCodec = s23.LPPAPDUCodec

// LPPAPDUValueCodec is the concrete ValueCodec[LPPAPDU].
type LPPAPDUValueCodec = s23.LPPAPDUValueCodec

// LPPATransactionID represents the ASN.1 type LPPATransactionID (INTEGER).
type LPPATransactionID = s00.LPPATransactionID

// LPPATransactionIDAPERValue is the concrete APERValue[LPPATransactionID].
type LPPATransactionIDAPERValue = s00.LPPATransactionIDAPERValue

// LPPATransactionIDCodec binds the complete source value type.
var LPPATransactionIDCodec func() LPPATransactionIDValueCodec = s04.LPPATransactionIDCodec

// LPPATransactionIDValueCodec is the concrete ValueCodec[LPPATransactionID].
type LPPATransactionIDValueCodec = s00.LPPATransactionIDValueCodec
type MBSFNsubframeConfiguration = s09.MBSFNsubframeConfiguration

// MBSFNsubframeConfigurationAPERValue is the concrete APERValue[MBSFNsubframeConfiguration].
type MBSFNsubframeConfigurationAPERValue = s09.MBSFNsubframeConfigurationAPERValue

// MBSFNsubframeConfigurationCodec binds the complete source value type.
var MBSFNsubframeConfigurationCodec func() MBSFNsubframeConfigurationConcreteValueCodec = s18.MBSFNsubframeConfigurationCodec

// MBSFNsubframeConfigurationComplete carries a complete MBSFNsubframeConfiguration encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MBSFNsubframeConfigurationComplete = s18.MBSFNsubframeConfigurationComplete

// MBSFNsubframeConfigurationConcreteValueCodec is the concrete ValueCodec[MBSFNsubframeConfiguration].
type MBSFNsubframeConfigurationConcreteValueCodec = s09.MBSFNsubframeConfigurationConcreteValueCodec

// MBSFNsubframeConfigurationValue represents the ASN.1 type MBSFNsubframeConfigurationValue (SEQUENCE).
type MBSFNsubframeConfigurationValue = s09.MBSFNsubframeConfigurationValue

// MBSFNsubframeConfigurationValueAPERValue is the concrete APERValue[MBSFNsubframeConfigurationValue].
type MBSFNsubframeConfigurationValueAPERValue = s09.MBSFNsubframeConfigurationValueAPERValue

// MBSFNsubframeConfigurationValueCodec binds the complete source value type.
var MBSFNsubframeConfigurationValueCodec func() MBSFNsubframeConfigurationValueValueCodec = s09.MBSFNsubframeConfigurationValueCodec

// MBSFNsubframeConfigurationValueValueCodec is the concrete ValueCodec[MBSFNsubframeConfigurationValue].
type MBSFNsubframeConfigurationValueValueCodec = s09.MBSFNsubframeConfigurationValueValueCodec

// MarshalAPERAddOTDOACellInformation encodes a complete named list.
var MarshalAPERAddOTDOACellInformation func(v AddOTDOACellInformationComplete, options ...aper.EncodeOption) ([]byte, error) = s17.MarshalAPERAddOTDOACellInformation

// MarshalAPERAddOTDOACells encodes a complete named list.
var MarshalAPERAddOTDOACells func(v AddOTDOACellsComplete, options ...aper.EncodeOption) ([]byte, error) = s17.MarshalAPERAddOTDOACells

// MarshalAPERAssistanceInformationFailureList encodes a complete named list.
var MarshalAPERAssistanceInformationFailureList func(v AssistanceInformationFailureListComplete, options ...aper.EncodeOption) ([]byte, error) = s17.MarshalAPERAssistanceInformationFailureList

// MarshalAPERCriticalityDiagnosticsIEList encodes a complete named list.
var MarshalAPERCriticalityDiagnosticsIEList func(v CriticalityDiagnosticsIEListComplete, options ...aper.EncodeOption) ([]byte, error) = s17.MarshalAPERCriticalityDiagnosticsIEList

// MarshalAPERInterRATMeasurementQuantities encodes a complete named list.
var MarshalAPERInterRATMeasurementQuantities func(v InterRATMeasurementQuantitiesComplete, options ...aper.EncodeOption) ([]byte, error) = s17.MarshalAPERInterRATMeasurementQuantities

// MarshalAPERInterRATMeasurementResult encodes a complete named list.
var MarshalAPERInterRATMeasurementResult func(v InterRATMeasurementResultComplete, options ...aper.EncodeOption) ([]byte, error) = s20.MarshalAPERInterRATMeasurementResult

// MarshalAPERMBSFNsubframeConfiguration encodes a complete named list.
var MarshalAPERMBSFNsubframeConfiguration func(v MBSFNsubframeConfigurationComplete, options ...aper.EncodeOption) ([]byte, error) = s18.MarshalAPERMBSFNsubframeConfiguration

// MarshalAPERMeasuredResults encodes a complete named list.
var MarshalAPERMeasuredResults func(v MeasuredResultsComplete, options ...aper.EncodeOption) ([]byte, error) = s18.MarshalAPERMeasuredResults

// MarshalAPERMeasurementQuantities encodes a complete named list.
var MarshalAPERMeasurementQuantities func(v MeasurementQuantitiesComplete, options ...aper.EncodeOption) ([]byte, error) = s18.MarshalAPERMeasurementQuantities

// MarshalAPEROTDOACellInformation encodes a complete named list.
var MarshalAPEROTDOACellInformation func(v OTDOACellInformationComplete, options ...aper.EncodeOption) ([]byte, error) = s18.MarshalAPEROTDOACellInformation

// MarshalAPEROTDOACells encodes a complete named list.
var MarshalAPEROTDOACells func(v OTDOACellsComplete, options ...aper.EncodeOption) ([]byte, error) = s18.MarshalAPEROTDOACells

// MarshalAPEROTDOAInformationType encodes a complete named list.
var MarshalAPEROTDOAInformationType func(v OTDOAInformationTypeComplete, options ...aper.EncodeOption) ([]byte, error) = s18.MarshalAPEROTDOAInformationType

// MarshalAPERPRSFrequencyHoppingConfigurationBandPositions encodes a complete named list.
var MarshalAPERPRSFrequencyHoppingConfigurationBandPositions func(v PRSFrequencyHoppingConfigurationBandPositionsComplete, options ...aper.EncodeOption) ([]byte, error) = s19.MarshalAPERPRSFrequencyHoppingConfigurationBandPositions

// MarshalAPERPosSIBSegments encodes a complete named list.
var MarshalAPERPosSIBSegments func(v PosSIBSegmentsComplete, options ...aper.EncodeOption) ([]byte, error) = s19.MarshalAPERPosSIBSegments

// MarshalAPERPosSIBs encodes a complete named list.
var MarshalAPERPosSIBs func(v PosSIBsComplete, options ...aper.EncodeOption) ([]byte, error) = s19.MarshalAPERPosSIBs

// MarshalAPERResultGERAN encodes a complete named list.
var MarshalAPERResultGERAN func(v ResultGERANComplete, options ...aper.EncodeOption) ([]byte, error) = s19.MarshalAPERResultGERAN

// MarshalAPERResultNR encodes a complete named list.
var MarshalAPERResultNR func(v ResultNRComplete, options ...aper.EncodeOption) ([]byte, error) = s20.MarshalAPERResultNR

// MarshalAPERResultRSRP encodes a complete named list.
var MarshalAPERResultRSRP func(v ResultRSRPComplete, options ...aper.EncodeOption) ([]byte, error) = s19.MarshalAPERResultRSRP

// MarshalAPERResultRSRQ encodes a complete named list.
var MarshalAPERResultRSRQ func(v ResultRSRQComplete, options ...aper.EncodeOption) ([]byte, error) = s19.MarshalAPERResultRSRQ

// MarshalAPERResultUTRAN encodes a complete named list.
var MarshalAPERResultUTRAN func(v ResultUTRANComplete, options ...aper.EncodeOption) ([]byte, error) = s19.MarshalAPERResultUTRAN

// MarshalAPERResultsPerSSBIndexList encodes a complete named list.
var MarshalAPERResultsPerSSBIndexList func(v ResultsPerSSBIndexListComplete, options ...aper.EncodeOption) ([]byte, error) = s19.MarshalAPERResultsPerSSBIndexList

// MarshalAPERSRSConfigurationForAllCells encodes a complete named list.
var MarshalAPERSRSConfigurationForAllCells func(v SRSConfigurationForAllCellsComplete, options ...aper.EncodeOption) ([]byte, error) = s20.MarshalAPERSRSConfigurationForAllCells

// MarshalAPERSystemInformation encodes a complete named list.
var MarshalAPERSystemInformation func(v SystemInformationComplete, options ...aper.EncodeOption) ([]byte, error) = s20.MarshalAPERSystemInformation

// MarshalAPERWLANChannelList encodes a complete named list.
var MarshalAPERWLANChannelList func(v WLANChannelListComplete, options ...aper.EncodeOption) ([]byte, error) = s20.MarshalAPERWLANChannelList

// MarshalAPERWLANMeasurementQuantities encodes a complete named list.
var MarshalAPERWLANMeasurementQuantities func(v WLANMeasurementQuantitiesComplete, options ...aper.EncodeOption) ([]byte, error) = s21.MarshalAPERWLANMeasurementQuantities

// MarshalAPERWLANMeasurementResult encodes a complete named list.
var MarshalAPERWLANMeasurementResult func(v WLANMeasurementResultComplete, options ...aper.EncodeOption) ([]byte, error) = s22.MarshalAPERWLANMeasurementResult

// MaxCellReport is the integer constant for maxCellReport.
const MaxCellReport = s00.MaxCellReport

// MaxCellineNB is the integer constant for maxCellineNB.
const MaxCellineNB = s00.MaxCellineNB

// MaxCellineNBExt is the integer constant for maxCellineNB-ext.
const MaxCellineNBExt = s00.MaxCellineNBExt

// MaxGERANMeas is the integer constant for maxGERANMeas.
const MaxGERANMeas = s00.MaxGERANMeas

// MaxMBSFNAllocations is the integer constant for maxMBSFN-Allocations.
const MaxMBSFNAllocations = s00.MaxMBSFNAllocations

// MaxNRmeas is the integer constant for maxNRmeas.
const MaxNRmeas = s00.MaxNRmeas

// MaxNoMeas is the integer constant for maxNoMeas.
const MaxNoMeas = s00.MaxNoMeas

// MaxNrOfErrors is the integer constant for maxNrOfErrors.
const MaxNrOfErrors = s00.MaxNrOfErrors

// MaxNrOfPosSIBs is the integer constant for maxNrOfPosSIBs.
const MaxNrOfPosSIBs = s00.MaxNrOfPosSIBs

// MaxNrOfPosSImessage is the integer constant for maxNrOfPosSImessage.
const MaxNrOfPosSImessage = s00.MaxNrOfPosSImessage

// MaxNrOfSegments is the integer constant for maxNrOfSegments.
const MaxNrOfSegments = s00.MaxNrOfSegments

// MaxPrivateIEs is the integer constant for maxPrivateIEs.
const MaxPrivateIEs = s00.MaxPrivateIEs

// MaxProtocolExtensions is the integer constant for maxProtocolExtensions.
const MaxProtocolExtensions = s00.MaxProtocolExtensions

// MaxProtocolIEs is the integer constant for maxProtocolIEs.
const MaxProtocolIEs = s00.MaxProtocolIEs

// MaxResultsPerSSBIndex is the integer constant for maxResultsPerSSBIndex.
const MaxResultsPerSSBIndex = s00.MaxResultsPerSSBIndex

// MaxServCell is the integer constant for maxServCell.
const MaxServCell = s00.MaxServCell

// MaxUTRANMeas is the integer constant for maxUTRANMeas.
const MaxUTRANMeas = s00.MaxUTRANMeas

// MaxWLANchannels is the integer constant for maxWLANchannels.
const MaxWLANchannels = s00.MaxWLANchannels

// MaxnoAssistInfoFailureListItems is the integer constant for maxnoAssistInfoFailureListItems.
const MaxnoAssistInfoFailureListItems = s00.MaxnoAssistInfoFailureListItems

// MaxnoFreqHoppingBandsMinusOne is the integer constant for maxnoFreqHoppingBandsMinusOne.
const MaxnoFreqHoppingBandsMinusOne = s00.MaxnoFreqHoppingBandsMinusOne

// MaxnoOTDOAtypes is the integer constant for maxnoOTDOAtypes.
const MaxnoOTDOAtypes = s00.MaxnoOTDOAtypes

type MeasuredResults = s13.MeasuredResults

// MeasuredResultsAPERValue is the concrete APERValue[MeasuredResults].
type MeasuredResultsAPERValue = s13.MeasuredResultsAPERValue

// MeasuredResultsCodec binds the complete source value type.
var MeasuredResultsCodec func() MeasuredResultsConcreteValueCodec = s18.MeasuredResultsCodec

// MeasuredResultsComplete carries a complete MeasuredResults encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MeasuredResultsComplete = s18.MeasuredResultsComplete

// MeasuredResultsConcreteValueCodec is the concrete ValueCodec[MeasuredResults].
type MeasuredResultsConcreteValueCodec = s13.MeasuredResultsConcreteValueCodec

// MeasuredResultsValue represents the ASN.1 CHOICE type MeasuredResultsValue.
type MeasuredResultsValue = s13.MeasuredResultsValue

// MeasuredResultsValueAPERValue is the concrete APERValue[MeasuredResultsValue].
type MeasuredResultsValueAPERValue = s13.MeasuredResultsValueAPERValue

// MeasuredResultsValue choice constants.
const MeasuredResultsValueChoiceResultRSRP = s00.MeasuredResultsValueChoiceResultRSRP

// MeasuredResultsValue choice constants.
const MeasuredResultsValueChoiceResultRSRQ = s00.MeasuredResultsValueChoiceResultRSRQ

// MeasuredResultsValue choice constants.
const MeasuredResultsValueChoiceValueAngleOfArrival = s00.MeasuredResultsValueChoiceValueAngleOfArrival

// MeasuredResultsValue choice constants.
const MeasuredResultsValueChoiceValueTimingAdvanceType1 = s00.MeasuredResultsValueChoiceValueTimingAdvanceType1

// MeasuredResultsValue choice constants.
const MeasuredResultsValueChoiceValueTimingAdvanceType2 = s00.MeasuredResultsValueChoiceValueTimingAdvanceType2

// MeasuredResultsValueCodec binds the complete source value type.
var MeasuredResultsValueCodec func() MeasuredResultsValueValueCodec = s13.MeasuredResultsValueCodec

// MeasuredResultsValueValueCodec is the concrete ValueCodec[MeasuredResultsValue].
type MeasuredResultsValueValueCodec = s13.MeasuredResultsValueValueCodec

// MeasurementID represents the ASN.1 type Measurement-ID (INTEGER).
type MeasurementID = s00.MeasurementID

// MeasurementIDAPERValue is the concrete APERValue[MeasurementID].
type MeasurementIDAPERValue = s00.MeasurementIDAPERValue

// MeasurementIDCodec binds the complete APER value type.
var MeasurementIDCodec func() MeasurementIDValueCodec = s06.MeasurementIDCodec

// MeasurementIDValueCodec is the concrete ValueCodec[MeasurementID].
type MeasurementIDValueCodec = s00.MeasurementIDValueCodec

// MeasurementPeriodicity represents the ASN.1 ENUMERATED type MeasurementPeriodicity.
type MeasurementPeriodicity = s00.MeasurementPeriodicity

// MeasurementPeriodicityAPERValue is the concrete APERValue[MeasurementPeriodicity].
type MeasurementPeriodicityAPERValue = s00.MeasurementPeriodicityAPERValue

// MeasurementPeriodicityCodec binds the complete APER value type.
var MeasurementPeriodicityCodec func() MeasurementPeriodicityValueCodec = s21.MeasurementPeriodicityCodec

const MeasurementPeriodicityMin1 = s00.MeasurementPeriodicityMin1
const MeasurementPeriodicityMin12 = s00.MeasurementPeriodicityMin12
const MeasurementPeriodicityMin30 = s00.MeasurementPeriodicityMin30
const MeasurementPeriodicityMin6 = s00.MeasurementPeriodicityMin6
const MeasurementPeriodicityMin60 = s00.MeasurementPeriodicityMin60
const MeasurementPeriodicityMs1024 = s00.MeasurementPeriodicityMs1024
const MeasurementPeriodicityMs10240 = s00.MeasurementPeriodicityMs10240
const MeasurementPeriodicityMs120 = s00.MeasurementPeriodicityMs120
const MeasurementPeriodicityMs2048 = s00.MeasurementPeriodicityMs2048
const MeasurementPeriodicityMs240 = s00.MeasurementPeriodicityMs240
const MeasurementPeriodicityMs480 = s00.MeasurementPeriodicityMs480
const MeasurementPeriodicityMs5120 = s00.MeasurementPeriodicityMs5120
const MeasurementPeriodicityMs640 = s00.MeasurementPeriodicityMs640

// MeasurementPeriodicityValueCodec is the concrete ValueCodec[MeasurementPeriodicity].
type MeasurementPeriodicityValueCodec = s00.MeasurementPeriodicityValueCodec
type MeasurementQuantities = s06.MeasurementQuantities

// MeasurementQuantitiesAPERValue is the concrete APERValue[MeasurementQuantities].
type MeasurementQuantitiesAPERValue = s06.MeasurementQuantitiesAPERValue

// MeasurementQuantitiesCodec binds the complete APER value type.
var MeasurementQuantitiesCodec func() MeasurementQuantitiesConcreteValueCodec = s21.MeasurementQuantitiesCodec

// MeasurementQuantitiesComplete carries a complete MeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MeasurementQuantitiesComplete = s18.MeasurementQuantitiesComplete

// MeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[MeasurementQuantities].
type MeasurementQuantitiesConcreteValueCodec = s06.MeasurementQuantitiesConcreteValueCodec

// MeasurementQuantitiesItem represents the ASN.1 type MeasurementQuantities-Item (SEQUENCE).
type MeasurementQuantitiesItem = s06.MeasurementQuantitiesItem

// MeasurementQuantitiesItemAPERValue is the concrete APERValue[MeasurementQuantitiesItem].
type MeasurementQuantitiesItemAPERValue = s06.MeasurementQuantitiesItemAPERValue

// MeasurementQuantitiesItemCodec binds the complete APER value type.
var MeasurementQuantitiesItemCodec func() MeasurementQuantitiesItemValueCodec = s07.MeasurementQuantitiesItemCodec

// MeasurementQuantitiesItemIEContainer is the concrete ProtocolIEContainer[MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemIEContainer = s06.MeasurementQuantitiesItemIEContainer

// MeasurementQuantitiesItemIEField is the concrete ProtocolIEField[MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemIEField = s06.MeasurementQuantitiesItemIEField
type MeasurementQuantitiesItemIETable = s07.MeasurementQuantitiesItemIETable
type MeasurementQuantitiesItemIEValue = s06.MeasurementQuantitiesItemIEValue

// MeasurementQuantitiesItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemIEValueProtocolIESingleContainer = s06.MeasurementQuantitiesItemIEValueProtocolIESingleContainer

var MeasurementQuantitiesItemIEs func() MeasurementQuantitiesItemIETable = s07.MeasurementQuantitiesItemIEs

// MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding is the concrete IEBinding[MeasurementQuantitiesItem, MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding = s06.MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding

// MeasurementQuantitiesItemValueCodec is the concrete ValueCodec[MeasurementQuantitiesItem].
type MeasurementQuantitiesItemValueCodec = s06.MeasurementQuantitiesItemValueCodec

// MeasurementQuantitiesValue represents the ASN.1 ENUMERATED type MeasurementQuantitiesValue.
type MeasurementQuantitiesValue = s00.MeasurementQuantitiesValue

// MeasurementQuantitiesValueAPERValue is the concrete APERValue[MeasurementQuantitiesValue].
type MeasurementQuantitiesValueAPERValue = s00.MeasurementQuantitiesValueAPERValue

const MeasurementQuantitiesValueAngleOfArrival = s00.MeasurementQuantitiesValueAngleOfArrival
const MeasurementQuantitiesValueCellID = s00.MeasurementQuantitiesValueCellID

// MeasurementQuantitiesValueCodec binds the complete source value type.
var MeasurementQuantitiesValueCodec func() MeasurementQuantitiesValueValueCodec = s02.MeasurementQuantitiesValueCodec

type MeasurementQuantitiesValueExtIETable = s04.MeasurementQuantitiesValueExtIETable

var MeasurementQuantitiesValueExtIEs func() MeasurementQuantitiesValueExtIETable = s04.MeasurementQuantitiesValueExtIEs

// MeasurementQuantitiesValueExtIEsExtContainer is the concrete ProtocolExtensionContainer[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsExtContainer = s04.MeasurementQuantitiesValueExtIEsExtContainer

// MeasurementQuantitiesValueExtIEsExtField is the concrete ProtocolExtensionField[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsExtField = s04.MeasurementQuantitiesValueExtIEsExtField

// MeasurementQuantitiesValueExtIEsIEContainer is the concrete ProtocolIEContainer[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsIEContainer = s04.MeasurementQuantitiesValueExtIEsIEContainer

// MeasurementQuantitiesValueExtIEsIEField is the concrete ProtocolIEField[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsIEField = s04.MeasurementQuantitiesValueExtIEsIEField
type MeasurementQuantitiesValueExtIEsValue = s02.MeasurementQuantitiesValueExtIEsValue

const MeasurementQuantitiesValueRSRP = s00.MeasurementQuantitiesValueRSRP
const MeasurementQuantitiesValueRSRQ = s00.MeasurementQuantitiesValueRSRQ
const MeasurementQuantitiesValueTimingAdvanceType1 = s00.MeasurementQuantitiesValueTimingAdvanceType1
const MeasurementQuantitiesValueTimingAdvanceType2 = s00.MeasurementQuantitiesValueTimingAdvanceType2

// MeasurementQuantitiesValueValueCodec is the concrete ValueCodec[MeasurementQuantitiesValue].
type MeasurementQuantitiesValueValueCodec = s00.MeasurementQuantitiesValueValueCodec

const MissingMandatory = s00.MissingMandatory

// NPRSConfiguration represents the ASN.1 type NPRSConfiguration (SEQUENCE).
type NPRSConfiguration = s07.NPRSConfiguration

// NPRSConfigurationAPERValue is the concrete APERValue[NPRSConfiguration].
type NPRSConfigurationAPERValue = s07.NPRSConfigurationAPERValue

// NPRSConfigurationCodec binds the complete source value type.
var NPRSConfigurationCodec func() NPRSConfigurationValueCodec = s07.NPRSConfigurationCodec

// NPRSConfigurationValueCodec is the concrete ValueCodec[NPRSConfiguration].
type NPRSConfigurationValueCodec = s07.NPRSConfigurationValueCodec

// NPRSMutingConfiguration represents the ASN.1 CHOICE type NPRSMutingConfiguration.
type NPRSMutingConfiguration = s07.NPRSMutingConfiguration

// NPRSMutingConfigurationAPERValue is the concrete APERValue[NPRSMutingConfiguration].
type NPRSMutingConfigurationAPERValue = s07.NPRSMutingConfigurationAPERValue

// NPRSMutingConfiguration choice constants.
const NPRSMutingConfigurationChoiceEight = s00.NPRSMutingConfigurationChoiceEight

// NPRSMutingConfiguration choice constants.
const NPRSMutingConfigurationChoiceFour = s00.NPRSMutingConfigurationChoiceFour

// NPRSMutingConfiguration choice constants.
const NPRSMutingConfigurationChoiceSixteen = s00.NPRSMutingConfigurationChoiceSixteen

// NPRSMutingConfiguration choice constants.
const NPRSMutingConfigurationChoiceTwo = s00.NPRSMutingConfigurationChoiceTwo

// NPRSMutingConfigurationCodec binds the complete source value type.
var NPRSMutingConfigurationCodec func() NPRSMutingConfigurationValueCodec = s07.NPRSMutingConfigurationCodec

// NPRSMutingConfigurationValueCodec is the concrete ValueCodec[NPRSMutingConfiguration].
type NPRSMutingConfigurationValueCodec = s07.NPRSMutingConfigurationValueCodec

// NPRSSequenceInfo represents the ASN.1 type NPRSSequenceInfo (INTEGER).
type NPRSSequenceInfo = s00.NPRSSequenceInfo

// NPRSSequenceInfoAPERValue is the concrete APERValue[NPRSSequenceInfo].
type NPRSSequenceInfoAPERValue = s00.NPRSSequenceInfoAPERValue

// NPRSSequenceInfoCodec binds the complete source value type.
var NPRSSequenceInfoCodec func() NPRSSequenceInfoValueCodec = s02.NPRSSequenceInfoCodec

// NPRSSequenceInfoValueCodec is the concrete ValueCodec[NPRSSequenceInfo].
type NPRSSequenceInfoValueCodec = s00.NPRSSequenceInfoValueCodec

// NPRSSubframePartA represents the ASN.1 type NPRSSubframePartA (SEQUENCE).
type NPRSSubframePartA = s07.NPRSSubframePartA

// NPRSSubframePartAAPERValue is the concrete APERValue[NPRSSubframePartA].
type NPRSSubframePartAAPERValue = s07.NPRSSubframePartAAPERValue

// NPRSSubframePartACodec binds the complete source value type.
var NPRSSubframePartACodec func() NPRSSubframePartAValueCodec = s07.NPRSSubframePartACodec

// NPRSSubframePartAValueCodec is the concrete ValueCodec[NPRSSubframePartA].
type NPRSSubframePartAValueCodec = s07.NPRSSubframePartAValueCodec

// NPRSSubframePartB represents the ASN.1 type NPRSSubframePartB (SEQUENCE).
type NPRSSubframePartB = s07.NPRSSubframePartB

// NPRSSubframePartBAPERValue is the concrete APERValue[NPRSSubframePartB].
type NPRSSubframePartBAPERValue = s07.NPRSSubframePartBAPERValue

// NPRSSubframePartBCodec binds the complete source value type.
var NPRSSubframePartBCodec func() NPRSSubframePartBValueCodec = s07.NPRSSubframePartBCodec

// NPRSSubframePartBValueCodec is the concrete ValueCodec[NPRSSubframePartB].
type NPRSSubframePartBValueCodec = s07.NPRSSubframePartBValueCodec

// NRARFCN represents the ASN.1 type NRARFCN (INTEGER).
type NRARFCN = s00.NRARFCN

// NRARFCNAPERValue is the concrete APERValue[NRARFCN].
type NRARFCNAPERValue = s00.NRARFCNAPERValue

// NRARFCNCodec binds the complete source value type.
var NRARFCNCodec func() NRARFCNValueCodec = s04.NRARFCNCodec

// NRARFCNValueCodec is the concrete ValueCodec[NRARFCN].
type NRARFCNValueCodec = s00.NRARFCNValueCodec

// NRCGI represents the ASN.1 type NR-CGI (SEQUENCE).
type NRCGI = s07.NRCGI

// NRCGIAPERValue is the concrete APERValue[NRCGI].
type NRCGIAPERValue = s07.NRCGIAPERValue

// NRCGICodec binds the complete APER value type.
var NRCGICodec func() NRCGIValueCodec = s19.NRCGICodec

type NRCGIExtIETable = s04.NRCGIExtIETable

var NRCGIExtIEs func() NRCGIExtIETable = s04.NRCGIExtIEs

// NRCGIExtIEsExtContainer is the concrete ProtocolExtensionContainer[NRCGIExtIEsValue].
type NRCGIExtIEsExtContainer = s04.NRCGIExtIEsExtContainer

// NRCGIExtIEsExtField is the concrete ProtocolExtensionField[NRCGIExtIEsValue].
type NRCGIExtIEsExtField = s04.NRCGIExtIEsExtField

// NRCGIExtIEsIEContainer is the concrete ProtocolIEContainer[NRCGIExtIEsValue].
type NRCGIExtIEsIEContainer = s04.NRCGIExtIEsIEContainer

// NRCGIExtIEsIEField is the concrete ProtocolIEField[NRCGIExtIEsValue].
type NRCGIExtIEsIEField = s04.NRCGIExtIEsIEField
type NRCGIExtIEsValue = s02.NRCGIExtIEsValue

// NRCGIValueCodec is the concrete ValueCodec[NRCGI].
type NRCGIValueCodec = s07.NRCGIValueCodec

// NRCellIdentity represents the ASN.1 type NRCellIdentity (BIT_STRING).
type NRCellIdentity = s00.NRCellIdentity

// NRCellIdentityAPERValue is the concrete APERValue[NRCellIdentity].
type NRCellIdentityAPERValue = s00.NRCellIdentityAPERValue

// NRCellIdentityCodec binds the complete source value type.
var NRCellIdentityCodec func() NRCellIdentityValueCodec = s02.NRCellIdentityCodec

// NRCellIdentityValueCodec is the concrete ValueCodec[NRCellIdentity].
type NRCellIdentityValueCodec = s00.NRCellIdentityValueCodec

// NRPCI represents the ASN.1 type NRPCI (INTEGER).
type NRPCI = s00.NRPCI

// NRPCIAPERValue is the concrete APERValue[NRPCI].
type NRPCIAPERValue = s00.NRPCIAPERValue

// NRPCICodec binds the complete source value type.
var NRPCICodec func() NRPCIValueCodec = s04.NRPCICodec

// NRPCIValueCodec is the concrete ValueCodec[NRPCI].
type NRPCIValueCodec = s00.NRPCIValueCodec

// NarrowBandIndex represents the ASN.1 type NarrowBandIndex (INTEGER).
type NarrowBandIndex = s00.NarrowBandIndex

// NarrowBandIndexAPERValue is the concrete APERValue[NarrowBandIndex].
type NarrowBandIndexAPERValue = s00.NarrowBandIndexAPERValue

// NarrowBandIndexCodec binds the complete source value type.
var NarrowBandIndexCodec func() NarrowBandIndexValueCodec = s02.NarrowBandIndexCodec

// NarrowBandIndexValueCodec is the concrete ValueCodec[NarrowBandIndex].
type NarrowBandIndexValueCodec = s00.NarrowBandIndexValueCodec

var NewAssistanceInformationControl func(fields AssistanceInformationControlIEContainer, options ...aper.BuildOption) (AssistanceInformationControl, error) = s24.NewAssistanceInformationControl
var NewAssistanceInformationFeedback func(fields AssistanceInformationFeedbackIEContainer, options ...aper.BuildOption) (AssistanceInformationFeedback, error) = s23.NewAssistanceInformationFeedback

// NewBitmapsforNPRSForty constructs a checked complete value.
var NewBitmapsforNPRSForty func(v runtime.BitString, options ...aper.BuildOption) (BitmapsforNPRS, error) = s11.NewBitmapsforNPRSForty

// NewBitmapsforNPRSFortyTdd constructs a checked complete value.
var NewBitmapsforNPRSFortyTdd func(v runtime.BitString, options ...aper.BuildOption) (BitmapsforNPRS, error) = s11.NewBitmapsforNPRSFortyTdd

// NewBitmapsforNPRSTen constructs a checked complete value.
var NewBitmapsforNPRSTen func(v runtime.BitString, options ...aper.BuildOption) (BitmapsforNPRS, error) = s11.NewBitmapsforNPRSTen

// NewBitmapsforNPRSTenTdd constructs a checked complete value.
var NewBitmapsforNPRSTenTdd func(v runtime.BitString, options ...aper.BuildOption) (BitmapsforNPRS, error) = s11.NewBitmapsforNPRSTenTdd

// NewBitmapsforNPRSUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewBitmapsforNPRSUnknownExtension func(index uint64, contents []byte, options ...aper.BuildOption) (BitmapsforNPRS, error) = s07.NewBitmapsforNPRSUnknownExtension

// NewCauseMisc constructs a checked complete value.
var NewCauseMisc func(v CauseMisc, options ...aper.BuildOption) (Cause, error) = s11.NewCauseMisc

// NewCauseProtocol constructs a checked complete value.
var NewCauseProtocol func(v CauseProtocol, options ...aper.BuildOption) (Cause, error) = s11.NewCauseProtocol

// NewCauseRadioNetwork constructs a checked complete value.
var NewCauseRadioNetwork func(v CauseRadioNetwork, options ...aper.BuildOption) (Cause, error) = s11.NewCauseRadioNetwork

// NewCauseUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewCauseUnknownExtension func(index uint64, contents []byte, options ...aper.BuildOption) (Cause, error) = s07.NewCauseUnknownExtension
var NewECIDMeasurementFailureIndication func(fields ECIDMeasurementFailureIndicationIEContainer, options ...aper.BuildOption) (ECIDMeasurementFailureIndication, error) = s23.NewECIDMeasurementFailureIndication
var NewECIDMeasurementInitiationFailure func(fields ECIDMeasurementInitiationFailureIEContainer, options ...aper.BuildOption) (ECIDMeasurementInitiationFailure, error) = s23.NewECIDMeasurementInitiationFailure
var NewECIDMeasurementInitiationRequest func(fields ECIDMeasurementInitiationRequestIEContainer, options ...aper.BuildOption) (ECIDMeasurementInitiationRequest, error) = s24.NewECIDMeasurementInitiationRequest
var NewECIDMeasurementInitiationResponse func(fields ECIDMeasurementInitiationResponseIEContainer, options ...aper.BuildOption) (ECIDMeasurementInitiationResponse, error) = s24.NewECIDMeasurementInitiationResponse
var NewECIDMeasurementReport func(fields ECIDMeasurementReportIEContainer, options ...aper.BuildOption) (ECIDMeasurementReport, error) = s23.NewECIDMeasurementReport
var NewECIDMeasurementTerminationCommand func(fields ECIDMeasurementTerminationCommandIEContainer, options ...aper.BuildOption) (ECIDMeasurementTerminationCommand, error) = s23.NewECIDMeasurementTerminationCommand
var NewErrorIndication func(fields ErrorIndicationIEContainer, options ...aper.BuildOption) (ErrorIndication, error) = s23.NewErrorIndication

// NewInterRATMeasuredResultsValueResultGERAN constructs a checked complete value.
var NewInterRATMeasuredResultsValueResultGERAN func(v ResultGERAN, options ...aper.BuildOption) (InterRATMeasuredResultsValue, error) = s20.NewInterRATMeasuredResultsValueResultGERAN

// NewInterRATMeasuredResultsValueResultNR constructs a checked complete value.
var NewInterRATMeasuredResultsValueResultNR func(v ResultNR, options ...aper.BuildOption) (InterRATMeasuredResultsValue, error) = s20.NewInterRATMeasuredResultsValueResultNR

// NewInterRATMeasuredResultsValueResultUTRAN constructs a checked complete value.
var NewInterRATMeasuredResultsValueResultUTRAN func(v ResultUTRAN, options ...aper.BuildOption) (InterRATMeasuredResultsValue, error) = s20.NewInterRATMeasuredResultsValueResultUTRAN

// NewInterRATMeasuredResultsValueUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewInterRATMeasuredResultsValueUnknownExtension func(index uint64, contents []byte, options ...aper.BuildOption) (InterRATMeasuredResultsValue, error) = s20.NewInterRATMeasuredResultsValueUnknownExtension

// NewLPPAPDUInitiatingMessage constructs and validates a complete LPPa message.
var NewLPPAPDUInitiatingMessage func(v InitiatingMessage, options ...aper.BuildOption) (LPPAPDU, error) = s24.NewLPPAPDUInitiatingMessage

// NewLPPAPDUSuccessfulOutcome constructs and validates a complete LPPa message.
var NewLPPAPDUSuccessfulOutcome func(v SuccessfulOutcome, options ...aper.BuildOption) (LPPAPDU, error) = s24.NewLPPAPDUSuccessfulOutcome

// NewLPPAPDUUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewLPPAPDUUnknownExtension func(index uint64, contents []byte, options ...aper.BuildOption) (LPPAPDU, error) = s23.NewLPPAPDUUnknownExtension

// NewLPPAPDUUnsuccessfulOutcome constructs and validates a complete LPPa message.
var NewLPPAPDUUnsuccessfulOutcome func(v UnsuccessfulOutcome, options ...aper.BuildOption) (LPPAPDU, error) = s24.NewLPPAPDUUnsuccessfulOutcome

// NewMeasuredResultsValueResultRSRP constructs a checked complete value.
var NewMeasuredResultsValueResultRSRP func(v ResultRSRP, options ...aper.BuildOption) (MeasuredResultsValue, error) = s13.NewMeasuredResultsValueResultRSRP

// NewMeasuredResultsValueResultRSRQ constructs a checked complete value.
var NewMeasuredResultsValueResultRSRQ func(v ResultRSRQ, options ...aper.BuildOption) (MeasuredResultsValue, error) = s13.NewMeasuredResultsValueResultRSRQ

// NewMeasuredResultsValueUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewMeasuredResultsValueUnknownExtension func(index uint64, contents []byte, options ...aper.BuildOption) (MeasuredResultsValue, error) = s13.NewMeasuredResultsValueUnknownExtension

// NewMeasuredResultsValueValueAngleOfArrival constructs a checked complete value.
var NewMeasuredResultsValueValueAngleOfArrival func(v int64, options ...aper.BuildOption) (MeasuredResultsValue, error) = s13.NewMeasuredResultsValueValueAngleOfArrival

// NewMeasuredResultsValueValueTimingAdvanceType1 constructs a checked complete value.
var NewMeasuredResultsValueValueTimingAdvanceType1 func(v int64, options ...aper.BuildOption) (MeasuredResultsValue, error) = s13.NewMeasuredResultsValueValueTimingAdvanceType1

// NewMeasuredResultsValueValueTimingAdvanceType2 constructs a checked complete value.
var NewMeasuredResultsValueValueTimingAdvanceType2 func(v int64, options ...aper.BuildOption) (MeasuredResultsValue, error) = s13.NewMeasuredResultsValueValueTimingAdvanceType2

// NewNPRSMutingConfigurationEight constructs a checked complete value.
var NewNPRSMutingConfigurationEight func(v runtime.BitString, options ...aper.BuildOption) (NPRSMutingConfiguration, error) = s11.NewNPRSMutingConfigurationEight

// NewNPRSMutingConfigurationFour constructs a checked complete value.
var NewNPRSMutingConfigurationFour func(v runtime.BitString, options ...aper.BuildOption) (NPRSMutingConfiguration, error) = s11.NewNPRSMutingConfigurationFour

// NewNPRSMutingConfigurationSixteen constructs a checked complete value.
var NewNPRSMutingConfigurationSixteen func(v runtime.BitString, options ...aper.BuildOption) (NPRSMutingConfiguration, error) = s11.NewNPRSMutingConfigurationSixteen

// NewNPRSMutingConfigurationTwo constructs a checked complete value.
var NewNPRSMutingConfigurationTwo func(v runtime.BitString, options ...aper.BuildOption) (NPRSMutingConfiguration, error) = s11.NewNPRSMutingConfigurationTwo

// NewNPRSMutingConfigurationUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewNPRSMutingConfigurationUnknownExtension func(index uint64, contents []byte, options ...aper.BuildOption) (NPRSMutingConfiguration, error) = s07.NewNPRSMutingConfigurationUnknownExtension

// NewOTDOACellInformationItemCPLength constructs a checked complete value.
var NewOTDOACellInformationItemCPLength func(v CPLength, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemCPLength

// NewOTDOACellInformationItemCellId constructs a checked complete value.
var NewOTDOACellInformationItemCellId func(v ECGI, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemCellId

// NewOTDOACellInformationItemCrsCPlength constructs a checked complete value.
var NewOTDOACellInformationItemCrsCPlength func(v CPLength, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemCrsCPlength

// NewOTDOACellInformationItemDLBandwidth constructs a checked complete value.
var NewOTDOACellInformationItemDLBandwidth func(v DLBandwidth, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemDLBandwidth

// NewOTDOACellInformationItemEARFCN constructs a checked complete value.
var NewOTDOACellInformationItemEARFCN func(v EARFCN, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemEARFCN

// NewOTDOACellInformationItemEUTRANAccessPointPosition constructs a checked complete value.
var NewOTDOACellInformationItemEUTRANAccessPointPosition func(v EUTRANAccessPointPosition, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemEUTRANAccessPointPosition

// NewOTDOACellInformationItemMBSFNsubframeConfiguration constructs a checked complete value.
var NewOTDOACellInformationItemMBSFNsubframeConfiguration func(v MBSFNsubframeConfiguration, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemMBSFNsubframeConfiguration

// NewOTDOACellInformationItemNPRSConfiguration constructs a checked complete value.
var NewOTDOACellInformationItemNPRSConfiguration func(v NPRSConfiguration, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemNPRSConfiguration

// NewOTDOACellInformationItemNPRSID constructs a checked complete value.
var NewOTDOACellInformationItemNPRSID func(v *big.Int, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemNPRSID

// NewOTDOACellInformationItemNPRSSequenceInfo constructs a checked complete value.
var NewOTDOACellInformationItemNPRSSequenceInfo func(v NPRSSequenceInfo, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemNPRSSequenceInfo

// NewOTDOACellInformationItemNPRSType2 constructs a checked complete value.
var NewOTDOACellInformationItemNPRSType2 func(v NPRSConfiguration, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemNPRSType2

// NewOTDOACellInformationItemNumberOfAntennaPorts constructs a checked complete value.
var NewOTDOACellInformationItemNumberOfAntennaPorts func(v NumberOfAntennaPorts, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemNumberOfAntennaPorts

// NewOTDOACellInformationItemNumberOfDlFrames constructs a checked complete value.
var NewOTDOACellInformationItemNumberOfDlFrames func(v NumberOfDlFrames, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemNumberOfDlFrames

// NewOTDOACellInformationItemNumberOfDlFramesExtended constructs a checked complete value.
var NewOTDOACellInformationItemNumberOfDlFramesExtended func(v NumberOfDlFramesExtended, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemNumberOfDlFramesExtended

// NewOTDOACellInformationItemOffsetNBChanneltoEARFCN constructs a checked complete value.
var NewOTDOACellInformationItemOffsetNBChanneltoEARFCN func(v OffsetNBChanneltoEARFCN, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemOffsetNBChanneltoEARFCN

// NewOTDOACellInformationItemOperationModeInfo constructs a checked complete value.
var NewOTDOACellInformationItemOperationModeInfo func(v OperationModeInfo, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemOperationModeInfo

// NewOTDOACellInformationItemPCI constructs a checked complete value.
var NewOTDOACellInformationItemPCI func(v PCI, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemPCI

// NewOTDOACellInformationItemPRSBandwidth constructs a checked complete value.
var NewOTDOACellInformationItemPRSBandwidth func(v PRSBandwidth, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemPRSBandwidth

// NewOTDOACellInformationItemPRSConfigurationIndex constructs a checked complete value.
var NewOTDOACellInformationItemPRSConfigurationIndex func(v PRSConfigurationIndex, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemPRSConfigurationIndex

// NewOTDOACellInformationItemPRSFreqHoppingConfig constructs a checked complete value.
var NewOTDOACellInformationItemPRSFreqHoppingConfig func(v PRSFrequencyHoppingConfiguration, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemPRSFreqHoppingConfig

// NewOTDOACellInformationItemPRSMutingConfiguration constructs a checked complete value.
var NewOTDOACellInformationItemPRSMutingConfiguration func(v PRSMutingConfiguration, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemPRSMutingConfiguration

// NewOTDOACellInformationItemPRSOccasionGroup constructs a checked complete value.
var NewOTDOACellInformationItemPRSOccasionGroup func(v PRSOccasionGroup, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemPRSOccasionGroup

// NewOTDOACellInformationItemPrsid constructs a checked complete value.
var NewOTDOACellInformationItemPrsid func(v PRSID, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemPrsid

// NewOTDOACellInformationItemRepetitionNumberofSIB1NB constructs a checked complete value.
var NewOTDOACellInformationItemRepetitionNumberofSIB1NB func(v RepetitionNumberofSIB1NB, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemRepetitionNumberofSIB1NB

// NewOTDOACellInformationItemSFNInitialisationTime constructs a checked complete value.
var NewOTDOACellInformationItemSFNInitialisationTime func(v SFNInitialisationTime, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemSFNInitialisationTime

// NewOTDOACellInformationItemTAC constructs a checked complete value.
var NewOTDOACellInformationItemTAC func(v TAC, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemTAC

// NewOTDOACellInformationItemTddConfiguration constructs a checked complete value.
var NewOTDOACellInformationItemTddConfiguration func(v TDDConfiguration, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemTddConfiguration

// NewOTDOACellInformationItemTpType constructs a checked complete value.
var NewOTDOACellInformationItemTpType func(v TPType, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemTpType

// NewOTDOACellInformationItemTpid constructs a checked complete value.
var NewOTDOACellInformationItemTpid func(v TPID, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s16.NewOTDOACellInformationItemTpid

// NewOTDOACellInformationItemUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewOTDOACellInformationItemUnknownExtension func(index uint64, contents []byte, options ...aper.BuildOption) (OTDOACellInformationItem, error) = s15.NewOTDOACellInformationItemUnknownExtension
var NewOTDOAInformationFailure func(fields OTDOAInformationFailureIEContainer, options ...aper.BuildOption) (OTDOAInformationFailure, error) = s23.NewOTDOAInformationFailure
var NewOTDOAInformationRequest func(fields OTDOAInformationRequestIEContainer, options ...aper.BuildOption) (OTDOAInformationRequest, error) = s23.NewOTDOAInformationRequest
var NewOTDOAInformationResponse func(fields OTDOAInformationResponseIEContainer, options ...aper.BuildOption) (OTDOAInformationResponse, error) = s24.NewOTDOAInformationResponse
var NewOpaqueInitiatingMessage func(code ProcedureCode, criticality Criticality, transactionID LPPATransactionID, data []byte) (InitiatingMessage, error) = s21.NewOpaqueInitiatingMessage
var NewOpaqueSuccessfulOutcome func(code ProcedureCode, criticality Criticality, transactionID LPPATransactionID, data []byte) (SuccessfulOutcome, error) = s23.NewOpaqueSuccessfulOutcome
var NewOpaqueUnsuccessfulOutcome func(code ProcedureCode, criticality Criticality, transactionID LPPATransactionID, data []byte) (UnsuccessfulOutcome, error) = s16.NewOpaqueUnsuccessfulOutcome

// NewPRSMutingConfigurationEight constructs a checked complete value.
var NewPRSMutingConfigurationEight func(v runtime.BitString, options ...aper.BuildOption) (PRSMutingConfiguration, error) = s11.NewPRSMutingConfigurationEight

// NewPRSMutingConfigurationFiveHundredAndTwelve constructs a checked complete value.
var NewPRSMutingConfigurationFiveHundredAndTwelve func(v runtime.BitString, options ...aper.BuildOption) (PRSMutingConfiguration, error) = s11.NewPRSMutingConfigurationFiveHundredAndTwelve

// NewPRSMutingConfigurationFour constructs a checked complete value.
var NewPRSMutingConfigurationFour func(v runtime.BitString, options ...aper.BuildOption) (PRSMutingConfiguration, error) = s12.NewPRSMutingConfigurationFour

// NewPRSMutingConfigurationOneHundredAndTwentyEight constructs a checked complete value.
var NewPRSMutingConfigurationOneHundredAndTwentyEight func(v runtime.BitString, options ...aper.BuildOption) (PRSMutingConfiguration, error) = s12.NewPRSMutingConfigurationOneHundredAndTwentyEight

// NewPRSMutingConfigurationOneThousandAndTwentyFour constructs a checked complete value.
var NewPRSMutingConfigurationOneThousandAndTwentyFour func(v runtime.BitString, options ...aper.BuildOption) (PRSMutingConfiguration, error) = s12.NewPRSMutingConfigurationOneThousandAndTwentyFour

// NewPRSMutingConfigurationSixteen constructs a checked complete value.
var NewPRSMutingConfigurationSixteen func(v runtime.BitString, options ...aper.BuildOption) (PRSMutingConfiguration, error) = s12.NewPRSMutingConfigurationSixteen

// NewPRSMutingConfigurationSixtyFour constructs a checked complete value.
var NewPRSMutingConfigurationSixtyFour func(v runtime.BitString, options ...aper.BuildOption) (PRSMutingConfiguration, error) = s12.NewPRSMutingConfigurationSixtyFour

// NewPRSMutingConfigurationThirtyTwo constructs a checked complete value.
var NewPRSMutingConfigurationThirtyTwo func(v runtime.BitString, options ...aper.BuildOption) (PRSMutingConfiguration, error) = s12.NewPRSMutingConfigurationThirtyTwo

// NewPRSMutingConfigurationTwo constructs a checked complete value.
var NewPRSMutingConfigurationTwo func(v runtime.BitString, options ...aper.BuildOption) (PRSMutingConfiguration, error) = s12.NewPRSMutingConfigurationTwo

// NewPRSMutingConfigurationTwoHundredAndFiftySix constructs a checked complete value.
var NewPRSMutingConfigurationTwoHundredAndFiftySix func(v runtime.BitString, options ...aper.BuildOption) (PRSMutingConfiguration, error) = s12.NewPRSMutingConfigurationTwoHundredAndFiftySix

// NewPRSMutingConfigurationUnknownExtension builds a checked, owned unknown CHOICE alternative.
var NewPRSMutingConfigurationUnknownExtension func(index uint64, contents []byte, options ...aper.BuildOption) (PRSMutingConfiguration, error) = s08.NewPRSMutingConfigurationUnknownExtension

type NewPayloadCodec[T any] = s23.NewPayloadCodec[T]

// NewPrivateIEIDGlobal constructs a checked complete value.
var NewPrivateIEIDGlobal func(v runtime.ObjectIdentifier, options ...aper.BuildOption) (PrivateIEID, error) = s12.NewPrivateIEIDGlobal

// NewPrivateIEIDLocal constructs a checked complete value.
var NewPrivateIEIDLocal func(v int64, options ...aper.BuildOption) (PrivateIEID, error) = s12.NewPrivateIEIDLocal
var NewPrivateMessage func(fields PrivateMessageIEsValuePrivateIEContainer, options ...aper.BuildOption) (PrivateMessage, error) = s20.NewPrivateMessage

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD constructs a checked complete value.
var NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD func(v PhysCellIDUTRAFDD, options ...aper.BuildOption) (ResultUTRANItemPhysCellIDUTRAN, error) = s12.NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD constructs a checked complete value.
var NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD func(v PhysCellIDUTRATDD, options ...aper.BuildOption) (ResultUTRANItemPhysCellIDUTRAN, error) = s12.NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD

// NewSubframeallocationFourFrames constructs a checked complete value.
var NewSubframeallocationFourFrames func(v runtime.BitString, options ...aper.BuildOption) (Subframeallocation, error) = s12.NewSubframeallocationFourFrames

// NewSubframeallocationOneFrame constructs a checked complete value.
var NewSubframeallocationOneFrame func(v runtime.BitString, options ...aper.BuildOption) (Subframeallocation, error) = s12.NewSubframeallocationOneFrame
var NewUTDOAInformationFailure func(fields UTDOAInformationFailureIEContainer, options ...aper.BuildOption) (UTDOAInformationFailure, error) = s24.NewUTDOAInformationFailure
var NewUTDOAInformationRequest func(fields UTDOAInformationRequestIEContainer, options ...aper.BuildOption) (UTDOAInformationRequest, error) = s24.NewUTDOAInformationRequest
var NewUTDOAInformationResponse func(fields UTDOAInformationResponseIEContainer, options ...aper.BuildOption) (UTDOAInformationResponse, error) = s24.NewUTDOAInformationResponse
var NewUTDOAInformationUpdate func(fields UTDOAInformationUpdateIEContainer, options ...aper.BuildOption) (UTDOAInformationUpdate, error) = s24.NewUTDOAInformationUpdate

const NotAllowed = s00.NotAllowed

// NumberOfAntennaPorts represents the ASN.1 ENUMERATED type NumberOfAntennaPorts.
type NumberOfAntennaPorts = s00.NumberOfAntennaPorts

// NumberOfAntennaPortsAPERValue is the concrete APERValue[NumberOfAntennaPorts].
type NumberOfAntennaPortsAPERValue = s00.NumberOfAntennaPortsAPERValue

// NumberOfAntennaPortsCodec binds the complete source value type.
var NumberOfAntennaPortsCodec func() NumberOfAntennaPortsValueCodec = s02.NumberOfAntennaPortsCodec

const NumberOfAntennaPortsN1OrN2 = s00.NumberOfAntennaPortsN1OrN2
const NumberOfAntennaPortsN4 = s00.NumberOfAntennaPortsN4

// NumberOfAntennaPortsValueCodec is the concrete ValueCodec[NumberOfAntennaPorts].
type NumberOfAntennaPortsValueCodec = s00.NumberOfAntennaPortsValueCodec

// NumberOfDlFrames represents the ASN.1 ENUMERATED type NumberOfDlFrames.
type NumberOfDlFrames = s00.NumberOfDlFrames

// NumberOfDlFramesAPERValue is the concrete APERValue[NumberOfDlFrames].
type NumberOfDlFramesAPERValue = s00.NumberOfDlFramesAPERValue

// NumberOfDlFramesCodec binds the complete source value type.
var NumberOfDlFramesCodec func() NumberOfDlFramesValueCodec = s02.NumberOfDlFramesCodec

// NumberOfDlFramesExtended represents the ASN.1 type NumberOfDlFrames-Extended (INTEGER).
type NumberOfDlFramesExtended = s00.NumberOfDlFramesExtended

// NumberOfDlFramesExtendedAPERValue is the concrete APERValue[NumberOfDlFramesExtended].
type NumberOfDlFramesExtendedAPERValue = s00.NumberOfDlFramesExtendedAPERValue

// NumberOfDlFramesExtendedCodec binds the complete source value type.
var NumberOfDlFramesExtendedCodec func() NumberOfDlFramesExtendedValueCodec = s02.NumberOfDlFramesExtendedCodec

// NumberOfDlFramesExtendedValueCodec is the concrete ValueCodec[NumberOfDlFramesExtended].
type NumberOfDlFramesExtendedValueCodec = s00.NumberOfDlFramesExtendedValueCodec

const NumberOfDlFramesSf1 = s00.NumberOfDlFramesSf1
const NumberOfDlFramesSf2 = s00.NumberOfDlFramesSf2
const NumberOfDlFramesSf4 = s00.NumberOfDlFramesSf4
const NumberOfDlFramesSf6 = s00.NumberOfDlFramesSf6

// NumberOfDlFramesValueCodec is the concrete ValueCodec[NumberOfDlFrames].
type NumberOfDlFramesValueCodec = s00.NumberOfDlFramesValueCodec

// NumberOfFrequencyHoppingBands represents the ASN.1 ENUMERATED type NumberOfFrequencyHoppingBands.
type NumberOfFrequencyHoppingBands = s00.NumberOfFrequencyHoppingBands

// NumberOfFrequencyHoppingBandsAPERValue is the concrete APERValue[NumberOfFrequencyHoppingBands].
type NumberOfFrequencyHoppingBandsAPERValue = s01.NumberOfFrequencyHoppingBandsAPERValue

// NumberOfFrequencyHoppingBandsCodec binds the complete source value type.
var NumberOfFrequencyHoppingBandsCodec func() NumberOfFrequencyHoppingBandsValueCodec = s02.NumberOfFrequencyHoppingBandsCodec

const NumberOfFrequencyHoppingBandsFourbands = s00.NumberOfFrequencyHoppingBandsFourbands
const NumberOfFrequencyHoppingBandsTwobands = s00.NumberOfFrequencyHoppingBandsTwobands

// NumberOfFrequencyHoppingBandsValueCodec is the concrete ValueCodec[NumberOfFrequencyHoppingBands].
type NumberOfFrequencyHoppingBandsValueCodec = s01.NumberOfFrequencyHoppingBandsValueCodec
type OTDOACellInformation = s15.OTDOACellInformation

// OTDOACellInformationAPERValue is the concrete APERValue[OTDOACellInformation].
type OTDOACellInformationAPERValue = s15.OTDOACellInformationAPERValue

// OTDOACellInformationCodec binds the complete source value type.
var OTDOACellInformationCodec func() OTDOACellInformationValueCodec = s18.OTDOACellInformationCodec

// OTDOACellInformationComplete carries a complete OTDOACellInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOACellInformationComplete = s18.OTDOACellInformationComplete

// OTDOACellInformationItem represents the ASN.1 CHOICE type OTDOACell-Information-Item.
type OTDOACellInformationItem = s15.OTDOACellInformationItem

// OTDOACellInformationItemAPERValue is the concrete APERValue[OTDOACellInformationItem].
type OTDOACellInformationItemAPERValue = s15.OTDOACellInformationItemAPERValue

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceCPLength = s00.OTDOACellInformationItemChoiceCPLength

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceCellId = s00.OTDOACellInformationItemChoiceCellId

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceCrsCPlength = s00.OTDOACellInformationItemChoiceCrsCPlength

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceDLBandwidth = s00.OTDOACellInformationItemChoiceDLBandwidth

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceEARFCN = s00.OTDOACellInformationItemChoiceEARFCN

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceEUTRANAccessPointPosition = s00.OTDOACellInformationItemChoiceEUTRANAccessPointPosition

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceMBSFNsubframeConfiguration = s00.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNPRSConfiguration = s00.OTDOACellInformationItemChoiceNPRSConfiguration

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNPRSID = s00.OTDOACellInformationItemChoiceNPRSID

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNPRSSequenceInfo = s00.OTDOACellInformationItemChoiceNPRSSequenceInfo

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNPRSType2 = s00.OTDOACellInformationItemChoiceNPRSType2

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNumberOfAntennaPorts = s00.OTDOACellInformationItemChoiceNumberOfAntennaPorts

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNumberOfDlFrames = s00.OTDOACellInformationItemChoiceNumberOfDlFrames

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceNumberOfDlFramesExtended = s00.OTDOACellInformationItemChoiceNumberOfDlFramesExtended

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN = s00.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceOperationModeInfo = s00.OTDOACellInformationItemChoiceOperationModeInfo

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePCI = s00.OTDOACellInformationItemChoicePCI

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePRSBandwidth = s00.OTDOACellInformationItemChoicePRSBandwidth

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePRSConfigurationIndex = s00.OTDOACellInformationItemChoicePRSConfigurationIndex

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePRSFreqHoppingConfig = s00.OTDOACellInformationItemChoicePRSFreqHoppingConfig

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePRSMutingConfiguration = s00.OTDOACellInformationItemChoicePRSMutingConfiguration

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePRSOccasionGroup = s00.OTDOACellInformationItemChoicePRSOccasionGroup

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoicePrsid = s00.OTDOACellInformationItemChoicePrsid

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB = s00.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceSFNInitialisationTime = s00.OTDOACellInformationItemChoiceSFNInitialisationTime

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceTAC = s00.OTDOACellInformationItemChoiceTAC

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceTddConfiguration = s00.OTDOACellInformationItemChoiceTddConfiguration

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceTpType = s00.OTDOACellInformationItemChoiceTpType

// OTDOACellInformationItem choice constants.
const OTDOACellInformationItemChoiceTpid = s00.OTDOACellInformationItemChoiceTpid

// OTDOACellInformationItemCodec binds the complete source value type.
var OTDOACellInformationItemCodec func() OTDOACellInformationItemValueCodec = s15.OTDOACellInformationItemCodec

// OTDOACellInformationItemValueCodec is the concrete ValueCodec[OTDOACellInformationItem].
type OTDOACellInformationItemValueCodec = s15.OTDOACellInformationItemValueCodec

// OTDOACellInformationValueCodec is the concrete ValueCodec[OTDOACellInformation].
type OTDOACellInformationValueCodec = s15.OTDOACellInformationValueCodec
type OTDOACells = s16.OTDOACells

// OTDOACellsAPERValue is the concrete APERValue[OTDOACells].
type OTDOACellsAPERValue = s16.OTDOACellsAPERValue

// OTDOACellsCodec binds the complete APER value type.
var OTDOACellsCodec func() OTDOACellsValueCodec = s18.OTDOACellsCodec

// OTDOACellsComplete carries a complete OTDOACells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOACellsComplete = s18.OTDOACellsComplete

// OTDOACellsElem represents the ASN.1 type OTDOACells-Elem (SEQUENCE).
type OTDOACellsElem = s16.OTDOACellsElem

// OTDOACellsElemAPERValue is the concrete APERValue[OTDOACellsElem].
type OTDOACellsElemAPERValue = s16.OTDOACellsElemAPERValue

// OTDOACellsElemCodec binds the complete source value type.
var OTDOACellsElemCodec func() OTDOACellsElemValueCodec = s16.OTDOACellsElemCodec

// OTDOACellsElemValueCodec is the concrete ValueCodec[OTDOACellsElem].
type OTDOACellsElemValueCodec = s16.OTDOACellsElemValueCodec
type OTDOACellsExtIETable = s04.OTDOACellsExtIETable

var OTDOACellsExtIEs func() OTDOACellsExtIETable = s04.OTDOACellsExtIEs

// OTDOACellsExtIEsExtContainer is the concrete ProtocolExtensionContainer[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsExtContainer = s04.OTDOACellsExtIEsExtContainer

// OTDOACellsExtIEsExtField is the concrete ProtocolExtensionField[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsExtField = s04.OTDOACellsExtIEsExtField

// OTDOACellsExtIEsIEContainer is the concrete ProtocolIEContainer[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsIEContainer = s04.OTDOACellsExtIEsIEContainer

// OTDOACellsExtIEsIEField is the concrete ProtocolIEField[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsIEField = s04.OTDOACellsExtIEsIEField
type OTDOACellsExtIEsValue = s02.OTDOACellsExtIEsValue

// OTDOACellsValueCodec is the concrete ValueCodec[OTDOACells].
type OTDOACellsValueCodec = s16.OTDOACellsValueCodec
type OTDOAInformationExchangeDescriptor = s24.OTDOAInformationExchangeDescriptor

var OTDOAInformationExchangeProcedure func() OTDOAInformationExchangeDescriptor = s24.OTDOAInformationExchangeProcedure

// OTDOAInformationFailure represents the ASN.1 type OTDOAInformationFailure (SEQUENCE).
type OTDOAInformationFailure = s12.OTDOAInformationFailure

// OTDOAInformationFailureAPERValue is the concrete APERValue[OTDOAInformationFailure].
type OTDOAInformationFailureAPERValue = s12.OTDOAInformationFailureAPERValue

// OTDOAInformationFailureCauseIEBinding is the concrete IEBinding[Cause, OTDOAInformationFailureIEValue].
type OTDOAInformationFailureCauseIEBinding = s10.OTDOAInformationFailureCauseIEBinding

// OTDOAInformationFailureCodec binds the complete APER value type.
var OTDOAInformationFailureCodec func() OTDOAInformationFailureValueCodec = s24.OTDOAInformationFailureCodec

// OTDOAInformationFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, OTDOAInformationFailureIEValue].
type OTDOAInformationFailureCriticalityDiagnosticsIEBinding = s10.OTDOAInformationFailureCriticalityDiagnosticsIEBinding

// OTDOAInformationFailureIEContainer is the concrete ProtocolIEContainer[OTDOAInformationFailureIEValue].
type OTDOAInformationFailureIEContainer = s10.OTDOAInformationFailureIEContainer

// OTDOAInformationFailureIEField is the concrete ProtocolIEField[OTDOAInformationFailureIEValue].
type OTDOAInformationFailureIEField = s10.OTDOAInformationFailureIEField
type OTDOAInformationFailureIETable = s10.OTDOAInformationFailureIETable
type OTDOAInformationFailureIEValue = s10.OTDOAInformationFailureIEValue

var OTDOAInformationFailureIEs func() OTDOAInformationFailureIETable = s10.OTDOAInformationFailureIEs

// OTDOAInformationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[OTDOAInformationFailure].
type OTDOAInformationFailureUnsuccessfulBinding = s16.OTDOAInformationFailureUnsuccessfulBinding

// OTDOAInformationFailureValueCodec is the concrete ValueCodec[OTDOAInformationFailure].
type OTDOAInformationFailureValueCodec = s12.OTDOAInformationFailureValueCodec

// OTDOAInformationItem represents the ASN.1 ENUMERATED type OTDOA-Information-Item.
type OTDOAInformationItem = s00.OTDOAInformationItem

// OTDOAInformationItemAPERValue is the concrete APERValue[OTDOAInformationItem].
type OTDOAInformationItemAPERValue = s01.OTDOAInformationItemAPERValue

const OTDOAInformationItemCellid = s00.OTDOAInformationItemCellid

// OTDOAInformationItemCodec binds the complete source value type.
var OTDOAInformationItemCodec func() OTDOAInformationItemValueCodec = s02.OTDOAInformationItemCodec

const OTDOAInformationItemCpLength = s00.OTDOAInformationItemCpLength
const OTDOAInformationItemCrsCPlength = s00.OTDOAInformationItemCrsCPlength
const OTDOAInformationItemDlBandwidth = s00.OTDOAInformationItemDlBandwidth
const OTDOAInformationItemEUTRANAccessPointPosition = s00.OTDOAInformationItemEUTRANAccessPointPosition
const OTDOAInformationItemEarfcn = s00.OTDOAInformationItemEarfcn
const OTDOAInformationItemMBSFNsubframeConfiguration = s00.OTDOAInformationItemMBSFNsubframeConfiguration
const OTDOAInformationItemMultipleprsConfigurationsperCell = s00.OTDOAInformationItemMultipleprsConfigurationsperCell
const OTDOAInformationItemNPRSConfiguration = s00.OTDOAInformationItemNPRSConfiguration
const OTDOAInformationItemNPRSID = s00.OTDOAInformationItemNPRSID
const OTDOAInformationItemNPRSSequenceInfo = s00.OTDOAInformationItemNPRSSequenceInfo
const OTDOAInformationItemNPRSType2 = s00.OTDOAInformationItemNPRSType2
const OTDOAInformationItemNoAntennaPorts = s00.OTDOAInformationItemNoAntennaPorts
const OTDOAInformationItemNoDlFrames = s00.OTDOAInformationItemNoDlFrames
const OTDOAInformationItemOffsetNBChannelNumbertoEARFCN = s00.OTDOAInformationItemOffsetNBChannelNumbertoEARFCN
const OTDOAInformationItemOperationModeInfo = s00.OTDOAInformationItemOperationModeInfo
const OTDOAInformationItemPci = s00.OTDOAInformationItemPci
const OTDOAInformationItemPrsBandwidth = s00.OTDOAInformationItemPrsBandwidth
const OTDOAInformationItemPrsConfigIndex = s00.OTDOAInformationItemPrsConfigIndex
const OTDOAInformationItemPrsFrequencyHoppingConfiguration = s00.OTDOAInformationItemPrsFrequencyHoppingConfiguration
const OTDOAInformationItemPrsOccasionGroup = s00.OTDOAInformationItemPrsOccasionGroup
const OTDOAInformationItemPrsid = s00.OTDOAInformationItemPrsid
const OTDOAInformationItemPrsmutingconfiguration = s00.OTDOAInformationItemPrsmutingconfiguration
const OTDOAInformationItemRepetitionNumberofSIB1NB = s00.OTDOAInformationItemRepetitionNumberofSIB1NB
const OTDOAInformationItemSFNInitTime = s00.OTDOAInformationItemSFNInitTime
const OTDOAInformationItemTac = s00.OTDOAInformationItemTac
const OTDOAInformationItemTddConfig = s00.OTDOAInformationItemTddConfig
const OTDOAInformationItemTpType = s00.OTDOAInformationItemTpType
const OTDOAInformationItemTpid = s00.OTDOAInformationItemTpid

// OTDOAInformationItemValueCodec is the concrete ValueCodec[OTDOAInformationItem].
type OTDOAInformationItemValueCodec = s01.OTDOAInformationItemValueCodec

// OTDOAInformationRequest represents the ASN.1 type OTDOAInformationRequest (SEQUENCE).
type OTDOAInformationRequest = s18.OTDOAInformationRequest

// OTDOAInformationRequestAPERValue is the concrete APERValue[OTDOAInformationRequest].
type OTDOAInformationRequestAPERValue = s18.OTDOAInformationRequestAPERValue

// OTDOAInformationRequestCodec binds the complete APER value type.
var OTDOAInformationRequestCodec func() OTDOAInformationRequestValueCodec = s24.OTDOAInformationRequestCodec

// OTDOAInformationRequestIEContainer is the concrete ProtocolIEContainer[OTDOAInformationRequestIEValue].
type OTDOAInformationRequestIEContainer = s18.OTDOAInformationRequestIEContainer

// OTDOAInformationRequestIEField is the concrete ProtocolIEField[OTDOAInformationRequestIEValue].
type OTDOAInformationRequestIEField = s18.OTDOAInformationRequestIEField
type OTDOAInformationRequestIETable = s18.OTDOAInformationRequestIETable
type OTDOAInformationRequestIEValue = s18.OTDOAInformationRequestIEValue

var OTDOAInformationRequestIEs func() OTDOAInformationRequestIETable = s18.OTDOAInformationRequestIEs

// OTDOAInformationRequestInitiatingBinding is the concrete InitiatingBinding[OTDOAInformationRequest].
type OTDOAInformationRequestInitiatingBinding = s21.OTDOAInformationRequestInitiatingBinding

// OTDOAInformationRequestOTDOAInformationTypeIEBinding is the concrete IEBinding[OTDOAInformationType, OTDOAInformationRequestIEValue].
type OTDOAInformationRequestOTDOAInformationTypeIEBinding = s18.OTDOAInformationRequestOTDOAInformationTypeIEBinding

// OTDOAInformationRequestValueCodec is the concrete ValueCodec[OTDOAInformationRequest].
type OTDOAInformationRequestValueCodec = s18.OTDOAInformationRequestValueCodec

// OTDOAInformationResponse represents the ASN.1 type OTDOAInformationResponse (SEQUENCE).
type OTDOAInformationResponse = s18.OTDOAInformationResponse

// OTDOAInformationResponseAPERValue is the concrete APERValue[OTDOAInformationResponse].
type OTDOAInformationResponseAPERValue = s18.OTDOAInformationResponseAPERValue

// OTDOAInformationResponseAddOTDOACellsIEBinding is the concrete IEBinding[AddOTDOACells, OTDOAInformationResponseIEValue].
type OTDOAInformationResponseAddOTDOACellsIEBinding = s18.OTDOAInformationResponseAddOTDOACellsIEBinding

// OTDOAInformationResponseCodec binds the complete APER value type.
var OTDOAInformationResponseCodec func() OTDOAInformationResponseValueCodec = s24.OTDOAInformationResponseCodec

// OTDOAInformationResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, OTDOAInformationResponseIEValue].
type OTDOAInformationResponseCriticalityDiagnosticsIEBinding = s18.OTDOAInformationResponseCriticalityDiagnosticsIEBinding

// OTDOAInformationResponseIEContainer is the concrete ProtocolIEContainer[OTDOAInformationResponseIEValue].
type OTDOAInformationResponseIEContainer = s18.OTDOAInformationResponseIEContainer

// OTDOAInformationResponseIEField is the concrete ProtocolIEField[OTDOAInformationResponseIEValue].
type OTDOAInformationResponseIEField = s18.OTDOAInformationResponseIEField
type OTDOAInformationResponseIETable = s18.OTDOAInformationResponseIETable
type OTDOAInformationResponseIEValue = s18.OTDOAInformationResponseIEValue

var OTDOAInformationResponseIEs func() OTDOAInformationResponseIETable = s18.OTDOAInformationResponseIEs

// OTDOAInformationResponseOTDOACellsIEBinding is the concrete IEBinding[OTDOACells, OTDOAInformationResponseIEValue].
type OTDOAInformationResponseOTDOACellsIEBinding = s18.OTDOAInformationResponseOTDOACellsIEBinding

// OTDOAInformationResponseSuccessfulBinding is the concrete SuccessfulBinding[OTDOAInformationResponse].
type OTDOAInformationResponseSuccessfulBinding = s23.OTDOAInformationResponseSuccessfulBinding

// OTDOAInformationResponseValueCodec is the concrete ValueCodec[OTDOAInformationResponse].
type OTDOAInformationResponseValueCodec = s18.OTDOAInformationResponseValueCodec
type OTDOAInformationType = s07.OTDOAInformationType

// OTDOAInformationTypeAPERValue is the concrete APERValue[OTDOAInformationType].
type OTDOAInformationTypeAPERValue = s07.OTDOAInformationTypeAPERValue

// OTDOAInformationTypeCodec binds the complete APER value type.
var OTDOAInformationTypeCodec func() OTDOAInformationTypeValueCodec = s18.OTDOAInformationTypeCodec

// OTDOAInformationTypeComplete carries a complete OTDOAInformationType encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOAInformationTypeComplete = s18.OTDOAInformationTypeComplete

// OTDOAInformationTypeIEContainer is the concrete ProtocolIEContainer[OTDOAInformationTypeIEValue].
type OTDOAInformationTypeIEContainer = s07.OTDOAInformationTypeIEContainer

// OTDOAInformationTypeIEField is the concrete ProtocolIEField[OTDOAInformationTypeIEValue].
type OTDOAInformationTypeIEField = s07.OTDOAInformationTypeIEField
type OTDOAInformationTypeIETable = s07.OTDOAInformationTypeIETable
type OTDOAInformationTypeIEValue = s07.OTDOAInformationTypeIEValue

// OTDOAInformationTypeIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[OTDOAInformationTypeIEValue].
type OTDOAInformationTypeIEValueProtocolIESingleContainer = s07.OTDOAInformationTypeIEValueProtocolIESingleContainer

var OTDOAInformationTypeIEs func() OTDOAInformationTypeIETable = s07.OTDOAInformationTypeIEs

// OTDOAInformationTypeItem represents the ASN.1 type OTDOA-Information-Type-Item (SEQUENCE).
type OTDOAInformationTypeItem = s07.OTDOAInformationTypeItem

// OTDOAInformationTypeItemAPERValue is the concrete APERValue[OTDOAInformationTypeItem].
type OTDOAInformationTypeItemAPERValue = s07.OTDOAInformationTypeItemAPERValue

// OTDOAInformationTypeItemCodec binds the complete APER value type.
var OTDOAInformationTypeItemCodec func() OTDOAInformationTypeItemValueCodec = s07.OTDOAInformationTypeItemCodec

type OTDOAInformationTypeItemExtIETable = s04.OTDOAInformationTypeItemExtIETable

var OTDOAInformationTypeItemExtIEs func() OTDOAInformationTypeItemExtIETable = s04.OTDOAInformationTypeItemExtIEs

// OTDOAInformationTypeItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsExtContainer = s04.OTDOAInformationTypeItemExtIEsExtContainer

// OTDOAInformationTypeItemExtIEsExtField is the concrete ProtocolExtensionField[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsExtField = s04.OTDOAInformationTypeItemExtIEsExtField

// OTDOAInformationTypeItemExtIEsIEContainer is the concrete ProtocolIEContainer[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsIEContainer = s04.OTDOAInformationTypeItemExtIEsIEContainer

// OTDOAInformationTypeItemExtIEsIEField is the concrete ProtocolIEField[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsIEField = s04.OTDOAInformationTypeItemExtIEsIEField
type OTDOAInformationTypeItemExtIEsValue = s02.OTDOAInformationTypeItemExtIEsValue

// OTDOAInformationTypeItemValueCodec is the concrete ValueCodec[OTDOAInformationTypeItem].
type OTDOAInformationTypeItemValueCodec = s07.OTDOAInformationTypeItemValueCodec

// OTDOAInformationTypeOTDOAInformationTypeItemIEBinding is the concrete IEBinding[OTDOAInformationTypeItem, OTDOAInformationTypeIEValue].
type OTDOAInformationTypeOTDOAInformationTypeItemIEBinding = s07.OTDOAInformationTypeOTDOAInformationTypeItemIEBinding

// OTDOAInformationTypeValueCodec is the concrete ValueCodec[OTDOAInformationType].
type OTDOAInformationTypeValueCodec = s07.OTDOAInformationTypeValueCodec

// OffsetNBChanneltoEARFCN represents the ASN.1 ENUMERATED type OffsetNBChanneltoEARFCN.
type OffsetNBChanneltoEARFCN = s00.OffsetNBChanneltoEARFCN

// OffsetNBChanneltoEARFCNAPERValue is the concrete APERValue[OffsetNBChanneltoEARFCN].
type OffsetNBChanneltoEARFCNAPERValue = s01.OffsetNBChanneltoEARFCNAPERValue

// OffsetNBChanneltoEARFCNCodec binds the complete source value type.
var OffsetNBChanneltoEARFCNCodec func() OffsetNBChanneltoEARFCNValueCodec = s02.OffsetNBChanneltoEARFCNCodec

const OffsetNBChanneltoEARFCNEight = s00.OffsetNBChanneltoEARFCNEight
const OffsetNBChanneltoEARFCNFive = s00.OffsetNBChanneltoEARFCNFive
const OffsetNBChanneltoEARFCNFour = s00.OffsetNBChanneltoEARFCNFour
const OffsetNBChanneltoEARFCNMinusEight = s00.OffsetNBChanneltoEARFCNMinusEight
const OffsetNBChanneltoEARFCNMinusFive = s00.OffsetNBChanneltoEARFCNMinusFive
const OffsetNBChanneltoEARFCNMinusFour = s00.OffsetNBChanneltoEARFCNMinusFour
const OffsetNBChanneltoEARFCNMinusNine = s00.OffsetNBChanneltoEARFCNMinusNine
const OffsetNBChanneltoEARFCNMinusOne = s00.OffsetNBChanneltoEARFCNMinusOne
const OffsetNBChanneltoEARFCNMinusSeven = s00.OffsetNBChanneltoEARFCNMinusSeven
const OffsetNBChanneltoEARFCNMinusSix = s00.OffsetNBChanneltoEARFCNMinusSix
const OffsetNBChanneltoEARFCNMinusTen = s00.OffsetNBChanneltoEARFCNMinusTen
const OffsetNBChanneltoEARFCNMinusThree = s00.OffsetNBChanneltoEARFCNMinusThree
const OffsetNBChanneltoEARFCNMinusTwo = s00.OffsetNBChanneltoEARFCNMinusTwo
const OffsetNBChanneltoEARFCNMinusZeroDotFive = s00.OffsetNBChanneltoEARFCNMinusZeroDotFive
const OffsetNBChanneltoEARFCNNine = s00.OffsetNBChanneltoEARFCNNine
const OffsetNBChanneltoEARFCNOne = s00.OffsetNBChanneltoEARFCNOne
const OffsetNBChanneltoEARFCNSeven = s00.OffsetNBChanneltoEARFCNSeven
const OffsetNBChanneltoEARFCNSix = s00.OffsetNBChanneltoEARFCNSix
const OffsetNBChanneltoEARFCNThree = s00.OffsetNBChanneltoEARFCNThree
const OffsetNBChanneltoEARFCNTwo = s00.OffsetNBChanneltoEARFCNTwo

// OffsetNBChanneltoEARFCNValueCodec is the concrete ValueCodec[OffsetNBChanneltoEARFCN].
type OffsetNBChanneltoEARFCNValueCodec = s01.OffsetNBChanneltoEARFCNValueCodec

const OffsetNBChanneltoEARFCNZero = s00.OffsetNBChanneltoEARFCNZero

// OperationModeInfo represents the ASN.1 ENUMERATED type OperationModeInfo.
type OperationModeInfo = s00.OperationModeInfo

// OperationModeInfoAPERValue is the concrete APERValue[OperationModeInfo].
type OperationModeInfoAPERValue = s01.OperationModeInfoAPERValue

// OperationModeInfoCodec binds the complete source value type.
var OperationModeInfoCodec func() OperationModeInfoValueCodec = s02.OperationModeInfoCodec

const OperationModeInfoGuardband = s00.OperationModeInfoGuardband
const OperationModeInfoInband = s00.OperationModeInfoInband
const OperationModeInfoStandalone = s00.OperationModeInfoStandalone

// OperationModeInfoValueCodec is the concrete ValueCodec[OperationModeInfo].
type OperationModeInfoValueCodec = s01.OperationModeInfoValueCodec

// Outcome represents the ASN.1 ENUMERATED type Outcome.
type Outcome = s00.Outcome

// OutcomeAPERValue is the concrete APERValue[Outcome].
type OutcomeAPERValue = s01.OutcomeAPERValue

// OutcomeCodec binds the complete source value type.
var OutcomeCodec func() OutcomeValueCodec = s02.OutcomeCodec

const OutcomeFailed = s00.OutcomeFailed

// OutcomeValueCodec is the concrete ValueCodec[Outcome].
type OutcomeValueCodec = s01.OutcomeValueCodec

// PCI represents the ASN.1 type PCI (INTEGER).
type PCI = s00.PCI

// PCIAPERValue is the concrete APERValue[PCI].
type PCIAPERValue = s01.PCIAPERValue

// PCICodec binds the complete source value type.
var PCICodec func() PCIValueCodec = s02.PCICodec

// PCIValueCodec is the concrete ValueCodec[PCI].
type PCIValueCodec = s01.PCIValueCodec

// PLMNIdentity represents the ASN.1 type PLMN-Identity (OCTET_STRING).
type PLMNIdentity = s00.PLMNIdentity

// PLMNIdentityAPERValue is the concrete APERValue[PLMNIdentity].
type PLMNIdentityAPERValue = s01.PLMNIdentityAPERValue

// PLMNIdentityCodec binds the complete source value type.
var PLMNIdentityCodec func() PLMNIdentityValueCodec = s02.PLMNIdentityCodec

// PLMNIdentityValueCodec is the concrete ValueCodec[PLMNIdentity].
type PLMNIdentityValueCodec = s01.PLMNIdentityValueCodec

// PRSBandwidth represents the ASN.1 ENUMERATED type PRS-Bandwidth.
type PRSBandwidth = s00.PRSBandwidth

// PRSBandwidthAPERValue is the concrete APERValue[PRSBandwidth].
type PRSBandwidthAPERValue = s01.PRSBandwidthAPERValue

const PRSBandwidthBw100 = s00.PRSBandwidthBw100
const PRSBandwidthBw15 = s00.PRSBandwidthBw15
const PRSBandwidthBw25 = s00.PRSBandwidthBw25
const PRSBandwidthBw50 = s00.PRSBandwidthBw50
const PRSBandwidthBw6 = s00.PRSBandwidthBw6
const PRSBandwidthBw75 = s00.PRSBandwidthBw75

// PRSBandwidthCodec binds the complete source value type.
var PRSBandwidthCodec func() PRSBandwidthValueCodec = s02.PRSBandwidthCodec

// PRSBandwidthValueCodec is the concrete ValueCodec[PRSBandwidth].
type PRSBandwidthValueCodec = s01.PRSBandwidthValueCodec

// PRSConfigurationIndex represents the ASN.1 type PRS-Configuration-Index (INTEGER).
type PRSConfigurationIndex = s00.PRSConfigurationIndex

// PRSConfigurationIndexAPERValue is the concrete APERValue[PRSConfigurationIndex].
type PRSConfigurationIndexAPERValue = s01.PRSConfigurationIndexAPERValue

// PRSConfigurationIndexCodec binds the complete source value type.
var PRSConfigurationIndexCodec func() PRSConfigurationIndexValueCodec = s02.PRSConfigurationIndexCodec

// PRSConfigurationIndexValueCodec is the concrete ValueCodec[PRSConfigurationIndex].
type PRSConfigurationIndexValueCodec = s01.PRSConfigurationIndexValueCodec

// PRSFrequencyHoppingConfiguration represents the ASN.1 type PRSFrequencyHoppingConfiguration (SEQUENCE).
type PRSFrequencyHoppingConfiguration = s08.PRSFrequencyHoppingConfiguration

// PRSFrequencyHoppingConfigurationAPERValue is the concrete APERValue[PRSFrequencyHoppingConfiguration].
type PRSFrequencyHoppingConfigurationAPERValue = s08.PRSFrequencyHoppingConfigurationAPERValue
type PRSFrequencyHoppingConfigurationBandPositions = s00.PRSFrequencyHoppingConfigurationBandPositions

// PRSFrequencyHoppingConfigurationBandPositionsAPERValue is the concrete APERValue[PRSFrequencyHoppingConfigurationBandPositions].
type PRSFrequencyHoppingConfigurationBandPositionsAPERValue = s01.PRSFrequencyHoppingConfigurationBandPositionsAPERValue

// PRSFrequencyHoppingConfigurationBandPositionsCodec binds the complete source value type.
var PRSFrequencyHoppingConfigurationBandPositionsCodec func() PRSFrequencyHoppingConfigurationBandPositionsValueCodec = s19.PRSFrequencyHoppingConfigurationBandPositionsCodec

// PRSFrequencyHoppingConfigurationBandPositionsComplete carries a complete PRSFrequencyHoppingConfigurationBandPositions encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PRSFrequencyHoppingConfigurationBandPositionsComplete = s19.PRSFrequencyHoppingConfigurationBandPositionsComplete

// PRSFrequencyHoppingConfigurationBandPositionsValueCodec is the concrete ValueCodec[PRSFrequencyHoppingConfigurationBandPositions].
type PRSFrequencyHoppingConfigurationBandPositionsValueCodec = s01.PRSFrequencyHoppingConfigurationBandPositionsValueCodec

// PRSFrequencyHoppingConfigurationCodec binds the complete source value type.
var PRSFrequencyHoppingConfigurationCodec func() PRSFrequencyHoppingConfigurationValueCodec = s08.PRSFrequencyHoppingConfigurationCodec

type PRSFrequencyHoppingConfigurationItemIETable = s04.PRSFrequencyHoppingConfigurationItemIETable

var PRSFrequencyHoppingConfigurationItemIEs func() PRSFrequencyHoppingConfigurationItemIETable = s04.PRSFrequencyHoppingConfigurationItemIEs

// PRSFrequencyHoppingConfigurationItemIEsExtContainer is the concrete ProtocolExtensionContainer[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsExtContainer = s04.PRSFrequencyHoppingConfigurationItemIEsExtContainer

// PRSFrequencyHoppingConfigurationItemIEsExtField is the concrete ProtocolExtensionField[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsExtField = s04.PRSFrequencyHoppingConfigurationItemIEsExtField

// PRSFrequencyHoppingConfigurationItemIEsIEContainer is the concrete ProtocolIEContainer[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsIEContainer = s04.PRSFrequencyHoppingConfigurationItemIEsIEContainer

// PRSFrequencyHoppingConfigurationItemIEsIEField is the concrete ProtocolIEField[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsIEField = s04.PRSFrequencyHoppingConfigurationItemIEsIEField
type PRSFrequencyHoppingConfigurationItemIEsValue = s02.PRSFrequencyHoppingConfigurationItemIEsValue

// PRSFrequencyHoppingConfigurationValueCodec is the concrete ValueCodec[PRSFrequencyHoppingConfiguration].
type PRSFrequencyHoppingConfigurationValueCodec = s08.PRSFrequencyHoppingConfigurationValueCodec

// PRSID represents the ASN.1 type PRS-ID (INTEGER).
type PRSID = s00.PRSID

// PRSIDAPERValue is the concrete APERValue[PRSID].
type PRSIDAPERValue = s01.PRSIDAPERValue

// PRSIDCodec binds the complete source value type.
var PRSIDCodec func() PRSIDValueCodec = s02.PRSIDCodec

// PRSIDValueCodec is the concrete ValueCodec[PRSID].
type PRSIDValueCodec = s01.PRSIDValueCodec

// PRSMutingConfiguration represents the ASN.1 CHOICE type PRSMutingConfiguration.
type PRSMutingConfiguration = s08.PRSMutingConfiguration

// PRSMutingConfigurationAPERValue is the concrete APERValue[PRSMutingConfiguration].
type PRSMutingConfigurationAPERValue = s08.PRSMutingConfigurationAPERValue

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceEight = s00.PRSMutingConfigurationChoiceEight

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceFiveHundredAndTwelve = s00.PRSMutingConfigurationChoiceFiveHundredAndTwelve

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceFour = s00.PRSMutingConfigurationChoiceFour

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceOneHundredAndTwentyEight = s00.PRSMutingConfigurationChoiceOneHundredAndTwentyEight

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceOneThousandAndTwentyFour = s00.PRSMutingConfigurationChoiceOneThousandAndTwentyFour

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceSixteen = s00.PRSMutingConfigurationChoiceSixteen

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceSixtyFour = s00.PRSMutingConfigurationChoiceSixtyFour

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceThirtyTwo = s00.PRSMutingConfigurationChoiceThirtyTwo

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceTwo = s00.PRSMutingConfigurationChoiceTwo

// PRSMutingConfiguration choice constants.
const PRSMutingConfigurationChoiceTwoHundredAndFiftySix = s00.PRSMutingConfigurationChoiceTwoHundredAndFiftySix

// PRSMutingConfigurationCodec binds the complete source value type.
var PRSMutingConfigurationCodec func() PRSMutingConfigurationValueCodec = s08.PRSMutingConfigurationCodec

// PRSMutingConfigurationValueCodec is the concrete ValueCodec[PRSMutingConfiguration].
type PRSMutingConfigurationValueCodec = s08.PRSMutingConfigurationValueCodec

// PRSOccasionGroup represents the ASN.1 ENUMERATED type PRSOccasionGroup.
type PRSOccasionGroup = s00.PRSOccasionGroup

// PRSOccasionGroupAPERValue is the concrete APERValue[PRSOccasionGroup].
type PRSOccasionGroupAPERValue = s01.PRSOccasionGroupAPERValue

// PRSOccasionGroupCodec binds the complete source value type.
var PRSOccasionGroupCodec func() PRSOccasionGroupValueCodec = s02.PRSOccasionGroupCodec

const PRSOccasionGroupOg128 = s00.PRSOccasionGroupOg128
const PRSOccasionGroupOg16 = s00.PRSOccasionGroupOg16
const PRSOccasionGroupOg2 = s00.PRSOccasionGroupOg2
const PRSOccasionGroupOg32 = s00.PRSOccasionGroupOg32
const PRSOccasionGroupOg4 = s00.PRSOccasionGroupOg4
const PRSOccasionGroupOg64 = s00.PRSOccasionGroupOg64
const PRSOccasionGroupOg8 = s00.PRSOccasionGroupOg8

// PRSOccasionGroupValueCodec is the concrete ValueCodec[PRSOccasionGroup].
type PRSOccasionGroupValueCodec = s01.PRSOccasionGroupValueCodec

// PayloadCodec owns a typed foreign decoder and encoder. The callbacks must
// enforce the foreign schema and consume a complete value.
type PayloadCodec[T any] = s23.PayloadCodec[T]
type PayloadDeviation = s00.PayloadDeviation

// PayloadLimits bound a single call across a foreign byte boundary.
// Zero fields select finite defaults; the foreign callback applies its own
// schema and work/depth accounting.
type PayloadLimits = s00.PayloadLimits
type PayloadReport = s00.PayloadReport

// PhysCellIDGERAN represents the ASN.1 type PhysCellIDGERAN (INTEGER).
type PhysCellIDGERAN = s00.PhysCellIDGERAN

// PhysCellIDGERANAPERValue is the concrete APERValue[PhysCellIDGERAN].
type PhysCellIDGERANAPERValue = s01.PhysCellIDGERANAPERValue

// PhysCellIDGERANCodec binds the complete source value type.
var PhysCellIDGERANCodec func() PhysCellIDGERANValueCodec = s02.PhysCellIDGERANCodec

// PhysCellIDGERANValueCodec is the concrete ValueCodec[PhysCellIDGERAN].
type PhysCellIDGERANValueCodec = s01.PhysCellIDGERANValueCodec

// PhysCellIDUTRAFDD represents the ASN.1 type PhysCellIDUTRA-FDD (INTEGER).
type PhysCellIDUTRAFDD = s00.PhysCellIDUTRAFDD

// PhysCellIDUTRAFDDAPERValue is the concrete APERValue[PhysCellIDUTRAFDD].
type PhysCellIDUTRAFDDAPERValue = s01.PhysCellIDUTRAFDDAPERValue

// PhysCellIDUTRAFDDCodec binds the complete source value type.
var PhysCellIDUTRAFDDCodec func() PhysCellIDUTRAFDDValueCodec = s02.PhysCellIDUTRAFDDCodec

// PhysCellIDUTRAFDDValueCodec is the concrete ValueCodec[PhysCellIDUTRAFDD].
type PhysCellIDUTRAFDDValueCodec = s01.PhysCellIDUTRAFDDValueCodec

// PhysCellIDUTRATDD represents the ASN.1 type PhysCellIDUTRA-TDD (INTEGER).
type PhysCellIDUTRATDD = s00.PhysCellIDUTRATDD

// PhysCellIDUTRATDDAPERValue is the concrete APERValue[PhysCellIDUTRATDD].
type PhysCellIDUTRATDDAPERValue = s01.PhysCellIDUTRATDDAPERValue

// PhysCellIDUTRATDDCodec binds the complete source value type.
var PhysCellIDUTRATDDCodec func() PhysCellIDUTRATDDValueCodec = s02.PhysCellIDUTRATDDCodec

// PhysCellIDUTRATDDValueCodec is the concrete ValueCodec[PhysCellIDUTRATDD].
type PhysCellIDUTRATDDValueCodec = s01.PhysCellIDUTRATDDValueCodec
type PosSIBSegments = s08.PosSIBSegments

// PosSIBSegmentsAPERValue is the concrete APERValue[PosSIBSegments].
type PosSIBSegmentsAPERValue = s08.PosSIBSegmentsAPERValue

// PosSIBSegmentsCodec binds the complete source value type.
var PosSIBSegmentsCodec func() PosSIBSegmentsValueCodec = s19.PosSIBSegmentsCodec

// PosSIBSegmentsComplete carries a complete PosSIBSegments encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PosSIBSegmentsComplete = s19.PosSIBSegmentsComplete

// PosSIBSegmentsElem represents the ASN.1 type PosSIB-Segments-Elem (SEQUENCE).
type PosSIBSegmentsElem = s08.PosSIBSegmentsElem

// PosSIBSegmentsElemAPERValue is the concrete APERValue[PosSIBSegmentsElem].
type PosSIBSegmentsElemAPERValue = s08.PosSIBSegmentsElemAPERValue

// PosSIBSegmentsElemCodec binds the complete source value type.
var PosSIBSegmentsElemCodec func() PosSIBSegmentsElemValueCodec = s08.PosSIBSegmentsElemCodec

// PosSIBSegmentsElemValueCodec is the concrete ValueCodec[PosSIBSegmentsElem].
type PosSIBSegmentsElemValueCodec = s08.PosSIBSegmentsElemValueCodec
type PosSIBSegmentsExtIETable = s04.PosSIBSegmentsExtIETable

var PosSIBSegmentsExtIEs func() PosSIBSegmentsExtIETable = s04.PosSIBSegmentsExtIEs

// PosSIBSegmentsExtIEsExtContainer is the concrete ProtocolExtensionContainer[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsExtContainer = s04.PosSIBSegmentsExtIEsExtContainer

// PosSIBSegmentsExtIEsExtField is the concrete ProtocolExtensionField[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsExtField = s04.PosSIBSegmentsExtIEsExtField

// PosSIBSegmentsExtIEsIEContainer is the concrete ProtocolIEContainer[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsIEContainer = s04.PosSIBSegmentsExtIEsIEContainer

// PosSIBSegmentsExtIEsIEField is the concrete ProtocolIEField[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsIEField = s04.PosSIBSegmentsExtIEsIEField
type PosSIBSegmentsExtIEsValue = s02.PosSIBSegmentsExtIEsValue

// PosSIBSegmentsValueCodec is the concrete ValueCodec[PosSIBSegments].
type PosSIBSegmentsValueCodec = s08.PosSIBSegmentsValueCodec

// PosSIBType represents the ASN.1 ENUMERATED type PosSIB-Type.
type PosSIBType = s00.PosSIBType

// PosSIBTypeAPERValue is the concrete APERValue[PosSIBType].
type PosSIBTypeAPERValue = s01.PosSIBTypeAPERValue

// PosSIBTypeCodec binds the complete source value type.
var PosSIBTypeCodec func() PosSIBTypeValueCodec = s02.PosSIBTypeCodec

const PosSIBTypePosSibType11 = s00.PosSIBTypePosSibType11
const PosSIBTypePosSibType12 = s00.PosSIBTypePosSibType12
const PosSIBTypePosSibType13 = s00.PosSIBTypePosSibType13
const PosSIBTypePosSibType14 = s00.PosSIBTypePosSibType14
const PosSIBTypePosSibType15 = s00.PosSIBTypePosSibType15
const PosSIBTypePosSibType16 = s00.PosSIBTypePosSibType16
const PosSIBTypePosSibType17 = s00.PosSIBTypePosSibType17
const PosSIBTypePosSibType21 = s00.PosSIBTypePosSibType21
const PosSIBTypePosSibType210 = s00.PosSIBTypePosSibType210
const PosSIBTypePosSibType211 = s00.PosSIBTypePosSibType211
const PosSIBTypePosSibType212 = s00.PosSIBTypePosSibType212
const PosSIBTypePosSibType213 = s00.PosSIBTypePosSibType213
const PosSIBTypePosSibType214 = s00.PosSIBTypePosSibType214
const PosSIBTypePosSibType215 = s00.PosSIBTypePosSibType215
const PosSIBTypePosSibType216 = s00.PosSIBTypePosSibType216
const PosSIBTypePosSibType217 = s00.PosSIBTypePosSibType217
const PosSIBTypePosSibType218 = s00.PosSIBTypePosSibType218
const PosSIBTypePosSibType219 = s00.PosSIBTypePosSibType219
const PosSIBTypePosSibType22 = s00.PosSIBTypePosSibType22
const PosSIBTypePosSibType224 = s00.PosSIBTypePosSibType224
const PosSIBTypePosSibType225 = s00.PosSIBTypePosSibType225
const PosSIBTypePosSibType23 = s00.PosSIBTypePosSibType23
const PosSIBTypePosSibType24 = s00.PosSIBTypePosSibType24
const PosSIBTypePosSibType25 = s00.PosSIBTypePosSibType25
const PosSIBTypePosSibType26 = s00.PosSIBTypePosSibType26
const PosSIBTypePosSibType27 = s00.PosSIBTypePosSibType27
const PosSIBTypePosSibType28 = s00.PosSIBTypePosSibType28
const PosSIBTypePosSibType29 = s00.PosSIBTypePosSibType29
const PosSIBTypePosSibType31 = s00.PosSIBTypePosSibType31
const PosSIBTypePosSibType41 = s00.PosSIBTypePosSibType41
const PosSIBTypePosSibType51 = s00.PosSIBTypePosSibType51

// PosSIBTypeValueCodec is the concrete ValueCodec[PosSIBType].
type PosSIBTypeValueCodec = s01.PosSIBTypeValueCodec
type PosSIBs = s10.PosSIBs

// PosSIBsAPERValue is the concrete APERValue[PosSIBs].
type PosSIBsAPERValue = s10.PosSIBsAPERValue

// PosSIBsCodec binds the complete source value type.
var PosSIBsCodec func() PosSIBsValueCodec = s19.PosSIBsCodec

// PosSIBsComplete carries a complete PosSIBs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PosSIBsComplete = s19.PosSIBsComplete

// PosSIBsElem represents the ASN.1 type PosSIBs-Elem (SEQUENCE).
type PosSIBsElem = s10.PosSIBsElem

// PosSIBsElemAPERValue is the concrete APERValue[PosSIBsElem].
type PosSIBsElemAPERValue = s10.PosSIBsElemAPERValue

// PosSIBsElemCodec binds the complete source value type.
var PosSIBsElemCodec func() PosSIBsElemValueCodec = s10.PosSIBsElemCodec

// PosSIBsElemValueCodec is the concrete ValueCodec[PosSIBsElem].
type PosSIBsElemValueCodec = s10.PosSIBsElemValueCodec
type PosSIBsExtIETable = s04.PosSIBsExtIETable

var PosSIBsExtIEs func() PosSIBsExtIETable = s04.PosSIBsExtIEs

// PosSIBsExtIEsExtContainer is the concrete ProtocolExtensionContainer[PosSIBsExtIEsValue].
type PosSIBsExtIEsExtContainer = s04.PosSIBsExtIEsExtContainer

// PosSIBsExtIEsExtField is the concrete ProtocolExtensionField[PosSIBsExtIEsValue].
type PosSIBsExtIEsExtField = s04.PosSIBsExtIEsExtField

// PosSIBsExtIEsIEContainer is the concrete ProtocolIEContainer[PosSIBsExtIEsValue].
type PosSIBsExtIEsIEContainer = s04.PosSIBsExtIEsIEContainer

// PosSIBsExtIEsIEField is the concrete ProtocolIEField[PosSIBsExtIEsValue].
type PosSIBsExtIEsIEField = s04.PosSIBsExtIEsIEField
type PosSIBsExtIEsValue = s03.PosSIBsExtIEsValue

// PosSIBsValueCodec is the concrete ValueCodec[PosSIBs].
type PosSIBsValueCodec = s10.PosSIBsValueCodec

// Presence represents the ASN.1 ENUMERATED type Presence.
type Presence = s00.Presence

// PresenceAPERValue is the concrete APERValue[Presence].
type PresenceAPERValue = s01.PresenceAPERValue

// PresenceCodec binds the complete source value type.
var PresenceCodec func() PresenceValueCodec = s02.PresenceCodec

const PresenceConditional = s00.PresenceConditional
const PresenceMandatory = s00.PresenceMandatory
const PresenceOptional = s00.PresenceOptional

// PresenceValueCodec is the concrete ValueCodec[Presence].
type PresenceValueCodec = s01.PresenceValueCodec
type PrivateIEContainer[V s23.ProtocolPrivateValueConstraint[V]] = s23.PrivateIEContainer[V]
type PrivateIEField[V s23.ProtocolPrivateValueConstraint[V]] = s23.PrivateIEField[V]

// PrivateIEID represents the ASN.1 CHOICE type PrivateIE-ID.
type PrivateIEID = s08.PrivateIEID

// PrivateIEIDAPERValue is the concrete APERValue[PrivateIEID].
type PrivateIEIDAPERValue = s08.PrivateIEIDAPERValue

// PrivateIEID choice constants.
const PrivateIEIDChoiceGlobal = s00.PrivateIEIDChoiceGlobal

// PrivateIEID choice constants.
const PrivateIEIDChoiceLocal = s00.PrivateIEIDChoiceLocal

// PrivateIEIDCodec binds the complete source value type.
var PrivateIEIDCodec func() PrivateIEIDValueCodec = s08.PrivateIEIDCodec

// PrivateIEIDValueCodec is the concrete ValueCodec[PrivateIEID].
type PrivateIEIDValueCodec = s08.PrivateIEIDValueCodec

// PrivateMessage represents the ASN.1 type PrivateMessage (SEQUENCE).
type PrivateMessage = s12.PrivateMessage

// PrivateMessageAPERValue is the concrete APERValue[PrivateMessage].
type PrivateMessageAPERValue = s12.PrivateMessageAPERValue

// PrivateMessageCodec binds the complete APER value type.
var PrivateMessageCodec func() PrivateMessageValueCodec = s21.PrivateMessageCodec

type PrivateMessageDescriptor = s21.PrivateMessageDescriptor
type PrivateMessageIETable = s08.PrivateMessageIETable

var PrivateMessageIEs func() PrivateMessageIETable = s08.PrivateMessageIEs

type PrivateMessageIEsValue = s08.PrivateMessageIEsValue

// PrivateMessageIEsValuePrivateIEContainer is the concrete PrivateIEContainer[PrivateMessageIEsValue].
type PrivateMessageIEsValuePrivateIEContainer = s08.PrivateMessageIEsValuePrivateIEContainer

// PrivateMessageIEsValuePrivateIEField is the concrete PrivateIEField[PrivateMessageIEsValue].
type PrivateMessageIEsValuePrivateIEField = s08.PrivateMessageIEsValuePrivateIEField

// PrivateMessageInitiatingBinding is the concrete InitiatingBinding[PrivateMessage].
type PrivateMessageInitiatingBinding = s21.PrivateMessageInitiatingBinding

var PrivateMessageProcedure func() PrivateMessageDescriptor = s21.PrivateMessageProcedure

// PrivateMessageValueCodec is the concrete ValueCodec[PrivateMessage].
type PrivateMessageValueCodec = s12.PrivateMessageValueCodec

// ProcedureCode represents the ASN.1 type ProcedureCode (INTEGER).
type ProcedureCode = s00.ProcedureCode

// ProcedureCodeAPERValue is the concrete APERValue[ProcedureCode].
type ProcedureCodeAPERValue = s01.ProcedureCodeAPERValue

// ProcedureCodeCodec binds the complete source value type.
var ProcedureCodeCodec func() ProcedureCodeValueCodec = s04.ProcedureCodeCodec

// ProcedureCodeValueCodec is the concrete ValueCodec[ProcedureCode].
type ProcedureCodeValueCodec = s01.ProcedureCodeValueCodec
type ProcedureInfo = s00.ProcedureInfo
type ProtocolExtensionContainer[V s23.ProtocolOpenValueConstraint[V]] = s23.ProtocolExtensionContainer[V]
type ProtocolExtensionField[V s23.ProtocolOpenValueConstraint[V]] = s23.ProtocolExtensionField[V]
type ProtocolIEContainer[V s23.ProtocolOpenValueConstraint[V]] = s23.ProtocolIEContainer[V]
type ProtocolIEContainerList[V s23.ProtocolOpenValueConstraint[V]] = s23.ProtocolIEContainerList[V]
type ProtocolIEContainerPair[A s23.ProtocolOpenValueConstraint[A], B s23.ProtocolOpenValueConstraint[B]] = s23.ProtocolIEContainerPair[A, B]
type ProtocolIEContainerPairList[A s23.ProtocolOpenValueConstraint[A], B s23.ProtocolOpenValueConstraint[B]] = s23.ProtocolIEContainerPairList[A, B]
type ProtocolIEField[V s23.ProtocolOpenValueConstraint[V]] = s23.ProtocolIEField[V]
type ProtocolIEFieldPair[A s23.ProtocolOpenValueConstraint[A], B s23.ProtocolOpenValueConstraint[B]] = s23.ProtocolIEFieldPair[A, B]

// ProtocolIEID represents the ASN.1 type ProtocolIE-ID (INTEGER).
type ProtocolIEID = s00.ProtocolIEID

// ProtocolIEIDAPERValue is the concrete APERValue[ProtocolIEID].
type ProtocolIEIDAPERValue = s01.ProtocolIEIDAPERValue

// ProtocolIEIDCodec binds the complete source value type.
var ProtocolIEIDCodec func() ProtocolIEIDValueCodec = s04.ProtocolIEIDCodec

// ProtocolIEIDValueCodec is the concrete ValueCodec[ProtocolIEID].
type ProtocolIEIDValueCodec = s01.ProtocolIEIDValueCodec
type ProtocolIESingleContainer[V s23.ProtocolOpenValueConstraint[V]] = s23.ProtocolIESingleContainer[V]

// RSSI represents the ASN.1 type RSSI (INTEGER).
type RSSI = s00.RSSI

// RSSIAPERValue is the concrete APERValue[RSSI].
type RSSIAPERValue = s01.RSSIAPERValue

// RSSICodec binds the complete source value type.
var RSSICodec func() RSSIValueCodec = s03.RSSICodec

// RSSIValueCodec is the concrete ValueCodec[RSSI].
type RSSIValueCodec = s01.RSSIValueCodec

const RepeatedIE = s00.RepeatedIE

// RepetitionNumberofSIB1NB represents the ASN.1 ENUMERATED type RepetitionNumberofSIB1-NB.
type RepetitionNumberofSIB1NB = s00.RepetitionNumberofSIB1NB

// RepetitionNumberofSIB1NBAPERValue is the concrete APERValue[RepetitionNumberofSIB1NB].
type RepetitionNumberofSIB1NBAPERValue = s01.RepetitionNumberofSIB1NBAPERValue

// RepetitionNumberofSIB1NBCodec binds the complete source value type.
var RepetitionNumberofSIB1NBCodec func() RepetitionNumberofSIB1NBValueCodec = s03.RepetitionNumberofSIB1NBCodec

const RepetitionNumberofSIB1NBR16 = s00.RepetitionNumberofSIB1NBR16
const RepetitionNumberofSIB1NBR4 = s00.RepetitionNumberofSIB1NBR4
const RepetitionNumberofSIB1NBR8 = s00.RepetitionNumberofSIB1NBR8

// RepetitionNumberofSIB1NBValueCodec is the concrete ValueCodec[RepetitionNumberofSIB1NB].
type RepetitionNumberofSIB1NBValueCodec = s01.RepetitionNumberofSIB1NBValueCodec

// ReportCharacteristics represents the ASN.1 ENUMERATED type ReportCharacteristics.
type ReportCharacteristics = s00.ReportCharacteristics

// ReportCharacteristicsAPERValue is the concrete APERValue[ReportCharacteristics].
type ReportCharacteristicsAPERValue = s01.ReportCharacteristicsAPERValue

// ReportCharacteristicsCodec binds the complete APER value type.
var ReportCharacteristicsCodec func() ReportCharacteristicsValueCodec = s21.ReportCharacteristicsCodec

const ReportCharacteristicsOnDemand = s00.ReportCharacteristicsOnDemand
const ReportCharacteristicsPeriodic = s00.ReportCharacteristicsPeriodic

// ReportCharacteristicsValueCodec is the concrete ValueCodec[ReportCharacteristics].
type ReportCharacteristicsValueCodec = s01.ReportCharacteristicsValueCodec

// RequestedSRSTransmissionCharacteristics represents the ASN.1 type RequestedSRSTransmissionCharacteristics (SEQUENCE).
type RequestedSRSTransmissionCharacteristics = s08.RequestedSRSTransmissionCharacteristics

// RequestedSRSTransmissionCharacteristicsAPERValue is the concrete APERValue[RequestedSRSTransmissionCharacteristics].
type RequestedSRSTransmissionCharacteristicsAPERValue = s08.RequestedSRSTransmissionCharacteristicsAPERValue

// RequestedSRSTransmissionCharacteristicsCodec binds the complete APER value type.
var RequestedSRSTransmissionCharacteristicsCodec func() RequestedSRSTransmissionCharacteristicsValueCodec = s09.RequestedSRSTransmissionCharacteristicsCodec

// RequestedSRSTransmissionCharacteristicsValueCodec is the concrete ValueCodec[RequestedSRSTransmissionCharacteristics].
type RequestedSRSTransmissionCharacteristicsValueCodec = s08.RequestedSRSTransmissionCharacteristicsValueCodec
type ResultGERAN = s12.ResultGERAN

// ResultGERANAPERValue is the concrete APERValue[ResultGERAN].
type ResultGERANAPERValue = s12.ResultGERANAPERValue

// ResultGERANCodec binds the complete source value type.
var ResultGERANCodec func() ResultGERANValueCodec = s19.ResultGERANCodec

// ResultGERANComplete carries a complete ResultGERAN encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultGERANComplete = s19.ResultGERANComplete

// ResultGERANItem represents the ASN.1 type ResultGERAN-Item (SEQUENCE).
type ResultGERANItem = s12.ResultGERANItem

// ResultGERANItemAPERValue is the concrete APERValue[ResultGERANItem].
type ResultGERANItemAPERValue = s12.ResultGERANItemAPERValue

// ResultGERANItemCodec binds the complete source value type.
var ResultGERANItemCodec func() ResultGERANItemValueCodec = s12.ResultGERANItemCodec

type ResultGERANItemExtIETable = s04.ResultGERANItemExtIETable

var ResultGERANItemExtIEs func() ResultGERANItemExtIETable = s04.ResultGERANItemExtIEs

// ResultGERANItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsExtContainer = s04.ResultGERANItemExtIEsExtContainer

// ResultGERANItemExtIEsExtField is the concrete ProtocolExtensionField[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsExtField = s04.ResultGERANItemExtIEsExtField

// ResultGERANItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsIEContainer = s04.ResultGERANItemExtIEsIEContainer

// ResultGERANItemExtIEsIEField is the concrete ProtocolIEField[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsIEField = s04.ResultGERANItemExtIEsIEField
type ResultGERANItemExtIEsValue = s03.ResultGERANItemExtIEsValue

// ResultGERANItemValueCodec is the concrete ValueCodec[ResultGERANItem].
type ResultGERANItemValueCodec = s12.ResultGERANItemValueCodec

// ResultGERANValueCodec is the concrete ValueCodec[ResultGERAN].
type ResultGERANValueCodec = s12.ResultGERANValueCodec
type ResultNR = s19.ResultNR

// ResultNRAPERValue is the concrete APERValue[ResultNR].
type ResultNRAPERValue = s19.ResultNRAPERValue

// ResultNRCodec binds the complete source value type.
var ResultNRCodec func() ResultNRValueCodec = s20.ResultNRCodec

// ResultNRComplete carries a complete ResultNR encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultNRComplete = s20.ResultNRComplete

// ResultNRItem represents the ASN.1 type ResultNR-Item (SEQUENCE).
type ResultNRItem = s19.ResultNRItem

// ResultNRItemAPERValue is the concrete APERValue[ResultNRItem].
type ResultNRItemAPERValue = s19.ResultNRItemAPERValue

// ResultNRItemCodec binds the complete source value type.
var ResultNRItemCodec func() ResultNRItemValueCodec = s19.ResultNRItemCodec

type ResultNRItemExtIETable = s19.ResultNRItemExtIETable

var ResultNRItemExtIEs func() ResultNRItemExtIETable = s19.ResultNRItemExtIEs

// ResultNRItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsExtContainer = s19.ResultNRItemExtIEsExtContainer

// ResultNRItemExtIEsExtField is the concrete ProtocolExtensionField[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsExtField = s19.ResultNRItemExtIEsExtField

// ResultNRItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsIEContainer = s19.ResultNRItemExtIEsIEContainer

// ResultNRItemExtIEsIEField is the concrete ProtocolIEField[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsIEField = s19.ResultNRItemExtIEsIEField

// ResultNRItemExtIEsNRCGIExtBinding is the concrete ExtensionBinding[NRCGI, ResultNRItemExtIEsValue].
type ResultNRItemExtIEsNRCGIExtBinding = s19.ResultNRItemExtIEsNRCGIExtBinding

// ResultNRItemExtIEsResultsPerSSBIndexListExtBinding is the concrete ExtensionBinding[ResultsPerSSBIndexList, ResultNRItemExtIEsValue].
type ResultNRItemExtIEsResultsPerSSBIndexListExtBinding = s19.ResultNRItemExtIEsResultsPerSSBIndexListExtBinding
type ResultNRItemExtIEsValue = s19.ResultNRItemExtIEsValue

// ResultNRItemValueCodec is the concrete ValueCodec[ResultNRItem].
type ResultNRItemValueCodec = s19.ResultNRItemValueCodec

// ResultNRValueCodec is the concrete ValueCodec[ResultNR].
type ResultNRValueCodec = s19.ResultNRValueCodec
type ResultRSRP = s12.ResultRSRP

// ResultRSRPAPERValue is the concrete APERValue[ResultRSRP].
type ResultRSRPAPERValue = s12.ResultRSRPAPERValue

// ResultRSRPCodec binds the complete source value type.
var ResultRSRPCodec func() ResultRSRPValueCodec = s19.ResultRSRPCodec

// ResultRSRPComplete carries a complete ResultRSRP encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultRSRPComplete = s19.ResultRSRPComplete

// ResultRSRPItem represents the ASN.1 type ResultRSRP-Item (SEQUENCE).
type ResultRSRPItem = s12.ResultRSRPItem

// ResultRSRPItemAPERValue is the concrete APERValue[ResultRSRPItem].
type ResultRSRPItemAPERValue = s12.ResultRSRPItemAPERValue

// ResultRSRPItemCodec binds the complete source value type.
var ResultRSRPItemCodec func() ResultRSRPItemValueCodec = s12.ResultRSRPItemCodec

type ResultRSRPItemExtIETable = s04.ResultRSRPItemExtIETable

var ResultRSRPItemExtIEs func() ResultRSRPItemExtIETable = s04.ResultRSRPItemExtIEs

// ResultRSRPItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsExtContainer = s04.ResultRSRPItemExtIEsExtContainer

// ResultRSRPItemExtIEsExtField is the concrete ProtocolExtensionField[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsExtField = s04.ResultRSRPItemExtIEsExtField

// ResultRSRPItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsIEContainer = s04.ResultRSRPItemExtIEsIEContainer

// ResultRSRPItemExtIEsIEField is the concrete ProtocolIEField[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsIEField = s04.ResultRSRPItemExtIEsIEField
type ResultRSRPItemExtIEsValue = s03.ResultRSRPItemExtIEsValue

// ResultRSRPItemValueCodec is the concrete ValueCodec[ResultRSRPItem].
type ResultRSRPItemValueCodec = s12.ResultRSRPItemValueCodec

// ResultRSRPValueCodec is the concrete ValueCodec[ResultRSRP].
type ResultRSRPValueCodec = s12.ResultRSRPValueCodec
type ResultRSRQ = s13.ResultRSRQ

// ResultRSRQAPERValue is the concrete APERValue[ResultRSRQ].
type ResultRSRQAPERValue = s13.ResultRSRQAPERValue

// ResultRSRQCodec binds the complete source value type.
var ResultRSRQCodec func() ResultRSRQValueCodec = s19.ResultRSRQCodec

// ResultRSRQComplete carries a complete ResultRSRQ encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultRSRQComplete = s19.ResultRSRQComplete

// ResultRSRQItem represents the ASN.1 type ResultRSRQ-Item (SEQUENCE).
type ResultRSRQItem = s13.ResultRSRQItem

// ResultRSRQItemAPERValue is the concrete APERValue[ResultRSRQItem].
type ResultRSRQItemAPERValue = s13.ResultRSRQItemAPERValue

// ResultRSRQItemCodec binds the complete source value type.
var ResultRSRQItemCodec func() ResultRSRQItemValueCodec = s13.ResultRSRQItemCodec

type ResultRSRQItemExtIETable = s04.ResultRSRQItemExtIETable

var ResultRSRQItemExtIEs func() ResultRSRQItemExtIETable = s04.ResultRSRQItemExtIEs

// ResultRSRQItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsExtContainer = s04.ResultRSRQItemExtIEsExtContainer

// ResultRSRQItemExtIEsExtField is the concrete ProtocolExtensionField[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsExtField = s04.ResultRSRQItemExtIEsExtField

// ResultRSRQItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsIEContainer = s04.ResultRSRQItemExtIEsIEContainer

// ResultRSRQItemExtIEsIEField is the concrete ProtocolIEField[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsIEField = s04.ResultRSRQItemExtIEsIEField
type ResultRSRQItemExtIEsValue = s03.ResultRSRQItemExtIEsValue

// ResultRSRQItemValueCodec is the concrete ValueCodec[ResultRSRQItem].
type ResultRSRQItemValueCodec = s13.ResultRSRQItemValueCodec

// ResultRSRQValueCodec is the concrete ValueCodec[ResultRSRQ].
type ResultRSRQValueCodec = s13.ResultRSRQValueCodec
type ResultUTRAN = s14.ResultUTRAN

// ResultUTRANAPERValue is the concrete APERValue[ResultUTRAN].
type ResultUTRANAPERValue = s14.ResultUTRANAPERValue

// ResultUTRANCodec binds the complete source value type.
var ResultUTRANCodec func() ResultUTRANValueCodec = s19.ResultUTRANCodec

// ResultUTRANComplete carries a complete ResultUTRAN encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultUTRANComplete = s19.ResultUTRANComplete

// ResultUTRANItem represents the ASN.1 type ResultUTRAN-Item (SEQUENCE).
type ResultUTRANItem = s14.ResultUTRANItem

// ResultUTRANItemAPERValue is the concrete APERValue[ResultUTRANItem].
type ResultUTRANItemAPERValue = s14.ResultUTRANItemAPERValue

// ResultUTRANItemCodec binds the complete source value type.
var ResultUTRANItemCodec func() ResultUTRANItemValueCodec = s14.ResultUTRANItemCodec

type ResultUTRANItemExtIETable = s04.ResultUTRANItemExtIETable

var ResultUTRANItemExtIEs func() ResultUTRANItemExtIETable = s04.ResultUTRANItemExtIEs

// ResultUTRANItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsExtContainer = s04.ResultUTRANItemExtIEsExtContainer

// ResultUTRANItemExtIEsExtField is the concrete ProtocolExtensionField[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsExtField = s04.ResultUTRANItemExtIEsExtField

// ResultUTRANItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsIEContainer = s04.ResultUTRANItemExtIEsIEContainer

// ResultUTRANItemExtIEsIEField is the concrete ProtocolIEField[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsIEField = s04.ResultUTRANItemExtIEsIEField
type ResultUTRANItemExtIEsValue = s03.ResultUTRANItemExtIEsValue

// ResultUTRANItemPhysCellIDUTRAN represents the ASN.1 CHOICE type ResultUTRAN-Item-physCellIDUTRAN.
type ResultUTRANItemPhysCellIDUTRAN = s08.ResultUTRANItemPhysCellIDUTRAN

// ResultUTRANItemPhysCellIDUTRANAPERValue is the concrete APERValue[ResultUTRANItemPhysCellIDUTRAN].
type ResultUTRANItemPhysCellIDUTRANAPERValue = s08.ResultUTRANItemPhysCellIDUTRANAPERValue

// ResultUTRANItemPhysCellIDUTRAN choice constants.
const ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD = s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD

// ResultUTRANItemPhysCellIDUTRAN choice constants.
const ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD = s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD

// ResultUTRANItemPhysCellIDUTRANCodec binds the complete source value type.
var ResultUTRANItemPhysCellIDUTRANCodec func() ResultUTRANItemPhysCellIDUTRANValueCodec = s08.ResultUTRANItemPhysCellIDUTRANCodec

// ResultUTRANItemPhysCellIDUTRANValueCodec is the concrete ValueCodec[ResultUTRANItemPhysCellIDUTRAN].
type ResultUTRANItemPhysCellIDUTRANValueCodec = s08.ResultUTRANItemPhysCellIDUTRANValueCodec

// ResultUTRANItemValueCodec is the concrete ValueCodec[ResultUTRANItem].
type ResultUTRANItemValueCodec = s14.ResultUTRANItemValueCodec

// ResultUTRANValueCodec is the concrete ValueCodec[ResultUTRAN].
type ResultUTRANValueCodec = s14.ResultUTRANValueCodec

// ResultsPerSSBIndexItem represents the ASN.1 type ResultsPerSSB-Index-Item (SEQUENCE).
type ResultsPerSSBIndexItem = s14.ResultsPerSSBIndexItem

// ResultsPerSSBIndexItemAPERValue is the concrete APERValue[ResultsPerSSBIndexItem].
type ResultsPerSSBIndexItemAPERValue = s14.ResultsPerSSBIndexItemAPERValue

// ResultsPerSSBIndexItemCodec binds the complete source value type.
var ResultsPerSSBIndexItemCodec func() ResultsPerSSBIndexItemValueCodec = s14.ResultsPerSSBIndexItemCodec

type ResultsPerSSBIndexItemExtIETable = s04.ResultsPerSSBIndexItemExtIETable

var ResultsPerSSBIndexItemExtIEs func() ResultsPerSSBIndexItemExtIETable = s04.ResultsPerSSBIndexItemExtIEs

// ResultsPerSSBIndexItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsExtContainer = s04.ResultsPerSSBIndexItemExtIEsExtContainer

// ResultsPerSSBIndexItemExtIEsExtField is the concrete ProtocolExtensionField[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsExtField = s04.ResultsPerSSBIndexItemExtIEsExtField

// ResultsPerSSBIndexItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsIEContainer = s04.ResultsPerSSBIndexItemExtIEsIEContainer

// ResultsPerSSBIndexItemExtIEsIEField is the concrete ProtocolIEField[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsIEField = s04.ResultsPerSSBIndexItemExtIEsIEField
type ResultsPerSSBIndexItemExtIEsValue = s03.ResultsPerSSBIndexItemExtIEsValue

// ResultsPerSSBIndexItemValueCodec is the concrete ValueCodec[ResultsPerSSBIndexItem].
type ResultsPerSSBIndexItemValueCodec = s14.ResultsPerSSBIndexItemValueCodec
type ResultsPerSSBIndexList = s14.ResultsPerSSBIndexList

// ResultsPerSSBIndexListAPERValue is the concrete APERValue[ResultsPerSSBIndexList].
type ResultsPerSSBIndexListAPERValue = s14.ResultsPerSSBIndexListAPERValue

// ResultsPerSSBIndexListCodec binds the complete APER value type.
var ResultsPerSSBIndexListCodec func() ResultsPerSSBIndexListValueCodec = s19.ResultsPerSSBIndexListCodec

// ResultsPerSSBIndexListComplete carries a complete ResultsPerSSBIndexList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultsPerSSBIndexListComplete = s19.ResultsPerSSBIndexListComplete

// ResultsPerSSBIndexListValueCodec is the concrete ValueCodec[ResultsPerSSBIndexList].
type ResultsPerSSBIndexListValueCodec = s14.ResultsPerSSBIndexListValueCodec

// SFNInitialisationTime represents the ASN.1 type SFNInitialisationTime (BIT_STRING).
type SFNInitialisationTime = s00.SFNInitialisationTime

// SFNInitialisationTimeAPERValue is the concrete APERValue[SFNInitialisationTime].
type SFNInitialisationTimeAPERValue = s01.SFNInitialisationTimeAPERValue

// SFNInitialisationTimeCodec binds the complete source value type.
var SFNInitialisationTimeCodec func() SFNInitialisationTimeValueCodec = s03.SFNInitialisationTimeCodec

// SFNInitialisationTimeValueCodec is the concrete ValueCodec[SFNInitialisationTime].
type SFNInitialisationTimeValueCodec = s01.SFNInitialisationTimeValueCodec
type SRSConfigurationForAllCells = s09.SRSConfigurationForAllCells

// SRSConfigurationForAllCellsAPERValue is the concrete APERValue[SRSConfigurationForAllCells].
type SRSConfigurationForAllCellsAPERValue = s09.SRSConfigurationForAllCellsAPERValue

// SRSConfigurationForAllCellsCodec binds the complete source value type.
var SRSConfigurationForAllCellsCodec func() SRSConfigurationForAllCellsValueCodec = s20.SRSConfigurationForAllCellsCodec

// SRSConfigurationForAllCellsComplete carries a complete SRSConfigurationForAllCells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SRSConfigurationForAllCellsComplete = s20.SRSConfigurationForAllCellsComplete

// SRSConfigurationForAllCellsValueCodec is the concrete ValueCodec[SRSConfigurationForAllCells].
type SRSConfigurationForAllCellsValueCodec = s09.SRSConfigurationForAllCellsValueCodec

// SRSConfigurationForOneCell represents the ASN.1 type SRSConfigurationForOneCell (SEQUENCE).
type SRSConfigurationForOneCell = s09.SRSConfigurationForOneCell

// SRSConfigurationForOneCellAPERValue is the concrete APERValue[SRSConfigurationForOneCell].
type SRSConfigurationForOneCellAPERValue = s09.SRSConfigurationForOneCellAPERValue

// SRSConfigurationForOneCellCodec binds the complete source value type.
var SRSConfigurationForOneCellCodec func() SRSConfigurationForOneCellValueCodec = s09.SRSConfigurationForOneCellCodec

// SRSConfigurationForOneCellValueCodec is the concrete ValueCodec[SRSConfigurationForOneCell].
type SRSConfigurationForOneCellValueCodec = s09.SRSConfigurationForOneCellValueCodec

// SSBIndex represents the ASN.1 type SSB-Index (INTEGER).
type SSBIndex = s00.SSBIndex

// SSBIndexAPERValue is the concrete APERValue[SSBIndex].
type SSBIndexAPERValue = s01.SSBIndexAPERValue

// SSBIndexCodec binds the complete source value type.
var SSBIndexCodec func() SSBIndexValueCodec = s04.SSBIndexCodec

// SSBIndexValueCodec is the concrete ValueCodec[SSBIndex].
type SSBIndexValueCodec = s01.SSBIndexValueCodec

// SSID represents the ASN.1 type SSID (OCTET_STRING).
type SSID = s00.SSID

// SSIDAPERValue is the concrete APERValue[SSID].
type SSIDAPERValue = s01.SSIDAPERValue

// SSIDCodec binds the complete source value type.
var SSIDCodec func() SSIDValueCodec = s03.SSIDCodec

// SSIDValueCodec is the concrete ValueCodec[SSID].
type SSIDValueCodec = s01.SSIDValueCodec

// SSNRRSRP represents the ASN.1 type SS-NRRSRP (INTEGER).
type SSNRRSRP = s00.SSNRRSRP

// SSNRRSRPAPERValue is the concrete APERValue[SSNRRSRP].
type SSNRRSRPAPERValue = s01.SSNRRSRPAPERValue

// SSNRRSRPCodec binds the complete source value type.
var SSNRRSRPCodec func() SSNRRSRPValueCodec = s04.SSNRRSRPCodec

// SSNRRSRPValueCodec is the concrete ValueCodec[SSNRRSRP].
type SSNRRSRPValueCodec = s01.SSNRRSRPValueCodec

// SSNRRSRQ represents the ASN.1 type SS-NRRSRQ (INTEGER).
type SSNRRSRQ = s00.SSNRRSRQ

// SSNRRSRQAPERValue is the concrete APERValue[SSNRRSRQ].
type SSNRRSRQAPERValue = s01.SSNRRSRQAPERValue

// SSNRRSRQCodec binds the complete source value type.
var SSNRRSRQCodec func() SSNRRSRQValueCodec = s04.SSNRRSRQCodec

// SSNRRSRQValueCodec is the concrete ValueCodec[SSNRRSRQ].
type SSNRRSRQValueCodec = s01.SSNRRSRQValueCodec

// Subframeallocation represents the ASN.1 CHOICE type Subframeallocation.
type Subframeallocation = s09.Subframeallocation

// SubframeallocationAPERValue is the concrete APERValue[Subframeallocation].
type SubframeallocationAPERValue = s09.SubframeallocationAPERValue

// Subframeallocation choice constants.
const SubframeallocationChoiceFourFrames = s00.SubframeallocationChoiceFourFrames

// Subframeallocation choice constants.
const SubframeallocationChoiceOneFrame = s00.SubframeallocationChoiceOneFrame

// SubframeallocationCodec binds the complete source value type.
var SubframeallocationCodec func() SubframeallocationValueCodec = s09.SubframeallocationCodec

// SubframeallocationValueCodec is the concrete ValueCodec[Subframeallocation].
type SubframeallocationValueCodec = s09.SubframeallocationValueCodec
type SuccessfulBinding[T any] = s23.SuccessfulBinding[T]

// SuccessfulOutcome represents the ASN.1 type SuccessfulOutcome (SEQUENCE).
type SuccessfulOutcome = s22.SuccessfulOutcome

// SuccessfulOutcomeAPERValue is the concrete APERValue[SuccessfulOutcome].
type SuccessfulOutcomeAPERValue = s23.SuccessfulOutcomeAPERValue

// SuccessfulOutcomeCodec binds the complete source value type.
var SuccessfulOutcomeCodec func() SuccessfulOutcomeValueCodec = s23.SuccessfulOutcomeCodec

// SuccessfulOutcomeValueCodec is the concrete ValueCodec[SuccessfulOutcome].
type SuccessfulOutcomeValueCodec = s23.SuccessfulOutcomeValueCodec

var SuccessfulReason func(code ProcedureCode) aper.OpaqueReason = s00.SuccessfulReason

type SuccessfulValue = s22.SuccessfulValue
type SystemInformation = s14.SystemInformation

// SystemInformationAPERValue is the concrete APERValue[SystemInformation].
type SystemInformationAPERValue = s14.SystemInformationAPERValue

// SystemInformationCodec binds the complete source value type.
var SystemInformationCodec func() SystemInformationValueCodec = s20.SystemInformationCodec

// SystemInformationComplete carries a complete SystemInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SystemInformationComplete = s20.SystemInformationComplete

// SystemInformationElem represents the ASN.1 type SystemInformation-Elem (SEQUENCE).
type SystemInformationElem = s14.SystemInformationElem

// SystemInformationElemAPERValue is the concrete APERValue[SystemInformationElem].
type SystemInformationElemAPERValue = s14.SystemInformationElemAPERValue

// SystemInformationElemCodec binds the complete source value type.
var SystemInformationElemCodec func() SystemInformationElemValueCodec = s14.SystemInformationElemCodec

// SystemInformationElemValueCodec is the concrete ValueCodec[SystemInformationElem].
type SystemInformationElemValueCodec = s14.SystemInformationElemValueCodec
type SystemInformationExtIETable = s04.SystemInformationExtIETable

var SystemInformationExtIEs func() SystemInformationExtIETable = s04.SystemInformationExtIEs

// SystemInformationExtIEsExtContainer is the concrete ProtocolExtensionContainer[SystemInformationExtIEsValue].
type SystemInformationExtIEsExtContainer = s04.SystemInformationExtIEsExtContainer

// SystemInformationExtIEsExtField is the concrete ProtocolExtensionField[SystemInformationExtIEsValue].
type SystemInformationExtIEsExtField = s04.SystemInformationExtIEsExtField

// SystemInformationExtIEsIEContainer is the concrete ProtocolIEContainer[SystemInformationExtIEsValue].
type SystemInformationExtIEsIEContainer = s04.SystemInformationExtIEsIEContainer

// SystemInformationExtIEsIEField is the concrete ProtocolIEField[SystemInformationExtIEsValue].
type SystemInformationExtIEsIEField = s04.SystemInformationExtIEsIEField
type SystemInformationExtIEsValue = s03.SystemInformationExtIEsValue

// SystemInformationValueCodec is the concrete ValueCodec[SystemInformation].
type SystemInformationValueCodec = s14.SystemInformationValueCodec

// TAC represents the ASN.1 type TAC (OCTET_STRING).
type TAC = s00.TAC

// TACAPERValue is the concrete APERValue[TAC].
type TACAPERValue = s01.TACAPERValue

// TACCodec binds the complete source value type.
var TACCodec func() TACValueCodec = s03.TACCodec

// TACValueCodec is the concrete ValueCodec[TAC].
type TACValueCodec = s01.TACValueCodec

// TDDConfiguration represents the ASN.1 type TDDConfiguration (SEQUENCE).
type TDDConfiguration = s15.TDDConfiguration

// TDDConfigurationAPERValue is the concrete APERValue[TDDConfiguration].
type TDDConfigurationAPERValue = s15.TDDConfigurationAPERValue

// TDDConfigurationCodec binds the complete source value type.
var TDDConfigurationCodec func() TDDConfigurationValueCodec = s15.TDDConfigurationCodec

type TDDConfigurationExtIETable = s04.TDDConfigurationExtIETable

var TDDConfigurationExtIEs func() TDDConfigurationExtIETable = s04.TDDConfigurationExtIEs

// TDDConfigurationExtIEsExtContainer is the concrete ProtocolExtensionContainer[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsExtContainer = s04.TDDConfigurationExtIEsExtContainer

// TDDConfigurationExtIEsExtField is the concrete ProtocolExtensionField[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsExtField = s04.TDDConfigurationExtIEsExtField

// TDDConfigurationExtIEsIEContainer is the concrete ProtocolIEContainer[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsIEContainer = s04.TDDConfigurationExtIEsIEContainer

// TDDConfigurationExtIEsIEField is the concrete ProtocolIEField[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsIEField = s04.TDDConfigurationExtIEsIEField
type TDDConfigurationExtIEsValue = s03.TDDConfigurationExtIEsValue

// TDDConfigurationValueCodec is the concrete ValueCodec[TDDConfiguration].
type TDDConfigurationValueCodec = s15.TDDConfigurationValueCodec

// TPID represents the ASN.1 type TP-ID (INTEGER).
type TPID = s00.TPID

// TPIDAPERValue is the concrete APERValue[TPID].
type TPIDAPERValue = s01.TPIDAPERValue

// TPIDCodec binds the complete source value type.
var TPIDCodec func() TPIDValueCodec = s03.TPIDCodec

// TPIDValueCodec is the concrete ValueCodec[TPID].
type TPIDValueCodec = s01.TPIDValueCodec

// TPType represents the ASN.1 ENUMERATED type TP-Type.
type TPType = s00.TPType

// TPTypeAPERValue is the concrete APERValue[TPType].
type TPTypeAPERValue = s01.TPTypeAPERValue

// TPTypeCodec binds the complete source value type.
var TPTypeCodec func() TPTypeValueCodec = s03.TPTypeCodec

const TPTypePrsOnlyTp = s00.TPTypePrsOnlyTp

// TPTypeValueCodec is the concrete ValueCodec[TPType].
type TPTypeValueCodec = s01.TPTypeValueCodec
type TableID = s00.TableID

// TriggeringMessage represents the ASN.1 ENUMERATED type TriggeringMessage.
type TriggeringMessage = s00.TriggeringMessage

// TriggeringMessageAPERValue is the concrete APERValue[TriggeringMessage].
type TriggeringMessageAPERValue = s01.TriggeringMessageAPERValue

// TriggeringMessageCodec binds the complete source value type.
var TriggeringMessageCodec func() TriggeringMessageValueCodec = s03.TriggeringMessageCodec

const TriggeringMessageInitiatingMessage = s00.TriggeringMessageInitiatingMessage
const TriggeringMessageSuccessfulOutcome = s00.TriggeringMessageSuccessfulOutcome
const TriggeringMessageUnsuccessfulOutcome = s00.TriggeringMessageUnsuccessfulOutcome

// TriggeringMessageValueCodec is the concrete ValueCodec[TriggeringMessage].
type TriggeringMessageValueCodec = s01.TriggeringMessageValueCodec
type TypeID = s00.TypeID

// TypeOfError represents the ASN.1 ENUMERATED type TypeOfError.
type TypeOfError = s00.TypeOfError

// TypeOfErrorAPERValue is the concrete APERValue[TypeOfError].
type TypeOfErrorAPERValue = s01.TypeOfErrorAPERValue

// TypeOfErrorCodec binds the complete source value type.
var TypeOfErrorCodec func() TypeOfErrorValueCodec = s03.TypeOfErrorCodec

const TypeOfErrorMissing = s00.TypeOfErrorMissing
const TypeOfErrorNotUnderstood = s00.TypeOfErrorNotUnderstood

// TypeOfErrorValueCodec is the concrete ValueCodec[TypeOfError].
type TypeOfErrorValueCodec = s01.TypeOfErrorValueCodec

// UARFCN represents the ASN.1 type UARFCN (INTEGER).
type UARFCN = s00.UARFCN

// UARFCNAPERValue is the concrete APERValue[UARFCN].
type UARFCNAPERValue = s01.UARFCNAPERValue

// UARFCNCodec binds the complete source value type.
var UARFCNCodec func() UARFCNValueCodec = s03.UARFCNCodec

// UARFCNValueCodec is the concrete ValueCodec[UARFCN].
type UARFCNValueCodec = s01.UARFCNValueCodec

// ULConfiguration represents the ASN.1 type ULConfiguration (SEQUENCE).
type ULConfiguration = s10.ULConfiguration

// ULConfigurationAPERValue is the concrete APERValue[ULConfiguration].
type ULConfigurationAPERValue = s10.ULConfigurationAPERValue

// ULConfigurationCodec binds the complete APER value type.
var ULConfigurationCodec func() ULConfigurationValueCodec = s10.ULConfigurationCodec

// ULConfigurationValueCodec is the concrete ValueCodec[ULConfiguration].
type ULConfigurationValueCodec = s10.ULConfigurationValueCodec
type UTDOAInformationExchangeDescriptor = s24.UTDOAInformationExchangeDescriptor

var UTDOAInformationExchangeProcedure func() UTDOAInformationExchangeDescriptor = s24.UTDOAInformationExchangeProcedure

// UTDOAInformationFailure represents the ASN.1 type UTDOAInformationFailure (SEQUENCE).
type UTDOAInformationFailure = s16.UTDOAInformationFailure

// UTDOAInformationFailureAPERValue is the concrete APERValue[UTDOAInformationFailure].
type UTDOAInformationFailureAPERValue = s16.UTDOAInformationFailureAPERValue

// UTDOAInformationFailureCauseIEBinding is the concrete IEBinding[Cause, UTDOAInformationFailureIEValue].
type UTDOAInformationFailureCauseIEBinding = s10.UTDOAInformationFailureCauseIEBinding

// UTDOAInformationFailureCodec binds the complete APER value type.
var UTDOAInformationFailureCodec func() UTDOAInformationFailureValueCodec = s24.UTDOAInformationFailureCodec

// UTDOAInformationFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UTDOAInformationFailureIEValue].
type UTDOAInformationFailureCriticalityDiagnosticsIEBinding = s10.UTDOAInformationFailureCriticalityDiagnosticsIEBinding

// UTDOAInformationFailureIEContainer is the concrete ProtocolIEContainer[UTDOAInformationFailureIEValue].
type UTDOAInformationFailureIEContainer = s10.UTDOAInformationFailureIEContainer

// UTDOAInformationFailureIEField is the concrete ProtocolIEField[UTDOAInformationFailureIEValue].
type UTDOAInformationFailureIEField = s10.UTDOAInformationFailureIEField
type UTDOAInformationFailureIETable = s10.UTDOAInformationFailureIETable
type UTDOAInformationFailureIEValue = s10.UTDOAInformationFailureIEValue

var UTDOAInformationFailureIEs func() UTDOAInformationFailureIETable = s10.UTDOAInformationFailureIEs

// UTDOAInformationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[UTDOAInformationFailure].
type UTDOAInformationFailureUnsuccessfulBinding = s16.UTDOAInformationFailureUnsuccessfulBinding

// UTDOAInformationFailureValueCodec is the concrete ValueCodec[UTDOAInformationFailure].
type UTDOAInformationFailureValueCodec = s16.UTDOAInformationFailureValueCodec

// UTDOAInformationRequest represents the ASN.1 type UTDOAInformationRequest (SEQUENCE).
type UTDOAInformationRequest = s16.UTDOAInformationRequest

// UTDOAInformationRequestAPERValue is the concrete APERValue[UTDOAInformationRequest].
type UTDOAInformationRequestAPERValue = s16.UTDOAInformationRequestAPERValue

// UTDOAInformationRequestCodec binds the complete APER value type.
var UTDOAInformationRequestCodec func() UTDOAInformationRequestValueCodec = s24.UTDOAInformationRequestCodec

// UTDOAInformationRequestIEContainer is the concrete ProtocolIEContainer[UTDOAInformationRequestIEValue].
type UTDOAInformationRequestIEContainer = s09.UTDOAInformationRequestIEContainer

// UTDOAInformationRequestIEField is the concrete ProtocolIEField[UTDOAInformationRequestIEValue].
type UTDOAInformationRequestIEField = s09.UTDOAInformationRequestIEField
type UTDOAInformationRequestIETable = s09.UTDOAInformationRequestIETable
type UTDOAInformationRequestIEValue = s09.UTDOAInformationRequestIEValue

var UTDOAInformationRequestIEs func() UTDOAInformationRequestIETable = s09.UTDOAInformationRequestIEs

// UTDOAInformationRequestInitiatingBinding is the concrete InitiatingBinding[UTDOAInformationRequest].
type UTDOAInformationRequestInitiatingBinding = s21.UTDOAInformationRequestInitiatingBinding

// UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding is the concrete IEBinding[RequestedSRSTransmissionCharacteristics, UTDOAInformationRequestIEValue].
type UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding = s09.UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding

// UTDOAInformationRequestValueCodec is the concrete ValueCodec[UTDOAInformationRequest].
type UTDOAInformationRequestValueCodec = s16.UTDOAInformationRequestValueCodec

// UTDOAInformationResponse represents the ASN.1 type UTDOAInformationResponse (SEQUENCE).
type UTDOAInformationResponse = s17.UTDOAInformationResponse

// UTDOAInformationResponseAPERValue is the concrete APERValue[UTDOAInformationResponse].
type UTDOAInformationResponseAPERValue = s17.UTDOAInformationResponseAPERValue

// UTDOAInformationResponseCodec binds the complete APER value type.
var UTDOAInformationResponseCodec func() UTDOAInformationResponseValueCodec = s24.UTDOAInformationResponseCodec

// UTDOAInformationResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, UTDOAInformationResponseIEValue].
type UTDOAInformationResponseCriticalityDiagnosticsIEBinding = s10.UTDOAInformationResponseCriticalityDiagnosticsIEBinding

// UTDOAInformationResponseIEContainer is the concrete ProtocolIEContainer[UTDOAInformationResponseIEValue].
type UTDOAInformationResponseIEContainer = s10.UTDOAInformationResponseIEContainer

// UTDOAInformationResponseIEField is the concrete ProtocolIEField[UTDOAInformationResponseIEValue].
type UTDOAInformationResponseIEField = s10.UTDOAInformationResponseIEField
type UTDOAInformationResponseIETable = s10.UTDOAInformationResponseIETable
type UTDOAInformationResponseIEValue = s10.UTDOAInformationResponseIEValue

var UTDOAInformationResponseIEs func() UTDOAInformationResponseIETable = s10.UTDOAInformationResponseIEs

// UTDOAInformationResponseSuccessfulBinding is the concrete SuccessfulBinding[UTDOAInformationResponse].
type UTDOAInformationResponseSuccessfulBinding = s23.UTDOAInformationResponseSuccessfulBinding

// UTDOAInformationResponseULConfigurationIEBinding is the concrete IEBinding[ULConfiguration, UTDOAInformationResponseIEValue].
type UTDOAInformationResponseULConfigurationIEBinding = s10.UTDOAInformationResponseULConfigurationIEBinding

// UTDOAInformationResponseValueCodec is the concrete ValueCodec[UTDOAInformationResponse].
type UTDOAInformationResponseValueCodec = s17.UTDOAInformationResponseValueCodec

// UTDOAInformationUpdate represents the ASN.1 type UTDOAInformationUpdate (SEQUENCE).
type UTDOAInformationUpdate = s17.UTDOAInformationUpdate

// UTDOAInformationUpdateAPERValue is the concrete APERValue[UTDOAInformationUpdate].
type UTDOAInformationUpdateAPERValue = s17.UTDOAInformationUpdateAPERValue

// UTDOAInformationUpdateCodec binds the complete APER value type.
var UTDOAInformationUpdateCodec func() UTDOAInformationUpdateValueCodec = s24.UTDOAInformationUpdateCodec

type UTDOAInformationUpdateDescriptor = s24.UTDOAInformationUpdateDescriptor

// UTDOAInformationUpdateIEContainer is the concrete ProtocolIEContainer[UTDOAInformationUpdateIEValue].
type UTDOAInformationUpdateIEContainer = s11.UTDOAInformationUpdateIEContainer

// UTDOAInformationUpdateIEField is the concrete ProtocolIEField[UTDOAInformationUpdateIEValue].
type UTDOAInformationUpdateIEField = s11.UTDOAInformationUpdateIEField
type UTDOAInformationUpdateIETable = s11.UTDOAInformationUpdateIETable
type UTDOAInformationUpdateIEValue = s11.UTDOAInformationUpdateIEValue

var UTDOAInformationUpdateIEs func() UTDOAInformationUpdateIETable = s11.UTDOAInformationUpdateIEs

// UTDOAInformationUpdateInitiatingBinding is the concrete InitiatingBinding[UTDOAInformationUpdate].
type UTDOAInformationUpdateInitiatingBinding = s21.UTDOAInformationUpdateInitiatingBinding

var UTDOAInformationUpdateProcedure func() UTDOAInformationUpdateDescriptor = s24.UTDOAInformationUpdateProcedure

// UTDOAInformationUpdateULConfigurationIEBinding is the concrete IEBinding[ULConfiguration, UTDOAInformationUpdateIEValue].
type UTDOAInformationUpdateULConfigurationIEBinding = s11.UTDOAInformationUpdateULConfigurationIEBinding

// UTDOAInformationUpdateValueCodec is the concrete ValueCodec[UTDOAInformationUpdate].
type UTDOAInformationUpdateValueCodec = s17.UTDOAInformationUpdateValueCodec

// UTRAEcN0 represents the ASN.1 type UTRA-EcN0 (INTEGER).
type UTRAEcN0 = s00.UTRAEcN0

// UTRAEcN0APERValue is the concrete APERValue[UTRAEcN0].
type UTRAEcN0APERValue = s01.UTRAEcN0APERValue

// UTRAEcN0Codec binds the complete source value type.
var UTRAEcN0Codec func() UTRAEcN0ValueCodec = s03.UTRAEcN0Codec

// UTRAEcN0ValueCodec is the concrete ValueCodec[UTRAEcN0].
type UTRAEcN0ValueCodec = s01.UTRAEcN0ValueCodec

// UTRARSCP represents the ASN.1 type UTRA-RSCP (INTEGER).
type UTRARSCP = s00.UTRARSCP

// UTRARSCPAPERValue is the concrete APERValue[UTRARSCP].
type UTRARSCPAPERValue = s01.UTRARSCPAPERValue

// UTRARSCPCodec binds the complete source value type.
var UTRARSCPCodec func() UTRARSCPValueCodec = s03.UTRARSCPCodec

// UTRARSCPValueCodec is the concrete ValueCodec[UTRARSCP].
type UTRARSCPValueCodec = s01.UTRARSCPValueCodec

const UnavailableOutcome = s00.UnavailableOutcome
const UnknownProcedure = s00.UnknownProcedure

// UnmarshalAPERAddOTDOACellInformation decodes a complete named list.
var UnmarshalAPERAddOTDOACellInformation func(data []byte, options ...aper.DecodeOption) (AddOTDOACellInformationComplete, aper.DecodeReport, error) = s17.UnmarshalAPERAddOTDOACellInformation

// UnmarshalAPERAddOTDOACells decodes a complete named list.
var UnmarshalAPERAddOTDOACells func(data []byte, options ...aper.DecodeOption) (AddOTDOACellsComplete, aper.DecodeReport, error) = s17.UnmarshalAPERAddOTDOACells

// UnmarshalAPERAssistanceInformationFailureList decodes a complete named list.
var UnmarshalAPERAssistanceInformationFailureList func(data []byte, options ...aper.DecodeOption) (AssistanceInformationFailureListComplete, aper.DecodeReport, error) = s17.UnmarshalAPERAssistanceInformationFailureList

// UnmarshalAPERCriticalityDiagnosticsIEList decodes a complete named list.
var UnmarshalAPERCriticalityDiagnosticsIEList func(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsIEListComplete, aper.DecodeReport, error) = s17.UnmarshalAPERCriticalityDiagnosticsIEList

// UnmarshalAPERInterRATMeasurementQuantities decodes a complete named list.
var UnmarshalAPERInterRATMeasurementQuantities func(data []byte, options ...aper.DecodeOption) (InterRATMeasurementQuantitiesComplete, aper.DecodeReport, error) = s17.UnmarshalAPERInterRATMeasurementQuantities

// UnmarshalAPERInterRATMeasurementResult decodes a complete named list.
var UnmarshalAPERInterRATMeasurementResult func(data []byte, options ...aper.DecodeOption) (InterRATMeasurementResultComplete, aper.DecodeReport, error) = s20.UnmarshalAPERInterRATMeasurementResult

// UnmarshalAPERMBSFNsubframeConfiguration decodes a complete named list.
var UnmarshalAPERMBSFNsubframeConfiguration func(data []byte, options ...aper.DecodeOption) (MBSFNsubframeConfigurationComplete, aper.DecodeReport, error) = s18.UnmarshalAPERMBSFNsubframeConfiguration

// UnmarshalAPERMeasuredResults decodes a complete named list.
var UnmarshalAPERMeasuredResults func(data []byte, options ...aper.DecodeOption) (MeasuredResultsComplete, aper.DecodeReport, error) = s18.UnmarshalAPERMeasuredResults

// UnmarshalAPERMeasurementQuantities decodes a complete named list.
var UnmarshalAPERMeasurementQuantities func(data []byte, options ...aper.DecodeOption) (MeasurementQuantitiesComplete, aper.DecodeReport, error) = s18.UnmarshalAPERMeasurementQuantities

// UnmarshalAPEROTDOACellInformation decodes a complete named list.
var UnmarshalAPEROTDOACellInformation func(data []byte, options ...aper.DecodeOption) (OTDOACellInformationComplete, aper.DecodeReport, error) = s18.UnmarshalAPEROTDOACellInformation

// UnmarshalAPEROTDOACells decodes a complete named list.
var UnmarshalAPEROTDOACells func(data []byte, options ...aper.DecodeOption) (OTDOACellsComplete, aper.DecodeReport, error) = s18.UnmarshalAPEROTDOACells

// UnmarshalAPEROTDOAInformationType decodes a complete named list.
var UnmarshalAPEROTDOAInformationType func(data []byte, options ...aper.DecodeOption) (OTDOAInformationTypeComplete, aper.DecodeReport, error) = s18.UnmarshalAPEROTDOAInformationType

// UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions decodes a complete named list.
var UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions func(data []byte, options ...aper.DecodeOption) (PRSFrequencyHoppingConfigurationBandPositionsComplete, aper.DecodeReport, error) = s19.UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions

// UnmarshalAPERPosSIBSegments decodes a complete named list.
var UnmarshalAPERPosSIBSegments func(data []byte, options ...aper.DecodeOption) (PosSIBSegmentsComplete, aper.DecodeReport, error) = s19.UnmarshalAPERPosSIBSegments

// UnmarshalAPERPosSIBs decodes a complete named list.
var UnmarshalAPERPosSIBs func(data []byte, options ...aper.DecodeOption) (PosSIBsComplete, aper.DecodeReport, error) = s19.UnmarshalAPERPosSIBs

// UnmarshalAPERResultGERAN decodes a complete named list.
var UnmarshalAPERResultGERAN func(data []byte, options ...aper.DecodeOption) (ResultGERANComplete, aper.DecodeReport, error) = s19.UnmarshalAPERResultGERAN

// UnmarshalAPERResultNR decodes a complete named list.
var UnmarshalAPERResultNR func(data []byte, options ...aper.DecodeOption) (ResultNRComplete, aper.DecodeReport, error) = s20.UnmarshalAPERResultNR

// UnmarshalAPERResultRSRP decodes a complete named list.
var UnmarshalAPERResultRSRP func(data []byte, options ...aper.DecodeOption) (ResultRSRPComplete, aper.DecodeReport, error) = s19.UnmarshalAPERResultRSRP

// UnmarshalAPERResultRSRQ decodes a complete named list.
var UnmarshalAPERResultRSRQ func(data []byte, options ...aper.DecodeOption) (ResultRSRQComplete, aper.DecodeReport, error) = s19.UnmarshalAPERResultRSRQ

// UnmarshalAPERResultUTRAN decodes a complete named list.
var UnmarshalAPERResultUTRAN func(data []byte, options ...aper.DecodeOption) (ResultUTRANComplete, aper.DecodeReport, error) = s19.UnmarshalAPERResultUTRAN

// UnmarshalAPERResultsPerSSBIndexList decodes a complete named list.
var UnmarshalAPERResultsPerSSBIndexList func(data []byte, options ...aper.DecodeOption) (ResultsPerSSBIndexListComplete, aper.DecodeReport, error) = s19.UnmarshalAPERResultsPerSSBIndexList

// UnmarshalAPERSRSConfigurationForAllCells decodes a complete named list.
var UnmarshalAPERSRSConfigurationForAllCells func(data []byte, options ...aper.DecodeOption) (SRSConfigurationForAllCellsComplete, aper.DecodeReport, error) = s20.UnmarshalAPERSRSConfigurationForAllCells

// UnmarshalAPERSystemInformation decodes a complete named list.
var UnmarshalAPERSystemInformation func(data []byte, options ...aper.DecodeOption) (SystemInformationComplete, aper.DecodeReport, error) = s20.UnmarshalAPERSystemInformation

// UnmarshalAPERWLANChannelList decodes a complete named list.
var UnmarshalAPERWLANChannelList func(data []byte, options ...aper.DecodeOption) (WLANChannelListComplete, aper.DecodeReport, error) = s20.UnmarshalAPERWLANChannelList

// UnmarshalAPERWLANMeasurementQuantities decodes a complete named list.
var UnmarshalAPERWLANMeasurementQuantities func(data []byte, options ...aper.DecodeOption) (WLANMeasurementQuantitiesComplete, aper.DecodeReport, error) = s21.UnmarshalAPERWLANMeasurementQuantities

// UnmarshalAPERWLANMeasurementResult decodes a complete named list.
var UnmarshalAPERWLANMeasurementResult func(data []byte, options ...aper.DecodeOption) (WLANMeasurementResultComplete, aper.DecodeReport, error) = s22.UnmarshalAPERWLANMeasurementResult

type UnsuccessfulBinding[T any] = s23.UnsuccessfulBinding[T]

// UnsuccessfulOutcome represents the ASN.1 type UnsuccessfulOutcome (SEQUENCE).
type UnsuccessfulOutcome = s16.UnsuccessfulOutcome

// UnsuccessfulOutcomeAPERValue is the concrete APERValue[UnsuccessfulOutcome].
type UnsuccessfulOutcomeAPERValue = s16.UnsuccessfulOutcomeAPERValue

// UnsuccessfulOutcomeCodec binds the complete source value type.
var UnsuccessfulOutcomeCodec func() UnsuccessfulOutcomeValueCodec = s16.UnsuccessfulOutcomeCodec

// UnsuccessfulOutcomeValueCodec is the concrete ValueCodec[UnsuccessfulOutcome].
type UnsuccessfulOutcomeValueCodec = s16.UnsuccessfulOutcomeValueCodec

var UnsuccessfulReason func(code ProcedureCode) aper.OpaqueReason = s00.UnsuccessfulReason

type UnsuccessfulValue = s16.UnsuccessfulValue

var ValidateAssistanceInformationControl func(v *AssistanceInformationControl, options ...aper.ValidationOption) (ValidationReport, error) = s24.ValidateAssistanceInformationControl
var ValidateAssistanceInformationFeedback func(v *AssistanceInformationFeedback, options ...aper.ValidationOption) (ValidationReport, error) = s23.ValidateAssistanceInformationFeedback
var ValidateECIDMeasurementFailureIndication func(v *ECIDMeasurementFailureIndication, options ...aper.ValidationOption) (ValidationReport, error) = s23.ValidateECIDMeasurementFailureIndication
var ValidateECIDMeasurementInitiationFailure func(v *ECIDMeasurementInitiationFailure, options ...aper.ValidationOption) (ValidationReport, error) = s23.ValidateECIDMeasurementInitiationFailure
var ValidateECIDMeasurementInitiationRequest func(v *ECIDMeasurementInitiationRequest, options ...aper.ValidationOption) (ValidationReport, error) = s24.ValidateECIDMeasurementInitiationRequest
var ValidateECIDMeasurementInitiationResponse func(v *ECIDMeasurementInitiationResponse, options ...aper.ValidationOption) (ValidationReport, error) = s24.ValidateECIDMeasurementInitiationResponse
var ValidateECIDMeasurementReport func(v *ECIDMeasurementReport, options ...aper.ValidationOption) (ValidationReport, error) = s23.ValidateECIDMeasurementReport
var ValidateECIDMeasurementTerminationCommand func(v *ECIDMeasurementTerminationCommand, options ...aper.ValidationOption) (ValidationReport, error) = s23.ValidateECIDMeasurementTerminationCommand
var ValidateErrorIndication func(v *ErrorIndication, options ...aper.ValidationOption) (ValidationReport, error) = s23.ValidateErrorIndication
var ValidateMessage func(v *LPPAPDU, options ...aper.ValidationOption) (ValidationReport, error) = s24.ValidateMessage
var ValidateOTDOAInformationFailure func(v *OTDOAInformationFailure, options ...aper.ValidationOption) (ValidationReport, error) = s23.ValidateOTDOAInformationFailure
var ValidateOTDOAInformationRequest func(v *OTDOAInformationRequest, options ...aper.ValidationOption) (ValidationReport, error) = s23.ValidateOTDOAInformationRequest
var ValidateOTDOAInformationResponse func(v *OTDOAInformationResponse, options ...aper.ValidationOption) (ValidationReport, error) = s24.ValidateOTDOAInformationResponse
var ValidatePrivateMessage func(v *PrivateMessage, options ...aper.ValidationOption) (ValidationReport, error) = s20.ValidatePrivateMessage
var ValidateUTDOAInformationFailure func(v *UTDOAInformationFailure, options ...aper.ValidationOption) (ValidationReport, error) = s24.ValidateUTDOAInformationFailure
var ValidateUTDOAInformationRequest func(v *UTDOAInformationRequest, options ...aper.ValidationOption) (ValidationReport, error) = s24.ValidateUTDOAInformationRequest
var ValidateUTDOAInformationResponse func(v *UTDOAInformationResponse, options ...aper.ValidationOption) (ValidationReport, error) = s24.ValidateUTDOAInformationResponse
var ValidateUTDOAInformationUpdate func(v *UTDOAInformationUpdate, options ...aper.ValidationOption) (ValidationReport, error) = s24.ValidateUTDOAInformationUpdate

type ValidationCode = s00.ValidationCode
type ValidationIssue = s09.ValidationIssue
type ValidationReport = s09.ValidationReport
type ValidationSeverity = s00.ValidationSeverity

const ValidationSeverityError = s00.ValidationSeverityError
const ValidationSeverityInformational = s00.ValidationSeverityInformational
const ValidationSeverityUnrecognized = s00.ValidationSeverityUnrecognized

// ValueCodec binds one source value type to its complete APER encoding.
type ValueCodec[T any] = s23.ValueCodec[T]

const ValueIDMismatch = s00.ValueIDMismatch

// ValueRSRP represents the ASN.1 type ValueRSRP (INTEGER).
type ValueRSRP = s00.ValueRSRP

// ValueRSRPAPERValue is the concrete APERValue[ValueRSRP].
type ValueRSRPAPERValue = s01.ValueRSRPAPERValue

// ValueRSRPCodec binds the complete source value type.
var ValueRSRPCodec func() ValueRSRPValueCodec = s03.ValueRSRPCodec

// ValueRSRPValueCodec is the concrete ValueCodec[ValueRSRP].
type ValueRSRPValueCodec = s01.ValueRSRPValueCodec

// ValueRSRQ represents the ASN.1 type ValueRSRQ (INTEGER).
type ValueRSRQ = s00.ValueRSRQ

// ValueRSRQAPERValue is the concrete APERValue[ValueRSRQ].
type ValueRSRQAPERValue = s01.ValueRSRQAPERValue

// ValueRSRQCodec binds the complete source value type.
var ValueRSRQCodec func() ValueRSRQValueCodec = s03.ValueRSRQCodec

// ValueRSRQValueCodec is the concrete ValueCodec[ValueRSRQ].
type ValueRSRQValueCodec = s01.ValueRSRQValueCodec

// WLANBand represents the ASN.1 ENUMERATED type WLANBand.
type WLANBand = s00.WLANBand

// WLANBandAPERValue is the concrete APERValue[WLANBand].
type WLANBandAPERValue = s01.WLANBandAPERValue

const WLANBandBand2dot4 = s00.WLANBandBand2dot4
const WLANBandBand5 = s00.WLANBandBand5

// WLANBandCodec binds the complete source value type.
var WLANBandCodec func() WLANBandValueCodec = s03.WLANBandCodec

// WLANBandValueCodec is the concrete ValueCodec[WLANBand].
type WLANBandValueCodec = s01.WLANBandValueCodec

// WLANChannel represents the ASN.1 type WLANChannel (INTEGER).
type WLANChannel = s00.WLANChannel

// WLANChannelAPERValue is the concrete APERValue[WLANChannel].
type WLANChannelAPERValue = s01.WLANChannelAPERValue

// WLANChannelCodec binds the complete source value type.
var WLANChannelCodec func() WLANChannelValueCodec = s04.WLANChannelCodec

type WLANChannelList = s00.WLANChannelList

// WLANChannelListAPERValue is the concrete APERValue[WLANChannelList].
type WLANChannelListAPERValue = s01.WLANChannelListAPERValue

// WLANChannelListCodec binds the complete source value type.
var WLANChannelListCodec func() WLANChannelListValueCodec = s20.WLANChannelListCodec

// WLANChannelListComplete carries a complete WLANChannelList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANChannelListComplete = s20.WLANChannelListComplete

// WLANChannelListValueCodec is the concrete ValueCodec[WLANChannelList].
type WLANChannelListValueCodec = s01.WLANChannelListValueCodec

// WLANChannelValueCodec is the concrete ValueCodec[WLANChannel].
type WLANChannelValueCodec = s01.WLANChannelValueCodec

// WLANCountryCode represents the ASN.1 ENUMERATED type WLANCountryCode.
type WLANCountryCode = s00.WLANCountryCode

// WLANCountryCodeAPERValue is the concrete APERValue[WLANCountryCode].
type WLANCountryCodeAPERValue = s01.WLANCountryCodeAPERValue

// WLANCountryCodeCodec binds the complete source value type.
var WLANCountryCodeCodec func() WLANCountryCodeValueCodec = s03.WLANCountryCodeCodec

const WLANCountryCodeEurope = s00.WLANCountryCodeEurope
const WLANCountryCodeGlobal = s00.WLANCountryCodeGlobal
const WLANCountryCodeJapan = s00.WLANCountryCodeJapan
const WLANCountryCodeUnitedStates = s00.WLANCountryCodeUnitedStates

// WLANCountryCodeValueCodec is the concrete ValueCodec[WLANCountryCode].
type WLANCountryCodeValueCodec = s02.WLANCountryCodeValueCodec
type WLANMeasurementQuantities = s20.WLANMeasurementQuantities

// WLANMeasurementQuantitiesAPERValue is the concrete APERValue[WLANMeasurementQuantities].
type WLANMeasurementQuantitiesAPERValue = s20.WLANMeasurementQuantitiesAPERValue

// WLANMeasurementQuantitiesCodec binds the complete APER value type.
var WLANMeasurementQuantitiesCodec func() WLANMeasurementQuantitiesConcreteValueCodec = s21.WLANMeasurementQuantitiesCodec

// WLANMeasurementQuantitiesComplete carries a complete WLANMeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasurementQuantitiesComplete = s20.WLANMeasurementQuantitiesComplete

// WLANMeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[WLANMeasurementQuantities].
type WLANMeasurementQuantitiesConcreteValueCodec = s20.WLANMeasurementQuantitiesConcreteValueCodec

// WLANMeasurementQuantitiesItem represents the ASN.1 type WLANMeasurementQuantities-Item (SEQUENCE).
type WLANMeasurementQuantitiesItem = s20.WLANMeasurementQuantitiesItem

// WLANMeasurementQuantitiesItemAPERValue is the concrete APERValue[WLANMeasurementQuantitiesItem].
type WLANMeasurementQuantitiesItemAPERValue = s20.WLANMeasurementQuantitiesItemAPERValue

// WLANMeasurementQuantitiesItemCodec binds the complete APER value type.
var WLANMeasurementQuantitiesItemCodec func() WLANMeasurementQuantitiesItemValueCodec = s20.WLANMeasurementQuantitiesItemCodec

// WLANMeasurementQuantitiesItemIEContainer is the concrete ProtocolIEContainer[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEContainer = s20.WLANMeasurementQuantitiesItemIEContainer

// WLANMeasurementQuantitiesItemIEField is the concrete ProtocolIEField[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEField = s20.WLANMeasurementQuantitiesItemIEField
type WLANMeasurementQuantitiesItemIETable = s20.WLANMeasurementQuantitiesItemIETable
type WLANMeasurementQuantitiesItemIEValue = s20.WLANMeasurementQuantitiesItemIEValue

// WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer = s20.WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer

var WLANMeasurementQuantitiesItemIEs func() WLANMeasurementQuantitiesItemIETable = s20.WLANMeasurementQuantitiesItemIEs

// WLANMeasurementQuantitiesItemValueCodec is the concrete ValueCodec[WLANMeasurementQuantitiesItem].
type WLANMeasurementQuantitiesItemValueCodec = s20.WLANMeasurementQuantitiesItemValueCodec

// WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding is the concrete IEBinding[WLANMeasurementQuantitiesItem, WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding = s20.WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding

// WLANMeasurementQuantitiesValue represents the ASN.1 ENUMERATED type WLANMeasurementQuantitiesValue.
type WLANMeasurementQuantitiesValue = s00.WLANMeasurementQuantitiesValue

// WLANMeasurementQuantitiesValueAPERValue is the concrete APERValue[WLANMeasurementQuantitiesValue].
type WLANMeasurementQuantitiesValueAPERValue = s02.WLANMeasurementQuantitiesValueAPERValue

// WLANMeasurementQuantitiesValueCodec binds the complete source value type.
var WLANMeasurementQuantitiesValueCodec func() WLANMeasurementQuantitiesValueValueCodec = s03.WLANMeasurementQuantitiesValueCodec

type WLANMeasurementQuantitiesValueExtIETable = s04.WLANMeasurementQuantitiesValueExtIETable

var WLANMeasurementQuantitiesValueExtIEs func() WLANMeasurementQuantitiesValueExtIETable = s04.WLANMeasurementQuantitiesValueExtIEs

// WLANMeasurementQuantitiesValueExtIEsExtContainer is the concrete ProtocolExtensionContainer[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsExtContainer = s04.WLANMeasurementQuantitiesValueExtIEsExtContainer

// WLANMeasurementQuantitiesValueExtIEsExtField is the concrete ProtocolExtensionField[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsExtField = s04.WLANMeasurementQuantitiesValueExtIEsExtField

// WLANMeasurementQuantitiesValueExtIEsIEContainer is the concrete ProtocolIEContainer[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsIEContainer = s04.WLANMeasurementQuantitiesValueExtIEsIEContainer

// WLANMeasurementQuantitiesValueExtIEsIEField is the concrete ProtocolIEField[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsIEField = s04.WLANMeasurementQuantitiesValueExtIEsIEField
type WLANMeasurementQuantitiesValueExtIEsValue = s03.WLANMeasurementQuantitiesValueExtIEsValue

// WLANMeasurementQuantitiesValueValueCodec is the concrete ValueCodec[WLANMeasurementQuantitiesValue].
type WLANMeasurementQuantitiesValueValueCodec = s02.WLANMeasurementQuantitiesValueValueCodec

const WLANMeasurementQuantitiesValueWlan = s00.WLANMeasurementQuantitiesValueWlan

type WLANMeasurementResult = s22.WLANMeasurementResult

// WLANMeasurementResultAPERValue is the concrete APERValue[WLANMeasurementResult].
type WLANMeasurementResultAPERValue = s22.WLANMeasurementResultAPERValue

// WLANMeasurementResultCodec binds the complete APER value type.
var WLANMeasurementResultCodec func() WLANMeasurementResultValueCodec = s22.WLANMeasurementResultCodec

// WLANMeasurementResultComplete carries a complete WLANMeasurementResult encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasurementResultComplete = s22.WLANMeasurementResultComplete

// WLANMeasurementResultItem represents the ASN.1 type WLANMeasurementResult-Item (SEQUENCE).
type WLANMeasurementResultItem = s22.WLANMeasurementResultItem

// WLANMeasurementResultItemAPERValue is the concrete APERValue[WLANMeasurementResultItem].
type WLANMeasurementResultItemAPERValue = s22.WLANMeasurementResultItemAPERValue

// WLANMeasurementResultItemCodec binds the complete source value type.
var WLANMeasurementResultItemCodec func() WLANMeasurementResultItemValueCodec = s22.WLANMeasurementResultItemCodec

type WLANMeasurementResultItemExtIETable = s04.WLANMeasurementResultItemExtIETable

var WLANMeasurementResultItemExtIEs func() WLANMeasurementResultItemExtIETable = s04.WLANMeasurementResultItemExtIEs

// WLANMeasurementResultItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsExtContainer = s04.WLANMeasurementResultItemExtIEsExtContainer

// WLANMeasurementResultItemExtIEsExtField is the concrete ProtocolExtensionField[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsExtField = s04.WLANMeasurementResultItemExtIEsExtField

// WLANMeasurementResultItemExtIEsIEContainer is the concrete ProtocolIEContainer[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsIEContainer = s04.WLANMeasurementResultItemExtIEsIEContainer

// WLANMeasurementResultItemExtIEsIEField is the concrete ProtocolIEField[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsIEField = s04.WLANMeasurementResultItemExtIEsIEField
type WLANMeasurementResultItemExtIEsValue = s03.WLANMeasurementResultItemExtIEsValue

// WLANMeasurementResultItemValueCodec is the concrete ValueCodec[WLANMeasurementResultItem].
type WLANMeasurementResultItemValueCodec = s22.WLANMeasurementResultItemValueCodec

// WLANMeasurementResultValueCodec is the concrete ValueCodec[WLANMeasurementResult].
type WLANMeasurementResultValueCodec = s22.WLANMeasurementResultValueCodec

// WLANOperatingClass represents the ASN.1 type WLANOperatingClass (INTEGER).
type WLANOperatingClass = s00.WLANOperatingClass

// WLANOperatingClassAPERValue is the concrete APERValue[WLANOperatingClass].
type WLANOperatingClassAPERValue = s02.WLANOperatingClassAPERValue

// WLANOperatingClassCodec binds the complete source value type.
var WLANOperatingClassCodec func() WLANOperatingClassValueCodec = s04.WLANOperatingClassCodec

// WLANOperatingClassValueCodec is the concrete ValueCodec[WLANOperatingClass].
type WLANOperatingClassValueCodec = s02.WLANOperatingClassValueCodec

// WLANRSSI represents the ASN.1 type WLAN-RSSI (INTEGER).
type WLANRSSI = s00.WLANRSSI

// WLANRSSIAPERValue is the concrete APERValue[WLANRSSI].
type WLANRSSIAPERValue = s02.WLANRSSIAPERValue

// WLANRSSICodec binds the complete source value type.
var WLANRSSICodec func() WLANRSSIValueCodec = s03.WLANRSSICodec

// WLANRSSIValueCodec is the concrete ValueCodec[WLANRSSI].
type WLANRSSIValueCodec = s02.WLANRSSIValueCodec

const WrongCriticality = s00.WrongCriticality
const WrongOrder = s00.WrongOrder
