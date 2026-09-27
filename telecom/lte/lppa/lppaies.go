// Code generated from ASN.1 module "LPPA-IEs". DO NOT EDIT.

package lppa

import (
	"fmt"
	"math/big"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = per.NewBitBuffer
)

// AddOTDOACells represents the ASN.1 type Add-OTDOACells (SEQUENCE_OF).
type AddOTDOACells = []AddOTDOACellsElem

// AddOTDOACellInformation represents the ASN.1 type Add-OTDOACell-Information (SEQUENCE_OF).
type AddOTDOACellInformation = []OTDOACellInformationItem

// AssistanceInformation represents the ASN.1 type Assistance-Information (SEQUENCE).
type AssistanceInformation struct {
	SystemInformation       SystemInformation          `asn1:"tag:0,context,implicit"`
	SystemInformationIndef_ bool                       `asn1:"-" json:"-"`
	IEExtensions            ProtocolExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_      bool                       `asn1:"-" json:"-"`
	ExtCount_               int64                      `asn1:"-" json:"-"`
	ExtPresent_             []bool                     `asn1:"-" json:"-"`
	ExtData_                [][]byte                   `asn1:"-" json:"-"`
	PERPadding_             per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_          []per.CompletePadding      `asn1:"-" json:"-"`
}

// AssistanceInformationFailureList represents the ASN.1 type AssistanceInformationFailureList (SEQUENCE_OF).
type AssistanceInformationFailureList = []AssistanceInformationFailureListElem

// AssistanceInformationMetaData represents the ASN.1 type AssistanceInformationMetaData (SEQUENCE).
type AssistanceInformationMetaData struct {
	Encrypted          *int64                     `asn1:"tag:0,context,implicit,optional" json:"Encrypted,omitempty"`
	GNSSID             *int64                     `asn1:"tag:1,context,implicit,optional" json:"GNSSID,omitempty"`
	SBASID             *int64                     `asn1:"tag:2,context,implicit,optional" json:"SBASID,omitempty"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
	PERPadding_        per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_     []per.CompletePadding      `asn1:"-" json:"-"`
}

// BCCH represents the ASN.1 type BCCH (INTEGER).
type BCCH = *big.Int

// BitmapsforNPRS choice constants.
const (
	BitmapsforNPRSChoiceTen      = 1
	BitmapsforNPRSChoiceForty    = 2
	BitmapsforNPRSChoiceTenTdd   = 3
	BitmapsforNPRSChoiceFortyTdd = 4
)

// BitmapsforNPRS represents the ASN.1 CHOICE type BitmapsforNPRS.
type BitmapsforNPRS struct {
	Choice              int
	PERPadding_         per.CompletePadding         `json:"-"`
	PEROpenTypePadding_ per.CompletePadding         `json:"-"`
	UnknownExtension    *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	Ten                 *runtime.BitString          `json:"Ten,omitempty"`
	Forty               *runtime.BitString          `json:"Forty,omitempty"`
	TenTdd              *runtime.BitString          `json:"TenTdd,omitempty"`
	FortyTdd            *runtime.BitString          `json:"FortyTdd,omitempty"`
}

// NewBitmapsforNPRSTen creates a BitmapsforNPRS with the ten alternative.
func NewBitmapsforNPRSTen(v runtime.BitString) BitmapsforNPRS {
	return BitmapsforNPRS{
		Choice: BitmapsforNPRSChoiceTen,
		Ten:    &v,
	}
}

// NewBitmapsforNPRSForty creates a BitmapsforNPRS with the forty alternative.
func NewBitmapsforNPRSForty(v runtime.BitString) BitmapsforNPRS {
	return BitmapsforNPRS{
		Choice: BitmapsforNPRSChoiceForty,
		Forty:  &v,
	}
}

// NewBitmapsforNPRSTenTdd creates a BitmapsforNPRS with the ten-tdd alternative.
func NewBitmapsforNPRSTenTdd(v runtime.BitString) BitmapsforNPRS {
	return BitmapsforNPRS{
		Choice: BitmapsforNPRSChoiceTenTdd,
		TenTdd: &v,
	}
}

// NewBitmapsforNPRSFortyTdd creates a BitmapsforNPRS with the forty-tdd alternative.
func NewBitmapsforNPRSFortyTdd(v runtime.BitString) BitmapsforNPRS {
	return BitmapsforNPRS{
		Choice:   BitmapsforNPRSChoiceFortyTdd,
		FortyTdd: &v,
	}
}

// Broadcast represents the ASN.1 ENUMERATED type Broadcast.
type Broadcast int64

const (
	BroadcastStart Broadcast = 0
	BroadcastStop  Broadcast = 1
)

func (v Broadcast) String() string {
	switch v {
	case BroadcastStart:
		return "start"
	case BroadcastStop:
		return "stop"
	default:
		return "unknown"
	}
}

// BroadcastPeriodicity represents the ASN.1 ENUMERATED type BroadcastPeriodicity.
type BroadcastPeriodicity int64

const (
	BroadcastPeriodicityMs80   BroadcastPeriodicity = 0
	BroadcastPeriodicityMs160  BroadcastPeriodicity = 1
	BroadcastPeriodicityMs320  BroadcastPeriodicity = 2
	BroadcastPeriodicityMs640  BroadcastPeriodicity = 3
	BroadcastPeriodicityMs1280 BroadcastPeriodicity = 4
	BroadcastPeriodicityMs2560 BroadcastPeriodicity = 5
	BroadcastPeriodicityMs5120 BroadcastPeriodicity = 6
)

func (v BroadcastPeriodicity) String() string {
	switch v {
	case BroadcastPeriodicityMs80:
		return "ms80"
	case BroadcastPeriodicityMs160:
		return "ms160"
	case BroadcastPeriodicityMs320:
		return "ms320"
	case BroadcastPeriodicityMs640:
		return "ms640"
	case BroadcastPeriodicityMs1280:
		return "ms1280"
	case BroadcastPeriodicityMs2560:
		return "ms2560"
	case BroadcastPeriodicityMs5120:
		return "ms5120"
	default:
		return "unknown"
	}
}

// BSSID represents the ASN.1 type BSSID (OCTET_STRING).
type BSSID = []byte

// Cause choice constants.
const (
	CauseChoiceRadioNetwork = 1
	CauseChoiceProtocol     = 2
	CauseChoiceMisc         = 3
)

// Cause represents the ASN.1 CHOICE type Cause.
type Cause struct {
	Choice              int
	PERPadding_         per.CompletePadding         `json:"-"`
	PEROpenTypePadding_ per.CompletePadding         `json:"-"`
	UnknownExtension    *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	RadioNetwork        *CauseRadioNetwork          `json:"RadioNetwork,omitempty"`
	Protocol            *CauseProtocol              `json:"Protocol,omitempty"`
	Misc                *CauseMisc                  `json:"Misc,omitempty"`
}

// NewCauseRadioNetwork creates a Cause with the radioNetwork alternative.
func NewCauseRadioNetwork(v CauseRadioNetwork) Cause {
	return Cause{
		Choice:       CauseChoiceRadioNetwork,
		RadioNetwork: &v,
	}
}

// NewCauseProtocol creates a Cause with the protocol alternative.
func NewCauseProtocol(v CauseProtocol) Cause {
	return Cause{
		Choice:   CauseChoiceProtocol,
		Protocol: &v,
	}
}

// NewCauseMisc creates a Cause with the misc alternative.
func NewCauseMisc(v CauseMisc) Cause {
	return Cause{
		Choice: CauseChoiceMisc,
		Misc:   &v,
	}
}

// CauseMisc represents the ASN.1 ENUMERATED type CauseMisc.
type CauseMisc int64

const (
	CauseMiscUnspecified CauseMisc = 0
)

func (v CauseMisc) String() string {
	switch v {
	case CauseMiscUnspecified:
		return "unspecified"
	default:
		return "unknown"
	}
}

// CauseProtocol represents the ASN.1 ENUMERATED type CauseProtocol.
type CauseProtocol int64

const (
	CauseProtocolTransferSyntaxError                          CauseProtocol = 0
	CauseProtocolAbstractSyntaxErrorReject                    CauseProtocol = 1
	CauseProtocolAbstractSyntaxErrorIgnoreAndNotify           CauseProtocol = 2
	CauseProtocolMessageNotCompatibleWithReceiverState        CauseProtocol = 3
	CauseProtocolSemanticError                                CauseProtocol = 4
	CauseProtocolUnspecified                                  CauseProtocol = 5
	CauseProtocolAbstractSyntaxErrorFalselyConstructedMessage CauseProtocol = 6
)

func (v CauseProtocol) String() string {
	switch v {
	case CauseProtocolTransferSyntaxError:
		return "transfer-syntax-error"
	case CauseProtocolAbstractSyntaxErrorReject:
		return "abstract-syntax-error-reject"
	case CauseProtocolAbstractSyntaxErrorIgnoreAndNotify:
		return "abstract-syntax-error-ignore-and-notify"
	case CauseProtocolMessageNotCompatibleWithReceiverState:
		return "message-not-compatible-with-receiver-state"
	case CauseProtocolSemanticError:
		return "semantic-error"
	case CauseProtocolUnspecified:
		return "unspecified"
	case CauseProtocolAbstractSyntaxErrorFalselyConstructedMessage:
		return "abstract-syntax-error-falsely-constructed-message"
	default:
		return "unknown"
	}
}

// CauseRadioNetwork represents the ASN.1 ENUMERATED type CauseRadioNetwork.
type CauseRadioNetwork int64

const (
	CauseRadioNetworkUnspecified                          CauseRadioNetwork = 0
	CauseRadioNetworkRequestedItemNotSupported            CauseRadioNetwork = 1
	CauseRadioNetworkRequestedItemTemporarilyNotAvailable CauseRadioNetwork = 2
)

func (v CauseRadioNetwork) String() string {
	switch v {
	case CauseRadioNetworkUnspecified:
		return "unspecified"
	case CauseRadioNetworkRequestedItemNotSupported:
		return "requested-item-not-supported"
	case CauseRadioNetworkRequestedItemTemporarilyNotAvailable:
		return "requested-item-temporarily-not-available"
	default:
		return "unknown"
	}
}

// CellPortionID represents the ASN.1 type Cell-Portion-ID (INTEGER).
type CellPortionID = *big.Int

// CPLength represents the ASN.1 ENUMERATED type CPLength.
type CPLength int64

const (
	CPLengthNormal   CPLength = 0
	CPLengthExtended CPLength = 1
)

func (v CPLength) String() string {
	switch v {
	case CPLengthNormal:
		return "normal"
	case CPLengthExtended:
		return "extended"
	default:
		return "unknown"
	}
}

// CriticalityDiagnostics represents the ASN.1 type CriticalityDiagnostics (SEQUENCE).
type CriticalityDiagnostics struct {
	ProcedureCode                   *ProcedureCode               `asn1:"tag:0,context,implicit,optional" json:"ProcedureCode,omitempty"`
	TriggeringMessage               *TriggeringMessage           `asn1:"tag:1,context,implicit,optional" json:"TriggeringMessage,omitempty"`
	ProcedureCriticality            *Criticality                 `asn1:"tag:2,context,implicit,optional" json:"ProcedureCriticality,omitempty"`
	LppatransactionID               *LPPATransactionID           `asn1:"tag:3,context,implicit,optional" json:"LppatransactionID,omitempty"`
	IEsCriticalityDiagnostics       CriticalityDiagnosticsIEList `asn1:"tag:4,context,implicit,optional" json:"IEsCriticalityDiagnostics,omitempty"`
	IEsCriticalityDiagnosticsIndef_ bool                         `asn1:"-" json:"-"`
	IEExtensions                    ProtocolExtensionContainer   `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_              bool                         `asn1:"-" json:"-"`
	ExtCount_                       int64                        `asn1:"-" json:"-"`
	ExtPresent_                     []bool                       `asn1:"-" json:"-"`
	ExtData_                        [][]byte                     `asn1:"-" json:"-"`
	PERPadding_                     per.CompletePadding          `asn1:"-" json:"-"`
	PERExtPadding_                  []per.CompletePadding        `asn1:"-" json:"-"`
}

// CriticalityDiagnosticsIEList represents the ASN.1 type CriticalityDiagnostics-IE-List (SEQUENCE_OF).
type CriticalityDiagnosticsIEList = []CriticalityDiagnosticsIEListElem

// DLBandwidth represents the ASN.1 ENUMERATED type DL-Bandwidth.
type DLBandwidth int64

const (
	DLBandwidthBw6   DLBandwidth = 0
	DLBandwidthBw15  DLBandwidth = 1
	DLBandwidthBw25  DLBandwidth = 2
	DLBandwidthBw50  DLBandwidth = 3
	DLBandwidthBw75  DLBandwidth = 4
	DLBandwidthBw100 DLBandwidth = 5
)

func (v DLBandwidth) String() string {
	switch v {
	case DLBandwidthBw6:
		return "bw6"
	case DLBandwidthBw15:
		return "bw15"
	case DLBandwidthBw25:
		return "bw25"
	case DLBandwidthBw50:
		return "bw50"
	case DLBandwidthBw75:
		return "bw75"
	case DLBandwidthBw100:
		return "bw100"
	default:
		return "unknown"
	}
}

// ECIDMeasurementResult represents the ASN.1 type E-CID-MeasurementResult (SEQUENCE).
type ECIDMeasurementResult struct {
	ServingCellID             ECGI                       `asn1:"tag:0,context,implicit"`
	ServingCellTAC            TAC                        `asn1:"tag:1,context,implicit"`
	EUTRANAccessPointPosition *EUTRANAccessPointPosition `asn1:"tag:2,context,implicit,optional" json:"EUTRANAccessPointPosition,omitempty"`
	MeasuredResults           MeasuredResults            `asn1:"tag:3,context,implicit,optional" json:"MeasuredResults,omitempty"`
	MeasuredResultsIndef_     bool                       `asn1:"-" json:"-"`
	ExtCount_                 int64                      `asn1:"-" json:"-"`
	ExtPresent_               []bool                     `asn1:"-" json:"-"`
	ExtData_                  [][]byte                   `asn1:"-" json:"-"`
	PERPadding_               per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_            []per.CompletePadding      `asn1:"-" json:"-"`
}

// ECGI represents the ASN.1 type ECGI (SEQUENCE).
type ECGI struct {
	PLMNIdentity         PLMNIdentity               `asn1:"tag:0,context,implicit"`
	EUTRANcellIdentifier EUTRANCellIdentifier       `asn1:"tag:1,context,implicit"`
	IEExtensions         ProtocolExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_   bool                       `asn1:"-" json:"-"`
	ExtCount_            int64                      `asn1:"-" json:"-"`
	ExtPresent_          []bool                     `asn1:"-" json:"-"`
	ExtData_             [][]byte                   `asn1:"-" json:"-"`
	PERPadding_          per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_       []per.CompletePadding      `asn1:"-" json:"-"`
}

// EUTRANCellIdentifier represents the ASN.1 type EUTRANCellIdentifier (BIT_STRING).
type EUTRANCellIdentifier = runtime.BitString

// EARFCN represents the ASN.1 type EARFCN (INTEGER).
type EARFCN = *big.Int

// EUTRANAccessPointPosition represents the ASN.1 type E-UTRANAccessPointPosition (SEQUENCE).
type EUTRANAccessPointPosition struct {
	LatitudeSign           int64                 `asn1:"tag:0,context,implicit"`
	Latitude               int64                 `asn1:"tag:1,context,implicit"`
	Longitude              int64                 `asn1:"tag:2,context,implicit"`
	DirectionOfAltitude    int64                 `asn1:"tag:3,context,implicit"`
	Altitude               int64                 `asn1:"tag:4,context,implicit"`
	UncertaintySemiMajor   int64                 `asn1:"tag:5,context,implicit"`
	UncertaintySemiMinor   int64                 `asn1:"tag:6,context,implicit"`
	OrientationOfMajorAxis int64                 `asn1:"tag:7,context,implicit"`
	UncertaintyAltitude    int64                 `asn1:"tag:8,context,implicit"`
	Confidence             int64                 `asn1:"tag:9,context,implicit"`
	ExtCount_              int64                 `asn1:"-" json:"-"`
	ExtPresent_            []bool                `asn1:"-" json:"-"`
	ExtData_               [][]byte              `asn1:"-" json:"-"`
	PERPadding_            per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_         []per.CompletePadding `asn1:"-" json:"-"`
}

// HESSID represents the ASN.1 type HESSID (OCTET_STRING).
type HESSID = []byte

// InterRATMeasurementQuantities represents the ASN.1 type InterRATMeasurementQuantities (SEQUENCE_OF).
type InterRATMeasurementQuantities = []ProtocolIESingleContainer

// InterRATMeasurementQuantitiesItem represents the ASN.1 type InterRATMeasurementQuantities-Item (SEQUENCE).
type InterRATMeasurementQuantitiesItem struct {
	InterRATMeasurementQuantitiesValue InterRATMeasurementQuantitiesValue `asn1:"tag:0,context,implicit"`
	IEExtensions                       ProtocolExtensionContainer         `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_                 bool                               `asn1:"-" json:"-"`
	ExtCount_                          int64                              `asn1:"-" json:"-"`
	ExtPresent_                        []bool                             `asn1:"-" json:"-"`
	ExtData_                           [][]byte                           `asn1:"-" json:"-"`
	PERPadding_                        per.CompletePadding                `asn1:"-" json:"-"`
	PERExtPadding_                     []per.CompletePadding              `asn1:"-" json:"-"`
}

// InterRATMeasurementQuantitiesValue represents the ASN.1 ENUMERATED type InterRATMeasurementQuantitiesValue.
type InterRATMeasurementQuantitiesValue int64

const (
	InterRATMeasurementQuantitiesValueGeran InterRATMeasurementQuantitiesValue = 0
	InterRATMeasurementQuantitiesValueUtran InterRATMeasurementQuantitiesValue = 1
	InterRATMeasurementQuantitiesValueNr    InterRATMeasurementQuantitiesValue = 2
)

func (v InterRATMeasurementQuantitiesValue) String() string {
	switch v {
	case InterRATMeasurementQuantitiesValueGeran:
		return "geran"
	case InterRATMeasurementQuantitiesValueUtran:
		return "utran"
	case InterRATMeasurementQuantitiesValueNr:
		return "nr"
	default:
		return "unknown"
	}
}

// InterRATMeasurementResult represents the ASN.1 type InterRATMeasurementResult (SEQUENCE_OF).
type InterRATMeasurementResult = []InterRATMeasuredResultsValue

// InterRATMeasuredResultsValue choice constants.
const (
	InterRATMeasuredResultsValueChoiceResultGERAN = 1
	InterRATMeasuredResultsValueChoiceResultUTRAN = 2
	InterRATMeasuredResultsValueChoiceResultNR    = 3
)

// InterRATMeasuredResultsValue represents the ASN.1 CHOICE type InterRATMeasuredResultsValue.
type InterRATMeasuredResultsValue struct {
	Choice              int
	PERPadding_         per.CompletePadding         `json:"-"`
	PEROpenTypePadding_ per.CompletePadding         `json:"-"`
	UnknownExtension    *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	ResultGERAN         ResultGERAN                 `json:"ResultGERAN,omitempty"`
	ResultUTRAN         ResultUTRAN                 `json:"ResultUTRAN,omitempty"`
	ResultNR            ResultNR                    `json:"ResultNR,omitempty"`
}

// NewInterRATMeasuredResultsValueResultGERAN creates a InterRATMeasuredResultsValue with the resultGERAN alternative.
func NewInterRATMeasuredResultsValueResultGERAN(v ResultGERAN) InterRATMeasuredResultsValue {
	return InterRATMeasuredResultsValue{
		Choice:      InterRATMeasuredResultsValueChoiceResultGERAN,
		ResultGERAN: v,
	}
}

// NewInterRATMeasuredResultsValueResultUTRAN creates a InterRATMeasuredResultsValue with the resultUTRAN alternative.
func NewInterRATMeasuredResultsValueResultUTRAN(v ResultUTRAN) InterRATMeasuredResultsValue {
	return InterRATMeasuredResultsValue{
		Choice:      InterRATMeasuredResultsValueChoiceResultUTRAN,
		ResultUTRAN: v,
	}
}

// NewInterRATMeasuredResultsValueResultNR creates a InterRATMeasuredResultsValue with the resultNR alternative.
func NewInterRATMeasuredResultsValueResultNR(v ResultNR) InterRATMeasuredResultsValue {
	return InterRATMeasuredResultsValue{
		Choice:   InterRATMeasuredResultsValueChoiceResultNR,
		ResultNR: v,
	}
}

// MeasurementID represents the ASN.1 type Measurement-ID (INTEGER).
type MeasurementID = *big.Int

// MeasurementPeriodicity represents the ASN.1 ENUMERATED type MeasurementPeriodicity.
type MeasurementPeriodicity int64

const (
	MeasurementPeriodicityMs120   MeasurementPeriodicity = 0
	MeasurementPeriodicityMs240   MeasurementPeriodicity = 1
	MeasurementPeriodicityMs480   MeasurementPeriodicity = 2
	MeasurementPeriodicityMs640   MeasurementPeriodicity = 3
	MeasurementPeriodicityMs1024  MeasurementPeriodicity = 4
	MeasurementPeriodicityMs2048  MeasurementPeriodicity = 5
	MeasurementPeriodicityMs5120  MeasurementPeriodicity = 6
	MeasurementPeriodicityMs10240 MeasurementPeriodicity = 7
	MeasurementPeriodicityMin1    MeasurementPeriodicity = 8
	MeasurementPeriodicityMin6    MeasurementPeriodicity = 9
	MeasurementPeriodicityMin12   MeasurementPeriodicity = 10
	MeasurementPeriodicityMin30   MeasurementPeriodicity = 11
	MeasurementPeriodicityMin60   MeasurementPeriodicity = 12
)

func (v MeasurementPeriodicity) String() string {
	switch v {
	case MeasurementPeriodicityMs120:
		return "ms120"
	case MeasurementPeriodicityMs240:
		return "ms240"
	case MeasurementPeriodicityMs480:
		return "ms480"
	case MeasurementPeriodicityMs640:
		return "ms640"
	case MeasurementPeriodicityMs1024:
		return "ms1024"
	case MeasurementPeriodicityMs2048:
		return "ms2048"
	case MeasurementPeriodicityMs5120:
		return "ms5120"
	case MeasurementPeriodicityMs10240:
		return "ms10240"
	case MeasurementPeriodicityMin1:
		return "min1"
	case MeasurementPeriodicityMin6:
		return "min6"
	case MeasurementPeriodicityMin12:
		return "min12"
	case MeasurementPeriodicityMin30:
		return "min30"
	case MeasurementPeriodicityMin60:
		return "min60"
	default:
		return "unknown"
	}
}

// MeasurementQuantities represents the ASN.1 type MeasurementQuantities (SEQUENCE_OF).
type MeasurementQuantities = []ProtocolIESingleContainer

// MeasurementQuantitiesItem represents the ASN.1 type MeasurementQuantities-Item (SEQUENCE).
type MeasurementQuantitiesItem struct {
	MeasurementQuantitiesValue MeasurementQuantitiesValue `asn1:"tag:0,context,implicit"`
	IEExtensions               ProtocolExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_         bool                       `asn1:"-" json:"-"`
	ExtCount_                  int64                      `asn1:"-" json:"-"`
	ExtPresent_                []bool                     `asn1:"-" json:"-"`
	ExtData_                   [][]byte                   `asn1:"-" json:"-"`
	PERPadding_                per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_             []per.CompletePadding      `asn1:"-" json:"-"`
}

// MeasurementQuantitiesValue represents the ASN.1 ENUMERATED type MeasurementQuantitiesValue.
type MeasurementQuantitiesValue int64

const (
	MeasurementQuantitiesValueCellID             MeasurementQuantitiesValue = 0
	MeasurementQuantitiesValueAngleOfArrival     MeasurementQuantitiesValue = 1
	MeasurementQuantitiesValueTimingAdvanceType1 MeasurementQuantitiesValue = 2
	MeasurementQuantitiesValueTimingAdvanceType2 MeasurementQuantitiesValue = 3
	MeasurementQuantitiesValueRSRP               MeasurementQuantitiesValue = 4
	MeasurementQuantitiesValueRSRQ               MeasurementQuantitiesValue = 5
)

func (v MeasurementQuantitiesValue) String() string {
	switch v {
	case MeasurementQuantitiesValueCellID:
		return "cell-ID"
	case MeasurementQuantitiesValueAngleOfArrival:
		return "angleOfArrival"
	case MeasurementQuantitiesValueTimingAdvanceType1:
		return "timingAdvanceType1"
	case MeasurementQuantitiesValueTimingAdvanceType2:
		return "timingAdvanceType2"
	case MeasurementQuantitiesValueRSRP:
		return "rSRP"
	case MeasurementQuantitiesValueRSRQ:
		return "rSRQ"
	default:
		return "unknown"
	}
}

// MeasuredResults represents the ASN.1 type MeasuredResults (SEQUENCE_OF).
type MeasuredResults = []MeasuredResultsValue

// MeasuredResultsValue choice constants.
const (
	MeasuredResultsValueChoiceValueAngleOfArrival     = 1
	MeasuredResultsValueChoiceValueTimingAdvanceType1 = 2
	MeasuredResultsValueChoiceValueTimingAdvanceType2 = 3
	MeasuredResultsValueChoiceResultRSRP              = 4
	MeasuredResultsValueChoiceResultRSRQ              = 5
)

// MeasuredResultsValue represents the ASN.1 CHOICE type MeasuredResultsValue.
type MeasuredResultsValue struct {
	Choice                  int
	PERPadding_             per.CompletePadding         `json:"-"`
	PEROpenTypePadding_     per.CompletePadding         `json:"-"`
	UnknownExtension        *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	ValueAngleOfArrival     *int64                      `json:"ValueAngleOfArrival,omitempty"`
	ValueTimingAdvanceType1 *int64                      `json:"ValueTimingAdvanceType1,omitempty"`
	ValueTimingAdvanceType2 *int64                      `json:"ValueTimingAdvanceType2,omitempty"`
	ResultRSRP              ResultRSRP                  `json:"ResultRSRP,omitempty"`
	ResultRSRQ              ResultRSRQ                  `json:"ResultRSRQ,omitempty"`
}

// NewMeasuredResultsValueValueAngleOfArrival creates a MeasuredResultsValue with the valueAngleOfArrival alternative.
func NewMeasuredResultsValueValueAngleOfArrival(v int64) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:              MeasuredResultsValueChoiceValueAngleOfArrival,
		ValueAngleOfArrival: &v,
	}
}

// NewMeasuredResultsValueValueTimingAdvanceType1 creates a MeasuredResultsValue with the valueTimingAdvanceType1 alternative.
func NewMeasuredResultsValueValueTimingAdvanceType1(v int64) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:                  MeasuredResultsValueChoiceValueTimingAdvanceType1,
		ValueTimingAdvanceType1: &v,
	}
}

// NewMeasuredResultsValueValueTimingAdvanceType2 creates a MeasuredResultsValue with the valueTimingAdvanceType2 alternative.
func NewMeasuredResultsValueValueTimingAdvanceType2(v int64) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:                  MeasuredResultsValueChoiceValueTimingAdvanceType2,
		ValueTimingAdvanceType2: &v,
	}
}

// NewMeasuredResultsValueResultRSRP creates a MeasuredResultsValue with the resultRSRP alternative.
func NewMeasuredResultsValueResultRSRP(v ResultRSRP) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:     MeasuredResultsValueChoiceResultRSRP,
		ResultRSRP: v,
	}
}

// NewMeasuredResultsValueResultRSRQ creates a MeasuredResultsValue with the resultRSRQ alternative.
func NewMeasuredResultsValueResultRSRQ(v ResultRSRQ) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:     MeasuredResultsValueChoiceResultRSRQ,
		ResultRSRQ: v,
	}
}

// MBSFNsubframeConfiguration represents the ASN.1 type MBSFNsubframeConfiguration (SEQUENCE_OF).
type MBSFNsubframeConfiguration = []MBSFNsubframeConfigurationValue

// MBSFNsubframeConfigurationValue represents the ASN.1 type MBSFNsubframeConfigurationValue (SEQUENCE).
type MBSFNsubframeConfigurationValue struct {
	RadioframeAllocationPeriod int64               `asn1:"tag:0,context,implicit"`
	RadioframeAllocationOffset int64               `asn1:"tag:1,context,implicit"`
	SubframeAllocation         Subframeallocation  `asn1:"tag:2,context,explicit"`
	PERPadding_                per.CompletePadding `asn1:"-" json:"-"`
}

// NarrowBandIndex represents the ASN.1 type NarrowBandIndex (INTEGER).
type NarrowBandIndex = *big.Int

// NRCellIdentity represents the ASN.1 type NRCellIdentity (BIT_STRING).
type NRCellIdentity = runtime.BitString

// NRCGI represents the ASN.1 type NR-CGI (SEQUENCE).
type NRCGI struct {
	PLMNIdentity       PLMNIdentity               `asn1:"tag:0,context,implicit"`
	NRCellIdentity     NRCellIdentity             `asn1:"tag:1,context,implicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
	PERPadding_        per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_     []per.CompletePadding      `asn1:"-" json:"-"`
}

// NPRSConfiguration represents the ASN.1 type NPRSConfiguration (SEQUENCE).
type NPRSConfiguration struct {
	NPRSSubframePartA *NPRSSubframePartA    `asn1:"tag:0,context,implicit,optional" json:"NPRSSubframePartA,omitempty"`
	NPRSSubframePartB *NPRSSubframePartB    `asn1:"tag:1,context,implicit,optional" json:"NPRSSubframePartB,omitempty"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	PERPadding_       per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_    []per.CompletePadding `asn1:"-" json:"-"`
}

// NPRSMutingConfiguration choice constants.
const (
	NPRSMutingConfigurationChoiceTwo     = 1
	NPRSMutingConfigurationChoiceFour    = 2
	NPRSMutingConfigurationChoiceEight   = 3
	NPRSMutingConfigurationChoiceSixteen = 4
)

// NPRSMutingConfiguration represents the ASN.1 CHOICE type NPRSMutingConfiguration.
type NPRSMutingConfiguration struct {
	Choice              int
	PERPadding_         per.CompletePadding         `json:"-"`
	PEROpenTypePadding_ per.CompletePadding         `json:"-"`
	UnknownExtension    *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	Two                 *runtime.BitString          `json:"Two,omitempty"`
	Four                *runtime.BitString          `json:"Four,omitempty"`
	Eight               *runtime.BitString          `json:"Eight,omitempty"`
	Sixteen             *runtime.BitString          `json:"Sixteen,omitempty"`
}

// NewNPRSMutingConfigurationTwo creates a NPRSMutingConfiguration with the two alternative.
func NewNPRSMutingConfigurationTwo(v runtime.BitString) NPRSMutingConfiguration {
	return NPRSMutingConfiguration{
		Choice: NPRSMutingConfigurationChoiceTwo,
		Two:    &v,
	}
}

// NewNPRSMutingConfigurationFour creates a NPRSMutingConfiguration with the four alternative.
func NewNPRSMutingConfigurationFour(v runtime.BitString) NPRSMutingConfiguration {
	return NPRSMutingConfiguration{
		Choice: NPRSMutingConfigurationChoiceFour,
		Four:   &v,
	}
}

// NewNPRSMutingConfigurationEight creates a NPRSMutingConfiguration with the eight alternative.
func NewNPRSMutingConfigurationEight(v runtime.BitString) NPRSMutingConfiguration {
	return NPRSMutingConfiguration{
		Choice: NPRSMutingConfigurationChoiceEight,
		Eight:  &v,
	}
}

// NewNPRSMutingConfigurationSixteen creates a NPRSMutingConfiguration with the sixteen alternative.
func NewNPRSMutingConfigurationSixteen(v runtime.BitString) NPRSMutingConfiguration {
	return NPRSMutingConfiguration{
		Choice:  NPRSMutingConfigurationChoiceSixteen,
		Sixteen: &v,
	}
}

// NPRSSubframePartA represents the ASN.1 type NPRSSubframePartA (SEQUENCE).
type NPRSSubframePartA struct {
	BitmapsforNPRS          BitmapsforNPRS           `asn1:"tag:0,context,explicit"`
	NPRSMutingConfiguration *NPRSMutingConfiguration `asn1:"tag:1,context,explicit,optional" json:"NPRSMutingConfiguration,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
	PERPadding_             per.CompletePadding      `asn1:"-" json:"-"`
	PERExtPadding_          []per.CompletePadding    `asn1:"-" json:"-"`
}

// NPRSSubframePartB represents the ASN.1 type NPRSSubframePartB (SEQUENCE).
type NPRSSubframePartB struct {
	NumberofNPRSOneOccasion int64                    `asn1:"tag:0,context,implicit"`
	PeriodicityofNPRS       int64                    `asn1:"tag:1,context,implicit"`
	Startingsubframeoffset  int64                    `asn1:"tag:2,context,implicit"`
	NPRSMutingConfiguration *NPRSMutingConfiguration `asn1:"tag:3,context,explicit,optional" json:"NPRSMutingConfiguration,omitempty"`
	SIB1NBSubframeTDD       *int64                   `asn1:"tag:4,context,implicit,optional" json:"SIB1NBSubframeTDD,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
	PERPadding_             per.CompletePadding      `asn1:"-" json:"-"`
	PERExtPadding_          []per.CompletePadding    `asn1:"-" json:"-"`
}

// NumberOfAntennaPorts represents the ASN.1 ENUMERATED type NumberOfAntennaPorts.
type NumberOfAntennaPorts int64

const (
	NumberOfAntennaPortsN1OrN2 NumberOfAntennaPorts = 0
	NumberOfAntennaPortsN4     NumberOfAntennaPorts = 1
)

func (v NumberOfAntennaPorts) String() string {
	switch v {
	case NumberOfAntennaPortsN1OrN2:
		return "n1-or-n2"
	case NumberOfAntennaPortsN4:
		return "n4"
	default:
		return "unknown"
	}
}

// NumberOfDlFrames represents the ASN.1 ENUMERATED type NumberOfDlFrames.
type NumberOfDlFrames int64

const (
	NumberOfDlFramesSf1 NumberOfDlFrames = 0
	NumberOfDlFramesSf2 NumberOfDlFrames = 1
	NumberOfDlFramesSf4 NumberOfDlFrames = 2
	NumberOfDlFramesSf6 NumberOfDlFrames = 3
)

func (v NumberOfDlFrames) String() string {
	switch v {
	case NumberOfDlFramesSf1:
		return "sf1"
	case NumberOfDlFramesSf2:
		return "sf2"
	case NumberOfDlFramesSf4:
		return "sf4"
	case NumberOfDlFramesSf6:
		return "sf6"
	default:
		return "unknown"
	}
}

// NumberOfDlFramesExtended represents the ASN.1 type NumberOfDlFrames-Extended (INTEGER).
type NumberOfDlFramesExtended = *big.Int

// NumberOfFrequencyHoppingBands represents the ASN.1 ENUMERATED type NumberOfFrequencyHoppingBands.
type NumberOfFrequencyHoppingBands int64

const (
	NumberOfFrequencyHoppingBandsTwobands  NumberOfFrequencyHoppingBands = 0
	NumberOfFrequencyHoppingBandsFourbands NumberOfFrequencyHoppingBands = 1
)

func (v NumberOfFrequencyHoppingBands) String() string {
	switch v {
	case NumberOfFrequencyHoppingBandsTwobands:
		return "twobands"
	case NumberOfFrequencyHoppingBandsFourbands:
		return "fourbands"
	default:
		return "unknown"
	}
}

// NPRSSequenceInfo represents the ASN.1 type NPRSSequenceInfo (INTEGER).
type NPRSSequenceInfo = *big.Int

// NRARFCN represents the ASN.1 type NRARFCN (INTEGER).
type NRARFCN = int64

// NRPCI represents the ASN.1 type NRPCI (INTEGER).
type NRPCI = int64

// OffsetNBChanneltoEARFCN represents the ASN.1 ENUMERATED type OffsetNBChanneltoEARFCN.
type OffsetNBChanneltoEARFCN int64

const (
	OffsetNBChanneltoEARFCNMinusTen         OffsetNBChanneltoEARFCN = 0
	OffsetNBChanneltoEARFCNMinusNine        OffsetNBChanneltoEARFCN = 1
	OffsetNBChanneltoEARFCNMinusEight       OffsetNBChanneltoEARFCN = 2
	OffsetNBChanneltoEARFCNMinusSeven       OffsetNBChanneltoEARFCN = 3
	OffsetNBChanneltoEARFCNMinusSix         OffsetNBChanneltoEARFCN = 4
	OffsetNBChanneltoEARFCNMinusFive        OffsetNBChanneltoEARFCN = 5
	OffsetNBChanneltoEARFCNMinusFour        OffsetNBChanneltoEARFCN = 6
	OffsetNBChanneltoEARFCNMinusThree       OffsetNBChanneltoEARFCN = 7
	OffsetNBChanneltoEARFCNMinusTwo         OffsetNBChanneltoEARFCN = 8
	OffsetNBChanneltoEARFCNMinusOne         OffsetNBChanneltoEARFCN = 9
	OffsetNBChanneltoEARFCNMinusZeroDotFive OffsetNBChanneltoEARFCN = 10
	OffsetNBChanneltoEARFCNZero             OffsetNBChanneltoEARFCN = 11
	OffsetNBChanneltoEARFCNOne              OffsetNBChanneltoEARFCN = 12
	OffsetNBChanneltoEARFCNTwo              OffsetNBChanneltoEARFCN = 13
	OffsetNBChanneltoEARFCNThree            OffsetNBChanneltoEARFCN = 14
	OffsetNBChanneltoEARFCNFour             OffsetNBChanneltoEARFCN = 15
	OffsetNBChanneltoEARFCNFive             OffsetNBChanneltoEARFCN = 16
	OffsetNBChanneltoEARFCNSix              OffsetNBChanneltoEARFCN = 17
	OffsetNBChanneltoEARFCNSeven            OffsetNBChanneltoEARFCN = 18
	OffsetNBChanneltoEARFCNEight            OffsetNBChanneltoEARFCN = 19
	OffsetNBChanneltoEARFCNNine             OffsetNBChanneltoEARFCN = 20
)

func (v OffsetNBChanneltoEARFCN) String() string {
	switch v {
	case OffsetNBChanneltoEARFCNMinusTen:
		return "minusTen"
	case OffsetNBChanneltoEARFCNMinusNine:
		return "minusNine"
	case OffsetNBChanneltoEARFCNMinusEight:
		return "minusEight"
	case OffsetNBChanneltoEARFCNMinusSeven:
		return "minusSeven"
	case OffsetNBChanneltoEARFCNMinusSix:
		return "minusSix"
	case OffsetNBChanneltoEARFCNMinusFive:
		return "minusFive"
	case OffsetNBChanneltoEARFCNMinusFour:
		return "minusFour"
	case OffsetNBChanneltoEARFCNMinusThree:
		return "minusThree"
	case OffsetNBChanneltoEARFCNMinusTwo:
		return "minusTwo"
	case OffsetNBChanneltoEARFCNMinusOne:
		return "minusOne"
	case OffsetNBChanneltoEARFCNMinusZeroDotFive:
		return "minusZeroDotFive"
	case OffsetNBChanneltoEARFCNZero:
		return "zero"
	case OffsetNBChanneltoEARFCNOne:
		return "one"
	case OffsetNBChanneltoEARFCNTwo:
		return "two"
	case OffsetNBChanneltoEARFCNThree:
		return "three"
	case OffsetNBChanneltoEARFCNFour:
		return "four"
	case OffsetNBChanneltoEARFCNFive:
		return "five"
	case OffsetNBChanneltoEARFCNSix:
		return "six"
	case OffsetNBChanneltoEARFCNSeven:
		return "seven"
	case OffsetNBChanneltoEARFCNEight:
		return "eight"
	case OffsetNBChanneltoEARFCNNine:
		return "nine"
	default:
		return "unknown"
	}
}

// OperationModeInfo represents the ASN.1 ENUMERATED type OperationModeInfo.
type OperationModeInfo int64

const (
	OperationModeInfoInband     OperationModeInfo = 0
	OperationModeInfoGuardband  OperationModeInfo = 1
	OperationModeInfoStandalone OperationModeInfo = 2
)

func (v OperationModeInfo) String() string {
	switch v {
	case OperationModeInfoInband:
		return "inband"
	case OperationModeInfoGuardband:
		return "guardband"
	case OperationModeInfoStandalone:
		return "standalone"
	default:
		return "unknown"
	}
}

// OTDOACells represents the ASN.1 type OTDOACells (SEQUENCE_OF).
type OTDOACells = []OTDOACellsElem

// OTDOACellInformation represents the ASN.1 type OTDOACell-Information (SEQUENCE_OF).
type OTDOACellInformation = []OTDOACellInformationItem

// OTDOACellInformationItem choice constants.
const (
	OTDOACellInformationItemChoicePCI                        = 1
	OTDOACellInformationItemChoiceCellId                     = 2
	OTDOACellInformationItemChoiceTAC                        = 3
	OTDOACellInformationItemChoiceEARFCN                     = 4
	OTDOACellInformationItemChoicePRSBandwidth               = 5
	OTDOACellInformationItemChoicePRSConfigurationIndex      = 6
	OTDOACellInformationItemChoiceCPLength                   = 7
	OTDOACellInformationItemChoiceNumberOfDlFrames           = 8
	OTDOACellInformationItemChoiceNumberOfAntennaPorts       = 9
	OTDOACellInformationItemChoiceSFNInitialisationTime      = 10
	OTDOACellInformationItemChoiceEUTRANAccessPointPosition  = 11
	OTDOACellInformationItemChoicePRSMutingConfiguration     = 12
	OTDOACellInformationItemChoicePrsid                      = 13
	OTDOACellInformationItemChoiceTpid                       = 14
	OTDOACellInformationItemChoiceTpType                     = 15
	OTDOACellInformationItemChoiceNumberOfDlFramesExtended   = 16
	OTDOACellInformationItemChoiceCrsCPlength                = 17
	OTDOACellInformationItemChoiceMBSFNsubframeConfiguration = 18
	OTDOACellInformationItemChoiceNPRSConfiguration          = 19
	OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN    = 20
	OTDOACellInformationItemChoiceOperationModeInfo          = 21
	OTDOACellInformationItemChoiceNPRSID                     = 22
	OTDOACellInformationItemChoiceDLBandwidth                = 23
	OTDOACellInformationItemChoicePRSOccasionGroup           = 24
	OTDOACellInformationItemChoicePRSFreqHoppingConfig       = 25
	OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB   = 26
	OTDOACellInformationItemChoiceNPRSSequenceInfo           = 27
	OTDOACellInformationItemChoiceNPRSType2                  = 28
	OTDOACellInformationItemChoiceTddConfiguration           = 29
)

// OTDOACellInformationItem represents the ASN.1 CHOICE type OTDOACell-Information-Item.
type OTDOACellInformationItem struct {
	Choice                     int
	PERPadding_                per.CompletePadding               `json:"-"`
	PEROpenTypePadding_        per.CompletePadding               `json:"-"`
	UnknownExtension           *runtime.PERChoiceExtension       `json:"UnknownExtension,omitempty"`
	PCI                        PCI                               `json:"PCI,omitempty"`
	CellId                     *ECGI                             `json:"CellId,omitempty"`
	TAC                        *TAC                              `json:"TAC,omitempty"`
	EARFCN                     EARFCN                            `json:"EARFCN,omitempty"`
	PRSBandwidth               *PRSBandwidth                     `json:"PRSBandwidth,omitempty"`
	PRSConfigurationIndex      PRSConfigurationIndex             `json:"PRSConfigurationIndex,omitempty"`
	CPLength                   *CPLength                         `json:"CPLength,omitempty"`
	NumberOfDlFrames           *NumberOfDlFrames                 `json:"NumberOfDlFrames,omitempty"`
	NumberOfAntennaPorts       *NumberOfAntennaPorts             `json:"NumberOfAntennaPorts,omitempty"`
	SFNInitialisationTime      *SFNInitialisationTime            `json:"SFNInitialisationTime,omitempty"`
	EUTRANAccessPointPosition  *EUTRANAccessPointPosition        `json:"EUTRANAccessPointPosition,omitempty"`
	PRSMutingConfiguration     *PRSMutingConfiguration           `json:"PRSMutingConfiguration,omitempty"`
	Prsid                      PRSID                             `json:"Prsid,omitempty"`
	Tpid                       TPID                              `json:"Tpid,omitempty"`
	TpType                     *TPType                           `json:"TpType,omitempty"`
	NumberOfDlFramesExtended   NumberOfDlFramesExtended          `json:"NumberOfDlFramesExtended,omitempty"`
	CrsCPlength                *CPLength                         `json:"CrsCPlength,omitempty"`
	MBSFNsubframeConfiguration MBSFNsubframeConfiguration        `json:"MBSFNsubframeConfiguration,omitempty"`
	NPRSConfiguration          *NPRSConfiguration                `json:"NPRSConfiguration,omitempty"`
	OffsetNBChanneltoEARFCN    *OffsetNBChanneltoEARFCN          `json:"OffsetNBChanneltoEARFCN,omitempty"`
	OperationModeInfo          *OperationModeInfo                `json:"OperationModeInfo,omitempty"`
	NPRSID                     *big.Int                          `json:"NPRSID,omitempty"`
	DLBandwidth                *DLBandwidth                      `json:"DLBandwidth,omitempty"`
	PRSOccasionGroup           *PRSOccasionGroup                 `json:"PRSOccasionGroup,omitempty"`
	PRSFreqHoppingConfig       *PRSFrequencyHoppingConfiguration `json:"PRSFreqHoppingConfig,omitempty"`
	RepetitionNumberofSIB1NB   *RepetitionNumberofSIB1NB         `json:"RepetitionNumberofSIB1NB,omitempty"`
	NPRSSequenceInfo           NPRSSequenceInfo                  `json:"NPRSSequenceInfo,omitempty"`
	NPRSType2                  *NPRSConfiguration                `json:"NPRSType2,omitempty"`
	TddConfiguration           *TDDConfiguration                 `json:"TddConfiguration,omitempty"`
}

// NewOTDOACellInformationItemPCI creates a OTDOACellInformationItem with the pCI alternative.
func NewOTDOACellInformationItemPCI(v PCI) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice: OTDOACellInformationItemChoicePCI,
		PCI:    v,
	}
}

// NewOTDOACellInformationItemCellId creates a OTDOACellInformationItem with the cellId alternative.
func NewOTDOACellInformationItemCellId(v ECGI) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice: OTDOACellInformationItemChoiceCellId,
		CellId: &v,
	}
}

// NewOTDOACellInformationItemTAC creates a OTDOACellInformationItem with the tAC alternative.
func NewOTDOACellInformationItemTAC(v TAC) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice: OTDOACellInformationItemChoiceTAC,
		TAC:    &v,
	}
}

// NewOTDOACellInformationItemEARFCN creates a OTDOACellInformationItem with the eARFCN alternative.
func NewOTDOACellInformationItemEARFCN(v EARFCN) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice: OTDOACellInformationItemChoiceEARFCN,
		EARFCN: v,
	}
}

// NewOTDOACellInformationItemPRSBandwidth creates a OTDOACellInformationItem with the pRS-Bandwidth alternative.
func NewOTDOACellInformationItemPRSBandwidth(v PRSBandwidth) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:       OTDOACellInformationItemChoicePRSBandwidth,
		PRSBandwidth: &v,
	}
}

// NewOTDOACellInformationItemPRSConfigurationIndex creates a OTDOACellInformationItem with the pRS-ConfigurationIndex alternative.
func NewOTDOACellInformationItemPRSConfigurationIndex(v PRSConfigurationIndex) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:                OTDOACellInformationItemChoicePRSConfigurationIndex,
		PRSConfigurationIndex: v,
	}
}

// NewOTDOACellInformationItemCPLength creates a OTDOACellInformationItem with the cPLength alternative.
func NewOTDOACellInformationItemCPLength(v CPLength) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:   OTDOACellInformationItemChoiceCPLength,
		CPLength: &v,
	}
}

// NewOTDOACellInformationItemNumberOfDlFrames creates a OTDOACellInformationItem with the numberOfDlFrames alternative.
func NewOTDOACellInformationItemNumberOfDlFrames(v NumberOfDlFrames) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:           OTDOACellInformationItemChoiceNumberOfDlFrames,
		NumberOfDlFrames: &v,
	}
}

// NewOTDOACellInformationItemNumberOfAntennaPorts creates a OTDOACellInformationItem with the numberOfAntennaPorts alternative.
func NewOTDOACellInformationItemNumberOfAntennaPorts(v NumberOfAntennaPorts) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:               OTDOACellInformationItemChoiceNumberOfAntennaPorts,
		NumberOfAntennaPorts: &v,
	}
}

// NewOTDOACellInformationItemSFNInitialisationTime creates a OTDOACellInformationItem with the sFNInitialisationTime alternative.
func NewOTDOACellInformationItemSFNInitialisationTime(v SFNInitialisationTime) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:                OTDOACellInformationItemChoiceSFNInitialisationTime,
		SFNInitialisationTime: &v,
	}
}

// NewOTDOACellInformationItemEUTRANAccessPointPosition creates a OTDOACellInformationItem with the e-UTRANAccessPointPosition alternative.
func NewOTDOACellInformationItemEUTRANAccessPointPosition(v EUTRANAccessPointPosition) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:                    OTDOACellInformationItemChoiceEUTRANAccessPointPosition,
		EUTRANAccessPointPosition: &v,
	}
}

// NewOTDOACellInformationItemPRSMutingConfiguration creates a OTDOACellInformationItem with the pRSMutingConfiguration alternative.
func NewOTDOACellInformationItemPRSMutingConfiguration(v PRSMutingConfiguration) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:                 OTDOACellInformationItemChoicePRSMutingConfiguration,
		PRSMutingConfiguration: &v,
	}
}

// NewOTDOACellInformationItemPrsid creates a OTDOACellInformationItem with the prsid alternative.
func NewOTDOACellInformationItemPrsid(v PRSID) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice: OTDOACellInformationItemChoicePrsid,
		Prsid:  v,
	}
}

// NewOTDOACellInformationItemTpid creates a OTDOACellInformationItem with the tpid alternative.
func NewOTDOACellInformationItemTpid(v TPID) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice: OTDOACellInformationItemChoiceTpid,
		Tpid:   v,
	}
}

// NewOTDOACellInformationItemTpType creates a OTDOACellInformationItem with the tpType alternative.
func NewOTDOACellInformationItemTpType(v TPType) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice: OTDOACellInformationItemChoiceTpType,
		TpType: &v,
	}
}

// NewOTDOACellInformationItemNumberOfDlFramesExtended creates a OTDOACellInformationItem with the numberOfDlFrames-Extended alternative.
func NewOTDOACellInformationItemNumberOfDlFramesExtended(v NumberOfDlFramesExtended) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:                   OTDOACellInformationItemChoiceNumberOfDlFramesExtended,
		NumberOfDlFramesExtended: v,
	}
}

// NewOTDOACellInformationItemCrsCPlength creates a OTDOACellInformationItem with the crsCPlength alternative.
func NewOTDOACellInformationItemCrsCPlength(v CPLength) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:      OTDOACellInformationItemChoiceCrsCPlength,
		CrsCPlength: &v,
	}
}

// NewOTDOACellInformationItemMBSFNsubframeConfiguration creates a OTDOACellInformationItem with the mBSFNsubframeConfiguration alternative.
func NewOTDOACellInformationItemMBSFNsubframeConfiguration(v MBSFNsubframeConfiguration) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:                     OTDOACellInformationItemChoiceMBSFNsubframeConfiguration,
		MBSFNsubframeConfiguration: v,
	}
}

// NewOTDOACellInformationItemNPRSConfiguration creates a OTDOACellInformationItem with the nPRSConfiguration alternative.
func NewOTDOACellInformationItemNPRSConfiguration(v NPRSConfiguration) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:            OTDOACellInformationItemChoiceNPRSConfiguration,
		NPRSConfiguration: &v,
	}
}

// NewOTDOACellInformationItemOffsetNBChanneltoEARFCN creates a OTDOACellInformationItem with the offsetNBChanneltoEARFCN alternative.
func NewOTDOACellInformationItemOffsetNBChanneltoEARFCN(v OffsetNBChanneltoEARFCN) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:                  OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN,
		OffsetNBChanneltoEARFCN: &v,
	}
}

// NewOTDOACellInformationItemOperationModeInfo creates a OTDOACellInformationItem with the operationModeInfo alternative.
func NewOTDOACellInformationItemOperationModeInfo(v OperationModeInfo) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:            OTDOACellInformationItemChoiceOperationModeInfo,
		OperationModeInfo: &v,
	}
}

// NewOTDOACellInformationItemNPRSID creates a OTDOACellInformationItem with the nPRS-ID alternative.
func NewOTDOACellInformationItemNPRSID(v *big.Int) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice: OTDOACellInformationItemChoiceNPRSID,
		NPRSID: v,
	}
}

// NewOTDOACellInformationItemDLBandwidth creates a OTDOACellInformationItem with the dL-Bandwidth alternative.
func NewOTDOACellInformationItemDLBandwidth(v DLBandwidth) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:      OTDOACellInformationItemChoiceDLBandwidth,
		DLBandwidth: &v,
	}
}

// NewOTDOACellInformationItemPRSOccasionGroup creates a OTDOACellInformationItem with the pRSOccasionGroup alternative.
func NewOTDOACellInformationItemPRSOccasionGroup(v PRSOccasionGroup) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:           OTDOACellInformationItemChoicePRSOccasionGroup,
		PRSOccasionGroup: &v,
	}
}

// NewOTDOACellInformationItemPRSFreqHoppingConfig creates a OTDOACellInformationItem with the pRSFreqHoppingConfig alternative.
func NewOTDOACellInformationItemPRSFreqHoppingConfig(v PRSFrequencyHoppingConfiguration) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:               OTDOACellInformationItemChoicePRSFreqHoppingConfig,
		PRSFreqHoppingConfig: &v,
	}
}

// NewOTDOACellInformationItemRepetitionNumberofSIB1NB creates a OTDOACellInformationItem with the repetitionNumberofSIB1-NB alternative.
func NewOTDOACellInformationItemRepetitionNumberofSIB1NB(v RepetitionNumberofSIB1NB) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:                   OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB,
		RepetitionNumberofSIB1NB: &v,
	}
}

// NewOTDOACellInformationItemNPRSSequenceInfo creates a OTDOACellInformationItem with the nPRSSequenceInfo alternative.
func NewOTDOACellInformationItemNPRSSequenceInfo(v NPRSSequenceInfo) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:           OTDOACellInformationItemChoiceNPRSSequenceInfo,
		NPRSSequenceInfo: v,
	}
}

// NewOTDOACellInformationItemNPRSType2 creates a OTDOACellInformationItem with the nPRSType2 alternative.
func NewOTDOACellInformationItemNPRSType2(v NPRSConfiguration) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:    OTDOACellInformationItemChoiceNPRSType2,
		NPRSType2: &v,
	}
}

// NewOTDOACellInformationItemTddConfiguration creates a OTDOACellInformationItem with the tddConfiguration alternative.
func NewOTDOACellInformationItemTddConfiguration(v TDDConfiguration) OTDOACellInformationItem {
	return OTDOACellInformationItem{
		Choice:           OTDOACellInformationItemChoiceTddConfiguration,
		TddConfiguration: &v,
	}
}

// OTDOAInformationItem represents the ASN.1 ENUMERATED type OTDOA-Information-Item.
type OTDOAInformationItem int64

const (
	OTDOAInformationItemPci                              OTDOAInformationItem = 0
	OTDOAInformationItemCellid                           OTDOAInformationItem = 1
	OTDOAInformationItemTac                              OTDOAInformationItem = 2
	OTDOAInformationItemEarfcn                           OTDOAInformationItem = 3
	OTDOAInformationItemPrsBandwidth                     OTDOAInformationItem = 4
	OTDOAInformationItemPrsConfigIndex                   OTDOAInformationItem = 5
	OTDOAInformationItemCpLength                         OTDOAInformationItem = 6
	OTDOAInformationItemNoDlFrames                       OTDOAInformationItem = 7
	OTDOAInformationItemNoAntennaPorts                   OTDOAInformationItem = 8
	OTDOAInformationItemSFNInitTime                      OTDOAInformationItem = 9
	OTDOAInformationItemEUTRANAccessPointPosition        OTDOAInformationItem = 10
	OTDOAInformationItemPrsmutingconfiguration           OTDOAInformationItem = 11
	OTDOAInformationItemPrsid                            OTDOAInformationItem = 12
	OTDOAInformationItemTpid                             OTDOAInformationItem = 13
	OTDOAInformationItemTpType                           OTDOAInformationItem = 14
	OTDOAInformationItemCrsCPlength                      OTDOAInformationItem = 15
	OTDOAInformationItemMBSFNsubframeConfiguration       OTDOAInformationItem = 16
	OTDOAInformationItemNPRSConfiguration                OTDOAInformationItem = 17
	OTDOAInformationItemOffsetNBChannelNumbertoEARFCN    OTDOAInformationItem = 18
	OTDOAInformationItemOperationModeInfo                OTDOAInformationItem = 19
	OTDOAInformationItemNPRSID                           OTDOAInformationItem = 20
	OTDOAInformationItemDlBandwidth                      OTDOAInformationItem = 21
	OTDOAInformationItemMultipleprsConfigurationsperCell OTDOAInformationItem = 22
	OTDOAInformationItemPrsOccasionGroup                 OTDOAInformationItem = 23
	OTDOAInformationItemPrsFrequencyHoppingConfiguration OTDOAInformationItem = 24
	OTDOAInformationItemRepetitionNumberofSIB1NB         OTDOAInformationItem = 25
	OTDOAInformationItemNPRSSequenceInfo                 OTDOAInformationItem = 26
	OTDOAInformationItemNPRSType2                        OTDOAInformationItem = 27
	OTDOAInformationItemTddConfig                        OTDOAInformationItem = 28
)

func (v OTDOAInformationItem) String() string {
	switch v {
	case OTDOAInformationItemPci:
		return "pci"
	case OTDOAInformationItemCellid:
		return "cellid"
	case OTDOAInformationItemTac:
		return "tac"
	case OTDOAInformationItemEarfcn:
		return "earfcn"
	case OTDOAInformationItemPrsBandwidth:
		return "prsBandwidth"
	case OTDOAInformationItemPrsConfigIndex:
		return "prsConfigIndex"
	case OTDOAInformationItemCpLength:
		return "cpLength"
	case OTDOAInformationItemNoDlFrames:
		return "noDlFrames"
	case OTDOAInformationItemNoAntennaPorts:
		return "noAntennaPorts"
	case OTDOAInformationItemSFNInitTime:
		return "sFNInitTime"
	case OTDOAInformationItemEUTRANAccessPointPosition:
		return "e-UTRANAccessPointPosition"
	case OTDOAInformationItemPrsmutingconfiguration:
		return "prsmutingconfiguration"
	case OTDOAInformationItemPrsid:
		return "prsid"
	case OTDOAInformationItemTpid:
		return "tpid"
	case OTDOAInformationItemTpType:
		return "tpType"
	case OTDOAInformationItemCrsCPlength:
		return "crsCPlength"
	case OTDOAInformationItemMBSFNsubframeConfiguration:
		return "mBSFNsubframeConfiguration"
	case OTDOAInformationItemNPRSConfiguration:
		return "nPRSConfiguration"
	case OTDOAInformationItemOffsetNBChannelNumbertoEARFCN:
		return "offsetNBChannelNumbertoEARFCN"
	case OTDOAInformationItemOperationModeInfo:
		return "operationModeInfo"
	case OTDOAInformationItemNPRSID:
		return "nPRS-ID"
	case OTDOAInformationItemDlBandwidth:
		return "dlBandwidth"
	case OTDOAInformationItemMultipleprsConfigurationsperCell:
		return "multipleprsConfigurationsperCell"
	case OTDOAInformationItemPrsOccasionGroup:
		return "prsOccasionGroup"
	case OTDOAInformationItemPrsFrequencyHoppingConfiguration:
		return "prsFrequencyHoppingConfiguration"
	case OTDOAInformationItemRepetitionNumberofSIB1NB:
		return "repetitionNumberofSIB1-NB"
	case OTDOAInformationItemNPRSSequenceInfo:
		return "nPRSSequenceInfo"
	case OTDOAInformationItemNPRSType2:
		return "nPRSType2"
	case OTDOAInformationItemTddConfig:
		return "tddConfig"
	default:
		return "unknown"
	}
}

// Outcome represents the ASN.1 ENUMERATED type Outcome.
type Outcome int64

const (
	OutcomeFailed Outcome = 0
)

func (v Outcome) String() string {
	switch v {
	case OutcomeFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// PCI represents the ASN.1 type PCI (INTEGER).
type PCI = *big.Int

// PhysCellIDGERAN represents the ASN.1 type PhysCellIDGERAN (INTEGER).
type PhysCellIDGERAN = *big.Int

// PhysCellIDUTRAFDD represents the ASN.1 type PhysCellIDUTRA-FDD (INTEGER).
type PhysCellIDUTRAFDD = *big.Int

// PhysCellIDUTRATDD represents the ASN.1 type PhysCellIDUTRA-TDD (INTEGER).
type PhysCellIDUTRATDD = *big.Int

// PLMNIdentity represents the ASN.1 type PLMN-Identity (OCTET_STRING).
type PLMNIdentity = []byte

// PosSIBs represents the ASN.1 type PosSIBs (SEQUENCE_OF).
type PosSIBs = []PosSIBsElem

// PosSIBSegments represents the ASN.1 type PosSIB-Segments (SEQUENCE_OF).
type PosSIBSegments = []PosSIBSegmentsElem

// PosSIBType represents the ASN.1 ENUMERATED type PosSIB-Type.
type PosSIBType int64

const (
	PosSIBTypePosSibType11  PosSIBType = 0
	PosSIBTypePosSibType12  PosSIBType = 1
	PosSIBTypePosSibType13  PosSIBType = 2
	PosSIBTypePosSibType14  PosSIBType = 3
	PosSIBTypePosSibType15  PosSIBType = 4
	PosSIBTypePosSibType16  PosSIBType = 5
	PosSIBTypePosSibType17  PosSIBType = 6
	PosSIBTypePosSibType21  PosSIBType = 7
	PosSIBTypePosSibType22  PosSIBType = 8
	PosSIBTypePosSibType23  PosSIBType = 9
	PosSIBTypePosSibType24  PosSIBType = 10
	PosSIBTypePosSibType25  PosSIBType = 11
	PosSIBTypePosSibType26  PosSIBType = 12
	PosSIBTypePosSibType27  PosSIBType = 13
	PosSIBTypePosSibType28  PosSIBType = 14
	PosSIBTypePosSibType29  PosSIBType = 15
	PosSIBTypePosSibType210 PosSIBType = 16
	PosSIBTypePosSibType211 PosSIBType = 17
	PosSIBTypePosSibType212 PosSIBType = 18
	PosSIBTypePosSibType213 PosSIBType = 19
	PosSIBTypePosSibType214 PosSIBType = 20
	PosSIBTypePosSibType215 PosSIBType = 21
	PosSIBTypePosSibType216 PosSIBType = 22
	PosSIBTypePosSibType217 PosSIBType = 23
	PosSIBTypePosSibType218 PosSIBType = 24
	PosSIBTypePosSibType219 PosSIBType = 25
	PosSIBTypePosSibType31  PosSIBType = 26
	PosSIBTypePosSibType41  PosSIBType = 27
	PosSIBTypePosSibType51  PosSIBType = 28
	PosSIBTypePosSibType224 PosSIBType = 29
	PosSIBTypePosSibType225 PosSIBType = 30
)

func (v PosSIBType) String() string {
	switch v {
	case PosSIBTypePosSibType11:
		return "posSibType1-1"
	case PosSIBTypePosSibType12:
		return "posSibType1-2"
	case PosSIBTypePosSibType13:
		return "posSibType1-3"
	case PosSIBTypePosSibType14:
		return "posSibType1-4"
	case PosSIBTypePosSibType15:
		return "posSibType1-5"
	case PosSIBTypePosSibType16:
		return "posSibType1-6"
	case PosSIBTypePosSibType17:
		return "posSibType1-7"
	case PosSIBTypePosSibType21:
		return "posSibType2-1"
	case PosSIBTypePosSibType22:
		return "posSibType2-2"
	case PosSIBTypePosSibType23:
		return "posSibType2-3"
	case PosSIBTypePosSibType24:
		return "posSibType2-4"
	case PosSIBTypePosSibType25:
		return "posSibType2-5"
	case PosSIBTypePosSibType26:
		return "posSibType2-6"
	case PosSIBTypePosSibType27:
		return "posSibType2-7"
	case PosSIBTypePosSibType28:
		return "posSibType2-8"
	case PosSIBTypePosSibType29:
		return "posSibType2-9"
	case PosSIBTypePosSibType210:
		return "posSibType2-10"
	case PosSIBTypePosSibType211:
		return "posSibType2-11"
	case PosSIBTypePosSibType212:
		return "posSibType2-12"
	case PosSIBTypePosSibType213:
		return "posSibType2-13"
	case PosSIBTypePosSibType214:
		return "posSibType2-14"
	case PosSIBTypePosSibType215:
		return "posSibType2-15"
	case PosSIBTypePosSibType216:
		return "posSibType2-16"
	case PosSIBTypePosSibType217:
		return "posSibType2-17"
	case PosSIBTypePosSibType218:
		return "posSibType2-18"
	case PosSIBTypePosSibType219:
		return "posSibType2-19"
	case PosSIBTypePosSibType31:
		return "posSibType3-1"
	case PosSIBTypePosSibType41:
		return "posSibType4-1"
	case PosSIBTypePosSibType51:
		return "posSibType5-1"
	case PosSIBTypePosSibType224:
		return "posSibType2-24"
	case PosSIBTypePosSibType225:
		return "posSibType2-25"
	default:
		return "unknown"
	}
}

// PRSBandwidth represents the ASN.1 ENUMERATED type PRS-Bandwidth.
type PRSBandwidth int64

const (
	PRSBandwidthBw6   PRSBandwidth = 0
	PRSBandwidthBw15  PRSBandwidth = 1
	PRSBandwidthBw25  PRSBandwidth = 2
	PRSBandwidthBw50  PRSBandwidth = 3
	PRSBandwidthBw75  PRSBandwidth = 4
	PRSBandwidthBw100 PRSBandwidth = 5
)

func (v PRSBandwidth) String() string {
	switch v {
	case PRSBandwidthBw6:
		return "bw6"
	case PRSBandwidthBw15:
		return "bw15"
	case PRSBandwidthBw25:
		return "bw25"
	case PRSBandwidthBw50:
		return "bw50"
	case PRSBandwidthBw75:
		return "bw75"
	case PRSBandwidthBw100:
		return "bw100"
	default:
		return "unknown"
	}
}

// PRSConfigurationIndex represents the ASN.1 type PRS-Configuration-Index (INTEGER).
type PRSConfigurationIndex = *big.Int

// PRSID represents the ASN.1 type PRS-ID (INTEGER).
type PRSID = *big.Int

// PRSMutingConfiguration choice constants.
const (
	PRSMutingConfigurationChoiceTwo                      = 1
	PRSMutingConfigurationChoiceFour                     = 2
	PRSMutingConfigurationChoiceEight                    = 3
	PRSMutingConfigurationChoiceSixteen                  = 4
	PRSMutingConfigurationChoiceThirtyTwo                = 5
	PRSMutingConfigurationChoiceSixtyFour                = 6
	PRSMutingConfigurationChoiceOneHundredAndTwentyEight = 7
	PRSMutingConfigurationChoiceTwoHundredAndFiftySix    = 8
	PRSMutingConfigurationChoiceFiveHundredAndTwelve     = 9
	PRSMutingConfigurationChoiceOneThousandAndTwentyFour = 10
)

// PRSMutingConfiguration represents the ASN.1 CHOICE type PRSMutingConfiguration.
type PRSMutingConfiguration struct {
	Choice                   int
	PERPadding_              per.CompletePadding         `json:"-"`
	PEROpenTypePadding_      per.CompletePadding         `json:"-"`
	UnknownExtension         *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	Two                      *runtime.BitString          `json:"Two,omitempty"`
	Four                     *runtime.BitString          `json:"Four,omitempty"`
	Eight                    *runtime.BitString          `json:"Eight,omitempty"`
	Sixteen                  *runtime.BitString          `json:"Sixteen,omitempty"`
	ThirtyTwo                *runtime.BitString          `json:"ThirtyTwo,omitempty"`
	SixtyFour                *runtime.BitString          `json:"SixtyFour,omitempty"`
	OneHundredAndTwentyEight *runtime.BitString          `json:"OneHundredAndTwentyEight,omitempty"`
	TwoHundredAndFiftySix    *runtime.BitString          `json:"TwoHundredAndFiftySix,omitempty"`
	FiveHundredAndTwelve     *runtime.BitString          `json:"FiveHundredAndTwelve,omitempty"`
	OneThousandAndTwentyFour *runtime.BitString          `json:"OneThousandAndTwentyFour,omitempty"`
}

// NewPRSMutingConfigurationTwo creates a PRSMutingConfiguration with the two alternative.
func NewPRSMutingConfigurationTwo(v runtime.BitString) PRSMutingConfiguration {
	return PRSMutingConfiguration{
		Choice: PRSMutingConfigurationChoiceTwo,
		Two:    &v,
	}
}

// NewPRSMutingConfigurationFour creates a PRSMutingConfiguration with the four alternative.
func NewPRSMutingConfigurationFour(v runtime.BitString) PRSMutingConfiguration {
	return PRSMutingConfiguration{
		Choice: PRSMutingConfigurationChoiceFour,
		Four:   &v,
	}
}

// NewPRSMutingConfigurationEight creates a PRSMutingConfiguration with the eight alternative.
func NewPRSMutingConfigurationEight(v runtime.BitString) PRSMutingConfiguration {
	return PRSMutingConfiguration{
		Choice: PRSMutingConfigurationChoiceEight,
		Eight:  &v,
	}
}

// NewPRSMutingConfigurationSixteen creates a PRSMutingConfiguration with the sixteen alternative.
func NewPRSMutingConfigurationSixteen(v runtime.BitString) PRSMutingConfiguration {
	return PRSMutingConfiguration{
		Choice:  PRSMutingConfigurationChoiceSixteen,
		Sixteen: &v,
	}
}

// NewPRSMutingConfigurationThirtyTwo creates a PRSMutingConfiguration with the thirty-two alternative.
func NewPRSMutingConfigurationThirtyTwo(v runtime.BitString) PRSMutingConfiguration {
	return PRSMutingConfiguration{
		Choice:    PRSMutingConfigurationChoiceThirtyTwo,
		ThirtyTwo: &v,
	}
}

// NewPRSMutingConfigurationSixtyFour creates a PRSMutingConfiguration with the sixty-four alternative.
func NewPRSMutingConfigurationSixtyFour(v runtime.BitString) PRSMutingConfiguration {
	return PRSMutingConfiguration{
		Choice:    PRSMutingConfigurationChoiceSixtyFour,
		SixtyFour: &v,
	}
}

// NewPRSMutingConfigurationOneHundredAndTwentyEight creates a PRSMutingConfiguration with the one-hundred-and-twenty-eight alternative.
func NewPRSMutingConfigurationOneHundredAndTwentyEight(v runtime.BitString) PRSMutingConfiguration {
	return PRSMutingConfiguration{
		Choice:                   PRSMutingConfigurationChoiceOneHundredAndTwentyEight,
		OneHundredAndTwentyEight: &v,
	}
}

// NewPRSMutingConfigurationTwoHundredAndFiftySix creates a PRSMutingConfiguration with the two-hundred-and-fifty-six alternative.
func NewPRSMutingConfigurationTwoHundredAndFiftySix(v runtime.BitString) PRSMutingConfiguration {
	return PRSMutingConfiguration{
		Choice:                PRSMutingConfigurationChoiceTwoHundredAndFiftySix,
		TwoHundredAndFiftySix: &v,
	}
}

// NewPRSMutingConfigurationFiveHundredAndTwelve creates a PRSMutingConfiguration with the five-hundred-and-twelve alternative.
func NewPRSMutingConfigurationFiveHundredAndTwelve(v runtime.BitString) PRSMutingConfiguration {
	return PRSMutingConfiguration{
		Choice:               PRSMutingConfigurationChoiceFiveHundredAndTwelve,
		FiveHundredAndTwelve: &v,
	}
}

// NewPRSMutingConfigurationOneThousandAndTwentyFour creates a PRSMutingConfiguration with the one-thousand-and-twenty-four alternative.
func NewPRSMutingConfigurationOneThousandAndTwentyFour(v runtime.BitString) PRSMutingConfiguration {
	return PRSMutingConfiguration{
		Choice:                   PRSMutingConfigurationChoiceOneThousandAndTwentyFour,
		OneThousandAndTwentyFour: &v,
	}
}

// PRSOccasionGroup represents the ASN.1 ENUMERATED type PRSOccasionGroup.
type PRSOccasionGroup int64

const (
	PRSOccasionGroupOg2   PRSOccasionGroup = 0
	PRSOccasionGroupOg4   PRSOccasionGroup = 1
	PRSOccasionGroupOg8   PRSOccasionGroup = 2
	PRSOccasionGroupOg16  PRSOccasionGroup = 3
	PRSOccasionGroupOg32  PRSOccasionGroup = 4
	PRSOccasionGroupOg64  PRSOccasionGroup = 5
	PRSOccasionGroupOg128 PRSOccasionGroup = 6
)

func (v PRSOccasionGroup) String() string {
	switch v {
	case PRSOccasionGroupOg2:
		return "og2"
	case PRSOccasionGroupOg4:
		return "og4"
	case PRSOccasionGroupOg8:
		return "og8"
	case PRSOccasionGroupOg16:
		return "og16"
	case PRSOccasionGroupOg32:
		return "og32"
	case PRSOccasionGroupOg64:
		return "og64"
	case PRSOccasionGroupOg128:
		return "og128"
	default:
		return "unknown"
	}
}

// PRSFrequencyHoppingConfiguration represents the ASN.1 type PRSFrequencyHoppingConfiguration (SEQUENCE).
type PRSFrequencyHoppingConfiguration struct {
	NoOfFreqHoppingBands NumberOfFrequencyHoppingBands                 `asn1:"tag:0,context,implicit"`
	BandPositions        PRSFrequencyHoppingConfigurationBandPositions `asn1:"tag:1,context,implicit"`
	BandPositionsIndef_  bool                                          `asn1:"-" json:"-"`
	IEExtensions         ProtocolExtensionContainer                    `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_   bool                                          `asn1:"-" json:"-"`
	ExtCount_            int64                                         `asn1:"-" json:"-"`
	ExtPresent_          []bool                                        `asn1:"-" json:"-"`
	ExtData_             [][]byte                                      `asn1:"-" json:"-"`
	PERPadding_          per.CompletePadding                           `asn1:"-" json:"-"`
	PERExtPadding_       []per.CompletePadding                         `asn1:"-" json:"-"`
}

// RepetitionNumberofSIB1NB represents the ASN.1 ENUMERATED type RepetitionNumberofSIB1-NB.
type RepetitionNumberofSIB1NB int64

const (
	RepetitionNumberofSIB1NBR4  RepetitionNumberofSIB1NB = 0
	RepetitionNumberofSIB1NBR8  RepetitionNumberofSIB1NB = 1
	RepetitionNumberofSIB1NBR16 RepetitionNumberofSIB1NB = 2
)

func (v RepetitionNumberofSIB1NB) String() string {
	switch v {
	case RepetitionNumberofSIB1NBR4:
		return "r4"
	case RepetitionNumberofSIB1NBR8:
		return "r8"
	case RepetitionNumberofSIB1NBR16:
		return "r16"
	default:
		return "unknown"
	}
}

// ReportCharacteristics represents the ASN.1 ENUMERATED type ReportCharacteristics.
type ReportCharacteristics int64

const (
	ReportCharacteristicsOnDemand ReportCharacteristics = 0
	ReportCharacteristicsPeriodic ReportCharacteristics = 1
)

func (v ReportCharacteristics) String() string {
	switch v {
	case ReportCharacteristicsOnDemand:
		return "onDemand"
	case ReportCharacteristicsPeriodic:
		return "periodic"
	default:
		return "unknown"
	}
}

// RequestedSRSTransmissionCharacteristics represents the ASN.1 type RequestedSRSTransmissionCharacteristics (SEQUENCE).
type RequestedSRSTransmissionCharacteristics struct {
	NumberOfTransmissions *big.Int              `asn1:"tag:0,context,implicit"`
	Bandwidth             *big.Int              `asn1:"tag:1,context,implicit"`
	ExtCount_             int64                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                `asn1:"-" json:"-"`
	ExtData_              [][]byte              `asn1:"-" json:"-"`
	PERPadding_           per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_        []per.CompletePadding `asn1:"-" json:"-"`
}

// ResultRSRP represents the ASN.1 type ResultRSRP (SEQUENCE_OF).
type ResultRSRP = []ResultRSRPItem

// ResultRSRPItem represents the ASN.1 type ResultRSRP-Item (SEQUENCE).
type ResultRSRPItem struct {
	PCI                PCI                        `asn1:"tag:0,context,implicit"`
	EARFCN             EARFCN                     `asn1:"tag:1,context,implicit"`
	ECGI               *ECGI                      `asn1:"tag:2,context,implicit,optional" json:"ECGI,omitempty"`
	ValueRSRP          ValueRSRP                  `asn1:"tag:3,context,implicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
	PERPadding_        per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_     []per.CompletePadding      `asn1:"-" json:"-"`
}

// ResultRSRQ represents the ASN.1 type ResultRSRQ (SEQUENCE_OF).
type ResultRSRQ = []ResultRSRQItem

// ResultRSRQItem represents the ASN.1 type ResultRSRQ-Item (SEQUENCE).
type ResultRSRQItem struct {
	PCI                PCI                        `asn1:"tag:0,context,implicit"`
	EARFCN             EARFCN                     `asn1:"tag:1,context,implicit"`
	ECGI               *ECGI                      `asn1:"tag:2,context,implicit,optional" json:"ECGI,omitempty"`
	ValueRSRQ          ValueRSRQ                  `asn1:"tag:3,context,implicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
	PERPadding_        per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_     []per.CompletePadding      `asn1:"-" json:"-"`
}

// ResultGERAN represents the ASN.1 type ResultGERAN (SEQUENCE_OF).
type ResultGERAN = []ResultGERANItem

// ResultGERANItem represents the ASN.1 type ResultGERAN-Item (SEQUENCE).
type ResultGERANItem struct {
	BCCH               BCCH                       `asn1:"tag:0,context,implicit"`
	PhysCellIDGERAN    PhysCellIDGERAN            `asn1:"tag:1,context,implicit"`
	RSSI               RSSI                       `asn1:"tag:2,context,implicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
	PERPadding_        per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_     []per.CompletePadding      `asn1:"-" json:"-"`
}

// ResultUTRAN represents the ASN.1 type ResultUTRAN (SEQUENCE_OF).
type ResultUTRAN = []ResultUTRANItem

// ResultUTRANItem represents the ASN.1 type ResultUTRAN-Item (SEQUENCE).
type ResultUTRANItem struct {
	UARFCN             UARFCN                         `asn1:"tag:0,context,implicit"`
	PhysCellIDUTRAN    ResultUTRANItemPhysCellIDUTRAN `asn1:"tag:1,context,explicit"`
	UTRARSCP           UTRARSCP                       `asn1:"tag:2,context,implicit,optional" json:"UTRARSCP,omitempty"`
	UTRAEcN0           UTRAEcN0                       `asn1:"tag:3,context,implicit,optional" json:"UTRAEcN0,omitempty"`
	IEExtensions       ProtocolExtensionContainer     `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                           `asn1:"-" json:"-"`
	ExtCount_          int64                          `asn1:"-" json:"-"`
	ExtPresent_        []bool                         `asn1:"-" json:"-"`
	ExtData_           [][]byte                       `asn1:"-" json:"-"`
	PERPadding_        per.CompletePadding            `asn1:"-" json:"-"`
	PERExtPadding_     []per.CompletePadding          `asn1:"-" json:"-"`
}

// ResultNR represents the ASN.1 type ResultNR (SEQUENCE_OF).
type ResultNR = []ResultNRItem

// ResultNRItem represents the ASN.1 type ResultNR-Item (SEQUENCE).
type ResultNRItem struct {
	NRARFCN            NRARFCN                    `asn1:"tag:0,context,implicit"`
	NRPCI              NRPCI                      `asn1:"tag:1,context,implicit"`
	SSNRRSRP           *SSNRRSRP                  `asn1:"tag:2,context,implicit,optional" json:"SSNRRSRP,omitempty"`
	SSNRRSRQ           *SSNRRSRQ                  `asn1:"tag:3,context,implicit,optional" json:"SSNRRSRQ,omitempty"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
	PERPadding_        per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_     []per.CompletePadding      `asn1:"-" json:"-"`
}

// ResultsPerSSBIndexList represents the ASN.1 type ResultsPerSSB-Index-List (SEQUENCE_OF).
type ResultsPerSSBIndexList = []ResultsPerSSBIndexItem

// ResultsPerSSBIndexItem represents the ASN.1 type ResultsPerSSB-Index-Item (SEQUENCE).
type ResultsPerSSBIndexItem struct {
	SSBIndex           SSBIndex                   `asn1:"tag:0,context,implicit"`
	SSNRRSRPBeamValue  *SSNRRSRP                  `asn1:"tag:1,context,implicit,optional" json:"SSNRRSRPBeamValue,omitempty"`
	SSNRRSRQBeamValue  *SSNRRSRQ                  `asn1:"tag:2,context,implicit,optional" json:"SSNRRSRQBeamValue,omitempty"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
	PERPadding_        per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_     []per.CompletePadding      `asn1:"-" json:"-"`
}

// RSSI represents the ASN.1 type RSSI (INTEGER).
type RSSI = *big.Int

// SFNInitialisationTime represents the ASN.1 type SFNInitialisationTime (BIT_STRING).
type SFNInitialisationTime = runtime.BitString

// SRSConfigurationForAllCells represents the ASN.1 type SRSConfigurationForAllCells (SEQUENCE_OF).
type SRSConfigurationForAllCells = []SRSConfigurationForOneCell

// SRSConfigurationForOneCell represents the ASN.1 type SRSConfigurationForOneCell (SEQUENCE).
type SRSConfigurationForOneCell struct {
	Pci                     PCI                   `asn1:"tag:0,context,implicit"`
	UlEarfcn                EARFCN                `asn1:"tag:1,context,implicit"`
	UlBandwidth             int64                 `asn1:"tag:2,context,implicit"`
	UlCyclicPrefixLength    CPLength              `asn1:"tag:3,context,implicit"`
	SrsBandwidthConfig      int64                 `asn1:"tag:4,context,implicit"`
	SrsBandwidth            int64                 `asn1:"tag:5,context,implicit"`
	SrsAntennaPort          int64                 `asn1:"tag:6,context,implicit"`
	SrsHoppingBandwidth     int64                 `asn1:"tag:7,context,implicit"`
	SrsCyclicShift          int64                 `asn1:"tag:8,context,implicit"`
	SrsConfigIndex          int64                 `asn1:"tag:9,context,implicit"`
	MaxUpPts                *int64                `asn1:"tag:10,context,implicit,optional" json:"MaxUpPts,omitempty"`
	TransmissionComb        int64                 `asn1:"tag:11,context,implicit"`
	FreqDomainPosition      int64                 `asn1:"tag:12,context,implicit"`
	GroupHoppingEnabled     bool                  `asn1:"tag:13,context,implicit"`
	GroupHoppingEnabledRaw_ byte                  `asn1:"-" json:"-"`
	DeltaSS                 *int64                `asn1:"tag:14,context,implicit,optional" json:"DeltaSS,omitempty"`
	SfnInitialisationTime   SFNInitialisationTime `asn1:"tag:15,context,implicit"`
	ExtCount_               int64                 `asn1:"-" json:"-"`
	ExtPresent_             []bool                `asn1:"-" json:"-"`
	ExtData_                [][]byte              `asn1:"-" json:"-"`
	PERPadding_             per.CompletePadding   `asn1:"-" json:"-"`
	PERExtPadding_          []per.CompletePadding `asn1:"-" json:"-"`
}

// Subframeallocation choice constants.
const (
	SubframeallocationChoiceOneFrame   = 1
	SubframeallocationChoiceFourFrames = 2
)

// Subframeallocation represents the ASN.1 CHOICE type Subframeallocation.
type Subframeallocation struct {
	Choice              int
	PERPadding_         per.CompletePadding `json:"-"`
	PEROpenTypePadding_ per.CompletePadding `json:"-"`
	OneFrame            *runtime.BitString  `json:"OneFrame,omitempty"`
	FourFrames          *runtime.BitString  `json:"FourFrames,omitempty"`
}

// NewSubframeallocationOneFrame creates a Subframeallocation with the oneFrame alternative.
func NewSubframeallocationOneFrame(v runtime.BitString) Subframeallocation {
	return Subframeallocation{
		Choice:   SubframeallocationChoiceOneFrame,
		OneFrame: &v,
	}
}

// NewSubframeallocationFourFrames creates a Subframeallocation with the fourFrames alternative.
func NewSubframeallocationFourFrames(v runtime.BitString) Subframeallocation {
	return Subframeallocation{
		Choice:     SubframeallocationChoiceFourFrames,
		FourFrames: &v,
	}
}

// SSNRRSRP represents the ASN.1 type SS-NRRSRP (INTEGER).
type SSNRRSRP = int64

// SSNRRSRQ represents the ASN.1 type SS-NRRSRQ (INTEGER).
type SSNRRSRQ = int64

// SSBIndex represents the ASN.1 type SSB-Index (INTEGER).
type SSBIndex = int64

// SSID represents the ASN.1 type SSID (OCTET_STRING).
type SSID = []byte

// SystemInformation represents the ASN.1 type SystemInformation (SEQUENCE_OF).
type SystemInformation = []SystemInformationElem

// TAC represents the ASN.1 type TAC (OCTET_STRING).
type TAC = []byte

// TDDConfiguration represents the ASN.1 type TDDConfiguration (SEQUENCE).
type TDDConfiguration struct {
	SubframeAssignment int64                      `asn1:"tag:0,context,implicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
	PERPadding_        per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_     []per.CompletePadding      `asn1:"-" json:"-"`
}

// TPID represents the ASN.1 type TP-ID (INTEGER).
type TPID = *big.Int

// TPType represents the ASN.1 ENUMERATED type TP-Type.
type TPType int64

const (
	TPTypePrsOnlyTp TPType = 0
)

func (v TPType) String() string {
	switch v {
	case TPTypePrsOnlyTp:
		return "prs-only-tp"
	default:
		return "unknown"
	}
}

// TypeOfError represents the ASN.1 ENUMERATED type TypeOfError.
type TypeOfError int64

const (
	TypeOfErrorNotUnderstood TypeOfError = 0
	TypeOfErrorMissing       TypeOfError = 1
)

func (v TypeOfError) String() string {
	switch v {
	case TypeOfErrorNotUnderstood:
		return "not-understood"
	case TypeOfErrorMissing:
		return "missing"
	default:
		return "unknown"
	}
}

// ULConfiguration represents the ASN.1 type ULConfiguration (SEQUENCE).
type ULConfiguration struct {
	Pci                    PCI                         `asn1:"tag:0,context,implicit"`
	UlEarfcn               EARFCN                      `asn1:"tag:1,context,implicit"`
	TimingAdvanceType1     *int64                      `asn1:"tag:2,context,implicit,optional" json:"TimingAdvanceType1,omitempty"`
	TimingAdvanceType2     *int64                      `asn1:"tag:3,context,implicit,optional" json:"TimingAdvanceType2,omitempty"`
	NumberOfTransmissions  *big.Int                    `asn1:"tag:4,context,implicit"`
	SrsConfiguration       SRSConfigurationForAllCells `asn1:"tag:5,context,implicit"`
	SrsConfigurationIndef_ bool                        `asn1:"-" json:"-"`
	ExtCount_              int64                       `asn1:"-" json:"-"`
	ExtPresent_            []bool                      `asn1:"-" json:"-"`
	ExtData_               [][]byte                    `asn1:"-" json:"-"`
	PERPadding_            per.CompletePadding         `asn1:"-" json:"-"`
	PERExtPadding_         []per.CompletePadding       `asn1:"-" json:"-"`
}

// UARFCN represents the ASN.1 type UARFCN (INTEGER).
type UARFCN = *big.Int

// UTRAEcN0 represents the ASN.1 type UTRA-EcN0 (INTEGER).
type UTRAEcN0 = *big.Int

// UTRARSCP represents the ASN.1 type UTRA-RSCP (INTEGER).
type UTRARSCP = *big.Int

// ValueRSRP represents the ASN.1 type ValueRSRP (INTEGER).
type ValueRSRP = *big.Int

// ValueRSRQ represents the ASN.1 type ValueRSRQ (INTEGER).
type ValueRSRQ = *big.Int

// WLANMeasurementQuantities represents the ASN.1 type WLANMeasurementQuantities (SEQUENCE_OF).
type WLANMeasurementQuantities = []ProtocolIESingleContainer

// WLANMeasurementQuantitiesItem represents the ASN.1 type WLANMeasurementQuantities-Item (SEQUENCE).
type WLANMeasurementQuantitiesItem struct {
	WLANMeasurementQuantitiesValue WLANMeasurementQuantitiesValue `asn1:"tag:0,context,implicit"`
	IEExtensions                   ProtocolExtensionContainer     `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_             bool                           `asn1:"-" json:"-"`
	ExtCount_                      int64                          `asn1:"-" json:"-"`
	ExtPresent_                    []bool                         `asn1:"-" json:"-"`
	ExtData_                       [][]byte                       `asn1:"-" json:"-"`
	PERPadding_                    per.CompletePadding            `asn1:"-" json:"-"`
	PERExtPadding_                 []per.CompletePadding          `asn1:"-" json:"-"`
}

// WLANMeasurementQuantitiesValue represents the ASN.1 ENUMERATED type WLANMeasurementQuantitiesValue.
type WLANMeasurementQuantitiesValue int64

const (
	WLANMeasurementQuantitiesValueWlan WLANMeasurementQuantitiesValue = 0
)

func (v WLANMeasurementQuantitiesValue) String() string {
	switch v {
	case WLANMeasurementQuantitiesValueWlan:
		return "wlan"
	default:
		return "unknown"
	}
}

// WLANMeasurementResult represents the ASN.1 type WLANMeasurementResult (SEQUENCE_OF).
type WLANMeasurementResult = []WLANMeasurementResultItem

// WLANMeasurementResultItem represents the ASN.1 type WLANMeasurementResult-Item (SEQUENCE).
type WLANMeasurementResultItem struct {
	WLANRSSI              WLANRSSI                   `asn1:"tag:0,context,implicit"`
	SSID                  *SSID                      `asn1:"tag:1,context,implicit,optional" json:"SSID,omitempty"`
	BSSID                 *BSSID                     `asn1:"tag:2,context,implicit,optional" json:"BSSID,omitempty"`
	HESSID                *HESSID                    `asn1:"tag:3,context,implicit,optional" json:"HESSID,omitempty"`
	OperatingClass        *WLANOperatingClass        `asn1:"tag:4,context,implicit,optional" json:"OperatingClass,omitempty"`
	CountryCode           *WLANCountryCode           `asn1:"tag:5,context,implicit,optional" json:"CountryCode,omitempty"`
	WLANChannelList       WLANChannelList            `asn1:"tag:6,context,implicit,optional" json:"WLANChannelList,omitempty"`
	WLANChannelListIndef_ bool                       `asn1:"-" json:"-"`
	WLANBand              *WLANBand                  `asn1:"tag:7,context,implicit,optional" json:"WLANBand,omitempty"`
	IEExtensions          ProtocolExtensionContainer `asn1:"tag:8,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_    bool                       `asn1:"-" json:"-"`
	ExtCount_             int64                      `asn1:"-" json:"-"`
	ExtPresent_           []bool                     `asn1:"-" json:"-"`
	ExtData_              [][]byte                   `asn1:"-" json:"-"`
	PERPadding_           per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_        []per.CompletePadding      `asn1:"-" json:"-"`
}

// WLANRSSI represents the ASN.1 type WLAN-RSSI (INTEGER).
type WLANRSSI = *big.Int

// WLANBand represents the ASN.1 ENUMERATED type WLANBand.
type WLANBand int64

const (
	WLANBandBand2dot4 WLANBand = 0
	WLANBandBand5     WLANBand = 1
)

func (v WLANBand) String() string {
	switch v {
	case WLANBandBand2dot4:
		return "band2dot4"
	case WLANBandBand5:
		return "band5"
	default:
		return "unknown"
	}
}

// WLANChannelList represents the ASN.1 type WLANChannelList (SEQUENCE_OF).
type WLANChannelList = []WLANChannel

// WLANChannel represents the ASN.1 type WLANChannel (INTEGER).
type WLANChannel = int64

// WLANCountryCode represents the ASN.1 ENUMERATED type WLANCountryCode.
type WLANCountryCode int64

const (
	WLANCountryCodeUnitedStates WLANCountryCode = 0
	WLANCountryCodeEurope       WLANCountryCode = 1
	WLANCountryCodeJapan        WLANCountryCode = 2
	WLANCountryCodeGlobal       WLANCountryCode = 3
)

func (v WLANCountryCode) String() string {
	switch v {
	case WLANCountryCodeUnitedStates:
		return "unitedStates"
	case WLANCountryCodeEurope:
		return "europe"
	case WLANCountryCodeJapan:
		return "japan"
	case WLANCountryCodeGlobal:
		return "global"
	default:
		return "unknown"
	}
}

// WLANOperatingClass represents the ASN.1 type WLANOperatingClass (INTEGER).
type WLANOperatingClass = int64

// AddOTDOACellsElem represents the ASN.1 type Add-OTDOACells-Elem (SEQUENCE).
type AddOTDOACellsElem struct {
	AddOTDOACellInfo       AddOTDOACellInformation    `asn1:"tag:0,context,implicit"`
	AddOTDOACellInfoIndef_ bool                       `asn1:"-" json:"-"`
	IEExtensions           ProtocolExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_     bool                       `asn1:"-" json:"-"`
	ExtCount_              int64                      `asn1:"-" json:"-"`
	ExtPresent_            []bool                     `asn1:"-" json:"-"`
	ExtData_               [][]byte                   `asn1:"-" json:"-"`
	PERPadding_            per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_         []per.CompletePadding      `asn1:"-" json:"-"`
}

// AssistanceInformationFailureListElem represents the ASN.1 type AssistanceInformationFailureList-Elem (SEQUENCE).
type AssistanceInformationFailureListElem struct {
	PosSIBType         PosSIBType                 `asn1:"tag:0,context,implicit"`
	Outcome            Outcome                    `asn1:"tag:1,context,implicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
	PERPadding_        per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_     []per.CompletePadding      `asn1:"-" json:"-"`
}

// CriticalityDiagnosticsIEListElem represents the ASN.1 type CriticalityDiagnostics-IE-List-Elem (SEQUENCE).
type CriticalityDiagnosticsIEListElem struct {
	IECriticality      Criticality                `asn1:"tag:0,context,implicit"`
	IEID               ProtocolIEID               `asn1:"tag:1,context,implicit"`
	TypeOfError        TypeOfError                `asn1:"tag:2,context,implicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
	PERPadding_        per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_     []per.CompletePadding      `asn1:"-" json:"-"`
}

// OTDOACellsElem represents the ASN.1 type OTDOACells-Elem (SEQUENCE).
type OTDOACellsElem struct {
	OTDOACellInfo       OTDOACellInformation       `asn1:"tag:0,context,implicit"`
	OTDOACellInfoIndef_ bool                       `asn1:"-" json:"-"`
	IEExtensions        ProtocolExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_  bool                       `asn1:"-" json:"-"`
	ExtCount_           int64                      `asn1:"-" json:"-"`
	ExtPresent_         []bool                     `asn1:"-" json:"-"`
	ExtData_            [][]byte                   `asn1:"-" json:"-"`
	PERPadding_         per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_      []per.CompletePadding      `asn1:"-" json:"-"`
}

// PosSIBsElem represents the ASN.1 type PosSIBs-Elem (SEQUENCE).
type PosSIBsElem struct {
	PosSIBType                    PosSIBType                     `asn1:"tag:0,context,implicit"`
	PosSIBSegments                PosSIBSegments                 `asn1:"tag:1,context,implicit"`
	PosSIBSegmentsIndef_          bool                           `asn1:"-" json:"-"`
	AssistanceInformationMetaData *AssistanceInformationMetaData `asn1:"tag:2,context,implicit,optional" json:"AssistanceInformationMetaData,omitempty"`
	BroadcastPriority             *big.Int                       `asn1:"tag:3,context,implicit,optional" json:"BroadcastPriority,omitempty"`
	IEExtensions                  ProtocolExtensionContainer     `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_            bool                           `asn1:"-" json:"-"`
	ExtCount_                     int64                          `asn1:"-" json:"-"`
	ExtPresent_                   []bool                         `asn1:"-" json:"-"`
	ExtData_                      [][]byte                       `asn1:"-" json:"-"`
	PERPadding_                   per.CompletePadding            `asn1:"-" json:"-"`
	PERExtPadding_                []per.CompletePadding          `asn1:"-" json:"-"`
}

// PosSIBSegmentsElem represents the ASN.1 type PosSIB-Segments-Elem (SEQUENCE).
type PosSIBSegmentsElem struct {
	AssistanceDataSIBelement []byte                     `asn1:"tag:0,context,implicit"`
	IEExtensions             ProtocolExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_       bool                       `asn1:"-" json:"-"`
	ExtCount_                int64                      `asn1:"-" json:"-"`
	ExtPresent_              []bool                     `asn1:"-" json:"-"`
	ExtData_                 [][]byte                   `asn1:"-" json:"-"`
	PERPadding_              per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_           []per.CompletePadding      `asn1:"-" json:"-"`
}

// PRSFrequencyHoppingConfigurationBandPositions represents the ASN.1 type PRSFrequencyHoppingConfiguration-bandPositions (SEQUENCE_OF).
type PRSFrequencyHoppingConfigurationBandPositions = []NarrowBandIndex

// ResultUTRANItemPhysCellIDUTRAN choice constants.
const (
	ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD = 1
	ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD = 2
)

// ResultUTRANItemPhysCellIDUTRAN represents the ASN.1 CHOICE type ResultUTRAN-Item-physCellIDUTRAN.
type ResultUTRANItemPhysCellIDUTRAN struct {
	Choice              int
	PERPadding_         per.CompletePadding `json:"-"`
	PEROpenTypePadding_ per.CompletePadding `json:"-"`
	PhysCellIDUTRAFDD   PhysCellIDUTRAFDD   `json:"PhysCellIDUTRAFDD,omitempty"`
	PhysCellIDUTRATDD   PhysCellIDUTRATDD   `json:"PhysCellIDUTRATDD,omitempty"`
}

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD creates a ResultUTRANItemPhysCellIDUTRAN with the physCellIDUTRA-FDD alternative.
func NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD(v PhysCellIDUTRAFDD) ResultUTRANItemPhysCellIDUTRAN {
	return ResultUTRANItemPhysCellIDUTRAN{
		Choice:            ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD,
		PhysCellIDUTRAFDD: v,
	}
}

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD creates a ResultUTRANItemPhysCellIDUTRAN with the physCellIDUTRA-TDD alternative.
func NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD(v PhysCellIDUTRATDD) ResultUTRANItemPhysCellIDUTRAN {
	return ResultUTRANItemPhysCellIDUTRAN{
		Choice:            ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD,
		PhysCellIDUTRATDD: v,
	}
}

// SystemInformationElem represents the ASN.1 type SystemInformation-Elem (SEQUENCE).
type SystemInformationElem struct {
	BroadcastPeriodicity BroadcastPeriodicity       `asn1:"tag:0,context,implicit"`
	PosSIBs              PosSIBs                    `asn1:"tag:1,context,implicit"`
	PosSIBsIndef_        bool                       `asn1:"-" json:"-"`
	IEExtensions         ProtocolExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_   bool                       `asn1:"-" json:"-"`
	ExtCount_            int64                      `asn1:"-" json:"-"`
	ExtPresent_          []bool                     `asn1:"-" json:"-"`
	ExtData_             [][]byte                   `asn1:"-" json:"-"`
	PERPadding_          per.CompletePadding        `asn1:"-" json:"-"`
	PERExtPadding_       []per.CompletePadding      `asn1:"-" json:"-"`
}

type asn1cAPERAddOTDOACellsListValue struct{ Value AddOTDOACells }

// AddOTDOACellsComplete carries a complete AddOTDOACells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AddOTDOACellsComplete struct {
	Value       AddOTDOACells
	PERPadding_ per.CompletePadding
}

func (v *AddOTDOACellsComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERAddOTDOACellsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *AddOTDOACellsComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERAddOTDOACellsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACells")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACells")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERAddOTDOACells encodes a AddOTDOACells list to APER.
func MarshalAPERAddOTDOACells(list AddOTDOACellsComplete) ([]byte, error) { return list.MarshalAPER() }

// MarshalAPERAddOTDOACellsTo appends a AddOTDOACells list to bb.
func MarshalAPERAddOTDOACellsTo(list AddOTDOACells, bb *per.BitBuffer) error {
	v := asn1cAPERAddOTDOACellsListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 3840, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERAddOTDOACells decodes a AddOTDOACells list from APER.
func UnmarshalAPERAddOTDOACells(data []byte) (AddOTDOACellsComplete, error) {
	var value AddOTDOACellsComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERAddOTDOACellsFrom decodes a AddOTDOACells list from bb.
func UnmarshalAPERAddOTDOACellsFrom(bb *per.BitBuffer) (AddOTDOACells, error) {
	var v asn1cAPERAddOTDOACellsListValue
	if err := unmarshalAPERAddOTDOACellsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERAddOTDOACellsInto(v *asn1cAPERAddOTDOACellsListValue, bb *per.BitBuffer) error {
	v.Value = make(AddOTDOACells, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 3840, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem AddOTDOACellsElem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

type asn1cAPERAddOTDOACellInformationListValue struct{ Value AddOTDOACellInformation }

// AddOTDOACellInformationComplete carries a complete AddOTDOACellInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AddOTDOACellInformationComplete struct {
	Value       AddOTDOACellInformation
	PERPadding_ per.CompletePadding
}

func (v *AddOTDOACellInformationComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERAddOTDOACellInformationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *AddOTDOACellInformationComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERAddOTDOACellInformationFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACellInformation")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACellInformation")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERAddOTDOACellInformation encodes a AddOTDOACellInformation list to APER.
func MarshalAPERAddOTDOACellInformation(list AddOTDOACellInformationComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERAddOTDOACellInformationTo appends a AddOTDOACellInformation list to bb.
func MarshalAPERAddOTDOACellInformationTo(list AddOTDOACellInformation, bb *per.BitBuffer) error {
	v := asn1cAPERAddOTDOACellInformationListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERAddOTDOACellInformation decodes a AddOTDOACellInformation list from APER.
func UnmarshalAPERAddOTDOACellInformation(data []byte) (AddOTDOACellInformationComplete, error) {
	var value AddOTDOACellInformationComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERAddOTDOACellInformationFrom decodes a AddOTDOACellInformation list from bb.
func UnmarshalAPERAddOTDOACellInformationFrom(bb *per.BitBuffer) (AddOTDOACellInformation, error) {
	var v asn1cAPERAddOTDOACellInformationListValue
	if err := unmarshalAPERAddOTDOACellInformationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERAddOTDOACellInformationInto(v *asn1cAPERAddOTDOACellInformationListValue, bb *per.BitBuffer) error {
	v.Value = make(AddOTDOACellInformation, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem OTDOACellInformationItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes AssistanceInformation to APER format.
func (v *AssistanceInformation) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *AssistanceInformation) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.SystemInformation)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_systeminformation, fragmentLength_systeminformation int64) error {
		for _, elem := range v.SystemInformation[fragmentOffset_systeminformation : fragmentOffset_systeminformation+fragmentLength_systeminformation] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding systemInformation element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding systemInformation: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes AssistanceInformation from APER format.
func (v *AssistanceInformation) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformation")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformation")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *AssistanceInformation) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = AssistanceInformation{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.SystemInformation = make(SystemInformation, 0)
	_, errCollection_systeminformation := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_systeminformation, fragmentLength_systeminformation int64) error {
		for i := int64(0); i < fragmentLength_systeminformation; i++ {
			var elem SystemInformationElem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("SystemInformation[%d]", fragmentOffset_systeminformation+i))
			}
			v.SystemInformation = append(v.SystemInformation, elem)
		}
		return nil
	})
	if errCollection_systeminformation != nil {
		return runtime.WrapDecodePath(errCollection_systeminformation, "SystemInformation")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERAssistanceInformationFailureListListValue struct {
	Value AssistanceInformationFailureList
}

// AssistanceInformationFailureListComplete carries a complete AssistanceInformationFailureList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AssistanceInformationFailureListComplete struct {
	Value       AssistanceInformationFailureList
	PERPadding_ per.CompletePadding
}

func (v *AssistanceInformationFailureListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERAssistanceInformationFailureListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *AssistanceInformationFailureListComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERAssistanceInformationFailureListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFailureList")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFailureList")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERAssistanceInformationFailureList encodes a AssistanceInformationFailureList list to APER.
func MarshalAPERAssistanceInformationFailureList(list AssistanceInformationFailureListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERAssistanceInformationFailureListTo appends a AssistanceInformationFailureList list to bb.
func MarshalAPERAssistanceInformationFailureListTo(list AssistanceInformationFailureList, bb *per.BitBuffer) error {
	v := asn1cAPERAssistanceInformationFailureListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERAssistanceInformationFailureList decodes a AssistanceInformationFailureList list from APER.
func UnmarshalAPERAssistanceInformationFailureList(data []byte) (AssistanceInformationFailureListComplete, error) {
	var value AssistanceInformationFailureListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERAssistanceInformationFailureListFrom decodes a AssistanceInformationFailureList list from bb.
func UnmarshalAPERAssistanceInformationFailureListFrom(bb *per.BitBuffer) (AssistanceInformationFailureList, error) {
	var v asn1cAPERAssistanceInformationFailureListListValue
	if err := unmarshalAPERAssistanceInformationFailureListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERAssistanceInformationFailureListInto(v *asn1cAPERAssistanceInformationFailureListListValue, bb *per.BitBuffer) error {
	v.Value = make(AssistanceInformationFailureList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem AssistanceInformationFailureListElem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes AssistanceInformationMetaData to APER format.
func (v *AssistanceInformationMetaData) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *AssistanceInformationMetaData) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.Encrypted != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.GNSSID != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SBASID != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.Encrypted != nil {
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.Encrypted), 1, true); err != nil {
			return fmt.Errorf("encoding encrypted: %w", err)
		}
	}
	if v.GNSSID != nil {
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.GNSSID), 6, true); err != nil {
			return fmt.Errorf("encoding gNSSID: %w", err)
		}
	}
	if v.SBASID != nil {
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.SBASID), 4, true); err != nil {
			return fmt.Errorf("encoding sBASID: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes AssistanceInformationMetaData from APER format.
func (v *AssistanceInformationMetaData) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationMetaData")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationMetaData")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *AssistanceInformationMetaData) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = AssistanceInformationMetaData{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_encrypted, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_gnssid, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sbasid, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_encrypted {
		val_encrypted, err := per.DecodeEnumeratedAligned(bb, 1, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Encrypted")
		}
		v.Encrypted = &val_encrypted
	}
	if opt_gnssid {
		val_gnssid, err := per.DecodeEnumeratedAligned(bb, 6, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "GNSSID")
		}
		v.GNSSID = &val_gnssid
	}
	if opt_sbasid {
		val_sbasid, err := per.DecodeEnumeratedAligned(bb, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "SBASID")
		}
		v.SBASID = &val_sbasid
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes BitmapsforNPRS to APER format.
func (v *BitmapsforNPRS) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *BitmapsforNPRS) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("BitmapsforNPRS: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("BitmapsforNPRS: extension index %d must be non-negative", v.UnknownExtension.Index)
		}
		if v.UnknownExtension.Index < 2 {
			return fmt.Errorf("BitmapsforNPRS: extension index %d is known to this schema", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 2
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-2-1)); err != nil {
			return err
		}
		inner := per.NewBitBuffer()
		switch v.Choice {
		case BitmapsforNPRSChoiceTenTdd:
			if v.TenTdd == nil {
				return fmt.Errorf("choice alternative ten-tdd is nil")
			}
			if err := per.EncodeBitStringAligned(inner, v.TenTdd.Bytes, v.TenTdd.BitLength, 8, 8, true); err != nil {
				return fmt.Errorf("encoding ten-tdd: %w", err)
			}
		case BitmapsforNPRSChoiceFortyTdd:
			if v.FortyTdd == nil {
				return fmt.Errorf("choice alternative forty-tdd is nil")
			}
			if err := per.EncodeBitStringAligned(inner, v.FortyTdd.Bytes, v.FortyTdd.BitLength, 32, 32, true); err != nil {
				return fmt.Errorf("encoding forty-tdd: %w", err)
			}
		default:
			return fmt.Errorf("unknown BitmapsforNPRS extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(v.PEROpenTypePadding_)
		if err != nil {
			return err
		}
		if err := per.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case BitmapsforNPRSChoiceTen:
		if v.Ten == nil {
			return fmt.Errorf("choice alternative ten is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.Ten.Bytes, v.Ten.BitLength, 10, 10, true); err != nil {
			return fmt.Errorf("encoding ten: %w", err)
		}
	case BitmapsforNPRSChoiceForty:
		if v.Forty == nil {
			return fmt.Errorf("choice alternative forty is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.Forty.Bytes, v.Forty.BitLength, 40, 40, true); err != nil {
			return fmt.Errorf("encoding forty: %w", err)
		}
	default:
		return fmt.Errorf("unknown BitmapsforNPRS choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes BitmapsforNPRS from APER format.
func (v *BitmapsforNPRS) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BitmapsforNPRS")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BitmapsforNPRS")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *BitmapsforNPRS) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = BitmapsforNPRS{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if extIdx >= 2 {
			v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
			return nil
		}
		inner := per.NewBitBufferFromBytes(openData)
		v.Choice = int(extIdx) + 2 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case BitmapsforNPRSChoiceTenTdd:
			extensionPath = "TenTdd"
			bsBytes_tentdd, bsBitLen_tentdd, err := per.DecodeBitStringAligned(inner, 8, 8, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "TenTdd")
			}
			tmp_tentdd := runtime.BitString{Bytes: bsBytes_tentdd, BitLength: bsBitLen_tentdd}
			v.TenTdd = &tmp_tentdd
		case BitmapsforNPRSChoiceFortyTdd:
			extensionPath = "FortyTdd"
			bsBytes_fortytdd, bsBitLen_fortytdd, err := per.DecodeBitStringAligned(inner, 32, 32, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "FortyTdd")
			}
			tmp_fortytdd := runtime.BitString{Bytes: bsBytes_fortytdd, BitLength: bsBitLen_fortytdd}
			v.FortyTdd = &tmp_fortytdd
		}
		padding, err := per.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.PEROpenTypePadding_ = padding
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case BitmapsforNPRSChoiceTen:
		bsBytes_ten, bsBitLen_ten, err := per.DecodeBitStringAligned(bb, 10, 10, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Ten")
		}
		tmp_ten := runtime.BitString{Bytes: bsBytes_ten, BitLength: bsBitLen_ten}
		v.Ten = &tmp_ten
	case BitmapsforNPRSChoiceForty:
		bsBytes_forty, bsBitLen_forty, err := per.DecodeBitStringAligned(bb, 40, 40, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Forty")
		}
		tmp_forty := runtime.BitString{Bytes: bsBytes_forty, BitLength: bsBitLen_forty}
		v.Forty = &tmp_forty
	}
	return nil
}

// MarshalAPER encodes Cause to APER format.
func (v *Cause) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *Cause) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("Cause: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("Cause: extension index %d must be non-negative", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 3
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("Cause: extension choice %d not supported", v.Choice)
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case CauseChoiceRadioNetwork:
		if v.RadioNetwork == nil {
			return fmt.Errorf("choice alternative radioNetwork is nil")
		}
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.RadioNetwork), 3, true); err != nil {
			return fmt.Errorf("encoding radioNetwork: %w", err)
		}
	case CauseChoiceProtocol:
		if v.Protocol == nil {
			return fmt.Errorf("choice alternative protocol is nil")
		}
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.Protocol), 7, true); err != nil {
			return fmt.Errorf("encoding protocol: %w", err)
		}
	case CauseChoiceMisc:
		if v.Misc == nil {
			return fmt.Errorf("choice alternative misc is nil")
		}
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.Misc), 1, true); err != nil {
			return fmt.Errorf("encoding misc: %w", err)
		}
	default:
		return fmt.Errorf("unknown Cause choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes Cause from APER format.
func (v *Cause) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *Cause) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = Cause{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case CauseChoiceRadioNetwork:
		val_radionetwork, err := per.DecodeEnumeratedAligned(bb, 3, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "RadioNetwork")
		}
		tmp_radionetwork := CauseRadioNetwork(val_radionetwork)
		v.RadioNetwork = &tmp_radionetwork
	case CauseChoiceProtocol:
		val_protocol, err := per.DecodeEnumeratedAligned(bb, 7, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Protocol")
		}
		tmp_protocol := CauseProtocol(val_protocol)
		v.Protocol = &tmp_protocol
	case CauseChoiceMisc:
		val_misc, err := per.DecodeEnumeratedAligned(bb, 1, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Misc")
		}
		tmp_misc := CauseMisc(val_misc)
		v.Misc = &tmp_misc
	}
	return nil
}

// MarshalAPER encodes CriticalityDiagnostics to APER format.
func (v *CriticalityDiagnostics) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *CriticalityDiagnostics) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.ProcedureCode != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.TriggeringMessage != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ProcedureCriticality != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.LppatransactionID != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEsCriticalityDiagnostics != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.ProcedureCode != nil {
		if err := per.EncodeIntegerAligned(bb, int64(*v.ProcedureCode), int64Ptr(0), int64Ptr(255), false); err != nil {
			return fmt.Errorf("encoding procedureCode: %w", err)
		}
	}
	if v.TriggeringMessage != nil {
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.TriggeringMessage), 3, false); err != nil {
			return fmt.Errorf("encoding triggeringMessage: %w", err)
		}
	}
	if v.ProcedureCriticality != nil {
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.ProcedureCriticality), 3, false); err != nil {
			return fmt.Errorf("encoding procedureCriticality: %w", err)
		}
	}
	if v.LppatransactionID != nil {
		if err := per.EncodeIntegerAligned(bb, int64(*v.LppatransactionID), int64Ptr(0), int64Ptr(32767), false); err != nil {
			return fmt.Errorf("encoding lppatransactionID: %w", err)
		}
	}
	if v.IEsCriticalityDiagnostics != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEsCriticalityDiagnostics)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_iescriticalitydiagnostics, fragmentLength_iescriticalitydiagnostics int64) error {
			for _, elem := range v.IEsCriticalityDiagnostics[fragmentOffset_iescriticalitydiagnostics : fragmentOffset_iescriticalitydiagnostics+fragmentLength_iescriticalitydiagnostics] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iEsCriticalityDiagnostics element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iEsCriticalityDiagnostics: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes CriticalityDiagnostics from APER format.
func (v *CriticalityDiagnostics) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnostics")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnostics")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *CriticalityDiagnostics) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CriticalityDiagnostics{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_procedurecode, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_triggeringmessage, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_procedurecriticality, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_lppatransactionid, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_iescriticalitydiagnostics, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_procedurecode {
		val_procedurecode, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ProcedureCode")
		}
		tmp_procedurecode := ProcedureCode(val_procedurecode)
		v.ProcedureCode = &tmp_procedurecode
	}
	if opt_triggeringmessage {
		val_triggeringmessage, err := per.DecodeEnumeratedAligned(bb, 3, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "TriggeringMessage")
		}
		tmp_triggeringmessage := TriggeringMessage(val_triggeringmessage)
		v.TriggeringMessage = &tmp_triggeringmessage
	}
	if opt_procedurecriticality {
		val_procedurecriticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ProcedureCriticality")
		}
		tmp_procedurecriticality := Criticality(val_procedurecriticality)
		v.ProcedureCriticality = &tmp_procedurecriticality
	}
	if opt_lppatransactionid {
		val_lppatransactionid, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(32767), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "LppatransactionID")
		}
		tmp_lppatransactionid := LPPATransactionID(val_lppatransactionid)
		v.LppatransactionID = &tmp_lppatransactionid
	}
	if opt_iescriticalitydiagnostics {
		tmp_iescriticalitydiagnostics := make(CriticalityDiagnosticsIEList, 0)
		_, errCollection_iescriticalitydiagnostics := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_iescriticalitydiagnostics, fragmentLength_iescriticalitydiagnostics int64) error {
			for i := int64(0); i < fragmentLength_iescriticalitydiagnostics; i++ {
				var elem CriticalityDiagnosticsIEListElem
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEsCriticalityDiagnostics[%d]", fragmentOffset_iescriticalitydiagnostics+i))
				}
				tmp_iescriticalitydiagnostics = append(tmp_iescriticalitydiagnostics, elem)
			}
			return nil
		})
		if errCollection_iescriticalitydiagnostics != nil {
			return runtime.WrapDecodePath(errCollection_iescriticalitydiagnostics, "IEsCriticalityDiagnostics")
		}
		v.IEsCriticalityDiagnostics = tmp_iescriticalitydiagnostics
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERCriticalityDiagnosticsIEListListValue struct{ Value CriticalityDiagnosticsIEList }

// CriticalityDiagnosticsIEListComplete carries a complete CriticalityDiagnosticsIEList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CriticalityDiagnosticsIEListComplete struct {
	Value       CriticalityDiagnosticsIEList
	PERPadding_ per.CompletePadding
}

func (v *CriticalityDiagnosticsIEListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERCriticalityDiagnosticsIEListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *CriticalityDiagnosticsIEListComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERCriticalityDiagnosticsIEListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEList")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEList")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERCriticalityDiagnosticsIEList encodes a CriticalityDiagnosticsIEList list to APER.
func MarshalAPERCriticalityDiagnosticsIEList(list CriticalityDiagnosticsIEListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERCriticalityDiagnosticsIEListTo appends a CriticalityDiagnosticsIEList list to bb.
func MarshalAPERCriticalityDiagnosticsIEListTo(list CriticalityDiagnosticsIEList, bb *per.BitBuffer) error {
	v := asn1cAPERCriticalityDiagnosticsIEListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERCriticalityDiagnosticsIEList decodes a CriticalityDiagnosticsIEList list from APER.
func UnmarshalAPERCriticalityDiagnosticsIEList(data []byte) (CriticalityDiagnosticsIEListComplete, error) {
	var value CriticalityDiagnosticsIEListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCriticalityDiagnosticsIEListFrom decodes a CriticalityDiagnosticsIEList list from bb.
func UnmarshalAPERCriticalityDiagnosticsIEListFrom(bb *per.BitBuffer) (CriticalityDiagnosticsIEList, error) {
	var v asn1cAPERCriticalityDiagnosticsIEListListValue
	if err := unmarshalAPERCriticalityDiagnosticsIEListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERCriticalityDiagnosticsIEListInto(v *asn1cAPERCriticalityDiagnosticsIEListListValue, bb *per.BitBuffer) error {
	v.Value = make(CriticalityDiagnosticsIEList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem CriticalityDiagnosticsIEListElem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ECIDMeasurementResult to APER format.
func (v *ECIDMeasurementResult) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ECIDMeasurementResult) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.EUTRANAccessPointPosition != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasuredResults != nil); err != nil {
		return err
	}
	if err := v.ServingCellID.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding servingCell-ID: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.ServingCellTAC), 2, 2, true); err != nil {
		return fmt.Errorf("encoding servingCellTAC: %w", err)
	}
	if v.EUTRANAccessPointPosition != nil {
		if err := v.EUTRANAccessPointPosition.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding e-UTRANAccessPointPosition: %w", err)
		}
	}
	if v.MeasuredResults != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasuredResults)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_measuredresults, fragmentLength_measuredresults int64) error {
			for _, elem := range v.MeasuredResults[fragmentOffset_measuredresults : fragmentOffset_measuredresults+fragmentLength_measuredresults] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding measuredResults element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measuredResults: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ECIDMeasurementResult from APER format.
func (v *ECIDMeasurementResult) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementResult")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementResult")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ECIDMeasurementResult) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ECIDMeasurementResult{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_eutranaccesspointposition, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measuredresults, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.ServingCellID.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ServingCellID")
	}
	val_servingcelltac, err := per.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ServingCellTAC")
	}
	v.ServingCellTAC = TAC(val_servingcelltac)
	if opt_eutranaccesspointposition {
		var dec_eutranaccesspointposition EUTRANAccessPointPosition
		if err := dec_eutranaccesspointposition.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "EUTRANAccessPointPosition")
		}
		v.EUTRANAccessPointPosition = &dec_eutranaccesspointposition
	}
	if opt_measuredresults {
		tmp_measuredresults := make(MeasuredResults, 0)
		_, errCollection_measuredresults := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_measuredresults, fragmentLength_measuredresults int64) error {
			for i := int64(0); i < fragmentLength_measuredresults; i++ {
				var elem MeasuredResultsValue
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasuredResults[%d]", fragmentOffset_measuredresults+i))
				}
				tmp_measuredresults = append(tmp_measuredresults, elem)
			}
			return nil
		})
		if errCollection_measuredresults != nil {
			return runtime.WrapDecodePath(errCollection_measuredresults, "MeasuredResults")
		}
		v.MeasuredResults = tmp_measuredresults
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes ECGI to APER format.
func (v *ECGI) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ECGI) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := per.EncodeBitStringAligned(bb, v.EUTRANcellIdentifier.Bytes, v.EUTRANcellIdentifier.BitLength, 28, 28, true); err != nil {
		return fmt.Errorf("encoding eUTRANcellIdentifier: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ECGI from APER format.
func (v *ECGI) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECGI")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ECGI")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ECGI) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ECGI{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_plmnidentity, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = PLMNIdentity(val_plmnidentity)
	bsBytes_eutrancellidentifier, bsBitLen_eutrancellidentifier, err := per.DecodeBitStringAligned(bb, 28, 28, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EUTRANcellIdentifier")
	}
	v.EUTRANcellIdentifier = runtime.BitString{Bytes: bsBytes_eutrancellidentifier, BitLength: bsBitLen_eutrancellidentifier}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes EUTRANAccessPointPosition to APER format.
func (v *EUTRANAccessPointPosition) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *EUTRANAccessPointPosition) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.LatitudeSign), 2, false); err != nil {
		return fmt.Errorf("encoding latitudeSign: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.Latitude), int64Ptr(0), int64Ptr(8388607), false); err != nil {
		return fmt.Errorf("encoding latitude: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.Longitude), int64Ptr(-8388608), int64Ptr(8388607), false); err != nil {
		return fmt.Errorf("encoding longitude: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.DirectionOfAltitude), 2, false); err != nil {
		return fmt.Errorf("encoding directionOfAltitude: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.Altitude), int64Ptr(0), int64Ptr(32767), false); err != nil {
		return fmt.Errorf("encoding altitude: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.UncertaintySemiMajor), int64Ptr(0), int64Ptr(127), false); err != nil {
		return fmt.Errorf("encoding uncertaintySemi-major: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.UncertaintySemiMinor), int64Ptr(0), int64Ptr(127), false); err != nil {
		return fmt.Errorf("encoding uncertaintySemi-minor: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.OrientationOfMajorAxis), int64Ptr(0), int64Ptr(179), false); err != nil {
		return fmt.Errorf("encoding orientationOfMajorAxis: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.UncertaintyAltitude), int64Ptr(0), int64Ptr(127), false); err != nil {
		return fmt.Errorf("encoding uncertaintyAltitude: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.Confidence), int64Ptr(0), int64Ptr(100), false); err != nil {
		return fmt.Errorf("encoding confidence: %w", err)
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes EUTRANAccessPointPosition from APER format.
func (v *EUTRANAccessPointPosition) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANAccessPointPosition")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "EUTRANAccessPointPosition")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *EUTRANAccessPointPosition) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EUTRANAccessPointPosition{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_latitudesign, err := per.DecodeEnumeratedAligned(bb, 2, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LatitudeSign")
	}
	v.LatitudeSign = val_latitudesign
	val_latitude, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(8388607), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Latitude")
	}
	v.Latitude = val_latitude
	val_longitude, err := per.DecodeIntegerAligned(bb, int64Ptr(-8388608), int64Ptr(8388607), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Longitude")
	}
	v.Longitude = val_longitude
	val_directionofaltitude, err := per.DecodeEnumeratedAligned(bb, 2, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "DirectionOfAltitude")
	}
	v.DirectionOfAltitude = val_directionofaltitude
	val_altitude, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(32767), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Altitude")
	}
	v.Altitude = val_altitude
	val_uncertaintysemimajor, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(127), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UncertaintySemiMajor")
	}
	v.UncertaintySemiMajor = val_uncertaintysemimajor
	val_uncertaintysemiminor, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(127), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UncertaintySemiMinor")
	}
	v.UncertaintySemiMinor = val_uncertaintysemiminor
	val_orientationofmajoraxis, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(179), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "OrientationOfMajorAxis")
	}
	v.OrientationOfMajorAxis = val_orientationofmajoraxis
	val_uncertaintyaltitude, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(127), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UncertaintyAltitude")
	}
	v.UncertaintyAltitude = val_uncertaintyaltitude
	val_confidence, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(100), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Confidence")
	}
	v.Confidence = val_confidence
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERInterRATMeasurementQuantitiesListValue struct{ Value InterRATMeasurementQuantities }

// InterRATMeasurementQuantitiesComplete carries a complete InterRATMeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type InterRATMeasurementQuantitiesComplete struct {
	Value       InterRATMeasurementQuantities
	PERPadding_ per.CompletePadding
}

func (v *InterRATMeasurementQuantitiesComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERInterRATMeasurementQuantitiesTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *InterRATMeasurementQuantitiesComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERInterRATMeasurementQuantitiesFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantities")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantities")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERInterRATMeasurementQuantities encodes a InterRATMeasurementQuantities list to APER.
func MarshalAPERInterRATMeasurementQuantities(list InterRATMeasurementQuantitiesComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERInterRATMeasurementQuantitiesTo appends a InterRATMeasurementQuantities list to bb.
func MarshalAPERInterRATMeasurementQuantitiesTo(list InterRATMeasurementQuantities, bb *per.BitBuffer) error {
	v := asn1cAPERInterRATMeasurementQuantitiesListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERInterRATMeasurementQuantities decodes a InterRATMeasurementQuantities list from APER.
func UnmarshalAPERInterRATMeasurementQuantities(data []byte) (InterRATMeasurementQuantitiesComplete, error) {
	var value InterRATMeasurementQuantitiesComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERInterRATMeasurementQuantitiesFrom decodes a InterRATMeasurementQuantities list from bb.
func UnmarshalAPERInterRATMeasurementQuantitiesFrom(bb *per.BitBuffer) (InterRATMeasurementQuantities, error) {
	var v asn1cAPERInterRATMeasurementQuantitiesListValue
	if err := unmarshalAPERInterRATMeasurementQuantitiesInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERInterRATMeasurementQuantitiesInto(v *asn1cAPERInterRATMeasurementQuantitiesListValue, bb *per.BitBuffer) error {
	v.Value = make(InterRATMeasurementQuantities, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ProtocolIESingleContainer
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes InterRATMeasurementQuantitiesItem to APER format.
func (v *InterRATMeasurementQuantitiesItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *InterRATMeasurementQuantitiesItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.InterRATMeasurementQuantitiesValue), 2, true); err != nil {
		return fmt.Errorf("encoding interRATMeasurementQuantitiesValue: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes InterRATMeasurementQuantitiesItem from APER format.
func (v *InterRATMeasurementQuantitiesItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantitiesItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantitiesItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *InterRATMeasurementQuantitiesItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = InterRATMeasurementQuantitiesItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_interratmeasurementquantitiesvalue, err := per.DecodeEnumeratedAligned(bb, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantitiesValue")
	}
	v.InterRATMeasurementQuantitiesValue = InterRATMeasurementQuantitiesValue(val_interratmeasurementquantitiesvalue)
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERInterRATMeasurementResultListValue struct{ Value InterRATMeasurementResult }

// InterRATMeasurementResultComplete carries a complete InterRATMeasurementResult encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type InterRATMeasurementResultComplete struct {
	Value       InterRATMeasurementResult
	PERPadding_ per.CompletePadding
}

func (v *InterRATMeasurementResultComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERInterRATMeasurementResultTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *InterRATMeasurementResultComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERInterRATMeasurementResultFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementResult")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementResult")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERInterRATMeasurementResult encodes a InterRATMeasurementResult list to APER.
func MarshalAPERInterRATMeasurementResult(list InterRATMeasurementResultComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERInterRATMeasurementResultTo appends a InterRATMeasurementResult list to bb.
func MarshalAPERInterRATMeasurementResultTo(list InterRATMeasurementResult, bb *per.BitBuffer) error {
	v := asn1cAPERInterRATMeasurementResultListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERInterRATMeasurementResult decodes a InterRATMeasurementResult list from APER.
func UnmarshalAPERInterRATMeasurementResult(data []byte) (InterRATMeasurementResultComplete, error) {
	var value InterRATMeasurementResultComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERInterRATMeasurementResultFrom decodes a InterRATMeasurementResult list from bb.
func UnmarshalAPERInterRATMeasurementResultFrom(bb *per.BitBuffer) (InterRATMeasurementResult, error) {
	var v asn1cAPERInterRATMeasurementResultListValue
	if err := unmarshalAPERInterRATMeasurementResultInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERInterRATMeasurementResultInto(v *asn1cAPERInterRATMeasurementResultListValue, bb *per.BitBuffer) error {
	v.Value = make(InterRATMeasurementResult, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem InterRATMeasuredResultsValue
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes InterRATMeasuredResultsValue to APER format.
func (v *InterRATMeasuredResultsValue) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *InterRATMeasuredResultsValue) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("InterRATMeasuredResultsValue: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("InterRATMeasuredResultsValue: extension index %d must be non-negative", v.UnknownExtension.Index)
		}
		if v.UnknownExtension.Index < 1 {
			return fmt.Errorf("InterRATMeasuredResultsValue: extension index %d is known to this schema", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 2
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-2-1)); err != nil {
			return err
		}
		inner := per.NewBitBuffer()
		switch v.Choice {
		case InterRATMeasuredResultsValueChoiceResultNR:
			if err := per.EncodeCollection(inner, int64(len(v.ResultNR)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_resultnr, fragmentLength_resultnr int64) error {
				for _, elem := range v.ResultNR[fragmentOffset_resultnr : fragmentOffset_resultnr+fragmentLength_resultnr] {
					if err := elem.MarshalAPERTo(inner); err != nil {
						return fmt.Errorf("encoding resultNR element: %w", err)
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("encoding resultNR: %w", err)
			}
		default:
			return fmt.Errorf("unknown InterRATMeasuredResultsValue extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(v.PEROpenTypePadding_)
		if err != nil {
			return err
		}
		if err := per.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case InterRATMeasuredResultsValueChoiceResultGERAN:
		if err := per.EncodeCollection(bb, int64(len(v.ResultGERAN)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultgeran, fragmentLength_resultgeran int64) error {
			for _, elem := range v.ResultGERAN[fragmentOffset_resultgeran : fragmentOffset_resultgeran+fragmentLength_resultgeran] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding resultGERAN element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding resultGERAN: %w", err)
		}
	case InterRATMeasuredResultsValueChoiceResultUTRAN:
		if err := per.EncodeCollection(bb, int64(len(v.ResultUTRAN)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultutran, fragmentLength_resultutran int64) error {
			for _, elem := range v.ResultUTRAN[fragmentOffset_resultutran : fragmentOffset_resultutran+fragmentLength_resultutran] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding resultUTRAN element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding resultUTRAN: %w", err)
		}
	default:
		return fmt.Errorf("unknown InterRATMeasuredResultsValue choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes InterRATMeasuredResultsValue from APER format.
func (v *InterRATMeasuredResultsValue) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasuredResultsValue")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasuredResultsValue")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *InterRATMeasuredResultsValue) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = InterRATMeasuredResultsValue{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if extIdx >= 1 {
			v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
			return nil
		}
		inner := per.NewBitBufferFromBytes(openData)
		v.Choice = int(extIdx) + 2 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case InterRATMeasuredResultsValueChoiceResultNR:
			extensionPath = "ResultNR"
			tmp_resultnr := make(ResultNR, 0)
			_, errCollection_resultnr := per.DecodeCollection(inner, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_resultnr, fragmentLength_resultnr int64) error {
				for i := int64(0); i < fragmentLength_resultnr; i++ {
					var elem ResultNRItem
					if err := elem.UnmarshalAPERFrom(inner); err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("ResultNR[%d]", fragmentOffset_resultnr+i))
					}
					tmp_resultnr = append(tmp_resultnr, elem)
				}
				return nil
			})
			if errCollection_resultnr != nil {
				return runtime.WrapDecodePath(errCollection_resultnr, "ResultNR")
			}
			v.ResultNR = tmp_resultnr
		}
		padding, err := per.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.PEROpenTypePadding_ = padding
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case InterRATMeasuredResultsValueChoiceResultGERAN:
		tmp_resultgeran := make(ResultGERAN, 0)
		_, errCollection_resultgeran := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultgeran, fragmentLength_resultgeran int64) error {
			for i := int64(0); i < fragmentLength_resultgeran; i++ {
				var elem ResultGERANItem
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ResultGERAN[%d]", fragmentOffset_resultgeran+i))
				}
				tmp_resultgeran = append(tmp_resultgeran, elem)
			}
			return nil
		})
		if errCollection_resultgeran != nil {
			return runtime.WrapDecodePath(errCollection_resultgeran, "ResultGERAN")
		}
		v.ResultGERAN = tmp_resultgeran
	case InterRATMeasuredResultsValueChoiceResultUTRAN:
		tmp_resultutran := make(ResultUTRAN, 0)
		_, errCollection_resultutran := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultutran, fragmentLength_resultutran int64) error {
			for i := int64(0); i < fragmentLength_resultutran; i++ {
				var elem ResultUTRANItem
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ResultUTRAN[%d]", fragmentOffset_resultutran+i))
				}
				tmp_resultutran = append(tmp_resultutran, elem)
			}
			return nil
		})
		if errCollection_resultutran != nil {
			return runtime.WrapDecodePath(errCollection_resultutran, "ResultUTRAN")
		}
		v.ResultUTRAN = tmp_resultutran
	}
	return nil
}

type asn1cAPERMeasurementQuantitiesListValue struct{ Value MeasurementQuantities }

// MeasurementQuantitiesComplete carries a complete MeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MeasurementQuantitiesComplete struct {
	Value       MeasurementQuantities
	PERPadding_ per.CompletePadding
}

func (v *MeasurementQuantitiesComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERMeasurementQuantitiesTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *MeasurementQuantitiesComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERMeasurementQuantitiesFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantities")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantities")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERMeasurementQuantities encodes a MeasurementQuantities list to APER.
func MarshalAPERMeasurementQuantities(list MeasurementQuantitiesComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERMeasurementQuantitiesTo appends a MeasurementQuantities list to bb.
func MarshalAPERMeasurementQuantitiesTo(list MeasurementQuantities, bb *per.BitBuffer) error {
	v := asn1cAPERMeasurementQuantitiesListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERMeasurementQuantities decodes a MeasurementQuantities list from APER.
func UnmarshalAPERMeasurementQuantities(data []byte) (MeasurementQuantitiesComplete, error) {
	var value MeasurementQuantitiesComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERMeasurementQuantitiesFrom decodes a MeasurementQuantities list from bb.
func UnmarshalAPERMeasurementQuantitiesFrom(bb *per.BitBuffer) (MeasurementQuantities, error) {
	var v asn1cAPERMeasurementQuantitiesListValue
	if err := unmarshalAPERMeasurementQuantitiesInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERMeasurementQuantitiesInto(v *asn1cAPERMeasurementQuantitiesListValue, bb *per.BitBuffer) error {
	v.Value = make(MeasurementQuantities, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ProtocolIESingleContainer
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes MeasurementQuantitiesItem to APER format.
func (v *MeasurementQuantitiesItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *MeasurementQuantitiesItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.MeasurementQuantitiesValue), 6, true); err != nil {
		return fmt.Errorf("encoding measurementQuantitiesValue: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes MeasurementQuantitiesItem from APER format.
func (v *MeasurementQuantitiesItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantitiesItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantitiesItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *MeasurementQuantitiesItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MeasurementQuantitiesItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_measurementquantitiesvalue, err := per.DecodeEnumeratedAligned(bb, 6, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantitiesValue")
	}
	v.MeasurementQuantitiesValue = MeasurementQuantitiesValue(val_measurementquantitiesvalue)
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERMeasuredResultsListValue struct{ Value MeasuredResults }

// MeasuredResultsComplete carries a complete MeasuredResults encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MeasuredResultsComplete struct {
	Value       MeasuredResults
	PERPadding_ per.CompletePadding
}

func (v *MeasuredResultsComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERMeasuredResultsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *MeasuredResultsComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERMeasuredResultsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasuredResults")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasuredResults")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERMeasuredResults encodes a MeasuredResults list to APER.
func MarshalAPERMeasuredResults(list MeasuredResultsComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERMeasuredResultsTo appends a MeasuredResults list to bb.
func MarshalAPERMeasuredResultsTo(list MeasuredResults, bb *per.BitBuffer) error {
	v := asn1cAPERMeasuredResultsListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERMeasuredResults decodes a MeasuredResults list from APER.
func UnmarshalAPERMeasuredResults(data []byte) (MeasuredResultsComplete, error) {
	var value MeasuredResultsComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERMeasuredResultsFrom decodes a MeasuredResults list from bb.
func UnmarshalAPERMeasuredResultsFrom(bb *per.BitBuffer) (MeasuredResults, error) {
	var v asn1cAPERMeasuredResultsListValue
	if err := unmarshalAPERMeasuredResultsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERMeasuredResultsInto(v *asn1cAPERMeasuredResultsListValue, bb *per.BitBuffer) error {
	v.Value = make(MeasuredResults, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem MeasuredResultsValue
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes MeasuredResultsValue to APER format.
func (v *MeasuredResultsValue) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *MeasuredResultsValue) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("MeasuredResultsValue: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("MeasuredResultsValue: extension index %d must be non-negative", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 5
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("MeasuredResultsValue: extension choice %d not supported", v.Choice)
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 4); err != nil {
		return err
	}
	switch v.Choice {
	case MeasuredResultsValueChoiceValueAngleOfArrival:
		if v.ValueAngleOfArrival == nil {
			return fmt.Errorf("choice alternative valueAngleOfArrival is nil")
		}
		if err := per.EncodeIntegerAligned(bb, int64(*v.ValueAngleOfArrival), int64Ptr(0), int64Ptr(719), false); err != nil {
			return fmt.Errorf("encoding valueAngleOfArrival: %w", err)
		}
	case MeasuredResultsValueChoiceValueTimingAdvanceType1:
		if v.ValueTimingAdvanceType1 == nil {
			return fmt.Errorf("choice alternative valueTimingAdvanceType1 is nil")
		}
		if err := per.EncodeIntegerAligned(bb, int64(*v.ValueTimingAdvanceType1), int64Ptr(0), int64Ptr(7690), false); err != nil {
			return fmt.Errorf("encoding valueTimingAdvanceType1: %w", err)
		}
	case MeasuredResultsValueChoiceValueTimingAdvanceType2:
		if v.ValueTimingAdvanceType2 == nil {
			return fmt.Errorf("choice alternative valueTimingAdvanceType2 is nil")
		}
		if err := per.EncodeIntegerAligned(bb, int64(*v.ValueTimingAdvanceType2), int64Ptr(0), int64Ptr(7690), false); err != nil {
			return fmt.Errorf("encoding valueTimingAdvanceType2: %w", err)
		}
	case MeasuredResultsValueChoiceResultRSRP:
		if err := per.EncodeCollection(bb, int64(len(v.ResultRSRP)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrp, fragmentLength_resultrsrp int64) error {
			for _, elem := range v.ResultRSRP[fragmentOffset_resultrsrp : fragmentOffset_resultrsrp+fragmentLength_resultrsrp] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding resultRSRP element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding resultRSRP: %w", err)
		}
	case MeasuredResultsValueChoiceResultRSRQ:
		if err := per.EncodeCollection(bb, int64(len(v.ResultRSRQ)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrq, fragmentLength_resultrsrq int64) error {
			for _, elem := range v.ResultRSRQ[fragmentOffset_resultrsrq : fragmentOffset_resultrsrq+fragmentLength_resultrsrq] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding resultRSRQ element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding resultRSRQ: %w", err)
		}
	default:
		return fmt.Errorf("unknown MeasuredResultsValue choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes MeasuredResultsValue from APER format.
func (v *MeasuredResultsValue) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MeasuredResultsValue")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasuredResultsValue")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *MeasuredResultsValue) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MeasuredResultsValue{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 4)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case MeasuredResultsValueChoiceValueAngleOfArrival:
		val_valueangleofarrival, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(719), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ValueAngleOfArrival")
		}
		v.ValueAngleOfArrival = &val_valueangleofarrival
	case MeasuredResultsValueChoiceValueTimingAdvanceType1:
		val_valuetimingadvancetype1, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(7690), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ValueTimingAdvanceType1")
		}
		v.ValueTimingAdvanceType1 = &val_valuetimingadvancetype1
	case MeasuredResultsValueChoiceValueTimingAdvanceType2:
		val_valuetimingadvancetype2, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(7690), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ValueTimingAdvanceType2")
		}
		v.ValueTimingAdvanceType2 = &val_valuetimingadvancetype2
	case MeasuredResultsValueChoiceResultRSRP:
		tmp_resultrsrp := make(ResultRSRP, 0)
		_, errCollection_resultrsrp := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrp, fragmentLength_resultrsrp int64) error {
			for i := int64(0); i < fragmentLength_resultrsrp; i++ {
				var elem ResultRSRPItem
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ResultRSRP[%d]", fragmentOffset_resultrsrp+i))
				}
				tmp_resultrsrp = append(tmp_resultrsrp, elem)
			}
			return nil
		})
		if errCollection_resultrsrp != nil {
			return runtime.WrapDecodePath(errCollection_resultrsrp, "ResultRSRP")
		}
		v.ResultRSRP = tmp_resultrsrp
	case MeasuredResultsValueChoiceResultRSRQ:
		tmp_resultrsrq := make(ResultRSRQ, 0)
		_, errCollection_resultrsrq := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrq, fragmentLength_resultrsrq int64) error {
			for i := int64(0); i < fragmentLength_resultrsrq; i++ {
				var elem ResultRSRQItem
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ResultRSRQ[%d]", fragmentOffset_resultrsrq+i))
				}
				tmp_resultrsrq = append(tmp_resultrsrq, elem)
			}
			return nil
		})
		if errCollection_resultrsrq != nil {
			return runtime.WrapDecodePath(errCollection_resultrsrq, "ResultRSRQ")
		}
		v.ResultRSRQ = tmp_resultrsrq
	}
	return nil
}

type asn1cAPERMBSFNsubframeConfigurationListValue struct{ Value MBSFNsubframeConfiguration }

// MBSFNsubframeConfigurationComplete carries a complete MBSFNsubframeConfiguration encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MBSFNsubframeConfigurationComplete struct {
	Value       MBSFNsubframeConfiguration
	PERPadding_ per.CompletePadding
}

func (v *MBSFNsubframeConfigurationComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERMBSFNsubframeConfigurationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *MBSFNsubframeConfigurationComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERMBSFNsubframeConfigurationFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MBSFNsubframeConfiguration")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MBSFNsubframeConfiguration")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERMBSFNsubframeConfiguration encodes a MBSFNsubframeConfiguration list to APER.
func MarshalAPERMBSFNsubframeConfiguration(list MBSFNsubframeConfigurationComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERMBSFNsubframeConfigurationTo appends a MBSFNsubframeConfiguration list to bb.
func MarshalAPERMBSFNsubframeConfigurationTo(list MBSFNsubframeConfiguration, bb *per.BitBuffer) error {
	v := asn1cAPERMBSFNsubframeConfigurationListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERMBSFNsubframeConfiguration decodes a MBSFNsubframeConfiguration list from APER.
func UnmarshalAPERMBSFNsubframeConfiguration(data []byte) (MBSFNsubframeConfigurationComplete, error) {
	var value MBSFNsubframeConfigurationComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERMBSFNsubframeConfigurationFrom decodes a MBSFNsubframeConfiguration list from bb.
func UnmarshalAPERMBSFNsubframeConfigurationFrom(bb *per.BitBuffer) (MBSFNsubframeConfiguration, error) {
	var v asn1cAPERMBSFNsubframeConfigurationListValue
	if err := unmarshalAPERMBSFNsubframeConfigurationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERMBSFNsubframeConfigurationInto(v *asn1cAPERMBSFNsubframeConfigurationListValue, bb *per.BitBuffer) error {
	v.Value = make(MBSFNsubframeConfiguration, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem MBSFNsubframeConfigurationValue
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes MBSFNsubframeConfigurationValue to APER format.
func (v *MBSFNsubframeConfigurationValue) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *MBSFNsubframeConfigurationValue) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeEnumeratedAligned(bb, int64(v.RadioframeAllocationPeriod), 6, false); err != nil {
		return fmt.Errorf("encoding radioframeAllocationPeriod: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.RadioframeAllocationOffset), int64Ptr(0), int64Ptr(7), false); err != nil {
		return fmt.Errorf("encoding radioframeAllocationOffset: %w", err)
	}
	if err := v.SubframeAllocation.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding subframeAllocation: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes MBSFNsubframeConfigurationValue from APER format.
func (v *MBSFNsubframeConfigurationValue) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MBSFNsubframeConfigurationValue")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MBSFNsubframeConfigurationValue")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *MBSFNsubframeConfigurationValue) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MBSFNsubframeConfigurationValue{}
	val_radioframeallocationperiod, err := per.DecodeEnumeratedAligned(bb, 6, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "RadioframeAllocationPeriod")
	}
	v.RadioframeAllocationPeriod = val_radioframeallocationperiod
	val_radioframeallocationoffset, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(7), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "RadioframeAllocationOffset")
	}
	v.RadioframeAllocationOffset = val_radioframeallocationoffset
	if err := v.SubframeAllocation.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SubframeAllocation")
	}
	return nil
}

// MarshalAPER encodes NRCGI to APER format.
func (v *NRCGI) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *NRCGI) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := per.EncodeBitStringAligned(bb, v.NRCellIdentity.Bytes, v.NRCellIdentity.BitLength, 36, 36, true); err != nil {
		return fmt.Errorf("encoding nRCellIdentity: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes NRCGI from APER format.
func (v *NRCGI) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NRCGI")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "NRCGI")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *NRCGI) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = NRCGI{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_plmnidentity, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = PLMNIdentity(val_plmnidentity)
	bsBytes_nrcellidentity, bsBitLen_nrcellidentity, err := per.DecodeBitStringAligned(bb, 36, 36, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NRCellIdentity")
	}
	v.NRCellIdentity = runtime.BitString{Bytes: bsBytes_nrcellidentity, BitLength: bsBitLen_nrcellidentity}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes NPRSConfiguration to APER format.
func (v *NPRSConfiguration) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *NPRSConfiguration) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NPRSSubframePartA != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NPRSSubframePartB != nil); err != nil {
		return err
	}
	if v.NPRSSubframePartA != nil {
		if err := v.NPRSSubframePartA.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding nPRSSubframePartA: %w", err)
		}
	}
	if v.NPRSSubframePartB != nil {
		if err := v.NPRSSubframePartB.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding nPRSSubframePartB: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes NPRSConfiguration from APER format.
func (v *NPRSConfiguration) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NPRSConfiguration")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "NPRSConfiguration")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *NPRSConfiguration) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = NPRSConfiguration{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nprssubframeparta, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_nprssubframepartb, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_nprssubframeparta {
		var dec_nprssubframeparta NPRSSubframePartA
		if err := dec_nprssubframeparta.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NPRSSubframePartA")
		}
		v.NPRSSubframePartA = &dec_nprssubframeparta
	}
	if opt_nprssubframepartb {
		var dec_nprssubframepartb NPRSSubframePartB
		if err := dec_nprssubframepartb.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NPRSSubframePartB")
		}
		v.NPRSSubframePartB = &dec_nprssubframepartb
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes NPRSMutingConfiguration to APER format.
func (v *NPRSMutingConfiguration) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *NPRSMutingConfiguration) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("NPRSMutingConfiguration: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("NPRSMutingConfiguration: extension index %d must be non-negative", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 4
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("NPRSMutingConfiguration: extension choice %d not supported", v.Choice)
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case NPRSMutingConfigurationChoiceTwo:
		if v.Two == nil {
			return fmt.Errorf("choice alternative two is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.Two.Bytes, v.Two.BitLength, 2, 2, true); err != nil {
			return fmt.Errorf("encoding two: %w", err)
		}
	case NPRSMutingConfigurationChoiceFour:
		if v.Four == nil {
			return fmt.Errorf("choice alternative four is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.Four.Bytes, v.Four.BitLength, 4, 4, true); err != nil {
			return fmt.Errorf("encoding four: %w", err)
		}
	case NPRSMutingConfigurationChoiceEight:
		if v.Eight == nil {
			return fmt.Errorf("choice alternative eight is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.Eight.Bytes, v.Eight.BitLength, 8, 8, true); err != nil {
			return fmt.Errorf("encoding eight: %w", err)
		}
	case NPRSMutingConfigurationChoiceSixteen:
		if v.Sixteen == nil {
			return fmt.Errorf("choice alternative sixteen is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.Sixteen.Bytes, v.Sixteen.BitLength, 16, 16, true); err != nil {
			return fmt.Errorf("encoding sixteen: %w", err)
		}
	default:
		return fmt.Errorf("unknown NPRSMutingConfiguration choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes NPRSMutingConfiguration from APER format.
func (v *NPRSMutingConfiguration) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NPRSMutingConfiguration")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "NPRSMutingConfiguration")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *NPRSMutingConfiguration) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = NPRSMutingConfiguration{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 3)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case NPRSMutingConfigurationChoiceTwo:
		bsBytes_two, bsBitLen_two, err := per.DecodeBitStringAligned(bb, 2, 2, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Two")
		}
		tmp_two := runtime.BitString{Bytes: bsBytes_two, BitLength: bsBitLen_two}
		v.Two = &tmp_two
	case NPRSMutingConfigurationChoiceFour:
		bsBytes_four, bsBitLen_four, err := per.DecodeBitStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Four")
		}
		tmp_four := runtime.BitString{Bytes: bsBytes_four, BitLength: bsBitLen_four}
		v.Four = &tmp_four
	case NPRSMutingConfigurationChoiceEight:
		bsBytes_eight, bsBitLen_eight, err := per.DecodeBitStringAligned(bb, 8, 8, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Eight")
		}
		tmp_eight := runtime.BitString{Bytes: bsBytes_eight, BitLength: bsBitLen_eight}
		v.Eight = &tmp_eight
	case NPRSMutingConfigurationChoiceSixteen:
		bsBytes_sixteen, bsBitLen_sixteen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Sixteen")
		}
		tmp_sixteen := runtime.BitString{Bytes: bsBytes_sixteen, BitLength: bsBitLen_sixteen}
		v.Sixteen = &tmp_sixteen
	}
	return nil
}

// MarshalAPER encodes NPRSSubframePartA to APER format.
func (v *NPRSSubframePartA) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *NPRSSubframePartA) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NPRSMutingConfiguration != nil); err != nil {
		return err
	}
	if err := v.BitmapsforNPRS.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding bitmapsforNPRS: %w", err)
	}
	if v.NPRSMutingConfiguration != nil {
		if err := v.NPRSMutingConfiguration.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding nPRSMutingConfiguration: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes NPRSSubframePartA from APER format.
func (v *NPRSSubframePartA) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NPRSSubframePartA")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "NPRSSubframePartA")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *NPRSSubframePartA) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = NPRSSubframePartA{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nprsmutingconfiguration, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.BitmapsforNPRS.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BitmapsforNPRS")
	}
	if opt_nprsmutingconfiguration {
		var dec_nprsmutingconfiguration NPRSMutingConfiguration
		if err := dec_nprsmutingconfiguration.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NPRSMutingConfiguration")
		}
		v.NPRSMutingConfiguration = &dec_nprsmutingconfiguration
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes NPRSSubframePartB to APER format.
func (v *NPRSSubframePartB) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *NPRSSubframePartB) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.SIB1NBSubframeTDD != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NPRSMutingConfiguration != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.NumberofNPRSOneOccasion), 8, true); err != nil {
		return fmt.Errorf("encoding numberofNPRSOneOccasion: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.PeriodicityofNPRS), 4, true); err != nil {
		return fmt.Errorf("encoding periodicityofNPRS: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Startingsubframeoffset), 8, true); err != nil {
		return fmt.Errorf("encoding startingsubframeoffset: %w", err)
	}
	if v.NPRSMutingConfiguration != nil {
		if err := v.NPRSMutingConfiguration.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding nPRSMutingConfiguration: %w", err)
		}
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.SIB1NBSubframeTDD != nil {
			extHighest = 0
		}
		if v.ExtCount_ > extHighest {
			extHighest = v.ExtCount_
		}
		for i, present := range v.ExtPresent_ {
			if present && int64(i) > extHighest {
				extHighest = int64(i)
			}
		}
		for i, data := range v.ExtData_ {
			if data != nil && int64(i) > extHighest {
				extHighest = int64(i)
			}
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, extHighest); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SIB1NBSubframeTDD != nil
			if err := per.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		for i := int64(1); i <= extHighest; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SIB1NBSubframeTDD != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SIB1NBSubframeTDD != nil); err != nil {
				return err
			}
			if v.SIB1NBSubframeTDD != nil {
				if err := per.EncodeEnumeratedAligned(extBuf, int64(*v.SIB1NBSubframeTDD), 3, true); err != nil {
					return fmt.Errorf("encoding sIB1-NB-Subframe-TDD: %w", err)
				}
			}
			var extPadding per.CompletePadding
			if len(v.PERExtPadding_) > 0 {
				extPadding = v.PERExtPadding_[0]
			}
			extBytes, err := extBuf.CompleteBytesWithPadding(extPadding)
			if err != nil {
				return err
			}
			if err := per.EncodeOpenTypeAligned(bb, extBytes); err != nil {
				return err
			}
		}
		for i := int64(1); i <= extHighest; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes NPRSSubframePartB from APER format.
func (v *NPRSSubframePartB) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NPRSSubframePartB")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "NPRSSubframePartB")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *NPRSSubframePartB) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = NPRSSubframePartB{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nprsmutingconfiguration, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_numberofnprsoneoccasion, err := per.DecodeEnumeratedAligned(bb, 8, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberofNPRSOneOccasion")
	}
	v.NumberofNPRSOneOccasion = val_numberofnprsoneoccasion
	val_periodicityofnprs, err := per.DecodeEnumeratedAligned(bb, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PeriodicityofNPRS")
	}
	v.PeriodicityofNPRS = val_periodicityofnprs
	val_startingsubframeoffset, err := per.DecodeEnumeratedAligned(bb, 8, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "Startingsubframeoffset")
	}
	v.Startingsubframeoffset = val_startingsubframeoffset
	if opt_nprsmutingconfiguration {
		var dec_nprsmutingconfiguration NPRSMutingConfiguration
		if err := dec_nprsmutingconfiguration.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NPRSMutingConfiguration")
		}
		v.NPRSMutingConfiguration = &dec_nprsmutingconfiguration
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtPresent_ = extPresent
		v.ExtData_ = make([][]byte, extCount+1)
		v.PERExtPadding_ = make([]per.CompletePadding, extCount+1)
		if int64(0) <= extCount && extPresent[0] {
			extData, err := per.DecodeOpenTypeAligned(bb)
			if err != nil {
				return runtime.WrapDecodePath(err, "ExtData_[0]")
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_sib1nbsubframetdd, err := per.DecodeBoolean(extBB)
			if err != nil {
				return runtime.WrapDecodePath(err, "SIB1NBSubframeTDD")
			}
			if ext_opt_sib1nbsubframetdd {
				val_sib1nbsubframetdd, err := per.DecodeEnumeratedAligned(extBB, 3, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "SIB1NBSubframeTDD")
				}
				v.SIB1NBSubframeTDD = &val_sib1nbsubframetdd
			}
			padding, err := per.CaptureOpenTypePadding(extBB)
			if err != nil {
				return runtime.WrapDecodePath(err, "ExtData_[0]")
			}
			v.PERExtPadding_[0] = padding
		}
		for i := int64(1); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPEROTDOACellsListValue struct{ Value OTDOACells }

// OTDOACellsComplete carries a complete OTDOACells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOACellsComplete struct {
	Value       OTDOACells
	PERPadding_ per.CompletePadding
}

func (v *OTDOACellsComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPEROTDOACellsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *OTDOACellsComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPEROTDOACellsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACells")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACells")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPEROTDOACells encodes a OTDOACells list to APER.
func MarshalAPEROTDOACells(list OTDOACellsComplete) ([]byte, error) { return list.MarshalAPER() }

// MarshalAPEROTDOACellsTo appends a OTDOACells list to bb.
func MarshalAPEROTDOACellsTo(list OTDOACells, bb *per.BitBuffer) error {
	v := asn1cAPEROTDOACellsListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPEROTDOACells decodes a OTDOACells list from APER.
func UnmarshalAPEROTDOACells(data []byte) (OTDOACellsComplete, error) {
	var value OTDOACellsComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPEROTDOACellsFrom decodes a OTDOACells list from bb.
func UnmarshalAPEROTDOACellsFrom(bb *per.BitBuffer) (OTDOACells, error) {
	var v asn1cAPEROTDOACellsListValue
	if err := unmarshalAPEROTDOACellsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPEROTDOACellsInto(v *asn1cAPEROTDOACellsListValue, bb *per.BitBuffer) error {
	v.Value = make(OTDOACells, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem OTDOACellsElem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

type asn1cAPEROTDOACellInformationListValue struct{ Value OTDOACellInformation }

// OTDOACellInformationComplete carries a complete OTDOACellInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOACellInformationComplete struct {
	Value       OTDOACellInformation
	PERPadding_ per.CompletePadding
}

func (v *OTDOACellInformationComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPEROTDOACellInformationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *OTDOACellInformationComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPEROTDOACellInformationFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellInformation")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellInformation")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPEROTDOACellInformation encodes a OTDOACellInformation list to APER.
func MarshalAPEROTDOACellInformation(list OTDOACellInformationComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPEROTDOACellInformationTo appends a OTDOACellInformation list to bb.
func MarshalAPEROTDOACellInformationTo(list OTDOACellInformation, bb *per.BitBuffer) error {
	v := asn1cAPEROTDOACellInformationListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPEROTDOACellInformation decodes a OTDOACellInformation list from APER.
func UnmarshalAPEROTDOACellInformation(data []byte) (OTDOACellInformationComplete, error) {
	var value OTDOACellInformationComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPEROTDOACellInformationFrom decodes a OTDOACellInformation list from bb.
func UnmarshalAPEROTDOACellInformationFrom(bb *per.BitBuffer) (OTDOACellInformation, error) {
	var v asn1cAPEROTDOACellInformationListValue
	if err := unmarshalAPEROTDOACellInformationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPEROTDOACellInformationInto(v *asn1cAPEROTDOACellInformationListValue, bb *per.BitBuffer) error {
	v.Value = make(OTDOACellInformation, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem OTDOACellInformationItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes OTDOACellInformationItem to APER format.
func (v *OTDOACellInformationItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *OTDOACellInformationItem) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("OTDOACellInformationItem: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("OTDOACellInformationItem: extension index %d must be non-negative", v.UnknownExtension.Index)
		}
		if v.UnknownExtension.Index < 18 {
			return fmt.Errorf("OTDOACellInformationItem: extension index %d is known to this schema", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 11
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-11-1)); err != nil {
			return err
		}
		inner := per.NewBitBuffer()
		switch v.Choice {
		case OTDOACellInformationItemChoicePRSMutingConfiguration:
			if v.PRSMutingConfiguration == nil {
				return fmt.Errorf("choice alternative pRSMutingConfiguration is nil")
			}
			if err := v.PRSMutingConfiguration.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding pRSMutingConfiguration: %w", err)
			}
		case OTDOACellInformationItemChoicePrsid:
			if err := per.EncodeIntegerBigBoundsAligned(inner, v.Prsid, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true); err != nil {
				return fmt.Errorf("encoding prsid: %w", err)
			}
		case OTDOACellInformationItemChoiceTpid:
			if err := per.EncodeIntegerBigBoundsAligned(inner, v.Tpid, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true); err != nil {
				return fmt.Errorf("encoding tpid: %w", err)
			}
		case OTDOACellInformationItemChoiceTpType:
			if v.TpType == nil {
				return fmt.Errorf("choice alternative tpType is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.TpType), 1, true); err != nil {
				return fmt.Errorf("encoding tpType: %w", err)
			}
		case OTDOACellInformationItemChoiceNumberOfDlFramesExtended:
			if err := per.EncodeIntegerBigBoundsAligned(inner, v.NumberOfDlFramesExtended, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("160"), true); err != nil {
				return fmt.Errorf("encoding numberOfDlFrames-Extended: %w", err)
			}
		case OTDOACellInformationItemChoiceCrsCPlength:
			if v.CrsCPlength == nil {
				return fmt.Errorf("choice alternative crsCPlength is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.CrsCPlength), 2, true); err != nil {
				return fmt.Errorf("encoding crsCPlength: %w", err)
			}
		case OTDOACellInformationItemChoiceMBSFNsubframeConfiguration:
			if err := per.EncodeCollection(inner, int64(len(v.MBSFNsubframeConfiguration)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_mbsfnsubframeconfiguration, fragmentLength_mbsfnsubframeconfiguration int64) error {
				for _, elem := range v.MBSFNsubframeConfiguration[fragmentOffset_mbsfnsubframeconfiguration : fragmentOffset_mbsfnsubframeconfiguration+fragmentLength_mbsfnsubframeconfiguration] {
					if err := elem.MarshalAPERTo(inner); err != nil {
						return fmt.Errorf("encoding mBSFNsubframeConfiguration element: %w", err)
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("encoding mBSFNsubframeConfiguration: %w", err)
			}
		case OTDOACellInformationItemChoiceNPRSConfiguration:
			if v.NPRSConfiguration == nil {
				return fmt.Errorf("choice alternative nPRSConfiguration is nil")
			}
			if err := v.NPRSConfiguration.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding nPRSConfiguration: %w", err)
			}
		case OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN:
			if v.OffsetNBChanneltoEARFCN == nil {
				return fmt.Errorf("choice alternative offsetNBChanneltoEARFCN is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.OffsetNBChanneltoEARFCN), 21, true); err != nil {
				return fmt.Errorf("encoding offsetNBChanneltoEARFCN: %w", err)
			}
		case OTDOACellInformationItemChoiceOperationModeInfo:
			if v.OperationModeInfo == nil {
				return fmt.Errorf("choice alternative operationModeInfo is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.OperationModeInfo), 3, true); err != nil {
				return fmt.Errorf("encoding operationModeInfo: %w", err)
			}
		case OTDOACellInformationItemChoiceNPRSID:
			if err := per.EncodeIntegerBigBoundsAligned(inner, v.NPRSID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true); err != nil {
				return fmt.Errorf("encoding nPRS-ID: %w", err)
			}
		case OTDOACellInformationItemChoiceDLBandwidth:
			if v.DLBandwidth == nil {
				return fmt.Errorf("choice alternative dL-Bandwidth is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.DLBandwidth), 6, true); err != nil {
				return fmt.Errorf("encoding dL-Bandwidth: %w", err)
			}
		case OTDOACellInformationItemChoicePRSOccasionGroup:
			if v.PRSOccasionGroup == nil {
				return fmt.Errorf("choice alternative pRSOccasionGroup is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.PRSOccasionGroup), 7, true); err != nil {
				return fmt.Errorf("encoding pRSOccasionGroup: %w", err)
			}
		case OTDOACellInformationItemChoicePRSFreqHoppingConfig:
			if v.PRSFreqHoppingConfig == nil {
				return fmt.Errorf("choice alternative pRSFreqHoppingConfig is nil")
			}
			if err := v.PRSFreqHoppingConfig.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding pRSFreqHoppingConfig: %w", err)
			}
		case OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB:
			if v.RepetitionNumberofSIB1NB == nil {
				return fmt.Errorf("choice alternative repetitionNumberofSIB1-NB is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.RepetitionNumberofSIB1NB), 3, true); err != nil {
				return fmt.Errorf("encoding repetitionNumberofSIB1-NB: %w", err)
			}
		case OTDOACellInformationItemChoiceNPRSSequenceInfo:
			if err := per.EncodeIntegerBigBoundsAligned(inner, v.NPRSSequenceInfo, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("174"), true); err != nil {
				return fmt.Errorf("encoding nPRSSequenceInfo: %w", err)
			}
		case OTDOACellInformationItemChoiceNPRSType2:
			if v.NPRSType2 == nil {
				return fmt.Errorf("choice alternative nPRSType2 is nil")
			}
			if err := v.NPRSType2.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding nPRSType2: %w", err)
			}
		case OTDOACellInformationItemChoiceTddConfiguration:
			if v.TddConfiguration == nil {
				return fmt.Errorf("choice alternative tddConfiguration is nil")
			}
			if err := v.TddConfiguration.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding tddConfiguration: %w", err)
			}
		default:
			return fmt.Errorf("unknown OTDOACellInformationItem extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(v.PEROpenTypePadding_)
		if err != nil {
			return err
		}
		if err := per.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 10); err != nil {
		return err
	}
	switch v.Choice {
	case OTDOACellInformationItemChoicePCI:
		if err := per.EncodeIntegerBigBoundsAligned(bb, v.PCI, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true); err != nil {
			return fmt.Errorf("encoding pCI: %w", err)
		}
	case OTDOACellInformationItemChoiceCellId:
		if v.CellId == nil {
			return fmt.Errorf("choice alternative cellId is nil")
		}
		if err := v.CellId.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding cellId: %w", err)
		}
	case OTDOACellInformationItemChoiceTAC:
		if v.TAC == nil {
			return fmt.Errorf("choice alternative tAC is nil")
		}
		if err := per.EncodeOctetStringAligned(bb, []byte(*v.TAC), 2, 2, true); err != nil {
			return fmt.Errorf("encoding tAC: %w", err)
		}
	case OTDOACellInformationItemChoiceEARFCN:
		if err := per.EncodeIntegerBigBoundsAligned(bb, v.EARFCN, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("65535"), true); err != nil {
			return fmt.Errorf("encoding eARFCN: %w", err)
		}
	case OTDOACellInformationItemChoicePRSBandwidth:
		if v.PRSBandwidth == nil {
			return fmt.Errorf("choice alternative pRS-Bandwidth is nil")
		}
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.PRSBandwidth), 6, true); err != nil {
			return fmt.Errorf("encoding pRS-Bandwidth: %w", err)
		}
	case OTDOACellInformationItemChoicePRSConfigurationIndex:
		if err := per.EncodeIntegerBigBoundsAligned(bb, v.PRSConfigurationIndex, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true); err != nil {
			return fmt.Errorf("encoding pRS-ConfigurationIndex: %w", err)
		}
	case OTDOACellInformationItemChoiceCPLength:
		if v.CPLength == nil {
			return fmt.Errorf("choice alternative cPLength is nil")
		}
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.CPLength), 2, true); err != nil {
			return fmt.Errorf("encoding cPLength: %w", err)
		}
	case OTDOACellInformationItemChoiceNumberOfDlFrames:
		if v.NumberOfDlFrames == nil {
			return fmt.Errorf("choice alternative numberOfDlFrames is nil")
		}
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.NumberOfDlFrames), 4, true); err != nil {
			return fmt.Errorf("encoding numberOfDlFrames: %w", err)
		}
	case OTDOACellInformationItemChoiceNumberOfAntennaPorts:
		if v.NumberOfAntennaPorts == nil {
			return fmt.Errorf("choice alternative numberOfAntennaPorts is nil")
		}
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.NumberOfAntennaPorts), 2, true); err != nil {
			return fmt.Errorf("encoding numberOfAntennaPorts: %w", err)
		}
	case OTDOACellInformationItemChoiceSFNInitialisationTime:
		if v.SFNInitialisationTime == nil {
			return fmt.Errorf("choice alternative sFNInitialisationTime is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.SFNInitialisationTime.Bytes, v.SFNInitialisationTime.BitLength, 64, 64, true); err != nil {
			return fmt.Errorf("encoding sFNInitialisationTime: %w", err)
		}
	case OTDOACellInformationItemChoiceEUTRANAccessPointPosition:
		if v.EUTRANAccessPointPosition == nil {
			return fmt.Errorf("choice alternative e-UTRANAccessPointPosition is nil")
		}
		if err := v.EUTRANAccessPointPosition.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding e-UTRANAccessPointPosition: %w", err)
		}
	default:
		return fmt.Errorf("unknown OTDOACellInformationItem choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes OTDOACellInformationItem from APER format.
func (v *OTDOACellInformationItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellInformationItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellInformationItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *OTDOACellInformationItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = OTDOACellInformationItem{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if extIdx >= 18 {
			v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
			return nil
		}
		inner := per.NewBitBufferFromBytes(openData)
		v.Choice = int(extIdx) + 11 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case OTDOACellInformationItemChoicePRSMutingConfiguration:
			extensionPath = "PRSMutingConfiguration"
			var dec_prsmutingconfiguration PRSMutingConfiguration
			if err := dec_prsmutingconfiguration.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "PRSMutingConfiguration")
			}
			v.PRSMutingConfiguration = &dec_prsmutingconfiguration
		case OTDOACellInformationItemChoicePrsid:
			extensionPath = "Prsid"
			val_prsid, err := per.DecodeIntegerBigBoundsAligned(inner, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return runtime.WrapDecodePath(err, "Prsid")
			}
			v.Prsid = val_prsid
		case OTDOACellInformationItemChoiceTpid:
			extensionPath = "Tpid"
			val_tpid, err := per.DecodeIntegerBigBoundsAligned(inner, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return runtime.WrapDecodePath(err, "Tpid")
			}
			v.Tpid = val_tpid
		case OTDOACellInformationItemChoiceTpType:
			extensionPath = "TpType"
			val_tptype, err := per.DecodeEnumeratedAligned(inner, 1, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "TpType")
			}
			tmp_tptype := TPType(val_tptype)
			v.TpType = &tmp_tptype
		case OTDOACellInformationItemChoiceNumberOfDlFramesExtended:
			extensionPath = "NumberOfDlFramesExtended"
			val_numberofdlframesextended, err := per.DecodeIntegerBigBoundsAligned(inner, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("160"), true)
			if err != nil {
				return runtime.WrapDecodePath(err, "NumberOfDlFramesExtended")
			}
			v.NumberOfDlFramesExtended = val_numberofdlframesextended
		case OTDOACellInformationItemChoiceCrsCPlength:
			extensionPath = "CrsCPlength"
			val_crscplength, err := per.DecodeEnumeratedAligned(inner, 2, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "CrsCPlength")
			}
			tmp_crscplength := CPLength(val_crscplength)
			v.CrsCPlength = &tmp_crscplength
		case OTDOACellInformationItemChoiceMBSFNsubframeConfiguration:
			extensionPath = "MBSFNsubframeConfiguration"
			tmp_mbsfnsubframeconfiguration := make(MBSFNsubframeConfiguration, 0)
			_, errCollection_mbsfnsubframeconfiguration := per.DecodeCollection(inner, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_mbsfnsubframeconfiguration, fragmentLength_mbsfnsubframeconfiguration int64) error {
				for i := int64(0); i < fragmentLength_mbsfnsubframeconfiguration; i++ {
					var elem MBSFNsubframeConfigurationValue
					if err := elem.UnmarshalAPERFrom(inner); err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("MBSFNsubframeConfiguration[%d]", fragmentOffset_mbsfnsubframeconfiguration+i))
					}
					tmp_mbsfnsubframeconfiguration = append(tmp_mbsfnsubframeconfiguration, elem)
				}
				return nil
			})
			if errCollection_mbsfnsubframeconfiguration != nil {
				return runtime.WrapDecodePath(errCollection_mbsfnsubframeconfiguration, "MBSFNsubframeConfiguration")
			}
			v.MBSFNsubframeConfiguration = tmp_mbsfnsubframeconfiguration
		case OTDOACellInformationItemChoiceNPRSConfiguration:
			extensionPath = "NPRSConfiguration"
			var dec_nprsconfiguration NPRSConfiguration
			if err := dec_nprsconfiguration.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "NPRSConfiguration")
			}
			v.NPRSConfiguration = &dec_nprsconfiguration
		case OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN:
			extensionPath = "OffsetNBChanneltoEARFCN"
			val_offsetnbchanneltoearfcn, err := per.DecodeEnumeratedAligned(inner, 21, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "OffsetNBChanneltoEARFCN")
			}
			tmp_offsetnbchanneltoearfcn := OffsetNBChanneltoEARFCN(val_offsetnbchanneltoearfcn)
			v.OffsetNBChanneltoEARFCN = &tmp_offsetnbchanneltoearfcn
		case OTDOACellInformationItemChoiceOperationModeInfo:
			extensionPath = "OperationModeInfo"
			val_operationmodeinfo, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "OperationModeInfo")
			}
			tmp_operationmodeinfo := OperationModeInfo(val_operationmodeinfo)
			v.OperationModeInfo = &tmp_operationmodeinfo
		case OTDOACellInformationItemChoiceNPRSID:
			extensionPath = "NPRSID"
			val_nprsid, err := per.DecodeIntegerBigBoundsAligned(inner, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return runtime.WrapDecodePath(err, "NPRSID")
			}
			v.NPRSID = val_nprsid
		case OTDOACellInformationItemChoiceDLBandwidth:
			extensionPath = "DLBandwidth"
			val_dlbandwidth, err := per.DecodeEnumeratedAligned(inner, 6, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "DLBandwidth")
			}
			tmp_dlbandwidth := DLBandwidth(val_dlbandwidth)
			v.DLBandwidth = &tmp_dlbandwidth
		case OTDOACellInformationItemChoicePRSOccasionGroup:
			extensionPath = "PRSOccasionGroup"
			val_prsoccasiongroup, err := per.DecodeEnumeratedAligned(inner, 7, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "PRSOccasionGroup")
			}
			tmp_prsoccasiongroup := PRSOccasionGroup(val_prsoccasiongroup)
			v.PRSOccasionGroup = &tmp_prsoccasiongroup
		case OTDOACellInformationItemChoicePRSFreqHoppingConfig:
			extensionPath = "PRSFreqHoppingConfig"
			var dec_prsfreqhoppingconfig PRSFrequencyHoppingConfiguration
			if err := dec_prsfreqhoppingconfig.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "PRSFreqHoppingConfig")
			}
			v.PRSFreqHoppingConfig = &dec_prsfreqhoppingconfig
		case OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB:
			extensionPath = "RepetitionNumberofSIB1NB"
			val_repetitionnumberofsib1nb, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "RepetitionNumberofSIB1NB")
			}
			tmp_repetitionnumberofsib1nb := RepetitionNumberofSIB1NB(val_repetitionnumberofsib1nb)
			v.RepetitionNumberofSIB1NB = &tmp_repetitionnumberofsib1nb
		case OTDOACellInformationItemChoiceNPRSSequenceInfo:
			extensionPath = "NPRSSequenceInfo"
			val_nprssequenceinfo, err := per.DecodeIntegerBigBoundsAligned(inner, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("174"), true)
			if err != nil {
				return runtime.WrapDecodePath(err, "NPRSSequenceInfo")
			}
			v.NPRSSequenceInfo = val_nprssequenceinfo
		case OTDOACellInformationItemChoiceNPRSType2:
			extensionPath = "NPRSType2"
			var dec_nprstype2 NPRSConfiguration
			if err := dec_nprstype2.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "NPRSType2")
			}
			v.NPRSType2 = &dec_nprstype2
		case OTDOACellInformationItemChoiceTddConfiguration:
			extensionPath = "TddConfiguration"
			var dec_tddconfiguration TDDConfiguration
			if err := dec_tddconfiguration.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "TddConfiguration")
			}
			v.TddConfiguration = &dec_tddconfiguration
		}
		padding, err := per.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.PEROpenTypePadding_ = padding
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 10)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case OTDOACellInformationItemChoicePCI:
		val_pci, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PCI")
		}
		v.PCI = val_pci
	case OTDOACellInformationItemChoiceCellId:
		var dec_cellid ECGI
		if err := dec_cellid.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CellId")
		}
		v.CellId = &dec_cellid
	case OTDOACellInformationItemChoiceTAC:
		val_tac, err := per.DecodeOctetStringAligned(bb, 2, 2, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "TAC")
		}
		tmp_tac := TAC(val_tac)
		v.TAC = &tmp_tac
	case OTDOACellInformationItemChoiceEARFCN:
		val_earfcn, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("65535"), true)
		if err != nil {
			return runtime.WrapDecodePath(err, "EARFCN")
		}
		v.EARFCN = val_earfcn
	case OTDOACellInformationItemChoicePRSBandwidth:
		val_prsbandwidth, err := per.DecodeEnumeratedAligned(bb, 6, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PRSBandwidth")
		}
		tmp_prsbandwidth := PRSBandwidth(val_prsbandwidth)
		v.PRSBandwidth = &tmp_prsbandwidth
	case OTDOACellInformationItemChoicePRSConfigurationIndex:
		val_prsconfigurationindex, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PRSConfigurationIndex")
		}
		v.PRSConfigurationIndex = val_prsconfigurationindex
	case OTDOACellInformationItemChoiceCPLength:
		val_cplength, err := per.DecodeEnumeratedAligned(bb, 2, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "CPLength")
		}
		tmp_cplength := CPLength(val_cplength)
		v.CPLength = &tmp_cplength
	case OTDOACellInformationItemChoiceNumberOfDlFrames:
		val_numberofdlframes, err := per.DecodeEnumeratedAligned(bb, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "NumberOfDlFrames")
		}
		tmp_numberofdlframes := NumberOfDlFrames(val_numberofdlframes)
		v.NumberOfDlFrames = &tmp_numberofdlframes
	case OTDOACellInformationItemChoiceNumberOfAntennaPorts:
		val_numberofantennaports, err := per.DecodeEnumeratedAligned(bb, 2, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "NumberOfAntennaPorts")
		}
		tmp_numberofantennaports := NumberOfAntennaPorts(val_numberofantennaports)
		v.NumberOfAntennaPorts = &tmp_numberofantennaports
	case OTDOACellInformationItemChoiceSFNInitialisationTime:
		bsBytes_sfninitialisationtime, bsBitLen_sfninitialisationtime, err := per.DecodeBitStringAligned(bb, 64, 64, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "SFNInitialisationTime")
		}
		tmp_sfninitialisationtime := runtime.BitString{Bytes: bsBytes_sfninitialisationtime, BitLength: bsBitLen_sfninitialisationtime}
		v.SFNInitialisationTime = &tmp_sfninitialisationtime
	case OTDOACellInformationItemChoiceEUTRANAccessPointPosition:
		var dec_eutranaccesspointposition EUTRANAccessPointPosition
		if err := dec_eutranaccesspointposition.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "EUTRANAccessPointPosition")
		}
		v.EUTRANAccessPointPosition = &dec_eutranaccesspointposition
	}
	return nil
}

type asn1cAPERPosSIBsListValue struct{ Value PosSIBs }

// PosSIBsComplete carries a complete PosSIBs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PosSIBsComplete struct {
	Value       PosSIBs
	PERPadding_ per.CompletePadding
}

func (v *PosSIBsComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERPosSIBsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *PosSIBsComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERPosSIBsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBs")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBs")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERPosSIBs encodes a PosSIBs list to APER.
func MarshalAPERPosSIBs(list PosSIBsComplete) ([]byte, error) { return list.MarshalAPER() }

// MarshalAPERPosSIBsTo appends a PosSIBs list to bb.
func MarshalAPERPosSIBsTo(list PosSIBs, bb *per.BitBuffer) error {
	v := asn1cAPERPosSIBsListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERPosSIBs decodes a PosSIBs list from APER.
func UnmarshalAPERPosSIBs(data []byte) (PosSIBsComplete, error) {
	var value PosSIBsComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERPosSIBsFrom decodes a PosSIBs list from bb.
func UnmarshalAPERPosSIBsFrom(bb *per.BitBuffer) (PosSIBs, error) {
	var v asn1cAPERPosSIBsListValue
	if err := unmarshalAPERPosSIBsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERPosSIBsInto(v *asn1cAPERPosSIBsListValue, bb *per.BitBuffer) error {
	v.Value = make(PosSIBs, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem PosSIBsElem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

type asn1cAPERPosSIBSegmentsListValue struct{ Value PosSIBSegments }

// PosSIBSegmentsComplete carries a complete PosSIBSegments encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PosSIBSegmentsComplete struct {
	Value       PosSIBSegments
	PERPadding_ per.CompletePadding
}

func (v *PosSIBSegmentsComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERPosSIBSegmentsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *PosSIBSegmentsComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERPosSIBSegmentsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBSegments")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBSegments")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERPosSIBSegments encodes a PosSIBSegments list to APER.
func MarshalAPERPosSIBSegments(list PosSIBSegmentsComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERPosSIBSegmentsTo appends a PosSIBSegments list to bb.
func MarshalAPERPosSIBSegmentsTo(list PosSIBSegments, bb *per.BitBuffer) error {
	v := asn1cAPERPosSIBSegmentsListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERPosSIBSegments decodes a PosSIBSegments list from APER.
func UnmarshalAPERPosSIBSegments(data []byte) (PosSIBSegmentsComplete, error) {
	var value PosSIBSegmentsComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERPosSIBSegmentsFrom decodes a PosSIBSegments list from bb.
func UnmarshalAPERPosSIBSegmentsFrom(bb *per.BitBuffer) (PosSIBSegments, error) {
	var v asn1cAPERPosSIBSegmentsListValue
	if err := unmarshalAPERPosSIBSegmentsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERPosSIBSegmentsInto(v *asn1cAPERPosSIBSegmentsListValue, bb *per.BitBuffer) error {
	v.Value = make(PosSIBSegments, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem PosSIBSegmentsElem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes PRSMutingConfiguration to APER format.
func (v *PRSMutingConfiguration) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *PRSMutingConfiguration) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("PRSMutingConfiguration: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("PRSMutingConfiguration: extension index %d must be non-negative", v.UnknownExtension.Index)
		}
		if v.UnknownExtension.Index < 6 {
			return fmt.Errorf("PRSMutingConfiguration: extension index %d is known to this schema", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 4
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-4-1)); err != nil {
			return err
		}
		inner := per.NewBitBuffer()
		switch v.Choice {
		case PRSMutingConfigurationChoiceThirtyTwo:
			if v.ThirtyTwo == nil {
				return fmt.Errorf("choice alternative thirty-two is nil")
			}
			if err := per.EncodeBitStringAligned(inner, v.ThirtyTwo.Bytes, v.ThirtyTwo.BitLength, 32, 32, true); err != nil {
				return fmt.Errorf("encoding thirty-two: %w", err)
			}
		case PRSMutingConfigurationChoiceSixtyFour:
			if v.SixtyFour == nil {
				return fmt.Errorf("choice alternative sixty-four is nil")
			}
			if err := per.EncodeBitStringAligned(inner, v.SixtyFour.Bytes, v.SixtyFour.BitLength, 64, 64, true); err != nil {
				return fmt.Errorf("encoding sixty-four: %w", err)
			}
		case PRSMutingConfigurationChoiceOneHundredAndTwentyEight:
			if v.OneHundredAndTwentyEight == nil {
				return fmt.Errorf("choice alternative one-hundred-and-twenty-eight is nil")
			}
			if err := per.EncodeBitStringAligned(inner, v.OneHundredAndTwentyEight.Bytes, v.OneHundredAndTwentyEight.BitLength, 128, 128, true); err != nil {
				return fmt.Errorf("encoding one-hundred-and-twenty-eight: %w", err)
			}
		case PRSMutingConfigurationChoiceTwoHundredAndFiftySix:
			if v.TwoHundredAndFiftySix == nil {
				return fmt.Errorf("choice alternative two-hundred-and-fifty-six is nil")
			}
			if err := per.EncodeBitStringAligned(inner, v.TwoHundredAndFiftySix.Bytes, v.TwoHundredAndFiftySix.BitLength, 256, 256, true); err != nil {
				return fmt.Errorf("encoding two-hundred-and-fifty-six: %w", err)
			}
		case PRSMutingConfigurationChoiceFiveHundredAndTwelve:
			if v.FiveHundredAndTwelve == nil {
				return fmt.Errorf("choice alternative five-hundred-and-twelve is nil")
			}
			if err := per.EncodeBitStringAligned(inner, v.FiveHundredAndTwelve.Bytes, v.FiveHundredAndTwelve.BitLength, 512, 512, true); err != nil {
				return fmt.Errorf("encoding five-hundred-and-twelve: %w", err)
			}
		case PRSMutingConfigurationChoiceOneThousandAndTwentyFour:
			if v.OneThousandAndTwentyFour == nil {
				return fmt.Errorf("choice alternative one-thousand-and-twenty-four is nil")
			}
			if err := per.EncodeBitStringAligned(inner, v.OneThousandAndTwentyFour.Bytes, v.OneThousandAndTwentyFour.BitLength, 1024, 1024, true); err != nil {
				return fmt.Errorf("encoding one-thousand-and-twenty-four: %w", err)
			}
		default:
			return fmt.Errorf("unknown PRSMutingConfiguration extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(v.PEROpenTypePadding_)
		if err != nil {
			return err
		}
		if err := per.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case PRSMutingConfigurationChoiceTwo:
		if v.Two == nil {
			return fmt.Errorf("choice alternative two is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.Two.Bytes, v.Two.BitLength, 2, 2, true); err != nil {
			return fmt.Errorf("encoding two: %w", err)
		}
	case PRSMutingConfigurationChoiceFour:
		if v.Four == nil {
			return fmt.Errorf("choice alternative four is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.Four.Bytes, v.Four.BitLength, 4, 4, true); err != nil {
			return fmt.Errorf("encoding four: %w", err)
		}
	case PRSMutingConfigurationChoiceEight:
		if v.Eight == nil {
			return fmt.Errorf("choice alternative eight is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.Eight.Bytes, v.Eight.BitLength, 8, 8, true); err != nil {
			return fmt.Errorf("encoding eight: %w", err)
		}
	case PRSMutingConfigurationChoiceSixteen:
		if v.Sixteen == nil {
			return fmt.Errorf("choice alternative sixteen is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.Sixteen.Bytes, v.Sixteen.BitLength, 16, 16, true); err != nil {
			return fmt.Errorf("encoding sixteen: %w", err)
		}
	default:
		return fmt.Errorf("unknown PRSMutingConfiguration choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes PRSMutingConfiguration from APER format.
func (v *PRSMutingConfiguration) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PRSMutingConfiguration")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PRSMutingConfiguration")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *PRSMutingConfiguration) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PRSMutingConfiguration{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if extIdx >= 6 {
			v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
			return nil
		}
		inner := per.NewBitBufferFromBytes(openData)
		v.Choice = int(extIdx) + 4 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case PRSMutingConfigurationChoiceThirtyTwo:
			extensionPath = "ThirtyTwo"
			bsBytes_thirtytwo, bsBitLen_thirtytwo, err := per.DecodeBitStringAligned(inner, 32, 32, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "ThirtyTwo")
			}
			tmp_thirtytwo := runtime.BitString{Bytes: bsBytes_thirtytwo, BitLength: bsBitLen_thirtytwo}
			v.ThirtyTwo = &tmp_thirtytwo
		case PRSMutingConfigurationChoiceSixtyFour:
			extensionPath = "SixtyFour"
			bsBytes_sixtyfour, bsBitLen_sixtyfour, err := per.DecodeBitStringAligned(inner, 64, 64, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "SixtyFour")
			}
			tmp_sixtyfour := runtime.BitString{Bytes: bsBytes_sixtyfour, BitLength: bsBitLen_sixtyfour}
			v.SixtyFour = &tmp_sixtyfour
		case PRSMutingConfigurationChoiceOneHundredAndTwentyEight:
			extensionPath = "OneHundredAndTwentyEight"
			bsBytes_onehundredandtwentyeight, bsBitLen_onehundredandtwentyeight, err := per.DecodeBitStringAligned(inner, 128, 128, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "OneHundredAndTwentyEight")
			}
			tmp_onehundredandtwentyeight := runtime.BitString{Bytes: bsBytes_onehundredandtwentyeight, BitLength: bsBitLen_onehundredandtwentyeight}
			v.OneHundredAndTwentyEight = &tmp_onehundredandtwentyeight
		case PRSMutingConfigurationChoiceTwoHundredAndFiftySix:
			extensionPath = "TwoHundredAndFiftySix"
			bsBytes_twohundredandfiftysix, bsBitLen_twohundredandfiftysix, err := per.DecodeBitStringAligned(inner, 256, 256, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "TwoHundredAndFiftySix")
			}
			tmp_twohundredandfiftysix := runtime.BitString{Bytes: bsBytes_twohundredandfiftysix, BitLength: bsBitLen_twohundredandfiftysix}
			v.TwoHundredAndFiftySix = &tmp_twohundredandfiftysix
		case PRSMutingConfigurationChoiceFiveHundredAndTwelve:
			extensionPath = "FiveHundredAndTwelve"
			bsBytes_fivehundredandtwelve, bsBitLen_fivehundredandtwelve, err := per.DecodeBitStringAligned(inner, 512, 512, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "FiveHundredAndTwelve")
			}
			tmp_fivehundredandtwelve := runtime.BitString{Bytes: bsBytes_fivehundredandtwelve, BitLength: bsBitLen_fivehundredandtwelve}
			v.FiveHundredAndTwelve = &tmp_fivehundredandtwelve
		case PRSMutingConfigurationChoiceOneThousandAndTwentyFour:
			extensionPath = "OneThousandAndTwentyFour"
			bsBytes_onethousandandtwentyfour, bsBitLen_onethousandandtwentyfour, err := per.DecodeBitStringAligned(inner, 1024, 1024, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "OneThousandAndTwentyFour")
			}
			tmp_onethousandandtwentyfour := runtime.BitString{Bytes: bsBytes_onethousandandtwentyfour, BitLength: bsBitLen_onethousandandtwentyfour}
			v.OneThousandAndTwentyFour = &tmp_onethousandandtwentyfour
		}
		padding, err := per.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.PEROpenTypePadding_ = padding
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 3)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case PRSMutingConfigurationChoiceTwo:
		bsBytes_two, bsBitLen_two, err := per.DecodeBitStringAligned(bb, 2, 2, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Two")
		}
		tmp_two := runtime.BitString{Bytes: bsBytes_two, BitLength: bsBitLen_two}
		v.Two = &tmp_two
	case PRSMutingConfigurationChoiceFour:
		bsBytes_four, bsBitLen_four, err := per.DecodeBitStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Four")
		}
		tmp_four := runtime.BitString{Bytes: bsBytes_four, BitLength: bsBitLen_four}
		v.Four = &tmp_four
	case PRSMutingConfigurationChoiceEight:
		bsBytes_eight, bsBitLen_eight, err := per.DecodeBitStringAligned(bb, 8, 8, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Eight")
		}
		tmp_eight := runtime.BitString{Bytes: bsBytes_eight, BitLength: bsBitLen_eight}
		v.Eight = &tmp_eight
	case PRSMutingConfigurationChoiceSixteen:
		bsBytes_sixteen, bsBitLen_sixteen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Sixteen")
		}
		tmp_sixteen := runtime.BitString{Bytes: bsBytes_sixteen, BitLength: bsBitLen_sixteen}
		v.Sixteen = &tmp_sixteen
	}
	return nil
}

// MarshalAPER encodes PRSFrequencyHoppingConfiguration to APER format.
func (v *PRSFrequencyHoppingConfiguration) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *PRSFrequencyHoppingConfiguration) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.NoOfFreqHoppingBands), 2, true); err != nil {
		return fmt.Errorf("encoding noOfFreqHoppingBands: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.BandPositions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 7, HasUpper: true}, true, func(fragmentOffset_bandpositions, fragmentLength_bandpositions int64) error {
		for _, elem := range v.BandPositions[fragmentOffset_bandpositions : fragmentOffset_bandpositions+fragmentLength_bandpositions] {
			if err := per.EncodeIntegerBigBoundsAligned(bb, elem, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
				return fmt.Errorf("encoding bandPositions element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding bandPositions: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes PRSFrequencyHoppingConfiguration from APER format.
func (v *PRSFrequencyHoppingConfiguration) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PRSFrequencyHoppingConfiguration")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PRSFrequencyHoppingConfiguration")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *PRSFrequencyHoppingConfiguration) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PRSFrequencyHoppingConfiguration{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_nooffreqhoppingbands, err := per.DecodeEnumeratedAligned(bb, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NoOfFreqHoppingBands")
	}
	v.NoOfFreqHoppingBands = NumberOfFrequencyHoppingBands(val_nooffreqhoppingbands)
	v.BandPositions = make(PRSFrequencyHoppingConfigurationBandPositions, 0)
	_, errCollection_bandpositions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 7, HasUpper: true}, true, func(fragmentOffset_bandpositions, fragmentLength_bandpositions int64) error {
		for i := int64(0); i < fragmentLength_bandpositions; i++ {
			val, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("BandPositions[%d]", fragmentOffset_bandpositions+i))
			}
			v.BandPositions = append(v.BandPositions, val)
		}
		return nil
	})
	if errCollection_bandpositions != nil {
		return runtime.WrapDecodePath(errCollection_bandpositions, "BandPositions")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes RequestedSRSTransmissionCharacteristics to APER format.
func (v *RequestedSRSTransmissionCharacteristics) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *RequestedSRSTransmissionCharacteristics) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.NumberOfTransmissions, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("500"), true); err != nil {
		return fmt.Errorf("encoding numberOfTransmissions: %w", err)
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.Bandwidth, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("100"), true); err != nil {
		return fmt.Errorf("encoding bandwidth: %w", err)
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes RequestedSRSTransmissionCharacteristics from APER format.
func (v *RequestedSRSTransmissionCharacteristics) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RequestedSRSTransmissionCharacteristics")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "RequestedSRSTransmissionCharacteristics")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *RequestedSRSTransmissionCharacteristics) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = RequestedSRSTransmissionCharacteristics{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_numberoftransmissions, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("500"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberOfTransmissions")
	}
	v.NumberOfTransmissions = val_numberoftransmissions
	val_bandwidth, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("100"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "Bandwidth")
	}
	v.Bandwidth = val_bandwidth
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERResultRSRPListValue struct{ Value ResultRSRP }

// ResultRSRPComplete carries a complete ResultRSRP encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultRSRPComplete struct {
	Value       ResultRSRP
	PERPadding_ per.CompletePadding
}

func (v *ResultRSRPComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERResultRSRPTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultRSRPComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERResultRSRPFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRP")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRP")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERResultRSRP encodes a ResultRSRP list to APER.
func MarshalAPERResultRSRP(list ResultRSRPComplete) ([]byte, error) { return list.MarshalAPER() }

// MarshalAPERResultRSRPTo appends a ResultRSRP list to bb.
func MarshalAPERResultRSRPTo(list ResultRSRP, bb *per.BitBuffer) error {
	v := asn1cAPERResultRSRPListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERResultRSRP decodes a ResultRSRP list from APER.
func UnmarshalAPERResultRSRP(data []byte) (ResultRSRPComplete, error) {
	var value ResultRSRPComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultRSRPFrom decodes a ResultRSRP list from bb.
func UnmarshalAPERResultRSRPFrom(bb *per.BitBuffer) (ResultRSRP, error) {
	var v asn1cAPERResultRSRPListValue
	if err := unmarshalAPERResultRSRPInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERResultRSRPInto(v *asn1cAPERResultRSRPListValue, bb *per.BitBuffer) error {
	v.Value = make(ResultRSRP, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ResultRSRPItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ResultRSRPItem to APER format.
func (v *ResultRSRPItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultRSRPItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.ECGI != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.PCI, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true); err != nil {
		return fmt.Errorf("encoding pCI: %w", err)
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.EARFCN, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("65535"), true); err != nil {
		return fmt.Errorf("encoding eARFCN: %w", err)
	}
	if v.ECGI != nil {
		if err := v.ECGI.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding eCGI: %w", err)
		}
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ValueRSRP, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("97"), true); err != nil {
		return fmt.Errorf("encoding valueRSRP: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ResultRSRPItem from APER format.
func (v *ResultRSRPItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRPItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRPItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ResultRSRPItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ResultRSRPItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ecgi, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PCI")
	}
	v.PCI = val_pci
	val_earfcn, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("65535"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EARFCN")
	}
	v.EARFCN = val_earfcn
	if opt_ecgi {
		var dec_ecgi ECGI
		if err := dec_ecgi.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "ECGI")
		}
		v.ECGI = &dec_ecgi
	}
	val_valuersrp, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("97"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ValueRSRP")
	}
	v.ValueRSRP = val_valuersrp
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERResultRSRQListValue struct{ Value ResultRSRQ }

// ResultRSRQComplete carries a complete ResultRSRQ encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultRSRQComplete struct {
	Value       ResultRSRQ
	PERPadding_ per.CompletePadding
}

func (v *ResultRSRQComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERResultRSRQTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultRSRQComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERResultRSRQFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRQ")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRQ")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERResultRSRQ encodes a ResultRSRQ list to APER.
func MarshalAPERResultRSRQ(list ResultRSRQComplete) ([]byte, error) { return list.MarshalAPER() }

// MarshalAPERResultRSRQTo appends a ResultRSRQ list to bb.
func MarshalAPERResultRSRQTo(list ResultRSRQ, bb *per.BitBuffer) error {
	v := asn1cAPERResultRSRQListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERResultRSRQ decodes a ResultRSRQ list from APER.
func UnmarshalAPERResultRSRQ(data []byte) (ResultRSRQComplete, error) {
	var value ResultRSRQComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultRSRQFrom decodes a ResultRSRQ list from bb.
func UnmarshalAPERResultRSRQFrom(bb *per.BitBuffer) (ResultRSRQ, error) {
	var v asn1cAPERResultRSRQListValue
	if err := unmarshalAPERResultRSRQInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERResultRSRQInto(v *asn1cAPERResultRSRQListValue, bb *per.BitBuffer) error {
	v.Value = make(ResultRSRQ, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ResultRSRQItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ResultRSRQItem to APER format.
func (v *ResultRSRQItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultRSRQItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.ECGI != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.PCI, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true); err != nil {
		return fmt.Errorf("encoding pCI: %w", err)
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.EARFCN, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("65535"), true); err != nil {
		return fmt.Errorf("encoding eARFCN: %w", err)
	}
	if v.ECGI != nil {
		if err := v.ECGI.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding eCGI: %w", err)
		}
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ValueRSRQ, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("34"), true); err != nil {
		return fmt.Errorf("encoding valueRSRQ: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ResultRSRQItem from APER format.
func (v *ResultRSRQItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRQItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRQItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ResultRSRQItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ResultRSRQItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ecgi, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PCI")
	}
	v.PCI = val_pci
	val_earfcn, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("65535"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EARFCN")
	}
	v.EARFCN = val_earfcn
	if opt_ecgi {
		var dec_ecgi ECGI
		if err := dec_ecgi.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "ECGI")
		}
		v.ECGI = &dec_ecgi
	}
	val_valuersrq, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("34"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ValueRSRQ")
	}
	v.ValueRSRQ = val_valuersrq
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERResultGERANListValue struct{ Value ResultGERAN }

// ResultGERANComplete carries a complete ResultGERAN encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultGERANComplete struct {
	Value       ResultGERAN
	PERPadding_ per.CompletePadding
}

func (v *ResultGERANComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERResultGERANTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultGERANComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERResultGERANFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultGERAN")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultGERAN")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERResultGERAN encodes a ResultGERAN list to APER.
func MarshalAPERResultGERAN(list ResultGERANComplete) ([]byte, error) { return list.MarshalAPER() }

// MarshalAPERResultGERANTo appends a ResultGERAN list to bb.
func MarshalAPERResultGERANTo(list ResultGERAN, bb *per.BitBuffer) error {
	v := asn1cAPERResultGERANListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERResultGERAN decodes a ResultGERAN list from APER.
func UnmarshalAPERResultGERAN(data []byte) (ResultGERANComplete, error) {
	var value ResultGERANComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultGERANFrom decodes a ResultGERAN list from bb.
func UnmarshalAPERResultGERANFrom(bb *per.BitBuffer) (ResultGERAN, error) {
	var v asn1cAPERResultGERANListValue
	if err := unmarshalAPERResultGERANInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERResultGERANInto(v *asn1cAPERResultGERANListValue, bb *per.BitBuffer) error {
	v.Value = make(ResultGERAN, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ResultGERANItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ResultGERANItem to APER format.
func (v *ResultGERANItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultGERANItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.BCCH, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("1023"), true); err != nil {
		return fmt.Errorf("encoding bCCH: %w", err)
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.PhysCellIDGERAN, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("63"), true); err != nil {
		return fmt.Errorf("encoding physCellIDGERAN: %w", err)
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.RSSI, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("63"), true); err != nil {
		return fmt.Errorf("encoding rSSI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ResultGERANItem from APER format.
func (v *ResultGERANItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultGERANItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultGERANItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ResultGERANItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ResultGERANItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_bcch, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("1023"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "BCCH")
	}
	v.BCCH = val_bcch
	val_physcellidgeran, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("63"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PhysCellIDGERAN")
	}
	v.PhysCellIDGERAN = val_physcellidgeran
	val_rssi, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("63"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "RSSI")
	}
	v.RSSI = val_rssi
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERResultUTRANListValue struct{ Value ResultUTRAN }

// ResultUTRANComplete carries a complete ResultUTRAN encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultUTRANComplete struct {
	Value       ResultUTRAN
	PERPadding_ per.CompletePadding
}

func (v *ResultUTRANComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERResultUTRANTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultUTRANComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERResultUTRANFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRAN")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRAN")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERResultUTRAN encodes a ResultUTRAN list to APER.
func MarshalAPERResultUTRAN(list ResultUTRANComplete) ([]byte, error) { return list.MarshalAPER() }

// MarshalAPERResultUTRANTo appends a ResultUTRAN list to bb.
func MarshalAPERResultUTRANTo(list ResultUTRAN, bb *per.BitBuffer) error {
	v := asn1cAPERResultUTRANListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERResultUTRAN decodes a ResultUTRAN list from APER.
func UnmarshalAPERResultUTRAN(data []byte) (ResultUTRANComplete, error) {
	var value ResultUTRANComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultUTRANFrom decodes a ResultUTRAN list from bb.
func UnmarshalAPERResultUTRANFrom(bb *per.BitBuffer) (ResultUTRAN, error) {
	var v asn1cAPERResultUTRANListValue
	if err := unmarshalAPERResultUTRANInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERResultUTRANInto(v *asn1cAPERResultUTRANListValue, bb *per.BitBuffer) error {
	v.Value = make(ResultUTRAN, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ResultUTRANItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ResultUTRANItem to APER format.
func (v *ResultUTRANItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultUTRANItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.UTRARSCP != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.UTRAEcN0 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.UARFCN, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("16383"), true); err != nil {
		return fmt.Errorf("encoding uARFCN: %w", err)
	}
	if err := v.PhysCellIDUTRAN.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding physCellIDUTRAN: %w", err)
	}
	if v.UTRARSCP != nil {
		if err := per.EncodeIntegerBigBoundsAligned(bb, v.UTRARSCP, runtime.MustParseBigIntDecimal("-5"), runtime.MustParseBigIntDecimal("91"), true); err != nil {
			return fmt.Errorf("encoding uTRA-RSCP: %w", err)
		}
	}
	if v.UTRAEcN0 != nil {
		if err := per.EncodeIntegerBigBoundsAligned(bb, v.UTRAEcN0, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("49"), true); err != nil {
			return fmt.Errorf("encoding uTRA-EcN0: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ResultUTRANItem from APER format.
func (v *ResultUTRANItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRANItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRANItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ResultUTRANItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ResultUTRANItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_utrarscp, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_utraecn0, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_uarfcn, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("16383"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "UARFCN")
	}
	v.UARFCN = val_uarfcn
	if err := v.PhysCellIDUTRAN.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PhysCellIDUTRAN")
	}
	if opt_utrarscp {
		val_utrarscp, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("-5"), runtime.MustParseBigIntDecimal("91"), true)
		if err != nil {
			return runtime.WrapDecodePath(err, "UTRARSCP")
		}
		v.UTRARSCP = val_utrarscp
	}
	if opt_utraecn0 {
		val_utraecn0, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("49"), true)
		if err != nil {
			return runtime.WrapDecodePath(err, "UTRAEcN0")
		}
		v.UTRAEcN0 = val_utraecn0
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERResultNRListValue struct{ Value ResultNR }

// ResultNRComplete carries a complete ResultNR encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultNRComplete struct {
	Value       ResultNR
	PERPadding_ per.CompletePadding
}

func (v *ResultNRComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERResultNRTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultNRComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERResultNRFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultNR")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultNR")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERResultNR encodes a ResultNR list to APER.
func MarshalAPERResultNR(list ResultNRComplete) ([]byte, error) { return list.MarshalAPER() }

// MarshalAPERResultNRTo appends a ResultNR list to bb.
func MarshalAPERResultNRTo(list ResultNR, bb *per.BitBuffer) error {
	v := asn1cAPERResultNRListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERResultNR decodes a ResultNR list from APER.
func UnmarshalAPERResultNR(data []byte) (ResultNRComplete, error) {
	var value ResultNRComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultNRFrom decodes a ResultNR list from bb.
func UnmarshalAPERResultNRFrom(bb *per.BitBuffer) (ResultNR, error) {
	var v asn1cAPERResultNRListValue
	if err := unmarshalAPERResultNRInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERResultNRInto(v *asn1cAPERResultNRListValue, bb *per.BitBuffer) error {
	v.Value = make(ResultNR, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ResultNRItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ResultNRItem to APER format.
func (v *ResultNRItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultNRItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SSNRRSRP != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SSNRRSRQ != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.NRARFCN), int64Ptr(0), int64Ptr(3279165), false); err != nil {
		return fmt.Errorf("encoding nRARFCN: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.NRPCI), int64Ptr(0), int64Ptr(1007), false); err != nil {
		return fmt.Errorf("encoding nRPCI: %w", err)
	}
	if v.SSNRRSRP != nil {
		if err := per.EncodeIntegerAligned(bb, int64(*v.SSNRRSRP), int64Ptr(0), int64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding sS-NRRSRP: %w", err)
		}
	}
	if v.SSNRRSRQ != nil {
		if err := per.EncodeIntegerAligned(bb, int64(*v.SSNRRSRQ), int64Ptr(0), int64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding sS-NRRSRQ: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ResultNRItem from APER format.
func (v *ResultNRItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultNRItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultNRItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ResultNRItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ResultNRItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ssnrrsrp, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ssnrrsrq, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_nrarfcn, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(3279165), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NRARFCN")
	}
	v.NRARFCN = NRARFCN(val_nrarfcn)
	val_nrpci, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(1007), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NRPCI")
	}
	v.NRPCI = NRPCI(val_nrpci)
	if opt_ssnrrsrp {
		val_ssnrrsrp, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSNRRSRP")
		}
		tmp_ssnrrsrp := SSNRRSRP(val_ssnrrsrp)
		v.SSNRRSRP = &tmp_ssnrrsrp
	}
	if opt_ssnrrsrq {
		val_ssnrrsrq, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSNRRSRQ")
		}
		tmp_ssnrrsrq := SSNRRSRQ(val_ssnrrsrq)
		v.SSNRRSRQ = &tmp_ssnrrsrq
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERResultsPerSSBIndexListListValue struct{ Value ResultsPerSSBIndexList }

// ResultsPerSSBIndexListComplete carries a complete ResultsPerSSBIndexList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultsPerSSBIndexListComplete struct {
	Value       ResultsPerSSBIndexList
	PERPadding_ per.CompletePadding
}

func (v *ResultsPerSSBIndexListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERResultsPerSSBIndexListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultsPerSSBIndexListComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERResultsPerSSBIndexListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultsPerSSBIndexList")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultsPerSSBIndexList")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERResultsPerSSBIndexList encodes a ResultsPerSSBIndexList list to APER.
func MarshalAPERResultsPerSSBIndexList(list ResultsPerSSBIndexListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERResultsPerSSBIndexListTo appends a ResultsPerSSBIndexList list to bb.
func MarshalAPERResultsPerSSBIndexListTo(list ResultsPerSSBIndexList, bb *per.BitBuffer) error {
	v := asn1cAPERResultsPerSSBIndexListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERResultsPerSSBIndexList decodes a ResultsPerSSBIndexList list from APER.
func UnmarshalAPERResultsPerSSBIndexList(data []byte) (ResultsPerSSBIndexListComplete, error) {
	var value ResultsPerSSBIndexListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultsPerSSBIndexListFrom decodes a ResultsPerSSBIndexList list from bb.
func UnmarshalAPERResultsPerSSBIndexListFrom(bb *per.BitBuffer) (ResultsPerSSBIndexList, error) {
	var v asn1cAPERResultsPerSSBIndexListListValue
	if err := unmarshalAPERResultsPerSSBIndexListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERResultsPerSSBIndexListInto(v *asn1cAPERResultsPerSSBIndexListListValue, bb *per.BitBuffer) error {
	v.Value = make(ResultsPerSSBIndexList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ResultsPerSSBIndexItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ResultsPerSSBIndexItem to APER format.
func (v *ResultsPerSSBIndexItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultsPerSSBIndexItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SSNRRSRPBeamValue != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SSNRRSRQBeamValue != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.SSBIndex), int64Ptr(0), int64Ptr(63), false); err != nil {
		return fmt.Errorf("encoding sSB-Index: %w", err)
	}
	if v.SSNRRSRPBeamValue != nil {
		if err := per.EncodeIntegerAligned(bb, int64(*v.SSNRRSRPBeamValue), int64Ptr(0), int64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding sS-NRRSRPBeamValue: %w", err)
		}
	}
	if v.SSNRRSRQBeamValue != nil {
		if err := per.EncodeIntegerAligned(bb, int64(*v.SSNRRSRQBeamValue), int64Ptr(0), int64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding sS-NRRSRQBeamValue: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ResultsPerSSBIndexItem from APER format.
func (v *ResultsPerSSBIndexItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultsPerSSBIndexItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultsPerSSBIndexItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ResultsPerSSBIndexItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ResultsPerSSBIndexItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ssnrrsrpbeamvalue, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ssnrrsrqbeamvalue, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_ssbindex, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(63), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SSBIndex")
	}
	v.SSBIndex = SSBIndex(val_ssbindex)
	if opt_ssnrrsrpbeamvalue {
		val_ssnrrsrpbeamvalue, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSNRRSRPBeamValue")
		}
		tmp_ssnrrsrpbeamvalue := SSNRRSRP(val_ssnrrsrpbeamvalue)
		v.SSNRRSRPBeamValue = &tmp_ssnrrsrpbeamvalue
	}
	if opt_ssnrrsrqbeamvalue {
		val_ssnrrsrqbeamvalue, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSNRRSRQBeamValue")
		}
		tmp_ssnrrsrqbeamvalue := SSNRRSRQ(val_ssnrrsrqbeamvalue)
		v.SSNRRSRQBeamValue = &tmp_ssnrrsrqbeamvalue
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERSRSConfigurationForAllCellsListValue struct{ Value SRSConfigurationForAllCells }

// SRSConfigurationForAllCellsComplete carries a complete SRSConfigurationForAllCells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SRSConfigurationForAllCellsComplete struct {
	Value       SRSConfigurationForAllCells
	PERPadding_ per.CompletePadding
}

func (v *SRSConfigurationForAllCellsComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERSRSConfigurationForAllCellsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *SRSConfigurationForAllCellsComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERSRSConfigurationForAllCellsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SRSConfigurationForAllCells")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SRSConfigurationForAllCells")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERSRSConfigurationForAllCells encodes a SRSConfigurationForAllCells list to APER.
func MarshalAPERSRSConfigurationForAllCells(list SRSConfigurationForAllCellsComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERSRSConfigurationForAllCellsTo appends a SRSConfigurationForAllCells list to bb.
func MarshalAPERSRSConfigurationForAllCellsTo(list SRSConfigurationForAllCells, bb *per.BitBuffer) error {
	v := asn1cAPERSRSConfigurationForAllCellsListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERSRSConfigurationForAllCells decodes a SRSConfigurationForAllCells list from APER.
func UnmarshalAPERSRSConfigurationForAllCells(data []byte) (SRSConfigurationForAllCellsComplete, error) {
	var value SRSConfigurationForAllCellsComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERSRSConfigurationForAllCellsFrom decodes a SRSConfigurationForAllCells list from bb.
func UnmarshalAPERSRSConfigurationForAllCellsFrom(bb *per.BitBuffer) (SRSConfigurationForAllCells, error) {
	var v asn1cAPERSRSConfigurationForAllCellsListValue
	if err := unmarshalAPERSRSConfigurationForAllCellsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERSRSConfigurationForAllCellsInto(v *asn1cAPERSRSConfigurationForAllCellsListValue, bb *per.BitBuffer) error {
	v.Value = make(SRSConfigurationForAllCells, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem SRSConfigurationForOneCell
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes SRSConfigurationForOneCell to APER format.
func (v *SRSConfigurationForOneCell) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *SRSConfigurationForOneCell) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MaxUpPts != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.DeltaSS != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.Pci, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true); err != nil {
		return fmt.Errorf("encoding pci: %w", err)
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.UlEarfcn, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("65535"), true); err != nil {
		return fmt.Errorf("encoding ul-earfcn: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.UlBandwidth), 6, false); err != nil {
		return fmt.Errorf("encoding ul-bandwidth: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.UlCyclicPrefixLength), 2, true); err != nil {
		return fmt.Errorf("encoding ul-cyclicPrefixLength: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.SrsBandwidthConfig), 8, false); err != nil {
		return fmt.Errorf("encoding srs-BandwidthConfig: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.SrsBandwidth), 4, false); err != nil {
		return fmt.Errorf("encoding srs-Bandwidth: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.SrsAntennaPort), 3, true); err != nil {
		return fmt.Errorf("encoding srs-AntennaPort: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.SrsHoppingBandwidth), 4, false); err != nil {
		return fmt.Errorf("encoding srs-HoppingBandwidth: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.SrsCyclicShift), 8, false); err != nil {
		return fmt.Errorf("encoding srs-cyclicShift: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.SrsConfigIndex), int64Ptr(0), int64Ptr(1023), false); err != nil {
		return fmt.Errorf("encoding srs-ConfigIndex: %w", err)
	}
	if v.MaxUpPts != nil {
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.MaxUpPts), 1, false); err != nil {
			return fmt.Errorf("encoding maxUpPts: %w", err)
		}
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.TransmissionComb), int64Ptr(0), int64Ptr(1), false); err != nil {
		return fmt.Errorf("encoding transmissionComb: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.FreqDomainPosition), int64Ptr(0), int64Ptr(23), false); err != nil {
		return fmt.Errorf("encoding freqDomainPosition: %w", err)
	}
	if err := per.EncodeBoolean(bb, v.GroupHoppingEnabled); err != nil {
		return fmt.Errorf("encoding groupHoppingEnabled: %w", err)
	}
	if v.DeltaSS != nil {
		if err := per.EncodeIntegerAligned(bb, int64(*v.DeltaSS), int64Ptr(0), int64Ptr(29), false); err != nil {
			return fmt.Errorf("encoding deltaSS: %w", err)
		}
	}
	if err := per.EncodeBitStringAligned(bb, v.SfnInitialisationTime.Bytes, v.SfnInitialisationTime.BitLength, 64, 64, true); err != nil {
		return fmt.Errorf("encoding sfnInitialisationTime: %w", err)
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes SRSConfigurationForOneCell from APER format.
func (v *SRSConfigurationForOneCell) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SRSConfigurationForOneCell")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SRSConfigurationForOneCell")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *SRSConfigurationForOneCell) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = SRSConfigurationForOneCell{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_maxuppts, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_deltass, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "Pci")
	}
	v.Pci = val_pci
	val_ulearfcn, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("65535"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "UlEarfcn")
	}
	v.UlEarfcn = val_ulearfcn
	val_ulbandwidth, err := per.DecodeEnumeratedAligned(bb, 6, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UlBandwidth")
	}
	v.UlBandwidth = val_ulbandwidth
	val_ulcyclicprefixlength, err := per.DecodeEnumeratedAligned(bb, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "UlCyclicPrefixLength")
	}
	v.UlCyclicPrefixLength = CPLength(val_ulcyclicprefixlength)
	val_srsbandwidthconfig, err := per.DecodeEnumeratedAligned(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsBandwidthConfig")
	}
	v.SrsBandwidthConfig = val_srsbandwidthconfig
	val_srsbandwidth, err := per.DecodeEnumeratedAligned(bb, 4, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsBandwidth")
	}
	v.SrsBandwidth = val_srsbandwidth
	val_srsantennaport, err := per.DecodeEnumeratedAligned(bb, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsAntennaPort")
	}
	v.SrsAntennaPort = val_srsantennaport
	val_srshoppingbandwidth, err := per.DecodeEnumeratedAligned(bb, 4, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsHoppingBandwidth")
	}
	v.SrsHoppingBandwidth = val_srshoppingbandwidth
	val_srscyclicshift, err := per.DecodeEnumeratedAligned(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsCyclicShift")
	}
	v.SrsCyclicShift = val_srscyclicshift
	val_srsconfigindex, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(1023), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsConfigIndex")
	}
	v.SrsConfigIndex = val_srsconfigindex
	if opt_maxuppts {
		val_maxuppts, err := per.DecodeEnumeratedAligned(bb, 1, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "MaxUpPts")
		}
		v.MaxUpPts = &val_maxuppts
	}
	val_transmissioncomb, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(1), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransmissionComb")
	}
	v.TransmissionComb = val_transmissioncomb
	val_freqdomainposition, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(23), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "FreqDomainPosition")
	}
	v.FreqDomainPosition = val_freqdomainposition
	val_grouphoppingenabled, err := per.DecodeBoolean(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "GroupHoppingEnabled")
	}
	v.GroupHoppingEnabled = val_grouphoppingenabled
	if opt_deltass {
		val_deltass, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(29), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "DeltaSS")
		}
		v.DeltaSS = &val_deltass
	}
	bsBytes_sfninitialisationtime, bsBitLen_sfninitialisationtime, err := per.DecodeBitStringAligned(bb, 64, 64, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "SfnInitialisationTime")
	}
	v.SfnInitialisationTime = runtime.BitString{Bytes: bsBytes_sfninitialisationtime, BitLength: bsBitLen_sfninitialisationtime}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes Subframeallocation to APER format.
func (v *Subframeallocation) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *Subframeallocation) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case SubframeallocationChoiceOneFrame:
		if v.OneFrame == nil {
			return fmt.Errorf("choice alternative oneFrame is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.OneFrame.Bytes, v.OneFrame.BitLength, 6, 6, true); err != nil {
			return fmt.Errorf("encoding oneFrame: %w", err)
		}
	case SubframeallocationChoiceFourFrames:
		if v.FourFrames == nil {
			return fmt.Errorf("choice alternative fourFrames is nil")
		}
		if err := per.EncodeBitStringAligned(bb, v.FourFrames.Bytes, v.FourFrames.BitLength, 24, 24, true); err != nil {
			return fmt.Errorf("encoding fourFrames: %w", err)
		}
	default:
		return fmt.Errorf("unknown Subframeallocation choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes Subframeallocation from APER format.
func (v *Subframeallocation) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Subframeallocation")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "Subframeallocation")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *Subframeallocation) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = Subframeallocation{}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case SubframeallocationChoiceOneFrame:
		bsBytes_oneframe, bsBitLen_oneframe, err := per.DecodeBitStringAligned(bb, 6, 6, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "OneFrame")
		}
		tmp_oneframe := runtime.BitString{Bytes: bsBytes_oneframe, BitLength: bsBitLen_oneframe}
		v.OneFrame = &tmp_oneframe
	case SubframeallocationChoiceFourFrames:
		bsBytes_fourframes, bsBitLen_fourframes, err := per.DecodeBitStringAligned(bb, 24, 24, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "FourFrames")
		}
		tmp_fourframes := runtime.BitString{Bytes: bsBytes_fourframes, BitLength: bsBitLen_fourframes}
		v.FourFrames = &tmp_fourframes
	}
	return nil
}

type asn1cAPERSystemInformationListValue struct{ Value SystemInformation }

// SystemInformationComplete carries a complete SystemInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SystemInformationComplete struct {
	Value       SystemInformation
	PERPadding_ per.CompletePadding
}

func (v *SystemInformationComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERSystemInformationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *SystemInformationComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERSystemInformationFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SystemInformation")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SystemInformation")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERSystemInformation encodes a SystemInformation list to APER.
func MarshalAPERSystemInformation(list SystemInformationComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERSystemInformationTo appends a SystemInformation list to bb.
func MarshalAPERSystemInformationTo(list SystemInformation, bb *per.BitBuffer) error {
	v := asn1cAPERSystemInformationListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERSystemInformation decodes a SystemInformation list from APER.
func UnmarshalAPERSystemInformation(data []byte) (SystemInformationComplete, error) {
	var value SystemInformationComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERSystemInformationFrom decodes a SystemInformation list from bb.
func UnmarshalAPERSystemInformationFrom(bb *per.BitBuffer) (SystemInformation, error) {
	var v asn1cAPERSystemInformationListValue
	if err := unmarshalAPERSystemInformationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERSystemInformationInto(v *asn1cAPERSystemInformationListValue, bb *per.BitBuffer) error {
	v.Value = make(SystemInformation, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem SystemInformationElem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes TDDConfiguration to APER format.
func (v *TDDConfiguration) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *TDDConfiguration) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.SubframeAssignment), 7, true); err != nil {
		return fmt.Errorf("encoding subframeAssignment: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes TDDConfiguration from APER format.
func (v *TDDConfiguration) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TDDConfiguration")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TDDConfiguration")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *TDDConfiguration) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = TDDConfiguration{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_subframeassignment, err := per.DecodeEnumeratedAligned(bb, 7, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "SubframeAssignment")
	}
	v.SubframeAssignment = val_subframeassignment
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes ULConfiguration to APER format.
func (v *ULConfiguration) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ULConfiguration) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.TimingAdvanceType1 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.TimingAdvanceType2 != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.Pci, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true); err != nil {
		return fmt.Errorf("encoding pci: %w", err)
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.UlEarfcn, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("65535"), true); err != nil {
		return fmt.Errorf("encoding ul-earfcn: %w", err)
	}
	if v.TimingAdvanceType1 != nil {
		if err := per.EncodeIntegerAligned(bb, int64(*v.TimingAdvanceType1), int64Ptr(0), int64Ptr(7690), false); err != nil {
			return fmt.Errorf("encoding timingAdvanceType1: %w", err)
		}
	}
	if v.TimingAdvanceType2 != nil {
		if err := per.EncodeIntegerAligned(bb, int64(*v.TimingAdvanceType2), int64Ptr(0), int64Ptr(7690), false); err != nil {
			return fmt.Errorf("encoding timingAdvanceType2: %w", err)
		}
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.NumberOfTransmissions, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("500"), true); err != nil {
		return fmt.Errorf("encoding numberOfTransmissions: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.SrsConfiguration)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_srsconfiguration, fragmentLength_srsconfiguration int64) error {
		for _, elem := range v.SrsConfiguration[fragmentOffset_srsconfiguration : fragmentOffset_srsconfiguration+fragmentLength_srsconfiguration] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding srsConfiguration element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding srsConfiguration: %w", err)
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes ULConfiguration from APER format.
func (v *ULConfiguration) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULConfiguration")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULConfiguration")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ULConfiguration) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ULConfiguration{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_timingadvancetype1, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_timingadvancetype2, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "Pci")
	}
	v.Pci = val_pci
	val_ulearfcn, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("65535"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "UlEarfcn")
	}
	v.UlEarfcn = val_ulearfcn
	if opt_timingadvancetype1 {
		val_timingadvancetype1, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(7690), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "TimingAdvanceType1")
		}
		v.TimingAdvanceType1 = &val_timingadvancetype1
	}
	if opt_timingadvancetype2 {
		val_timingadvancetype2, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(7690), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "TimingAdvanceType2")
		}
		v.TimingAdvanceType2 = &val_timingadvancetype2
	}
	val_numberoftransmissions, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("500"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberOfTransmissions")
	}
	v.NumberOfTransmissions = val_numberoftransmissions
	v.SrsConfiguration = make(SRSConfigurationForAllCells, 0)
	_, errCollection_srsconfiguration := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_srsconfiguration, fragmentLength_srsconfiguration int64) error {
		for i := int64(0); i < fragmentLength_srsconfiguration; i++ {
			var elem SRSConfigurationForOneCell
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("SrsConfiguration[%d]", fragmentOffset_srsconfiguration+i))
			}
			v.SrsConfiguration = append(v.SrsConfiguration, elem)
		}
		return nil
	})
	if errCollection_srsconfiguration != nil {
		return runtime.WrapDecodePath(errCollection_srsconfiguration, "SrsConfiguration")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERWLANMeasurementQuantitiesListValue struct{ Value WLANMeasurementQuantities }

// WLANMeasurementQuantitiesComplete carries a complete WLANMeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasurementQuantitiesComplete struct {
	Value       WLANMeasurementQuantities
	PERPadding_ per.CompletePadding
}

func (v *WLANMeasurementQuantitiesComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERWLANMeasurementQuantitiesTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *WLANMeasurementQuantitiesComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERWLANMeasurementQuantitiesFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantities")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantities")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERWLANMeasurementQuantities encodes a WLANMeasurementQuantities list to APER.
func MarshalAPERWLANMeasurementQuantities(list WLANMeasurementQuantitiesComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERWLANMeasurementQuantitiesTo appends a WLANMeasurementQuantities list to bb.
func MarshalAPERWLANMeasurementQuantitiesTo(list WLANMeasurementQuantities, bb *per.BitBuffer) error {
	v := asn1cAPERWLANMeasurementQuantitiesListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERWLANMeasurementQuantities decodes a WLANMeasurementQuantities list from APER.
func UnmarshalAPERWLANMeasurementQuantities(data []byte) (WLANMeasurementQuantitiesComplete, error) {
	var value WLANMeasurementQuantitiesComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERWLANMeasurementQuantitiesFrom decodes a WLANMeasurementQuantities list from bb.
func UnmarshalAPERWLANMeasurementQuantitiesFrom(bb *per.BitBuffer) (WLANMeasurementQuantities, error) {
	var v asn1cAPERWLANMeasurementQuantitiesListValue
	if err := unmarshalAPERWLANMeasurementQuantitiesInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERWLANMeasurementQuantitiesInto(v *asn1cAPERWLANMeasurementQuantitiesListValue, bb *per.BitBuffer) error {
	v.Value = make(WLANMeasurementQuantities, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ProtocolIESingleContainer
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes WLANMeasurementQuantitiesItem to APER format.
func (v *WLANMeasurementQuantitiesItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *WLANMeasurementQuantitiesItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.WLANMeasurementQuantitiesValue), 1, true); err != nil {
		return fmt.Errorf("encoding wLANMeasurementQuantitiesValue: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes WLANMeasurementQuantitiesItem from APER format.
func (v *WLANMeasurementQuantitiesItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantitiesItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantitiesItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *WLANMeasurementQuantitiesItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = WLANMeasurementQuantitiesItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_wlanmeasurementquantitiesvalue, err := per.DecodeEnumeratedAligned(bb, 1, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantitiesValue")
	}
	v.WLANMeasurementQuantitiesValue = WLANMeasurementQuantitiesValue(val_wlanmeasurementquantitiesvalue)
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERWLANMeasurementResultListValue struct{ Value WLANMeasurementResult }

// WLANMeasurementResultComplete carries a complete WLANMeasurementResult encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasurementResultComplete struct {
	Value       WLANMeasurementResult
	PERPadding_ per.CompletePadding
}

func (v *WLANMeasurementResultComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERWLANMeasurementResultTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *WLANMeasurementResultComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERWLANMeasurementResultFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementResult")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementResult")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERWLANMeasurementResult encodes a WLANMeasurementResult list to APER.
func MarshalAPERWLANMeasurementResult(list WLANMeasurementResultComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERWLANMeasurementResultTo appends a WLANMeasurementResult list to bb.
func MarshalAPERWLANMeasurementResultTo(list WLANMeasurementResult, bb *per.BitBuffer) error {
	v := asn1cAPERWLANMeasurementResultListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERWLANMeasurementResult decodes a WLANMeasurementResult list from APER.
func UnmarshalAPERWLANMeasurementResult(data []byte) (WLANMeasurementResultComplete, error) {
	var value WLANMeasurementResultComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERWLANMeasurementResultFrom decodes a WLANMeasurementResult list from bb.
func UnmarshalAPERWLANMeasurementResultFrom(bb *per.BitBuffer) (WLANMeasurementResult, error) {
	var v asn1cAPERWLANMeasurementResultListValue
	if err := unmarshalAPERWLANMeasurementResultInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERWLANMeasurementResultInto(v *asn1cAPERWLANMeasurementResultListValue, bb *per.BitBuffer) error {
	v.Value = make(WLANMeasurementResult, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem WLANMeasurementResultItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes WLANMeasurementResultItem to APER format.
func (v *WLANMeasurementResultItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *WLANMeasurementResultItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SSID != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.BSSID != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.HESSID != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.OperatingClass != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.CountryCode != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.WLANChannelList != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.WLANBand != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.WLANRSSI, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("141"), true); err != nil {
		return fmt.Errorf("encoding wLAN-RSSI: %w", err)
	}
	if v.SSID != nil {
		if err := per.EncodeOctetStringAligned(bb, []byte(*v.SSID), 1, 32, true); err != nil {
			return fmt.Errorf("encoding sSID: %w", err)
		}
	}
	if v.BSSID != nil {
		if err := per.EncodeOctetStringAligned(bb, []byte(*v.BSSID), 6, 6, true); err != nil {
			return fmt.Errorf("encoding bSSID: %w", err)
		}
	}
	if v.HESSID != nil {
		if err := per.EncodeOctetStringAligned(bb, []byte(*v.HESSID), 6, 6, true); err != nil {
			return fmt.Errorf("encoding hESSID: %w", err)
		}
	}
	if v.OperatingClass != nil {
		if err := per.EncodeIntegerAligned(bb, int64(*v.OperatingClass), int64Ptr(0), int64Ptr(255), false); err != nil {
			return fmt.Errorf("encoding operatingClass: %w", err)
		}
	}
	if v.CountryCode != nil {
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.CountryCode), 4, true); err != nil {
			return fmt.Errorf("encoding countryCode: %w", err)
		}
	}
	if v.WLANChannelList != nil {
		if err := per.EncodeCollection(bb, int64(len(v.WLANChannelList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_wlanchannellist, fragmentLength_wlanchannellist int64) error {
			for _, elem := range v.WLANChannelList[fragmentOffset_wlanchannellist : fragmentOffset_wlanchannellist+fragmentLength_wlanchannellist] {
				if err := per.EncodeIntegerAligned(bb, int64(elem), int64Ptr(0), int64Ptr(255), false); err != nil {
					return fmt.Errorf("encoding wLANChannelList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding wLANChannelList: %w", err)
		}
	}
	if v.WLANBand != nil {
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.WLANBand), 2, true); err != nil {
			return fmt.Errorf("encoding wLANBand: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes WLANMeasurementResultItem from APER format.
func (v *WLANMeasurementResultItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementResultItem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementResultItem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *WLANMeasurementResultItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = WLANMeasurementResultItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ssid, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_bssid, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_hessid, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_operatingclass, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_countrycode, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_wlanchannellist, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_wlanband, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_wlanrssi, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("141"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANRSSI")
	}
	v.WLANRSSI = val_wlanrssi
	if opt_ssid {
		val_ssid, err := per.DecodeOctetStringAligned(bb, 1, 32, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSID")
		}
		tmp_ssid := SSID(val_ssid)
		v.SSID = &tmp_ssid
	}
	if opt_bssid {
		val_bssid, err := per.DecodeOctetStringAligned(bb, 6, 6, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "BSSID")
		}
		tmp_bssid := BSSID(val_bssid)
		v.BSSID = &tmp_bssid
	}
	if opt_hessid {
		val_hessid, err := per.DecodeOctetStringAligned(bb, 6, 6, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "HESSID")
		}
		tmp_hessid := HESSID(val_hessid)
		v.HESSID = &tmp_hessid
	}
	if opt_operatingclass {
		val_operatingclass, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "OperatingClass")
		}
		tmp_operatingclass := WLANOperatingClass(val_operatingclass)
		v.OperatingClass = &tmp_operatingclass
	}
	if opt_countrycode {
		val_countrycode, err := per.DecodeEnumeratedAligned(bb, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "CountryCode")
		}
		tmp_countrycode := WLANCountryCode(val_countrycode)
		v.CountryCode = &tmp_countrycode
	}
	if opt_wlanchannellist {
		tmp_wlanchannellist := make(WLANChannelList, 0)
		_, errCollection_wlanchannellist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_wlanchannellist, fragmentLength_wlanchannellist int64) error {
			for i := int64(0); i < fragmentLength_wlanchannellist; i++ {
				val, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("WLANChannelList[%d]", fragmentOffset_wlanchannellist+i))
				}
				tmp_wlanchannellist = append(tmp_wlanchannellist, WLANChannel(val))
			}
			return nil
		})
		if errCollection_wlanchannellist != nil {
			return runtime.WrapDecodePath(errCollection_wlanchannellist, "WLANChannelList")
		}
		v.WLANChannelList = tmp_wlanchannellist
	}
	if opt_wlanband {
		val_wlanband, err := per.DecodeEnumeratedAligned(bb, 2, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "WLANBand")
		}
		tmp_wlanband := WLANBand(val_wlanband)
		v.WLANBand = &tmp_wlanband
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERWLANChannelListListValue struct{ Value WLANChannelList }

// WLANChannelListComplete carries a complete WLANChannelList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANChannelListComplete struct {
	Value       WLANChannelList
	PERPadding_ per.CompletePadding
}

func (v *WLANChannelListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERWLANChannelListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *WLANChannelListComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERWLANChannelListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANChannelList")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANChannelList")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERWLANChannelList encodes a WLANChannelList list to APER.
func MarshalAPERWLANChannelList(list WLANChannelListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERWLANChannelListTo appends a WLANChannelList list to bb.
func MarshalAPERWLANChannelListTo(list WLANChannelList, bb *per.BitBuffer) error {
	v := asn1cAPERWLANChannelListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := per.EncodeIntegerAligned(bb, int64(elem), int64Ptr(0), int64Ptr(255), false); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERWLANChannelList decodes a WLANChannelList list from APER.
func UnmarshalAPERWLANChannelList(data []byte) (WLANChannelListComplete, error) {
	var value WLANChannelListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERWLANChannelListFrom decodes a WLANChannelList list from bb.
func UnmarshalAPERWLANChannelListFrom(bb *per.BitBuffer) (WLANChannelList, error) {
	var v asn1cAPERWLANChannelListListValue
	if err := unmarshalAPERWLANChannelListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERWLANChannelListInto(v *asn1cAPERWLANChannelListListValue, bb *per.BitBuffer) error {
	v.Value = make(WLANChannelList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, WLANChannel(val))
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes AddOTDOACellsElem to APER format.
func (v *AddOTDOACellsElem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *AddOTDOACellsElem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.AddOTDOACellInfo)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_addotdoacellinfo, fragmentLength_addotdoacellinfo int64) error {
		for _, elem := range v.AddOTDOACellInfo[fragmentOffset_addotdoacellinfo : fragmentOffset_addotdoacellinfo+fragmentLength_addotdoacellinfo] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding add-OTDOACellInfo element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding add-OTDOACellInfo: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes AddOTDOACellsElem from APER format.
func (v *AddOTDOACellsElem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACellsElem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACellsElem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *AddOTDOACellsElem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = AddOTDOACellsElem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.AddOTDOACellInfo = make(AddOTDOACellInformation, 0)
	_, errCollection_addotdoacellinfo := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_addotdoacellinfo, fragmentLength_addotdoacellinfo int64) error {
		for i := int64(0); i < fragmentLength_addotdoacellinfo; i++ {
			var elem OTDOACellInformationItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("AddOTDOACellInfo[%d]", fragmentOffset_addotdoacellinfo+i))
			}
			v.AddOTDOACellInfo = append(v.AddOTDOACellInfo, elem)
		}
		return nil
	})
	if errCollection_addotdoacellinfo != nil {
		return runtime.WrapDecodePath(errCollection_addotdoacellinfo, "AddOTDOACellInfo")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes AssistanceInformationFailureListElem to APER format.
func (v *AssistanceInformationFailureListElem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *AssistanceInformationFailureListElem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.PosSIBType), 27, true); err != nil {
		return fmt.Errorf("encoding posSIB-Type: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Outcome), 1, true); err != nil {
		return fmt.Errorf("encoding outcome: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes AssistanceInformationFailureListElem from APER format.
func (v *AssistanceInformationFailureListElem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFailureListElem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFailureListElem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *AssistanceInformationFailureListElem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = AssistanceInformationFailureListElem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_possibtype, err := per.DecodeEnumeratedAligned(bb, 27, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBType")
	}
	v.PosSIBType = PosSIBType(val_possibtype)
	val_outcome, err := per.DecodeEnumeratedAligned(bb, 1, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "Outcome")
	}
	v.Outcome = Outcome(val_outcome)
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes CriticalityDiagnosticsIEListElem to APER format.
func (v *CriticalityDiagnosticsIEListElem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *CriticalityDiagnosticsIEListElem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.IECriticality), 3, false); err != nil {
		return fmt.Errorf("encoding iECriticality: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.IEID), int64Ptr(0), int64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding iE-ID: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.TypeOfError), 2, true); err != nil {
		return fmt.Errorf("encoding typeOfError: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes CriticalityDiagnosticsIEListElem from APER format.
func (v *CriticalityDiagnosticsIEListElem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEListElem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEListElem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *CriticalityDiagnosticsIEListElem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CriticalityDiagnosticsIEListElem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_iecriticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "IECriticality")
	}
	v.IECriticality = Criticality(val_iecriticality)
	val_ieid, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "IEID")
	}
	v.IEID = ProtocolIEID(val_ieid)
	val_typeoferror, err := per.DecodeEnumeratedAligned(bb, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TypeOfError")
	}
	v.TypeOfError = TypeOfError(val_typeoferror)
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes OTDOACellsElem to APER format.
func (v *OTDOACellsElem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *OTDOACellsElem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.OTDOACellInfo)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_otdoacellinfo, fragmentLength_otdoacellinfo int64) error {
		for _, elem := range v.OTDOACellInfo[fragmentOffset_otdoacellinfo : fragmentOffset_otdoacellinfo+fragmentLength_otdoacellinfo] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding oTDOACellInfo element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding oTDOACellInfo: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes OTDOACellsElem from APER format.
func (v *OTDOACellsElem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellsElem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellsElem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *OTDOACellsElem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = OTDOACellsElem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.OTDOACellInfo = make(OTDOACellInformation, 0)
	_, errCollection_otdoacellinfo := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_otdoacellinfo, fragmentLength_otdoacellinfo int64) error {
		for i := int64(0); i < fragmentLength_otdoacellinfo; i++ {
			var elem OTDOACellInformationItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOACellInfo[%d]", fragmentOffset_otdoacellinfo+i))
			}
			v.OTDOACellInfo = append(v.OTDOACellInfo, elem)
		}
		return nil
	})
	if errCollection_otdoacellinfo != nil {
		return runtime.WrapDecodePath(errCollection_otdoacellinfo, "OTDOACellInfo")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes PosSIBsElem to APER format.
func (v *PosSIBsElem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *PosSIBsElem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AssistanceInformationMetaData != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.BroadcastPriority != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.PosSIBType), 27, true); err != nil {
		return fmt.Errorf("encoding posSIB-Type: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.PosSIBSegments)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_possibsegments, fragmentLength_possibsegments int64) error {
		for _, elem := range v.PosSIBSegments[fragmentOffset_possibsegments : fragmentOffset_possibsegments+fragmentLength_possibsegments] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding posSIB-Segments element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding posSIB-Segments: %w", err)
	}
	if v.AssistanceInformationMetaData != nil {
		if err := v.AssistanceInformationMetaData.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding assistanceInformationMetaData: %w", err)
		}
	}
	if v.BroadcastPriority != nil {
		if err := per.EncodeIntegerBigBoundsAligned(bb, v.BroadcastPriority, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("16"), true); err != nil {
			return fmt.Errorf("encoding broadcastPriority: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes PosSIBsElem from APER format.
func (v *PosSIBsElem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PosSIBsElem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBsElem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *PosSIBsElem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PosSIBsElem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_assistanceinformationmetadata, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_broadcastpriority, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_possibtype, err := per.DecodeEnumeratedAligned(bb, 27, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBType")
	}
	v.PosSIBType = PosSIBType(val_possibtype)
	v.PosSIBSegments = make(PosSIBSegments, 0)
	_, errCollection_possibsegments := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_possibsegments, fragmentLength_possibsegments int64) error {
		for i := int64(0); i < fragmentLength_possibsegments; i++ {
			var elem PosSIBSegmentsElem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PosSIBSegments[%d]", fragmentOffset_possibsegments+i))
			}
			v.PosSIBSegments = append(v.PosSIBSegments, elem)
		}
		return nil
	})
	if errCollection_possibsegments != nil {
		return runtime.WrapDecodePath(errCollection_possibsegments, "PosSIBSegments")
	}
	if opt_assistanceinformationmetadata {
		var dec_assistanceinformationmetadata AssistanceInformationMetaData
		if err := dec_assistanceinformationmetadata.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AssistanceInformationMetaData")
		}
		v.AssistanceInformationMetaData = &dec_assistanceinformationmetadata
	}
	if opt_broadcastpriority {
		val_broadcastpriority, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("16"), true)
		if err != nil {
			return runtime.WrapDecodePath(err, "BroadcastPriority")
		}
		v.BroadcastPriority = val_broadcastpriority
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes PosSIBSegmentsElem to APER format.
func (v *PosSIBSegmentsElem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *PosSIBSegmentsElem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeOctetStringAligned(bb, v.AssistanceDataSIBelement, 0, 0, false); err != nil {
		return fmt.Errorf("encoding assistanceDataSIBelement: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes PosSIBSegmentsElem from APER format.
func (v *PosSIBSegmentsElem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PosSIBSegmentsElem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBSegmentsElem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *PosSIBSegmentsElem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PosSIBSegmentsElem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_assistancedatasibelement, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataSIBelement")
	}
	v.AssistanceDataSIBelement = val_assistancedatasibelement
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERPRSFrequencyHoppingConfigurationBandPositionsListValue struct {
	Value PRSFrequencyHoppingConfigurationBandPositions
}

// PRSFrequencyHoppingConfigurationBandPositionsComplete carries a complete PRSFrequencyHoppingConfigurationBandPositions encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PRSFrequencyHoppingConfigurationBandPositionsComplete struct {
	Value       PRSFrequencyHoppingConfigurationBandPositions
	PERPadding_ per.CompletePadding
}

func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERPRSFrequencyHoppingConfigurationBandPositionsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositionsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PRSFrequencyHoppingConfigurationBandPositions")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PRSFrequencyHoppingConfigurationBandPositions")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERPRSFrequencyHoppingConfigurationBandPositions encodes a PRSFrequencyHoppingConfigurationBandPositions list to APER.
func MarshalAPERPRSFrequencyHoppingConfigurationBandPositions(list PRSFrequencyHoppingConfigurationBandPositionsComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERPRSFrequencyHoppingConfigurationBandPositionsTo appends a PRSFrequencyHoppingConfigurationBandPositions list to bb.
func MarshalAPERPRSFrequencyHoppingConfigurationBandPositionsTo(list PRSFrequencyHoppingConfigurationBandPositions, bb *per.BitBuffer) error {
	v := asn1cAPERPRSFrequencyHoppingConfigurationBandPositionsListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 7, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := per.EncodeIntegerBigBoundsAligned(bb, elem, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions decodes a PRSFrequencyHoppingConfigurationBandPositions list from APER.
func UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions(data []byte) (PRSFrequencyHoppingConfigurationBandPositionsComplete, error) {
	var value PRSFrequencyHoppingConfigurationBandPositionsComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositionsFrom decodes a PRSFrequencyHoppingConfigurationBandPositions list from bb.
func UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositionsFrom(bb *per.BitBuffer) (PRSFrequencyHoppingConfigurationBandPositions, error) {
	var v asn1cAPERPRSFrequencyHoppingConfigurationBandPositionsListValue
	if err := unmarshalAPERPRSFrequencyHoppingConfigurationBandPositionsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERPRSFrequencyHoppingConfigurationBandPositionsInto(v *asn1cAPERPRSFrequencyHoppingConfigurationBandPositionsListValue, bb *per.BitBuffer) error {
	v.Value = make(PRSFrequencyHoppingConfigurationBandPositions, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 7, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, val)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ResultUTRANItemPhysCellIDUTRAN to APER format.
func (v *ResultUTRANItemPhysCellIDUTRAN) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ResultUTRANItemPhysCellIDUTRAN) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD:
		if err := per.EncodeIntegerBigBoundsAligned(bb, v.PhysCellIDUTRAFDD, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("511"), true); err != nil {
			return fmt.Errorf("encoding physCellIDUTRA-FDD: %w", err)
		}
	case ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD:
		if err := per.EncodeIntegerBigBoundsAligned(bb, v.PhysCellIDUTRATDD, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("127"), true); err != nil {
			return fmt.Errorf("encoding physCellIDUTRA-TDD: %w", err)
		}
	default:
		return fmt.Errorf("unknown ResultUTRANItemPhysCellIDUTRAN choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes ResultUTRANItemPhysCellIDUTRAN from APER format.
func (v *ResultUTRANItemPhysCellIDUTRAN) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *ResultUTRANItemPhysCellIDUTRAN) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ResultUTRANItemPhysCellIDUTRAN{}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD:
		val_physcellidutrafdd, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("511"), true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PhysCellIDUTRAFDD")
		}
		v.PhysCellIDUTRAFDD = val_physcellidutrafdd
	case ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD:
		val_physcellidutratdd, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("127"), true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PhysCellIDUTRATDD")
		}
		v.PhysCellIDUTRATDD = val_physcellidutratdd
	}
	return nil
}

// MarshalAPER encodes SystemInformationElem to APER format.
func (v *SystemInformationElem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *SystemInformationElem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.BroadcastPeriodicity), 7, true); err != nil {
		return fmt.Errorf("encoding broadcastPeriodicity: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.PosSIBs)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_possibs, fragmentLength_possibs int64) error {
		for _, elem := range v.PosSIBs[fragmentOffset_possibs : fragmentOffset_possibs+fragmentLength_possibs] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding posSIBs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding posSIBs: %w", err)
	}
	if v.IEExtensions != nil {
		if err := per.EncodeCollection(bb, int64(len(v.IEExtensions)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalAPER decodes SystemInformationElem from APER format.
func (v *SystemInformationElem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SystemInformationElem")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SystemInformationElem")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *SystemInformationElem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = SystemInformationElem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_broadcastperiodicity, err := per.DecodeEnumeratedAligned(bb, 7, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "BroadcastPeriodicity")
	}
	v.BroadcastPeriodicity = BroadcastPeriodicity(val_broadcastperiodicity)
	v.PosSIBs = make(PosSIBs, 0)
	_, errCollection_possibs := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_possibs, fragmentLength_possibs int64) error {
		for i := int64(0); i < fragmentLength_possibs; i++ {
			var elem PosSIBsElem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PosSIBs[%d]", fragmentOffset_possibs+i))
			}
			v.PosSIBs = append(v.PosSIBs, elem)
		}
		return nil
	})
	if errCollection_possibs != nil {
		return runtime.WrapDecodePath(errCollection_possibs, "PosSIBs")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ProtocolExtensionContainer, 0)
		_, errCollection_ieextensions := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ProtocolExtensionField
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				tmp_ieextensions = append(tmp_ieextensions, elem)
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}
