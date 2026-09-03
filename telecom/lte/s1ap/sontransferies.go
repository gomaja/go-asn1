// Code generated from ASN.1 module "SonTransfer-IEs". DO NOT EDIT.

package s1ap

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

const (

	// MaxnoofIRATReportingCells is the integer constant for maxnoofIRATReportingCells.
	MaxnoofIRATReportingCells int64 = 128

	// MaxnoofcandidateCells is the integer constant for maxnoofcandidateCells.
	MaxnoofcandidateCells int64 = 16

	// MaxnoofCellineNB is the integer constant for maxnoofCellineNB.
	MaxnoofCellineNB int64 = 256
)

// SONtransferApplicationIdentity represents the ASN.1 ENUMERATED type SONtransferApplicationIdentity.
type SONtransferApplicationIdentity int64

const (
	SONtransferApplicationIdentityCellLoadReporting               SONtransferApplicationIdentity = 0
	SONtransferApplicationIdentityMultiCellLoadReporting          SONtransferApplicationIdentity = 1
	SONtransferApplicationIdentityEventTriggeredCellLoadReporting SONtransferApplicationIdentity = 2
	SONtransferApplicationIdentityHoReporting                     SONtransferApplicationIdentity = 3
	SONtransferApplicationIdentityEutranCellActivation            SONtransferApplicationIdentity = 4
	SONtransferApplicationIdentityEnergySavingsIndication         SONtransferApplicationIdentity = 5
	SONtransferApplicationIdentityFailureEventReporting           SONtransferApplicationIdentity = 6
)

func (v SONtransferApplicationIdentity) String() string {
	switch v {
	case SONtransferApplicationIdentityCellLoadReporting:
		return "cell-load-reporting"
	case SONtransferApplicationIdentityMultiCellLoadReporting:
		return "multi-cell-load-reporting"
	case SONtransferApplicationIdentityEventTriggeredCellLoadReporting:
		return "event-triggered-cell-load-reporting"
	case SONtransferApplicationIdentityHoReporting:
		return "ho-reporting"
	case SONtransferApplicationIdentityEutranCellActivation:
		return "eutran-cell-activation"
	case SONtransferApplicationIdentityEnergySavingsIndication:
		return "energy-savings-indication"
	case SONtransferApplicationIdentityFailureEventReporting:
		return "failure-event-reporting"
	default:
		return "unknown"
	}
}

// SONtransferRequestContainer choice constants.
const (
	SONtransferRequestContainerChoiceCellLoadReporting               = 1
	SONtransferRequestContainerChoiceMultiCellLoadReporting          = 2
	SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting = 3
	SONtransferRequestContainerChoiceHOReporting                     = 4
	SONtransferRequestContainerChoiceEutranCellActivation            = 5
	SONtransferRequestContainerChoiceEnergySavingsIndication         = 6
	SONtransferRequestContainerChoiceFailureEventReporting           = 7
)

// SONtransferRequestContainer represents the ASN.1 CHOICE type SONtransferRequestContainer.
type SONtransferRequestContainer struct {
	Choice                          int
	UnknownExtension                *runtime.PERChoiceExtension             `json:"UnknownExtension,omitempty"`
	CellLoadReporting               *struct{}                               `json:"CellLoadReporting,omitempty"`
	MultiCellLoadReporting          *MultiCellLoadReportingRequest          `json:"MultiCellLoadReporting,omitempty"`
	EventTriggeredCellLoadReporting *EventTriggeredCellLoadReportingRequest `json:"EventTriggeredCellLoadReporting,omitempty"`
	HOReporting                     *HOReport                               `json:"HOReporting,omitempty"`
	EutranCellActivation            *CellActivationRequest                  `json:"EutranCellActivation,omitempty"`
	EnergySavingsIndication         *CellStateIndication                    `json:"EnergySavingsIndication,omitempty"`
	FailureEventReporting           *FailureEventReport                     `json:"FailureEventReporting,omitempty"`
}

// NewSONtransferRequestContainerCellLoadReporting creates a SONtransferRequestContainer with the cellLoadReporting alternative.
func NewSONtransferRequestContainerCellLoadReporting(v struct{}) SONtransferRequestContainer {
	return SONtransferRequestContainer{
		Choice:            SONtransferRequestContainerChoiceCellLoadReporting,
		CellLoadReporting: &v,
	}
}

// NewSONtransferRequestContainerMultiCellLoadReporting creates a SONtransferRequestContainer with the multiCellLoadReporting alternative.
func NewSONtransferRequestContainerMultiCellLoadReporting(v MultiCellLoadReportingRequest) SONtransferRequestContainer {
	return SONtransferRequestContainer{
		Choice:                 SONtransferRequestContainerChoiceMultiCellLoadReporting,
		MultiCellLoadReporting: &v,
	}
}

// NewSONtransferRequestContainerEventTriggeredCellLoadReporting creates a SONtransferRequestContainer with the eventTriggeredCellLoadReporting alternative.
func NewSONtransferRequestContainerEventTriggeredCellLoadReporting(v EventTriggeredCellLoadReportingRequest) SONtransferRequestContainer {
	return SONtransferRequestContainer{
		Choice:                          SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting,
		EventTriggeredCellLoadReporting: &v,
	}
}

// NewSONtransferRequestContainerHOReporting creates a SONtransferRequestContainer with the hOReporting alternative.
func NewSONtransferRequestContainerHOReporting(v HOReport) SONtransferRequestContainer {
	return SONtransferRequestContainer{
		Choice:      SONtransferRequestContainerChoiceHOReporting,
		HOReporting: &v,
	}
}

// NewSONtransferRequestContainerEutranCellActivation creates a SONtransferRequestContainer with the eutranCellActivation alternative.
func NewSONtransferRequestContainerEutranCellActivation(v CellActivationRequest) SONtransferRequestContainer {
	return SONtransferRequestContainer{
		Choice:               SONtransferRequestContainerChoiceEutranCellActivation,
		EutranCellActivation: &v,
	}
}

// NewSONtransferRequestContainerEnergySavingsIndication creates a SONtransferRequestContainer with the energySavingsIndication alternative.
func NewSONtransferRequestContainerEnergySavingsIndication(v CellStateIndication) SONtransferRequestContainer {
	return SONtransferRequestContainer{
		Choice:                  SONtransferRequestContainerChoiceEnergySavingsIndication,
		EnergySavingsIndication: &v,
	}
}

// NewSONtransferRequestContainerFailureEventReporting creates a SONtransferRequestContainer with the failureEventReporting alternative.
func NewSONtransferRequestContainerFailureEventReporting(v FailureEventReport) SONtransferRequestContainer {
	return SONtransferRequestContainer{
		Choice:                SONtransferRequestContainerChoiceFailureEventReporting,
		FailureEventReporting: &v,
	}
}

// SONtransferResponseContainer choice constants.
const (
	SONtransferResponseContainerChoiceCellLoadReporting               = 1
	SONtransferResponseContainerChoiceMultiCellLoadReporting          = 2
	SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting = 3
	SONtransferResponseContainerChoiceHOReporting                     = 4
	SONtransferResponseContainerChoiceEutranCellActivation            = 5
	SONtransferResponseContainerChoiceEnergySavingsIndication         = 6
	SONtransferResponseContainerChoiceFailureEventReporting           = 7
)

// SONtransferResponseContainer represents the ASN.1 CHOICE type SONtransferResponseContainer.
type SONtransferResponseContainer struct {
	Choice                          int
	UnknownExtension                *runtime.PERChoiceExtension              `json:"UnknownExtension,omitempty"`
	CellLoadReporting               *CellLoadReportingResponse               `json:"CellLoadReporting,omitempty"`
	MultiCellLoadReporting          MultiCellLoadReportingResponse           `json:"MultiCellLoadReporting,omitempty"`
	EventTriggeredCellLoadReporting *EventTriggeredCellLoadReportingResponse `json:"EventTriggeredCellLoadReporting,omitempty"`
	HOReporting                     *struct{}                                `json:"HOReporting,omitempty"`
	EutranCellActivation            *CellActivationResponse                  `json:"EutranCellActivation,omitempty"`
	EnergySavingsIndication         *struct{}                                `json:"EnergySavingsIndication,omitempty"`
	FailureEventReporting           *struct{}                                `json:"FailureEventReporting,omitempty"`
}

// NewSONtransferResponseContainerCellLoadReporting creates a SONtransferResponseContainer with the cellLoadReporting alternative.
func NewSONtransferResponseContainerCellLoadReporting(v CellLoadReportingResponse) SONtransferResponseContainer {
	return SONtransferResponseContainer{
		Choice:            SONtransferResponseContainerChoiceCellLoadReporting,
		CellLoadReporting: &v,
	}
}

// NewSONtransferResponseContainerMultiCellLoadReporting creates a SONtransferResponseContainer with the multiCellLoadReporting alternative.
func NewSONtransferResponseContainerMultiCellLoadReporting(v MultiCellLoadReportingResponse) SONtransferResponseContainer {
	return SONtransferResponseContainer{
		Choice:                 SONtransferResponseContainerChoiceMultiCellLoadReporting,
		MultiCellLoadReporting: v,
	}
}

// NewSONtransferResponseContainerEventTriggeredCellLoadReporting creates a SONtransferResponseContainer with the eventTriggeredCellLoadReporting alternative.
func NewSONtransferResponseContainerEventTriggeredCellLoadReporting(v EventTriggeredCellLoadReportingResponse) SONtransferResponseContainer {
	return SONtransferResponseContainer{
		Choice:                          SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting,
		EventTriggeredCellLoadReporting: &v,
	}
}

// NewSONtransferResponseContainerHOReporting creates a SONtransferResponseContainer with the hOReporting alternative.
func NewSONtransferResponseContainerHOReporting(v struct{}) SONtransferResponseContainer {
	return SONtransferResponseContainer{
		Choice:      SONtransferResponseContainerChoiceHOReporting,
		HOReporting: &v,
	}
}

// NewSONtransferResponseContainerEutranCellActivation creates a SONtransferResponseContainer with the eutranCellActivation alternative.
func NewSONtransferResponseContainerEutranCellActivation(v CellActivationResponse) SONtransferResponseContainer {
	return SONtransferResponseContainer{
		Choice:               SONtransferResponseContainerChoiceEutranCellActivation,
		EutranCellActivation: &v,
	}
}

// NewSONtransferResponseContainerEnergySavingsIndication creates a SONtransferResponseContainer with the energySavingsIndication alternative.
func NewSONtransferResponseContainerEnergySavingsIndication(v struct{}) SONtransferResponseContainer {
	return SONtransferResponseContainer{
		Choice:                  SONtransferResponseContainerChoiceEnergySavingsIndication,
		EnergySavingsIndication: &v,
	}
}

// NewSONtransferResponseContainerFailureEventReporting creates a SONtransferResponseContainer with the failureEventReporting alternative.
func NewSONtransferResponseContainerFailureEventReporting(v struct{}) SONtransferResponseContainer {
	return SONtransferResponseContainer{
		Choice:                SONtransferResponseContainerChoiceFailureEventReporting,
		FailureEventReporting: &v,
	}
}

// SONtransferCause choice constants.
const (
	SONtransferCauseChoiceCellLoadReporting               = 1
	SONtransferCauseChoiceMultiCellLoadReporting          = 2
	SONtransferCauseChoiceEventTriggeredCellLoadReporting = 3
	SONtransferCauseChoiceHOReporting                     = 4
	SONtransferCauseChoiceEutranCellActivation            = 5
	SONtransferCauseChoiceEnergySavingsIndication         = 6
	SONtransferCauseChoiceFailureEventReporting           = 7
)

// SONtransferCause represents the ASN.1 CHOICE type SONtransferCause.
type SONtransferCause struct {
	Choice                          int
	UnknownExtension                *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	CellLoadReporting               *CellLoadReportingCause     `json:"CellLoadReporting,omitempty"`
	MultiCellLoadReporting          *CellLoadReportingCause     `json:"MultiCellLoadReporting,omitempty"`
	EventTriggeredCellLoadReporting *CellLoadReportingCause     `json:"EventTriggeredCellLoadReporting,omitempty"`
	HOReporting                     *HOReportingCause           `json:"HOReporting,omitempty"`
	EutranCellActivation            *CellActivationCause        `json:"EutranCellActivation,omitempty"`
	EnergySavingsIndication         *CellStateIndicationCause   `json:"EnergySavingsIndication,omitempty"`
	FailureEventReporting           *FailureEventReportingCause `json:"FailureEventReporting,omitempty"`
}

// NewSONtransferCauseCellLoadReporting creates a SONtransferCause with the cellLoadReporting alternative.
func NewSONtransferCauseCellLoadReporting(v CellLoadReportingCause) SONtransferCause {
	return SONtransferCause{
		Choice:            SONtransferCauseChoiceCellLoadReporting,
		CellLoadReporting: &v,
	}
}

// NewSONtransferCauseMultiCellLoadReporting creates a SONtransferCause with the multiCellLoadReporting alternative.
func NewSONtransferCauseMultiCellLoadReporting(v CellLoadReportingCause) SONtransferCause {
	return SONtransferCause{
		Choice:                 SONtransferCauseChoiceMultiCellLoadReporting,
		MultiCellLoadReporting: &v,
	}
}

// NewSONtransferCauseEventTriggeredCellLoadReporting creates a SONtransferCause with the eventTriggeredCellLoadReporting alternative.
func NewSONtransferCauseEventTriggeredCellLoadReporting(v CellLoadReportingCause) SONtransferCause {
	return SONtransferCause{
		Choice:                          SONtransferCauseChoiceEventTriggeredCellLoadReporting,
		EventTriggeredCellLoadReporting: &v,
	}
}

// NewSONtransferCauseHOReporting creates a SONtransferCause with the hOReporting alternative.
func NewSONtransferCauseHOReporting(v HOReportingCause) SONtransferCause {
	return SONtransferCause{
		Choice:      SONtransferCauseChoiceHOReporting,
		HOReporting: &v,
	}
}

// NewSONtransferCauseEutranCellActivation creates a SONtransferCause with the eutranCellActivation alternative.
func NewSONtransferCauseEutranCellActivation(v CellActivationCause) SONtransferCause {
	return SONtransferCause{
		Choice:               SONtransferCauseChoiceEutranCellActivation,
		EutranCellActivation: &v,
	}
}

// NewSONtransferCauseEnergySavingsIndication creates a SONtransferCause with the energySavingsIndication alternative.
func NewSONtransferCauseEnergySavingsIndication(v CellStateIndicationCause) SONtransferCause {
	return SONtransferCause{
		Choice:                  SONtransferCauseChoiceEnergySavingsIndication,
		EnergySavingsIndication: &v,
	}
}

// NewSONtransferCauseFailureEventReporting creates a SONtransferCause with the failureEventReporting alternative.
func NewSONtransferCauseFailureEventReporting(v FailureEventReportingCause) SONtransferCause {
	return SONtransferCause{
		Choice:                SONtransferCauseChoiceFailureEventReporting,
		FailureEventReporting: &v,
	}
}

// CellLoadReportingCause represents the ASN.1 ENUMERATED type CellLoadReportingCause.
type CellLoadReportingCause int64

const (
	CellLoadReportingCauseApplicationContainerSyntaxError     CellLoadReportingCause = 0
	CellLoadReportingCauseInconsistentReportingCellIdentifier CellLoadReportingCause = 1
	CellLoadReportingCauseUnspecified                         CellLoadReportingCause = 2
)

func (v CellLoadReportingCause) String() string {
	switch v {
	case CellLoadReportingCauseApplicationContainerSyntaxError:
		return "application-container-syntax-error"
	case CellLoadReportingCauseInconsistentReportingCellIdentifier:
		return "inconsistent-reporting-cell-identifier"
	case CellLoadReportingCauseUnspecified:
		return "unspecified"
	default:
		return "unknown"
	}
}

// HOReportingCause represents the ASN.1 ENUMERATED type HOReportingCause.
type HOReportingCause int64

const (
	HOReportingCauseApplicationContainerSyntaxError     HOReportingCause = 0
	HOReportingCauseInconsistentReportingCellIdentifier HOReportingCause = 1
	HOReportingCauseUnspecified                         HOReportingCause = 2
)

func (v HOReportingCause) String() string {
	switch v {
	case HOReportingCauseApplicationContainerSyntaxError:
		return "application-container-syntax-error"
	case HOReportingCauseInconsistentReportingCellIdentifier:
		return "inconsistent-reporting-cell-identifier"
	case HOReportingCauseUnspecified:
		return "unspecified"
	default:
		return "unknown"
	}
}

// CellActivationCause represents the ASN.1 ENUMERATED type CellActivationCause.
type CellActivationCause int64

const (
	CellActivationCauseApplicationContainerSyntaxError     CellActivationCause = 0
	CellActivationCauseInconsistentReportingCellIdentifier CellActivationCause = 1
	CellActivationCauseUnspecified                         CellActivationCause = 2
)

func (v CellActivationCause) String() string {
	switch v {
	case CellActivationCauseApplicationContainerSyntaxError:
		return "application-container-syntax-error"
	case CellActivationCauseInconsistentReportingCellIdentifier:
		return "inconsistent-reporting-cell-identifier"
	case CellActivationCauseUnspecified:
		return "unspecified"
	default:
		return "unknown"
	}
}

// CellStateIndicationCause represents the ASN.1 ENUMERATED type CellStateIndicationCause.
type CellStateIndicationCause int64

const (
	CellStateIndicationCauseApplicationContainerSyntaxError     CellStateIndicationCause = 0
	CellStateIndicationCauseInconsistentReportingCellIdentifier CellStateIndicationCause = 1
	CellStateIndicationCauseUnspecified                         CellStateIndicationCause = 2
)

func (v CellStateIndicationCause) String() string {
	switch v {
	case CellStateIndicationCauseApplicationContainerSyntaxError:
		return "application-container-syntax-error"
	case CellStateIndicationCauseInconsistentReportingCellIdentifier:
		return "inconsistent-reporting-cell-identifier"
	case CellStateIndicationCauseUnspecified:
		return "unspecified"
	default:
		return "unknown"
	}
}

// FailureEventReportingCause represents the ASN.1 ENUMERATED type FailureEventReportingCause.
type FailureEventReportingCause int64

const (
	FailureEventReportingCauseApplicationContainerSyntaxError     FailureEventReportingCause = 0
	FailureEventReportingCauseInconsistentReportingCellIdentifier FailureEventReportingCause = 1
	FailureEventReportingCauseUnspecified                         FailureEventReportingCause = 2
)

func (v FailureEventReportingCause) String() string {
	switch v {
	case FailureEventReportingCauseApplicationContainerSyntaxError:
		return "application-container-syntax-error"
	case FailureEventReportingCauseInconsistentReportingCellIdentifier:
		return "inconsistent-reporting-cell-identifier"
	case FailureEventReportingCauseUnspecified:
		return "unspecified"
	default:
		return "unknown"
	}
}

// CellLoadReportingResponse choice constants.
const (
	CellLoadReportingResponseChoiceEUTRAN = 1
	CellLoadReportingResponseChoiceUTRAN  = 2
	CellLoadReportingResponseChoiceGERAN  = 3
	CellLoadReportingResponseChoiceEHRPD  = 4
)

// CellLoadReportingResponse represents the ASN.1 CHOICE type CellLoadReportingResponse.
type CellLoadReportingResponse struct {
	Choice           int
	UnknownExtension *runtime.PERChoiceExtension       `json:"UnknownExtension,omitempty"`
	EUTRAN           *EUTRANcellLoadReportingResponse  `json:"EUTRAN,omitempty"`
	UTRAN            []byte                            `json:"UTRAN,omitempty"`
	GERAN            []byte                            `json:"GERAN,omitempty"`
	EHRPD            *EHRPDSectorLoadReportingResponse `json:"EHRPD,omitempty"`
}

// NewCellLoadReportingResponseEUTRAN creates a CellLoadReportingResponse with the eUTRAN alternative.
func NewCellLoadReportingResponseEUTRAN(v EUTRANcellLoadReportingResponse) CellLoadReportingResponse {
	return CellLoadReportingResponse{
		Choice: CellLoadReportingResponseChoiceEUTRAN,
		EUTRAN: &v,
	}
}

// NewCellLoadReportingResponseUTRAN creates a CellLoadReportingResponse with the uTRAN alternative.
func NewCellLoadReportingResponseUTRAN(v []byte) CellLoadReportingResponse {
	return CellLoadReportingResponse{
		Choice: CellLoadReportingResponseChoiceUTRAN,
		UTRAN:  v,
	}
}

// NewCellLoadReportingResponseGERAN creates a CellLoadReportingResponse with the gERAN alternative.
func NewCellLoadReportingResponseGERAN(v []byte) CellLoadReportingResponse {
	return CellLoadReportingResponse{
		Choice: CellLoadReportingResponseChoiceGERAN,
		GERAN:  v,
	}
}

// NewCellLoadReportingResponseEHRPD creates a CellLoadReportingResponse with the eHRPD alternative.
func NewCellLoadReportingResponseEHRPD(v EHRPDSectorLoadReportingResponse) CellLoadReportingResponse {
	return CellLoadReportingResponse{
		Choice: CellLoadReportingResponseChoiceEHRPD,
		EHRPD:  &v,
	}
}

// CompositeAvailableCapacityGroup represents the ASN.1 type CompositeAvailableCapacityGroup (OCTET_STRING).
type CompositeAvailableCapacityGroup = []byte

// EUTRANcellLoadReportingResponse represents the ASN.1 type EUTRANcellLoadReportingResponse (SEQUENCE).
type EUTRANcellLoadReportingResponse struct {
	CompositeAvailableCapacityGroup CompositeAvailableCapacityGroup `asn1:"tag:0,context,implicit"`
	ExtCount_                       int64                           `asn1:"-" json:"-"`
	ExtPresent_                     []bool                          `asn1:"-" json:"-"`
	ExtData_                        [][]byte                        `asn1:"-" json:"-"`
}

// EUTRANResponse represents the ASN.1 type EUTRANResponse (SEQUENCE).
type EUTRANResponse struct {
	CellID                          []byte                          `asn1:"tag:0,context,implicit"`
	EUTRANcellLoadReportingResponse EUTRANcellLoadReportingResponse `asn1:"tag:1,context,implicit"`
	ExtCount_                       int64                           `asn1:"-" json:"-"`
	ExtPresent_                     []bool                          `asn1:"-" json:"-"`
	ExtData_                        [][]byte                        `asn1:"-" json:"-"`
}

// EHRPDSectorID represents the ASN.1 type EHRPD-Sector-ID (OCTET_STRING).
type EHRPDSectorID = []byte

// IRATCellID choice constants.
const (
	IRATCellIDChoiceEUTRAN = 1
	IRATCellIDChoiceUTRAN  = 2
	IRATCellIDChoiceGERAN  = 3
	IRATCellIDChoiceEHRPD  = 4
)

// IRATCellID represents the ASN.1 CHOICE type IRAT-Cell-ID.
type IRATCellID struct {
	Choice           int
	UnknownExtension *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	EUTRAN           []byte                      `json:"EUTRAN,omitempty"`
	UTRAN            []byte                      `json:"UTRAN,omitempty"`
	GERAN            []byte                      `json:"GERAN,omitempty"`
	EHRPD            *EHRPDSectorID              `json:"EHRPD,omitempty"`
}

// NewIRATCellIDEUTRAN creates a IRATCellID with the eUTRAN alternative.
func NewIRATCellIDEUTRAN(v []byte) IRATCellID {
	return IRATCellID{
		Choice: IRATCellIDChoiceEUTRAN,
		EUTRAN: v,
	}
}

// NewIRATCellIDUTRAN creates a IRATCellID with the uTRAN alternative.
func NewIRATCellIDUTRAN(v []byte) IRATCellID {
	return IRATCellID{
		Choice: IRATCellIDChoiceUTRAN,
		UTRAN:  v,
	}
}

// NewIRATCellIDGERAN creates a IRATCellID with the gERAN alternative.
func NewIRATCellIDGERAN(v []byte) IRATCellID {
	return IRATCellID{
		Choice: IRATCellIDChoiceGERAN,
		GERAN:  v,
	}
}

// NewIRATCellIDEHRPD creates a IRATCellID with the eHRPD alternative.
func NewIRATCellIDEHRPD(v EHRPDSectorID) IRATCellID {
	return IRATCellID{
		Choice: IRATCellIDChoiceEHRPD,
		EHRPD:  &v,
	}
}

// RequestedCellList represents the ASN.1 type RequestedCellList (SEQUENCE_OF).
type RequestedCellList = []IRATCellID

// MultiCellLoadReportingRequest represents the ASN.1 type MultiCellLoadReportingRequest (SEQUENCE).
type MultiCellLoadReportingRequest struct {
	RequestedCellList       RequestedCellList `asn1:"tag:0,context,implicit"`
	RequestedCellListIndef_ bool              `asn1:"-" json:"-"`
	ExtCount_               int64             `asn1:"-" json:"-"`
	ExtPresent_             []bool            `asn1:"-" json:"-"`
	ExtData_                [][]byte          `asn1:"-" json:"-"`
}

// ReportingCellListItem represents the ASN.1 type ReportingCellList-Item (SEQUENCE).
type ReportingCellListItem struct {
	CellID      IRATCellID `asn1:"tag:0,context,explicit"`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	ExtData_    [][]byte   `asn1:"-" json:"-"`
}

// ReportingCellList represents the ASN.1 type ReportingCellList (SEQUENCE_OF).
type ReportingCellList = []ReportingCellListItem

// MultiCellLoadReportingResponse represents the ASN.1 type MultiCellLoadReportingResponse (SEQUENCE_OF).
type MultiCellLoadReportingResponse = []MultiCellLoadReportingResponseItem

// MultiCellLoadReportingResponseItem choice constants.
const (
	MultiCellLoadReportingResponseItemChoiceEUTRANResponse = 1
	MultiCellLoadReportingResponseItemChoiceUTRANResponse  = 2
	MultiCellLoadReportingResponseItemChoiceGERANResponse  = 3
	MultiCellLoadReportingResponseItemChoiceEHRPD          = 4
)

// MultiCellLoadReportingResponseItem represents the ASN.1 CHOICE type MultiCellLoadReportingResponse-Item.
type MultiCellLoadReportingResponseItem struct {
	Choice           int
	UnknownExtension *runtime.PERChoiceExtension                `json:"UnknownExtension,omitempty"`
	EUTRANResponse   *EUTRANResponse                            `json:"EUTRANResponse,omitempty"`
	UTRANResponse    []byte                                     `json:"UTRANResponse,omitempty"`
	GERANResponse    []byte                                     `json:"GERANResponse,omitempty"`
	EHRPD            *EHRPDMultiSectorLoadReportingResponseItem `json:"EHRPD,omitempty"`
}

// NewMultiCellLoadReportingResponseItemEUTRANResponse creates a MultiCellLoadReportingResponseItem with the eUTRANResponse alternative.
func NewMultiCellLoadReportingResponseItemEUTRANResponse(v EUTRANResponse) MultiCellLoadReportingResponseItem {
	return MultiCellLoadReportingResponseItem{
		Choice:         MultiCellLoadReportingResponseItemChoiceEUTRANResponse,
		EUTRANResponse: &v,
	}
}

// NewMultiCellLoadReportingResponseItemUTRANResponse creates a MultiCellLoadReportingResponseItem with the uTRANResponse alternative.
func NewMultiCellLoadReportingResponseItemUTRANResponse(v []byte) MultiCellLoadReportingResponseItem {
	return MultiCellLoadReportingResponseItem{
		Choice:        MultiCellLoadReportingResponseItemChoiceUTRANResponse,
		UTRANResponse: v,
	}
}

// NewMultiCellLoadReportingResponseItemGERANResponse creates a MultiCellLoadReportingResponseItem with the gERANResponse alternative.
func NewMultiCellLoadReportingResponseItemGERANResponse(v []byte) MultiCellLoadReportingResponseItem {
	return MultiCellLoadReportingResponseItem{
		Choice:        MultiCellLoadReportingResponseItemChoiceGERANResponse,
		GERANResponse: v,
	}
}

// NewMultiCellLoadReportingResponseItemEHRPD creates a MultiCellLoadReportingResponseItem with the eHRPD alternative.
func NewMultiCellLoadReportingResponseItemEHRPD(v EHRPDMultiSectorLoadReportingResponseItem) MultiCellLoadReportingResponseItem {
	return MultiCellLoadReportingResponseItem{
		Choice: MultiCellLoadReportingResponseItemChoiceEHRPD,
		EHRPD:  &v,
	}
}

// NumberOfMeasurementReportingLevels represents the ASN.1 ENUMERATED type NumberOfMeasurementReportingLevels.
type NumberOfMeasurementReportingLevels int64

const (
	NumberOfMeasurementReportingLevelsRl2  NumberOfMeasurementReportingLevels = 0
	NumberOfMeasurementReportingLevelsRl3  NumberOfMeasurementReportingLevels = 1
	NumberOfMeasurementReportingLevelsRl4  NumberOfMeasurementReportingLevels = 2
	NumberOfMeasurementReportingLevelsRl5  NumberOfMeasurementReportingLevels = 3
	NumberOfMeasurementReportingLevelsRl10 NumberOfMeasurementReportingLevels = 4
)

func (v NumberOfMeasurementReportingLevels) String() string {
	switch v {
	case NumberOfMeasurementReportingLevelsRl2:
		return "rl2"
	case NumberOfMeasurementReportingLevelsRl3:
		return "rl3"
	case NumberOfMeasurementReportingLevelsRl4:
		return "rl4"
	case NumberOfMeasurementReportingLevelsRl5:
		return "rl5"
	case NumberOfMeasurementReportingLevelsRl10:
		return "rl10"
	default:
		return "unknown"
	}
}

// EventTriggeredCellLoadReportingRequest represents the ASN.1 type EventTriggeredCellLoadReportingRequest (SEQUENCE).
type EventTriggeredCellLoadReportingRequest struct {
	NumberOfMeasurementReportingLevels NumberOfMeasurementReportingLevels `asn1:"tag:0,context,implicit"`
	ExtCount_                          int64                              `asn1:"-" json:"-"`
	ExtPresent_                        []bool                             `asn1:"-" json:"-"`
	ExtData_                           [][]byte                           `asn1:"-" json:"-"`
}

// OverloadFlag represents the ASN.1 ENUMERATED type OverloadFlag.
type OverloadFlag int64

const (
	OverloadFlagOverload OverloadFlag = 0
)

func (v OverloadFlag) String() string {
	switch v {
	case OverloadFlagOverload:
		return "overload"
	default:
		return "unknown"
	}
}

// EventTriggeredCellLoadReportingResponse represents the ASN.1 type EventTriggeredCellLoadReportingResponse (SEQUENCE).
type EventTriggeredCellLoadReportingResponse struct {
	CellLoadReportingResponse CellLoadReportingResponse `asn1:"tag:0,context,explicit"`
	OverloadFlag              *OverloadFlag             `asn1:"tag:1,context,implicit,optional" json:"OverloadFlag,omitempty"`
	ExtCount_                 int64                     `asn1:"-" json:"-"`
	ExtPresent_               []bool                    `asn1:"-" json:"-"`
	ExtData_                  [][]byte                  `asn1:"-" json:"-"`
}

// HOReport represents the ASN.1 type HOReport (SEQUENCE).
type HOReport struct {
	HoType                  HoType            `asn1:"tag:0,context,implicit"`
	HoReportType            HoReportType      `asn1:"tag:1,context,implicit"`
	HosourceID              IRATCellID        `asn1:"tag:2,context,explicit"`
	HoTargetID              IRATCellID        `asn1:"tag:3,context,explicit"`
	CandidateCellList       CandidateCellList `asn1:"tag:4,context,implicit"`
	CandidateCellListIndef_ bool              `asn1:"-" json:"-"`
	CandidatePCIList        CandidatePCIList  `asn1:"tag:5,context,implicit,optional" json:"CandidatePCIList,omitempty"`
	CandidatePCIListIndef_  bool              `asn1:"-" json:"-"`
	ExtCount_               int64             `asn1:"-" json:"-"`
	ExtPresent_             []bool            `asn1:"-" json:"-"`
	ExtData_                [][]byte          `asn1:"-" json:"-"`
}

// HoType represents the ASN.1 ENUMERATED type HoType.
type HoType int64

const (
	HoTypeLtetoutran HoType = 0
	HoTypeLtetogeran HoType = 1
)

func (v HoType) String() string {
	switch v {
	case HoTypeLtetoutran:
		return "ltetoutran"
	case HoTypeLtetogeran:
		return "ltetogeran"
	default:
		return "unknown"
	}
}

// HoReportType represents the ASN.1 ENUMERATED type HoReportType.
type HoReportType int64

const (
	HoReportTypeUnnecessaryhotoanotherrat HoReportType = 0
	HoReportTypeEarlyirathandover         HoReportType = 1
)

func (v HoReportType) String() string {
	switch v {
	case HoReportTypeUnnecessaryhotoanotherrat:
		return "unnecessaryhotoanotherrat"
	case HoReportTypeEarlyirathandover:
		return "earlyirathandover"
	default:
		return "unknown"
	}
}

// CandidateCellList represents the ASN.1 type CandidateCellList (SEQUENCE_OF).
type CandidateCellList = []IRATCellID

// CandidatePCIList represents the ASN.1 type CandidatePCIList (SEQUENCE_OF).
type CandidatePCIList = []CandidatePCI

// CandidatePCI represents the ASN.1 type CandidatePCI (SEQUENCE).
type CandidatePCI struct {
	PCI         int64    `asn1:"tag:0,context,implicit"`
	EARFCN      []byte   `asn1:"tag:1,context,implicit"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// CellActivationRequest represents the ASN.1 type CellActivationRequest (SEQUENCE).
type CellActivationRequest struct {
	CellsToActivateList       CellsToActivateList `asn1:"tag:0,context,implicit"`
	CellsToActivateListIndef_ bool                `asn1:"-" json:"-"`
	MinimumActivationTime     *int64              `asn1:"tag:1,context,implicit,optional" json:"MinimumActivationTime,omitempty"`
	ExtCount_                 int64               `asn1:"-" json:"-"`
	ExtPresent_               []bool              `asn1:"-" json:"-"`
	ExtData_                  [][]byte            `asn1:"-" json:"-"`
}

// CellsToActivateList represents the ASN.1 type CellsToActivateList (SEQUENCE_OF).
type CellsToActivateList = []CellsToActivateListItem

// CellsToActivateListItem represents the ASN.1 type CellsToActivateList-Item (SEQUENCE).
type CellsToActivateListItem struct {
	CellID      []byte   `asn1:"tag:0,context,implicit"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// CellActivationResponse represents the ASN.1 type CellActivationResponse (SEQUENCE).
type CellActivationResponse struct {
	ActivatedCellsList       ActivatedCellsList `asn1:"tag:0,context,implicit"`
	ActivatedCellsListIndef_ bool               `asn1:"-" json:"-"`
	ExtCount_                int64              `asn1:"-" json:"-"`
	ExtPresent_              []bool             `asn1:"-" json:"-"`
	ExtData_                 [][]byte           `asn1:"-" json:"-"`
}

// ActivatedCellsList represents the ASN.1 type ActivatedCellsList (SEQUENCE_OF).
type ActivatedCellsList = []ActivatedCellsListItem

// ActivatedCellsListItem represents the ASN.1 type ActivatedCellsList-Item (SEQUENCE).
type ActivatedCellsListItem struct {
	CellID      []byte   `asn1:"tag:0,context,implicit"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// CellStateIndication represents the ASN.1 type CellStateIndication (SEQUENCE).
type CellStateIndication struct {
	NotificationCellList       NotificationCellList `asn1:"tag:0,context,implicit"`
	NotificationCellListIndef_ bool                 `asn1:"-" json:"-"`
	ExtCount_                  int64                `asn1:"-" json:"-"`
	ExtPresent_                []bool               `asn1:"-" json:"-"`
	ExtData_                   [][]byte             `asn1:"-" json:"-"`
}

// NotificationCellList represents the ASN.1 type NotificationCellList (SEQUENCE_OF).
type NotificationCellList = []NotificationCellListItem

// NotificationCellListItem represents the ASN.1 type NotificationCellList-Item (SEQUENCE).
type NotificationCellListItem struct {
	CellID      []byte     `asn1:"tag:0,context,implicit"`
	NotifyFlag  NotifyFlag `asn1:"tag:1,context,implicit"`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	ExtData_    [][]byte   `asn1:"-" json:"-"`
}

// NotifyFlag represents the ASN.1 ENUMERATED type NotifyFlag.
type NotifyFlag int64

const (
	NotifyFlagActivated   NotifyFlag = 0
	NotifyFlagDeactivated NotifyFlag = 1
)

func (v NotifyFlag) String() string {
	switch v {
	case NotifyFlagActivated:
		return "activated"
	case NotifyFlagDeactivated:
		return "deactivated"
	default:
		return "unknown"
	}
}

// FailureEventReport choice constants.
const (
	FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN = 1
)

// FailureEventReport represents the ASN.1 CHOICE type FailureEventReport.
type FailureEventReport struct {
	Choice                             int
	UnknownExtension                   *runtime.PERChoiceExtension               `json:"UnknownExtension,omitempty"`
	TooEarlyInterRATHOReportFromEUTRAN *TooEarlyInterRATHOReportReportFromEUTRAN `json:"TooEarlyInterRATHOReportFromEUTRAN,omitempty"`
}

// NewFailureEventReportTooEarlyInterRATHOReportFromEUTRAN creates a FailureEventReport with the tooEarlyInterRATHOReportFromEUTRAN alternative.
func NewFailureEventReportTooEarlyInterRATHOReportFromEUTRAN(v TooEarlyInterRATHOReportReportFromEUTRAN) FailureEventReport {
	return FailureEventReport{
		Choice:                             FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN,
		TooEarlyInterRATHOReportFromEUTRAN: &v,
	}
}

// TooEarlyInterRATHOReportReportFromEUTRAN represents the ASN.1 type TooEarlyInterRATHOReportReportFromEUTRAN (SEQUENCE).
type TooEarlyInterRATHOReportReportFromEUTRAN struct {
	UERLFReportContainer []byte               `asn1:"tag:0,context,implicit"`
	MobilityInformation  *MobilityInformation `asn1:"tag:1,context,implicit,optional" json:"MobilityInformation,omitempty"`
	ExtCount_            int64                `asn1:"-" json:"-"`
	ExtPresent_          []bool               `asn1:"-" json:"-"`
	ExtData_             [][]byte             `asn1:"-" json:"-"`
}

// EHRPDCapacityValue represents the ASN.1 type EHRPDCapacityValue (INTEGER).
type EHRPDCapacityValue = int64

// EHRPDSectorCapacityClassValue represents the ASN.1 type EHRPDSectorCapacityClassValue (INTEGER).
type EHRPDSectorCapacityClassValue = *big.Int

// EHRPDSectorLoadReportingResponse represents the ASN.1 type EHRPDSectorLoadReportingResponse (SEQUENCE).
type EHRPDSectorLoadReportingResponse struct {
	DLEHRPDCompositeAvailableCapacity EHRPDCompositeAvailableCapacity `asn1:"tag:0,context,implicit"`
	ULEHRPDCompositeAvailableCapacity EHRPDCompositeAvailableCapacity `asn1:"tag:1,context,implicit"`
	ExtCount_                         int64                           `asn1:"-" json:"-"`
	ExtPresent_                       []bool                          `asn1:"-" json:"-"`
	ExtData_                          [][]byte                        `asn1:"-" json:"-"`
}

// EHRPDCompositeAvailableCapacity represents the ASN.1 type EHRPDCompositeAvailableCapacity (SEQUENCE).
type EHRPDCompositeAvailableCapacity struct {
	EHRPDSectorCapacityClassValue EHRPDSectorCapacityClassValue `asn1:"tag:0,context,implicit"`
	EHRPDCapacityValue            EHRPDCapacityValue            `asn1:"tag:1,context,implicit"`
	ExtCount_                     int64                         `asn1:"-" json:"-"`
	ExtPresent_                   []bool                        `asn1:"-" json:"-"`
	ExtData_                      [][]byte                      `asn1:"-" json:"-"`
}

// EHRPDMultiSectorLoadReportingResponseItem represents the ASN.1 type EHRPDMultiSectorLoadReportingResponseItem (SEQUENCE).
type EHRPDMultiSectorLoadReportingResponseItem struct {
	EHRPDSectorID                    EHRPDSectorID                    `asn1:"tag:0,context,implicit"`
	EHRPDSectorLoadReportingResponse EHRPDSectorLoadReportingResponse `asn1:"tag:1,context,implicit"`
	ExtCount_                        int64                            `asn1:"-" json:"-"`
	ExtPresent_                      []bool                           `asn1:"-" json:"-"`
	ExtData_                         [][]byte                         `asn1:"-" json:"-"`
}

// MarshalAPER encodes SONtransferRequestContainer to APER format.
func (v *SONtransferRequestContainer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SONtransferRequestContainer) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("SONtransferRequestContainer: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 6 {
			return fmt.Errorf("SONtransferRequestContainer: extension index %d is known to this schema", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 1
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-1-1)); err != nil {
			return err
		}
		inner := per.NewBitBuffer()
		switch v.Choice {
		case SONtransferRequestContainerChoiceMultiCellLoadReporting:
			if v.MultiCellLoadReporting == nil {
				return fmt.Errorf("choice alternative multiCellLoadReporting is nil")
			}
			if err := v.MultiCellLoadReporting.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding multiCellLoadReporting: %w", err)
			}
		case SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting:
			if v.EventTriggeredCellLoadReporting == nil {
				return fmt.Errorf("choice alternative eventTriggeredCellLoadReporting is nil")
			}
			if err := v.EventTriggeredCellLoadReporting.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding eventTriggeredCellLoadReporting: %w", err)
			}
		case SONtransferRequestContainerChoiceHOReporting:
			if v.HOReporting == nil {
				return fmt.Errorf("choice alternative hOReporting is nil")
			}
			if err := v.HOReporting.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding hOReporting: %w", err)
			}
		case SONtransferRequestContainerChoiceEutranCellActivation:
			if v.EutranCellActivation == nil {
				return fmt.Errorf("choice alternative eutranCellActivation is nil")
			}
			if err := v.EutranCellActivation.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding eutranCellActivation: %w", err)
			}
		case SONtransferRequestContainerChoiceEnergySavingsIndication:
			if v.EnergySavingsIndication == nil {
				return fmt.Errorf("choice alternative energySavingsIndication is nil")
			}
			if err := v.EnergySavingsIndication.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding energySavingsIndication: %w", err)
			}
		case SONtransferRequestContainerChoiceFailureEventReporting:
			if v.FailureEventReporting == nil {
				return fmt.Errorf("choice alternative failureEventReporting is nil")
			}
			if err := v.FailureEventReporting.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding failureEventReporting: %w", err)
			}
		default:
			return fmt.Errorf("unknown SONtransferRequestContainer extension choice %d", v.Choice)
		}
		if err := per.EncodeOpenTypeAligned(bb, inner.Bytes()); err != nil {
			return err
		}
		return nil
	}
	switch v.Choice {
	case SONtransferRequestContainerChoiceCellLoadReporting:
	default:
		return fmt.Errorf("unknown SONtransferRequestContainer choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONtransferRequestContainer from APER format.
func (v *SONtransferRequestContainer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *SONtransferRequestContainer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = SONtransferRequestContainer{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return err
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return err
		}
		if extIdx >= 6 {
			v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
			return nil
		}
		inner := per.NewBitBufferFromBytes(openData)
		v.Choice = int(extIdx) + 1 + 1
		switch v.Choice {
		case SONtransferRequestContainerChoiceMultiCellLoadReporting:
			var dec_multicellloadreporting MultiCellLoadReportingRequest
			if err := dec_multicellloadreporting.UnmarshalAPERFrom(inner); err != nil {
				return fmt.Errorf("decoding multiCellLoadReporting: %w", err)
			}
			v.MultiCellLoadReporting = &dec_multicellloadreporting
		case SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting:
			var dec_eventtriggeredcellloadreporting EventTriggeredCellLoadReportingRequest
			if err := dec_eventtriggeredcellloadreporting.UnmarshalAPERFrom(inner); err != nil {
				return fmt.Errorf("decoding eventTriggeredCellLoadReporting: %w", err)
			}
			v.EventTriggeredCellLoadReporting = &dec_eventtriggeredcellloadreporting
		case SONtransferRequestContainerChoiceHOReporting:
			var dec_horeporting HOReport
			if err := dec_horeporting.UnmarshalAPERFrom(inner); err != nil {
				return fmt.Errorf("decoding hOReporting: %w", err)
			}
			v.HOReporting = &dec_horeporting
		case SONtransferRequestContainerChoiceEutranCellActivation:
			var dec_eutrancellactivation CellActivationRequest
			if err := dec_eutrancellactivation.UnmarshalAPERFrom(inner); err != nil {
				return fmt.Errorf("decoding eutranCellActivation: %w", err)
			}
			v.EutranCellActivation = &dec_eutrancellactivation
		case SONtransferRequestContainerChoiceEnergySavingsIndication:
			var dec_energysavingsindication CellStateIndication
			if err := dec_energysavingsindication.UnmarshalAPERFrom(inner); err != nil {
				return fmt.Errorf("decoding energySavingsIndication: %w", err)
			}
			v.EnergySavingsIndication = &dec_energysavingsindication
		case SONtransferRequestContainerChoiceFailureEventReporting:
			var dec_failureeventreporting FailureEventReport
			if err := dec_failureeventreporting.UnmarshalAPERFrom(inner); err != nil {
				return fmt.Errorf("decoding failureEventReporting: %w", err)
			}
			v.FailureEventReporting = &dec_failureeventreporting
		}
		if err := per.ValidateOpenTypePadding(inner); err != nil {
			return fmt.Errorf("SONtransferRequestContainer: extension choice %d: %w", v.Choice, err)
		}
		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case SONtransferRequestContainerChoiceCellLoadReporting:
	}
	return nil
}

// MarshalAPER encodes SONtransferResponseContainer to APER format.
func (v *SONtransferResponseContainer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SONtransferResponseContainer) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("SONtransferResponseContainer: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 6 {
			return fmt.Errorf("SONtransferResponseContainer: extension index %d is known to this schema", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 1
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-1-1)); err != nil {
			return err
		}
		inner := per.NewBitBuffer()
		switch v.Choice {
		case SONtransferResponseContainerChoiceMultiCellLoadReporting:
			if err := per.EncodeCollection(inner, int64(len(v.MultiCellLoadReporting)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_multicellloadreporting, fragmentLength_multicellloadreporting int64) error {
				for _, elem := range v.MultiCellLoadReporting[fragmentOffset_multicellloadreporting : fragmentOffset_multicellloadreporting+fragmentLength_multicellloadreporting] {
					if err := elem.MarshalAPERTo(inner); err != nil {
						return fmt.Errorf("encoding multiCellLoadReporting element: %w", err)
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("encoding multiCellLoadReporting: %w", err)
			}
		case SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting:
			if v.EventTriggeredCellLoadReporting == nil {
				return fmt.Errorf("choice alternative eventTriggeredCellLoadReporting is nil")
			}
			if err := v.EventTriggeredCellLoadReporting.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding eventTriggeredCellLoadReporting: %w", err)
			}
		case SONtransferResponseContainerChoiceHOReporting:
		case SONtransferResponseContainerChoiceEutranCellActivation:
			if v.EutranCellActivation == nil {
				return fmt.Errorf("choice alternative eutranCellActivation is nil")
			}
			if err := v.EutranCellActivation.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding eutranCellActivation: %w", err)
			}
		case SONtransferResponseContainerChoiceEnergySavingsIndication:
		case SONtransferResponseContainerChoiceFailureEventReporting:
		default:
			return fmt.Errorf("unknown SONtransferResponseContainer extension choice %d", v.Choice)
		}
		if err := per.EncodeOpenTypeAligned(bb, inner.Bytes()); err != nil {
			return err
		}
		return nil
	}
	switch v.Choice {
	case SONtransferResponseContainerChoiceCellLoadReporting:
		if v.CellLoadReporting == nil {
			return fmt.Errorf("choice alternative cellLoadReporting is nil")
		}
		if err := v.CellLoadReporting.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding cellLoadReporting: %w", err)
		}
	default:
		return fmt.Errorf("unknown SONtransferResponseContainer choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONtransferResponseContainer from APER format.
func (v *SONtransferResponseContainer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *SONtransferResponseContainer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = SONtransferResponseContainer{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return err
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return err
		}
		if extIdx >= 6 {
			v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
			return nil
		}
		inner := per.NewBitBufferFromBytes(openData)
		v.Choice = int(extIdx) + 1 + 1
		switch v.Choice {
		case SONtransferResponseContainerChoiceMultiCellLoadReporting:
			tmp_multicellloadreporting := make(MultiCellLoadReportingResponse, 0)
			_, errCollection_multicellloadreporting := per.DecodeCollection(inner, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_multicellloadreporting, fragmentLength_multicellloadreporting int64) error {
				for i := int64(0); i < fragmentLength_multicellloadreporting; i++ {
					var elem MultiCellLoadReportingResponseItem
					if err := elem.UnmarshalAPERFrom(inner); err != nil {
						return fmt.Errorf("decoding multiCellLoadReporting element %d: %w", fragmentOffset_multicellloadreporting+i, err)
					}
					tmp_multicellloadreporting = append(tmp_multicellloadreporting, elem)
				}
				return nil
			})
			if errCollection_multicellloadreporting != nil {
				return fmt.Errorf("decoding multiCellLoadReporting: %w", errCollection_multicellloadreporting)
			}
			v.MultiCellLoadReporting = tmp_multicellloadreporting
		case SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting:
			var dec_eventtriggeredcellloadreporting EventTriggeredCellLoadReportingResponse
			if err := dec_eventtriggeredcellloadreporting.UnmarshalAPERFrom(inner); err != nil {
				return fmt.Errorf("decoding eventTriggeredCellLoadReporting: %w", err)
			}
			v.EventTriggeredCellLoadReporting = &dec_eventtriggeredcellloadreporting
		case SONtransferResponseContainerChoiceHOReporting:
		case SONtransferResponseContainerChoiceEutranCellActivation:
			var dec_eutrancellactivation CellActivationResponse
			if err := dec_eutrancellactivation.UnmarshalAPERFrom(inner); err != nil {
				return fmt.Errorf("decoding eutranCellActivation: %w", err)
			}
			v.EutranCellActivation = &dec_eutrancellactivation
		case SONtransferResponseContainerChoiceEnergySavingsIndication:
		case SONtransferResponseContainerChoiceFailureEventReporting:
		}
		if err := per.ValidateOpenTypePadding(inner); err != nil {
			return fmt.Errorf("SONtransferResponseContainer: extension choice %d: %w", v.Choice, err)
		}
		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case SONtransferResponseContainerChoiceCellLoadReporting:
		var dec_cellloadreporting CellLoadReportingResponse
		if err := dec_cellloadreporting.UnmarshalAPERFrom(bb); err != nil {
			return fmt.Errorf("decoding cellLoadReporting: %w", err)
		}
		v.CellLoadReporting = &dec_cellloadreporting
	}
	return nil
}

// MarshalAPER encodes SONtransferCause to APER format.
func (v *SONtransferCause) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SONtransferCause) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("SONtransferCause: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 6 {
			return fmt.Errorf("SONtransferCause: extension index %d is known to this schema", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 1
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-1-1)); err != nil {
			return err
		}
		inner := per.NewBitBuffer()
		switch v.Choice {
		case SONtransferCauseChoiceMultiCellLoadReporting:
			if v.MultiCellLoadReporting == nil {
				return fmt.Errorf("choice alternative multiCellLoadReporting is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.MultiCellLoadReporting), 3, true); err != nil {
				return fmt.Errorf("encoding multiCellLoadReporting: %w", err)
			}
		case SONtransferCauseChoiceEventTriggeredCellLoadReporting:
			if v.EventTriggeredCellLoadReporting == nil {
				return fmt.Errorf("choice alternative eventTriggeredCellLoadReporting is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.EventTriggeredCellLoadReporting), 3, true); err != nil {
				return fmt.Errorf("encoding eventTriggeredCellLoadReporting: %w", err)
			}
		case SONtransferCauseChoiceHOReporting:
			if v.HOReporting == nil {
				return fmt.Errorf("choice alternative hOReporting is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.HOReporting), 3, true); err != nil {
				return fmt.Errorf("encoding hOReporting: %w", err)
			}
		case SONtransferCauseChoiceEutranCellActivation:
			if v.EutranCellActivation == nil {
				return fmt.Errorf("choice alternative eutranCellActivation is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.EutranCellActivation), 3, true); err != nil {
				return fmt.Errorf("encoding eutranCellActivation: %w", err)
			}
		case SONtransferCauseChoiceEnergySavingsIndication:
			if v.EnergySavingsIndication == nil {
				return fmt.Errorf("choice alternative energySavingsIndication is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.EnergySavingsIndication), 3, true); err != nil {
				return fmt.Errorf("encoding energySavingsIndication: %w", err)
			}
		case SONtransferCauseChoiceFailureEventReporting:
			if v.FailureEventReporting == nil {
				return fmt.Errorf("choice alternative failureEventReporting is nil")
			}
			if err := per.EncodeEnumeratedAligned(inner, int64(*v.FailureEventReporting), 3, true); err != nil {
				return fmt.Errorf("encoding failureEventReporting: %w", err)
			}
		default:
			return fmt.Errorf("unknown SONtransferCause extension choice %d", v.Choice)
		}
		if err := per.EncodeOpenTypeAligned(bb, inner.Bytes()); err != nil {
			return err
		}
		return nil
	}
	switch v.Choice {
	case SONtransferCauseChoiceCellLoadReporting:
		if v.CellLoadReporting == nil {
			return fmt.Errorf("choice alternative cellLoadReporting is nil")
		}
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.CellLoadReporting), 3, true); err != nil {
			return fmt.Errorf("encoding cellLoadReporting: %w", err)
		}
	default:
		return fmt.Errorf("unknown SONtransferCause choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONtransferCause from APER format.
func (v *SONtransferCause) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *SONtransferCause) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = SONtransferCause{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return err
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return err
		}
		if extIdx >= 6 {
			v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
			return nil
		}
		inner := per.NewBitBufferFromBytes(openData)
		v.Choice = int(extIdx) + 1 + 1
		switch v.Choice {
		case SONtransferCauseChoiceMultiCellLoadReporting:
			val_multicellloadreporting, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return fmt.Errorf("decoding multiCellLoadReporting: %w", err)
			}
			tmp_multicellloadreporting := CellLoadReportingCause(val_multicellloadreporting)
			v.MultiCellLoadReporting = &tmp_multicellloadreporting
		case SONtransferCauseChoiceEventTriggeredCellLoadReporting:
			val_eventtriggeredcellloadreporting, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return fmt.Errorf("decoding eventTriggeredCellLoadReporting: %w", err)
			}
			tmp_eventtriggeredcellloadreporting := CellLoadReportingCause(val_eventtriggeredcellloadreporting)
			v.EventTriggeredCellLoadReporting = &tmp_eventtriggeredcellloadreporting
		case SONtransferCauseChoiceHOReporting:
			val_horeporting, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return fmt.Errorf("decoding hOReporting: %w", err)
			}
			tmp_horeporting := HOReportingCause(val_horeporting)
			v.HOReporting = &tmp_horeporting
		case SONtransferCauseChoiceEutranCellActivation:
			val_eutrancellactivation, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return fmt.Errorf("decoding eutranCellActivation: %w", err)
			}
			tmp_eutrancellactivation := CellActivationCause(val_eutrancellactivation)
			v.EutranCellActivation = &tmp_eutrancellactivation
		case SONtransferCauseChoiceEnergySavingsIndication:
			val_energysavingsindication, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return fmt.Errorf("decoding energySavingsIndication: %w", err)
			}
			tmp_energysavingsindication := CellStateIndicationCause(val_energysavingsindication)
			v.EnergySavingsIndication = &tmp_energysavingsindication
		case SONtransferCauseChoiceFailureEventReporting:
			val_failureeventreporting, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return fmt.Errorf("decoding failureEventReporting: %w", err)
			}
			tmp_failureeventreporting := FailureEventReportingCause(val_failureeventreporting)
			v.FailureEventReporting = &tmp_failureeventreporting
		}
		if err := per.ValidateOpenTypePadding(inner); err != nil {
			return fmt.Errorf("SONtransferCause: extension choice %d: %w", v.Choice, err)
		}
		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case SONtransferCauseChoiceCellLoadReporting:
		val_cellloadreporting, err := per.DecodeEnumeratedAligned(bb, 3, true)
		if err != nil {
			return fmt.Errorf("decoding cellLoadReporting: %w", err)
		}
		tmp_cellloadreporting := CellLoadReportingCause(val_cellloadreporting)
		v.CellLoadReporting = &tmp_cellloadreporting
	}
	return nil
}

// MarshalAPER encodes CellLoadReportingResponse to APER format.
func (v *CellLoadReportingResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CellLoadReportingResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("CellLoadReportingResponse: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 1 {
			return fmt.Errorf("CellLoadReportingResponse: extension index %d is known to this schema", v.UnknownExtension.Index)
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
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-3-1)); err != nil {
			return err
		}
		inner := per.NewBitBuffer()
		switch v.Choice {
		case CellLoadReportingResponseChoiceEHRPD:
			if v.EHRPD == nil {
				return fmt.Errorf("choice alternative eHRPD is nil")
			}
			if err := v.EHRPD.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding eHRPD: %w", err)
			}
		default:
			return fmt.Errorf("unknown CellLoadReportingResponse extension choice %d", v.Choice)
		}
		if err := per.EncodeOpenTypeAligned(bb, inner.Bytes()); err != nil {
			return err
		}
		return nil
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case CellLoadReportingResponseChoiceEUTRAN:
		if v.EUTRAN == nil {
			return fmt.Errorf("choice alternative eUTRAN is nil")
		}
		if err := v.EUTRAN.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding eUTRAN: %w", err)
		}
	case CellLoadReportingResponseChoiceUTRAN:
		if err := per.EncodeOctetStringAligned(bb, v.UTRAN, 0, 0, false); err != nil {
			return fmt.Errorf("encoding uTRAN: %w", err)
		}
	case CellLoadReportingResponseChoiceGERAN:
		if err := per.EncodeOctetStringAligned(bb, v.GERAN, 0, 0, false); err != nil {
			return fmt.Errorf("encoding gERAN: %w", err)
		}
	default:
		return fmt.Errorf("unknown CellLoadReportingResponse choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes CellLoadReportingResponse from APER format.
func (v *CellLoadReportingResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *CellLoadReportingResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CellLoadReportingResponse{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return err
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return err
		}
		if extIdx >= 1 {
			v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
			return nil
		}
		inner := per.NewBitBufferFromBytes(openData)
		v.Choice = int(extIdx) + 3 + 1
		switch v.Choice {
		case CellLoadReportingResponseChoiceEHRPD:
			var dec_ehrpd EHRPDSectorLoadReportingResponse
			if err := dec_ehrpd.UnmarshalAPERFrom(inner); err != nil {
				return fmt.Errorf("decoding eHRPD: %w", err)
			}
			v.EHRPD = &dec_ehrpd
		}
		if err := per.ValidateOpenTypePadding(inner); err != nil {
			return fmt.Errorf("CellLoadReportingResponse: extension choice %d: %w", v.Choice, err)
		}
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case CellLoadReportingResponseChoiceEUTRAN:
		var dec_eutran EUTRANcellLoadReportingResponse
		if err := dec_eutran.UnmarshalAPERFrom(bb); err != nil {
			return fmt.Errorf("decoding eUTRAN: %w", err)
		}
		v.EUTRAN = &dec_eutran
	case CellLoadReportingResponseChoiceUTRAN:
		val_utran, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return fmt.Errorf("decoding uTRAN: %w", err)
		}
		tmp_utran := val_utran
		v.UTRAN = tmp_utran
	case CellLoadReportingResponseChoiceGERAN:
		val_geran, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return fmt.Errorf("decoding gERAN: %w", err)
		}
		tmp_geran := val_geran
		v.GERAN = tmp_geran
	}
	return nil
}

// MarshalAPER encodes EUTRANcellLoadReportingResponse to APER format.
func (v *EUTRANcellLoadReportingResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *EUTRANcellLoadReportingResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.CompositeAvailableCapacityGroup), 0, 0, false); err != nil {
		return fmt.Errorf("encoding compositeAvailableCapacityGroup: %w", err)
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

// UnmarshalAPER decodes EUTRANcellLoadReportingResponse from APER format.
func (v *EUTRANcellLoadReportingResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *EUTRANcellLoadReportingResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EUTRANcellLoadReportingResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_compositeavailablecapacitygroup, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return fmt.Errorf("decoding compositeAvailableCapacityGroup: %w", err)
	}
	v.CompositeAvailableCapacityGroup = CompositeAvailableCapacityGroup(val_compositeavailablecapacitygroup)
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes EUTRANResponse to APER format.
func (v *EUTRANResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *EUTRANResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeOctetStringAligned(bb, v.CellID, 0, 0, false); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
	}
	if err := v.EUTRANcellLoadReportingResponse.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding eUTRANcellLoadReportingResponse: %w", err)
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

// UnmarshalAPER decodes EUTRANResponse from APER format.
func (v *EUTRANResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *EUTRANResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EUTRANResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return fmt.Errorf("decoding cell-ID: %w", err)
	}
	v.CellID = val_cellid
	if err := v.EUTRANcellLoadReportingResponse.UnmarshalAPERFrom(bb); err != nil {
		return fmt.Errorf("decoding eUTRANcellLoadReportingResponse: %w", err)
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes IRATCellID to APER format.
func (v *IRATCellID) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *IRATCellID) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("IRATCellID: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 1 {
			return fmt.Errorf("IRATCellID: extension index %d is known to this schema", v.UnknownExtension.Index)
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
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-3-1)); err != nil {
			return err
		}
		inner := per.NewBitBuffer()
		switch v.Choice {
		case IRATCellIDChoiceEHRPD:
			if v.EHRPD == nil {
				return fmt.Errorf("choice alternative eHRPD is nil")
			}
			if err := per.EncodeOctetStringAligned(inner, []byte(*v.EHRPD), 16, 16, true); err != nil {
				return fmt.Errorf("encoding eHRPD: %w", err)
			}
		default:
			return fmt.Errorf("unknown IRATCellID extension choice %d", v.Choice)
		}
		if err := per.EncodeOpenTypeAligned(bb, inner.Bytes()); err != nil {
			return err
		}
		return nil
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case IRATCellIDChoiceEUTRAN:
		if err := per.EncodeOctetStringAligned(bb, v.EUTRAN, 0, 0, false); err != nil {
			return fmt.Errorf("encoding eUTRAN: %w", err)
		}
	case IRATCellIDChoiceUTRAN:
		if err := per.EncodeOctetStringAligned(bb, v.UTRAN, 0, 0, false); err != nil {
			return fmt.Errorf("encoding uTRAN: %w", err)
		}
	case IRATCellIDChoiceGERAN:
		if err := per.EncodeOctetStringAligned(bb, v.GERAN, 0, 0, false); err != nil {
			return fmt.Errorf("encoding gERAN: %w", err)
		}
	default:
		return fmt.Errorf("unknown IRATCellID choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes IRATCellID from APER format.
func (v *IRATCellID) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *IRATCellID) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = IRATCellID{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return err
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return err
		}
		if extIdx >= 1 {
			v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
			return nil
		}
		inner := per.NewBitBufferFromBytes(openData)
		v.Choice = int(extIdx) + 3 + 1
		switch v.Choice {
		case IRATCellIDChoiceEHRPD:
			val_ehrpd, err := per.DecodeOctetStringAligned(inner, 16, 16, true)
			if err != nil {
				return fmt.Errorf("decoding eHRPD: %w", err)
			}
			tmp_ehrpd := EHRPDSectorID(val_ehrpd)
			v.EHRPD = &tmp_ehrpd
		}
		if err := per.ValidateOpenTypePadding(inner); err != nil {
			return fmt.Errorf("IRATCellID: extension choice %d: %w", v.Choice, err)
		}
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case IRATCellIDChoiceEUTRAN:
		val_eutran, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return fmt.Errorf("decoding eUTRAN: %w", err)
		}
		tmp_eutran := val_eutran
		v.EUTRAN = tmp_eutran
	case IRATCellIDChoiceUTRAN:
		val_utran, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return fmt.Errorf("decoding uTRAN: %w", err)
		}
		tmp_utran := val_utran
		v.UTRAN = tmp_utran
	case IRATCellIDChoiceGERAN:
		val_geran, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return fmt.Errorf("decoding gERAN: %w", err)
		}
		tmp_geran := val_geran
		v.GERAN = tmp_geran
	}
	return nil
}

type asn1cAPERRequestedCellListListValue struct{ Value RequestedCellList }

// MarshalAPERRequestedCellList encodes a RequestedCellList list to APER.
func MarshalAPERRequestedCellList(list RequestedCellList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERRequestedCellListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERRequestedCellListTo appends a RequestedCellList list to bb.
func MarshalAPERRequestedCellListTo(list RequestedCellList, bb *per.BitBuffer) error {
	v := asn1cAPERRequestedCellListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// UnmarshalAPERRequestedCellList decodes a RequestedCellList list from APER.
func UnmarshalAPERRequestedCellList(data []byte) (RequestedCellList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERRequestedCellListFrom(bb)
	if err != nil {
		return nil, err
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, err
	}
	return value, nil
}

// UnmarshalAPERRequestedCellListFrom decodes a RequestedCellList list from bb.
func UnmarshalAPERRequestedCellListFrom(bb *per.BitBuffer) (RequestedCellList, error) {
	var v asn1cAPERRequestedCellListListValue
	if err := unmarshalAPERRequestedCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERRequestedCellListInto(v *asn1cAPERRequestedCellListListValue, bb *per.BitBuffer) error {
	v.Value = make(RequestedCellList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem IRATCellID
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding value element %d: %w", fragmentOffset_value+i, err)
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return fmt.Errorf("decoding value: %w", errCollection_value)
	}
	return nil
}

// MarshalAPER encodes MultiCellLoadReportingRequest to APER format.
func (v *MultiCellLoadReportingRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *MultiCellLoadReportingRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.RequestedCellList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_requestedcelllist, fragmentLength_requestedcelllist int64) error {
		for _, elem := range v.RequestedCellList[fragmentOffset_requestedcelllist : fragmentOffset_requestedcelllist+fragmentLength_requestedcelllist] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding requestedCellList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding requestedCellList: %w", err)
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

// UnmarshalAPER decodes MultiCellLoadReportingRequest from APER format.
func (v *MultiCellLoadReportingRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *MultiCellLoadReportingRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MultiCellLoadReportingRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.RequestedCellList = make(RequestedCellList, 0)
	_, errCollection_requestedcelllist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_requestedcelllist, fragmentLength_requestedcelllist int64) error {
		for i := int64(0); i < fragmentLength_requestedcelllist; i++ {
			var elem IRATCellID
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding requestedCellList element %d: %w", fragmentOffset_requestedcelllist+i, err)
			}
			v.RequestedCellList = append(v.RequestedCellList, elem)
		}
		return nil
	})
	if errCollection_requestedcelllist != nil {
		return fmt.Errorf("decoding requestedCellList: %w", errCollection_requestedcelllist)
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes ReportingCellListItem to APER format.
func (v *ReportingCellListItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ReportingCellListItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := v.CellID.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
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

// UnmarshalAPER decodes ReportingCellListItem from APER format.
func (v *ReportingCellListItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *ReportingCellListItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ReportingCellListItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.CellID.UnmarshalAPERFrom(bb); err != nil {
		return fmt.Errorf("decoding cell-ID: %w", err)
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERReportingCellListListValue struct{ Value ReportingCellList }

// MarshalAPERReportingCellList encodes a ReportingCellList list to APER.
func MarshalAPERReportingCellList(list ReportingCellList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERReportingCellListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERReportingCellListTo appends a ReportingCellList list to bb.
func MarshalAPERReportingCellListTo(list ReportingCellList, bb *per.BitBuffer) error {
	v := asn1cAPERReportingCellListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// UnmarshalAPERReportingCellList decodes a ReportingCellList list from APER.
func UnmarshalAPERReportingCellList(data []byte) (ReportingCellList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERReportingCellListFrom(bb)
	if err != nil {
		return nil, err
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, err
	}
	return value, nil
}

// UnmarshalAPERReportingCellListFrom decodes a ReportingCellList list from bb.
func UnmarshalAPERReportingCellListFrom(bb *per.BitBuffer) (ReportingCellList, error) {
	var v asn1cAPERReportingCellListListValue
	if err := unmarshalAPERReportingCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERReportingCellListInto(v *asn1cAPERReportingCellListListValue, bb *per.BitBuffer) error {
	v.Value = make(ReportingCellList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ReportingCellListItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding value element %d: %w", fragmentOffset_value+i, err)
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return fmt.Errorf("decoding value: %w", errCollection_value)
	}
	return nil
}

type asn1cAPERMultiCellLoadReportingResponseListValue struct {
	Value MultiCellLoadReportingResponse
}

// MarshalAPERMultiCellLoadReportingResponse encodes a MultiCellLoadReportingResponse list to APER.
func MarshalAPERMultiCellLoadReportingResponse(list MultiCellLoadReportingResponse) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERMultiCellLoadReportingResponseTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERMultiCellLoadReportingResponseTo appends a MultiCellLoadReportingResponse list to bb.
func MarshalAPERMultiCellLoadReportingResponseTo(list MultiCellLoadReportingResponse, bb *per.BitBuffer) error {
	v := asn1cAPERMultiCellLoadReportingResponseListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// UnmarshalAPERMultiCellLoadReportingResponse decodes a MultiCellLoadReportingResponse list from APER.
func UnmarshalAPERMultiCellLoadReportingResponse(data []byte) (MultiCellLoadReportingResponse, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERMultiCellLoadReportingResponseFrom(bb)
	if err != nil {
		return nil, err
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, err
	}
	return value, nil
}

// UnmarshalAPERMultiCellLoadReportingResponseFrom decodes a MultiCellLoadReportingResponse list from bb.
func UnmarshalAPERMultiCellLoadReportingResponseFrom(bb *per.BitBuffer) (MultiCellLoadReportingResponse, error) {
	var v asn1cAPERMultiCellLoadReportingResponseListValue
	if err := unmarshalAPERMultiCellLoadReportingResponseInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERMultiCellLoadReportingResponseInto(v *asn1cAPERMultiCellLoadReportingResponseListValue, bb *per.BitBuffer) error {
	v.Value = make(MultiCellLoadReportingResponse, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem MultiCellLoadReportingResponseItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding value element %d: %w", fragmentOffset_value+i, err)
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return fmt.Errorf("decoding value: %w", errCollection_value)
	}
	return nil
}

// MarshalAPER encodes MultiCellLoadReportingResponseItem to APER format.
func (v *MultiCellLoadReportingResponseItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *MultiCellLoadReportingResponseItem) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("MultiCellLoadReportingResponseItem: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 1 {
			return fmt.Errorf("MultiCellLoadReportingResponseItem: extension index %d is known to this schema", v.UnknownExtension.Index)
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
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-3-1)); err != nil {
			return err
		}
		inner := per.NewBitBuffer()
		switch v.Choice {
		case MultiCellLoadReportingResponseItemChoiceEHRPD:
			if v.EHRPD == nil {
				return fmt.Errorf("choice alternative eHRPD is nil")
			}
			if err := v.EHRPD.MarshalAPERTo(inner); err != nil {
				return fmt.Errorf("encoding eHRPD: %w", err)
			}
		default:
			return fmt.Errorf("unknown MultiCellLoadReportingResponseItem extension choice %d", v.Choice)
		}
		if err := per.EncodeOpenTypeAligned(bb, inner.Bytes()); err != nil {
			return err
		}
		return nil
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case MultiCellLoadReportingResponseItemChoiceEUTRANResponse:
		if v.EUTRANResponse == nil {
			return fmt.Errorf("choice alternative eUTRANResponse is nil")
		}
		if err := v.EUTRANResponse.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding eUTRANResponse: %w", err)
		}
	case MultiCellLoadReportingResponseItemChoiceUTRANResponse:
		if err := per.EncodeOctetStringAligned(bb, v.UTRANResponse, 0, 0, false); err != nil {
			return fmt.Errorf("encoding uTRANResponse: %w", err)
		}
	case MultiCellLoadReportingResponseItemChoiceGERANResponse:
		if err := per.EncodeOctetStringAligned(bb, v.GERANResponse, 0, 0, false); err != nil {
			return fmt.Errorf("encoding gERANResponse: %w", err)
		}
	default:
		return fmt.Errorf("unknown MultiCellLoadReportingResponseItem choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes MultiCellLoadReportingResponseItem from APER format.
func (v *MultiCellLoadReportingResponseItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *MultiCellLoadReportingResponseItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MultiCellLoadReportingResponseItem{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return err
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return err
		}
		if extIdx >= 1 {
			v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
			return nil
		}
		inner := per.NewBitBufferFromBytes(openData)
		v.Choice = int(extIdx) + 3 + 1
		switch v.Choice {
		case MultiCellLoadReportingResponseItemChoiceEHRPD:
			var dec_ehrpd EHRPDMultiSectorLoadReportingResponseItem
			if err := dec_ehrpd.UnmarshalAPERFrom(inner); err != nil {
				return fmt.Errorf("decoding eHRPD: %w", err)
			}
			v.EHRPD = &dec_ehrpd
		}
		if err := per.ValidateOpenTypePadding(inner); err != nil {
			return fmt.Errorf("MultiCellLoadReportingResponseItem: extension choice %d: %w", v.Choice, err)
		}
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case MultiCellLoadReportingResponseItemChoiceEUTRANResponse:
		var dec_eutranresponse EUTRANResponse
		if err := dec_eutranresponse.UnmarshalAPERFrom(bb); err != nil {
			return fmt.Errorf("decoding eUTRANResponse: %w", err)
		}
		v.EUTRANResponse = &dec_eutranresponse
	case MultiCellLoadReportingResponseItemChoiceUTRANResponse:
		val_utranresponse, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return fmt.Errorf("decoding uTRANResponse: %w", err)
		}
		tmp_utranresponse := val_utranresponse
		v.UTRANResponse = tmp_utranresponse
	case MultiCellLoadReportingResponseItemChoiceGERANResponse:
		val_geranresponse, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return fmt.Errorf("decoding gERANResponse: %w", err)
		}
		tmp_geranresponse := val_geranresponse
		v.GERANResponse = tmp_geranresponse
	}
	return nil
}

// MarshalAPER encodes EventTriggeredCellLoadReportingRequest to APER format.
func (v *EventTriggeredCellLoadReportingRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *EventTriggeredCellLoadReportingRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.NumberOfMeasurementReportingLevels), 5, true); err != nil {
		return fmt.Errorf("encoding numberOfMeasurementReportingLevels: %w", err)
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

// UnmarshalAPER decodes EventTriggeredCellLoadReportingRequest from APER format.
func (v *EventTriggeredCellLoadReportingRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *EventTriggeredCellLoadReportingRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EventTriggeredCellLoadReportingRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_numberofmeasurementreportinglevels, err := per.DecodeEnumeratedAligned(bb, 5, true)
	if err != nil {
		return fmt.Errorf("decoding numberOfMeasurementReportingLevels: %w", err)
	}
	v.NumberOfMeasurementReportingLevels = NumberOfMeasurementReportingLevels(val_numberofmeasurementreportinglevels)
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes EventTriggeredCellLoadReportingResponse to APER format.
func (v *EventTriggeredCellLoadReportingResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *EventTriggeredCellLoadReportingResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.OverloadFlag != nil); err != nil {
		return err
	}
	if err := v.CellLoadReportingResponse.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding cellLoadReportingResponse: %w", err)
	}
	if v.OverloadFlag != nil {
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.OverloadFlag), 1, true); err != nil {
			return fmt.Errorf("encoding overloadFlag: %w", err)
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

// UnmarshalAPER decodes EventTriggeredCellLoadReportingResponse from APER format.
func (v *EventTriggeredCellLoadReportingResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *EventTriggeredCellLoadReportingResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EventTriggeredCellLoadReportingResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_overloadflag, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.CellLoadReportingResponse.UnmarshalAPERFrom(bb); err != nil {
		return fmt.Errorf("decoding cellLoadReportingResponse: %w", err)
	}
	if opt_overloadflag {
		val_overloadflag, err := per.DecodeEnumeratedAligned(bb, 1, true)
		if err != nil {
			return fmt.Errorf("decoding overloadFlag: %w", err)
		}
		tmp_overloadflag := OverloadFlag(val_overloadflag)
		v.OverloadFlag = &tmp_overloadflag
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes HOReport to APER format.
func (v *HOReport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HOReport) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.CandidatePCIList != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.HoType), 2, true); err != nil {
		return fmt.Errorf("encoding hoType: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.HoReportType), 1, true); err != nil {
		return fmt.Errorf("encoding hoReportType: %w", err)
	}
	if err := v.HosourceID.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding hosourceID: %w", err)
	}
	if err := v.HoTargetID.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding hoTargetID: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.CandidateCellList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatecelllist, fragmentLength_candidatecelllist int64) error {
		for _, elem := range v.CandidateCellList[fragmentOffset_candidatecelllist : fragmentOffset_candidatecelllist+fragmentLength_candidatecelllist] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding candidateCellList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding candidateCellList: %w", err)
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.CandidatePCIList != nil {
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
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.CandidatePCIList != nil
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
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.CandidatePCIList != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.CandidatePCIList != nil); err != nil {
				return err
			}
			if v.CandidatePCIList != nil {
				if err := per.EncodeCollection(extBuf, int64(len(v.CandidatePCIList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatepcilist, fragmentLength_candidatepcilist int64) error {
					for _, elem := range v.CandidatePCIList[fragmentOffset_candidatepcilist : fragmentOffset_candidatepcilist+fragmentLength_candidatepcilist] {
						if err := elem.MarshalAPERTo(extBuf); err != nil {
							return fmt.Errorf("encoding candidatePCIList element: %w", err)
						}
					}
					return nil
				}); err != nil {
					return fmt.Errorf("encoding candidatePCIList: %w", err)
				}
			}
			if err := per.EncodeOpenTypeAligned(bb, extBuf.Bytes()); err != nil {
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

// UnmarshalAPER decodes HOReport from APER format.
func (v *HOReport) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *HOReport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HOReport{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_hotype, err := per.DecodeEnumeratedAligned(bb, 2, true)
	if err != nil {
		return fmt.Errorf("decoding hoType: %w", err)
	}
	v.HoType = HoType(val_hotype)
	val_horeporttype, err := per.DecodeEnumeratedAligned(bb, 1, true)
	if err != nil {
		return fmt.Errorf("decoding hoReportType: %w", err)
	}
	v.HoReportType = HoReportType(val_horeporttype)
	if err := v.HosourceID.UnmarshalAPERFrom(bb); err != nil {
		return fmt.Errorf("decoding hosourceID: %w", err)
	}
	if err := v.HoTargetID.UnmarshalAPERFrom(bb); err != nil {
		return fmt.Errorf("decoding hoTargetID: %w", err)
	}
	v.CandidateCellList = make(CandidateCellList, 0)
	_, errCollection_candidatecelllist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatecelllist, fragmentLength_candidatecelllist int64) error {
		for i := int64(0); i < fragmentLength_candidatecelllist; i++ {
			var elem IRATCellID
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding candidateCellList element %d: %w", fragmentOffset_candidatecelllist+i, err)
			}
			v.CandidateCellList = append(v.CandidateCellList, elem)
		}
		return nil
	})
	if errCollection_candidatecelllist != nil {
		return fmt.Errorf("decoding candidateCellList: %w", errCollection_candidatecelllist)
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtPresent_ = extPresent
		v.ExtData_ = make([][]byte, extCount+1)
		if int64(0) <= extCount && extPresent[0] {
			extData, err := per.DecodeOpenTypeAligned(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_candidatepcilist, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_candidatepcilist {
				tmp_candidatepcilist := make(CandidatePCIList, 0)
				_, errCollection_candidatepcilist := per.DecodeCollection(extBB, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatepcilist, fragmentLength_candidatepcilist int64) error {
					for i := int64(0); i < fragmentLength_candidatepcilist; i++ {
						var elem CandidatePCI
						if err := elem.UnmarshalAPERFrom(extBB); err != nil {
							return fmt.Errorf("decoding candidatePCIList element %d: %w", fragmentOffset_candidatepcilist+i, err)
						}
						tmp_candidatepcilist = append(tmp_candidatepcilist, elem)
					}
					return nil
				})
				if errCollection_candidatepcilist != nil {
					return fmt.Errorf("decoding candidatePCIList: %w", errCollection_candidatepcilist)
				}
				v.CandidatePCIList = tmp_candidatepcilist
			}
			if err := per.ValidateOpenTypePadding(extBB); err != nil {
				return fmt.Errorf("HOReport: extension group 0: %w", err)
			}
		}
		for i := int64(1); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERCandidateCellListListValue struct{ Value CandidateCellList }

// MarshalAPERCandidateCellList encodes a CandidateCellList list to APER.
func MarshalAPERCandidateCellList(list CandidateCellList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERCandidateCellListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERCandidateCellListTo appends a CandidateCellList list to bb.
func MarshalAPERCandidateCellListTo(list CandidateCellList, bb *per.BitBuffer) error {
	v := asn1cAPERCandidateCellListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// UnmarshalAPERCandidateCellList decodes a CandidateCellList list from APER.
func UnmarshalAPERCandidateCellList(data []byte) (CandidateCellList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERCandidateCellListFrom(bb)
	if err != nil {
		return nil, err
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, err
	}
	return value, nil
}

// UnmarshalAPERCandidateCellListFrom decodes a CandidateCellList list from bb.
func UnmarshalAPERCandidateCellListFrom(bb *per.BitBuffer) (CandidateCellList, error) {
	var v asn1cAPERCandidateCellListListValue
	if err := unmarshalAPERCandidateCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERCandidateCellListInto(v *asn1cAPERCandidateCellListListValue, bb *per.BitBuffer) error {
	v.Value = make(CandidateCellList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem IRATCellID
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding value element %d: %w", fragmentOffset_value+i, err)
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return fmt.Errorf("decoding value: %w", errCollection_value)
	}
	return nil
}

type asn1cAPERCandidatePCIListListValue struct{ Value CandidatePCIList }

// MarshalAPERCandidatePCIList encodes a CandidatePCIList list to APER.
func MarshalAPERCandidatePCIList(list CandidatePCIList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERCandidatePCIListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERCandidatePCIListTo appends a CandidatePCIList list to bb.
func MarshalAPERCandidatePCIListTo(list CandidatePCIList, bb *per.BitBuffer) error {
	v := asn1cAPERCandidatePCIListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// UnmarshalAPERCandidatePCIList decodes a CandidatePCIList list from APER.
func UnmarshalAPERCandidatePCIList(data []byte) (CandidatePCIList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERCandidatePCIListFrom(bb)
	if err != nil {
		return nil, err
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, err
	}
	return value, nil
}

// UnmarshalAPERCandidatePCIListFrom decodes a CandidatePCIList list from bb.
func UnmarshalAPERCandidatePCIListFrom(bb *per.BitBuffer) (CandidatePCIList, error) {
	var v asn1cAPERCandidatePCIListListValue
	if err := unmarshalAPERCandidatePCIListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERCandidatePCIListInto(v *asn1cAPERCandidatePCIListListValue, bb *per.BitBuffer) error {
	v.Value = make(CandidatePCIList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem CandidatePCI
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding value element %d: %w", fragmentOffset_value+i, err)
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return fmt.Errorf("decoding value: %w", errCollection_value)
	}
	return nil
}

// MarshalAPER encodes CandidatePCI to APER format.
func (v *CandidatePCI) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CandidatePCI) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.PCI), int64Ptr(0), int64Ptr(503), false); err != nil {
		return fmt.Errorf("encoding pCI: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, v.EARFCN, 0, 0, false); err != nil {
		return fmt.Errorf("encoding eARFCN: %w", err)
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

// UnmarshalAPER decodes CandidatePCI from APER format.
func (v *CandidatePCI) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *CandidatePCI) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CandidatePCI{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return fmt.Errorf("decoding pCI: %w", err)
	}
	v.PCI = val_pci
	val_earfcn, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return fmt.Errorf("decoding eARFCN: %w", err)
	}
	v.EARFCN = val_earfcn
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes CellActivationRequest to APER format.
func (v *CellActivationRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CellActivationRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MinimumActivationTime != nil); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.CellsToActivateList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_cellstoactivatelist, fragmentLength_cellstoactivatelist int64) error {
		for _, elem := range v.CellsToActivateList[fragmentOffset_cellstoactivatelist : fragmentOffset_cellstoactivatelist+fragmentLength_cellstoactivatelist] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding cellsToActivateList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding cellsToActivateList: %w", err)
	}
	if v.MinimumActivationTime != nil {
		if err := per.EncodeIntegerAligned(bb, int64(*v.MinimumActivationTime), int64Ptr(1), int64Ptr(60), false); err != nil {
			return fmt.Errorf("encoding minimumActivationTime: %w", err)
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

// UnmarshalAPER decodes CellActivationRequest from APER format.
func (v *CellActivationRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *CellActivationRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CellActivationRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_minimumactivationtime, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.CellsToActivateList = make(CellsToActivateList, 0)
	_, errCollection_cellstoactivatelist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_cellstoactivatelist, fragmentLength_cellstoactivatelist int64) error {
		for i := int64(0); i < fragmentLength_cellstoactivatelist; i++ {
			var elem CellsToActivateListItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding cellsToActivateList element %d: %w", fragmentOffset_cellstoactivatelist+i, err)
			}
			v.CellsToActivateList = append(v.CellsToActivateList, elem)
		}
		return nil
	})
	if errCollection_cellstoactivatelist != nil {
		return fmt.Errorf("decoding cellsToActivateList: %w", errCollection_cellstoactivatelist)
	}
	if opt_minimumactivationtime {
		val_minimumactivationtime, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(60), false)
		if err != nil {
			return fmt.Errorf("decoding minimumActivationTime: %w", err)
		}
		v.MinimumActivationTime = &val_minimumactivationtime
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERCellsToActivateListListValue struct{ Value CellsToActivateList }

// MarshalAPERCellsToActivateList encodes a CellsToActivateList list to APER.
func MarshalAPERCellsToActivateList(list CellsToActivateList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERCellsToActivateListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERCellsToActivateListTo appends a CellsToActivateList list to bb.
func MarshalAPERCellsToActivateListTo(list CellsToActivateList, bb *per.BitBuffer) error {
	v := asn1cAPERCellsToActivateListListValue{Value: list}
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

// UnmarshalAPERCellsToActivateList decodes a CellsToActivateList list from APER.
func UnmarshalAPERCellsToActivateList(data []byte) (CellsToActivateList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERCellsToActivateListFrom(bb)
	if err != nil {
		return nil, err
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, err
	}
	return value, nil
}

// UnmarshalAPERCellsToActivateListFrom decodes a CellsToActivateList list from bb.
func UnmarshalAPERCellsToActivateListFrom(bb *per.BitBuffer) (CellsToActivateList, error) {
	var v asn1cAPERCellsToActivateListListValue
	if err := unmarshalAPERCellsToActivateListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERCellsToActivateListInto(v *asn1cAPERCellsToActivateListListValue, bb *per.BitBuffer) error {
	v.Value = make(CellsToActivateList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem CellsToActivateListItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding value element %d: %w", fragmentOffset_value+i, err)
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return fmt.Errorf("decoding value: %w", errCollection_value)
	}
	return nil
}

// MarshalAPER encodes CellsToActivateListItem to APER format.
func (v *CellsToActivateListItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CellsToActivateListItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeOctetStringAligned(bb, v.CellID, 0, 0, false); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
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

// UnmarshalAPER decodes CellsToActivateListItem from APER format.
func (v *CellsToActivateListItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *CellsToActivateListItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CellsToActivateListItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return fmt.Errorf("decoding cell-ID: %w", err)
	}
	v.CellID = val_cellid
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes CellActivationResponse to APER format.
func (v *CellActivationResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CellActivationResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ActivatedCellsList)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_activatedcellslist, fragmentLength_activatedcellslist int64) error {
		for _, elem := range v.ActivatedCellsList[fragmentOffset_activatedcellslist : fragmentOffset_activatedcellslist+fragmentLength_activatedcellslist] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding activatedCellsList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding activatedCellsList: %w", err)
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

// UnmarshalAPER decodes CellActivationResponse from APER format.
func (v *CellActivationResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *CellActivationResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CellActivationResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ActivatedCellsList = make(ActivatedCellsList, 0)
	_, errCollection_activatedcellslist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_activatedcellslist, fragmentLength_activatedcellslist int64) error {
		for i := int64(0); i < fragmentLength_activatedcellslist; i++ {
			var elem ActivatedCellsListItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding activatedCellsList element %d: %w", fragmentOffset_activatedcellslist+i, err)
			}
			v.ActivatedCellsList = append(v.ActivatedCellsList, elem)
		}
		return nil
	})
	if errCollection_activatedcellslist != nil {
		return fmt.Errorf("decoding activatedCellsList: %w", errCollection_activatedcellslist)
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERActivatedCellsListListValue struct{ Value ActivatedCellsList }

// MarshalAPERActivatedCellsList encodes a ActivatedCellsList list to APER.
func MarshalAPERActivatedCellsList(list ActivatedCellsList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERActivatedCellsListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERActivatedCellsListTo appends a ActivatedCellsList list to bb.
func MarshalAPERActivatedCellsListTo(list ActivatedCellsList, bb *per.BitBuffer) error {
	v := asn1cAPERActivatedCellsListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// UnmarshalAPERActivatedCellsList decodes a ActivatedCellsList list from APER.
func UnmarshalAPERActivatedCellsList(data []byte) (ActivatedCellsList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERActivatedCellsListFrom(bb)
	if err != nil {
		return nil, err
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, err
	}
	return value, nil
}

// UnmarshalAPERActivatedCellsListFrom decodes a ActivatedCellsList list from bb.
func UnmarshalAPERActivatedCellsListFrom(bb *per.BitBuffer) (ActivatedCellsList, error) {
	var v asn1cAPERActivatedCellsListListValue
	if err := unmarshalAPERActivatedCellsListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERActivatedCellsListInto(v *asn1cAPERActivatedCellsListListValue, bb *per.BitBuffer) error {
	v.Value = make(ActivatedCellsList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ActivatedCellsListItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding value element %d: %w", fragmentOffset_value+i, err)
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return fmt.Errorf("decoding value: %w", errCollection_value)
	}
	return nil
}

// MarshalAPER encodes ActivatedCellsListItem to APER format.
func (v *ActivatedCellsListItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ActivatedCellsListItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeOctetStringAligned(bb, v.CellID, 0, 0, false); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
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

// UnmarshalAPER decodes ActivatedCellsListItem from APER format.
func (v *ActivatedCellsListItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *ActivatedCellsListItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ActivatedCellsListItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return fmt.Errorf("decoding cell-ID: %w", err)
	}
	v.CellID = val_cellid
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes CellStateIndication to APER format.
func (v *CellStateIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CellStateIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.NotificationCellList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_notificationcelllist, fragmentLength_notificationcelllist int64) error {
		for _, elem := range v.NotificationCellList[fragmentOffset_notificationcelllist : fragmentOffset_notificationcelllist+fragmentLength_notificationcelllist] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding notificationCellList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding notificationCellList: %w", err)
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

// UnmarshalAPER decodes CellStateIndication from APER format.
func (v *CellStateIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *CellStateIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CellStateIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.NotificationCellList = make(NotificationCellList, 0)
	_, errCollection_notificationcelllist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_notificationcelllist, fragmentLength_notificationcelllist int64) error {
		for i := int64(0); i < fragmentLength_notificationcelllist; i++ {
			var elem NotificationCellListItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding notificationCellList element %d: %w", fragmentOffset_notificationcelllist+i, err)
			}
			v.NotificationCellList = append(v.NotificationCellList, elem)
		}
		return nil
	})
	if errCollection_notificationcelllist != nil {
		return fmt.Errorf("decoding notificationCellList: %w", errCollection_notificationcelllist)
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cAPERNotificationCellListListValue struct{ Value NotificationCellList }

// MarshalAPERNotificationCellList encodes a NotificationCellList list to APER.
func MarshalAPERNotificationCellList(list NotificationCellList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERNotificationCellListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERNotificationCellListTo appends a NotificationCellList list to bb.
func MarshalAPERNotificationCellListTo(list NotificationCellList, bb *per.BitBuffer) error {
	v := asn1cAPERNotificationCellListListValue{Value: list}
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

// UnmarshalAPERNotificationCellList decodes a NotificationCellList list from APER.
func UnmarshalAPERNotificationCellList(data []byte) (NotificationCellList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERNotificationCellListFrom(bb)
	if err != nil {
		return nil, err
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, err
	}
	return value, nil
}

// UnmarshalAPERNotificationCellListFrom decodes a NotificationCellList list from bb.
func UnmarshalAPERNotificationCellListFrom(bb *per.BitBuffer) (NotificationCellList, error) {
	var v asn1cAPERNotificationCellListListValue
	if err := unmarshalAPERNotificationCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERNotificationCellListInto(v *asn1cAPERNotificationCellListListValue, bb *per.BitBuffer) error {
	v.Value = make(NotificationCellList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem NotificationCellListItem
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return fmt.Errorf("decoding value element %d: %w", fragmentOffset_value+i, err)
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return fmt.Errorf("decoding value: %w", errCollection_value)
	}
	return nil
}

// MarshalAPER encodes NotificationCellListItem to APER format.
func (v *NotificationCellListItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *NotificationCellListItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeOctetStringAligned(bb, v.CellID, 0, 0, false); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.NotifyFlag), 2, true); err != nil {
		return fmt.Errorf("encoding notifyFlag: %w", err)
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

// UnmarshalAPER decodes NotificationCellListItem from APER format.
func (v *NotificationCellListItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *NotificationCellListItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = NotificationCellListItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return fmt.Errorf("decoding cell-ID: %w", err)
	}
	v.CellID = val_cellid
	val_notifyflag, err := per.DecodeEnumeratedAligned(bb, 2, true)
	if err != nil {
		return fmt.Errorf("decoding notifyFlag: %w", err)
	}
	v.NotifyFlag = NotifyFlag(val_notifyflag)
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes FailureEventReport to APER format.
func (v *FailureEventReport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *FailureEventReport) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("FailureEventReport: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("FailureEventReport: extension index %d is known to this schema", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 1
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("FailureEventReport: extension choice %d not supported", v.Choice)
	}
	switch v.Choice {
	case FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN:
		if v.TooEarlyInterRATHOReportFromEUTRAN == nil {
			return fmt.Errorf("choice alternative tooEarlyInterRATHOReportFromEUTRAN is nil")
		}
		if err := v.TooEarlyInterRATHOReportFromEUTRAN.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding tooEarlyInterRATHOReportFromEUTRAN: %w", err)
		}
	default:
		return fmt.Errorf("unknown FailureEventReport choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes FailureEventReport from APER format.
func (v *FailureEventReport) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *FailureEventReport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = FailureEventReport{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return err
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return err
		}
		v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN:
		var dec_tooearlyinterrathoreportfromeutran TooEarlyInterRATHOReportReportFromEUTRAN
		if err := dec_tooearlyinterrathoreportfromeutran.UnmarshalAPERFrom(bb); err != nil {
			return fmt.Errorf("decoding tooEarlyInterRATHOReportFromEUTRAN: %w", err)
		}
		v.TooEarlyInterRATHOReportFromEUTRAN = &dec_tooearlyinterrathoreportfromeutran
	}
	return nil
}

// MarshalAPER encodes TooEarlyInterRATHOReportReportFromEUTRAN to APER format.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *TooEarlyInterRATHOReportReportFromEUTRAN) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MobilityInformation != nil); err != nil {
		return err
	}
	if err := per.EncodeOctetStringAligned(bb, v.UERLFReportContainer, 0, 0, false); err != nil {
		return fmt.Errorf("encoding uERLFReportContainer: %w", err)
	}
	if v.MobilityInformation != nil {
		if err := per.EncodeBitStringAligned(bb, v.MobilityInformation.Bytes, v.MobilityInformation.BitLength, 32, 32, true); err != nil {
			return fmt.Errorf("encoding mobilityInformation: %w", err)
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

// UnmarshalAPER decodes TooEarlyInterRATHOReportReportFromEUTRAN from APER format.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *TooEarlyInterRATHOReportReportFromEUTRAN) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = TooEarlyInterRATHOReportReportFromEUTRAN{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_mobilityinformation, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_uerlfreportcontainer, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return fmt.Errorf("decoding uERLFReportContainer: %w", err)
	}
	v.UERLFReportContainer = val_uerlfreportcontainer
	if opt_mobilityinformation {
		bsBytes_mobilityinformation, bsBitLen_mobilityinformation, err := per.DecodeBitStringAligned(bb, 32, 32, true)
		if err != nil {
			return fmt.Errorf("decoding mobilityInformation: %w", err)
		}
		tmp_mobilityinformation := runtime.BitString{Bytes: bsBytes_mobilityinformation, BitLength: bsBitLen_mobilityinformation}
		v.MobilityInformation = &tmp_mobilityinformation
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes EHRPDSectorLoadReportingResponse to APER format.
func (v *EHRPDSectorLoadReportingResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *EHRPDSectorLoadReportingResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := v.DLEHRPDCompositeAvailableCapacity.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding dL-EHRPD-CompositeAvailableCapacity: %w", err)
	}
	if err := v.ULEHRPDCompositeAvailableCapacity.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding uL-EHRPD-CompositeAvailableCapacity: %w", err)
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

// UnmarshalAPER decodes EHRPDSectorLoadReportingResponse from APER format.
func (v *EHRPDSectorLoadReportingResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *EHRPDSectorLoadReportingResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EHRPDSectorLoadReportingResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.DLEHRPDCompositeAvailableCapacity.UnmarshalAPERFrom(bb); err != nil {
		return fmt.Errorf("decoding dL-EHRPD-CompositeAvailableCapacity: %w", err)
	}
	if err := v.ULEHRPDCompositeAvailableCapacity.UnmarshalAPERFrom(bb); err != nil {
		return fmt.Errorf("decoding uL-EHRPD-CompositeAvailableCapacity: %w", err)
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes EHRPDCompositeAvailableCapacity to APER format.
func (v *EHRPDCompositeAvailableCapacity) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *EHRPDCompositeAvailableCapacity) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.EHRPDSectorCapacityClassValue, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("100"), true); err != nil {
		return fmt.Errorf("encoding eHRPDSectorCapacityClassValue: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.EHRPDCapacityValue), int64Ptr(0), int64Ptr(100), false); err != nil {
		return fmt.Errorf("encoding eHRPDCapacityValue: %w", err)
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

// UnmarshalAPER decodes EHRPDCompositeAvailableCapacity from APER format.
func (v *EHRPDCompositeAvailableCapacity) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *EHRPDCompositeAvailableCapacity) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EHRPDCompositeAvailableCapacity{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_ehrpdsectorcapacityclassvalue, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("100"), true)
	if err != nil {
		return fmt.Errorf("decoding eHRPDSectorCapacityClassValue: %w", err)
	}
	v.EHRPDSectorCapacityClassValue = val_ehrpdsectorcapacityclassvalue
	val_ehrpdcapacityvalue, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(100), false)
	if err != nil {
		return fmt.Errorf("decoding eHRPDCapacityValue: %w", err)
	}
	v.EHRPDCapacityValue = EHRPDCapacityValue(val_ehrpdcapacityvalue)
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalAPER encodes EHRPDMultiSectorLoadReportingResponseItem to APER format.
func (v *EHRPDMultiSectorLoadReportingResponseItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *EHRPDMultiSectorLoadReportingResponseItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.EHRPDSectorID), 16, 16, true); err != nil {
		return fmt.Errorf("encoding eHRPD-Sector-ID: %w", err)
	}
	if err := v.EHRPDSectorLoadReportingResponse.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding eHRPDSectorLoadReportingResponse: %w", err)
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

// UnmarshalAPER decodes EHRPDMultiSectorLoadReportingResponseItem from APER format.
func (v *EHRPDMultiSectorLoadReportingResponseItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return err
	}
	return per.ValidateFinalPadding(bb)
}

func (v *EHRPDMultiSectorLoadReportingResponseItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EHRPDMultiSectorLoadReportingResponseItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_ehrpdsectorid, err := per.DecodeOctetStringAligned(bb, 16, 16, true)
	if err != nil {
		return fmt.Errorf("decoding eHRPD-Sector-ID: %w", err)
	}
	v.EHRPDSectorID = EHRPDSectorID(val_ehrpdsectorid)
	if err := v.EHRPDSectorLoadReportingResponse.UnmarshalAPERFrom(bb); err != nil {
		return fmt.Errorf("decoding eHRPDSectorLoadReportingResponse: %w", err)
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmapAligned(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}
