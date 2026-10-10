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
	PERPadding_                     per.CompletePadding                     `json:"-"`
	PEROpenTypePadding_             per.CompletePadding                     `json:"-"`
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
	PERPadding_                     per.CompletePadding                      `json:"-"`
	PEROpenTypePadding_             per.CompletePadding                      `json:"-"`
	UnknownExtension                *runtime.PERChoiceExtension              `json:"UnknownExtension,omitempty"`
	CellLoadReporting               *CellLoadReportingResponse               `json:"CellLoadReporting,omitempty"`
	MultiCellLoadReporting          MultiCellLoadReportingResponse           `json:"MultiCellLoadReporting,omitzero"`
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
	PERPadding_                     per.CompletePadding         `json:"-"`
	PEROpenTypePadding_             per.CompletePadding         `json:"-"`
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
	Choice              int
	PERPadding_         per.CompletePadding               `json:"-"`
	PEROpenTypePadding_ per.CompletePadding               `json:"-"`
	UnknownExtension    *runtime.PERChoiceExtension       `json:"UnknownExtension,omitempty"`
	EUTRAN              *EUTRANcellLoadReportingResponse  `json:"EUTRAN,omitempty"`
	UTRAN               []byte                            `json:"UTRAN,omitzero"`
	GERAN               []byte                            `json:"GERAN,omitzero"`
	EHRPD               *EHRPDSectorLoadReportingResponse `json:"EHRPD,omitempty"`
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
	PERPadding_                     per.FinalPadding                `asn1:"-" json:"-"`
	PERExtPadding_                  []per.CompletePadding           `asn1:"-" json:"-"`
}

// EUTRANResponse represents the ASN.1 type EUTRANResponse (SEQUENCE).
type EUTRANResponse struct {
	CellID                          []byte                          `asn1:"tag:0,context,implicit"`
	EUTRANcellLoadReportingResponse EUTRANcellLoadReportingResponse `asn1:"tag:1,context,implicit"`
	ExtCount_                       int64                           `asn1:"-" json:"-"`
	ExtPresent_                     []bool                          `asn1:"-" json:"-"`
	ExtData_                        [][]byte                        `asn1:"-" json:"-"`
	PERPadding_                     per.FinalPadding                `asn1:"-" json:"-"`
	PERExtPadding_                  []per.CompletePadding           `asn1:"-" json:"-"`
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
	Choice              int
	PERPadding_         per.CompletePadding         `json:"-"`
	PEROpenTypePadding_ per.CompletePadding         `json:"-"`
	UnknownExtension    *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	EUTRAN              []byte                      `json:"EUTRAN,omitzero"`
	UTRAN               []byte                      `json:"UTRAN,omitzero"`
	GERAN               []byte                      `json:"GERAN,omitzero"`
	EHRPD               *EHRPDSectorID              `json:"EHRPD,omitempty"`
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
	RequestedCellList       RequestedCellList     `asn1:"tag:0,context,implicit"`
	RequestedCellListIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_               int64                 `asn1:"-" json:"-"`
	ExtPresent_             []bool                `asn1:"-" json:"-"`
	ExtData_                [][]byte              `asn1:"-" json:"-"`
	PERPadding_             per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_          []per.CompletePadding `asn1:"-" json:"-"`
}

// ReportingCellListItem represents the ASN.1 type ReportingCellList-Item (SEQUENCE).
type ReportingCellListItem struct {
	CellID         IRATCellID            `asn1:"tag:0,context,explicit"`
	ExtCount_      int64                 `asn1:"-" json:"-"`
	ExtPresent_    []bool                `asn1:"-" json:"-"`
	ExtData_       [][]byte              `asn1:"-" json:"-"`
	PERPadding_    per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_ []per.CompletePadding `asn1:"-" json:"-"`
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
	Choice              int
	PERPadding_         per.CompletePadding                        `json:"-"`
	PEROpenTypePadding_ per.CompletePadding                        `json:"-"`
	UnknownExtension    *runtime.PERChoiceExtension                `json:"UnknownExtension,omitempty"`
	EUTRANResponse      *EUTRANResponse                            `json:"EUTRANResponse,omitempty"`
	UTRANResponse       []byte                                     `json:"UTRANResponse,omitzero"`
	GERANResponse       []byte                                     `json:"GERANResponse,omitzero"`
	EHRPD               *EHRPDMultiSectorLoadReportingResponseItem `json:"EHRPD,omitempty"`
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
	PERPadding_                        per.FinalPadding                   `asn1:"-" json:"-"`
	PERExtPadding_                     []per.CompletePadding              `asn1:"-" json:"-"`
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
	PERPadding_               per.FinalPadding          `asn1:"-" json:"-"`
	PERExtPadding_            []per.CompletePadding     `asn1:"-" json:"-"`
}

// HOReport represents the ASN.1 type HOReport (SEQUENCE).
type HOReport struct {
	HoType                  HoType                `asn1:"tag:0,context,implicit"`
	HoReportType            HoReportType          `asn1:"tag:1,context,implicit"`
	HosourceID              IRATCellID            `asn1:"tag:2,context,explicit"`
	HoTargetID              IRATCellID            `asn1:"tag:3,context,explicit"`
	CandidateCellList       CandidateCellList     `asn1:"tag:4,context,implicit"`
	CandidateCellListIndef_ bool                  `asn1:"-" json:"-"`
	CandidatePCIList        CandidatePCIList      `asn1:"tag:5,context,implicit,optional" json:"CandidatePCIList,omitzero"`
	CandidatePCIListIndef_  bool                  `asn1:"-" json:"-"`
	ExtCount_               int64                 `asn1:"-" json:"-"`
	ExtPresent_             []bool                `asn1:"-" json:"-"`
	ExtData_                [][]byte              `asn1:"-" json:"-"`
	PERPadding_             per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_          []per.CompletePadding `asn1:"-" json:"-"`
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
	PCI            int64                 `asn1:"tag:0,context,implicit"`
	EARFCN         []byte                `asn1:"tag:1,context,implicit"`
	ExtCount_      int64                 `asn1:"-" json:"-"`
	ExtPresent_    []bool                `asn1:"-" json:"-"`
	ExtData_       [][]byte              `asn1:"-" json:"-"`
	PERPadding_    per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_ []per.CompletePadding `asn1:"-" json:"-"`
}

// CellActivationRequest represents the ASN.1 type CellActivationRequest (SEQUENCE).
type CellActivationRequest struct {
	CellsToActivateList       CellsToActivateList   `asn1:"tag:0,context,implicit"`
	CellsToActivateListIndef_ bool                  `asn1:"-" json:"-"`
	MinimumActivationTime     *int64                `asn1:"tag:1,context,implicit,optional" json:"MinimumActivationTime,omitempty"`
	ExtCount_                 int64                 `asn1:"-" json:"-"`
	ExtPresent_               []bool                `asn1:"-" json:"-"`
	ExtData_                  [][]byte              `asn1:"-" json:"-"`
	PERPadding_               per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_            []per.CompletePadding `asn1:"-" json:"-"`
}

// CellsToActivateList represents the ASN.1 type CellsToActivateList (SEQUENCE_OF).

type CellsToActivateList = []CellsToActivateListItem

// CellsToActivateListItem represents the ASN.1 type CellsToActivateList-Item (SEQUENCE).
type CellsToActivateListItem struct {
	CellID         []byte                `asn1:"tag:0,context,implicit"`
	ExtCount_      int64                 `asn1:"-" json:"-"`
	ExtPresent_    []bool                `asn1:"-" json:"-"`
	ExtData_       [][]byte              `asn1:"-" json:"-"`
	PERPadding_    per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_ []per.CompletePadding `asn1:"-" json:"-"`
}

// CellActivationResponse represents the ASN.1 type CellActivationResponse (SEQUENCE).
type CellActivationResponse struct {
	ActivatedCellsList       ActivatedCellsList    `asn1:"tag:0,context,implicit"`
	ActivatedCellsListIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_                int64                 `asn1:"-" json:"-"`
	ExtPresent_              []bool                `asn1:"-" json:"-"`
	ExtData_                 [][]byte              `asn1:"-" json:"-"`
	PERPadding_              per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_           []per.CompletePadding `asn1:"-" json:"-"`
}

// ActivatedCellsList represents the ASN.1 type ActivatedCellsList (SEQUENCE_OF).

type ActivatedCellsList = []ActivatedCellsListItem

// ActivatedCellsListItem represents the ASN.1 type ActivatedCellsList-Item (SEQUENCE).
type ActivatedCellsListItem struct {
	CellID         []byte                `asn1:"tag:0,context,implicit"`
	ExtCount_      int64                 `asn1:"-" json:"-"`
	ExtPresent_    []bool                `asn1:"-" json:"-"`
	ExtData_       [][]byte              `asn1:"-" json:"-"`
	PERPadding_    per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_ []per.CompletePadding `asn1:"-" json:"-"`
}

// CellStateIndication represents the ASN.1 type CellStateIndication (SEQUENCE).
type CellStateIndication struct {
	NotificationCellList       NotificationCellList  `asn1:"tag:0,context,implicit"`
	NotificationCellListIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_                  int64                 `asn1:"-" json:"-"`
	ExtPresent_                []bool                `asn1:"-" json:"-"`
	ExtData_                   [][]byte              `asn1:"-" json:"-"`
	PERPadding_                per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_             []per.CompletePadding `asn1:"-" json:"-"`
}

// NotificationCellList represents the ASN.1 type NotificationCellList (SEQUENCE_OF).

type NotificationCellList = []NotificationCellListItem

// NotificationCellListItem represents the ASN.1 type NotificationCellList-Item (SEQUENCE).
type NotificationCellListItem struct {
	CellID         []byte                `asn1:"tag:0,context,implicit"`
	NotifyFlag     NotifyFlag            `asn1:"tag:1,context,implicit"`
	ExtCount_      int64                 `asn1:"-" json:"-"`
	ExtPresent_    []bool                `asn1:"-" json:"-"`
	ExtData_       [][]byte              `asn1:"-" json:"-"`
	PERPadding_    per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_ []per.CompletePadding `asn1:"-" json:"-"`
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
	PERPadding_                        per.CompletePadding                       `json:"-"`
	PEROpenTypePadding_                per.CompletePadding                       `json:"-"`
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
	UERLFReportContainer []byte                `asn1:"tag:0,context,implicit"`
	MobilityInformation  *MobilityInformation  `asn1:"tag:1,context,implicit,optional" json:"MobilityInformation,omitempty"`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	ExtData_             [][]byte              `asn1:"-" json:"-"`
	PERPadding_          per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_       []per.CompletePadding `asn1:"-" json:"-"`
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
	PERPadding_                       per.FinalPadding                `asn1:"-" json:"-"`
	PERExtPadding_                    []per.CompletePadding           `asn1:"-" json:"-"`
}

// EHRPDCompositeAvailableCapacity represents the ASN.1 type EHRPDCompositeAvailableCapacity (SEQUENCE).
type EHRPDCompositeAvailableCapacity struct {
	EHRPDSectorCapacityClassValue EHRPDSectorCapacityClassValue `asn1:"tag:0,context,implicit"`
	EHRPDCapacityValue            EHRPDCapacityValue            `asn1:"tag:1,context,implicit"`
	ExtCount_                     int64                         `asn1:"-" json:"-"`
	ExtPresent_                   []bool                        `asn1:"-" json:"-"`
	ExtData_                      [][]byte                      `asn1:"-" json:"-"`
	PERPadding_                   per.FinalPadding              `asn1:"-" json:"-"`
	PERExtPadding_                []per.CompletePadding         `asn1:"-" json:"-"`
}

// EHRPDMultiSectorLoadReportingResponseItem represents the ASN.1 type EHRPDMultiSectorLoadReportingResponseItem (SEQUENCE).
type EHRPDMultiSectorLoadReportingResponseItem struct {
	EHRPDSectorID                    EHRPDSectorID                    `asn1:"tag:0,context,implicit"`
	EHRPDSectorLoadReportingResponse EHRPDSectorLoadReportingResponse `asn1:"tag:1,context,implicit"`
	ExtCount_                        int64                            `asn1:"-" json:"-"`
	ExtPresent_                      []bool                           `asn1:"-" json:"-"`
	ExtData_                         [][]byte                         `asn1:"-" json:"-"`
	PERPadding_                      per.FinalPadding                 `asn1:"-" json:"-"`
	PERExtPadding_                   []per.CompletePadding            `asn1:"-" json:"-"`
}

// MarshalAPER encodes SONtransferRequestContainer to APER format.
func (v *SONtransferRequestContainer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *SONtransferRequestContainer) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("SONtransferRequestContainer: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("SONtransferRequestContainer: extension index %d must be non-negative", v.UnknownExtension.Index)
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
	if v.Choice < 1 {
		return fmt.Errorf("SONtransferRequestContainer: choice %d must be positive", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 1 {
			return fmt.Errorf("extension choice index outside root")
		}
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
		openBytes, err := inner.CompleteBytesWithPadding(v.PEROpenTypePadding_)
		if err != nil {
			return err
		}
		if err := per.EncodeOpenTypeAligned(bb, openBytes); err != nil {
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
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes SONtransferRequestContainer with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *SONtransferRequestContainer) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferRequestContainer")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferRequestContainer")
	}
	padding, err := per.CaptureFinalBits(bb, "SONtransferRequestContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONtransferRequestContainer")
	}
	v.PERPadding_ = padding.Padding()
	return nil
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
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:205
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(1) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 1 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case SONtransferRequestContainerChoiceMultiCellLoadReporting:
			extensionPath = "MultiCellLoadReporting"
			var dec_multicellloadreporting MultiCellLoadReportingRequest
			if err := dec_multicellloadreporting.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "MultiCellLoadReporting")
			}
			v.MultiCellLoadReporting = &dec_multicellloadreporting
		case SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting:
			extensionPath = "EventTriggeredCellLoadReporting"
			var dec_eventtriggeredcellloadreporting EventTriggeredCellLoadReportingRequest
			if err := dec_eventtriggeredcellloadreporting.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReporting")
			}
			v.EventTriggeredCellLoadReporting = &dec_eventtriggeredcellloadreporting
		case SONtransferRequestContainerChoiceHOReporting:
			extensionPath = "HOReporting"
			var dec_horeporting HOReport
			if err := dec_horeporting.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "HOReporting")
			}
			v.HOReporting = &dec_horeporting
		case SONtransferRequestContainerChoiceEutranCellActivation:
			extensionPath = "EutranCellActivation"
			var dec_eutrancellactivation CellActivationRequest
			if err := dec_eutrancellactivation.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "EutranCellActivation")
			}
			v.EutranCellActivation = &dec_eutrancellactivation
		case SONtransferRequestContainerChoiceEnergySavingsIndication:
			extensionPath = "EnergySavingsIndication"
			var dec_energysavingsindication CellStateIndication
			if err := dec_energysavingsindication.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "EnergySavingsIndication")
			}
			v.EnergySavingsIndication = &dec_energysavingsindication
		case SONtransferRequestContainerChoiceFailureEventReporting:
			extensionPath = "FailureEventReporting"
			var dec_failureeventreporting FailureEventReport
			if err := dec_failureeventreporting.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "FailureEventReporting")
			}
			v.FailureEventReporting = &dec_failureeventreporting
		}
		padding, err := per.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.PEROpenTypePadding_ = padding
		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case SONtransferRequestContainerChoiceCellLoadReporting:
		v.CellLoadReporting = new(struct{})
	}
	return nil
}

// MarshalAPER encodes SONtransferResponseContainer to APER format.
func (v *SONtransferResponseContainer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *SONtransferResponseContainer) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("SONtransferResponseContainer: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("SONtransferResponseContainer: extension index %d must be non-negative", v.UnknownExtension.Index)
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
	if v.Choice < 1 {
		return fmt.Errorf("SONtransferResponseContainer: choice %d must be positive", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 1 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-1-1)); err != nil {
			return err
		}
		inner := per.NewBitBuffer()
		switch v.Choice {
		case SONtransferResponseContainerChoiceMultiCellLoadReporting:
			if err := per.EncodeCollection(inner, int64(len(v.MultiCellLoadReporting)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_multicellloadreporting, fragmentLength_multicellloadreporting int64) error {
				// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
				if fragmentOffset_multicellloadreporting < 0 || fragmentOffset_multicellloadreporting > int64(len(v.MultiCellLoadReporting)) || fragmentLength_multicellloadreporting < 0 || fragmentLength_multicellloadreporting > int64(len(v.MultiCellLoadReporting[fragmentOffset_multicellloadreporting:])) {
					return fmt.Errorf("collection fragment outside value")
				}
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
		openBytes, err := inner.CompleteBytesWithPadding(v.PEROpenTypePadding_)
		if err != nil {
			return err
		}
		if err := per.EncodeOpenTypeAligned(bb, openBytes); err != nil {
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
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes SONtransferResponseContainer with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *SONtransferResponseContainer) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferResponseContainer")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferResponseContainer")
	}
	padding, err := per.CaptureFinalBits(bb, "SONtransferResponseContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONtransferResponseContainer")
	}
	v.PERPadding_ = padding.Padding()
	return nil
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
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:205
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(1) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 1 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case SONtransferResponseContainerChoiceMultiCellLoadReporting:
			extensionPath = "MultiCellLoadReporting"
			tmp_multicellloadreporting := make(MultiCellLoadReportingResponse, 0)
			_, errCollection_multicellloadreporting := per.DecodeCollection(inner, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_multicellloadreporting, fragmentLength_multicellloadreporting int64) error {
				// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
				if fragmentOffset_multicellloadreporting < 0 || fragmentLength_multicellloadreporting < 0 || fragmentLength_multicellloadreporting > int64(^uint(0)>>1) || fragmentOffset_multicellloadreporting > int64(^uint(0)>>1)-fragmentLength_multicellloadreporting {
					return fmt.Errorf("collection fragment count out of range")
				}
				for i := int64(0); i < fragmentLength_multicellloadreporting; i++ {
					var elem MultiCellLoadReportingResponseItem
					if err := elem.UnmarshalAPERFrom(inner); err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("MultiCellLoadReporting[%d]", fragmentOffset_multicellloadreporting+i))
					}
					tmp_multicellloadreporting = append(tmp_multicellloadreporting, elem)
				}
				return nil
			})
			if errCollection_multicellloadreporting != nil {
				return runtime.WrapDecodePath(errCollection_multicellloadreporting, "MultiCellLoadReporting")
			}
			v.MultiCellLoadReporting = tmp_multicellloadreporting
		case SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting:
			extensionPath = "EventTriggeredCellLoadReporting"
			var dec_eventtriggeredcellloadreporting EventTriggeredCellLoadReportingResponse
			if err := dec_eventtriggeredcellloadreporting.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReporting")
			}
			v.EventTriggeredCellLoadReporting = &dec_eventtriggeredcellloadreporting
		case SONtransferResponseContainerChoiceHOReporting:
			extensionPath = "HOReporting"
			v.HOReporting = new(struct{})
		case SONtransferResponseContainerChoiceEutranCellActivation:
			extensionPath = "EutranCellActivation"
			var dec_eutrancellactivation CellActivationResponse
			if err := dec_eutrancellactivation.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "EutranCellActivation")
			}
			v.EutranCellActivation = &dec_eutrancellactivation
		case SONtransferResponseContainerChoiceEnergySavingsIndication:
			extensionPath = "EnergySavingsIndication"
			v.EnergySavingsIndication = new(struct{})
		case SONtransferResponseContainerChoiceFailureEventReporting:
			extensionPath = "FailureEventReporting"
			v.FailureEventReporting = new(struct{})
		}
		padding, err := per.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.PEROpenTypePadding_ = padding
		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case SONtransferResponseContainerChoiceCellLoadReporting:
		toleranceMark_cellloadreporting := bb.EnterComponent("CellLoadReporting")
		var dec_cellloadreporting CellLoadReportingResponse
		if err := dec_cellloadreporting.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CellLoadReporting")
		}
		v.CellLoadReporting = &dec_cellloadreporting
		bb.LeaveComponent(toleranceMark_cellloadreporting)
	}
	return nil
}

// MarshalAPER encodes SONtransferCause to APER format.
func (v *SONtransferCause) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *SONtransferCause) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("SONtransferCause: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("SONtransferCause: extension index %d must be non-negative", v.UnknownExtension.Index)
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
	if v.Choice < 1 {
		return fmt.Errorf("SONtransferCause: choice %d must be positive", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 1 {
			return fmt.Errorf("extension choice index outside root")
		}
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
		openBytes, err := inner.CompleteBytesWithPadding(v.PEROpenTypePadding_)
		if err != nil {
			return err
		}
		if err := per.EncodeOpenTypeAligned(bb, openBytes); err != nil {
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
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes SONtransferCause with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *SONtransferCause) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferCause")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferCause")
	}
	padding, err := per.CaptureFinalBits(bb, "SONtransferCause")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONtransferCause")
	}
	v.PERPadding_ = padding.Padding()
	return nil
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
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:205
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(1) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 1 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case SONtransferCauseChoiceMultiCellLoadReporting:
			extensionPath = "MultiCellLoadReporting"
			val_multicellloadreporting, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "MultiCellLoadReporting")
			}
			tmp_multicellloadreporting := CellLoadReportingCause(val_multicellloadreporting)
			v.MultiCellLoadReporting = &tmp_multicellloadreporting
		case SONtransferCauseChoiceEventTriggeredCellLoadReporting:
			extensionPath = "EventTriggeredCellLoadReporting"
			val_eventtriggeredcellloadreporting, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReporting")
			}
			tmp_eventtriggeredcellloadreporting := CellLoadReportingCause(val_eventtriggeredcellloadreporting)
			v.EventTriggeredCellLoadReporting = &tmp_eventtriggeredcellloadreporting
		case SONtransferCauseChoiceHOReporting:
			extensionPath = "HOReporting"
			val_horeporting, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "HOReporting")
			}
			tmp_horeporting := HOReportingCause(val_horeporting)
			v.HOReporting = &tmp_horeporting
		case SONtransferCauseChoiceEutranCellActivation:
			extensionPath = "EutranCellActivation"
			val_eutrancellactivation, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "EutranCellActivation")
			}
			tmp_eutrancellactivation := CellActivationCause(val_eutrancellactivation)
			v.EutranCellActivation = &tmp_eutrancellactivation
		case SONtransferCauseChoiceEnergySavingsIndication:
			extensionPath = "EnergySavingsIndication"
			val_energysavingsindication, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "EnergySavingsIndication")
			}
			tmp_energysavingsindication := CellStateIndicationCause(val_energysavingsindication)
			v.EnergySavingsIndication = &tmp_energysavingsindication
		case SONtransferCauseChoiceFailureEventReporting:
			extensionPath = "FailureEventReporting"
			val_failureeventreporting, err := per.DecodeEnumeratedAligned(inner, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "FailureEventReporting")
			}
			tmp_failureeventreporting := FailureEventReportingCause(val_failureeventreporting)
			v.FailureEventReporting = &tmp_failureeventreporting
		}
		padding, err := per.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.PEROpenTypePadding_ = padding
		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case SONtransferCauseChoiceCellLoadReporting:
		val_cellloadreporting, err := per.DecodeEnumeratedAligned(bb, 3, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "CellLoadReporting")
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
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *CellLoadReportingResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("CellLoadReportingResponse: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("CellLoadReportingResponse: extension index %d must be non-negative", v.UnknownExtension.Index)
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
	if v.Choice < 1 {
		return fmt.Errorf("CellLoadReportingResponse: choice %d must be positive", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 3 {
			return fmt.Errorf("extension choice index outside root")
		}
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
		openBytes, err := inner.CompleteBytesWithPadding(v.PEROpenTypePadding_)
		if err != nil {
			return err
		}
		if err := per.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
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
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes CellLoadReportingResponse with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *CellLoadReportingResponse) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellLoadReportingResponse")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellLoadReportingResponse")
	}
	padding, err := per.CaptureFinalBits(bb, "CellLoadReportingResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellLoadReportingResponse")
	}
	v.PERPadding_ = padding.Padding()
	return nil
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
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:205
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(3) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 3 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case CellLoadReportingResponseChoiceEHRPD:
			extensionPath = "EHRPD"
			var dec_ehrpd EHRPDSectorLoadReportingResponse
			if err := dec_ehrpd.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "EHRPD")
			}
			v.EHRPD = &dec_ehrpd
		}
		padding, err := per.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.PEROpenTypePadding_ = padding
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:235
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case CellLoadReportingResponseChoiceEUTRAN:
		toleranceMark_eutran := bb.EnterComponent("EUTRAN")
		var dec_eutran EUTRANcellLoadReportingResponse
		if err := dec_eutran.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "EUTRAN")
		}
		v.EUTRAN = &dec_eutran
		bb.LeaveComponent(toleranceMark_eutran)
	case CellLoadReportingResponseChoiceUTRAN:
		val_utran, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "UTRAN")
		}
		tmp_utran := val_utran
		v.UTRAN = tmp_utran
	case CellLoadReportingResponseChoiceGERAN:
		val_geran, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "GERAN")
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
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes EUTRANcellLoadReportingResponse from APER format.
func (v *EUTRANcellLoadReportingResponse) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes EUTRANcellLoadReportingResponse with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *EUTRANcellLoadReportingResponse) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANcellLoadReportingResponse")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANcellLoadReportingResponse")
	}
	padding, err := per.CaptureFinalBits(bb, "EUTRANcellLoadReportingResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "EUTRANcellLoadReportingResponse")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *EUTRANcellLoadReportingResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EUTRANcellLoadReportingResponse{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_compositeavailablecapacitygroup, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CompositeAvailableCapacityGroup")
	}
	v.CompositeAvailableCapacityGroup = CompositeAvailableCapacityGroup(val_compositeavailablecapacitygroup)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes EUTRANResponse to APER format.
func (v *EUTRANResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes EUTRANResponse from APER format.
func (v *EUTRANResponse) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes EUTRANResponse with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *EUTRANResponse) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANResponse")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANResponse")
	}
	padding, err := per.CaptureFinalBits(bb, "EUTRANResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "EUTRANResponse")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *EUTRANResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EUTRANResponse{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	v.CellID = val_cellid
	toleranceMark_eutrancellloadreportingresponse := bb.EnterComponent("EUTRANcellLoadReportingResponse")
	if err := v.EUTRANcellLoadReportingResponse.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANcellLoadReportingResponse")
	}
	bb.LeaveComponent(toleranceMark_eutrancellloadreportingresponse)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes IRATCellID to APER format.
func (v *IRATCellID) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *IRATCellID) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("IRATCellID: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("IRATCellID: extension index %d must be non-negative", v.UnknownExtension.Index)
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
	if v.Choice < 1 {
		return fmt.Errorf("IRATCellID: choice %d must be positive", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 3 {
			return fmt.Errorf("extension choice index outside root")
		}
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
		openBytes, err := inner.CompleteBytesWithPadding(v.PEROpenTypePadding_)
		if err != nil {
			return err
		}
		if err := per.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
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
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes IRATCellID with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *IRATCellID) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "IRATCellID")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "IRATCellID")
	}
	padding, err := per.CaptureFinalBits(bb, "IRATCellID")
	if err != nil {
		return runtime.WrapDecodePath(err, "IRATCellID")
	}
	v.PERPadding_ = padding.Padding()
	return nil
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
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:205
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(3) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 3 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case IRATCellIDChoiceEHRPD:
			extensionPath = "EHRPD"
			val_ehrpd, err := per.DecodeOctetStringAligned(inner, 16, 16, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "EHRPD")
			}
			tmp_ehrpd := EHRPDSectorID(val_ehrpd)
			v.EHRPD = &tmp_ehrpd
		}
		padding, err := per.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.PEROpenTypePadding_ = padding
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:235
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case IRATCellIDChoiceEUTRAN:
		val_eutran, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "EUTRAN")
		}
		tmp_eutran := val_eutran
		v.EUTRAN = tmp_eutran
	case IRATCellIDChoiceUTRAN:
		val_utran, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "UTRAN")
		}
		tmp_utran := val_utran
		v.UTRAN = tmp_utran
	case IRATCellIDChoiceGERAN:
		val_geran, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "GERAN")
		}
		tmp_geran := val_geran
		v.GERAN = tmp_geran
	}
	return nil
}

type asn1cAPERRequestedCellListListValue struct{ Value RequestedCellList }

// RequestedCellListComplete carries a complete RequestedCellList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type RequestedCellListComplete struct {
	Value       RequestedCellList
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *RequestedCellListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERRequestedCellListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

// UnmarshalAPER decodes RequestedCellList from APER format.
func (v *RequestedCellListComplete) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes RequestedCellList with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *RequestedCellListComplete) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RequestedCellList")
	}
	value, err := UnmarshalAPERRequestedCellListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "RequestedCellList")
	}
	padding, err := per.CaptureFinalBits(bb, "RequestedCellList")
	if err != nil {
		return runtime.WrapDecodePath(err, "RequestedCellList")
	}
	v.Value, v.PERPadding_ = value, padding.Padding()
	return nil
}

// MarshalAPERRequestedCellList encodes a RequestedCellList list to APER.
func MarshalAPERRequestedCellList(list RequestedCellListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERRequestedCellListTo appends a RequestedCellList list to bb.
func MarshalAPERRequestedCellListTo(list RequestedCellList, bb *per.BitBuffer) error {
	v := asn1cAPERRequestedCellListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERRequestedCellList(data []byte) (RequestedCellListComplete, error) {
	var value RequestedCellListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem IRATCellID
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

// MarshalAPER encodes MultiCellLoadReportingRequest to APER format.
func (v *MultiCellLoadReportingRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *MultiCellLoadReportingRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.RequestedCellList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_requestedcelllist, fragmentLength_requestedcelllist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_requestedcelllist < 0 || fragmentOffset_requestedcelllist > int64(len(v.RequestedCellList)) || fragmentLength_requestedcelllist < 0 || fragmentLength_requestedcelllist > int64(len(v.RequestedCellList[fragmentOffset_requestedcelllist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes MultiCellLoadReportingRequest from APER format.
func (v *MultiCellLoadReportingRequest) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes MultiCellLoadReportingRequest with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *MultiCellLoadReportingRequest) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingRequest")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingRequest")
	}
	padding, err := per.CaptureFinalBits(bb, "MultiCellLoadReportingRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingRequest")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *MultiCellLoadReportingRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MultiCellLoadReportingRequest{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.RequestedCellList = make(RequestedCellList, 0)
	_, errCollection_requestedcelllist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_requestedcelllist, fragmentLength_requestedcelllist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_requestedcelllist < 0 || fragmentLength_requestedcelllist < 0 || fragmentLength_requestedcelllist > int64(^uint(0)>>1) || fragmentOffset_requestedcelllist > int64(^uint(0)>>1)-fragmentLength_requestedcelllist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_requestedcelllist; i++ {
			var elem IRATCellID
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("RequestedCellList[%d]", fragmentOffset_requestedcelllist+i))
			}
			v.RequestedCellList = append(v.RequestedCellList, elem)
		}
		return nil
	})
	if errCollection_requestedcelllist != nil {
		return runtime.WrapDecodePath(errCollection_requestedcelllist, "RequestedCellList")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes ReportingCellListItem to APER format.
func (v *ReportingCellListItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes ReportingCellListItem from APER format.
func (v *ReportingCellListItem) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes ReportingCellListItem with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *ReportingCellListItem) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellListItem")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellListItem")
	}
	padding, err := per.CaptureFinalBits(bb, "ReportingCellListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellListItem")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *ReportingCellListItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ReportingCellListItem{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.CellID.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

type asn1cAPERReportingCellListListValue struct{ Value ReportingCellList }

// ReportingCellListComplete carries a complete ReportingCellList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ReportingCellListComplete struct {
	Value       ReportingCellList
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *ReportingCellListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERReportingCellListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

// UnmarshalAPER decodes ReportingCellList from APER format.
func (v *ReportingCellListComplete) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes ReportingCellList with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *ReportingCellListComplete) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellList")
	}
	value, err := UnmarshalAPERReportingCellListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellList")
	}
	padding, err := per.CaptureFinalBits(bb, "ReportingCellList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellList")
	}
	v.Value, v.PERPadding_ = value, padding.Padding()
	return nil
}

// MarshalAPERReportingCellList encodes a ReportingCellList list to APER.
func MarshalAPERReportingCellList(list ReportingCellListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERReportingCellListTo appends a ReportingCellList list to bb.
func MarshalAPERReportingCellListTo(list ReportingCellList, bb *per.BitBuffer) error {
	v := asn1cAPERReportingCellListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERReportingCellList(data []byte) (ReportingCellListComplete, error) {
	var value ReportingCellListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(ReportingCellList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ReportingCellListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

type asn1cAPERMultiCellLoadReportingResponseListValue struct {
	Value MultiCellLoadReportingResponse
}

// MultiCellLoadReportingResponseComplete carries a complete MultiCellLoadReportingResponse encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MultiCellLoadReportingResponseComplete struct {
	Value       MultiCellLoadReportingResponse
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *MultiCellLoadReportingResponseComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERMultiCellLoadReportingResponseTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

// UnmarshalAPER decodes MultiCellLoadReportingResponse from APER format.
func (v *MultiCellLoadReportingResponseComplete) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes MultiCellLoadReportingResponse with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *MultiCellLoadReportingResponseComplete) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponse")
	}
	value, err := UnmarshalAPERMultiCellLoadReportingResponseFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponse")
	}
	padding, err := per.CaptureFinalBits(bb, "MultiCellLoadReportingResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponse")
	}
	v.Value, v.PERPadding_ = value, padding.Padding()
	return nil
}

// MarshalAPERMultiCellLoadReportingResponse encodes a MultiCellLoadReportingResponse list to APER.
func MarshalAPERMultiCellLoadReportingResponse(list MultiCellLoadReportingResponseComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERMultiCellLoadReportingResponseTo appends a MultiCellLoadReportingResponse list to bb.
func MarshalAPERMultiCellLoadReportingResponseTo(list MultiCellLoadReportingResponse, bb *per.BitBuffer) error {
	v := asn1cAPERMultiCellLoadReportingResponseListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERMultiCellLoadReportingResponse(data []byte) (MultiCellLoadReportingResponseComplete, error) {
	var value MultiCellLoadReportingResponseComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(MultiCellLoadReportingResponse, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem MultiCellLoadReportingResponseItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MarshalAPER encodes MultiCellLoadReportingResponseItem to APER format.
func (v *MultiCellLoadReportingResponseItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *MultiCellLoadReportingResponseItem) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("MultiCellLoadReportingResponseItem: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("MultiCellLoadReportingResponseItem: extension index %d must be non-negative", v.UnknownExtension.Index)
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
	if v.Choice < 1 {
		return fmt.Errorf("MultiCellLoadReportingResponseItem: choice %d must be positive", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 3 {
			return fmt.Errorf("extension choice index outside root")
		}
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
		openBytes, err := inner.CompleteBytesWithPadding(v.PEROpenTypePadding_)
		if err != nil {
			return err
		}
		if err := per.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
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
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes MultiCellLoadReportingResponseItem with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *MultiCellLoadReportingResponseItem) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponseItem")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponseItem")
	}
	padding, err := per.CaptureFinalBits(bb, "MultiCellLoadReportingResponseItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponseItem")
	}
	v.PERPadding_ = padding.Padding()
	return nil
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
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:205
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(3) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 3 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case MultiCellLoadReportingResponseItemChoiceEHRPD:
			extensionPath = "EHRPD"
			var dec_ehrpd EHRPDMultiSectorLoadReportingResponseItem
			if err := dec_ehrpd.UnmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "EHRPD")
			}
			v.EHRPD = &dec_ehrpd
		}
		padding, err := per.CaptureOpenTypePadding(inner)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.PEROpenTypePadding_ = padding
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:235
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case MultiCellLoadReportingResponseItemChoiceEUTRANResponse:
		toleranceMark_eutranresponse := bb.EnterComponent("EUTRANResponse")
		var dec_eutranresponse EUTRANResponse
		if err := dec_eutranresponse.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "EUTRANResponse")
		}
		v.EUTRANResponse = &dec_eutranresponse
		bb.LeaveComponent(toleranceMark_eutranresponse)
	case MultiCellLoadReportingResponseItemChoiceUTRANResponse:
		val_utranresponse, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "UTRANResponse")
		}
		tmp_utranresponse := val_utranresponse
		v.UTRANResponse = tmp_utranresponse
	case MultiCellLoadReportingResponseItemChoiceGERANResponse:
		val_geranresponse, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "GERANResponse")
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
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes EventTriggeredCellLoadReportingRequest from APER format.
func (v *EventTriggeredCellLoadReportingRequest) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes EventTriggeredCellLoadReportingRequest with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *EventTriggeredCellLoadReportingRequest) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingRequest")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingRequest")
	}
	padding, err := per.CaptureFinalBits(bb, "EventTriggeredCellLoadReportingRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingRequest")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *EventTriggeredCellLoadReportingRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EventTriggeredCellLoadReportingRequest{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_numberofmeasurementreportinglevels, err := per.DecodeEnumeratedAligned(bb, 5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberOfMeasurementReportingLevels")
	}
	v.NumberOfMeasurementReportingLevels = NumberOfMeasurementReportingLevels(val_numberofmeasurementreportinglevels)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes EventTriggeredCellLoadReportingResponse to APER format.
func (v *EventTriggeredCellLoadReportingResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes EventTriggeredCellLoadReportingResponse from APER format.
func (v *EventTriggeredCellLoadReportingResponse) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes EventTriggeredCellLoadReportingResponse with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *EventTriggeredCellLoadReportingResponse) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingResponse")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingResponse")
	}
	padding, err := per.CaptureFinalBits(bb, "EventTriggeredCellLoadReportingResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingResponse")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *EventTriggeredCellLoadReportingResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EventTriggeredCellLoadReportingResponse{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_overloadflag, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_cellloadreportingresponse := bb.EnterComponent("CellLoadReportingResponse")
	if err := v.CellLoadReportingResponse.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellLoadReportingResponse")
	}
	bb.LeaveComponent(toleranceMark_cellloadreportingresponse)
	if opt_overloadflag {
		val_overloadflag, err := per.DecodeEnumeratedAligned(bb, 1, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "OverloadFlag")
		}
		tmp_overloadflag := OverloadFlag(val_overloadflag)
		v.OverloadFlag = &tmp_overloadflag
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes HOReport to APER format.
func (v *HOReport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_candidatecelllist < 0 || fragmentOffset_candidatecelllist > int64(len(v.CandidateCellList)) || fragmentLength_candidatecelllist < 0 || fragmentLength_candidatecelllist > int64(len(v.CandidateCellList[fragmentOffset_candidatecelllist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extHighest+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extHighest < 16383; gen/codegen_aper.go:350
		if extHighest < 0 || extHighest >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extHighest)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extHighest+1); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := v.CandidatePCIList != nil
			if err := per.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_HIGHEST_1: 0 <= extHighest < max int; gen/codegen_aper.go:366
		if extHighest < 0 || extHighest >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extHighest; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if v.CandidatePCIList != nil {
			extBuf := per.NewBitBuffer()
			if v.CandidatePCIList != nil {
				if err := per.EncodeCollection(extBuf, int64(len(v.CandidatePCIList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatepcilist, fragmentLength_candidatepcilist int64) error {
					// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
					if fragmentOffset_candidatepcilist < 0 || fragmentOffset_candidatepcilist > int64(len(v.CandidatePCIList)) || fragmentLength_candidatepcilist < 0 || fragmentLength_candidatepcilist > int64(len(v.CandidatePCIList[fragmentOffset_candidatepcilist:])) {
						return fmt.Errorf("collection fragment outside value")
					}
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
		// arithmetic pattern APER_EXT_HIGHEST_2: 0 <= extHighest < max int; gen/codegen_aper.go:418
		if extHighest < 0 || extHighest >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes HOReport from APER format.
func (v *HOReport) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes HOReport with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *HOReport) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HOReport")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HOReport")
	}
	padding, err := per.CaptureFinalBits(bb, "HOReport")
	if err != nil {
		return runtime.WrapDecodePath(err, "HOReport")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *HOReport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HOReport{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_hotype, err := per.DecodeEnumeratedAligned(bb, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "HoType")
	}
	v.HoType = HoType(val_hotype)
	val_horeporttype, err := per.DecodeEnumeratedAligned(bb, 1, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "HoReportType")
	}
	v.HoReportType = HoReportType(val_horeporttype)
	if err := v.HosourceID.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HosourceID")
	}
	if err := v.HoTargetID.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HoTargetID")
	}
	v.CandidateCellList = make(CandidateCellList, 0)
	_, errCollection_candidatecelllist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatecelllist, fragmentLength_candidatecelllist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_candidatecelllist < 0 || fragmentLength_candidatecelllist < 0 || fragmentLength_candidatecelllist > int64(^uint(0)>>1) || fragmentOffset_candidatecelllist > int64(^uint(0)>>1)-fragmentLength_candidatecelllist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_candidatecelllist; i++ {
			var elem IRATCellID
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CandidateCellList[%d]", fragmentOffset_candidatecelllist+i))
			}
			v.CandidateCellList = append(v.CandidateCellList, elem)
		}
		return nil
	})
	if errCollection_candidatecelllist != nil {
		return runtime.WrapDecodePath(errCollection_candidatecelllist, "CandidateCellList")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_ALLOC_1: 0 <= extCount < max int; gen/codegen_aper.go:544
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		// arithmetic pattern APER_EXT_COUNT_ALLOC_2: 0 <= extCount < max int; gen/codegen_aper.go:546
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.PERExtPadding_ = make([]per.CompletePadding, extCount+1)
		if int64(0) <= extCount && extPresent[0] && extAdditions.Received(bb, 0) {
			extData, err := per.DecodeOpenTypeAligned(bb)
			if err != nil {
				return runtime.WrapDecodePath(err, "ExtData_[0]")
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			tmp_candidatepcilist := make(CandidatePCIList, 0)
			_, errCollection_candidatepcilist := per.DecodeCollection(extBB, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatepcilist, fragmentLength_candidatepcilist int64) error {
				// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
				if fragmentOffset_candidatepcilist < 0 || fragmentLength_candidatepcilist < 0 || fragmentLength_candidatepcilist > int64(^uint(0)>>1) || fragmentOffset_candidatepcilist > int64(^uint(0)>>1)-fragmentLength_candidatepcilist {
					return fmt.Errorf("collection fragment count out of range")
				}
				for i := int64(0); i < fragmentLength_candidatepcilist; i++ {
					var elem CandidatePCI
					if err := elem.UnmarshalAPERFrom(extBB); err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("CandidatePCIList[%d]", fragmentOffset_candidatepcilist+i))
					}
					tmp_candidatepcilist = append(tmp_candidatepcilist, elem)
				}
				return nil
			})
			if errCollection_candidatepcilist != nil {
				return runtime.WrapDecodePath(errCollection_candidatepcilist, "CandidatePCIList")
			}
			v.CandidatePCIList = tmp_candidatepcilist
			padding, err := per.CaptureOpenTypePadding(extBB)
			if err != nil {
				return runtime.WrapDecodePath(err, "ExtData_[0]")
			}
			v.PERExtPadding_[0] = padding
		}
		// arithmetic pattern APER_EXT_COUNT_LOOP_1: 0 <= extCount < max int; gen/codegen_aper.go:597
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

type asn1cAPERCandidateCellListListValue struct{ Value CandidateCellList }

// CandidateCellListComplete carries a complete CandidateCellList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CandidateCellListComplete struct {
	Value       CandidateCellList
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *CandidateCellListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERCandidateCellListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

// UnmarshalAPER decodes CandidateCellList from APER format.
func (v *CandidateCellListComplete) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes CandidateCellList with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *CandidateCellListComplete) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CandidateCellList")
	}
	value, err := UnmarshalAPERCandidateCellListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidateCellList")
	}
	padding, err := per.CaptureFinalBits(bb, "CandidateCellList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidateCellList")
	}
	v.Value, v.PERPadding_ = value, padding.Padding()
	return nil
}

// MarshalAPERCandidateCellList encodes a CandidateCellList list to APER.
func MarshalAPERCandidateCellList(list CandidateCellListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERCandidateCellListTo appends a CandidateCellList list to bb.
func MarshalAPERCandidateCellListTo(list CandidateCellList, bb *per.BitBuffer) error {
	v := asn1cAPERCandidateCellListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERCandidateCellList(data []byte) (CandidateCellListComplete, error) {
	var value CandidateCellListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem IRATCellID
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

type asn1cAPERCandidatePCIListListValue struct{ Value CandidatePCIList }

// CandidatePCIListComplete carries a complete CandidatePCIList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CandidatePCIListComplete struct {
	Value       CandidatePCIList
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *CandidatePCIListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERCandidatePCIListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

// UnmarshalAPER decodes CandidatePCIList from APER format.
func (v *CandidatePCIListComplete) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes CandidatePCIList with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *CandidatePCIListComplete) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCIList")
	}
	value, err := UnmarshalAPERCandidatePCIListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCIList")
	}
	padding, err := per.CaptureFinalBits(bb, "CandidatePCIList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCIList")
	}
	v.Value, v.PERPadding_ = value, padding.Padding()
	return nil
}

// MarshalAPERCandidatePCIList encodes a CandidatePCIList list to APER.
func MarshalAPERCandidatePCIList(list CandidatePCIListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERCandidatePCIListTo appends a CandidatePCIList list to bb.
func MarshalAPERCandidatePCIListTo(list CandidatePCIList, bb *per.BitBuffer) error {
	v := asn1cAPERCandidatePCIListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERCandidatePCIList(data []byte) (CandidatePCIListComplete, error) {
	var value CandidatePCIListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(CandidatePCIList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem CandidatePCI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MarshalAPER encodes CandidatePCI to APER format.
func (v *CandidatePCI) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes CandidatePCI from APER format.
func (v *CandidatePCI) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes CandidatePCI with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *CandidatePCI) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCI")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCI")
	}
	padding, err := per.CaptureFinalBits(bb, "CandidatePCI")
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCI")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *CandidatePCI) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CandidatePCI{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PCI")
	}
	v.PCI = val_pci
	val_earfcn, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "EARFCN")
	}
	v.EARFCN = val_earfcn
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes CellActivationRequest to APER format.
func (v *CellActivationRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_cellstoactivatelist < 0 || fragmentOffset_cellstoactivatelist > int64(len(v.CellsToActivateList)) || fragmentLength_cellstoactivatelist < 0 || fragmentLength_cellstoactivatelist > int64(len(v.CellsToActivateList[fragmentOffset_cellstoactivatelist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes CellActivationRequest from APER format.
func (v *CellActivationRequest) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes CellActivationRequest with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *CellActivationRequest) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationRequest")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationRequest")
	}
	padding, err := per.CaptureFinalBits(bb, "CellActivationRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellActivationRequest")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *CellActivationRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CellActivationRequest{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_minimumactivationtime, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_cellstoactivatelist := bb.EnterComponent("CellsToActivateList")
	v.CellsToActivateList = make(CellsToActivateList, 0)
	_, errCollection_cellstoactivatelist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_cellstoactivatelist, fragmentLength_cellstoactivatelist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_cellstoactivatelist < 0 || fragmentLength_cellstoactivatelist < 0 || fragmentLength_cellstoactivatelist > int64(^uint(0)>>1) || fragmentOffset_cellstoactivatelist > int64(^uint(0)>>1)-fragmentLength_cellstoactivatelist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_cellstoactivatelist; i++ {
			var elem CellsToActivateListItem
			elementMark := bb.EnterIndex(fragmentOffset_cellstoactivatelist + i)
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CellsToActivateList[%d]", fragmentOffset_cellstoactivatelist+i))
			}
			bb.LeaveComponent(elementMark)
			v.CellsToActivateList = append(v.CellsToActivateList, elem)
		}
		return nil
	})
	if errCollection_cellstoactivatelist != nil {
		return runtime.WrapDecodePath(errCollection_cellstoactivatelist, "CellsToActivateList")
	}
	bb.LeaveComponent(toleranceMark_cellstoactivatelist)
	if opt_minimumactivationtime {
		val_minimumactivationtime, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(60), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "MinimumActivationTime")
		}
		v.MinimumActivationTime = &val_minimumactivationtime
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

type asn1cAPERCellsToActivateListListValue struct{ Value CellsToActivateList }

// CellsToActivateListComplete carries a complete CellsToActivateList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CellsToActivateListComplete struct {
	Value       CellsToActivateList
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *CellsToActivateListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERCellsToActivateListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

// UnmarshalAPER decodes CellsToActivateList from APER format.
func (v *CellsToActivateListComplete) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes CellsToActivateList with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *CellsToActivateListComplete) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateList")
	}
	value, err := UnmarshalAPERCellsToActivateListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateList")
	}
	padding, err := per.CaptureFinalBits(bb, "CellsToActivateList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateList")
	}
	v.Value, v.PERPadding_ = value, padding.Padding()
	return nil
}

// MarshalAPERCellsToActivateList encodes a CellsToActivateList list to APER.
func MarshalAPERCellsToActivateList(list CellsToActivateListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERCellsToActivateListTo appends a CellsToActivateList list to bb.
func MarshalAPERCellsToActivateListTo(list CellsToActivateList, bb *per.BitBuffer) error {
	v := asn1cAPERCellsToActivateListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERCellsToActivateList(data []byte) (CellsToActivateListComplete, error) {
	var value CellsToActivateListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(CellsToActivateList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem CellsToActivateListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MarshalAPER encodes CellsToActivateListItem to APER format.
func (v *CellsToActivateListItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes CellsToActivateListItem from APER format.
func (v *CellsToActivateListItem) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes CellsToActivateListItem with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *CellsToActivateListItem) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateListItem")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateListItem")
	}
	padding, err := per.CaptureFinalBits(bb, "CellsToActivateListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateListItem")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *CellsToActivateListItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CellsToActivateListItem{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	v.CellID = val_cellid
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes CellActivationResponse to APER format.
func (v *CellActivationResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *CellActivationResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ActivatedCellsList)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_activatedcellslist, fragmentLength_activatedcellslist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_activatedcellslist < 0 || fragmentOffset_activatedcellslist > int64(len(v.ActivatedCellsList)) || fragmentLength_activatedcellslist < 0 || fragmentLength_activatedcellslist > int64(len(v.ActivatedCellsList[fragmentOffset_activatedcellslist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes CellActivationResponse from APER format.
func (v *CellActivationResponse) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes CellActivationResponse with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *CellActivationResponse) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	padding, err := per.CaptureFinalBits(bb, "CellActivationResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *CellActivationResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CellActivationResponse{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_activatedcellslist := bb.EnterComponent("ActivatedCellsList")
	v.ActivatedCellsList = make(ActivatedCellsList, 0)
	_, errCollection_activatedcellslist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_activatedcellslist, fragmentLength_activatedcellslist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_activatedcellslist < 0 || fragmentLength_activatedcellslist < 0 || fragmentLength_activatedcellslist > int64(^uint(0)>>1) || fragmentOffset_activatedcellslist > int64(^uint(0)>>1)-fragmentLength_activatedcellslist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_activatedcellslist; i++ {
			var elem ActivatedCellsListItem
			elementMark := bb.EnterIndex(fragmentOffset_activatedcellslist + i)
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ActivatedCellsList[%d]", fragmentOffset_activatedcellslist+i))
			}
			bb.LeaveComponent(elementMark)
			v.ActivatedCellsList = append(v.ActivatedCellsList, elem)
		}
		return nil
	})
	if errCollection_activatedcellslist != nil {
		return runtime.WrapDecodePath(errCollection_activatedcellslist, "ActivatedCellsList")
	}
	bb.LeaveComponent(toleranceMark_activatedcellslist)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

type asn1cAPERActivatedCellsListListValue struct{ Value ActivatedCellsList }

// ActivatedCellsListComplete carries a complete ActivatedCellsList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ActivatedCellsListComplete struct {
	Value       ActivatedCellsList
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *ActivatedCellsListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERActivatedCellsListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

// UnmarshalAPER decodes ActivatedCellsList from APER format.
func (v *ActivatedCellsListComplete) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes ActivatedCellsList with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *ActivatedCellsListComplete) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsList")
	}
	value, err := UnmarshalAPERActivatedCellsListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsList")
	}
	padding, err := per.CaptureFinalBits(bb, "ActivatedCellsList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsList")
	}
	v.Value, v.PERPadding_ = value, padding.Padding()
	return nil
}

// MarshalAPERActivatedCellsList encodes a ActivatedCellsList list to APER.
func MarshalAPERActivatedCellsList(list ActivatedCellsListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERActivatedCellsListTo appends a ActivatedCellsList list to bb.
func MarshalAPERActivatedCellsListTo(list ActivatedCellsList, bb *per.BitBuffer) error {
	v := asn1cAPERActivatedCellsListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERActivatedCellsList(data []byte) (ActivatedCellsListComplete, error) {
	var value ActivatedCellsListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(ActivatedCellsList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ActivatedCellsListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MarshalAPER encodes ActivatedCellsListItem to APER format.
func (v *ActivatedCellsListItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes ActivatedCellsListItem from APER format.
func (v *ActivatedCellsListItem) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes ActivatedCellsListItem with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *ActivatedCellsListItem) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsListItem")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsListItem")
	}
	padding, err := per.CaptureFinalBits(bb, "ActivatedCellsListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsListItem")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *ActivatedCellsListItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ActivatedCellsListItem{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	v.CellID = val_cellid
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes CellStateIndication to APER format.
func (v *CellStateIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *CellStateIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.NotificationCellList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_notificationcelllist, fragmentLength_notificationcelllist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_notificationcelllist < 0 || fragmentOffset_notificationcelllist > int64(len(v.NotificationCellList)) || fragmentLength_notificationcelllist < 0 || fragmentLength_notificationcelllist > int64(len(v.NotificationCellList[fragmentOffset_notificationcelllist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes CellStateIndication from APER format.
func (v *CellStateIndication) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes CellStateIndication with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *CellStateIndication) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellStateIndication")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellStateIndication")
	}
	padding, err := per.CaptureFinalBits(bb, "CellStateIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellStateIndication")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *CellStateIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CellStateIndication{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_notificationcelllist := bb.EnterComponent("NotificationCellList")
	v.NotificationCellList = make(NotificationCellList, 0)
	_, errCollection_notificationcelllist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_notificationcelllist, fragmentLength_notificationcelllist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_notificationcelllist < 0 || fragmentLength_notificationcelllist < 0 || fragmentLength_notificationcelllist > int64(^uint(0)>>1) || fragmentOffset_notificationcelllist > int64(^uint(0)>>1)-fragmentLength_notificationcelllist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_notificationcelllist; i++ {
			var elem NotificationCellListItem
			elementMark := bb.EnterIndex(fragmentOffset_notificationcelllist + i)
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("NotificationCellList[%d]", fragmentOffset_notificationcelllist+i))
			}
			bb.LeaveComponent(elementMark)
			v.NotificationCellList = append(v.NotificationCellList, elem)
		}
		return nil
	})
	if errCollection_notificationcelllist != nil {
		return runtime.WrapDecodePath(errCollection_notificationcelllist, "NotificationCellList")
	}
	bb.LeaveComponent(toleranceMark_notificationcelllist)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

type asn1cAPERNotificationCellListListValue struct{ Value NotificationCellList }

// NotificationCellListComplete carries a complete NotificationCellList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type NotificationCellListComplete struct {
	Value       NotificationCellList
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *NotificationCellListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERNotificationCellListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

// UnmarshalAPER decodes NotificationCellList from APER format.
func (v *NotificationCellListComplete) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes NotificationCellList with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *NotificationCellListComplete) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellList")
	}
	value, err := UnmarshalAPERNotificationCellListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellList")
	}
	padding, err := per.CaptureFinalBits(bb, "NotificationCellList")
	if err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellList")
	}
	v.Value, v.PERPadding_ = value, padding.Padding()
	return nil
}

// MarshalAPERNotificationCellList encodes a NotificationCellList list to APER.
func MarshalAPERNotificationCellList(list NotificationCellListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERNotificationCellListTo appends a NotificationCellList list to bb.
func MarshalAPERNotificationCellListTo(list NotificationCellList, bb *per.BitBuffer) error {
	v := asn1cAPERNotificationCellListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERNotificationCellList(data []byte) (NotificationCellListComplete, error) {
	var value NotificationCellListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(NotificationCellList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem NotificationCellListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MarshalAPER encodes NotificationCellListItem to APER format.
func (v *NotificationCellListItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes NotificationCellListItem from APER format.
func (v *NotificationCellListItem) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes NotificationCellListItem with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *NotificationCellListItem) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellListItem")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellListItem")
	}
	padding, err := per.CaptureFinalBits(bb, "NotificationCellListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellListItem")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *NotificationCellListItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = NotificationCellListItem{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	v.CellID = val_cellid
	val_notifyflag, err := per.DecodeEnumeratedAligned(bb, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NotifyFlag")
	}
	v.NotifyFlag = NotifyFlag(val_notifyflag)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes FailureEventReport to APER format.
func (v *FailureEventReport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *FailureEventReport) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("FailureEventReport: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("FailureEventReport: extension index %d must be non-negative", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	if v.Choice < 1 {
		return fmt.Errorf("FailureEventReport: choice %d must be positive", v.Choice)
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
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes FailureEventReport with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *FailureEventReport) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "FailureEventReport")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "FailureEventReport")
	}
	padding, err := per.CaptureFinalBits(bb, "FailureEventReport")
	if err != nil {
		return runtime.WrapDecodePath(err, "FailureEventReport")
	}
	v.PERPadding_ = padding.Padding()
	return nil
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
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN:
		toleranceMark_tooearlyinterrathoreportfromeutran := bb.EnterComponent("TooEarlyInterRATHOReportFromEUTRAN")
		var dec_tooearlyinterrathoreportfromeutran TooEarlyInterRATHOReportReportFromEUTRAN
		if err := dec_tooearlyinterrathoreportfromeutran.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TooEarlyInterRATHOReportFromEUTRAN")
		}
		v.TooEarlyInterRATHOReportFromEUTRAN = &dec_tooearlyinterrathoreportfromeutran
		bb.LeaveComponent(toleranceMark_tooearlyinterrathoreportfromeutran)
	}
	return nil
}

// MarshalAPER encodes TooEarlyInterRATHOReportReportFromEUTRAN to APER format.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes TooEarlyInterRATHOReportReportFromEUTRAN from APER format.
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes TooEarlyInterRATHOReportReportFromEUTRAN with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *TooEarlyInterRATHOReportReportFromEUTRAN) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TooEarlyInterRATHOReportReportFromEUTRAN")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TooEarlyInterRATHOReportReportFromEUTRAN")
	}
	padding, err := per.CaptureFinalBits(bb, "TooEarlyInterRATHOReportReportFromEUTRAN")
	if err != nil {
		return runtime.WrapDecodePath(err, "TooEarlyInterRATHOReportReportFromEUTRAN")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *TooEarlyInterRATHOReportReportFromEUTRAN) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = TooEarlyInterRATHOReportReportFromEUTRAN{}
	extAdditions := per.BeginExtensionAdditions(bb)
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
		return runtime.WrapDecodePath(err, "UERLFReportContainer")
	}
	v.UERLFReportContainer = val_uerlfreportcontainer
	if opt_mobilityinformation {
		bsBytes_mobilityinformation, bsBitLen_mobilityinformation, err := per.DecodeBitStringAligned(bb, 32, 32, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "MobilityInformation")
		}
		tmp_mobilityinformation := runtime.BitString{Bytes: bsBytes_mobilityinformation, BitLength: bsBitLen_mobilityinformation}
		v.MobilityInformation = &tmp_mobilityinformation
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes EHRPDSectorLoadReportingResponse to APER format.
func (v *EHRPDSectorLoadReportingResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes EHRPDSectorLoadReportingResponse from APER format.
func (v *EHRPDSectorLoadReportingResponse) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes EHRPDSectorLoadReportingResponse with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *EHRPDSectorLoadReportingResponse) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorLoadReportingResponse")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorLoadReportingResponse")
	}
	padding, err := per.CaptureFinalBits(bb, "EHRPDSectorLoadReportingResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorLoadReportingResponse")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *EHRPDSectorLoadReportingResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EHRPDSectorLoadReportingResponse{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_dlehrpdcompositeavailablecapacity := bb.EnterComponent("DLEHRPDCompositeAvailableCapacity")
	if err := v.DLEHRPDCompositeAvailableCapacity.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLEHRPDCompositeAvailableCapacity")
	}
	bb.LeaveComponent(toleranceMark_dlehrpdcompositeavailablecapacity)
	toleranceMark_ulehrpdcompositeavailablecapacity := bb.EnterComponent("ULEHRPDCompositeAvailableCapacity")
	if err := v.ULEHRPDCompositeAvailableCapacity.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULEHRPDCompositeAvailableCapacity")
	}
	bb.LeaveComponent(toleranceMark_ulehrpdcompositeavailablecapacity)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes EHRPDCompositeAvailableCapacity to APER format.
func (v *EHRPDCompositeAvailableCapacity) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes EHRPDCompositeAvailableCapacity from APER format.
func (v *EHRPDCompositeAvailableCapacity) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes EHRPDCompositeAvailableCapacity with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *EHRPDCompositeAvailableCapacity) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDCompositeAvailableCapacity")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDCompositeAvailableCapacity")
	}
	padding, err := per.CaptureFinalBits(bb, "EHRPDCompositeAvailableCapacity")
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDCompositeAvailableCapacity")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *EHRPDCompositeAvailableCapacity) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EHRPDCompositeAvailableCapacity{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_ehrpdsectorcapacityclassvalue, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("100"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorCapacityClassValue")
	}
	v.EHRPDSectorCapacityClassValue = val_ehrpdsectorcapacityclassvalue
	val_ehrpdcapacityvalue, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(100), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDCapacityValue")
	}
	v.EHRPDCapacityValue = EHRPDCapacityValue(val_ehrpdcapacityvalue)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}

// MarshalAPER encodes EHRPDMultiSectorLoadReportingResponseItem to APER format.
func (v *EHRPDMultiSectorLoadReportingResponseItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
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
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:434
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:438
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:445
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
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
	per.AppendTruncatedExtension(bb, v.PERPadding_)
	return nil
}

// UnmarshalAPER decodes EHRPDMultiSectorLoadReportingResponseItem from APER format.
func (v *EHRPDMultiSectorLoadReportingResponseItem) UnmarshalAPER(data []byte) error {
	return v.UnmarshalAPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalAPERWithOptions decodes EHRPDMultiSectorLoadReportingResponseItem with explicit receiver options:
// TruncatedExtensionTolerance and MaxZeroWidthCharacters (see
// per.BitBuffer.SetDecodeOptionsAligned).
func (v *EHRPDMultiSectorLoadReportingResponseItem) UnmarshalAPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDMultiSectorLoadReportingResponseItem")
	}
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDMultiSectorLoadReportingResponseItem")
	}
	padding, err := per.CaptureFinalBits(bb, "EHRPDMultiSectorLoadReportingResponseItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDMultiSectorLoadReportingResponseItem")
	}
	v.PERPadding_ = padding.WithRecords(v.PERPadding_)
	return nil
}

func (v *EHRPDMultiSectorLoadReportingResponseItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = EHRPDMultiSectorLoadReportingResponseItem{}
	extAdditions := per.BeginExtensionAdditions(bb)
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_ehrpdsectorid, err := per.DecodeOctetStringAligned(bb, 16, 16, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorID")
	}
	v.EHRPDSectorID = EHRPDSectorID(val_ehrpdsectorid)
	toleranceMark_ehrpdsectorloadreportingresponse := bb.EnterComponent("EHRPDSectorLoadReportingResponse")
	if err := v.EHRPDSectorLoadReportingResponse.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorLoadReportingResponse")
	}
	bb.LeaveComponent(toleranceMark_ehrpdsectorloadreportingresponse)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:616
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:619
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				data, err := per.DecodeOpenTypeAligned(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
		if extAdditions.Emptied() {
			v.ExtCount_, v.ExtPresent_, v.ExtData_, v.PERExtPadding_ = 0, nil, nil, nil
		}
	}
	v.PERPadding_ = extAdditions.Record(v.PERPadding_)
	return nil
}
