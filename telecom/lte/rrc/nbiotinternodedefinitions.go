// Code generated from ASN.1 module "NBIOT-InterNodeDefinitions". DO NOT EDIT.

package rrc

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = per.NewBitBuffer
)

// HandoverPreparationInformationNB represents the ASN.1 type HandoverPreparationInformation-NB (SEQUENCE).
type HandoverPreparationInformationNB struct {
	CriticalExtensions HandoverPreparationInformationNBCriticalExtensions `asn1:"tag:0,context,explicit"`
}

// HandoverPreparationInformationNBIEs represents the ASN.1 type HandoverPreparationInformation-NB-IEs (SEQUENCE).
type HandoverPreparationInformationNBIEs struct {
	UeRadioAccessCapabilityInfoR13 UECapabilityNBR13                         `asn1:"tag:0,context,implicit"`
	AsConfigR13                    ASConfigNB                                `asn1:"tag:1,context,implicit"`
	RrmConfigR13                   *RRMConfigNB                              `asn1:"tag:2,context,implicit,optional" json:"RrmConfigR13,omitempty"`
	AsContextR13                   *ASContextNB                              `asn1:"tag:3,context,implicit,optional" json:"AsContextR13,omitempty"`
	NonCriticalExtension           *HandoverPreparationInformationNBV1380IEs `asn1:"tag:4,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationNBV1380IEs represents the ASN.1 type HandoverPreparationInformation-NB-v1380-IEs (SEQUENCE).
type HandoverPreparationInformationNBV1380IEs struct {
	LateNonCriticalExtension []byte                                     `asn1:"tag:0,context,implicit,optional" json:"LateNonCriticalExtension,omitempty"`
	NonCriticalExtension     *HandoverPreparationInformationNBExtR14IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationNBExtR14IEs represents the ASN.1 type HandoverPreparationInformation-NB-Ext-r14-IEs (SEQUENCE).
type HandoverPreparationInformationNBExtR14IEs struct {
	UeRadioAccessCapabilityInfoExtR14 *UECapabilityNBExtR14IEs                                       `asn1:"tag:0,context,implicit,optional" json:"UeRadioAccessCapabilityInfoExtR14,omitempty"`
	NonCriticalExtension              *HandoverPreparationInformationNBExtR14IEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// UEPagingCoverageInformationNB represents the ASN.1 type UEPagingCoverageInformation-NB (SEQUENCE).
type UEPagingCoverageInformationNB struct {
	CriticalExtensions UEPagingCoverageInformationNBCriticalExtensions `asn1:"tag:0,context,explicit"`
}

// UEPagingCoverageInformationNBIEs represents the ASN.1 type UEPagingCoverageInformation-NB-IEs (SEQUENCE).
type UEPagingCoverageInformationNBIEs struct {
	NpdcchNumRepetitionPagingR13 *int64                                 `asn1:"tag:0,context,implicit,optional" json:"NpdcchNumRepetitionPagingR13,omitempty"`
	NonCriticalExtension         *UEPagingCoverageInformationNBV1700IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// UEPagingCoverageInformationNBV1700IEs represents the ASN.1 type UEPagingCoverageInformation-NB-v1700-IEs (SEQUENCE).
type UEPagingCoverageInformationNBV1700IEs struct {
	CbpIndexR17          *int64                                                     `asn1:"tag:0,context,implicit,optional" json:"CbpIndexR17,omitempty"`
	NonCriticalExtension *UEPagingCoverageInformationNBV1700IEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// UERadioAccessCapabilityInformationNB represents the ASN.1 type UERadioAccessCapabilityInformation-NB (SEQUENCE).
type UERadioAccessCapabilityInformationNB struct {
	CriticalExtensions UERadioAccessCapabilityInformationNBCriticalExtensions `asn1:"tag:0,context,explicit"`
}

// UERadioAccessCapabilityInformationNBIEs represents the ASN.1 type UERadioAccessCapabilityInformation-NB-IEs (SEQUENCE).
type UERadioAccessCapabilityInformationNBIEs struct {
	UeRadioAccessCapabilityInfoR13 UECapabilityNBR13                             `asn1:"tag:0,context,implicit"`
	NonCriticalExtension           *UERadioAccessCapabilityInformationNBV1380IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// UERadioAccessCapabilityInformationNBV1380IEs represents the ASN.1 type UERadioAccessCapabilityInformation-NB-v1380-IEs (SEQUENCE).
type UERadioAccessCapabilityInformationNBV1380IEs struct {
	LateNonCriticalExtension []byte                                      `asn1:"tag:0,context,implicit,optional" json:"LateNonCriticalExtension,omitempty"`
	NonCriticalExtension     *UERadioAccessCapabilityInformationNBR14IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// UERadioAccessCapabilityInformationNBR14IEs represents the ASN.1 type UERadioAccessCapabilityInformation-NB-r14-IEs (SEQUENCE).
type UERadioAccessCapabilityInformationNBR14IEs struct {
	UeRadioAccessCapabilityInfoR14 *UECapabilityInformationNB                                      `asn1:"tag:0,context,implicit,optional" json:"UeRadioAccessCapabilityInfoR14,omitempty"`
	NonCriticalExtension           *UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// UERadioPagingInformationNB represents the ASN.1 type UERadioPagingInformation-NB (SEQUENCE).
type UERadioPagingInformationNB struct {
	CriticalExtensions UERadioPagingInformationNBCriticalExtensions `asn1:"tag:0,context,explicit"`
}

// UERadioPagingInformationNBIEs represents the ASN.1 type UERadioPagingInformation-NB-IEs (SEQUENCE).
type UERadioPagingInformationNBIEs struct {
	UeRadioPagingInfoR13 UERadioPagingInfoNBR13                             `asn1:"tag:0,context,implicit"`
	NonCriticalExtension *UERadioPagingInformationNBIEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// ASConfigNB represents the ASN.1 type AS-Config-NB (SEQUENCE).
type ASConfigNB struct {
	SourceRadioResourceConfigR13     RadioResourceConfigDedicatedNBR13 `asn1:"tag:0,context,implicit"`
	SourceSecurityAlgorithmConfigR13 SecurityAlgorithmConfig           `asn1:"tag:1,context,implicit"`
	SourceUEIdentityR13              CRNTI                             `asn1:"tag:2,context,implicit"`
	SourceDlCarrierFreqR13           CarrierFreqNBR13                  `asn1:"tag:3,context,implicit"`
	SourceDLCarrierFreqV1550         *CarrierFreqNBV1550               `asn1:"tag:4,context,implicit,optional" json:"SourceDLCarrierFreqV1550,omitempty"`
	ExtCount_                        int64                             `asn1:"-" json:"-"`
	ExtPresent_                      []bool                            `asn1:"-" json:"-"`
	ExtData_                         [][]byte                          `asn1:"-" json:"-"`
}

// ASContextNB represents the ASN.1 type AS-Context-NB (SEQUENCE).
type ASContextNB struct {
	ReestablishmentInfoR13 *ReestablishmentInfoNB `asn1:"tag:0,context,implicit,optional" json:"ReestablishmentInfoR13,omitempty"`
	ExtCount_              int64                  `asn1:"-" json:"-"`
	ExtPresent_            []bool                 `asn1:"-" json:"-"`
	ExtData_               [][]byte               `asn1:"-" json:"-"`
}

// ReestablishmentInfoNB represents the ASN.1 type ReestablishmentInfo-NB (SEQUENCE).
type ReestablishmentInfoNB struct {
	SourcePhysCellIdR13                PhysCellId                `asn1:"tag:0,context,implicit"`
	TargetCellShortMACIR13             ShortMACI                 `asn1:"tag:1,context,implicit"`
	AdditionalReestabInfoListR13       AdditionalReestabInfoList `asn1:"tag:2,context,implicit,optional" json:"AdditionalReestabInfoListR13,omitempty"`
	AdditionalReestabInfoListR13Indef_ bool                      `asn1:"-" json:"-"`
	ExtCount_                          int64                     `asn1:"-" json:"-"`
	ExtPresent_                        []bool                    `asn1:"-" json:"-"`
	ExtData_                           [][]byte                  `asn1:"-" json:"-"`
}

// RRMConfigNB represents the ASN.1 type RRM-Config-NB (SEQUENCE).
type RRMConfigNB struct {
	UeInactiveTime *int64   `asn1:"tag:0,context,implicit,optional" json:"UeInactiveTime,omitempty"`
	ExtCount_      int64    `asn1:"-" json:"-"`
	ExtPresent_    []bool   `asn1:"-" json:"-"`
	ExtData_       [][]byte `asn1:"-" json:"-"`
}

// HandoverPreparationInformationNBCriticalExtensions choice constants.
const (
	HandoverPreparationInformationNBCriticalExtensionsChoiceC1                       = 1
	HandoverPreparationInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture = 2
)

// HandoverPreparationInformationNBCriticalExtensions represents the ASN.1 CHOICE type HandoverPreparationInformation-NB-criticalExtensions.
type HandoverPreparationInformationNBCriticalExtensions struct {
	Choice                   int
	C1                       *HandoverPreparationInformationNBCriticalExtensionsC1                       `json:"C1,omitempty"`
	CriticalExtensionsFuture *HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture `json:"CriticalExtensionsFuture,omitempty"`
}

// NewHandoverPreparationInformationNBCriticalExtensionsC1 creates a HandoverPreparationInformationNBCriticalExtensions with the c1 alternative.
func NewHandoverPreparationInformationNBCriticalExtensionsC1(v HandoverPreparationInformationNBCriticalExtensionsC1) HandoverPreparationInformationNBCriticalExtensions {
	return HandoverPreparationInformationNBCriticalExtensions{
		Choice: HandoverPreparationInformationNBCriticalExtensionsChoiceC1,
		C1:     &v,
	}
}

// NewHandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture creates a HandoverPreparationInformationNBCriticalExtensions with the criticalExtensionsFuture alternative.
func NewHandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture(v HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture) HandoverPreparationInformationNBCriticalExtensions {
	return HandoverPreparationInformationNBCriticalExtensions{
		Choice:                   HandoverPreparationInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture,
		CriticalExtensionsFuture: &v,
	}
}

// HandoverPreparationInformationNBCriticalExtensionsC1 choice constants.
const (
	HandoverPreparationInformationNBCriticalExtensionsC1ChoiceHandoverPreparationInformationR13 = 1
	HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare3                            = 2
	HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare2                            = 3
	HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare1                            = 4
)

// HandoverPreparationInformationNBCriticalExtensionsC1 represents the ASN.1 CHOICE type HandoverPreparationInformation-NB-criticalExtensions-c1.
type HandoverPreparationInformationNBCriticalExtensionsC1 struct {
	Choice                            int
	HandoverPreparationInformationR13 *HandoverPreparationInformationNBIEs `json:"HandoverPreparationInformationR13,omitempty"`
	Spare3                            *struct{}                            `json:"Spare3,omitempty"`
	Spare2                            *struct{}                            `json:"Spare2,omitempty"`
	Spare1                            *struct{}                            `json:"Spare1,omitempty"`
}

// NewHandoverPreparationInformationNBCriticalExtensionsC1HandoverPreparationInformationR13 creates a HandoverPreparationInformationNBCriticalExtensionsC1 with the handoverPreparationInformation-r13 alternative.
func NewHandoverPreparationInformationNBCriticalExtensionsC1HandoverPreparationInformationR13(v HandoverPreparationInformationNBIEs) HandoverPreparationInformationNBCriticalExtensionsC1 {
	return HandoverPreparationInformationNBCriticalExtensionsC1{
		Choice:                            HandoverPreparationInformationNBCriticalExtensionsC1ChoiceHandoverPreparationInformationR13,
		HandoverPreparationInformationR13: &v,
	}
}

// NewHandoverPreparationInformationNBCriticalExtensionsC1Spare3 creates a HandoverPreparationInformationNBCriticalExtensionsC1 with the spare3 alternative.
func NewHandoverPreparationInformationNBCriticalExtensionsC1Spare3(v struct{}) HandoverPreparationInformationNBCriticalExtensionsC1 {
	return HandoverPreparationInformationNBCriticalExtensionsC1{
		Choice: HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare3,
		Spare3: &v,
	}
}

// NewHandoverPreparationInformationNBCriticalExtensionsC1Spare2 creates a HandoverPreparationInformationNBCriticalExtensionsC1 with the spare2 alternative.
func NewHandoverPreparationInformationNBCriticalExtensionsC1Spare2(v struct{}) HandoverPreparationInformationNBCriticalExtensionsC1 {
	return HandoverPreparationInformationNBCriticalExtensionsC1{
		Choice: HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare2,
		Spare2: &v,
	}
}

// NewHandoverPreparationInformationNBCriticalExtensionsC1Spare1 creates a HandoverPreparationInformationNBCriticalExtensionsC1 with the spare1 alternative.
func NewHandoverPreparationInformationNBCriticalExtensionsC1Spare1(v struct{}) HandoverPreparationInformationNBCriticalExtensionsC1 {
	return HandoverPreparationInformationNBCriticalExtensionsC1{
		Choice: HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare1,
		Spare1: &v,
	}
}

// HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture represents the ASN.1 type HandoverPreparationInformation-NB-criticalExtensions-criticalExtensionsFuture (SEQUENCE).
type HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture struct {
}

// HandoverPreparationInformationNBExtR14IEsNonCriticalExtension represents the ASN.1 type HandoverPreparationInformation-NB-Ext-r14-IEs-nonCriticalExtension (SEQUENCE).
type HandoverPreparationInformationNBExtR14IEsNonCriticalExtension struct {
}

// UEPagingCoverageInformationNBCriticalExtensions choice constants.
const (
	UEPagingCoverageInformationNBCriticalExtensionsChoiceC1                       = 1
	UEPagingCoverageInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture = 2
)

// UEPagingCoverageInformationNBCriticalExtensions represents the ASN.1 CHOICE type UEPagingCoverageInformation-NB-criticalExtensions.
type UEPagingCoverageInformationNBCriticalExtensions struct {
	Choice                   int
	C1                       *UEPagingCoverageInformationNBCriticalExtensionsC1                       `json:"C1,omitempty"`
	CriticalExtensionsFuture *UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture `json:"CriticalExtensionsFuture,omitempty"`
}

// NewUEPagingCoverageInformationNBCriticalExtensionsC1 creates a UEPagingCoverageInformationNBCriticalExtensions with the c1 alternative.
func NewUEPagingCoverageInformationNBCriticalExtensionsC1(v UEPagingCoverageInformationNBCriticalExtensionsC1) UEPagingCoverageInformationNBCriticalExtensions {
	return UEPagingCoverageInformationNBCriticalExtensions{
		Choice: UEPagingCoverageInformationNBCriticalExtensionsChoiceC1,
		C1:     &v,
	}
}

// NewUEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture creates a UEPagingCoverageInformationNBCriticalExtensions with the criticalExtensionsFuture alternative.
func NewUEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture(v UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture) UEPagingCoverageInformationNBCriticalExtensions {
	return UEPagingCoverageInformationNBCriticalExtensions{
		Choice:                   UEPagingCoverageInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture,
		CriticalExtensionsFuture: &v,
	}
}

// UEPagingCoverageInformationNBCriticalExtensionsC1 choice constants.
const (
	UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceUePagingCoverageInformationR13 = 1
	UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare3                         = 2
	UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare2                         = 3
	UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare1                         = 4
)

// UEPagingCoverageInformationNBCriticalExtensionsC1 represents the ASN.1 CHOICE type UEPagingCoverageInformation-NB-criticalExtensions-c1.
type UEPagingCoverageInformationNBCriticalExtensionsC1 struct {
	Choice                         int
	UePagingCoverageInformationR13 *UEPagingCoverageInformationNBIEs `json:"UePagingCoverageInformationR13,omitempty"`
	Spare3                         *struct{}                         `json:"Spare3,omitempty"`
	Spare2                         *struct{}                         `json:"Spare2,omitempty"`
	Spare1                         *struct{}                         `json:"Spare1,omitempty"`
}

// NewUEPagingCoverageInformationNBCriticalExtensionsC1UePagingCoverageInformationR13 creates a UEPagingCoverageInformationNBCriticalExtensionsC1 with the uePagingCoverageInformation-r13 alternative.
func NewUEPagingCoverageInformationNBCriticalExtensionsC1UePagingCoverageInformationR13(v UEPagingCoverageInformationNBIEs) UEPagingCoverageInformationNBCriticalExtensionsC1 {
	return UEPagingCoverageInformationNBCriticalExtensionsC1{
		Choice:                         UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceUePagingCoverageInformationR13,
		UePagingCoverageInformationR13: &v,
	}
}

// NewUEPagingCoverageInformationNBCriticalExtensionsC1Spare3 creates a UEPagingCoverageInformationNBCriticalExtensionsC1 with the spare3 alternative.
func NewUEPagingCoverageInformationNBCriticalExtensionsC1Spare3(v struct{}) UEPagingCoverageInformationNBCriticalExtensionsC1 {
	return UEPagingCoverageInformationNBCriticalExtensionsC1{
		Choice: UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare3,
		Spare3: &v,
	}
}

// NewUEPagingCoverageInformationNBCriticalExtensionsC1Spare2 creates a UEPagingCoverageInformationNBCriticalExtensionsC1 with the spare2 alternative.
func NewUEPagingCoverageInformationNBCriticalExtensionsC1Spare2(v struct{}) UEPagingCoverageInformationNBCriticalExtensionsC1 {
	return UEPagingCoverageInformationNBCriticalExtensionsC1{
		Choice: UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare2,
		Spare2: &v,
	}
}

// NewUEPagingCoverageInformationNBCriticalExtensionsC1Spare1 creates a UEPagingCoverageInformationNBCriticalExtensionsC1 with the spare1 alternative.
func NewUEPagingCoverageInformationNBCriticalExtensionsC1Spare1(v struct{}) UEPagingCoverageInformationNBCriticalExtensionsC1 {
	return UEPagingCoverageInformationNBCriticalExtensionsC1{
		Choice: UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare1,
		Spare1: &v,
	}
}

// UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture represents the ASN.1 type UEPagingCoverageInformation-NB-criticalExtensions-criticalExtensionsFuture (SEQUENCE).
type UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture struct {
}

// UEPagingCoverageInformationNBV1700IEsNonCriticalExtension represents the ASN.1 type UEPagingCoverageInformation-NB-v1700-IEs-nonCriticalExtension (SEQUENCE).
type UEPagingCoverageInformationNBV1700IEsNonCriticalExtension struct {
}

// UERadioAccessCapabilityInformationNBCriticalExtensions choice constants.
const (
	UERadioAccessCapabilityInformationNBCriticalExtensionsChoiceC1                       = 1
	UERadioAccessCapabilityInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture = 2
)

// UERadioAccessCapabilityInformationNBCriticalExtensions represents the ASN.1 CHOICE type UERadioAccessCapabilityInformation-NB-criticalExtensions.
type UERadioAccessCapabilityInformationNBCriticalExtensions struct {
	Choice                   int
	C1                       *UERadioAccessCapabilityInformationNBCriticalExtensionsC1                       `json:"C1,omitempty"`
	CriticalExtensionsFuture *UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture `json:"CriticalExtensionsFuture,omitempty"`
}

// NewUERadioAccessCapabilityInformationNBCriticalExtensionsC1 creates a UERadioAccessCapabilityInformationNBCriticalExtensions with the c1 alternative.
func NewUERadioAccessCapabilityInformationNBCriticalExtensionsC1(v UERadioAccessCapabilityInformationNBCriticalExtensionsC1) UERadioAccessCapabilityInformationNBCriticalExtensions {
	return UERadioAccessCapabilityInformationNBCriticalExtensions{
		Choice: UERadioAccessCapabilityInformationNBCriticalExtensionsChoiceC1,
		C1:     &v,
	}
}

// NewUERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture creates a UERadioAccessCapabilityInformationNBCriticalExtensions with the criticalExtensionsFuture alternative.
func NewUERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture(v UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture) UERadioAccessCapabilityInformationNBCriticalExtensions {
	return UERadioAccessCapabilityInformationNBCriticalExtensions{
		Choice:                   UERadioAccessCapabilityInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture,
		CriticalExtensionsFuture: &v,
	}
}

// UERadioAccessCapabilityInformationNBCriticalExtensionsC1 choice constants.
const (
	UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceUeRadioAccessCapabilityInformationR13 = 1
	UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare3                                = 2
	UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare2                                = 3
	UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare1                                = 4
)

// UERadioAccessCapabilityInformationNBCriticalExtensionsC1 represents the ASN.1 CHOICE type UERadioAccessCapabilityInformation-NB-criticalExtensions-c1.
type UERadioAccessCapabilityInformationNBCriticalExtensionsC1 struct {
	Choice                                int
	UeRadioAccessCapabilityInformationR13 *UERadioAccessCapabilityInformationNBIEs `json:"UeRadioAccessCapabilityInformationR13,omitempty"`
	Spare3                                *struct{}                                `json:"Spare3,omitempty"`
	Spare2                                *struct{}                                `json:"Spare2,omitempty"`
	Spare1                                *struct{}                                `json:"Spare1,omitempty"`
}

// NewUERadioAccessCapabilityInformationNBCriticalExtensionsC1UeRadioAccessCapabilityInformationR13 creates a UERadioAccessCapabilityInformationNBCriticalExtensionsC1 with the ueRadioAccessCapabilityInformation-r13 alternative.
func NewUERadioAccessCapabilityInformationNBCriticalExtensionsC1UeRadioAccessCapabilityInformationR13(v UERadioAccessCapabilityInformationNBIEs) UERadioAccessCapabilityInformationNBCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationNBCriticalExtensionsC1{
		Choice:                                UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceUeRadioAccessCapabilityInformationR13,
		UeRadioAccessCapabilityInformationR13: &v,
	}
}

// NewUERadioAccessCapabilityInformationNBCriticalExtensionsC1Spare3 creates a UERadioAccessCapabilityInformationNBCriticalExtensionsC1 with the spare3 alternative.
func NewUERadioAccessCapabilityInformationNBCriticalExtensionsC1Spare3(v struct{}) UERadioAccessCapabilityInformationNBCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationNBCriticalExtensionsC1{
		Choice: UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare3,
		Spare3: &v,
	}
}

// NewUERadioAccessCapabilityInformationNBCriticalExtensionsC1Spare2 creates a UERadioAccessCapabilityInformationNBCriticalExtensionsC1 with the spare2 alternative.
func NewUERadioAccessCapabilityInformationNBCriticalExtensionsC1Spare2(v struct{}) UERadioAccessCapabilityInformationNBCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationNBCriticalExtensionsC1{
		Choice: UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare2,
		Spare2: &v,
	}
}

// NewUERadioAccessCapabilityInformationNBCriticalExtensionsC1Spare1 creates a UERadioAccessCapabilityInformationNBCriticalExtensionsC1 with the spare1 alternative.
func NewUERadioAccessCapabilityInformationNBCriticalExtensionsC1Spare1(v struct{}) UERadioAccessCapabilityInformationNBCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationNBCriticalExtensionsC1{
		Choice: UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare1,
		Spare1: &v,
	}
}

// UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture represents the ASN.1 type UERadioAccessCapabilityInformation-NB-criticalExtensions-criticalExtensionsFuture (SEQUENCE).
type UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture struct {
}

// UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension represents the ASN.1 type UERadioAccessCapabilityInformation-NB-r14-IEs-nonCriticalExtension (SEQUENCE).
type UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension struct {
}

// UERadioPagingInformationNBCriticalExtensions choice constants.
const (
	UERadioPagingInformationNBCriticalExtensionsChoiceC1                       = 1
	UERadioPagingInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture = 2
)

// UERadioPagingInformationNBCriticalExtensions represents the ASN.1 CHOICE type UERadioPagingInformation-NB-criticalExtensions.
type UERadioPagingInformationNBCriticalExtensions struct {
	Choice                   int
	C1                       *UERadioPagingInformationNBCriticalExtensionsC1                       `json:"C1,omitempty"`
	CriticalExtensionsFuture *UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture `json:"CriticalExtensionsFuture,omitempty"`
}

// NewUERadioPagingInformationNBCriticalExtensionsC1 creates a UERadioPagingInformationNBCriticalExtensions with the c1 alternative.
func NewUERadioPagingInformationNBCriticalExtensionsC1(v UERadioPagingInformationNBCriticalExtensionsC1) UERadioPagingInformationNBCriticalExtensions {
	return UERadioPagingInformationNBCriticalExtensions{
		Choice: UERadioPagingInformationNBCriticalExtensionsChoiceC1,
		C1:     &v,
	}
}

// NewUERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture creates a UERadioPagingInformationNBCriticalExtensions with the criticalExtensionsFuture alternative.
func NewUERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture(v UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture) UERadioPagingInformationNBCriticalExtensions {
	return UERadioPagingInformationNBCriticalExtensions{
		Choice:                   UERadioPagingInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture,
		CriticalExtensionsFuture: &v,
	}
}

// UERadioPagingInformationNBCriticalExtensionsC1 choice constants.
const (
	UERadioPagingInformationNBCriticalExtensionsC1ChoiceUeRadioPagingInformationR13 = 1
	UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare3                      = 2
	UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare2                      = 3
	UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare1                      = 4
)

// UERadioPagingInformationNBCriticalExtensionsC1 represents the ASN.1 CHOICE type UERadioPagingInformation-NB-criticalExtensions-c1.
type UERadioPagingInformationNBCriticalExtensionsC1 struct {
	Choice                      int
	UeRadioPagingInformationR13 *UERadioPagingInformationNBIEs `json:"UeRadioPagingInformationR13,omitempty"`
	Spare3                      *struct{}                      `json:"Spare3,omitempty"`
	Spare2                      *struct{}                      `json:"Spare2,omitempty"`
	Spare1                      *struct{}                      `json:"Spare1,omitempty"`
}

// NewUERadioPagingInformationNBCriticalExtensionsC1UeRadioPagingInformationR13 creates a UERadioPagingInformationNBCriticalExtensionsC1 with the ueRadioPagingInformation-r13 alternative.
func NewUERadioPagingInformationNBCriticalExtensionsC1UeRadioPagingInformationR13(v UERadioPagingInformationNBIEs) UERadioPagingInformationNBCriticalExtensionsC1 {
	return UERadioPagingInformationNBCriticalExtensionsC1{
		Choice:                      UERadioPagingInformationNBCriticalExtensionsC1ChoiceUeRadioPagingInformationR13,
		UeRadioPagingInformationR13: &v,
	}
}

// NewUERadioPagingInformationNBCriticalExtensionsC1Spare3 creates a UERadioPagingInformationNBCriticalExtensionsC1 with the spare3 alternative.
func NewUERadioPagingInformationNBCriticalExtensionsC1Spare3(v struct{}) UERadioPagingInformationNBCriticalExtensionsC1 {
	return UERadioPagingInformationNBCriticalExtensionsC1{
		Choice: UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare3,
		Spare3: &v,
	}
}

// NewUERadioPagingInformationNBCriticalExtensionsC1Spare2 creates a UERadioPagingInformationNBCriticalExtensionsC1 with the spare2 alternative.
func NewUERadioPagingInformationNBCriticalExtensionsC1Spare2(v struct{}) UERadioPagingInformationNBCriticalExtensionsC1 {
	return UERadioPagingInformationNBCriticalExtensionsC1{
		Choice: UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare2,
		Spare2: &v,
	}
}

// NewUERadioPagingInformationNBCriticalExtensionsC1Spare1 creates a UERadioPagingInformationNBCriticalExtensionsC1 with the spare1 alternative.
func NewUERadioPagingInformationNBCriticalExtensionsC1Spare1(v struct{}) UERadioPagingInformationNBCriticalExtensionsC1 {
	return UERadioPagingInformationNBCriticalExtensionsC1{
		Choice: UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare1,
		Spare1: &v,
	}
}

// UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture represents the ASN.1 type UERadioPagingInformation-NB-criticalExtensions-criticalExtensionsFuture (SEQUENCE).
type UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture struct {
}

// UERadioPagingInformationNBIEsNonCriticalExtension represents the ASN.1 type UERadioPagingInformation-NB-IEs-nonCriticalExtension (SEQUENCE).
type UERadioPagingInformationNBIEsNonCriticalExtension struct {
}

// MarshalUPER encodes HandoverPreparationInformationNB to UPER format.
func (v *HandoverPreparationInformationNB) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverPreparationInformationNB) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CriticalExtensions.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding criticalExtensions: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationNB from UPER format.
func (v *HandoverPreparationInformationNB) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNB")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNB")
	}
	return nil
}

func (v *HandoverPreparationInformationNB) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationNB{}
	if err := v.CriticalExtensions.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CriticalExtensions")
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationNBIEs to UPER format.
func (v *HandoverPreparationInformationNBIEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverPreparationInformationNBIEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.RrmConfigR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.AsContextR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if err := v.UeRadioAccessCapabilityInfoR13.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding ue-RadioAccessCapabilityInfo-r13: %w", err)
	}
	if err := v.AsConfigR13.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding as-Config-r13: %w", err)
	}
	if v.RrmConfigR13 != nil {
		if err := v.RrmConfigR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding rrm-Config-r13: %w", err)
		}
	}
	if v.AsContextR13 != nil {
		if err := v.AsContextR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Context-r13: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationNBIEs from UPER format.
func (v *HandoverPreparationInformationNBIEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBIEs")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBIEs")
	}
	return nil
}

func (v *HandoverPreparationInformationNBIEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationNBIEs{}
	// Read preamble bitmap for optional root fields
	opt_rrmconfigr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ascontextr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.UeRadioAccessCapabilityInfoR13.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UeRadioAccessCapabilityInfoR13")
	}
	if err := v.AsConfigR13.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AsConfigR13")
	}
	if opt_rrmconfigr13 {
		var dec_rrmconfigr13 RRMConfigNB
		if err := dec_rrmconfigr13.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RrmConfigR13")
		}
		v.RrmConfigR13 = &dec_rrmconfigr13
	}
	if opt_ascontextr13 {
		var dec_ascontextr13 ASContextNB
		if err := dec_ascontextr13.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AsContextR13")
		}
		v.AsContextR13 = &dec_ascontextr13
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationNBV1380IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NonCriticalExtension")
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationNBV1380IEs to UPER format.
func (v *HandoverPreparationInformationNBV1380IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverPreparationInformationNBV1380IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.LateNonCriticalExtension != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.LateNonCriticalExtension != nil {
		if err := per.EncodeOctetStringExt(bb, v.LateNonCriticalExtension, 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding lateNonCriticalExtension: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationNBV1380IEs from UPER format.
func (v *HandoverPreparationInformationNBV1380IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBV1380IEs")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBV1380IEs")
	}
	return nil
}

func (v *HandoverPreparationInformationNBV1380IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationNBV1380IEs{}
	// Read preamble bitmap for optional root fields
	opt_latenoncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_latenoncriticalextension {
		val_latenoncriticalextension, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "LateNonCriticalExtension")
		}
		tmp_latenoncriticalextension := val_latenoncriticalextension
		v.LateNonCriticalExtension = tmp_latenoncriticalextension
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationNBExtR14IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NonCriticalExtension")
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationNBExtR14IEs to UPER format.
func (v *HandoverPreparationInformationNBExtR14IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverPreparationInformationNBExtR14IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.UeRadioAccessCapabilityInfoExtR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.UeRadioAccessCapabilityInfoExtR14 != nil {
		containedBB_ueradioaccesscapabilityinfoextr14 := per.NewBitBuffer()
		if err := (*v.UeRadioAccessCapabilityInfoExtR14).MarshalUPERTo(containedBB_ueradioaccesscapabilityinfoextr14); err != nil {
			return fmt.Errorf("encoding contained ue-RadioAccessCapabilityInfoExt-r14: %w", err)
		}
		if err := per.EncodeOctetStringExt(bb, containedBB_ueradioaccesscapabilityinfoextr14.Bytes(), 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding ue-RadioAccessCapabilityInfoExt-r14: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationNBExtR14IEs from UPER format.
func (v *HandoverPreparationInformationNBExtR14IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBExtR14IEs")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBExtR14IEs")
	}
	return nil
}

func (v *HandoverPreparationInformationNBExtR14IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationNBExtR14IEs{}
	// Read preamble bitmap for optional root fields
	opt_ueradioaccesscapabilityinfoextr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_ueradioaccesscapabilityinfoextr14 {
		containedBytes_ueradioaccesscapabilityinfoextr14, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "UeRadioAccessCapabilityInfoExtR14")
		}
		var contained_ueradioaccesscapabilityinfoextr14 UECapabilityNBExtR14IEs
		if err := contained_ueradioaccesscapabilityinfoextr14.UnmarshalUPER(containedBytes_ueradioaccesscapabilityinfoextr14); err != nil {
			return fmt.Errorf("decoding contained ue-RadioAccessCapabilityInfoExt-r14: %w", err)
		}
		v.UeRadioAccessCapabilityInfoExtR14 = &contained_ueradioaccesscapabilityinfoextr14
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationNBExtR14IEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NonCriticalExtension")
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationNB to UPER format.
func (v *UEPagingCoverageInformationNB) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEPagingCoverageInformationNB) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CriticalExtensions.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding criticalExtensions: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationNB from UPER format.
func (v *UEPagingCoverageInformationNB) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNB")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNB")
	}
	return nil
}

func (v *UEPagingCoverageInformationNB) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationNB{}
	if err := v.CriticalExtensions.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CriticalExtensions")
	}
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationNBIEs to UPER format.
func (v *UEPagingCoverageInformationNBIEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEPagingCoverageInformationNBIEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NpdcchNumRepetitionPagingR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.NpdcchNumRepetitionPagingR13 != nil {
		if err := per.EncodeInteger(bb, int64(*v.NpdcchNumRepetitionPagingR13), int64Ptr(1), int64Ptr(2048), false); err != nil {
			return fmt.Errorf("encoding npdcch-NumRepetitionPaging-r13: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationNBIEs from UPER format.
func (v *UEPagingCoverageInformationNBIEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBIEs")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBIEs")
	}
	return nil
}

func (v *UEPagingCoverageInformationNBIEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationNBIEs{}
	// Read preamble bitmap for optional root fields
	opt_npdcchnumrepetitionpagingr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_npdcchnumrepetitionpagingr13 {
		val_npdcchnumrepetitionpagingr13, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(2048), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "NpdcchNumRepetitionPagingR13")
		}
		v.NpdcchNumRepetitionPagingR13 = &val_npdcchnumrepetitionpagingr13
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension UEPagingCoverageInformationNBV1700IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NonCriticalExtension")
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationNBV1700IEs to UPER format.
func (v *UEPagingCoverageInformationNBV1700IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEPagingCoverageInformationNBV1700IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.CbpIndexR17 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.CbpIndexR17 != nil {
		if err := per.EncodeInteger(bb, int64(*v.CbpIndexR17), int64Ptr(1), int64Ptr(2), false); err != nil {
			return fmt.Errorf("encoding cbp-Index-r17: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationNBV1700IEs from UPER format.
func (v *UEPagingCoverageInformationNBV1700IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBV1700IEs")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBV1700IEs")
	}
	return nil
}

func (v *UEPagingCoverageInformationNBV1700IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationNBV1700IEs{}
	// Read preamble bitmap for optional root fields
	opt_cbpindexr17, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_cbpindexr17 {
		val_cbpindexr17, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(2), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "CbpIndexR17")
		}
		v.CbpIndexR17 = &val_cbpindexr17
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension UEPagingCoverageInformationNBV1700IEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NonCriticalExtension")
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationNB to UPER format.
func (v *UERadioAccessCapabilityInformationNB) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioAccessCapabilityInformationNB) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CriticalExtensions.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding criticalExtensions: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationNB from UPER format.
func (v *UERadioAccessCapabilityInformationNB) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNB")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNB")
	}
	return nil
}

func (v *UERadioAccessCapabilityInformationNB) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationNB{}
	if err := v.CriticalExtensions.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CriticalExtensions")
	}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationNBIEs to UPER format.
func (v *UERadioAccessCapabilityInformationNBIEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioAccessCapabilityInformationNBIEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	containedBB_ueradioaccesscapabilityinfor13 := per.NewBitBuffer()
	if err := (v.UeRadioAccessCapabilityInfoR13).MarshalUPERTo(containedBB_ueradioaccesscapabilityinfor13); err != nil {
		return fmt.Errorf("encoding contained ue-RadioAccessCapabilityInfo-r13: %w", err)
	}
	if err := per.EncodeOctetStringExt(bb, containedBB_ueradioaccesscapabilityinfor13.Bytes(), 0, 0, false, false); err != nil {
		return fmt.Errorf("encoding ue-RadioAccessCapabilityInfo-r13: %w", err)
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationNBIEs from UPER format.
func (v *UERadioAccessCapabilityInformationNBIEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBIEs")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBIEs")
	}
	return nil
}

func (v *UERadioAccessCapabilityInformationNBIEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationNBIEs{}
	// Read preamble bitmap for optional root fields
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	containedBytes_ueradioaccesscapabilityinfor13, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UeRadioAccessCapabilityInfoR13")
	}
	var contained_ueradioaccesscapabilityinfor13 UECapabilityNBR13
	if err := contained_ueradioaccesscapabilityinfor13.UnmarshalUPER(containedBytes_ueradioaccesscapabilityinfor13); err != nil {
		return fmt.Errorf("decoding contained ue-RadioAccessCapabilityInfo-r13: %w", err)
	}
	v.UeRadioAccessCapabilityInfoR13 = contained_ueradioaccesscapabilityinfor13
	if opt_noncriticalextension {
		var dec_noncriticalextension UERadioAccessCapabilityInformationNBV1380IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NonCriticalExtension")
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationNBV1380IEs to UPER format.
func (v *UERadioAccessCapabilityInformationNBV1380IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioAccessCapabilityInformationNBV1380IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.LateNonCriticalExtension != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.LateNonCriticalExtension != nil {
		if err := per.EncodeOctetStringExt(bb, v.LateNonCriticalExtension, 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding lateNonCriticalExtension: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationNBV1380IEs from UPER format.
func (v *UERadioAccessCapabilityInformationNBV1380IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBV1380IEs")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBV1380IEs")
	}
	return nil
}

func (v *UERadioAccessCapabilityInformationNBV1380IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationNBV1380IEs{}
	// Read preamble bitmap for optional root fields
	opt_latenoncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_latenoncriticalextension {
		val_latenoncriticalextension, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "LateNonCriticalExtension")
		}
		tmp_latenoncriticalextension := val_latenoncriticalextension
		v.LateNonCriticalExtension = tmp_latenoncriticalextension
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension UERadioAccessCapabilityInformationNBR14IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NonCriticalExtension")
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationNBR14IEs to UPER format.
func (v *UERadioAccessCapabilityInformationNBR14IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioAccessCapabilityInformationNBR14IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.UeRadioAccessCapabilityInfoR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.UeRadioAccessCapabilityInfoR14 != nil {
		containedBB_ueradioaccesscapabilityinfor14 := per.NewBitBuffer()
		if err := (*v.UeRadioAccessCapabilityInfoR14).MarshalUPERTo(containedBB_ueradioaccesscapabilityinfor14); err != nil {
			return fmt.Errorf("encoding contained ue-RadioAccessCapabilityInfo-r14: %w", err)
		}
		if err := per.EncodeOctetStringExt(bb, containedBB_ueradioaccesscapabilityinfor14.Bytes(), 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding ue-RadioAccessCapabilityInfo-r14: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationNBR14IEs from UPER format.
func (v *UERadioAccessCapabilityInformationNBR14IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBR14IEs")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBR14IEs")
	}
	return nil
}

func (v *UERadioAccessCapabilityInformationNBR14IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationNBR14IEs{}
	// Read preamble bitmap for optional root fields
	opt_ueradioaccesscapabilityinfor14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_ueradioaccesscapabilityinfor14 {
		containedBytes_ueradioaccesscapabilityinfor14, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "UeRadioAccessCapabilityInfoR14")
		}
		var contained_ueradioaccesscapabilityinfor14 UECapabilityInformationNB
		if err := contained_ueradioaccesscapabilityinfor14.UnmarshalUPER(containedBytes_ueradioaccesscapabilityinfor14); err != nil {
			return fmt.Errorf("decoding contained ue-RadioAccessCapabilityInfo-r14: %w", err)
		}
		v.UeRadioAccessCapabilityInfoR14 = &contained_ueradioaccesscapabilityinfor14
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NonCriticalExtension")
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationNB to UPER format.
func (v *UERadioPagingInformationNB) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioPagingInformationNB) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CriticalExtensions.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding criticalExtensions: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationNB from UPER format.
func (v *UERadioPagingInformationNB) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNB")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNB")
	}
	return nil
}

func (v *UERadioPagingInformationNB) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationNB{}
	if err := v.CriticalExtensions.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CriticalExtensions")
	}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationNBIEs to UPER format.
func (v *UERadioPagingInformationNBIEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioPagingInformationNBIEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	containedBB_ueradiopaginginfor13 := per.NewBitBuffer()
	if err := (v.UeRadioPagingInfoR13).MarshalUPERTo(containedBB_ueradiopaginginfor13); err != nil {
		return fmt.Errorf("encoding contained ue-RadioPagingInfo-r13: %w", err)
	}
	if err := per.EncodeOctetStringExt(bb, containedBB_ueradiopaginginfor13.Bytes(), 0, 0, false, false); err != nil {
		return fmt.Errorf("encoding ue-RadioPagingInfo-r13: %w", err)
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationNBIEs from UPER format.
func (v *UERadioPagingInformationNBIEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNBIEs")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNBIEs")
	}
	return nil
}

func (v *UERadioPagingInformationNBIEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationNBIEs{}
	// Read preamble bitmap for optional root fields
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	containedBytes_ueradiopaginginfor13, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UeRadioPagingInfoR13")
	}
	var contained_ueradiopaginginfor13 UERadioPagingInfoNBR13
	if err := contained_ueradiopaginginfor13.UnmarshalUPER(containedBytes_ueradiopaginginfor13); err != nil {
		return fmt.Errorf("decoding contained ue-RadioPagingInfo-r13: %w", err)
	}
	v.UeRadioPagingInfoR13 = contained_ueradiopaginginfor13
	if opt_noncriticalextension {
		var dec_noncriticalextension UERadioPagingInformationNBIEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NonCriticalExtension")
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes ASConfigNB to UPER format.
func (v *ASConfigNB) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ASConfigNB) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.SourceDLCarrierFreqV1550 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := v.SourceRadioResourceConfigR13.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding sourceRadioResourceConfig-r13: %w", err)
	}
	if err := v.SourceSecurityAlgorithmConfigR13.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding sourceSecurityAlgorithmConfig-r13: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.SourceUEIdentityR13.Bytes, v.SourceUEIdentityR13.BitLength, 16, 16, true, false); err != nil {
		return fmt.Errorf("encoding sourceUE-Identity-r13: %w", err)
	}
	if err := v.SourceDlCarrierFreqR13.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding sourceDl-CarrierFreq-r13: %w", err)
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.SourceDLCarrierFreqV1550 != nil {
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
		if err := per.EncodeNormallySmallNonNegative(bb, extHighest); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SourceDLCarrierFreqV1550 != nil
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
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SourceDLCarrierFreqV1550 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SourceDLCarrierFreqV1550 != nil); err != nil {
				return err
			}
			if v.SourceDLCarrierFreqV1550 != nil {
				if err := v.SourceDLCarrierFreqV1550.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding sourceDL-CarrierFreq-v1550: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.CompleteBytes()); err != nil {
				return err
			}
		}
		for i := int64(1); i <= extHighest; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenType(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes ASConfigNB from UPER format.
func (v *ASConfigNB) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ASConfigNB")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ASConfigNB")
	}
	return nil
}

func (v *ASConfigNB) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigNB{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.SourceRadioResourceConfigR13.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceRadioResourceConfigR13")
	}
	if err := v.SourceSecurityAlgorithmConfigR13.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceSecurityAlgorithmConfigR13")
	}
	bsBytes_sourceueidentityr13, bsBitLen_sourceueidentityr13, err := per.DecodeBitStringExt(bb, 16, 16, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SourceUEIdentityR13")
	}
	v.SourceUEIdentityR13 = runtime.BitString{Bytes: bsBytes_sourceueidentityr13, BitLength: bsBitLen_sourceueidentityr13}
	if err := v.SourceDlCarrierFreqR13.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceDlCarrierFreqR13")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtPresent_ = extPresent
		v.ExtData_ = make([][]byte, extCount+1)
		if int64(0) <= extCount && extPresent[0] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return runtime.WrapDecodePath(err, "ExtData_[0]")
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_sourcedlcarrierfreqv1550, err := per.DecodeBoolean(extBB)
			if err != nil {
				return runtime.WrapDecodePath(err, "SourceDLCarrierFreqV1550")
			}
			if ext_opt_sourcedlcarrierfreqv1550 {
				var dec_sourcedlcarrierfreqv1550 CarrierFreqNBV1550
				if err := dec_sourcedlcarrierfreqv1550.UnmarshalUPERFrom(extBB); err != nil {
					return runtime.WrapDecodePath(err, "SourceDLCarrierFreqV1550")
				}
				v.SourceDLCarrierFreqV1550 = &dec_sourcedlcarrierfreqv1550
			}
			if err := per.ValidateOpenTypePadding(extBB); err != nil {
				return runtime.WrapDecodePath(err, "ExtData_[0]")
			}
		}
		for i := int64(1); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes ASContextNB to UPER format.
func (v *ASContextNB) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ASContextNB) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.ReestablishmentInfoR13 != nil); err != nil {
		return err
	}
	if v.ReestablishmentInfoR13 != nil {
		if err := v.ReestablishmentInfoR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding reestablishmentInfo-r13: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegative(bb, v.ExtCount_); err != nil {
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
				if err := per.EncodeOpenType(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes ASContextNB from UPER format.
func (v *ASContextNB) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ASContextNB")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ASContextNB")
	}
	return nil
}

func (v *ASContextNB) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASContextNB{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_reestablishmentinfor13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_reestablishmentinfor13 {
		var dec_reestablishmentinfor13 ReestablishmentInfoNB
		if err := dec_reestablishmentinfor13.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "ReestablishmentInfoR13")
		}
		v.ReestablishmentInfoR13 = &dec_reestablishmentinfor13
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes ReestablishmentInfoNB to UPER format.
func (v *ReestablishmentInfoNB) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ReestablishmentInfoNB) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AdditionalReestabInfoListR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeInteger(bb, int64(v.SourcePhysCellIdR13), int64Ptr(0), int64Ptr(503), false); err != nil {
		return fmt.Errorf("encoding sourcePhysCellId-r13: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.TargetCellShortMACIR13.Bytes, v.TargetCellShortMACIR13.BitLength, 16, 16, true, false); err != nil {
		return fmt.Errorf("encoding targetCellShortMAC-I-r13: %w", err)
	}
	if v.AdditionalReestabInfoListR13 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.AdditionalReestabInfoListR13)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_additionalreestabinfolistr13, fragmentLength_additionalreestabinfolistr13 int64) error {
			for _, elem := range v.AdditionalReestabInfoListR13[fragmentOffset_additionalreestabinfolistr13 : fragmentOffset_additionalreestabinfolistr13+fragmentLength_additionalreestabinfolistr13] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding additionalReestabInfoList-r13 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding additionalReestabInfoList-r13: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegative(bb, v.ExtCount_); err != nil {
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
				if err := per.EncodeOpenType(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes ReestablishmentInfoNB from UPER format.
func (v *ReestablishmentInfoNB) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ReestablishmentInfoNB")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ReestablishmentInfoNB")
	}
	return nil
}

func (v *ReestablishmentInfoNB) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ReestablishmentInfoNB{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_additionalreestabinfolistr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_sourcephyscellidr13, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SourcePhysCellIdR13")
	}
	v.SourcePhysCellIdR13 = PhysCellId(val_sourcephyscellidr13)
	bsBytes_targetcellshortmacir13, bsBitLen_targetcellshortmacir13, err := per.DecodeBitStringExt(bb, 16, 16, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "TargetCellShortMACIR13")
	}
	v.TargetCellShortMACIR13 = runtime.BitString{Bytes: bsBytes_targetcellshortmacir13, BitLength: bsBitLen_targetcellshortmacir13}
	if opt_additionalreestabinfolistr13 {
		tmp_additionalreestabinfolistr13 := make(AdditionalReestabInfoList, 0)
		_, errCollection_additionalreestabinfolistr13 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_additionalreestabinfolistr13, fragmentLength_additionalreestabinfolistr13 int64) error {
			for i := int64(0); i < fragmentLength_additionalreestabinfolistr13; i++ {
				var elem AdditionalReestabInfo
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("AdditionalReestabInfoListR13[%d]", fragmentOffset_additionalreestabinfolistr13+i))
				}
				tmp_additionalreestabinfolistr13 = append(tmp_additionalreestabinfolistr13, elem)
			}
			return nil
		})
		if errCollection_additionalreestabinfolistr13 != nil {
			return runtime.WrapDecodePath(errCollection_additionalreestabinfolistr13, "AdditionalReestabInfoListR13")
		}
		v.AdditionalReestabInfoListR13 = tmp_additionalreestabinfolistr13
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes RRMConfigNB to UPER format.
func (v *RRMConfigNB) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *RRMConfigNB) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.UeInactiveTime != nil); err != nil {
		return err
	}
	if v.UeInactiveTime != nil {
		if err := per.EncodeEnumerated(bb, int64(*v.UeInactiveTime), 64, false); err != nil {
			return fmt.Errorf("encoding ue-InactiveTime: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegative(bb, v.ExtCount_); err != nil {
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
				if err := per.EncodeOpenType(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes RRMConfigNB from UPER format.
func (v *RRMConfigNB) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RRMConfigNB")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "RRMConfigNB")
	}
	return nil
}

func (v *RRMConfigNB) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = RRMConfigNB{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ueinactivetime, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_ueinactivetime {
		val_ueinactivetime, err := per.DecodeEnumerated(bb, 64, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "UeInactiveTime")
		}
		v.UeInactiveTime = &val_ueinactivetime
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationNBCriticalExtensions to UPER format.
func (v *HandoverPreparationInformationNBCriticalExtensions) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverPreparationInformationNBCriticalExtensions) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case HandoverPreparationInformationNBCriticalExtensionsChoiceC1:
		if v.C1 == nil {
			return fmt.Errorf("choice alternative c1 is nil")
		}
		if err := v.C1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding c1: %w", err)
		}
	case HandoverPreparationInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture:
		if v.CriticalExtensionsFuture == nil {
			return fmt.Errorf("choice alternative criticalExtensionsFuture is nil")
		}
		if err := v.CriticalExtensionsFuture.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding criticalExtensionsFuture: %w", err)
		}
	default:
		return fmt.Errorf("unknown HandoverPreparationInformationNBCriticalExtensions choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationNBCriticalExtensions from UPER format.
func (v *HandoverPreparationInformationNBCriticalExtensions) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBCriticalExtensions")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBCriticalExtensions")
	}
	return nil
}

func (v *HandoverPreparationInformationNBCriticalExtensions) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationNBCriticalExtensions{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case HandoverPreparationInformationNBCriticalExtensionsChoiceC1:
		var dec_c1 HandoverPreparationInformationNBCriticalExtensionsC1
		if err := dec_c1.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "C1")
		}
		v.C1 = &dec_c1
	case HandoverPreparationInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture:
		var dec_criticalextensionsfuture HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture
		if err := dec_criticalextensionsfuture.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CriticalExtensionsFuture")
		}
		v.CriticalExtensionsFuture = &dec_criticalextensionsfuture
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationNBCriticalExtensionsC1 to UPER format.
func (v *HandoverPreparationInformationNBCriticalExtensionsC1) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverPreparationInformationNBCriticalExtensionsC1) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case HandoverPreparationInformationNBCriticalExtensionsC1ChoiceHandoverPreparationInformationR13:
		if v.HandoverPreparationInformationR13 == nil {
			return fmt.Errorf("choice alternative handoverPreparationInformation-r13 is nil")
		}
		if err := v.HandoverPreparationInformationR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding handoverPreparationInformation-r13: %w", err)
		}
	case HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare3:
	case HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare2:
	case HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare1:
	default:
		return fmt.Errorf("unknown HandoverPreparationInformationNBCriticalExtensionsC1 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationNBCriticalExtensionsC1 from UPER format.
func (v *HandoverPreparationInformationNBCriticalExtensionsC1) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBCriticalExtensionsC1")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBCriticalExtensionsC1")
	}
	return nil
}

func (v *HandoverPreparationInformationNBCriticalExtensionsC1) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationNBCriticalExtensionsC1{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 3)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case HandoverPreparationInformationNBCriticalExtensionsC1ChoiceHandoverPreparationInformationR13:
		var dec_handoverpreparationinformationr13 HandoverPreparationInformationNBIEs
		if err := dec_handoverpreparationinformationr13.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "HandoverPreparationInformationR13")
		}
		v.HandoverPreparationInformationR13 = &dec_handoverpreparationinformationr13
	case HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare3:
	case HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare2:
	case HandoverPreparationInformationNBCriticalExtensionsC1ChoiceSpare1:
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture to UPER format.
func (v *HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture from UPER format.
func (v *HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture")
	}
	return nil
}

func (v *HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationNBCriticalExtensionsCriticalExtensionsFuture{}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationNBExtR14IEsNonCriticalExtension to UPER format.
func (v *HandoverPreparationInformationNBExtR14IEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverPreparationInformationNBExtR14IEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationNBExtR14IEsNonCriticalExtension from UPER format.
func (v *HandoverPreparationInformationNBExtR14IEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBExtR14IEsNonCriticalExtension")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationInformationNBExtR14IEsNonCriticalExtension")
	}
	return nil
}

func (v *HandoverPreparationInformationNBExtR14IEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationNBExtR14IEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationNBCriticalExtensions to UPER format.
func (v *UEPagingCoverageInformationNBCriticalExtensions) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEPagingCoverageInformationNBCriticalExtensions) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case UEPagingCoverageInformationNBCriticalExtensionsChoiceC1:
		if v.C1 == nil {
			return fmt.Errorf("choice alternative c1 is nil")
		}
		if err := v.C1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding c1: %w", err)
		}
	case UEPagingCoverageInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture:
		if v.CriticalExtensionsFuture == nil {
			return fmt.Errorf("choice alternative criticalExtensionsFuture is nil")
		}
		if err := v.CriticalExtensionsFuture.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding criticalExtensionsFuture: %w", err)
		}
	default:
		return fmt.Errorf("unknown UEPagingCoverageInformationNBCriticalExtensions choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationNBCriticalExtensions from UPER format.
func (v *UEPagingCoverageInformationNBCriticalExtensions) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBCriticalExtensions")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBCriticalExtensions")
	}
	return nil
}

func (v *UEPagingCoverageInformationNBCriticalExtensions) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationNBCriticalExtensions{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UEPagingCoverageInformationNBCriticalExtensionsChoiceC1:
		var dec_c1 UEPagingCoverageInformationNBCriticalExtensionsC1
		if err := dec_c1.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "C1")
		}
		v.C1 = &dec_c1
	case UEPagingCoverageInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture:
		var dec_criticalextensionsfuture UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture
		if err := dec_criticalextensionsfuture.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CriticalExtensionsFuture")
		}
		v.CriticalExtensionsFuture = &dec_criticalextensionsfuture
	}
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationNBCriticalExtensionsC1 to UPER format.
func (v *UEPagingCoverageInformationNBCriticalExtensionsC1) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEPagingCoverageInformationNBCriticalExtensionsC1) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceUePagingCoverageInformationR13:
		if v.UePagingCoverageInformationR13 == nil {
			return fmt.Errorf("choice alternative uePagingCoverageInformation-r13 is nil")
		}
		if err := v.UePagingCoverageInformationR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding uePagingCoverageInformation-r13: %w", err)
		}
	case UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare3:
	case UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare2:
	case UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare1:
	default:
		return fmt.Errorf("unknown UEPagingCoverageInformationNBCriticalExtensionsC1 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationNBCriticalExtensionsC1 from UPER format.
func (v *UEPagingCoverageInformationNBCriticalExtensionsC1) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBCriticalExtensionsC1")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBCriticalExtensionsC1")
	}
	return nil
}

func (v *UEPagingCoverageInformationNBCriticalExtensionsC1) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationNBCriticalExtensionsC1{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 3)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceUePagingCoverageInformationR13:
		var dec_uepagingcoverageinformationr13 UEPagingCoverageInformationNBIEs
		if err := dec_uepagingcoverageinformationr13.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UePagingCoverageInformationR13")
		}
		v.UePagingCoverageInformationR13 = &dec_uepagingcoverageinformationr13
	case UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare3:
	case UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare2:
	case UEPagingCoverageInformationNBCriticalExtensionsC1ChoiceSpare1:
	}
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture to UPER format.
func (v *UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture from UPER format.
func (v *UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture")
	}
	return nil
}

func (v *UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationNBCriticalExtensionsCriticalExtensionsFuture{}
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationNBV1700IEsNonCriticalExtension to UPER format.
func (v *UEPagingCoverageInformationNBV1700IEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEPagingCoverageInformationNBV1700IEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationNBV1700IEsNonCriticalExtension from UPER format.
func (v *UEPagingCoverageInformationNBV1700IEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBV1700IEsNonCriticalExtension")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEPagingCoverageInformationNBV1700IEsNonCriticalExtension")
	}
	return nil
}

func (v *UEPagingCoverageInformationNBV1700IEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationNBV1700IEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationNBCriticalExtensions to UPER format.
func (v *UERadioAccessCapabilityInformationNBCriticalExtensions) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioAccessCapabilityInformationNBCriticalExtensions) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case UERadioAccessCapabilityInformationNBCriticalExtensionsChoiceC1:
		if v.C1 == nil {
			return fmt.Errorf("choice alternative c1 is nil")
		}
		if err := v.C1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding c1: %w", err)
		}
	case UERadioAccessCapabilityInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture:
		if v.CriticalExtensionsFuture == nil {
			return fmt.Errorf("choice alternative criticalExtensionsFuture is nil")
		}
		if err := v.CriticalExtensionsFuture.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding criticalExtensionsFuture: %w", err)
		}
	default:
		return fmt.Errorf("unknown UERadioAccessCapabilityInformationNBCriticalExtensions choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationNBCriticalExtensions from UPER format.
func (v *UERadioAccessCapabilityInformationNBCriticalExtensions) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBCriticalExtensions")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBCriticalExtensions")
	}
	return nil
}

func (v *UERadioAccessCapabilityInformationNBCriticalExtensions) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationNBCriticalExtensions{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UERadioAccessCapabilityInformationNBCriticalExtensionsChoiceC1:
		var dec_c1 UERadioAccessCapabilityInformationNBCriticalExtensionsC1
		if err := dec_c1.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "C1")
		}
		v.C1 = &dec_c1
	case UERadioAccessCapabilityInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture:
		var dec_criticalextensionsfuture UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture
		if err := dec_criticalextensionsfuture.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CriticalExtensionsFuture")
		}
		v.CriticalExtensionsFuture = &dec_criticalextensionsfuture
	}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationNBCriticalExtensionsC1 to UPER format.
func (v *UERadioAccessCapabilityInformationNBCriticalExtensionsC1) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioAccessCapabilityInformationNBCriticalExtensionsC1) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceUeRadioAccessCapabilityInformationR13:
		if v.UeRadioAccessCapabilityInformationR13 == nil {
			return fmt.Errorf("choice alternative ueRadioAccessCapabilityInformation-r13 is nil")
		}
		if err := v.UeRadioAccessCapabilityInformationR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding ueRadioAccessCapabilityInformation-r13: %w", err)
		}
	case UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare3:
	case UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare2:
	case UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare1:
	default:
		return fmt.Errorf("unknown UERadioAccessCapabilityInformationNBCriticalExtensionsC1 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationNBCriticalExtensionsC1 from UPER format.
func (v *UERadioAccessCapabilityInformationNBCriticalExtensionsC1) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBCriticalExtensionsC1")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBCriticalExtensionsC1")
	}
	return nil
}

func (v *UERadioAccessCapabilityInformationNBCriticalExtensionsC1) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationNBCriticalExtensionsC1{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 3)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceUeRadioAccessCapabilityInformationR13:
		var dec_ueradioaccesscapabilityinformationr13 UERadioAccessCapabilityInformationNBIEs
		if err := dec_ueradioaccesscapabilityinformationr13.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UeRadioAccessCapabilityInformationR13")
		}
		v.UeRadioAccessCapabilityInformationR13 = &dec_ueradioaccesscapabilityinformationr13
	case UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare3:
	case UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare2:
	case UERadioAccessCapabilityInformationNBCriticalExtensionsC1ChoiceSpare1:
	}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture to UPER format.
func (v *UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture from UPER format.
func (v *UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture")
	}
	return nil
}

func (v *UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationNBCriticalExtensionsCriticalExtensionsFuture{}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension to UPER format.
func (v *UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension from UPER format.
func (v *UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension")
	}
	return nil
}

func (v *UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationNBR14IEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationNBCriticalExtensions to UPER format.
func (v *UERadioPagingInformationNBCriticalExtensions) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioPagingInformationNBCriticalExtensions) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case UERadioPagingInformationNBCriticalExtensionsChoiceC1:
		if v.C1 == nil {
			return fmt.Errorf("choice alternative c1 is nil")
		}
		if err := v.C1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding c1: %w", err)
		}
	case UERadioPagingInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture:
		if v.CriticalExtensionsFuture == nil {
			return fmt.Errorf("choice alternative criticalExtensionsFuture is nil")
		}
		if err := v.CriticalExtensionsFuture.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding criticalExtensionsFuture: %w", err)
		}
	default:
		return fmt.Errorf("unknown UERadioPagingInformationNBCriticalExtensions choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationNBCriticalExtensions from UPER format.
func (v *UERadioPagingInformationNBCriticalExtensions) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNBCriticalExtensions")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNBCriticalExtensions")
	}
	return nil
}

func (v *UERadioPagingInformationNBCriticalExtensions) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationNBCriticalExtensions{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UERadioPagingInformationNBCriticalExtensionsChoiceC1:
		var dec_c1 UERadioPagingInformationNBCriticalExtensionsC1
		if err := dec_c1.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "C1")
		}
		v.C1 = &dec_c1
	case UERadioPagingInformationNBCriticalExtensionsChoiceCriticalExtensionsFuture:
		var dec_criticalextensionsfuture UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture
		if err := dec_criticalextensionsfuture.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CriticalExtensionsFuture")
		}
		v.CriticalExtensionsFuture = &dec_criticalextensionsfuture
	}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationNBCriticalExtensionsC1 to UPER format.
func (v *UERadioPagingInformationNBCriticalExtensionsC1) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioPagingInformationNBCriticalExtensionsC1) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case UERadioPagingInformationNBCriticalExtensionsC1ChoiceUeRadioPagingInformationR13:
		if v.UeRadioPagingInformationR13 == nil {
			return fmt.Errorf("choice alternative ueRadioPagingInformation-r13 is nil")
		}
		if err := v.UeRadioPagingInformationR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding ueRadioPagingInformation-r13: %w", err)
		}
	case UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare3:
	case UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare2:
	case UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare1:
	default:
		return fmt.Errorf("unknown UERadioPagingInformationNBCriticalExtensionsC1 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationNBCriticalExtensionsC1 from UPER format.
func (v *UERadioPagingInformationNBCriticalExtensionsC1) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNBCriticalExtensionsC1")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNBCriticalExtensionsC1")
	}
	return nil
}

func (v *UERadioPagingInformationNBCriticalExtensionsC1) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationNBCriticalExtensionsC1{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 3)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UERadioPagingInformationNBCriticalExtensionsC1ChoiceUeRadioPagingInformationR13:
		var dec_ueradiopaginginformationr13 UERadioPagingInformationNBIEs
		if err := dec_ueradiopaginginformationr13.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UeRadioPagingInformationR13")
		}
		v.UeRadioPagingInformationR13 = &dec_ueradiopaginginformationr13
	case UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare3:
	case UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare2:
	case UERadioPagingInformationNBCriticalExtensionsC1ChoiceSpare1:
	}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture to UPER format.
func (v *UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture from UPER format.
func (v *UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture")
	}
	return nil
}

func (v *UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationNBCriticalExtensionsCriticalExtensionsFuture{}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationNBIEsNonCriticalExtension to UPER format.
func (v *UERadioPagingInformationNBIEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioPagingInformationNBIEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationNBIEsNonCriticalExtension from UPER format.
func (v *UERadioPagingInformationNBIEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNBIEsNonCriticalExtension")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioPagingInformationNBIEsNonCriticalExtension")
	}
	return nil
}

func (v *UERadioPagingInformationNBIEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationNBIEsNonCriticalExtension{}
	return nil
}
