// Code generated from ASN.1 module "EUTRA-InterNodeDefinitions". DO NOT EDIT.

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

const (

	// MaxReestabInfo is the integer constant for maxReestabInfo.
	MaxReestabInfo int64 = 32
)

// HandoverCommand represents the ASN.1 type HandoverCommand (SEQUENCE).
type HandoverCommand struct {
	CriticalExtensions HandoverCommandCriticalExtensions `asn1:"tag:0,context,explicit"`
}

// HandoverCommandR8IEs represents the ASN.1 type HandoverCommand-r8-IEs (SEQUENCE).
type HandoverCommandR8IEs struct {
	HandoverCommandMessage DLDCCHMessage                             `asn1:"tag:0,context,implicit"`
	NonCriticalExtension   *HandoverCommandR8IEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformation represents the ASN.1 type HandoverPreparationInformation (SEQUENCE).
type HandoverPreparationInformation struct {
	CriticalExtensions HandoverPreparationInformationCriticalExtensions `asn1:"tag:0,context,explicit"`
}

// HandoverPreparationInformationR8IEs represents the ASN.1 type HandoverPreparationInformation-r8-IEs (SEQUENCE).
type HandoverPreparationInformationR8IEs struct {
	UeRadioAccessCapabilityInfo       UECapabilityRATContainerList           `asn1:"tag:0,context,implicit"`
	UeRadioAccessCapabilityInfoIndef_ bool                                   `asn1:"-" json:"-"`
	AsConfig                          *ASConfig                              `asn1:"tag:1,context,implicit,optional" json:"AsConfig,omitempty"`
	RrmConfig                         *RRMConfig                             `asn1:"tag:2,context,implicit,optional" json:"RrmConfig,omitempty"`
	AsContext                         *ASContext                             `asn1:"tag:3,context,implicit,optional" json:"AsContext,omitempty"`
	NonCriticalExtension              *HandoverPreparationInformationV920IEs `asn1:"tag:4,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV920IEs represents the ASN.1 type HandoverPreparationInformation-v920-IEs (SEQUENCE).
type HandoverPreparationInformationV920IEs struct {
	UeConfigReleaseR9    *int64                                 `asn1:"tag:0,context,implicit,optional" json:"UeConfigReleaseR9,omitempty"`
	NonCriticalExtension *HandoverPreparationInformationV9d0IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV9d0IEs represents the ASN.1 type HandoverPreparationInformation-v9d0-IEs (SEQUENCE).
type HandoverPreparationInformationV9d0IEs struct {
	LateNonCriticalExtension *HandoverPreparationInformationV9j0IEs `asn1:"tag:0,context,implicit,optional" json:"LateNonCriticalExtension,omitempty"`
	NonCriticalExtension     *HandoverPreparationInformationV9e0IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV9j0IEs represents the ASN.1 type HandoverPreparationInformation-v9j0-IEs (SEQUENCE).
type HandoverPreparationInformationV9j0IEs struct {
	LateNonCriticalExtension []byte                                  `asn1:"tag:0,context,implicit,optional" json:"LateNonCriticalExtension,omitempty"`
	NonCriticalExtension     *HandoverPreparationInformationV10j0IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV10j0IEs represents the ASN.1 type HandoverPreparationInformation-v10j0-IEs (SEQUENCE).
type HandoverPreparationInformationV10j0IEs struct {
	AsConfigV10j0        *ASConfigV10j0                          `asn1:"tag:0,context,implicit,optional" json:"AsConfigV10j0,omitempty"`
	NonCriticalExtension *HandoverPreparationInformationV10x0IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV10x0IEs represents the ASN.1 type HandoverPreparationInformation-v10x0-IEs (SEQUENCE).
type HandoverPreparationInformationV10x0IEs struct {
	LateNonCriticalExtension []byte                                  `asn1:"tag:0,context,implicit,optional" json:"LateNonCriticalExtension,omitempty"`
	NonCriticalExtension     *HandoverPreparationInformationV13c0IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV13c0IEs represents the ASN.1 type HandoverPreparationInformation-v13c0-IEs (SEQUENCE).
type HandoverPreparationInformationV13c0IEs struct {
	AsConfigV13c0        *ASConfigV13c0                                              `asn1:"tag:0,context,implicit,optional" json:"AsConfigV13c0,omitempty"`
	NonCriticalExtension *HandoverPreparationInformationV13c0IEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV9e0IEs represents the ASN.1 type HandoverPreparationInformation-v9e0-IEs (SEQUENCE).
type HandoverPreparationInformationV9e0IEs struct {
	AsConfigV9e0         *ASConfigV9e0                           `asn1:"tag:0,context,implicit,optional" json:"AsConfigV9e0,omitempty"`
	NonCriticalExtension *HandoverPreparationInformationV1130IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV1130IEs represents the ASN.1 type HandoverPreparationInformation-v1130-IEs (SEQUENCE).
type HandoverPreparationInformationV1130IEs struct {
	AsContextV1130       *ASContextV1130                         `asn1:"tag:0,context,implicit,optional" json:"AsContextV1130,omitempty"`
	NonCriticalExtension *HandoverPreparationInformationV1250IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV1250IEs represents the ASN.1 type HandoverPreparationInformation-v1250-IEs (SEQUENCE).
type HandoverPreparationInformationV1250IEs struct {
	UeSupportedEARFCNR12 *ARFCNValueEUTRAR9                      `asn1:"tag:0,context,implicit,optional" json:"UeSupportedEARFCNR12,omitempty"`
	AsConfigV1250        *ASConfigV1250                          `asn1:"tag:1,context,implicit,optional" json:"AsConfigV1250,omitempty"`
	NonCriticalExtension *HandoverPreparationInformationV1320IEs `asn1:"tag:2,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV1320IEs represents the ASN.1 type HandoverPreparationInformation-v1320-IEs (SEQUENCE).
type HandoverPreparationInformationV1320IEs struct {
	AsConfigV1320        *ASConfigV1320                          `asn1:"tag:0,context,implicit,optional" json:"AsConfigV1320,omitempty"`
	AsContextV1320       *ASContextV1320                         `asn1:"tag:1,context,implicit,optional" json:"AsContextV1320,omitempty"`
	NonCriticalExtension *HandoverPreparationInformationV1430IEs `asn1:"tag:2,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV1430IEs represents the ASN.1 type HandoverPreparationInformation-v1430-IEs (SEQUENCE).
type HandoverPreparationInformationV1430IEs struct {
	AsConfigV1430         *ASConfigV1430                          `asn1:"tag:0,context,implicit,optional" json:"AsConfigV1430,omitempty"`
	MakeBeforeBreakReqR14 *int64                                  `asn1:"tag:1,context,implicit,optional" json:"MakeBeforeBreakReqR14,omitempty"`
	NonCriticalExtension  *HandoverPreparationInformationV1530IEs `asn1:"tag:2,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV1530IEs represents the ASN.1 type HandoverPreparationInformation-v1530-IEs (SEQUENCE).
type HandoverPreparationInformationV1530IEs struct {
	RanNotificationAreaInfoR15 *RANNotificationAreaInfoR15             `asn1:"tag:0,context,explicit,optional" json:"RanNotificationAreaInfoR15,omitempty"`
	NonCriticalExtension       *HandoverPreparationInformationV1540IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV1540IEs represents the ASN.1 type HandoverPreparationInformation-v1540-IEs (SEQUENCE).
type HandoverPreparationInformationV1540IEs struct {
	SourceRBConfigIntra5GCR15 []byte                                  `asn1:"tag:0,context,implicit,optional" json:"SourceRBConfigIntra5GCR15,omitempty"`
	NonCriticalExtension      *HandoverPreparationInformationV1610IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV1610IEs represents the ASN.1 type HandoverPreparationInformation-v1610-IEs (SEQUENCE).
type HandoverPreparationInformationV1610IEs struct {
	AsContextV1610       *ASContextV1610                         `asn1:"tag:0,context,implicit,optional" json:"AsContextV1610,omitempty"`
	NonCriticalExtension *HandoverPreparationInformationV1620IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV1620IEs represents the ASN.1 type HandoverPreparationInformation-v1620-IEs (SEQUENCE).
type HandoverPreparationInformationV1620IEs struct {
	AsContextV1620       *ASContextV1620                         `asn1:"tag:0,context,implicit,optional" json:"AsContextV1620,omitempty"`
	NonCriticalExtension *HandoverPreparationInformationV1630IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV1630IEs represents the ASN.1 type HandoverPreparationInformation-v1630-IEs (SEQUENCE).
type HandoverPreparationInformationV1630IEs struct {
	AsContextV1630       *ASContextV1630                         `asn1:"tag:0,context,implicit,optional" json:"AsContextV1630,omitempty"`
	NonCriticalExtension *HandoverPreparationInformationV1700IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// HandoverPreparationInformationV1700IEs represents the ASN.1 type HandoverPreparationInformation-v1700-IEs (SEQUENCE).
type HandoverPreparationInformationV1700IEs struct {
	AsConfigV1700        *ASConfigV1700                                              `asn1:"tag:0,context,implicit,optional" json:"AsConfigV1700,omitempty"`
	NonCriticalExtension *HandoverPreparationInformationV1700IEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// SCGConfigR12 represents the ASN.1 type SCG-Config-r12 (SEQUENCE).
type SCGConfigR12 struct {
	CriticalExtensions SCGConfigR12CriticalExtensions `asn1:"tag:0,context,explicit"`
}

// SCGConfigR12IEs represents the ASN.1 type SCG-Config-r12-IEs (SEQUENCE).
type SCGConfigR12IEs struct {
	ScgRadioConfigR12    *SCGConfigPartSCGR12 `asn1:"tag:0,context,implicit,optional" json:"ScgRadioConfigR12,omitempty"`
	NonCriticalExtension *SCGConfigV12i0aIEs  `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// SCGConfigV12i0aIEs represents the ASN.1 type SCG-Config-v12i0a-IEs (SEQUENCE).
type SCGConfigV12i0aIEs struct {
	LateNonCriticalExtension *SCGConfigV12i0bIEs `asn1:"tag:0,context,implicit,optional" json:"LateNonCriticalExtension,omitempty"`
	NonCriticalExtension     *SCGConfigV13c0IEs  `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// SCGConfigV12i0bIEs represents the ASN.1 type SCG-Config-v12i0b-IEs (SEQUENCE).
type SCGConfigV12i0bIEs struct {
	ScgRadioConfigV12i0  *SCGConfigPartSCGV12f0                  `asn1:"tag:0,context,implicit,optional" json:"ScgRadioConfigV12i0,omitempty"`
	NonCriticalExtension *SCGConfigV12i0bIEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// SCGConfigV13c0IEs represents the ASN.1 type SCG-Config-v13c0-IEs (SEQUENCE).
type SCGConfigV13c0IEs struct {
	ScgRadioConfigV13c0  *SCGConfigPartSCGV13c0                 `asn1:"tag:0,context,implicit,optional" json:"ScgRadioConfigV13c0,omitempty"`
	NonCriticalExtension *SCGConfigV13c0IEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// SCGConfigInfoR12 represents the ASN.1 type SCG-ConfigInfo-r12 (SEQUENCE).
type SCGConfigInfoR12 struct {
	CriticalExtensions SCGConfigInfoR12CriticalExtensions `asn1:"tag:0,context,explicit"`
}

// SCGConfigInfoR12IEs represents the ASN.1 type SCG-ConfigInfo-r12-IEs (SEQUENCE).
type SCGConfigInfoR12IEs struct {
	RadioResourceConfigDedMCGR12       *RadioResourceConfigDedicated `asn1:"tag:0,context,implicit,optional" json:"RadioResourceConfigDedMCGR12,omitempty"`
	SCellToAddModListMCGR12            SCellToAddModListR10          `asn1:"tag:1,context,implicit,optional" json:"SCellToAddModListMCGR12,omitempty"`
	SCellToAddModListMCGR12Indef_      bool                          `asn1:"-" json:"-"`
	MeasGapConfigR12                   *MeasGapConfig                `asn1:"tag:2,context,explicit,optional" json:"MeasGapConfigR12,omitempty"`
	PowerCoordinationInfoR12           *PowerCoordinationInfoR12     `asn1:"tag:3,context,implicit,optional" json:"PowerCoordinationInfoR12,omitempty"`
	ScgRadioConfigR12                  *SCGConfigPartSCGR12          `asn1:"tag:4,context,implicit,optional" json:"ScgRadioConfigR12,omitempty"`
	EutraCapabilityInfoR12             *UECapabilityInformation      `asn1:"tag:5,context,implicit,optional" json:"EutraCapabilityInfoR12,omitempty"`
	ScgConfigRestrictInfoR12           *SCGConfigRestrictInfoR12     `asn1:"tag:6,context,implicit,optional" json:"ScgConfigRestrictInfoR12,omitempty"`
	MbmsInterestIndicationR12          *MBMSInterestIndicationR11    `asn1:"tag:7,context,implicit,optional" json:"MbmsInterestIndicationR12,omitempty"`
	MeasResultServCellListSCGR12       MeasResultServCellListSCGR12  `asn1:"tag:8,context,implicit,optional" json:"MeasResultServCellListSCGR12,omitempty"`
	MeasResultServCellListSCGR12Indef_ bool                          `asn1:"-" json:"-"`
	DrbToAddModListSCGR12              DRBInfoListSCGR12             `asn1:"tag:9,context,implicit,optional" json:"DrbToAddModListSCGR12,omitempty"`
	DrbToAddModListSCGR12Indef_        bool                          `asn1:"-" json:"-"`
	DrbToReleaseListSCGR12             DRBToReleaseList              `asn1:"tag:10,context,implicit,optional" json:"DrbToReleaseListSCGR12,omitempty"`
	DrbToReleaseListSCGR12Indef_       bool                          `asn1:"-" json:"-"`
	SCellToAddModListSCGR12            SCellToAddModListSCGR12       `asn1:"tag:11,context,implicit,optional" json:"SCellToAddModListSCGR12,omitempty"`
	SCellToAddModListSCGR12Indef_      bool                          `asn1:"-" json:"-"`
	SCellToReleaseListSCGR12           SCellToReleaseListR10         `asn1:"tag:12,context,implicit,optional" json:"SCellToReleaseListSCGR12,omitempty"`
	SCellToReleaseListSCGR12Indef_     bool                          `asn1:"-" json:"-"`
	PMaxR12                            *PMax                         `asn1:"tag:13,context,implicit,optional" json:"PMaxR12,omitempty"`
	NonCriticalExtension               *SCGConfigInfoV1310IEs        `asn1:"tag:14,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// SCGConfigInfoV1310IEs represents the ASN.1 type SCG-ConfigInfo-v1310-IEs (SEQUENCE).
type SCGConfigInfoV1310IEs struct {
	MeasResultSSTDR13                     *MeasResultSSTDR13              `asn1:"tag:0,context,implicit,optional" json:"MeasResultSSTDR13,omitempty"`
	SCellToAddModListMCGExtR13            SCellToAddModListExtR13         `asn1:"tag:1,context,implicit,optional" json:"SCellToAddModListMCGExtR13,omitempty"`
	SCellToAddModListMCGExtR13Indef_      bool                            `asn1:"-" json:"-"`
	MeasResultServCellListSCGExtR13       MeasResultServCellListSCGExtR13 `asn1:"tag:2,context,implicit,optional" json:"MeasResultServCellListSCGExtR13,omitempty"`
	MeasResultServCellListSCGExtR13Indef_ bool                            `asn1:"-" json:"-"`
	SCellToAddModListSCGExtR13            SCellToAddModListSCGExtR13      `asn1:"tag:3,context,implicit,optional" json:"SCellToAddModListSCGExtR13,omitempty"`
	SCellToAddModListSCGExtR13Indef_      bool                            `asn1:"-" json:"-"`
	SCellToReleaseListSCGExtR13           SCellToReleaseListExtR13        `asn1:"tag:4,context,implicit,optional" json:"SCellToReleaseListSCGExtR13,omitempty"`
	SCellToReleaseListSCGExtR13Indef_     bool                            `asn1:"-" json:"-"`
	NonCriticalExtension                  *SCGConfigInfoV1330IEs          `asn1:"tag:5,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// SCGConfigInfoV1330IEs represents the ASN.1 type SCG-ConfigInfo-v1330-IEs (SEQUENCE).
type SCGConfigInfoV1330IEs struct {
	MeasResultListRSSISCGR13       MeasResultListRSSISCGR13 `asn1:"tag:0,context,implicit,optional" json:"MeasResultListRSSISCGR13,omitempty"`
	MeasResultListRSSISCGR13Indef_ bool                     `asn1:"-" json:"-"`
	NonCriticalExtension           *SCGConfigInfoV1430IEs   `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// SCGConfigInfoV1430IEs represents the ASN.1 type SCG-ConfigInfo-v1430-IEs (SEQUENCE).
type SCGConfigInfoV1430IEs struct {
	MakeBeforeBreakSCGReqR14 *int64                     `asn1:"tag:0,context,implicit,optional" json:"MakeBeforeBreakSCGReqR14,omitempty"`
	MeasGapConfigPerCCList   *MeasGapConfigPerCCListR14 `asn1:"tag:1,context,explicit,optional" json:"MeasGapConfigPerCCList,omitempty"`
	NonCriticalExtension     *SCGConfigInfoV1530IEs     `asn1:"tag:2,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// SCGConfigInfoV1530IEs represents the ASN.1 type SCG-ConfigInfo-v1530-IEs (SEQUENCE).
type SCGConfigInfoV1530IEs struct {
	DrbToAddModListSCGR15        DRBInfoListSCGR15                          `asn1:"tag:0,context,implicit,optional" json:"DrbToAddModListSCGR15,omitempty"`
	DrbToAddModListSCGR15Indef_  bool                                       `asn1:"-" json:"-"`
	DrbToReleaseListSCGR15       DRBToReleaseListR15                        `asn1:"tag:1,context,implicit,optional" json:"DrbToReleaseListSCGR15,omitempty"`
	DrbToReleaseListSCGR15Indef_ bool                                       `asn1:"-" json:"-"`
	NonCriticalExtension         *SCGConfigInfoV1530IEsNonCriticalExtension `asn1:"tag:2,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// DRBInfoListSCGR12 represents the ASN.1 type DRB-InfoListSCG-r12 (SEQUENCE_OF).
type DRBInfoListSCGR12 = []DRBInfoSCGR12

// DRBInfoListSCGR15 represents the ASN.1 type DRB-InfoListSCG-r15 (SEQUENCE_OF).
type DRBInfoListSCGR15 = []DRBInfoSCGR12

// DRBInfoSCGR12 represents the ASN.1 type DRB-InfoSCG-r12 (SEQUENCE).
type DRBInfoSCGR12 struct {
	EpsBearerIdentityR12 *int64      `asn1:"tag:0,context,implicit,optional" json:"EpsBearerIdentityR12,omitempty"`
	DrbIdentityR12       DRBIdentity `asn1:"tag:1,context,implicit"`
	DrbTypeR12           *int64      `asn1:"tag:2,context,implicit,optional" json:"DrbTypeR12,omitempty"`
	ExtCount_            int64       `asn1:"-" json:"-"`
	ExtPresent_          []bool      `asn1:"-" json:"-"`
	ExtData_             [][]byte    `asn1:"-" json:"-"`
}

// SCellToAddModListSCGR12 represents the ASN.1 type SCellToAddModListSCG-r12 (SEQUENCE_OF).
type SCellToAddModListSCGR12 = []CellToAddModR12

// SCellToAddModListSCGExtR13 represents the ASN.1 type SCellToAddModListSCG-Ext-r13 (SEQUENCE_OF).
type SCellToAddModListSCGExtR13 = []CellToAddModR12

// CellToAddModR12 represents the ASN.1 type Cell-ToAddMod-r12 (SEQUENCE).
type CellToAddModR12 struct {
	SCellIndexR12            SCellIndexR10                            `asn1:"tag:0,context,implicit"`
	CellIdentificationR12    *CellToAddModR12CellIdentificationR12    `asn1:"tag:1,context,implicit,optional" json:"CellIdentificationR12,omitempty"`
	MeasResultCellToAddR12   *CellToAddModR12MeasResultCellToAddR12   `asn1:"tag:2,context,implicit,optional" json:"MeasResultCellToAddR12,omitempty"`
	SCellIndexR13            *SCellIndexR13                           `asn1:"tag:3,context,implicit,optional" json:"SCellIndexR13,omitempty"`
	MeasResultCellToAddV1310 *CellToAddModR12MeasResultCellToAddV1310 `asn1:"tag:4,context,implicit,optional" json:"MeasResultCellToAddV1310,omitempty"`
	ExtCount_                int64                                    `asn1:"-" json:"-"`
	ExtPresent_              []bool                                   `asn1:"-" json:"-"`
	ExtData_                 [][]byte                                 `asn1:"-" json:"-"`
}

// MeasResultServCellListSCGR12 represents the ASN.1 type MeasResultServCellListSCG-r12 (SEQUENCE_OF).
type MeasResultServCellListSCGR12 = []MeasResultServCellSCGR12

// MeasResultServCellListSCGExtR13 represents the ASN.1 type MeasResultServCellListSCG-Ext-r13 (SEQUENCE_OF).
type MeasResultServCellListSCGExtR13 = []MeasResultServCellSCGR12

// MeasResultServCellSCGR12 represents the ASN.1 type MeasResultServCellSCG-r12 (SEQUENCE).
type MeasResultServCellSCGR12 struct {
	ServCellIdR12        ServCellIndexR10                              `asn1:"tag:0,context,implicit"`
	MeasResultSCellR12   MeasResultServCellSCGR12MeasResultSCellR12    `asn1:"tag:1,context,implicit"`
	ServCellIdR13        *ServCellIndexR13                             `asn1:"tag:2,context,implicit,optional" json:"ServCellIdR13,omitempty"`
	MeasResultSCellV1310 *MeasResultServCellSCGR12MeasResultSCellV1310 `asn1:"tag:3,context,implicit,optional" json:"MeasResultSCellV1310,omitempty"`
	ExtCount_            int64                                         `asn1:"-" json:"-"`
	ExtPresent_          []bool                                        `asn1:"-" json:"-"`
	ExtData_             [][]byte                                      `asn1:"-" json:"-"`
}

// MeasResultListRSSISCGR13 represents the ASN.1 type MeasResultListRSSI-SCG-r13 (SEQUENCE_OF).
type MeasResultListRSSISCGR13 = []MeasResultRSSISCGR13

// MeasResultRSSISCGR13 represents the ASN.1 type MeasResultRSSI-SCG-r13 (SEQUENCE).
type MeasResultRSSISCGR13 struct {
	ServCellIdR13        ServCellIndexR13     `asn1:"tag:0,context,implicit"`
	MeasResultForRSSIR13 MeasResultForRSSIR13 `asn1:"tag:1,context,implicit"`
}

// SCGConfigRestrictInfoR12 represents the ASN.1 type SCG-ConfigRestrictInfo-r12 (SEQUENCE).
type SCGConfigRestrictInfoR12 struct {
	MaxSCHTBBitsDLR12 int64 `asn1:"tag:0,context,implicit"`
	MaxSCHTBBitsULR12 int64 `asn1:"tag:1,context,implicit"`
}

// UEPagingCoverageInformation represents the ASN.1 type UEPagingCoverageInformation (SEQUENCE).
type UEPagingCoverageInformation struct {
	CriticalExtensions UEPagingCoverageInformationCriticalExtensions `asn1:"tag:0,context,explicit"`
}

// UEPagingCoverageInformationR13IEs represents the ASN.1 type UEPagingCoverageInformation-r13-IEs (SEQUENCE).
type UEPagingCoverageInformationR13IEs struct {
	MpdcchNumRepetitionR13 *int64                                                 `asn1:"tag:0,context,implicit,optional" json:"MpdcchNumRepetitionR13,omitempty"`
	NonCriticalExtension   *UEPagingCoverageInformationR13IEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// UERadioAccessCapabilityInformation represents the ASN.1 type UERadioAccessCapabilityInformation (SEQUENCE).
type UERadioAccessCapabilityInformation struct {
	CriticalExtensions UERadioAccessCapabilityInformationCriticalExtensions `asn1:"tag:0,context,explicit"`
}

// UERadioAccessCapabilityInformationR8IEs represents the ASN.1 type UERadioAccessCapabilityInformation-r8-IEs (SEQUENCE).
type UERadioAccessCapabilityInformationR8IEs struct {
	UeRadioAccessCapabilityInfo UECapabilityInformation                                      `asn1:"tag:0,context,implicit"`
	NonCriticalExtension        *UERadioAccessCapabilityInformationR8IEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// UERadioPagingInformation represents the ASN.1 type UERadioPagingInformation (SEQUENCE).
type UERadioPagingInformation struct {
	CriticalExtensions UERadioPagingInformationCriticalExtensions `asn1:"tag:0,context,explicit"`
}

// UERadioPagingInformationR12IEs represents the ASN.1 type UERadioPagingInformation-r12-IEs (SEQUENCE).
type UERadioPagingInformationR12IEs struct {
	UeRadioPagingInfoR12 UERadioPagingInfoR12              `asn1:"tag:0,context,implicit"`
	NonCriticalExtension *UERadioPagingInformationV1310IEs `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// UERadioPagingInformationV1310IEs represents the ASN.1 type UERadioPagingInformation-v1310-IEs (SEQUENCE).
type UERadioPagingInformationV1310IEs struct {
	SupportedBandListEUTRAForPagingR13       UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13 `asn1:"tag:0,context,implicit,optional" json:"SupportedBandListEUTRAForPagingR13,omitempty"`
	SupportedBandListEUTRAForPagingR13Indef_ bool                                                               `asn1:"-" json:"-"`
	NonCriticalExtension                     *UERadioPagingInformationV1610IEs                                  `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// UERadioPagingInformationV1610IEs represents the ASN.1 type UERadioPagingInformation-v1610-IEs (SEQUENCE).
type UERadioPagingInformationV1610IEs struct {
	AccessStratumReleaseR16 *int64                                                `asn1:"tag:0,context,implicit,optional" json:"AccessStratumReleaseR16,omitempty"`
	NonCriticalExtension    *UERadioPagingInformationV1610IEsNonCriticalExtension `asn1:"tag:1,context,implicit,optional" json:"NonCriticalExtension,omitempty"`
}

// ASConfig represents the ASN.1 type AS-Config (SEQUENCE).
type ASConfig struct {
	SourceMeasConfig                     MeasConfig                          `asn1:"tag:0,context,implicit"`
	SourceRadioResourceConfig            RadioResourceConfigDedicated        `asn1:"tag:1,context,implicit"`
	SourceSecurityAlgorithmConfig        SecurityAlgorithmConfig             `asn1:"tag:2,context,implicit"`
	SourceUEIdentity                     CRNTI                               `asn1:"tag:3,context,implicit"`
	SourceMasterInformationBlock         MasterInformationBlock              `asn1:"tag:4,context,implicit"`
	SourceSystemInformationBlockType1    SystemInformationBlockType1         `asn1:"tag:5,context,implicit"`
	SourceSystemInformationBlockType2    SystemInformationBlockType2         `asn1:"tag:6,context,implicit"`
	AntennaInfoCommon                    AntennaInfoCommon                   `asn1:"tag:7,context,implicit"`
	SourceDlCarrierFreq                  ARFCNValueEUTRA                     `asn1:"tag:8,context,implicit"`
	SourceSystemInformationBlockType1Ext *SystemInformationBlockType1V890IEs `asn1:"tag:9,context,implicit,optional" json:"SourceSystemInformationBlockType1Ext,omitempty"`
	SourceOtherConfigR9                  *OtherConfigR9                      `asn1:"tag:10,context,implicit" json:"SourceOtherConfigR9,omitempty"`
	SourceSCellConfigListR10             SCellToAddModListR10                `asn1:"tag:11,context,implicit,optional" json:"SourceSCellConfigListR10,omitempty"`
	SourceSCellConfigListR10Indef_       bool                                `asn1:"-" json:"-"`
	SourceConfigSCGR12                   *SCGConfigR12                       `asn1:"tag:12,context,implicit,optional" json:"SourceConfigSCGR12,omitempty"`
	AsConfigNRR15                        *ASConfigNRR15                      `asn1:"tag:13,context,implicit,optional" json:"AsConfigNRR15,omitempty"`
	AsConfigV1550                        *ASConfigV1550                      `asn1:"tag:14,context,implicit,optional" json:"AsConfigV1550,omitempty"`
	AsConfigNRV1570                      *ASConfigNRV1570                    `asn1:"tag:15,context,implicit,optional" json:"AsConfigNRV1570,omitempty"`
	AsConfigNRV1620                      *ASConfigNRV1620                    `asn1:"tag:16,context,implicit,optional" json:"AsConfigNRV1620,omitempty"`
	ExtCount_                            int64                               `asn1:"-" json:"-"`
	ExtPresent_                          []bool                              `asn1:"-" json:"-"`
	ExtData_                             [][]byte                            `asn1:"-" json:"-"`
}

// ASConfigV9e0 represents the ASN.1 type AS-Config-v9e0 (SEQUENCE).
type ASConfigV9e0 struct {
	SourceDlCarrierFreqV9e0 ARFCNValueEUTRAV9e0 `asn1:"tag:0,context,implicit"`
}

// ASConfigV10j0 represents the ASN.1 type AS-Config-v10j0 (SEQUENCE).
type ASConfigV10j0 struct {
	AntennaInfoDedicatedPCellV10i0 *AntennaInfoDedicatedV10i0 `asn1:"tag:0,context,implicit,optional" json:"AntennaInfoDedicatedPCellV10i0,omitempty"`
}

// ASConfigV1250 represents the ASN.1 type AS-Config-v1250 (SEQUENCE).
type ASConfigV1250 struct {
	SourceWlanOffloadConfigR12 *WLANOffloadConfigR12 `asn1:"tag:0,context,implicit,optional" json:"SourceWlanOffloadConfigR12,omitempty"`
	SourceSLCommConfigR12      *SLCommConfigR12      `asn1:"tag:1,context,implicit,optional" json:"SourceSLCommConfigR12,omitempty"`
	SourceSLDiscConfigR12      *SLDiscConfigR12      `asn1:"tag:2,context,implicit,optional" json:"SourceSLDiscConfigR12,omitempty"`
}

// ASConfigV1320 represents the ASN.1 type AS-Config-v1320 (SEQUENCE).
type ASConfigV1320 struct {
	SourceSCellConfigListR13       SCellToAddModListExtR13 `asn1:"tag:0,context,implicit,optional" json:"SourceSCellConfigListR13,omitempty"`
	SourceSCellConfigListR13Indef_ bool                    `asn1:"-" json:"-"`
	SourceRCLWIConfigurationR13    *RCLWIConfigurationR13  `asn1:"tag:1,context,explicit,optional" json:"SourceRCLWIConfigurationR13,omitempty"`
}

// ASConfigV13c0 represents the ASN.1 type AS-Config-v13c0 (SEQUENCE).
type ASConfigV13c0 struct {
	RadioResourceConfigDedicatedV13c01 *RadioResourceConfigDedicatedV1370 `asn1:"tag:0,context,implicit,optional" json:"RadioResourceConfigDedicatedV13c01,omitempty"`
	RadioResourceConfigDedicatedV13c02 *RadioResourceConfigDedicatedV13c0 `asn1:"tag:1,context,implicit,optional" json:"RadioResourceConfigDedicatedV13c02,omitempty"`
	SCellToAddModListV13c0             SCellToAddModListV13c0             `asn1:"tag:2,context,implicit,optional" json:"SCellToAddModListV13c0,omitempty"`
	SCellToAddModListV13c0Indef_       bool                               `asn1:"-" json:"-"`
	SCellToAddModListExtV13c0          SCellToAddModListExtV13c0          `asn1:"tag:3,context,implicit,optional" json:"SCellToAddModListExtV13c0,omitempty"`
	SCellToAddModListExtV13c0Indef_    bool                               `asn1:"-" json:"-"`
}

// ASConfigV1430 represents the ASN.1 type AS-Config-v1430 (SEQUENCE).
type ASConfigV1430 struct {
	SourceSLV2XCommConfigR14      *SLV2XConfigDedicatedR14 `asn1:"tag:0,context,implicit,optional" json:"SourceSLV2XCommConfigR14,omitempty"`
	SourceLWAConfigR14            *LWAConfigR13            `asn1:"tag:1,context,implicit,optional" json:"SourceLWAConfigR14,omitempty"`
	SourceWLANMeasResultR14       MeasResultListWLANR13    `asn1:"tag:2,context,implicit,optional" json:"SourceWLANMeasResultR14,omitempty"`
	SourceWLANMeasResultR14Indef_ bool                     `asn1:"-" json:"-"`
}

// ASConfigNRR15 represents the ASN.1 type AS-ConfigNR-r15 (SEQUENCE).
type ASConfigNRR15 struct {
	SourceRBConfigNRR15      []byte `asn1:"tag:0,context,implicit,optional" json:"SourceRBConfigNRR15,omitempty"`
	SourceRBConfigSNNRR15    []byte `asn1:"tag:1,context,implicit,optional" json:"SourceRBConfigSNNRR15,omitempty"`
	SourceOtherConfigSNNRR15 []byte `asn1:"tag:2,context,implicit,optional" json:"SourceOtherConfigSNNRR15,omitempty"`
}

// ASConfigNRV1570 represents the ASN.1 type AS-ConfigNR-v1570 (SEQUENCE).
type ASConfigNRV1570 struct {
	SourceSCGConfiguredNRR15 int64 `asn1:"tag:0,context,implicit"`
}

// ASConfigV1550 represents the ASN.1 type AS-Config-v1550 (SEQUENCE).
type ASConfigV1550 struct {
	TdmPatternConfigR15 *ASConfigV1550TdmPatternConfigR15 `asn1:"tag:0,context,implicit,optional" json:"TdmPatternConfigR15,omitempty"`
	PMaxEUTRAR15        *PMax                             `asn1:"tag:1,context,implicit,optional" json:"PMaxEUTRAR15,omitempty"`
}

// ASConfigNRV1620 represents the ASN.1 type AS-ConfigNR-v1620 (SEQUENCE).
type ASConfigNRV1620 struct {
	TdmPatternConfig2R16 TDMPatternConfigR15 `asn1:"tag:0,context,explicit"`
}

// ASConfigV1700 represents the ASN.1 type AS-Config-v1700 (SEQUENCE).
type ASConfigV1700 struct {
	ScgStateR17 *int64 `asn1:"tag:0,context,implicit,optional" json:"ScgStateR17,omitempty"`
}

// ASContext represents the ASN.1 type AS-Context (SEQUENCE).
type ASContext struct {
	ReestablishmentInfo *ReestablishmentInfo `asn1:"tag:0,context,implicit,optional" json:"ReestablishmentInfo,omitempty"`
}

// ASContextV1130 represents the ASN.1 type AS-Context-v1130 (SEQUENCE).
type ASContextV1130 struct {
	IdcIndicationR11                     *InDeviceCoexIndicationR11  `asn1:"tag:0,context,implicit,optional" json:"IdcIndicationR11,omitempty"`
	MbmsInterestIndicationR11            *MBMSInterestIndicationR11  `asn1:"tag:1,context,implicit,optional" json:"MbmsInterestIndicationR11,omitempty"`
	UeAssistanceInformationR11           *UEAssistanceInformationR11 `asn1:"tag:2,context,implicit,optional" json:"UeAssistanceInformationR11,omitempty"`
	SidelinkUEInformationR12             *SidelinkUEInformationR12   `asn1:"tag:3,context,implicit,optional" json:"SidelinkUEInformationR12,omitempty"`
	SourceContextENDCR15                 []byte                      `asn1:"tag:4,context,implicit,optional" json:"SourceContextENDCR15,omitempty"`
	SelectedbandCombinationInfoENDCV1540 []byte                      `asn1:"tag:5,context,implicit,optional" json:"SelectedbandCombinationInfoENDCV1540,omitempty"`
	ExtCount_                            int64                       `asn1:"-" json:"-"`
	ExtPresent_                          []bool                      `asn1:"-" json:"-"`
	ExtData_                             [][]byte                    `asn1:"-" json:"-"`
}

// ASContextV1320 represents the ASN.1 type AS-Context-v1320 (SEQUENCE).
type ASContextV1320 struct {
	WlanConnectionStatusReportR13 *WLANConnectionStatusReportR13 `asn1:"tag:0,context,implicit,optional" json:"WlanConnectionStatusReportR13,omitempty"`
}

// ASContextV1610 represents the ASN.1 type AS-Context-v1610 (SEQUENCE).
type ASContextV1610 struct {
	SidelinkUEInformationNRR16   []byte                     `asn1:"tag:0,context,implicit,optional" json:"SidelinkUEInformationNRR16,omitempty"`
	UeAssistanceInformationNRR16 []byte                     `asn1:"tag:1,context,implicit,optional" json:"UeAssistanceInformationNRR16,omitempty"`
	ConfigRestrictInfoDAPSR16    *ConfigRestrictInfoDAPSR16 `asn1:"tag:2,context,implicit,optional" json:"ConfigRestrictInfoDAPSR16,omitempty"`
}

// ASContextV1620 represents the ASN.1 type AS-Context-v1620 (SEQUENCE).
type ASContextV1620 struct {
	UeAssistanceInformationNRSCGR16 []byte `asn1:"tag:0,context,implicit,optional" json:"UeAssistanceInformationNRSCGR16,omitempty"`
}

// ASContextV1630 represents the ASN.1 type AS-Context-v1630 (SEQUENCE).
type ASContextV1630 struct {
	ConfigRestrictInfoDAPSV1630 *ConfigRestrictInfoDAPSV1630 `asn1:"tag:0,context,implicit,optional" json:"ConfigRestrictInfoDAPSV1630,omitempty"`
}

// ConfigRestrictInfoDAPSR16 represents the ASN.1 type ConfigRestrictInfoDAPS-r16 (SEQUENCE).
type ConfigRestrictInfoDAPSR16 struct {
	MaxSCHTBBitsDLR16 *int64 `asn1:"tag:0,context,implicit,optional" json:"MaxSCHTBBitsDLR16,omitempty"`
	MaxSCHTBBitsULR16 *int64 `asn1:"tag:1,context,implicit,optional" json:"MaxSCHTBBitsULR16,omitempty"`
}

// ConfigRestrictInfoDAPSV1630 represents the ASN.1 type ConfigRestrictInfoDAPS-v1630 (SEQUENCE).
type ConfigRestrictInfoDAPSV1630 struct {
	DapsPowerCoordinationInfoR16 *DAPSPowerCoordinationInfoR16 `asn1:"tag:0,context,implicit,optional" json:"DapsPowerCoordinationInfoR16,omitempty"`
}

// ReestablishmentInfo represents the ASN.1 type ReestablishmentInfo (SEQUENCE).
type ReestablishmentInfo struct {
	SourcePhysCellId                PhysCellId                `asn1:"tag:0,context,implicit"`
	TargetCellShortMACI             ShortMACI                 `asn1:"tag:1,context,implicit"`
	AdditionalReestabInfoList       AdditionalReestabInfoList `asn1:"tag:2,context,implicit,optional" json:"AdditionalReestabInfoList,omitempty"`
	AdditionalReestabInfoListIndef_ bool                      `asn1:"-" json:"-"`
	ExtCount_                       int64                     `asn1:"-" json:"-"`
	ExtPresent_                     []bool                    `asn1:"-" json:"-"`
	ExtData_                        [][]byte                  `asn1:"-" json:"-"`
}

// AdditionalReestabInfoList represents the ASN.1 type AdditionalReestabInfoList (SEQUENCE_OF).
type AdditionalReestabInfoList = []AdditionalReestabInfo

// AdditionalReestabInfo represents the ASN.1 type AdditionalReestabInfo (SEQUENCE).
type AdditionalReestabInfo struct {
	CellIdentity  CellIdentity  `asn1:"tag:0,context,implicit"`
	KeyENodeBStar KeyENodeBStar `asn1:"tag:1,context,implicit"`
	ShortMACI     ShortMACI     `asn1:"tag:2,context,implicit"`
}

// KeyENodeBStar represents the ASN.1 type Key-eNodeB-Star (BIT_STRING).
type KeyENodeBStar = runtime.BitString

// RRMConfig represents the ASN.1 type RRM-Config (SEQUENCE).
type RRMConfig struct {
	UeInactiveTime                   *int64                      `asn1:"tag:0,context,implicit,optional" json:"UeInactiveTime,omitempty"`
	CandidateCellInfoListR10         CandidateCellInfoListR10    `asn1:"tag:1,context,implicit,optional" json:"CandidateCellInfoListR10,omitempty"`
	CandidateCellInfoListR10Indef_   bool                        `asn1:"-" json:"-"`
	CandidateCellInfoListNRR15       MeasResultServFreqListNRR15 `asn1:"tag:2,context,implicit,optional" json:"CandidateCellInfoListNRR15,omitempty"`
	CandidateCellInfoListNRR15Indef_ bool                        `asn1:"-" json:"-"`
	ExtCount_                        int64                       `asn1:"-" json:"-"`
	ExtPresent_                      []bool                      `asn1:"-" json:"-"`
	ExtData_                         [][]byte                    `asn1:"-" json:"-"`
}

// CandidateCellInfoListR10 represents the ASN.1 type CandidateCellInfoList-r10 (SEQUENCE_OF).
type CandidateCellInfoListR10 = []CandidateCellInfoR10

// CandidateCellInfoR10 represents the ASN.1 type CandidateCellInfo-r10 (SEQUENCE).
type CandidateCellInfoR10 struct {
	PhysCellIdR10      PhysCellId           `asn1:"tag:0,context,implicit"`
	DlCarrierFreqR10   ARFCNValueEUTRA      `asn1:"tag:1,context,implicit"`
	RsrpResultR10      *RSRPRange           `asn1:"tag:2,context,implicit,optional" json:"RsrpResultR10,omitempty"`
	RsrqResultR10      *RSRQRange           `asn1:"tag:3,context,implicit,optional" json:"RsrqResultR10,omitempty"`
	DlCarrierFreqV1090 *ARFCNValueEUTRAV9e0 `asn1:"tag:4,context,implicit,optional" json:"DlCarrierFreqV1090,omitempty"`
	RsrqResultV1250    *RSRQRangeV1250      `asn1:"tag:5,context,implicit,optional" json:"RsrqResultV1250,omitempty"`
	RsSinrResultR13    *RSSINRRangeR13      `asn1:"tag:6,context,implicit,optional" json:"RsSinrResultR13,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// HandoverCommandCriticalExtensions choice constants.
const (
	HandoverCommandCriticalExtensionsChoiceC1                       = 1
	HandoverCommandCriticalExtensionsChoiceCriticalExtensionsFuture = 2
)

// HandoverCommandCriticalExtensions represents the ASN.1 CHOICE type HandoverCommand-criticalExtensions.
type HandoverCommandCriticalExtensions struct {
	Choice                   int
	C1                       *HandoverCommandCriticalExtensionsC1                       `json:"C1,omitempty"`
	CriticalExtensionsFuture *HandoverCommandCriticalExtensionsCriticalExtensionsFuture `json:"CriticalExtensionsFuture,omitempty"`
}

// NewHandoverCommandCriticalExtensionsC1 creates a HandoverCommandCriticalExtensions with the c1 alternative.
func NewHandoverCommandCriticalExtensionsC1(v HandoverCommandCriticalExtensionsC1) HandoverCommandCriticalExtensions {
	return HandoverCommandCriticalExtensions{
		Choice: HandoverCommandCriticalExtensionsChoiceC1,
		C1:     &v,
	}
}

// NewHandoverCommandCriticalExtensionsCriticalExtensionsFuture creates a HandoverCommandCriticalExtensions with the criticalExtensionsFuture alternative.
func NewHandoverCommandCriticalExtensionsCriticalExtensionsFuture(v HandoverCommandCriticalExtensionsCriticalExtensionsFuture) HandoverCommandCriticalExtensions {
	return HandoverCommandCriticalExtensions{
		Choice:                   HandoverCommandCriticalExtensionsChoiceCriticalExtensionsFuture,
		CriticalExtensionsFuture: &v,
	}
}

// HandoverCommandCriticalExtensionsC1 choice constants.
const (
	HandoverCommandCriticalExtensionsC1ChoiceHandoverCommandR8 = 1
	HandoverCommandCriticalExtensionsC1ChoiceSpare7            = 2
	HandoverCommandCriticalExtensionsC1ChoiceSpare6            = 3
	HandoverCommandCriticalExtensionsC1ChoiceSpare5            = 4
	HandoverCommandCriticalExtensionsC1ChoiceSpare4            = 5
	HandoverCommandCriticalExtensionsC1ChoiceSpare3            = 6
	HandoverCommandCriticalExtensionsC1ChoiceSpare2            = 7
	HandoverCommandCriticalExtensionsC1ChoiceSpare1            = 8
)

// HandoverCommandCriticalExtensionsC1 represents the ASN.1 CHOICE type HandoverCommand-criticalExtensions-c1.
type HandoverCommandCriticalExtensionsC1 struct {
	Choice            int
	HandoverCommandR8 *HandoverCommandR8IEs `json:"HandoverCommandR8,omitempty"`
	Spare7            *struct{}             `json:"Spare7,omitempty"`
	Spare6            *struct{}             `json:"Spare6,omitempty"`
	Spare5            *struct{}             `json:"Spare5,omitempty"`
	Spare4            *struct{}             `json:"Spare4,omitempty"`
	Spare3            *struct{}             `json:"Spare3,omitempty"`
	Spare2            *struct{}             `json:"Spare2,omitempty"`
	Spare1            *struct{}             `json:"Spare1,omitempty"`
}

// NewHandoverCommandCriticalExtensionsC1HandoverCommandR8 creates a HandoverCommandCriticalExtensionsC1 with the handoverCommand-r8 alternative.
func NewHandoverCommandCriticalExtensionsC1HandoverCommandR8(v HandoverCommandR8IEs) HandoverCommandCriticalExtensionsC1 {
	return HandoverCommandCriticalExtensionsC1{
		Choice:            HandoverCommandCriticalExtensionsC1ChoiceHandoverCommandR8,
		HandoverCommandR8: &v,
	}
}

// NewHandoverCommandCriticalExtensionsC1Spare7 creates a HandoverCommandCriticalExtensionsC1 with the spare7 alternative.
func NewHandoverCommandCriticalExtensionsC1Spare7(v struct{}) HandoverCommandCriticalExtensionsC1 {
	return HandoverCommandCriticalExtensionsC1{
		Choice: HandoverCommandCriticalExtensionsC1ChoiceSpare7,
		Spare7: &v,
	}
}

// NewHandoverCommandCriticalExtensionsC1Spare6 creates a HandoverCommandCriticalExtensionsC1 with the spare6 alternative.
func NewHandoverCommandCriticalExtensionsC1Spare6(v struct{}) HandoverCommandCriticalExtensionsC1 {
	return HandoverCommandCriticalExtensionsC1{
		Choice: HandoverCommandCriticalExtensionsC1ChoiceSpare6,
		Spare6: &v,
	}
}

// NewHandoverCommandCriticalExtensionsC1Spare5 creates a HandoverCommandCriticalExtensionsC1 with the spare5 alternative.
func NewHandoverCommandCriticalExtensionsC1Spare5(v struct{}) HandoverCommandCriticalExtensionsC1 {
	return HandoverCommandCriticalExtensionsC1{
		Choice: HandoverCommandCriticalExtensionsC1ChoiceSpare5,
		Spare5: &v,
	}
}

// NewHandoverCommandCriticalExtensionsC1Spare4 creates a HandoverCommandCriticalExtensionsC1 with the spare4 alternative.
func NewHandoverCommandCriticalExtensionsC1Spare4(v struct{}) HandoverCommandCriticalExtensionsC1 {
	return HandoverCommandCriticalExtensionsC1{
		Choice: HandoverCommandCriticalExtensionsC1ChoiceSpare4,
		Spare4: &v,
	}
}

// NewHandoverCommandCriticalExtensionsC1Spare3 creates a HandoverCommandCriticalExtensionsC1 with the spare3 alternative.
func NewHandoverCommandCriticalExtensionsC1Spare3(v struct{}) HandoverCommandCriticalExtensionsC1 {
	return HandoverCommandCriticalExtensionsC1{
		Choice: HandoverCommandCriticalExtensionsC1ChoiceSpare3,
		Spare3: &v,
	}
}

// NewHandoverCommandCriticalExtensionsC1Spare2 creates a HandoverCommandCriticalExtensionsC1 with the spare2 alternative.
func NewHandoverCommandCriticalExtensionsC1Spare2(v struct{}) HandoverCommandCriticalExtensionsC1 {
	return HandoverCommandCriticalExtensionsC1{
		Choice: HandoverCommandCriticalExtensionsC1ChoiceSpare2,
		Spare2: &v,
	}
}

// NewHandoverCommandCriticalExtensionsC1Spare1 creates a HandoverCommandCriticalExtensionsC1 with the spare1 alternative.
func NewHandoverCommandCriticalExtensionsC1Spare1(v struct{}) HandoverCommandCriticalExtensionsC1 {
	return HandoverCommandCriticalExtensionsC1{
		Choice: HandoverCommandCriticalExtensionsC1ChoiceSpare1,
		Spare1: &v,
	}
}

// HandoverCommandCriticalExtensionsCriticalExtensionsFuture represents the ASN.1 type HandoverCommand-criticalExtensions-criticalExtensionsFuture (SEQUENCE).
type HandoverCommandCriticalExtensionsCriticalExtensionsFuture struct {
}

// HandoverCommandR8IEsNonCriticalExtension represents the ASN.1 type HandoverCommand-r8-IEs-nonCriticalExtension (SEQUENCE).
type HandoverCommandR8IEsNonCriticalExtension struct {
}

// HandoverPreparationInformationCriticalExtensions choice constants.
const (
	HandoverPreparationInformationCriticalExtensionsChoiceC1                       = 1
	HandoverPreparationInformationCriticalExtensionsChoiceCriticalExtensionsFuture = 2
)

// HandoverPreparationInformationCriticalExtensions represents the ASN.1 CHOICE type HandoverPreparationInformation-criticalExtensions.
type HandoverPreparationInformationCriticalExtensions struct {
	Choice                   int
	C1                       *HandoverPreparationInformationCriticalExtensionsC1                       `json:"C1,omitempty"`
	CriticalExtensionsFuture *HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture `json:"CriticalExtensionsFuture,omitempty"`
}

// NewHandoverPreparationInformationCriticalExtensionsC1 creates a HandoverPreparationInformationCriticalExtensions with the c1 alternative.
func NewHandoverPreparationInformationCriticalExtensionsC1(v HandoverPreparationInformationCriticalExtensionsC1) HandoverPreparationInformationCriticalExtensions {
	return HandoverPreparationInformationCriticalExtensions{
		Choice: HandoverPreparationInformationCriticalExtensionsChoiceC1,
		C1:     &v,
	}
}

// NewHandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture creates a HandoverPreparationInformationCriticalExtensions with the criticalExtensionsFuture alternative.
func NewHandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture(v HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture) HandoverPreparationInformationCriticalExtensions {
	return HandoverPreparationInformationCriticalExtensions{
		Choice:                   HandoverPreparationInformationCriticalExtensionsChoiceCriticalExtensionsFuture,
		CriticalExtensionsFuture: &v,
	}
}

// HandoverPreparationInformationCriticalExtensionsC1 choice constants.
const (
	HandoverPreparationInformationCriticalExtensionsC1ChoiceHandoverPreparationInformationR8 = 1
	HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare7                           = 2
	HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare6                           = 3
	HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare5                           = 4
	HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare4                           = 5
	HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare3                           = 6
	HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare2                           = 7
	HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare1                           = 8
)

// HandoverPreparationInformationCriticalExtensionsC1 represents the ASN.1 CHOICE type HandoverPreparationInformation-criticalExtensions-c1.
type HandoverPreparationInformationCriticalExtensionsC1 struct {
	Choice                           int
	HandoverPreparationInformationR8 *HandoverPreparationInformationR8IEs `json:"HandoverPreparationInformationR8,omitempty"`
	Spare7                           *struct{}                            `json:"Spare7,omitempty"`
	Spare6                           *struct{}                            `json:"Spare6,omitempty"`
	Spare5                           *struct{}                            `json:"Spare5,omitempty"`
	Spare4                           *struct{}                            `json:"Spare4,omitempty"`
	Spare3                           *struct{}                            `json:"Spare3,omitempty"`
	Spare2                           *struct{}                            `json:"Spare2,omitempty"`
	Spare1                           *struct{}                            `json:"Spare1,omitempty"`
}

// NewHandoverPreparationInformationCriticalExtensionsC1HandoverPreparationInformationR8 creates a HandoverPreparationInformationCriticalExtensionsC1 with the handoverPreparationInformation-r8 alternative.
func NewHandoverPreparationInformationCriticalExtensionsC1HandoverPreparationInformationR8(v HandoverPreparationInformationR8IEs) HandoverPreparationInformationCriticalExtensionsC1 {
	return HandoverPreparationInformationCriticalExtensionsC1{
		Choice:                           HandoverPreparationInformationCriticalExtensionsC1ChoiceHandoverPreparationInformationR8,
		HandoverPreparationInformationR8: &v,
	}
}

// NewHandoverPreparationInformationCriticalExtensionsC1Spare7 creates a HandoverPreparationInformationCriticalExtensionsC1 with the spare7 alternative.
func NewHandoverPreparationInformationCriticalExtensionsC1Spare7(v struct{}) HandoverPreparationInformationCriticalExtensionsC1 {
	return HandoverPreparationInformationCriticalExtensionsC1{
		Choice: HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare7,
		Spare7: &v,
	}
}

// NewHandoverPreparationInformationCriticalExtensionsC1Spare6 creates a HandoverPreparationInformationCriticalExtensionsC1 with the spare6 alternative.
func NewHandoverPreparationInformationCriticalExtensionsC1Spare6(v struct{}) HandoverPreparationInformationCriticalExtensionsC1 {
	return HandoverPreparationInformationCriticalExtensionsC1{
		Choice: HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare6,
		Spare6: &v,
	}
}

// NewHandoverPreparationInformationCriticalExtensionsC1Spare5 creates a HandoverPreparationInformationCriticalExtensionsC1 with the spare5 alternative.
func NewHandoverPreparationInformationCriticalExtensionsC1Spare5(v struct{}) HandoverPreparationInformationCriticalExtensionsC1 {
	return HandoverPreparationInformationCriticalExtensionsC1{
		Choice: HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare5,
		Spare5: &v,
	}
}

// NewHandoverPreparationInformationCriticalExtensionsC1Spare4 creates a HandoverPreparationInformationCriticalExtensionsC1 with the spare4 alternative.
func NewHandoverPreparationInformationCriticalExtensionsC1Spare4(v struct{}) HandoverPreparationInformationCriticalExtensionsC1 {
	return HandoverPreparationInformationCriticalExtensionsC1{
		Choice: HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare4,
		Spare4: &v,
	}
}

// NewHandoverPreparationInformationCriticalExtensionsC1Spare3 creates a HandoverPreparationInformationCriticalExtensionsC1 with the spare3 alternative.
func NewHandoverPreparationInformationCriticalExtensionsC1Spare3(v struct{}) HandoverPreparationInformationCriticalExtensionsC1 {
	return HandoverPreparationInformationCriticalExtensionsC1{
		Choice: HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare3,
		Spare3: &v,
	}
}

// NewHandoverPreparationInformationCriticalExtensionsC1Spare2 creates a HandoverPreparationInformationCriticalExtensionsC1 with the spare2 alternative.
func NewHandoverPreparationInformationCriticalExtensionsC1Spare2(v struct{}) HandoverPreparationInformationCriticalExtensionsC1 {
	return HandoverPreparationInformationCriticalExtensionsC1{
		Choice: HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare2,
		Spare2: &v,
	}
}

// NewHandoverPreparationInformationCriticalExtensionsC1Spare1 creates a HandoverPreparationInformationCriticalExtensionsC1 with the spare1 alternative.
func NewHandoverPreparationInformationCriticalExtensionsC1Spare1(v struct{}) HandoverPreparationInformationCriticalExtensionsC1 {
	return HandoverPreparationInformationCriticalExtensionsC1{
		Choice: HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare1,
		Spare1: &v,
	}
}

// HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture represents the ASN.1 type HandoverPreparationInformation-criticalExtensions-criticalExtensionsFuture (SEQUENCE).
type HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture struct {
}

// HandoverPreparationInformationV13c0IEsNonCriticalExtension represents the ASN.1 type HandoverPreparationInformation-v13c0-IEs-nonCriticalExtension (SEQUENCE).
type HandoverPreparationInformationV13c0IEsNonCriticalExtension struct {
}

// HandoverPreparationInformationV1700IEsNonCriticalExtension represents the ASN.1 type HandoverPreparationInformation-v1700-IEs-nonCriticalExtension (SEQUENCE).
type HandoverPreparationInformationV1700IEsNonCriticalExtension struct {
}

// SCGConfigR12CriticalExtensions choice constants.
const (
	SCGConfigR12CriticalExtensionsChoiceC1                       = 1
	SCGConfigR12CriticalExtensionsChoiceCriticalExtensionsFuture = 2
)

// SCGConfigR12CriticalExtensions represents the ASN.1 CHOICE type SCG-Config-r12-criticalExtensions.
type SCGConfigR12CriticalExtensions struct {
	Choice                   int
	C1                       *SCGConfigR12CriticalExtensionsC1                       `json:"C1,omitempty"`
	CriticalExtensionsFuture *SCGConfigR12CriticalExtensionsCriticalExtensionsFuture `json:"CriticalExtensionsFuture,omitempty"`
}

// NewSCGConfigR12CriticalExtensionsC1 creates a SCGConfigR12CriticalExtensions with the c1 alternative.
func NewSCGConfigR12CriticalExtensionsC1(v SCGConfigR12CriticalExtensionsC1) SCGConfigR12CriticalExtensions {
	return SCGConfigR12CriticalExtensions{
		Choice: SCGConfigR12CriticalExtensionsChoiceC1,
		C1:     &v,
	}
}

// NewSCGConfigR12CriticalExtensionsCriticalExtensionsFuture creates a SCGConfigR12CriticalExtensions with the criticalExtensionsFuture alternative.
func NewSCGConfigR12CriticalExtensionsCriticalExtensionsFuture(v SCGConfigR12CriticalExtensionsCriticalExtensionsFuture) SCGConfigR12CriticalExtensions {
	return SCGConfigR12CriticalExtensions{
		Choice:                   SCGConfigR12CriticalExtensionsChoiceCriticalExtensionsFuture,
		CriticalExtensionsFuture: &v,
	}
}

// SCGConfigR12CriticalExtensionsC1 choice constants.
const (
	SCGConfigR12CriticalExtensionsC1ChoiceScgConfigR12 = 1
	SCGConfigR12CriticalExtensionsC1ChoiceSpare7       = 2
	SCGConfigR12CriticalExtensionsC1ChoiceSpare6       = 3
	SCGConfigR12CriticalExtensionsC1ChoiceSpare5       = 4
	SCGConfigR12CriticalExtensionsC1ChoiceSpare4       = 5
	SCGConfigR12CriticalExtensionsC1ChoiceSpare3       = 6
	SCGConfigR12CriticalExtensionsC1ChoiceSpare2       = 7
	SCGConfigR12CriticalExtensionsC1ChoiceSpare1       = 8
)

// SCGConfigR12CriticalExtensionsC1 represents the ASN.1 CHOICE type SCG-Config-r12-criticalExtensions-c1.
type SCGConfigR12CriticalExtensionsC1 struct {
	Choice       int
	ScgConfigR12 *SCGConfigR12IEs `json:"ScgConfigR12,omitempty"`
	Spare7       *struct{}        `json:"Spare7,omitempty"`
	Spare6       *struct{}        `json:"Spare6,omitempty"`
	Spare5       *struct{}        `json:"Spare5,omitempty"`
	Spare4       *struct{}        `json:"Spare4,omitempty"`
	Spare3       *struct{}        `json:"Spare3,omitempty"`
	Spare2       *struct{}        `json:"Spare2,omitempty"`
	Spare1       *struct{}        `json:"Spare1,omitempty"`
}

// NewSCGConfigR12CriticalExtensionsC1ScgConfigR12 creates a SCGConfigR12CriticalExtensionsC1 with the scg-Config-r12 alternative.
func NewSCGConfigR12CriticalExtensionsC1ScgConfigR12(v SCGConfigR12IEs) SCGConfigR12CriticalExtensionsC1 {
	return SCGConfigR12CriticalExtensionsC1{
		Choice:       SCGConfigR12CriticalExtensionsC1ChoiceScgConfigR12,
		ScgConfigR12: &v,
	}
}

// NewSCGConfigR12CriticalExtensionsC1Spare7 creates a SCGConfigR12CriticalExtensionsC1 with the spare7 alternative.
func NewSCGConfigR12CriticalExtensionsC1Spare7(v struct{}) SCGConfigR12CriticalExtensionsC1 {
	return SCGConfigR12CriticalExtensionsC1{
		Choice: SCGConfigR12CriticalExtensionsC1ChoiceSpare7,
		Spare7: &v,
	}
}

// NewSCGConfigR12CriticalExtensionsC1Spare6 creates a SCGConfigR12CriticalExtensionsC1 with the spare6 alternative.
func NewSCGConfigR12CriticalExtensionsC1Spare6(v struct{}) SCGConfigR12CriticalExtensionsC1 {
	return SCGConfigR12CriticalExtensionsC1{
		Choice: SCGConfigR12CriticalExtensionsC1ChoiceSpare6,
		Spare6: &v,
	}
}

// NewSCGConfigR12CriticalExtensionsC1Spare5 creates a SCGConfigR12CriticalExtensionsC1 with the spare5 alternative.
func NewSCGConfigR12CriticalExtensionsC1Spare5(v struct{}) SCGConfigR12CriticalExtensionsC1 {
	return SCGConfigR12CriticalExtensionsC1{
		Choice: SCGConfigR12CriticalExtensionsC1ChoiceSpare5,
		Spare5: &v,
	}
}

// NewSCGConfigR12CriticalExtensionsC1Spare4 creates a SCGConfigR12CriticalExtensionsC1 with the spare4 alternative.
func NewSCGConfigR12CriticalExtensionsC1Spare4(v struct{}) SCGConfigR12CriticalExtensionsC1 {
	return SCGConfigR12CriticalExtensionsC1{
		Choice: SCGConfigR12CriticalExtensionsC1ChoiceSpare4,
		Spare4: &v,
	}
}

// NewSCGConfigR12CriticalExtensionsC1Spare3 creates a SCGConfigR12CriticalExtensionsC1 with the spare3 alternative.
func NewSCGConfigR12CriticalExtensionsC1Spare3(v struct{}) SCGConfigR12CriticalExtensionsC1 {
	return SCGConfigR12CriticalExtensionsC1{
		Choice: SCGConfigR12CriticalExtensionsC1ChoiceSpare3,
		Spare3: &v,
	}
}

// NewSCGConfigR12CriticalExtensionsC1Spare2 creates a SCGConfigR12CriticalExtensionsC1 with the spare2 alternative.
func NewSCGConfigR12CriticalExtensionsC1Spare2(v struct{}) SCGConfigR12CriticalExtensionsC1 {
	return SCGConfigR12CriticalExtensionsC1{
		Choice: SCGConfigR12CriticalExtensionsC1ChoiceSpare2,
		Spare2: &v,
	}
}

// NewSCGConfigR12CriticalExtensionsC1Spare1 creates a SCGConfigR12CriticalExtensionsC1 with the spare1 alternative.
func NewSCGConfigR12CriticalExtensionsC1Spare1(v struct{}) SCGConfigR12CriticalExtensionsC1 {
	return SCGConfigR12CriticalExtensionsC1{
		Choice: SCGConfigR12CriticalExtensionsC1ChoiceSpare1,
		Spare1: &v,
	}
}

// SCGConfigR12CriticalExtensionsCriticalExtensionsFuture represents the ASN.1 type SCG-Config-r12-criticalExtensions-criticalExtensionsFuture (SEQUENCE).
type SCGConfigR12CriticalExtensionsCriticalExtensionsFuture struct {
}

// SCGConfigV12i0bIEsNonCriticalExtension represents the ASN.1 type SCG-Config-v12i0b-IEs-nonCriticalExtension (SEQUENCE).
type SCGConfigV12i0bIEsNonCriticalExtension struct {
}

// SCGConfigV13c0IEsNonCriticalExtension represents the ASN.1 type SCG-Config-v13c0-IEs-nonCriticalExtension (SEQUENCE).
type SCGConfigV13c0IEsNonCriticalExtension struct {
}

// SCGConfigInfoR12CriticalExtensions choice constants.
const (
	SCGConfigInfoR12CriticalExtensionsChoiceC1                       = 1
	SCGConfigInfoR12CriticalExtensionsChoiceCriticalExtensionsFuture = 2
)

// SCGConfigInfoR12CriticalExtensions represents the ASN.1 CHOICE type SCG-ConfigInfo-r12-criticalExtensions.
type SCGConfigInfoR12CriticalExtensions struct {
	Choice                   int
	C1                       *SCGConfigInfoR12CriticalExtensionsC1                       `json:"C1,omitempty"`
	CriticalExtensionsFuture *SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture `json:"CriticalExtensionsFuture,omitempty"`
}

// NewSCGConfigInfoR12CriticalExtensionsC1 creates a SCGConfigInfoR12CriticalExtensions with the c1 alternative.
func NewSCGConfigInfoR12CriticalExtensionsC1(v SCGConfigInfoR12CriticalExtensionsC1) SCGConfigInfoR12CriticalExtensions {
	return SCGConfigInfoR12CriticalExtensions{
		Choice: SCGConfigInfoR12CriticalExtensionsChoiceC1,
		C1:     &v,
	}
}

// NewSCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture creates a SCGConfigInfoR12CriticalExtensions with the criticalExtensionsFuture alternative.
func NewSCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture(v SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture) SCGConfigInfoR12CriticalExtensions {
	return SCGConfigInfoR12CriticalExtensions{
		Choice:                   SCGConfigInfoR12CriticalExtensionsChoiceCriticalExtensionsFuture,
		CriticalExtensionsFuture: &v,
	}
}

// SCGConfigInfoR12CriticalExtensionsC1 choice constants.
const (
	SCGConfigInfoR12CriticalExtensionsC1ChoiceScgConfigInfoR12 = 1
	SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare7           = 2
	SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare6           = 3
	SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare5           = 4
	SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare4           = 5
	SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare3           = 6
	SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare2           = 7
	SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare1           = 8
)

// SCGConfigInfoR12CriticalExtensionsC1 represents the ASN.1 CHOICE type SCG-ConfigInfo-r12-criticalExtensions-c1.
type SCGConfigInfoR12CriticalExtensionsC1 struct {
	Choice           int
	ScgConfigInfoR12 *SCGConfigInfoR12IEs `json:"ScgConfigInfoR12,omitempty"`
	Spare7           *struct{}            `json:"Spare7,omitempty"`
	Spare6           *struct{}            `json:"Spare6,omitempty"`
	Spare5           *struct{}            `json:"Spare5,omitempty"`
	Spare4           *struct{}            `json:"Spare4,omitempty"`
	Spare3           *struct{}            `json:"Spare3,omitempty"`
	Spare2           *struct{}            `json:"Spare2,omitempty"`
	Spare1           *struct{}            `json:"Spare1,omitempty"`
}

// NewSCGConfigInfoR12CriticalExtensionsC1ScgConfigInfoR12 creates a SCGConfigInfoR12CriticalExtensionsC1 with the scg-ConfigInfo-r12 alternative.
func NewSCGConfigInfoR12CriticalExtensionsC1ScgConfigInfoR12(v SCGConfigInfoR12IEs) SCGConfigInfoR12CriticalExtensionsC1 {
	return SCGConfigInfoR12CriticalExtensionsC1{
		Choice:           SCGConfigInfoR12CriticalExtensionsC1ChoiceScgConfigInfoR12,
		ScgConfigInfoR12: &v,
	}
}

// NewSCGConfigInfoR12CriticalExtensionsC1Spare7 creates a SCGConfigInfoR12CriticalExtensionsC1 with the spare7 alternative.
func NewSCGConfigInfoR12CriticalExtensionsC1Spare7(v struct{}) SCGConfigInfoR12CriticalExtensionsC1 {
	return SCGConfigInfoR12CriticalExtensionsC1{
		Choice: SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare7,
		Spare7: &v,
	}
}

// NewSCGConfigInfoR12CriticalExtensionsC1Spare6 creates a SCGConfigInfoR12CriticalExtensionsC1 with the spare6 alternative.
func NewSCGConfigInfoR12CriticalExtensionsC1Spare6(v struct{}) SCGConfigInfoR12CriticalExtensionsC1 {
	return SCGConfigInfoR12CriticalExtensionsC1{
		Choice: SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare6,
		Spare6: &v,
	}
}

// NewSCGConfigInfoR12CriticalExtensionsC1Spare5 creates a SCGConfigInfoR12CriticalExtensionsC1 with the spare5 alternative.
func NewSCGConfigInfoR12CriticalExtensionsC1Spare5(v struct{}) SCGConfigInfoR12CriticalExtensionsC1 {
	return SCGConfigInfoR12CriticalExtensionsC1{
		Choice: SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare5,
		Spare5: &v,
	}
}

// NewSCGConfigInfoR12CriticalExtensionsC1Spare4 creates a SCGConfigInfoR12CriticalExtensionsC1 with the spare4 alternative.
func NewSCGConfigInfoR12CriticalExtensionsC1Spare4(v struct{}) SCGConfigInfoR12CriticalExtensionsC1 {
	return SCGConfigInfoR12CriticalExtensionsC1{
		Choice: SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare4,
		Spare4: &v,
	}
}

// NewSCGConfigInfoR12CriticalExtensionsC1Spare3 creates a SCGConfigInfoR12CriticalExtensionsC1 with the spare3 alternative.
func NewSCGConfigInfoR12CriticalExtensionsC1Spare3(v struct{}) SCGConfigInfoR12CriticalExtensionsC1 {
	return SCGConfigInfoR12CriticalExtensionsC1{
		Choice: SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare3,
		Spare3: &v,
	}
}

// NewSCGConfigInfoR12CriticalExtensionsC1Spare2 creates a SCGConfigInfoR12CriticalExtensionsC1 with the spare2 alternative.
func NewSCGConfigInfoR12CriticalExtensionsC1Spare2(v struct{}) SCGConfigInfoR12CriticalExtensionsC1 {
	return SCGConfigInfoR12CriticalExtensionsC1{
		Choice: SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare2,
		Spare2: &v,
	}
}

// NewSCGConfigInfoR12CriticalExtensionsC1Spare1 creates a SCGConfigInfoR12CriticalExtensionsC1 with the spare1 alternative.
func NewSCGConfigInfoR12CriticalExtensionsC1Spare1(v struct{}) SCGConfigInfoR12CriticalExtensionsC1 {
	return SCGConfigInfoR12CriticalExtensionsC1{
		Choice: SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare1,
		Spare1: &v,
	}
}

// SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture represents the ASN.1 type SCG-ConfigInfo-r12-criticalExtensions-criticalExtensionsFuture (SEQUENCE).
type SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture struct {
}

// SCGConfigInfoV1530IEsNonCriticalExtension represents the ASN.1 type SCG-ConfigInfo-v1530-IEs-nonCriticalExtension (SEQUENCE).
type SCGConfigInfoV1530IEsNonCriticalExtension struct {
}

// CellToAddModR12CellIdentificationR12 represents the ASN.1 type Cell-ToAddMod-r12-cellIdentification-r12 (SEQUENCE).
type CellToAddModR12CellIdentificationR12 struct {
	PhysCellIdR12    PhysCellId        `asn1:"tag:0,context,implicit"`
	DlCarrierFreqR12 ARFCNValueEUTRAR9 `asn1:"tag:1,context,implicit"`
}

// CellToAddModR12MeasResultCellToAddR12 represents the ASN.1 type Cell-ToAddMod-r12-measResultCellToAdd-r12 (SEQUENCE).
type CellToAddModR12MeasResultCellToAddR12 struct {
	RsrpResultR12 RSRPRange `asn1:"tag:0,context,implicit"`
	RsrqResultR12 RSRQRange `asn1:"tag:1,context,implicit"`
}

// CellToAddModR12MeasResultCellToAddV1310 represents the ASN.1 type Cell-ToAddMod-r12-measResultCellToAdd-v1310 (SEQUENCE).
type CellToAddModR12MeasResultCellToAddV1310 struct {
	RsSinrResultR13 RSSINRRangeR13 `asn1:"tag:0,context,implicit"`
}

// MeasResultServCellSCGR12MeasResultSCellR12 represents the ASN.1 type MeasResultServCellSCG-r12-measResultSCell-r12 (SEQUENCE).
type MeasResultServCellSCGR12MeasResultSCellR12 struct {
	RsrpResultSCellR12 RSRPRange `asn1:"tag:0,context,implicit"`
	RsrqResultSCellR12 RSRQRange `asn1:"tag:1,context,implicit"`
}

// MeasResultServCellSCGR12MeasResultSCellV1310 represents the ASN.1 type MeasResultServCellSCG-r12-measResultSCell-v1310 (SEQUENCE).
type MeasResultServCellSCGR12MeasResultSCellV1310 struct {
	RsSinrResultSCellR13 RSSINRRangeR13 `asn1:"tag:0,context,implicit"`
}

// UEPagingCoverageInformationCriticalExtensions choice constants.
const (
	UEPagingCoverageInformationCriticalExtensionsChoiceC1                       = 1
	UEPagingCoverageInformationCriticalExtensionsChoiceCriticalExtensionsFuture = 2
)

// UEPagingCoverageInformationCriticalExtensions represents the ASN.1 CHOICE type UEPagingCoverageInformation-criticalExtensions.
type UEPagingCoverageInformationCriticalExtensions struct {
	Choice                   int
	C1                       *UEPagingCoverageInformationCriticalExtensionsC1                       `json:"C1,omitempty"`
	CriticalExtensionsFuture *UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture `json:"CriticalExtensionsFuture,omitempty"`
}

// NewUEPagingCoverageInformationCriticalExtensionsC1 creates a UEPagingCoverageInformationCriticalExtensions with the c1 alternative.
func NewUEPagingCoverageInformationCriticalExtensionsC1(v UEPagingCoverageInformationCriticalExtensionsC1) UEPagingCoverageInformationCriticalExtensions {
	return UEPagingCoverageInformationCriticalExtensions{
		Choice: UEPagingCoverageInformationCriticalExtensionsChoiceC1,
		C1:     &v,
	}
}

// NewUEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture creates a UEPagingCoverageInformationCriticalExtensions with the criticalExtensionsFuture alternative.
func NewUEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture(v UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture) UEPagingCoverageInformationCriticalExtensions {
	return UEPagingCoverageInformationCriticalExtensions{
		Choice:                   UEPagingCoverageInformationCriticalExtensionsChoiceCriticalExtensionsFuture,
		CriticalExtensionsFuture: &v,
	}
}

// UEPagingCoverageInformationCriticalExtensionsC1 choice constants.
const (
	UEPagingCoverageInformationCriticalExtensionsC1ChoiceUePagingCoverageInformationR13 = 1
	UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare7                         = 2
	UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare6                         = 3
	UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare5                         = 4
	UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare4                         = 5
	UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare3                         = 6
	UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare2                         = 7
	UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare1                         = 8
)

// UEPagingCoverageInformationCriticalExtensionsC1 represents the ASN.1 CHOICE type UEPagingCoverageInformation-criticalExtensions-c1.
type UEPagingCoverageInformationCriticalExtensionsC1 struct {
	Choice                         int
	UePagingCoverageInformationR13 *UEPagingCoverageInformationR13IEs `json:"UePagingCoverageInformationR13,omitempty"`
	Spare7                         *struct{}                          `json:"Spare7,omitempty"`
	Spare6                         *struct{}                          `json:"Spare6,omitempty"`
	Spare5                         *struct{}                          `json:"Spare5,omitempty"`
	Spare4                         *struct{}                          `json:"Spare4,omitempty"`
	Spare3                         *struct{}                          `json:"Spare3,omitempty"`
	Spare2                         *struct{}                          `json:"Spare2,omitempty"`
	Spare1                         *struct{}                          `json:"Spare1,omitempty"`
}

// NewUEPagingCoverageInformationCriticalExtensionsC1UePagingCoverageInformationR13 creates a UEPagingCoverageInformationCriticalExtensionsC1 with the uePagingCoverageInformation-r13 alternative.
func NewUEPagingCoverageInformationCriticalExtensionsC1UePagingCoverageInformationR13(v UEPagingCoverageInformationR13IEs) UEPagingCoverageInformationCriticalExtensionsC1 {
	return UEPagingCoverageInformationCriticalExtensionsC1{
		Choice:                         UEPagingCoverageInformationCriticalExtensionsC1ChoiceUePagingCoverageInformationR13,
		UePagingCoverageInformationR13: &v,
	}
}

// NewUEPagingCoverageInformationCriticalExtensionsC1Spare7 creates a UEPagingCoverageInformationCriticalExtensionsC1 with the spare7 alternative.
func NewUEPagingCoverageInformationCriticalExtensionsC1Spare7(v struct{}) UEPagingCoverageInformationCriticalExtensionsC1 {
	return UEPagingCoverageInformationCriticalExtensionsC1{
		Choice: UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare7,
		Spare7: &v,
	}
}

// NewUEPagingCoverageInformationCriticalExtensionsC1Spare6 creates a UEPagingCoverageInformationCriticalExtensionsC1 with the spare6 alternative.
func NewUEPagingCoverageInformationCriticalExtensionsC1Spare6(v struct{}) UEPagingCoverageInformationCriticalExtensionsC1 {
	return UEPagingCoverageInformationCriticalExtensionsC1{
		Choice: UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare6,
		Spare6: &v,
	}
}

// NewUEPagingCoverageInformationCriticalExtensionsC1Spare5 creates a UEPagingCoverageInformationCriticalExtensionsC1 with the spare5 alternative.
func NewUEPagingCoverageInformationCriticalExtensionsC1Spare5(v struct{}) UEPagingCoverageInformationCriticalExtensionsC1 {
	return UEPagingCoverageInformationCriticalExtensionsC1{
		Choice: UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare5,
		Spare5: &v,
	}
}

// NewUEPagingCoverageInformationCriticalExtensionsC1Spare4 creates a UEPagingCoverageInformationCriticalExtensionsC1 with the spare4 alternative.
func NewUEPagingCoverageInformationCriticalExtensionsC1Spare4(v struct{}) UEPagingCoverageInformationCriticalExtensionsC1 {
	return UEPagingCoverageInformationCriticalExtensionsC1{
		Choice: UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare4,
		Spare4: &v,
	}
}

// NewUEPagingCoverageInformationCriticalExtensionsC1Spare3 creates a UEPagingCoverageInformationCriticalExtensionsC1 with the spare3 alternative.
func NewUEPagingCoverageInformationCriticalExtensionsC1Spare3(v struct{}) UEPagingCoverageInformationCriticalExtensionsC1 {
	return UEPagingCoverageInformationCriticalExtensionsC1{
		Choice: UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare3,
		Spare3: &v,
	}
}

// NewUEPagingCoverageInformationCriticalExtensionsC1Spare2 creates a UEPagingCoverageInformationCriticalExtensionsC1 with the spare2 alternative.
func NewUEPagingCoverageInformationCriticalExtensionsC1Spare2(v struct{}) UEPagingCoverageInformationCriticalExtensionsC1 {
	return UEPagingCoverageInformationCriticalExtensionsC1{
		Choice: UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare2,
		Spare2: &v,
	}
}

// NewUEPagingCoverageInformationCriticalExtensionsC1Spare1 creates a UEPagingCoverageInformationCriticalExtensionsC1 with the spare1 alternative.
func NewUEPagingCoverageInformationCriticalExtensionsC1Spare1(v struct{}) UEPagingCoverageInformationCriticalExtensionsC1 {
	return UEPagingCoverageInformationCriticalExtensionsC1{
		Choice: UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare1,
		Spare1: &v,
	}
}

// UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture represents the ASN.1 type UEPagingCoverageInformation-criticalExtensions-criticalExtensionsFuture (SEQUENCE).
type UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture struct {
}

// UEPagingCoverageInformationR13IEsNonCriticalExtension represents the ASN.1 type UEPagingCoverageInformation-r13-IEs-nonCriticalExtension (SEQUENCE).
type UEPagingCoverageInformationR13IEsNonCriticalExtension struct {
}

// UERadioAccessCapabilityInformationCriticalExtensions choice constants.
const (
	UERadioAccessCapabilityInformationCriticalExtensionsChoiceC1                       = 1
	UERadioAccessCapabilityInformationCriticalExtensionsChoiceCriticalExtensionsFuture = 2
)

// UERadioAccessCapabilityInformationCriticalExtensions represents the ASN.1 CHOICE type UERadioAccessCapabilityInformation-criticalExtensions.
type UERadioAccessCapabilityInformationCriticalExtensions struct {
	Choice                   int
	C1                       *UERadioAccessCapabilityInformationCriticalExtensionsC1                       `json:"C1,omitempty"`
	CriticalExtensionsFuture *UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture `json:"CriticalExtensionsFuture,omitempty"`
}

// NewUERadioAccessCapabilityInformationCriticalExtensionsC1 creates a UERadioAccessCapabilityInformationCriticalExtensions with the c1 alternative.
func NewUERadioAccessCapabilityInformationCriticalExtensionsC1(v UERadioAccessCapabilityInformationCriticalExtensionsC1) UERadioAccessCapabilityInformationCriticalExtensions {
	return UERadioAccessCapabilityInformationCriticalExtensions{
		Choice: UERadioAccessCapabilityInformationCriticalExtensionsChoiceC1,
		C1:     &v,
	}
}

// NewUERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture creates a UERadioAccessCapabilityInformationCriticalExtensions with the criticalExtensionsFuture alternative.
func NewUERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture(v UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture) UERadioAccessCapabilityInformationCriticalExtensions {
	return UERadioAccessCapabilityInformationCriticalExtensions{
		Choice:                   UERadioAccessCapabilityInformationCriticalExtensionsChoiceCriticalExtensionsFuture,
		CriticalExtensionsFuture: &v,
	}
}

// UERadioAccessCapabilityInformationCriticalExtensionsC1 choice constants.
const (
	UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceUeRadioAccessCapabilityInformationR8 = 1
	UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare7                               = 2
	UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare6                               = 3
	UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare5                               = 4
	UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare4                               = 5
	UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare3                               = 6
	UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare2                               = 7
	UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare1                               = 8
)

// UERadioAccessCapabilityInformationCriticalExtensionsC1 represents the ASN.1 CHOICE type UERadioAccessCapabilityInformation-criticalExtensions-c1.
type UERadioAccessCapabilityInformationCriticalExtensionsC1 struct {
	Choice                               int
	UeRadioAccessCapabilityInformationR8 *UERadioAccessCapabilityInformationR8IEs `json:"UeRadioAccessCapabilityInformationR8,omitempty"`
	Spare7                               *struct{}                                `json:"Spare7,omitempty"`
	Spare6                               *struct{}                                `json:"Spare6,omitempty"`
	Spare5                               *struct{}                                `json:"Spare5,omitempty"`
	Spare4                               *struct{}                                `json:"Spare4,omitempty"`
	Spare3                               *struct{}                                `json:"Spare3,omitempty"`
	Spare2                               *struct{}                                `json:"Spare2,omitempty"`
	Spare1                               *struct{}                                `json:"Spare1,omitempty"`
}

// NewUERadioAccessCapabilityInformationCriticalExtensionsC1UeRadioAccessCapabilityInformationR8 creates a UERadioAccessCapabilityInformationCriticalExtensionsC1 with the ueRadioAccessCapabilityInformation-r8 alternative.
func NewUERadioAccessCapabilityInformationCriticalExtensionsC1UeRadioAccessCapabilityInformationR8(v UERadioAccessCapabilityInformationR8IEs) UERadioAccessCapabilityInformationCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationCriticalExtensionsC1{
		Choice:                               UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceUeRadioAccessCapabilityInformationR8,
		UeRadioAccessCapabilityInformationR8: &v,
	}
}

// NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare7 creates a UERadioAccessCapabilityInformationCriticalExtensionsC1 with the spare7 alternative.
func NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare7(v struct{}) UERadioAccessCapabilityInformationCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationCriticalExtensionsC1{
		Choice: UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare7,
		Spare7: &v,
	}
}

// NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare6 creates a UERadioAccessCapabilityInformationCriticalExtensionsC1 with the spare6 alternative.
func NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare6(v struct{}) UERadioAccessCapabilityInformationCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationCriticalExtensionsC1{
		Choice: UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare6,
		Spare6: &v,
	}
}

// NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare5 creates a UERadioAccessCapabilityInformationCriticalExtensionsC1 with the spare5 alternative.
func NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare5(v struct{}) UERadioAccessCapabilityInformationCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationCriticalExtensionsC1{
		Choice: UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare5,
		Spare5: &v,
	}
}

// NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare4 creates a UERadioAccessCapabilityInformationCriticalExtensionsC1 with the spare4 alternative.
func NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare4(v struct{}) UERadioAccessCapabilityInformationCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationCriticalExtensionsC1{
		Choice: UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare4,
		Spare4: &v,
	}
}

// NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare3 creates a UERadioAccessCapabilityInformationCriticalExtensionsC1 with the spare3 alternative.
func NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare3(v struct{}) UERadioAccessCapabilityInformationCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationCriticalExtensionsC1{
		Choice: UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare3,
		Spare3: &v,
	}
}

// NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare2 creates a UERadioAccessCapabilityInformationCriticalExtensionsC1 with the spare2 alternative.
func NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare2(v struct{}) UERadioAccessCapabilityInformationCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationCriticalExtensionsC1{
		Choice: UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare2,
		Spare2: &v,
	}
}

// NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare1 creates a UERadioAccessCapabilityInformationCriticalExtensionsC1 with the spare1 alternative.
func NewUERadioAccessCapabilityInformationCriticalExtensionsC1Spare1(v struct{}) UERadioAccessCapabilityInformationCriticalExtensionsC1 {
	return UERadioAccessCapabilityInformationCriticalExtensionsC1{
		Choice: UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare1,
		Spare1: &v,
	}
}

// UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture represents the ASN.1 type UERadioAccessCapabilityInformation-criticalExtensions-criticalExtensionsFuture (SEQUENCE).
type UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture struct {
}

// UERadioAccessCapabilityInformationR8IEsNonCriticalExtension represents the ASN.1 type UERadioAccessCapabilityInformation-r8-IEs-nonCriticalExtension (SEQUENCE).
type UERadioAccessCapabilityInformationR8IEsNonCriticalExtension struct {
}

// UERadioPagingInformationCriticalExtensions choice constants.
const (
	UERadioPagingInformationCriticalExtensionsChoiceC1                       = 1
	UERadioPagingInformationCriticalExtensionsChoiceCriticalExtensionsFuture = 2
)

// UERadioPagingInformationCriticalExtensions represents the ASN.1 CHOICE type UERadioPagingInformation-criticalExtensions.
type UERadioPagingInformationCriticalExtensions struct {
	Choice                   int
	C1                       *UERadioPagingInformationCriticalExtensionsC1                       `json:"C1,omitempty"`
	CriticalExtensionsFuture *UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture `json:"CriticalExtensionsFuture,omitempty"`
}

// NewUERadioPagingInformationCriticalExtensionsC1 creates a UERadioPagingInformationCriticalExtensions with the c1 alternative.
func NewUERadioPagingInformationCriticalExtensionsC1(v UERadioPagingInformationCriticalExtensionsC1) UERadioPagingInformationCriticalExtensions {
	return UERadioPagingInformationCriticalExtensions{
		Choice: UERadioPagingInformationCriticalExtensionsChoiceC1,
		C1:     &v,
	}
}

// NewUERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture creates a UERadioPagingInformationCriticalExtensions with the criticalExtensionsFuture alternative.
func NewUERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture(v UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture) UERadioPagingInformationCriticalExtensions {
	return UERadioPagingInformationCriticalExtensions{
		Choice:                   UERadioPagingInformationCriticalExtensionsChoiceCriticalExtensionsFuture,
		CriticalExtensionsFuture: &v,
	}
}

// UERadioPagingInformationCriticalExtensionsC1 choice constants.
const (
	UERadioPagingInformationCriticalExtensionsC1ChoiceUeRadioPagingInformationR12 = 1
	UERadioPagingInformationCriticalExtensionsC1ChoiceSpare7                      = 2
	UERadioPagingInformationCriticalExtensionsC1ChoiceSpare6                      = 3
	UERadioPagingInformationCriticalExtensionsC1ChoiceSpare5                      = 4
	UERadioPagingInformationCriticalExtensionsC1ChoiceSpare4                      = 5
	UERadioPagingInformationCriticalExtensionsC1ChoiceSpare3                      = 6
	UERadioPagingInformationCriticalExtensionsC1ChoiceSpare2                      = 7
	UERadioPagingInformationCriticalExtensionsC1ChoiceSpare1                      = 8
)

// UERadioPagingInformationCriticalExtensionsC1 represents the ASN.1 CHOICE type UERadioPagingInformation-criticalExtensions-c1.
type UERadioPagingInformationCriticalExtensionsC1 struct {
	Choice                      int
	UeRadioPagingInformationR12 *UERadioPagingInformationR12IEs `json:"UeRadioPagingInformationR12,omitempty"`
	Spare7                      *struct{}                       `json:"Spare7,omitempty"`
	Spare6                      *struct{}                       `json:"Spare6,omitempty"`
	Spare5                      *struct{}                       `json:"Spare5,omitempty"`
	Spare4                      *struct{}                       `json:"Spare4,omitempty"`
	Spare3                      *struct{}                       `json:"Spare3,omitempty"`
	Spare2                      *struct{}                       `json:"Spare2,omitempty"`
	Spare1                      *struct{}                       `json:"Spare1,omitempty"`
}

// NewUERadioPagingInformationCriticalExtensionsC1UeRadioPagingInformationR12 creates a UERadioPagingInformationCriticalExtensionsC1 with the ueRadioPagingInformation-r12 alternative.
func NewUERadioPagingInformationCriticalExtensionsC1UeRadioPagingInformationR12(v UERadioPagingInformationR12IEs) UERadioPagingInformationCriticalExtensionsC1 {
	return UERadioPagingInformationCriticalExtensionsC1{
		Choice:                      UERadioPagingInformationCriticalExtensionsC1ChoiceUeRadioPagingInformationR12,
		UeRadioPagingInformationR12: &v,
	}
}

// NewUERadioPagingInformationCriticalExtensionsC1Spare7 creates a UERadioPagingInformationCriticalExtensionsC1 with the spare7 alternative.
func NewUERadioPagingInformationCriticalExtensionsC1Spare7(v struct{}) UERadioPagingInformationCriticalExtensionsC1 {
	return UERadioPagingInformationCriticalExtensionsC1{
		Choice: UERadioPagingInformationCriticalExtensionsC1ChoiceSpare7,
		Spare7: &v,
	}
}

// NewUERadioPagingInformationCriticalExtensionsC1Spare6 creates a UERadioPagingInformationCriticalExtensionsC1 with the spare6 alternative.
func NewUERadioPagingInformationCriticalExtensionsC1Spare6(v struct{}) UERadioPagingInformationCriticalExtensionsC1 {
	return UERadioPagingInformationCriticalExtensionsC1{
		Choice: UERadioPagingInformationCriticalExtensionsC1ChoiceSpare6,
		Spare6: &v,
	}
}

// NewUERadioPagingInformationCriticalExtensionsC1Spare5 creates a UERadioPagingInformationCriticalExtensionsC1 with the spare5 alternative.
func NewUERadioPagingInformationCriticalExtensionsC1Spare5(v struct{}) UERadioPagingInformationCriticalExtensionsC1 {
	return UERadioPagingInformationCriticalExtensionsC1{
		Choice: UERadioPagingInformationCriticalExtensionsC1ChoiceSpare5,
		Spare5: &v,
	}
}

// NewUERadioPagingInformationCriticalExtensionsC1Spare4 creates a UERadioPagingInformationCriticalExtensionsC1 with the spare4 alternative.
func NewUERadioPagingInformationCriticalExtensionsC1Spare4(v struct{}) UERadioPagingInformationCriticalExtensionsC1 {
	return UERadioPagingInformationCriticalExtensionsC1{
		Choice: UERadioPagingInformationCriticalExtensionsC1ChoiceSpare4,
		Spare4: &v,
	}
}

// NewUERadioPagingInformationCriticalExtensionsC1Spare3 creates a UERadioPagingInformationCriticalExtensionsC1 with the spare3 alternative.
func NewUERadioPagingInformationCriticalExtensionsC1Spare3(v struct{}) UERadioPagingInformationCriticalExtensionsC1 {
	return UERadioPagingInformationCriticalExtensionsC1{
		Choice: UERadioPagingInformationCriticalExtensionsC1ChoiceSpare3,
		Spare3: &v,
	}
}

// NewUERadioPagingInformationCriticalExtensionsC1Spare2 creates a UERadioPagingInformationCriticalExtensionsC1 with the spare2 alternative.
func NewUERadioPagingInformationCriticalExtensionsC1Spare2(v struct{}) UERadioPagingInformationCriticalExtensionsC1 {
	return UERadioPagingInformationCriticalExtensionsC1{
		Choice: UERadioPagingInformationCriticalExtensionsC1ChoiceSpare2,
		Spare2: &v,
	}
}

// NewUERadioPagingInformationCriticalExtensionsC1Spare1 creates a UERadioPagingInformationCriticalExtensionsC1 with the spare1 alternative.
func NewUERadioPagingInformationCriticalExtensionsC1Spare1(v struct{}) UERadioPagingInformationCriticalExtensionsC1 {
	return UERadioPagingInformationCriticalExtensionsC1{
		Choice: UERadioPagingInformationCriticalExtensionsC1ChoiceSpare1,
		Spare1: &v,
	}
}

// UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture represents the ASN.1 type UERadioPagingInformation-criticalExtensions-criticalExtensionsFuture (SEQUENCE).
type UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture struct {
}

// UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13 represents the ASN.1 type UERadioPagingInformation-v1310-IEs-supportedBandListEUTRAForPaging-r13 (SEQUENCE_OF).
type UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13 = []FreqBandIndicatorR11

// UERadioPagingInformationV1610IEsNonCriticalExtension represents the ASN.1 type UERadioPagingInformation-v1610-IEs-nonCriticalExtension (SEQUENCE).
type UERadioPagingInformationV1610IEsNonCriticalExtension struct {
}

// ASConfigV1550TdmPatternConfigR15 represents the ASN.1 type AS-Config-v1550-tdm-PatternConfig-r15 (SEQUENCE).
type ASConfigV1550TdmPatternConfigR15 struct {
	SubframeAssignmentR15 SubframeAssignmentR15 `asn1:"tag:0,context,implicit"`
	HarqOffsetR15         int64                 `asn1:"tag:1,context,implicit"`
}

// MarshalUPER encodes HandoverCommand to UPER format.
func (v *HandoverCommand) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverCommand) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CriticalExtensions.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding criticalExtensions: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes HandoverCommand from UPER format.
func (v *HandoverCommand) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverCommand) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverCommand{}
	if err := v.CriticalExtensions.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding criticalExtensions: %w", err)
	}
	return nil
}

// MarshalUPER encodes HandoverCommandR8IEs to UPER format.
func (v *HandoverCommandR8IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverCommandR8IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	containedBB_handovercommandmessage := per.NewBitBuffer()
	if err := (v.HandoverCommandMessage).MarshalUPERTo(containedBB_handovercommandmessage); err != nil {
		return fmt.Errorf("encoding contained handoverCommandMessage: %w", err)
	}
	if err := per.EncodeOctetStringExt(bb, containedBB_handovercommandmessage.Bytes(), 0, 0, false, false); err != nil {
		return fmt.Errorf("encoding handoverCommandMessage: %w", err)
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverCommandR8IEs from UPER format.
func (v *HandoverCommandR8IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverCommandR8IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverCommandR8IEs{}
	// Read preamble bitmap for optional root fields
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	containedBytes_handovercommandmessage, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
	if err != nil {
		return fmt.Errorf("decoding handoverCommandMessage: %w", err)
	}
	var contained_handovercommandmessage DLDCCHMessage
	if err := contained_handovercommandmessage.UnmarshalUPER(containedBytes_handovercommandmessage); err != nil {
		return fmt.Errorf("decoding contained handoverCommandMessage: %w", err)
	}
	v.HandoverCommandMessage = contained_handovercommandmessage
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverCommandR8IEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformation to UPER format.
func (v *HandoverPreparationInformation) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformation) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CriticalExtensions.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding criticalExtensions: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformation from UPER format.
func (v *HandoverPreparationInformation) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformation) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformation{}
	if err := v.CriticalExtensions.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding criticalExtensions: %w", err)
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationR8IEs to UPER format.
func (v *HandoverPreparationInformationR8IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationR8IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AsConfig != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.RrmConfig != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.AsContext != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.UeRadioAccessCapabilityInfo)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_ueradioaccesscapabilityinfo, fragmentLength_ueradioaccesscapabilityinfo int64) error {
		for _, elem := range v.UeRadioAccessCapabilityInfo[fragmentOffset_ueradioaccesscapabilityinfo : fragmentOffset_ueradioaccesscapabilityinfo+fragmentLength_ueradioaccesscapabilityinfo] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding ue-RadioAccessCapabilityInfo element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding ue-RadioAccessCapabilityInfo: %w", err)
	}
	if v.AsConfig != nil {
		if err := v.AsConfig.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Config: %w", err)
		}
	}
	if v.RrmConfig != nil {
		if err := v.RrmConfig.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding rrm-Config: %w", err)
		}
	}
	if v.AsContext != nil {
		if err := v.AsContext.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Context: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationR8IEs from UPER format.
func (v *HandoverPreparationInformationR8IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationR8IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationR8IEs{}
	// Read preamble bitmap for optional root fields
	opt_asconfig, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_rrmconfig, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ascontext, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.UeRadioAccessCapabilityInfo = make(UECapabilityRATContainerList, 0)
	_, errCollection_ueradioaccesscapabilityinfo := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_ueradioaccesscapabilityinfo, fragmentLength_ueradioaccesscapabilityinfo int64) error {
		for i := int64(0); i < fragmentLength_ueradioaccesscapabilityinfo; i++ {
			var elem UECapabilityRATContainer
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding ue-RadioAccessCapabilityInfo element %d: %w", fragmentOffset_ueradioaccesscapabilityinfo+i, err)
			}
			v.UeRadioAccessCapabilityInfo = append(v.UeRadioAccessCapabilityInfo, elem)
		}
		return nil
	})
	if errCollection_ueradioaccesscapabilityinfo != nil {
		return fmt.Errorf("decoding ue-RadioAccessCapabilityInfo: %w", errCollection_ueradioaccesscapabilityinfo)
	}
	if opt_asconfig {
		var dec_asconfig ASConfig
		if err := dec_asconfig.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Config: %w", err)
		}
		v.AsConfig = &dec_asconfig
	}
	if opt_rrmconfig {
		var dec_rrmconfig RRMConfig
		if err := dec_rrmconfig.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding rrm-Config: %w", err)
		}
		v.RrmConfig = &dec_rrmconfig
	}
	if opt_ascontext {
		var dec_ascontext ASContext
		if err := dec_ascontext.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Context: %w", err)
		}
		v.AsContext = &dec_ascontext
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV920IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV920IEs to UPER format.
func (v *HandoverPreparationInformationV920IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV920IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.UeConfigReleaseR9 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.UeConfigReleaseR9 != nil {
		if err := per.EncodeEnumerated(bb, int64(*v.UeConfigReleaseR9), 8, true); err != nil {
			return fmt.Errorf("encoding ue-ConfigRelease-r9: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV920IEs from UPER format.
func (v *HandoverPreparationInformationV920IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV920IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV920IEs{}
	// Read preamble bitmap for optional root fields
	opt_ueconfigreleaser9, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_ueconfigreleaser9 {
		val_ueconfigreleaser9, err := per.DecodeEnumerated(bb, 8, true)
		if err != nil {
			return fmt.Errorf("decoding ue-ConfigRelease-r9: %w", err)
		}
		v.UeConfigReleaseR9 = &val_ueconfigreleaser9
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV9d0IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV9d0IEs to UPER format.
func (v *HandoverPreparationInformationV9d0IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV9d0IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.LateNonCriticalExtension != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.LateNonCriticalExtension != nil {
		containedBB_latenoncriticalextension := per.NewBitBuffer()
		if err := (*v.LateNonCriticalExtension).MarshalUPERTo(containedBB_latenoncriticalextension); err != nil {
			return fmt.Errorf("encoding contained lateNonCriticalExtension: %w", err)
		}
		if err := per.EncodeOctetStringExt(bb, containedBB_latenoncriticalextension.Bytes(), 0, 0, false, false); err != nil {
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

// UnmarshalUPER decodes HandoverPreparationInformationV9d0IEs from UPER format.
func (v *HandoverPreparationInformationV9d0IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV9d0IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV9d0IEs{}
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
		containedBytes_latenoncriticalextension, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding lateNonCriticalExtension: %w", err)
		}
		var contained_latenoncriticalextension HandoverPreparationInformationV9j0IEs
		if err := contained_latenoncriticalextension.UnmarshalUPER(containedBytes_latenoncriticalextension); err != nil {
			return fmt.Errorf("decoding contained lateNonCriticalExtension: %w", err)
		}
		v.LateNonCriticalExtension = &contained_latenoncriticalextension
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV9e0IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV9j0IEs to UPER format.
func (v *HandoverPreparationInformationV9j0IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV9j0IEs) MarshalUPERTo(bb *per.BitBuffer) error {
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

// UnmarshalUPER decodes HandoverPreparationInformationV9j0IEs from UPER format.
func (v *HandoverPreparationInformationV9j0IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV9j0IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV9j0IEs{}
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
			return fmt.Errorf("decoding lateNonCriticalExtension: %w", err)
		}
		tmp_latenoncriticalextension := val_latenoncriticalextension
		v.LateNonCriticalExtension = tmp_latenoncriticalextension
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV10j0IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV10j0IEs to UPER format.
func (v *HandoverPreparationInformationV10j0IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV10j0IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AsConfigV10j0 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.AsConfigV10j0 != nil {
		if err := v.AsConfigV10j0.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Config-v10j0: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV10j0IEs from UPER format.
func (v *HandoverPreparationInformationV10j0IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV10j0IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV10j0IEs{}
	// Read preamble bitmap for optional root fields
	opt_asconfigv10j0, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_asconfigv10j0 {
		var dec_asconfigv10j0 ASConfigV10j0
		if err := dec_asconfigv10j0.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Config-v10j0: %w", err)
		}
		v.AsConfigV10j0 = &dec_asconfigv10j0
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV10x0IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV10x0IEs to UPER format.
func (v *HandoverPreparationInformationV10x0IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV10x0IEs) MarshalUPERTo(bb *per.BitBuffer) error {
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

// UnmarshalUPER decodes HandoverPreparationInformationV10x0IEs from UPER format.
func (v *HandoverPreparationInformationV10x0IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV10x0IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV10x0IEs{}
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
			return fmt.Errorf("decoding lateNonCriticalExtension: %w", err)
		}
		tmp_latenoncriticalextension := val_latenoncriticalextension
		v.LateNonCriticalExtension = tmp_latenoncriticalextension
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV13c0IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV13c0IEs to UPER format.
func (v *HandoverPreparationInformationV13c0IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV13c0IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AsConfigV13c0 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.AsConfigV13c0 != nil {
		if err := v.AsConfigV13c0.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Config-v13c0: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV13c0IEs from UPER format.
func (v *HandoverPreparationInformationV13c0IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV13c0IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV13c0IEs{}
	// Read preamble bitmap for optional root fields
	opt_asconfigv13c0, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_asconfigv13c0 {
		var dec_asconfigv13c0 ASConfigV13c0
		if err := dec_asconfigv13c0.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Config-v13c0: %w", err)
		}
		v.AsConfigV13c0 = &dec_asconfigv13c0
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV13c0IEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV9e0IEs to UPER format.
func (v *HandoverPreparationInformationV9e0IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV9e0IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AsConfigV9e0 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.AsConfigV9e0 != nil {
		if err := v.AsConfigV9e0.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Config-v9e0: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV9e0IEs from UPER format.
func (v *HandoverPreparationInformationV9e0IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV9e0IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV9e0IEs{}
	// Read preamble bitmap for optional root fields
	opt_asconfigv9e0, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_asconfigv9e0 {
		var dec_asconfigv9e0 ASConfigV9e0
		if err := dec_asconfigv9e0.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Config-v9e0: %w", err)
		}
		v.AsConfigV9e0 = &dec_asconfigv9e0
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV1130IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV1130IEs to UPER format.
func (v *HandoverPreparationInformationV1130IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV1130IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AsContextV1130 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.AsContextV1130 != nil {
		if err := v.AsContextV1130.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Context-v1130: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV1130IEs from UPER format.
func (v *HandoverPreparationInformationV1130IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV1130IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV1130IEs{}
	// Read preamble bitmap for optional root fields
	opt_ascontextv1130, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_ascontextv1130 {
		var dec_ascontextv1130 ASContextV1130
		if err := dec_ascontextv1130.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Context-v1130: %w", err)
		}
		v.AsContextV1130 = &dec_ascontextv1130
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV1250IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV1250IEs to UPER format.
func (v *HandoverPreparationInformationV1250IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV1250IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.UeSupportedEARFCNR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.AsConfigV1250 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.UeSupportedEARFCNR12 != nil {
		if err := per.EncodeInteger(bb, int64(*v.UeSupportedEARFCNR12), int64Ptr(0), int64Ptr(262143), false); err != nil {
			return fmt.Errorf("encoding ue-SupportedEARFCN-r12: %w", err)
		}
	}
	if v.AsConfigV1250 != nil {
		if err := v.AsConfigV1250.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Config-v1250: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV1250IEs from UPER format.
func (v *HandoverPreparationInformationV1250IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV1250IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV1250IEs{}
	// Read preamble bitmap for optional root fields
	opt_uesupportedearfcnr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_asconfigv1250, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_uesupportedearfcnr12 {
		val_uesupportedearfcnr12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(262143), false)
		if err != nil {
			return fmt.Errorf("decoding ue-SupportedEARFCN-r12: %w", err)
		}
		tmp_uesupportedearfcnr12 := ARFCNValueEUTRAR9(val_uesupportedearfcnr12)
		v.UeSupportedEARFCNR12 = &tmp_uesupportedearfcnr12
	}
	if opt_asconfigv1250 {
		var dec_asconfigv1250 ASConfigV1250
		if err := dec_asconfigv1250.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Config-v1250: %w", err)
		}
		v.AsConfigV1250 = &dec_asconfigv1250
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV1320IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV1320IEs to UPER format.
func (v *HandoverPreparationInformationV1320IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV1320IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AsConfigV1320 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.AsContextV1320 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.AsConfigV1320 != nil {
		if err := v.AsConfigV1320.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Config-v1320: %w", err)
		}
	}
	if v.AsContextV1320 != nil {
		if err := v.AsContextV1320.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Context-v1320: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV1320IEs from UPER format.
func (v *HandoverPreparationInformationV1320IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV1320IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV1320IEs{}
	// Read preamble bitmap for optional root fields
	opt_asconfigv1320, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ascontextv1320, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_asconfigv1320 {
		var dec_asconfigv1320 ASConfigV1320
		if err := dec_asconfigv1320.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Config-v1320: %w", err)
		}
		v.AsConfigV1320 = &dec_asconfigv1320
	}
	if opt_ascontextv1320 {
		var dec_ascontextv1320 ASContextV1320
		if err := dec_ascontextv1320.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Context-v1320: %w", err)
		}
		v.AsContextV1320 = &dec_ascontextv1320
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV1430IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV1430IEs to UPER format.
func (v *HandoverPreparationInformationV1430IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV1430IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AsConfigV1430 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MakeBeforeBreakReqR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.AsConfigV1430 != nil {
		if err := v.AsConfigV1430.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Config-v1430: %w", err)
		}
	}
	if v.MakeBeforeBreakReqR14 != nil {
		if err := per.EncodeEnumerated(bb, int64(*v.MakeBeforeBreakReqR14), 1, false); err != nil {
			return fmt.Errorf("encoding makeBeforeBreakReq-r14: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV1430IEs from UPER format.
func (v *HandoverPreparationInformationV1430IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV1430IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV1430IEs{}
	// Read preamble bitmap for optional root fields
	opt_asconfigv1430, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_makebeforebreakreqr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_asconfigv1430 {
		var dec_asconfigv1430 ASConfigV1430
		if err := dec_asconfigv1430.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Config-v1430: %w", err)
		}
		v.AsConfigV1430 = &dec_asconfigv1430
	}
	if opt_makebeforebreakreqr14 {
		val_makebeforebreakreqr14, err := per.DecodeEnumerated(bb, 1, false)
		if err != nil {
			return fmt.Errorf("decoding makeBeforeBreakReq-r14: %w", err)
		}
		v.MakeBeforeBreakReqR14 = &val_makebeforebreakreqr14
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV1530IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV1530IEs to UPER format.
func (v *HandoverPreparationInformationV1530IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV1530IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.RanNotificationAreaInfoR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.RanNotificationAreaInfoR15 != nil {
		if err := v.RanNotificationAreaInfoR15.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding ran-NotificationAreaInfo-r15: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV1530IEs from UPER format.
func (v *HandoverPreparationInformationV1530IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV1530IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV1530IEs{}
	// Read preamble bitmap for optional root fields
	opt_rannotificationareainfor15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_rannotificationareainfor15 {
		var dec_rannotificationareainfor15 RANNotificationAreaInfoR15
		if err := dec_rannotificationareainfor15.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding ran-NotificationAreaInfo-r15: %w", err)
		}
		v.RanNotificationAreaInfoR15 = &dec_rannotificationareainfor15
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV1540IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV1540IEs to UPER format.
func (v *HandoverPreparationInformationV1540IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV1540IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SourceRBConfigIntra5GCR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.SourceRBConfigIntra5GCR15 != nil {
		if err := per.EncodeOctetStringExt(bb, v.SourceRBConfigIntra5GCR15, 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding sourceRB-ConfigIntra5GC-r15: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV1540IEs from UPER format.
func (v *HandoverPreparationInformationV1540IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV1540IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV1540IEs{}
	// Read preamble bitmap for optional root fields
	opt_sourcerbconfigintra5gcr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_sourcerbconfigintra5gcr15 {
		val_sourcerbconfigintra5gcr15, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding sourceRB-ConfigIntra5GC-r15: %w", err)
		}
		tmp_sourcerbconfigintra5gcr15 := val_sourcerbconfigintra5gcr15
		v.SourceRBConfigIntra5GCR15 = tmp_sourcerbconfigintra5gcr15
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV1610IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV1610IEs to UPER format.
func (v *HandoverPreparationInformationV1610IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV1610IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AsContextV1610 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.AsContextV1610 != nil {
		if err := v.AsContextV1610.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Context-v1610: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV1610IEs from UPER format.
func (v *HandoverPreparationInformationV1610IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV1610IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV1610IEs{}
	// Read preamble bitmap for optional root fields
	opt_ascontextv1610, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_ascontextv1610 {
		var dec_ascontextv1610 ASContextV1610
		if err := dec_ascontextv1610.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Context-v1610: %w", err)
		}
		v.AsContextV1610 = &dec_ascontextv1610
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV1620IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV1620IEs to UPER format.
func (v *HandoverPreparationInformationV1620IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV1620IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AsContextV1620 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.AsContextV1620 != nil {
		if err := v.AsContextV1620.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Context-v1620: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV1620IEs from UPER format.
func (v *HandoverPreparationInformationV1620IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV1620IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV1620IEs{}
	// Read preamble bitmap for optional root fields
	opt_ascontextv1620, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_ascontextv1620 {
		var dec_ascontextv1620 ASContextV1620
		if err := dec_ascontextv1620.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Context-v1620: %w", err)
		}
		v.AsContextV1620 = &dec_ascontextv1620
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV1630IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV1630IEs to UPER format.
func (v *HandoverPreparationInformationV1630IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV1630IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AsContextV1630 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.AsContextV1630 != nil {
		if err := v.AsContextV1630.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Context-v1630: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV1630IEs from UPER format.
func (v *HandoverPreparationInformationV1630IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV1630IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV1630IEs{}
	// Read preamble bitmap for optional root fields
	opt_ascontextv1630, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_ascontextv1630 {
		var dec_ascontextv1630 ASContextV1630
		if err := dec_ascontextv1630.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Context-v1630: %w", err)
		}
		v.AsContextV1630 = &dec_ascontextv1630
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV1700IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV1700IEs to UPER format.
func (v *HandoverPreparationInformationV1700IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV1700IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AsConfigV1700 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.AsConfigV1700 != nil {
		if err := v.AsConfigV1700.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding as-Config-v1700: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV1700IEs from UPER format.
func (v *HandoverPreparationInformationV1700IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV1700IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV1700IEs{}
	// Read preamble bitmap for optional root fields
	opt_asconfigv1700, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_asconfigv1700 {
		var dec_asconfigv1700 ASConfigV1700
		if err := dec_asconfigv1700.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding as-Config-v1700: %w", err)
		}
		v.AsConfigV1700 = &dec_asconfigv1700
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension HandoverPreparationInformationV1700IEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes SCGConfigR12 to UPER format.
func (v *SCGConfigR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigR12) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CriticalExtensions.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding criticalExtensions: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigR12 from UPER format.
func (v *SCGConfigR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigR12{}
	if err := v.CriticalExtensions.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding criticalExtensions: %w", err)
	}
	return nil
}

// MarshalUPER encodes SCGConfigR12IEs to UPER format.
func (v *SCGConfigR12IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigR12IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.ScgRadioConfigR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.ScgRadioConfigR12 != nil {
		if err := v.ScgRadioConfigR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding scg-RadioConfig-r12: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigR12IEs from UPER format.
func (v *SCGConfigR12IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigR12IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigR12IEs{}
	// Read preamble bitmap for optional root fields
	opt_scgradioconfigr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_scgradioconfigr12 {
		var dec_scgradioconfigr12 SCGConfigPartSCGR12
		if err := dec_scgradioconfigr12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding scg-RadioConfig-r12: %w", err)
		}
		v.ScgRadioConfigR12 = &dec_scgradioconfigr12
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension SCGConfigV12i0aIEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes SCGConfigV12i0aIEs to UPER format.
func (v *SCGConfigV12i0aIEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigV12i0aIEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.LateNonCriticalExtension != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.LateNonCriticalExtension != nil {
		containedBB_latenoncriticalextension := per.NewBitBuffer()
		if err := (*v.LateNonCriticalExtension).MarshalUPERTo(containedBB_latenoncriticalextension); err != nil {
			return fmt.Errorf("encoding contained lateNonCriticalExtension: %w", err)
		}
		if err := per.EncodeOctetStringExt(bb, containedBB_latenoncriticalextension.Bytes(), 0, 0, false, false); err != nil {
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

// UnmarshalUPER decodes SCGConfigV12i0aIEs from UPER format.
func (v *SCGConfigV12i0aIEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigV12i0aIEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigV12i0aIEs{}
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
		containedBytes_latenoncriticalextension, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding lateNonCriticalExtension: %w", err)
		}
		var contained_latenoncriticalextension SCGConfigV12i0bIEs
		if err := contained_latenoncriticalextension.UnmarshalUPER(containedBytes_latenoncriticalextension); err != nil {
			return fmt.Errorf("decoding contained lateNonCriticalExtension: %w", err)
		}
		v.LateNonCriticalExtension = &contained_latenoncriticalextension
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension SCGConfigV13c0IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes SCGConfigV12i0bIEs to UPER format.
func (v *SCGConfigV12i0bIEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigV12i0bIEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.ScgRadioConfigV12i0 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.ScgRadioConfigV12i0 != nil {
		if err := v.ScgRadioConfigV12i0.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding scg-RadioConfig-v12i0: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigV12i0bIEs from UPER format.
func (v *SCGConfigV12i0bIEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigV12i0bIEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigV12i0bIEs{}
	// Read preamble bitmap for optional root fields
	opt_scgradioconfigv12i0, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_scgradioconfigv12i0 {
		var dec_scgradioconfigv12i0 SCGConfigPartSCGV12f0
		if err := dec_scgradioconfigv12i0.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding scg-RadioConfig-v12i0: %w", err)
		}
		v.ScgRadioConfigV12i0 = &dec_scgradioconfigv12i0
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension SCGConfigV12i0bIEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes SCGConfigV13c0IEs to UPER format.
func (v *SCGConfigV13c0IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigV13c0IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.ScgRadioConfigV13c0 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.ScgRadioConfigV13c0 != nil {
		if err := v.ScgRadioConfigV13c0.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding scg-RadioConfig-v13c0: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigV13c0IEs from UPER format.
func (v *SCGConfigV13c0IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigV13c0IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigV13c0IEs{}
	// Read preamble bitmap for optional root fields
	opt_scgradioconfigv13c0, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_scgradioconfigv13c0 {
		var dec_scgradioconfigv13c0 SCGConfigPartSCGV13c0
		if err := dec_scgradioconfigv13c0.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding scg-RadioConfig-v13c0: %w", err)
		}
		v.ScgRadioConfigV13c0 = &dec_scgradioconfigv13c0
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension SCGConfigV13c0IEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes SCGConfigInfoR12 to UPER format.
func (v *SCGConfigInfoR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigInfoR12) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CriticalExtensions.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding criticalExtensions: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigInfoR12 from UPER format.
func (v *SCGConfigInfoR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigInfoR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigInfoR12{}
	if err := v.CriticalExtensions.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding criticalExtensions: %w", err)
	}
	return nil
}

// MarshalUPER encodes SCGConfigInfoR12IEs to UPER format.
func (v *SCGConfigInfoR12IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigInfoR12IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.RadioResourceConfigDedMCGR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SCellToAddModListMCGR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasGapConfigR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.PowerCoordinationInfoR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ScgRadioConfigR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.EutraCapabilityInfoR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ScgConfigRestrictInfoR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MbmsInterestIndicationR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasResultServCellListSCGR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.DrbToAddModListSCGR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.DrbToReleaseListSCGR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SCellToAddModListSCGR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SCellToReleaseListSCGR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.PMaxR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.RadioResourceConfigDedMCGR12 != nil {
		if err := v.RadioResourceConfigDedMCGR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioResourceConfigDedMCG-r12: %w", err)
		}
	}
	if v.SCellToAddModListMCGR12 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.SCellToAddModListMCGR12)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistmcgr12, fragmentLength_scelltoaddmodlistmcgr12 int64) error {
			for _, elem := range v.SCellToAddModListMCGR12[fragmentOffset_scelltoaddmodlistmcgr12 : fragmentOffset_scelltoaddmodlistmcgr12+fragmentLength_scelltoaddmodlistmcgr12] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding sCellToAddModListMCG-r12 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding sCellToAddModListMCG-r12: %w", err)
		}
	}
	if v.MeasGapConfigR12 != nil {
		if err := v.MeasGapConfigR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding measGapConfig-r12: %w", err)
		}
	}
	if v.PowerCoordinationInfoR12 != nil {
		if err := v.PowerCoordinationInfoR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding powerCoordinationInfo-r12: %w", err)
		}
	}
	if v.ScgRadioConfigR12 != nil {
		if err := v.ScgRadioConfigR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding scg-RadioConfig-r12: %w", err)
		}
	}
	if v.EutraCapabilityInfoR12 != nil {
		containedBB_eutracapabilityinfor12 := per.NewBitBuffer()
		if err := (*v.EutraCapabilityInfoR12).MarshalUPERTo(containedBB_eutracapabilityinfor12); err != nil {
			return fmt.Errorf("encoding contained eutra-CapabilityInfo-r12: %w", err)
		}
		if err := per.EncodeOctetStringExt(bb, containedBB_eutracapabilityinfor12.Bytes(), 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding eutra-CapabilityInfo-r12: %w", err)
		}
	}
	if v.ScgConfigRestrictInfoR12 != nil {
		if err := v.ScgConfigRestrictInfoR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding scg-ConfigRestrictInfo-r12: %w", err)
		}
	}
	if v.MbmsInterestIndicationR12 != nil {
		containedBB_mbmsinterestindicationr12 := per.NewBitBuffer()
		if err := (*v.MbmsInterestIndicationR12).MarshalUPERTo(containedBB_mbmsinterestindicationr12); err != nil {
			return fmt.Errorf("encoding contained mbmsInterestIndication-r12: %w", err)
		}
		if err := per.EncodeOctetStringExt(bb, containedBB_mbmsinterestindicationr12.Bytes(), 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding mbmsInterestIndication-r12: %w", err)
		}
	}
	if v.MeasResultServCellListSCGR12 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasResultServCellListSCGR12)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, false, func(fragmentOffset_measresultservcelllistscgr12, fragmentLength_measresultservcelllistscgr12 int64) error {
			for _, elem := range v.MeasResultServCellListSCGR12[fragmentOffset_measresultservcelllistscgr12 : fragmentOffset_measresultservcelllistscgr12+fragmentLength_measresultservcelllistscgr12] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measResultServCellListSCG-r12 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measResultServCellListSCG-r12: %w", err)
		}
	}
	if v.DrbToAddModListSCGR12 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.DrbToAddModListSCGR12)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 11, HasUpper: true}, false, func(fragmentOffset_drbtoaddmodlistscgr12, fragmentLength_drbtoaddmodlistscgr12 int64) error {
			for _, elem := range v.DrbToAddModListSCGR12[fragmentOffset_drbtoaddmodlistscgr12 : fragmentOffset_drbtoaddmodlistscgr12+fragmentLength_drbtoaddmodlistscgr12] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding drb-ToAddModListSCG-r12 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding drb-ToAddModListSCG-r12: %w", err)
		}
	}
	if v.DrbToReleaseListSCGR12 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.DrbToReleaseListSCGR12)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 11, HasUpper: true}, false, func(fragmentOffset_drbtoreleaselistscgr12, fragmentLength_drbtoreleaselistscgr12 int64) error {
			for _, elem := range v.DrbToReleaseListSCGR12[fragmentOffset_drbtoreleaselistscgr12 : fragmentOffset_drbtoreleaselistscgr12+fragmentLength_drbtoreleaselistscgr12] {
				if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(32), false); err != nil {
					return fmt.Errorf("encoding drb-ToReleaseListSCG-r12 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding drb-ToReleaseListSCG-r12: %w", err)
		}
	}
	if v.SCellToAddModListSCGR12 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.SCellToAddModListSCGR12)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistscgr12, fragmentLength_scelltoaddmodlistscgr12 int64) error {
			for _, elem := range v.SCellToAddModListSCGR12[fragmentOffset_scelltoaddmodlistscgr12 : fragmentOffset_scelltoaddmodlistscgr12+fragmentLength_scelltoaddmodlistscgr12] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding sCellToAddModListSCG-r12 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding sCellToAddModListSCG-r12: %w", err)
		}
	}
	if v.SCellToReleaseListSCGR12 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.SCellToReleaseListSCGR12)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_scelltoreleaselistscgr12, fragmentLength_scelltoreleaselistscgr12 int64) error {
			for _, elem := range v.SCellToReleaseListSCGR12[fragmentOffset_scelltoreleaselistscgr12 : fragmentOffset_scelltoreleaselistscgr12+fragmentLength_scelltoreleaselistscgr12] {
				if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(7), false); err != nil {
					return fmt.Errorf("encoding sCellToReleaseListSCG-r12 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding sCellToReleaseListSCG-r12: %w", err)
		}
	}
	if v.PMaxR12 != nil {
		if err := per.EncodeInteger(bb, int64(*v.PMaxR12), int64Ptr(-30), int64Ptr(33), false); err != nil {
			return fmt.Errorf("encoding p-Max-r12: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigInfoR12IEs from UPER format.
func (v *SCGConfigInfoR12IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigInfoR12IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigInfoR12IEs{}
	// Read preamble bitmap for optional root fields
	opt_radioresourceconfigdedmcgr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_scelltoaddmodlistmcgr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measgapconfigr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_powercoordinationinfor12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_scgradioconfigr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_eutracapabilityinfor12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_scgconfigrestrictinfor12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_mbmsinterestindicationr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measresultservcelllistscgr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_drbtoaddmodlistscgr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_drbtoreleaselistscgr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_scelltoaddmodlistscgr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_scelltoreleaselistscgr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_pmaxr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_radioresourceconfigdedmcgr12 {
		var dec_radioresourceconfigdedmcgr12 RadioResourceConfigDedicated
		if err := dec_radioresourceconfigdedmcgr12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding radioResourceConfigDedMCG-r12: %w", err)
		}
		v.RadioResourceConfigDedMCGR12 = &dec_radioresourceconfigdedmcgr12
	}
	if opt_scelltoaddmodlistmcgr12 {
		tmp_scelltoaddmodlistmcgr12 := make(SCellToAddModListR10, 0)
		_, errCollection_scelltoaddmodlistmcgr12 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistmcgr12, fragmentLength_scelltoaddmodlistmcgr12 int64) error {
			for i := int64(0); i < fragmentLength_scelltoaddmodlistmcgr12; i++ {
				var elem SCellToAddModR10
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding sCellToAddModListMCG-r12 element %d: %w", fragmentOffset_scelltoaddmodlistmcgr12+i, err)
				}
				tmp_scelltoaddmodlistmcgr12 = append(tmp_scelltoaddmodlistmcgr12, elem)
			}
			return nil
		})
		if errCollection_scelltoaddmodlistmcgr12 != nil {
			return fmt.Errorf("decoding sCellToAddModListMCG-r12: %w", errCollection_scelltoaddmodlistmcgr12)
		}
		v.SCellToAddModListMCGR12 = tmp_scelltoaddmodlistmcgr12
	}
	if opt_measgapconfigr12 {
		var dec_measgapconfigr12 MeasGapConfig
		if err := dec_measgapconfigr12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding measGapConfig-r12: %w", err)
		}
		v.MeasGapConfigR12 = &dec_measgapconfigr12
	}
	if opt_powercoordinationinfor12 {
		var dec_powercoordinationinfor12 PowerCoordinationInfoR12
		if err := dec_powercoordinationinfor12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding powerCoordinationInfo-r12: %w", err)
		}
		v.PowerCoordinationInfoR12 = &dec_powercoordinationinfor12
	}
	if opt_scgradioconfigr12 {
		var dec_scgradioconfigr12 SCGConfigPartSCGR12
		if err := dec_scgradioconfigr12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding scg-RadioConfig-r12: %w", err)
		}
		v.ScgRadioConfigR12 = &dec_scgradioconfigr12
	}
	if opt_eutracapabilityinfor12 {
		containedBytes_eutracapabilityinfor12, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding eutra-CapabilityInfo-r12: %w", err)
		}
		var contained_eutracapabilityinfor12 UECapabilityInformation
		if err := contained_eutracapabilityinfor12.UnmarshalUPER(containedBytes_eutracapabilityinfor12); err != nil {
			return fmt.Errorf("decoding contained eutra-CapabilityInfo-r12: %w", err)
		}
		v.EutraCapabilityInfoR12 = &contained_eutracapabilityinfor12
	}
	if opt_scgconfigrestrictinfor12 {
		var dec_scgconfigrestrictinfor12 SCGConfigRestrictInfoR12
		if err := dec_scgconfigrestrictinfor12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding scg-ConfigRestrictInfo-r12: %w", err)
		}
		v.ScgConfigRestrictInfoR12 = &dec_scgconfigrestrictinfor12
	}
	if opt_mbmsinterestindicationr12 {
		containedBytes_mbmsinterestindicationr12, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding mbmsInterestIndication-r12: %w", err)
		}
		var contained_mbmsinterestindicationr12 MBMSInterestIndicationR11
		if err := contained_mbmsinterestindicationr12.UnmarshalUPER(containedBytes_mbmsinterestindicationr12); err != nil {
			return fmt.Errorf("decoding contained mbmsInterestIndication-r12: %w", err)
		}
		v.MbmsInterestIndicationR12 = &contained_mbmsinterestindicationr12
	}
	if opt_measresultservcelllistscgr12 {
		tmp_measresultservcelllistscgr12 := make(MeasResultServCellListSCGR12, 0)
		_, errCollection_measresultservcelllistscgr12 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, false, func(fragmentOffset_measresultservcelllistscgr12, fragmentLength_measresultservcelllistscgr12 int64) error {
			for i := int64(0); i < fragmentLength_measresultservcelllistscgr12; i++ {
				var elem MeasResultServCellSCGR12
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding measResultServCellListSCG-r12 element %d: %w", fragmentOffset_measresultservcelllistscgr12+i, err)
				}
				tmp_measresultservcelllistscgr12 = append(tmp_measresultservcelllistscgr12, elem)
			}
			return nil
		})
		if errCollection_measresultservcelllistscgr12 != nil {
			return fmt.Errorf("decoding measResultServCellListSCG-r12: %w", errCollection_measresultservcelllistscgr12)
		}
		v.MeasResultServCellListSCGR12 = tmp_measresultservcelllistscgr12
	}
	if opt_drbtoaddmodlistscgr12 {
		tmp_drbtoaddmodlistscgr12 := make(DRBInfoListSCGR12, 0)
		_, errCollection_drbtoaddmodlistscgr12 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 11, HasUpper: true}, false, func(fragmentOffset_drbtoaddmodlistscgr12, fragmentLength_drbtoaddmodlistscgr12 int64) error {
			for i := int64(0); i < fragmentLength_drbtoaddmodlistscgr12; i++ {
				var elem DRBInfoSCGR12
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding drb-ToAddModListSCG-r12 element %d: %w", fragmentOffset_drbtoaddmodlistscgr12+i, err)
				}
				tmp_drbtoaddmodlistscgr12 = append(tmp_drbtoaddmodlistscgr12, elem)
			}
			return nil
		})
		if errCollection_drbtoaddmodlistscgr12 != nil {
			return fmt.Errorf("decoding drb-ToAddModListSCG-r12: %w", errCollection_drbtoaddmodlistscgr12)
		}
		v.DrbToAddModListSCGR12 = tmp_drbtoaddmodlistscgr12
	}
	if opt_drbtoreleaselistscgr12 {
		tmp_drbtoreleaselistscgr12 := make(DRBToReleaseList, 0)
		_, errCollection_drbtoreleaselistscgr12 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 11, HasUpper: true}, false, func(fragmentOffset_drbtoreleaselistscgr12, fragmentLength_drbtoreleaselistscgr12 int64) error {
			for i := int64(0); i < fragmentLength_drbtoreleaselistscgr12; i++ {
				val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(32), false)
				if err != nil {
					return fmt.Errorf("decoding drb-ToReleaseListSCG-r12 element %d: %w", fragmentOffset_drbtoreleaselistscgr12+i, err)
				}
				tmp_drbtoreleaselistscgr12 = append(tmp_drbtoreleaselistscgr12, DRBIdentity(val))
			}
			return nil
		})
		if errCollection_drbtoreleaselistscgr12 != nil {
			return fmt.Errorf("decoding drb-ToReleaseListSCG-r12: %w", errCollection_drbtoreleaselistscgr12)
		}
		v.DrbToReleaseListSCGR12 = tmp_drbtoreleaselistscgr12
	}
	if opt_scelltoaddmodlistscgr12 {
		tmp_scelltoaddmodlistscgr12 := make(SCellToAddModListSCGR12, 0)
		_, errCollection_scelltoaddmodlistscgr12 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistscgr12, fragmentLength_scelltoaddmodlistscgr12 int64) error {
			for i := int64(0); i < fragmentLength_scelltoaddmodlistscgr12; i++ {
				var elem CellToAddModR12
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding sCellToAddModListSCG-r12 element %d: %w", fragmentOffset_scelltoaddmodlistscgr12+i, err)
				}
				tmp_scelltoaddmodlistscgr12 = append(tmp_scelltoaddmodlistscgr12, elem)
			}
			return nil
		})
		if errCollection_scelltoaddmodlistscgr12 != nil {
			return fmt.Errorf("decoding sCellToAddModListSCG-r12: %w", errCollection_scelltoaddmodlistscgr12)
		}
		v.SCellToAddModListSCGR12 = tmp_scelltoaddmodlistscgr12
	}
	if opt_scelltoreleaselistscgr12 {
		tmp_scelltoreleaselistscgr12 := make(SCellToReleaseListR10, 0)
		_, errCollection_scelltoreleaselistscgr12 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_scelltoreleaselistscgr12, fragmentLength_scelltoreleaselistscgr12 int64) error {
			for i := int64(0); i < fragmentLength_scelltoreleaselistscgr12; i++ {
				val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(7), false)
				if err != nil {
					return fmt.Errorf("decoding sCellToReleaseListSCG-r12 element %d: %w", fragmentOffset_scelltoreleaselistscgr12+i, err)
				}
				tmp_scelltoreleaselistscgr12 = append(tmp_scelltoreleaselistscgr12, SCellIndexR10(val))
			}
			return nil
		})
		if errCollection_scelltoreleaselistscgr12 != nil {
			return fmt.Errorf("decoding sCellToReleaseListSCG-r12: %w", errCollection_scelltoreleaselistscgr12)
		}
		v.SCellToReleaseListSCGR12 = tmp_scelltoreleaselistscgr12
	}
	if opt_pmaxr12 {
		val_pmaxr12, err := per.DecodeInteger(bb, int64Ptr(-30), int64Ptr(33), false)
		if err != nil {
			return fmt.Errorf("decoding p-Max-r12: %w", err)
		}
		tmp_pmaxr12 := PMax(val_pmaxr12)
		v.PMaxR12 = &tmp_pmaxr12
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension SCGConfigInfoV1310IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes SCGConfigInfoV1310IEs to UPER format.
func (v *SCGConfigInfoV1310IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigInfoV1310IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MeasResultSSTDR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SCellToAddModListMCGExtR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasResultServCellListSCGExtR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SCellToAddModListSCGExtR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SCellToReleaseListSCGExtR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.MeasResultSSTDR13 != nil {
		if err := v.MeasResultSSTDR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding measResultSSTD-r13: %w", err)
		}
	}
	if v.SCellToAddModListMCGExtR13 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.SCellToAddModListMCGExtR13)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistmcgextr13, fragmentLength_scelltoaddmodlistmcgextr13 int64) error {
			for _, elem := range v.SCellToAddModListMCGExtR13[fragmentOffset_scelltoaddmodlistmcgextr13 : fragmentOffset_scelltoaddmodlistmcgextr13+fragmentLength_scelltoaddmodlistmcgextr13] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding sCellToAddModListMCG-Ext-r13 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding sCellToAddModListMCG-Ext-r13: %w", err)
		}
	}
	if v.MeasResultServCellListSCGExtR13 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasResultServCellListSCGExtR13)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measresultservcelllistscgextr13, fragmentLength_measresultservcelllistscgextr13 int64) error {
			for _, elem := range v.MeasResultServCellListSCGExtR13[fragmentOffset_measresultservcelllistscgextr13 : fragmentOffset_measresultservcelllistscgextr13+fragmentLength_measresultservcelllistscgextr13] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measResultServCellListSCG-Ext-r13 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measResultServCellListSCG-Ext-r13: %w", err)
		}
	}
	if v.SCellToAddModListSCGExtR13 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.SCellToAddModListSCGExtR13)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistscgextr13, fragmentLength_scelltoaddmodlistscgextr13 int64) error {
			for _, elem := range v.SCellToAddModListSCGExtR13[fragmentOffset_scelltoaddmodlistscgextr13 : fragmentOffset_scelltoaddmodlistscgextr13+fragmentLength_scelltoaddmodlistscgextr13] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding sCellToAddModListSCG-Ext-r13 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding sCellToAddModListSCG-Ext-r13: %w", err)
		}
	}
	if v.SCellToReleaseListSCGExtR13 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.SCellToReleaseListSCGExtR13)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_scelltoreleaselistscgextr13, fragmentLength_scelltoreleaselistscgextr13 int64) error {
			for _, elem := range v.SCellToReleaseListSCGExtR13[fragmentOffset_scelltoreleaselistscgextr13 : fragmentOffset_scelltoreleaselistscgextr13+fragmentLength_scelltoreleaselistscgextr13] {
				if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(31), false); err != nil {
					return fmt.Errorf("encoding sCellToReleaseListSCG-Ext-r13 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding sCellToReleaseListSCG-Ext-r13: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigInfoV1310IEs from UPER format.
func (v *SCGConfigInfoV1310IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigInfoV1310IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigInfoV1310IEs{}
	// Read preamble bitmap for optional root fields
	opt_measresultsstdr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_scelltoaddmodlistmcgextr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measresultservcelllistscgextr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_scelltoaddmodlistscgextr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_scelltoreleaselistscgextr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_measresultsstdr13 {
		var dec_measresultsstdr13 MeasResultSSTDR13
		if err := dec_measresultsstdr13.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding measResultSSTD-r13: %w", err)
		}
		v.MeasResultSSTDR13 = &dec_measresultsstdr13
	}
	if opt_scelltoaddmodlistmcgextr13 {
		tmp_scelltoaddmodlistmcgextr13 := make(SCellToAddModListExtR13, 0)
		_, errCollection_scelltoaddmodlistmcgextr13 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistmcgextr13, fragmentLength_scelltoaddmodlistmcgextr13 int64) error {
			for i := int64(0); i < fragmentLength_scelltoaddmodlistmcgextr13; i++ {
				var elem SCellToAddModExtR13
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding sCellToAddModListMCG-Ext-r13 element %d: %w", fragmentOffset_scelltoaddmodlistmcgextr13+i, err)
				}
				tmp_scelltoaddmodlistmcgextr13 = append(tmp_scelltoaddmodlistmcgextr13, elem)
			}
			return nil
		})
		if errCollection_scelltoaddmodlistmcgextr13 != nil {
			return fmt.Errorf("decoding sCellToAddModListMCG-Ext-r13: %w", errCollection_scelltoaddmodlistmcgextr13)
		}
		v.SCellToAddModListMCGExtR13 = tmp_scelltoaddmodlistmcgextr13
	}
	if opt_measresultservcelllistscgextr13 {
		tmp_measresultservcelllistscgextr13 := make(MeasResultServCellListSCGExtR13, 0)
		_, errCollection_measresultservcelllistscgextr13 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measresultservcelllistscgextr13, fragmentLength_measresultservcelllistscgextr13 int64) error {
			for i := int64(0); i < fragmentLength_measresultservcelllistscgextr13; i++ {
				var elem MeasResultServCellSCGR12
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding measResultServCellListSCG-Ext-r13 element %d: %w", fragmentOffset_measresultservcelllistscgextr13+i, err)
				}
				tmp_measresultservcelllistscgextr13 = append(tmp_measresultservcelllistscgextr13, elem)
			}
			return nil
		})
		if errCollection_measresultservcelllistscgextr13 != nil {
			return fmt.Errorf("decoding measResultServCellListSCG-Ext-r13: %w", errCollection_measresultservcelllistscgextr13)
		}
		v.MeasResultServCellListSCGExtR13 = tmp_measresultservcelllistscgextr13
	}
	if opt_scelltoaddmodlistscgextr13 {
		tmp_scelltoaddmodlistscgextr13 := make(SCellToAddModListSCGExtR13, 0)
		_, errCollection_scelltoaddmodlistscgextr13 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistscgextr13, fragmentLength_scelltoaddmodlistscgextr13 int64) error {
			for i := int64(0); i < fragmentLength_scelltoaddmodlistscgextr13; i++ {
				var elem CellToAddModR12
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding sCellToAddModListSCG-Ext-r13 element %d: %w", fragmentOffset_scelltoaddmodlistscgextr13+i, err)
				}
				tmp_scelltoaddmodlistscgextr13 = append(tmp_scelltoaddmodlistscgextr13, elem)
			}
			return nil
		})
		if errCollection_scelltoaddmodlistscgextr13 != nil {
			return fmt.Errorf("decoding sCellToAddModListSCG-Ext-r13: %w", errCollection_scelltoaddmodlistscgextr13)
		}
		v.SCellToAddModListSCGExtR13 = tmp_scelltoaddmodlistscgextr13
	}
	if opt_scelltoreleaselistscgextr13 {
		tmp_scelltoreleaselistscgextr13 := make(SCellToReleaseListExtR13, 0)
		_, errCollection_scelltoreleaselistscgextr13 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_scelltoreleaselistscgextr13, fragmentLength_scelltoreleaselistscgextr13 int64) error {
			for i := int64(0); i < fragmentLength_scelltoreleaselistscgextr13; i++ {
				val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(31), false)
				if err != nil {
					return fmt.Errorf("decoding sCellToReleaseListSCG-Ext-r13 element %d: %w", fragmentOffset_scelltoreleaselistscgextr13+i, err)
				}
				tmp_scelltoreleaselistscgextr13 = append(tmp_scelltoreleaselistscgextr13, SCellIndexR13(val))
			}
			return nil
		})
		if errCollection_scelltoreleaselistscgextr13 != nil {
			return fmt.Errorf("decoding sCellToReleaseListSCG-Ext-r13: %w", errCollection_scelltoreleaselistscgextr13)
		}
		v.SCellToReleaseListSCGExtR13 = tmp_scelltoreleaselistscgextr13
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension SCGConfigInfoV1330IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes SCGConfigInfoV1330IEs to UPER format.
func (v *SCGConfigInfoV1330IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigInfoV1330IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MeasResultListRSSISCGR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.MeasResultListRSSISCGR13 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasResultListRSSISCGR13)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measresultlistrssiscgr13, fragmentLength_measresultlistrssiscgr13 int64) error {
			for _, elem := range v.MeasResultListRSSISCGR13[fragmentOffset_measresultlistrssiscgr13 : fragmentOffset_measresultlistrssiscgr13+fragmentLength_measresultlistrssiscgr13] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measResultListRSSI-SCG-r13 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measResultListRSSI-SCG-r13: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigInfoV1330IEs from UPER format.
func (v *SCGConfigInfoV1330IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigInfoV1330IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigInfoV1330IEs{}
	// Read preamble bitmap for optional root fields
	opt_measresultlistrssiscgr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_measresultlistrssiscgr13 {
		tmp_measresultlistrssiscgr13 := make(MeasResultListRSSISCGR13, 0)
		_, errCollection_measresultlistrssiscgr13 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measresultlistrssiscgr13, fragmentLength_measresultlistrssiscgr13 int64) error {
			for i := int64(0); i < fragmentLength_measresultlistrssiscgr13; i++ {
				var elem MeasResultRSSISCGR13
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding measResultListRSSI-SCG-r13 element %d: %w", fragmentOffset_measresultlistrssiscgr13+i, err)
				}
				tmp_measresultlistrssiscgr13 = append(tmp_measresultlistrssiscgr13, elem)
			}
			return nil
		})
		if errCollection_measresultlistrssiscgr13 != nil {
			return fmt.Errorf("decoding measResultListRSSI-SCG-r13: %w", errCollection_measresultlistrssiscgr13)
		}
		v.MeasResultListRSSISCGR13 = tmp_measresultlistrssiscgr13
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension SCGConfigInfoV1430IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes SCGConfigInfoV1430IEs to UPER format.
func (v *SCGConfigInfoV1430IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigInfoV1430IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MakeBeforeBreakSCGReqR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasGapConfigPerCCList != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.MakeBeforeBreakSCGReqR14 != nil {
		if err := per.EncodeEnumerated(bb, int64(*v.MakeBeforeBreakSCGReqR14), 1, false); err != nil {
			return fmt.Errorf("encoding makeBeforeBreakSCG-Req-r14: %w", err)
		}
	}
	if v.MeasGapConfigPerCCList != nil {
		if err := v.MeasGapConfigPerCCList.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding measGapConfigPerCC-List: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigInfoV1430IEs from UPER format.
func (v *SCGConfigInfoV1430IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigInfoV1430IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigInfoV1430IEs{}
	// Read preamble bitmap for optional root fields
	opt_makebeforebreakscgreqr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measgapconfigpercclist, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_makebeforebreakscgreqr14 {
		val_makebeforebreakscgreqr14, err := per.DecodeEnumerated(bb, 1, false)
		if err != nil {
			return fmt.Errorf("decoding makeBeforeBreakSCG-Req-r14: %w", err)
		}
		v.MakeBeforeBreakSCGReqR14 = &val_makebeforebreakscgreqr14
	}
	if opt_measgapconfigpercclist {
		var dec_measgapconfigpercclist MeasGapConfigPerCCListR14
		if err := dec_measgapconfigpercclist.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding measGapConfigPerCC-List: %w", err)
		}
		v.MeasGapConfigPerCCList = &dec_measgapconfigpercclist
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension SCGConfigInfoV1530IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes SCGConfigInfoV1530IEs to UPER format.
func (v *SCGConfigInfoV1530IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigInfoV1530IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.DrbToAddModListSCGR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.DrbToReleaseListSCGR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.DrbToAddModListSCGR15 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.DrbToAddModListSCGR15)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 15, HasUpper: true}, false, func(fragmentOffset_drbtoaddmodlistscgr15, fragmentLength_drbtoaddmodlistscgr15 int64) error {
			for _, elem := range v.DrbToAddModListSCGR15[fragmentOffset_drbtoaddmodlistscgr15 : fragmentOffset_drbtoaddmodlistscgr15+fragmentLength_drbtoaddmodlistscgr15] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding drb-ToAddModListSCG-r15 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding drb-ToAddModListSCG-r15: %w", err)
		}
	}
	if v.DrbToReleaseListSCGR15 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.DrbToReleaseListSCGR15)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 15, HasUpper: true}, false, func(fragmentOffset_drbtoreleaselistscgr15, fragmentLength_drbtoreleaselistscgr15 int64) error {
			for _, elem := range v.DrbToReleaseListSCGR15[fragmentOffset_drbtoreleaselistscgr15 : fragmentOffset_drbtoreleaselistscgr15+fragmentLength_drbtoreleaselistscgr15] {
				if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(32), false); err != nil {
					return fmt.Errorf("encoding drb-ToReleaseListSCG-r15 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding drb-ToReleaseListSCG-r15: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigInfoV1530IEs from UPER format.
func (v *SCGConfigInfoV1530IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigInfoV1530IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigInfoV1530IEs{}
	// Read preamble bitmap for optional root fields
	opt_drbtoaddmodlistscgr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_drbtoreleaselistscgr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_drbtoaddmodlistscgr15 {
		tmp_drbtoaddmodlistscgr15 := make(DRBInfoListSCGR15, 0)
		_, errCollection_drbtoaddmodlistscgr15 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 15, HasUpper: true}, false, func(fragmentOffset_drbtoaddmodlistscgr15, fragmentLength_drbtoaddmodlistscgr15 int64) error {
			for i := int64(0); i < fragmentLength_drbtoaddmodlistscgr15; i++ {
				var elem DRBInfoSCGR12
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding drb-ToAddModListSCG-r15 element %d: %w", fragmentOffset_drbtoaddmodlistscgr15+i, err)
				}
				tmp_drbtoaddmodlistscgr15 = append(tmp_drbtoaddmodlistscgr15, elem)
			}
			return nil
		})
		if errCollection_drbtoaddmodlistscgr15 != nil {
			return fmt.Errorf("decoding drb-ToAddModListSCG-r15: %w", errCollection_drbtoaddmodlistscgr15)
		}
		v.DrbToAddModListSCGR15 = tmp_drbtoaddmodlistscgr15
	}
	if opt_drbtoreleaselistscgr15 {
		tmp_drbtoreleaselistscgr15 := make(DRBToReleaseListR15, 0)
		_, errCollection_drbtoreleaselistscgr15 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 15, HasUpper: true}, false, func(fragmentOffset_drbtoreleaselistscgr15, fragmentLength_drbtoreleaselistscgr15 int64) error {
			for i := int64(0); i < fragmentLength_drbtoreleaselistscgr15; i++ {
				val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(32), false)
				if err != nil {
					return fmt.Errorf("decoding drb-ToReleaseListSCG-r15 element %d: %w", fragmentOffset_drbtoreleaselistscgr15+i, err)
				}
				tmp_drbtoreleaselistscgr15 = append(tmp_drbtoreleaselistscgr15, DRBIdentity(val))
			}
			return nil
		})
		if errCollection_drbtoreleaselistscgr15 != nil {
			return fmt.Errorf("decoding drb-ToReleaseListSCG-r15: %w", errCollection_drbtoreleaselistscgr15)
		}
		v.DrbToReleaseListSCGR15 = tmp_drbtoreleaselistscgr15
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension SCGConfigInfoV1530IEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

type asn1cUPERDRBInfoListSCGR12ListValue struct{ Value DRBInfoListSCGR12 }

// MarshalUPERDRBInfoListSCGR12 encodes a DRBInfoListSCGR12 list to UPER.
func MarshalUPERDRBInfoListSCGR12(list DRBInfoListSCGR12) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERDRBInfoListSCGR12To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERDRBInfoListSCGR12To appends a DRBInfoListSCGR12 list to bb.
func MarshalUPERDRBInfoListSCGR12To(list DRBInfoListSCGR12, bb *per.BitBuffer) error {
	v := asn1cUPERDRBInfoListSCGR12ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 11, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERDRBInfoListSCGR12 decodes a DRBInfoListSCGR12 list from UPER.
func UnmarshalUPERDRBInfoListSCGR12(data []byte) (DRBInfoListSCGR12, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERDRBInfoListSCGR12From(bb)
}

// UnmarshalUPERDRBInfoListSCGR12From decodes a DRBInfoListSCGR12 list from bb.
func UnmarshalUPERDRBInfoListSCGR12From(bb *per.BitBuffer) (DRBInfoListSCGR12, error) {
	var v asn1cUPERDRBInfoListSCGR12ListValue
	if err := unmarshalUPERDRBInfoListSCGR12Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERDRBInfoListSCGR12Into(v *asn1cUPERDRBInfoListSCGR12ListValue, bb *per.BitBuffer) error {
	v.Value = make(DRBInfoListSCGR12, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 11, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem DRBInfoSCGR12
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

type asn1cUPERDRBInfoListSCGR15ListValue struct{ Value DRBInfoListSCGR15 }

// MarshalUPERDRBInfoListSCGR15 encodes a DRBInfoListSCGR15 list to UPER.
func MarshalUPERDRBInfoListSCGR15(list DRBInfoListSCGR15) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERDRBInfoListSCGR15To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERDRBInfoListSCGR15To appends a DRBInfoListSCGR15 list to bb.
func MarshalUPERDRBInfoListSCGR15To(list DRBInfoListSCGR15, bb *per.BitBuffer) error {
	v := asn1cUPERDRBInfoListSCGR15ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 15, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERDRBInfoListSCGR15 decodes a DRBInfoListSCGR15 list from UPER.
func UnmarshalUPERDRBInfoListSCGR15(data []byte) (DRBInfoListSCGR15, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERDRBInfoListSCGR15From(bb)
}

// UnmarshalUPERDRBInfoListSCGR15From decodes a DRBInfoListSCGR15 list from bb.
func UnmarshalUPERDRBInfoListSCGR15From(bb *per.BitBuffer) (DRBInfoListSCGR15, error) {
	var v asn1cUPERDRBInfoListSCGR15ListValue
	if err := unmarshalUPERDRBInfoListSCGR15Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERDRBInfoListSCGR15Into(v *asn1cUPERDRBInfoListSCGR15ListValue, bb *per.BitBuffer) error {
	v.Value = make(DRBInfoListSCGR15, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 15, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem DRBInfoSCGR12
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

// MarshalUPER encodes DRBInfoSCGR12 to UPER format.
func (v *DRBInfoSCGR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *DRBInfoSCGR12) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.EpsBearerIdentityR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.DrbTypeR12 != nil); err != nil {
		return err
	}
	if v.EpsBearerIdentityR12 != nil {
		if err := per.EncodeInteger(bb, int64(*v.EpsBearerIdentityR12), int64Ptr(0), int64Ptr(15), false); err != nil {
			return fmt.Errorf("encoding eps-BearerIdentity-r12: %w", err)
		}
	}
	if err := per.EncodeInteger(bb, int64(v.DrbIdentityR12), int64Ptr(1), int64Ptr(32), false); err != nil {
		return fmt.Errorf("encoding drb-Identity-r12: %w", err)
	}
	if v.DrbTypeR12 != nil {
		if err := per.EncodeEnumerated(bb, int64(*v.DrbTypeR12), 2, false); err != nil {
			return fmt.Errorf("encoding drb-Type-r12: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegative(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i] {
				if i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil {
					if err := per.EncodeOpenType(bb, v.ExtData_[i]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes DRBInfoSCGR12 from UPER format.
func (v *DRBInfoSCGR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *DRBInfoSCGR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = DRBInfoSCGR12{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_epsbeareridentityr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_drbtyper12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_epsbeareridentityr12 {
		val_epsbeareridentityr12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(15), false)
		if err != nil {
			return fmt.Errorf("decoding eps-BearerIdentity-r12: %w", err)
		}
		v.EpsBearerIdentityR12 = &val_epsbeareridentityr12
	}
	val_drbidentityr12, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(32), false)
	if err != nil {
		return fmt.Errorf("decoding drb-Identity-r12: %w", err)
	}
	v.DrbIdentityR12 = DRBIdentity(val_drbidentityr12)
	if opt_drbtyper12 {
		val_drbtyper12, err := per.DecodeEnumerated(bb, 2, false)
		if err != nil {
			return fmt.Errorf("decoding drb-Type-r12: %w", err)
		}
		v.DrbTypeR12 = &val_drbtyper12
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cUPERSCellToAddModListSCGR12ListValue struct{ Value SCellToAddModListSCGR12 }

// MarshalUPERSCellToAddModListSCGR12 encodes a SCellToAddModListSCGR12 list to UPER.
func MarshalUPERSCellToAddModListSCGR12(list SCellToAddModListSCGR12) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSCellToAddModListSCGR12To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSCellToAddModListSCGR12To appends a SCellToAddModListSCGR12 list to bb.
func MarshalUPERSCellToAddModListSCGR12To(list SCellToAddModListSCGR12, bb *per.BitBuffer) error {
	v := asn1cUPERSCellToAddModListSCGR12ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERSCellToAddModListSCGR12 decodes a SCellToAddModListSCGR12 list from UPER.
func UnmarshalUPERSCellToAddModListSCGR12(data []byte) (SCellToAddModListSCGR12, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSCellToAddModListSCGR12From(bb)
}

// UnmarshalUPERSCellToAddModListSCGR12From decodes a SCellToAddModListSCGR12 list from bb.
func UnmarshalUPERSCellToAddModListSCGR12From(bb *per.BitBuffer) (SCellToAddModListSCGR12, error) {
	var v asn1cUPERSCellToAddModListSCGR12ListValue
	if err := unmarshalUPERSCellToAddModListSCGR12Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSCellToAddModListSCGR12Into(v *asn1cUPERSCellToAddModListSCGR12ListValue, bb *per.BitBuffer) error {
	v.Value = make(SCellToAddModListSCGR12, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem CellToAddModR12
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

type asn1cUPERSCellToAddModListSCGExtR13ListValue struct{ Value SCellToAddModListSCGExtR13 }

// MarshalUPERSCellToAddModListSCGExtR13 encodes a SCellToAddModListSCGExtR13 list to UPER.
func MarshalUPERSCellToAddModListSCGExtR13(list SCellToAddModListSCGExtR13) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSCellToAddModListSCGExtR13To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSCellToAddModListSCGExtR13To appends a SCellToAddModListSCGExtR13 list to bb.
func MarshalUPERSCellToAddModListSCGExtR13To(list SCellToAddModListSCGExtR13, bb *per.BitBuffer) error {
	v := asn1cUPERSCellToAddModListSCGExtR13ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERSCellToAddModListSCGExtR13 decodes a SCellToAddModListSCGExtR13 list from UPER.
func UnmarshalUPERSCellToAddModListSCGExtR13(data []byte) (SCellToAddModListSCGExtR13, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSCellToAddModListSCGExtR13From(bb)
}

// UnmarshalUPERSCellToAddModListSCGExtR13From decodes a SCellToAddModListSCGExtR13 list from bb.
func UnmarshalUPERSCellToAddModListSCGExtR13From(bb *per.BitBuffer) (SCellToAddModListSCGExtR13, error) {
	var v asn1cUPERSCellToAddModListSCGExtR13ListValue
	if err := unmarshalUPERSCellToAddModListSCGExtR13Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSCellToAddModListSCGExtR13Into(v *asn1cUPERSCellToAddModListSCGExtR13ListValue, bb *per.BitBuffer) error {
	v.Value = make(SCellToAddModListSCGExtR13, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem CellToAddModR12
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

// MarshalUPER encodes CellToAddModR12 to UPER format.
func (v *CellToAddModR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CellToAddModR12) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.SCellIndexR13 != nil || v.MeasResultCellToAddV1310 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.CellIdentificationR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasResultCellToAddR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeInteger(bb, int64(v.SCellIndexR12), int64Ptr(1), int64Ptr(7), false); err != nil {
		return fmt.Errorf("encoding sCellIndex-r12: %w", err)
	}
	if v.CellIdentificationR12 != nil {
		if err := v.CellIdentificationR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding cellIdentification-r12: %w", err)
		}
	}
	if v.MeasResultCellToAddR12 != nil {
		if err := v.MeasResultCellToAddR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding measResultCellToAdd-r12: %w", err)
		}
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.SCellIndexR13 != nil || v.MeasResultCellToAddV1310 != nil {
			extHighest = 0
		}
		if v.ExtCount_ > extHighest {
			extHighest = v.ExtCount_
		}
		if err := per.EncodeNormallySmallNonNegative(bb, extHighest); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SCellIndexR13 != nil || v.MeasResultCellToAddV1310 != nil
			if err := per.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		for i := int64(1); i <= extHighest; i++ {
			p := i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SCellIndexR13 != nil || v.MeasResultCellToAddV1310 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SCellIndexR13 != nil); err != nil {
				return err
			}
			if err := per.EncodeBoolean(extBuf, v.MeasResultCellToAddV1310 != nil); err != nil {
				return err
			}
			if v.SCellIndexR13 != nil {
				if err := per.EncodeInteger(extBuf, int64(*v.SCellIndexR13), int64Ptr(1), int64Ptr(31), false); err != nil {
					return fmt.Errorf("encoding sCellIndex-r13: %w", err)
				}
			}
			if v.MeasResultCellToAddV1310 != nil {
				if err := v.MeasResultCellToAddV1310.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding measResultCellToAdd-v1310: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		for i := int64(1); i <= extHighest; i++ {
			if i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i] {
				if i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil {
					if err := per.EncodeOpenType(bb, v.ExtData_[i]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes CellToAddModR12 from UPER format.
func (v *CellToAddModR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *CellToAddModR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = CellToAddModR12{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_cellidentificationr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measresultcelltoaddr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_scellindexr12, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(7), false)
	if err != nil {
		return fmt.Errorf("decoding sCellIndex-r12: %w", err)
	}
	v.SCellIndexR12 = SCellIndexR10(val_scellindexr12)
	if opt_cellidentificationr12 {
		var dec_cellidentificationr12 CellToAddModR12CellIdentificationR12
		if err := dec_cellidentificationr12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding cellIdentification-r12: %w", err)
		}
		v.CellIdentificationR12 = &dec_cellidentificationr12
	}
	if opt_measresultcelltoaddr12 {
		var dec_measresultcelltoaddr12 CellToAddModR12MeasResultCellToAddR12
		if err := dec_measresultcelltoaddr12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding measResultCellToAdd-r12: %w", err)
		}
		v.MeasResultCellToAddR12 = &dec_measresultcelltoaddr12
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtPresent_ = extPresent
		if int64(0) <= extCount && extPresent[0] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_scellindexr13, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			ext_opt_measresultcelltoaddv1310, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_scellindexr13 {
				val_scellindexr13, err := per.DecodeInteger(extBB, int64Ptr(1), int64Ptr(31), false)
				if err != nil {
					return fmt.Errorf("decoding sCellIndex-r13: %w", err)
				}
				tmp_scellindexr13 := SCellIndexR13(val_scellindexr13)
				v.SCellIndexR13 = &tmp_scellindexr13
			}
			if ext_opt_measresultcelltoaddv1310 {
				var dec_measresultcelltoaddv1310 CellToAddModR12MeasResultCellToAddV1310
				if err := dec_measresultcelltoaddv1310.UnmarshalUPERFrom(extBB); err != nil {
					return fmt.Errorf("decoding measResultCellToAdd-v1310: %w", err)
				}
				v.MeasResultCellToAddV1310 = &dec_measresultcelltoaddv1310
			}
		}
		v.ExtData_ = make([][]byte, extCount+1)
		for i := int64(1); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cUPERMeasResultServCellListSCGR12ListValue struct{ Value MeasResultServCellListSCGR12 }

// MarshalUPERMeasResultServCellListSCGR12 encodes a MeasResultServCellListSCGR12 list to UPER.
func MarshalUPERMeasResultServCellListSCGR12(list MeasResultServCellListSCGR12) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERMeasResultServCellListSCGR12To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERMeasResultServCellListSCGR12To appends a MeasResultServCellListSCGR12 list to bb.
func MarshalUPERMeasResultServCellListSCGR12To(list MeasResultServCellListSCGR12, bb *per.BitBuffer) error {
	v := asn1cUPERMeasResultServCellListSCGR12ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERMeasResultServCellListSCGR12 decodes a MeasResultServCellListSCGR12 list from UPER.
func UnmarshalUPERMeasResultServCellListSCGR12(data []byte) (MeasResultServCellListSCGR12, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERMeasResultServCellListSCGR12From(bb)
}

// UnmarshalUPERMeasResultServCellListSCGR12From decodes a MeasResultServCellListSCGR12 list from bb.
func UnmarshalUPERMeasResultServCellListSCGR12From(bb *per.BitBuffer) (MeasResultServCellListSCGR12, error) {
	var v asn1cUPERMeasResultServCellListSCGR12ListValue
	if err := unmarshalUPERMeasResultServCellListSCGR12Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERMeasResultServCellListSCGR12Into(v *asn1cUPERMeasResultServCellListSCGR12ListValue, bb *per.BitBuffer) error {
	v.Value = make(MeasResultServCellListSCGR12, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem MeasResultServCellSCGR12
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

type asn1cUPERMeasResultServCellListSCGExtR13ListValue struct {
	Value MeasResultServCellListSCGExtR13
}

// MarshalUPERMeasResultServCellListSCGExtR13 encodes a MeasResultServCellListSCGExtR13 list to UPER.
func MarshalUPERMeasResultServCellListSCGExtR13(list MeasResultServCellListSCGExtR13) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERMeasResultServCellListSCGExtR13To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERMeasResultServCellListSCGExtR13To appends a MeasResultServCellListSCGExtR13 list to bb.
func MarshalUPERMeasResultServCellListSCGExtR13To(list MeasResultServCellListSCGExtR13, bb *per.BitBuffer) error {
	v := asn1cUPERMeasResultServCellListSCGExtR13ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERMeasResultServCellListSCGExtR13 decodes a MeasResultServCellListSCGExtR13 list from UPER.
func UnmarshalUPERMeasResultServCellListSCGExtR13(data []byte) (MeasResultServCellListSCGExtR13, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERMeasResultServCellListSCGExtR13From(bb)
}

// UnmarshalUPERMeasResultServCellListSCGExtR13From decodes a MeasResultServCellListSCGExtR13 list from bb.
func UnmarshalUPERMeasResultServCellListSCGExtR13From(bb *per.BitBuffer) (MeasResultServCellListSCGExtR13, error) {
	var v asn1cUPERMeasResultServCellListSCGExtR13ListValue
	if err := unmarshalUPERMeasResultServCellListSCGExtR13Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERMeasResultServCellListSCGExtR13Into(v *asn1cUPERMeasResultServCellListSCGExtR13ListValue, bb *per.BitBuffer) error {
	v.Value = make(MeasResultServCellListSCGExtR13, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem MeasResultServCellSCGR12
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

// MarshalUPER encodes MeasResultServCellSCGR12 to UPER format.
func (v *MeasResultServCellSCGR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *MeasResultServCellSCGR12) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.ServCellIdR13 != nil || v.MeasResultSCellV1310 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeInteger(bb, int64(v.ServCellIdR12), int64Ptr(0), int64Ptr(7), false); err != nil {
		return fmt.Errorf("encoding servCellId-r12: %w", err)
	}
	if err := v.MeasResultSCellR12.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding measResultSCell-r12: %w", err)
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.ServCellIdR13 != nil || v.MeasResultSCellV1310 != nil {
			extHighest = 0
		}
		if v.ExtCount_ > extHighest {
			extHighest = v.ExtCount_
		}
		if err := per.EncodeNormallySmallNonNegative(bb, extHighest); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.ServCellIdR13 != nil || v.MeasResultSCellV1310 != nil
			if err := per.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		for i := int64(1); i <= extHighest; i++ {
			p := i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.ServCellIdR13 != nil || v.MeasResultSCellV1310 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.ServCellIdR13 != nil); err != nil {
				return err
			}
			if err := per.EncodeBoolean(extBuf, v.MeasResultSCellV1310 != nil); err != nil {
				return err
			}
			if v.ServCellIdR13 != nil {
				if err := per.EncodeInteger(extBuf, int64(*v.ServCellIdR13), int64Ptr(0), int64Ptr(31), false); err != nil {
					return fmt.Errorf("encoding servCellId-r13: %w", err)
				}
			}
			if v.MeasResultSCellV1310 != nil {
				if err := v.MeasResultSCellV1310.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding measResultSCell-v1310: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		for i := int64(1); i <= extHighest; i++ {
			if i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i] {
				if i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil {
					if err := per.EncodeOpenType(bb, v.ExtData_[i]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes MeasResultServCellSCGR12 from UPER format.
func (v *MeasResultServCellSCGR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *MeasResultServCellSCGR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = MeasResultServCellSCGR12{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_servcellidr12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(7), false)
	if err != nil {
		return fmt.Errorf("decoding servCellId-r12: %w", err)
	}
	v.ServCellIdR12 = ServCellIndexR10(val_servcellidr12)
	if err := v.MeasResultSCellR12.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding measResultSCell-r12: %w", err)
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtPresent_ = extPresent
		if int64(0) <= extCount && extPresent[0] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_servcellidr13, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			ext_opt_measresultscellv1310, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_servcellidr13 {
				val_servcellidr13, err := per.DecodeInteger(extBB, int64Ptr(0), int64Ptr(31), false)
				if err != nil {
					return fmt.Errorf("decoding servCellId-r13: %w", err)
				}
				tmp_servcellidr13 := ServCellIndexR13(val_servcellidr13)
				v.ServCellIdR13 = &tmp_servcellidr13
			}
			if ext_opt_measresultscellv1310 {
				var dec_measresultscellv1310 MeasResultServCellSCGR12MeasResultSCellV1310
				if err := dec_measresultscellv1310.UnmarshalUPERFrom(extBB); err != nil {
					return fmt.Errorf("decoding measResultSCell-v1310: %w", err)
				}
				v.MeasResultSCellV1310 = &dec_measresultscellv1310
			}
		}
		v.ExtData_ = make([][]byte, extCount+1)
		for i := int64(1); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cUPERMeasResultListRSSISCGR13ListValue struct{ Value MeasResultListRSSISCGR13 }

// MarshalUPERMeasResultListRSSISCGR13 encodes a MeasResultListRSSISCGR13 list to UPER.
func MarshalUPERMeasResultListRSSISCGR13(list MeasResultListRSSISCGR13) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERMeasResultListRSSISCGR13To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERMeasResultListRSSISCGR13To appends a MeasResultListRSSISCGR13 list to bb.
func MarshalUPERMeasResultListRSSISCGR13To(list MeasResultListRSSISCGR13, bb *per.BitBuffer) error {
	v := asn1cUPERMeasResultListRSSISCGR13ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERMeasResultListRSSISCGR13 decodes a MeasResultListRSSISCGR13 list from UPER.
func UnmarshalUPERMeasResultListRSSISCGR13(data []byte) (MeasResultListRSSISCGR13, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERMeasResultListRSSISCGR13From(bb)
}

// UnmarshalUPERMeasResultListRSSISCGR13From decodes a MeasResultListRSSISCGR13 list from bb.
func UnmarshalUPERMeasResultListRSSISCGR13From(bb *per.BitBuffer) (MeasResultListRSSISCGR13, error) {
	var v asn1cUPERMeasResultListRSSISCGR13ListValue
	if err := unmarshalUPERMeasResultListRSSISCGR13Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERMeasResultListRSSISCGR13Into(v *asn1cUPERMeasResultListRSSISCGR13ListValue, bb *per.BitBuffer) error {
	v.Value = make(MeasResultListRSSISCGR13, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem MeasResultRSSISCGR13
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

// MarshalUPER encodes MeasResultRSSISCGR13 to UPER format.
func (v *MeasResultRSSISCGR13) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *MeasResultRSSISCGR13) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.ServCellIdR13), int64Ptr(0), int64Ptr(31), false); err != nil {
		return fmt.Errorf("encoding servCellId-r13: %w", err)
	}
	if err := v.MeasResultForRSSIR13.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding measResultForRSSI-r13: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes MeasResultRSSISCGR13 from UPER format.
func (v *MeasResultRSSISCGR13) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *MeasResultRSSISCGR13) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = MeasResultRSSISCGR13{}
	val_servcellidr13, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(31), false)
	if err != nil {
		return fmt.Errorf("decoding servCellId-r13: %w", err)
	}
	v.ServCellIdR13 = ServCellIndexR13(val_servcellidr13)
	if err := v.MeasResultForRSSIR13.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding measResultForRSSI-r13: %w", err)
	}
	return nil
}

// MarshalUPER encodes SCGConfigRestrictInfoR12 to UPER format.
func (v *SCGConfigRestrictInfoR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigRestrictInfoR12) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.MaxSCHTBBitsDLR12), int64Ptr(1), int64Ptr(100), false); err != nil {
		return fmt.Errorf("encoding maxSCH-TB-BitsDL-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.MaxSCHTBBitsULR12), int64Ptr(1), int64Ptr(100), false); err != nil {
		return fmt.Errorf("encoding maxSCH-TB-BitsUL-r12: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigRestrictInfoR12 from UPER format.
func (v *SCGConfigRestrictInfoR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigRestrictInfoR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigRestrictInfoR12{}
	val_maxschtbbitsdlr12, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(100), false)
	if err != nil {
		return fmt.Errorf("decoding maxSCH-TB-BitsDL-r12: %w", err)
	}
	v.MaxSCHTBBitsDLR12 = val_maxschtbbitsdlr12
	val_maxschtbbitsulr12, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(100), false)
	if err != nil {
		return fmt.Errorf("decoding maxSCH-TB-BitsUL-r12: %w", err)
	}
	v.MaxSCHTBBitsULR12 = val_maxschtbbitsulr12
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformation to UPER format.
func (v *UEPagingCoverageInformation) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UEPagingCoverageInformation) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CriticalExtensions.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding criticalExtensions: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformation from UPER format.
func (v *UEPagingCoverageInformation) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UEPagingCoverageInformation) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformation{}
	if err := v.CriticalExtensions.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding criticalExtensions: %w", err)
	}
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationR13IEs to UPER format.
func (v *UEPagingCoverageInformationR13IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UEPagingCoverageInformationR13IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MpdcchNumRepetitionR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.MpdcchNumRepetitionR13 != nil {
		if err := per.EncodeInteger(bb, int64(*v.MpdcchNumRepetitionR13), int64Ptr(1), int64Ptr(256), false); err != nil {
			return fmt.Errorf("encoding mpdcch-NumRepetition-r13: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationR13IEs from UPER format.
func (v *UEPagingCoverageInformationR13IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UEPagingCoverageInformationR13IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationR13IEs{}
	// Read preamble bitmap for optional root fields
	opt_mpdcchnumrepetitionr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_mpdcchnumrepetitionr13 {
		val_mpdcchnumrepetitionr13, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(256), false)
		if err != nil {
			return fmt.Errorf("decoding mpdcch-NumRepetition-r13: %w", err)
		}
		v.MpdcchNumRepetitionR13 = &val_mpdcchnumrepetitionr13
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension UEPagingCoverageInformationR13IEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformation to UPER format.
func (v *UERadioAccessCapabilityInformation) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioAccessCapabilityInformation) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CriticalExtensions.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding criticalExtensions: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformation from UPER format.
func (v *UERadioAccessCapabilityInformation) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioAccessCapabilityInformation) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformation{}
	if err := v.CriticalExtensions.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding criticalExtensions: %w", err)
	}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationR8IEs to UPER format.
func (v *UERadioAccessCapabilityInformationR8IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioAccessCapabilityInformationR8IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	containedBB_ueradioaccesscapabilityinfo := per.NewBitBuffer()
	if err := (v.UeRadioAccessCapabilityInfo).MarshalUPERTo(containedBB_ueradioaccesscapabilityinfo); err != nil {
		return fmt.Errorf("encoding contained ue-RadioAccessCapabilityInfo: %w", err)
	}
	if err := per.EncodeOctetStringExt(bb, containedBB_ueradioaccesscapabilityinfo.Bytes(), 0, 0, false, false); err != nil {
		return fmt.Errorf("encoding ue-RadioAccessCapabilityInfo: %w", err)
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationR8IEs from UPER format.
func (v *UERadioAccessCapabilityInformationR8IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioAccessCapabilityInformationR8IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationR8IEs{}
	// Read preamble bitmap for optional root fields
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	containedBytes_ueradioaccesscapabilityinfo, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
	if err != nil {
		return fmt.Errorf("decoding ue-RadioAccessCapabilityInfo: %w", err)
	}
	var contained_ueradioaccesscapabilityinfo UECapabilityInformation
	if err := contained_ueradioaccesscapabilityinfo.UnmarshalUPER(containedBytes_ueradioaccesscapabilityinfo); err != nil {
		return fmt.Errorf("decoding contained ue-RadioAccessCapabilityInfo: %w", err)
	}
	v.UeRadioAccessCapabilityInfo = contained_ueradioaccesscapabilityinfo
	if opt_noncriticalextension {
		var dec_noncriticalextension UERadioAccessCapabilityInformationR8IEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes UERadioPagingInformation to UPER format.
func (v *UERadioPagingInformation) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioPagingInformation) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CriticalExtensions.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding criticalExtensions: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformation from UPER format.
func (v *UERadioPagingInformation) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioPagingInformation) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformation{}
	if err := v.CriticalExtensions.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding criticalExtensions: %w", err)
	}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationR12IEs to UPER format.
func (v *UERadioPagingInformationR12IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioPagingInformationR12IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	containedBB_ueradiopaginginfor12 := per.NewBitBuffer()
	if err := (v.UeRadioPagingInfoR12).MarshalUPERTo(containedBB_ueradiopaginginfor12); err != nil {
		return fmt.Errorf("encoding contained ue-RadioPagingInfo-r12: %w", err)
	}
	if err := per.EncodeOctetStringExt(bb, containedBB_ueradiopaginginfor12.Bytes(), 0, 0, false, false); err != nil {
		return fmt.Errorf("encoding ue-RadioPagingInfo-r12: %w", err)
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationR12IEs from UPER format.
func (v *UERadioPagingInformationR12IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioPagingInformationR12IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationR12IEs{}
	// Read preamble bitmap for optional root fields
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	containedBytes_ueradiopaginginfor12, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
	if err != nil {
		return fmt.Errorf("decoding ue-RadioPagingInfo-r12: %w", err)
	}
	var contained_ueradiopaginginfor12 UERadioPagingInfoR12
	if err := contained_ueradiopaginginfor12.UnmarshalUPER(containedBytes_ueradiopaginginfor12); err != nil {
		return fmt.Errorf("decoding contained ue-RadioPagingInfo-r12: %w", err)
	}
	v.UeRadioPagingInfoR12 = contained_ueradiopaginginfor12
	if opt_noncriticalextension {
		var dec_noncriticalextension UERadioPagingInformationV1310IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationV1310IEs to UPER format.
func (v *UERadioPagingInformationV1310IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioPagingInformationV1310IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SupportedBandListEUTRAForPagingR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.SupportedBandListEUTRAForPagingR13 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.SupportedBandListEUTRAForPagingR13)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, false, func(fragmentOffset_supportedbandlisteutraforpagingr13, fragmentLength_supportedbandlisteutraforpagingr13 int64) error {
			for _, elem := range v.SupportedBandListEUTRAForPagingR13[fragmentOffset_supportedbandlisteutraforpagingr13 : fragmentOffset_supportedbandlisteutraforpagingr13+fragmentLength_supportedbandlisteutraforpagingr13] {
				if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(256), false); err != nil {
					return fmt.Errorf("encoding supportedBandListEUTRAForPaging-r13 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding supportedBandListEUTRAForPaging-r13: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationV1310IEs from UPER format.
func (v *UERadioPagingInformationV1310IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioPagingInformationV1310IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationV1310IEs{}
	// Read preamble bitmap for optional root fields
	opt_supportedbandlisteutraforpagingr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_supportedbandlisteutraforpagingr13 {
		tmp_supportedbandlisteutraforpagingr13 := make(UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13, 0)
		_, errCollection_supportedbandlisteutraforpagingr13 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, false, func(fragmentOffset_supportedbandlisteutraforpagingr13, fragmentLength_supportedbandlisteutraforpagingr13 int64) error {
			for i := int64(0); i < fragmentLength_supportedbandlisteutraforpagingr13; i++ {
				val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(256), false)
				if err != nil {
					return fmt.Errorf("decoding supportedBandListEUTRAForPaging-r13 element %d: %w", fragmentOffset_supportedbandlisteutraforpagingr13+i, err)
				}
				tmp_supportedbandlisteutraforpagingr13 = append(tmp_supportedbandlisteutraforpagingr13, FreqBandIndicatorR11(val))
			}
			return nil
		})
		if errCollection_supportedbandlisteutraforpagingr13 != nil {
			return fmt.Errorf("decoding supportedBandListEUTRAForPaging-r13: %w", errCollection_supportedbandlisteutraforpagingr13)
		}
		v.SupportedBandListEUTRAForPagingR13 = tmp_supportedbandlisteutraforpagingr13
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension UERadioPagingInformationV1610IEs
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationV1610IEs to UPER format.
func (v *UERadioPagingInformationV1610IEs) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioPagingInformationV1610IEs) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AccessStratumReleaseR16 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NonCriticalExtension != nil); err != nil {
		return err
	}
	if v.AccessStratumReleaseR16 != nil {
		if err := per.EncodeEnumerated(bb, int64(*v.AccessStratumReleaseR16), 1, false); err != nil {
			return fmt.Errorf("encoding accessStratumRelease-r16: %w", err)
		}
	}
	if v.NonCriticalExtension != nil {
		if err := v.NonCriticalExtension.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nonCriticalExtension: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationV1610IEs from UPER format.
func (v *UERadioPagingInformationV1610IEs) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioPagingInformationV1610IEs) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationV1610IEs{}
	// Read preamble bitmap for optional root fields
	opt_accessstratumreleaser16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_noncriticalextension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_accessstratumreleaser16 {
		val_accessstratumreleaser16, err := per.DecodeEnumerated(bb, 1, false)
		if err != nil {
			return fmt.Errorf("decoding accessStratumRelease-r16: %w", err)
		}
		v.AccessStratumReleaseR16 = &val_accessstratumreleaser16
	}
	if opt_noncriticalextension {
		var dec_noncriticalextension UERadioPagingInformationV1610IEsNonCriticalExtension
		if err := dec_noncriticalextension.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding nonCriticalExtension: %w", err)
		}
		v.NonCriticalExtension = &dec_noncriticalextension
	}
	return nil
}

// MarshalUPER encodes ASConfig to UPER format.
func (v *ASConfig) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfig) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.SourceSystemInformationBlockType1Ext != nil || v.SourceOtherConfigR9 != nil || v.SourceSCellConfigListR10 != nil || v.SourceConfigSCGR12 != nil || v.AsConfigNRR15 != nil || v.AsConfigV1550 != nil || v.AsConfigNRV1570 != nil || v.AsConfigNRV1620 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := v.SourceMeasConfig.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding sourceMeasConfig: %w", err)
	}
	if err := v.SourceRadioResourceConfig.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding sourceRadioResourceConfig: %w", err)
	}
	if err := v.SourceSecurityAlgorithmConfig.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding sourceSecurityAlgorithmConfig: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.SourceUEIdentity.Bytes, v.SourceUEIdentity.BitLength, 16, 16, true, false); err != nil {
		return fmt.Errorf("encoding sourceUE-Identity: %w", err)
	}
	if err := v.SourceMasterInformationBlock.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding sourceMasterInformationBlock: %w", err)
	}
	if v.SourceSystemInformationBlockType1.NonCriticalExtension != nil {
		return fmt.Errorf("encoding SourceSystemInformationBlockType1 violates WITH COMPONENTS: NonCriticalExtension must be absent")
	}
	if err := v.SourceSystemInformationBlockType1.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding sourceSystemInformationBlockType1: %w", err)
	}
	if err := v.SourceSystemInformationBlockType2.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding sourceSystemInformationBlockType2: %w", err)
	}
	if err := v.AntennaInfoCommon.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding antennaInfoCommon: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.SourceDlCarrierFreq), int64Ptr(0), int64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding sourceDl-CarrierFreq: %w", err)
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.SourceSystemInformationBlockType1Ext != nil || v.SourceOtherConfigR9 != nil {
			extHighest = 0
		}
		if v.SourceSCellConfigListR10 != nil {
			extHighest = 1
		}
		if v.SourceConfigSCGR12 != nil {
			extHighest = 2
		}
		if v.AsConfigNRR15 != nil {
			extHighest = 3
		}
		if v.AsConfigV1550 != nil {
			extHighest = 4
		}
		if v.AsConfigNRV1570 != nil {
			extHighest = 5
		}
		if v.AsConfigNRV1620 != nil {
			extHighest = 6
		}
		if v.ExtCount_ > extHighest {
			extHighest = v.ExtCount_
		}
		if err := per.EncodeNormallySmallNonNegative(bb, extHighest); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SourceSystemInformationBlockType1Ext != nil || v.SourceOtherConfigR9 != nil
			if err := per.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		if int64(1) <= extHighest {
			present1 := (int64(1) < int64(len(v.ExtPresent_)) && v.ExtPresent_[1]) || v.SourceSCellConfigListR10 != nil
			if err := per.EncodeBoolean(bb, present1); err != nil {
				return err
			}
		}
		if int64(2) <= extHighest {
			present2 := (int64(2) < int64(len(v.ExtPresent_)) && v.ExtPresent_[2]) || v.SourceConfigSCGR12 != nil
			if err := per.EncodeBoolean(bb, present2); err != nil {
				return err
			}
		}
		if int64(3) <= extHighest {
			present3 := (int64(3) < int64(len(v.ExtPresent_)) && v.ExtPresent_[3]) || v.AsConfigNRR15 != nil
			if err := per.EncodeBoolean(bb, present3); err != nil {
				return err
			}
		}
		if int64(4) <= extHighest {
			present4 := (int64(4) < int64(len(v.ExtPresent_)) && v.ExtPresent_[4]) || v.AsConfigV1550 != nil
			if err := per.EncodeBoolean(bb, present4); err != nil {
				return err
			}
		}
		if int64(5) <= extHighest {
			present5 := (int64(5) < int64(len(v.ExtPresent_)) && v.ExtPresent_[5]) || v.AsConfigNRV1570 != nil
			if err := per.EncodeBoolean(bb, present5); err != nil {
				return err
			}
		}
		if int64(6) <= extHighest {
			present6 := (int64(6) < int64(len(v.ExtPresent_)) && v.ExtPresent_[6]) || v.AsConfigNRV1620 != nil
			if err := per.EncodeBoolean(bb, present6); err != nil {
				return err
			}
		}
		for i := int64(7); i <= extHighest; i++ {
			p := i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SourceSystemInformationBlockType1Ext != nil || v.SourceOtherConfigR9 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SourceSystemInformationBlockType1Ext != nil); err != nil {
				return err
			}
			if v.SourceSystemInformationBlockType1Ext != nil {
				containedBB_sourcesysteminformationblocktype1ext := per.NewBitBuffer()
				if err := (*v.SourceSystemInformationBlockType1Ext).MarshalUPERTo(containedBB_sourcesysteminformationblocktype1ext); err != nil {
					return fmt.Errorf("encoding contained sourceSystemInformationBlockType1Ext: %w", err)
				}
				if err := per.EncodeOctetStringExt(extBuf, containedBB_sourcesysteminformationblocktype1ext.Bytes(), 0, 0, false, false); err != nil {
					return fmt.Errorf("encoding sourceSystemInformationBlockType1Ext: %w", err)
				}
			}
			if err := v.SourceOtherConfigR9.MarshalUPERTo(extBuf); err != nil {
				return fmt.Errorf("encoding sourceOtherConfig-r9: %w", err)
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(1) < int64(len(v.ExtPresent_)) && v.ExtPresent_[1]) || v.SourceSCellConfigListR10 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SourceSCellConfigListR10 != nil); err != nil {
				return err
			}
			if v.SourceSCellConfigListR10 != nil {
				if err := per.EncodeCollection(extBuf, int64(len(v.SourceSCellConfigListR10)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_sourcescellconfiglistr10, fragmentLength_sourcescellconfiglistr10 int64) error {
					for _, elem := range v.SourceSCellConfigListR10[fragmentOffset_sourcescellconfiglistr10 : fragmentOffset_sourcescellconfiglistr10+fragmentLength_sourcescellconfiglistr10] {
						if err := elem.MarshalUPERTo(extBuf); err != nil {
							return fmt.Errorf("encoding sourceSCellConfigList-r10 element: %w", err)
						}
					}
					return nil
				}); err != nil {
					return fmt.Errorf("encoding sourceSCellConfigList-r10: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(2) < int64(len(v.ExtPresent_)) && v.ExtPresent_[2]) || v.SourceConfigSCGR12 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SourceConfigSCGR12 != nil); err != nil {
				return err
			}
			if v.SourceConfigSCGR12 != nil {
				if err := v.SourceConfigSCGR12.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding sourceConfigSCG-r12: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(3) < int64(len(v.ExtPresent_)) && v.ExtPresent_[3]) || v.AsConfigNRR15 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.AsConfigNRR15 != nil); err != nil {
				return err
			}
			if v.AsConfigNRR15 != nil {
				if err := v.AsConfigNRR15.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding as-ConfigNR-r15: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(4) < int64(len(v.ExtPresent_)) && v.ExtPresent_[4]) || v.AsConfigV1550 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.AsConfigV1550 != nil); err != nil {
				return err
			}
			if v.AsConfigV1550 != nil {
				if err := v.AsConfigV1550.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding as-Config-v1550: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(5) < int64(len(v.ExtPresent_)) && v.ExtPresent_[5]) || v.AsConfigNRV1570 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.AsConfigNRV1570 != nil); err != nil {
				return err
			}
			if v.AsConfigNRV1570 != nil {
				if err := v.AsConfigNRV1570.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding as-ConfigNR-v1570: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(6) < int64(len(v.ExtPresent_)) && v.ExtPresent_[6]) || v.AsConfigNRV1620 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.AsConfigNRV1620 != nil); err != nil {
				return err
			}
			if v.AsConfigNRV1620 != nil {
				if err := v.AsConfigNRV1620.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding as-ConfigNR-v1620: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		for i := int64(7); i <= extHighest; i++ {
			if i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i] {
				if i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil {
					if err := per.EncodeOpenType(bb, v.ExtData_[i]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes ASConfig from UPER format.
func (v *ASConfig) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfig) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfig{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.SourceMeasConfig.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding sourceMeasConfig: %w", err)
	}
	if err := v.SourceRadioResourceConfig.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding sourceRadioResourceConfig: %w", err)
	}
	if err := v.SourceSecurityAlgorithmConfig.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding sourceSecurityAlgorithmConfig: %w", err)
	}
	bsBytes_sourceueidentity, bsBitLen_sourceueidentity, err := per.DecodeBitStringExt(bb, 16, 16, true, false)
	if err != nil {
		return fmt.Errorf("decoding sourceUE-Identity: %w", err)
	}
	v.SourceUEIdentity = runtime.BitString{Bytes: bsBytes_sourceueidentity, BitLength: bsBitLen_sourceueidentity}
	if err := v.SourceMasterInformationBlock.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding sourceMasterInformationBlock: %w", err)
	}
	if err := v.SourceSystemInformationBlockType1.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding sourceSystemInformationBlockType1: %w", err)
	}
	if v.SourceSystemInformationBlockType1.NonCriticalExtension != nil {
		return fmt.Errorf("decoded SourceSystemInformationBlockType1 violates WITH COMPONENTS: NonCriticalExtension must be absent")
	}
	if err := v.SourceSystemInformationBlockType2.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding sourceSystemInformationBlockType2: %w", err)
	}
	if err := v.AntennaInfoCommon.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding antennaInfoCommon: %w", err)
	}
	val_sourcedlcarrierfreq, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return fmt.Errorf("decoding sourceDl-CarrierFreq: %w", err)
	}
	v.SourceDlCarrierFreq = ARFCNValueEUTRA(val_sourcedlcarrierfreq)
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtPresent_ = extPresent
		if int64(0) <= extCount && extPresent[0] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_sourcesysteminformationblocktype1ext, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_sourcesysteminformationblocktype1ext {
				containedBytes_sourcesysteminformationblocktype1ext, err := per.DecodeOctetStringExt(extBB, 0, 0, false, false)
				if err != nil {
					return fmt.Errorf("decoding sourceSystemInformationBlockType1Ext: %w", err)
				}
				var contained_sourcesysteminformationblocktype1ext SystemInformationBlockType1V890IEs
				if err := contained_sourcesysteminformationblocktype1ext.UnmarshalUPER(containedBytes_sourcesysteminformationblocktype1ext); err != nil {
					return fmt.Errorf("decoding contained sourceSystemInformationBlockType1Ext: %w", err)
				}
				v.SourceSystemInformationBlockType1Ext = &contained_sourcesysteminformationblocktype1ext
			}
			var dec_sourceotherconfigr9 OtherConfigR9
			if err := dec_sourceotherconfigr9.UnmarshalUPERFrom(extBB); err != nil {
				return fmt.Errorf("decoding sourceOtherConfig-r9: %w", err)
			}
			v.SourceOtherConfigR9 = &dec_sourceotherconfigr9
		}
		if int64(1) <= extCount && extPresent[1] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_sourcescellconfiglistr10, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_sourcescellconfiglistr10 {
				tmp_sourcescellconfiglistr10 := make(SCellToAddModListR10, 0)
				_, errCollection_sourcescellconfiglistr10 := per.DecodeCollection(extBB, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_sourcescellconfiglistr10, fragmentLength_sourcescellconfiglistr10 int64) error {
					for i := int64(0); i < fragmentLength_sourcescellconfiglistr10; i++ {
						var elem SCellToAddModR10
						if err := elem.UnmarshalUPERFrom(extBB); err != nil {
							return fmt.Errorf("decoding sourceSCellConfigList-r10 element %d: %w", fragmentOffset_sourcescellconfiglistr10+i, err)
						}
						tmp_sourcescellconfiglistr10 = append(tmp_sourcescellconfiglistr10, elem)
					}
					return nil
				})
				if errCollection_sourcescellconfiglistr10 != nil {
					return fmt.Errorf("decoding sourceSCellConfigList-r10: %w", errCollection_sourcescellconfiglistr10)
				}
				v.SourceSCellConfigListR10 = tmp_sourcescellconfiglistr10
			}
		}
		if int64(2) <= extCount && extPresent[2] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_sourceconfigscgr12, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_sourceconfigscgr12 {
				var dec_sourceconfigscgr12 SCGConfigR12
				if err := dec_sourceconfigscgr12.UnmarshalUPERFrom(extBB); err != nil {
					return fmt.Errorf("decoding sourceConfigSCG-r12: %w", err)
				}
				v.SourceConfigSCGR12 = &dec_sourceconfigscgr12
			}
		}
		if int64(3) <= extCount && extPresent[3] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_asconfignrr15, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_asconfignrr15 {
				var dec_asconfignrr15 ASConfigNRR15
				if err := dec_asconfignrr15.UnmarshalUPERFrom(extBB); err != nil {
					return fmt.Errorf("decoding as-ConfigNR-r15: %w", err)
				}
				v.AsConfigNRR15 = &dec_asconfignrr15
			}
		}
		if int64(4) <= extCount && extPresent[4] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_asconfigv1550, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_asconfigv1550 {
				var dec_asconfigv1550 ASConfigV1550
				if err := dec_asconfigv1550.UnmarshalUPERFrom(extBB); err != nil {
					return fmt.Errorf("decoding as-Config-v1550: %w", err)
				}
				v.AsConfigV1550 = &dec_asconfigv1550
			}
		}
		if int64(5) <= extCount && extPresent[5] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_asconfignrv1570, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_asconfignrv1570 {
				var dec_asconfignrv1570 ASConfigNRV1570
				if err := dec_asconfignrv1570.UnmarshalUPERFrom(extBB); err != nil {
					return fmt.Errorf("decoding as-ConfigNR-v1570: %w", err)
				}
				v.AsConfigNRV1570 = &dec_asconfignrv1570
			}
		}
		if int64(6) <= extCount && extPresent[6] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_asconfignrv1620, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_asconfignrv1620 {
				var dec_asconfignrv1620 ASConfigNRV1620
				if err := dec_asconfignrv1620.UnmarshalUPERFrom(extBB); err != nil {
					return fmt.Errorf("decoding as-ConfigNR-v1620: %w", err)
				}
				v.AsConfigNRV1620 = &dec_asconfignrv1620
			}
		}
		v.ExtData_ = make([][]byte, extCount+1)
		for i := int64(7); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes ASConfigV9e0 to UPER format.
func (v *ASConfigV9e0) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigV9e0) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.SourceDlCarrierFreqV9e0), int64Ptr(65536), int64Ptr(262143), false); err != nil {
		return fmt.Errorf("encoding sourceDl-CarrierFreq-v9e0: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes ASConfigV9e0 from UPER format.
func (v *ASConfigV9e0) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigV9e0) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigV9e0{}
	val_sourcedlcarrierfreqv9e0, err := per.DecodeInteger(bb, int64Ptr(65536), int64Ptr(262143), false)
	if err != nil {
		return fmt.Errorf("decoding sourceDl-CarrierFreq-v9e0: %w", err)
	}
	v.SourceDlCarrierFreqV9e0 = ARFCNValueEUTRAV9e0(val_sourcedlcarrierfreqv9e0)
	return nil
}

// MarshalUPER encodes ASConfigV10j0 to UPER format.
func (v *ASConfigV10j0) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigV10j0) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AntennaInfoDedicatedPCellV10i0 != nil); err != nil {
		return err
	}
	if v.AntennaInfoDedicatedPCellV10i0 != nil {
		if err := v.AntennaInfoDedicatedPCellV10i0.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding antennaInfoDedicatedPCell-v10i0: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASConfigV10j0 from UPER format.
func (v *ASConfigV10j0) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigV10j0) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigV10j0{}
	// Read preamble bitmap for optional root fields
	opt_antennainfodedicatedpcellv10i0, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_antennainfodedicatedpcellv10i0 {
		var dec_antennainfodedicatedpcellv10i0 AntennaInfoDedicatedV10i0
		if err := dec_antennainfodedicatedpcellv10i0.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding antennaInfoDedicatedPCell-v10i0: %w", err)
		}
		v.AntennaInfoDedicatedPCellV10i0 = &dec_antennainfodedicatedpcellv10i0
	}
	return nil
}

// MarshalUPER encodes ASConfigV1250 to UPER format.
func (v *ASConfigV1250) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigV1250) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SourceWlanOffloadConfigR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SourceSLCommConfigR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SourceSLDiscConfigR12 != nil); err != nil {
		return err
	}
	if v.SourceWlanOffloadConfigR12 != nil {
		if err := v.SourceWlanOffloadConfigR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding sourceWlan-OffloadConfig-r12: %w", err)
		}
	}
	if v.SourceSLCommConfigR12 != nil {
		if err := v.SourceSLCommConfigR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding sourceSL-CommConfig-r12: %w", err)
		}
	}
	if v.SourceSLDiscConfigR12 != nil {
		if err := v.SourceSLDiscConfigR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding sourceSL-DiscConfig-r12: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASConfigV1250 from UPER format.
func (v *ASConfigV1250) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigV1250) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigV1250{}
	// Read preamble bitmap for optional root fields
	opt_sourcewlanoffloadconfigr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sourceslcommconfigr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sourcesldiscconfigr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_sourcewlanoffloadconfigr12 {
		var dec_sourcewlanoffloadconfigr12 WLANOffloadConfigR12
		if err := dec_sourcewlanoffloadconfigr12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding sourceWlan-OffloadConfig-r12: %w", err)
		}
		v.SourceWlanOffloadConfigR12 = &dec_sourcewlanoffloadconfigr12
	}
	if opt_sourceslcommconfigr12 {
		var dec_sourceslcommconfigr12 SLCommConfigR12
		if err := dec_sourceslcommconfigr12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding sourceSL-CommConfig-r12: %w", err)
		}
		v.SourceSLCommConfigR12 = &dec_sourceslcommconfigr12
	}
	if opt_sourcesldiscconfigr12 {
		var dec_sourcesldiscconfigr12 SLDiscConfigR12
		if err := dec_sourcesldiscconfigr12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding sourceSL-DiscConfig-r12: %w", err)
		}
		v.SourceSLDiscConfigR12 = &dec_sourcesldiscconfigr12
	}
	return nil
}

// MarshalUPER encodes ASConfigV1320 to UPER format.
func (v *ASConfigV1320) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigV1320) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SourceSCellConfigListR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SourceRCLWIConfigurationR13 != nil); err != nil {
		return err
	}
	if v.SourceSCellConfigListR13 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.SourceSCellConfigListR13)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_sourcescellconfiglistr13, fragmentLength_sourcescellconfiglistr13 int64) error {
			for _, elem := range v.SourceSCellConfigListR13[fragmentOffset_sourcescellconfiglistr13 : fragmentOffset_sourcescellconfiglistr13+fragmentLength_sourcescellconfiglistr13] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding sourceSCellConfigList-r13 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding sourceSCellConfigList-r13: %w", err)
		}
	}
	if v.SourceRCLWIConfigurationR13 != nil {
		if err := v.SourceRCLWIConfigurationR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding sourceRCLWI-Configuration-r13: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASConfigV1320 from UPER format.
func (v *ASConfigV1320) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigV1320) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigV1320{}
	// Read preamble bitmap for optional root fields
	opt_sourcescellconfiglistr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sourcerclwiconfigurationr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_sourcescellconfiglistr13 {
		tmp_sourcescellconfiglistr13 := make(SCellToAddModListExtR13, 0)
		_, errCollection_sourcescellconfiglistr13 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_sourcescellconfiglistr13, fragmentLength_sourcescellconfiglistr13 int64) error {
			for i := int64(0); i < fragmentLength_sourcescellconfiglistr13; i++ {
				var elem SCellToAddModExtR13
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding sourceSCellConfigList-r13 element %d: %w", fragmentOffset_sourcescellconfiglistr13+i, err)
				}
				tmp_sourcescellconfiglistr13 = append(tmp_sourcescellconfiglistr13, elem)
			}
			return nil
		})
		if errCollection_sourcescellconfiglistr13 != nil {
			return fmt.Errorf("decoding sourceSCellConfigList-r13: %w", errCollection_sourcescellconfiglistr13)
		}
		v.SourceSCellConfigListR13 = tmp_sourcescellconfiglistr13
	}
	if opt_sourcerclwiconfigurationr13 {
		var dec_sourcerclwiconfigurationr13 RCLWIConfigurationR13
		if err := dec_sourcerclwiconfigurationr13.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding sourceRCLWI-Configuration-r13: %w", err)
		}
		v.SourceRCLWIConfigurationR13 = &dec_sourcerclwiconfigurationr13
	}
	return nil
}

// MarshalUPER encodes ASConfigV13c0 to UPER format.
func (v *ASConfigV13c0) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigV13c0) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.RadioResourceConfigDedicatedV13c01 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.RadioResourceConfigDedicatedV13c02 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SCellToAddModListV13c0 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SCellToAddModListExtV13c0 != nil); err != nil {
		return err
	}
	if v.RadioResourceConfigDedicatedV13c01 != nil {
		if err := v.RadioResourceConfigDedicatedV13c01.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioResourceConfigDedicated-v13c01: %w", err)
		}
	}
	if v.RadioResourceConfigDedicatedV13c02 != nil {
		if err := v.RadioResourceConfigDedicatedV13c02.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding radioResourceConfigDedicated-v13c02: %w", err)
		}
	}
	if v.SCellToAddModListV13c0 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.SCellToAddModListV13c0)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistv13c0, fragmentLength_scelltoaddmodlistv13c0 int64) error {
			for _, elem := range v.SCellToAddModListV13c0[fragmentOffset_scelltoaddmodlistv13c0 : fragmentOffset_scelltoaddmodlistv13c0+fragmentLength_scelltoaddmodlistv13c0] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding sCellToAddModList-v13c0 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding sCellToAddModList-v13c0: %w", err)
		}
	}
	if v.SCellToAddModListExtV13c0 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.SCellToAddModListExtV13c0)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistextv13c0, fragmentLength_scelltoaddmodlistextv13c0 int64) error {
			for _, elem := range v.SCellToAddModListExtV13c0[fragmentOffset_scelltoaddmodlistextv13c0 : fragmentOffset_scelltoaddmodlistextv13c0+fragmentLength_scelltoaddmodlistextv13c0] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding sCellToAddModListExt-v13c0 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding sCellToAddModListExt-v13c0: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASConfigV13c0 from UPER format.
func (v *ASConfigV13c0) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigV13c0) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigV13c0{}
	// Read preamble bitmap for optional root fields
	opt_radioresourceconfigdedicatedv13c01, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_radioresourceconfigdedicatedv13c02, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_scelltoaddmodlistv13c0, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_scelltoaddmodlistextv13c0, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_radioresourceconfigdedicatedv13c01 {
		var dec_radioresourceconfigdedicatedv13c01 RadioResourceConfigDedicatedV1370
		if err := dec_radioresourceconfigdedicatedv13c01.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding radioResourceConfigDedicated-v13c01: %w", err)
		}
		v.RadioResourceConfigDedicatedV13c01 = &dec_radioresourceconfigdedicatedv13c01
	}
	if opt_radioresourceconfigdedicatedv13c02 {
		var dec_radioresourceconfigdedicatedv13c02 RadioResourceConfigDedicatedV13c0
		if err := dec_radioresourceconfigdedicatedv13c02.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding radioResourceConfigDedicated-v13c02: %w", err)
		}
		v.RadioResourceConfigDedicatedV13c02 = &dec_radioresourceconfigdedicatedv13c02
	}
	if opt_scelltoaddmodlistv13c0 {
		tmp_scelltoaddmodlistv13c0 := make(SCellToAddModListV13c0, 0)
		_, errCollection_scelltoaddmodlistv13c0 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistv13c0, fragmentLength_scelltoaddmodlistv13c0 int64) error {
			for i := int64(0); i < fragmentLength_scelltoaddmodlistv13c0; i++ {
				var elem SCellToAddModV13c0
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding sCellToAddModList-v13c0 element %d: %w", fragmentOffset_scelltoaddmodlistv13c0+i, err)
				}
				tmp_scelltoaddmodlistv13c0 = append(tmp_scelltoaddmodlistv13c0, elem)
			}
			return nil
		})
		if errCollection_scelltoaddmodlistv13c0 != nil {
			return fmt.Errorf("decoding sCellToAddModList-v13c0: %w", errCollection_scelltoaddmodlistv13c0)
		}
		v.SCellToAddModListV13c0 = tmp_scelltoaddmodlistv13c0
	}
	if opt_scelltoaddmodlistextv13c0 {
		tmp_scelltoaddmodlistextv13c0 := make(SCellToAddModListExtV13c0, 0)
		_, errCollection_scelltoaddmodlistextv13c0 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 31, HasUpper: true}, false, func(fragmentOffset_scelltoaddmodlistextv13c0, fragmentLength_scelltoaddmodlistextv13c0 int64) error {
			for i := int64(0); i < fragmentLength_scelltoaddmodlistextv13c0; i++ {
				var elem SCellToAddModV13c0
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding sCellToAddModListExt-v13c0 element %d: %w", fragmentOffset_scelltoaddmodlistextv13c0+i, err)
				}
				tmp_scelltoaddmodlistextv13c0 = append(tmp_scelltoaddmodlistextv13c0, elem)
			}
			return nil
		})
		if errCollection_scelltoaddmodlistextv13c0 != nil {
			return fmt.Errorf("decoding sCellToAddModListExt-v13c0: %w", errCollection_scelltoaddmodlistextv13c0)
		}
		v.SCellToAddModListExtV13c0 = tmp_scelltoaddmodlistextv13c0
	}
	return nil
}

// MarshalUPER encodes ASConfigV1430 to UPER format.
func (v *ASConfigV1430) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigV1430) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SourceSLV2XCommConfigR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SourceLWAConfigR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SourceWLANMeasResultR14 != nil); err != nil {
		return err
	}
	if v.SourceSLV2XCommConfigR14 != nil {
		if err := v.SourceSLV2XCommConfigR14.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding sourceSL-V2X-CommConfig-r14: %w", err)
		}
	}
	if v.SourceLWAConfigR14 != nil {
		if err := v.SourceLWAConfigR14.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding sourceLWA-Config-r14: %w", err)
		}
	}
	if v.SourceWLANMeasResultR14 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.SourceWLANMeasResultR14)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_sourcewlanmeasresultr14, fragmentLength_sourcewlanmeasresultr14 int64) error {
			for _, elem := range v.SourceWLANMeasResultR14[fragmentOffset_sourcewlanmeasresultr14 : fragmentOffset_sourcewlanmeasresultr14+fragmentLength_sourcewlanmeasresultr14] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding sourceWLAN-MeasResult-r14 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding sourceWLAN-MeasResult-r14: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASConfigV1430 from UPER format.
func (v *ASConfigV1430) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigV1430) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigV1430{}
	// Read preamble bitmap for optional root fields
	opt_sourceslv2xcommconfigr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sourcelwaconfigr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sourcewlanmeasresultr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_sourceslv2xcommconfigr14 {
		var dec_sourceslv2xcommconfigr14 SLV2XConfigDedicatedR14
		if err := dec_sourceslv2xcommconfigr14.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding sourceSL-V2X-CommConfig-r14: %w", err)
		}
		v.SourceSLV2XCommConfigR14 = &dec_sourceslv2xcommconfigr14
	}
	if opt_sourcelwaconfigr14 {
		var dec_sourcelwaconfigr14 LWAConfigR13
		if err := dec_sourcelwaconfigr14.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding sourceLWA-Config-r14: %w", err)
		}
		v.SourceLWAConfigR14 = &dec_sourcelwaconfigr14
	}
	if opt_sourcewlanmeasresultr14 {
		tmp_sourcewlanmeasresultr14 := make(MeasResultListWLANR13, 0)
		_, errCollection_sourcewlanmeasresultr14 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_sourcewlanmeasresultr14, fragmentLength_sourcewlanmeasresultr14 int64) error {
			for i := int64(0); i < fragmentLength_sourcewlanmeasresultr14; i++ {
				var elem MeasResultWLANR13
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding sourceWLAN-MeasResult-r14 element %d: %w", fragmentOffset_sourcewlanmeasresultr14+i, err)
				}
				tmp_sourcewlanmeasresultr14 = append(tmp_sourcewlanmeasresultr14, elem)
			}
			return nil
		})
		if errCollection_sourcewlanmeasresultr14 != nil {
			return fmt.Errorf("decoding sourceWLAN-MeasResult-r14: %w", errCollection_sourcewlanmeasresultr14)
		}
		v.SourceWLANMeasResultR14 = tmp_sourcewlanmeasresultr14
	}
	return nil
}

// MarshalUPER encodes ASConfigNRR15 to UPER format.
func (v *ASConfigNRR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigNRR15) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SourceRBConfigNRR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SourceRBConfigSNNRR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SourceOtherConfigSNNRR15 != nil); err != nil {
		return err
	}
	if v.SourceRBConfigNRR15 != nil {
		if err := per.EncodeOctetStringExt(bb, v.SourceRBConfigNRR15, 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding sourceRB-ConfigNR-r15: %w", err)
		}
	}
	if v.SourceRBConfigSNNRR15 != nil {
		if err := per.EncodeOctetStringExt(bb, v.SourceRBConfigSNNRR15, 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding sourceRB-ConfigSN-NR-r15: %w", err)
		}
	}
	if v.SourceOtherConfigSNNRR15 != nil {
		if err := per.EncodeOctetStringExt(bb, v.SourceOtherConfigSNNRR15, 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding sourceOtherConfigSN-NR-r15: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASConfigNRR15 from UPER format.
func (v *ASConfigNRR15) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigNRR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigNRR15{}
	// Read preamble bitmap for optional root fields
	opt_sourcerbconfignrr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sourcerbconfigsnnrr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sourceotherconfigsnnrr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_sourcerbconfignrr15 {
		val_sourcerbconfignrr15, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding sourceRB-ConfigNR-r15: %w", err)
		}
		tmp_sourcerbconfignrr15 := val_sourcerbconfignrr15
		v.SourceRBConfigNRR15 = tmp_sourcerbconfignrr15
	}
	if opt_sourcerbconfigsnnrr15 {
		val_sourcerbconfigsnnrr15, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding sourceRB-ConfigSN-NR-r15: %w", err)
		}
		tmp_sourcerbconfigsnnrr15 := val_sourcerbconfigsnnrr15
		v.SourceRBConfigSNNRR15 = tmp_sourcerbconfigsnnrr15
	}
	if opt_sourceotherconfigsnnrr15 {
		val_sourceotherconfigsnnrr15, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding sourceOtherConfigSN-NR-r15: %w", err)
		}
		tmp_sourceotherconfigsnnrr15 := val_sourceotherconfigsnnrr15
		v.SourceOtherConfigSNNRR15 = tmp_sourceotherconfigsnnrr15
	}
	return nil
}

// MarshalUPER encodes ASConfigNRV1570 to UPER format.
func (v *ASConfigNRV1570) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigNRV1570) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeEnumerated(bb, int64(v.SourceSCGConfiguredNRR15), 1, false); err != nil {
		return fmt.Errorf("encoding sourceSCG-ConfiguredNR-r15: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes ASConfigNRV1570 from UPER format.
func (v *ASConfigNRV1570) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigNRV1570) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigNRV1570{}
	val_sourcescgconfigurednrr15, err := per.DecodeEnumerated(bb, 1, false)
	if err != nil {
		return fmt.Errorf("decoding sourceSCG-ConfiguredNR-r15: %w", err)
	}
	v.SourceSCGConfiguredNRR15 = val_sourcescgconfigurednrr15
	return nil
}

// MarshalUPER encodes ASConfigV1550 to UPER format.
func (v *ASConfigV1550) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigV1550) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.TdmPatternConfigR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.PMaxEUTRAR15 != nil); err != nil {
		return err
	}
	if v.TdmPatternConfigR15 != nil {
		if err := v.TdmPatternConfigR15.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding tdm-PatternConfig-r15: %w", err)
		}
	}
	if v.PMaxEUTRAR15 != nil {
		if err := per.EncodeInteger(bb, int64(*v.PMaxEUTRAR15), int64Ptr(-30), int64Ptr(33), false); err != nil {
			return fmt.Errorf("encoding p-MaxEUTRA-r15: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASConfigV1550 from UPER format.
func (v *ASConfigV1550) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigV1550) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigV1550{}
	// Read preamble bitmap for optional root fields
	opt_tdmpatternconfigr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_pmaxeutrar15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_tdmpatternconfigr15 {
		var dec_tdmpatternconfigr15 ASConfigV1550TdmPatternConfigR15
		if err := dec_tdmpatternconfigr15.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding tdm-PatternConfig-r15: %w", err)
		}
		v.TdmPatternConfigR15 = &dec_tdmpatternconfigr15
	}
	if opt_pmaxeutrar15 {
		val_pmaxeutrar15, err := per.DecodeInteger(bb, int64Ptr(-30), int64Ptr(33), false)
		if err != nil {
			return fmt.Errorf("decoding p-MaxEUTRA-r15: %w", err)
		}
		tmp_pmaxeutrar15 := PMax(val_pmaxeutrar15)
		v.PMaxEUTRAR15 = &tmp_pmaxeutrar15
	}
	return nil
}

// MarshalUPER encodes ASConfigNRV1620 to UPER format.
func (v *ASConfigNRV1620) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigNRV1620) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.TdmPatternConfig2R16.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding tdm-PatternConfig2-r16: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes ASConfigNRV1620 from UPER format.
func (v *ASConfigNRV1620) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigNRV1620) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigNRV1620{}
	if err := v.TdmPatternConfig2R16.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding tdm-PatternConfig2-r16: %w", err)
	}
	return nil
}

// MarshalUPER encodes ASConfigV1700 to UPER format.
func (v *ASConfigV1700) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigV1700) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.ScgStateR17 != nil); err != nil {
		return err
	}
	if v.ScgStateR17 != nil {
		if err := per.EncodeEnumerated(bb, int64(*v.ScgStateR17), 1, false); err != nil {
			return fmt.Errorf("encoding scg-State-r17: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASConfigV1700 from UPER format.
func (v *ASConfigV1700) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigV1700) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigV1700{}
	// Read preamble bitmap for optional root fields
	opt_scgstater17, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_scgstater17 {
		val_scgstater17, err := per.DecodeEnumerated(bb, 1, false)
		if err != nil {
			return fmt.Errorf("decoding scg-State-r17: %w", err)
		}
		v.ScgStateR17 = &val_scgstater17
	}
	return nil
}

// MarshalUPER encodes ASContext to UPER format.
func (v *ASContext) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASContext) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.ReestablishmentInfo != nil); err != nil {
		return err
	}
	if v.ReestablishmentInfo != nil {
		if err := v.ReestablishmentInfo.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding reestablishmentInfo: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASContext from UPER format.
func (v *ASContext) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASContext) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASContext{}
	// Read preamble bitmap for optional root fields
	opt_reestablishmentinfo, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_reestablishmentinfo {
		var dec_reestablishmentinfo ReestablishmentInfo
		if err := dec_reestablishmentinfo.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding reestablishmentInfo: %w", err)
		}
		v.ReestablishmentInfo = &dec_reestablishmentinfo
	}
	return nil
}

// MarshalUPER encodes ASContextV1130 to UPER format.
func (v *ASContextV1130) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASContextV1130) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.SidelinkUEInformationR12 != nil || v.SourceContextENDCR15 != nil || v.SelectedbandCombinationInfoENDCV1540 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IdcIndicationR11 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MbmsInterestIndicationR11 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.UeAssistanceInformationR11 != nil); err != nil {
		return err
	}
	if v.IdcIndicationR11 != nil {
		containedBB_idcindicationr11 := per.NewBitBuffer()
		if err := (*v.IdcIndicationR11).MarshalUPERTo(containedBB_idcindicationr11); err != nil {
			return fmt.Errorf("encoding contained idc-Indication-r11: %w", err)
		}
		if err := per.EncodeOctetStringExt(bb, containedBB_idcindicationr11.Bytes(), 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding idc-Indication-r11: %w", err)
		}
	}
	if v.MbmsInterestIndicationR11 != nil {
		containedBB_mbmsinterestindicationr11 := per.NewBitBuffer()
		if err := (*v.MbmsInterestIndicationR11).MarshalUPERTo(containedBB_mbmsinterestindicationr11); err != nil {
			return fmt.Errorf("encoding contained mbmsInterestIndication-r11: %w", err)
		}
		if err := per.EncodeOctetStringExt(bb, containedBB_mbmsinterestindicationr11.Bytes(), 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding mbmsInterestIndication-r11: %w", err)
		}
	}
	if v.UeAssistanceInformationR11 != nil {
		containedBB_ueassistanceinformationr11 := per.NewBitBuffer()
		if err := (*v.UeAssistanceInformationR11).MarshalUPERTo(containedBB_ueassistanceinformationr11); err != nil {
			return fmt.Errorf("encoding contained ueAssistanceInformation-r11: %w", err)
		}
		if err := per.EncodeOctetStringExt(bb, containedBB_ueassistanceinformationr11.Bytes(), 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding ueAssistanceInformation-r11: %w", err)
		}
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.SidelinkUEInformationR12 != nil {
			extHighest = 0
		}
		if v.SourceContextENDCR15 != nil {
			extHighest = 1
		}
		if v.SelectedbandCombinationInfoENDCV1540 != nil {
			extHighest = 2
		}
		if v.ExtCount_ > extHighest {
			extHighest = v.ExtCount_
		}
		if err := per.EncodeNormallySmallNonNegative(bb, extHighest); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SidelinkUEInformationR12 != nil
			if err := per.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		if int64(1) <= extHighest {
			present1 := (int64(1) < int64(len(v.ExtPresent_)) && v.ExtPresent_[1]) || v.SourceContextENDCR15 != nil
			if err := per.EncodeBoolean(bb, present1); err != nil {
				return err
			}
		}
		if int64(2) <= extHighest {
			present2 := (int64(2) < int64(len(v.ExtPresent_)) && v.ExtPresent_[2]) || v.SelectedbandCombinationInfoENDCV1540 != nil
			if err := per.EncodeBoolean(bb, present2); err != nil {
				return err
			}
		}
		for i := int64(3); i <= extHighest; i++ {
			p := i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SidelinkUEInformationR12 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SidelinkUEInformationR12 != nil); err != nil {
				return err
			}
			if v.SidelinkUEInformationR12 != nil {
				containedBB_sidelinkueinformationr12 := per.NewBitBuffer()
				if err := (*v.SidelinkUEInformationR12).MarshalUPERTo(containedBB_sidelinkueinformationr12); err != nil {
					return fmt.Errorf("encoding contained sidelinkUEInformation-r12: %w", err)
				}
				if err := per.EncodeOctetStringExt(extBuf, containedBB_sidelinkueinformationr12.Bytes(), 0, 0, false, false); err != nil {
					return fmt.Errorf("encoding sidelinkUEInformation-r12: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(1) < int64(len(v.ExtPresent_)) && v.ExtPresent_[1]) || v.SourceContextENDCR15 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SourceContextENDCR15 != nil); err != nil {
				return err
			}
			if v.SourceContextENDCR15 != nil {
				if err := per.EncodeOctetStringExt(extBuf, v.SourceContextENDCR15, 0, 0, false, false); err != nil {
					return fmt.Errorf("encoding sourceContextEN-DC-r15: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(2) < int64(len(v.ExtPresent_)) && v.ExtPresent_[2]) || v.SelectedbandCombinationInfoENDCV1540 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SelectedbandCombinationInfoENDCV1540 != nil); err != nil {
				return err
			}
			if v.SelectedbandCombinationInfoENDCV1540 != nil {
				if err := per.EncodeOctetStringExt(extBuf, v.SelectedbandCombinationInfoENDCV1540, 0, 0, false, false); err != nil {
					return fmt.Errorf("encoding selectedbandCombinationInfoEN-DC-v1540: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		for i := int64(3); i <= extHighest; i++ {
			if i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i] {
				if i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil {
					if err := per.EncodeOpenType(bb, v.ExtData_[i]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes ASContextV1130 from UPER format.
func (v *ASContextV1130) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASContextV1130) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASContextV1130{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_idcindicationr11, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_mbmsinterestindicationr11, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ueassistanceinformationr11, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_idcindicationr11 {
		containedBytes_idcindicationr11, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding idc-Indication-r11: %w", err)
		}
		var contained_idcindicationr11 InDeviceCoexIndicationR11
		if err := contained_idcindicationr11.UnmarshalUPER(containedBytes_idcindicationr11); err != nil {
			return fmt.Errorf("decoding contained idc-Indication-r11: %w", err)
		}
		v.IdcIndicationR11 = &contained_idcindicationr11
	}
	if opt_mbmsinterestindicationr11 {
		containedBytes_mbmsinterestindicationr11, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding mbmsInterestIndication-r11: %w", err)
		}
		var contained_mbmsinterestindicationr11 MBMSInterestIndicationR11
		if err := contained_mbmsinterestindicationr11.UnmarshalUPER(containedBytes_mbmsinterestindicationr11); err != nil {
			return fmt.Errorf("decoding contained mbmsInterestIndication-r11: %w", err)
		}
		v.MbmsInterestIndicationR11 = &contained_mbmsinterestindicationr11
	}
	if opt_ueassistanceinformationr11 {
		containedBytes_ueassistanceinformationr11, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding ueAssistanceInformation-r11: %w", err)
		}
		var contained_ueassistanceinformationr11 UEAssistanceInformationR11
		if err := contained_ueassistanceinformationr11.UnmarshalUPER(containedBytes_ueassistanceinformationr11); err != nil {
			return fmt.Errorf("decoding contained ueAssistanceInformation-r11: %w", err)
		}
		v.UeAssistanceInformationR11 = &contained_ueassistanceinformationr11
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtPresent_ = extPresent
		if int64(0) <= extCount && extPresent[0] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_sidelinkueinformationr12, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_sidelinkueinformationr12 {
				containedBytes_sidelinkueinformationr12, err := per.DecodeOctetStringExt(extBB, 0, 0, false, false)
				if err != nil {
					return fmt.Errorf("decoding sidelinkUEInformation-r12: %w", err)
				}
				var contained_sidelinkueinformationr12 SidelinkUEInformationR12
				if err := contained_sidelinkueinformationr12.UnmarshalUPER(containedBytes_sidelinkueinformationr12); err != nil {
					return fmt.Errorf("decoding contained sidelinkUEInformation-r12: %w", err)
				}
				v.SidelinkUEInformationR12 = &contained_sidelinkueinformationr12
			}
		}
		if int64(1) <= extCount && extPresent[1] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_sourcecontextendcr15, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_sourcecontextendcr15 {
				val_sourcecontextendcr15, err := per.DecodeOctetStringExt(extBB, 0, 0, false, false)
				if err != nil {
					return fmt.Errorf("decoding sourceContextEN-DC-r15: %w", err)
				}
				tmp_sourcecontextendcr15 := val_sourcecontextendcr15
				v.SourceContextENDCR15 = tmp_sourcecontextendcr15
			}
		}
		if int64(2) <= extCount && extPresent[2] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_selectedbandcombinationinfoendcv1540, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_selectedbandcombinationinfoendcv1540 {
				val_selectedbandcombinationinfoendcv1540, err := per.DecodeOctetStringExt(extBB, 0, 0, false, false)
				if err != nil {
					return fmt.Errorf("decoding selectedbandCombinationInfoEN-DC-v1540: %w", err)
				}
				tmp_selectedbandcombinationinfoendcv1540 := val_selectedbandcombinationinfoendcv1540
				v.SelectedbandCombinationInfoENDCV1540 = tmp_selectedbandcombinationinfoendcv1540
			}
		}
		v.ExtData_ = make([][]byte, extCount+1)
		for i := int64(3); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes ASContextV1320 to UPER format.
func (v *ASContextV1320) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASContextV1320) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.WlanConnectionStatusReportR13 != nil); err != nil {
		return err
	}
	if v.WlanConnectionStatusReportR13 != nil {
		containedBB_wlanconnectionstatusreportr13 := per.NewBitBuffer()
		if err := (*v.WlanConnectionStatusReportR13).MarshalUPERTo(containedBB_wlanconnectionstatusreportr13); err != nil {
			return fmt.Errorf("encoding contained wlanConnectionStatusReport-r13: %w", err)
		}
		if err := per.EncodeOctetStringExt(bb, containedBB_wlanconnectionstatusreportr13.Bytes(), 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding wlanConnectionStatusReport-r13: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASContextV1320 from UPER format.
func (v *ASContextV1320) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASContextV1320) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASContextV1320{}
	// Read preamble bitmap for optional root fields
	opt_wlanconnectionstatusreportr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_wlanconnectionstatusreportr13 {
		containedBytes_wlanconnectionstatusreportr13, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding wlanConnectionStatusReport-r13: %w", err)
		}
		var contained_wlanconnectionstatusreportr13 WLANConnectionStatusReportR13
		if err := contained_wlanconnectionstatusreportr13.UnmarshalUPER(containedBytes_wlanconnectionstatusreportr13); err != nil {
			return fmt.Errorf("decoding contained wlanConnectionStatusReport-r13: %w", err)
		}
		v.WlanConnectionStatusReportR13 = &contained_wlanconnectionstatusreportr13
	}
	return nil
}

// MarshalUPER encodes ASContextV1610 to UPER format.
func (v *ASContextV1610) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASContextV1610) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SidelinkUEInformationNRR16 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.UeAssistanceInformationNRR16 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ConfigRestrictInfoDAPSR16 != nil); err != nil {
		return err
	}
	if v.SidelinkUEInformationNRR16 != nil {
		if err := per.EncodeOctetStringExt(bb, v.SidelinkUEInformationNRR16, 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding sidelinkUEInformationNR-r16: %w", err)
		}
	}
	if v.UeAssistanceInformationNRR16 != nil {
		if err := per.EncodeOctetStringExt(bb, v.UeAssistanceInformationNRR16, 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding ueAssistanceInformationNR-r16: %w", err)
		}
	}
	if v.ConfigRestrictInfoDAPSR16 != nil {
		if err := v.ConfigRestrictInfoDAPSR16.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding configRestrictInfoDAPS-r16: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASContextV1610 from UPER format.
func (v *ASContextV1610) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASContextV1610) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASContextV1610{}
	// Read preamble bitmap for optional root fields
	opt_sidelinkueinformationnrr16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ueassistanceinformationnrr16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_configrestrictinfodapsr16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_sidelinkueinformationnrr16 {
		val_sidelinkueinformationnrr16, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding sidelinkUEInformationNR-r16: %w", err)
		}
		tmp_sidelinkueinformationnrr16 := val_sidelinkueinformationnrr16
		v.SidelinkUEInformationNRR16 = tmp_sidelinkueinformationnrr16
	}
	if opt_ueassistanceinformationnrr16 {
		val_ueassistanceinformationnrr16, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding ueAssistanceInformationNR-r16: %w", err)
		}
		tmp_ueassistanceinformationnrr16 := val_ueassistanceinformationnrr16
		v.UeAssistanceInformationNRR16 = tmp_ueassistanceinformationnrr16
	}
	if opt_configrestrictinfodapsr16 {
		var dec_configrestrictinfodapsr16 ConfigRestrictInfoDAPSR16
		if err := dec_configrestrictinfodapsr16.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding configRestrictInfoDAPS-r16: %w", err)
		}
		v.ConfigRestrictInfoDAPSR16 = &dec_configrestrictinfodapsr16
	}
	return nil
}

// MarshalUPER encodes ASContextV1620 to UPER format.
func (v *ASContextV1620) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASContextV1620) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.UeAssistanceInformationNRSCGR16 != nil); err != nil {
		return err
	}
	if v.UeAssistanceInformationNRSCGR16 != nil {
		if err := per.EncodeOctetStringExt(bb, v.UeAssistanceInformationNRSCGR16, 0, 0, false, false); err != nil {
			return fmt.Errorf("encoding ueAssistanceInformationNR-SCG-r16: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASContextV1620 from UPER format.
func (v *ASContextV1620) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASContextV1620) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASContextV1620{}
	// Read preamble bitmap for optional root fields
	opt_ueassistanceinformationnrscgr16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_ueassistanceinformationnrscgr16 {
		val_ueassistanceinformationnrscgr16, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
		if err != nil {
			return fmt.Errorf("decoding ueAssistanceInformationNR-SCG-r16: %w", err)
		}
		tmp_ueassistanceinformationnrscgr16 := val_ueassistanceinformationnrscgr16
		v.UeAssistanceInformationNRSCGR16 = tmp_ueassistanceinformationnrscgr16
	}
	return nil
}

// MarshalUPER encodes ASContextV1630 to UPER format.
func (v *ASContextV1630) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASContextV1630) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.ConfigRestrictInfoDAPSV1630 != nil); err != nil {
		return err
	}
	if v.ConfigRestrictInfoDAPSV1630 != nil {
		if err := v.ConfigRestrictInfoDAPSV1630.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding configRestrictInfoDAPS-v1630: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ASContextV1630 from UPER format.
func (v *ASContextV1630) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASContextV1630) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASContextV1630{}
	// Read preamble bitmap for optional root fields
	opt_configrestrictinfodapsv1630, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_configrestrictinfodapsv1630 {
		var dec_configrestrictinfodapsv1630 ConfigRestrictInfoDAPSV1630
		if err := dec_configrestrictinfodapsv1630.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding configRestrictInfoDAPS-v1630: %w", err)
		}
		v.ConfigRestrictInfoDAPSV1630 = &dec_configrestrictinfodapsv1630
	}
	return nil
}

// MarshalUPER encodes ConfigRestrictInfoDAPSR16 to UPER format.
func (v *ConfigRestrictInfoDAPSR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ConfigRestrictInfoDAPSR16) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MaxSCHTBBitsDLR16 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MaxSCHTBBitsULR16 != nil); err != nil {
		return err
	}
	if v.MaxSCHTBBitsDLR16 != nil {
		if err := per.EncodeInteger(bb, int64(*v.MaxSCHTBBitsDLR16), int64Ptr(1), int64Ptr(100), false); err != nil {
			return fmt.Errorf("encoding maxSCH-TB-BitsDL-r16: %w", err)
		}
	}
	if v.MaxSCHTBBitsULR16 != nil {
		if err := per.EncodeInteger(bb, int64(*v.MaxSCHTBBitsULR16), int64Ptr(1), int64Ptr(100), false); err != nil {
			return fmt.Errorf("encoding maxSCH-TB-BitsUL-r16: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ConfigRestrictInfoDAPSR16 from UPER format.
func (v *ConfigRestrictInfoDAPSR16) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ConfigRestrictInfoDAPSR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ConfigRestrictInfoDAPSR16{}
	// Read preamble bitmap for optional root fields
	opt_maxschtbbitsdlr16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_maxschtbbitsulr16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_maxschtbbitsdlr16 {
		val_maxschtbbitsdlr16, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(100), false)
		if err != nil {
			return fmt.Errorf("decoding maxSCH-TB-BitsDL-r16: %w", err)
		}
		v.MaxSCHTBBitsDLR16 = &val_maxschtbbitsdlr16
	}
	if opt_maxschtbbitsulr16 {
		val_maxschtbbitsulr16, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(100), false)
		if err != nil {
			return fmt.Errorf("decoding maxSCH-TB-BitsUL-r16: %w", err)
		}
		v.MaxSCHTBBitsULR16 = &val_maxschtbbitsulr16
	}
	return nil
}

// MarshalUPER encodes ConfigRestrictInfoDAPSV1630 to UPER format.
func (v *ConfigRestrictInfoDAPSV1630) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ConfigRestrictInfoDAPSV1630) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.DapsPowerCoordinationInfoR16 != nil); err != nil {
		return err
	}
	if v.DapsPowerCoordinationInfoR16 != nil {
		if err := v.DapsPowerCoordinationInfoR16.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding daps-PowerCoordinationInfo-r16: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes ConfigRestrictInfoDAPSV1630 from UPER format.
func (v *ConfigRestrictInfoDAPSV1630) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ConfigRestrictInfoDAPSV1630) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ConfigRestrictInfoDAPSV1630{}
	// Read preamble bitmap for optional root fields
	opt_dapspowercoordinationinfor16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_dapspowercoordinationinfor16 {
		var dec_dapspowercoordinationinfor16 DAPSPowerCoordinationInfoR16
		if err := dec_dapspowercoordinationinfor16.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding daps-PowerCoordinationInfo-r16: %w", err)
		}
		v.DapsPowerCoordinationInfoR16 = &dec_dapspowercoordinationinfor16
	}
	return nil
}

// MarshalUPER encodes ReestablishmentInfo to UPER format.
func (v *ReestablishmentInfo) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ReestablishmentInfo) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AdditionalReestabInfoList != nil); err != nil {
		return err
	}
	if err := per.EncodeInteger(bb, int64(v.SourcePhysCellId), int64Ptr(0), int64Ptr(503), false); err != nil {
		return fmt.Errorf("encoding sourcePhysCellId: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.TargetCellShortMACI.Bytes, v.TargetCellShortMACI.BitLength, 16, 16, true, false); err != nil {
		return fmt.Errorf("encoding targetCellShortMAC-I: %w", err)
	}
	if v.AdditionalReestabInfoList != nil {
		if err := per.EncodeCollection(bb, int64(len(v.AdditionalReestabInfoList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_additionalreestabinfolist, fragmentLength_additionalreestabinfolist int64) error {
			for _, elem := range v.AdditionalReestabInfoList[fragmentOffset_additionalreestabinfolist : fragmentOffset_additionalreestabinfolist+fragmentLength_additionalreestabinfolist] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding additionalReestabInfoList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding additionalReestabInfoList: %w", err)
		}
	}
	if hasExtensions {
		if err := per.EncodeNormallySmallNonNegative(bb, v.ExtCount_); err != nil {
			return err
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			p := i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		for i := int64(0); i <= v.ExtCount_; i++ {
			if i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i] {
				if i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil {
					if err := per.EncodeOpenType(bb, v.ExtData_[i]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes ReestablishmentInfo from UPER format.
func (v *ReestablishmentInfo) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ReestablishmentInfo) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ReestablishmentInfo{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_additionalreestabinfolist, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_sourcephyscellid, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return fmt.Errorf("decoding sourcePhysCellId: %w", err)
	}
	v.SourcePhysCellId = PhysCellId(val_sourcephyscellid)
	bsBytes_targetcellshortmaci, bsBitLen_targetcellshortmaci, err := per.DecodeBitStringExt(bb, 16, 16, true, false)
	if err != nil {
		return fmt.Errorf("decoding targetCellShortMAC-I: %w", err)
	}
	v.TargetCellShortMACI = runtime.BitString{Bytes: bsBytes_targetcellshortmaci, BitLength: bsBitLen_targetcellshortmaci}
	if opt_additionalreestabinfolist {
		tmp_additionalreestabinfolist := make(AdditionalReestabInfoList, 0)
		_, errCollection_additionalreestabinfolist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_additionalreestabinfolist, fragmentLength_additionalreestabinfolist int64) error {
			for i := int64(0); i < fragmentLength_additionalreestabinfolist; i++ {
				var elem AdditionalReestabInfo
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return fmt.Errorf("decoding additionalReestabInfoList element %d: %w", fragmentOffset_additionalreestabinfolist+i, err)
				}
				tmp_additionalreestabinfolist = append(tmp_additionalreestabinfolist, elem)
			}
			return nil
		})
		if errCollection_additionalreestabinfolist != nil {
			return fmt.Errorf("decoding additionalReestabInfoList: %w", errCollection_additionalreestabinfolist)
		}
		v.AdditionalReestabInfoList = tmp_additionalreestabinfolist
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cUPERAdditionalReestabInfoListListValue struct{ Value AdditionalReestabInfoList }

// MarshalUPERAdditionalReestabInfoList encodes a AdditionalReestabInfoList list to UPER.
func MarshalUPERAdditionalReestabInfoList(list AdditionalReestabInfoList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERAdditionalReestabInfoListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERAdditionalReestabInfoListTo appends a AdditionalReestabInfoList list to bb.
func MarshalUPERAdditionalReestabInfoListTo(list AdditionalReestabInfoList, bb *per.BitBuffer) error {
	v := asn1cUPERAdditionalReestabInfoListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERAdditionalReestabInfoList decodes a AdditionalReestabInfoList list from UPER.
func UnmarshalUPERAdditionalReestabInfoList(data []byte) (AdditionalReestabInfoList, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERAdditionalReestabInfoListFrom(bb)
}

// UnmarshalUPERAdditionalReestabInfoListFrom decodes a AdditionalReestabInfoList list from bb.
func UnmarshalUPERAdditionalReestabInfoListFrom(bb *per.BitBuffer) (AdditionalReestabInfoList, error) {
	var v asn1cUPERAdditionalReestabInfoListListValue
	if err := unmarshalUPERAdditionalReestabInfoListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERAdditionalReestabInfoListInto(v *asn1cUPERAdditionalReestabInfoListListValue, bb *per.BitBuffer) error {
	v.Value = make(AdditionalReestabInfoList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem AdditionalReestabInfo
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

// MarshalUPER encodes AdditionalReestabInfo to UPER format.
func (v *AdditionalReestabInfo) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *AdditionalReestabInfo) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeBitStringExt(bb, v.CellIdentity.Bytes, v.CellIdentity.BitLength, 28, 28, true, false); err != nil {
		return fmt.Errorf("encoding cellIdentity: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.KeyENodeBStar.Bytes, v.KeyENodeBStar.BitLength, 256, 256, true, false); err != nil {
		return fmt.Errorf("encoding key-eNodeB-Star: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.ShortMACI.Bytes, v.ShortMACI.BitLength, 16, 16, true, false); err != nil {
		return fmt.Errorf("encoding shortMAC-I: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes AdditionalReestabInfo from UPER format.
func (v *AdditionalReestabInfo) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *AdditionalReestabInfo) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = AdditionalReestabInfo{}
	bsBytes_cellidentity, bsBitLen_cellidentity, err := per.DecodeBitStringExt(bb, 28, 28, true, false)
	if err != nil {
		return fmt.Errorf("decoding cellIdentity: %w", err)
	}
	v.CellIdentity = runtime.BitString{Bytes: bsBytes_cellidentity, BitLength: bsBitLen_cellidentity}
	bsBytes_keyenodebstar, bsBitLen_keyenodebstar, err := per.DecodeBitStringExt(bb, 256, 256, true, false)
	if err != nil {
		return fmt.Errorf("decoding key-eNodeB-Star: %w", err)
	}
	v.KeyENodeBStar = runtime.BitString{Bytes: bsBytes_keyenodebstar, BitLength: bsBitLen_keyenodebstar}
	bsBytes_shortmaci, bsBitLen_shortmaci, err := per.DecodeBitStringExt(bb, 16, 16, true, false)
	if err != nil {
		return fmt.Errorf("decoding shortMAC-I: %w", err)
	}
	v.ShortMACI = runtime.BitString{Bytes: bsBytes_shortmaci, BitLength: bsBitLen_shortmaci}
	return nil
}

// MarshalUPER encodes RRMConfig to UPER format.
func (v *RRMConfig) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *RRMConfig) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.CandidateCellInfoListR10 != nil || v.CandidateCellInfoListNRR15 != nil
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
		extHighest := int64(0)
		if v.CandidateCellInfoListR10 != nil {
			extHighest = 0
		}
		if v.CandidateCellInfoListNRR15 != nil {
			extHighest = 1
		}
		if v.ExtCount_ > extHighest {
			extHighest = v.ExtCount_
		}
		if err := per.EncodeNormallySmallNonNegative(bb, extHighest); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.CandidateCellInfoListR10 != nil
			if err := per.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		if int64(1) <= extHighest {
			present1 := (int64(1) < int64(len(v.ExtPresent_)) && v.ExtPresent_[1]) || v.CandidateCellInfoListNRR15 != nil
			if err := per.EncodeBoolean(bb, present1); err != nil {
				return err
			}
		}
		for i := int64(2); i <= extHighest; i++ {
			p := i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.CandidateCellInfoListR10 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.CandidateCellInfoListR10 != nil); err != nil {
				return err
			}
			if v.CandidateCellInfoListR10 != nil {
				if err := per.EncodeCollection(extBuf, int64(len(v.CandidateCellInfoListR10)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_candidatecellinfolistr10, fragmentLength_candidatecellinfolistr10 int64) error {
					for _, elem := range v.CandidateCellInfoListR10[fragmentOffset_candidatecellinfolistr10 : fragmentOffset_candidatecellinfolistr10+fragmentLength_candidatecellinfolistr10] {
						if err := elem.MarshalUPERTo(extBuf); err != nil {
							return fmt.Errorf("encoding candidateCellInfoList-r10 element: %w", err)
						}
					}
					return nil
				}); err != nil {
					return fmt.Errorf("encoding candidateCellInfoList-r10: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(1) < int64(len(v.ExtPresent_)) && v.ExtPresent_[1]) || v.CandidateCellInfoListNRR15 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.CandidateCellInfoListNRR15 != nil); err != nil {
				return err
			}
			if v.CandidateCellInfoListNRR15 != nil {
				if err := per.EncodeCollection(extBuf, int64(len(v.CandidateCellInfoListNRR15)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_candidatecellinfolistnrr15, fragmentLength_candidatecellinfolistnrr15 int64) error {
					for _, elem := range v.CandidateCellInfoListNRR15[fragmentOffset_candidatecellinfolistnrr15 : fragmentOffset_candidatecellinfolistnrr15+fragmentLength_candidatecellinfolistnrr15] {
						if err := elem.MarshalUPERTo(extBuf); err != nil {
							return fmt.Errorf("encoding candidateCellInfoListNR-r15 element: %w", err)
						}
					}
					return nil
				}); err != nil {
					return fmt.Errorf("encoding candidateCellInfoListNR-r15: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		for i := int64(2); i <= extHighest; i++ {
			if i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i] {
				if i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil {
					if err := per.EncodeOpenType(bb, v.ExtData_[i]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes RRMConfig from UPER format.
func (v *RRMConfig) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *RRMConfig) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = RRMConfig{}
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
			return fmt.Errorf("decoding ue-InactiveTime: %w", err)
		}
		v.UeInactiveTime = &val_ueinactivetime
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtPresent_ = extPresent
		if int64(0) <= extCount && extPresent[0] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_candidatecellinfolistr10, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_candidatecellinfolistr10 {
				tmp_candidatecellinfolistr10 := make(CandidateCellInfoListR10, 0)
				_, errCollection_candidatecellinfolistr10 := per.DecodeCollection(extBB, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_candidatecellinfolistr10, fragmentLength_candidatecellinfolistr10 int64) error {
					for i := int64(0); i < fragmentLength_candidatecellinfolistr10; i++ {
						var elem CandidateCellInfoR10
						if err := elem.UnmarshalUPERFrom(extBB); err != nil {
							return fmt.Errorf("decoding candidateCellInfoList-r10 element %d: %w", fragmentOffset_candidatecellinfolistr10+i, err)
						}
						tmp_candidatecellinfolistr10 = append(tmp_candidatecellinfolistr10, elem)
					}
					return nil
				})
				if errCollection_candidatecellinfolistr10 != nil {
					return fmt.Errorf("decoding candidateCellInfoList-r10: %w", errCollection_candidatecellinfolistr10)
				}
				v.CandidateCellInfoListR10 = tmp_candidatecellinfolistr10
			}
		}
		if int64(1) <= extCount && extPresent[1] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_candidatecellinfolistnrr15, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_candidatecellinfolistnrr15 {
				tmp_candidatecellinfolistnrr15 := make(MeasResultServFreqListNRR15, 0)
				_, errCollection_candidatecellinfolistnrr15 := per.DecodeCollection(extBB, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_candidatecellinfolistnrr15, fragmentLength_candidatecellinfolistnrr15 int64) error {
					for i := int64(0); i < fragmentLength_candidatecellinfolistnrr15; i++ {
						var elem MeasResultServFreqNRR15
						if err := elem.UnmarshalUPERFrom(extBB); err != nil {
							return fmt.Errorf("decoding candidateCellInfoListNR-r15 element %d: %w", fragmentOffset_candidatecellinfolistnrr15+i, err)
						}
						tmp_candidatecellinfolistnrr15 = append(tmp_candidatecellinfolistnrr15, elem)
					}
					return nil
				})
				if errCollection_candidatecellinfolistnrr15 != nil {
					return fmt.Errorf("decoding candidateCellInfoListNR-r15: %w", errCollection_candidatecellinfolistnrr15)
				}
				v.CandidateCellInfoListNRR15 = tmp_candidatecellinfolistnrr15
			}
		}
		v.ExtData_ = make([][]byte, extCount+1)
		for i := int64(2); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

type asn1cUPERCandidateCellInfoListR10ListValue struct{ Value CandidateCellInfoListR10 }

// MarshalUPERCandidateCellInfoListR10 encodes a CandidateCellInfoListR10 list to UPER.
func MarshalUPERCandidateCellInfoListR10(list CandidateCellInfoListR10) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERCandidateCellInfoListR10To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERCandidateCellInfoListR10To appends a CandidateCellInfoListR10 list to bb.
func MarshalUPERCandidateCellInfoListR10To(list CandidateCellInfoListR10, bb *per.BitBuffer) error {
	v := asn1cUPERCandidateCellInfoListR10ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERCandidateCellInfoListR10 decodes a CandidateCellInfoListR10 list from UPER.
func UnmarshalUPERCandidateCellInfoListR10(data []byte) (CandidateCellInfoListR10, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERCandidateCellInfoListR10From(bb)
}

// UnmarshalUPERCandidateCellInfoListR10From decodes a CandidateCellInfoListR10 list from bb.
func UnmarshalUPERCandidateCellInfoListR10From(bb *per.BitBuffer) (CandidateCellInfoListR10, error) {
	var v asn1cUPERCandidateCellInfoListR10ListValue
	if err := unmarshalUPERCandidateCellInfoListR10Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERCandidateCellInfoListR10Into(v *asn1cUPERCandidateCellInfoListR10ListValue, bb *per.BitBuffer) error {
	v.Value = make(CandidateCellInfoListR10, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem CandidateCellInfoR10
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

// MarshalUPER encodes CandidateCellInfoR10 to UPER format.
func (v *CandidateCellInfoR10) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CandidateCellInfoR10) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.DlCarrierFreqV1090 != nil || v.RsrqResultV1250 != nil || v.RsSinrResultR13 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.RsrpResultR10 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.RsrqResultR10 != nil); err != nil {
		return err
	}
	if err := per.EncodeInteger(bb, int64(v.PhysCellIdR10), int64Ptr(0), int64Ptr(503), false); err != nil {
		return fmt.Errorf("encoding physCellId-r10: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.DlCarrierFreqR10), int64Ptr(0), int64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding dl-CarrierFreq-r10: %w", err)
	}
	if v.RsrpResultR10 != nil {
		if err := per.EncodeInteger(bb, int64(*v.RsrpResultR10), int64Ptr(0), int64Ptr(97), false); err != nil {
			return fmt.Errorf("encoding rsrpResult-r10: %w", err)
		}
	}
	if v.RsrqResultR10 != nil {
		if err := per.EncodeInteger(bb, int64(*v.RsrqResultR10), int64Ptr(0), int64Ptr(34), false); err != nil {
			return fmt.Errorf("encoding rsrqResult-r10: %w", err)
		}
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.DlCarrierFreqV1090 != nil {
			extHighest = 0
		}
		if v.RsrqResultV1250 != nil {
			extHighest = 1
		}
		if v.RsSinrResultR13 != nil {
			extHighest = 2
		}
		if v.ExtCount_ > extHighest {
			extHighest = v.ExtCount_
		}
		if err := per.EncodeNormallySmallNonNegative(bb, extHighest); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.DlCarrierFreqV1090 != nil
			if err := per.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		if int64(1) <= extHighest {
			present1 := (int64(1) < int64(len(v.ExtPresent_)) && v.ExtPresent_[1]) || v.RsrqResultV1250 != nil
			if err := per.EncodeBoolean(bb, present1); err != nil {
				return err
			}
		}
		if int64(2) <= extHighest {
			present2 := (int64(2) < int64(len(v.ExtPresent_)) && v.ExtPresent_[2]) || v.RsSinrResultR13 != nil
			if err := per.EncodeBoolean(bb, present2); err != nil {
				return err
			}
		}
		for i := int64(3); i <= extHighest; i++ {
			p := i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.DlCarrierFreqV1090 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.DlCarrierFreqV1090 != nil); err != nil {
				return err
			}
			if v.DlCarrierFreqV1090 != nil {
				if err := per.EncodeInteger(extBuf, int64(*v.DlCarrierFreqV1090), int64Ptr(65536), int64Ptr(262143), false); err != nil {
					return fmt.Errorf("encoding dl-CarrierFreq-v1090: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(1) < int64(len(v.ExtPresent_)) && v.ExtPresent_[1]) || v.RsrqResultV1250 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.RsrqResultV1250 != nil); err != nil {
				return err
			}
			if v.RsrqResultV1250 != nil {
				if err := per.EncodeInteger(extBuf, int64(*v.RsrqResultV1250), int64Ptr(-30), int64Ptr(46), false); err != nil {
					return fmt.Errorf("encoding rsrqResult-v1250: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(2) < int64(len(v.ExtPresent_)) && v.ExtPresent_[2]) || v.RsSinrResultR13 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.RsSinrResultR13 != nil); err != nil {
				return err
			}
			if v.RsSinrResultR13 != nil {
				if err := per.EncodeInteger(extBuf, int64(*v.RsSinrResultR13), int64Ptr(0), int64Ptr(127), false); err != nil {
					return fmt.Errorf("encoding rs-sinr-Result-r13: %w", err)
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		for i := int64(3); i <= extHighest; i++ {
			if i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i] {
				if i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil {
					if err := per.EncodeOpenType(bb, v.ExtData_[i]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes CandidateCellInfoR10 from UPER format.
func (v *CandidateCellInfoR10) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *CandidateCellInfoR10) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = CandidateCellInfoR10{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_rsrpresultr10, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_rsrqresultr10, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_physcellidr10, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return fmt.Errorf("decoding physCellId-r10: %w", err)
	}
	v.PhysCellIdR10 = PhysCellId(val_physcellidr10)
	val_dlcarrierfreqr10, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return fmt.Errorf("decoding dl-CarrierFreq-r10: %w", err)
	}
	v.DlCarrierFreqR10 = ARFCNValueEUTRA(val_dlcarrierfreqr10)
	if opt_rsrpresultr10 {
		val_rsrpresultr10, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(97), false)
		if err != nil {
			return fmt.Errorf("decoding rsrpResult-r10: %w", err)
		}
		tmp_rsrpresultr10 := RSRPRange(val_rsrpresultr10)
		v.RsrpResultR10 = &tmp_rsrpresultr10
	}
	if opt_rsrqresultr10 {
		val_rsrqresultr10, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(34), false)
		if err != nil {
			return fmt.Errorf("decoding rsrqResult-r10: %w", err)
		}
		tmp_rsrqresultr10 := RSRQRange(val_rsrqresultr10)
		v.RsrqResultR10 = &tmp_rsrqresultr10
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return err
		}
		v.ExtCount_ = extCount
		v.ExtPresent_ = extPresent
		if int64(0) <= extCount && extPresent[0] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_dlcarrierfreqv1090, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_dlcarrierfreqv1090 {
				val_dlcarrierfreqv1090, err := per.DecodeInteger(extBB, int64Ptr(65536), int64Ptr(262143), false)
				if err != nil {
					return fmt.Errorf("decoding dl-CarrierFreq-v1090: %w", err)
				}
				tmp_dlcarrierfreqv1090 := ARFCNValueEUTRAV9e0(val_dlcarrierfreqv1090)
				v.DlCarrierFreqV1090 = &tmp_dlcarrierfreqv1090
			}
		}
		if int64(1) <= extCount && extPresent[1] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_rsrqresultv1250, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_rsrqresultv1250 {
				val_rsrqresultv1250, err := per.DecodeInteger(extBB, int64Ptr(-30), int64Ptr(46), false)
				if err != nil {
					return fmt.Errorf("decoding rsrqResult-v1250: %w", err)
				}
				tmp_rsrqresultv1250 := RSRQRangeV1250(val_rsrqresultv1250)
				v.RsrqResultV1250 = &tmp_rsrqresultv1250
			}
		}
		if int64(2) <= extCount && extPresent[2] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_rssinrresultr13, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_rssinrresultr13 {
				val_rssinrresultr13, err := per.DecodeInteger(extBB, int64Ptr(0), int64Ptr(127), false)
				if err != nil {
					return fmt.Errorf("decoding rs-sinr-Result-r13: %w", err)
				}
				tmp_rssinrresultr13 := RSSINRRangeR13(val_rssinrresultr13)
				v.RsSinrResultR13 = &tmp_rssinrresultr13
			}
		}
		v.ExtData_ = make([][]byte, extCount+1)
		for i := int64(3); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return err
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes HandoverCommandCriticalExtensions to UPER format.
func (v *HandoverCommandCriticalExtensions) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverCommandCriticalExtensions) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case HandoverCommandCriticalExtensionsChoiceC1:
		if v.C1 == nil {
			return fmt.Errorf("choice alternative c1 is nil")
		}
		if err := v.C1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding c1: %w", err)
		}
	case HandoverCommandCriticalExtensionsChoiceCriticalExtensionsFuture:
		if v.CriticalExtensionsFuture == nil {
			return fmt.Errorf("choice alternative criticalExtensionsFuture is nil")
		}
		if err := v.CriticalExtensionsFuture.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding criticalExtensionsFuture: %w", err)
		}
	default:
		return fmt.Errorf("unknown HandoverCommandCriticalExtensions choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes HandoverCommandCriticalExtensions from UPER format.
func (v *HandoverCommandCriticalExtensions) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverCommandCriticalExtensions) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverCommandCriticalExtensions{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case HandoverCommandCriticalExtensionsChoiceC1:
		var dec_c1 HandoverCommandCriticalExtensionsC1
		if err := dec_c1.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding c1: %w", err)
		}
		v.C1 = &dec_c1
	case HandoverCommandCriticalExtensionsChoiceCriticalExtensionsFuture:
		var dec_criticalextensionsfuture HandoverCommandCriticalExtensionsCriticalExtensionsFuture
		if err := dec_criticalextensionsfuture.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding criticalExtensionsFuture: %w", err)
		}
		v.CriticalExtensionsFuture = &dec_criticalextensionsfuture
	}
	return nil
}

// MarshalUPER encodes HandoverCommandCriticalExtensionsC1 to UPER format.
func (v *HandoverCommandCriticalExtensionsC1) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverCommandCriticalExtensionsC1) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 7); err != nil {
		return err
	}
	switch v.Choice {
	case HandoverCommandCriticalExtensionsC1ChoiceHandoverCommandR8:
		if v.HandoverCommandR8 == nil {
			return fmt.Errorf("choice alternative handoverCommand-r8 is nil")
		}
		if err := v.HandoverCommandR8.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding handoverCommand-r8: %w", err)
		}
	case HandoverCommandCriticalExtensionsC1ChoiceSpare7:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare6:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare5:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare4:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare3:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare2:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare1:
	default:
		return fmt.Errorf("unknown HandoverCommandCriticalExtensionsC1 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes HandoverCommandCriticalExtensionsC1 from UPER format.
func (v *HandoverCommandCriticalExtensionsC1) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverCommandCriticalExtensionsC1) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverCommandCriticalExtensionsC1{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 7)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case HandoverCommandCriticalExtensionsC1ChoiceHandoverCommandR8:
		var dec_handovercommandr8 HandoverCommandR8IEs
		if err := dec_handovercommandr8.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding handoverCommand-r8: %w", err)
		}
		v.HandoverCommandR8 = &dec_handovercommandr8
	case HandoverCommandCriticalExtensionsC1ChoiceSpare7:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare6:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare5:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare4:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare3:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare2:
	case HandoverCommandCriticalExtensionsC1ChoiceSpare1:
	}
	return nil
}

// MarshalUPER encodes HandoverCommandCriticalExtensionsCriticalExtensionsFuture to UPER format.
func (v *HandoverCommandCriticalExtensionsCriticalExtensionsFuture) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverCommandCriticalExtensionsCriticalExtensionsFuture) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes HandoverCommandCriticalExtensionsCriticalExtensionsFuture from UPER format.
func (v *HandoverCommandCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverCommandCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverCommandCriticalExtensionsCriticalExtensionsFuture{}
	return nil
}

// MarshalUPER encodes HandoverCommandR8IEsNonCriticalExtension to UPER format.
func (v *HandoverCommandR8IEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverCommandR8IEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes HandoverCommandR8IEsNonCriticalExtension from UPER format.
func (v *HandoverCommandR8IEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverCommandR8IEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverCommandR8IEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationCriticalExtensions to UPER format.
func (v *HandoverPreparationInformationCriticalExtensions) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationCriticalExtensions) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case HandoverPreparationInformationCriticalExtensionsChoiceC1:
		if v.C1 == nil {
			return fmt.Errorf("choice alternative c1 is nil")
		}
		if err := v.C1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding c1: %w", err)
		}
	case HandoverPreparationInformationCriticalExtensionsChoiceCriticalExtensionsFuture:
		if v.CriticalExtensionsFuture == nil {
			return fmt.Errorf("choice alternative criticalExtensionsFuture is nil")
		}
		if err := v.CriticalExtensionsFuture.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding criticalExtensionsFuture: %w", err)
		}
	default:
		return fmt.Errorf("unknown HandoverPreparationInformationCriticalExtensions choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationCriticalExtensions from UPER format.
func (v *HandoverPreparationInformationCriticalExtensions) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationCriticalExtensions) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationCriticalExtensions{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case HandoverPreparationInformationCriticalExtensionsChoiceC1:
		var dec_c1 HandoverPreparationInformationCriticalExtensionsC1
		if err := dec_c1.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding c1: %w", err)
		}
		v.C1 = &dec_c1
	case HandoverPreparationInformationCriticalExtensionsChoiceCriticalExtensionsFuture:
		var dec_criticalextensionsfuture HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture
		if err := dec_criticalextensionsfuture.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding criticalExtensionsFuture: %w", err)
		}
		v.CriticalExtensionsFuture = &dec_criticalextensionsfuture
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationCriticalExtensionsC1 to UPER format.
func (v *HandoverPreparationInformationCriticalExtensionsC1) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationCriticalExtensionsC1) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 7); err != nil {
		return err
	}
	switch v.Choice {
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceHandoverPreparationInformationR8:
		if v.HandoverPreparationInformationR8 == nil {
			return fmt.Errorf("choice alternative handoverPreparationInformation-r8 is nil")
		}
		if err := v.HandoverPreparationInformationR8.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding handoverPreparationInformation-r8: %w", err)
		}
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare7:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare6:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare5:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare4:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare3:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare2:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare1:
	default:
		return fmt.Errorf("unknown HandoverPreparationInformationCriticalExtensionsC1 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationCriticalExtensionsC1 from UPER format.
func (v *HandoverPreparationInformationCriticalExtensionsC1) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationCriticalExtensionsC1) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationCriticalExtensionsC1{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 7)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceHandoverPreparationInformationR8:
		var dec_handoverpreparationinformationr8 HandoverPreparationInformationR8IEs
		if err := dec_handoverpreparationinformationr8.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding handoverPreparationInformation-r8: %w", err)
		}
		v.HandoverPreparationInformationR8 = &dec_handoverpreparationinformationr8
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare7:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare6:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare5:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare4:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare3:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare2:
	case HandoverPreparationInformationCriticalExtensionsC1ChoiceSpare1:
	}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture to UPER format.
func (v *HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture from UPER format.
func (v *HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationCriticalExtensionsCriticalExtensionsFuture{}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV13c0IEsNonCriticalExtension to UPER format.
func (v *HandoverPreparationInformationV13c0IEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV13c0IEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV13c0IEsNonCriticalExtension from UPER format.
func (v *HandoverPreparationInformationV13c0IEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV13c0IEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV13c0IEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes HandoverPreparationInformationV1700IEsNonCriticalExtension to UPER format.
func (v *HandoverPreparationInformationV1700IEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *HandoverPreparationInformationV1700IEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes HandoverPreparationInformationV1700IEsNonCriticalExtension from UPER format.
func (v *HandoverPreparationInformationV1700IEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *HandoverPreparationInformationV1700IEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationInformationV1700IEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes SCGConfigR12CriticalExtensions to UPER format.
func (v *SCGConfigR12CriticalExtensions) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigR12CriticalExtensions) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case SCGConfigR12CriticalExtensionsChoiceC1:
		if v.C1 == nil {
			return fmt.Errorf("choice alternative c1 is nil")
		}
		if err := v.C1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding c1: %w", err)
		}
	case SCGConfigR12CriticalExtensionsChoiceCriticalExtensionsFuture:
		if v.CriticalExtensionsFuture == nil {
			return fmt.Errorf("choice alternative criticalExtensionsFuture is nil")
		}
		if err := v.CriticalExtensionsFuture.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding criticalExtensionsFuture: %w", err)
		}
	default:
		return fmt.Errorf("unknown SCGConfigR12CriticalExtensions choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigR12CriticalExtensions from UPER format.
func (v *SCGConfigR12CriticalExtensions) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigR12CriticalExtensions) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigR12CriticalExtensions{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case SCGConfigR12CriticalExtensionsChoiceC1:
		var dec_c1 SCGConfigR12CriticalExtensionsC1
		if err := dec_c1.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding c1: %w", err)
		}
		v.C1 = &dec_c1
	case SCGConfigR12CriticalExtensionsChoiceCriticalExtensionsFuture:
		var dec_criticalextensionsfuture SCGConfigR12CriticalExtensionsCriticalExtensionsFuture
		if err := dec_criticalextensionsfuture.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding criticalExtensionsFuture: %w", err)
		}
		v.CriticalExtensionsFuture = &dec_criticalextensionsfuture
	}
	return nil
}

// MarshalUPER encodes SCGConfigR12CriticalExtensionsC1 to UPER format.
func (v *SCGConfigR12CriticalExtensionsC1) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigR12CriticalExtensionsC1) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 7); err != nil {
		return err
	}
	switch v.Choice {
	case SCGConfigR12CriticalExtensionsC1ChoiceScgConfigR12:
		if v.ScgConfigR12 == nil {
			return fmt.Errorf("choice alternative scg-Config-r12 is nil")
		}
		if err := v.ScgConfigR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding scg-Config-r12: %w", err)
		}
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare7:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare6:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare5:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare4:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare3:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare2:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare1:
	default:
		return fmt.Errorf("unknown SCGConfigR12CriticalExtensionsC1 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigR12CriticalExtensionsC1 from UPER format.
func (v *SCGConfigR12CriticalExtensionsC1) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigR12CriticalExtensionsC1) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigR12CriticalExtensionsC1{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 7)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case SCGConfigR12CriticalExtensionsC1ChoiceScgConfigR12:
		var dec_scgconfigr12 SCGConfigR12IEs
		if err := dec_scgconfigr12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding scg-Config-r12: %w", err)
		}
		v.ScgConfigR12 = &dec_scgconfigr12
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare7:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare6:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare5:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare4:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare3:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare2:
	case SCGConfigR12CriticalExtensionsC1ChoiceSpare1:
	}
	return nil
}

// MarshalUPER encodes SCGConfigR12CriticalExtensionsCriticalExtensionsFuture to UPER format.
func (v *SCGConfigR12CriticalExtensionsCriticalExtensionsFuture) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigR12CriticalExtensionsCriticalExtensionsFuture) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes SCGConfigR12CriticalExtensionsCriticalExtensionsFuture from UPER format.
func (v *SCGConfigR12CriticalExtensionsCriticalExtensionsFuture) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigR12CriticalExtensionsCriticalExtensionsFuture) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigR12CriticalExtensionsCriticalExtensionsFuture{}
	return nil
}

// MarshalUPER encodes SCGConfigV12i0bIEsNonCriticalExtension to UPER format.
func (v *SCGConfigV12i0bIEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigV12i0bIEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes SCGConfigV12i0bIEsNonCriticalExtension from UPER format.
func (v *SCGConfigV12i0bIEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigV12i0bIEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigV12i0bIEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes SCGConfigV13c0IEsNonCriticalExtension to UPER format.
func (v *SCGConfigV13c0IEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigV13c0IEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes SCGConfigV13c0IEsNonCriticalExtension from UPER format.
func (v *SCGConfigV13c0IEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigV13c0IEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigV13c0IEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes SCGConfigInfoR12CriticalExtensions to UPER format.
func (v *SCGConfigInfoR12CriticalExtensions) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigInfoR12CriticalExtensions) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case SCGConfigInfoR12CriticalExtensionsChoiceC1:
		if v.C1 == nil {
			return fmt.Errorf("choice alternative c1 is nil")
		}
		if err := v.C1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding c1: %w", err)
		}
	case SCGConfigInfoR12CriticalExtensionsChoiceCriticalExtensionsFuture:
		if v.CriticalExtensionsFuture == nil {
			return fmt.Errorf("choice alternative criticalExtensionsFuture is nil")
		}
		if err := v.CriticalExtensionsFuture.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding criticalExtensionsFuture: %w", err)
		}
	default:
		return fmt.Errorf("unknown SCGConfigInfoR12CriticalExtensions choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigInfoR12CriticalExtensions from UPER format.
func (v *SCGConfigInfoR12CriticalExtensions) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigInfoR12CriticalExtensions) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigInfoR12CriticalExtensions{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case SCGConfigInfoR12CriticalExtensionsChoiceC1:
		var dec_c1 SCGConfigInfoR12CriticalExtensionsC1
		if err := dec_c1.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding c1: %w", err)
		}
		v.C1 = &dec_c1
	case SCGConfigInfoR12CriticalExtensionsChoiceCriticalExtensionsFuture:
		var dec_criticalextensionsfuture SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture
		if err := dec_criticalextensionsfuture.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding criticalExtensionsFuture: %w", err)
		}
		v.CriticalExtensionsFuture = &dec_criticalextensionsfuture
	}
	return nil
}

// MarshalUPER encodes SCGConfigInfoR12CriticalExtensionsC1 to UPER format.
func (v *SCGConfigInfoR12CriticalExtensionsC1) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigInfoR12CriticalExtensionsC1) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 7); err != nil {
		return err
	}
	switch v.Choice {
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceScgConfigInfoR12:
		if v.ScgConfigInfoR12 == nil {
			return fmt.Errorf("choice alternative scg-ConfigInfo-r12 is nil")
		}
		if err := v.ScgConfigInfoR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding scg-ConfigInfo-r12: %w", err)
		}
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare7:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare6:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare5:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare4:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare3:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare2:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare1:
	default:
		return fmt.Errorf("unknown SCGConfigInfoR12CriticalExtensionsC1 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes SCGConfigInfoR12CriticalExtensionsC1 from UPER format.
func (v *SCGConfigInfoR12CriticalExtensionsC1) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigInfoR12CriticalExtensionsC1) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigInfoR12CriticalExtensionsC1{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 7)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceScgConfigInfoR12:
		var dec_scgconfiginfor12 SCGConfigInfoR12IEs
		if err := dec_scgconfiginfor12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding scg-ConfigInfo-r12: %w", err)
		}
		v.ScgConfigInfoR12 = &dec_scgconfiginfor12
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare7:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare6:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare5:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare4:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare3:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare2:
	case SCGConfigInfoR12CriticalExtensionsC1ChoiceSpare1:
	}
	return nil
}

// MarshalUPER encodes SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture to UPER format.
func (v *SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture from UPER format.
func (v *SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigInfoR12CriticalExtensionsCriticalExtensionsFuture{}
	return nil
}

// MarshalUPER encodes SCGConfigInfoV1530IEsNonCriticalExtension to UPER format.
func (v *SCGConfigInfoV1530IEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SCGConfigInfoV1530IEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes SCGConfigInfoV1530IEsNonCriticalExtension from UPER format.
func (v *SCGConfigInfoV1530IEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SCGConfigInfoV1530IEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SCGConfigInfoV1530IEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes CellToAddModR12CellIdentificationR12 to UPER format.
func (v *CellToAddModR12CellIdentificationR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CellToAddModR12CellIdentificationR12) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.PhysCellIdR12), int64Ptr(0), int64Ptr(503), false); err != nil {
		return fmt.Errorf("encoding physCellId-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.DlCarrierFreqR12), int64Ptr(0), int64Ptr(262143), false); err != nil {
		return fmt.Errorf("encoding dl-CarrierFreq-r12: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes CellToAddModR12CellIdentificationR12 from UPER format.
func (v *CellToAddModR12CellIdentificationR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *CellToAddModR12CellIdentificationR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = CellToAddModR12CellIdentificationR12{}
	val_physcellidr12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return fmt.Errorf("decoding physCellId-r12: %w", err)
	}
	v.PhysCellIdR12 = PhysCellId(val_physcellidr12)
	val_dlcarrierfreqr12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(262143), false)
	if err != nil {
		return fmt.Errorf("decoding dl-CarrierFreq-r12: %w", err)
	}
	v.DlCarrierFreqR12 = ARFCNValueEUTRAR9(val_dlcarrierfreqr12)
	return nil
}

// MarshalUPER encodes CellToAddModR12MeasResultCellToAddR12 to UPER format.
func (v *CellToAddModR12MeasResultCellToAddR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CellToAddModR12MeasResultCellToAddR12) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.RsrpResultR12), int64Ptr(0), int64Ptr(97), false); err != nil {
		return fmt.Errorf("encoding rsrpResult-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.RsrqResultR12), int64Ptr(0), int64Ptr(34), false); err != nil {
		return fmt.Errorf("encoding rsrqResult-r12: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes CellToAddModR12MeasResultCellToAddR12 from UPER format.
func (v *CellToAddModR12MeasResultCellToAddR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *CellToAddModR12MeasResultCellToAddR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = CellToAddModR12MeasResultCellToAddR12{}
	val_rsrpresultr12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(97), false)
	if err != nil {
		return fmt.Errorf("decoding rsrpResult-r12: %w", err)
	}
	v.RsrpResultR12 = RSRPRange(val_rsrpresultr12)
	val_rsrqresultr12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(34), false)
	if err != nil {
		return fmt.Errorf("decoding rsrqResult-r12: %w", err)
	}
	v.RsrqResultR12 = RSRQRange(val_rsrqresultr12)
	return nil
}

// MarshalUPER encodes CellToAddModR12MeasResultCellToAddV1310 to UPER format.
func (v *CellToAddModR12MeasResultCellToAddV1310) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CellToAddModR12MeasResultCellToAddV1310) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.RsSinrResultR13), int64Ptr(0), int64Ptr(127), false); err != nil {
		return fmt.Errorf("encoding rs-sinr-Result-r13: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes CellToAddModR12MeasResultCellToAddV1310 from UPER format.
func (v *CellToAddModR12MeasResultCellToAddV1310) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *CellToAddModR12MeasResultCellToAddV1310) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = CellToAddModR12MeasResultCellToAddV1310{}
	val_rssinrresultr13, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(127), false)
	if err != nil {
		return fmt.Errorf("decoding rs-sinr-Result-r13: %w", err)
	}
	v.RsSinrResultR13 = RSSINRRangeR13(val_rssinrresultr13)
	return nil
}

// MarshalUPER encodes MeasResultServCellSCGR12MeasResultSCellR12 to UPER format.
func (v *MeasResultServCellSCGR12MeasResultSCellR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *MeasResultServCellSCGR12MeasResultSCellR12) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.RsrpResultSCellR12), int64Ptr(0), int64Ptr(97), false); err != nil {
		return fmt.Errorf("encoding rsrpResultSCell-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.RsrqResultSCellR12), int64Ptr(0), int64Ptr(34), false); err != nil {
		return fmt.Errorf("encoding rsrqResultSCell-r12: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes MeasResultServCellSCGR12MeasResultSCellR12 from UPER format.
func (v *MeasResultServCellSCGR12MeasResultSCellR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *MeasResultServCellSCGR12MeasResultSCellR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = MeasResultServCellSCGR12MeasResultSCellR12{}
	val_rsrpresultscellr12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(97), false)
	if err != nil {
		return fmt.Errorf("decoding rsrpResultSCell-r12: %w", err)
	}
	v.RsrpResultSCellR12 = RSRPRange(val_rsrpresultscellr12)
	val_rsrqresultscellr12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(34), false)
	if err != nil {
		return fmt.Errorf("decoding rsrqResultSCell-r12: %w", err)
	}
	v.RsrqResultSCellR12 = RSRQRange(val_rsrqresultscellr12)
	return nil
}

// MarshalUPER encodes MeasResultServCellSCGR12MeasResultSCellV1310 to UPER format.
func (v *MeasResultServCellSCGR12MeasResultSCellV1310) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *MeasResultServCellSCGR12MeasResultSCellV1310) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.RsSinrResultSCellR13), int64Ptr(0), int64Ptr(127), false); err != nil {
		return fmt.Errorf("encoding rs-sinr-ResultSCell-r13: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes MeasResultServCellSCGR12MeasResultSCellV1310 from UPER format.
func (v *MeasResultServCellSCGR12MeasResultSCellV1310) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *MeasResultServCellSCGR12MeasResultSCellV1310) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = MeasResultServCellSCGR12MeasResultSCellV1310{}
	val_rssinrresultscellr13, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(127), false)
	if err != nil {
		return fmt.Errorf("decoding rs-sinr-ResultSCell-r13: %w", err)
	}
	v.RsSinrResultSCellR13 = RSSINRRangeR13(val_rssinrresultscellr13)
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationCriticalExtensions to UPER format.
func (v *UEPagingCoverageInformationCriticalExtensions) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UEPagingCoverageInformationCriticalExtensions) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case UEPagingCoverageInformationCriticalExtensionsChoiceC1:
		if v.C1 == nil {
			return fmt.Errorf("choice alternative c1 is nil")
		}
		if err := v.C1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding c1: %w", err)
		}
	case UEPagingCoverageInformationCriticalExtensionsChoiceCriticalExtensionsFuture:
		if v.CriticalExtensionsFuture == nil {
			return fmt.Errorf("choice alternative criticalExtensionsFuture is nil")
		}
		if err := v.CriticalExtensionsFuture.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding criticalExtensionsFuture: %w", err)
		}
	default:
		return fmt.Errorf("unknown UEPagingCoverageInformationCriticalExtensions choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationCriticalExtensions from UPER format.
func (v *UEPagingCoverageInformationCriticalExtensions) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UEPagingCoverageInformationCriticalExtensions) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationCriticalExtensions{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UEPagingCoverageInformationCriticalExtensionsChoiceC1:
		var dec_c1 UEPagingCoverageInformationCriticalExtensionsC1
		if err := dec_c1.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding c1: %w", err)
		}
		v.C1 = &dec_c1
	case UEPagingCoverageInformationCriticalExtensionsChoiceCriticalExtensionsFuture:
		var dec_criticalextensionsfuture UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture
		if err := dec_criticalextensionsfuture.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding criticalExtensionsFuture: %w", err)
		}
		v.CriticalExtensionsFuture = &dec_criticalextensionsfuture
	}
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationCriticalExtensionsC1 to UPER format.
func (v *UEPagingCoverageInformationCriticalExtensionsC1) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UEPagingCoverageInformationCriticalExtensionsC1) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 7); err != nil {
		return err
	}
	switch v.Choice {
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceUePagingCoverageInformationR13:
		if v.UePagingCoverageInformationR13 == nil {
			return fmt.Errorf("choice alternative uePagingCoverageInformation-r13 is nil")
		}
		if err := v.UePagingCoverageInformationR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding uePagingCoverageInformation-r13: %w", err)
		}
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare7:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare6:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare5:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare4:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare3:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare2:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare1:
	default:
		return fmt.Errorf("unknown UEPagingCoverageInformationCriticalExtensionsC1 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationCriticalExtensionsC1 from UPER format.
func (v *UEPagingCoverageInformationCriticalExtensionsC1) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UEPagingCoverageInformationCriticalExtensionsC1) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationCriticalExtensionsC1{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 7)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceUePagingCoverageInformationR13:
		var dec_uepagingcoverageinformationr13 UEPagingCoverageInformationR13IEs
		if err := dec_uepagingcoverageinformationr13.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding uePagingCoverageInformation-r13: %w", err)
		}
		v.UePagingCoverageInformationR13 = &dec_uepagingcoverageinformationr13
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare7:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare6:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare5:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare4:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare3:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare2:
	case UEPagingCoverageInformationCriticalExtensionsC1ChoiceSpare1:
	}
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture to UPER format.
func (v *UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture from UPER format.
func (v *UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationCriticalExtensionsCriticalExtensionsFuture{}
	return nil
}

// MarshalUPER encodes UEPagingCoverageInformationR13IEsNonCriticalExtension to UPER format.
func (v *UEPagingCoverageInformationR13IEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UEPagingCoverageInformationR13IEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UEPagingCoverageInformationR13IEsNonCriticalExtension from UPER format.
func (v *UEPagingCoverageInformationR13IEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UEPagingCoverageInformationR13IEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UEPagingCoverageInformationR13IEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationCriticalExtensions to UPER format.
func (v *UERadioAccessCapabilityInformationCriticalExtensions) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioAccessCapabilityInformationCriticalExtensions) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case UERadioAccessCapabilityInformationCriticalExtensionsChoiceC1:
		if v.C1 == nil {
			return fmt.Errorf("choice alternative c1 is nil")
		}
		if err := v.C1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding c1: %w", err)
		}
	case UERadioAccessCapabilityInformationCriticalExtensionsChoiceCriticalExtensionsFuture:
		if v.CriticalExtensionsFuture == nil {
			return fmt.Errorf("choice alternative criticalExtensionsFuture is nil")
		}
		if err := v.CriticalExtensionsFuture.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding criticalExtensionsFuture: %w", err)
		}
	default:
		return fmt.Errorf("unknown UERadioAccessCapabilityInformationCriticalExtensions choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationCriticalExtensions from UPER format.
func (v *UERadioAccessCapabilityInformationCriticalExtensions) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioAccessCapabilityInformationCriticalExtensions) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationCriticalExtensions{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UERadioAccessCapabilityInformationCriticalExtensionsChoiceC1:
		var dec_c1 UERadioAccessCapabilityInformationCriticalExtensionsC1
		if err := dec_c1.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding c1: %w", err)
		}
		v.C1 = &dec_c1
	case UERadioAccessCapabilityInformationCriticalExtensionsChoiceCriticalExtensionsFuture:
		var dec_criticalextensionsfuture UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture
		if err := dec_criticalextensionsfuture.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding criticalExtensionsFuture: %w", err)
		}
		v.CriticalExtensionsFuture = &dec_criticalextensionsfuture
	}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationCriticalExtensionsC1 to UPER format.
func (v *UERadioAccessCapabilityInformationCriticalExtensionsC1) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioAccessCapabilityInformationCriticalExtensionsC1) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 7); err != nil {
		return err
	}
	switch v.Choice {
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceUeRadioAccessCapabilityInformationR8:
		if v.UeRadioAccessCapabilityInformationR8 == nil {
			return fmt.Errorf("choice alternative ueRadioAccessCapabilityInformation-r8 is nil")
		}
		if err := v.UeRadioAccessCapabilityInformationR8.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding ueRadioAccessCapabilityInformation-r8: %w", err)
		}
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare7:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare6:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare5:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare4:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare3:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare2:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare1:
	default:
		return fmt.Errorf("unknown UERadioAccessCapabilityInformationCriticalExtensionsC1 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationCriticalExtensionsC1 from UPER format.
func (v *UERadioAccessCapabilityInformationCriticalExtensionsC1) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioAccessCapabilityInformationCriticalExtensionsC1) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationCriticalExtensionsC1{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 7)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceUeRadioAccessCapabilityInformationR8:
		var dec_ueradioaccesscapabilityinformationr8 UERadioAccessCapabilityInformationR8IEs
		if err := dec_ueradioaccesscapabilityinformationr8.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding ueRadioAccessCapabilityInformation-r8: %w", err)
		}
		v.UeRadioAccessCapabilityInformationR8 = &dec_ueradioaccesscapabilityinformationr8
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare7:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare6:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare5:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare4:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare3:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare2:
	case UERadioAccessCapabilityInformationCriticalExtensionsC1ChoiceSpare1:
	}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture to UPER format.
func (v *UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture from UPER format.
func (v *UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationCriticalExtensionsCriticalExtensionsFuture{}
	return nil
}

// MarshalUPER encodes UERadioAccessCapabilityInformationR8IEsNonCriticalExtension to UPER format.
func (v *UERadioAccessCapabilityInformationR8IEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioAccessCapabilityInformationR8IEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UERadioAccessCapabilityInformationR8IEsNonCriticalExtension from UPER format.
func (v *UERadioAccessCapabilityInformationR8IEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioAccessCapabilityInformationR8IEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioAccessCapabilityInformationR8IEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationCriticalExtensions to UPER format.
func (v *UERadioPagingInformationCriticalExtensions) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioPagingInformationCriticalExtensions) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case UERadioPagingInformationCriticalExtensionsChoiceC1:
		if v.C1 == nil {
			return fmt.Errorf("choice alternative c1 is nil")
		}
		if err := v.C1.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding c1: %w", err)
		}
	case UERadioPagingInformationCriticalExtensionsChoiceCriticalExtensionsFuture:
		if v.CriticalExtensionsFuture == nil {
			return fmt.Errorf("choice alternative criticalExtensionsFuture is nil")
		}
		if err := v.CriticalExtensionsFuture.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding criticalExtensionsFuture: %w", err)
		}
	default:
		return fmt.Errorf("unknown UERadioPagingInformationCriticalExtensions choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationCriticalExtensions from UPER format.
func (v *UERadioPagingInformationCriticalExtensions) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioPagingInformationCriticalExtensions) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationCriticalExtensions{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UERadioPagingInformationCriticalExtensionsChoiceC1:
		var dec_c1 UERadioPagingInformationCriticalExtensionsC1
		if err := dec_c1.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding c1: %w", err)
		}
		v.C1 = &dec_c1
	case UERadioPagingInformationCriticalExtensionsChoiceCriticalExtensionsFuture:
		var dec_criticalextensionsfuture UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture
		if err := dec_criticalextensionsfuture.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding criticalExtensionsFuture: %w", err)
		}
		v.CriticalExtensionsFuture = &dec_criticalextensionsfuture
	}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationCriticalExtensionsC1 to UPER format.
func (v *UERadioPagingInformationCriticalExtensionsC1) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioPagingInformationCriticalExtensionsC1) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 7); err != nil {
		return err
	}
	switch v.Choice {
	case UERadioPagingInformationCriticalExtensionsC1ChoiceUeRadioPagingInformationR12:
		if v.UeRadioPagingInformationR12 == nil {
			return fmt.Errorf("choice alternative ueRadioPagingInformation-r12 is nil")
		}
		if err := v.UeRadioPagingInformationR12.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding ueRadioPagingInformation-r12: %w", err)
		}
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare7:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare6:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare5:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare4:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare3:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare2:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare1:
	default:
		return fmt.Errorf("unknown UERadioPagingInformationCriticalExtensionsC1 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationCriticalExtensionsC1 from UPER format.
func (v *UERadioPagingInformationCriticalExtensionsC1) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioPagingInformationCriticalExtensionsC1) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationCriticalExtensionsC1{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 7)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case UERadioPagingInformationCriticalExtensionsC1ChoiceUeRadioPagingInformationR12:
		var dec_ueradiopaginginformationr12 UERadioPagingInformationR12IEs
		if err := dec_ueradiopaginginformationr12.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding ueRadioPagingInformation-r12: %w", err)
		}
		v.UeRadioPagingInformationR12 = &dec_ueradiopaginginformationr12
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare7:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare6:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare5:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare4:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare3:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare2:
	case UERadioPagingInformationCriticalExtensionsC1ChoiceSpare1:
	}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture to UPER format.
func (v *UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture from UPER format.
func (v *UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationCriticalExtensionsCriticalExtensionsFuture{}
	return nil
}

type asn1cUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13ListValue struct {
	Value UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13
}

// MarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13 encodes a UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13 list to UPER.
func MarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13(list UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13To appends a UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13 list to bb.
func MarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13To(list UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13, bb *per.BitBuffer) error {
	v := asn1cUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(256), false); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13 decodes a UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13 list from UPER.
func UnmarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13(data []byte) (UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13From(bb)
}

// UnmarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13From decodes a UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13 list from bb.
func UnmarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13From(bb *per.BitBuffer) (UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13, error) {
	var v asn1cUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13ListValue
	if err := unmarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13Into(v *asn1cUPERUERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13ListValue, bb *per.BitBuffer) error {
	v.Value = make(UERadioPagingInformationV1310IEsSupportedBandListEUTRAForPagingR13, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(256), false)
			if err != nil {
				return fmt.Errorf("decoding value element %d: %w", fragmentOffset_value+i, err)
			}
			v.Value = append(v.Value, FreqBandIndicatorR11(val))
		}
		return nil
	})
	if errCollection_value != nil {
		return fmt.Errorf("decoding value: %w", errCollection_value)
	}
	return nil
}

// MarshalUPER encodes UERadioPagingInformationV1610IEsNonCriticalExtension to UPER format.
func (v *UERadioPagingInformationV1610IEsNonCriticalExtension) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *UERadioPagingInformationV1610IEsNonCriticalExtension) MarshalUPERTo(bb *per.BitBuffer) error {
	return nil
}

// UnmarshalUPER decodes UERadioPagingInformationV1610IEsNonCriticalExtension from UPER format.
func (v *UERadioPagingInformationV1610IEsNonCriticalExtension) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *UERadioPagingInformationV1610IEsNonCriticalExtension) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = UERadioPagingInformationV1610IEsNonCriticalExtension{}
	return nil
}

// MarshalUPER encodes ASConfigV1550TdmPatternConfigR15 to UPER format.
func (v *ASConfigV1550TdmPatternConfigR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ASConfigV1550TdmPatternConfigR15) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeEnumerated(bb, int64(v.SubframeAssignmentR15), 7, false); err != nil {
		return fmt.Errorf("encoding subframeAssignment-r15: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.HarqOffsetR15), int64Ptr(0), int64Ptr(9), false); err != nil {
		return fmt.Errorf("encoding harq-Offset-r15: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes ASConfigV1550TdmPatternConfigR15 from UPER format.
func (v *ASConfigV1550TdmPatternConfigR15) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *ASConfigV1550TdmPatternConfigR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = ASConfigV1550TdmPatternConfigR15{}
	val_subframeassignmentr15, err := per.DecodeEnumerated(bb, 7, false)
	if err != nil {
		return fmt.Errorf("decoding subframeAssignment-r15: %w", err)
	}
	v.SubframeAssignmentR15 = SubframeAssignmentR15(val_subframeassignmentr15)
	val_harqoffsetr15, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(9), false)
	if err != nil {
		return fmt.Errorf("decoding harq-Offset-r15: %w", err)
	}
	v.HarqOffsetR15 = val_harqoffsetr15
	return nil
}
