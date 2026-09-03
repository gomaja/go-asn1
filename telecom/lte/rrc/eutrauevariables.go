// Code generated from ASN.1 module "EUTRA-UE-Variables". DO NOT EDIT.

package rrc

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

	// MaxLogMeasR10 is the integer constant for maxLogMeas-r10.
	MaxLogMeasR10 int64 = 4060
)

// VarConditionalReconfiguration represents the ASN.1 type VarConditionalReconfiguration (SEQUENCE).
type VarConditionalReconfiguration struct {
	CondReconfigurationListR16       CondReconfigurationToAddModListR16 `asn1:"tag:0,context,implicit,optional" json:"CondReconfigurationListR16,omitempty"`
	CondReconfigurationListR16Indef_ bool                               `asn1:"-" json:"-"`
}

// VarConnEstFailReportR11 represents the ASN.1 type VarConnEstFailReport-r11 (SEQUENCE).
type VarConnEstFailReportR11 struct {
	ConnEstFailReportR11 ConnEstFailReportR11 `asn1:"tag:0,context,implicit"`
	PlmnIdentityR11      PLMNIdentity         `asn1:"tag:1,context,implicit"`
}

// VarLogMeasConfigR10 represents the ASN.1 type VarLogMeasConfig-r10 (SEQUENCE).
type VarLogMeasConfigR10 struct {
	AreaConfigurationR10 *AreaConfigurationR10 `asn1:"tag:0,context,explicit,optional" json:"AreaConfigurationR10,omitempty"`
	LoggingDurationR10   LoggingDurationR10    `asn1:"tag:1,context,implicit"`
	LoggingIntervalR10   LoggingIntervalR10    `asn1:"tag:2,context,implicit"`
}

// VarLogMeasConfigR11 represents the ASN.1 type VarLogMeasConfig-r11 (SEQUENCE).
type VarLogMeasConfigR11 struct {
	AreaConfigurationR10   *AreaConfigurationR10   `asn1:"tag:0,context,explicit,optional" json:"AreaConfigurationR10,omitempty"`
	AreaConfigurationV1130 *AreaConfigurationV1130 `asn1:"tag:1,context,implicit,optional" json:"AreaConfigurationV1130,omitempty"`
	LoggingDurationR10     LoggingDurationR10      `asn1:"tag:2,context,implicit"`
	LoggingIntervalR10     LoggingIntervalR10      `asn1:"tag:3,context,implicit"`
}

// VarLogMeasConfigR12 represents the ASN.1 type VarLogMeasConfig-r12 (SEQUENCE).
type VarLogMeasConfigR12 struct {
	AreaConfigurationR10         *AreaConfigurationR10   `asn1:"tag:0,context,explicit,optional" json:"AreaConfigurationR10,omitempty"`
	AreaConfigurationV1130       *AreaConfigurationV1130 `asn1:"tag:1,context,implicit,optional" json:"AreaConfigurationV1130,omitempty"`
	LoggingDurationR10           LoggingDurationR10      `asn1:"tag:2,context,implicit"`
	LoggingIntervalR10           LoggingIntervalR10      `asn1:"tag:3,context,implicit"`
	TargetMBSFNAreaListR12       TargetMBSFNAreaListR12  `asn1:"tag:4,context,implicit,optional" json:"TargetMBSFNAreaListR12,omitempty"`
	TargetMBSFNAreaListR12Indef_ bool                    `asn1:"-" json:"-"`
}

// VarLogMeasConfigR15 represents the ASN.1 type VarLogMeasConfig-r15 (SEQUENCE).
type VarLogMeasConfigR15 struct {
	AreaConfigurationR10         *AreaConfigurationR10   `asn1:"tag:0,context,explicit,optional" json:"AreaConfigurationR10,omitempty"`
	AreaConfigurationV1130       *AreaConfigurationV1130 `asn1:"tag:1,context,implicit,optional" json:"AreaConfigurationV1130,omitempty"`
	LoggingDurationR10           LoggingDurationR10      `asn1:"tag:2,context,implicit"`
	LoggingIntervalR10           LoggingIntervalR10      `asn1:"tag:3,context,implicit"`
	TargetMBSFNAreaListR12       TargetMBSFNAreaListR12  `asn1:"tag:4,context,implicit,optional" json:"TargetMBSFNAreaListR12,omitempty"`
	TargetMBSFNAreaListR12Indef_ bool                    `asn1:"-" json:"-"`
	BtNameListR15                BTNameListR15           `asn1:"tag:5,context,implicit,optional" json:"BtNameListR15,omitempty"`
	BtNameListR15Indef_          bool                    `asn1:"-" json:"-"`
	WlanNameListR15              WLANNameListR15         `asn1:"tag:6,context,implicit,optional" json:"WlanNameListR15,omitempty"`
	WlanNameListR15Indef_        bool                    `asn1:"-" json:"-"`
}

// VarLogMeasConfigR17 represents the ASN.1 type VarLogMeasConfig-r17 (SEQUENCE).
type VarLogMeasConfigR17 struct {
	AreaConfigurationR10         *AreaConfigurationR10        `asn1:"tag:0,context,explicit,optional" json:"AreaConfigurationR10,omitempty"`
	AreaConfigurationV1130       *AreaConfigurationV1130      `asn1:"tag:1,context,implicit,optional" json:"AreaConfigurationV1130,omitempty"`
	LoggingDurationR10           LoggingDurationR10           `asn1:"tag:2,context,implicit"`
	LoggingIntervalR10           LoggingIntervalR10           `asn1:"tag:3,context,implicit"`
	TargetMBSFNAreaListR12       TargetMBSFNAreaListR12       `asn1:"tag:4,context,implicit,optional" json:"TargetMBSFNAreaListR12,omitempty"`
	TargetMBSFNAreaListR12Indef_ bool                         `asn1:"-" json:"-"`
	BtNameListR15                BTNameListR15                `asn1:"tag:5,context,implicit,optional" json:"BtNameListR15,omitempty"`
	BtNameListR15Indef_          bool                         `asn1:"-" json:"-"`
	WlanNameListR15              WLANNameListR15              `asn1:"tag:6,context,implicit,optional" json:"WlanNameListR15,omitempty"`
	WlanNameListR15Indef_        bool                         `asn1:"-" json:"-"`
	LoggedEventTriggerConfigR17  *LoggedEventTriggerConfigR17 `asn1:"tag:7,context,implicit,optional" json:"LoggedEventTriggerConfigR17,omitempty"`
	MeasUncomBarPreR17           *int64                       `asn1:"tag:8,context,implicit,optional" json:"MeasUncomBarPreR17,omitempty"`
}

// VarLogMeasReportR10 represents the ASN.1 type VarLogMeasReport-r10 (SEQUENCE).
type VarLogMeasReportR10 struct {
	TraceReferenceR10           TraceReferenceR10   `asn1:"tag:0,context,implicit"`
	TraceRecordingSessionRefR10 []byte              `asn1:"tag:1,context,implicit"`
	TceIdR10                    []byte              `asn1:"tag:2,context,implicit"`
	PlmnIdentityR10             PLMNIdentity        `asn1:"tag:3,context,implicit"`
	AbsoluteTimeInfoR10         AbsoluteTimeInfoR10 `asn1:"tag:4,context,implicit"`
	LogMeasInfoListR10          LogMeasInfoList2R10 `asn1:"tag:5,context,implicit"`
	LogMeasInfoListR10Indef_    bool                `asn1:"-" json:"-"`
}

// VarLogMeasReportR11 represents the ASN.1 type VarLogMeasReport-r11 (SEQUENCE).
type VarLogMeasReportR11 struct {
	TraceReferenceR10           TraceReferenceR10    `asn1:"tag:0,context,implicit"`
	TraceRecordingSessionRefR10 []byte               `asn1:"tag:1,context,implicit"`
	TceIdR10                    []byte               `asn1:"tag:2,context,implicit"`
	PlmnIdentityListR11         PLMNIdentityList3R11 `asn1:"tag:3,context,implicit"`
	PlmnIdentityListR11Indef_   bool                 `asn1:"-" json:"-"`
	AbsoluteTimeInfoR10         AbsoluteTimeInfoR10  `asn1:"tag:4,context,implicit"`
	LogMeasInfoListR10          LogMeasInfoList2R10  `asn1:"tag:5,context,implicit"`
	LogMeasInfoListR10Indef_    bool                 `asn1:"-" json:"-"`
	SigLoggedMeasTypeR18        int64                `asn1:"tag:6,context,implicit"`
}

// LogMeasInfoList2R10 represents the ASN.1 type LogMeasInfoList2-r10 (SEQUENCE_OF).
type LogMeasInfoList2R10 = []LogMeasInfoR10

// VarMeasConfig represents the ASN.1 type VarMeasConfig (SEQUENCE).
type VarMeasConfig struct {
	MeasIdList                 MeasIdToAddModList           `asn1:"tag:0,context,implicit,optional" json:"MeasIdList,omitempty"`
	MeasIdListIndef_           bool                         `asn1:"-" json:"-"`
	MeasIdListExtR12           MeasIdToAddModListExtR12     `asn1:"tag:1,context,implicit,optional" json:"MeasIdListExtR12,omitempty"`
	MeasIdListExtR12Indef_     bool                         `asn1:"-" json:"-"`
	MeasIdListV1310            MeasIdToAddModListV1310      `asn1:"tag:2,context,implicit,optional" json:"MeasIdListV1310,omitempty"`
	MeasIdListV1310Indef_      bool                         `asn1:"-" json:"-"`
	MeasIdListExtV1310         MeasIdToAddModListExtV1310   `asn1:"tag:3,context,implicit,optional" json:"MeasIdListExtV1310,omitempty"`
	MeasIdListExtV1310Indef_   bool                         `asn1:"-" json:"-"`
	MeasObjectList             MeasObjectToAddModList       `asn1:"tag:4,context,implicit,optional" json:"MeasObjectList,omitempty"`
	MeasObjectListIndef_       bool                         `asn1:"-" json:"-"`
	MeasObjectListExtR13       MeasObjectToAddModListExtR13 `asn1:"tag:5,context,implicit,optional" json:"MeasObjectListExtR13,omitempty"`
	MeasObjectListExtR13Indef_ bool                         `asn1:"-" json:"-"`
	MeasObjectListV9i0         MeasObjectToAddModListV9e0   `asn1:"tag:6,context,implicit,optional" json:"MeasObjectListV9i0,omitempty"`
	MeasObjectListV9i0Indef_   bool                         `asn1:"-" json:"-"`
	ReportConfigList           ReportConfigToAddModList     `asn1:"tag:7,context,implicit,optional" json:"ReportConfigList,omitempty"`
	ReportConfigListIndef_     bool                         `asn1:"-" json:"-"`
	QuantityConfig             *QuantityConfig              `asn1:"tag:8,context,implicit,optional" json:"QuantityConfig,omitempty"`
	MeasScaleFactorR12         *MeasScaleFactorR12          `asn1:"tag:9,context,implicit,optional" json:"MeasScaleFactorR12,omitempty"`
	SMeasure                   *int64                       `asn1:"tag:10,context,implicit,optional" json:"SMeasure,omitempty"`
	SpeedStatePars             *VarMeasConfigSpeedStatePars `asn1:"tag:11,context,explicit,optional" json:"SpeedStatePars,omitempty"`
	AllowInterruptionsR11      *bool                        `asn1:"tag:12,context,implicit,optional" json:"AllowInterruptionsR11,omitempty"`
	AllowInterruptionsR11Raw_  byte                         `asn1:"-" json:"-"`
}

// VarMeasIdleConfigR15 represents the ASN.1 type VarMeasIdleConfig-r15 (SEQUENCE).
type VarMeasIdleConfigR15 struct {
	MeasIdleCarrierListEUTRAR15       EUTRACarrierListR15 `asn1:"tag:0,context,implicit,optional" json:"MeasIdleCarrierListEUTRAR15,omitempty"`
	MeasIdleCarrierListEUTRAR15Indef_ bool                `asn1:"-" json:"-"`
	MeasIdleDurationR15               int64               `asn1:"tag:1,context,implicit"`
}

// VarMeasIdleConfigR16 represents the ASN.1 type VarMeasIdleConfig-r16 (SEQUENCE).
type VarMeasIdleConfigR16 struct {
	MeasIdleCarrierListNRR16       NRCarrierListR16    `asn1:"tag:0,context,implicit,optional" json:"MeasIdleCarrierListNRR16,omitempty"`
	MeasIdleCarrierListNRR16Indef_ bool                `asn1:"-" json:"-"`
	ValidityAreaListR16            ValidityAreaListR16 `asn1:"tag:1,context,implicit,optional" json:"ValidityAreaListR16,omitempty"`
	ValidityAreaListR16Indef_      bool                `asn1:"-" json:"-"`
}

// VarMeasIdleReportR15 represents the ASN.1 type VarMeasIdleReport-r15 (SEQUENCE).
type VarMeasIdleReportR15 struct {
	MeasReportIdleR15       MeasResultListIdleR15 `asn1:"tag:0,context,implicit"`
	MeasReportIdleR15Indef_ bool                  `asn1:"-" json:"-"`
}

// VarMeasIdleReportR16 represents the ASN.1 type VarMeasIdleReport-r16 (SEQUENCE).
type VarMeasIdleReportR16 struct {
	MeasReportIdleR16         MeasResultListExtIdleR16 `asn1:"tag:0,context,implicit,optional" json:"MeasReportIdleR16,omitempty"`
	MeasReportIdleR16Indef_   bool                     `asn1:"-" json:"-"`
	MeasReportIdleNRR16       MeasResultListIdleNRR16  `asn1:"tag:1,context,implicit,optional" json:"MeasReportIdleNRR16,omitempty"`
	MeasReportIdleNRR16Indef_ bool                     `asn1:"-" json:"-"`
}

// VarMeasReportList represents the ASN.1 type VarMeasReportList (SEQUENCE_OF).
type VarMeasReportList = []VarMeasReport

// VarMeasReportListR12 represents the ASN.1 type VarMeasReportList-r12 (SEQUENCE_OF).
type VarMeasReportListR12 = []VarMeasReport

// VarMeasReport represents the ASN.1 type VarMeasReport (SEQUENCE).
type VarMeasReport struct {
	MeasId                      MeasId                    `asn1:"tag:0,context,implicit"`
	MeasIdV1250                 *MeasIdV1250              `asn1:"tag:1,context,implicit,optional" json:"MeasIdV1250,omitempty"`
	CellsTriggeredList          CellsTriggeredList        `asn1:"tag:2,context,implicit,optional" json:"CellsTriggeredList,omitempty"`
	CellsTriggeredListIndef_    bool                      `asn1:"-" json:"-"`
	CsiRSTriggeredListR12       CSIRSTriggeredListR12     `asn1:"tag:3,context,implicit,optional" json:"CsiRSTriggeredListR12,omitempty"`
	CsiRSTriggeredListR12Indef_ bool                      `asn1:"-" json:"-"`
	PoolsTriggeredListR14       TxResourcePoolMeasListR14 `asn1:"tag:4,context,implicit,optional" json:"PoolsTriggeredListR14,omitempty"`
	PoolsTriggeredListR14Indef_ bool                      `asn1:"-" json:"-"`
	NumberOfReportsSent         *big.Int                  `asn1:"tag:5,context,implicit"`
}

// CellsTriggeredList represents the ASN.1 type CellsTriggeredList (SEQUENCE_OF).
type CellsTriggeredList = []CellsTriggeredListElem

// CSIRSTriggeredListR12 represents the ASN.1 type CSI-RS-TriggeredList-r12 (SEQUENCE_OF).
type CSIRSTriggeredListR12 = []MeasCSIRSIdR12

// SSBIndexListR15 represents the ASN.1 type SSB-IndexList-r15 (SEQUENCE_OF).
type SSBIndexListR15 = []RSIndexNRR15

// VarMobilityHistoryReportR12 represents the ASN.1 type VarMobilityHistoryReport-r12 (SEQUENCE_OF).
type VarMobilityHistoryReportR12 = VisitedCellInfoListR12

// VarPendingRnaUpdateR15 represents the ASN.1 type VarPendingRnaUpdate-r15 (SEQUENCE).
type VarPendingRnaUpdateR15 struct {
	PendingRnaUpdate     *bool `asn1:"tag:0,context,implicit,optional" json:"PendingRnaUpdate,omitempty"`
	PendingRnaUpdateRaw_ byte  `asn1:"-" json:"-"`
}

// VarRLFReportR10 represents the ASN.1 type VarRLF-Report-r10 (SEQUENCE).
type VarRLFReportR10 struct {
	RlfReportR10    RLFReportR9  `asn1:"tag:0,context,implicit"`
	PlmnIdentityR10 PLMNIdentity `asn1:"tag:1,context,implicit"`
}

// VarRLFReportR11 represents the ASN.1 type VarRLF-Report-r11 (SEQUENCE).
type VarRLFReportR11 struct {
	RlfReportR10              RLFReportR9          `asn1:"tag:0,context,implicit"`
	PlmnIdentityListR11       PLMNIdentityList3R11 `asn1:"tag:1,context,implicit"`
	PlmnIdentityListR11Indef_ bool                 `asn1:"-" json:"-"`
}

// VarShortINACTIVEMACInputR15 represents the ASN.1 type VarShortINACTIVE-MAC-Input-r15 (SEQUENCE).
type VarShortINACTIVEMACInputR15 struct {
	CellIdentityR15 CellIdentity `asn1:"tag:0,context,implicit"`
	PhysCellIdR15   PhysCellId   `asn1:"tag:1,context,implicit"`
	CRNTIR15        CRNTI        `asn1:"tag:2,context,implicit"`
}

// VarShortMACInput represents the ASN.1 type VarShortMAC-Input (SEQUENCE).
type VarShortMACInput struct {
	CellIdentity CellIdentity `asn1:"tag:0,context,implicit"`
	PhysCellId   PhysCellId   `asn1:"tag:1,context,implicit"`
	CRNTI        CRNTI        `asn1:"tag:2,context,implicit"`
}

// VarShortResumeMACInputR13 represents the ASN.1 type VarShortResumeMAC-Input-r13 (SEQUENCE).
type VarShortResumeMACInputR13 struct {
	CellIdentityR13        CellIdentity      `asn1:"tag:0,context,implicit"`
	PhysCellIdR13          PhysCellId        `asn1:"tag:1,context,implicit"`
	CRNTIR13               CRNTI             `asn1:"tag:2,context,implicit"`
	ResumeDiscriminatorR13 runtime.BitString `asn1:"tag:3,context,implicit"`
}

// VarWLANMobilityConfig represents the ASN.1 type VarWLAN-MobilityConfig (SEQUENCE).
type VarWLANMobilityConfig struct {
	WlanMobilitySetR13       WLANIdListR13         `asn1:"tag:0,context,implicit,optional" json:"WlanMobilitySetR13,omitempty"`
	WlanMobilitySetR13Indef_ bool                  `asn1:"-" json:"-"`
	SuccessReportRequested   *int64                `asn1:"tag:1,context,implicit,optional" json:"SuccessReportRequested,omitempty"`
	WlanSuspendConfigR14     *WLANSuspendConfigR14 `asn1:"tag:2,context,implicit,optional" json:"WlanSuspendConfigR14,omitempty"`
}

// VarWLANStatusR13 represents the ASN.1 type VarWLAN-Status-r13 (SEQUENCE).
type VarWLANStatusR13 struct {
	StatusR13 WLANStatusR13    `asn1:"tag:0,context,implicit"`
	StatusR14 *WLANStatusV1430 `asn1:"tag:1,context,implicit,optional" json:"StatusR14,omitempty"`
}

// VarMeasConfigSpeedStatePars choice constants.
const (
	VarMeasConfigSpeedStateParsChoiceRelease = 1
	VarMeasConfigSpeedStateParsChoiceSetup   = 2
)

// VarMeasConfigSpeedStatePars represents the ASN.1 CHOICE type VarMeasConfig-speedStatePars.
type VarMeasConfigSpeedStatePars struct {
	Choice  int
	Release *struct{}                         `json:"Release,omitempty"`
	Setup   *VarMeasConfigSpeedStateParsSetup `json:"Setup,omitempty"`
}

// NewVarMeasConfigSpeedStateParsRelease creates a VarMeasConfigSpeedStatePars with the release alternative.
func NewVarMeasConfigSpeedStateParsRelease(v struct{}) VarMeasConfigSpeedStatePars {
	return VarMeasConfigSpeedStatePars{
		Choice:  VarMeasConfigSpeedStateParsChoiceRelease,
		Release: &v,
	}
}

// NewVarMeasConfigSpeedStateParsSetup creates a VarMeasConfigSpeedStatePars with the setup alternative.
func NewVarMeasConfigSpeedStateParsSetup(v VarMeasConfigSpeedStateParsSetup) VarMeasConfigSpeedStatePars {
	return VarMeasConfigSpeedStatePars{
		Choice: VarMeasConfigSpeedStateParsChoiceSetup,
		Setup:  &v,
	}
}

// VarMeasConfigSpeedStateParsSetup represents the ASN.1 type VarMeasConfig-speedStatePars-setup (SEQUENCE).
type VarMeasConfigSpeedStateParsSetup struct {
	MobilityStateParameters MobilityStateParameters `asn1:"tag:0,context,implicit"`
	TimeToTriggerSF         SpeedStateScaleFactors  `asn1:"tag:1,context,implicit"`
}

// CellsTriggeredListElem choice constants.
const (
	CellsTriggeredListElemChoicePhysCellIdEUTRA    = 1
	CellsTriggeredListElemChoicePhysCellIdUTRA     = 2
	CellsTriggeredListElemChoicePhysCellIdGERAN    = 3
	CellsTriggeredListElemChoicePhysCellIdCDMA2000 = 4
	CellsTriggeredListElemChoiceWlanIdentifiersR13 = 5
	CellsTriggeredListElemChoicePhysCellIdNRR15    = 6
)

// CellsTriggeredListElem represents the ASN.1 CHOICE type CellsTriggeredList-Elem.
type CellsTriggeredListElem struct {
	Choice             int
	PhysCellIdEUTRA    *PhysCellId                            `json:"PhysCellIdEUTRA,omitempty"`
	PhysCellIdUTRA     *CellsTriggeredListElemPhysCellIdUTRA  `json:"PhysCellIdUTRA,omitempty"`
	PhysCellIdGERAN    *CellsTriggeredListElemPhysCellIdGERAN `json:"PhysCellIdGERAN,omitempty"`
	PhysCellIdCDMA2000 *PhysCellIdCDMA2000                    `json:"PhysCellIdCDMA2000,omitempty"`
	WlanIdentifiersR13 *WLANIdentifiersR12                    `json:"WlanIdentifiersR13,omitempty"`
	PhysCellIdNRR15    *CellsTriggeredListElemPhysCellIdNRR15 `json:"PhysCellIdNRR15,omitempty"`
}

// NewCellsTriggeredListElemPhysCellIdEUTRA creates a CellsTriggeredListElem with the physCellIdEUTRA alternative.
func NewCellsTriggeredListElemPhysCellIdEUTRA(v PhysCellId) CellsTriggeredListElem {
	return CellsTriggeredListElem{
		Choice:          CellsTriggeredListElemChoicePhysCellIdEUTRA,
		PhysCellIdEUTRA: &v,
	}
}

// NewCellsTriggeredListElemPhysCellIdUTRA creates a CellsTriggeredListElem with the physCellIdUTRA alternative.
func NewCellsTriggeredListElemPhysCellIdUTRA(v CellsTriggeredListElemPhysCellIdUTRA) CellsTriggeredListElem {
	return CellsTriggeredListElem{
		Choice:         CellsTriggeredListElemChoicePhysCellIdUTRA,
		PhysCellIdUTRA: &v,
	}
}

// NewCellsTriggeredListElemPhysCellIdGERAN creates a CellsTriggeredListElem with the physCellIdGERAN alternative.
func NewCellsTriggeredListElemPhysCellIdGERAN(v CellsTriggeredListElemPhysCellIdGERAN) CellsTriggeredListElem {
	return CellsTriggeredListElem{
		Choice:          CellsTriggeredListElemChoicePhysCellIdGERAN,
		PhysCellIdGERAN: &v,
	}
}

// NewCellsTriggeredListElemPhysCellIdCDMA2000 creates a CellsTriggeredListElem with the physCellIdCDMA2000 alternative.
func NewCellsTriggeredListElemPhysCellIdCDMA2000(v PhysCellIdCDMA2000) CellsTriggeredListElem {
	return CellsTriggeredListElem{
		Choice:             CellsTriggeredListElemChoicePhysCellIdCDMA2000,
		PhysCellIdCDMA2000: &v,
	}
}

// NewCellsTriggeredListElemWlanIdentifiersR13 creates a CellsTriggeredListElem with the wlan-Identifiers-r13 alternative.
func NewCellsTriggeredListElemWlanIdentifiersR13(v WLANIdentifiersR12) CellsTriggeredListElem {
	return CellsTriggeredListElem{
		Choice:             CellsTriggeredListElemChoiceWlanIdentifiersR13,
		WlanIdentifiersR13: &v,
	}
}

// NewCellsTriggeredListElemPhysCellIdNRR15 creates a CellsTriggeredListElem with the physCellIdNR-r15 alternative.
func NewCellsTriggeredListElemPhysCellIdNRR15(v CellsTriggeredListElemPhysCellIdNRR15) CellsTriggeredListElem {
	return CellsTriggeredListElem{
		Choice:          CellsTriggeredListElemChoicePhysCellIdNRR15,
		PhysCellIdNRR15: &v,
	}
}

// CellsTriggeredListElemPhysCellIdUTRA choice constants.
const (
	CellsTriggeredListElemPhysCellIdUTRAChoiceFdd = 1
	CellsTriggeredListElemPhysCellIdUTRAChoiceTdd = 2
)

// CellsTriggeredListElemPhysCellIdUTRA represents the ASN.1 CHOICE type CellsTriggeredList-Elem-physCellIdUTRA.
type CellsTriggeredListElemPhysCellIdUTRA struct {
	Choice int
	Fdd    *PhysCellIdUTRAFDD `json:"Fdd,omitempty"`
	Tdd    *PhysCellIdUTRATDD `json:"Tdd,omitempty"`
}

// NewCellsTriggeredListElemPhysCellIdUTRAFdd creates a CellsTriggeredListElemPhysCellIdUTRA with the fdd alternative.
func NewCellsTriggeredListElemPhysCellIdUTRAFdd(v PhysCellIdUTRAFDD) CellsTriggeredListElemPhysCellIdUTRA {
	return CellsTriggeredListElemPhysCellIdUTRA{
		Choice: CellsTriggeredListElemPhysCellIdUTRAChoiceFdd,
		Fdd:    &v,
	}
}

// NewCellsTriggeredListElemPhysCellIdUTRATdd creates a CellsTriggeredListElemPhysCellIdUTRA with the tdd alternative.
func NewCellsTriggeredListElemPhysCellIdUTRATdd(v PhysCellIdUTRATDD) CellsTriggeredListElemPhysCellIdUTRA {
	return CellsTriggeredListElemPhysCellIdUTRA{
		Choice: CellsTriggeredListElemPhysCellIdUTRAChoiceTdd,
		Tdd:    &v,
	}
}

// CellsTriggeredListElemPhysCellIdGERAN represents the ASN.1 type CellsTriggeredList-Elem-physCellIdGERAN (SEQUENCE).
type CellsTriggeredListElemPhysCellIdGERAN struct {
	CarrierFreq CarrierFreqGERAN `asn1:"tag:0,context,implicit"`
	PhysCellId  PhysCellIdGERAN  `asn1:"tag:1,context,implicit"`
}

// CellsTriggeredListElemPhysCellIdNRR15 represents the ASN.1 type CellsTriggeredList-Elem-physCellIdNR-r15 (SEQUENCE).
type CellsTriggeredListElemPhysCellIdNRR15 struct {
	CarrierFreq          ARFCNValueNRR15 `asn1:"tag:0,context,implicit"`
	PhysCellId           PhysCellIdNRR15 `asn1:"tag:1,context,implicit"`
	RsIndexListR15       SSBIndexListR15 `asn1:"tag:2,context,implicit,optional" json:"RsIndexListR15,omitempty"`
	RsIndexListR15Indef_ bool            `asn1:"-" json:"-"`
}

// MarshalUPER encodes VarConditionalReconfiguration to UPER format.
func (v *VarConditionalReconfiguration) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarConditionalReconfiguration) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.CondReconfigurationListR16 != nil); err != nil {
		return err
	}
	if v.CondReconfigurationListR16 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.CondReconfigurationListR16)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_condreconfigurationlistr16, fragmentLength_condreconfigurationlistr16 int64) error {
			for _, elem := range v.CondReconfigurationListR16[fragmentOffset_condreconfigurationlistr16 : fragmentOffset_condreconfigurationlistr16+fragmentLength_condreconfigurationlistr16] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding condReconfigurationList-r16 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding condReconfigurationList-r16: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarConditionalReconfiguration from UPER format.
func (v *VarConditionalReconfiguration) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarConditionalReconfiguration")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarConditionalReconfiguration")
	}
	return nil
}

func (v *VarConditionalReconfiguration) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarConditionalReconfiguration{}
	// Read preamble bitmap for optional root fields
	opt_condreconfigurationlistr16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_condreconfigurationlistr16 {
		tmp_condreconfigurationlistr16 := make(CondReconfigurationToAddModListR16, 0)
		_, errCollection_condreconfigurationlistr16 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_condreconfigurationlistr16, fragmentLength_condreconfigurationlistr16 int64) error {
			for i := int64(0); i < fragmentLength_condreconfigurationlistr16; i++ {
				var elem CondReconfigurationAddModR16
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("CondReconfigurationListR16[%d]", fragmentOffset_condreconfigurationlistr16+i))
				}
				tmp_condreconfigurationlistr16 = append(tmp_condreconfigurationlistr16, elem)
			}
			return nil
		})
		if errCollection_condreconfigurationlistr16 != nil {
			return runtime.WrapDecodePath(errCollection_condreconfigurationlistr16, "CondReconfigurationListR16")
		}
		v.CondReconfigurationListR16 = tmp_condreconfigurationlistr16
	}
	return nil
}

// MarshalUPER encodes VarConnEstFailReportR11 to UPER format.
func (v *VarConnEstFailReportR11) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarConnEstFailReportR11) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.ConnEstFailReportR11.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding connEstFailReport-r11: %w", err)
	}
	if err := v.PlmnIdentityR11.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding plmn-Identity-r11: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarConnEstFailReportR11 from UPER format.
func (v *VarConnEstFailReportR11) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarConnEstFailReportR11")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarConnEstFailReportR11")
	}
	return nil
}

func (v *VarConnEstFailReportR11) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarConnEstFailReportR11{}
	if err := v.ConnEstFailReportR11.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ConnEstFailReportR11")
	}
	if err := v.PlmnIdentityR11.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PlmnIdentityR11")
	}
	return nil
}

// MarshalUPER encodes VarLogMeasConfigR10 to UPER format.
func (v *VarLogMeasConfigR10) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarLogMeasConfigR10) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AreaConfigurationR10 != nil); err != nil {
		return err
	}
	if v.AreaConfigurationR10 != nil {
		if err := v.AreaConfigurationR10.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding areaConfiguration-r10: %w", err)
		}
	}
	if err := per.EncodeEnumerated(bb, int64(v.LoggingDurationR10), 8, false); err != nil {
		return fmt.Errorf("encoding loggingDuration-r10: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.LoggingIntervalR10), 8, false); err != nil {
		return fmt.Errorf("encoding loggingInterval-r10: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarLogMeasConfigR10 from UPER format.
func (v *VarLogMeasConfigR10) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasConfigR10")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasConfigR10")
	}
	return nil
}

func (v *VarLogMeasConfigR10) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarLogMeasConfigR10{}
	// Read preamble bitmap for optional root fields
	opt_areaconfigurationr10, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_areaconfigurationr10 {
		var dec_areaconfigurationr10 AreaConfigurationR10
		if err := dec_areaconfigurationr10.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AreaConfigurationR10")
		}
		v.AreaConfigurationR10 = &dec_areaconfigurationr10
	}
	val_loggingdurationr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingDurationR10")
	}
	v.LoggingDurationR10 = LoggingDurationR10(val_loggingdurationr10)
	val_loggingintervalr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingIntervalR10")
	}
	v.LoggingIntervalR10 = LoggingIntervalR10(val_loggingintervalr10)
	return nil
}

// MarshalUPER encodes VarLogMeasConfigR11 to UPER format.
func (v *VarLogMeasConfigR11) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarLogMeasConfigR11) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AreaConfigurationR10 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.AreaConfigurationV1130 != nil); err != nil {
		return err
	}
	if v.AreaConfigurationR10 != nil {
		if err := v.AreaConfigurationR10.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding areaConfiguration-r10: %w", err)
		}
	}
	if v.AreaConfigurationV1130 != nil {
		if err := v.AreaConfigurationV1130.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding areaConfiguration-v1130: %w", err)
		}
	}
	if err := per.EncodeEnumerated(bb, int64(v.LoggingDurationR10), 8, false); err != nil {
		return fmt.Errorf("encoding loggingDuration-r10: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.LoggingIntervalR10), 8, false); err != nil {
		return fmt.Errorf("encoding loggingInterval-r10: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarLogMeasConfigR11 from UPER format.
func (v *VarLogMeasConfigR11) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasConfigR11")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasConfigR11")
	}
	return nil
}

func (v *VarLogMeasConfigR11) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarLogMeasConfigR11{}
	// Read preamble bitmap for optional root fields
	opt_areaconfigurationr10, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_areaconfigurationv1130, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_areaconfigurationr10 {
		var dec_areaconfigurationr10 AreaConfigurationR10
		if err := dec_areaconfigurationr10.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AreaConfigurationR10")
		}
		v.AreaConfigurationR10 = &dec_areaconfigurationr10
	}
	if opt_areaconfigurationv1130 {
		var dec_areaconfigurationv1130 AreaConfigurationV1130
		if err := dec_areaconfigurationv1130.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AreaConfigurationV1130")
		}
		v.AreaConfigurationV1130 = &dec_areaconfigurationv1130
	}
	val_loggingdurationr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingDurationR10")
	}
	v.LoggingDurationR10 = LoggingDurationR10(val_loggingdurationr10)
	val_loggingintervalr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingIntervalR10")
	}
	v.LoggingIntervalR10 = LoggingIntervalR10(val_loggingintervalr10)
	return nil
}

// MarshalUPER encodes VarLogMeasConfigR12 to UPER format.
func (v *VarLogMeasConfigR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarLogMeasConfigR12) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AreaConfigurationR10 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.AreaConfigurationV1130 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.TargetMBSFNAreaListR12 != nil); err != nil {
		return err
	}
	if v.AreaConfigurationR10 != nil {
		if err := v.AreaConfigurationR10.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding areaConfiguration-r10: %w", err)
		}
	}
	if v.AreaConfigurationV1130 != nil {
		if err := v.AreaConfigurationV1130.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding areaConfiguration-v1130: %w", err)
		}
	}
	if err := per.EncodeEnumerated(bb, int64(v.LoggingDurationR10), 8, false); err != nil {
		return fmt.Errorf("encoding loggingDuration-r10: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.LoggingIntervalR10), 8, false); err != nil {
		return fmt.Errorf("encoding loggingInterval-r10: %w", err)
	}
	if v.TargetMBSFNAreaListR12 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.TargetMBSFNAreaListR12)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_targetmbsfnarealistr12, fragmentLength_targetmbsfnarealistr12 int64) error {
			for _, elem := range v.TargetMBSFNAreaListR12[fragmentOffset_targetmbsfnarealistr12 : fragmentOffset_targetmbsfnarealistr12+fragmentLength_targetmbsfnarealistr12] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding targetMBSFN-AreaList-r12 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding targetMBSFN-AreaList-r12: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarLogMeasConfigR12 from UPER format.
func (v *VarLogMeasConfigR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasConfigR12")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasConfigR12")
	}
	return nil
}

func (v *VarLogMeasConfigR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarLogMeasConfigR12{}
	// Read preamble bitmap for optional root fields
	opt_areaconfigurationr10, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_areaconfigurationv1130, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_targetmbsfnarealistr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_areaconfigurationr10 {
		var dec_areaconfigurationr10 AreaConfigurationR10
		if err := dec_areaconfigurationr10.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AreaConfigurationR10")
		}
		v.AreaConfigurationR10 = &dec_areaconfigurationr10
	}
	if opt_areaconfigurationv1130 {
		var dec_areaconfigurationv1130 AreaConfigurationV1130
		if err := dec_areaconfigurationv1130.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AreaConfigurationV1130")
		}
		v.AreaConfigurationV1130 = &dec_areaconfigurationv1130
	}
	val_loggingdurationr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingDurationR10")
	}
	v.LoggingDurationR10 = LoggingDurationR10(val_loggingdurationr10)
	val_loggingintervalr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingIntervalR10")
	}
	v.LoggingIntervalR10 = LoggingIntervalR10(val_loggingintervalr10)
	if opt_targetmbsfnarealistr12 {
		tmp_targetmbsfnarealistr12 := make(TargetMBSFNAreaListR12, 0)
		_, errCollection_targetmbsfnarealistr12 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_targetmbsfnarealistr12, fragmentLength_targetmbsfnarealistr12 int64) error {
			for i := int64(0); i < fragmentLength_targetmbsfnarealistr12; i++ {
				var elem TargetMBSFNAreaR12
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("TargetMBSFNAreaListR12[%d]", fragmentOffset_targetmbsfnarealistr12+i))
				}
				tmp_targetmbsfnarealistr12 = append(tmp_targetmbsfnarealistr12, elem)
			}
			return nil
		})
		if errCollection_targetmbsfnarealistr12 != nil {
			return runtime.WrapDecodePath(errCollection_targetmbsfnarealistr12, "TargetMBSFNAreaListR12")
		}
		v.TargetMBSFNAreaListR12 = tmp_targetmbsfnarealistr12
	}
	return nil
}

// MarshalUPER encodes VarLogMeasConfigR15 to UPER format.
func (v *VarLogMeasConfigR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarLogMeasConfigR15) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AreaConfigurationR10 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.AreaConfigurationV1130 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.TargetMBSFNAreaListR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.BtNameListR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.WlanNameListR15 != nil); err != nil {
		return err
	}
	if v.AreaConfigurationR10 != nil {
		if err := v.AreaConfigurationR10.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding areaConfiguration-r10: %w", err)
		}
	}
	if v.AreaConfigurationV1130 != nil {
		if err := v.AreaConfigurationV1130.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding areaConfiguration-v1130: %w", err)
		}
	}
	if err := per.EncodeEnumerated(bb, int64(v.LoggingDurationR10), 8, false); err != nil {
		return fmt.Errorf("encoding loggingDuration-r10: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.LoggingIntervalR10), 8, false); err != nil {
		return fmt.Errorf("encoding loggingInterval-r10: %w", err)
	}
	if v.TargetMBSFNAreaListR12 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.TargetMBSFNAreaListR12)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_targetmbsfnarealistr12, fragmentLength_targetmbsfnarealistr12 int64) error {
			for _, elem := range v.TargetMBSFNAreaListR12[fragmentOffset_targetmbsfnarealistr12 : fragmentOffset_targetmbsfnarealistr12+fragmentLength_targetmbsfnarealistr12] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding targetMBSFN-AreaList-r12 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding targetMBSFN-AreaList-r12: %w", err)
		}
	}
	if v.BtNameListR15 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.BtNameListR15)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_btnamelistr15, fragmentLength_btnamelistr15 int64) error {
			for _, elem := range v.BtNameListR15[fragmentOffset_btnamelistr15 : fragmentOffset_btnamelistr15+fragmentLength_btnamelistr15] {
				if err := per.EncodeOctetString(bb, []byte(elem), 1, 248, true); err != nil {
					return fmt.Errorf("encoding bt-NameList-r15 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding bt-NameList-r15: %w", err)
		}
	}
	if v.WlanNameListR15 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.WlanNameListR15)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_wlannamelistr15, fragmentLength_wlannamelistr15 int64) error {
			for _, elem := range v.WlanNameListR15[fragmentOffset_wlannamelistr15 : fragmentOffset_wlannamelistr15+fragmentLength_wlannamelistr15] {
				if err := per.EncodeOctetString(bb, []byte(elem), 1, 32, true); err != nil {
					return fmt.Errorf("encoding wlan-NameList-r15 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding wlan-NameList-r15: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarLogMeasConfigR15 from UPER format.
func (v *VarLogMeasConfigR15) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasConfigR15")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasConfigR15")
	}
	return nil
}

func (v *VarLogMeasConfigR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarLogMeasConfigR15{}
	// Read preamble bitmap for optional root fields
	opt_areaconfigurationr10, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_areaconfigurationv1130, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_targetmbsfnarealistr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_btnamelistr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_wlannamelistr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_areaconfigurationr10 {
		var dec_areaconfigurationr10 AreaConfigurationR10
		if err := dec_areaconfigurationr10.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AreaConfigurationR10")
		}
		v.AreaConfigurationR10 = &dec_areaconfigurationr10
	}
	if opt_areaconfigurationv1130 {
		var dec_areaconfigurationv1130 AreaConfigurationV1130
		if err := dec_areaconfigurationv1130.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AreaConfigurationV1130")
		}
		v.AreaConfigurationV1130 = &dec_areaconfigurationv1130
	}
	val_loggingdurationr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingDurationR10")
	}
	v.LoggingDurationR10 = LoggingDurationR10(val_loggingdurationr10)
	val_loggingintervalr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingIntervalR10")
	}
	v.LoggingIntervalR10 = LoggingIntervalR10(val_loggingintervalr10)
	if opt_targetmbsfnarealistr12 {
		tmp_targetmbsfnarealistr12 := make(TargetMBSFNAreaListR12, 0)
		_, errCollection_targetmbsfnarealistr12 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_targetmbsfnarealistr12, fragmentLength_targetmbsfnarealistr12 int64) error {
			for i := int64(0); i < fragmentLength_targetmbsfnarealistr12; i++ {
				var elem TargetMBSFNAreaR12
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("TargetMBSFNAreaListR12[%d]", fragmentOffset_targetmbsfnarealistr12+i))
				}
				tmp_targetmbsfnarealistr12 = append(tmp_targetmbsfnarealistr12, elem)
			}
			return nil
		})
		if errCollection_targetmbsfnarealistr12 != nil {
			return runtime.WrapDecodePath(errCollection_targetmbsfnarealistr12, "TargetMBSFNAreaListR12")
		}
		v.TargetMBSFNAreaListR12 = tmp_targetmbsfnarealistr12
	}
	if opt_btnamelistr15 {
		tmp_btnamelistr15 := make(BTNameListR15, 0)
		_, errCollection_btnamelistr15 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_btnamelistr15, fragmentLength_btnamelistr15 int64) error {
			for i := int64(0); i < fragmentLength_btnamelistr15; i++ {
				val, err := per.DecodeOctetString(bb, 1, 248, true)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("BtNameListR15[%d]", fragmentOffset_btnamelistr15+i))
				}
				tmp_btnamelistr15 = append(tmp_btnamelistr15, val)
			}
			return nil
		})
		if errCollection_btnamelistr15 != nil {
			return runtime.WrapDecodePath(errCollection_btnamelistr15, "BtNameListR15")
		}
		v.BtNameListR15 = tmp_btnamelistr15
	}
	if opt_wlannamelistr15 {
		tmp_wlannamelistr15 := make(WLANNameListR15, 0)
		_, errCollection_wlannamelistr15 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_wlannamelistr15, fragmentLength_wlannamelistr15 int64) error {
			for i := int64(0); i < fragmentLength_wlannamelistr15; i++ {
				val, err := per.DecodeOctetString(bb, 1, 32, true)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("WlanNameListR15[%d]", fragmentOffset_wlannamelistr15+i))
				}
				tmp_wlannamelistr15 = append(tmp_wlannamelistr15, val)
			}
			return nil
		})
		if errCollection_wlannamelistr15 != nil {
			return runtime.WrapDecodePath(errCollection_wlannamelistr15, "WlanNameListR15")
		}
		v.WlanNameListR15 = tmp_wlannamelistr15
	}
	return nil
}

// MarshalUPER encodes VarLogMeasConfigR17 to UPER format.
func (v *VarLogMeasConfigR17) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarLogMeasConfigR17) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AreaConfigurationR10 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.AreaConfigurationV1130 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.TargetMBSFNAreaListR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.BtNameListR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.WlanNameListR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.LoggedEventTriggerConfigR17 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasUncomBarPreR17 != nil); err != nil {
		return err
	}
	if v.AreaConfigurationR10 != nil {
		if err := v.AreaConfigurationR10.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding areaConfiguration-r10: %w", err)
		}
	}
	if v.AreaConfigurationV1130 != nil {
		if err := v.AreaConfigurationV1130.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding areaConfiguration-v1130: %w", err)
		}
	}
	if err := per.EncodeEnumerated(bb, int64(v.LoggingDurationR10), 8, false); err != nil {
		return fmt.Errorf("encoding loggingDuration-r10: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.LoggingIntervalR10), 8, false); err != nil {
		return fmt.Errorf("encoding loggingInterval-r10: %w", err)
	}
	if v.TargetMBSFNAreaListR12 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.TargetMBSFNAreaListR12)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_targetmbsfnarealistr12, fragmentLength_targetmbsfnarealistr12 int64) error {
			for _, elem := range v.TargetMBSFNAreaListR12[fragmentOffset_targetmbsfnarealistr12 : fragmentOffset_targetmbsfnarealistr12+fragmentLength_targetmbsfnarealistr12] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding targetMBSFN-AreaList-r12 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding targetMBSFN-AreaList-r12: %w", err)
		}
	}
	if v.BtNameListR15 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.BtNameListR15)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_btnamelistr15, fragmentLength_btnamelistr15 int64) error {
			for _, elem := range v.BtNameListR15[fragmentOffset_btnamelistr15 : fragmentOffset_btnamelistr15+fragmentLength_btnamelistr15] {
				if err := per.EncodeOctetString(bb, []byte(elem), 1, 248, true); err != nil {
					return fmt.Errorf("encoding bt-NameList-r15 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding bt-NameList-r15: %w", err)
		}
	}
	if v.WlanNameListR15 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.WlanNameListR15)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_wlannamelistr15, fragmentLength_wlannamelistr15 int64) error {
			for _, elem := range v.WlanNameListR15[fragmentOffset_wlannamelistr15 : fragmentOffset_wlannamelistr15+fragmentLength_wlannamelistr15] {
				if err := per.EncodeOctetString(bb, []byte(elem), 1, 32, true); err != nil {
					return fmt.Errorf("encoding wlan-NameList-r15 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding wlan-NameList-r15: %w", err)
		}
	}
	if v.LoggedEventTriggerConfigR17 != nil {
		if err := v.LoggedEventTriggerConfigR17.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding loggedEventTriggerConfig-r17: %w", err)
		}
	}
	if v.MeasUncomBarPreR17 != nil {
		if err := per.EncodeEnumerated(bb, int64(*v.MeasUncomBarPreR17), 1, false); err != nil {
			return fmt.Errorf("encoding measUncomBarPre-r17: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarLogMeasConfigR17 from UPER format.
func (v *VarLogMeasConfigR17) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasConfigR17")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasConfigR17")
	}
	return nil
}

func (v *VarLogMeasConfigR17) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarLogMeasConfigR17{}
	// Read preamble bitmap for optional root fields
	opt_areaconfigurationr10, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_areaconfigurationv1130, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_targetmbsfnarealistr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_btnamelistr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_wlannamelistr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_loggedeventtriggerconfigr17, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measuncombarprer17, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_areaconfigurationr10 {
		var dec_areaconfigurationr10 AreaConfigurationR10
		if err := dec_areaconfigurationr10.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AreaConfigurationR10")
		}
		v.AreaConfigurationR10 = &dec_areaconfigurationr10
	}
	if opt_areaconfigurationv1130 {
		var dec_areaconfigurationv1130 AreaConfigurationV1130
		if err := dec_areaconfigurationv1130.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "AreaConfigurationV1130")
		}
		v.AreaConfigurationV1130 = &dec_areaconfigurationv1130
	}
	val_loggingdurationr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingDurationR10")
	}
	v.LoggingDurationR10 = LoggingDurationR10(val_loggingdurationr10)
	val_loggingintervalr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingIntervalR10")
	}
	v.LoggingIntervalR10 = LoggingIntervalR10(val_loggingintervalr10)
	if opt_targetmbsfnarealistr12 {
		tmp_targetmbsfnarealistr12 := make(TargetMBSFNAreaListR12, 0)
		_, errCollection_targetmbsfnarealistr12 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_targetmbsfnarealistr12, fragmentLength_targetmbsfnarealistr12 int64) error {
			for i := int64(0); i < fragmentLength_targetmbsfnarealistr12; i++ {
				var elem TargetMBSFNAreaR12
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("TargetMBSFNAreaListR12[%d]", fragmentOffset_targetmbsfnarealistr12+i))
				}
				tmp_targetmbsfnarealistr12 = append(tmp_targetmbsfnarealistr12, elem)
			}
			return nil
		})
		if errCollection_targetmbsfnarealistr12 != nil {
			return runtime.WrapDecodePath(errCollection_targetmbsfnarealistr12, "TargetMBSFNAreaListR12")
		}
		v.TargetMBSFNAreaListR12 = tmp_targetmbsfnarealistr12
	}
	if opt_btnamelistr15 {
		tmp_btnamelistr15 := make(BTNameListR15, 0)
		_, errCollection_btnamelistr15 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_btnamelistr15, fragmentLength_btnamelistr15 int64) error {
			for i := int64(0); i < fragmentLength_btnamelistr15; i++ {
				val, err := per.DecodeOctetString(bb, 1, 248, true)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("BtNameListR15[%d]", fragmentOffset_btnamelistr15+i))
				}
				tmp_btnamelistr15 = append(tmp_btnamelistr15, val)
			}
			return nil
		})
		if errCollection_btnamelistr15 != nil {
			return runtime.WrapDecodePath(errCollection_btnamelistr15, "BtNameListR15")
		}
		v.BtNameListR15 = tmp_btnamelistr15
	}
	if opt_wlannamelistr15 {
		tmp_wlannamelistr15 := make(WLANNameListR15, 0)
		_, errCollection_wlannamelistr15 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_wlannamelistr15, fragmentLength_wlannamelistr15 int64) error {
			for i := int64(0); i < fragmentLength_wlannamelistr15; i++ {
				val, err := per.DecodeOctetString(bb, 1, 32, true)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("WlanNameListR15[%d]", fragmentOffset_wlannamelistr15+i))
				}
				tmp_wlannamelistr15 = append(tmp_wlannamelistr15, val)
			}
			return nil
		})
		if errCollection_wlannamelistr15 != nil {
			return runtime.WrapDecodePath(errCollection_wlannamelistr15, "WlanNameListR15")
		}
		v.WlanNameListR15 = tmp_wlannamelistr15
	}
	if opt_loggedeventtriggerconfigr17 {
		var dec_loggedeventtriggerconfigr17 LoggedEventTriggerConfigR17
		if err := dec_loggedeventtriggerconfigr17.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "LoggedEventTriggerConfigR17")
		}
		v.LoggedEventTriggerConfigR17 = &dec_loggedeventtriggerconfigr17
	}
	if opt_measuncombarprer17 {
		val_measuncombarprer17, err := per.DecodeEnumerated(bb, 1, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "MeasUncomBarPreR17")
		}
		v.MeasUncomBarPreR17 = &val_measuncombarprer17
	}
	return nil
}

// MarshalUPER encodes VarLogMeasReportR10 to UPER format.
func (v *VarLogMeasReportR10) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarLogMeasReportR10) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.TraceReferenceR10.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding traceReference-r10: %w", err)
	}
	if err := per.EncodeOctetStringExt(bb, v.TraceRecordingSessionRefR10, 2, 2, true, false); err != nil {
		return fmt.Errorf("encoding traceRecordingSessionRef-r10: %w", err)
	}
	if err := per.EncodeOctetStringExt(bb, v.TceIdR10, 1, 1, true, false); err != nil {
		return fmt.Errorf("encoding tce-Id-r10: %w", err)
	}
	if err := v.PlmnIdentityR10.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding plmn-Identity-r10: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.AbsoluteTimeInfoR10.Bytes, v.AbsoluteTimeInfoR10.BitLength, 48, 48, true, false); err != nil {
		return fmt.Errorf("encoding absoluteTimeInfo-r10: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.LogMeasInfoListR10)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4060, HasUpper: true}, false, func(fragmentOffset_logmeasinfolistr10, fragmentLength_logmeasinfolistr10 int64) error {
		for _, elem := range v.LogMeasInfoListR10[fragmentOffset_logmeasinfolistr10 : fragmentOffset_logmeasinfolistr10+fragmentLength_logmeasinfolistr10] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding logMeasInfoList-r10 element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding logMeasInfoList-r10: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarLogMeasReportR10 from UPER format.
func (v *VarLogMeasReportR10) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasReportR10")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasReportR10")
	}
	return nil
}

func (v *VarLogMeasReportR10) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarLogMeasReportR10{}
	if err := v.TraceReferenceR10.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TraceReferenceR10")
	}
	val_tracerecordingsessionrefr10, err := per.DecodeOctetStringExt(bb, 2, 2, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "TraceRecordingSessionRefR10")
	}
	v.TraceRecordingSessionRefR10 = val_tracerecordingsessionrefr10
	val_tceidr10, err := per.DecodeOctetStringExt(bb, 1, 1, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "TceIdR10")
	}
	v.TceIdR10 = val_tceidr10
	if err := v.PlmnIdentityR10.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PlmnIdentityR10")
	}
	bsBytes_absolutetimeinfor10, bsBitLen_absolutetimeinfor10, err := per.DecodeBitStringExt(bb, 48, 48, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "AbsoluteTimeInfoR10")
	}
	v.AbsoluteTimeInfoR10 = runtime.BitString{Bytes: bsBytes_absolutetimeinfor10, BitLength: bsBitLen_absolutetimeinfor10}
	v.LogMeasInfoListR10 = make(LogMeasInfoList2R10, 0)
	_, errCollection_logmeasinfolistr10 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4060, HasUpper: true}, false, func(fragmentOffset_logmeasinfolistr10, fragmentLength_logmeasinfolistr10 int64) error {
		for i := int64(0); i < fragmentLength_logmeasinfolistr10; i++ {
			var elem LogMeasInfoR10
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("LogMeasInfoListR10[%d]", fragmentOffset_logmeasinfolistr10+i))
			}
			v.LogMeasInfoListR10 = append(v.LogMeasInfoListR10, elem)
		}
		return nil
	})
	if errCollection_logmeasinfolistr10 != nil {
		return runtime.WrapDecodePath(errCollection_logmeasinfolistr10, "LogMeasInfoListR10")
	}
	return nil
}

// MarshalUPER encodes VarLogMeasReportR11 to UPER format.
func (v *VarLogMeasReportR11) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarLogMeasReportR11) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.TraceReferenceR10.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding traceReference-r10: %w", err)
	}
	if err := per.EncodeOctetStringExt(bb, v.TraceRecordingSessionRefR10, 2, 2, true, false); err != nil {
		return fmt.Errorf("encoding traceRecordingSessionRef-r10: %w", err)
	}
	if err := per.EncodeOctetStringExt(bb, v.TceIdR10, 1, 1, true, false); err != nil {
		return fmt.Errorf("encoding tce-Id-r10: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.PlmnIdentityListR11)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, false, func(fragmentOffset_plmnidentitylistr11, fragmentLength_plmnidentitylistr11 int64) error {
		for _, elem := range v.PlmnIdentityListR11[fragmentOffset_plmnidentitylistr11 : fragmentOffset_plmnidentitylistr11+fragmentLength_plmnidentitylistr11] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding plmn-IdentityList-r11 element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding plmn-IdentityList-r11: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.AbsoluteTimeInfoR10.Bytes, v.AbsoluteTimeInfoR10.BitLength, 48, 48, true, false); err != nil {
		return fmt.Errorf("encoding absoluteTimeInfo-r10: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.LogMeasInfoListR10)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4060, HasUpper: true}, false, func(fragmentOffset_logmeasinfolistr10, fragmentLength_logmeasinfolistr10 int64) error {
		for _, elem := range v.LogMeasInfoListR10[fragmentOffset_logmeasinfolistr10 : fragmentOffset_logmeasinfolistr10+fragmentLength_logmeasinfolistr10] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding logMeasInfoList-r10 element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding logMeasInfoList-r10: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.SigLoggedMeasTypeR18), 1, false); err != nil {
		return fmt.Errorf("encoding sigLoggedMeasType-r18: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarLogMeasReportR11 from UPER format.
func (v *VarLogMeasReportR11) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasReportR11")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarLogMeasReportR11")
	}
	return nil
}

func (v *VarLogMeasReportR11) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarLogMeasReportR11{}
	if err := v.TraceReferenceR10.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TraceReferenceR10")
	}
	val_tracerecordingsessionrefr10, err := per.DecodeOctetStringExt(bb, 2, 2, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "TraceRecordingSessionRefR10")
	}
	v.TraceRecordingSessionRefR10 = val_tracerecordingsessionrefr10
	val_tceidr10, err := per.DecodeOctetStringExt(bb, 1, 1, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "TceIdR10")
	}
	v.TceIdR10 = val_tceidr10
	v.PlmnIdentityListR11 = make(PLMNIdentityList3R11, 0)
	_, errCollection_plmnidentitylistr11 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, false, func(fragmentOffset_plmnidentitylistr11, fragmentLength_plmnidentitylistr11 int64) error {
		for i := int64(0); i < fragmentLength_plmnidentitylistr11; i++ {
			var elem PLMNIdentity
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PlmnIdentityListR11[%d]", fragmentOffset_plmnidentitylistr11+i))
			}
			v.PlmnIdentityListR11 = append(v.PlmnIdentityListR11, elem)
		}
		return nil
	})
	if errCollection_plmnidentitylistr11 != nil {
		return runtime.WrapDecodePath(errCollection_plmnidentitylistr11, "PlmnIdentityListR11")
	}
	bsBytes_absolutetimeinfor10, bsBitLen_absolutetimeinfor10, err := per.DecodeBitStringExt(bb, 48, 48, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "AbsoluteTimeInfoR10")
	}
	v.AbsoluteTimeInfoR10 = runtime.BitString{Bytes: bsBytes_absolutetimeinfor10, BitLength: bsBitLen_absolutetimeinfor10}
	v.LogMeasInfoListR10 = make(LogMeasInfoList2R10, 0)
	_, errCollection_logmeasinfolistr10 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4060, HasUpper: true}, false, func(fragmentOffset_logmeasinfolistr10, fragmentLength_logmeasinfolistr10 int64) error {
		for i := int64(0); i < fragmentLength_logmeasinfolistr10; i++ {
			var elem LogMeasInfoR10
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("LogMeasInfoListR10[%d]", fragmentOffset_logmeasinfolistr10+i))
			}
			v.LogMeasInfoListR10 = append(v.LogMeasInfoListR10, elem)
		}
		return nil
	})
	if errCollection_logmeasinfolistr10 != nil {
		return runtime.WrapDecodePath(errCollection_logmeasinfolistr10, "LogMeasInfoListR10")
	}
	val_sigloggedmeastyper18, err := per.DecodeEnumerated(bb, 1, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SigLoggedMeasTypeR18")
	}
	v.SigLoggedMeasTypeR18 = val_sigloggedmeastyper18
	return nil
}

type asn1cUPERLogMeasInfoList2R10ListValue struct{ Value LogMeasInfoList2R10 }

// MarshalUPERLogMeasInfoList2R10 encodes a LogMeasInfoList2R10 list to UPER.
func MarshalUPERLogMeasInfoList2R10(list LogMeasInfoList2R10) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERLogMeasInfoList2R10To(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalUPERLogMeasInfoList2R10To appends a LogMeasInfoList2R10 list to bb.
func MarshalUPERLogMeasInfoList2R10To(list LogMeasInfoList2R10, bb *per.BitBuffer) error {
	v := asn1cUPERLogMeasInfoList2R10ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4060, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// UnmarshalUPERLogMeasInfoList2R10 decodes a LogMeasInfoList2R10 list from UPER.
func UnmarshalUPERLogMeasInfoList2R10(data []byte) (LogMeasInfoList2R10, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalUPERLogMeasInfoList2R10From(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "LogMeasInfoList2R10")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "LogMeasInfoList2R10")
	}
	return value, nil
}

// UnmarshalUPERLogMeasInfoList2R10From decodes a LogMeasInfoList2R10 list from bb.
func UnmarshalUPERLogMeasInfoList2R10From(bb *per.BitBuffer) (LogMeasInfoList2R10, error) {
	var v asn1cUPERLogMeasInfoList2R10ListValue
	if err := unmarshalUPERLogMeasInfoList2R10Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERLogMeasInfoList2R10Into(v *asn1cUPERLogMeasInfoList2R10ListValue, bb *per.BitBuffer) error {
	v.Value = make(LogMeasInfoList2R10, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4060, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem LogMeasInfoR10
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

// MarshalUPER encodes VarMeasConfig to UPER format.
func (v *VarMeasConfig) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarMeasConfig) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MeasIdList != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasIdListExtR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasIdListV1310 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasIdListExtV1310 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasObjectList != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasObjectListExtR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasObjectListV9i0 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ReportConfigList != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.QuantityConfig != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasScaleFactorR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SMeasure != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SpeedStatePars != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.AllowInterruptionsR11 != nil); err != nil {
		return err
	}
	if v.MeasIdList != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasIdList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measidlist, fragmentLength_measidlist int64) error {
			for _, elem := range v.MeasIdList[fragmentOffset_measidlist : fragmentOffset_measidlist+fragmentLength_measidlist] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measIdList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measIdList: %w", err)
		}
	}
	if v.MeasIdListExtR12 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasIdListExtR12)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measidlistextr12, fragmentLength_measidlistextr12 int64) error {
			for _, elem := range v.MeasIdListExtR12[fragmentOffset_measidlistextr12 : fragmentOffset_measidlistextr12+fragmentLength_measidlistextr12] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measIdListExt-r12 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measIdListExt-r12: %w", err)
		}
	}
	if v.MeasIdListV1310 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasIdListV1310)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measidlistv1310, fragmentLength_measidlistv1310 int64) error {
			for _, elem := range v.MeasIdListV1310[fragmentOffset_measidlistv1310 : fragmentOffset_measidlistv1310+fragmentLength_measidlistv1310] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measIdList-v1310 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measIdList-v1310: %w", err)
		}
	}
	if v.MeasIdListExtV1310 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasIdListExtV1310)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measidlistextv1310, fragmentLength_measidlistextv1310 int64) error {
			for _, elem := range v.MeasIdListExtV1310[fragmentOffset_measidlistextv1310 : fragmentOffset_measidlistextv1310+fragmentLength_measidlistextv1310] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measIdListExt-v1310 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measIdListExt-v1310: %w", err)
		}
	}
	if v.MeasObjectList != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasObjectList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measobjectlist, fragmentLength_measobjectlist int64) error {
			for _, elem := range v.MeasObjectList[fragmentOffset_measobjectlist : fragmentOffset_measobjectlist+fragmentLength_measobjectlist] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measObjectList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measObjectList: %w", err)
		}
	}
	if v.MeasObjectListExtR13 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasObjectListExtR13)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measobjectlistextr13, fragmentLength_measobjectlistextr13 int64) error {
			for _, elem := range v.MeasObjectListExtR13[fragmentOffset_measobjectlistextr13 : fragmentOffset_measobjectlistextr13+fragmentLength_measobjectlistextr13] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measObjectListExt-r13 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measObjectListExt-r13: %w", err)
		}
	}
	if v.MeasObjectListV9i0 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasObjectListV9i0)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measobjectlistv9i0, fragmentLength_measobjectlistv9i0 int64) error {
			for _, elem := range v.MeasObjectListV9i0[fragmentOffset_measobjectlistv9i0 : fragmentOffset_measobjectlistv9i0+fragmentLength_measobjectlistv9i0] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measObjectList-v9i0 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measObjectList-v9i0: %w", err)
		}
	}
	if v.ReportConfigList != nil {
		if err := per.EncodeCollection(bb, int64(len(v.ReportConfigList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_reportconfiglist, fragmentLength_reportconfiglist int64) error {
			for _, elem := range v.ReportConfigList[fragmentOffset_reportconfiglist : fragmentOffset_reportconfiglist+fragmentLength_reportconfiglist] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding reportConfigList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding reportConfigList: %w", err)
		}
	}
	if v.QuantityConfig != nil {
		if err := v.QuantityConfig.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding quantityConfig: %w", err)
		}
	}
	if v.MeasScaleFactorR12 != nil {
		if err := per.EncodeEnumerated(bb, int64(*v.MeasScaleFactorR12), 2, false); err != nil {
			return fmt.Errorf("encoding measScaleFactor-r12: %w", err)
		}
	}
	if v.SMeasure != nil {
		if err := per.EncodeInteger(bb, int64(*v.SMeasure), int64Ptr(-140), int64Ptr(-44), false); err != nil {
			return fmt.Errorf("encoding s-Measure: %w", err)
		}
	}
	if v.SpeedStatePars != nil {
		if err := v.SpeedStatePars.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding speedStatePars: %w", err)
		}
	}
	if v.AllowInterruptionsR11 != nil {
		if err := per.EncodeBoolean(bb, *v.AllowInterruptionsR11); err != nil {
			return fmt.Errorf("encoding allowInterruptions-r11: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarMeasConfig from UPER format.
func (v *VarMeasConfig) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasConfig")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasConfig")
	}
	return nil
}

func (v *VarMeasConfig) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarMeasConfig{}
	// Read preamble bitmap for optional root fields
	opt_measidlist, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measidlistextr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measidlistv1310, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measidlistextv1310, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measobjectlist, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measobjectlistextr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measobjectlistv9i0, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_reportconfiglist, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_quantityconfig, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measscalefactorr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_smeasure, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_speedstatepars, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_allowinterruptionsr11, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_measidlist {
		tmp_measidlist := make(MeasIdToAddModList, 0)
		_, errCollection_measidlist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measidlist, fragmentLength_measidlist int64) error {
			for i := int64(0); i < fragmentLength_measidlist; i++ {
				var elem MeasIdToAddMod
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasIdList[%d]", fragmentOffset_measidlist+i))
				}
				tmp_measidlist = append(tmp_measidlist, elem)
			}
			return nil
		})
		if errCollection_measidlist != nil {
			return runtime.WrapDecodePath(errCollection_measidlist, "MeasIdList")
		}
		v.MeasIdList = tmp_measidlist
	}
	if opt_measidlistextr12 {
		tmp_measidlistextr12 := make(MeasIdToAddModListExtR12, 0)
		_, errCollection_measidlistextr12 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measidlistextr12, fragmentLength_measidlistextr12 int64) error {
			for i := int64(0); i < fragmentLength_measidlistextr12; i++ {
				var elem MeasIdToAddModExtR12
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasIdListExtR12[%d]", fragmentOffset_measidlistextr12+i))
				}
				tmp_measidlistextr12 = append(tmp_measidlistextr12, elem)
			}
			return nil
		})
		if errCollection_measidlistextr12 != nil {
			return runtime.WrapDecodePath(errCollection_measidlistextr12, "MeasIdListExtR12")
		}
		v.MeasIdListExtR12 = tmp_measidlistextr12
	}
	if opt_measidlistv1310 {
		tmp_measidlistv1310 := make(MeasIdToAddModListV1310, 0)
		_, errCollection_measidlistv1310 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measidlistv1310, fragmentLength_measidlistv1310 int64) error {
			for i := int64(0); i < fragmentLength_measidlistv1310; i++ {
				var elem MeasIdToAddModV1310
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasIdListV1310[%d]", fragmentOffset_measidlistv1310+i))
				}
				tmp_measidlistv1310 = append(tmp_measidlistv1310, elem)
			}
			return nil
		})
		if errCollection_measidlistv1310 != nil {
			return runtime.WrapDecodePath(errCollection_measidlistv1310, "MeasIdListV1310")
		}
		v.MeasIdListV1310 = tmp_measidlistv1310
	}
	if opt_measidlistextv1310 {
		tmp_measidlistextv1310 := make(MeasIdToAddModListExtV1310, 0)
		_, errCollection_measidlistextv1310 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measidlistextv1310, fragmentLength_measidlistextv1310 int64) error {
			for i := int64(0); i < fragmentLength_measidlistextv1310; i++ {
				var elem MeasIdToAddModV1310
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasIdListExtV1310[%d]", fragmentOffset_measidlistextv1310+i))
				}
				tmp_measidlistextv1310 = append(tmp_measidlistextv1310, elem)
			}
			return nil
		})
		if errCollection_measidlistextv1310 != nil {
			return runtime.WrapDecodePath(errCollection_measidlistextv1310, "MeasIdListExtV1310")
		}
		v.MeasIdListExtV1310 = tmp_measidlistextv1310
	}
	if opt_measobjectlist {
		tmp_measobjectlist := make(MeasObjectToAddModList, 0)
		_, errCollection_measobjectlist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measobjectlist, fragmentLength_measobjectlist int64) error {
			for i := int64(0); i < fragmentLength_measobjectlist; i++ {
				var elem MeasObjectToAddMod
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasObjectList[%d]", fragmentOffset_measobjectlist+i))
				}
				tmp_measobjectlist = append(tmp_measobjectlist, elem)
			}
			return nil
		})
		if errCollection_measobjectlist != nil {
			return runtime.WrapDecodePath(errCollection_measobjectlist, "MeasObjectList")
		}
		v.MeasObjectList = tmp_measobjectlist
	}
	if opt_measobjectlistextr13 {
		tmp_measobjectlistextr13 := make(MeasObjectToAddModListExtR13, 0)
		_, errCollection_measobjectlistextr13 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measobjectlistextr13, fragmentLength_measobjectlistextr13 int64) error {
			for i := int64(0); i < fragmentLength_measobjectlistextr13; i++ {
				var elem MeasObjectToAddModExtR13
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasObjectListExtR13[%d]", fragmentOffset_measobjectlistextr13+i))
				}
				tmp_measobjectlistextr13 = append(tmp_measobjectlistextr13, elem)
			}
			return nil
		})
		if errCollection_measobjectlistextr13 != nil {
			return runtime.WrapDecodePath(errCollection_measobjectlistextr13, "MeasObjectListExtR13")
		}
		v.MeasObjectListExtR13 = tmp_measobjectlistextr13
	}
	if opt_measobjectlistv9i0 {
		tmp_measobjectlistv9i0 := make(MeasObjectToAddModListV9e0, 0)
		_, errCollection_measobjectlistv9i0 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_measobjectlistv9i0, fragmentLength_measobjectlistv9i0 int64) error {
			for i := int64(0); i < fragmentLength_measobjectlistv9i0; i++ {
				var elem MeasObjectToAddModV9e0
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasObjectListV9i0[%d]", fragmentOffset_measobjectlistv9i0+i))
				}
				tmp_measobjectlistv9i0 = append(tmp_measobjectlistv9i0, elem)
			}
			return nil
		})
		if errCollection_measobjectlistv9i0 != nil {
			return runtime.WrapDecodePath(errCollection_measobjectlistv9i0, "MeasObjectListV9i0")
		}
		v.MeasObjectListV9i0 = tmp_measobjectlistv9i0
	}
	if opt_reportconfiglist {
		tmp_reportconfiglist := make(ReportConfigToAddModList, 0)
		_, errCollection_reportconfiglist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_reportconfiglist, fragmentLength_reportconfiglist int64) error {
			for i := int64(0); i < fragmentLength_reportconfiglist; i++ {
				var elem ReportConfigToAddMod
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ReportConfigList[%d]", fragmentOffset_reportconfiglist+i))
				}
				tmp_reportconfiglist = append(tmp_reportconfiglist, elem)
			}
			return nil
		})
		if errCollection_reportconfiglist != nil {
			return runtime.WrapDecodePath(errCollection_reportconfiglist, "ReportConfigList")
		}
		v.ReportConfigList = tmp_reportconfiglist
	}
	if opt_quantityconfig {
		var dec_quantityconfig QuantityConfig
		if err := dec_quantityconfig.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "QuantityConfig")
		}
		v.QuantityConfig = &dec_quantityconfig
	}
	if opt_measscalefactorr12 {
		val_measscalefactorr12, err := per.DecodeEnumerated(bb, 2, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "MeasScaleFactorR12")
		}
		tmp_measscalefactorr12 := MeasScaleFactorR12(val_measscalefactorr12)
		v.MeasScaleFactorR12 = &tmp_measscalefactorr12
	}
	if opt_smeasure {
		val_smeasure, err := per.DecodeInteger(bb, int64Ptr(-140), int64Ptr(-44), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SMeasure")
		}
		v.SMeasure = &val_smeasure
	}
	if opt_speedstatepars {
		var dec_speedstatepars VarMeasConfigSpeedStatePars
		if err := dec_speedstatepars.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SpeedStatePars")
		}
		v.SpeedStatePars = &dec_speedstatepars
	}
	if opt_allowinterruptionsr11 {
		val_allowinterruptionsr11, err := per.DecodeBoolean(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "AllowInterruptionsR11")
		}
		v.AllowInterruptionsR11 = &val_allowinterruptionsr11
	}
	return nil
}

// MarshalUPER encodes VarMeasIdleConfigR15 to UPER format.
func (v *VarMeasIdleConfigR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarMeasIdleConfigR15) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MeasIdleCarrierListEUTRAR15 != nil); err != nil {
		return err
	}
	if v.MeasIdleCarrierListEUTRAR15 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasIdleCarrierListEUTRAR15)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_measidlecarrierlisteutrar15, fragmentLength_measidlecarrierlisteutrar15 int64) error {
			for _, elem := range v.MeasIdleCarrierListEUTRAR15[fragmentOffset_measidlecarrierlisteutrar15 : fragmentOffset_measidlecarrierlisteutrar15+fragmentLength_measidlecarrierlisteutrar15] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measIdleCarrierListEUTRA-r15 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measIdleCarrierListEUTRA-r15: %w", err)
		}
	}
	if err := per.EncodeEnumerated(bb, int64(v.MeasIdleDurationR15), 7, false); err != nil {
		return fmt.Errorf("encoding measIdleDuration-r15: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarMeasIdleConfigR15 from UPER format.
func (v *VarMeasIdleConfigR15) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasIdleConfigR15")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasIdleConfigR15")
	}
	return nil
}

func (v *VarMeasIdleConfigR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarMeasIdleConfigR15{}
	// Read preamble bitmap for optional root fields
	opt_measidlecarrierlisteutrar15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_measidlecarrierlisteutrar15 {
		tmp_measidlecarrierlisteutrar15 := make(EUTRACarrierListR15, 0)
		_, errCollection_measidlecarrierlisteutrar15 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_measidlecarrierlisteutrar15, fragmentLength_measidlecarrierlisteutrar15 int64) error {
			for i := int64(0); i < fragmentLength_measidlecarrierlisteutrar15; i++ {
				var elem MeasIdleCarrierEUTRAR15
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasIdleCarrierListEUTRAR15[%d]", fragmentOffset_measidlecarrierlisteutrar15+i))
				}
				tmp_measidlecarrierlisteutrar15 = append(tmp_measidlecarrierlisteutrar15, elem)
			}
			return nil
		})
		if errCollection_measidlecarrierlisteutrar15 != nil {
			return runtime.WrapDecodePath(errCollection_measidlecarrierlisteutrar15, "MeasIdleCarrierListEUTRAR15")
		}
		v.MeasIdleCarrierListEUTRAR15 = tmp_measidlecarrierlisteutrar15
	}
	val_measidledurationr15, err := per.DecodeEnumerated(bb, 7, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasIdleDurationR15")
	}
	v.MeasIdleDurationR15 = val_measidledurationr15
	return nil
}

// MarshalUPER encodes VarMeasIdleConfigR16 to UPER format.
func (v *VarMeasIdleConfigR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarMeasIdleConfigR16) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MeasIdleCarrierListNRR16 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ValidityAreaListR16 != nil); err != nil {
		return err
	}
	if v.MeasIdleCarrierListNRR16 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasIdleCarrierListNRR16)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_measidlecarrierlistnrr16, fragmentLength_measidlecarrierlistnrr16 int64) error {
			for _, elem := range v.MeasIdleCarrierListNRR16[fragmentOffset_measidlecarrierlistnrr16 : fragmentOffset_measidlecarrierlistnrr16+fragmentLength_measidlecarrierlistnrr16] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measIdleCarrierListNR-r16 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measIdleCarrierListNR-r16: %w", err)
		}
	}
	if v.ValidityAreaListR16 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.ValidityAreaListR16)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_validityarealistr16, fragmentLength_validityarealistr16 int64) error {
			for _, elem := range v.ValidityAreaListR16[fragmentOffset_validityarealistr16 : fragmentOffset_validityarealistr16+fragmentLength_validityarealistr16] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding validityAreaList-r16 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding validityAreaList-r16: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarMeasIdleConfigR16 from UPER format.
func (v *VarMeasIdleConfigR16) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasIdleConfigR16")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasIdleConfigR16")
	}
	return nil
}

func (v *VarMeasIdleConfigR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarMeasIdleConfigR16{}
	// Read preamble bitmap for optional root fields
	opt_measidlecarrierlistnrr16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_validityarealistr16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_measidlecarrierlistnrr16 {
		tmp_measidlecarrierlistnrr16 := make(NRCarrierListR16, 0)
		_, errCollection_measidlecarrierlistnrr16 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_measidlecarrierlistnrr16, fragmentLength_measidlecarrierlistnrr16 int64) error {
			for i := int64(0); i < fragmentLength_measidlecarrierlistnrr16; i++ {
				var elem MeasIdleCarrierNRR16
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasIdleCarrierListNRR16[%d]", fragmentOffset_measidlecarrierlistnrr16+i))
				}
				tmp_measidlecarrierlistnrr16 = append(tmp_measidlecarrierlistnrr16, elem)
			}
			return nil
		})
		if errCollection_measidlecarrierlistnrr16 != nil {
			return runtime.WrapDecodePath(errCollection_measidlecarrierlistnrr16, "MeasIdleCarrierListNRR16")
		}
		v.MeasIdleCarrierListNRR16 = tmp_measidlecarrierlistnrr16
	}
	if opt_validityarealistr16 {
		tmp_validityarealistr16 := make(ValidityAreaListR16, 0)
		_, errCollection_validityarealistr16 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_validityarealistr16, fragmentLength_validityarealistr16 int64) error {
			for i := int64(0); i < fragmentLength_validityarealistr16; i++ {
				var elem ValidityAreaR16
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ValidityAreaListR16[%d]", fragmentOffset_validityarealistr16+i))
				}
				tmp_validityarealistr16 = append(tmp_validityarealistr16, elem)
			}
			return nil
		})
		if errCollection_validityarealistr16 != nil {
			return runtime.WrapDecodePath(errCollection_validityarealistr16, "ValidityAreaListR16")
		}
		v.ValidityAreaListR16 = tmp_validityarealistr16
	}
	return nil
}

// MarshalUPER encodes VarMeasIdleReportR15 to UPER format.
func (v *VarMeasIdleReportR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarMeasIdleReportR15) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeCollection(bb, int64(len(v.MeasReportIdleR15)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 3, HasUpper: true}, false, func(fragmentOffset_measreportidler15, fragmentLength_measreportidler15 int64) error {
		for _, elem := range v.MeasReportIdleR15[fragmentOffset_measreportidler15 : fragmentOffset_measreportidler15+fragmentLength_measreportidler15] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measReportIdle-r15 element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding measReportIdle-r15: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarMeasIdleReportR15 from UPER format.
func (v *VarMeasIdleReportR15) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasIdleReportR15")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasIdleReportR15")
	}
	return nil
}

func (v *VarMeasIdleReportR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarMeasIdleReportR15{}
	v.MeasReportIdleR15 = make(MeasResultListIdleR15, 0)
	_, errCollection_measreportidler15 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 3, HasUpper: true}, false, func(fragmentOffset_measreportidler15, fragmentLength_measreportidler15 int64) error {
		for i := int64(0); i < fragmentLength_measreportidler15; i++ {
			var elem MeasResultIdleR15
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("MeasReportIdleR15[%d]", fragmentOffset_measreportidler15+i))
			}
			v.MeasReportIdleR15 = append(v.MeasReportIdleR15, elem)
		}
		return nil
	})
	if errCollection_measreportidler15 != nil {
		return runtime.WrapDecodePath(errCollection_measreportidler15, "MeasReportIdleR15")
	}
	return nil
}

// MarshalUPER encodes VarMeasIdleReportR16 to UPER format.
func (v *VarMeasIdleReportR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarMeasIdleReportR16) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MeasReportIdleR16 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.MeasReportIdleNRR16 != nil); err != nil {
		return err
	}
	if v.MeasReportIdleR16 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasReportIdleR16)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, false, func(fragmentOffset_measreportidler16, fragmentLength_measreportidler16 int64) error {
			for _, outerElem := range v.MeasReportIdleR16[fragmentOffset_measreportidler16 : fragmentOffset_measreportidler16+fragmentLength_measreportidler16] {
				if err := MarshalUPERMeasResultIdleListEUTRAR15To(outerElem, bb); err != nil {
					return fmt.Errorf("encoding measReportIdle-r16 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measReportIdle-r16: %w", err)
		}
	}
	if v.MeasReportIdleNRR16 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.MeasReportIdleNRR16)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_measreportidlenrr16, fragmentLength_measreportidlenrr16 int64) error {
			for _, elem := range v.MeasReportIdleNRR16[fragmentOffset_measreportidlenrr16 : fragmentOffset_measreportidlenrr16+fragmentLength_measreportidlenrr16] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding measReportIdleNR-r16 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measReportIdleNR-r16: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarMeasIdleReportR16 from UPER format.
func (v *VarMeasIdleReportR16) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasIdleReportR16")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasIdleReportR16")
	}
	return nil
}

func (v *VarMeasIdleReportR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarMeasIdleReportR16{}
	// Read preamble bitmap for optional root fields
	opt_measreportidler16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measreportidlenrr16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_measreportidler16 {
		tmp_measreportidler16 := make(MeasResultListExtIdleR16, 0)
		_, errCollection_measreportidler16 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, false, func(fragmentOffset_measreportidler16, fragmentLength_measreportidler16 int64) error {
			for i_measreportidler16 := int64(0); i_measreportidler16 < fragmentLength_measreportidler16; i_measreportidler16++ {
				elem, err := UnmarshalUPERMeasResultIdleListEUTRAR15From(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasReportIdleR16[%d]", fragmentOffset_measreportidler16+i_measreportidler16))
				}
				tmp_measreportidler16 = append(tmp_measreportidler16, elem)
			}
			return nil
		})
		if errCollection_measreportidler16 != nil {
			return runtime.WrapDecodePath(errCollection_measreportidler16, "MeasReportIdleR16")
		}
		v.MeasReportIdleR16 = tmp_measreportidler16
	}
	if opt_measreportidlenrr16 {
		tmp_measreportidlenrr16 := make(MeasResultListIdleNRR16, 0)
		_, errCollection_measreportidlenrr16 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, false, func(fragmentOffset_measreportidlenrr16, fragmentLength_measreportidlenrr16 int64) error {
			for i := int64(0); i < fragmentLength_measreportidlenrr16; i++ {
				var elem MeasResultIdleNRR16
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasReportIdleNRR16[%d]", fragmentOffset_measreportidlenrr16+i))
				}
				tmp_measreportidlenrr16 = append(tmp_measreportidlenrr16, elem)
			}
			return nil
		})
		if errCollection_measreportidlenrr16 != nil {
			return runtime.WrapDecodePath(errCollection_measreportidlenrr16, "MeasReportIdleNRR16")
		}
		v.MeasReportIdleNRR16 = tmp_measreportidlenrr16
	}
	return nil
}

type asn1cUPERVarMeasReportListListValue struct{ Value VarMeasReportList }

// MarshalUPERVarMeasReportList encodes a VarMeasReportList list to UPER.
func MarshalUPERVarMeasReportList(list VarMeasReportList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERVarMeasReportListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalUPERVarMeasReportListTo appends a VarMeasReportList list to bb.
func MarshalUPERVarMeasReportListTo(list VarMeasReportList, bb *per.BitBuffer) error {
	v := asn1cUPERVarMeasReportListListValue{Value: list}
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

// UnmarshalUPERVarMeasReportList decodes a VarMeasReportList list from UPER.
func UnmarshalUPERVarMeasReportList(data []byte) (VarMeasReportList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalUPERVarMeasReportListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "VarMeasReportList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "VarMeasReportList")
	}
	return value, nil
}

// UnmarshalUPERVarMeasReportListFrom decodes a VarMeasReportList list from bb.
func UnmarshalUPERVarMeasReportListFrom(bb *per.BitBuffer) (VarMeasReportList, error) {
	var v asn1cUPERVarMeasReportListListValue
	if err := unmarshalUPERVarMeasReportListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERVarMeasReportListInto(v *asn1cUPERVarMeasReportListListValue, bb *per.BitBuffer) error {
	v.Value = make(VarMeasReportList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem VarMeasReport
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

type asn1cUPERVarMeasReportListR12ListValue struct{ Value VarMeasReportListR12 }

// MarshalUPERVarMeasReportListR12 encodes a VarMeasReportListR12 list to UPER.
func MarshalUPERVarMeasReportListR12(list VarMeasReportListR12) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERVarMeasReportListR12To(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalUPERVarMeasReportListR12To appends a VarMeasReportListR12 list to bb.
func MarshalUPERVarMeasReportListR12To(list VarMeasReportListR12, bb *per.BitBuffer) error {
	v := asn1cUPERVarMeasReportListR12ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// UnmarshalUPERVarMeasReportListR12 decodes a VarMeasReportListR12 list from UPER.
func UnmarshalUPERVarMeasReportListR12(data []byte) (VarMeasReportListR12, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalUPERVarMeasReportListR12From(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "VarMeasReportListR12")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "VarMeasReportListR12")
	}
	return value, nil
}

// UnmarshalUPERVarMeasReportListR12From decodes a VarMeasReportListR12 list from bb.
func UnmarshalUPERVarMeasReportListR12From(bb *per.BitBuffer) (VarMeasReportListR12, error) {
	var v asn1cUPERVarMeasReportListR12ListValue
	if err := unmarshalUPERVarMeasReportListR12Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERVarMeasReportListR12Into(v *asn1cUPERVarMeasReportListR12ListValue, bb *per.BitBuffer) error {
	v.Value = make(VarMeasReportListR12, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem VarMeasReport
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

// MarshalUPER encodes VarMeasReport to UPER format.
func (v *VarMeasReport) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarMeasReport) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MeasIdV1250 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.CellsTriggeredList != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.CsiRSTriggeredListR12 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.PoolsTriggeredListR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeInteger(bb, int64(v.MeasId), int64Ptr(1), int64Ptr(32), false); err != nil {
		return fmt.Errorf("encoding measId: %w", err)
	}
	if v.MeasIdV1250 != nil {
		if err := per.EncodeInteger(bb, int64(*v.MeasIdV1250), int64Ptr(33), int64Ptr(64), false); err != nil {
			return fmt.Errorf("encoding measId-v1250: %w", err)
		}
	}
	if v.CellsTriggeredList != nil {
		if err := per.EncodeCollection(bb, int64(len(v.CellsTriggeredList)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_cellstriggeredlist, fragmentLength_cellstriggeredlist int64) error {
			for _, elem := range v.CellsTriggeredList[fragmentOffset_cellstriggeredlist : fragmentOffset_cellstriggeredlist+fragmentLength_cellstriggeredlist] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding cellsTriggeredList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding cellsTriggeredList: %w", err)
		}
	}
	if v.CsiRSTriggeredListR12 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.CsiRSTriggeredListR12)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 96, HasUpper: true}, false, func(fragmentOffset_csirstriggeredlistr12, fragmentLength_csirstriggeredlistr12 int64) error {
			for _, elem := range v.CsiRSTriggeredListR12[fragmentOffset_csirstriggeredlistr12 : fragmentOffset_csirstriggeredlistr12+fragmentLength_csirstriggeredlistr12] {
				if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(96), false); err != nil {
					return fmt.Errorf("encoding csi-RS-TriggeredList-r12 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding csi-RS-TriggeredList-r12: %w", err)
		}
	}
	if v.PoolsTriggeredListR14 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.PoolsTriggeredListR14)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 72, HasUpper: true}, false, func(fragmentOffset_poolstriggeredlistr14, fragmentLength_poolstriggeredlistr14 int64) error {
			for _, elem := range v.PoolsTriggeredListR14[fragmentOffset_poolstriggeredlistr14 : fragmentOffset_poolstriggeredlistr14+fragmentLength_poolstriggeredlistr14] {
				if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(72), false); err != nil {
					return fmt.Errorf("encoding poolsTriggeredList-r14 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding poolsTriggeredList-r14: %w", err)
		}
	}
	if err := per.EncodeIntegerBig(bb, v.NumberOfReportsSent, nil, nil, false); err != nil {
		return fmt.Errorf("encoding numberOfReportsSent: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarMeasReport from UPER format.
func (v *VarMeasReport) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasReport")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasReport")
	}
	return nil
}

func (v *VarMeasReport) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarMeasReport{}
	// Read preamble bitmap for optional root fields
	opt_measidv1250, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_cellstriggeredlist, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_csirstriggeredlistr12, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_poolstriggeredlistr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_measid, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(32), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasId")
	}
	v.MeasId = MeasId(val_measid)
	if opt_measidv1250 {
		val_measidv1250, err := per.DecodeInteger(bb, int64Ptr(33), int64Ptr(64), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "MeasIdV1250")
		}
		tmp_measidv1250 := MeasIdV1250(val_measidv1250)
		v.MeasIdV1250 = &tmp_measidv1250
	}
	if opt_cellstriggeredlist {
		tmp_cellstriggeredlist := make(CellsTriggeredList, 0)
		_, errCollection_cellstriggeredlist := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_cellstriggeredlist, fragmentLength_cellstriggeredlist int64) error {
			for i := int64(0); i < fragmentLength_cellstriggeredlist; i++ {
				var elem CellsTriggeredListElem
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("CellsTriggeredList[%d]", fragmentOffset_cellstriggeredlist+i))
				}
				tmp_cellstriggeredlist = append(tmp_cellstriggeredlist, elem)
			}
			return nil
		})
		if errCollection_cellstriggeredlist != nil {
			return runtime.WrapDecodePath(errCollection_cellstriggeredlist, "CellsTriggeredList")
		}
		v.CellsTriggeredList = tmp_cellstriggeredlist
	}
	if opt_csirstriggeredlistr12 {
		tmp_csirstriggeredlistr12 := make(CSIRSTriggeredListR12, 0)
		_, errCollection_csirstriggeredlistr12 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 96, HasUpper: true}, false, func(fragmentOffset_csirstriggeredlistr12, fragmentLength_csirstriggeredlistr12 int64) error {
			for i := int64(0); i < fragmentLength_csirstriggeredlistr12; i++ {
				val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(96), false)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("CsiRSTriggeredListR12[%d]", fragmentOffset_csirstriggeredlistr12+i))
				}
				tmp_csirstriggeredlistr12 = append(tmp_csirstriggeredlistr12, MeasCSIRSIdR12(val))
			}
			return nil
		})
		if errCollection_csirstriggeredlistr12 != nil {
			return runtime.WrapDecodePath(errCollection_csirstriggeredlistr12, "CsiRSTriggeredListR12")
		}
		v.CsiRSTriggeredListR12 = tmp_csirstriggeredlistr12
	}
	if opt_poolstriggeredlistr14 {
		tmp_poolstriggeredlistr14 := make(TxResourcePoolMeasListR14, 0)
		_, errCollection_poolstriggeredlistr14 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 72, HasUpper: true}, false, func(fragmentOffset_poolstriggeredlistr14, fragmentLength_poolstriggeredlistr14 int64) error {
			for i := int64(0); i < fragmentLength_poolstriggeredlistr14; i++ {
				val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(72), false)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("PoolsTriggeredListR14[%d]", fragmentOffset_poolstriggeredlistr14+i))
				}
				tmp_poolstriggeredlistr14 = append(tmp_poolstriggeredlistr14, SLV2XTxPoolReportIdentityR14(val))
			}
			return nil
		})
		if errCollection_poolstriggeredlistr14 != nil {
			return runtime.WrapDecodePath(errCollection_poolstriggeredlistr14, "PoolsTriggeredListR14")
		}
		v.PoolsTriggeredListR14 = tmp_poolstriggeredlistr14
	}
	val_numberofreportssent, err := per.DecodeIntegerBig(bb, nil, nil, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberOfReportsSent")
	}
	v.NumberOfReportsSent = val_numberofreportssent
	return nil
}

type asn1cUPERCellsTriggeredListListValue struct{ Value CellsTriggeredList }

// MarshalUPERCellsTriggeredList encodes a CellsTriggeredList list to UPER.
func MarshalUPERCellsTriggeredList(list CellsTriggeredList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERCellsTriggeredListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalUPERCellsTriggeredListTo appends a CellsTriggeredList list to bb.
func MarshalUPERCellsTriggeredListTo(list CellsTriggeredList, bb *per.BitBuffer) error {
	v := asn1cUPERCellsTriggeredListListValue{Value: list}
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

// UnmarshalUPERCellsTriggeredList decodes a CellsTriggeredList list from UPER.
func UnmarshalUPERCellsTriggeredList(data []byte) (CellsTriggeredList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalUPERCellsTriggeredListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "CellsTriggeredList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "CellsTriggeredList")
	}
	return value, nil
}

// UnmarshalUPERCellsTriggeredListFrom decodes a CellsTriggeredList list from bb.
func UnmarshalUPERCellsTriggeredListFrom(bb *per.BitBuffer) (CellsTriggeredList, error) {
	var v asn1cUPERCellsTriggeredListListValue
	if err := unmarshalUPERCellsTriggeredListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERCellsTriggeredListInto(v *asn1cUPERCellsTriggeredListListValue, bb *per.BitBuffer) error {
	v.Value = make(CellsTriggeredList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem CellsTriggeredListElem
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
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

type asn1cUPERCSIRSTriggeredListR12ListValue struct{ Value CSIRSTriggeredListR12 }

// MarshalUPERCSIRSTriggeredListR12 encodes a CSIRSTriggeredListR12 list to UPER.
func MarshalUPERCSIRSTriggeredListR12(list CSIRSTriggeredListR12) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERCSIRSTriggeredListR12To(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalUPERCSIRSTriggeredListR12To appends a CSIRSTriggeredListR12 list to bb.
func MarshalUPERCSIRSTriggeredListR12To(list CSIRSTriggeredListR12, bb *per.BitBuffer) error {
	v := asn1cUPERCSIRSTriggeredListR12ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 96, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(96), false); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERCSIRSTriggeredListR12 decodes a CSIRSTriggeredListR12 list from UPER.
func UnmarshalUPERCSIRSTriggeredListR12(data []byte) (CSIRSTriggeredListR12, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalUPERCSIRSTriggeredListR12From(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "CSIRSTriggeredListR12")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "CSIRSTriggeredListR12")
	}
	return value, nil
}

// UnmarshalUPERCSIRSTriggeredListR12From decodes a CSIRSTriggeredListR12 list from bb.
func UnmarshalUPERCSIRSTriggeredListR12From(bb *per.BitBuffer) (CSIRSTriggeredListR12, error) {
	var v asn1cUPERCSIRSTriggeredListR12ListValue
	if err := unmarshalUPERCSIRSTriggeredListR12Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERCSIRSTriggeredListR12Into(v *asn1cUPERCSIRSTriggeredListR12ListValue, bb *per.BitBuffer) error {
	v.Value = make(CSIRSTriggeredListR12, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 96, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(96), false)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, MeasCSIRSIdR12(val))
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

type asn1cUPERSSBIndexListR15ListValue struct{ Value SSBIndexListR15 }

// MarshalUPERSSBIndexListR15 encodes a SSBIndexListR15 list to UPER.
func MarshalUPERSSBIndexListR15(list SSBIndexListR15) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSSBIndexListR15To(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalUPERSSBIndexListR15To appends a SSBIndexListR15 list to bb.
func MarshalUPERSSBIndexListR15To(list SSBIndexListR15, bb *per.BitBuffer) error {
	v := asn1cUPERSSBIndexListR15ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := per.EncodeInteger(bb, int64(elem), int64Ptr(0), int64Ptr(63), false); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERSSBIndexListR15 decodes a SSBIndexListR15 list from UPER.
func UnmarshalUPERSSBIndexListR15(data []byte) (SSBIndexListR15, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalUPERSSBIndexListR15From(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "SSBIndexListR15")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "SSBIndexListR15")
	}
	return value, nil
}

// UnmarshalUPERSSBIndexListR15From decodes a SSBIndexListR15 list from bb.
func UnmarshalUPERSSBIndexListR15From(bb *per.BitBuffer) (SSBIndexListR15, error) {
	var v asn1cUPERSSBIndexListR15ListValue
	if err := unmarshalUPERSSBIndexListR15Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSSBIndexListR15Into(v *asn1cUPERSSBIndexListR15ListValue, bb *per.BitBuffer) error {
	v.Value = make(SSBIndexListR15, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(63), false)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, RSIndexNRR15(val))
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalUPER encodes VarPendingRnaUpdateR15 to UPER format.
func (v *VarPendingRnaUpdateR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarPendingRnaUpdateR15) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.PendingRnaUpdate != nil); err != nil {
		return err
	}
	if v.PendingRnaUpdate != nil {
		if err := per.EncodeBoolean(bb, *v.PendingRnaUpdate); err != nil {
			return fmt.Errorf("encoding pendingRnaUpdate: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarPendingRnaUpdateR15 from UPER format.
func (v *VarPendingRnaUpdateR15) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarPendingRnaUpdateR15")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarPendingRnaUpdateR15")
	}
	return nil
}

func (v *VarPendingRnaUpdateR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarPendingRnaUpdateR15{}
	// Read preamble bitmap for optional root fields
	opt_pendingrnaupdate, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_pendingrnaupdate {
		val_pendingrnaupdate, err := per.DecodeBoolean(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "PendingRnaUpdate")
		}
		v.PendingRnaUpdate = &val_pendingrnaupdate
	}
	return nil
}

// MarshalUPER encodes VarRLFReportR10 to UPER format.
func (v *VarRLFReportR10) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarRLFReportR10) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.RlfReportR10.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding rlf-Report-r10: %w", err)
	}
	if err := v.PlmnIdentityR10.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding plmn-Identity-r10: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarRLFReportR10 from UPER format.
func (v *VarRLFReportR10) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarRLFReportR10")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarRLFReportR10")
	}
	return nil
}

func (v *VarRLFReportR10) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarRLFReportR10{}
	if err := v.RlfReportR10.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RlfReportR10")
	}
	if err := v.PlmnIdentityR10.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PlmnIdentityR10")
	}
	return nil
}

// MarshalUPER encodes VarRLFReportR11 to UPER format.
func (v *VarRLFReportR11) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarRLFReportR11) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.RlfReportR10.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding rlf-Report-r10: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.PlmnIdentityListR11)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, false, func(fragmentOffset_plmnidentitylistr11, fragmentLength_plmnidentitylistr11 int64) error {
		for _, elem := range v.PlmnIdentityListR11[fragmentOffset_plmnidentitylistr11 : fragmentOffset_plmnidentitylistr11+fragmentLength_plmnidentitylistr11] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding plmn-IdentityList-r11 element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding plmn-IdentityList-r11: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarRLFReportR11 from UPER format.
func (v *VarRLFReportR11) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarRLFReportR11")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarRLFReportR11")
	}
	return nil
}

func (v *VarRLFReportR11) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarRLFReportR11{}
	if err := v.RlfReportR10.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RlfReportR10")
	}
	v.PlmnIdentityListR11 = make(PLMNIdentityList3R11, 0)
	_, errCollection_plmnidentitylistr11 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, false, func(fragmentOffset_plmnidentitylistr11, fragmentLength_plmnidentitylistr11 int64) error {
		for i := int64(0); i < fragmentLength_plmnidentitylistr11; i++ {
			var elem PLMNIdentity
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PlmnIdentityListR11[%d]", fragmentOffset_plmnidentitylistr11+i))
			}
			v.PlmnIdentityListR11 = append(v.PlmnIdentityListR11, elem)
		}
		return nil
	})
	if errCollection_plmnidentitylistr11 != nil {
		return runtime.WrapDecodePath(errCollection_plmnidentitylistr11, "PlmnIdentityListR11")
	}
	return nil
}

// MarshalUPER encodes VarShortINACTIVEMACInputR15 to UPER format.
func (v *VarShortINACTIVEMACInputR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarShortINACTIVEMACInputR15) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeBitStringExt(bb, v.CellIdentityR15.Bytes, v.CellIdentityR15.BitLength, 28, 28, true, false); err != nil {
		return fmt.Errorf("encoding cellIdentity-r15: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.PhysCellIdR15), int64Ptr(0), int64Ptr(503), false); err != nil {
		return fmt.Errorf("encoding physCellId-r15: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.CRNTIR15.Bytes, v.CRNTIR15.BitLength, 16, 16, true, false); err != nil {
		return fmt.Errorf("encoding c-RNTI-r15: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarShortINACTIVEMACInputR15 from UPER format.
func (v *VarShortINACTIVEMACInputR15) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarShortINACTIVEMACInputR15")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarShortINACTIVEMACInputR15")
	}
	return nil
}

func (v *VarShortINACTIVEMACInputR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarShortINACTIVEMACInputR15{}
	bsBytes_cellidentityr15, bsBitLen_cellidentityr15, err := per.DecodeBitStringExt(bb, 28, 28, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdentityR15")
	}
	v.CellIdentityR15 = runtime.BitString{Bytes: bsBytes_cellidentityr15, BitLength: bsBitLen_cellidentityr15}
	val_physcellidr15, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PhysCellIdR15")
	}
	v.PhysCellIdR15 = PhysCellId(val_physcellidr15)
	bsBytes_crntir15, bsBitLen_crntir15, err := per.DecodeBitStringExt(bb, 16, 16, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CRNTIR15")
	}
	v.CRNTIR15 = runtime.BitString{Bytes: bsBytes_crntir15, BitLength: bsBitLen_crntir15}
	return nil
}

// MarshalUPER encodes VarShortMACInput to UPER format.
func (v *VarShortMACInput) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarShortMACInput) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeBitStringExt(bb, v.CellIdentity.Bytes, v.CellIdentity.BitLength, 28, 28, true, false); err != nil {
		return fmt.Errorf("encoding cellIdentity: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.PhysCellId), int64Ptr(0), int64Ptr(503), false); err != nil {
		return fmt.Errorf("encoding physCellId: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.CRNTI.Bytes, v.CRNTI.BitLength, 16, 16, true, false); err != nil {
		return fmt.Errorf("encoding c-RNTI: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarShortMACInput from UPER format.
func (v *VarShortMACInput) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarShortMACInput")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarShortMACInput")
	}
	return nil
}

func (v *VarShortMACInput) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarShortMACInput{}
	bsBytes_cellidentity, bsBitLen_cellidentity, err := per.DecodeBitStringExt(bb, 28, 28, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdentity")
	}
	v.CellIdentity = runtime.BitString{Bytes: bsBytes_cellidentity, BitLength: bsBitLen_cellidentity}
	val_physcellid, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PhysCellId")
	}
	v.PhysCellId = PhysCellId(val_physcellid)
	bsBytes_crnti, bsBitLen_crnti, err := per.DecodeBitStringExt(bb, 16, 16, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CRNTI")
	}
	v.CRNTI = runtime.BitString{Bytes: bsBytes_crnti, BitLength: bsBitLen_crnti}
	return nil
}

// MarshalUPER encodes VarShortResumeMACInputR13 to UPER format.
func (v *VarShortResumeMACInputR13) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarShortResumeMACInputR13) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeBitStringExt(bb, v.CellIdentityR13.Bytes, v.CellIdentityR13.BitLength, 28, 28, true, false); err != nil {
		return fmt.Errorf("encoding cellIdentity-r13: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.PhysCellIdR13), int64Ptr(0), int64Ptr(503), false); err != nil {
		return fmt.Errorf("encoding physCellId-r13: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.CRNTIR13.Bytes, v.CRNTIR13.BitLength, 16, 16, true, false); err != nil {
		return fmt.Errorf("encoding c-RNTI-r13: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.ResumeDiscriminatorR13.Bytes, v.ResumeDiscriminatorR13.BitLength, 1, 1, true, false); err != nil {
		return fmt.Errorf("encoding resumeDiscriminator-r13: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarShortResumeMACInputR13 from UPER format.
func (v *VarShortResumeMACInputR13) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarShortResumeMACInputR13")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarShortResumeMACInputR13")
	}
	return nil
}

func (v *VarShortResumeMACInputR13) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarShortResumeMACInputR13{}
	bsBytes_cellidentityr13, bsBitLen_cellidentityr13, err := per.DecodeBitStringExt(bb, 28, 28, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdentityR13")
	}
	v.CellIdentityR13 = runtime.BitString{Bytes: bsBytes_cellidentityr13, BitLength: bsBitLen_cellidentityr13}
	val_physcellidr13, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PhysCellIdR13")
	}
	v.PhysCellIdR13 = PhysCellId(val_physcellidr13)
	bsBytes_crntir13, bsBitLen_crntir13, err := per.DecodeBitStringExt(bb, 16, 16, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CRNTIR13")
	}
	v.CRNTIR13 = runtime.BitString{Bytes: bsBytes_crntir13, BitLength: bsBitLen_crntir13}
	bsBytes_resumediscriminatorr13, bsBitLen_resumediscriminatorr13, err := per.DecodeBitStringExt(bb, 1, 1, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResumeDiscriminatorR13")
	}
	v.ResumeDiscriminatorR13 = runtime.BitString{Bytes: bsBytes_resumediscriminatorr13, BitLength: bsBitLen_resumediscriminatorr13}
	return nil
}

// MarshalUPER encodes VarWLANMobilityConfig to UPER format.
func (v *VarWLANMobilityConfig) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarWLANMobilityConfig) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.WlanMobilitySetR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SuccessReportRequested != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.WlanSuspendConfigR14 != nil); err != nil {
		return err
	}
	if v.WlanMobilitySetR13 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.WlanMobilitySetR13)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_wlanmobilitysetr13, fragmentLength_wlanmobilitysetr13 int64) error {
			for _, elem := range v.WlanMobilitySetR13[fragmentOffset_wlanmobilitysetr13 : fragmentOffset_wlanmobilitysetr13+fragmentLength_wlanmobilitysetr13] {
				if err := elem.MarshalUPERTo(bb); err != nil {
					return fmt.Errorf("encoding wlan-MobilitySet-r13 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding wlan-MobilitySet-r13: %w", err)
		}
	}
	if v.SuccessReportRequested != nil {
		if err := per.EncodeEnumerated(bb, int64(*v.SuccessReportRequested), 1, false); err != nil {
			return fmt.Errorf("encoding successReportRequested: %w", err)
		}
	}
	if v.WlanSuspendConfigR14 != nil {
		if err := v.WlanSuspendConfigR14.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding wlan-SuspendConfig-r14: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarWLANMobilityConfig from UPER format.
func (v *VarWLANMobilityConfig) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarWLANMobilityConfig")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarWLANMobilityConfig")
	}
	return nil
}

func (v *VarWLANMobilityConfig) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarWLANMobilityConfig{}
	// Read preamble bitmap for optional root fields
	opt_wlanmobilitysetr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_successreportrequested, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_wlansuspendconfigr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_wlanmobilitysetr13 {
		tmp_wlanmobilitysetr13 := make(WLANIdListR13, 0)
		_, errCollection_wlanmobilitysetr13 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, false, func(fragmentOffset_wlanmobilitysetr13, fragmentLength_wlanmobilitysetr13 int64) error {
			for i := int64(0); i < fragmentLength_wlanmobilitysetr13; i++ {
				var elem WLANIdentifiersR12
				if err := elem.UnmarshalUPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("WlanMobilitySetR13[%d]", fragmentOffset_wlanmobilitysetr13+i))
				}
				tmp_wlanmobilitysetr13 = append(tmp_wlanmobilitysetr13, elem)
			}
			return nil
		})
		if errCollection_wlanmobilitysetr13 != nil {
			return runtime.WrapDecodePath(errCollection_wlanmobilitysetr13, "WlanMobilitySetR13")
		}
		v.WlanMobilitySetR13 = tmp_wlanmobilitysetr13
	}
	if opt_successreportrequested {
		val_successreportrequested, err := per.DecodeEnumerated(bb, 1, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SuccessReportRequested")
		}
		v.SuccessReportRequested = &val_successreportrequested
	}
	if opt_wlansuspendconfigr14 {
		var dec_wlansuspendconfigr14 WLANSuspendConfigR14
		if err := dec_wlansuspendconfigr14.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "WlanSuspendConfigR14")
		}
		v.WlanSuspendConfigR14 = &dec_wlansuspendconfigr14
	}
	return nil
}

// MarshalUPER encodes VarWLANStatusR13 to UPER format.
func (v *VarWLANStatusR13) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarWLANStatusR13) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.StatusR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumerated(bb, int64(v.StatusR13), 4, false); err != nil {
		return fmt.Errorf("encoding status-r13: %w", err)
	}
	if v.StatusR14 != nil {
		if err := per.EncodeEnumerated(bb, int64(*v.StatusR14), 2, false); err != nil {
			return fmt.Errorf("encoding status-r14: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarWLANStatusR13 from UPER format.
func (v *VarWLANStatusR13) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarWLANStatusR13")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarWLANStatusR13")
	}
	return nil
}

func (v *VarWLANStatusR13) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarWLANStatusR13{}
	// Read preamble bitmap for optional root fields
	opt_statusr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_statusr13, err := per.DecodeEnumerated(bb, 4, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "StatusR13")
	}
	v.StatusR13 = WLANStatusR13(val_statusr13)
	if opt_statusr14 {
		val_statusr14, err := per.DecodeEnumerated(bb, 2, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "StatusR14")
		}
		tmp_statusr14 := WLANStatusV1430(val_statusr14)
		v.StatusR14 = &tmp_statusr14
	}
	return nil
}

// MarshalUPER encodes VarMeasConfigSpeedStatePars to UPER format.
func (v *VarMeasConfigSpeedStatePars) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarMeasConfigSpeedStatePars) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case VarMeasConfigSpeedStateParsChoiceRelease:
	case VarMeasConfigSpeedStateParsChoiceSetup:
		if v.Setup == nil {
			return fmt.Errorf("choice alternative setup is nil")
		}
		if err := v.Setup.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding setup: %w", err)
		}
	default:
		return fmt.Errorf("unknown VarMeasConfigSpeedStatePars choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes VarMeasConfigSpeedStatePars from UPER format.
func (v *VarMeasConfigSpeedStatePars) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasConfigSpeedStatePars")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasConfigSpeedStatePars")
	}
	return nil
}

func (v *VarMeasConfigSpeedStatePars) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarMeasConfigSpeedStatePars{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case VarMeasConfigSpeedStateParsChoiceRelease:
	case VarMeasConfigSpeedStateParsChoiceSetup:
		var dec_setup VarMeasConfigSpeedStateParsSetup
		if err := dec_setup.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "Setup")
		}
		v.Setup = &dec_setup
	}
	return nil
}

// MarshalUPER encodes VarMeasConfigSpeedStateParsSetup to UPER format.
func (v *VarMeasConfigSpeedStateParsSetup) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *VarMeasConfigSpeedStateParsSetup) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.MobilityStateParameters.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding mobilityStateParameters: %w", err)
	}
	if err := v.TimeToTriggerSF.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding timeToTrigger-SF: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarMeasConfigSpeedStateParsSetup from UPER format.
func (v *VarMeasConfigSpeedStateParsSetup) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasConfigSpeedStateParsSetup")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarMeasConfigSpeedStateParsSetup")
	}
	return nil
}

func (v *VarMeasConfigSpeedStateParsSetup) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarMeasConfigSpeedStateParsSetup{}
	if err := v.MobilityStateParameters.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MobilityStateParameters")
	}
	if err := v.TimeToTriggerSF.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TimeToTriggerSF")
	}
	return nil
}

// MarshalUPER encodes CellsTriggeredListElem to UPER format.
func (v *CellsTriggeredListElem) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *CellsTriggeredListElem) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 5); err != nil {
		return err
	}
	switch v.Choice {
	case CellsTriggeredListElemChoicePhysCellIdEUTRA:
		if v.PhysCellIdEUTRA == nil {
			return fmt.Errorf("choice alternative physCellIdEUTRA is nil")
		}
		if err := per.EncodeInteger(bb, int64(*v.PhysCellIdEUTRA), int64Ptr(0), int64Ptr(503), false); err != nil {
			return fmt.Errorf("encoding physCellIdEUTRA: %w", err)
		}
	case CellsTriggeredListElemChoicePhysCellIdUTRA:
		if v.PhysCellIdUTRA == nil {
			return fmt.Errorf("choice alternative physCellIdUTRA is nil")
		}
		if err := v.PhysCellIdUTRA.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding physCellIdUTRA: %w", err)
		}
	case CellsTriggeredListElemChoicePhysCellIdGERAN:
		if v.PhysCellIdGERAN == nil {
			return fmt.Errorf("choice alternative physCellIdGERAN is nil")
		}
		if err := v.PhysCellIdGERAN.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding physCellIdGERAN: %w", err)
		}
	case CellsTriggeredListElemChoicePhysCellIdCDMA2000:
		if v.PhysCellIdCDMA2000 == nil {
			return fmt.Errorf("choice alternative physCellIdCDMA2000 is nil")
		}
		if err := per.EncodeInteger(bb, int64(*v.PhysCellIdCDMA2000), int64Ptr(0), int64Ptr(511), false); err != nil {
			return fmt.Errorf("encoding physCellIdCDMA2000: %w", err)
		}
	case CellsTriggeredListElemChoiceWlanIdentifiersR13:
		if v.WlanIdentifiersR13 == nil {
			return fmt.Errorf("choice alternative wlan-Identifiers-r13 is nil")
		}
		if err := v.WlanIdentifiersR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding wlan-Identifiers-r13: %w", err)
		}
	case CellsTriggeredListElemChoicePhysCellIdNRR15:
		if v.PhysCellIdNRR15 == nil {
			return fmt.Errorf("choice alternative physCellIdNR-r15 is nil")
		}
		if err := v.PhysCellIdNRR15.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding physCellIdNR-r15: %w", err)
		}
	default:
		return fmt.Errorf("unknown CellsTriggeredListElem choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes CellsTriggeredListElem from UPER format.
func (v *CellsTriggeredListElem) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellsTriggeredListElem")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellsTriggeredListElem")
	}
	return nil
}

func (v *CellsTriggeredListElem) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = CellsTriggeredListElem{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 5)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case CellsTriggeredListElemChoicePhysCellIdEUTRA:
		val_physcellideutra, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "PhysCellIdEUTRA")
		}
		tmp_physcellideutra := PhysCellId(val_physcellideutra)
		v.PhysCellIdEUTRA = &tmp_physcellideutra
	case CellsTriggeredListElemChoicePhysCellIdUTRA:
		var dec_physcellidutra CellsTriggeredListElemPhysCellIdUTRA
		if err := dec_physcellidutra.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PhysCellIdUTRA")
		}
		v.PhysCellIdUTRA = &dec_physcellidutra
	case CellsTriggeredListElemChoicePhysCellIdGERAN:
		var dec_physcellidgeran CellsTriggeredListElemPhysCellIdGERAN
		if err := dec_physcellidgeran.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PhysCellIdGERAN")
		}
		v.PhysCellIdGERAN = &dec_physcellidgeran
	case CellsTriggeredListElemChoicePhysCellIdCDMA2000:
		val_physcellidcdma2000, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(511), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "PhysCellIdCDMA2000")
		}
		tmp_physcellidcdma2000 := PhysCellIdCDMA2000(val_physcellidcdma2000)
		v.PhysCellIdCDMA2000 = &tmp_physcellidcdma2000
	case CellsTriggeredListElemChoiceWlanIdentifiersR13:
		var dec_wlanidentifiersr13 WLANIdentifiersR12
		if err := dec_wlanidentifiersr13.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "WlanIdentifiersR13")
		}
		v.WlanIdentifiersR13 = &dec_wlanidentifiersr13
	case CellsTriggeredListElemChoicePhysCellIdNRR15:
		var dec_physcellidnrr15 CellsTriggeredListElemPhysCellIdNRR15
		if err := dec_physcellidnrr15.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PhysCellIdNRR15")
		}
		v.PhysCellIdNRR15 = &dec_physcellidnrr15
	}
	return nil
}

// MarshalUPER encodes CellsTriggeredListElemPhysCellIdUTRA to UPER format.
func (v *CellsTriggeredListElemPhysCellIdUTRA) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *CellsTriggeredListElemPhysCellIdUTRA) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case CellsTriggeredListElemPhysCellIdUTRAChoiceFdd:
		if v.Fdd == nil {
			return fmt.Errorf("choice alternative fdd is nil")
		}
		if err := per.EncodeInteger(bb, int64(*v.Fdd), int64Ptr(0), int64Ptr(511), false); err != nil {
			return fmt.Errorf("encoding fdd: %w", err)
		}
	case CellsTriggeredListElemPhysCellIdUTRAChoiceTdd:
		if v.Tdd == nil {
			return fmt.Errorf("choice alternative tdd is nil")
		}
		if err := per.EncodeInteger(bb, int64(*v.Tdd), int64Ptr(0), int64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding tdd: %w", err)
		}
	default:
		return fmt.Errorf("unknown CellsTriggeredListElemPhysCellIdUTRA choice %d", v.Choice)
	}
	return nil
}

// UnmarshalUPER decodes CellsTriggeredListElemPhysCellIdUTRA from UPER format.
func (v *CellsTriggeredListElemPhysCellIdUTRA) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellsTriggeredListElemPhysCellIdUTRA")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellsTriggeredListElemPhysCellIdUTRA")
	}
	return nil
}

func (v *CellsTriggeredListElemPhysCellIdUTRA) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = CellsTriggeredListElemPhysCellIdUTRA{}
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case CellsTriggeredListElemPhysCellIdUTRAChoiceFdd:
		val_fdd, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(511), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "Fdd")
		}
		tmp_fdd := PhysCellIdUTRAFDD(val_fdd)
		v.Fdd = &tmp_fdd
	case CellsTriggeredListElemPhysCellIdUTRAChoiceTdd:
		val_tdd, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "Tdd")
		}
		tmp_tdd := PhysCellIdUTRATDD(val_tdd)
		v.Tdd = &tmp_tdd
	}
	return nil
}

// MarshalUPER encodes CellsTriggeredListElemPhysCellIdGERAN to UPER format.
func (v *CellsTriggeredListElemPhysCellIdGERAN) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *CellsTriggeredListElemPhysCellIdGERAN) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.CarrierFreq.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding carrierFreq: %w", err)
	}
	if err := v.PhysCellId.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding physCellId: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes CellsTriggeredListElemPhysCellIdGERAN from UPER format.
func (v *CellsTriggeredListElemPhysCellIdGERAN) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellsTriggeredListElemPhysCellIdGERAN")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellsTriggeredListElemPhysCellIdGERAN")
	}
	return nil
}

func (v *CellsTriggeredListElemPhysCellIdGERAN) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = CellsTriggeredListElemPhysCellIdGERAN{}
	if err := v.CarrierFreq.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CarrierFreq")
	}
	if err := v.PhysCellId.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PhysCellId")
	}
	return nil
}

// MarshalUPER encodes CellsTriggeredListElemPhysCellIdNRR15 to UPER format.
func (v *CellsTriggeredListElemPhysCellIdNRR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *CellsTriggeredListElemPhysCellIdNRR15) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.RsIndexListR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeInteger(bb, int64(v.CarrierFreq), int64Ptr(0), int64Ptr(3279165), false); err != nil {
		return fmt.Errorf("encoding carrierFreq: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.PhysCellId), int64Ptr(0), int64Ptr(1007), false); err != nil {
		return fmt.Errorf("encoding physCellId: %w", err)
	}
	if v.RsIndexListR15 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.RsIndexListR15)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, false, func(fragmentOffset_rsindexlistr15, fragmentLength_rsindexlistr15 int64) error {
			for _, elem := range v.RsIndexListR15[fragmentOffset_rsindexlistr15 : fragmentOffset_rsindexlistr15+fragmentLength_rsindexlistr15] {
				if err := per.EncodeInteger(bb, int64(elem), int64Ptr(0), int64Ptr(63), false); err != nil {
					return fmt.Errorf("encoding rs-IndexList-r15 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding rs-IndexList-r15: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes CellsTriggeredListElemPhysCellIdNRR15 from UPER format.
func (v *CellsTriggeredListElemPhysCellIdNRR15) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellsTriggeredListElemPhysCellIdNRR15")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellsTriggeredListElemPhysCellIdNRR15")
	}
	return nil
}

func (v *CellsTriggeredListElemPhysCellIdNRR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = CellsTriggeredListElemPhysCellIdNRR15{}
	// Read preamble bitmap for optional root fields
	opt_rsindexlistr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_carrierfreq, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(3279165), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CarrierFreq")
	}
	v.CarrierFreq = ARFCNValueNRR15(val_carrierfreq)
	val_physcellid, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(1007), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PhysCellId")
	}
	v.PhysCellId = PhysCellIdNRR15(val_physcellid)
	if opt_rsindexlistr15 {
		tmp_rsindexlistr15 := make(SSBIndexListR15, 0)
		_, errCollection_rsindexlistr15 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, false, func(fragmentOffset_rsindexlistr15, fragmentLength_rsindexlistr15 int64) error {
			for i := int64(0); i < fragmentLength_rsindexlistr15; i++ {
				val, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(63), false)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("RsIndexListR15[%d]", fragmentOffset_rsindexlistr15+i))
				}
				tmp_rsindexlistr15 = append(tmp_rsindexlistr15, RSIndexNRR15(val))
			}
			return nil
		})
		if errCollection_rsindexlistr15 != nil {
			return runtime.WrapDecodePath(errCollection_rsindexlistr15, "RsIndexListR15")
		}
		v.RsIndexListR15 = tmp_rsindexlistr15
	}
	return nil
}
