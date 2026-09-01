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

	// MaxLogMeasR10 is the integer constant for MaxLogMeasR10.
	MaxLogMeasR10 int64 = 4060
)

// VarConditionalReconfiguration represents the ASN.1 type VarConditionalReconfiguration (SEQUENCE).
type VarConditionalReconfiguration struct {
	CondReconfigurationListR16       CondReconfigurationToAddModListR16 `asn1:"tag:0,context,implicit,optional" json:"CondReconfigurationListR16,omitempty"`
	CondReconfigurationListR16Indef_ bool                               `asn1:"-" json:"-"`
}

// VarConnEstFailReportR11 represents the ASN.1 type VarConnEstFailReportR11 (SEQUENCE).
type VarConnEstFailReportR11 struct {
	ConnEstFailReportR11 ConnEstFailReportR11 `asn1:"tag:0,context,implicit"`
	PlmnIdentityR11      PLMNIdentity         `asn1:"tag:1,context,implicit"`
}

// VarLogMeasConfigR10 represents the ASN.1 type VarLogMeasConfigR10 (SEQUENCE).
type VarLogMeasConfigR10 struct {
	AreaConfigurationR10 *AreaConfigurationR10 `asn1:"tag:0,context,explicit,optional" json:"AreaConfigurationR10,omitempty"`
	LoggingDurationR10   LoggingDurationR10    `asn1:"tag:1,context,implicit"`
	LoggingIntervalR10   LoggingIntervalR10    `asn1:"tag:2,context,implicit"`
}

// VarLogMeasConfigR11 represents the ASN.1 type VarLogMeasConfigR11 (SEQUENCE).
type VarLogMeasConfigR11 struct {
	AreaConfigurationR10   *AreaConfigurationR10   `asn1:"tag:0,context,explicit,optional" json:"AreaConfigurationR10,omitempty"`
	AreaConfigurationV1130 *AreaConfigurationV1130 `asn1:"tag:1,context,implicit,optional" json:"AreaConfigurationV1130,omitempty"`
	LoggingDurationR10     LoggingDurationR10      `asn1:"tag:2,context,implicit"`
	LoggingIntervalR10     LoggingIntervalR10      `asn1:"tag:3,context,implicit"`
}

// VarLogMeasConfigR12 represents the ASN.1 type VarLogMeasConfigR12 (SEQUENCE).
type VarLogMeasConfigR12 struct {
	AreaConfigurationR10         *AreaConfigurationR10   `asn1:"tag:0,context,explicit,optional" json:"AreaConfigurationR10,omitempty"`
	AreaConfigurationV1130       *AreaConfigurationV1130 `asn1:"tag:1,context,implicit,optional" json:"AreaConfigurationV1130,omitempty"`
	LoggingDurationR10           LoggingDurationR10      `asn1:"tag:2,context,implicit"`
	LoggingIntervalR10           LoggingIntervalR10      `asn1:"tag:3,context,implicit"`
	TargetMBSFNAreaListR12       TargetMBSFNAreaListR12  `asn1:"tag:4,context,implicit,optional" json:"TargetMBSFNAreaListR12,omitempty"`
	TargetMBSFNAreaListR12Indef_ bool                    `asn1:"-" json:"-"`
}

// VarLogMeasConfigR15 represents the ASN.1 type VarLogMeasConfigR15 (SEQUENCE).
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

// VarLogMeasConfigR17 represents the ASN.1 type VarLogMeasConfigR17 (SEQUENCE).
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

// VarLogMeasReportR10 represents the ASN.1 type VarLogMeasReportR10 (SEQUENCE).
type VarLogMeasReportR10 struct {
	TraceReferenceR10           TraceReferenceR10   `asn1:"tag:0,context,implicit"`
	TraceRecordingSessionRefR10 []byte              `asn1:"tag:1,context,implicit"`
	TceIdR10                    []byte              `asn1:"tag:2,context,implicit"`
	PlmnIdentityR10             PLMNIdentity        `asn1:"tag:3,context,implicit"`
	AbsoluteTimeInfoR10         AbsoluteTimeInfoR10 `asn1:"tag:4,context,implicit"`
	LogMeasInfoListR10          LogMeasInfoList2R10 `asn1:"tag:5,context,implicit"`
	LogMeasInfoListR10Indef_    bool                `asn1:"-" json:"-"`
}

// VarLogMeasReportR11 represents the ASN.1 type VarLogMeasReportR11 (SEQUENCE).
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

// LogMeasInfoList2R10 represents the ASN.1 type LogMeasInfoList2R10 (SEQUENCE_OF).
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

// VarMeasIdleConfigR15 represents the ASN.1 type VarMeasIdleConfigR15 (SEQUENCE).
type VarMeasIdleConfigR15 struct {
	MeasIdleCarrierListEUTRAR15       EUTRACarrierListR15 `asn1:"tag:0,context,implicit,optional" json:"MeasIdleCarrierListEUTRAR15,omitempty"`
	MeasIdleCarrierListEUTRAR15Indef_ bool                `asn1:"-" json:"-"`
	MeasIdleDurationR15               int64               `asn1:"tag:1,context,implicit"`
}

// VarMeasIdleConfigR16 represents the ASN.1 type VarMeasIdleConfigR16 (SEQUENCE).
type VarMeasIdleConfigR16 struct {
	MeasIdleCarrierListNRR16       NRCarrierListR16    `asn1:"tag:0,context,implicit,optional" json:"MeasIdleCarrierListNRR16,omitempty"`
	MeasIdleCarrierListNRR16Indef_ bool                `asn1:"-" json:"-"`
	ValidityAreaListR16            ValidityAreaListR16 `asn1:"tag:1,context,implicit,optional" json:"ValidityAreaListR16,omitempty"`
	ValidityAreaListR16Indef_      bool                `asn1:"-" json:"-"`
}

// VarMeasIdleReportR15 represents the ASN.1 type VarMeasIdleReportR15 (SEQUENCE).
type VarMeasIdleReportR15 struct {
	MeasReportIdleR15       MeasResultListIdleR15 `asn1:"tag:0,context,implicit"`
	MeasReportIdleR15Indef_ bool                  `asn1:"-" json:"-"`
}

// VarMeasIdleReportR16 represents the ASN.1 type VarMeasIdleReportR16 (SEQUENCE).
type VarMeasIdleReportR16 struct {
	MeasReportIdleR16         MeasResultListExtIdleR16 `asn1:"tag:0,context,implicit,optional" json:"MeasReportIdleR16,omitempty"`
	MeasReportIdleR16Indef_   bool                     `asn1:"-" json:"-"`
	MeasReportIdleNRR16       MeasResultListIdleNRR16  `asn1:"tag:1,context,implicit,optional" json:"MeasReportIdleNRR16,omitempty"`
	MeasReportIdleNRR16Indef_ bool                     `asn1:"-" json:"-"`
}

// VarMeasReportList represents the ASN.1 type VarMeasReportList (SEQUENCE_OF).
type VarMeasReportList = []VarMeasReport

// VarMeasReportListR12 represents the ASN.1 type VarMeasReportListR12 (SEQUENCE_OF).
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

// CSIRSTriggeredListR12 represents the ASN.1 type CSIRSTriggeredListR12 (SEQUENCE_OF).
type CSIRSTriggeredListR12 = []MeasCSIRSIdR12

// SSBIndexListR15 represents the ASN.1 type SSBIndexListR15 (SEQUENCE_OF).
type SSBIndexListR15 = []RSIndexNRR15

// VarMobilityHistoryReportR12 represents the ASN.1 type VarMobilityHistoryReportR12 (SEQUENCE_OF).
type VarMobilityHistoryReportR12 = VisitedCellInfoListR12

// VarPendingRnaUpdateR15 represents the ASN.1 type VarPendingRnaUpdateR15 (SEQUENCE).
type VarPendingRnaUpdateR15 struct {
	PendingRnaUpdate     *bool `asn1:"tag:0,context,implicit,optional" json:"PendingRnaUpdate,omitempty"`
	PendingRnaUpdateRaw_ byte  `asn1:"-" json:"-"`
}

// VarRLFReportR10 represents the ASN.1 type VarRLFReportR10 (SEQUENCE).
type VarRLFReportR10 struct {
	RlfReportR10    RLFReportR9  `asn1:"tag:0,context,implicit"`
	PlmnIdentityR10 PLMNIdentity `asn1:"tag:1,context,implicit"`
}

// VarRLFReportR11 represents the ASN.1 type VarRLFReportR11 (SEQUENCE).
type VarRLFReportR11 struct {
	RlfReportR10              RLFReportR9          `asn1:"tag:0,context,implicit"`
	PlmnIdentityListR11       PLMNIdentityList3R11 `asn1:"tag:1,context,implicit"`
	PlmnIdentityListR11Indef_ bool                 `asn1:"-" json:"-"`
}

// VarShortINACTIVEMACInputR15 represents the ASN.1 type VarShortINACTIVEMACInputR15 (SEQUENCE).
type VarShortINACTIVEMACInputR15 struct {
	CellIdentityR15 CellIdentity `asn1:"tag:0,context,implicit"`
	PhysCellIdR15   PhysCellId   `asn1:"tag:1,context,implicit"`
	CRNTIR15        CRNTI        `asn1:"tag:2,context,implicit"`
}

// VarShortMACInput represents the ASN.1 type VarShortMACInput (SEQUENCE).
type VarShortMACInput struct {
	CellIdentity CellIdentity `asn1:"tag:0,context,implicit"`
	PhysCellId   PhysCellId   `asn1:"tag:1,context,implicit"`
	CRNTI        CRNTI        `asn1:"tag:2,context,implicit"`
}

// VarShortResumeMACInputR13 represents the ASN.1 type VarShortResumeMACInputR13 (SEQUENCE).
type VarShortResumeMACInputR13 struct {
	CellIdentityR13        CellIdentity      `asn1:"tag:0,context,implicit"`
	PhysCellIdR13          PhysCellId        `asn1:"tag:1,context,implicit"`
	CRNTIR13               CRNTI             `asn1:"tag:2,context,implicit"`
	ResumeDiscriminatorR13 runtime.BitString `asn1:"tag:3,context,implicit"`
}

// VarWLANMobilityConfig represents the ASN.1 type VarWLANMobilityConfig (SEQUENCE).
type VarWLANMobilityConfig struct {
	WlanMobilitySetR13       WLANIdListR13         `asn1:"tag:0,context,implicit,optional" json:"WlanMobilitySetR13,omitempty"`
	WlanMobilitySetR13Indef_ bool                  `asn1:"-" json:"-"`
	SuccessReportRequested   *int64                `asn1:"tag:1,context,implicit,optional" json:"SuccessReportRequested,omitempty"`
	WlanSuspendConfigR14     *WLANSuspendConfigR14 `asn1:"tag:2,context,implicit,optional" json:"WlanSuspendConfigR14,omitempty"`
}

// VarWLANStatusR13 represents the ASN.1 type VarWLANStatusR13 (SEQUENCE).
type VarWLANStatusR13 struct {
	StatusR13 WLANStatusR13    `asn1:"tag:0,context,implicit"`
	StatusR14 *WLANStatusV1430 `asn1:"tag:1,context,implicit,optional" json:"StatusR14,omitempty"`
}

// VarMeasConfigSpeedStatePars choice constants.
const (
	VarMeasConfigSpeedStateParsChoiceRelease = 1
	VarMeasConfigSpeedStateParsChoiceSetup   = 2
)

// VarMeasConfigSpeedStatePars represents the ASN.1 CHOICE type VarMeasConfigSpeedStatePars.
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

// VarMeasConfigSpeedStateParsSetup represents the ASN.1 type VarMeasConfigSpeedStateParsSetup (SEQUENCE).
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

// CellsTriggeredListElem represents the ASN.1 CHOICE type CellsTriggeredListElem.
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

// CellsTriggeredListElemPhysCellIdUTRA represents the ASN.1 CHOICE type CellsTriggeredListElemPhysCellIdUTRA.
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

// CellsTriggeredListElemPhysCellIdGERAN represents the ASN.1 type CellsTriggeredListElemPhysCellIdGERAN (SEQUENCE).
type CellsTriggeredListElemPhysCellIdGERAN struct {
	CarrierFreq CarrierFreqGERAN `asn1:"tag:0,context,implicit"`
	PhysCellId  PhysCellIdGERAN  `asn1:"tag:1,context,implicit"`
}

// CellsTriggeredListElemPhysCellIdNRR15 represents the ASN.1 type CellsTriggeredListElemPhysCellIdNRR15 (SEQUENCE).
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
	return bb.Bytes(), nil
}

func (v *VarConditionalReconfiguration) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.CondReconfigurationListR16 != nil); err != nil {
		return err
	}
	if v.CondReconfigurationListR16 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.CondReconfigurationListR16)), 1, 8); err != nil {
			return fmt.Errorf("encoding condReconfigurationList-r16 length: %w", err)
		}
		for _, elem := range v.CondReconfigurationListR16 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding condReconfigurationList-r16 element: %w", err)
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes VarConditionalReconfiguration from UPER format.
func (v *VarConditionalReconfiguration) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarConditionalReconfiguration) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	// Read preamble bitmap for optional root fields
	opt_condreconfigurationlistr16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_condreconfigurationlistr16 {
		seqLen_condreconfigurationlistr16, err := per.DecodeConstrainedWholeNumber(bb, 1, 8)
		if err != nil {
			return fmt.Errorf("decoding condReconfigurationList-r16 length: %w", err)
		}
		tmp_condreconfigurationlistr16 := make(CondReconfigurationToAddModListR16, seqLen_condreconfigurationlistr16)
		for i := int64(0); i < seqLen_condreconfigurationlistr16; i++ {
			if err := tmp_condreconfigurationlistr16[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding condReconfigurationList-r16 element: %w", err)
			}
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
	return bb.Bytes(), nil
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarConnEstFailReportR11) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	if err := v.ConnEstFailReportR11.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding connEstFailReport-r11: %w", err)
	}
	if err := v.PlmnIdentityR11.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding plmn-Identity-r11: %w", err)
	}
	return nil
}

// MarshalUPER encodes VarLogMeasConfigR10 to UPER format.
func (v *VarLogMeasConfigR10) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarLogMeasConfigR10) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	// Read preamble bitmap for optional root fields
	opt_areaconfigurationr10, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_areaconfigurationr10 {
		var dec_areaconfigurationr10 AreaConfigurationR10
		if err := dec_areaconfigurationr10.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding areaConfiguration-r10: %w", err)
		}
		v.AreaConfigurationR10 = &dec_areaconfigurationr10
	}
	val_loggingdurationr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return fmt.Errorf("decoding loggingDuration-r10: %w", err)
	}
	v.LoggingDurationR10 = LoggingDurationR10(val_loggingdurationr10)
	val_loggingintervalr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return fmt.Errorf("decoding loggingInterval-r10: %w", err)
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
	return bb.Bytes(), nil
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarLogMeasConfigR11) UnmarshalUPERFrom(bb *per.BitBuffer) error {
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
			return fmt.Errorf("decoding areaConfiguration-r10: %w", err)
		}
		v.AreaConfigurationR10 = &dec_areaconfigurationr10
	}
	if opt_areaconfigurationv1130 {
		var dec_areaconfigurationv1130 AreaConfigurationV1130
		if err := dec_areaconfigurationv1130.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding areaConfiguration-v1130: %w", err)
		}
		v.AreaConfigurationV1130 = &dec_areaconfigurationv1130
	}
	val_loggingdurationr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return fmt.Errorf("decoding loggingDuration-r10: %w", err)
	}
	v.LoggingDurationR10 = LoggingDurationR10(val_loggingdurationr10)
	val_loggingintervalr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return fmt.Errorf("decoding loggingInterval-r10: %w", err)
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
	return bb.Bytes(), nil
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
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.TargetMBSFNAreaListR12)), 0, 8); err != nil {
			return fmt.Errorf("encoding targetMBSFN-AreaList-r12 length: %w", err)
		}
		for _, elem := range v.TargetMBSFNAreaListR12 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding targetMBSFN-AreaList-r12 element: %w", err)
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes VarLogMeasConfigR12 from UPER format.
func (v *VarLogMeasConfigR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarLogMeasConfigR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
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
			return fmt.Errorf("decoding areaConfiguration-r10: %w", err)
		}
		v.AreaConfigurationR10 = &dec_areaconfigurationr10
	}
	if opt_areaconfigurationv1130 {
		var dec_areaconfigurationv1130 AreaConfigurationV1130
		if err := dec_areaconfigurationv1130.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding areaConfiguration-v1130: %w", err)
		}
		v.AreaConfigurationV1130 = &dec_areaconfigurationv1130
	}
	val_loggingdurationr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return fmt.Errorf("decoding loggingDuration-r10: %w", err)
	}
	v.LoggingDurationR10 = LoggingDurationR10(val_loggingdurationr10)
	val_loggingintervalr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return fmt.Errorf("decoding loggingInterval-r10: %w", err)
	}
	v.LoggingIntervalR10 = LoggingIntervalR10(val_loggingintervalr10)
	if opt_targetmbsfnarealistr12 {
		seqLen_targetmbsfnarealistr12, err := per.DecodeConstrainedWholeNumber(bb, 0, 8)
		if err != nil {
			return fmt.Errorf("decoding targetMBSFN-AreaList-r12 length: %w", err)
		}
		tmp_targetmbsfnarealistr12 := make(TargetMBSFNAreaListR12, seqLen_targetmbsfnarealistr12)
		for i := int64(0); i < seqLen_targetmbsfnarealistr12; i++ {
			if err := tmp_targetmbsfnarealistr12[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding targetMBSFN-AreaList-r12 element: %w", err)
			}
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
	return bb.Bytes(), nil
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
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.TargetMBSFNAreaListR12)), 0, 8); err != nil {
			return fmt.Errorf("encoding targetMBSFN-AreaList-r12 length: %w", err)
		}
		for _, elem := range v.TargetMBSFNAreaListR12 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding targetMBSFN-AreaList-r12 element: %w", err)
			}
		}
	}
	if v.BtNameListR15 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.BtNameListR15)), 1, 4); err != nil {
			return fmt.Errorf("encoding bt-NameList-r15 length: %w", err)
		}
		for _, elem := range v.BtNameListR15 {
			if err := per.EncodeOctetString(bb, []byte(elem), 1, 248, true); err != nil {
				return fmt.Errorf("encoding bt-NameList-r15 element: %w", err)
			}
		}
	}
	if v.WlanNameListR15 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.WlanNameListR15)), 1, 4); err != nil {
			return fmt.Errorf("encoding wlan-NameList-r15 length: %w", err)
		}
		for _, elem := range v.WlanNameListR15 {
			if err := per.EncodeOctetString(bb, []byte(elem), 1, 32, true); err != nil {
				return fmt.Errorf("encoding wlan-NameList-r15 element: %w", err)
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes VarLogMeasConfigR15 from UPER format.
func (v *VarLogMeasConfigR15) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarLogMeasConfigR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
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
			return fmt.Errorf("decoding areaConfiguration-r10: %w", err)
		}
		v.AreaConfigurationR10 = &dec_areaconfigurationr10
	}
	if opt_areaconfigurationv1130 {
		var dec_areaconfigurationv1130 AreaConfigurationV1130
		if err := dec_areaconfigurationv1130.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding areaConfiguration-v1130: %w", err)
		}
		v.AreaConfigurationV1130 = &dec_areaconfigurationv1130
	}
	val_loggingdurationr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return fmt.Errorf("decoding loggingDuration-r10: %w", err)
	}
	v.LoggingDurationR10 = LoggingDurationR10(val_loggingdurationr10)
	val_loggingintervalr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return fmt.Errorf("decoding loggingInterval-r10: %w", err)
	}
	v.LoggingIntervalR10 = LoggingIntervalR10(val_loggingintervalr10)
	if opt_targetmbsfnarealistr12 {
		seqLen_targetmbsfnarealistr12, err := per.DecodeConstrainedWholeNumber(bb, 0, 8)
		if err != nil {
			return fmt.Errorf("decoding targetMBSFN-AreaList-r12 length: %w", err)
		}
		tmp_targetmbsfnarealistr12 := make(TargetMBSFNAreaListR12, seqLen_targetmbsfnarealistr12)
		for i := int64(0); i < seqLen_targetmbsfnarealistr12; i++ {
			if err := tmp_targetmbsfnarealistr12[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding targetMBSFN-AreaList-r12 element: %w", err)
			}
		}
		v.TargetMBSFNAreaListR12 = tmp_targetmbsfnarealistr12
	}
	if opt_btnamelistr15 {
		seqLen_btnamelistr15, err := per.DecodeConstrainedWholeNumber(bb, 1, 4)
		if err != nil {
			return fmt.Errorf("decoding bt-NameList-r15 length: %w", err)
		}
		tmp_btnamelistr15 := make(BTNameListR15, seqLen_btnamelistr15)
		for i := int64(0); i < seqLen_btnamelistr15; i++ {
			val, err := per.DecodeOctetString(bb, 1, 248, true)
			if err != nil {
				return fmt.Errorf("decoding bt-NameList-r15 element: %w", err)
			}
			tmp_btnamelistr15[i] = val
		}
		v.BtNameListR15 = tmp_btnamelistr15
	}
	if opt_wlannamelistr15 {
		seqLen_wlannamelistr15, err := per.DecodeConstrainedWholeNumber(bb, 1, 4)
		if err != nil {
			return fmt.Errorf("decoding wlan-NameList-r15 length: %w", err)
		}
		tmp_wlannamelistr15 := make(WLANNameListR15, seqLen_wlannamelistr15)
		for i := int64(0); i < seqLen_wlannamelistr15; i++ {
			val, err := per.DecodeOctetString(bb, 1, 32, true)
			if err != nil {
				return fmt.Errorf("decoding wlan-NameList-r15 element: %w", err)
			}
			tmp_wlannamelistr15[i] = val
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
	return bb.Bytes(), nil
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
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.TargetMBSFNAreaListR12)), 0, 8); err != nil {
			return fmt.Errorf("encoding targetMBSFN-AreaList-r12 length: %w", err)
		}
		for _, elem := range v.TargetMBSFNAreaListR12 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding targetMBSFN-AreaList-r12 element: %w", err)
			}
		}
	}
	if v.BtNameListR15 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.BtNameListR15)), 1, 4); err != nil {
			return fmt.Errorf("encoding bt-NameList-r15 length: %w", err)
		}
		for _, elem := range v.BtNameListR15 {
			if err := per.EncodeOctetString(bb, []byte(elem), 1, 248, true); err != nil {
				return fmt.Errorf("encoding bt-NameList-r15 element: %w", err)
			}
		}
	}
	if v.WlanNameListR15 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.WlanNameListR15)), 1, 4); err != nil {
			return fmt.Errorf("encoding wlan-NameList-r15 length: %w", err)
		}
		for _, elem := range v.WlanNameListR15 {
			if err := per.EncodeOctetString(bb, []byte(elem), 1, 32, true); err != nil {
				return fmt.Errorf("encoding wlan-NameList-r15 element: %w", err)
			}
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarLogMeasConfigR17) UnmarshalUPERFrom(bb *per.BitBuffer) error {
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
			return fmt.Errorf("decoding areaConfiguration-r10: %w", err)
		}
		v.AreaConfigurationR10 = &dec_areaconfigurationr10
	}
	if opt_areaconfigurationv1130 {
		var dec_areaconfigurationv1130 AreaConfigurationV1130
		if err := dec_areaconfigurationv1130.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding areaConfiguration-v1130: %w", err)
		}
		v.AreaConfigurationV1130 = &dec_areaconfigurationv1130
	}
	val_loggingdurationr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return fmt.Errorf("decoding loggingDuration-r10: %w", err)
	}
	v.LoggingDurationR10 = LoggingDurationR10(val_loggingdurationr10)
	val_loggingintervalr10, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return fmt.Errorf("decoding loggingInterval-r10: %w", err)
	}
	v.LoggingIntervalR10 = LoggingIntervalR10(val_loggingintervalr10)
	if opt_targetmbsfnarealistr12 {
		seqLen_targetmbsfnarealistr12, err := per.DecodeConstrainedWholeNumber(bb, 0, 8)
		if err != nil {
			return fmt.Errorf("decoding targetMBSFN-AreaList-r12 length: %w", err)
		}
		tmp_targetmbsfnarealistr12 := make(TargetMBSFNAreaListR12, seqLen_targetmbsfnarealistr12)
		for i := int64(0); i < seqLen_targetmbsfnarealistr12; i++ {
			if err := tmp_targetmbsfnarealistr12[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding targetMBSFN-AreaList-r12 element: %w", err)
			}
		}
		v.TargetMBSFNAreaListR12 = tmp_targetmbsfnarealistr12
	}
	if opt_btnamelistr15 {
		seqLen_btnamelistr15, err := per.DecodeConstrainedWholeNumber(bb, 1, 4)
		if err != nil {
			return fmt.Errorf("decoding bt-NameList-r15 length: %w", err)
		}
		tmp_btnamelistr15 := make(BTNameListR15, seqLen_btnamelistr15)
		for i := int64(0); i < seqLen_btnamelistr15; i++ {
			val, err := per.DecodeOctetString(bb, 1, 248, true)
			if err != nil {
				return fmt.Errorf("decoding bt-NameList-r15 element: %w", err)
			}
			tmp_btnamelistr15[i] = val
		}
		v.BtNameListR15 = tmp_btnamelistr15
	}
	if opt_wlannamelistr15 {
		seqLen_wlannamelistr15, err := per.DecodeConstrainedWholeNumber(bb, 1, 4)
		if err != nil {
			return fmt.Errorf("decoding wlan-NameList-r15 length: %w", err)
		}
		tmp_wlannamelistr15 := make(WLANNameListR15, seqLen_wlannamelistr15)
		for i := int64(0); i < seqLen_wlannamelistr15; i++ {
			val, err := per.DecodeOctetString(bb, 1, 32, true)
			if err != nil {
				return fmt.Errorf("decoding wlan-NameList-r15 element: %w", err)
			}
			tmp_wlannamelistr15[i] = val
		}
		v.WlanNameListR15 = tmp_wlannamelistr15
	}
	if opt_loggedeventtriggerconfigr17 {
		var dec_loggedeventtriggerconfigr17 LoggedEventTriggerConfigR17
		if err := dec_loggedeventtriggerconfigr17.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding loggedEventTriggerConfig-r17: %w", err)
		}
		v.LoggedEventTriggerConfigR17 = &dec_loggedeventtriggerconfigr17
	}
	if opt_measuncombarprer17 {
		val_measuncombarprer17, err := per.DecodeEnumerated(bb, 1, false)
		if err != nil {
			return fmt.Errorf("decoding measUncomBarPre-r17: %w", err)
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
	return bb.Bytes(), nil
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
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.LogMeasInfoListR10)), 1, 4060); err != nil {
		return fmt.Errorf("encoding logMeasInfoList-r10 length: %w", err)
	}
	for _, elem := range v.LogMeasInfoListR10 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding logMeasInfoList-r10 element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarLogMeasReportR10 from UPER format.
func (v *VarLogMeasReportR10) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarLogMeasReportR10) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	if err := v.TraceReferenceR10.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding traceReference-r10: %w", err)
	}
	val_tracerecordingsessionrefr10, err := per.DecodeOctetStringExt(bb, 2, 2, true, false)
	if err != nil {
		return fmt.Errorf("decoding traceRecordingSessionRef-r10: %w", err)
	}
	v.TraceRecordingSessionRefR10 = val_tracerecordingsessionrefr10
	val_tceidr10, err := per.DecodeOctetStringExt(bb, 1, 1, true, false)
	if err != nil {
		return fmt.Errorf("decoding tce-Id-r10: %w", err)
	}
	v.TceIdR10 = val_tceidr10
	if err := v.PlmnIdentityR10.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding plmn-Identity-r10: %w", err)
	}
	bsBytes_absolutetimeinfor10, bsBitLen_absolutetimeinfor10, err := per.DecodeBitStringExt(bb, 48, 48, true, false)
	if err != nil {
		return fmt.Errorf("decoding absoluteTimeInfo-r10: %w", err)
	}
	v.AbsoluteTimeInfoR10 = runtime.BitString{Bytes: bsBytes_absolutetimeinfor10, BitLength: bsBitLen_absolutetimeinfor10}
	seqLen_logmeasinfolistr10, err := per.DecodeConstrainedWholeNumber(bb, 1, 4060)
	if err != nil {
		return fmt.Errorf("decoding logMeasInfoList-r10 length: %w", err)
	}
	v.LogMeasInfoListR10 = make(LogMeasInfoList2R10, seqLen_logmeasinfolistr10)
	for i := int64(0); i < seqLen_logmeasinfolistr10; i++ {
		if err := v.LogMeasInfoListR10[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding logMeasInfoList-r10 element: %w", err)
		}
	}
	return nil
}

// MarshalUPER encodes VarLogMeasReportR11 to UPER format.
func (v *VarLogMeasReportR11) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
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
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.PlmnIdentityListR11)), 1, 16); err != nil {
		return fmt.Errorf("encoding plmn-IdentityList-r11 length: %w", err)
	}
	for _, elem := range v.PlmnIdentityListR11 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding plmn-IdentityList-r11 element: %w", err)
		}
	}
	if err := per.EncodeBitStringExt(bb, v.AbsoluteTimeInfoR10.Bytes, v.AbsoluteTimeInfoR10.BitLength, 48, 48, true, false); err != nil {
		return fmt.Errorf("encoding absoluteTimeInfo-r10: %w", err)
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.LogMeasInfoListR10)), 1, 4060); err != nil {
		return fmt.Errorf("encoding logMeasInfoList-r10 length: %w", err)
	}
	for _, elem := range v.LogMeasInfoListR10 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding logMeasInfoList-r10 element: %w", err)
		}
	}
	if err := per.EncodeEnumerated(bb, int64(v.SigLoggedMeasTypeR18), 1, false); err != nil {
		return fmt.Errorf("encoding sigLoggedMeasType-r18: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarLogMeasReportR11 from UPER format.
func (v *VarLogMeasReportR11) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarLogMeasReportR11) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	if err := v.TraceReferenceR10.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding traceReference-r10: %w", err)
	}
	val_tracerecordingsessionrefr10, err := per.DecodeOctetStringExt(bb, 2, 2, true, false)
	if err != nil {
		return fmt.Errorf("decoding traceRecordingSessionRef-r10: %w", err)
	}
	v.TraceRecordingSessionRefR10 = val_tracerecordingsessionrefr10
	val_tceidr10, err := per.DecodeOctetStringExt(bb, 1, 1, true, false)
	if err != nil {
		return fmt.Errorf("decoding tce-Id-r10: %w", err)
	}
	v.TceIdR10 = val_tceidr10
	seqLen_plmnidentitylistr11, err := per.DecodeConstrainedWholeNumber(bb, 1, 16)
	if err != nil {
		return fmt.Errorf("decoding plmn-IdentityList-r11 length: %w", err)
	}
	v.PlmnIdentityListR11 = make(PLMNIdentityList3R11, seqLen_plmnidentitylistr11)
	for i := int64(0); i < seqLen_plmnidentitylistr11; i++ {
		if err := v.PlmnIdentityListR11[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding plmn-IdentityList-r11 element: %w", err)
		}
	}
	bsBytes_absolutetimeinfor10, bsBitLen_absolutetimeinfor10, err := per.DecodeBitStringExt(bb, 48, 48, true, false)
	if err != nil {
		return fmt.Errorf("decoding absoluteTimeInfo-r10: %w", err)
	}
	v.AbsoluteTimeInfoR10 = runtime.BitString{Bytes: bsBytes_absolutetimeinfor10, BitLength: bsBitLen_absolutetimeinfor10}
	seqLen_logmeasinfolistr10, err := per.DecodeConstrainedWholeNumber(bb, 1, 4060)
	if err != nil {
		return fmt.Errorf("decoding logMeasInfoList-r10 length: %w", err)
	}
	v.LogMeasInfoListR10 = make(LogMeasInfoList2R10, seqLen_logmeasinfolistr10)
	for i := int64(0); i < seqLen_logmeasinfolistr10; i++ {
		if err := v.LogMeasInfoListR10[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding logMeasInfoList-r10 element: %w", err)
		}
	}
	val_sigloggedmeastyper18, err := per.DecodeEnumerated(bb, 1, false)
	if err != nil {
		return fmt.Errorf("decoding sigLoggedMeasType-r18: %w", err)
	}
	v.SigLoggedMeasTypeR18 = val_sigloggedmeastyper18
	return nil
}

type asn1cUPERLogMeasInfoList2R10ListValue struct{ Value LogMeasInfoList2R10 }

// MarshalUPERLogMeasInfoList2R10 encodes a LogMeasInfoList2R10 list to UPER.
func MarshalUPERLogMeasInfoList2R10(list LogMeasInfoList2R10) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := marshalUPERLogMeasInfoList2R10To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func marshalUPERLogMeasInfoList2R10To(list LogMeasInfoList2R10, bb *per.BitBuffer) error {
	v := asn1cUPERLogMeasInfoList2R10ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 4060); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERLogMeasInfoList2R10 decodes a LogMeasInfoList2R10 list from UPER.
func UnmarshalUPERLogMeasInfoList2R10(data []byte) (LogMeasInfoList2R10, error) {
	bb := per.NewBitBufferFromBytes(data)
	return unmarshalUPERLogMeasInfoList2R10From(bb)
}

func unmarshalUPERLogMeasInfoList2R10From(bb *per.BitBuffer) (LogMeasInfoList2R10, error) {
	var v asn1cUPERLogMeasInfoList2R10ListValue
	if err := unmarshalUPERLogMeasInfoList2R10Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERLogMeasInfoList2R10Into(v *asn1cUPERLogMeasInfoList2R10ListValue, bb *per.BitBuffer) error {
	seqLen_value, err := per.DecodeConstrainedWholeNumber(bb, 1, 4060)
	if err != nil {
		return fmt.Errorf("decoding value length: %w", err)
	}
	v.Value = make(LogMeasInfoList2R10, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		if err := v.Value[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
	}
	return nil
}

// MarshalUPER encodes VarMeasConfig to UPER format.
func (v *VarMeasConfig) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
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
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasIdList)), 1, 32); err != nil {
			return fmt.Errorf("encoding measIdList length: %w", err)
		}
		for _, elem := range v.MeasIdList {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measIdList element: %w", err)
			}
		}
	}
	if v.MeasIdListExtR12 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasIdListExtR12)), 1, 32); err != nil {
			return fmt.Errorf("encoding measIdListExt-r12 length: %w", err)
		}
		for _, elem := range v.MeasIdListExtR12 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measIdListExt-r12 element: %w", err)
			}
		}
	}
	if v.MeasIdListV1310 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasIdListV1310)), 1, 32); err != nil {
			return fmt.Errorf("encoding measIdList-v1310 length: %w", err)
		}
		for _, elem := range v.MeasIdListV1310 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measIdList-v1310 element: %w", err)
			}
		}
	}
	if v.MeasIdListExtV1310 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasIdListExtV1310)), 1, 32); err != nil {
			return fmt.Errorf("encoding measIdListExt-v1310 length: %w", err)
		}
		for _, elem := range v.MeasIdListExtV1310 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measIdListExt-v1310 element: %w", err)
			}
		}
	}
	if v.MeasObjectList != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasObjectList)), 1, 32); err != nil {
			return fmt.Errorf("encoding measObjectList length: %w", err)
		}
		for _, elem := range v.MeasObjectList {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measObjectList element: %w", err)
			}
		}
	}
	if v.MeasObjectListExtR13 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasObjectListExtR13)), 1, 32); err != nil {
			return fmt.Errorf("encoding measObjectListExt-r13 length: %w", err)
		}
		for _, elem := range v.MeasObjectListExtR13 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measObjectListExt-r13 element: %w", err)
			}
		}
	}
	if v.MeasObjectListV9i0 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasObjectListV9i0)), 1, 32); err != nil {
			return fmt.Errorf("encoding measObjectList-v9i0 length: %w", err)
		}
		for _, elem := range v.MeasObjectListV9i0 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measObjectList-v9i0 element: %w", err)
			}
		}
	}
	if v.ReportConfigList != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.ReportConfigList)), 1, 32); err != nil {
			return fmt.Errorf("encoding reportConfigList length: %w", err)
		}
		for _, elem := range v.ReportConfigList {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding reportConfigList element: %w", err)
			}
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarMeasConfig) UnmarshalUPERFrom(bb *per.BitBuffer) error {
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
		seqLen_measidlist, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
		if err != nil {
			return fmt.Errorf("decoding measIdList length: %w", err)
		}
		tmp_measidlist := make(MeasIdToAddModList, seqLen_measidlist)
		for i := int64(0); i < seqLen_measidlist; i++ {
			if err := tmp_measidlist[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding measIdList element: %w", err)
			}
		}
		v.MeasIdList = tmp_measidlist
	}
	if opt_measidlistextr12 {
		seqLen_measidlistextr12, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
		if err != nil {
			return fmt.Errorf("decoding measIdListExt-r12 length: %w", err)
		}
		tmp_measidlistextr12 := make(MeasIdToAddModListExtR12, seqLen_measidlistextr12)
		for i := int64(0); i < seqLen_measidlistextr12; i++ {
			if err := tmp_measidlistextr12[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding measIdListExt-r12 element: %w", err)
			}
		}
		v.MeasIdListExtR12 = tmp_measidlistextr12
	}
	if opt_measidlistv1310 {
		seqLen_measidlistv1310, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
		if err != nil {
			return fmt.Errorf("decoding measIdList-v1310 length: %w", err)
		}
		tmp_measidlistv1310 := make(MeasIdToAddModListV1310, seqLen_measidlistv1310)
		for i := int64(0); i < seqLen_measidlistv1310; i++ {
			if err := tmp_measidlistv1310[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding measIdList-v1310 element: %w", err)
			}
		}
		v.MeasIdListV1310 = tmp_measidlistv1310
	}
	if opt_measidlistextv1310 {
		seqLen_measidlistextv1310, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
		if err != nil {
			return fmt.Errorf("decoding measIdListExt-v1310 length: %w", err)
		}
		tmp_measidlistextv1310 := make(MeasIdToAddModListExtV1310, seqLen_measidlistextv1310)
		for i := int64(0); i < seqLen_measidlistextv1310; i++ {
			if err := tmp_measidlistextv1310[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding measIdListExt-v1310 element: %w", err)
			}
		}
		v.MeasIdListExtV1310 = tmp_measidlistextv1310
	}
	if opt_measobjectlist {
		seqLen_measobjectlist, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
		if err != nil {
			return fmt.Errorf("decoding measObjectList length: %w", err)
		}
		tmp_measobjectlist := make(MeasObjectToAddModList, seqLen_measobjectlist)
		for i := int64(0); i < seqLen_measobjectlist; i++ {
			if err := tmp_measobjectlist[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding measObjectList element: %w", err)
			}
		}
		v.MeasObjectList = tmp_measobjectlist
	}
	if opt_measobjectlistextr13 {
		seqLen_measobjectlistextr13, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
		if err != nil {
			return fmt.Errorf("decoding measObjectListExt-r13 length: %w", err)
		}
		tmp_measobjectlistextr13 := make(MeasObjectToAddModListExtR13, seqLen_measobjectlistextr13)
		for i := int64(0); i < seqLen_measobjectlistextr13; i++ {
			if err := tmp_measobjectlistextr13[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding measObjectListExt-r13 element: %w", err)
			}
		}
		v.MeasObjectListExtR13 = tmp_measobjectlistextr13
	}
	if opt_measobjectlistv9i0 {
		seqLen_measobjectlistv9i0, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
		if err != nil {
			return fmt.Errorf("decoding measObjectList-v9i0 length: %w", err)
		}
		tmp_measobjectlistv9i0 := make(MeasObjectToAddModListV9e0, seqLen_measobjectlistv9i0)
		for i := int64(0); i < seqLen_measobjectlistv9i0; i++ {
			if err := tmp_measobjectlistv9i0[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding measObjectList-v9i0 element: %w", err)
			}
		}
		v.MeasObjectListV9i0 = tmp_measobjectlistv9i0
	}
	if opt_reportconfiglist {
		seqLen_reportconfiglist, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
		if err != nil {
			return fmt.Errorf("decoding reportConfigList length: %w", err)
		}
		tmp_reportconfiglist := make(ReportConfigToAddModList, seqLen_reportconfiglist)
		for i := int64(0); i < seqLen_reportconfiglist; i++ {
			if err := tmp_reportconfiglist[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding reportConfigList element: %w", err)
			}
		}
		v.ReportConfigList = tmp_reportconfiglist
	}
	if opt_quantityconfig {
		var dec_quantityconfig QuantityConfig
		if err := dec_quantityconfig.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding quantityConfig: %w", err)
		}
		v.QuantityConfig = &dec_quantityconfig
	}
	if opt_measscalefactorr12 {
		val_measscalefactorr12, err := per.DecodeEnumerated(bb, 2, false)
		if err != nil {
			return fmt.Errorf("decoding measScaleFactor-r12: %w", err)
		}
		tmp_measscalefactorr12 := MeasScaleFactorR12(val_measscalefactorr12)
		v.MeasScaleFactorR12 = &tmp_measscalefactorr12
	}
	if opt_smeasure {
		val_smeasure, err := per.DecodeInteger(bb, int64Ptr(-140), int64Ptr(-44), false)
		if err != nil {
			return fmt.Errorf("decoding s-Measure: %w", err)
		}
		v.SMeasure = &val_smeasure
	}
	if opt_speedstatepars {
		var dec_speedstatepars VarMeasConfigSpeedStatePars
		if err := dec_speedstatepars.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding speedStatePars: %w", err)
		}
		v.SpeedStatePars = &dec_speedstatepars
	}
	if opt_allowinterruptionsr11 {
		val_allowinterruptionsr11, err := per.DecodeBoolean(bb)
		if err != nil {
			return fmt.Errorf("decoding allowInterruptions-r11: %w", err)
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
	return bb.Bytes(), nil
}

func (v *VarMeasIdleConfigR15) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.MeasIdleCarrierListEUTRAR15 != nil); err != nil {
		return err
	}
	if v.MeasIdleCarrierListEUTRAR15 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasIdleCarrierListEUTRAR15)), 1, 8); err != nil {
			return fmt.Errorf("encoding measIdleCarrierListEUTRA-r15 length: %w", err)
		}
		for _, elem := range v.MeasIdleCarrierListEUTRAR15 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measIdleCarrierListEUTRA-r15 element: %w", err)
			}
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarMeasIdleConfigR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	// Read preamble bitmap for optional root fields
	opt_measidlecarrierlisteutrar15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_measidlecarrierlisteutrar15 {
		seqLen_measidlecarrierlisteutrar15, err := per.DecodeConstrainedWholeNumber(bb, 1, 8)
		if err != nil {
			return fmt.Errorf("decoding measIdleCarrierListEUTRA-r15 length: %w", err)
		}
		tmp_measidlecarrierlisteutrar15 := make(EUTRACarrierListR15, seqLen_measidlecarrierlisteutrar15)
		for i := int64(0); i < seqLen_measidlecarrierlisteutrar15; i++ {
			if err := tmp_measidlecarrierlisteutrar15[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding measIdleCarrierListEUTRA-r15 element: %w", err)
			}
		}
		v.MeasIdleCarrierListEUTRAR15 = tmp_measidlecarrierlisteutrar15
	}
	val_measidledurationr15, err := per.DecodeEnumerated(bb, 7, false)
	if err != nil {
		return fmt.Errorf("decoding measIdleDuration-r15: %w", err)
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
	return bb.Bytes(), nil
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
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasIdleCarrierListNRR16)), 1, 8); err != nil {
			return fmt.Errorf("encoding measIdleCarrierListNR-r16 length: %w", err)
		}
		for _, elem := range v.MeasIdleCarrierListNRR16 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measIdleCarrierListNR-r16 element: %w", err)
			}
		}
	}
	if v.ValidityAreaListR16 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.ValidityAreaListR16)), 1, 8); err != nil {
			return fmt.Errorf("encoding validityAreaList-r16 length: %w", err)
		}
		for _, elem := range v.ValidityAreaListR16 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding validityAreaList-r16 element: %w", err)
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes VarMeasIdleConfigR16 from UPER format.
func (v *VarMeasIdleConfigR16) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarMeasIdleConfigR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
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
		seqLen_measidlecarrierlistnrr16, err := per.DecodeConstrainedWholeNumber(bb, 1, 8)
		if err != nil {
			return fmt.Errorf("decoding measIdleCarrierListNR-r16 length: %w", err)
		}
		tmp_measidlecarrierlistnrr16 := make(NRCarrierListR16, seqLen_measidlecarrierlistnrr16)
		for i := int64(0); i < seqLen_measidlecarrierlistnrr16; i++ {
			if err := tmp_measidlecarrierlistnrr16[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding measIdleCarrierListNR-r16 element: %w", err)
			}
		}
		v.MeasIdleCarrierListNRR16 = tmp_measidlecarrierlistnrr16
	}
	if opt_validityarealistr16 {
		seqLen_validityarealistr16, err := per.DecodeConstrainedWholeNumber(bb, 1, 8)
		if err != nil {
			return fmt.Errorf("decoding validityAreaList-r16 length: %w", err)
		}
		tmp_validityarealistr16 := make(ValidityAreaListR16, seqLen_validityarealistr16)
		for i := int64(0); i < seqLen_validityarealistr16; i++ {
			if err := tmp_validityarealistr16[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding validityAreaList-r16 element: %w", err)
			}
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
	return bb.Bytes(), nil
}

func (v *VarMeasIdleReportR15) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasReportIdleR15)), 1, 3); err != nil {
		return fmt.Errorf("encoding measReportIdle-r15 length: %w", err)
	}
	for _, elem := range v.MeasReportIdleR15 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding measReportIdle-r15 element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarMeasIdleReportR15 from UPER format.
func (v *VarMeasIdleReportR15) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarMeasIdleReportR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	seqLen_measreportidler15, err := per.DecodeConstrainedWholeNumber(bb, 1, 3)
	if err != nil {
		return fmt.Errorf("decoding measReportIdle-r15 length: %w", err)
	}
	v.MeasReportIdleR15 = make(MeasResultListIdleR15, seqLen_measreportidler15)
	for i := int64(0); i < seqLen_measreportidler15; i++ {
		if err := v.MeasReportIdleR15[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding measReportIdle-r15 element: %w", err)
		}
	}
	return nil
}

// MarshalUPER encodes VarMeasIdleReportR16 to UPER format.
func (v *VarMeasIdleReportR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
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
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasReportIdleR16)), 1, 5); err != nil {
			return fmt.Errorf("encoding measReportIdle-r16 length: %w", err)
		}
		for _, outerElem := range v.MeasReportIdleR16 {
			if err := marshalUPERMeasResultIdleListEUTRAR15To(outerElem, bb); err != nil {
				return fmt.Errorf("encoding measReportIdle-r16 element: %w", err)
			}
		}
	}
	if v.MeasReportIdleNRR16 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasReportIdleNRR16)), 1, 8); err != nil {
			return fmt.Errorf("encoding measReportIdleNR-r16 length: %w", err)
		}
		for _, elem := range v.MeasReportIdleNRR16 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measReportIdleNR-r16 element: %w", err)
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes VarMeasIdleReportR16 from UPER format.
func (v *VarMeasIdleReportR16) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarMeasIdleReportR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
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
		seqLen_measreportidler16, err := per.DecodeConstrainedWholeNumber(bb, 1, 5)
		if err != nil {
			return fmt.Errorf("decoding measReportIdle-r16 length: %w", err)
		}
		tmp_measreportidler16 := make(MeasResultListExtIdleR16, seqLen_measreportidler16)
		for i_measreportidler16 := int64(0); i_measreportidler16 < seqLen_measreportidler16; i_measreportidler16++ {
			elem, err := unmarshalUPERMeasResultIdleListEUTRAR15From(bb)
			if err != nil {
				return fmt.Errorf("decoding measReportIdle-r16 element: %w", err)
			}
			tmp_measreportidler16[i_measreportidler16] = elem
		}
		v.MeasReportIdleR16 = tmp_measreportidler16
	}
	if opt_measreportidlenrr16 {
		seqLen_measreportidlenrr16, err := per.DecodeConstrainedWholeNumber(bb, 1, 8)
		if err != nil {
			return fmt.Errorf("decoding measReportIdleNR-r16 length: %w", err)
		}
		tmp_measreportidlenrr16 := make(MeasResultListIdleNRR16, seqLen_measreportidlenrr16)
		for i := int64(0); i < seqLen_measreportidlenrr16; i++ {
			if err := tmp_measreportidlenrr16[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding measReportIdleNR-r16 element: %w", err)
			}
		}
		v.MeasReportIdleNRR16 = tmp_measreportidlenrr16
	}
	return nil
}

type asn1cUPERVarMeasReportListListValue struct{ Value VarMeasReportList }

// MarshalUPERVarMeasReportList encodes a VarMeasReportList list to UPER.
func MarshalUPERVarMeasReportList(list VarMeasReportList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := marshalUPERVarMeasReportListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func marshalUPERVarMeasReportListTo(list VarMeasReportList, bb *per.BitBuffer) error {
	v := asn1cUPERVarMeasReportListListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 32); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERVarMeasReportList decodes a VarMeasReportList list from UPER.
func UnmarshalUPERVarMeasReportList(data []byte) (VarMeasReportList, error) {
	bb := per.NewBitBufferFromBytes(data)
	return unmarshalUPERVarMeasReportListFrom(bb)
}

func unmarshalUPERVarMeasReportListFrom(bb *per.BitBuffer) (VarMeasReportList, error) {
	var v asn1cUPERVarMeasReportListListValue
	if err := unmarshalUPERVarMeasReportListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERVarMeasReportListInto(v *asn1cUPERVarMeasReportListListValue, bb *per.BitBuffer) error {
	seqLen_value, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
	if err != nil {
		return fmt.Errorf("decoding value length: %w", err)
	}
	v.Value = make(VarMeasReportList, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		if err := v.Value[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
	}
	return nil
}

type asn1cUPERVarMeasReportListR12ListValue struct{ Value VarMeasReportListR12 }

// MarshalUPERVarMeasReportListR12 encodes a VarMeasReportListR12 list to UPER.
func MarshalUPERVarMeasReportListR12(list VarMeasReportListR12) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := marshalUPERVarMeasReportListR12To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func marshalUPERVarMeasReportListR12To(list VarMeasReportListR12, bb *per.BitBuffer) error {
	v := asn1cUPERVarMeasReportListR12ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 64); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERVarMeasReportListR12 decodes a VarMeasReportListR12 list from UPER.
func UnmarshalUPERVarMeasReportListR12(data []byte) (VarMeasReportListR12, error) {
	bb := per.NewBitBufferFromBytes(data)
	return unmarshalUPERVarMeasReportListR12From(bb)
}

func unmarshalUPERVarMeasReportListR12From(bb *per.BitBuffer) (VarMeasReportListR12, error) {
	var v asn1cUPERVarMeasReportListR12ListValue
	if err := unmarshalUPERVarMeasReportListR12Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERVarMeasReportListR12Into(v *asn1cUPERVarMeasReportListR12ListValue, bb *per.BitBuffer) error {
	seqLen_value, err := per.DecodeConstrainedWholeNumber(bb, 1, 64)
	if err != nil {
		return fmt.Errorf("decoding value length: %w", err)
	}
	v.Value = make(VarMeasReportListR12, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		if err := v.Value[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
	}
	return nil
}

// MarshalUPER encodes VarMeasReport to UPER format.
func (v *VarMeasReport) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
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
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.CellsTriggeredList)), 1, 32); err != nil {
			return fmt.Errorf("encoding cellsTriggeredList length: %w", err)
		}
		for _, elem := range v.CellsTriggeredList {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding cellsTriggeredList element: %w", err)
			}
		}
	}
	if v.CsiRSTriggeredListR12 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.CsiRSTriggeredListR12)), 1, 96); err != nil {
			return fmt.Errorf("encoding csi-RS-TriggeredList-r12 length: %w", err)
		}
		for _, elem := range v.CsiRSTriggeredListR12 {
			if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(96), false); err != nil {
				return fmt.Errorf("encoding csi-RS-TriggeredList-r12 element: %w", err)
			}
		}
	}
	if v.PoolsTriggeredListR14 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.PoolsTriggeredListR14)), 1, 72); err != nil {
			return fmt.Errorf("encoding poolsTriggeredList-r14 length: %w", err)
		}
		for _, elem := range v.PoolsTriggeredListR14 {
			if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(72), false); err != nil {
				return fmt.Errorf("encoding poolsTriggeredList-r14 element: %w", err)
			}
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarMeasReport) UnmarshalUPERFrom(bb *per.BitBuffer) error {
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
		return fmt.Errorf("decoding measId: %w", err)
	}
	v.MeasId = MeasId(val_measid)
	if opt_measidv1250 {
		val_measidv1250, err := per.DecodeInteger(bb, int64Ptr(33), int64Ptr(64), false)
		if err != nil {
			return fmt.Errorf("decoding measId-v1250: %w", err)
		}
		tmp_measidv1250 := MeasIdV1250(val_measidv1250)
		v.MeasIdV1250 = &tmp_measidv1250
	}
	if opt_cellstriggeredlist {
		seqLen_cellstriggeredlist, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
		if err != nil {
			return fmt.Errorf("decoding cellsTriggeredList length: %w", err)
		}
		tmp_cellstriggeredlist := make(CellsTriggeredList, seqLen_cellstriggeredlist)
		for i := int64(0); i < seqLen_cellstriggeredlist; i++ {
			if err := tmp_cellstriggeredlist[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding cellsTriggeredList element: %w", err)
			}
		}
		v.CellsTriggeredList = tmp_cellstriggeredlist
	}
	if opt_csirstriggeredlistr12 {
		seqLen_csirstriggeredlistr12, err := per.DecodeConstrainedWholeNumber(bb, 1, 96)
		if err != nil {
			return fmt.Errorf("decoding csi-RS-TriggeredList-r12 length: %w", err)
		}
		tmp_csirstriggeredlistr12 := make(CSIRSTriggeredListR12, seqLen_csirstriggeredlistr12)
		for i := int64(0); i < seqLen_csirstriggeredlistr12; i++ {
			val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(96), false)
			if err != nil {
				return fmt.Errorf("decoding csi-RS-TriggeredList-r12 element: %w", err)
			}
			tmp_csirstriggeredlistr12[i] = MeasCSIRSIdR12(val)
		}
		v.CsiRSTriggeredListR12 = tmp_csirstriggeredlistr12
	}
	if opt_poolstriggeredlistr14 {
		seqLen_poolstriggeredlistr14, err := per.DecodeConstrainedWholeNumber(bb, 1, 72)
		if err != nil {
			return fmt.Errorf("decoding poolsTriggeredList-r14 length: %w", err)
		}
		tmp_poolstriggeredlistr14 := make(TxResourcePoolMeasListR14, seqLen_poolstriggeredlistr14)
		for i := int64(0); i < seqLen_poolstriggeredlistr14; i++ {
			val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(72), false)
			if err != nil {
				return fmt.Errorf("decoding poolsTriggeredList-r14 element: %w", err)
			}
			tmp_poolstriggeredlistr14[i] = SLV2XTxPoolReportIdentityR14(val)
		}
		v.PoolsTriggeredListR14 = tmp_poolstriggeredlistr14
	}
	val_numberofreportssent, err := per.DecodeIntegerBig(bb, nil, nil, false)
	if err != nil {
		return fmt.Errorf("decoding numberOfReportsSent: %w", err)
	}
	v.NumberOfReportsSent = val_numberofreportssent
	return nil
}

type asn1cUPERCellsTriggeredListListValue struct{ Value CellsTriggeredList }

// MarshalUPERCellsTriggeredList encodes a CellsTriggeredList list to UPER.
func MarshalUPERCellsTriggeredList(list CellsTriggeredList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := marshalUPERCellsTriggeredListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func marshalUPERCellsTriggeredListTo(list CellsTriggeredList, bb *per.BitBuffer) error {
	v := asn1cUPERCellsTriggeredListListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 32); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERCellsTriggeredList decodes a CellsTriggeredList list from UPER.
func UnmarshalUPERCellsTriggeredList(data []byte) (CellsTriggeredList, error) {
	bb := per.NewBitBufferFromBytes(data)
	return unmarshalUPERCellsTriggeredListFrom(bb)
}

func unmarshalUPERCellsTriggeredListFrom(bb *per.BitBuffer) (CellsTriggeredList, error) {
	var v asn1cUPERCellsTriggeredListListValue
	if err := unmarshalUPERCellsTriggeredListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERCellsTriggeredListInto(v *asn1cUPERCellsTriggeredListListValue, bb *per.BitBuffer) error {
	seqLen_value, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
	if err != nil {
		return fmt.Errorf("decoding value length: %w", err)
	}
	v.Value = make(CellsTriggeredList, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		if err := v.Value[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
	}
	return nil
}

type asn1cUPERCSIRSTriggeredListR12ListValue struct{ Value CSIRSTriggeredListR12 }

// MarshalUPERCSIRSTriggeredListR12 encodes a CSIRSTriggeredListR12 list to UPER.
func MarshalUPERCSIRSTriggeredListR12(list CSIRSTriggeredListR12) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := marshalUPERCSIRSTriggeredListR12To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func marshalUPERCSIRSTriggeredListR12To(list CSIRSTriggeredListR12, bb *per.BitBuffer) error {
	v := asn1cUPERCSIRSTriggeredListR12ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 96); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := per.EncodeInteger(bb, int64(elem), int64Ptr(1), int64Ptr(96), false); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERCSIRSTriggeredListR12 decodes a CSIRSTriggeredListR12 list from UPER.
func UnmarshalUPERCSIRSTriggeredListR12(data []byte) (CSIRSTriggeredListR12, error) {
	bb := per.NewBitBufferFromBytes(data)
	return unmarshalUPERCSIRSTriggeredListR12From(bb)
}

func unmarshalUPERCSIRSTriggeredListR12From(bb *per.BitBuffer) (CSIRSTriggeredListR12, error) {
	var v asn1cUPERCSIRSTriggeredListR12ListValue
	if err := unmarshalUPERCSIRSTriggeredListR12Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERCSIRSTriggeredListR12Into(v *asn1cUPERCSIRSTriggeredListR12ListValue, bb *per.BitBuffer) error {
	seqLen_value, err := per.DecodeConstrainedWholeNumber(bb, 1, 96)
	if err != nil {
		return fmt.Errorf("decoding value length: %w", err)
	}
	v.Value = make(CSIRSTriggeredListR12, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		val, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(96), false)
		if err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
		v.Value[i] = MeasCSIRSIdR12(val)
	}
	return nil
}

type asn1cUPERSSBIndexListR15ListValue struct{ Value SSBIndexListR15 }

// MarshalUPERSSBIndexListR15 encodes a SSBIndexListR15 list to UPER.
func MarshalUPERSSBIndexListR15(list SSBIndexListR15) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := marshalUPERSSBIndexListR15To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func marshalUPERSSBIndexListR15To(list SSBIndexListR15, bb *per.BitBuffer) error {
	v := asn1cUPERSSBIndexListR15ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 64); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := per.EncodeInteger(bb, int64(elem), int64Ptr(0), int64Ptr(63), false); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSSBIndexListR15 decodes a SSBIndexListR15 list from UPER.
func UnmarshalUPERSSBIndexListR15(data []byte) (SSBIndexListR15, error) {
	bb := per.NewBitBufferFromBytes(data)
	return unmarshalUPERSSBIndexListR15From(bb)
}

func unmarshalUPERSSBIndexListR15From(bb *per.BitBuffer) (SSBIndexListR15, error) {
	var v asn1cUPERSSBIndexListR15ListValue
	if err := unmarshalUPERSSBIndexListR15Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSSBIndexListR15Into(v *asn1cUPERSSBIndexListR15ListValue, bb *per.BitBuffer) error {
	seqLen_value, err := per.DecodeConstrainedWholeNumber(bb, 1, 64)
	if err != nil {
		return fmt.Errorf("decoding value length: %w", err)
	}
	v.Value = make(SSBIndexListR15, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		val, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(63), false)
		if err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
		v.Value[i] = RSIndexNRR15(val)
	}
	return nil
}

// MarshalUPER encodes VarPendingRnaUpdateR15 to UPER format.
func (v *VarPendingRnaUpdateR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarPendingRnaUpdateR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	// Read preamble bitmap for optional root fields
	opt_pendingrnaupdate, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_pendingrnaupdate {
		val_pendingrnaupdate, err := per.DecodeBoolean(bb)
		if err != nil {
			return fmt.Errorf("decoding pendingRnaUpdate: %w", err)
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
	return bb.Bytes(), nil
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarRLFReportR10) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	if err := v.RlfReportR10.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding rlf-Report-r10: %w", err)
	}
	if err := v.PlmnIdentityR10.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding plmn-Identity-r10: %w", err)
	}
	return nil
}

// MarshalUPER encodes VarRLFReportR11 to UPER format.
func (v *VarRLFReportR11) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *VarRLFReportR11) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.RlfReportR10.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding rlf-Report-r10: %w", err)
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.PlmnIdentityListR11)), 1, 16); err != nil {
		return fmt.Errorf("encoding plmn-IdentityList-r11 length: %w", err)
	}
	for _, elem := range v.PlmnIdentityListR11 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding plmn-IdentityList-r11 element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarRLFReportR11 from UPER format.
func (v *VarRLFReportR11) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarRLFReportR11) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	if err := v.RlfReportR10.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding rlf-Report-r10: %w", err)
	}
	seqLen_plmnidentitylistr11, err := per.DecodeConstrainedWholeNumber(bb, 1, 16)
	if err != nil {
		return fmt.Errorf("decoding plmn-IdentityList-r11 length: %w", err)
	}
	v.PlmnIdentityListR11 = make(PLMNIdentityList3R11, seqLen_plmnidentitylistr11)
	for i := int64(0); i < seqLen_plmnidentitylistr11; i++ {
		if err := v.PlmnIdentityListR11[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding plmn-IdentityList-r11 element: %w", err)
		}
	}
	return nil
}

// MarshalUPER encodes VarShortINACTIVEMACInputR15 to UPER format.
func (v *VarShortINACTIVEMACInputR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarShortINACTIVEMACInputR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	bsBytes_cellidentityr15, bsBitLen_cellidentityr15, err := per.DecodeBitStringExt(bb, 28, 28, true, false)
	if err != nil {
		return fmt.Errorf("decoding cellIdentity-r15: %w", err)
	}
	v.CellIdentityR15 = runtime.BitString{Bytes: bsBytes_cellidentityr15, BitLength: bsBitLen_cellidentityr15}
	val_physcellidr15, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return fmt.Errorf("decoding physCellId-r15: %w", err)
	}
	v.PhysCellIdR15 = PhysCellId(val_physcellidr15)
	bsBytes_crntir15, bsBitLen_crntir15, err := per.DecodeBitStringExt(bb, 16, 16, true, false)
	if err != nil {
		return fmt.Errorf("decoding c-RNTI-r15: %w", err)
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
	return bb.Bytes(), nil
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarShortMACInput) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	bsBytes_cellidentity, bsBitLen_cellidentity, err := per.DecodeBitStringExt(bb, 28, 28, true, false)
	if err != nil {
		return fmt.Errorf("decoding cellIdentity: %w", err)
	}
	v.CellIdentity = runtime.BitString{Bytes: bsBytes_cellidentity, BitLength: bsBitLen_cellidentity}
	val_physcellid, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return fmt.Errorf("decoding physCellId: %w", err)
	}
	v.PhysCellId = PhysCellId(val_physcellid)
	bsBytes_crnti, bsBitLen_crnti, err := per.DecodeBitStringExt(bb, 16, 16, true, false)
	if err != nil {
		return fmt.Errorf("decoding c-RNTI: %w", err)
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
	return bb.Bytes(), nil
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarShortResumeMACInputR13) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	bsBytes_cellidentityr13, bsBitLen_cellidentityr13, err := per.DecodeBitStringExt(bb, 28, 28, true, false)
	if err != nil {
		return fmt.Errorf("decoding cellIdentity-r13: %w", err)
	}
	v.CellIdentityR13 = runtime.BitString{Bytes: bsBytes_cellidentityr13, BitLength: bsBitLen_cellidentityr13}
	val_physcellidr13, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
	if err != nil {
		return fmt.Errorf("decoding physCellId-r13: %w", err)
	}
	v.PhysCellIdR13 = PhysCellId(val_physcellidr13)
	bsBytes_crntir13, bsBitLen_crntir13, err := per.DecodeBitStringExt(bb, 16, 16, true, false)
	if err != nil {
		return fmt.Errorf("decoding c-RNTI-r13: %w", err)
	}
	v.CRNTIR13 = runtime.BitString{Bytes: bsBytes_crntir13, BitLength: bsBitLen_crntir13}
	bsBytes_resumediscriminatorr13, bsBitLen_resumediscriminatorr13, err := per.DecodeBitStringExt(bb, 1, 1, true, false)
	if err != nil {
		return fmt.Errorf("decoding resumeDiscriminator-r13: %w", err)
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
	return bb.Bytes(), nil
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
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.WlanMobilitySetR13)), 1, 32); err != nil {
			return fmt.Errorf("encoding wlan-MobilitySet-r13 length: %w", err)
		}
		for _, elem := range v.WlanMobilitySetR13 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding wlan-MobilitySet-r13 element: %w", err)
			}
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarWLANMobilityConfig) UnmarshalUPERFrom(bb *per.BitBuffer) error {
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
		seqLen_wlanmobilitysetr13, err := per.DecodeConstrainedWholeNumber(bb, 1, 32)
		if err != nil {
			return fmt.Errorf("decoding wlan-MobilitySet-r13 length: %w", err)
		}
		tmp_wlanmobilitysetr13 := make(WLANIdListR13, seqLen_wlanmobilitysetr13)
		for i := int64(0); i < seqLen_wlanmobilitysetr13; i++ {
			if err := tmp_wlanmobilitysetr13[i].UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding wlan-MobilitySet-r13 element: %w", err)
			}
		}
		v.WlanMobilitySetR13 = tmp_wlanmobilitysetr13
	}
	if opt_successreportrequested {
		val_successreportrequested, err := per.DecodeEnumerated(bb, 1, false)
		if err != nil {
			return fmt.Errorf("decoding successReportRequested: %w", err)
		}
		v.SuccessReportRequested = &val_successreportrequested
	}
	if opt_wlansuspendconfigr14 {
		var dec_wlansuspendconfigr14 WLANSuspendConfigR14
		if err := dec_wlansuspendconfigr14.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding wlan-SuspendConfig-r14: %w", err)
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
	return bb.Bytes(), nil
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarWLANStatusR13) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	// Read preamble bitmap for optional root fields
	opt_statusr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_statusr13, err := per.DecodeEnumerated(bb, 4, false)
	if err != nil {
		return fmt.Errorf("decoding status-r13: %w", err)
	}
	v.StatusR13 = WLANStatusR13(val_statusr13)
	if opt_statusr14 {
		val_statusr14, err := per.DecodeEnumerated(bb, 2, false)
		if err != nil {
			return fmt.Errorf("decoding status-r14: %w", err)
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
	return bb.Bytes(), nil
}

func (v *VarMeasConfigSpeedStatePars) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case VarMeasConfigSpeedStateParsChoiceRelease:
	case VarMeasConfigSpeedStateParsChoiceSetup:
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarMeasConfigSpeedStatePars) UnmarshalUPERFrom(bb *per.BitBuffer) error {
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
			return fmt.Errorf("decoding setup: %w", err)
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
	return bb.Bytes(), nil
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarMeasConfigSpeedStateParsSetup) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	if err := v.MobilityStateParameters.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding mobilityStateParameters: %w", err)
	}
	if err := v.TimeToTriggerSF.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding timeToTrigger-SF: %w", err)
	}
	return nil
}

// MarshalUPER encodes CellsTriggeredListElem to UPER format.
func (v *CellsTriggeredListElem) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *CellsTriggeredListElem) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 5); err != nil {
		return err
	}
	switch v.Choice {
	case CellsTriggeredListElemChoicePhysCellIdEUTRA:
		if err := per.EncodeInteger(bb, int64(*v.PhysCellIdEUTRA), int64Ptr(0), int64Ptr(503), false); err != nil {
			return fmt.Errorf("encoding physCellIdEUTRA: %w", err)
		}
	case CellsTriggeredListElemChoicePhysCellIdUTRA:
		if err := v.PhysCellIdUTRA.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding physCellIdUTRA: %w", err)
		}
	case CellsTriggeredListElemChoicePhysCellIdGERAN:
		if err := v.PhysCellIdGERAN.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding physCellIdGERAN: %w", err)
		}
	case CellsTriggeredListElemChoicePhysCellIdCDMA2000:
		if err := per.EncodeInteger(bb, int64(*v.PhysCellIdCDMA2000), int64Ptr(0), int64Ptr(511), false); err != nil {
			return fmt.Errorf("encoding physCellIdCDMA2000: %w", err)
		}
	case CellsTriggeredListElemChoiceWlanIdentifiersR13:
		if err := v.WlanIdentifiersR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding wlan-Identifiers-r13: %w", err)
		}
	case CellsTriggeredListElemChoicePhysCellIdNRR15:
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *CellsTriggeredListElem) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 5)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case CellsTriggeredListElemChoicePhysCellIdEUTRA:
		val_physcellideutra, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(503), false)
		if err != nil {
			return fmt.Errorf("decoding physCellIdEUTRA: %w", err)
		}
		tmp_physcellideutra := PhysCellId(val_physcellideutra)
		v.PhysCellIdEUTRA = &tmp_physcellideutra
	case CellsTriggeredListElemChoicePhysCellIdUTRA:
		var dec_physcellidutra CellsTriggeredListElemPhysCellIdUTRA
		if err := dec_physcellidutra.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding physCellIdUTRA: %w", err)
		}
		v.PhysCellIdUTRA = &dec_physcellidutra
	case CellsTriggeredListElemChoicePhysCellIdGERAN:
		var dec_physcellidgeran CellsTriggeredListElemPhysCellIdGERAN
		if err := dec_physcellidgeran.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding physCellIdGERAN: %w", err)
		}
		v.PhysCellIdGERAN = &dec_physcellidgeran
	case CellsTriggeredListElemChoicePhysCellIdCDMA2000:
		val_physcellidcdma2000, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(511), false)
		if err != nil {
			return fmt.Errorf("decoding physCellIdCDMA2000: %w", err)
		}
		tmp_physcellidcdma2000 := PhysCellIdCDMA2000(val_physcellidcdma2000)
		v.PhysCellIdCDMA2000 = &tmp_physcellidcdma2000
	case CellsTriggeredListElemChoiceWlanIdentifiersR13:
		var dec_wlanidentifiersr13 WLANIdentifiersR12
		if err := dec_wlanidentifiersr13.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding wlan-Identifiers-r13: %w", err)
		}
		v.WlanIdentifiersR13 = &dec_wlanidentifiersr13
	case CellsTriggeredListElemChoicePhysCellIdNRR15:
		var dec_physcellidnrr15 CellsTriggeredListElemPhysCellIdNRR15
		if err := dec_physcellidnrr15.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding physCellIdNR-r15: %w", err)
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
	return bb.Bytes(), nil
}

func (v *CellsTriggeredListElemPhysCellIdUTRA) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case CellsTriggeredListElemPhysCellIdUTRAChoiceFdd:
		if err := per.EncodeInteger(bb, int64(*v.Fdd), int64Ptr(0), int64Ptr(511), false); err != nil {
			return fmt.Errorf("encoding fdd: %w", err)
		}
	case CellsTriggeredListElemPhysCellIdUTRAChoiceTdd:
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *CellsTriggeredListElemPhysCellIdUTRA) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	idx, err := per.DecodeConstrainedWholeNumber(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case CellsTriggeredListElemPhysCellIdUTRAChoiceFdd:
		val_fdd, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(511), false)
		if err != nil {
			return fmt.Errorf("decoding fdd: %w", err)
		}
		tmp_fdd := PhysCellIdUTRAFDD(val_fdd)
		v.Fdd = &tmp_fdd
	case CellsTriggeredListElemPhysCellIdUTRAChoiceTdd:
		val_tdd, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(127), false)
		if err != nil {
			return fmt.Errorf("decoding tdd: %w", err)
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
	return bb.Bytes(), nil
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
	return v.UnmarshalUPERFrom(bb)
}

func (v *CellsTriggeredListElemPhysCellIdGERAN) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	if err := v.CarrierFreq.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding carrierFreq: %w", err)
	}
	if err := v.PhysCellId.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding physCellId: %w", err)
	}
	return nil
}

// MarshalUPER encodes CellsTriggeredListElemPhysCellIdNRR15 to UPER format.
func (v *CellsTriggeredListElemPhysCellIdNRR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
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
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.RsIndexListR15)), 1, 64); err != nil {
			return fmt.Errorf("encoding rs-IndexList-r15 length: %w", err)
		}
		for _, elem := range v.RsIndexListR15 {
			if err := per.EncodeInteger(bb, int64(elem), int64Ptr(0), int64Ptr(63), false); err != nil {
				return fmt.Errorf("encoding rs-IndexList-r15 element: %w", err)
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes CellsTriggeredListElemPhysCellIdNRR15 from UPER format.
func (v *CellsTriggeredListElemPhysCellIdNRR15) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *CellsTriggeredListElemPhysCellIdNRR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	// Read preamble bitmap for optional root fields
	opt_rsindexlistr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_carrierfreq, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(3279165), false)
	if err != nil {
		return fmt.Errorf("decoding carrierFreq: %w", err)
	}
	v.CarrierFreq = ARFCNValueNRR15(val_carrierfreq)
	val_physcellid, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(1007), false)
	if err != nil {
		return fmt.Errorf("decoding physCellId: %w", err)
	}
	v.PhysCellId = PhysCellIdNRR15(val_physcellid)
	if opt_rsindexlistr15 {
		seqLen_rsindexlistr15, err := per.DecodeConstrainedWholeNumber(bb, 1, 64)
		if err != nil {
			return fmt.Errorf("decoding rs-IndexList-r15 length: %w", err)
		}
		tmp_rsindexlistr15 := make(SSBIndexListR15, seqLen_rsindexlistr15)
		for i := int64(0); i < seqLen_rsindexlistr15; i++ {
			val, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(63), false)
			if err != nil {
				return fmt.Errorf("decoding rs-IndexList-r15 element: %w", err)
			}
			tmp_rsindexlistr15[i] = RSIndexNRR15(val)
		}
		v.RsIndexListR15 = tmp_rsindexlistr15
	}
	return nil
}
