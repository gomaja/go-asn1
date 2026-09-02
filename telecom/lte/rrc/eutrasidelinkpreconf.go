// Code generated from ASN.1 module "EUTRA-Sidelink-Preconf". DO NOT EDIT.

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

// SLPreconfigurationR12 represents the ASN.1 type SL-Preconfiguration-r12 (SEQUENCE).
type SLPreconfigurationR12 struct {
	PreconfigGeneralR12    SLPreconfigGeneralR12                    `asn1:"tag:0,context,implicit"`
	PreconfigSyncR12       SLPreconfigSyncR12                       `asn1:"tag:1,context,implicit"`
	PreconfigCommR12       SLPreconfigCommPoolList4R12              `asn1:"tag:2,context,implicit"`
	PreconfigCommR12Indef_ bool                                     `asn1:"-" json:"-"`
	PreconfigCommV1310     *SLPreconfigurationR12PreconfigCommV1310 `asn1:"tag:3,context,implicit,optional" json:"PreconfigCommV1310,omitempty"`
	PreconfigDiscR13       *SLPreconfigurationR12PreconfigDiscR13   `asn1:"tag:4,context,implicit,optional" json:"PreconfigDiscR13,omitempty"`
	PreconfigRelayR13      *SLPreconfigRelayR13                     `asn1:"tag:5,context,implicit,optional" json:"PreconfigRelayR13,omitempty"`
	ExtCount_              int64                                    `asn1:"-" json:"-"`
	ExtPresent_            []bool                                   `asn1:"-" json:"-"`
	ExtData_               [][]byte                                 `asn1:"-" json:"-"`
}

// SLPreconfigGeneralR12 represents the ASN.1 type SL-PreconfigGeneral-r12 (SEQUENCE).
type SLPreconfigGeneralR12 struct {
	RohcProfilesR12                 SLPreconfigGeneralR12RohcProfilesR12 `asn1:"tag:0,context,implicit"`
	CarrierFreqR12                  ARFCNValueEUTRAR9                    `asn1:"tag:1,context,implicit"`
	MaxTxPowerR12                   PMax                                 `asn1:"tag:2,context,implicit"`
	AdditionalSpectrumEmissionR12   AdditionalSpectrumEmission           `asn1:"tag:3,context,implicit"`
	SlBandwidthR12                  int64                                `asn1:"tag:4,context,implicit"`
	TddConfigSLR12                  TDDConfigSLR12                       `asn1:"tag:5,context,implicit"`
	ReservedR12                     runtime.BitString                    `asn1:"tag:6,context,implicit"`
	AdditionalSpectrumEmissionV1440 *AdditionalSpectrumEmissionV10l0     `asn1:"tag:7,context,implicit,optional" json:"AdditionalSpectrumEmissionV1440,omitempty"`
	ExtCount_                       int64                                `asn1:"-" json:"-"`
	ExtPresent_                     []bool                               `asn1:"-" json:"-"`
	ExtData_                        [][]byte                             `asn1:"-" json:"-"`
}

// SLPreconfigSyncR12 represents the ASN.1 type SL-PreconfigSync-r12 (SEQUENCE).
type SLPreconfigSyncR12 struct {
	SyncCPLenR12            SLCPLenR12               `asn1:"tag:0,context,implicit"`
	SyncOffsetIndicator1R12 SLOffsetIndicatorSyncR12 `asn1:"tag:1,context,implicit"`
	SyncOffsetIndicator2R12 SLOffsetIndicatorSyncR12 `asn1:"tag:2,context,implicit"`
	SyncTxParametersR12     P0SLR12                  `asn1:"tag:3,context,implicit"`
	SyncTxThreshOoCR12      RSRPRangeSL3R12          `asn1:"tag:4,context,implicit"`
	FilterCoefficientR12    FilterCoefficient        `asn1:"tag:5,context,implicit"`
	SyncRefMinHystR12       int64                    `asn1:"tag:6,context,implicit"`
	SyncRefDiffHystR12      int64                    `asn1:"tag:7,context,implicit"`
	SyncTxPeriodicR13       *int64                   `asn1:"tag:8,context,implicit,optional" json:"SyncTxPeriodicR13,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
}

// SLPreconfigCommPoolList4R12 represents the ASN.1 type SL-PreconfigCommPoolList4-r12 (SEQUENCE_OF).
type SLPreconfigCommPoolList4R12 = []SLPreconfigCommPoolR12

// SLPreconfigCommRxPoolListR13 represents the ASN.1 type SL-PreconfigCommRxPoolList-r13 (SEQUENCE_OF).
type SLPreconfigCommRxPoolListR13 = []SLPreconfigCommPoolR12

// SLPreconfigCommTxPoolListR13 represents the ASN.1 type SL-PreconfigCommTxPoolList-r13 (SEQUENCE_OF).
type SLPreconfigCommTxPoolListR13 = []SLPreconfigCommPoolR12

// SLPreconfigCommPoolR12 represents the ASN.1 type SL-PreconfigCommPool-r12 (SEQUENCE).
type SLPreconfigCommPoolR12 struct {
	ScCPLenR12              SLCPLenR12             `asn1:"tag:0,context,implicit"`
	ScPeriodR12             SLPeriodCommR12        `asn1:"tag:1,context,implicit"`
	ScTFResourceConfigR12   SLTFResourceConfigR12  `asn1:"tag:2,context,implicit"`
	ScTxParametersR12       P0SLR12                `asn1:"tag:3,context,implicit"`
	DataCPLenR12            SLCPLenR12             `asn1:"tag:4,context,implicit"`
	DataTFResourceConfigR12 SLTFResourceConfigR12  `asn1:"tag:5,context,implicit"`
	DataHoppingConfigR12    SLHoppingConfigCommR12 `asn1:"tag:6,context,implicit"`
	DataTxParametersR12     P0SLR12                `asn1:"tag:7,context,implicit"`
	TrptSubsetR12           SLTRPTSubsetR12        `asn1:"tag:8,context,implicit"`
	PriorityListR13         SLPriorityListR13      `asn1:"tag:9,context,implicit,optional" json:"PriorityListR13,omitempty"`
	PriorityListR13Indef_   bool                   `asn1:"-" json:"-"`
	ExtCount_               int64                  `asn1:"-" json:"-"`
	ExtPresent_             []bool                 `asn1:"-" json:"-"`
	ExtData_                [][]byte               `asn1:"-" json:"-"`
}

// SLPreconfigDiscRxPoolListR13 represents the ASN.1 type SL-PreconfigDiscRxPoolList-r13 (SEQUENCE_OF).
type SLPreconfigDiscRxPoolListR13 = []SLPreconfigDiscPoolR13

// SLPreconfigDiscTxPoolListR13 represents the ASN.1 type SL-PreconfigDiscTxPoolList-r13 (SEQUENCE_OF).
type SLPreconfigDiscTxPoolListR13 = []SLPreconfigDiscPoolR13

// SLPreconfigDiscPoolR13 represents the ASN.1 type SL-PreconfigDiscPool-r13 (SEQUENCE).
type SLPreconfigDiscPoolR13 struct {
	CpLenR13            SLCPLenR12                             `asn1:"tag:0,context,implicit"`
	DiscPeriodR13       int64                                  `asn1:"tag:1,context,implicit"`
	NumRetxR13          int64                                  `asn1:"tag:2,context,implicit"`
	NumRepetitionR13    int64                                  `asn1:"tag:3,context,implicit"`
	TfResourceConfigR13 SLTFResourceConfigR12                  `asn1:"tag:4,context,implicit"`
	TxParametersR13     *SLPreconfigDiscPoolR13TxParametersR13 `asn1:"tag:5,context,implicit,optional" json:"TxParametersR13,omitempty"`
	ExtCount_           int64                                  `asn1:"-" json:"-"`
	ExtPresent_         []bool                                 `asn1:"-" json:"-"`
	ExtData_            [][]byte                               `asn1:"-" json:"-"`
}

// SLPreconfigRelayR13 represents the ASN.1 type SL-PreconfigRelay-r13 (SEQUENCE).
type SLPreconfigRelayR13 struct {
	ReselectionInfoOoCR13 ReselectionInfoRelayR13 `asn1:"tag:0,context,implicit"`
}

// SLV2XPreconfigurationR14 represents the ASN.1 type SL-V2X-Preconfiguration-r14 (SEQUENCE).
type SLV2XPreconfigurationR14 struct {
	V2xPreconfigFreqListR14          SLV2XPreconfigFreqListR14        `asn1:"tag:0,context,implicit"`
	V2xPreconfigFreqListR14Indef_    bool                             `asn1:"-" json:"-"`
	AnchorCarrierFreqListR14         SLAnchorCarrierFreqListV2XR14    `asn1:"tag:1,context,implicit,optional" json:"AnchorCarrierFreqListR14,omitempty"`
	AnchorCarrierFreqListR14Indef_   bool                             `asn1:"-" json:"-"`
	CbrPreconfigListR14              *SLCBRPreconfigTxConfigListR14   `asn1:"tag:2,context,implicit,optional" json:"CbrPreconfigListR14,omitempty"`
	V2xPacketDuplicationConfigR15    *SLV2XPacketDuplicationConfigR15 `asn1:"tag:3,context,implicit,optional" json:"V2xPacketDuplicationConfigR15,omitempty"`
	SyncFreqListR15                  SLV2XSyncFreqListR15             `asn1:"tag:4,context,implicit,optional" json:"SyncFreqListR15,omitempty"`
	SyncFreqListR15Indef_            bool                             `asn1:"-" json:"-"`
	SlssTxMultiFreqR15               *int64                           `asn1:"tag:5,context,implicit,optional" json:"SlssTxMultiFreqR15,omitempty"`
	V2xTxProfileListR15              SLV2XTxProfileListR15            `asn1:"tag:6,context,implicit,optional" json:"V2xTxProfileListR15,omitempty"`
	V2xTxProfileListR15Indef_        bool                             `asn1:"-" json:"-"`
	AnchorCarrierFreqListNRR16       SLNRAnchorCarrierFreqListR16     `asn1:"tag:7,context,implicit,optional" json:"AnchorCarrierFreqListNRR16,omitempty"`
	AnchorCarrierFreqListNRR16Indef_ bool                             `asn1:"-" json:"-"`
	ExtCount_                        int64                            `asn1:"-" json:"-"`
	ExtPresent_                      []bool                           `asn1:"-" json:"-"`
	ExtData_                         [][]byte                         `asn1:"-" json:"-"`
}

// SLCBRPreconfigTxConfigListR14 represents the ASN.1 type SL-CBR-PreconfigTxConfigList-r14 (SEQUENCE).
type SLCBRPreconfigTxConfigListR14 struct {
	CbrRangeCommonConfigListR14       SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14 `asn1:"tag:0,context,implicit"`
	CbrRangeCommonConfigListR14Indef_ bool                                                     `asn1:"-" json:"-"`
	SlCBRPSSCHTxConfigListR14         SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14   `asn1:"tag:1,context,implicit"`
	SlCBRPSSCHTxConfigListR14Indef_   bool                                                     `asn1:"-" json:"-"`
}

// SLV2XPreconfigFreqListR14 represents the ASN.1 type SL-V2X-PreconfigFreqList-r14 (SEQUENCE_OF).
type SLV2XPreconfigFreqListR14 = []SLV2XPreconfigFreqInfoR14

// SLV2XPreconfigFreqInfoR14 represents the ASN.1 type SL-V2X-PreconfigFreqInfo-r14 (SEQUENCE).
type SLV2XPreconfigFreqInfoR14 struct {
	V2xCommPreconfigGeneralR14          SLPreconfigGeneralR12           `asn1:"tag:0,context,implicit"`
	V2xCommPreconfigSyncR14             *SLPreconfigV2XSyncR14          `asn1:"tag:1,context,implicit,optional" json:"V2xCommPreconfigSyncR14,omitempty"`
	V2xCommRxPoolListR14                SLPreconfigV2XRxPoolListR14     `asn1:"tag:2,context,implicit"`
	V2xCommRxPoolListR14Indef_          bool                            `asn1:"-" json:"-"`
	V2xCommTxPoolListR14                SLPreconfigV2XTxPoolListR14     `asn1:"tag:3,context,implicit"`
	V2xCommTxPoolListR14Indef_          bool                            `asn1:"-" json:"-"`
	P2xCommTxPoolListR14                SLPreconfigV2XTxPoolListR14     `asn1:"tag:4,context,implicit"`
	P2xCommTxPoolListR14Indef_          bool                            `asn1:"-" json:"-"`
	V2xResourceSelectionConfigR14       *SLCommTxPoolSensingConfigR14   `asn1:"tag:5,context,implicit,optional" json:"V2xResourceSelectionConfigR14,omitempty"`
	ZoneConfigR14                       *SLZoneConfigR14                `asn1:"tag:6,context,implicit,optional" json:"ZoneConfigR14,omitempty"`
	SyncPriorityR14                     int64                           `asn1:"tag:7,context,implicit"`
	ThresSLTxPrioritizationR14          *SLPriorityR13                  `asn1:"tag:8,context,implicit,optional" json:"ThresSLTxPrioritizationR14,omitempty"`
	OffsetDFNR14                        *int64                          `asn1:"tag:9,context,implicit,optional" json:"OffsetDFNR14,omitempty"`
	V2xFreqSelectionConfigListR15       SLV2XFreqSelectionConfigListR15 `asn1:"tag:10,context,implicit,optional" json:"V2xFreqSelectionConfigListR15,omitempty"`
	V2xFreqSelectionConfigListR15Indef_ bool                            `asn1:"-" json:"-"`
	ExtCount_                           int64                           `asn1:"-" json:"-"`
	ExtPresent_                         []bool                          `asn1:"-" json:"-"`
	ExtData_                            [][]byte                        `asn1:"-" json:"-"`
}

// SLPreconfigV2XRxPoolListR14 represents the ASN.1 type SL-PreconfigV2X-RxPoolList-r14 (SEQUENCE_OF).
type SLPreconfigV2XRxPoolListR14 = []SLV2XPreconfigCommPoolR14

// SLPreconfigV2XTxPoolListR14 represents the ASN.1 type SL-PreconfigV2X-TxPoolList-r14 (SEQUENCE_OF).
type SLPreconfigV2XTxPoolListR14 = []SLV2XPreconfigCommPoolR14

// SLV2XPreconfigCommPoolR14 represents the ASN.1 type SL-V2X-PreconfigCommPool-r14 (SEQUENCE).
type SLV2XPreconfigCommPoolR14 struct {
	SlOffsetIndicatorR14                       *SLOffsetIndicatorR12                      `asn1:"tag:0,context,explicit,optional" json:"SlOffsetIndicatorR14,omitempty"`
	SlSubframeR14                              SubframeBitmapSLR14                        `asn1:"tag:1,context,explicit"`
	AdjacencyPSCCHPSSCHR14                     bool                                       `asn1:"tag:2,context,implicit"`
	AdjacencyPSCCHPSSCHR14Raw_                 byte                                       `asn1:"-" json:"-"`
	SizeSubchannelR14                          int64                                      `asn1:"tag:3,context,implicit"`
	NumSubchannelR14                           int64                                      `asn1:"tag:4,context,implicit"`
	StartRBSubchannelR14                       int64                                      `asn1:"tag:5,context,implicit"`
	StartRBPSCCHPoolR14                        *int64                                     `asn1:"tag:6,context,implicit,optional" json:"StartRBPSCCHPoolR14,omitempty"`
	DataTxParametersR14                        P0SLR12                                    `asn1:"tag:7,context,implicit"`
	ZoneIDR14                                  *int64                                     `asn1:"tag:8,context,implicit,optional" json:"ZoneIDR14,omitempty"`
	ThreshSRSSICBRR14                          *int64                                     `asn1:"tag:9,context,implicit,optional" json:"ThreshSRSSICBRR14,omitempty"`
	CbrPsschTxConfigListR14                    SLCBRPPPPTxPreconfigListR14                `asn1:"tag:10,context,implicit,optional" json:"CbrPsschTxConfigListR14,omitempty"`
	CbrPsschTxConfigListR14Indef_              bool                                       `asn1:"-" json:"-"`
	ResourceSelectionConfigP2XR14              *SLP2XResourceSelectionConfigR14           `asn1:"tag:11,context,implicit,optional" json:"ResourceSelectionConfigP2XR14,omitempty"`
	SyncAllowedR14                             *SLSyncAllowedR14                          `asn1:"tag:12,context,implicit,optional" json:"SyncAllowedR14,omitempty"`
	RestrictResourceReservationPeriodR14       SLRestrictResourceReservationPeriodListR14 `asn1:"tag:13,context,implicit,optional" json:"RestrictResourceReservationPeriodR14,omitempty"`
	RestrictResourceReservationPeriodR14Indef_ bool                                       `asn1:"-" json:"-"`
	SlMinT2ValueListR15                        SLMinT2ValueListR15                        `asn1:"tag:14,context,implicit,optional" json:"SlMinT2ValueListR15,omitempty"`
	SlMinT2ValueListR15Indef_                  bool                                       `asn1:"-" json:"-"`
	CbrPsschTxConfigListV1530                  SLCBRPPPPTxPreconfigListV1530              `asn1:"tag:15,context,implicit,optional" json:"CbrPsschTxConfigListV1530,omitempty"`
	CbrPsschTxConfigListV1530Indef_            bool                                       `asn1:"-" json:"-"`
	ExtCount_                                  int64                                      `asn1:"-" json:"-"`
	ExtPresent_                                []bool                                     `asn1:"-" json:"-"`
	ExtData_                                   [][]byte                                   `asn1:"-" json:"-"`
}

// SLPreconfigV2XSyncR14 represents the ASN.1 type SL-PreconfigV2X-Sync-r14 (SEQUENCE).
type SLPreconfigV2XSyncR14 struct {
	SyncOffsetIndicatorsR14 SLV2XSyncOffsetIndicatorsR14 `asn1:"tag:0,context,implicit"`
	SyncTxParametersR14     P0SLR12                      `asn1:"tag:1,context,implicit"`
	SyncTxThreshOoCR14      RSRPRangeSL3R12              `asn1:"tag:2,context,implicit"`
	FilterCoefficientR14    FilterCoefficient            `asn1:"tag:3,context,implicit"`
	SyncRefMinHystR14       int64                        `asn1:"tag:4,context,implicit"`
	SyncRefDiffHystR14      int64                        `asn1:"tag:5,context,implicit"`
	SlssTxDisabledR15       *int64                       `asn1:"tag:6,context,implicit,optional" json:"SlssTxDisabledR15,omitempty"`
	ExtCount_               int64                        `asn1:"-" json:"-"`
	ExtPresent_             []bool                       `asn1:"-" json:"-"`
	ExtData_                [][]byte                     `asn1:"-" json:"-"`
}

// SLV2XSyncOffsetIndicatorsR14 represents the ASN.1 type SL-V2X-SyncOffsetIndicators-r14 (SEQUENCE).
type SLV2XSyncOffsetIndicatorsR14 struct {
	SyncOffsetIndicator1R14 SLOffsetIndicatorSyncR14  `asn1:"tag:0,context,implicit"`
	SyncOffsetIndicator2R14 SLOffsetIndicatorSyncR14  `asn1:"tag:1,context,implicit"`
	SyncOffsetIndicator3R14 *SLOffsetIndicatorSyncR14 `asn1:"tag:2,context,implicit,optional" json:"SyncOffsetIndicator3R14,omitempty"`
}

// SLCBRPPPPTxPreconfigListR14 represents the ASN.1 type SL-CBR-PPPP-TxPreconfigList-r14 (SEQUENCE_OF).
type SLCBRPPPPTxPreconfigListR14 = []SLPPPPTxPreconfigIndexR14

// SLPPPPTxPreconfigIndexR14 represents the ASN.1 type SL-PPPP-TxPreconfigIndex-r14 (SEQUENCE).
type SLPPPPTxPreconfigIndexR14 struct {
	PriorityThresholdR14       SLPriorityR13                                 `asn1:"tag:0,context,implicit"`
	DefaultTxConfigIndexR14    int64                                         `asn1:"tag:1,context,implicit"`
	CbrConfigIndexR14          int64                                         `asn1:"tag:2,context,implicit"`
	TxConfigIndexListR14       SLPPPPTxPreconfigIndexR14TxConfigIndexListR14 `asn1:"tag:3,context,implicit"`
	TxConfigIndexListR14Indef_ bool                                          `asn1:"-" json:"-"`
}

// TxPreconfigIndexR14 represents the ASN.1 type Tx-PreconfigIndex-r14 (INTEGER).
type TxPreconfigIndexR14 = int64

// SLCBRPPPPTxPreconfigListV1530 represents the ASN.1 type SL-CBR-PPPP-TxPreconfigList-v1530 (SEQUENCE_OF).
type SLCBRPPPPTxPreconfigListV1530 = []SLPPPPTxPreconfigIndexV1530

// SLPPPPTxPreconfigIndexV1530 represents the ASN.1 type SL-PPPP-TxPreconfigIndex-v1530 (SEQUENCE).
type SLPPPPTxPreconfigIndexV1530 struct {
	McsPSSCHRangeR15       SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15 `asn1:"tag:0,context,implicit,optional" json:"McsPSSCHRangeR15,omitempty"`
	McsPSSCHRangeR15Indef_ bool                                        `asn1:"-" json:"-"`
}

// SLV2XTxProfileListR15 represents the ASN.1 type SL-V2X-TxProfileList-r15 (SEQUENCE_OF).
type SLV2XTxProfileListR15 = []SLV2XTxProfileR15

// SLV2XTxProfileR15 represents the ASN.1 ENUMERATED type SL-V2X-TxProfile-r15.
type SLV2XTxProfileR15 int64

const (
	SLV2XTxProfileR15Rel14  SLV2XTxProfileR15 = 0
	SLV2XTxProfileR15Rel15  SLV2XTxProfileR15 = 1
	SLV2XTxProfileR15Spare6 SLV2XTxProfileR15 = 2
	SLV2XTxProfileR15Spare5 SLV2XTxProfileR15 = 3
	SLV2XTxProfileR15Spare4 SLV2XTxProfileR15 = 4
	SLV2XTxProfileR15Spare3 SLV2XTxProfileR15 = 5
	SLV2XTxProfileR15Spare2 SLV2XTxProfileR15 = 6
	SLV2XTxProfileR15Spare1 SLV2XTxProfileR15 = 7
)

func (v SLV2XTxProfileR15) String() string {
	switch v {
	case SLV2XTxProfileR15Rel14:
		return "rel14"
	case SLV2XTxProfileR15Rel15:
		return "rel15"
	case SLV2XTxProfileR15Spare6:
		return "spare6"
	case SLV2XTxProfileR15Spare5:
		return "spare5"
	case SLV2XTxProfileR15Spare4:
		return "spare4"
	case SLV2XTxProfileR15Spare3:
		return "spare3"
	case SLV2XTxProfileR15Spare2:
		return "spare2"
	case SLV2XTxProfileR15Spare1:
		return "spare1"
	default:
		return "unknown"
	}
}

// SLPreconfigurationR12PreconfigCommV1310 represents the ASN.1 type SL-Preconfiguration-r12-preconfigComm-v1310 (SEQUENCE).
type SLPreconfigurationR12PreconfigCommV1310 struct {
	CommRxPoolListR13       SLPreconfigCommRxPoolListR13 `asn1:"tag:0,context,implicit"`
	CommRxPoolListR13Indef_ bool                         `asn1:"-" json:"-"`
	CommTxPoolListR13       SLPreconfigCommTxPoolListR13 `asn1:"tag:1,context,implicit,optional" json:"CommTxPoolListR13,omitempty"`
	CommTxPoolListR13Indef_ bool                         `asn1:"-" json:"-"`
}

// SLPreconfigurationR12PreconfigDiscR13 represents the ASN.1 type SL-Preconfiguration-r12-preconfigDisc-r13 (SEQUENCE).
type SLPreconfigurationR12PreconfigDiscR13 struct {
	DiscRxPoolListR13       SLPreconfigDiscRxPoolListR13 `asn1:"tag:0,context,implicit"`
	DiscRxPoolListR13Indef_ bool                         `asn1:"-" json:"-"`
	DiscTxPoolListR13       SLPreconfigDiscTxPoolListR13 `asn1:"tag:1,context,implicit,optional" json:"DiscTxPoolListR13,omitempty"`
	DiscTxPoolListR13Indef_ bool                         `asn1:"-" json:"-"`
}

// SLPreconfigGeneralR12RohcProfilesR12 represents the ASN.1 type SL-PreconfigGeneral-r12-rohc-Profiles-r12 (SEQUENCE).
type SLPreconfigGeneralR12RohcProfilesR12 struct {
	Profile0x0001R12     bool `asn1:"tag:0,context,implicit"`
	Profile0x0001R12Raw_ byte `asn1:"-" json:"-"`
	Profile0x0002R12     bool `asn1:"tag:1,context,implicit"`
	Profile0x0002R12Raw_ byte `asn1:"-" json:"-"`
	Profile0x0004R12     bool `asn1:"tag:2,context,implicit"`
	Profile0x0004R12Raw_ byte `asn1:"-" json:"-"`
	Profile0x0006R12     bool `asn1:"tag:3,context,implicit"`
	Profile0x0006R12Raw_ byte `asn1:"-" json:"-"`
	Profile0x0101R12     bool `asn1:"tag:4,context,implicit"`
	Profile0x0101R12Raw_ byte `asn1:"-" json:"-"`
	Profile0x0102R12     bool `asn1:"tag:5,context,implicit"`
	Profile0x0102R12Raw_ byte `asn1:"-" json:"-"`
	Profile0x0104R12     bool `asn1:"tag:6,context,implicit"`
	Profile0x0104R12Raw_ byte `asn1:"-" json:"-"`
}

// SLPreconfigDiscPoolR13TxParametersR13 represents the ASN.1 type SL-PreconfigDiscPool-r13-txParameters-r13 (SEQUENCE).
type SLPreconfigDiscPoolR13TxParametersR13 struct {
	TxParametersGeneralR13 P0SLR12 `asn1:"tag:0,context,implicit"`
	TxProbabilityR13       int64   `asn1:"tag:1,context,implicit"`
}

// SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14 represents the ASN.1 type SL-CBR-PreconfigTxConfigList-r14-cbr-RangeCommonConfigList-r14 (SEQUENCE_OF).
type SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14 = []SLCBRLevelsConfigR14

// SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14 represents the ASN.1 type SL-CBR-PreconfigTxConfigList-r14-sl-CBR-PSSCH-TxConfigList-r14 (SEQUENCE_OF).
type SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14 = []SLCBRPSSCHTxConfigR14

// SLPPPPTxPreconfigIndexR14TxConfigIndexListR14 represents the ASN.1 type SL-PPPP-TxPreconfigIndex-r14-tx-ConfigIndexList-r14 (SEQUENCE_OF).
type SLPPPPTxPreconfigIndexR14TxConfigIndexListR14 = []TxPreconfigIndexR14

// SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15 represents the ASN.1 type SL-PPPP-TxPreconfigIndex-v1530-mcs-PSSCH-Range-r15 (SEQUENCE_OF).
type SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15 = []MCSPSSCHRangeR15

// MarshalUPER encodes SLPreconfigurationR12 to UPER format.
func (v *SLPreconfigurationR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPreconfigurationR12) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.PreconfigCommV1310 != nil || v.PreconfigDiscR13 != nil || v.PreconfigRelayR13 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := v.PreconfigGeneralR12.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding preconfigGeneral-r12: %w", err)
	}
	if err := v.PreconfigSyncR12.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding preconfigSync-r12: %w", err)
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.PreconfigCommR12)), 1, 4); err != nil {
		return fmt.Errorf("encoding preconfigComm-r12 length: %w", err)
	}
	for _, elem := range v.PreconfigCommR12 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding preconfigComm-r12 element: %w", err)
		}
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.PreconfigCommV1310 != nil || v.PreconfigDiscR13 != nil || v.PreconfigRelayR13 != nil {
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
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.PreconfigCommV1310 != nil || v.PreconfigDiscR13 != nil || v.PreconfigRelayR13 != nil
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
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.PreconfigCommV1310 != nil || v.PreconfigDiscR13 != nil || v.PreconfigRelayR13 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.PreconfigCommV1310 != nil); err != nil {
				return err
			}
			if err := per.EncodeBoolean(extBuf, v.PreconfigDiscR13 != nil); err != nil {
				return err
			}
			if err := per.EncodeBoolean(extBuf, v.PreconfigRelayR13 != nil); err != nil {
				return err
			}
			if v.PreconfigCommV1310 != nil {
				if err := v.PreconfigCommV1310.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding preconfigComm-v1310: %w", err)
				}
			}
			if v.PreconfigDiscR13 != nil {
				if err := v.PreconfigDiscR13.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding preconfigDisc-r13: %w", err)
				}
			}
			if v.PreconfigRelayR13 != nil {
				if err := v.PreconfigRelayR13.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding preconfigRelay-r13: %w", err)
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

// UnmarshalUPER decodes SLPreconfigurationR12 from UPER format.
func (v *SLPreconfigurationR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPreconfigurationR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.PreconfigGeneralR12.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding preconfigGeneral-r12: %w", err)
	}
	if err := v.PreconfigSyncR12.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding preconfigSync-r12: %w", err)
	}
	var seqLen_preconfigcommr12 int64
	var errLength_preconfigcommr12 error
	seqLen_preconfigcommr12, errLength_preconfigcommr12 = per.DecodeConstrainedWholeNumber(bb, 1, 4)
	if errLength_preconfigcommr12 != nil {
		return fmt.Errorf("decoding preconfigComm-r12 length: %w", errLength_preconfigcommr12)
	}
	if seqLen_preconfigcommr12 < 1 {
		return fmt.Errorf("decoding preconfigComm-r12 length %d below lower bound 1", seqLen_preconfigcommr12)
	}
	if seqLen_preconfigcommr12 > 4 {
		return fmt.Errorf("decoding preconfigComm-r12 length %d above upper bound 4", seqLen_preconfigcommr12)
	}
	v.PreconfigCommR12 = make(SLPreconfigCommPoolList4R12, 0)
	for i := int64(0); i < seqLen_preconfigcommr12; i++ {
		var elem SLPreconfigCommPoolR12
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding preconfigComm-r12 element %d: %w", i, err)
		}
		v.PreconfigCommR12 = append(v.PreconfigCommR12, elem)
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
			ext_opt_preconfigcommv1310, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			ext_opt_preconfigdiscr13, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			ext_opt_preconfigrelayr13, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_preconfigcommv1310 {
				var dec_preconfigcommv1310 SLPreconfigurationR12PreconfigCommV1310
				if err := dec_preconfigcommv1310.UnmarshalUPERFrom(extBB); err != nil {
					return fmt.Errorf("decoding preconfigComm-v1310: %w", err)
				}
				v.PreconfigCommV1310 = &dec_preconfigcommv1310
			}
			if ext_opt_preconfigdiscr13 {
				var dec_preconfigdiscr13 SLPreconfigurationR12PreconfigDiscR13
				if err := dec_preconfigdiscr13.UnmarshalUPERFrom(extBB); err != nil {
					return fmt.Errorf("decoding preconfigDisc-r13: %w", err)
				}
				v.PreconfigDiscR13 = &dec_preconfigdiscr13
			}
			if ext_opt_preconfigrelayr13 {
				var dec_preconfigrelayr13 SLPreconfigRelayR13
				if err := dec_preconfigrelayr13.UnmarshalUPERFrom(extBB); err != nil {
					return fmt.Errorf("decoding preconfigRelay-r13: %w", err)
				}
				v.PreconfigRelayR13 = &dec_preconfigrelayr13
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

// MarshalUPER encodes SLPreconfigGeneralR12 to UPER format.
func (v *SLPreconfigGeneralR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPreconfigGeneralR12) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.AdditionalSpectrumEmissionV1440 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := v.RohcProfilesR12.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding rohc-Profiles-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.CarrierFreqR12), int64Ptr(0), int64Ptr(262143), false); err != nil {
		return fmt.Errorf("encoding carrierFreq-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.MaxTxPowerR12), int64Ptr(-30), int64Ptr(33), false); err != nil {
		return fmt.Errorf("encoding maxTxPower-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.AdditionalSpectrumEmissionR12), int64Ptr(1), int64Ptr(32), false); err != nil {
		return fmt.Errorf("encoding additionalSpectrumEmission-r12: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.SlBandwidthR12), 6, false); err != nil {
		return fmt.Errorf("encoding sl-bandwidth-r12: %w", err)
	}
	if err := v.TddConfigSLR12.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding tdd-ConfigSL-r12: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.ReservedR12.Bytes, v.ReservedR12.BitLength, 19, 19, true, false); err != nil {
		return fmt.Errorf("encoding reserved-r12: %w", err)
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.AdditionalSpectrumEmissionV1440 != nil {
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
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.AdditionalSpectrumEmissionV1440 != nil
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
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.AdditionalSpectrumEmissionV1440 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.AdditionalSpectrumEmissionV1440 != nil); err != nil {
				return err
			}
			if v.AdditionalSpectrumEmissionV1440 != nil {
				if err := per.EncodeInteger(extBuf, int64(*v.AdditionalSpectrumEmissionV1440), int64Ptr(33), int64Ptr(288), false); err != nil {
					return fmt.Errorf("encoding additionalSpectrumEmission-v1440: %w", err)
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

// UnmarshalUPER decodes SLPreconfigGeneralR12 from UPER format.
func (v *SLPreconfigGeneralR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPreconfigGeneralR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.RohcProfilesR12.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding rohc-Profiles-r12: %w", err)
	}
	val_carrierfreqr12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(262143), false)
	if err != nil {
		return fmt.Errorf("decoding carrierFreq-r12: %w", err)
	}
	v.CarrierFreqR12 = ARFCNValueEUTRAR9(val_carrierfreqr12)
	val_maxtxpowerr12, err := per.DecodeInteger(bb, int64Ptr(-30), int64Ptr(33), false)
	if err != nil {
		return fmt.Errorf("decoding maxTxPower-r12: %w", err)
	}
	v.MaxTxPowerR12 = PMax(val_maxtxpowerr12)
	val_additionalspectrumemissionr12, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(32), false)
	if err != nil {
		return fmt.Errorf("decoding additionalSpectrumEmission-r12: %w", err)
	}
	v.AdditionalSpectrumEmissionR12 = AdditionalSpectrumEmission(val_additionalspectrumemissionr12)
	val_slbandwidthr12, err := per.DecodeEnumerated(bb, 6, false)
	if err != nil {
		return fmt.Errorf("decoding sl-bandwidth-r12: %w", err)
	}
	v.SlBandwidthR12 = val_slbandwidthr12
	if err := v.TddConfigSLR12.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding tdd-ConfigSL-r12: %w", err)
	}
	bsBytes_reservedr12, bsBitLen_reservedr12, err := per.DecodeBitStringExt(bb, 19, 19, true, false)
	if err != nil {
		return fmt.Errorf("decoding reserved-r12: %w", err)
	}
	v.ReservedR12 = runtime.BitString{Bytes: bsBytes_reservedr12, BitLength: bsBitLen_reservedr12}
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
			ext_opt_additionalspectrumemissionv1440, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_additionalspectrumemissionv1440 {
				val_additionalspectrumemissionv1440, err := per.DecodeInteger(extBB, int64Ptr(33), int64Ptr(288), false)
				if err != nil {
					return fmt.Errorf("decoding additionalSpectrumEmission-v1440: %w", err)
				}
				tmp_additionalspectrumemissionv1440 := AdditionalSpectrumEmissionV10l0(val_additionalspectrumemissionv1440)
				v.AdditionalSpectrumEmissionV1440 = &tmp_additionalspectrumemissionv1440
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

// MarshalUPER encodes SLPreconfigSyncR12 to UPER format.
func (v *SLPreconfigSyncR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPreconfigSyncR12) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.SyncTxPeriodicR13 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeEnumerated(bb, int64(v.SyncCPLenR12), 2, false); err != nil {
		return fmt.Errorf("encoding syncCP-Len-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.SyncOffsetIndicator1R12), int64Ptr(0), int64Ptr(39), false); err != nil {
		return fmt.Errorf("encoding syncOffsetIndicator1-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.SyncOffsetIndicator2R12), int64Ptr(0), int64Ptr(39), false); err != nil {
		return fmt.Errorf("encoding syncOffsetIndicator2-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.SyncTxParametersR12), int64Ptr(-126), int64Ptr(31), false); err != nil {
		return fmt.Errorf("encoding syncTxParameters-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.SyncTxThreshOoCR12), int64Ptr(0), int64Ptr(11), false); err != nil {
		return fmt.Errorf("encoding syncTxThreshOoC-r12: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.FilterCoefficientR12), 16, true); err != nil {
		return fmt.Errorf("encoding filterCoefficient-r12: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.SyncRefMinHystR12), 5, false); err != nil {
		return fmt.Errorf("encoding syncRefMinHyst-r12: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.SyncRefDiffHystR12), 6, false); err != nil {
		return fmt.Errorf("encoding syncRefDiffHyst-r12: %w", err)
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.SyncTxPeriodicR13 != nil {
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
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SyncTxPeriodicR13 != nil
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
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SyncTxPeriodicR13 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SyncTxPeriodicR13 != nil); err != nil {
				return err
			}
			if v.SyncTxPeriodicR13 != nil {
				if err := per.EncodeEnumerated(extBuf, int64(*v.SyncTxPeriodicR13), 1, false); err != nil {
					return fmt.Errorf("encoding syncTxPeriodic-r13: %w", err)
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

// UnmarshalUPER decodes SLPreconfigSyncR12 from UPER format.
func (v *SLPreconfigSyncR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPreconfigSyncR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_synccplenr12, err := per.DecodeEnumerated(bb, 2, false)
	if err != nil {
		return fmt.Errorf("decoding syncCP-Len-r12: %w", err)
	}
	v.SyncCPLenR12 = SLCPLenR12(val_synccplenr12)
	val_syncoffsetindicator1r12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(39), false)
	if err != nil {
		return fmt.Errorf("decoding syncOffsetIndicator1-r12: %w", err)
	}
	v.SyncOffsetIndicator1R12 = SLOffsetIndicatorSyncR12(val_syncoffsetindicator1r12)
	val_syncoffsetindicator2r12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(39), false)
	if err != nil {
		return fmt.Errorf("decoding syncOffsetIndicator2-r12: %w", err)
	}
	v.SyncOffsetIndicator2R12 = SLOffsetIndicatorSyncR12(val_syncoffsetindicator2r12)
	val_synctxparametersr12, err := per.DecodeInteger(bb, int64Ptr(-126), int64Ptr(31), false)
	if err != nil {
		return fmt.Errorf("decoding syncTxParameters-r12: %w", err)
	}
	v.SyncTxParametersR12 = P0SLR12(val_synctxparametersr12)
	val_synctxthreshoocr12, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(11), false)
	if err != nil {
		return fmt.Errorf("decoding syncTxThreshOoC-r12: %w", err)
	}
	v.SyncTxThreshOoCR12 = RSRPRangeSL3R12(val_synctxthreshoocr12)
	val_filtercoefficientr12, err := per.DecodeEnumerated(bb, 16, true)
	if err != nil {
		return fmt.Errorf("decoding filterCoefficient-r12: %w", err)
	}
	v.FilterCoefficientR12 = FilterCoefficient(val_filtercoefficientr12)
	val_syncrefminhystr12, err := per.DecodeEnumerated(bb, 5, false)
	if err != nil {
		return fmt.Errorf("decoding syncRefMinHyst-r12: %w", err)
	}
	v.SyncRefMinHystR12 = val_syncrefminhystr12
	val_syncrefdiffhystr12, err := per.DecodeEnumerated(bb, 6, false)
	if err != nil {
		return fmt.Errorf("decoding syncRefDiffHyst-r12: %w", err)
	}
	v.SyncRefDiffHystR12 = val_syncrefdiffhystr12
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
			ext_opt_synctxperiodicr13, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_synctxperiodicr13 {
				val_synctxperiodicr13, err := per.DecodeEnumerated(extBB, 1, false)
				if err != nil {
					return fmt.Errorf("decoding syncTxPeriodic-r13: %w", err)
				}
				v.SyncTxPeriodicR13 = &val_synctxperiodicr13
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

type asn1cUPERSLPreconfigCommPoolList4R12ListValue struct{ Value SLPreconfigCommPoolList4R12 }

// MarshalUPERSLPreconfigCommPoolList4R12 encodes a SLPreconfigCommPoolList4R12 list to UPER.
func MarshalUPERSLPreconfigCommPoolList4R12(list SLPreconfigCommPoolList4R12) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLPreconfigCommPoolList4R12To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLPreconfigCommPoolList4R12To appends a SLPreconfigCommPoolList4R12 list to bb.
func MarshalUPERSLPreconfigCommPoolList4R12To(list SLPreconfigCommPoolList4R12, bb *per.BitBuffer) error {
	v := asn1cUPERSLPreconfigCommPoolList4R12ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 4); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLPreconfigCommPoolList4R12 decodes a SLPreconfigCommPoolList4R12 list from UPER.
func UnmarshalUPERSLPreconfigCommPoolList4R12(data []byte) (SLPreconfigCommPoolList4R12, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLPreconfigCommPoolList4R12From(bb)
}

// UnmarshalUPERSLPreconfigCommPoolList4R12From decodes a SLPreconfigCommPoolList4R12 list from bb.
func UnmarshalUPERSLPreconfigCommPoolList4R12From(bb *per.BitBuffer) (SLPreconfigCommPoolList4R12, error) {
	var v asn1cUPERSLPreconfigCommPoolList4R12ListValue
	if err := unmarshalUPERSLPreconfigCommPoolList4R12Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLPreconfigCommPoolList4R12Into(v *asn1cUPERSLPreconfigCommPoolList4R12ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 4)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 4 {
		return fmt.Errorf("decoding value length %d above upper bound 4", seqLen_value)
	}
	v.Value = make(SLPreconfigCommPoolList4R12, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem SLPreconfigCommPoolR12
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

type asn1cUPERSLPreconfigCommRxPoolListR13ListValue struct{ Value SLPreconfigCommRxPoolListR13 }

// MarshalUPERSLPreconfigCommRxPoolListR13 encodes a SLPreconfigCommRxPoolListR13 list to UPER.
func MarshalUPERSLPreconfigCommRxPoolListR13(list SLPreconfigCommRxPoolListR13) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLPreconfigCommRxPoolListR13To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLPreconfigCommRxPoolListR13To appends a SLPreconfigCommRxPoolListR13 list to bb.
func MarshalUPERSLPreconfigCommRxPoolListR13To(list SLPreconfigCommRxPoolListR13, bb *per.BitBuffer) error {
	v := asn1cUPERSLPreconfigCommRxPoolListR13ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 12); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLPreconfigCommRxPoolListR13 decodes a SLPreconfigCommRxPoolListR13 list from UPER.
func UnmarshalUPERSLPreconfigCommRxPoolListR13(data []byte) (SLPreconfigCommRxPoolListR13, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLPreconfigCommRxPoolListR13From(bb)
}

// UnmarshalUPERSLPreconfigCommRxPoolListR13From decodes a SLPreconfigCommRxPoolListR13 list from bb.
func UnmarshalUPERSLPreconfigCommRxPoolListR13From(bb *per.BitBuffer) (SLPreconfigCommRxPoolListR13, error) {
	var v asn1cUPERSLPreconfigCommRxPoolListR13ListValue
	if err := unmarshalUPERSLPreconfigCommRxPoolListR13Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLPreconfigCommRxPoolListR13Into(v *asn1cUPERSLPreconfigCommRxPoolListR13ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 12)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 12 {
		return fmt.Errorf("decoding value length %d above upper bound 12", seqLen_value)
	}
	v.Value = make(SLPreconfigCommRxPoolListR13, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem SLPreconfigCommPoolR12
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

type asn1cUPERSLPreconfigCommTxPoolListR13ListValue struct{ Value SLPreconfigCommTxPoolListR13 }

// MarshalUPERSLPreconfigCommTxPoolListR13 encodes a SLPreconfigCommTxPoolListR13 list to UPER.
func MarshalUPERSLPreconfigCommTxPoolListR13(list SLPreconfigCommTxPoolListR13) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLPreconfigCommTxPoolListR13To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLPreconfigCommTxPoolListR13To appends a SLPreconfigCommTxPoolListR13 list to bb.
func MarshalUPERSLPreconfigCommTxPoolListR13To(list SLPreconfigCommTxPoolListR13, bb *per.BitBuffer) error {
	v := asn1cUPERSLPreconfigCommTxPoolListR13ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 7); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLPreconfigCommTxPoolListR13 decodes a SLPreconfigCommTxPoolListR13 list from UPER.
func UnmarshalUPERSLPreconfigCommTxPoolListR13(data []byte) (SLPreconfigCommTxPoolListR13, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLPreconfigCommTxPoolListR13From(bb)
}

// UnmarshalUPERSLPreconfigCommTxPoolListR13From decodes a SLPreconfigCommTxPoolListR13 list from bb.
func UnmarshalUPERSLPreconfigCommTxPoolListR13From(bb *per.BitBuffer) (SLPreconfigCommTxPoolListR13, error) {
	var v asn1cUPERSLPreconfigCommTxPoolListR13ListValue
	if err := unmarshalUPERSLPreconfigCommTxPoolListR13Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLPreconfigCommTxPoolListR13Into(v *asn1cUPERSLPreconfigCommTxPoolListR13ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 7)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 7 {
		return fmt.Errorf("decoding value length %d above upper bound 7", seqLen_value)
	}
	v.Value = make(SLPreconfigCommTxPoolListR13, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem SLPreconfigCommPoolR12
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

// MarshalUPER encodes SLPreconfigCommPoolR12 to UPER format.
func (v *SLPreconfigCommPoolR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPreconfigCommPoolR12) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.PriorityListR13 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeEnumerated(bb, int64(v.ScCPLenR12), 2, false); err != nil {
		return fmt.Errorf("encoding sc-CP-Len-r12: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.ScPeriodR12), 16, false); err != nil {
		return fmt.Errorf("encoding sc-Period-r12: %w", err)
	}
	if err := v.ScTFResourceConfigR12.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding sc-TF-ResourceConfig-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.ScTxParametersR12), int64Ptr(-126), int64Ptr(31), false); err != nil {
		return fmt.Errorf("encoding sc-TxParameters-r12: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.DataCPLenR12), 2, false); err != nil {
		return fmt.Errorf("encoding data-CP-Len-r12: %w", err)
	}
	if err := v.DataTFResourceConfigR12.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding data-TF-ResourceConfig-r12: %w", err)
	}
	if err := v.DataHoppingConfigR12.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding dataHoppingConfig-r12: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.DataTxParametersR12), int64Ptr(-126), int64Ptr(31), false); err != nil {
		return fmt.Errorf("encoding dataTxParameters-r12: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.TrptSubsetR12.Bytes, v.TrptSubsetR12.BitLength, 3, 5, true, false); err != nil {
		return fmt.Errorf("encoding trpt-Subset-r12: %w", err)
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.PriorityListR13 != nil {
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
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.PriorityListR13 != nil
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
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.PriorityListR13 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.PriorityListR13 != nil); err != nil {
				return err
			}
			if v.PriorityListR13 != nil {
				if err := per.EncodeConstrainedWholeNumber(extBuf, int64(len(v.PriorityListR13)), 1, 8); err != nil {
					return fmt.Errorf("encoding priorityList-r13 length: %w", err)
				}
				for _, elem := range v.PriorityListR13 {
					if err := per.EncodeInteger(extBuf, int64(elem), int64Ptr(1), int64Ptr(8), false); err != nil {
						return fmt.Errorf("encoding priorityList-r13 element: %w", err)
					}
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

// UnmarshalUPER decodes SLPreconfigCommPoolR12 from UPER format.
func (v *SLPreconfigCommPoolR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPreconfigCommPoolR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_sccplenr12, err := per.DecodeEnumerated(bb, 2, false)
	if err != nil {
		return fmt.Errorf("decoding sc-CP-Len-r12: %w", err)
	}
	v.ScCPLenR12 = SLCPLenR12(val_sccplenr12)
	val_scperiodr12, err := per.DecodeEnumerated(bb, 16, false)
	if err != nil {
		return fmt.Errorf("decoding sc-Period-r12: %w", err)
	}
	v.ScPeriodR12 = SLPeriodCommR12(val_scperiodr12)
	if err := v.ScTFResourceConfigR12.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding sc-TF-ResourceConfig-r12: %w", err)
	}
	val_sctxparametersr12, err := per.DecodeInteger(bb, int64Ptr(-126), int64Ptr(31), false)
	if err != nil {
		return fmt.Errorf("decoding sc-TxParameters-r12: %w", err)
	}
	v.ScTxParametersR12 = P0SLR12(val_sctxparametersr12)
	val_datacplenr12, err := per.DecodeEnumerated(bb, 2, false)
	if err != nil {
		return fmt.Errorf("decoding data-CP-Len-r12: %w", err)
	}
	v.DataCPLenR12 = SLCPLenR12(val_datacplenr12)
	if err := v.DataTFResourceConfigR12.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding data-TF-ResourceConfig-r12: %w", err)
	}
	if err := v.DataHoppingConfigR12.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding dataHoppingConfig-r12: %w", err)
	}
	val_datatxparametersr12, err := per.DecodeInteger(bb, int64Ptr(-126), int64Ptr(31), false)
	if err != nil {
		return fmt.Errorf("decoding dataTxParameters-r12: %w", err)
	}
	v.DataTxParametersR12 = P0SLR12(val_datatxparametersr12)
	bsBytes_trptsubsetr12, bsBitLen_trptsubsetr12, err := per.DecodeBitStringExt(bb, 3, 5, true, false)
	if err != nil {
		return fmt.Errorf("decoding trpt-Subset-r12: %w", err)
	}
	v.TrptSubsetR12 = runtime.BitString{Bytes: bsBytes_trptsubsetr12, BitLength: bsBitLen_trptsubsetr12}
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
			ext_opt_prioritylistr13, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_prioritylistr13 {
				var seqLen_prioritylistr13 int64
				var errLength_prioritylistr13 error
				seqLen_prioritylistr13, errLength_prioritylistr13 = per.DecodeConstrainedWholeNumber(extBB, 1, 8)
				if errLength_prioritylistr13 != nil {
					return fmt.Errorf("decoding priorityList-r13 length: %w", errLength_prioritylistr13)
				}
				if seqLen_prioritylistr13 < 1 {
					return fmt.Errorf("decoding priorityList-r13 length %d below lower bound 1", seqLen_prioritylistr13)
				}
				if seqLen_prioritylistr13 > 8 {
					return fmt.Errorf("decoding priorityList-r13 length %d above upper bound 8", seqLen_prioritylistr13)
				}
				tmp_prioritylistr13 := make(SLPriorityListR13, 0)
				for i := int64(0); i < seqLen_prioritylistr13; i++ {
					val, err := per.DecodeInteger(extBB, int64Ptr(1), int64Ptr(8), false)
					if err != nil {
						return fmt.Errorf("decoding priorityList-r13 element %d: %w", i, err)
					}
					tmp_prioritylistr13 = append(tmp_prioritylistr13, SLPriorityR13(val))
				}
				v.PriorityListR13 = tmp_prioritylistr13
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

type asn1cUPERSLPreconfigDiscRxPoolListR13ListValue struct{ Value SLPreconfigDiscRxPoolListR13 }

// MarshalUPERSLPreconfigDiscRxPoolListR13 encodes a SLPreconfigDiscRxPoolListR13 list to UPER.
func MarshalUPERSLPreconfigDiscRxPoolListR13(list SLPreconfigDiscRxPoolListR13) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLPreconfigDiscRxPoolListR13To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLPreconfigDiscRxPoolListR13To appends a SLPreconfigDiscRxPoolListR13 list to bb.
func MarshalUPERSLPreconfigDiscRxPoolListR13To(list SLPreconfigDiscRxPoolListR13, bb *per.BitBuffer) error {
	v := asn1cUPERSLPreconfigDiscRxPoolListR13ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 16); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLPreconfigDiscRxPoolListR13 decodes a SLPreconfigDiscRxPoolListR13 list from UPER.
func UnmarshalUPERSLPreconfigDiscRxPoolListR13(data []byte) (SLPreconfigDiscRxPoolListR13, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLPreconfigDiscRxPoolListR13From(bb)
}

// UnmarshalUPERSLPreconfigDiscRxPoolListR13From decodes a SLPreconfigDiscRxPoolListR13 list from bb.
func UnmarshalUPERSLPreconfigDiscRxPoolListR13From(bb *per.BitBuffer) (SLPreconfigDiscRxPoolListR13, error) {
	var v asn1cUPERSLPreconfigDiscRxPoolListR13ListValue
	if err := unmarshalUPERSLPreconfigDiscRxPoolListR13Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLPreconfigDiscRxPoolListR13Into(v *asn1cUPERSLPreconfigDiscRxPoolListR13ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 16)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 16 {
		return fmt.Errorf("decoding value length %d above upper bound 16", seqLen_value)
	}
	v.Value = make(SLPreconfigDiscRxPoolListR13, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem SLPreconfigDiscPoolR13
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

type asn1cUPERSLPreconfigDiscTxPoolListR13ListValue struct{ Value SLPreconfigDiscTxPoolListR13 }

// MarshalUPERSLPreconfigDiscTxPoolListR13 encodes a SLPreconfigDiscTxPoolListR13 list to UPER.
func MarshalUPERSLPreconfigDiscTxPoolListR13(list SLPreconfigDiscTxPoolListR13) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLPreconfigDiscTxPoolListR13To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLPreconfigDiscTxPoolListR13To appends a SLPreconfigDiscTxPoolListR13 list to bb.
func MarshalUPERSLPreconfigDiscTxPoolListR13To(list SLPreconfigDiscTxPoolListR13, bb *per.BitBuffer) error {
	v := asn1cUPERSLPreconfigDiscTxPoolListR13ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 4); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLPreconfigDiscTxPoolListR13 decodes a SLPreconfigDiscTxPoolListR13 list from UPER.
func UnmarshalUPERSLPreconfigDiscTxPoolListR13(data []byte) (SLPreconfigDiscTxPoolListR13, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLPreconfigDiscTxPoolListR13From(bb)
}

// UnmarshalUPERSLPreconfigDiscTxPoolListR13From decodes a SLPreconfigDiscTxPoolListR13 list from bb.
func UnmarshalUPERSLPreconfigDiscTxPoolListR13From(bb *per.BitBuffer) (SLPreconfigDiscTxPoolListR13, error) {
	var v asn1cUPERSLPreconfigDiscTxPoolListR13ListValue
	if err := unmarshalUPERSLPreconfigDiscTxPoolListR13Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLPreconfigDiscTxPoolListR13Into(v *asn1cUPERSLPreconfigDiscTxPoolListR13ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 4)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 4 {
		return fmt.Errorf("decoding value length %d above upper bound 4", seqLen_value)
	}
	v.Value = make(SLPreconfigDiscTxPoolListR13, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem SLPreconfigDiscPoolR13
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

// MarshalUPER encodes SLPreconfigDiscPoolR13 to UPER format.
func (v *SLPreconfigDiscPoolR13) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPreconfigDiscPoolR13) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.TxParametersR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumerated(bb, int64(v.CpLenR13), 2, false); err != nil {
		return fmt.Errorf("encoding cp-Len-r13: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.DiscPeriodR13), 16, false); err != nil {
		return fmt.Errorf("encoding discPeriod-r13: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.NumRetxR13), int64Ptr(0), int64Ptr(3), false); err != nil {
		return fmt.Errorf("encoding numRetx-r13: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.NumRepetitionR13), int64Ptr(1), int64Ptr(50), false); err != nil {
		return fmt.Errorf("encoding numRepetition-r13: %w", err)
	}
	if err := v.TfResourceConfigR13.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding tf-ResourceConfig-r13: %w", err)
	}
	if v.TxParametersR13 != nil {
		if err := v.TxParametersR13.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding txParameters-r13: %w", err)
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

// UnmarshalUPER decodes SLPreconfigDiscPoolR13 from UPER format.
func (v *SLPreconfigDiscPoolR13) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPreconfigDiscPoolR13) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_txparametersr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cplenr13, err := per.DecodeEnumerated(bb, 2, false)
	if err != nil {
		return fmt.Errorf("decoding cp-Len-r13: %w", err)
	}
	v.CpLenR13 = SLCPLenR12(val_cplenr13)
	val_discperiodr13, err := per.DecodeEnumerated(bb, 16, false)
	if err != nil {
		return fmt.Errorf("decoding discPeriod-r13: %w", err)
	}
	v.DiscPeriodR13 = val_discperiodr13
	val_numretxr13, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(3), false)
	if err != nil {
		return fmt.Errorf("decoding numRetx-r13: %w", err)
	}
	v.NumRetxR13 = val_numretxr13
	val_numrepetitionr13, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(50), false)
	if err != nil {
		return fmt.Errorf("decoding numRepetition-r13: %w", err)
	}
	v.NumRepetitionR13 = val_numrepetitionr13
	if err := v.TfResourceConfigR13.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding tf-ResourceConfig-r13: %w", err)
	}
	if opt_txparametersr13 {
		var dec_txparametersr13 SLPreconfigDiscPoolR13TxParametersR13
		if err := dec_txparametersr13.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding txParameters-r13: %w", err)
		}
		v.TxParametersR13 = &dec_txparametersr13
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

// MarshalUPER encodes SLPreconfigRelayR13 to UPER format.
func (v *SLPreconfigRelayR13) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPreconfigRelayR13) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.ReselectionInfoOoCR13.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding reselectionInfoOoC-r13: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes SLPreconfigRelayR13 from UPER format.
func (v *SLPreconfigRelayR13) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPreconfigRelayR13) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	if err := v.ReselectionInfoOoCR13.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding reselectionInfoOoC-r13: %w", err)
	}
	return nil
}

// MarshalUPER encodes SLV2XPreconfigurationR14 to UPER format.
func (v *SLV2XPreconfigurationR14) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLV2XPreconfigurationR14) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.V2xPacketDuplicationConfigR15 != nil || v.SyncFreqListR15 != nil || v.SlssTxMultiFreqR15 != nil || v.V2xTxProfileListR15 != nil || v.AnchorCarrierFreqListNRR16 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.AnchorCarrierFreqListR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.CbrPreconfigListR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.V2xPreconfigFreqListR14)), 1, 8); err != nil {
		return fmt.Errorf("encoding v2x-PreconfigFreqList-r14 length: %w", err)
	}
	for _, elem := range v.V2xPreconfigFreqListR14 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding v2x-PreconfigFreqList-r14 element: %w", err)
		}
	}
	if v.AnchorCarrierFreqListR14 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.AnchorCarrierFreqListR14)), 1, 8); err != nil {
			return fmt.Errorf("encoding anchorCarrierFreqList-r14 length: %w", err)
		}
		for _, elem := range v.AnchorCarrierFreqListR14 {
			if err := per.EncodeInteger(bb, int64(elem), int64Ptr(0), int64Ptr(262143), false); err != nil {
				return fmt.Errorf("encoding anchorCarrierFreqList-r14 element: %w", err)
			}
		}
	}
	if v.CbrPreconfigListR14 != nil {
		if err := v.CbrPreconfigListR14.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding cbr-PreconfigList-r14: %w", err)
		}
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.V2xPacketDuplicationConfigR15 != nil || v.SyncFreqListR15 != nil || v.SlssTxMultiFreqR15 != nil || v.V2xTxProfileListR15 != nil {
			extHighest = 0
		}
		if v.AnchorCarrierFreqListNRR16 != nil {
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
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.V2xPacketDuplicationConfigR15 != nil || v.SyncFreqListR15 != nil || v.SlssTxMultiFreqR15 != nil || v.V2xTxProfileListR15 != nil
			if err := per.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		if int64(1) <= extHighest {
			present1 := (int64(1) < int64(len(v.ExtPresent_)) && v.ExtPresent_[1]) || v.AnchorCarrierFreqListNRR16 != nil
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
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.V2xPacketDuplicationConfigR15 != nil || v.SyncFreqListR15 != nil || v.SlssTxMultiFreqR15 != nil || v.V2xTxProfileListR15 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.V2xPacketDuplicationConfigR15 != nil); err != nil {
				return err
			}
			if err := per.EncodeBoolean(extBuf, v.SyncFreqListR15 != nil); err != nil {
				return err
			}
			if err := per.EncodeBoolean(extBuf, v.SlssTxMultiFreqR15 != nil); err != nil {
				return err
			}
			if err := per.EncodeBoolean(extBuf, v.V2xTxProfileListR15 != nil); err != nil {
				return err
			}
			if v.V2xPacketDuplicationConfigR15 != nil {
				if err := v.V2xPacketDuplicationConfigR15.MarshalUPERTo(extBuf); err != nil {
					return fmt.Errorf("encoding v2x-PacketDuplicationConfig-r15: %w", err)
				}
			}
			if v.SyncFreqListR15 != nil {
				if err := per.EncodeConstrainedWholeNumber(extBuf, int64(len(v.SyncFreqListR15)), 1, 8); err != nil {
					return fmt.Errorf("encoding syncFreqList-r15 length: %w", err)
				}
				for _, elem := range v.SyncFreqListR15 {
					if err := per.EncodeInteger(extBuf, int64(elem), int64Ptr(0), int64Ptr(262143), false); err != nil {
						return fmt.Errorf("encoding syncFreqList-r15 element: %w", err)
					}
				}
			}
			if v.SlssTxMultiFreqR15 != nil {
				if err := per.EncodeEnumerated(extBuf, int64(*v.SlssTxMultiFreqR15), 1, false); err != nil {
					return fmt.Errorf("encoding slss-TxMultiFreq-r15: %w", err)
				}
			}
			if v.V2xTxProfileListR15 != nil {
				if err := per.EncodeConstrainedWholeNumber(extBuf, int64(len(v.V2xTxProfileListR15)), 1, 256); err != nil {
					return fmt.Errorf("encoding v2x-TxProfileList-r15 length: %w", err)
				}
				for _, elem := range v.V2xTxProfileListR15 {
					if err := per.EncodeEnumerated(extBuf, int64(elem), 8, true); err != nil {
						return fmt.Errorf("encoding v2x-TxProfileList-r15 element: %w", err)
					}
				}
			}
			if err := per.EncodeOpenType(bb, extBuf.Bytes()); err != nil {
				return err
			}
		}
		if (int64(1) < int64(len(v.ExtPresent_)) && v.ExtPresent_[1]) || v.AnchorCarrierFreqListNRR16 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.AnchorCarrierFreqListNRR16 != nil); err != nil {
				return err
			}
			if v.AnchorCarrierFreqListNRR16 != nil {
				if err := per.EncodeConstrainedWholeNumber(extBuf, int64(len(v.AnchorCarrierFreqListNRR16)), 1, 8); err != nil {
					return fmt.Errorf("encoding anchorCarrierFreqListNR-r16 length: %w", err)
				}
				for _, elem := range v.AnchorCarrierFreqListNRR16 {
					if err := per.EncodeInteger(extBuf, int64(elem), int64Ptr(0), int64Ptr(3279165), false); err != nil {
						return fmt.Errorf("encoding anchorCarrierFreqListNR-r16 element: %w", err)
					}
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

// UnmarshalUPER decodes SLV2XPreconfigurationR14 from UPER format.
func (v *SLV2XPreconfigurationR14) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLV2XPreconfigurationR14) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_anchorcarrierfreqlistr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_cbrpreconfiglistr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	var seqLen_v2xpreconfigfreqlistr14 int64
	var errLength_v2xpreconfigfreqlistr14 error
	seqLen_v2xpreconfigfreqlistr14, errLength_v2xpreconfigfreqlistr14 = per.DecodeConstrainedWholeNumber(bb, 1, 8)
	if errLength_v2xpreconfigfreqlistr14 != nil {
		return fmt.Errorf("decoding v2x-PreconfigFreqList-r14 length: %w", errLength_v2xpreconfigfreqlistr14)
	}
	if seqLen_v2xpreconfigfreqlistr14 < 1 {
		return fmt.Errorf("decoding v2x-PreconfigFreqList-r14 length %d below lower bound 1", seqLen_v2xpreconfigfreqlistr14)
	}
	if seqLen_v2xpreconfigfreqlistr14 > 8 {
		return fmt.Errorf("decoding v2x-PreconfigFreqList-r14 length %d above upper bound 8", seqLen_v2xpreconfigfreqlistr14)
	}
	v.V2xPreconfigFreqListR14 = make(SLV2XPreconfigFreqListR14, 0)
	for i := int64(0); i < seqLen_v2xpreconfigfreqlistr14; i++ {
		var elem SLV2XPreconfigFreqInfoR14
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding v2x-PreconfigFreqList-r14 element %d: %w", i, err)
		}
		v.V2xPreconfigFreqListR14 = append(v.V2xPreconfigFreqListR14, elem)
	}
	if opt_anchorcarrierfreqlistr14 {
		var seqLen_anchorcarrierfreqlistr14 int64
		var errLength_anchorcarrierfreqlistr14 error
		seqLen_anchorcarrierfreqlistr14, errLength_anchorcarrierfreqlistr14 = per.DecodeConstrainedWholeNumber(bb, 1, 8)
		if errLength_anchorcarrierfreqlistr14 != nil {
			return fmt.Errorf("decoding anchorCarrierFreqList-r14 length: %w", errLength_anchorcarrierfreqlistr14)
		}
		if seqLen_anchorcarrierfreqlistr14 < 1 {
			return fmt.Errorf("decoding anchorCarrierFreqList-r14 length %d below lower bound 1", seqLen_anchorcarrierfreqlistr14)
		}
		if seqLen_anchorcarrierfreqlistr14 > 8 {
			return fmt.Errorf("decoding anchorCarrierFreqList-r14 length %d above upper bound 8", seqLen_anchorcarrierfreqlistr14)
		}
		tmp_anchorcarrierfreqlistr14 := make(SLAnchorCarrierFreqListV2XR14, 0)
		for i := int64(0); i < seqLen_anchorcarrierfreqlistr14; i++ {
			val, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(262143), false)
			if err != nil {
				return fmt.Errorf("decoding anchorCarrierFreqList-r14 element %d: %w", i, err)
			}
			tmp_anchorcarrierfreqlistr14 = append(tmp_anchorcarrierfreqlistr14, ARFCNValueEUTRAR9(val))
		}
		v.AnchorCarrierFreqListR14 = tmp_anchorcarrierfreqlistr14
	}
	if opt_cbrpreconfiglistr14 {
		var dec_cbrpreconfiglistr14 SLCBRPreconfigTxConfigListR14
		if err := dec_cbrpreconfiglistr14.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding cbr-PreconfigList-r14: %w", err)
		}
		v.CbrPreconfigListR14 = &dec_cbrpreconfiglistr14
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
			ext_opt_v2xpacketduplicationconfigr15, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			ext_opt_syncfreqlistr15, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			ext_opt_slsstxmultifreqr15, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			ext_opt_v2xtxprofilelistr15, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_v2xpacketduplicationconfigr15 {
				var dec_v2xpacketduplicationconfigr15 SLV2XPacketDuplicationConfigR15
				if err := dec_v2xpacketduplicationconfigr15.UnmarshalUPERFrom(extBB); err != nil {
					return fmt.Errorf("decoding v2x-PacketDuplicationConfig-r15: %w", err)
				}
				v.V2xPacketDuplicationConfigR15 = &dec_v2xpacketduplicationconfigr15
			}
			if ext_opt_syncfreqlistr15 {
				var seqLen_syncfreqlistr15 int64
				var errLength_syncfreqlistr15 error
				seqLen_syncfreqlistr15, errLength_syncfreqlistr15 = per.DecodeConstrainedWholeNumber(extBB, 1, 8)
				if errLength_syncfreqlistr15 != nil {
					return fmt.Errorf("decoding syncFreqList-r15 length: %w", errLength_syncfreqlistr15)
				}
				if seqLen_syncfreqlistr15 < 1 {
					return fmt.Errorf("decoding syncFreqList-r15 length %d below lower bound 1", seqLen_syncfreqlistr15)
				}
				if seqLen_syncfreqlistr15 > 8 {
					return fmt.Errorf("decoding syncFreqList-r15 length %d above upper bound 8", seqLen_syncfreqlistr15)
				}
				tmp_syncfreqlistr15 := make(SLV2XSyncFreqListR15, 0)
				for i := int64(0); i < seqLen_syncfreqlistr15; i++ {
					val, err := per.DecodeInteger(extBB, int64Ptr(0), int64Ptr(262143), false)
					if err != nil {
						return fmt.Errorf("decoding syncFreqList-r15 element %d: %w", i, err)
					}
					tmp_syncfreqlistr15 = append(tmp_syncfreqlistr15, ARFCNValueEUTRAR9(val))
				}
				v.SyncFreqListR15 = tmp_syncfreqlistr15
			}
			if ext_opt_slsstxmultifreqr15 {
				val_slsstxmultifreqr15, err := per.DecodeEnumerated(extBB, 1, false)
				if err != nil {
					return fmt.Errorf("decoding slss-TxMultiFreq-r15: %w", err)
				}
				v.SlssTxMultiFreqR15 = &val_slsstxmultifreqr15
			}
			if ext_opt_v2xtxprofilelistr15 {
				var seqLen_v2xtxprofilelistr15 int64
				var errLength_v2xtxprofilelistr15 error
				seqLen_v2xtxprofilelistr15, errLength_v2xtxprofilelistr15 = per.DecodeConstrainedWholeNumber(extBB, 1, 256)
				if errLength_v2xtxprofilelistr15 != nil {
					return fmt.Errorf("decoding v2x-TxProfileList-r15 length: %w", errLength_v2xtxprofilelistr15)
				}
				if seqLen_v2xtxprofilelistr15 < 1 {
					return fmt.Errorf("decoding v2x-TxProfileList-r15 length %d below lower bound 1", seqLen_v2xtxprofilelistr15)
				}
				if seqLen_v2xtxprofilelistr15 > 256 {
					return fmt.Errorf("decoding v2x-TxProfileList-r15 length %d above upper bound 256", seqLen_v2xtxprofilelistr15)
				}
				tmp_v2xtxprofilelistr15 := make(SLV2XTxProfileListR15, 0)
				for i := int64(0); i < seqLen_v2xtxprofilelistr15; i++ {
					val, err := per.DecodeEnumerated(extBB, 8, true)
					if err != nil {
						return fmt.Errorf("decoding v2x-TxProfileList-r15 element %d: %w", i, err)
					}
					tmp_v2xtxprofilelistr15 = append(tmp_v2xtxprofilelistr15, SLV2XTxProfileR15(val))
				}
				v.V2xTxProfileListR15 = tmp_v2xtxprofilelistr15
			}
		}
		if int64(1) <= extCount && extPresent[1] {
			extData, err := per.DecodeOpenType(bb)
			if err != nil {
				return err
			}
			extBB := per.NewBitBufferFromBytes(extData)
			_ = extBB
			ext_opt_anchorcarrierfreqlistnrr16, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_anchorcarrierfreqlistnrr16 {
				var seqLen_anchorcarrierfreqlistnrr16 int64
				var errLength_anchorcarrierfreqlistnrr16 error
				seqLen_anchorcarrierfreqlistnrr16, errLength_anchorcarrierfreqlistnrr16 = per.DecodeConstrainedWholeNumber(extBB, 1, 8)
				if errLength_anchorcarrierfreqlistnrr16 != nil {
					return fmt.Errorf("decoding anchorCarrierFreqListNR-r16 length: %w", errLength_anchorcarrierfreqlistnrr16)
				}
				if seqLen_anchorcarrierfreqlistnrr16 < 1 {
					return fmt.Errorf("decoding anchorCarrierFreqListNR-r16 length %d below lower bound 1", seqLen_anchorcarrierfreqlistnrr16)
				}
				if seqLen_anchorcarrierfreqlistnrr16 > 8 {
					return fmt.Errorf("decoding anchorCarrierFreqListNR-r16 length %d above upper bound 8", seqLen_anchorcarrierfreqlistnrr16)
				}
				tmp_anchorcarrierfreqlistnrr16 := make(SLNRAnchorCarrierFreqListR16, 0)
				for i := int64(0); i < seqLen_anchorcarrierfreqlistnrr16; i++ {
					val, err := per.DecodeInteger(extBB, int64Ptr(0), int64Ptr(3279165), false)
					if err != nil {
						return fmt.Errorf("decoding anchorCarrierFreqListNR-r16 element %d: %w", i, err)
					}
					tmp_anchorcarrierfreqlistnrr16 = append(tmp_anchorcarrierfreqlistnrr16, ARFCNValueNRR15(val))
				}
				v.AnchorCarrierFreqListNRR16 = tmp_anchorcarrierfreqlistnrr16
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

// MarshalUPER encodes SLCBRPreconfigTxConfigListR14 to UPER format.
func (v *SLCBRPreconfigTxConfigListR14) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLCBRPreconfigTxConfigListR14) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.CbrRangeCommonConfigListR14)), 1, 8); err != nil {
		return fmt.Errorf("encoding cbr-RangeCommonConfigList-r14 length: %w", err)
	}
	for _, outerElem := range v.CbrRangeCommonConfigListR14 {
		if err := MarshalUPERSLCBRLevelsConfigR14To(outerElem, bb); err != nil {
			return fmt.Errorf("encoding cbr-RangeCommonConfigList-r14 element: %w", err)
		}
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.SlCBRPSSCHTxConfigListR14)), 1, 128); err != nil {
		return fmt.Errorf("encoding sl-CBR-PSSCH-TxConfigList-r14 length: %w", err)
	}
	for _, elem := range v.SlCBRPSSCHTxConfigListR14 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding sl-CBR-PSSCH-TxConfigList-r14 element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes SLCBRPreconfigTxConfigListR14 from UPER format.
func (v *SLCBRPreconfigTxConfigListR14) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLCBRPreconfigTxConfigListR14) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	var seqLen_cbrrangecommonconfiglistr14 int64
	var errLength_cbrrangecommonconfiglistr14 error
	seqLen_cbrrangecommonconfiglistr14, errLength_cbrrangecommonconfiglistr14 = per.DecodeConstrainedWholeNumber(bb, 1, 8)
	if errLength_cbrrangecommonconfiglistr14 != nil {
		return fmt.Errorf("decoding cbr-RangeCommonConfigList-r14 length: %w", errLength_cbrrangecommonconfiglistr14)
	}
	if seqLen_cbrrangecommonconfiglistr14 < 1 {
		return fmt.Errorf("decoding cbr-RangeCommonConfigList-r14 length %d below lower bound 1", seqLen_cbrrangecommonconfiglistr14)
	}
	if seqLen_cbrrangecommonconfiglistr14 > 8 {
		return fmt.Errorf("decoding cbr-RangeCommonConfigList-r14 length %d above upper bound 8", seqLen_cbrrangecommonconfiglistr14)
	}
	v.CbrRangeCommonConfigListR14 = make(SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14, 0)
	for i_cbrrangecommonconfiglistr14 := int64(0); i_cbrrangecommonconfiglistr14 < seqLen_cbrrangecommonconfiglistr14; i_cbrrangecommonconfiglistr14++ {
		elem, err := UnmarshalUPERSLCBRLevelsConfigR14From(bb)
		if err != nil {
			return fmt.Errorf("decoding cbr-RangeCommonConfigList-r14 element: %w", err)
		}
		v.CbrRangeCommonConfigListR14 = append(v.CbrRangeCommonConfigListR14, elem)
	}
	var seqLen_slcbrpsschtxconfiglistr14 int64
	var errLength_slcbrpsschtxconfiglistr14 error
	seqLen_slcbrpsschtxconfiglistr14, errLength_slcbrpsschtxconfiglistr14 = per.DecodeConstrainedWholeNumber(bb, 1, 128)
	if errLength_slcbrpsschtxconfiglistr14 != nil {
		return fmt.Errorf("decoding sl-CBR-PSSCH-TxConfigList-r14 length: %w", errLength_slcbrpsschtxconfiglistr14)
	}
	if seqLen_slcbrpsschtxconfiglistr14 < 1 {
		return fmt.Errorf("decoding sl-CBR-PSSCH-TxConfigList-r14 length %d below lower bound 1", seqLen_slcbrpsschtxconfiglistr14)
	}
	if seqLen_slcbrpsschtxconfiglistr14 > 128 {
		return fmt.Errorf("decoding sl-CBR-PSSCH-TxConfigList-r14 length %d above upper bound 128", seqLen_slcbrpsschtxconfiglistr14)
	}
	v.SlCBRPSSCHTxConfigListR14 = make(SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14, 0)
	for i := int64(0); i < seqLen_slcbrpsschtxconfiglistr14; i++ {
		var elem SLCBRPSSCHTxConfigR14
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding sl-CBR-PSSCH-TxConfigList-r14 element %d: %w", i, err)
		}
		v.SlCBRPSSCHTxConfigListR14 = append(v.SlCBRPSSCHTxConfigListR14, elem)
	}
	return nil
}

type asn1cUPERSLV2XPreconfigFreqListR14ListValue struct{ Value SLV2XPreconfigFreqListR14 }

// MarshalUPERSLV2XPreconfigFreqListR14 encodes a SLV2XPreconfigFreqListR14 list to UPER.
func MarshalUPERSLV2XPreconfigFreqListR14(list SLV2XPreconfigFreqListR14) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLV2XPreconfigFreqListR14To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLV2XPreconfigFreqListR14To appends a SLV2XPreconfigFreqListR14 list to bb.
func MarshalUPERSLV2XPreconfigFreqListR14To(list SLV2XPreconfigFreqListR14, bb *per.BitBuffer) error {
	v := asn1cUPERSLV2XPreconfigFreqListR14ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 8); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLV2XPreconfigFreqListR14 decodes a SLV2XPreconfigFreqListR14 list from UPER.
func UnmarshalUPERSLV2XPreconfigFreqListR14(data []byte) (SLV2XPreconfigFreqListR14, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLV2XPreconfigFreqListR14From(bb)
}

// UnmarshalUPERSLV2XPreconfigFreqListR14From decodes a SLV2XPreconfigFreqListR14 list from bb.
func UnmarshalUPERSLV2XPreconfigFreqListR14From(bb *per.BitBuffer) (SLV2XPreconfigFreqListR14, error) {
	var v asn1cUPERSLV2XPreconfigFreqListR14ListValue
	if err := unmarshalUPERSLV2XPreconfigFreqListR14Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLV2XPreconfigFreqListR14Into(v *asn1cUPERSLV2XPreconfigFreqListR14ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 8)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 8 {
		return fmt.Errorf("decoding value length %d above upper bound 8", seqLen_value)
	}
	v.Value = make(SLV2XPreconfigFreqListR14, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem SLV2XPreconfigFreqInfoR14
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

// MarshalUPER encodes SLV2XPreconfigFreqInfoR14 to UPER format.
func (v *SLV2XPreconfigFreqInfoR14) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLV2XPreconfigFreqInfoR14) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.V2xFreqSelectionConfigListR15 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.V2xCommPreconfigSyncR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.V2xResourceSelectionConfigR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ZoneConfigR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ThresSLTxPrioritizationR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.OffsetDFNR14 != nil); err != nil {
		return err
	}
	if err := v.V2xCommPreconfigGeneralR14.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding v2x-CommPreconfigGeneral-r14: %w", err)
	}
	if v.V2xCommPreconfigSyncR14 != nil {
		if err := v.V2xCommPreconfigSyncR14.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding v2x-CommPreconfigSync-r14: %w", err)
		}
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.V2xCommRxPoolListR14)), 1, 16); err != nil {
		return fmt.Errorf("encoding v2x-CommRxPoolList-r14 length: %w", err)
	}
	for _, elem := range v.V2xCommRxPoolListR14 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding v2x-CommRxPoolList-r14 element: %w", err)
		}
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.V2xCommTxPoolListR14)), 1, 8); err != nil {
		return fmt.Errorf("encoding v2x-CommTxPoolList-r14 length: %w", err)
	}
	for _, elem := range v.V2xCommTxPoolListR14 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding v2x-CommTxPoolList-r14 element: %w", err)
		}
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.P2xCommTxPoolListR14)), 1, 8); err != nil {
		return fmt.Errorf("encoding p2x-CommTxPoolList-r14 length: %w", err)
	}
	for _, elem := range v.P2xCommTxPoolListR14 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding p2x-CommTxPoolList-r14 element: %w", err)
		}
	}
	if v.V2xResourceSelectionConfigR14 != nil {
		if err := v.V2xResourceSelectionConfigR14.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding v2x-ResourceSelectionConfig-r14: %w", err)
		}
	}
	if v.ZoneConfigR14 != nil {
		if err := v.ZoneConfigR14.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding zoneConfig-r14: %w", err)
		}
	}
	if err := per.EncodeEnumerated(bb, int64(v.SyncPriorityR14), 2, false); err != nil {
		return fmt.Errorf("encoding syncPriority-r14: %w", err)
	}
	if v.ThresSLTxPrioritizationR14 != nil {
		if err := per.EncodeInteger(bb, int64(*v.ThresSLTxPrioritizationR14), int64Ptr(1), int64Ptr(8), false); err != nil {
			return fmt.Errorf("encoding thresSL-TxPrioritization-r14: %w", err)
		}
	}
	if v.OffsetDFNR14 != nil {
		if err := per.EncodeInteger(bb, int64(*v.OffsetDFNR14), int64Ptr(0), int64Ptr(1000), false); err != nil {
			return fmt.Errorf("encoding offsetDFN-r14: %w", err)
		}
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.V2xFreqSelectionConfigListR15 != nil {
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
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.V2xFreqSelectionConfigListR15 != nil
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
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.V2xFreqSelectionConfigListR15 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.V2xFreqSelectionConfigListR15 != nil); err != nil {
				return err
			}
			if v.V2xFreqSelectionConfigListR15 != nil {
				if err := per.EncodeConstrainedWholeNumber(extBuf, int64(len(v.V2xFreqSelectionConfigListR15)), 1, 8); err != nil {
					return fmt.Errorf("encoding v2x-FreqSelectionConfigList-r15 length: %w", err)
				}
				for _, elem := range v.V2xFreqSelectionConfigListR15 {
					if err := elem.MarshalUPERTo(extBuf); err != nil {
						return fmt.Errorf("encoding v2x-FreqSelectionConfigList-r15 element: %w", err)
					}
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

// UnmarshalUPER decodes SLV2XPreconfigFreqInfoR14 from UPER format.
func (v *SLV2XPreconfigFreqInfoR14) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLV2XPreconfigFreqInfoR14) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_v2xcommpreconfigsyncr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_v2xresourceselectionconfigr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_zoneconfigr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_thressltxprioritizationr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_offsetdfnr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.V2xCommPreconfigGeneralR14.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding v2x-CommPreconfigGeneral-r14: %w", err)
	}
	if opt_v2xcommpreconfigsyncr14 {
		var dec_v2xcommpreconfigsyncr14 SLPreconfigV2XSyncR14
		if err := dec_v2xcommpreconfigsyncr14.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding v2x-CommPreconfigSync-r14: %w", err)
		}
		v.V2xCommPreconfigSyncR14 = &dec_v2xcommpreconfigsyncr14
	}
	var seqLen_v2xcommrxpoollistr14 int64
	var errLength_v2xcommrxpoollistr14 error
	seqLen_v2xcommrxpoollistr14, errLength_v2xcommrxpoollistr14 = per.DecodeConstrainedWholeNumber(bb, 1, 16)
	if errLength_v2xcommrxpoollistr14 != nil {
		return fmt.Errorf("decoding v2x-CommRxPoolList-r14 length: %w", errLength_v2xcommrxpoollistr14)
	}
	if seqLen_v2xcommrxpoollistr14 < 1 {
		return fmt.Errorf("decoding v2x-CommRxPoolList-r14 length %d below lower bound 1", seqLen_v2xcommrxpoollistr14)
	}
	if seqLen_v2xcommrxpoollistr14 > 16 {
		return fmt.Errorf("decoding v2x-CommRxPoolList-r14 length %d above upper bound 16", seqLen_v2xcommrxpoollistr14)
	}
	v.V2xCommRxPoolListR14 = make(SLPreconfigV2XRxPoolListR14, 0)
	for i := int64(0); i < seqLen_v2xcommrxpoollistr14; i++ {
		var elem SLV2XPreconfigCommPoolR14
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding v2x-CommRxPoolList-r14 element %d: %w", i, err)
		}
		v.V2xCommRxPoolListR14 = append(v.V2xCommRxPoolListR14, elem)
	}
	var seqLen_v2xcommtxpoollistr14 int64
	var errLength_v2xcommtxpoollistr14 error
	seqLen_v2xcommtxpoollistr14, errLength_v2xcommtxpoollistr14 = per.DecodeConstrainedWholeNumber(bb, 1, 8)
	if errLength_v2xcommtxpoollistr14 != nil {
		return fmt.Errorf("decoding v2x-CommTxPoolList-r14 length: %w", errLength_v2xcommtxpoollistr14)
	}
	if seqLen_v2xcommtxpoollistr14 < 1 {
		return fmt.Errorf("decoding v2x-CommTxPoolList-r14 length %d below lower bound 1", seqLen_v2xcommtxpoollistr14)
	}
	if seqLen_v2xcommtxpoollistr14 > 8 {
		return fmt.Errorf("decoding v2x-CommTxPoolList-r14 length %d above upper bound 8", seqLen_v2xcommtxpoollistr14)
	}
	v.V2xCommTxPoolListR14 = make(SLPreconfigV2XTxPoolListR14, 0)
	for i := int64(0); i < seqLen_v2xcommtxpoollistr14; i++ {
		var elem SLV2XPreconfigCommPoolR14
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding v2x-CommTxPoolList-r14 element %d: %w", i, err)
		}
		v.V2xCommTxPoolListR14 = append(v.V2xCommTxPoolListR14, elem)
	}
	var seqLen_p2xcommtxpoollistr14 int64
	var errLength_p2xcommtxpoollistr14 error
	seqLen_p2xcommtxpoollistr14, errLength_p2xcommtxpoollistr14 = per.DecodeConstrainedWholeNumber(bb, 1, 8)
	if errLength_p2xcommtxpoollistr14 != nil {
		return fmt.Errorf("decoding p2x-CommTxPoolList-r14 length: %w", errLength_p2xcommtxpoollistr14)
	}
	if seqLen_p2xcommtxpoollistr14 < 1 {
		return fmt.Errorf("decoding p2x-CommTxPoolList-r14 length %d below lower bound 1", seqLen_p2xcommtxpoollistr14)
	}
	if seqLen_p2xcommtxpoollistr14 > 8 {
		return fmt.Errorf("decoding p2x-CommTxPoolList-r14 length %d above upper bound 8", seqLen_p2xcommtxpoollistr14)
	}
	v.P2xCommTxPoolListR14 = make(SLPreconfigV2XTxPoolListR14, 0)
	for i := int64(0); i < seqLen_p2xcommtxpoollistr14; i++ {
		var elem SLV2XPreconfigCommPoolR14
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding p2x-CommTxPoolList-r14 element %d: %w", i, err)
		}
		v.P2xCommTxPoolListR14 = append(v.P2xCommTxPoolListR14, elem)
	}
	if opt_v2xresourceselectionconfigr14 {
		var dec_v2xresourceselectionconfigr14 SLCommTxPoolSensingConfigR14
		if err := dec_v2xresourceselectionconfigr14.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding v2x-ResourceSelectionConfig-r14: %w", err)
		}
		v.V2xResourceSelectionConfigR14 = &dec_v2xresourceselectionconfigr14
	}
	if opt_zoneconfigr14 {
		var dec_zoneconfigr14 SLZoneConfigR14
		if err := dec_zoneconfigr14.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding zoneConfig-r14: %w", err)
		}
		v.ZoneConfigR14 = &dec_zoneconfigr14
	}
	val_syncpriorityr14, err := per.DecodeEnumerated(bb, 2, false)
	if err != nil {
		return fmt.Errorf("decoding syncPriority-r14: %w", err)
	}
	v.SyncPriorityR14 = val_syncpriorityr14
	if opt_thressltxprioritizationr14 {
		val_thressltxprioritizationr14, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(8), false)
		if err != nil {
			return fmt.Errorf("decoding thresSL-TxPrioritization-r14: %w", err)
		}
		tmp_thressltxprioritizationr14 := SLPriorityR13(val_thressltxprioritizationr14)
		v.ThresSLTxPrioritizationR14 = &tmp_thressltxprioritizationr14
	}
	if opt_offsetdfnr14 {
		val_offsetdfnr14, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(1000), false)
		if err != nil {
			return fmt.Errorf("decoding offsetDFN-r14: %w", err)
		}
		v.OffsetDFNR14 = &val_offsetdfnr14
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
			ext_opt_v2xfreqselectionconfiglistr15, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_v2xfreqselectionconfiglistr15 {
				var seqLen_v2xfreqselectionconfiglistr15 int64
				var errLength_v2xfreqselectionconfiglistr15 error
				seqLen_v2xfreqselectionconfiglistr15, errLength_v2xfreqselectionconfiglistr15 = per.DecodeConstrainedWholeNumber(extBB, 1, 8)
				if errLength_v2xfreqselectionconfiglistr15 != nil {
					return fmt.Errorf("decoding v2x-FreqSelectionConfigList-r15 length: %w", errLength_v2xfreqselectionconfiglistr15)
				}
				if seqLen_v2xfreqselectionconfiglistr15 < 1 {
					return fmt.Errorf("decoding v2x-FreqSelectionConfigList-r15 length %d below lower bound 1", seqLen_v2xfreqselectionconfiglistr15)
				}
				if seqLen_v2xfreqselectionconfiglistr15 > 8 {
					return fmt.Errorf("decoding v2x-FreqSelectionConfigList-r15 length %d above upper bound 8", seqLen_v2xfreqselectionconfiglistr15)
				}
				tmp_v2xfreqselectionconfiglistr15 := make(SLV2XFreqSelectionConfigListR15, 0)
				for i := int64(0); i < seqLen_v2xfreqselectionconfiglistr15; i++ {
					var elem SLV2XFreqSelectionConfigR15
					if err := elem.UnmarshalUPERFrom(extBB); err != nil {
						return fmt.Errorf("decoding v2x-FreqSelectionConfigList-r15 element %d: %w", i, err)
					}
					tmp_v2xfreqselectionconfiglistr15 = append(tmp_v2xfreqselectionconfiglistr15, elem)
				}
				v.V2xFreqSelectionConfigListR15 = tmp_v2xfreqselectionconfiglistr15
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

type asn1cUPERSLPreconfigV2XRxPoolListR14ListValue struct{ Value SLPreconfigV2XRxPoolListR14 }

// MarshalUPERSLPreconfigV2XRxPoolListR14 encodes a SLPreconfigV2XRxPoolListR14 list to UPER.
func MarshalUPERSLPreconfigV2XRxPoolListR14(list SLPreconfigV2XRxPoolListR14) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLPreconfigV2XRxPoolListR14To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLPreconfigV2XRxPoolListR14To appends a SLPreconfigV2XRxPoolListR14 list to bb.
func MarshalUPERSLPreconfigV2XRxPoolListR14To(list SLPreconfigV2XRxPoolListR14, bb *per.BitBuffer) error {
	v := asn1cUPERSLPreconfigV2XRxPoolListR14ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 16); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLPreconfigV2XRxPoolListR14 decodes a SLPreconfigV2XRxPoolListR14 list from UPER.
func UnmarshalUPERSLPreconfigV2XRxPoolListR14(data []byte) (SLPreconfigV2XRxPoolListR14, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLPreconfigV2XRxPoolListR14From(bb)
}

// UnmarshalUPERSLPreconfigV2XRxPoolListR14From decodes a SLPreconfigV2XRxPoolListR14 list from bb.
func UnmarshalUPERSLPreconfigV2XRxPoolListR14From(bb *per.BitBuffer) (SLPreconfigV2XRxPoolListR14, error) {
	var v asn1cUPERSLPreconfigV2XRxPoolListR14ListValue
	if err := unmarshalUPERSLPreconfigV2XRxPoolListR14Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLPreconfigV2XRxPoolListR14Into(v *asn1cUPERSLPreconfigV2XRxPoolListR14ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 16)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 16 {
		return fmt.Errorf("decoding value length %d above upper bound 16", seqLen_value)
	}
	v.Value = make(SLPreconfigV2XRxPoolListR14, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem SLV2XPreconfigCommPoolR14
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

type asn1cUPERSLPreconfigV2XTxPoolListR14ListValue struct{ Value SLPreconfigV2XTxPoolListR14 }

// MarshalUPERSLPreconfigV2XTxPoolListR14 encodes a SLPreconfigV2XTxPoolListR14 list to UPER.
func MarshalUPERSLPreconfigV2XTxPoolListR14(list SLPreconfigV2XTxPoolListR14) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLPreconfigV2XTxPoolListR14To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLPreconfigV2XTxPoolListR14To appends a SLPreconfigV2XTxPoolListR14 list to bb.
func MarshalUPERSLPreconfigV2XTxPoolListR14To(list SLPreconfigV2XTxPoolListR14, bb *per.BitBuffer) error {
	v := asn1cUPERSLPreconfigV2XTxPoolListR14ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 8); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLPreconfigV2XTxPoolListR14 decodes a SLPreconfigV2XTxPoolListR14 list from UPER.
func UnmarshalUPERSLPreconfigV2XTxPoolListR14(data []byte) (SLPreconfigV2XTxPoolListR14, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLPreconfigV2XTxPoolListR14From(bb)
}

// UnmarshalUPERSLPreconfigV2XTxPoolListR14From decodes a SLPreconfigV2XTxPoolListR14 list from bb.
func UnmarshalUPERSLPreconfigV2XTxPoolListR14From(bb *per.BitBuffer) (SLPreconfigV2XTxPoolListR14, error) {
	var v asn1cUPERSLPreconfigV2XTxPoolListR14ListValue
	if err := unmarshalUPERSLPreconfigV2XTxPoolListR14Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLPreconfigV2XTxPoolListR14Into(v *asn1cUPERSLPreconfigV2XTxPoolListR14ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 8)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 8 {
		return fmt.Errorf("decoding value length %d above upper bound 8", seqLen_value)
	}
	v.Value = make(SLPreconfigV2XTxPoolListR14, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem SLV2XPreconfigCommPoolR14
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

// MarshalUPER encodes SLV2XPreconfigCommPoolR14 to UPER format.
func (v *SLV2XPreconfigCommPoolR14) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLV2XPreconfigCommPoolR14) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.SlMinT2ValueListR15 != nil || v.CbrPsschTxConfigListV1530 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SlOffsetIndicatorR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.StartRBPSCCHPoolR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ZoneIDR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ThreshSRSSICBRR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.CbrPsschTxConfigListR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ResourceSelectionConfigP2XR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SyncAllowedR14 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.RestrictResourceReservationPeriodR14 != nil); err != nil {
		return err
	}
	if v.SlOffsetIndicatorR14 != nil {
		if err := v.SlOffsetIndicatorR14.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding sl-OffsetIndicator-r14: %w", err)
		}
	}
	if err := v.SlSubframeR14.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding sl-Subframe-r14: %w", err)
	}
	if err := per.EncodeBoolean(bb, v.AdjacencyPSCCHPSSCHR14); err != nil {
		return fmt.Errorf("encoding adjacencyPSCCH-PSSCH-r14: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.SizeSubchannelR14), 32, false); err != nil {
		return fmt.Errorf("encoding sizeSubchannel-r14: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.NumSubchannelR14), 8, false); err != nil {
		return fmt.Errorf("encoding numSubchannel-r14: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.StartRBSubchannelR14), int64Ptr(0), int64Ptr(99), false); err != nil {
		return fmt.Errorf("encoding startRB-Subchannel-r14: %w", err)
	}
	if v.StartRBPSCCHPoolR14 != nil {
		if err := per.EncodeInteger(bb, int64(*v.StartRBPSCCHPoolR14), int64Ptr(0), int64Ptr(99), false); err != nil {
			return fmt.Errorf("encoding startRB-PSCCH-Pool-r14: %w", err)
		}
	}
	if err := per.EncodeInteger(bb, int64(v.DataTxParametersR14), int64Ptr(-126), int64Ptr(31), false); err != nil {
		return fmt.Errorf("encoding dataTxParameters-r14: %w", err)
	}
	if v.ZoneIDR14 != nil {
		if err := per.EncodeInteger(bb, int64(*v.ZoneIDR14), int64Ptr(0), int64Ptr(7), false); err != nil {
			return fmt.Errorf("encoding zoneID-r14: %w", err)
		}
	}
	if v.ThreshSRSSICBRR14 != nil {
		if err := per.EncodeInteger(bb, int64(*v.ThreshSRSSICBRR14), int64Ptr(0), int64Ptr(45), false); err != nil {
			return fmt.Errorf("encoding threshS-RSSI-CBR-r14: %w", err)
		}
	}
	if v.CbrPsschTxConfigListR14 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.CbrPsschTxConfigListR14)), 1, 8); err != nil {
			return fmt.Errorf("encoding cbr-pssch-TxConfigList-r14 length: %w", err)
		}
		for _, elem := range v.CbrPsschTxConfigListR14 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding cbr-pssch-TxConfigList-r14 element: %w", err)
			}
		}
	}
	if v.ResourceSelectionConfigP2XR14 != nil {
		if err := v.ResourceSelectionConfigP2XR14.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding resourceSelectionConfigP2X-r14: %w", err)
		}
	}
	if v.SyncAllowedR14 != nil {
		if err := v.SyncAllowedR14.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding syncAllowed-r14: %w", err)
		}
	}
	if v.RestrictResourceReservationPeriodR14 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.RestrictResourceReservationPeriodR14)), 1, 16); err != nil {
			return fmt.Errorf("encoding restrictResourceReservationPeriod-r14 length: %w", err)
		}
		for _, elem := range v.RestrictResourceReservationPeriodR14 {
			if err := per.EncodeEnumerated(bb, int64(elem), 16, false); err != nil {
				return fmt.Errorf("encoding restrictResourceReservationPeriod-r14 element: %w", err)
			}
		}
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.SlMinT2ValueListR15 != nil || v.CbrPsschTxConfigListV1530 != nil {
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
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SlMinT2ValueListR15 != nil || v.CbrPsschTxConfigListV1530 != nil
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
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SlMinT2ValueListR15 != nil || v.CbrPsschTxConfigListV1530 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SlMinT2ValueListR15 != nil); err != nil {
				return err
			}
			if err := per.EncodeBoolean(extBuf, v.CbrPsschTxConfigListV1530 != nil); err != nil {
				return err
			}
			if v.SlMinT2ValueListR15 != nil {
				if err := per.EncodeConstrainedWholeNumber(extBuf, int64(len(v.SlMinT2ValueListR15)), 1, 8); err != nil {
					return fmt.Errorf("encoding sl-MinT2ValueList-r15 length: %w", err)
				}
				for _, elem := range v.SlMinT2ValueListR15 {
					if err := elem.MarshalUPERTo(extBuf); err != nil {
						return fmt.Errorf("encoding sl-MinT2ValueList-r15 element: %w", err)
					}
				}
			}
			if v.CbrPsschTxConfigListV1530 != nil {
				if err := per.EncodeConstrainedWholeNumber(extBuf, int64(len(v.CbrPsschTxConfigListV1530)), 1, 8); err != nil {
					return fmt.Errorf("encoding cbr-pssch-TxConfigList-v1530 length: %w", err)
				}
				for _, elem := range v.CbrPsschTxConfigListV1530 {
					if err := elem.MarshalUPERTo(extBuf); err != nil {
						return fmt.Errorf("encoding cbr-pssch-TxConfigList-v1530 element: %w", err)
					}
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

// UnmarshalUPER decodes SLV2XPreconfigCommPoolR14 from UPER format.
func (v *SLV2XPreconfigCommPoolR14) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLV2XPreconfigCommPoolR14) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_sloffsetindicatorr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_startrbpscchpoolr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_zoneidr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_threshsrssicbrr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_cbrpsschtxconfiglistr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_resourceselectionconfigp2xr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_syncallowedr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_restrictresourcereservationperiodr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_sloffsetindicatorr14 {
		var dec_sloffsetindicatorr14 SLOffsetIndicatorR12
		if err := dec_sloffsetindicatorr14.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding sl-OffsetIndicator-r14: %w", err)
		}
		v.SlOffsetIndicatorR14 = &dec_sloffsetindicatorr14
	}
	if err := v.SlSubframeR14.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding sl-Subframe-r14: %w", err)
	}
	val_adjacencypscchpsschr14, err := per.DecodeBoolean(bb)
	if err != nil {
		return fmt.Errorf("decoding adjacencyPSCCH-PSSCH-r14: %w", err)
	}
	v.AdjacencyPSCCHPSSCHR14 = val_adjacencypscchpsschr14
	val_sizesubchannelr14, err := per.DecodeEnumerated(bb, 32, false)
	if err != nil {
		return fmt.Errorf("decoding sizeSubchannel-r14: %w", err)
	}
	v.SizeSubchannelR14 = val_sizesubchannelr14
	val_numsubchannelr14, err := per.DecodeEnumerated(bb, 8, false)
	if err != nil {
		return fmt.Errorf("decoding numSubchannel-r14: %w", err)
	}
	v.NumSubchannelR14 = val_numsubchannelr14
	val_startrbsubchannelr14, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(99), false)
	if err != nil {
		return fmt.Errorf("decoding startRB-Subchannel-r14: %w", err)
	}
	v.StartRBSubchannelR14 = val_startrbsubchannelr14
	if opt_startrbpscchpoolr14 {
		val_startrbpscchpoolr14, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(99), false)
		if err != nil {
			return fmt.Errorf("decoding startRB-PSCCH-Pool-r14: %w", err)
		}
		v.StartRBPSCCHPoolR14 = &val_startrbpscchpoolr14
	}
	val_datatxparametersr14, err := per.DecodeInteger(bb, int64Ptr(-126), int64Ptr(31), false)
	if err != nil {
		return fmt.Errorf("decoding dataTxParameters-r14: %w", err)
	}
	v.DataTxParametersR14 = P0SLR12(val_datatxparametersr14)
	if opt_zoneidr14 {
		val_zoneidr14, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(7), false)
		if err != nil {
			return fmt.Errorf("decoding zoneID-r14: %w", err)
		}
		v.ZoneIDR14 = &val_zoneidr14
	}
	if opt_threshsrssicbrr14 {
		val_threshsrssicbrr14, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(45), false)
		if err != nil {
			return fmt.Errorf("decoding threshS-RSSI-CBR-r14: %w", err)
		}
		v.ThreshSRSSICBRR14 = &val_threshsrssicbrr14
	}
	if opt_cbrpsschtxconfiglistr14 {
		var seqLen_cbrpsschtxconfiglistr14 int64
		var errLength_cbrpsschtxconfiglistr14 error
		seqLen_cbrpsschtxconfiglistr14, errLength_cbrpsschtxconfiglistr14 = per.DecodeConstrainedWholeNumber(bb, 1, 8)
		if errLength_cbrpsschtxconfiglistr14 != nil {
			return fmt.Errorf("decoding cbr-pssch-TxConfigList-r14 length: %w", errLength_cbrpsschtxconfiglistr14)
		}
		if seqLen_cbrpsschtxconfiglistr14 < 1 {
			return fmt.Errorf("decoding cbr-pssch-TxConfigList-r14 length %d below lower bound 1", seqLen_cbrpsschtxconfiglistr14)
		}
		if seqLen_cbrpsschtxconfiglistr14 > 8 {
			return fmt.Errorf("decoding cbr-pssch-TxConfigList-r14 length %d above upper bound 8", seqLen_cbrpsschtxconfiglistr14)
		}
		tmp_cbrpsschtxconfiglistr14 := make(SLCBRPPPPTxPreconfigListR14, 0)
		for i := int64(0); i < seqLen_cbrpsschtxconfiglistr14; i++ {
			var elem SLPPPPTxPreconfigIndexR14
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding cbr-pssch-TxConfigList-r14 element %d: %w", i, err)
			}
			tmp_cbrpsschtxconfiglistr14 = append(tmp_cbrpsschtxconfiglistr14, elem)
		}
		v.CbrPsschTxConfigListR14 = tmp_cbrpsschtxconfiglistr14
	}
	if opt_resourceselectionconfigp2xr14 {
		var dec_resourceselectionconfigp2xr14 SLP2XResourceSelectionConfigR14
		if err := dec_resourceselectionconfigp2xr14.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding resourceSelectionConfigP2X-r14: %w", err)
		}
		v.ResourceSelectionConfigP2XR14 = &dec_resourceselectionconfigp2xr14
	}
	if opt_syncallowedr14 {
		var dec_syncallowedr14 SLSyncAllowedR14
		if err := dec_syncallowedr14.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding syncAllowed-r14: %w", err)
		}
		v.SyncAllowedR14 = &dec_syncallowedr14
	}
	if opt_restrictresourcereservationperiodr14 {
		var seqLen_restrictresourcereservationperiodr14 int64
		var errLength_restrictresourcereservationperiodr14 error
		seqLen_restrictresourcereservationperiodr14, errLength_restrictresourcereservationperiodr14 = per.DecodeConstrainedWholeNumber(bb, 1, 16)
		if errLength_restrictresourcereservationperiodr14 != nil {
			return fmt.Errorf("decoding restrictResourceReservationPeriod-r14 length: %w", errLength_restrictresourcereservationperiodr14)
		}
		if seqLen_restrictresourcereservationperiodr14 < 1 {
			return fmt.Errorf("decoding restrictResourceReservationPeriod-r14 length %d below lower bound 1", seqLen_restrictresourcereservationperiodr14)
		}
		if seqLen_restrictresourcereservationperiodr14 > 16 {
			return fmt.Errorf("decoding restrictResourceReservationPeriod-r14 length %d above upper bound 16", seqLen_restrictresourcereservationperiodr14)
		}
		tmp_restrictresourcereservationperiodr14 := make(SLRestrictResourceReservationPeriodListR14, 0)
		for i := int64(0); i < seqLen_restrictresourcereservationperiodr14; i++ {
			val, err := per.DecodeEnumerated(bb, 16, false)
			if err != nil {
				return fmt.Errorf("decoding restrictResourceReservationPeriod-r14 element %d: %w", i, err)
			}
			tmp_restrictresourcereservationperiodr14 = append(tmp_restrictresourcereservationperiodr14, SLRestrictResourceReservationPeriodR14(val))
		}
		v.RestrictResourceReservationPeriodR14 = tmp_restrictresourcereservationperiodr14
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
			ext_opt_slmint2valuelistr15, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			ext_opt_cbrpsschtxconfiglistv1530, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_slmint2valuelistr15 {
				var seqLen_slmint2valuelistr15 int64
				var errLength_slmint2valuelistr15 error
				seqLen_slmint2valuelistr15, errLength_slmint2valuelistr15 = per.DecodeConstrainedWholeNumber(extBB, 1, 8)
				if errLength_slmint2valuelistr15 != nil {
					return fmt.Errorf("decoding sl-MinT2ValueList-r15 length: %w", errLength_slmint2valuelistr15)
				}
				if seqLen_slmint2valuelistr15 < 1 {
					return fmt.Errorf("decoding sl-MinT2ValueList-r15 length %d below lower bound 1", seqLen_slmint2valuelistr15)
				}
				if seqLen_slmint2valuelistr15 > 8 {
					return fmt.Errorf("decoding sl-MinT2ValueList-r15 length %d above upper bound 8", seqLen_slmint2valuelistr15)
				}
				tmp_slmint2valuelistr15 := make(SLMinT2ValueListR15, 0)
				for i := int64(0); i < seqLen_slmint2valuelistr15; i++ {
					var elem SLMinT2ValueR15
					if err := elem.UnmarshalUPERFrom(extBB); err != nil {
						return fmt.Errorf("decoding sl-MinT2ValueList-r15 element %d: %w", i, err)
					}
					tmp_slmint2valuelistr15 = append(tmp_slmint2valuelistr15, elem)
				}
				v.SlMinT2ValueListR15 = tmp_slmint2valuelistr15
			}
			if ext_opt_cbrpsschtxconfiglistv1530 {
				var seqLen_cbrpsschtxconfiglistv1530 int64
				var errLength_cbrpsschtxconfiglistv1530 error
				seqLen_cbrpsschtxconfiglistv1530, errLength_cbrpsschtxconfiglistv1530 = per.DecodeConstrainedWholeNumber(extBB, 1, 8)
				if errLength_cbrpsschtxconfiglistv1530 != nil {
					return fmt.Errorf("decoding cbr-pssch-TxConfigList-v1530 length: %w", errLength_cbrpsschtxconfiglistv1530)
				}
				if seqLen_cbrpsschtxconfiglistv1530 < 1 {
					return fmt.Errorf("decoding cbr-pssch-TxConfigList-v1530 length %d below lower bound 1", seqLen_cbrpsschtxconfiglistv1530)
				}
				if seqLen_cbrpsschtxconfiglistv1530 > 8 {
					return fmt.Errorf("decoding cbr-pssch-TxConfigList-v1530 length %d above upper bound 8", seqLen_cbrpsschtxconfiglistv1530)
				}
				tmp_cbrpsschtxconfiglistv1530 := make(SLCBRPPPPTxPreconfigListV1530, 0)
				for i := int64(0); i < seqLen_cbrpsschtxconfiglistv1530; i++ {
					var elem SLPPPPTxPreconfigIndexV1530
					if err := elem.UnmarshalUPERFrom(extBB); err != nil {
						return fmt.Errorf("decoding cbr-pssch-TxConfigList-v1530 element %d: %w", i, err)
					}
					tmp_cbrpsschtxconfiglistv1530 = append(tmp_cbrpsschtxconfiglistv1530, elem)
				}
				v.CbrPsschTxConfigListV1530 = tmp_cbrpsschtxconfiglistv1530
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

// MarshalUPER encodes SLPreconfigV2XSyncR14 to UPER format.
func (v *SLPreconfigV2XSyncR14) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPreconfigV2XSyncR14) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0 || v.SlssTxDisabledR15 != nil
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := v.SyncOffsetIndicatorsR14.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding syncOffsetIndicators-r14: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.SyncTxParametersR14), int64Ptr(-126), int64Ptr(31), false); err != nil {
		return fmt.Errorf("encoding syncTxParameters-r14: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.SyncTxThreshOoCR14), int64Ptr(0), int64Ptr(11), false); err != nil {
		return fmt.Errorf("encoding syncTxThreshOoC-r14: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.FilterCoefficientR14), 16, true); err != nil {
		return fmt.Errorf("encoding filterCoefficient-r14: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.SyncRefMinHystR14), 5, false); err != nil {
		return fmt.Errorf("encoding syncRefMinHyst-r14: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.SyncRefDiffHystR14), 6, false); err != nil {
		return fmt.Errorf("encoding syncRefDiffHyst-r14: %w", err)
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.SlssTxDisabledR15 != nil {
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
			present0 := (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SlssTxDisabledR15 != nil
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
		if (int64(0) < int64(len(v.ExtPresent_)) && v.ExtPresent_[0]) || v.SlssTxDisabledR15 != nil {
			extBuf := per.NewBitBuffer()
			if err := per.EncodeBoolean(extBuf, v.SlssTxDisabledR15 != nil); err != nil {
				return err
			}
			if v.SlssTxDisabledR15 != nil {
				if err := per.EncodeEnumerated(extBuf, int64(*v.SlssTxDisabledR15), 1, false); err != nil {
					return fmt.Errorf("encoding slss-TxDisabled-r15: %w", err)
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

// UnmarshalUPER decodes SLPreconfigV2XSyncR14 from UPER format.
func (v *SLPreconfigV2XSyncR14) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPreconfigV2XSyncR14) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.SyncOffsetIndicatorsR14.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding syncOffsetIndicators-r14: %w", err)
	}
	val_synctxparametersr14, err := per.DecodeInteger(bb, int64Ptr(-126), int64Ptr(31), false)
	if err != nil {
		return fmt.Errorf("decoding syncTxParameters-r14: %w", err)
	}
	v.SyncTxParametersR14 = P0SLR12(val_synctxparametersr14)
	val_synctxthreshoocr14, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(11), false)
	if err != nil {
		return fmt.Errorf("decoding syncTxThreshOoC-r14: %w", err)
	}
	v.SyncTxThreshOoCR14 = RSRPRangeSL3R12(val_synctxthreshoocr14)
	val_filtercoefficientr14, err := per.DecodeEnumerated(bb, 16, true)
	if err != nil {
		return fmt.Errorf("decoding filterCoefficient-r14: %w", err)
	}
	v.FilterCoefficientR14 = FilterCoefficient(val_filtercoefficientr14)
	val_syncrefminhystr14, err := per.DecodeEnumerated(bb, 5, false)
	if err != nil {
		return fmt.Errorf("decoding syncRefMinHyst-r14: %w", err)
	}
	v.SyncRefMinHystR14 = val_syncrefminhystr14
	val_syncrefdiffhystr14, err := per.DecodeEnumerated(bb, 6, false)
	if err != nil {
		return fmt.Errorf("decoding syncRefDiffHyst-r14: %w", err)
	}
	v.SyncRefDiffHystR14 = val_syncrefdiffhystr14
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
			ext_opt_slsstxdisabledr15, err := per.DecodeBoolean(extBB)
			if err != nil {
				return err
			}
			if ext_opt_slsstxdisabledr15 {
				val_slsstxdisabledr15, err := per.DecodeEnumerated(extBB, 1, false)
				if err != nil {
					return fmt.Errorf("decoding slss-TxDisabled-r15: %w", err)
				}
				v.SlssTxDisabledR15 = &val_slsstxdisabledr15
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

// MarshalUPER encodes SLV2XSyncOffsetIndicatorsR14 to UPER format.
func (v *SLV2XSyncOffsetIndicatorsR14) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLV2XSyncOffsetIndicatorsR14) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SyncOffsetIndicator3R14 != nil); err != nil {
		return err
	}
	if err := per.EncodeInteger(bb, int64(v.SyncOffsetIndicator1R14), int64Ptr(0), int64Ptr(159), false); err != nil {
		return fmt.Errorf("encoding syncOffsetIndicator1-r14: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.SyncOffsetIndicator2R14), int64Ptr(0), int64Ptr(159), false); err != nil {
		return fmt.Errorf("encoding syncOffsetIndicator2-r14: %w", err)
	}
	if v.SyncOffsetIndicator3R14 != nil {
		if err := per.EncodeInteger(bb, int64(*v.SyncOffsetIndicator3R14), int64Ptr(0), int64Ptr(159), false); err != nil {
			return fmt.Errorf("encoding syncOffsetIndicator3-r14: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes SLV2XSyncOffsetIndicatorsR14 from UPER format.
func (v *SLV2XSyncOffsetIndicatorsR14) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLV2XSyncOffsetIndicatorsR14) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	// Read preamble bitmap for optional root fields
	opt_syncoffsetindicator3r14, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_syncoffsetindicator1r14, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(159), false)
	if err != nil {
		return fmt.Errorf("decoding syncOffsetIndicator1-r14: %w", err)
	}
	v.SyncOffsetIndicator1R14 = SLOffsetIndicatorSyncR14(val_syncoffsetindicator1r14)
	val_syncoffsetindicator2r14, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(159), false)
	if err != nil {
		return fmt.Errorf("decoding syncOffsetIndicator2-r14: %w", err)
	}
	v.SyncOffsetIndicator2R14 = SLOffsetIndicatorSyncR14(val_syncoffsetindicator2r14)
	if opt_syncoffsetindicator3r14 {
		val_syncoffsetindicator3r14, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(159), false)
		if err != nil {
			return fmt.Errorf("decoding syncOffsetIndicator3-r14: %w", err)
		}
		tmp_syncoffsetindicator3r14 := SLOffsetIndicatorSyncR14(val_syncoffsetindicator3r14)
		v.SyncOffsetIndicator3R14 = &tmp_syncoffsetindicator3r14
	}
	return nil
}

type asn1cUPERSLCBRPPPPTxPreconfigListR14ListValue struct{ Value SLCBRPPPPTxPreconfigListR14 }

// MarshalUPERSLCBRPPPPTxPreconfigListR14 encodes a SLCBRPPPPTxPreconfigListR14 list to UPER.
func MarshalUPERSLCBRPPPPTxPreconfigListR14(list SLCBRPPPPTxPreconfigListR14) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLCBRPPPPTxPreconfigListR14To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLCBRPPPPTxPreconfigListR14To appends a SLCBRPPPPTxPreconfigListR14 list to bb.
func MarshalUPERSLCBRPPPPTxPreconfigListR14To(list SLCBRPPPPTxPreconfigListR14, bb *per.BitBuffer) error {
	v := asn1cUPERSLCBRPPPPTxPreconfigListR14ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 8); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLCBRPPPPTxPreconfigListR14 decodes a SLCBRPPPPTxPreconfigListR14 list from UPER.
func UnmarshalUPERSLCBRPPPPTxPreconfigListR14(data []byte) (SLCBRPPPPTxPreconfigListR14, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLCBRPPPPTxPreconfigListR14From(bb)
}

// UnmarshalUPERSLCBRPPPPTxPreconfigListR14From decodes a SLCBRPPPPTxPreconfigListR14 list from bb.
func UnmarshalUPERSLCBRPPPPTxPreconfigListR14From(bb *per.BitBuffer) (SLCBRPPPPTxPreconfigListR14, error) {
	var v asn1cUPERSLCBRPPPPTxPreconfigListR14ListValue
	if err := unmarshalUPERSLCBRPPPPTxPreconfigListR14Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLCBRPPPPTxPreconfigListR14Into(v *asn1cUPERSLCBRPPPPTxPreconfigListR14ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 8)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 8 {
		return fmt.Errorf("decoding value length %d above upper bound 8", seqLen_value)
	}
	v.Value = make(SLCBRPPPPTxPreconfigListR14, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem SLPPPPTxPreconfigIndexR14
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

// MarshalUPER encodes SLPPPPTxPreconfigIndexR14 to UPER format.
func (v *SLPPPPTxPreconfigIndexR14) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPPPPTxPreconfigIndexR14) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.PriorityThresholdR14), int64Ptr(1), int64Ptr(8), false); err != nil {
		return fmt.Errorf("encoding priorityThreshold-r14: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.DefaultTxConfigIndexR14), int64Ptr(0), int64Ptr(15), false); err != nil {
		return fmt.Errorf("encoding defaultTxConfigIndex-r14: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.CbrConfigIndexR14), int64Ptr(0), int64Ptr(7), false); err != nil {
		return fmt.Errorf("encoding cbr-ConfigIndex-r14: %w", err)
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.TxConfigIndexListR14)), 1, 16); err != nil {
		return fmt.Errorf("encoding tx-ConfigIndexList-r14 length: %w", err)
	}
	for _, elem := range v.TxConfigIndexListR14 {
		if err := per.EncodeInteger(bb, int64(elem), int64Ptr(0), int64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding tx-ConfigIndexList-r14 element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes SLPPPPTxPreconfigIndexR14 from UPER format.
func (v *SLPPPPTxPreconfigIndexR14) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPPPPTxPreconfigIndexR14) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	val_prioritythresholdr14, err := per.DecodeInteger(bb, int64Ptr(1), int64Ptr(8), false)
	if err != nil {
		return fmt.Errorf("decoding priorityThreshold-r14: %w", err)
	}
	v.PriorityThresholdR14 = SLPriorityR13(val_prioritythresholdr14)
	val_defaulttxconfigindexr14, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(15), false)
	if err != nil {
		return fmt.Errorf("decoding defaultTxConfigIndex-r14: %w", err)
	}
	v.DefaultTxConfigIndexR14 = val_defaulttxconfigindexr14
	val_cbrconfigindexr14, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(7), false)
	if err != nil {
		return fmt.Errorf("decoding cbr-ConfigIndex-r14: %w", err)
	}
	v.CbrConfigIndexR14 = val_cbrconfigindexr14
	var seqLen_txconfigindexlistr14 int64
	var errLength_txconfigindexlistr14 error
	seqLen_txconfigindexlistr14, errLength_txconfigindexlistr14 = per.DecodeConstrainedWholeNumber(bb, 1, 16)
	if errLength_txconfigindexlistr14 != nil {
		return fmt.Errorf("decoding tx-ConfigIndexList-r14 length: %w", errLength_txconfigindexlistr14)
	}
	if seqLen_txconfigindexlistr14 < 1 {
		return fmt.Errorf("decoding tx-ConfigIndexList-r14 length %d below lower bound 1", seqLen_txconfigindexlistr14)
	}
	if seqLen_txconfigindexlistr14 > 16 {
		return fmt.Errorf("decoding tx-ConfigIndexList-r14 length %d above upper bound 16", seqLen_txconfigindexlistr14)
	}
	v.TxConfigIndexListR14 = make(SLPPPPTxPreconfigIndexR14TxConfigIndexListR14, 0)
	for i := int64(0); i < seqLen_txconfigindexlistr14; i++ {
		val, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(127), false)
		if err != nil {
			return fmt.Errorf("decoding tx-ConfigIndexList-r14 element %d: %w", i, err)
		}
		v.TxConfigIndexListR14 = append(v.TxConfigIndexListR14, TxPreconfigIndexR14(val))
	}
	return nil
}

type asn1cUPERSLCBRPPPPTxPreconfigListV1530ListValue struct{ Value SLCBRPPPPTxPreconfigListV1530 }

// MarshalUPERSLCBRPPPPTxPreconfigListV1530 encodes a SLCBRPPPPTxPreconfigListV1530 list to UPER.
func MarshalUPERSLCBRPPPPTxPreconfigListV1530(list SLCBRPPPPTxPreconfigListV1530) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLCBRPPPPTxPreconfigListV1530To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLCBRPPPPTxPreconfigListV1530To appends a SLCBRPPPPTxPreconfigListV1530 list to bb.
func MarshalUPERSLCBRPPPPTxPreconfigListV1530To(list SLCBRPPPPTxPreconfigListV1530, bb *per.BitBuffer) error {
	v := asn1cUPERSLCBRPPPPTxPreconfigListV1530ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 8); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLCBRPPPPTxPreconfigListV1530 decodes a SLCBRPPPPTxPreconfigListV1530 list from UPER.
func UnmarshalUPERSLCBRPPPPTxPreconfigListV1530(data []byte) (SLCBRPPPPTxPreconfigListV1530, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLCBRPPPPTxPreconfigListV1530From(bb)
}

// UnmarshalUPERSLCBRPPPPTxPreconfigListV1530From decodes a SLCBRPPPPTxPreconfigListV1530 list from bb.
func UnmarshalUPERSLCBRPPPPTxPreconfigListV1530From(bb *per.BitBuffer) (SLCBRPPPPTxPreconfigListV1530, error) {
	var v asn1cUPERSLCBRPPPPTxPreconfigListV1530ListValue
	if err := unmarshalUPERSLCBRPPPPTxPreconfigListV1530Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLCBRPPPPTxPreconfigListV1530Into(v *asn1cUPERSLCBRPPPPTxPreconfigListV1530ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 8)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 8 {
		return fmt.Errorf("decoding value length %d above upper bound 8", seqLen_value)
	}
	v.Value = make(SLCBRPPPPTxPreconfigListV1530, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem SLPPPPTxPreconfigIndexV1530
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

// MarshalUPER encodes SLPPPPTxPreconfigIndexV1530 to UPER format.
func (v *SLPPPPTxPreconfigIndexV1530) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPPPPTxPreconfigIndexV1530) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.McsPSSCHRangeR15 != nil); err != nil {
		return err
	}
	if v.McsPSSCHRangeR15 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.McsPSSCHRangeR15)), 1, 16); err != nil {
			return fmt.Errorf("encoding mcs-PSSCH-Range-r15 length: %w", err)
		}
		for _, elem := range v.McsPSSCHRangeR15 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding mcs-PSSCH-Range-r15 element: %w", err)
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes SLPPPPTxPreconfigIndexV1530 from UPER format.
func (v *SLPPPPTxPreconfigIndexV1530) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPPPPTxPreconfigIndexV1530) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	// Read preamble bitmap for optional root fields
	opt_mcspsschranger15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_mcspsschranger15 {
		var seqLen_mcspsschranger15 int64
		var errLength_mcspsschranger15 error
		seqLen_mcspsschranger15, errLength_mcspsschranger15 = per.DecodeConstrainedWholeNumber(bb, 1, 16)
		if errLength_mcspsschranger15 != nil {
			return fmt.Errorf("decoding mcs-PSSCH-Range-r15 length: %w", errLength_mcspsschranger15)
		}
		if seqLen_mcspsschranger15 < 1 {
			return fmt.Errorf("decoding mcs-PSSCH-Range-r15 length %d below lower bound 1", seqLen_mcspsschranger15)
		}
		if seqLen_mcspsschranger15 > 16 {
			return fmt.Errorf("decoding mcs-PSSCH-Range-r15 length %d above upper bound 16", seqLen_mcspsschranger15)
		}
		tmp_mcspsschranger15 := make(SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15, 0)
		for i := int64(0); i < seqLen_mcspsschranger15; i++ {
			var elem MCSPSSCHRangeR15
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding mcs-PSSCH-Range-r15 element %d: %w", i, err)
			}
			tmp_mcspsschranger15 = append(tmp_mcspsschranger15, elem)
		}
		v.McsPSSCHRangeR15 = tmp_mcspsschranger15
	}
	return nil
}

type asn1cUPERSLV2XTxProfileListR15ListValue struct{ Value SLV2XTxProfileListR15 }

// MarshalUPERSLV2XTxProfileListR15 encodes a SLV2XTxProfileListR15 list to UPER.
func MarshalUPERSLV2XTxProfileListR15(list SLV2XTxProfileListR15) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLV2XTxProfileListR15To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLV2XTxProfileListR15To appends a SLV2XTxProfileListR15 list to bb.
func MarshalUPERSLV2XTxProfileListR15To(list SLV2XTxProfileListR15, bb *per.BitBuffer) error {
	v := asn1cUPERSLV2XTxProfileListR15ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 256); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := per.EncodeEnumerated(bb, int64(elem), 8, true); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLV2XTxProfileListR15 decodes a SLV2XTxProfileListR15 list from UPER.
func UnmarshalUPERSLV2XTxProfileListR15(data []byte) (SLV2XTxProfileListR15, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLV2XTxProfileListR15From(bb)
}

// UnmarshalUPERSLV2XTxProfileListR15From decodes a SLV2XTxProfileListR15 list from bb.
func UnmarshalUPERSLV2XTxProfileListR15From(bb *per.BitBuffer) (SLV2XTxProfileListR15, error) {
	var v asn1cUPERSLV2XTxProfileListR15ListValue
	if err := unmarshalUPERSLV2XTxProfileListR15Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLV2XTxProfileListR15Into(v *asn1cUPERSLV2XTxProfileListR15ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 256)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 256 {
		return fmt.Errorf("decoding value length %d above upper bound 256", seqLen_value)
	}
	v.Value = make(SLV2XTxProfileListR15, 0)
	for i := int64(0); i < seqLen_value; i++ {
		val, err := per.DecodeEnumerated(bb, 8, true)
		if err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, SLV2XTxProfileR15(val))
	}
	return nil
}

// MarshalUPER encodes SLPreconfigurationR12PreconfigCommV1310 to UPER format.
func (v *SLPreconfigurationR12PreconfigCommV1310) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPreconfigurationR12PreconfigCommV1310) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.CommTxPoolListR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.CommRxPoolListR13)), 1, 12); err != nil {
		return fmt.Errorf("encoding commRxPoolList-r13 length: %w", err)
	}
	for _, elem := range v.CommRxPoolListR13 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding commRxPoolList-r13 element: %w", err)
		}
	}
	if v.CommTxPoolListR13 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.CommTxPoolListR13)), 1, 7); err != nil {
			return fmt.Errorf("encoding commTxPoolList-r13 length: %w", err)
		}
		for _, elem := range v.CommTxPoolListR13 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding commTxPoolList-r13 element: %w", err)
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes SLPreconfigurationR12PreconfigCommV1310 from UPER format.
func (v *SLPreconfigurationR12PreconfigCommV1310) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPreconfigurationR12PreconfigCommV1310) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	// Read preamble bitmap for optional root fields
	opt_commtxpoollistr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	var seqLen_commrxpoollistr13 int64
	var errLength_commrxpoollistr13 error
	seqLen_commrxpoollistr13, errLength_commrxpoollistr13 = per.DecodeConstrainedWholeNumber(bb, 1, 12)
	if errLength_commrxpoollistr13 != nil {
		return fmt.Errorf("decoding commRxPoolList-r13 length: %w", errLength_commrxpoollistr13)
	}
	if seqLen_commrxpoollistr13 < 1 {
		return fmt.Errorf("decoding commRxPoolList-r13 length %d below lower bound 1", seqLen_commrxpoollistr13)
	}
	if seqLen_commrxpoollistr13 > 12 {
		return fmt.Errorf("decoding commRxPoolList-r13 length %d above upper bound 12", seqLen_commrxpoollistr13)
	}
	v.CommRxPoolListR13 = make(SLPreconfigCommRxPoolListR13, 0)
	for i := int64(0); i < seqLen_commrxpoollistr13; i++ {
		var elem SLPreconfigCommPoolR12
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding commRxPoolList-r13 element %d: %w", i, err)
		}
		v.CommRxPoolListR13 = append(v.CommRxPoolListR13, elem)
	}
	if opt_commtxpoollistr13 {
		var seqLen_commtxpoollistr13 int64
		var errLength_commtxpoollistr13 error
		seqLen_commtxpoollistr13, errLength_commtxpoollistr13 = per.DecodeConstrainedWholeNumber(bb, 1, 7)
		if errLength_commtxpoollistr13 != nil {
			return fmt.Errorf("decoding commTxPoolList-r13 length: %w", errLength_commtxpoollistr13)
		}
		if seqLen_commtxpoollistr13 < 1 {
			return fmt.Errorf("decoding commTxPoolList-r13 length %d below lower bound 1", seqLen_commtxpoollistr13)
		}
		if seqLen_commtxpoollistr13 > 7 {
			return fmt.Errorf("decoding commTxPoolList-r13 length %d above upper bound 7", seqLen_commtxpoollistr13)
		}
		tmp_commtxpoollistr13 := make(SLPreconfigCommTxPoolListR13, 0)
		for i := int64(0); i < seqLen_commtxpoollistr13; i++ {
			var elem SLPreconfigCommPoolR12
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding commTxPoolList-r13 element %d: %w", i, err)
			}
			tmp_commtxpoollistr13 = append(tmp_commtxpoollistr13, elem)
		}
		v.CommTxPoolListR13 = tmp_commtxpoollistr13
	}
	return nil
}

// MarshalUPER encodes SLPreconfigurationR12PreconfigDiscR13 to UPER format.
func (v *SLPreconfigurationR12PreconfigDiscR13) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPreconfigurationR12PreconfigDiscR13) MarshalUPERTo(bb *per.BitBuffer) error {
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.DiscTxPoolListR13 != nil); err != nil {
		return err
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.DiscRxPoolListR13)), 1, 16); err != nil {
		return fmt.Errorf("encoding discRxPoolList-r13 length: %w", err)
	}
	for _, elem := range v.DiscRxPoolListR13 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding discRxPoolList-r13 element: %w", err)
		}
	}
	if v.DiscTxPoolListR13 != nil {
		if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.DiscTxPoolListR13)), 1, 4); err != nil {
			return fmt.Errorf("encoding discTxPoolList-r13 length: %w", err)
		}
		for _, elem := range v.DiscTxPoolListR13 {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding discTxPoolList-r13 element: %w", err)
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes SLPreconfigurationR12PreconfigDiscR13 from UPER format.
func (v *SLPreconfigurationR12PreconfigDiscR13) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPreconfigurationR12PreconfigDiscR13) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	// Read preamble bitmap for optional root fields
	opt_disctxpoollistr13, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	var seqLen_discrxpoollistr13 int64
	var errLength_discrxpoollistr13 error
	seqLen_discrxpoollistr13, errLength_discrxpoollistr13 = per.DecodeConstrainedWholeNumber(bb, 1, 16)
	if errLength_discrxpoollistr13 != nil {
		return fmt.Errorf("decoding discRxPoolList-r13 length: %w", errLength_discrxpoollistr13)
	}
	if seqLen_discrxpoollistr13 < 1 {
		return fmt.Errorf("decoding discRxPoolList-r13 length %d below lower bound 1", seqLen_discrxpoollistr13)
	}
	if seqLen_discrxpoollistr13 > 16 {
		return fmt.Errorf("decoding discRxPoolList-r13 length %d above upper bound 16", seqLen_discrxpoollistr13)
	}
	v.DiscRxPoolListR13 = make(SLPreconfigDiscRxPoolListR13, 0)
	for i := int64(0); i < seqLen_discrxpoollistr13; i++ {
		var elem SLPreconfigDiscPoolR13
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding discRxPoolList-r13 element %d: %w", i, err)
		}
		v.DiscRxPoolListR13 = append(v.DiscRxPoolListR13, elem)
	}
	if opt_disctxpoollistr13 {
		var seqLen_disctxpoollistr13 int64
		var errLength_disctxpoollistr13 error
		seqLen_disctxpoollistr13, errLength_disctxpoollistr13 = per.DecodeConstrainedWholeNumber(bb, 1, 4)
		if errLength_disctxpoollistr13 != nil {
			return fmt.Errorf("decoding discTxPoolList-r13 length: %w", errLength_disctxpoollistr13)
		}
		if seqLen_disctxpoollistr13 < 1 {
			return fmt.Errorf("decoding discTxPoolList-r13 length %d below lower bound 1", seqLen_disctxpoollistr13)
		}
		if seqLen_disctxpoollistr13 > 4 {
			return fmt.Errorf("decoding discTxPoolList-r13 length %d above upper bound 4", seqLen_disctxpoollistr13)
		}
		tmp_disctxpoollistr13 := make(SLPreconfigDiscTxPoolListR13, 0)
		for i := int64(0); i < seqLen_disctxpoollistr13; i++ {
			var elem SLPreconfigDiscPoolR13
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return fmt.Errorf("decoding discTxPoolList-r13 element %d: %w", i, err)
			}
			tmp_disctxpoollistr13 = append(tmp_disctxpoollistr13, elem)
		}
		v.DiscTxPoolListR13 = tmp_disctxpoollistr13
	}
	return nil
}

// MarshalUPER encodes SLPreconfigGeneralR12RohcProfilesR12 to UPER format.
func (v *SLPreconfigGeneralR12RohcProfilesR12) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPreconfigGeneralR12RohcProfilesR12) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeBoolean(bb, v.Profile0x0001R12); err != nil {
		return fmt.Errorf("encoding profile0x0001-r12: %w", err)
	}
	if err := per.EncodeBoolean(bb, v.Profile0x0002R12); err != nil {
		return fmt.Errorf("encoding profile0x0002-r12: %w", err)
	}
	if err := per.EncodeBoolean(bb, v.Profile0x0004R12); err != nil {
		return fmt.Errorf("encoding profile0x0004-r12: %w", err)
	}
	if err := per.EncodeBoolean(bb, v.Profile0x0006R12); err != nil {
		return fmt.Errorf("encoding profile0x0006-r12: %w", err)
	}
	if err := per.EncodeBoolean(bb, v.Profile0x0101R12); err != nil {
		return fmt.Errorf("encoding profile0x0101-r12: %w", err)
	}
	if err := per.EncodeBoolean(bb, v.Profile0x0102R12); err != nil {
		return fmt.Errorf("encoding profile0x0102-r12: %w", err)
	}
	if err := per.EncodeBoolean(bb, v.Profile0x0104R12); err != nil {
		return fmt.Errorf("encoding profile0x0104-r12: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes SLPreconfigGeneralR12RohcProfilesR12 from UPER format.
func (v *SLPreconfigGeneralR12RohcProfilesR12) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPreconfigGeneralR12RohcProfilesR12) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	val_profile0x0001r12, err := per.DecodeBoolean(bb)
	if err != nil {
		return fmt.Errorf("decoding profile0x0001-r12: %w", err)
	}
	v.Profile0x0001R12 = val_profile0x0001r12
	val_profile0x0002r12, err := per.DecodeBoolean(bb)
	if err != nil {
		return fmt.Errorf("decoding profile0x0002-r12: %w", err)
	}
	v.Profile0x0002R12 = val_profile0x0002r12
	val_profile0x0004r12, err := per.DecodeBoolean(bb)
	if err != nil {
		return fmt.Errorf("decoding profile0x0004-r12: %w", err)
	}
	v.Profile0x0004R12 = val_profile0x0004r12
	val_profile0x0006r12, err := per.DecodeBoolean(bb)
	if err != nil {
		return fmt.Errorf("decoding profile0x0006-r12: %w", err)
	}
	v.Profile0x0006R12 = val_profile0x0006r12
	val_profile0x0101r12, err := per.DecodeBoolean(bb)
	if err != nil {
		return fmt.Errorf("decoding profile0x0101-r12: %w", err)
	}
	v.Profile0x0101R12 = val_profile0x0101r12
	val_profile0x0102r12, err := per.DecodeBoolean(bb)
	if err != nil {
		return fmt.Errorf("decoding profile0x0102-r12: %w", err)
	}
	v.Profile0x0102R12 = val_profile0x0102r12
	val_profile0x0104r12, err := per.DecodeBoolean(bb)
	if err != nil {
		return fmt.Errorf("decoding profile0x0104-r12: %w", err)
	}
	v.Profile0x0104R12 = val_profile0x0104r12
	return nil
}

// MarshalUPER encodes SLPreconfigDiscPoolR13TxParametersR13 to UPER format.
func (v *SLPreconfigDiscPoolR13TxParametersR13) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *SLPreconfigDiscPoolR13TxParametersR13) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.TxParametersGeneralR13), int64Ptr(-126), int64Ptr(31), false); err != nil {
		return fmt.Errorf("encoding txParametersGeneral-r13: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.TxProbabilityR13), 4, false); err != nil {
		return fmt.Errorf("encoding txProbability-r13: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes SLPreconfigDiscPoolR13TxParametersR13 from UPER format.
func (v *SLPreconfigDiscPoolR13TxParametersR13) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *SLPreconfigDiscPoolR13TxParametersR13) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	val_txparametersgeneralr13, err := per.DecodeInteger(bb, int64Ptr(-126), int64Ptr(31), false)
	if err != nil {
		return fmt.Errorf("decoding txParametersGeneral-r13: %w", err)
	}
	v.TxParametersGeneralR13 = P0SLR12(val_txparametersgeneralr13)
	val_txprobabilityr13, err := per.DecodeEnumerated(bb, 4, false)
	if err != nil {
		return fmt.Errorf("decoding txProbability-r13: %w", err)
	}
	v.TxProbabilityR13 = val_txprobabilityr13
	return nil
}

type asn1cUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14ListValue struct {
	Value SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14
}

// MarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14 encodes a SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14 list to UPER.
func MarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14(list SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14To appends a SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14 list to bb.
func MarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14To(list SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14, bb *per.BitBuffer) error {
	v := asn1cUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 8); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, outerElem := range v.Value {
		if err := MarshalUPERSLCBRLevelsConfigR14To(outerElem, bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14 decodes a SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14 list from UPER.
func UnmarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14(data []byte) (SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14From(bb)
}

// UnmarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14From decodes a SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14 list from bb.
func UnmarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14From(bb *per.BitBuffer) (SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14, error) {
	var v asn1cUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14ListValue
	if err := unmarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14Into(v *asn1cUPERSLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 8)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 8 {
		return fmt.Errorf("decoding value length %d above upper bound 8", seqLen_value)
	}
	v.Value = make(SLCBRPreconfigTxConfigListR14CbrRangeCommonConfigListR14, 0)
	for i_value := int64(0); i_value < seqLen_value; i_value++ {
		elem, err := UnmarshalUPERSLCBRLevelsConfigR14From(bb)
		if err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

type asn1cUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14ListValue struct {
	Value SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14
}

// MarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14 encodes a SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14 list to UPER.
func MarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14(list SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14To appends a SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14 list to bb.
func MarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14To(list SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14, bb *per.BitBuffer) error {
	v := asn1cUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 128); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14 decodes a SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14 list from UPER.
func UnmarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14(data []byte) (SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14From(bb)
}

// UnmarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14From decodes a SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14 list from bb.
func UnmarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14From(bb *per.BitBuffer) (SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14, error) {
	var v asn1cUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14ListValue
	if err := unmarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14Into(v *asn1cUPERSLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 128)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 128 {
		return fmt.Errorf("decoding value length %d above upper bound 128", seqLen_value)
	}
	v.Value = make(SLCBRPreconfigTxConfigListR14SlCBRPSSCHTxConfigListR14, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem SLCBRPSSCHTxConfigR14
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}

type asn1cUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14ListValue struct {
	Value SLPPPPTxPreconfigIndexR14TxConfigIndexListR14
}

// MarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14 encodes a SLPPPPTxPreconfigIndexR14TxConfigIndexListR14 list to UPER.
func MarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14(list SLPPPPTxPreconfigIndexR14TxConfigIndexListR14) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14To appends a SLPPPPTxPreconfigIndexR14TxConfigIndexListR14 list to bb.
func MarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14To(list SLPPPPTxPreconfigIndexR14TxConfigIndexListR14, bb *per.BitBuffer) error {
	v := asn1cUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 16); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := per.EncodeInteger(bb, int64(elem), int64Ptr(0), int64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14 decodes a SLPPPPTxPreconfigIndexR14TxConfigIndexListR14 list from UPER.
func UnmarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14(data []byte) (SLPPPPTxPreconfigIndexR14TxConfigIndexListR14, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14From(bb)
}

// UnmarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14From decodes a SLPPPPTxPreconfigIndexR14TxConfigIndexListR14 list from bb.
func UnmarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14From(bb *per.BitBuffer) (SLPPPPTxPreconfigIndexR14TxConfigIndexListR14, error) {
	var v asn1cUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14ListValue
	if err := unmarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14Into(v *asn1cUPERSLPPPPTxPreconfigIndexR14TxConfigIndexListR14ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 16)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 16 {
		return fmt.Errorf("decoding value length %d above upper bound 16", seqLen_value)
	}
	v.Value = make(SLPPPPTxPreconfigIndexR14TxConfigIndexListR14, 0)
	for i := int64(0); i < seqLen_value; i++ {
		val, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(127), false)
		if err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, TxPreconfigIndexR14(val))
	}
	return nil
}

type asn1cUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15ListValue struct {
	Value SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15
}

// MarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15 encodes a SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15 list to UPER.
func MarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15(list SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15To appends a SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15 list to bb.
func MarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15To(list SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15, bb *per.BitBuffer) error {
	v := asn1cUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 16); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15 decodes a SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15 list from UPER.
func UnmarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15(data []byte) (SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15From(bb)
}

// UnmarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15From decodes a SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15 list from bb.
func UnmarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15From(bb *per.BitBuffer) (SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15, error) {
	var v asn1cUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15ListValue
	if err := unmarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15Into(v *asn1cUPERSLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15ListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumber(bb, 1, 16)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 16 {
		return fmt.Errorf("decoding value length %d above upper bound 16", seqLen_value)
	}
	v.Value = make(SLPPPPTxPreconfigIndexV1530McsPSSCHRangeR15, 0)
	for i := int64(0); i < seqLen_value; i++ {
		var elem MCSPSSCHRangeR15
		if err := elem.UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element %d: %w", i, err)
		}
		v.Value = append(v.Value, elem)
	}
	return nil
}
