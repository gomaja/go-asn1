// Code generated from ASN.1 module "S1AP-PDU-Contents". DO NOT EDIT.

package s1ap

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

// ERABIEContainerList represents the ASN.1 type E-RAB-IE-ContainerList (SEQUENCE_OF).
type ERABIEContainerList = []ProtocolIESingleContainer

// ERABIEContainerPairList represents the ASN.1 type E-RAB-IE-ContainerPairList (SEQUENCE_OF).
type ERABIEContainerPairList = []ProtocolIEContainerPair

// ProtocolErrorIEContainerList represents the ASN.1 type ProtocolError-IE-ContainerList (SEQUENCE_OF).
type ProtocolErrorIEContainerList = []ProtocolIESingleContainer

// HandoverRequired represents the ASN.1 type HandoverRequired (SEQUENCE).
type HandoverRequired struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// HandoverCommand represents the ASN.1 type HandoverCommand (SEQUENCE).
type HandoverCommand struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABSubjecttoDataForwardingList represents the ASN.1 type E-RABSubjecttoDataForwardingList (SEQUENCE_OF).
type ERABSubjecttoDataForwardingList = []ProtocolIESingleContainer

// ERABDataForwardingItem represents the ASN.1 type E-RABDataForwardingItem (SEQUENCE).
type ERABDataForwardingItem struct {
	ERABID                  ERABID                     `asn1:"tag:0,context,implicit"`
	DLTransportLayerAddress *TransportLayerAddress     `asn1:"tag:1,context,implicit,optional" json:"DLTransportLayerAddress,omitempty"`
	DLGTPTEID               *GTPTEID                   `asn1:"tag:2,context,implicit,optional" json:"DLGTPTEID,omitempty"`
	ULTransportLayerAddress *TransportLayerAddress     `asn1:"tag:3,context,implicit,optional" json:"ULTransportLayerAddress,omitempty"`
	ULGTPTEID               *GTPTEID                   `asn1:"tag:4,context,implicit,optional" json:"ULGTPTEID,omitempty"`
	IEExtensions            ProtocolExtensionContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_      bool                       `asn1:"-" json:"-"`
	ExtCount_               int64                      `asn1:"-" json:"-"`
	ExtPresent_             []bool                     `asn1:"-" json:"-"`
	ExtData_                [][]byte                   `asn1:"-" json:"-"`
}

// HandoverPreparationFailure represents the ASN.1 type HandoverPreparationFailure (SEQUENCE).
type HandoverPreparationFailure struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// HandoverRequest represents the ASN.1 type HandoverRequest (SEQUENCE).
type HandoverRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABToBeSetupListHOReq represents the ASN.1 type E-RABToBeSetupListHOReq (SEQUENCE_OF).
type ERABToBeSetupListHOReq = []ProtocolIESingleContainer

// ERABToBeSetupItemHOReq represents the ASN.1 type E-RABToBeSetupItemHOReq (SEQUENCE).
type ERABToBeSetupItemHOReq struct {
	ERABID                 ERABID                     `asn1:"tag:0,context,implicit"`
	TransportLayerAddress  TransportLayerAddress      `asn1:"tag:1,context,implicit"`
	GTPTEID                GTPTEID                    `asn1:"tag:2,context,implicit"`
	ERABlevelQosParameters ERABLevelQoSParameters     `asn1:"tag:3,context,implicit"`
	IEExtensions           ProtocolExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_     bool                       `asn1:"-" json:"-"`
	ExtCount_              int64                      `asn1:"-" json:"-"`
	ExtPresent_            []bool                     `asn1:"-" json:"-"`
	ExtData_               [][]byte                   `asn1:"-" json:"-"`
}

// HandoverRequestAcknowledge represents the ASN.1 type HandoverRequestAcknowledge (SEQUENCE).
type HandoverRequestAcknowledge struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABAdmittedList represents the ASN.1 type E-RABAdmittedList (SEQUENCE_OF).
type ERABAdmittedList = []ProtocolIESingleContainer

// ERABAdmittedItem represents the ASN.1 type E-RABAdmittedItem (SEQUENCE).
type ERABAdmittedItem struct {
	ERABID                  ERABID                     `asn1:"tag:0,context,implicit"`
	TransportLayerAddress   TransportLayerAddress      `asn1:"tag:1,context,implicit"`
	GTPTEID                 GTPTEID                    `asn1:"tag:2,context,implicit"`
	DLTransportLayerAddress *TransportLayerAddress     `asn1:"tag:3,context,implicit,optional" json:"DLTransportLayerAddress,omitempty"`
	DLGTPTEID               *GTPTEID                   `asn1:"tag:4,context,implicit,optional" json:"DLGTPTEID,omitempty"`
	ULTransportLayerAddress *TransportLayerAddress     `asn1:"tag:5,context,implicit,optional" json:"ULTransportLayerAddress,omitempty"`
	ULGTPTEID               *GTPTEID                   `asn1:"tag:6,context,implicit,optional" json:"ULGTPTEID,omitempty"`
	IEExtensions            ProtocolExtensionContainer `asn1:"tag:7,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_      bool                       `asn1:"-" json:"-"`
	ExtCount_               int64                      `asn1:"-" json:"-"`
	ExtPresent_             []bool                     `asn1:"-" json:"-"`
	ExtData_                [][]byte                   `asn1:"-" json:"-"`
}

// ERABFailedtoSetupListHOReqAck represents the ASN.1 type E-RABFailedtoSetupListHOReqAck (SEQUENCE_OF).
type ERABFailedtoSetupListHOReqAck = []ProtocolIESingleContainer

// ERABFailedToSetupItemHOReqAck represents the ASN.1 type E-RABFailedToSetupItemHOReqAck (SEQUENCE).
type ERABFailedToSetupItemHOReqAck struct {
	ERABID             ERABID                     `asn1:"tag:0,context,implicit"`
	Cause              Cause                      `asn1:"tag:1,context,explicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
}

// HandoverFailure represents the ASN.1 type HandoverFailure (SEQUENCE).
type HandoverFailure struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// HandoverNotify represents the ASN.1 type HandoverNotify (SEQUENCE).
type HandoverNotify struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// PathSwitchRequest represents the ASN.1 type PathSwitchRequest (SEQUENCE).
type PathSwitchRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABToBeSwitchedDLList represents the ASN.1 type E-RABToBeSwitchedDLList (SEQUENCE_OF).
type ERABToBeSwitchedDLList = []ProtocolIESingleContainer

// ERABToBeSwitchedDLItem represents the ASN.1 type E-RABToBeSwitchedDLItem (SEQUENCE).
type ERABToBeSwitchedDLItem struct {
	ERABID                ERABID                     `asn1:"tag:0,context,implicit"`
	TransportLayerAddress TransportLayerAddress      `asn1:"tag:1,context,implicit"`
	GTPTEID               GTPTEID                    `asn1:"tag:2,context,implicit"`
	IEExtensions          ProtocolExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_    bool                       `asn1:"-" json:"-"`
	ExtCount_             int64                      `asn1:"-" json:"-"`
	ExtPresent_           []bool                     `asn1:"-" json:"-"`
	ExtData_              [][]byte                   `asn1:"-" json:"-"`
}

// PathSwitchRequestAcknowledge represents the ASN.1 type PathSwitchRequestAcknowledge (SEQUENCE).
type PathSwitchRequestAcknowledge struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABToBeSwitchedULList represents the ASN.1 type E-RABToBeSwitchedULList (SEQUENCE_OF).
type ERABToBeSwitchedULList = []ProtocolIESingleContainer

// ERABToBeSwitchedULItem represents the ASN.1 type E-RABToBeSwitchedULItem (SEQUENCE).
type ERABToBeSwitchedULItem struct {
	ERABID                ERABID                     `asn1:"tag:0,context,implicit"`
	TransportLayerAddress TransportLayerAddress      `asn1:"tag:1,context,implicit"`
	GTPTEID               GTPTEID                    `asn1:"tag:2,context,implicit"`
	IEExtensions          ProtocolExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_    bool                       `asn1:"-" json:"-"`
	ExtCount_             int64                      `asn1:"-" json:"-"`
	ExtPresent_           []bool                     `asn1:"-" json:"-"`
	ExtData_              [][]byte                   `asn1:"-" json:"-"`
}

// ERABToBeUpdatedList represents the ASN.1 type E-RABToBeUpdatedList (SEQUENCE_OF).
type ERABToBeUpdatedList = []ProtocolIESingleContainer

// ERABToBeUpdatedItem represents the ASN.1 type E-RABToBeUpdatedItem (SEQUENCE).
type ERABToBeUpdatedItem struct {
	ERABID             ERABID                     `asn1:"tag:0,context,implicit"`
	SecurityIndication *SecurityIndication        `asn1:"tag:1,context,implicit,optional" json:"SecurityIndication,omitempty"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
}

// PathSwitchRequestFailure represents the ASN.1 type PathSwitchRequestFailure (SEQUENCE).
type PathSwitchRequestFailure struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// HandoverCancel represents the ASN.1 type HandoverCancel (SEQUENCE).
type HandoverCancel struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// HandoverCancelAcknowledge represents the ASN.1 type HandoverCancelAcknowledge (SEQUENCE).
type HandoverCancelAcknowledge struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// HandoverSuccess represents the ASN.1 type HandoverSuccess (SEQUENCE).
type HandoverSuccess struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ENBEarlyStatusTransfer represents the ASN.1 type ENBEarlyStatusTransfer (SEQUENCE).
type ENBEarlyStatusTransfer struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// MMEEarlyStatusTransfer represents the ASN.1 type MMEEarlyStatusTransfer (SEQUENCE).
type MMEEarlyStatusTransfer struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABSetupRequest represents the ASN.1 type E-RABSetupRequest (SEQUENCE).
type ERABSetupRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABToBeSetupListBearerSUReq represents the ASN.1 type E-RABToBeSetupListBearerSUReq (SEQUENCE_OF).
type ERABToBeSetupListBearerSUReq = []ProtocolIESingleContainer

// ERABToBeSetupItemBearerSUReq represents the ASN.1 type E-RABToBeSetupItemBearerSUReq (SEQUENCE).
type ERABToBeSetupItemBearerSUReq struct {
	ERABID                 ERABID                     `asn1:"tag:0,context,implicit"`
	ERABlevelQoSParameters ERABLevelQoSParameters     `asn1:"tag:1,context,implicit"`
	TransportLayerAddress  TransportLayerAddress      `asn1:"tag:2,context,implicit"`
	GTPTEID                GTPTEID                    `asn1:"tag:3,context,implicit"`
	NASPDU                 NASPDU                     `asn1:"tag:4,context,implicit"`
	IEExtensions           ProtocolExtensionContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_     bool                       `asn1:"-" json:"-"`
	ExtCount_              int64                      `asn1:"-" json:"-"`
	ExtPresent_            []bool                     `asn1:"-" json:"-"`
	ExtData_               [][]byte                   `asn1:"-" json:"-"`
}

// ERABSetupResponse represents the ASN.1 type E-RABSetupResponse (SEQUENCE).
type ERABSetupResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABSetupListBearerSURes represents the ASN.1 type E-RABSetupListBearerSURes (SEQUENCE_OF).
type ERABSetupListBearerSURes = []ProtocolIESingleContainer

// ERABSetupItemBearerSURes represents the ASN.1 type E-RABSetupItemBearerSURes (SEQUENCE).
type ERABSetupItemBearerSURes struct {
	ERABID                ERABID                     `asn1:"tag:0,context,implicit"`
	TransportLayerAddress TransportLayerAddress      `asn1:"tag:1,context,implicit"`
	GTPTEID               GTPTEID                    `asn1:"tag:2,context,implicit"`
	IEExtensions          ProtocolExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_    bool                       `asn1:"-" json:"-"`
	ExtCount_             int64                      `asn1:"-" json:"-"`
	ExtPresent_           []bool                     `asn1:"-" json:"-"`
	ExtData_              [][]byte                   `asn1:"-" json:"-"`
}

// ERABModifyRequest represents the ASN.1 type E-RABModifyRequest (SEQUENCE).
type ERABModifyRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABToBeModifiedListBearerModReq represents the ASN.1 type E-RABToBeModifiedListBearerModReq (SEQUENCE_OF).
type ERABToBeModifiedListBearerModReq = []ProtocolIESingleContainer

// ERABToBeModifiedItemBearerModReq represents the ASN.1 type E-RABToBeModifiedItemBearerModReq (SEQUENCE).
type ERABToBeModifiedItemBearerModReq struct {
	ERABID                 ERABID                     `asn1:"tag:0,context,implicit"`
	ERABLevelQoSParameters ERABLevelQoSParameters     `asn1:"tag:1,context,implicit"`
	NASPDU                 NASPDU                     `asn1:"tag:2,context,implicit"`
	IEExtensions           ProtocolExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_     bool                       `asn1:"-" json:"-"`
	ExtCount_              int64                      `asn1:"-" json:"-"`
	ExtPresent_            []bool                     `asn1:"-" json:"-"`
	ExtData_               [][]byte                   `asn1:"-" json:"-"`
}

// ERABModifyResponse represents the ASN.1 type E-RABModifyResponse (SEQUENCE).
type ERABModifyResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABModifyListBearerModRes represents the ASN.1 type E-RABModifyListBearerModRes (SEQUENCE_OF).
type ERABModifyListBearerModRes = []ProtocolIESingleContainer

// ERABModifyItemBearerModRes represents the ASN.1 type E-RABModifyItemBearerModRes (SEQUENCE).
type ERABModifyItemBearerModRes struct {
	ERABID             ERABID                     `asn1:"tag:0,context,implicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
}

// ERABReleaseCommand represents the ASN.1 type E-RABReleaseCommand (SEQUENCE).
type ERABReleaseCommand struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABReleaseResponse represents the ASN.1 type E-RABReleaseResponse (SEQUENCE).
type ERABReleaseResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABReleaseListBearerRelComp represents the ASN.1 type E-RABReleaseListBearerRelComp (SEQUENCE_OF).
type ERABReleaseListBearerRelComp = []ProtocolIESingleContainer

// ERABReleaseItemBearerRelComp represents the ASN.1 type E-RABReleaseItemBearerRelComp (SEQUENCE).
type ERABReleaseItemBearerRelComp struct {
	ERABID             ERABID                     `asn1:"tag:0,context,implicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
}

// ERABReleaseIndication represents the ASN.1 type E-RABReleaseIndication (SEQUENCE).
type ERABReleaseIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// InitialContextSetupRequest represents the ASN.1 type InitialContextSetupRequest (SEQUENCE).
type InitialContextSetupRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABToBeSetupListCtxtSUReq represents the ASN.1 type E-RABToBeSetupListCtxtSUReq (SEQUENCE_OF).
type ERABToBeSetupListCtxtSUReq = []ProtocolIESingleContainer

// ERABToBeSetupItemCtxtSUReq represents the ASN.1 type E-RABToBeSetupItemCtxtSUReq (SEQUENCE).
type ERABToBeSetupItemCtxtSUReq struct {
	ERABID                 ERABID                     `asn1:"tag:0,context,implicit"`
	ERABlevelQoSParameters ERABLevelQoSParameters     `asn1:"tag:1,context,implicit"`
	TransportLayerAddress  TransportLayerAddress      `asn1:"tag:2,context,implicit"`
	GTPTEID                GTPTEID                    `asn1:"tag:3,context,implicit"`
	NASPDU                 *NASPDU                    `asn1:"tag:4,context,implicit,optional" json:"NASPDU,omitempty"`
	IEExtensions           ProtocolExtensionContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_     bool                       `asn1:"-" json:"-"`
	ExtCount_              int64                      `asn1:"-" json:"-"`
	ExtPresent_            []bool                     `asn1:"-" json:"-"`
	ExtData_               [][]byte                   `asn1:"-" json:"-"`
}

// InitialContextSetupResponse represents the ASN.1 type InitialContextSetupResponse (SEQUENCE).
type InitialContextSetupResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABSetupListCtxtSURes represents the ASN.1 type E-RABSetupListCtxtSURes (SEQUENCE_OF).
type ERABSetupListCtxtSURes = []ProtocolIESingleContainer

// ERABSetupItemCtxtSURes represents the ASN.1 type E-RABSetupItemCtxtSURes (SEQUENCE).
type ERABSetupItemCtxtSURes struct {
	ERABID                ERABID                     `asn1:"tag:0,context,implicit"`
	TransportLayerAddress TransportLayerAddress      `asn1:"tag:1,context,implicit"`
	GTPTEID               GTPTEID                    `asn1:"tag:2,context,implicit"`
	IEExtensions          ProtocolExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_    bool                       `asn1:"-" json:"-"`
	ExtCount_             int64                      `asn1:"-" json:"-"`
	ExtPresent_           []bool                     `asn1:"-" json:"-"`
	ExtData_              [][]byte                   `asn1:"-" json:"-"`
}

// InitialContextSetupFailure represents the ASN.1 type InitialContextSetupFailure (SEQUENCE).
type InitialContextSetupFailure struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// Paging represents the ASN.1 type Paging (SEQUENCE).
type Paging struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// TAIList represents the ASN.1 type TAIList (SEQUENCE_OF).
type TAIList = []ProtocolIESingleContainer

// TAIItem represents the ASN.1 type TAIItem (SEQUENCE).
type TAIItem struct {
	TAI                TAI                        `asn1:"tag:0,context,implicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
}

// UEContextReleaseRequest represents the ASN.1 type UEContextReleaseRequest (SEQUENCE).
type UEContextReleaseRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UEContextReleaseCommand represents the ASN.1 type UEContextReleaseCommand (SEQUENCE).
type UEContextReleaseCommand struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UEContextReleaseComplete represents the ASN.1 type UEContextReleaseComplete (SEQUENCE).
type UEContextReleaseComplete struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UEContextModificationRequest represents the ASN.1 type UEContextModificationRequest (SEQUENCE).
type UEContextModificationRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UEContextModificationResponse represents the ASN.1 type UEContextModificationResponse (SEQUENCE).
type UEContextModificationResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UEContextModificationFailure represents the ASN.1 type UEContextModificationFailure (SEQUENCE).
type UEContextModificationFailure struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UERadioCapabilityMatchRequest represents the ASN.1 type UERadioCapabilityMatchRequest (SEQUENCE).
type UERadioCapabilityMatchRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UERadioCapabilityMatchResponse represents the ASN.1 type UERadioCapabilityMatchResponse (SEQUENCE).
type UERadioCapabilityMatchResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// DownlinkNASTransport represents the ASN.1 type DownlinkNASTransport (SEQUENCE).
type DownlinkNASTransport struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// InitialUEMessage represents the ASN.1 type InitialUEMessage (SEQUENCE).
type InitialUEMessage struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UplinkNASTransport represents the ASN.1 type UplinkNASTransport (SEQUENCE).
type UplinkNASTransport struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// NASNonDeliveryIndication represents the ASN.1 type NASNonDeliveryIndication (SEQUENCE).
type NASNonDeliveryIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// RerouteNASRequest represents the ASN.1 type RerouteNASRequest (SEQUENCE).
type RerouteNASRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// S1Message represents the ASN.1 type S1-Message (OCTET_STRING).
type S1Message = []byte

// NASDeliveryIndication represents the ASN.1 type NASDeliveryIndication (SEQUENCE).
type NASDeliveryIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// Reset represents the ASN.1 type Reset (SEQUENCE).
type Reset struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ResetType choice constants.
const (
	ResetTypeChoiceS1Interface       = 1
	ResetTypeChoicePartOfS1Interface = 2
)

// ResetType represents the ASN.1 CHOICE type ResetType.
type ResetType struct {
	Choice            int
	UnknownExtension  *runtime.PERChoiceExtension            `json:"UnknownExtension,omitempty"`
	S1Interface       *ResetAll                              `json:"S1Interface,omitempty"`
	PartOfS1Interface UEAssociatedLogicalS1ConnectionListRes `json:"PartOfS1Interface,omitempty"`
}

// NewResetTypeS1Interface creates a ResetType with the s1-Interface alternative.
func NewResetTypeS1Interface(v ResetAll) ResetType {
	return ResetType{
		Choice:      ResetTypeChoiceS1Interface,
		S1Interface: &v,
	}
}

// NewResetTypePartOfS1Interface creates a ResetType with the partOfS1-Interface alternative.
func NewResetTypePartOfS1Interface(v UEAssociatedLogicalS1ConnectionListRes) ResetType {
	return ResetType{
		Choice:            ResetTypeChoicePartOfS1Interface,
		PartOfS1Interface: v,
	}
}

// ResetAll represents the ASN.1 ENUMERATED type ResetAll.
type ResetAll int64

const (
	ResetAllResetAll ResetAll = 0
)

func (v ResetAll) String() string {
	switch v {
	case ResetAllResetAll:
		return "reset-all"
	default:
		return "unknown"
	}
}

// UEAssociatedLogicalS1ConnectionListRes represents the ASN.1 type UE-associatedLogicalS1-ConnectionListRes (SEQUENCE_OF).
type UEAssociatedLogicalS1ConnectionListRes = []ProtocolIESingleContainer

// ResetAcknowledge represents the ASN.1 type ResetAcknowledge (SEQUENCE).
type ResetAcknowledge struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UEAssociatedLogicalS1ConnectionListResAck represents the ASN.1 type UE-associatedLogicalS1-ConnectionListResAck (SEQUENCE_OF).
type UEAssociatedLogicalS1ConnectionListResAck = []ProtocolIESingleContainer

// ErrorIndication represents the ASN.1 type ErrorIndication (SEQUENCE).
type ErrorIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// S1SetupRequest represents the ASN.1 type S1SetupRequest (SEQUENCE).
type S1SetupRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// S1SetupResponse represents the ASN.1 type S1SetupResponse (SEQUENCE).
type S1SetupResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// S1SetupFailure represents the ASN.1 type S1SetupFailure (SEQUENCE).
type S1SetupFailure struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ENBConfigurationUpdate represents the ASN.1 type ENBConfigurationUpdate (SEQUENCE).
type ENBConfigurationUpdate struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ENBConfigurationUpdateAcknowledge represents the ASN.1 type ENBConfigurationUpdateAcknowledge (SEQUENCE).
type ENBConfigurationUpdateAcknowledge struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ENBConfigurationUpdateFailure represents the ASN.1 type ENBConfigurationUpdateFailure (SEQUENCE).
type ENBConfigurationUpdateFailure struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// MMEConfigurationUpdate represents the ASN.1 type MMEConfigurationUpdate (SEQUENCE).
type MMEConfigurationUpdate struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// MMEConfigurationUpdateAcknowledge represents the ASN.1 type MMEConfigurationUpdateAcknowledge (SEQUENCE).
type MMEConfigurationUpdateAcknowledge struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// MMEConfigurationUpdateFailure represents the ASN.1 type MMEConfigurationUpdateFailure (SEQUENCE).
type MMEConfigurationUpdateFailure struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// DownlinkS1cdma2000tunnelling represents the ASN.1 type DownlinkS1cdma2000tunnelling (SEQUENCE).
type DownlinkS1cdma2000tunnelling struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UplinkS1cdma2000tunnelling represents the ASN.1 type UplinkS1cdma2000tunnelling (SEQUENCE).
type UplinkS1cdma2000tunnelling struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UECapabilityInfoIndication represents the ASN.1 type UECapabilityInfoIndication (SEQUENCE).
type UECapabilityInfoIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ENBStatusTransfer represents the ASN.1 type ENBStatusTransfer (SEQUENCE).
type ENBStatusTransfer struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// MMEStatusTransfer represents the ASN.1 type MMEStatusTransfer (SEQUENCE).
type MMEStatusTransfer struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// TraceStart represents the ASN.1 type TraceStart (SEQUENCE).
type TraceStart struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// TraceFailureIndication represents the ASN.1 type TraceFailureIndication (SEQUENCE).
type TraceFailureIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// DeactivateTrace represents the ASN.1 type DeactivateTrace (SEQUENCE).
type DeactivateTrace struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// CellTrafficTrace represents the ASN.1 type CellTrafficTrace (SEQUENCE).
type CellTrafficTrace struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// LocationReportingControl represents the ASN.1 type LocationReportingControl (SEQUENCE).
type LocationReportingControl struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// LocationReportingFailureIndication represents the ASN.1 type LocationReportingFailureIndication (SEQUENCE).
type LocationReportingFailureIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// LocationReport represents the ASN.1 type LocationReport (SEQUENCE).
type LocationReport struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// OverloadStart represents the ASN.1 type OverloadStart (SEQUENCE).
type OverloadStart struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// OverloadStop represents the ASN.1 type OverloadStop (SEQUENCE).
type OverloadStop struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// WriteReplaceWarningRequest represents the ASN.1 type WriteReplaceWarningRequest (SEQUENCE).
type WriteReplaceWarningRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// WriteReplaceWarningResponse represents the ASN.1 type WriteReplaceWarningResponse (SEQUENCE).
type WriteReplaceWarningResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ENBDirectInformationTransfer represents the ASN.1 type ENBDirectInformationTransfer (SEQUENCE).
type ENBDirectInformationTransfer struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// InterSystemInformationTransferType choice constants.
const (
	InterSystemInformationTransferTypeChoiceRIMTransfer = 1
)

// InterSystemInformationTransferType represents the ASN.1 CHOICE type Inter-SystemInformationTransferType.
type InterSystemInformationTransferType struct {
	Choice           int
	UnknownExtension *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	RIMTransfer      *RIMTransfer                `json:"RIMTransfer,omitempty"`
}

// NewInterSystemInformationTransferTypeRIMTransfer creates a InterSystemInformationTransferType with the rIMTransfer alternative.
func NewInterSystemInformationTransferTypeRIMTransfer(v RIMTransfer) InterSystemInformationTransferType {
	return InterSystemInformationTransferType{
		Choice:      InterSystemInformationTransferTypeChoiceRIMTransfer,
		RIMTransfer: &v,
	}
}

// MMEDirectInformationTransfer represents the ASN.1 type MMEDirectInformationTransfer (SEQUENCE).
type MMEDirectInformationTransfer struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ENBConfigurationTransfer represents the ASN.1 type ENBConfigurationTransfer (SEQUENCE).
type ENBConfigurationTransfer struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// MMEConfigurationTransfer represents the ASN.1 type MMEConfigurationTransfer (SEQUENCE).
type MMEConfigurationTransfer struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// PrivateMessage represents the ASN.1 type PrivateMessage (SEQUENCE).
type PrivateMessage struct {
	PrivateIEs       PrivateIEContainer `asn1:"tag:0,context,implicit"`
	PrivateIEsIndef_ bool               `asn1:"-" json:"-"`
	ExtCount_        int64              `asn1:"-" json:"-"`
	ExtPresent_      []bool             `asn1:"-" json:"-"`
	ExtData_         [][]byte           `asn1:"-" json:"-"`
}

// KillRequest represents the ASN.1 type KillRequest (SEQUENCE).
type KillRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// KillResponse represents the ASN.1 type KillResponse (SEQUENCE).
type KillResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// PWSRestartIndication represents the ASN.1 type PWSRestartIndication (SEQUENCE).
type PWSRestartIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// PWSFailureIndication represents the ASN.1 type PWSFailureIndication (SEQUENCE).
type PWSFailureIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// DownlinkUEAssociatedLPPaTransport represents the ASN.1 type DownlinkUEAssociatedLPPaTransport (SEQUENCE).
type DownlinkUEAssociatedLPPaTransport struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UplinkUEAssociatedLPPaTransport represents the ASN.1 type UplinkUEAssociatedLPPaTransport (SEQUENCE).
type UplinkUEAssociatedLPPaTransport struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// DownlinkNonUEAssociatedLPPaTransport represents the ASN.1 type DownlinkNonUEAssociatedLPPaTransport (SEQUENCE).
type DownlinkNonUEAssociatedLPPaTransport struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UplinkNonUEAssociatedLPPaTransport represents the ASN.1 type UplinkNonUEAssociatedLPPaTransport (SEQUENCE).
type UplinkNonUEAssociatedLPPaTransport struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABModificationIndication represents the ASN.1 type E-RABModificationIndication (SEQUENCE).
type ERABModificationIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABToBeModifiedListBearerModInd represents the ASN.1 type E-RABToBeModifiedListBearerModInd (SEQUENCE_OF).
type ERABToBeModifiedListBearerModInd = []ProtocolIESingleContainer

// ERABToBeModifiedItemBearerModInd represents the ASN.1 type E-RABToBeModifiedItemBearerModInd (SEQUENCE).
type ERABToBeModifiedItemBearerModInd struct {
	ERABID                ERABID                     `asn1:"tag:0,context,implicit"`
	TransportLayerAddress TransportLayerAddress      `asn1:"tag:1,context,implicit"`
	DLGTPTEID             GTPTEID                    `asn1:"tag:2,context,implicit"`
	IEExtensions          ProtocolExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_    bool                       `asn1:"-" json:"-"`
	ExtCount_             int64                      `asn1:"-" json:"-"`
	ExtPresent_           []bool                     `asn1:"-" json:"-"`
	ExtData_              [][]byte                   `asn1:"-" json:"-"`
}

// ERABNotToBeModifiedListBearerModInd represents the ASN.1 type E-RABNotToBeModifiedListBearerModInd (SEQUENCE_OF).
type ERABNotToBeModifiedListBearerModInd = []ProtocolIESingleContainer

// ERABNotToBeModifiedItemBearerModInd represents the ASN.1 type E-RABNotToBeModifiedItemBearerModInd (SEQUENCE).
type ERABNotToBeModifiedItemBearerModInd struct {
	ERABID                ERABID                     `asn1:"tag:0,context,implicit"`
	TransportLayerAddress TransportLayerAddress      `asn1:"tag:1,context,implicit"`
	DLGTPTEID             GTPTEID                    `asn1:"tag:2,context,implicit"`
	IEExtensions          ProtocolExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_    bool                       `asn1:"-" json:"-"`
	ExtCount_             int64                      `asn1:"-" json:"-"`
	ExtPresent_           []bool                     `asn1:"-" json:"-"`
	ExtData_              [][]byte                   `asn1:"-" json:"-"`
}

// CSGMembershipInfo represents the ASN.1 type CSGMembershipInfo (SEQUENCE).
type CSGMembershipInfo struct {
	CSGMembershipStatus CSGMembershipStatus        `asn1:"tag:0,context,implicit"`
	CSGId               CSGId                      `asn1:"tag:1,context,implicit"`
	CellAccessMode      *CellAccessMode            `asn1:"tag:2,context,implicit,optional" json:"CellAccessMode,omitempty"`
	PLMNidentity        *PLMNidentity              `asn1:"tag:3,context,implicit,optional" json:"PLMNidentity,omitempty"`
	IEExtensions        ProtocolExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_  bool                       `asn1:"-" json:"-"`
	ExtCount_           int64                      `asn1:"-" json:"-"`
	ExtPresent_         []bool                     `asn1:"-" json:"-"`
	ExtData_            [][]byte                   `asn1:"-" json:"-"`
}

// ERABModificationConfirm represents the ASN.1 type E-RABModificationConfirm (SEQUENCE).
type ERABModificationConfirm struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABModifyListBearerModConf represents the ASN.1 type E-RABModifyListBearerModConf (SEQUENCE_OF).
type ERABModifyListBearerModConf = []ProtocolIESingleContainer

// ERABModifyItemBearerModConf represents the ASN.1 type E-RABModifyItemBearerModConf (SEQUENCE).
type ERABModifyItemBearerModConf struct {
	ERABID             ERABID                     `asn1:"tag:0,context,implicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
}

// UEContextModificationIndication represents the ASN.1 type UEContextModificationIndication (SEQUENCE).
type UEContextModificationIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UEContextModificationConfirm represents the ASN.1 type UEContextModificationConfirm (SEQUENCE).
type UEContextModificationConfirm struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UEContextSuspendRequest represents the ASN.1 type UEContextSuspendRequest (SEQUENCE).
type UEContextSuspendRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UEContextSuspendResponse represents the ASN.1 type UEContextSuspendResponse (SEQUENCE).
type UEContextSuspendResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UEContextResumeRequest represents the ASN.1 type UEContextResumeRequest (SEQUENCE).
type UEContextResumeRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABFailedToResumeListResumeReq represents the ASN.1 type E-RABFailedToResumeListResumeReq (SEQUENCE_OF).
type ERABFailedToResumeListResumeReq = []ProtocolIESingleContainer

// ERABFailedToResumeItemResumeReq represents the ASN.1 type E-RABFailedToResumeItemResumeReq (SEQUENCE).
type ERABFailedToResumeItemResumeReq struct {
	ERABID             ERABID                     `asn1:"tag:0,context,implicit"`
	Cause              Cause                      `asn1:"tag:1,context,explicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
}

// UEContextResumeResponse represents the ASN.1 type UEContextResumeResponse (SEQUENCE).
type UEContextResumeResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ERABFailedToResumeListResumeRes represents the ASN.1 type E-RABFailedToResumeListResumeRes (SEQUENCE_OF).
type ERABFailedToResumeListResumeRes = []ProtocolIESingleContainer

// ERABFailedToResumeItemResumeRes represents the ASN.1 type E-RABFailedToResumeItemResumeRes (SEQUENCE).
type ERABFailedToResumeItemResumeRes struct {
	ERABID             ERABID                     `asn1:"tag:0,context,implicit"`
	Cause              Cause                      `asn1:"tag:1,context,explicit"`
	IEExtensions       ProtocolExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitempty"`
	IEExtensionsIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_          int64                      `asn1:"-" json:"-"`
	ExtPresent_        []bool                     `asn1:"-" json:"-"`
	ExtData_           [][]byte                   `asn1:"-" json:"-"`
}

// UEContextResumeFailure represents the ASN.1 type UEContextResumeFailure (SEQUENCE).
type UEContextResumeFailure struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ConnectionEstablishmentIndication represents the ASN.1 type ConnectionEstablishmentIndication (SEQUENCE).
type ConnectionEstablishmentIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// RetrieveUEInformation represents the ASN.1 type RetrieveUEInformation (SEQUENCE).
type RetrieveUEInformation struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UEInformationTransfer represents the ASN.1 type UEInformationTransfer (SEQUENCE).
type UEInformationTransfer struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ENBCPRelocationIndication represents the ASN.1 type ENBCPRelocationIndication (SEQUENCE).
type ENBCPRelocationIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// MMECPRelocationIndication represents the ASN.1 type MMECPRelocationIndication (SEQUENCE).
type MMECPRelocationIndication struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// SecondaryRATDataUsageReport represents the ASN.1 type SecondaryRATDataUsageReport (SEQUENCE).
type SecondaryRATDataUsageReport struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UERadioCapabilityIDMappingRequest represents the ASN.1 type UERadioCapabilityIDMappingRequest (SEQUENCE).
type UERadioCapabilityIDMappingRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// UERadioCapabilityIDMappingResponse represents the ASN.1 type UERadioCapabilityIDMappingResponse (SEQUENCE).
type UERadioCapabilityIDMappingResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// S1RemovalRequest represents the ASN.1 type S1RemovalRequest (SEQUENCE).
type S1RemovalRequest struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// S1RemovalResponse represents the ASN.1 type S1RemovalResponse (SEQUENCE).
type S1RemovalResponse struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// S1RemovalFailure represents the ASN.1 type S1RemovalFailure (SEQUENCE).
type S1RemovalFailure struct {
	ProtocolIEs       ProtocolIEContainer `asn1:"tag:0,context,implicit"`
	ProtocolIEsIndef_ bool                `asn1:"-" json:"-"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

type asn1cAPERERABIEContainerListListValue struct{ Value ERABIEContainerList }

// MarshalAPERERABIEContainerList encodes a ERABIEContainerList list to APER.
func MarshalAPERERABIEContainerList(list ERABIEContainerList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABIEContainerListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABIEContainerListTo appends a ERABIEContainerList list to bb.
func MarshalAPERERABIEContainerListTo(list ERABIEContainerList, bb *per.BitBuffer) error {
	v := asn1cAPERERABIEContainerListListValue{Value: list}
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

// UnmarshalAPERERABIEContainerList decodes a ERABIEContainerList list from APER.
func UnmarshalAPERERABIEContainerList(data []byte) (ERABIEContainerList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABIEContainerListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABIEContainerList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABIEContainerList")
	}
	return value, nil
}

// UnmarshalAPERERABIEContainerListFrom decodes a ERABIEContainerList list from bb.
func UnmarshalAPERERABIEContainerListFrom(bb *per.BitBuffer) (ERABIEContainerList, error) {
	var v asn1cAPERERABIEContainerListListValue
	if err := unmarshalAPERERABIEContainerListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABIEContainerListInto(v *asn1cAPERERABIEContainerListListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABIEContainerList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

type asn1cAPERERABIEContainerPairListListValue struct{ Value ERABIEContainerPairList }

// MarshalAPERERABIEContainerPairList encodes a ERABIEContainerPairList list to APER.
func MarshalAPERERABIEContainerPairList(list ERABIEContainerPairList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABIEContainerPairListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABIEContainerPairListTo appends a ERABIEContainerPairList list to bb.
func MarshalAPERERABIEContainerPairListTo(list ERABIEContainerPairList, bb *per.BitBuffer) error {
	v := asn1cAPERERABIEContainerPairListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, outerElem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := MarshalAPERProtocolIEContainerPairTo(outerElem, bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERERABIEContainerPairList decodes a ERABIEContainerPairList list from APER.
func UnmarshalAPERERABIEContainerPairList(data []byte) (ERABIEContainerPairList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABIEContainerPairListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABIEContainerPairList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABIEContainerPairList")
	}
	return value, nil
}

// UnmarshalAPERERABIEContainerPairListFrom decodes a ERABIEContainerPairList list from bb.
func UnmarshalAPERERABIEContainerPairListFrom(bb *per.BitBuffer) (ERABIEContainerPairList, error) {
	var v asn1cAPERERABIEContainerPairListListValue
	if err := unmarshalAPERERABIEContainerPairListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABIEContainerPairListInto(v *asn1cAPERERABIEContainerPairListListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABIEContainerPairList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i_value := int64(0); i_value < fragmentLength_value; i_value++ {
			elem, err := UnmarshalAPERProtocolIEContainerPairFrom(bb)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i_value))
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

type asn1cAPERProtocolErrorIEContainerListListValue struct{ Value ProtocolErrorIEContainerList }

// MarshalAPERProtocolErrorIEContainerList encodes a ProtocolErrorIEContainerList list to APER.
func MarshalAPERProtocolErrorIEContainerList(list ProtocolErrorIEContainerList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERProtocolErrorIEContainerListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERProtocolErrorIEContainerListTo appends a ProtocolErrorIEContainerList list to bb.
func MarshalAPERProtocolErrorIEContainerListTo(list ProtocolErrorIEContainerList, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolErrorIEContainerListListValue{Value: list}
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

// UnmarshalAPERProtocolErrorIEContainerList decodes a ProtocolErrorIEContainerList list from APER.
func UnmarshalAPERProtocolErrorIEContainerList(data []byte) (ProtocolErrorIEContainerList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERProtocolErrorIEContainerListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolErrorIEContainerList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolErrorIEContainerList")
	}
	return value, nil
}

// UnmarshalAPERProtocolErrorIEContainerListFrom decodes a ProtocolErrorIEContainerList list from bb.
func UnmarshalAPERProtocolErrorIEContainerListFrom(bb *per.BitBuffer) (ProtocolErrorIEContainerList, error) {
	var v asn1cAPERProtocolErrorIEContainerListListValue
	if err := unmarshalAPERProtocolErrorIEContainerListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERProtocolErrorIEContainerListInto(v *asn1cAPERProtocolErrorIEContainerListListValue, bb *per.BitBuffer) error {
	v.Value = make(ProtocolErrorIEContainerList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes HandoverRequired to APER format.
func (v *HandoverRequired) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverRequired) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes HandoverRequired from APER format.
func (v *HandoverRequired) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequired")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequired")
	}
	return nil
}

func (v *HandoverRequired) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HandoverRequired{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes HandoverCommand to APER format.
func (v *HandoverCommand) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverCommand) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes HandoverCommand from APER format.
func (v *HandoverCommand) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCommand")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCommand")
	}
	return nil
}

func (v *HandoverCommand) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HandoverCommand{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABSubjecttoDataForwardingListListValue struct {
	Value ERABSubjecttoDataForwardingList
}

// MarshalAPERERABSubjecttoDataForwardingList encodes a ERABSubjecttoDataForwardingList list to APER.
func MarshalAPERERABSubjecttoDataForwardingList(list ERABSubjecttoDataForwardingList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABSubjecttoDataForwardingListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABSubjecttoDataForwardingListTo appends a ERABSubjecttoDataForwardingList list to bb.
func MarshalAPERERABSubjecttoDataForwardingListTo(list ERABSubjecttoDataForwardingList, bb *per.BitBuffer) error {
	v := asn1cAPERERABSubjecttoDataForwardingListListValue{Value: list}
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

// UnmarshalAPERERABSubjecttoDataForwardingList decodes a ERABSubjecttoDataForwardingList list from APER.
func UnmarshalAPERERABSubjecttoDataForwardingList(data []byte) (ERABSubjecttoDataForwardingList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABSubjecttoDataForwardingListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABSubjecttoDataForwardingList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABSubjecttoDataForwardingList")
	}
	return value, nil
}

// UnmarshalAPERERABSubjecttoDataForwardingListFrom decodes a ERABSubjecttoDataForwardingList list from bb.
func UnmarshalAPERERABSubjecttoDataForwardingListFrom(bb *per.BitBuffer) (ERABSubjecttoDataForwardingList, error) {
	var v asn1cAPERERABSubjecttoDataForwardingListListValue
	if err := unmarshalAPERERABSubjecttoDataForwardingListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABSubjecttoDataForwardingListInto(v *asn1cAPERERABSubjecttoDataForwardingListListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABSubjecttoDataForwardingList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABDataForwardingItem to APER format.
func (v *ERABDataForwardingItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABDataForwardingItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.DLTransportLayerAddress != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.DLGTPTEID != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ULTransportLayerAddress != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ULGTPTEID != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if v.DLTransportLayerAddress != nil {
		if err := per.EncodeBitStringAlignedExt(bb, v.DLTransportLayerAddress.Bytes, v.DLTransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
			return fmt.Errorf("encoding dL-transportLayerAddress: %w", err)
		}
	}
	if v.DLGTPTEID != nil {
		if err := per.EncodeOctetStringAligned(bb, []byte(*v.DLGTPTEID), 4, 4, true); err != nil {
			return fmt.Errorf("encoding dL-gTP-TEID: %w", err)
		}
	}
	if v.ULTransportLayerAddress != nil {
		if err := per.EncodeBitStringAlignedExt(bb, v.ULTransportLayerAddress.Bytes, v.ULTransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
			return fmt.Errorf("encoding uL-TransportLayerAddress: %w", err)
		}
	}
	if v.ULGTPTEID != nil {
		if err := per.EncodeOctetStringAligned(bb, []byte(*v.ULGTPTEID), 4, 4, true); err != nil {
			return fmt.Errorf("encoding uL-GTP-TEID: %w", err)
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

// UnmarshalAPER decodes ERABDataForwardingItem from APER format.
func (v *ERABDataForwardingItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABDataForwardingItem")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABDataForwardingItem")
	}
	return nil
}

func (v *ERABDataForwardingItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABDataForwardingItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_dltransportlayeraddress, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_dlgtpteid, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ultransportlayeraddress, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ulgtpteid, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	if opt_dltransportlayeraddress {
		bsBytes_dltransportlayeraddress, bsBitLen_dltransportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "DLTransportLayerAddress")
		}
		tmp_dltransportlayeraddress := runtime.BitString{Bytes: bsBytes_dltransportlayeraddress, BitLength: bsBitLen_dltransportlayeraddress}
		v.DLTransportLayerAddress = &tmp_dltransportlayeraddress
	}
	if opt_dlgtpteid {
		val_dlgtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "DLGTPTEID")
		}
		tmp_dlgtpteid := GTPTEID(val_dlgtpteid)
		v.DLGTPTEID = &tmp_dlgtpteid
	}
	if opt_ultransportlayeraddress {
		bsBytes_ultransportlayeraddress, bsBitLen_ultransportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ULTransportLayerAddress")
		}
		tmp_ultransportlayeraddress := runtime.BitString{Bytes: bsBytes_ultransportlayeraddress, BitLength: bsBitLen_ultransportlayeraddress}
		v.ULTransportLayerAddress = &tmp_ultransportlayeraddress
	}
	if opt_ulgtpteid {
		val_ulgtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ULGTPTEID")
		}
		tmp_ulgtpteid := GTPTEID(val_ulgtpteid)
		v.ULGTPTEID = &tmp_ulgtpteid
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

// MarshalAPER encodes HandoverPreparationFailure to APER format.
func (v *HandoverPreparationFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverPreparationFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes HandoverPreparationFailure from APER format.
func (v *HandoverPreparationFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationFailure")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverPreparationFailure")
	}
	return nil
}

func (v *HandoverPreparationFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HandoverPreparationFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes HandoverRequest to APER format.
func (v *HandoverRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes HandoverRequest from APER format.
func (v *HandoverRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequest")
	}
	return nil
}

func (v *HandoverRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HandoverRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABToBeSetupListHOReqListValue struct{ Value ERABToBeSetupListHOReq }

// MarshalAPERERABToBeSetupListHOReq encodes a ERABToBeSetupListHOReq list to APER.
func MarshalAPERERABToBeSetupListHOReq(list ERABToBeSetupListHOReq) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABToBeSetupListHOReqTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABToBeSetupListHOReqTo appends a ERABToBeSetupListHOReq list to bb.
func MarshalAPERERABToBeSetupListHOReqTo(list ERABToBeSetupListHOReq, bb *per.BitBuffer) error {
	v := asn1cAPERERABToBeSetupListHOReqListValue{Value: list}
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

// UnmarshalAPERERABToBeSetupListHOReq decodes a ERABToBeSetupListHOReq list from APER.
func UnmarshalAPERERABToBeSetupListHOReq(data []byte) (ERABToBeSetupListHOReq, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABToBeSetupListHOReqFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeSetupListHOReq")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeSetupListHOReq")
	}
	return value, nil
}

// UnmarshalAPERERABToBeSetupListHOReqFrom decodes a ERABToBeSetupListHOReq list from bb.
func UnmarshalAPERERABToBeSetupListHOReqFrom(bb *per.BitBuffer) (ERABToBeSetupListHOReq, error) {
	var v asn1cAPERERABToBeSetupListHOReqListValue
	if err := unmarshalAPERERABToBeSetupListHOReqInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABToBeSetupListHOReqInto(v *asn1cAPERERABToBeSetupListHOReqListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABToBeSetupListHOReq, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABToBeSetupItemHOReq to APER format.
func (v *ERABToBeSetupItemHOReq) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABToBeSetupItemHOReq) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := per.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
	}
	if err := v.ERABlevelQosParameters.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding e-RABlevelQosParameters: %w", err)
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

// UnmarshalAPER decodes ERABToBeSetupItemHOReq from APER format.
func (v *ERABToBeSetupItemHOReq) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemHOReq")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemHOReq")
	}
	return nil
}

func (v *ERABToBeSetupItemHOReq) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABToBeSetupItemHOReq{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_gtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "GTPTEID")
	}
	v.GTPTEID = GTPTEID(val_gtpteid)
	if err := v.ERABlevelQosParameters.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABlevelQosParameters")
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

// MarshalAPER encodes HandoverRequestAcknowledge to APER format.
func (v *HandoverRequestAcknowledge) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverRequestAcknowledge) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes HandoverRequestAcknowledge from APER format.
func (v *HandoverRequestAcknowledge) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequestAcknowledge")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequestAcknowledge")
	}
	return nil
}

func (v *HandoverRequestAcknowledge) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HandoverRequestAcknowledge{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABAdmittedListListValue struct{ Value ERABAdmittedList }

// MarshalAPERERABAdmittedList encodes a ERABAdmittedList list to APER.
func MarshalAPERERABAdmittedList(list ERABAdmittedList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABAdmittedListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABAdmittedListTo appends a ERABAdmittedList list to bb.
func MarshalAPERERABAdmittedListTo(list ERABAdmittedList, bb *per.BitBuffer) error {
	v := asn1cAPERERABAdmittedListListValue{Value: list}
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

// UnmarshalAPERERABAdmittedList decodes a ERABAdmittedList list from APER.
func UnmarshalAPERERABAdmittedList(data []byte) (ERABAdmittedList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABAdmittedListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABAdmittedList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABAdmittedList")
	}
	return value, nil
}

// UnmarshalAPERERABAdmittedListFrom decodes a ERABAdmittedList list from bb.
func UnmarshalAPERERABAdmittedListFrom(bb *per.BitBuffer) (ERABAdmittedList, error) {
	var v asn1cAPERERABAdmittedListListValue
	if err := unmarshalAPERERABAdmittedListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABAdmittedListInto(v *asn1cAPERERABAdmittedListListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABAdmittedList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABAdmittedItem to APER format.
func (v *ERABAdmittedItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABAdmittedItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.DLTransportLayerAddress != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.DLGTPTEID != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ULTransportLayerAddress != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ULGTPTEID != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := per.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
	}
	if v.DLTransportLayerAddress != nil {
		if err := per.EncodeBitStringAlignedExt(bb, v.DLTransportLayerAddress.Bytes, v.DLTransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
			return fmt.Errorf("encoding dL-transportLayerAddress: %w", err)
		}
	}
	if v.DLGTPTEID != nil {
		if err := per.EncodeOctetStringAligned(bb, []byte(*v.DLGTPTEID), 4, 4, true); err != nil {
			return fmt.Errorf("encoding dL-gTP-TEID: %w", err)
		}
	}
	if v.ULTransportLayerAddress != nil {
		if err := per.EncodeBitStringAlignedExt(bb, v.ULTransportLayerAddress.Bytes, v.ULTransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
			return fmt.Errorf("encoding uL-TransportLayerAddress: %w", err)
		}
	}
	if v.ULGTPTEID != nil {
		if err := per.EncodeOctetStringAligned(bb, []byte(*v.ULGTPTEID), 4, 4, true); err != nil {
			return fmt.Errorf("encoding uL-GTP-TEID: %w", err)
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

// UnmarshalAPER decodes ERABAdmittedItem from APER format.
func (v *ERABAdmittedItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABAdmittedItem")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABAdmittedItem")
	}
	return nil
}

func (v *ERABAdmittedItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABAdmittedItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_dltransportlayeraddress, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_dlgtpteid, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ultransportlayeraddress, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ulgtpteid, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_gtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "GTPTEID")
	}
	v.GTPTEID = GTPTEID(val_gtpteid)
	if opt_dltransportlayeraddress {
		bsBytes_dltransportlayeraddress, bsBitLen_dltransportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "DLTransportLayerAddress")
		}
		tmp_dltransportlayeraddress := runtime.BitString{Bytes: bsBytes_dltransportlayeraddress, BitLength: bsBitLen_dltransportlayeraddress}
		v.DLTransportLayerAddress = &tmp_dltransportlayeraddress
	}
	if opt_dlgtpteid {
		val_dlgtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "DLGTPTEID")
		}
		tmp_dlgtpteid := GTPTEID(val_dlgtpteid)
		v.DLGTPTEID = &tmp_dlgtpteid
	}
	if opt_ultransportlayeraddress {
		bsBytes_ultransportlayeraddress, bsBitLen_ultransportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ULTransportLayerAddress")
		}
		tmp_ultransportlayeraddress := runtime.BitString{Bytes: bsBytes_ultransportlayeraddress, BitLength: bsBitLen_ultransportlayeraddress}
		v.ULTransportLayerAddress = &tmp_ultransportlayeraddress
	}
	if opt_ulgtpteid {
		val_ulgtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ULGTPTEID")
		}
		tmp_ulgtpteid := GTPTEID(val_ulgtpteid)
		v.ULGTPTEID = &tmp_ulgtpteid
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

type asn1cAPERERABFailedtoSetupListHOReqAckListValue struct{ Value ERABFailedtoSetupListHOReqAck }

// MarshalAPERERABFailedtoSetupListHOReqAck encodes a ERABFailedtoSetupListHOReqAck list to APER.
func MarshalAPERERABFailedtoSetupListHOReqAck(list ERABFailedtoSetupListHOReqAck) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABFailedtoSetupListHOReqAckTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABFailedtoSetupListHOReqAckTo appends a ERABFailedtoSetupListHOReqAck list to bb.
func MarshalAPERERABFailedtoSetupListHOReqAckTo(list ERABFailedtoSetupListHOReqAck, bb *per.BitBuffer) error {
	v := asn1cAPERERABFailedtoSetupListHOReqAckListValue{Value: list}
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

// UnmarshalAPERERABFailedtoSetupListHOReqAck decodes a ERABFailedtoSetupListHOReqAck list from APER.
func UnmarshalAPERERABFailedtoSetupListHOReqAck(data []byte) (ERABFailedtoSetupListHOReqAck, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABFailedtoSetupListHOReqAckFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABFailedtoSetupListHOReqAck")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABFailedtoSetupListHOReqAck")
	}
	return value, nil
}

// UnmarshalAPERERABFailedtoSetupListHOReqAckFrom decodes a ERABFailedtoSetupListHOReqAck list from bb.
func UnmarshalAPERERABFailedtoSetupListHOReqAckFrom(bb *per.BitBuffer) (ERABFailedtoSetupListHOReqAck, error) {
	var v asn1cAPERERABFailedtoSetupListHOReqAckListValue
	if err := unmarshalAPERERABFailedtoSetupListHOReqAckInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABFailedtoSetupListHOReqAckInto(v *asn1cAPERERABFailedtoSetupListHOReqAckListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABFailedtoSetupListHOReqAck, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABFailedToSetupItemHOReqAck to APER format.
func (v *ERABFailedToSetupItemHOReqAck) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABFailedToSetupItemHOReqAck) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := v.Cause.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding cause: %w", err)
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

// UnmarshalAPER decodes ERABFailedToSetupItemHOReqAck from APER format.
func (v *ERABFailedToSetupItemHOReqAck) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToSetupItemHOReqAck")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToSetupItemHOReqAck")
	}
	return nil
}

func (v *ERABFailedToSetupItemHOReqAck) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABFailedToSetupItemHOReqAck{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	if err := v.Cause.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
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

// MarshalAPER encodes HandoverFailure to APER format.
func (v *HandoverFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes HandoverFailure from APER format.
func (v *HandoverFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverFailure")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverFailure")
	}
	return nil
}

func (v *HandoverFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HandoverFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes HandoverNotify to APER format.
func (v *HandoverNotify) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverNotify) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes HandoverNotify from APER format.
func (v *HandoverNotify) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverNotify")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverNotify")
	}
	return nil
}

func (v *HandoverNotify) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HandoverNotify{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes PathSwitchRequest to APER format.
func (v *PathSwitchRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *PathSwitchRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes PathSwitchRequest from APER format.
func (v *PathSwitchRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequest")
	}
	return nil
}

func (v *PathSwitchRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PathSwitchRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABToBeSwitchedDLListListValue struct{ Value ERABToBeSwitchedDLList }

// MarshalAPERERABToBeSwitchedDLList encodes a ERABToBeSwitchedDLList list to APER.
func MarshalAPERERABToBeSwitchedDLList(list ERABToBeSwitchedDLList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABToBeSwitchedDLListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABToBeSwitchedDLListTo appends a ERABToBeSwitchedDLList list to bb.
func MarshalAPERERABToBeSwitchedDLListTo(list ERABToBeSwitchedDLList, bb *per.BitBuffer) error {
	v := asn1cAPERERABToBeSwitchedDLListListValue{Value: list}
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

// UnmarshalAPERERABToBeSwitchedDLList decodes a ERABToBeSwitchedDLList list from APER.
func UnmarshalAPERERABToBeSwitchedDLList(data []byte) (ERABToBeSwitchedDLList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABToBeSwitchedDLListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedDLList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedDLList")
	}
	return value, nil
}

// UnmarshalAPERERABToBeSwitchedDLListFrom decodes a ERABToBeSwitchedDLList list from bb.
func UnmarshalAPERERABToBeSwitchedDLListFrom(bb *per.BitBuffer) (ERABToBeSwitchedDLList, error) {
	var v asn1cAPERERABToBeSwitchedDLListListValue
	if err := unmarshalAPERERABToBeSwitchedDLListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABToBeSwitchedDLListInto(v *asn1cAPERERABToBeSwitchedDLListListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABToBeSwitchedDLList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABToBeSwitchedDLItem to APER format.
func (v *ERABToBeSwitchedDLItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABToBeSwitchedDLItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := per.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
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

// UnmarshalAPER decodes ERABToBeSwitchedDLItem from APER format.
func (v *ERABToBeSwitchedDLItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedDLItem")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedDLItem")
	}
	return nil
}

func (v *ERABToBeSwitchedDLItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABToBeSwitchedDLItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_gtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "GTPTEID")
	}
	v.GTPTEID = GTPTEID(val_gtpteid)
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

// MarshalAPER encodes PathSwitchRequestAcknowledge to APER format.
func (v *PathSwitchRequestAcknowledge) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *PathSwitchRequestAcknowledge) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes PathSwitchRequestAcknowledge from APER format.
func (v *PathSwitchRequestAcknowledge) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledge")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledge")
	}
	return nil
}

func (v *PathSwitchRequestAcknowledge) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PathSwitchRequestAcknowledge{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABToBeSwitchedULListListValue struct{ Value ERABToBeSwitchedULList }

// MarshalAPERERABToBeSwitchedULList encodes a ERABToBeSwitchedULList list to APER.
func MarshalAPERERABToBeSwitchedULList(list ERABToBeSwitchedULList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABToBeSwitchedULListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABToBeSwitchedULListTo appends a ERABToBeSwitchedULList list to bb.
func MarshalAPERERABToBeSwitchedULListTo(list ERABToBeSwitchedULList, bb *per.BitBuffer) error {
	v := asn1cAPERERABToBeSwitchedULListListValue{Value: list}
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

// UnmarshalAPERERABToBeSwitchedULList decodes a ERABToBeSwitchedULList list from APER.
func UnmarshalAPERERABToBeSwitchedULList(data []byte) (ERABToBeSwitchedULList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABToBeSwitchedULListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULList")
	}
	return value, nil
}

// UnmarshalAPERERABToBeSwitchedULListFrom decodes a ERABToBeSwitchedULList list from bb.
func UnmarshalAPERERABToBeSwitchedULListFrom(bb *per.BitBuffer) (ERABToBeSwitchedULList, error) {
	var v asn1cAPERERABToBeSwitchedULListListValue
	if err := unmarshalAPERERABToBeSwitchedULListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABToBeSwitchedULListInto(v *asn1cAPERERABToBeSwitchedULListListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABToBeSwitchedULList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABToBeSwitchedULItem to APER format.
func (v *ERABToBeSwitchedULItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABToBeSwitchedULItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := per.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
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

// UnmarshalAPER decodes ERABToBeSwitchedULItem from APER format.
func (v *ERABToBeSwitchedULItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedULItem")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedULItem")
	}
	return nil
}

func (v *ERABToBeSwitchedULItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABToBeSwitchedULItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_gtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "GTPTEID")
	}
	v.GTPTEID = GTPTEID(val_gtpteid)
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

type asn1cAPERERABToBeUpdatedListListValue struct{ Value ERABToBeUpdatedList }

// MarshalAPERERABToBeUpdatedList encodes a ERABToBeUpdatedList list to APER.
func MarshalAPERERABToBeUpdatedList(list ERABToBeUpdatedList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABToBeUpdatedListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABToBeUpdatedListTo appends a ERABToBeUpdatedList list to bb.
func MarshalAPERERABToBeUpdatedListTo(list ERABToBeUpdatedList, bb *per.BitBuffer) error {
	v := asn1cAPERERABToBeUpdatedListListValue{Value: list}
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

// UnmarshalAPERERABToBeUpdatedList decodes a ERABToBeUpdatedList list from APER.
func UnmarshalAPERERABToBeUpdatedList(data []byte) (ERABToBeUpdatedList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABToBeUpdatedListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeUpdatedList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeUpdatedList")
	}
	return value, nil
}

// UnmarshalAPERERABToBeUpdatedListFrom decodes a ERABToBeUpdatedList list from bb.
func UnmarshalAPERERABToBeUpdatedListFrom(bb *per.BitBuffer) (ERABToBeUpdatedList, error) {
	var v asn1cAPERERABToBeUpdatedListListValue
	if err := unmarshalAPERERABToBeUpdatedListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABToBeUpdatedListInto(v *asn1cAPERERABToBeUpdatedListListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABToBeUpdatedList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABToBeUpdatedItem to APER format.
func (v *ERABToBeUpdatedItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABToBeUpdatedItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.SecurityIndication != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if v.SecurityIndication != nil {
		if err := v.SecurityIndication.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding securityIndication: %w", err)
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

// UnmarshalAPER decodes ERABToBeUpdatedItem from APER format.
func (v *ERABToBeUpdatedItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeUpdatedItem")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeUpdatedItem")
	}
	return nil
}

func (v *ERABToBeUpdatedItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABToBeUpdatedItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_securityindication, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	if opt_securityindication {
		var dec_securityindication SecurityIndication
		if err := dec_securityindication.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SecurityIndication")
		}
		v.SecurityIndication = &dec_securityindication
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

// MarshalAPER encodes PathSwitchRequestFailure to APER format.
func (v *PathSwitchRequestFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *PathSwitchRequestFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes PathSwitchRequestFailure from APER format.
func (v *PathSwitchRequestFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestFailure")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestFailure")
	}
	return nil
}

func (v *PathSwitchRequestFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PathSwitchRequestFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes HandoverCancel to APER format.
func (v *HandoverCancel) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverCancel) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes HandoverCancel from APER format.
func (v *HandoverCancel) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCancel")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCancel")
	}
	return nil
}

func (v *HandoverCancel) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HandoverCancel{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes HandoverCancelAcknowledge to APER format.
func (v *HandoverCancelAcknowledge) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverCancelAcknowledge) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes HandoverCancelAcknowledge from APER format.
func (v *HandoverCancelAcknowledge) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCancelAcknowledge")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverCancelAcknowledge")
	}
	return nil
}

func (v *HandoverCancelAcknowledge) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HandoverCancelAcknowledge{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes HandoverSuccess to APER format.
func (v *HandoverSuccess) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *HandoverSuccess) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes HandoverSuccess from APER format.
func (v *HandoverSuccess) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverSuccess")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverSuccess")
	}
	return nil
}

func (v *HandoverSuccess) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = HandoverSuccess{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ENBEarlyStatusTransfer to APER format.
func (v *ENBEarlyStatusTransfer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ENBEarlyStatusTransfer) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ENBEarlyStatusTransfer from APER format.
func (v *ENBEarlyStatusTransfer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBEarlyStatusTransfer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBEarlyStatusTransfer")
	}
	return nil
}

func (v *ENBEarlyStatusTransfer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ENBEarlyStatusTransfer{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes MMEEarlyStatusTransfer to APER format.
func (v *MMEEarlyStatusTransfer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *MMEEarlyStatusTransfer) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes MMEEarlyStatusTransfer from APER format.
func (v *MMEEarlyStatusTransfer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEEarlyStatusTransfer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEEarlyStatusTransfer")
	}
	return nil
}

func (v *MMEEarlyStatusTransfer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MMEEarlyStatusTransfer{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ERABSetupRequest to APER format.
func (v *ERABSetupRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABSetupRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ERABSetupRequest from APER format.
func (v *ERABSetupRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupRequest")
	}
	return nil
}

func (v *ERABSetupRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABSetupRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABToBeSetupListBearerSUReqListValue struct{ Value ERABToBeSetupListBearerSUReq }

// MarshalAPERERABToBeSetupListBearerSUReq encodes a ERABToBeSetupListBearerSUReq list to APER.
func MarshalAPERERABToBeSetupListBearerSUReq(list ERABToBeSetupListBearerSUReq) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABToBeSetupListBearerSUReqTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABToBeSetupListBearerSUReqTo appends a ERABToBeSetupListBearerSUReq list to bb.
func MarshalAPERERABToBeSetupListBearerSUReqTo(list ERABToBeSetupListBearerSUReq, bb *per.BitBuffer) error {
	v := asn1cAPERERABToBeSetupListBearerSUReqListValue{Value: list}
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

// UnmarshalAPERERABToBeSetupListBearerSUReq decodes a ERABToBeSetupListBearerSUReq list from APER.
func UnmarshalAPERERABToBeSetupListBearerSUReq(data []byte) (ERABToBeSetupListBearerSUReq, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABToBeSetupListBearerSUReqFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeSetupListBearerSUReq")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeSetupListBearerSUReq")
	}
	return value, nil
}

// UnmarshalAPERERABToBeSetupListBearerSUReqFrom decodes a ERABToBeSetupListBearerSUReq list from bb.
func UnmarshalAPERERABToBeSetupListBearerSUReqFrom(bb *per.BitBuffer) (ERABToBeSetupListBearerSUReq, error) {
	var v asn1cAPERERABToBeSetupListBearerSUReqListValue
	if err := unmarshalAPERERABToBeSetupListBearerSUReqInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABToBeSetupListBearerSUReqInto(v *asn1cAPERERABToBeSetupListBearerSUReqListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABToBeSetupListBearerSUReq, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABToBeSetupItemBearerSUReq to APER format.
func (v *ERABToBeSetupItemBearerSUReq) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABToBeSetupItemBearerSUReq) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := v.ERABlevelQoSParameters.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding e-RABlevelQoSParameters: %w", err)
	}
	if err := per.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.NASPDU), 0, 0, false); err != nil {
		return fmt.Errorf("encoding nAS-PDU: %w", err)
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

// UnmarshalAPER decodes ERABToBeSetupItemBearerSUReq from APER format.
func (v *ERABToBeSetupItemBearerSUReq) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemBearerSUReq")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemBearerSUReq")
	}
	return nil
}

func (v *ERABToBeSetupItemBearerSUReq) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABToBeSetupItemBearerSUReq{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	if err := v.ERABlevelQoSParameters.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABlevelQoSParameters")
	}
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_gtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "GTPTEID")
	}
	v.GTPTEID = GTPTEID(val_gtpteid)
	val_naspdu, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NASPDU")
	}
	v.NASPDU = NASPDU(val_naspdu)
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

// MarshalAPER encodes ERABSetupResponse to APER format.
func (v *ERABSetupResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABSetupResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ERABSetupResponse from APER format.
func (v *ERABSetupResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupResponse")
	}
	return nil
}

func (v *ERABSetupResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABSetupResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABSetupListBearerSUResListValue struct{ Value ERABSetupListBearerSURes }

// MarshalAPERERABSetupListBearerSURes encodes a ERABSetupListBearerSURes list to APER.
func MarshalAPERERABSetupListBearerSURes(list ERABSetupListBearerSURes) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABSetupListBearerSUResTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABSetupListBearerSUResTo appends a ERABSetupListBearerSURes list to bb.
func MarshalAPERERABSetupListBearerSUResTo(list ERABSetupListBearerSURes, bb *per.BitBuffer) error {
	v := asn1cAPERERABSetupListBearerSUResListValue{Value: list}
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

// UnmarshalAPERERABSetupListBearerSURes decodes a ERABSetupListBearerSURes list from APER.
func UnmarshalAPERERABSetupListBearerSURes(data []byte) (ERABSetupListBearerSURes, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABSetupListBearerSUResFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABSetupListBearerSURes")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABSetupListBearerSURes")
	}
	return value, nil
}

// UnmarshalAPERERABSetupListBearerSUResFrom decodes a ERABSetupListBearerSURes list from bb.
func UnmarshalAPERERABSetupListBearerSUResFrom(bb *per.BitBuffer) (ERABSetupListBearerSURes, error) {
	var v asn1cAPERERABSetupListBearerSUResListValue
	if err := unmarshalAPERERABSetupListBearerSUResInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABSetupListBearerSUResInto(v *asn1cAPERERABSetupListBearerSUResListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABSetupListBearerSURes, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABSetupItemBearerSURes to APER format.
func (v *ERABSetupItemBearerSURes) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABSetupItemBearerSURes) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := per.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
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

// UnmarshalAPER decodes ERABSetupItemBearerSURes from APER format.
func (v *ERABSetupItemBearerSURes) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupItemBearerSURes")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupItemBearerSURes")
	}
	return nil
}

func (v *ERABSetupItemBearerSURes) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABSetupItemBearerSURes{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_gtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "GTPTEID")
	}
	v.GTPTEID = GTPTEID(val_gtpteid)
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

// MarshalAPER encodes ERABModifyRequest to APER format.
func (v *ERABModifyRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABModifyRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ERABModifyRequest from APER format.
func (v *ERABModifyRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyRequest")
	}
	return nil
}

func (v *ERABModifyRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABModifyRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABToBeModifiedListBearerModReqListValue struct {
	Value ERABToBeModifiedListBearerModReq
}

// MarshalAPERERABToBeModifiedListBearerModReq encodes a ERABToBeModifiedListBearerModReq list to APER.
func MarshalAPERERABToBeModifiedListBearerModReq(list ERABToBeModifiedListBearerModReq) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABToBeModifiedListBearerModReqTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABToBeModifiedListBearerModReqTo appends a ERABToBeModifiedListBearerModReq list to bb.
func MarshalAPERERABToBeModifiedListBearerModReqTo(list ERABToBeModifiedListBearerModReq, bb *per.BitBuffer) error {
	v := asn1cAPERERABToBeModifiedListBearerModReqListValue{Value: list}
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

// UnmarshalAPERERABToBeModifiedListBearerModReq decodes a ERABToBeModifiedListBearerModReq list from APER.
func UnmarshalAPERERABToBeModifiedListBearerModReq(data []byte) (ERABToBeModifiedListBearerModReq, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABToBeModifiedListBearerModReqFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModReq")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModReq")
	}
	return value, nil
}

// UnmarshalAPERERABToBeModifiedListBearerModReqFrom decodes a ERABToBeModifiedListBearerModReq list from bb.
func UnmarshalAPERERABToBeModifiedListBearerModReqFrom(bb *per.BitBuffer) (ERABToBeModifiedListBearerModReq, error) {
	var v asn1cAPERERABToBeModifiedListBearerModReqListValue
	if err := unmarshalAPERERABToBeModifiedListBearerModReqInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABToBeModifiedListBearerModReqInto(v *asn1cAPERERABToBeModifiedListBearerModReqListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABToBeModifiedListBearerModReq, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABToBeModifiedItemBearerModReq to APER format.
func (v *ERABToBeModifiedItemBearerModReq) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABToBeModifiedItemBearerModReq) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := v.ERABLevelQoSParameters.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding e-RABLevelQoSParameters: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.NASPDU), 0, 0, false); err != nil {
		return fmt.Errorf("encoding nAS-PDU: %w", err)
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

// UnmarshalAPER decodes ERABToBeModifiedItemBearerModReq from APER format.
func (v *ERABToBeModifiedItemBearerModReq) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReq")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModReq")
	}
	return nil
}

func (v *ERABToBeModifiedItemBearerModReq) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABToBeModifiedItemBearerModReq{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	if err := v.ERABLevelQoSParameters.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABLevelQoSParameters")
	}
	val_naspdu, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NASPDU")
	}
	v.NASPDU = NASPDU(val_naspdu)
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

// MarshalAPER encodes ERABModifyResponse to APER format.
func (v *ERABModifyResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABModifyResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ERABModifyResponse from APER format.
func (v *ERABModifyResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyResponse")
	}
	return nil
}

func (v *ERABModifyResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABModifyResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABModifyListBearerModResListValue struct{ Value ERABModifyListBearerModRes }

// MarshalAPERERABModifyListBearerModRes encodes a ERABModifyListBearerModRes list to APER.
func MarshalAPERERABModifyListBearerModRes(list ERABModifyListBearerModRes) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABModifyListBearerModResTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABModifyListBearerModResTo appends a ERABModifyListBearerModRes list to bb.
func MarshalAPERERABModifyListBearerModResTo(list ERABModifyListBearerModRes, bb *per.BitBuffer) error {
	v := asn1cAPERERABModifyListBearerModResListValue{Value: list}
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

// UnmarshalAPERERABModifyListBearerModRes decodes a ERABModifyListBearerModRes list from APER.
func UnmarshalAPERERABModifyListBearerModRes(data []byte) (ERABModifyListBearerModRes, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABModifyListBearerModResFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABModifyListBearerModRes")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABModifyListBearerModRes")
	}
	return value, nil
}

// UnmarshalAPERERABModifyListBearerModResFrom decodes a ERABModifyListBearerModRes list from bb.
func UnmarshalAPERERABModifyListBearerModResFrom(bb *per.BitBuffer) (ERABModifyListBearerModRes, error) {
	var v asn1cAPERERABModifyListBearerModResListValue
	if err := unmarshalAPERERABModifyListBearerModResInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABModifyListBearerModResInto(v *asn1cAPERERABModifyListBearerModResListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABModifyListBearerModRes, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABModifyItemBearerModRes to APER format.
func (v *ERABModifyItemBearerModRes) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABModifyItemBearerModRes) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
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

// UnmarshalAPER decodes ERABModifyItemBearerModRes from APER format.
func (v *ERABModifyItemBearerModRes) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyItemBearerModRes")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyItemBearerModRes")
	}
	return nil
}

func (v *ERABModifyItemBearerModRes) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABModifyItemBearerModRes{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
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

// MarshalAPER encodes ERABReleaseCommand to APER format.
func (v *ERABReleaseCommand) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABReleaseCommand) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ERABReleaseCommand from APER format.
func (v *ERABReleaseCommand) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseCommand")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseCommand")
	}
	return nil
}

func (v *ERABReleaseCommand) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABReleaseCommand{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ERABReleaseResponse to APER format.
func (v *ERABReleaseResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABReleaseResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ERABReleaseResponse from APER format.
func (v *ERABReleaseResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseResponse")
	}
	return nil
}

func (v *ERABReleaseResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABReleaseResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABReleaseListBearerRelCompListValue struct{ Value ERABReleaseListBearerRelComp }

// MarshalAPERERABReleaseListBearerRelComp encodes a ERABReleaseListBearerRelComp list to APER.
func MarshalAPERERABReleaseListBearerRelComp(list ERABReleaseListBearerRelComp) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABReleaseListBearerRelCompTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABReleaseListBearerRelCompTo appends a ERABReleaseListBearerRelComp list to bb.
func MarshalAPERERABReleaseListBearerRelCompTo(list ERABReleaseListBearerRelComp, bb *per.BitBuffer) error {
	v := asn1cAPERERABReleaseListBearerRelCompListValue{Value: list}
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

// UnmarshalAPERERABReleaseListBearerRelComp decodes a ERABReleaseListBearerRelComp list from APER.
func UnmarshalAPERERABReleaseListBearerRelComp(data []byte) (ERABReleaseListBearerRelComp, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABReleaseListBearerRelCompFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABReleaseListBearerRelComp")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABReleaseListBearerRelComp")
	}
	return value, nil
}

// UnmarshalAPERERABReleaseListBearerRelCompFrom decodes a ERABReleaseListBearerRelComp list from bb.
func UnmarshalAPERERABReleaseListBearerRelCompFrom(bb *per.BitBuffer) (ERABReleaseListBearerRelComp, error) {
	var v asn1cAPERERABReleaseListBearerRelCompListValue
	if err := unmarshalAPERERABReleaseListBearerRelCompInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABReleaseListBearerRelCompInto(v *asn1cAPERERABReleaseListBearerRelCompListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABReleaseListBearerRelComp, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABReleaseItemBearerRelComp to APER format.
func (v *ERABReleaseItemBearerRelComp) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABReleaseItemBearerRelComp) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
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

// UnmarshalAPER decodes ERABReleaseItemBearerRelComp from APER format.
func (v *ERABReleaseItemBearerRelComp) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelComp")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelComp")
	}
	return nil
}

func (v *ERABReleaseItemBearerRelComp) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABReleaseItemBearerRelComp{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
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

// MarshalAPER encodes ERABReleaseIndication to APER format.
func (v *ERABReleaseIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABReleaseIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ERABReleaseIndication from APER format.
func (v *ERABReleaseIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseIndication")
	}
	return nil
}

func (v *ERABReleaseIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABReleaseIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes InitialContextSetupRequest to APER format.
func (v *InitialContextSetupRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *InitialContextSetupRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes InitialContextSetupRequest from APER format.
func (v *InitialContextSetupRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupRequest")
	}
	return nil
}

func (v *InitialContextSetupRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = InitialContextSetupRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABToBeSetupListCtxtSUReqListValue struct{ Value ERABToBeSetupListCtxtSUReq }

// MarshalAPERERABToBeSetupListCtxtSUReq encodes a ERABToBeSetupListCtxtSUReq list to APER.
func MarshalAPERERABToBeSetupListCtxtSUReq(list ERABToBeSetupListCtxtSUReq) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABToBeSetupListCtxtSUReqTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABToBeSetupListCtxtSUReqTo appends a ERABToBeSetupListCtxtSUReq list to bb.
func MarshalAPERERABToBeSetupListCtxtSUReqTo(list ERABToBeSetupListCtxtSUReq, bb *per.BitBuffer) error {
	v := asn1cAPERERABToBeSetupListCtxtSUReqListValue{Value: list}
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

// UnmarshalAPERERABToBeSetupListCtxtSUReq decodes a ERABToBeSetupListCtxtSUReq list from APER.
func UnmarshalAPERERABToBeSetupListCtxtSUReq(data []byte) (ERABToBeSetupListCtxtSUReq, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABToBeSetupListCtxtSUReqFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeSetupListCtxtSUReq")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeSetupListCtxtSUReq")
	}
	return value, nil
}

// UnmarshalAPERERABToBeSetupListCtxtSUReqFrom decodes a ERABToBeSetupListCtxtSUReq list from bb.
func UnmarshalAPERERABToBeSetupListCtxtSUReqFrom(bb *per.BitBuffer) (ERABToBeSetupListCtxtSUReq, error) {
	var v asn1cAPERERABToBeSetupListCtxtSUReqListValue
	if err := unmarshalAPERERABToBeSetupListCtxtSUReqInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABToBeSetupListCtxtSUReqInto(v *asn1cAPERERABToBeSetupListCtxtSUReqListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABToBeSetupListCtxtSUReq, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABToBeSetupItemCtxtSUReq to APER format.
func (v *ERABToBeSetupItemCtxtSUReq) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABToBeSetupItemCtxtSUReq) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NASPDU != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := v.ERABlevelQoSParameters.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding e-RABlevelQoSParameters: %w", err)
	}
	if err := per.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
	}
	if v.NASPDU != nil {
		if err := per.EncodeOctetStringAligned(bb, []byte(*v.NASPDU), 0, 0, false); err != nil {
			return fmt.Errorf("encoding nAS-PDU: %w", err)
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

// UnmarshalAPER decodes ERABToBeSetupItemCtxtSUReq from APER format.
func (v *ERABToBeSetupItemCtxtSUReq) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemCtxtSUReq")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSetupItemCtxtSUReq")
	}
	return nil
}

func (v *ERABToBeSetupItemCtxtSUReq) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABToBeSetupItemCtxtSUReq{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_naspdu, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	if err := v.ERABlevelQoSParameters.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABlevelQoSParameters")
	}
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_gtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "GTPTEID")
	}
	v.GTPTEID = GTPTEID(val_gtpteid)
	if opt_naspdu {
		val_naspdu, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "NASPDU")
		}
		tmp_naspdu := NASPDU(val_naspdu)
		v.NASPDU = &tmp_naspdu
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

// MarshalAPER encodes InitialContextSetupResponse to APER format.
func (v *InitialContextSetupResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *InitialContextSetupResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes InitialContextSetupResponse from APER format.
func (v *InitialContextSetupResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupResponse")
	}
	return nil
}

func (v *InitialContextSetupResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = InitialContextSetupResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABSetupListCtxtSUResListValue struct{ Value ERABSetupListCtxtSURes }

// MarshalAPERERABSetupListCtxtSURes encodes a ERABSetupListCtxtSURes list to APER.
func MarshalAPERERABSetupListCtxtSURes(list ERABSetupListCtxtSURes) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABSetupListCtxtSUResTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABSetupListCtxtSUResTo appends a ERABSetupListCtxtSURes list to bb.
func MarshalAPERERABSetupListCtxtSUResTo(list ERABSetupListCtxtSURes, bb *per.BitBuffer) error {
	v := asn1cAPERERABSetupListCtxtSUResListValue{Value: list}
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

// UnmarshalAPERERABSetupListCtxtSURes decodes a ERABSetupListCtxtSURes list from APER.
func UnmarshalAPERERABSetupListCtxtSURes(data []byte) (ERABSetupListCtxtSURes, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABSetupListCtxtSUResFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABSetupListCtxtSURes")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABSetupListCtxtSURes")
	}
	return value, nil
}

// UnmarshalAPERERABSetupListCtxtSUResFrom decodes a ERABSetupListCtxtSURes list from bb.
func UnmarshalAPERERABSetupListCtxtSUResFrom(bb *per.BitBuffer) (ERABSetupListCtxtSURes, error) {
	var v asn1cAPERERABSetupListCtxtSUResListValue
	if err := unmarshalAPERERABSetupListCtxtSUResInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABSetupListCtxtSUResInto(v *asn1cAPERERABSetupListCtxtSUResListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABSetupListCtxtSURes, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABSetupItemCtxtSURes to APER format.
func (v *ERABSetupItemCtxtSURes) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABSetupItemCtxtSURes) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := per.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
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

// UnmarshalAPER decodes ERABSetupItemCtxtSURes from APER format.
func (v *ERABSetupItemCtxtSURes) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupItemCtxtSURes")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupItemCtxtSURes")
	}
	return nil
}

func (v *ERABSetupItemCtxtSURes) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABSetupItemCtxtSURes{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_gtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "GTPTEID")
	}
	v.GTPTEID = GTPTEID(val_gtpteid)
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

// MarshalAPER encodes InitialContextSetupFailure to APER format.
func (v *InitialContextSetupFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *InitialContextSetupFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes InitialContextSetupFailure from APER format.
func (v *InitialContextSetupFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupFailure")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupFailure")
	}
	return nil
}

func (v *InitialContextSetupFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = InitialContextSetupFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes Paging to APER format.
func (v *Paging) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *Paging) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes Paging from APER format.
func (v *Paging) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Paging")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "Paging")
	}
	return nil
}

func (v *Paging) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = Paging{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERTAIListListValue struct{ Value TAIList }

// MarshalAPERTAIList encodes a TAIList list to APER.
func MarshalAPERTAIList(list TAIList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERTAIListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERTAIListTo appends a TAIList list to bb.
func MarshalAPERTAIListTo(list TAIList, bb *per.BitBuffer) error {
	v := asn1cAPERTAIListListValue{Value: list}
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

// UnmarshalAPERTAIList decodes a TAIList list from APER.
func UnmarshalAPERTAIList(data []byte) (TAIList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERTAIListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "TAIList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "TAIList")
	}
	return value, nil
}

// UnmarshalAPERTAIListFrom decodes a TAIList list from bb.
func UnmarshalAPERTAIListFrom(bb *per.BitBuffer) (TAIList, error) {
	var v asn1cAPERTAIListListValue
	if err := unmarshalAPERTAIListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERTAIListInto(v *asn1cAPERTAIListListValue, bb *per.BitBuffer) error {
	v.Value = make(TAIList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes TAIItem to APER format.
func (v *TAIItem) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *TAIItem) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := v.TAI.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding tAI: %w", err)
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

// UnmarshalAPER decodes TAIItem from APER format.
func (v *TAIItem) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TAIItem")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "TAIItem")
	}
	return nil
}

func (v *TAIItem) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = TAIItem{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.TAI.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TAI")
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

// MarshalAPER encodes UEContextReleaseRequest to APER format.
func (v *UEContextReleaseRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextReleaseRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextReleaseRequest from APER format.
func (v *UEContextReleaseRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseRequest")
	}
	return nil
}

func (v *UEContextReleaseRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextReleaseRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UEContextReleaseCommand to APER format.
func (v *UEContextReleaseCommand) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextReleaseCommand) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextReleaseCommand from APER format.
func (v *UEContextReleaseCommand) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseCommand")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseCommand")
	}
	return nil
}

func (v *UEContextReleaseCommand) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextReleaseCommand{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UEContextReleaseComplete to APER format.
func (v *UEContextReleaseComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextReleaseComplete) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextReleaseComplete from APER format.
func (v *UEContextReleaseComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseComplete")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseComplete")
	}
	return nil
}

func (v *UEContextReleaseComplete) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextReleaseComplete{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UEContextModificationRequest to APER format.
func (v *UEContextModificationRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextModificationRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextModificationRequest from APER format.
func (v *UEContextModificationRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationRequest")
	}
	return nil
}

func (v *UEContextModificationRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextModificationRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UEContextModificationResponse to APER format.
func (v *UEContextModificationResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextModificationResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextModificationResponse from APER format.
func (v *UEContextModificationResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationResponse")
	}
	return nil
}

func (v *UEContextModificationResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextModificationResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UEContextModificationFailure to APER format.
func (v *UEContextModificationFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextModificationFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextModificationFailure from APER format.
func (v *UEContextModificationFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationFailure")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationFailure")
	}
	return nil
}

func (v *UEContextModificationFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextModificationFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UERadioCapabilityMatchRequest to APER format.
func (v *UERadioCapabilityMatchRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioCapabilityMatchRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UERadioCapabilityMatchRequest from APER format.
func (v *UERadioCapabilityMatchRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequest")
	}
	return nil
}

func (v *UERadioCapabilityMatchRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UERadioCapabilityMatchRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UERadioCapabilityMatchResponse to APER format.
func (v *UERadioCapabilityMatchResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioCapabilityMatchResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UERadioCapabilityMatchResponse from APER format.
func (v *UERadioCapabilityMatchResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponse")
	}
	return nil
}

func (v *UERadioCapabilityMatchResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UERadioCapabilityMatchResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes DownlinkNASTransport to APER format.
func (v *DownlinkNASTransport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *DownlinkNASTransport) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes DownlinkNASTransport from APER format.
func (v *DownlinkNASTransport) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkNASTransport")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkNASTransport")
	}
	return nil
}

func (v *DownlinkNASTransport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = DownlinkNASTransport{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes InitialUEMessage to APER format.
func (v *InitialUEMessage) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *InitialUEMessage) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes InitialUEMessage from APER format.
func (v *InitialUEMessage) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitialUEMessage")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitialUEMessage")
	}
	return nil
}

func (v *InitialUEMessage) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = InitialUEMessage{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UplinkNASTransport to APER format.
func (v *UplinkNASTransport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UplinkNASTransport) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UplinkNASTransport from APER format.
func (v *UplinkNASTransport) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNASTransport")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNASTransport")
	}
	return nil
}

func (v *UplinkNASTransport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UplinkNASTransport{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes NASNonDeliveryIndication to APER format.
func (v *NASNonDeliveryIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *NASNonDeliveryIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes NASNonDeliveryIndication from APER format.
func (v *NASNonDeliveryIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NASNonDeliveryIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "NASNonDeliveryIndication")
	}
	return nil
}

func (v *NASNonDeliveryIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = NASNonDeliveryIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes RerouteNASRequest to APER format.
func (v *RerouteNASRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *RerouteNASRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes RerouteNASRequest from APER format.
func (v *RerouteNASRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RerouteNASRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "RerouteNASRequest")
	}
	return nil
}

func (v *RerouteNASRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = RerouteNASRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes NASDeliveryIndication to APER format.
func (v *NASDeliveryIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *NASDeliveryIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes NASDeliveryIndication from APER format.
func (v *NASDeliveryIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NASDeliveryIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "NASDeliveryIndication")
	}
	return nil
}

func (v *NASDeliveryIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = NASDeliveryIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes Reset to APER format.
func (v *Reset) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *Reset) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes Reset from APER format.
func (v *Reset) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Reset")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "Reset")
	}
	return nil
}

func (v *Reset) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = Reset{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ResetType to APER format.
func (v *ResetType) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ResetType) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("ResetType: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("ResetType: extension index %d must be non-negative", v.UnknownExtension.Index)
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
		return fmt.Errorf("ResetType: extension choice %d not supported", v.Choice)
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case ResetTypeChoiceS1Interface:
		if v.S1Interface == nil {
			return fmt.Errorf("choice alternative s1-Interface is nil")
		}
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.S1Interface), 1, true); err != nil {
			return fmt.Errorf("encoding s1-Interface: %w", err)
		}
	case ResetTypeChoicePartOfS1Interface:
		if err := per.EncodeCollection(bb, int64(len(v.PartOfS1Interface)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_partofs1interface, fragmentLength_partofs1interface int64) error {
			for _, elem := range v.PartOfS1Interface[fragmentOffset_partofs1interface : fragmentOffset_partofs1interface+fragmentLength_partofs1interface] {
				if err := elem.MarshalAPERTo(bb); err != nil {
					return fmt.Errorf("encoding partOfS1-Interface element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding partOfS1-Interface: %w", err)
		}
	default:
		return fmt.Errorf("unknown ResetType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes ResetType from APER format.
func (v *ResetType) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResetType")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResetType")
	}
	return nil
}

func (v *ResetType) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ResetType{}
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
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case ResetTypeChoiceS1Interface:
		val_s1interface, err := per.DecodeEnumeratedAligned(bb, 1, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "S1Interface")
		}
		tmp_s1interface := ResetAll(val_s1interface)
		v.S1Interface = &tmp_s1interface
	case ResetTypeChoicePartOfS1Interface:
		tmp_partofs1interface := make(UEAssociatedLogicalS1ConnectionListRes, 0)
		_, errCollection_partofs1interface := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_partofs1interface, fragmentLength_partofs1interface int64) error {
			for i := int64(0); i < fragmentLength_partofs1interface; i++ {
				var elem ProtocolIESingleContainer
				if err := elem.UnmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("PartOfS1Interface[%d]", fragmentOffset_partofs1interface+i))
				}
				tmp_partofs1interface = append(tmp_partofs1interface, elem)
			}
			return nil
		})
		if errCollection_partofs1interface != nil {
			return runtime.WrapDecodePath(errCollection_partofs1interface, "PartOfS1Interface")
		}
		v.PartOfS1Interface = tmp_partofs1interface
	}
	return nil
}

type asn1cAPERUEAssociatedLogicalS1ConnectionListResListValue struct {
	Value UEAssociatedLogicalS1ConnectionListRes
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListRes encodes a UEAssociatedLogicalS1ConnectionListRes list to APER.
func MarshalAPERUEAssociatedLogicalS1ConnectionListRes(list UEAssociatedLogicalS1ConnectionListRes) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERUEAssociatedLogicalS1ConnectionListResTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListResTo appends a UEAssociatedLogicalS1ConnectionListRes list to bb.
func MarshalAPERUEAssociatedLogicalS1ConnectionListResTo(list UEAssociatedLogicalS1ConnectionListRes, bb *per.BitBuffer) error {
	v := asn1cAPERUEAssociatedLogicalS1ConnectionListResListValue{Value: list}
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

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListRes decodes a UEAssociatedLogicalS1ConnectionListRes list from APER.
func UnmarshalAPERUEAssociatedLogicalS1ConnectionListRes(data []byte) (UEAssociatedLogicalS1ConnectionListRes, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERUEAssociatedLogicalS1ConnectionListResFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListRes")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListRes")
	}
	return value, nil
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListResFrom decodes a UEAssociatedLogicalS1ConnectionListRes list from bb.
func UnmarshalAPERUEAssociatedLogicalS1ConnectionListResFrom(bb *per.BitBuffer) (UEAssociatedLogicalS1ConnectionListRes, error) {
	var v asn1cAPERUEAssociatedLogicalS1ConnectionListResListValue
	if err := unmarshalAPERUEAssociatedLogicalS1ConnectionListResInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERUEAssociatedLogicalS1ConnectionListResInto(v *asn1cAPERUEAssociatedLogicalS1ConnectionListResListValue, bb *per.BitBuffer) error {
	v.Value = make(UEAssociatedLogicalS1ConnectionListRes, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ResetAcknowledge to APER format.
func (v *ResetAcknowledge) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ResetAcknowledge) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ResetAcknowledge from APER format.
func (v *ResetAcknowledge) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResetAcknowledge")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResetAcknowledge")
	}
	return nil
}

func (v *ResetAcknowledge) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ResetAcknowledge{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERUEAssociatedLogicalS1ConnectionListResAckListValue struct {
	Value UEAssociatedLogicalS1ConnectionListResAck
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListResAck encodes a UEAssociatedLogicalS1ConnectionListResAck list to APER.
func MarshalAPERUEAssociatedLogicalS1ConnectionListResAck(list UEAssociatedLogicalS1ConnectionListResAck) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERUEAssociatedLogicalS1ConnectionListResAckTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListResAckTo appends a UEAssociatedLogicalS1ConnectionListResAck list to bb.
func MarshalAPERUEAssociatedLogicalS1ConnectionListResAckTo(list UEAssociatedLogicalS1ConnectionListResAck, bb *per.BitBuffer) error {
	v := asn1cAPERUEAssociatedLogicalS1ConnectionListResAckListValue{Value: list}
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

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAck decodes a UEAssociatedLogicalS1ConnectionListResAck list from APER.
func UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAck(data []byte) (UEAssociatedLogicalS1ConnectionListResAck, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListResAck")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListResAck")
	}
	return value, nil
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckFrom decodes a UEAssociatedLogicalS1ConnectionListResAck list from bb.
func UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckFrom(bb *per.BitBuffer) (UEAssociatedLogicalS1ConnectionListResAck, error) {
	var v asn1cAPERUEAssociatedLogicalS1ConnectionListResAckListValue
	if err := unmarshalAPERUEAssociatedLogicalS1ConnectionListResAckInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERUEAssociatedLogicalS1ConnectionListResAckInto(v *asn1cAPERUEAssociatedLogicalS1ConnectionListResAckListValue, bb *per.BitBuffer) error {
	v.Value = make(UEAssociatedLogicalS1ConnectionListResAck, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ErrorIndication to APER format.
func (v *ErrorIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ErrorIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ErrorIndication from APER format.
func (v *ErrorIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ErrorIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ErrorIndication")
	}
	return nil
}

func (v *ErrorIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ErrorIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes S1SetupRequest to APER format.
func (v *S1SetupRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *S1SetupRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes S1SetupRequest from APER format.
func (v *S1SetupRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1SetupRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1SetupRequest")
	}
	return nil
}

func (v *S1SetupRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = S1SetupRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes S1SetupResponse to APER format.
func (v *S1SetupResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *S1SetupResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes S1SetupResponse from APER format.
func (v *S1SetupResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1SetupResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1SetupResponse")
	}
	return nil
}

func (v *S1SetupResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = S1SetupResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes S1SetupFailure to APER format.
func (v *S1SetupFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *S1SetupFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes S1SetupFailure from APER format.
func (v *S1SetupFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1SetupFailure")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1SetupFailure")
	}
	return nil
}

func (v *S1SetupFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = S1SetupFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ENBConfigurationUpdate to APER format.
func (v *ENBConfigurationUpdate) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ENBConfigurationUpdate) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ENBConfigurationUpdate from APER format.
func (v *ENBConfigurationUpdate) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdate")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdate")
	}
	return nil
}

func (v *ENBConfigurationUpdate) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ENBConfigurationUpdate{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ENBConfigurationUpdateAcknowledge to APER format.
func (v *ENBConfigurationUpdateAcknowledge) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ENBConfigurationUpdateAcknowledge) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ENBConfigurationUpdateAcknowledge from APER format.
func (v *ENBConfigurationUpdateAcknowledge) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledge")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledge")
	}
	return nil
}

func (v *ENBConfigurationUpdateAcknowledge) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ENBConfigurationUpdateAcknowledge{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ENBConfigurationUpdateFailure to APER format.
func (v *ENBConfigurationUpdateFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ENBConfigurationUpdateFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ENBConfigurationUpdateFailure from APER format.
func (v *ENBConfigurationUpdateFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailure")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailure")
	}
	return nil
}

func (v *ENBConfigurationUpdateFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ENBConfigurationUpdateFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes MMEConfigurationUpdate to APER format.
func (v *MMEConfigurationUpdate) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *MMEConfigurationUpdate) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes MMEConfigurationUpdate from APER format.
func (v *MMEConfigurationUpdate) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdate")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdate")
	}
	return nil
}

func (v *MMEConfigurationUpdate) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MMEConfigurationUpdate{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes MMEConfigurationUpdateAcknowledge to APER format.
func (v *MMEConfigurationUpdateAcknowledge) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *MMEConfigurationUpdateAcknowledge) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes MMEConfigurationUpdateAcknowledge from APER format.
func (v *MMEConfigurationUpdateAcknowledge) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledge")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdateAcknowledge")
	}
	return nil
}

func (v *MMEConfigurationUpdateAcknowledge) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MMEConfigurationUpdateAcknowledge{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes MMEConfigurationUpdateFailure to APER format.
func (v *MMEConfigurationUpdateFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *MMEConfigurationUpdateFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes MMEConfigurationUpdateFailure from APER format.
func (v *MMEConfigurationUpdateFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailure")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationUpdateFailure")
	}
	return nil
}

func (v *MMEConfigurationUpdateFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MMEConfigurationUpdateFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes DownlinkS1cdma2000tunnelling to APER format.
func (v *DownlinkS1cdma2000tunnelling) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *DownlinkS1cdma2000tunnelling) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes DownlinkS1cdma2000tunnelling from APER format.
func (v *DownlinkS1cdma2000tunnelling) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkS1cdma2000tunnelling")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkS1cdma2000tunnelling")
	}
	return nil
}

func (v *DownlinkS1cdma2000tunnelling) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = DownlinkS1cdma2000tunnelling{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UplinkS1cdma2000tunnelling to APER format.
func (v *UplinkS1cdma2000tunnelling) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UplinkS1cdma2000tunnelling) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UplinkS1cdma2000tunnelling from APER format.
func (v *UplinkS1cdma2000tunnelling) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnelling")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnelling")
	}
	return nil
}

func (v *UplinkS1cdma2000tunnelling) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UplinkS1cdma2000tunnelling{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UECapabilityInfoIndication to APER format.
func (v *UECapabilityInfoIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UECapabilityInfoIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UECapabilityInfoIndication from APER format.
func (v *UECapabilityInfoIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UECapabilityInfoIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UECapabilityInfoIndication")
	}
	return nil
}

func (v *UECapabilityInfoIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UECapabilityInfoIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ENBStatusTransfer to APER format.
func (v *ENBStatusTransfer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ENBStatusTransfer) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ENBStatusTransfer from APER format.
func (v *ENBStatusTransfer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransfer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransfer")
	}
	return nil
}

func (v *ENBStatusTransfer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ENBStatusTransfer{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes MMEStatusTransfer to APER format.
func (v *MMEStatusTransfer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *MMEStatusTransfer) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes MMEStatusTransfer from APER format.
func (v *MMEStatusTransfer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEStatusTransfer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEStatusTransfer")
	}
	return nil
}

func (v *MMEStatusTransfer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MMEStatusTransfer{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes TraceStart to APER format.
func (v *TraceStart) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *TraceStart) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes TraceStart from APER format.
func (v *TraceStart) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TraceStart")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "TraceStart")
	}
	return nil
}

func (v *TraceStart) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = TraceStart{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes TraceFailureIndication to APER format.
func (v *TraceFailureIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *TraceFailureIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes TraceFailureIndication from APER format.
func (v *TraceFailureIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TraceFailureIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "TraceFailureIndication")
	}
	return nil
}

func (v *TraceFailureIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = TraceFailureIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes DeactivateTrace to APER format.
func (v *DeactivateTrace) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *DeactivateTrace) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes DeactivateTrace from APER format.
func (v *DeactivateTrace) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DeactivateTrace")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "DeactivateTrace")
	}
	return nil
}

func (v *DeactivateTrace) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = DeactivateTrace{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes CellTrafficTrace to APER format.
func (v *CellTrafficTrace) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *CellTrafficTrace) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes CellTrafficTrace from APER format.
func (v *CellTrafficTrace) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellTrafficTrace")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellTrafficTrace")
	}
	return nil
}

func (v *CellTrafficTrace) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CellTrafficTrace{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes LocationReportingControl to APER format.
func (v *LocationReportingControl) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *LocationReportingControl) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes LocationReportingControl from APER format.
func (v *LocationReportingControl) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LocationReportingControl")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "LocationReportingControl")
	}
	return nil
}

func (v *LocationReportingControl) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = LocationReportingControl{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes LocationReportingFailureIndication to APER format.
func (v *LocationReportingFailureIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *LocationReportingFailureIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes LocationReportingFailureIndication from APER format.
func (v *LocationReportingFailureIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LocationReportingFailureIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "LocationReportingFailureIndication")
	}
	return nil
}

func (v *LocationReportingFailureIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = LocationReportingFailureIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes LocationReport to APER format.
func (v *LocationReport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *LocationReport) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes LocationReport from APER format.
func (v *LocationReport) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LocationReport")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "LocationReport")
	}
	return nil
}

func (v *LocationReport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = LocationReport{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes OverloadStart to APER format.
func (v *OverloadStart) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *OverloadStart) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes OverloadStart from APER format.
func (v *OverloadStart) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OverloadStart")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "OverloadStart")
	}
	return nil
}

func (v *OverloadStart) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = OverloadStart{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes OverloadStop to APER format.
func (v *OverloadStop) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *OverloadStop) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes OverloadStop from APER format.
func (v *OverloadStop) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OverloadStop")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "OverloadStop")
	}
	return nil
}

func (v *OverloadStop) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = OverloadStop{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes WriteReplaceWarningRequest to APER format.
func (v *WriteReplaceWarningRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *WriteReplaceWarningRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes WriteReplaceWarningRequest from APER format.
func (v *WriteReplaceWarningRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WriteReplaceWarningRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "WriteReplaceWarningRequest")
	}
	return nil
}

func (v *WriteReplaceWarningRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = WriteReplaceWarningRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes WriteReplaceWarningResponse to APER format.
func (v *WriteReplaceWarningResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *WriteReplaceWarningResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes WriteReplaceWarningResponse from APER format.
func (v *WriteReplaceWarningResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WriteReplaceWarningResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "WriteReplaceWarningResponse")
	}
	return nil
}

func (v *WriteReplaceWarningResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = WriteReplaceWarningResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ENBDirectInformationTransfer to APER format.
func (v *ENBDirectInformationTransfer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ENBDirectInformationTransfer) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ENBDirectInformationTransfer from APER format.
func (v *ENBDirectInformationTransfer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBDirectInformationTransfer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBDirectInformationTransfer")
	}
	return nil
}

func (v *ENBDirectInformationTransfer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ENBDirectInformationTransfer{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes InterSystemInformationTransferType to APER format.
func (v *InterSystemInformationTransferType) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *InterSystemInformationTransferType) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("InterSystemInformationTransferType: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("InterSystemInformationTransferType: extension index %d must be non-negative", v.UnknownExtension.Index)
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
		return fmt.Errorf("InterSystemInformationTransferType: extension choice %d not supported", v.Choice)
	}
	switch v.Choice {
	case InterSystemInformationTransferTypeChoiceRIMTransfer:
		if v.RIMTransfer == nil {
			return fmt.Errorf("choice alternative rIMTransfer is nil")
		}
		if err := v.RIMTransfer.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding rIMTransfer: %w", err)
		}
	default:
		return fmt.Errorf("unknown InterSystemInformationTransferType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes InterSystemInformationTransferType from APER format.
func (v *InterSystemInformationTransferType) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemInformationTransferType")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemInformationTransferType")
	}
	return nil
}

func (v *InterSystemInformationTransferType) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = InterSystemInformationTransferType{}
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
	case InterSystemInformationTransferTypeChoiceRIMTransfer:
		var dec_rimtransfer RIMTransfer
		if err := dec_rimtransfer.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RIMTransfer")
		}
		v.RIMTransfer = &dec_rimtransfer
	}
	return nil
}

// MarshalAPER encodes MMEDirectInformationTransfer to APER format.
func (v *MMEDirectInformationTransfer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *MMEDirectInformationTransfer) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes MMEDirectInformationTransfer from APER format.
func (v *MMEDirectInformationTransfer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEDirectInformationTransfer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEDirectInformationTransfer")
	}
	return nil
}

func (v *MMEDirectInformationTransfer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MMEDirectInformationTransfer{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ENBConfigurationTransfer to APER format.
func (v *ENBConfigurationTransfer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ENBConfigurationTransfer) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ENBConfigurationTransfer from APER format.
func (v *ENBConfigurationTransfer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationTransfer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationTransfer")
	}
	return nil
}

func (v *ENBConfigurationTransfer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ENBConfigurationTransfer{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes MMEConfigurationTransfer to APER format.
func (v *MMEConfigurationTransfer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *MMEConfigurationTransfer) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes MMEConfigurationTransfer from APER format.
func (v *MMEConfigurationTransfer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationTransfer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationTransfer")
	}
	return nil
}

func (v *MMEConfigurationTransfer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MMEConfigurationTransfer{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes PrivateMessage to APER format.
func (v *PrivateMessage) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *PrivateMessage) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.PrivateIEs)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		for _, elem := range v.PrivateIEs[fragmentOffset_privateies : fragmentOffset_privateies+fragmentLength_privateies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding privateIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding privateIEs: %w", err)
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

// UnmarshalAPER decodes PrivateMessage from APER format.
func (v *PrivateMessage) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PrivateMessage")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "PrivateMessage")
	}
	return nil
}

func (v *PrivateMessage) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PrivateMessage{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.PrivateIEs = make(PrivateIEContainer, 0)
	_, errCollection_privateies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		for i := int64(0); i < fragmentLength_privateies; i++ {
			var elem PrivateIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PrivateIEs[%d]", fragmentOffset_privateies+i))
			}
			v.PrivateIEs = append(v.PrivateIEs, elem)
		}
		return nil
	})
	if errCollection_privateies != nil {
		return runtime.WrapDecodePath(errCollection_privateies, "PrivateIEs")
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

// MarshalAPER encodes KillRequest to APER format.
func (v *KillRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *KillRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes KillRequest from APER format.
func (v *KillRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "KillRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "KillRequest")
	}
	return nil
}

func (v *KillRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = KillRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes KillResponse to APER format.
func (v *KillResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *KillResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes KillResponse from APER format.
func (v *KillResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "KillResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "KillResponse")
	}
	return nil
}

func (v *KillResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = KillResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes PWSRestartIndication to APER format.
func (v *PWSRestartIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *PWSRestartIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes PWSRestartIndication from APER format.
func (v *PWSRestartIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PWSRestartIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "PWSRestartIndication")
	}
	return nil
}

func (v *PWSRestartIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PWSRestartIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes PWSFailureIndication to APER format.
func (v *PWSFailureIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *PWSFailureIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes PWSFailureIndication from APER format.
func (v *PWSFailureIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PWSFailureIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "PWSFailureIndication")
	}
	return nil
}

func (v *PWSFailureIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PWSFailureIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes DownlinkUEAssociatedLPPaTransport to APER format.
func (v *DownlinkUEAssociatedLPPaTransport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *DownlinkUEAssociatedLPPaTransport) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes DownlinkUEAssociatedLPPaTransport from APER format.
func (v *DownlinkUEAssociatedLPPaTransport) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransport")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransport")
	}
	return nil
}

func (v *DownlinkUEAssociatedLPPaTransport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = DownlinkUEAssociatedLPPaTransport{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UplinkUEAssociatedLPPaTransport to APER format.
func (v *UplinkUEAssociatedLPPaTransport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UplinkUEAssociatedLPPaTransport) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UplinkUEAssociatedLPPaTransport from APER format.
func (v *UplinkUEAssociatedLPPaTransport) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransport")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransport")
	}
	return nil
}

func (v *UplinkUEAssociatedLPPaTransport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UplinkUEAssociatedLPPaTransport{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes DownlinkNonUEAssociatedLPPaTransport to APER format.
func (v *DownlinkNonUEAssociatedLPPaTransport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *DownlinkNonUEAssociatedLPPaTransport) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes DownlinkNonUEAssociatedLPPaTransport from APER format.
func (v *DownlinkNonUEAssociatedLPPaTransport) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	return nil
}

func (v *DownlinkNonUEAssociatedLPPaTransport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = DownlinkNonUEAssociatedLPPaTransport{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UplinkNonUEAssociatedLPPaTransport to APER format.
func (v *UplinkNonUEAssociatedLPPaTransport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UplinkNonUEAssociatedLPPaTransport) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UplinkNonUEAssociatedLPPaTransport from APER format.
func (v *UplinkNonUEAssociatedLPPaTransport) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	return nil
}

func (v *UplinkNonUEAssociatedLPPaTransport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UplinkNonUEAssociatedLPPaTransport{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ERABModificationIndication to APER format.
func (v *ERABModificationIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABModificationIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ERABModificationIndication from APER format.
func (v *ERABModificationIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModificationIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModificationIndication")
	}
	return nil
}

func (v *ERABModificationIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABModificationIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABToBeModifiedListBearerModIndListValue struct {
	Value ERABToBeModifiedListBearerModInd
}

// MarshalAPERERABToBeModifiedListBearerModInd encodes a ERABToBeModifiedListBearerModInd list to APER.
func MarshalAPERERABToBeModifiedListBearerModInd(list ERABToBeModifiedListBearerModInd) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABToBeModifiedListBearerModIndTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABToBeModifiedListBearerModIndTo appends a ERABToBeModifiedListBearerModInd list to bb.
func MarshalAPERERABToBeModifiedListBearerModIndTo(list ERABToBeModifiedListBearerModInd, bb *per.BitBuffer) error {
	v := asn1cAPERERABToBeModifiedListBearerModIndListValue{Value: list}
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

// UnmarshalAPERERABToBeModifiedListBearerModInd decodes a ERABToBeModifiedListBearerModInd list from APER.
func UnmarshalAPERERABToBeModifiedListBearerModInd(data []byte) (ERABToBeModifiedListBearerModInd, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABToBeModifiedListBearerModIndFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModInd")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedListBearerModInd")
	}
	return value, nil
}

// UnmarshalAPERERABToBeModifiedListBearerModIndFrom decodes a ERABToBeModifiedListBearerModInd list from bb.
func UnmarshalAPERERABToBeModifiedListBearerModIndFrom(bb *per.BitBuffer) (ERABToBeModifiedListBearerModInd, error) {
	var v asn1cAPERERABToBeModifiedListBearerModIndListValue
	if err := unmarshalAPERERABToBeModifiedListBearerModIndInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABToBeModifiedListBearerModIndInto(v *asn1cAPERERABToBeModifiedListBearerModIndListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABToBeModifiedListBearerModInd, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABToBeModifiedItemBearerModInd to APER format.
func (v *ERABToBeModifiedItemBearerModInd) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABToBeModifiedItemBearerModInd) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := per.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.DLGTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding dL-GTP-TEID: %w", err)
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

// UnmarshalAPER decodes ERABToBeModifiedItemBearerModInd from APER format.
func (v *ERABToBeModifiedItemBearerModInd) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModInd")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModInd")
	}
	return nil
}

func (v *ERABToBeModifiedItemBearerModInd) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABToBeModifiedItemBearerModInd{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_dlgtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "DLGTPTEID")
	}
	v.DLGTPTEID = GTPTEID(val_dlgtpteid)
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

type asn1cAPERERABNotToBeModifiedListBearerModIndListValue struct {
	Value ERABNotToBeModifiedListBearerModInd
}

// MarshalAPERERABNotToBeModifiedListBearerModInd encodes a ERABNotToBeModifiedListBearerModInd list to APER.
func MarshalAPERERABNotToBeModifiedListBearerModInd(list ERABNotToBeModifiedListBearerModInd) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABNotToBeModifiedListBearerModIndTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABNotToBeModifiedListBearerModIndTo appends a ERABNotToBeModifiedListBearerModInd list to bb.
func MarshalAPERERABNotToBeModifiedListBearerModIndTo(list ERABNotToBeModifiedListBearerModInd, bb *per.BitBuffer) error {
	v := asn1cAPERERABNotToBeModifiedListBearerModIndListValue{Value: list}
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

// UnmarshalAPERERABNotToBeModifiedListBearerModInd decodes a ERABNotToBeModifiedListBearerModInd list from APER.
func UnmarshalAPERERABNotToBeModifiedListBearerModInd(data []byte) (ERABNotToBeModifiedListBearerModInd, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABNotToBeModifiedListBearerModIndFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedListBearerModInd")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedListBearerModInd")
	}
	return value, nil
}

// UnmarshalAPERERABNotToBeModifiedListBearerModIndFrom decodes a ERABNotToBeModifiedListBearerModInd list from bb.
func UnmarshalAPERERABNotToBeModifiedListBearerModIndFrom(bb *per.BitBuffer) (ERABNotToBeModifiedListBearerModInd, error) {
	var v asn1cAPERERABNotToBeModifiedListBearerModIndListValue
	if err := unmarshalAPERERABNotToBeModifiedListBearerModIndInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABNotToBeModifiedListBearerModIndInto(v *asn1cAPERERABNotToBeModifiedListBearerModIndListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABNotToBeModifiedListBearerModInd, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABNotToBeModifiedItemBearerModInd to APER format.
func (v *ERABNotToBeModifiedItemBearerModInd) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABNotToBeModifiedItemBearerModInd) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := per.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := per.EncodeOctetStringAligned(bb, []byte(v.DLGTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding dL-GTP-TEID: %w", err)
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

// UnmarshalAPER decodes ERABNotToBeModifiedItemBearerModInd from APER format.
func (v *ERABNotToBeModifiedItemBearerModInd) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModInd")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModInd")
	}
	return nil
}

func (v *ERABNotToBeModifiedItemBearerModInd) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABNotToBeModifiedItemBearerModInd{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_dlgtpteid, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "DLGTPTEID")
	}
	v.DLGTPTEID = GTPTEID(val_dlgtpteid)
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

// MarshalAPER encodes CSGMembershipInfo to APER format.
func (v *CSGMembershipInfo) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *CSGMembershipInfo) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.CellAccessMode != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.PLMNidentity != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.CSGMembershipStatus), 2, false); err != nil {
		return fmt.Errorf("encoding cSGMembershipStatus: %w", err)
	}
	if err := per.EncodeBitStringAligned(bb, v.CSGId.Bytes, v.CSGId.BitLength, 27, 27, true); err != nil {
		return fmt.Errorf("encoding cSG-Id: %w", err)
	}
	if v.CellAccessMode != nil {
		if err := per.EncodeEnumeratedAligned(bb, int64(*v.CellAccessMode), 1, true); err != nil {
			return fmt.Errorf("encoding cellAccessMode: %w", err)
		}
	}
	if v.PLMNidentity != nil {
		if err := per.EncodeOctetStringAligned(bb, []byte(*v.PLMNidentity), 3, 3, true); err != nil {
			return fmt.Errorf("encoding pLMNidentity: %w", err)
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

// UnmarshalAPER decodes CSGMembershipInfo from APER format.
func (v *CSGMembershipInfo) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CSGMembershipInfo")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "CSGMembershipInfo")
	}
	return nil
}

func (v *CSGMembershipInfo) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = CSGMembershipInfo{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_cellaccessmode, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_plmnidentity, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_csgmembershipstatus, err := per.DecodeEnumeratedAligned(bb, 2, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGMembershipStatus")
	}
	v.CSGMembershipStatus = CSGMembershipStatus(val_csgmembershipstatus)
	bsBytes_csgid, bsBitLen_csgid, err := per.DecodeBitStringAligned(bb, 27, 27, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGId")
	}
	v.CSGId = runtime.BitString{Bytes: bsBytes_csgid, BitLength: bsBitLen_csgid}
	if opt_cellaccessmode {
		val_cellaccessmode, err := per.DecodeEnumeratedAligned(bb, 1, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "CellAccessMode")
		}
		tmp_cellaccessmode := CellAccessMode(val_cellaccessmode)
		v.CellAccessMode = &tmp_cellaccessmode
	}
	if opt_plmnidentity {
		val_plmnidentity, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PLMNidentity")
		}
		tmp_plmnidentity := PLMNidentity(val_plmnidentity)
		v.PLMNidentity = &tmp_plmnidentity
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

// MarshalAPER encodes ERABModificationConfirm to APER format.
func (v *ERABModificationConfirm) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABModificationConfirm) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ERABModificationConfirm from APER format.
func (v *ERABModificationConfirm) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModificationConfirm")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModificationConfirm")
	}
	return nil
}

func (v *ERABModificationConfirm) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABModificationConfirm{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABModifyListBearerModConfListValue struct{ Value ERABModifyListBearerModConf }

// MarshalAPERERABModifyListBearerModConf encodes a ERABModifyListBearerModConf list to APER.
func MarshalAPERERABModifyListBearerModConf(list ERABModifyListBearerModConf) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABModifyListBearerModConfTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABModifyListBearerModConfTo appends a ERABModifyListBearerModConf list to bb.
func MarshalAPERERABModifyListBearerModConfTo(list ERABModifyListBearerModConf, bb *per.BitBuffer) error {
	v := asn1cAPERERABModifyListBearerModConfListValue{Value: list}
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

// UnmarshalAPERERABModifyListBearerModConf decodes a ERABModifyListBearerModConf list from APER.
func UnmarshalAPERERABModifyListBearerModConf(data []byte) (ERABModifyListBearerModConf, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABModifyListBearerModConfFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABModifyListBearerModConf")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABModifyListBearerModConf")
	}
	return value, nil
}

// UnmarshalAPERERABModifyListBearerModConfFrom decodes a ERABModifyListBearerModConf list from bb.
func UnmarshalAPERERABModifyListBearerModConfFrom(bb *per.BitBuffer) (ERABModifyListBearerModConf, error) {
	var v asn1cAPERERABModifyListBearerModConfListValue
	if err := unmarshalAPERERABModifyListBearerModConfInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABModifyListBearerModConfInto(v *asn1cAPERERABModifyListBearerModConfListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABModifyListBearerModConf, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABModifyItemBearerModConf to APER format.
func (v *ERABModifyItemBearerModConf) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABModifyItemBearerModConf) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
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

// UnmarshalAPER decodes ERABModifyItemBearerModConf from APER format.
func (v *ERABModifyItemBearerModConf) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyItemBearerModConf")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyItemBearerModConf")
	}
	return nil
}

func (v *ERABModifyItemBearerModConf) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABModifyItemBearerModConf{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
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

// MarshalAPER encodes UEContextModificationIndication to APER format.
func (v *UEContextModificationIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextModificationIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextModificationIndication from APER format.
func (v *UEContextModificationIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationIndication")
	}
	return nil
}

func (v *UEContextModificationIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextModificationIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UEContextModificationConfirm to APER format.
func (v *UEContextModificationConfirm) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextModificationConfirm) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextModificationConfirm from APER format.
func (v *UEContextModificationConfirm) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationConfirm")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationConfirm")
	}
	return nil
}

func (v *UEContextModificationConfirm) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextModificationConfirm{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UEContextSuspendRequest to APER format.
func (v *UEContextSuspendRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextSuspendRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextSuspendRequest from APER format.
func (v *UEContextSuspendRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendRequest")
	}
	return nil
}

func (v *UEContextSuspendRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextSuspendRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UEContextSuspendResponse to APER format.
func (v *UEContextSuspendResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextSuspendResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextSuspendResponse from APER format.
func (v *UEContextSuspendResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendResponse")
	}
	return nil
}

func (v *UEContextSuspendResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextSuspendResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UEContextResumeRequest to APER format.
func (v *UEContextResumeRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextResumeRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextResumeRequest from APER format.
func (v *UEContextResumeRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeRequest")
	}
	return nil
}

func (v *UEContextResumeRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextResumeRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABFailedToResumeListResumeReqListValue struct {
	Value ERABFailedToResumeListResumeReq
}

// MarshalAPERERABFailedToResumeListResumeReq encodes a ERABFailedToResumeListResumeReq list to APER.
func MarshalAPERERABFailedToResumeListResumeReq(list ERABFailedToResumeListResumeReq) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABFailedToResumeListResumeReqTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABFailedToResumeListResumeReqTo appends a ERABFailedToResumeListResumeReq list to bb.
func MarshalAPERERABFailedToResumeListResumeReqTo(list ERABFailedToResumeListResumeReq, bb *per.BitBuffer) error {
	v := asn1cAPERERABFailedToResumeListResumeReqListValue{Value: list}
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

// UnmarshalAPERERABFailedToResumeListResumeReq decodes a ERABFailedToResumeListResumeReq list from APER.
func UnmarshalAPERERABFailedToResumeListResumeReq(data []byte) (ERABFailedToResumeListResumeReq, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABFailedToResumeListResumeReqFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeListResumeReq")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeListResumeReq")
	}
	return value, nil
}

// UnmarshalAPERERABFailedToResumeListResumeReqFrom decodes a ERABFailedToResumeListResumeReq list from bb.
func UnmarshalAPERERABFailedToResumeListResumeReqFrom(bb *per.BitBuffer) (ERABFailedToResumeListResumeReq, error) {
	var v asn1cAPERERABFailedToResumeListResumeReqListValue
	if err := unmarshalAPERERABFailedToResumeListResumeReqInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABFailedToResumeListResumeReqInto(v *asn1cAPERERABFailedToResumeListResumeReqListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABFailedToResumeListResumeReq, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABFailedToResumeItemResumeReq to APER format.
func (v *ERABFailedToResumeItemResumeReq) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABFailedToResumeItemResumeReq) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := v.Cause.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding cause: %w", err)
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

// UnmarshalAPER decodes ERABFailedToResumeItemResumeReq from APER format.
func (v *ERABFailedToResumeItemResumeReq) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReq")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReq")
	}
	return nil
}

func (v *ERABFailedToResumeItemResumeReq) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABFailedToResumeItemResumeReq{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	if err := v.Cause.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
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

// MarshalAPER encodes UEContextResumeResponse to APER format.
func (v *UEContextResumeResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextResumeResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextResumeResponse from APER format.
func (v *UEContextResumeResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeResponse")
	}
	return nil
}

func (v *UEContextResumeResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextResumeResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

type asn1cAPERERABFailedToResumeListResumeResListValue struct {
	Value ERABFailedToResumeListResumeRes
}

// MarshalAPERERABFailedToResumeListResumeRes encodes a ERABFailedToResumeListResumeRes list to APER.
func MarshalAPERERABFailedToResumeListResumeRes(list ERABFailedToResumeListResumeRes) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERERABFailedToResumeListResumeResTo(list, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

// MarshalAPERERABFailedToResumeListResumeResTo appends a ERABFailedToResumeListResumeRes list to bb.
func MarshalAPERERABFailedToResumeListResumeResTo(list ERABFailedToResumeListResumeRes, bb *per.BitBuffer) error {
	v := asn1cAPERERABFailedToResumeListResumeResListValue{Value: list}
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

// UnmarshalAPERERABFailedToResumeListResumeRes decodes a ERABFailedToResumeListResumeRes list from APER.
func UnmarshalAPERERABFailedToResumeListResumeRes(data []byte) (ERABFailedToResumeListResumeRes, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERERABFailedToResumeListResumeResFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeListResumeRes")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeListResumeRes")
	}
	return value, nil
}

// UnmarshalAPERERABFailedToResumeListResumeResFrom decodes a ERABFailedToResumeListResumeRes list from bb.
func UnmarshalAPERERABFailedToResumeListResumeResFrom(bb *per.BitBuffer) (ERABFailedToResumeListResumeRes, error) {
	var v asn1cAPERERABFailedToResumeListResumeResListValue
	if err := unmarshalAPERERABFailedToResumeListResumeResInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERERABFailedToResumeListResumeResInto(v *asn1cAPERERABFailedToResumeListResumeResListValue, bb *per.BitBuffer) error {
	v.Value = make(ERABFailedToResumeListResumeRes, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ERABFailedToResumeItemResumeRes to APER format.
func (v *ERABFailedToResumeItemResumeRes) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ERABFailedToResumeItemResumeRes) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := per.EncodeIntegerBigBoundsAligned(bb, v.ERABID, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := v.Cause.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding cause: %w", err)
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

// UnmarshalAPER decodes ERABFailedToResumeItemResumeRes from APER format.
func (v *ERABFailedToResumeItemResumeRes) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeRes")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeRes")
	}
	return nil
}

func (v *ERABFailedToResumeItemResumeRes) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ERABFailedToResumeItemResumeRes{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("15"), true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	if err := v.Cause.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
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

// MarshalAPER encodes UEContextResumeFailure to APER format.
func (v *UEContextResumeFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEContextResumeFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEContextResumeFailure from APER format.
func (v *UEContextResumeFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeFailure")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeFailure")
	}
	return nil
}

func (v *UEContextResumeFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEContextResumeFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ConnectionEstablishmentIndication to APER format.
func (v *ConnectionEstablishmentIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ConnectionEstablishmentIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ConnectionEstablishmentIndication from APER format.
func (v *ConnectionEstablishmentIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ConnectionEstablishmentIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ConnectionEstablishmentIndication")
	}
	return nil
}

func (v *ConnectionEstablishmentIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ConnectionEstablishmentIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes RetrieveUEInformation to APER format.
func (v *RetrieveUEInformation) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *RetrieveUEInformation) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes RetrieveUEInformation from APER format.
func (v *RetrieveUEInformation) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RetrieveUEInformation")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "RetrieveUEInformation")
	}
	return nil
}

func (v *RetrieveUEInformation) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = RetrieveUEInformation{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UEInformationTransfer to APER format.
func (v *UEInformationTransfer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UEInformationTransfer) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UEInformationTransfer from APER format.
func (v *UEInformationTransfer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEInformationTransfer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEInformationTransfer")
	}
	return nil
}

func (v *UEInformationTransfer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UEInformationTransfer{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes ENBCPRelocationIndication to APER format.
func (v *ENBCPRelocationIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *ENBCPRelocationIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ENBCPRelocationIndication from APER format.
func (v *ENBCPRelocationIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBCPRelocationIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBCPRelocationIndication")
	}
	return nil
}

func (v *ENBCPRelocationIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ENBCPRelocationIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes MMECPRelocationIndication to APER format.
func (v *MMECPRelocationIndication) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *MMECPRelocationIndication) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes MMECPRelocationIndication from APER format.
func (v *MMECPRelocationIndication) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMECPRelocationIndication")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMECPRelocationIndication")
	}
	return nil
}

func (v *MMECPRelocationIndication) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = MMECPRelocationIndication{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes SecondaryRATDataUsageReport to APER format.
func (v *SecondaryRATDataUsageReport) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *SecondaryRATDataUsageReport) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes SecondaryRATDataUsageReport from APER format.
func (v *SecondaryRATDataUsageReport) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReport")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReport")
	}
	return nil
}

func (v *SecondaryRATDataUsageReport) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = SecondaryRATDataUsageReport{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UERadioCapabilityIDMappingRequest to APER format.
func (v *UERadioCapabilityIDMappingRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioCapabilityIDMappingRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UERadioCapabilityIDMappingRequest from APER format.
func (v *UERadioCapabilityIDMappingRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequest")
	}
	return nil
}

func (v *UERadioCapabilityIDMappingRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UERadioCapabilityIDMappingRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes UERadioCapabilityIDMappingResponse to APER format.
func (v *UERadioCapabilityIDMappingResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UERadioCapabilityIDMappingResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes UERadioCapabilityIDMappingResponse from APER format.
func (v *UERadioCapabilityIDMappingResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponse")
	}
	return nil
}

func (v *UERadioCapabilityIDMappingResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UERadioCapabilityIDMappingResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes S1RemovalRequest to APER format.
func (v *S1RemovalRequest) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *S1RemovalRequest) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes S1RemovalRequest from APER format.
func (v *S1RemovalRequest) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1RemovalRequest")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1RemovalRequest")
	}
	return nil
}

func (v *S1RemovalRequest) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = S1RemovalRequest{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes S1RemovalResponse to APER format.
func (v *S1RemovalResponse) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *S1RemovalResponse) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes S1RemovalResponse from APER format.
func (v *S1RemovalResponse) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1RemovalResponse")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1RemovalResponse")
	}
	return nil
}

func (v *S1RemovalResponse) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = S1RemovalResponse{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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

// MarshalAPER encodes S1RemovalFailure to APER format.
func (v *S1RemovalFailure) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *S1RemovalFailure) MarshalAPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.ProtocolIEs)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes S1RemovalFailure from APER format.
func (v *S1RemovalFailure) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1RemovalFailure")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1RemovalFailure")
	}
	return nil
}

func (v *S1RemovalFailure) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = S1RemovalFailure{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ProtocolIEContainer, 0)
	_, errCollection_protocolies := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			v.ProtocolIEs = append(v.ProtocolIEs, elem)
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
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
