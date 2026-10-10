// Code generated from ASN.1 module "MAP-CommonDataTypes". DO NOT EDIT.

package gsm_map

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

const (

	// MaxAddressLength6 is the integer constant for maxAddressLength.
	MaxAddressLength6 int64 = 20

	// MaxISDNAddressLength6 is the integer constant for maxISDN-AddressLength.
	MaxISDNAddressLength6 int64 = 9

	// MaxFTNAddressLength6 is the integer constant for maxFTN-AddressLength.
	MaxFTNAddressLength6 int64 = 15

	// MaxISDNSubaddressLength6 is the integer constant for maxISDN-SubaddressLength.
	MaxISDNSubaddressLength6 int64 = 21

	// MaxSignalInfoLength6 is the integer constant for maxSignalInfoLength.
	MaxSignalInfoLength6 int64 = 200

	// MaxLongSignalInfoLength6 is the integer constant for maxLongSignalInfoLength.
	MaxLongSignalInfoLength6 int64 = 2560

	// AlertingLevel06 is the octet string constant for alertingLevel-0.
	AlertingLevel06 = "\x00"

	// AlertingLevel16 is the octet string constant for alertingLevel-1.
	AlertingLevel16 = "\x01"

	// AlertingLevel26 is the octet string constant for alertingLevel-2.
	AlertingLevel26 = "\x02"

	// AlertingCategory16 is the octet string constant for alertingCategory-1.
	AlertingCategory16 = "\x04"

	// AlertingCategory26 is the octet string constant for alertingCategory-2.
	AlertingCategory26 = "\x05"

	// AlertingCategory36 is the octet string constant for alertingCategory-3.
	AlertingCategory36 = "\x06"

	// AlertingCategory46 is the octet string constant for alertingCategory-4.
	AlertingCategory46 = "\x07"

	// AlertingCategory56 is the octet string constant for alertingCategory-5.
	AlertingCategory56 = "\x08"

	// MaxNumOfHLRId6 is the integer constant for maxNumOfHLR-Id.
	MaxNumOfHLRId6 int64 = 50

	// EmergencyServices6 is the integer constant for emergencyServices.
	EmergencyServices6 int64 = 0

	// EmergencyAlertServices6 is the integer constant for emergencyAlertServices.
	EmergencyAlertServices6 int64 = 1

	// PersonTracking6 is the integer constant for personTracking.
	PersonTracking6 int64 = 2

	// FleetManagement6 is the integer constant for fleetManagement.
	FleetManagement6 int64 = 3

	// AssetManagement6 is the integer constant for assetManagement.
	AssetManagement6 int64 = 4

	// TrafficCongestionReporting6 is the integer constant for trafficCongestionReporting.
	TrafficCongestionReporting6 int64 = 5

	// RoadsideAssistance6 is the integer constant for roadsideAssistance.
	RoadsideAssistance6 int64 = 6

	// RoutingToNearestCommercialEnterprise6 is the integer constant for routingToNearestCommercialEnterprise.
	RoutingToNearestCommercialEnterprise6 int64 = 7

	// Navigation6 is the integer constant for navigation.
	Navigation6 int64 = 8

	// CitySightseeing6 is the integer constant for citySightseeing.
	CitySightseeing6 int64 = 9

	// LocalizedAdvertising6 is the integer constant for localizedAdvertising.
	LocalizedAdvertising6 int64 = 10

	// MobileYellowPages6 is the integer constant for mobileYellowPages.
	MobileYellowPages6 int64 = 11

	// TrafficAndPublicTransportationInfo6 is the integer constant for trafficAndPublicTransportationInfo.
	TrafficAndPublicTransportationInfo6 int64 = 12

	// Weather6 is the integer constant for weather.
	Weather6 int64 = 13

	// AssetAndServiceFinding6 is the integer constant for assetAndServiceFinding.
	AssetAndServiceFinding6 int64 = 14

	// Gaming6 is the integer constant for gaming.
	Gaming6 int64 = 15

	// FindYourFriend6 is the integer constant for findYourFriend.
	FindYourFriend6 int64 = 16

	// Dating6 is the integer constant for dating.
	Dating6 int64 = 17

	// Chatting6 is the integer constant for chatting.
	Chatting6 int64 = 18

	// RouteFinding6 is the integer constant for routeFinding.
	RouteFinding6 int64 = 19

	// WhereAmI6 is the integer constant for whereAmI.
	WhereAmI6 int64 = 20

	// Serv646 is the integer constant for serv64.
	Serv646 int64 = 64

	// Serv656 is the integer constant for serv65.
	Serv656 int64 = 65

	// Serv666 is the integer constant for serv66.
	Serv666 int64 = 66

	// Serv676 is the integer constant for serv67.
	Serv676 int64 = 67

	// Serv686 is the integer constant for serv68.
	Serv686 int64 = 68

	// Serv696 is the integer constant for serv69.
	Serv696 int64 = 69

	// Serv706 is the integer constant for serv70.
	Serv706 int64 = 70

	// Serv716 is the integer constant for serv71.
	Serv716 int64 = 71

	// Serv726 is the integer constant for serv72.
	Serv726 int64 = 72

	// Serv736 is the integer constant for serv73.
	Serv736 int64 = 73

	// Serv746 is the integer constant for serv74.
	Serv746 int64 = 74

	// Serv756 is the integer constant for serv75.
	Serv756 int64 = 75

	// Serv766 is the integer constant for serv76.
	Serv766 int64 = 76

	// Serv776 is the integer constant for serv77.
	Serv776 int64 = 77

	// Serv786 is the integer constant for serv78.
	Serv786 int64 = 78

	// Serv796 is the integer constant for serv79.
	Serv796 int64 = 79

	// Serv806 is the integer constant for serv80.
	Serv806 int64 = 80

	// Serv816 is the integer constant for serv81.
	Serv816 int64 = 81

	// Serv826 is the integer constant for serv82.
	Serv826 int64 = 82

	// Serv836 is the integer constant for serv83.
	Serv836 int64 = 83

	// Serv846 is the integer constant for serv84.
	Serv846 int64 = 84

	// Serv856 is the integer constant for serv85.
	Serv856 int64 = 85

	// Serv866 is the integer constant for serv86.
	Serv866 int64 = 86

	// Serv876 is the integer constant for serv87.
	Serv876 int64 = 87

	// Serv886 is the integer constant for serv88.
	Serv886 int64 = 88

	// Serv896 is the integer constant for serv89.
	Serv896 int64 = 89

	// Serv906 is the integer constant for serv90.
	Serv906 int64 = 90

	// Serv916 is the integer constant for serv91.
	Serv916 int64 = 91

	// Serv926 is the integer constant for serv92.
	Serv926 int64 = 92

	// Serv936 is the integer constant for serv93.
	Serv936 int64 = 93

	// Serv946 is the integer constant for serv94.
	Serv946 int64 = 94

	// Serv956 is the integer constant for serv95.
	Serv956 int64 = 95

	// Serv966 is the integer constant for serv96.
	Serv966 int64 = 96

	// Serv976 is the integer constant for serv97.
	Serv976 int64 = 97

	// Serv986 is the integer constant for serv98.
	Serv986 int64 = 98

	// Serv996 is the integer constant for serv99.
	Serv996 int64 = 99

	// Serv1006 is the integer constant for serv100.
	Serv1006 int64 = 100

	// Serv1016 is the integer constant for serv101.
	Serv1016 int64 = 101

	// Serv1026 is the integer constant for serv102.
	Serv1026 int64 = 102

	// Serv1036 is the integer constant for serv103.
	Serv1036 int64 = 103

	// Serv1046 is the integer constant for serv104.
	Serv1046 int64 = 104

	// Serv1056 is the integer constant for serv105.
	Serv1056 int64 = 105

	// Serv1066 is the integer constant for serv106.
	Serv1066 int64 = 106

	// Serv1076 is the integer constant for serv107.
	Serv1076 int64 = 107

	// Serv1086 is the integer constant for serv108.
	Serv1086 int64 = 108

	// Serv1096 is the integer constant for serv109.
	Serv1096 int64 = 109

	// Serv1106 is the integer constant for serv110.
	Serv1106 int64 = 110

	// Serv1116 is the integer constant for serv111.
	Serv1116 int64 = 111

	// Serv1126 is the integer constant for serv112.
	Serv1126 int64 = 112

	// Serv1136 is the integer constant for serv113.
	Serv1136 int64 = 113

	// Serv1146 is the integer constant for serv114.
	Serv1146 int64 = 114

	// Serv1156 is the integer constant for serv115.
	Serv1156 int64 = 115

	// Serv1166 is the integer constant for serv116.
	Serv1166 int64 = 116

	// Serv1176 is the integer constant for serv117.
	Serv1176 int64 = 117

	// Serv1186 is the integer constant for serv118.
	Serv1186 int64 = 118

	// Serv1196 is the integer constant for serv119.
	Serv1196 int64 = 119

	// Serv1206 is the integer constant for serv120.
	Serv1206 int64 = 120

	// Serv1216 is the integer constant for serv121.
	Serv1216 int64 = 121

	// Serv1226 is the integer constant for serv122.
	Serv1226 int64 = 122

	// Serv1236 is the integer constant for serv123.
	Serv1236 int64 = 123

	// Serv1246 is the integer constant for serv124.
	Serv1246 int64 = 124

	// Serv1256 is the integer constant for serv125.
	Serv1256 int64 = 125

	// Serv1266 is the integer constant for serv126.
	Serv1266 int64 = 126

	// Serv1276 is the integer constant for serv127.
	Serv1276 int64 = 127

	// PriorityLevelA6 is the integer constant for priorityLevelA.
	PriorityLevelA6 int64 = 6

	// PriorityLevelB6 is the integer constant for priorityLevelB.
	PriorityLevelB6 int64 = 5

	// PriorityLevel06 is the integer constant for priorityLevel0.
	PriorityLevel06 int64 = 0

	// PriorityLevel16 is the integer constant for priorityLevel1.
	PriorityLevel16 int64 = 1

	// PriorityLevel26 is the integer constant for priorityLevel2.
	PriorityLevel26 int64 = 2

	// PriorityLevel36 is the integer constant for priorityLevel3.
	PriorityLevel36 int64 = 3

	// PriorityLevel46 is the integer constant for priorityLevel4.
	PriorityLevel46 int64 = 4

	// MaxNumOfMCBearers6 is the integer constant for maxNumOfMC-Bearers.
	MaxNumOfMCBearers6 int64 = 7
)

// TBCDSTRING6 represents the ASN.1 type TBCD-STRING (OCTET_STRING).
type TBCDSTRING6 = []byte

// AddressString6 represents the ASN.1 type AddressString (OCTET_STRING).
type AddressString6 = []byte

// ISDNAddressString6 represents the ASN.1 type ISDN-AddressString (OCTET_STRING).
type ISDNAddressString6 = AddressString6

// FTNAddressString6 represents the ASN.1 type FTN-AddressString (OCTET_STRING).
type FTNAddressString6 = AddressString6

// ISDNSubaddressString6 represents the ASN.1 type ISDN-SubaddressString (OCTET_STRING).
type ISDNSubaddressString6 = []byte

// ExternalSignalInfo6 represents the ASN.1 type ExternalSignalInfo (SEQUENCE).
type ExternalSignalInfo6 struct {
	ProtocolId         ProtocolId6          `asn1:""`
	SignalInfo         SignalInfo6          `asn1:""`
	ExtensionContainer *ExtensionContainer6 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// SignalInfo6 represents the ASN.1 type SignalInfo (OCTET_STRING).
type SignalInfo6 = []byte

// ProtocolId6 represents the ASN.1 ENUMERATED type ProtocolId.
type ProtocolId6 int64

const (
	ProtocolId6Gsm0408    ProtocolId6 = 1
	ProtocolId6Gsm0806    ProtocolId6 = 2
	ProtocolId6GsmBSSMAP  ProtocolId6 = 3
	ProtocolId6Ets3001021 ProtocolId6 = 4
)

func (v ProtocolId6) String() string {
	switch v {
	case ProtocolId6Gsm0408:
		return "gsm-0408"
	case ProtocolId6Gsm0806:
		return "gsm-0806"
	case ProtocolId6GsmBSSMAP:
		return "gsm-BSSMAP"
	case ProtocolId6Ets3001021:
		return "ets-300102-1"
	default:
		return "unknown"
	}
}

// ExtExternalSignalInfo6 represents the ASN.1 type Ext-ExternalSignalInfo (SEQUENCE).
type ExtExternalSignalInfo6 struct {
	ExtProtocolId      ExtProtocolId6       `asn1:""`
	SignalInfo         SignalInfo6          `asn1:""`
	ExtensionContainer *ExtensionContainer6 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// ExtProtocolId6 represents the ASN.1 ENUMERATED type Ext-ProtocolId.
type ExtProtocolId6 int64

const (
	ExtProtocolId6Ets300356 ExtProtocolId6 = 1
)

func (v ExtProtocolId6) String() string {
	switch v {
	case ExtProtocolId6Ets300356:
		return "ets-300356"
	default:
		return "unknown"
	}
}

// AccessNetworkSignalInfo6 represents the ASN.1 type AccessNetworkSignalInfo (SEQUENCE).
type AccessNetworkSignalInfo6 struct {
	AccessNetworkProtocolId AccessNetworkProtocolId6 `asn1:""`
	SignalInfo              LongSignalInfo6          `asn1:""`
	ExtensionContainer      *ExtensionContainer6     `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
	berOriginal_            []byte                   `asn1:"-" json:"-"`
	berSnapshot_            []byte                   `asn1:"-" json:"-"`
}

// LongSignalInfo6 represents the ASN.1 type LongSignalInfo (OCTET_STRING).
type LongSignalInfo6 = []byte

// AccessNetworkProtocolId6 represents the ASN.1 ENUMERATED type AccessNetworkProtocolId.
type AccessNetworkProtocolId6 int64

const (
	AccessNetworkProtocolId6Ts3G48006 AccessNetworkProtocolId6 = 1
	AccessNetworkProtocolId6Ts3G25413 AccessNetworkProtocolId6 = 2
)

func (v AccessNetworkProtocolId6) String() string {
	switch v {
	case AccessNetworkProtocolId6Ts3G48006:
		return "ts3G-48006"
	case AccessNetworkProtocolId6Ts3G25413:
		return "ts3G-25413"
	default:
		return "unknown"
	}
}

// AlertingPattern6 represents the ASN.1 type AlertingPattern (OCTET_STRING).
type AlertingPattern6 = []byte

// IMSI6 represents the ASN.1 type IMSI (OCTET_STRING).
type IMSI6 = TBCDSTRING6

// Identity6 choice constants.
const (
	Identity6ChoiceImsi         = 1
	Identity6ChoiceImsiWithLMSI = 2
)

// Identity6 represents the ASN.1 CHOICE type Identity.
type Identity6 struct {
	Choice       int
	berOriginal_ []byte         `json:"-"`
	berSnapshot_ []byte         `json:"-"`
	Imsi         *IMSI6         `json:"Imsi,omitempty"`
	ImsiWithLMSI *IMSIWithLMSI6 `json:"ImsiWithLMSI,omitempty"`
}

// NewIdentity6Imsi creates a Identity6 with the imsi alternative.
func NewIdentity6Imsi(v IMSI6) Identity6 {
	return Identity6{
		Choice: Identity6ChoiceImsi,
		Imsi:   &v,
	}
}

// NewIdentity6ImsiWithLMSI creates a Identity6 with the imsi-WithLMSI alternative.
func NewIdentity6ImsiWithLMSI(v IMSIWithLMSI6) Identity6 {
	return Identity6{
		Choice:       Identity6ChoiceImsiWithLMSI,
		ImsiWithLMSI: &v,
	}
}

// IMSIWithLMSI6 represents the ASN.1 type IMSI-WithLMSI (SEQUENCE).
type IMSIWithLMSI6 struct {
	Imsi         IMSI6    `asn1:""`
	Lmsi         LMSI6    `asn1:""`
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// ASCICallReference6 represents the ASN.1 type ASCI-CallReference (OCTET_STRING).
type ASCICallReference6 = TBCDSTRING6

// TMSI6 represents the ASN.1 type TMSI (OCTET_STRING).
type TMSI6 = []byte

// SubscriberId6 choice constants.
const (
	SubscriberId6ChoiceImsi = 1
	SubscriberId6ChoiceTmsi = 2
)

// SubscriberId6 represents the ASN.1 CHOICE type SubscriberId.
type SubscriberId6 struct {
	Choice       int
	berOriginal_ []byte `json:"-"`
	berSnapshot_ []byte `json:"-"`
	Imsi         *IMSI6 `json:"Imsi,omitempty"`
	Tmsi         *TMSI6 `json:"Tmsi,omitempty"`
}

// NewSubscriberId6Imsi creates a SubscriberId6 with the imsi alternative.
func NewSubscriberId6Imsi(v IMSI6) SubscriberId6 {
	return SubscriberId6{
		Choice: SubscriberId6ChoiceImsi,
		Imsi:   &v,
	}
}

// NewSubscriberId6Tmsi creates a SubscriberId6 with the tmsi alternative.
func NewSubscriberId6Tmsi(v TMSI6) SubscriberId6 {
	return SubscriberId6{
		Choice: SubscriberId6ChoiceTmsi,
		Tmsi:   &v,
	}
}

// IMEI6 represents the ASN.1 type IMEI (OCTET_STRING).
type IMEI6 = TBCDSTRING6

// HLRId6 represents the ASN.1 type HLR-Id (OCTET_STRING).
type HLRId6 = IMSI6

// HLRList6 represents the ASN.1 type HLR-List (SEQUENCE_OF).
type HLRList6 struct {
	Values       []HLRId6 `json:"Values"`
	berOriginal_ []byte   `json:"-"`
	berSnapshot_ []byte   `json:"-"`
}

// LMSI6 represents the ASN.1 type LMSI (OCTET_STRING).
type LMSI6 = []byte

// GlobalCellId6 represents the ASN.1 type GlobalCellId (OCTET_STRING).
type GlobalCellId6 = []byte

// NetworkResource6 represents the ASN.1 ENUMERATED type NetworkResource.
type NetworkResource6 int64

const (
	NetworkResource6Plmn           NetworkResource6 = 0
	NetworkResource6Hlr            NetworkResource6 = 1
	NetworkResource6Vlr            NetworkResource6 = 2
	NetworkResource6Pvlr           NetworkResource6 = 3
	NetworkResource6ControllingMSC NetworkResource6 = 4
	NetworkResource6Vmsc           NetworkResource6 = 5
	NetworkResource6Eir            NetworkResource6 = 6
	NetworkResource6Rss            NetworkResource6 = 7
)

func (v NetworkResource6) String() string {
	switch v {
	case NetworkResource6Plmn:
		return "plmn"
	case NetworkResource6Hlr:
		return "hlr"
	case NetworkResource6Vlr:
		return "vlr"
	case NetworkResource6Pvlr:
		return "pvlr"
	case NetworkResource6ControllingMSC:
		return "controllingMSC"
	case NetworkResource6Vmsc:
		return "vmsc"
	case NetworkResource6Eir:
		return "eir"
	case NetworkResource6Rss:
		return "rss"
	default:
		return "unknown"
	}
}

// AdditionalNetworkResource6 represents the ASN.1 ENUMERATED type AdditionalNetworkResource.
type AdditionalNetworkResource6 int64

const (
	AdditionalNetworkResource6Sgsn   AdditionalNetworkResource6 = 0
	AdditionalNetworkResource6Ggsn   AdditionalNetworkResource6 = 1
	AdditionalNetworkResource6Gmlc   AdditionalNetworkResource6 = 2
	AdditionalNetworkResource6GsmSCF AdditionalNetworkResource6 = 3
	AdditionalNetworkResource6Nplr   AdditionalNetworkResource6 = 4
	AdditionalNetworkResource6Auc    AdditionalNetworkResource6 = 5
)

func (v AdditionalNetworkResource6) String() string {
	switch v {
	case AdditionalNetworkResource6Sgsn:
		return "sgsn"
	case AdditionalNetworkResource6Ggsn:
		return "ggsn"
	case AdditionalNetworkResource6Gmlc:
		return "gmlc"
	case AdditionalNetworkResource6GsmSCF:
		return "gsmSCF"
	case AdditionalNetworkResource6Nplr:
		return "nplr"
	case AdditionalNetworkResource6Auc:
		return "auc"
	default:
		return "unknown"
	}
}

// NAEAPreferredCI6 represents the ASN.1 type NAEA-PreferredCI (SEQUENCE).
type NAEAPreferredCI6 struct {
	NaeaPreferredCIC   NAEACIC6             `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionContainer6 `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// NAEACIC6 represents the ASN.1 type NAEA-CIC (OCTET_STRING).
type NAEACIC6 = []byte

// SubscriberIdentity6 choice constants.
const (
	SubscriberIdentity6ChoiceImsi   = 1
	SubscriberIdentity6ChoiceMsisdn = 2
)

// SubscriberIdentity6 represents the ASN.1 CHOICE type SubscriberIdentity.
type SubscriberIdentity6 struct {
	Choice       int
	berOriginal_ []byte              `json:"-"`
	berSnapshot_ []byte              `json:"-"`
	Imsi         *IMSI6              `json:"Imsi,omitempty"`
	Msisdn       *ISDNAddressString6 `json:"Msisdn,omitempty"`
}

// NewSubscriberIdentity6Imsi creates a SubscriberIdentity6 with the imsi alternative.
func NewSubscriberIdentity6Imsi(v IMSI6) SubscriberIdentity6 {
	return SubscriberIdentity6{
		Choice: SubscriberIdentity6ChoiceImsi,
		Imsi:   &v,
	}
}

// NewSubscriberIdentity6Msisdn creates a SubscriberIdentity6 with the msisdn alternative.
func NewSubscriberIdentity6Msisdn(v ISDNAddressString6) SubscriberIdentity6 {
	return SubscriberIdentity6{
		Choice: SubscriberIdentity6ChoiceMsisdn,
		Msisdn: &v,
	}
}

// LCSClientExternalID6 represents the ASN.1 type LCSClientExternalID (SEQUENCE).
type LCSClientExternalID6 struct {
	ExternalAddress    *ISDNAddressString6  `asn1:"tag:0,context,implicit,optional" json:"ExternalAddress,omitempty"`
	ExtensionContainer *ExtensionContainer6 `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// LCSClientInternalID6 represents the ASN.1 ENUMERATED type LCSClientInternalID.
type LCSClientInternalID6 int64

const (
	LCSClientInternalID6BroadcastService          LCSClientInternalID6 = 0
	LCSClientInternalID6OAndMHPLMN                LCSClientInternalID6 = 1
	LCSClientInternalID6OAndMVPLMN                LCSClientInternalID6 = 2
	LCSClientInternalID6AnonymousLocation         LCSClientInternalID6 = 3
	LCSClientInternalID6TargetMSsubscribedService LCSClientInternalID6 = 4
)

func (v LCSClientInternalID6) String() string {
	switch v {
	case LCSClientInternalID6BroadcastService:
		return "broadcastService"
	case LCSClientInternalID6OAndMHPLMN:
		return "o-andM-HPLMN"
	case LCSClientInternalID6OAndMVPLMN:
		return "o-andM-VPLMN"
	case LCSClientInternalID6AnonymousLocation:
		return "anonymousLocation"
	case LCSClientInternalID6TargetMSsubscribedService:
		return "targetMSsubscribedService"
	default:
		return "unknown"
	}
}

// LCSServiceTypeID6 represents the ASN.1 type LCSServiceTypeID (INTEGER).
type LCSServiceTypeID6 = int64

// PLMNId6 represents the ASN.1 type PLMN-Id (OCTET_STRING).
type PLMNId6 = []byte

// CellGlobalIdOrServiceAreaIdOrLAI6 choice constants.
const (
	CellGlobalIdOrServiceAreaIdOrLAI6ChoiceCellGlobalIdOrServiceAreaIdFixedLength = 1
	CellGlobalIdOrServiceAreaIdOrLAI6ChoiceLaiFixedLength                         = 2
)

// CellGlobalIdOrServiceAreaIdOrLAI6 represents the ASN.1 CHOICE type CellGlobalIdOrServiceAreaIdOrLAI.
type CellGlobalIdOrServiceAreaIdOrLAI6 struct {
	Choice                                 int
	berOriginal_                           []byte                                   `json:"-"`
	berSnapshot_                           []byte                                   `json:"-"`
	CellGlobalIdOrServiceAreaIdFixedLength *CellGlobalIdOrServiceAreaIdFixedLength6 `json:"CellGlobalIdOrServiceAreaIdFixedLength,omitempty"`
	LaiFixedLength                         *LAIFixedLength6                         `json:"LaiFixedLength,omitempty"`
}

// NewCellGlobalIdOrServiceAreaIdOrLAI6CellGlobalIdOrServiceAreaIdFixedLength creates a CellGlobalIdOrServiceAreaIdOrLAI6 with the cellGlobalIdOrServiceAreaIdFixedLength alternative.
func NewCellGlobalIdOrServiceAreaIdOrLAI6CellGlobalIdOrServiceAreaIdFixedLength(v CellGlobalIdOrServiceAreaIdFixedLength6) CellGlobalIdOrServiceAreaIdOrLAI6 {
	return CellGlobalIdOrServiceAreaIdOrLAI6{
		Choice:                                 CellGlobalIdOrServiceAreaIdOrLAI6ChoiceCellGlobalIdOrServiceAreaIdFixedLength,
		CellGlobalIdOrServiceAreaIdFixedLength: &v,
	}
}

// NewCellGlobalIdOrServiceAreaIdOrLAI6LaiFixedLength creates a CellGlobalIdOrServiceAreaIdOrLAI6 with the laiFixedLength alternative.
func NewCellGlobalIdOrServiceAreaIdOrLAI6LaiFixedLength(v LAIFixedLength6) CellGlobalIdOrServiceAreaIdOrLAI6 {
	return CellGlobalIdOrServiceAreaIdOrLAI6{
		Choice:         CellGlobalIdOrServiceAreaIdOrLAI6ChoiceLaiFixedLength,
		LaiFixedLength: &v,
	}
}

// CellGlobalIdOrServiceAreaIdFixedLength6 represents the ASN.1 type CellGlobalIdOrServiceAreaIdFixedLength (OCTET_STRING).
type CellGlobalIdOrServiceAreaIdFixedLength6 = []byte

// LAIFixedLength6 represents the ASN.1 type LAIFixedLength (OCTET_STRING).
type LAIFixedLength6 = []byte

// BasicServiceCode6 choice constants.
const (
	BasicServiceCode6ChoiceBearerService = 1
	BasicServiceCode6ChoiceTeleservice   = 2
)

// BasicServiceCode6 represents the ASN.1 CHOICE type BasicServiceCode.
type BasicServiceCode6 struct {
	Choice        int
	berOriginal_  []byte              `json:"-"`
	berSnapshot_  []byte              `json:"-"`
	BearerService *BearerServiceCode6 `json:"BearerService,omitempty"`
	Teleservice   *TeleserviceCode6   `json:"Teleservice,omitempty"`
}

// NewBasicServiceCode6BearerService creates a BasicServiceCode6 with the bearerService alternative.
func NewBasicServiceCode6BearerService(v BearerServiceCode6) BasicServiceCode6 {
	return BasicServiceCode6{
		Choice:        BasicServiceCode6ChoiceBearerService,
		BearerService: &v,
	}
}

// NewBasicServiceCode6Teleservice creates a BasicServiceCode6 with the teleservice alternative.
func NewBasicServiceCode6Teleservice(v TeleserviceCode6) BasicServiceCode6 {
	return BasicServiceCode6{
		Choice:      BasicServiceCode6ChoiceTeleservice,
		Teleservice: &v,
	}
}

// ExtBasicServiceCode6 choice constants.
const (
	ExtBasicServiceCode6ChoiceExtBearerService = 1
	ExtBasicServiceCode6ChoiceExtTeleservice   = 2
)

// ExtBasicServiceCode6 represents the ASN.1 CHOICE type Ext-BasicServiceCode.
type ExtBasicServiceCode6 struct {
	Choice           int
	berOriginal_     []byte                 `json:"-"`
	berSnapshot_     []byte                 `json:"-"`
	ExtBearerService *ExtBearerServiceCode6 `json:"ExtBearerService,omitempty"`
	ExtTeleservice   *ExtTeleserviceCode6   `json:"ExtTeleservice,omitempty"`
}

// NewExtBasicServiceCode6ExtBearerService creates a ExtBasicServiceCode6 with the ext-BearerService alternative.
func NewExtBasicServiceCode6ExtBearerService(v ExtBearerServiceCode6) ExtBasicServiceCode6 {
	return ExtBasicServiceCode6{
		Choice:           ExtBasicServiceCode6ChoiceExtBearerService,
		ExtBearerService: &v,
	}
}

// NewExtBasicServiceCode6ExtTeleservice creates a ExtBasicServiceCode6 with the ext-Teleservice alternative.
func NewExtBasicServiceCode6ExtTeleservice(v ExtTeleserviceCode6) ExtBasicServiceCode6 {
	return ExtBasicServiceCode6{
		Choice:         ExtBasicServiceCode6ChoiceExtTeleservice,
		ExtTeleservice: &v,
	}
}

// EMLPPInfo6 represents the ASN.1 type EMLPP-Info (SEQUENCE).
type EMLPPInfo6 struct {
	MaximumentitledPriority EMLPPPriority6       `asn1:""`
	DefaultPriority         EMLPPPriority6       `asn1:""`
	ExtensionContainer      *ExtensionContainer6 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                `asn1:"-" json:"-"`
	ExtPresent_             []bool               `asn1:"-" json:"-"`
	ExtData_                [][]byte             `asn1:"-" json:"-"`
	berOriginal_            []byte               `asn1:"-" json:"-"`
	berSnapshot_            []byte               `asn1:"-" json:"-"`
}

// EMLPPPriority6 represents the ASN.1 type EMLPP-Priority (INTEGER).
type EMLPPPriority6 = int64

// MCSSInfo6 represents the ASN.1 type MC-SS-Info (SEQUENCE).
type MCSSInfo6 struct {
	SsCode             SSCode6              `asn1:"tag:0,context,implicit"`
	SsStatus           ExtSSStatus6         `asn1:"tag:1,context,implicit"`
	NbrSB              MaxMCBearers6        `asn1:"tag:2,context,implicit"`
	NbrUser            MCBearers6           `asn1:"tag:3,context,implicit"`
	ExtensionContainer *ExtensionContainer6 `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// MaxMCBearers6 represents the ASN.1 type MaxMC-Bearers (INTEGER).
type MaxMCBearers6 = int64

// MCBearers6 represents the ASN.1 type MC-Bearers (INTEGER).
type MCBearers6 = int64

// ExtSSStatus6 represents the ASN.1 type Ext-SS-Status (OCTET_STRING).
type ExtSSStatus6 = []byte

// AgeOfLocationInformation6 represents the ASN.1 type AgeOfLocationInformation (INTEGER).
type AgeOfLocationInformation6 = int64

// MarshalBER encodes ExternalSignalInfo6 to BER format.
func (v *ExternalSignalInfo6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExternalSignalInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExternalSignalInfo6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := ber.CheckEncodedValue(opts, "protocolId", "ENUMERATED {1, 2, 3, 4}", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ExternalSignalInfo6 to DER format.
func (v *ExternalSignalInfo6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExternalSignalInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := ber.CheckEncodedValue(nil, "protocolId", "ENUMERATED {1, 2, 3, 4}", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(nil, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExternalSignalInfo6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExternalSignalInfo6 from BER/DER format.
func (v *ExternalSignalInfo6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExternalSignalInfo6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExternalSignalInfo6{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ExternalSignalInfo6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExternalSignalInfo6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field protocolId")
	}
	val_protocolid, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding protocolId: %w", err)
	}
	v.ProtocolId = ProtocolId6(val_protocolid)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := ber.CheckDecodedValue(opts, "protocolId", "ENUMERATED {1, 2, 3, 4}", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo6(val_signalinfo)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckDecodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer6)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer6
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo6", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo6", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ExtExternalSignalInfo6 to BER format.
func (v *ExtExternalSignalInfo6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtExternalSignalInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtExternalSignalInfo6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_extprotocolid := ber.EncodeEnumerated(int64(v.ExtProtocolId))
	children = append(children, enc_extprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ExtExternalSignalInfo6 to DER format.
func (v *ExtExternalSignalInfo6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtExternalSignalInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_extprotocolid := ber.EncodeEnumerated(int64(v.ExtProtocolId))
	children = append(children, enc_extprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(nil, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtExternalSignalInfo6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtExternalSignalInfo6 from BER/DER format.
func (v *ExtExternalSignalInfo6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtExternalSignalInfo6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtExternalSignalInfo6{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ExtExternalSignalInfo6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtExternalSignalInfo6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ext-ProtocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field ext-ProtocolId")
	}
	val_extprotocolid, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ext-ProtocolId: %w", err)
	}
	v.ExtProtocolId = ExtProtocolId6(val_extprotocolid)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo6(val_signalinfo)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckDecodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer6)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer6
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtExternalSignalInfo6", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExtExternalSignalInfo6", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AccessNetworkSignalInfo6 to BER format.
func (v *AccessNetworkSignalInfo6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AccessNetworkSignalInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AccessNetworkSignalInfo6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_accessnetworkprotocolid := ber.EncodeEnumerated(int64(v.AccessNetworkProtocolId))
	children = append(children, enc_accessnetworkprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 2560 {
		if constraintErr := ber.CheckEncodedLength(opts, "signalInfo", "SIZE (1..2560)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AccessNetworkSignalInfo6 to DER format.
func (v *AccessNetworkSignalInfo6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AccessNetworkSignalInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_accessnetworkprotocolid := ber.EncodeEnumerated(int64(v.AccessNetworkProtocolId))
	children = append(children, enc_accessnetworkprotocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 2560 {
		if constraintErr := ber.CheckEncodedLength(nil, "signalInfo", "SIZE (1..2560)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AccessNetworkSignalInfo6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AccessNetworkSignalInfo6 from BER/DER format.
func (v *AccessNetworkSignalInfo6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AccessNetworkSignalInfo6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AccessNetworkSignalInfo6{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding AccessNetworkSignalInfo6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AccessNetworkSignalInfo6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode accessNetworkProtocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field accessNetworkProtocolId")
	}
	val_accessnetworkprotocolid, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding accessNetworkProtocolId: %w", err)
	}
	v.AccessNetworkProtocolId = AccessNetworkProtocolId6(val_accessnetworkprotocolid)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = LongSignalInfo6(val_signalinfo)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 2560 {
		if constraintErr := ber.CheckDecodedLength(opts, "signalInfo", "SIZE (1..2560)", len(v.SignalInfo)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer6)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer6
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AccessNetworkSignalInfo6", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "AccessNetworkSignalInfo6", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes Identity6 to BER format.
func (v *Identity6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Identity6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Identity6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case Identity6ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice Identity6: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_0)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case Identity6ChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice Identity6: imsi-WithLMSI is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ImsiWithLMSI.MarshalBER(ber.ChildEncodeOptions(opts, "imsi-WithLMSI")...)
		if err != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Identity6", v.Choice)
	}
}

// MarshalDER encodes Identity6 to DER format.
func (v *Identity6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Identity6 receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case Identity6ChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice Identity6: imsi-WithLMSI is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ImsiWithLMSI.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI: %w", err)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Identity6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Identity6 from BER/DER format.
func (v *Identity6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Identity6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = Identity6{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Identity6 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Identity6: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding Identity6 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Identity6", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = Identity6ChoiceImsi
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return fmt.Errorf("decoding imsi: %w", osErr)
		}
		tmp := IMSI6(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = Identity6ChoiceImsiWithLMSI
		var dec IMSIWithLMSI6
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "imsi-WithLMSI")...); unmErr != nil {
			return fmt.Errorf("decoding imsi-WithLMSI: %w", unmErr)
		}
		v.ImsiWithLMSI = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Identity6 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes IMSIWithLMSI6 to BER format.
func (v *IMSIWithLMSI6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: IMSIWithLMSI6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IMSIWithLMSI6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	children = append(children, enc_imsi...)
	if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(v.Lmsi))
	if encodeErr_enc_lmsi != nil {
		return nil, fmt.Errorf("encoding lmsi: %w", encodeErr_enc_lmsi)
	}
	children = append(children, enc_lmsi...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IMSIWithLMSI6 to DER format.
func (v *IMSIWithLMSI6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IMSIWithLMSI6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	children = append(children, enc_imsi...)
	if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(v.Lmsi))
	if encodeErr_enc_lmsi != nil {
		return nil, fmt.Errorf("encoding lmsi: %w", encodeErr_enc_lmsi)
	}
	children = append(children, enc_lmsi...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IMSIWithLMSI6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IMSIWithLMSI6 from BER/DER format.
func (v *IMSIWithLMSI6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IMSIWithLMSI6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IMSIWithLMSI6{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding IMSIWithLMSI6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IMSIWithLMSI6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = IMSI6(val_imsi)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode lmsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field lmsi")
	}
	val_lmsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding lmsi: %w", err)
	}
	v.Lmsi = LMSI6(val_lmsi)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Lmsi) < 4 || len(v.Lmsi) > 4 {
		if constraintErr := ber.CheckDecodedLength(opts, "lmsi", "SIZE (4)", len(v.Lmsi)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IMSIWithLMSI6", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubscriberId6 to BER format.
func (v *SubscriberId6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberId6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SubscriberId6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SubscriberId6ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberId6: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_0)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SubscriberId6ChoiceTmsi:
		if v.Tmsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberId6: tmsi is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Tmsi))
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding tmsi: %w", encodeErr_enc_1)
		}
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding tmsi: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SubscriberId6", v.Choice)
	}
}

// MarshalDER encodes SubscriberId6 to DER format.
func (v *SubscriberId6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberId6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberId6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberId6 from BER/DER format.
func (v *SubscriberId6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SubscriberId6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SubscriberId6{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberId6 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberId6: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberId6 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberId6", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberId6ChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding imsi: %w", octetErr)
		}
		tmp := IMSI6(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberId6ChoiceTmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding tmsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding tmsi: %w", octetErr)
		}
		tmp := TMSI6(decVal)
		v.Tmsi = &tmp
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberId6 CHOICE", peekTag)
	}
	return nil
}

// MarshalBERHLRList6 encodes a HLRList6 list to BER.
func MarshalBERHLRList6(collection *HLRList6, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERHLRList6(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERHLRList6(collection *HLRList6, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(opts, "HLRList6", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 3 || len(elem) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (3..8)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERHLRList6 encodes a HLRList6 list to DER.
func MarshalDERHLRList6(collection *HLRList6) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(nil, "HLRList6", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 3 || len(elem) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (3..8)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding HLRList6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERHLRList6 decodes a HLRList6 list from BER.
func UnmarshalBERHLRList6(data []byte, opts ...ber.DecodeOption) (returnValue *HLRList6, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding HLRList6: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "HLRList6", Cause: ber.ErrExtraData}
	}
	var result []HLRId6
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 3 || len(val) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (3..8)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, HLRId6(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedLength(opts, "HLRList6", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &HLRList6{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERHLRList6(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes NAEAPreferredCI6 to BER format.
func (v *NAEAPreferredCI6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: NAEAPreferredCI6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NAEAPreferredCI6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.NaeaPreferredCIC) < 3 || len(v.NaeaPreferredCIC) > 3 {
		if constraintErr := ber.CheckEncodedLength(opts, "naea-PreferredCIC", "SIZE (3)", len(v.NaeaPreferredCIC)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_naeapreferredcic, encodeErr_enc_naeapreferredcic := ber.EncodeOctetString([]byte(v.NaeaPreferredCIC))
	if encodeErr_enc_naeapreferredcic != nil {
		return nil, fmt.Errorf("encoding naea-PreferredCIC: %w", encodeErr_enc_naeapreferredcic)
	}
	retagged_enc_naeapreferredcic, tagErr_enc_naeapreferredcic := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naeapreferredcic)
	if tagErr_enc_naeapreferredcic != nil {
		return nil, fmt.Errorf("encoding naea-PreferredCIC: %w", tagErr_enc_naeapreferredcic)
	}
	enc_naeapreferredcic = retagged_enc_naeapreferredcic
	children = append(children, enc_naeapreferredcic...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes NAEAPreferredCI6 to DER format.
func (v *NAEAPreferredCI6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NAEAPreferredCI6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.NaeaPreferredCIC) < 3 || len(v.NaeaPreferredCIC) > 3 {
		if constraintErr := ber.CheckEncodedLength(nil, "naea-PreferredCIC", "SIZE (3)", len(v.NaeaPreferredCIC)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_naeapreferredcic, encodeErr_enc_naeapreferredcic := ber.EncodeOctetString([]byte(v.NaeaPreferredCIC))
	if encodeErr_enc_naeapreferredcic != nil {
		return nil, fmt.Errorf("encoding naea-PreferredCIC: %w", encodeErr_enc_naeapreferredcic)
	}
	retagged_enc_naeapreferredcic, tagErr_enc_naeapreferredcic := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naeapreferredcic)
	if tagErr_enc_naeapreferredcic != nil {
		return nil, fmt.Errorf("encoding naea-PreferredCIC: %w", tagErr_enc_naeapreferredcic)
	}
	enc_naeapreferredcic = retagged_enc_naeapreferredcic
	children = append(children, enc_naeapreferredcic...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding NAEAPreferredCI6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NAEAPreferredCI6 from BER/DER format.
func (v *NAEAPreferredCI6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NAEAPreferredCI6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NAEAPreferredCI6{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding NAEAPreferredCI6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NAEAPreferredCI6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode naea-PreferredCIC
	if offset >= len(content) {
		return fmt.Errorf("missing required field naea-PreferredCIC")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for naea-PreferredCIC, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_naeapreferredcic, n_naeapreferredcic, rawVal_naeapreferredcic, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding naea-PreferredCIC: %w", err)
	}
	if decodedTag_naeapreferredcic.Class != tag.ClassContextSpecific || decodedTag_naeapreferredcic.Number != 0 {
		return fmt.Errorf("decoding naea-PreferredCIC: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naeapreferredcic)
	}
	decVal_naeapreferredcic, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_naeapreferredcic.Constructed, rawVal_naeapreferredcic, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding naea-PreferredCIC: %w", octetErr)
	}
	v.NaeaPreferredCIC = NAEACIC6(decVal_naeapreferredcic)
	if offset > len(content) || n_naeapreferredcic < 0 || n_naeapreferredcic > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_naeapreferredcic
	if len(v.NaeaPreferredCIC) < 3 || len(v.NaeaPreferredCIC) > 3 {
		if constraintErr := ber.CheckDecodedLength(opts, "naea-PreferredCIC", "SIZE (3)", len(v.NaeaPreferredCIC)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer6
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NAEAPreferredCI6", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "NAEAPreferredCI6", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubscriberIdentity6 to BER format.
func (v *SubscriberIdentity6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberIdentity6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SubscriberIdentity6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SubscriberIdentity6ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberIdentity6: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_0)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SubscriberIdentity6ChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("%w: choice SubscriberIdentity6: msisdn is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_1)
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SubscriberIdentity6", v.Choice)
	}
}

// MarshalDER encodes SubscriberIdentity6 to DER format.
func (v *SubscriberIdentity6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberIdentity6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberIdentity6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberIdentity6 from BER/DER format.
func (v *SubscriberIdentity6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SubscriberIdentity6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SubscriberIdentity6{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberIdentity6 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberIdentity6: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberIdentity6 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberIdentity6", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberIdentity6ChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding imsi: %w", octetErr)
		}
		tmp := IMSI6(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberIdentity6ChoiceMsisdn
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding msisdn: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding msisdn: %w", octetErr)
		}
		tmp := ISDNAddressString6(decVal)
		v.Msisdn = &tmp
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberIdentity6 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes LCSClientExternalID6 to BER format.
func (v *LCSClientExternalID6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSClientExternalID6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSClientExternalID6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExternalAddress != nil {
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "externalAddress", "SIZE (1..9)", len(*v.ExternalAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "externalAddress", "SIZE (1..20)", len(*v.ExternalAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_externaladdress, encodeErr_enc_externaladdress := ber.EncodeOctetString([]byte(*v.ExternalAddress))
		if encodeErr_enc_externaladdress != nil {
			return nil, fmt.Errorf("encoding externalAddress: %w", encodeErr_enc_externaladdress)
		}
		retagged_enc_externaladdress, tagErr_enc_externaladdress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_externaladdress)
		if tagErr_enc_externaladdress != nil {
			return nil, fmt.Errorf("encoding externalAddress: %w", tagErr_enc_externaladdress)
		}
		enc_externaladdress = retagged_enc_externaladdress
		children = append(children, enc_externaladdress...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes LCSClientExternalID6 to DER format.
func (v *LCSClientExternalID6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSClientExternalID6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExternalAddress != nil {
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "externalAddress", "SIZE (1..9)", len(*v.ExternalAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "externalAddress", "SIZE (1..20)", len(*v.ExternalAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_externaladdress, encodeErr_enc_externaladdress := ber.EncodeOctetString([]byte(*v.ExternalAddress))
		if encodeErr_enc_externaladdress != nil {
			return nil, fmt.Errorf("encoding externalAddress: %w", encodeErr_enc_externaladdress)
		}
		retagged_enc_externaladdress, tagErr_enc_externaladdress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_externaladdress)
		if tagErr_enc_externaladdress != nil {
			return nil, fmt.Errorf("encoding externalAddress: %w", tagErr_enc_externaladdress)
		}
		enc_externaladdress = retagged_enc_externaladdress
		children = append(children, enc_externaladdress...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding LCSClientExternalID6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSClientExternalID6 from BER/DER format.
func (v *LCSClientExternalID6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSClientExternalID6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSClientExternalID6{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding LCSClientExternalID6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSClientExternalID6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode externalAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_externaladdress, n_externaladdress, rawVal_externaladdress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding externalAddress: %w", err)
				}
				if decodedTag_externaladdress.Class != tag.ClassContextSpecific || decodedTag_externaladdress.Number != 0 {
					return fmt.Errorf("decoding externalAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_externaladdress)
				}
				decVal_externaladdress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_externaladdress.Constructed, rawVal_externaladdress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding externalAddress: %w", octetErr)
				}
				tmp_externaladdress := ISDNAddressString6(decVal_externaladdress)
				v.ExternalAddress = &tmp_externaladdress
				if offset > len(content) || n_externaladdress < 0 || n_externaladdress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_externaladdress
				if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "externalAddress", "SIZE (1..9)", len(*v.ExternalAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.ExternalAddress) < 1 || len(*v.ExternalAddress) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "externalAddress", "SIZE (1..20)", len(*v.ExternalAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer6
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSClientExternalID6", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSClientExternalID6", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CellGlobalIdOrServiceAreaIdOrLAI6 to BER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CellGlobalIdOrServiceAreaIdOrLAI6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CellGlobalIdOrServiceAreaIdOrLAI6ChoiceCellGlobalIdOrServiceAreaIdFixedLength:
		if v.CellGlobalIdOrServiceAreaIdFixedLength == nil {
			return nil, fmt.Errorf("%w: choice CellGlobalIdOrServiceAreaIdOrLAI6: cellGlobalIdOrServiceAreaIdFixedLength is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.CellGlobalIdOrServiceAreaIdFixedLength))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding cellGlobalIdOrServiceAreaIdFixedLength: %w", encodeErr_enc_0)
		}
		if len(*v.CellGlobalIdOrServiceAreaIdFixedLength) < 7 || len(*v.CellGlobalIdOrServiceAreaIdFixedLength) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "cellGlobalIdOrServiceAreaIdFixedLength", "SIZE (7)", len(*v.CellGlobalIdOrServiceAreaIdFixedLength)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding cellGlobalIdOrServiceAreaIdFixedLength: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case CellGlobalIdOrServiceAreaIdOrLAI6ChoiceLaiFixedLength:
		if v.LaiFixedLength == nil {
			return nil, fmt.Errorf("%w: choice CellGlobalIdOrServiceAreaIdOrLAI6: laiFixedLength is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.LaiFixedLength))
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding laiFixedLength: %w", encodeErr_enc_1)
		}
		if len(*v.LaiFixedLength) < 5 || len(*v.LaiFixedLength) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "laiFixedLength", "SIZE (5)", len(*v.LaiFixedLength)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding laiFixedLength: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CellGlobalIdOrServiceAreaIdOrLAI6", v.Choice)
	}
}

// MarshalDER encodes CellGlobalIdOrServiceAreaIdOrLAI6 to DER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CellGlobalIdOrServiceAreaIdOrLAI6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CellGlobalIdOrServiceAreaIdOrLAI6 from BER/DER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CellGlobalIdOrServiceAreaIdOrLAI6{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CellGlobalIdOrServiceAreaIdOrLAI6 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CellGlobalIdOrServiceAreaIdOrLAI6: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding CellGlobalIdOrServiceAreaIdOrLAI6 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CellGlobalIdOrServiceAreaIdOrLAI6", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAI6ChoiceCellGlobalIdOrServiceAreaIdFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding cellGlobalIdOrServiceAreaIdFixedLength: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding cellGlobalIdOrServiceAreaIdFixedLength: %w", octetErr)
		}
		tmp := CellGlobalIdOrServiceAreaIdFixedLength6(decVal)
		v.CellGlobalIdOrServiceAreaIdFixedLength = &tmp
		if len(*v.CellGlobalIdOrServiceAreaIdFixedLength) < 7 || len(*v.CellGlobalIdOrServiceAreaIdFixedLength) > 7 {
			if constraintErr := ber.CheckDecodedLength(opts, "cellGlobalIdOrServiceAreaIdFixedLength", "SIZE (7)", len(*v.CellGlobalIdOrServiceAreaIdFixedLength)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAI6ChoiceLaiFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding laiFixedLength: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding laiFixedLength: %w", octetErr)
		}
		tmp := LAIFixedLength6(decVal)
		v.LaiFixedLength = &tmp
		if len(*v.LaiFixedLength) < 5 || len(*v.LaiFixedLength) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "laiFixedLength", "SIZE (5)", len(*v.LaiFixedLength)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for CellGlobalIdOrServiceAreaIdOrLAI6 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes BasicServiceCode6 to BER format.
func (v *BasicServiceCode6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BasicServiceCode6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BasicServiceCode6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case BasicServiceCode6ChoiceBearerService:
		if v.BearerService == nil {
			return nil, fmt.Errorf("%w: choice BasicServiceCode6: bearerService is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.BearerService))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding bearerService: %w", encodeErr_enc_0)
		}
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding bearerService: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case BasicServiceCode6ChoiceTeleservice:
		if v.Teleservice == nil {
			return nil, fmt.Errorf("%w: choice BasicServiceCode6: teleservice is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Teleservice))
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding teleservice: %w", encodeErr_enc_1)
		}
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding teleservice: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for BasicServiceCode6", v.Choice)
	}
}

// MarshalDER encodes BasicServiceCode6 to DER format.
func (v *BasicServiceCode6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BasicServiceCode6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BasicServiceCode6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BasicServiceCode6 from BER/DER format.
func (v *BasicServiceCode6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BasicServiceCode6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = BasicServiceCode6{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for BasicServiceCode6 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for BasicServiceCode6: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding BasicServiceCode6 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "BasicServiceCode6", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = BasicServiceCode6ChoiceBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding bearerService: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding bearerService: %w", octetErr)
		}
		tmp := BearerServiceCode6(decVal)
		v.BearerService = &tmp
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = BasicServiceCode6ChoiceTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding teleservice: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding teleservice: %w", octetErr)
		}
		tmp := TeleserviceCode6(decVal)
		v.Teleservice = &tmp
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for BasicServiceCode6 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtBasicServiceCode6 to BER format.
func (v *ExtBasicServiceCode6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtBasicServiceCode6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtBasicServiceCode6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ExtBasicServiceCode6ChoiceExtBearerService:
		if v.ExtBearerService == nil {
			return nil, fmt.Errorf("%w: choice ExtBasicServiceCode6: ext-BearerService is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.ExtBearerService))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding ext-BearerService: %w", encodeErr_enc_0)
		}
		if len(*v.ExtBearerService) < 1 || len(*v.ExtBearerService) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "ext-BearerService", "SIZE (1..5)", len(*v.ExtBearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding ext-BearerService: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ExtBasicServiceCode6ChoiceExtTeleservice:
		if v.ExtTeleservice == nil {
			return nil, fmt.Errorf("%w: choice ExtBasicServiceCode6: ext-Teleservice is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.ExtTeleservice))
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding ext-Teleservice: %w", encodeErr_enc_1)
		}
		if len(*v.ExtTeleservice) < 1 || len(*v.ExtTeleservice) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "ext-Teleservice", "SIZE (1..5)", len(*v.ExtTeleservice)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding ext-Teleservice: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ExtBasicServiceCode6", v.Choice)
	}
}

// MarshalDER encodes ExtBasicServiceCode6 to DER format.
func (v *ExtBasicServiceCode6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtBasicServiceCode6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtBasicServiceCode6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtBasicServiceCode6 from BER/DER format.
func (v *ExtBasicServiceCode6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtBasicServiceCode6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtBasicServiceCode6{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtBasicServiceCode6 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtBasicServiceCode6: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding ExtBasicServiceCode6 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtBasicServiceCode6", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ExtBasicServiceCode6ChoiceExtBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-BearerService: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding ext-BearerService: %w", octetErr)
		}
		tmp := ExtBearerServiceCode6(decVal)
		v.ExtBearerService = &tmp
		if len(*v.ExtBearerService) < 1 || len(*v.ExtBearerService) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "ext-BearerService", "SIZE (1..5)", len(*v.ExtBearerService)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = ExtBasicServiceCode6ChoiceExtTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-Teleservice: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding ext-Teleservice: %w", octetErr)
		}
		tmp := ExtTeleserviceCode6(decVal)
		v.ExtTeleservice = &tmp
		if len(*v.ExtTeleservice) < 1 || len(*v.ExtTeleservice) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "ext-Teleservice", "SIZE (1..5)", len(*v.ExtTeleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for ExtBasicServiceCode6 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EMLPPInfo6 to BER format.
func (v *EMLPPInfo6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: EMLPPInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EMLPPInfo6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.MaximumentitledPriority) >= 0 && int64(v.MaximumentitledPriority) <= 15) {
		if constraintErr := ber.CheckEncodedValue(opts, "maximumentitledPriority", "(0..15)", fmt.Sprint(int64(v.MaximumentitledPriority))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_maximumentitledpriority := ber.EncodeInteger(int64(v.MaximumentitledPriority))
	children = append(children, enc_maximumentitledpriority...)
	if !(int64(v.DefaultPriority) >= 0 && int64(v.DefaultPriority) <= 15) {
		if constraintErr := ber.CheckEncodedValue(opts, "defaultPriority", "(0..15)", fmt.Sprint(int64(v.DefaultPriority))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_defaultpriority := ber.EncodeInteger(int64(v.DefaultPriority))
	children = append(children, enc_defaultpriority...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes EMLPPInfo6 to DER format.
func (v *EMLPPInfo6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EMLPPInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.MaximumentitledPriority) >= 0 && int64(v.MaximumentitledPriority) <= 15) {
		if constraintErr := ber.CheckEncodedValue(nil, "maximumentitledPriority", "(0..15)", fmt.Sprint(int64(v.MaximumentitledPriority))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_maximumentitledpriority := ber.EncodeInteger(int64(v.MaximumentitledPriority))
	children = append(children, enc_maximumentitledpriority...)
	if !(int64(v.DefaultPriority) >= 0 && int64(v.DefaultPriority) <= 15) {
		if constraintErr := ber.CheckEncodedValue(nil, "defaultPriority", "(0..15)", fmt.Sprint(int64(v.DefaultPriority))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_defaultpriority := ber.EncodeInteger(int64(v.DefaultPriority))
	children = append(children, enc_defaultpriority...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding EMLPPInfo6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EMLPPInfo6 from BER/DER format.
func (v *EMLPPInfo6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EMLPPInfo6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = EMLPPInfo6{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding EMLPPInfo6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EMLPPInfo6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode maximumentitledPriority
	if offset >= len(content) {
		return fmt.Errorf("missing required field maximumentitledPriority")
	}
	val_maximumentitledpriority, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding maximumentitledPriority: %w", err)
	}
	v.MaximumentitledPriority = EMLPPPriority6(val_maximumentitledpriority)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.MaximumentitledPriority) >= 0 && int64(v.MaximumentitledPriority) <= 15) {
		if constraintErr := ber.CheckDecodedValue(opts, "maximumentitledPriority", "(0..15)", fmt.Sprint(int64(v.MaximumentitledPriority))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode defaultPriority
	if offset >= len(content) {
		return fmt.Errorf("missing required field defaultPriority")
	}
	val_defaultpriority, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding defaultPriority: %w", err)
	}
	v.DefaultPriority = EMLPPPriority6(val_defaultpriority)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.DefaultPriority) >= 0 && int64(v.DefaultPriority) <= 15) {
		if constraintErr := ber.CheckDecodedValue(opts, "defaultPriority", "(0..15)", fmt.Sprint(int64(v.DefaultPriority))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer6)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer6
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EMLPPInfo6", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "EMLPPInfo6", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MCSSInfo6 to BER format.
func (v *MCSSInfo6) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: MCSSInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MCSSInfo6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 5 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
	}
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	if !(int64(v.NbrSB) >= 2 && int64(v.NbrSB) <= 7) {
		if constraintErr := ber.CheckEncodedValue(opts, "nbrSB", "(2..7)", fmt.Sprint(int64(v.NbrSB))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_nbrsb := ber.EncodeInteger(int64(v.NbrSB))
	retagged_enc_nbrsb, tagErr_enc_nbrsb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_nbrsb)
	if tagErr_enc_nbrsb != nil {
		return nil, fmt.Errorf("encoding nbrSB: %w", tagErr_enc_nbrsb)
	}
	enc_nbrsb = retagged_enc_nbrsb
	children = append(children, enc_nbrsb...)
	if !(int64(v.NbrUser) >= 1 && int64(v.NbrUser) <= 7) {
		if constraintErr := ber.CheckEncodedValue(opts, "nbrUser", "(1..7)", fmt.Sprint(int64(v.NbrUser))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_nbruser := ber.EncodeInteger(int64(v.NbrUser))
	retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_nbruser)
	if tagErr_enc_nbruser != nil {
		return nil, fmt.Errorf("encoding nbrUser: %w", tagErr_enc_nbruser)
	}
	enc_nbruser = retagged_enc_nbruser
	children = append(children, enc_nbruser...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes MCSSInfo6 to DER format.
func (v *MCSSInfo6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MCSSInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 5 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
	}
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	if !(int64(v.NbrSB) >= 2 && int64(v.NbrSB) <= 7) {
		if constraintErr := ber.CheckEncodedValue(nil, "nbrSB", "(2..7)", fmt.Sprint(int64(v.NbrSB))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_nbrsb := ber.EncodeInteger(int64(v.NbrSB))
	retagged_enc_nbrsb, tagErr_enc_nbrsb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_nbrsb)
	if tagErr_enc_nbrsb != nil {
		return nil, fmt.Errorf("encoding nbrSB: %w", tagErr_enc_nbrsb)
	}
	enc_nbrsb = retagged_enc_nbrsb
	children = append(children, enc_nbrsb...)
	if !(int64(v.NbrUser) >= 1 && int64(v.NbrUser) <= 7) {
		if constraintErr := ber.CheckEncodedValue(nil, "nbrUser", "(1..7)", fmt.Sprint(int64(v.NbrUser))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_nbruser := ber.EncodeInteger(int64(v.NbrUser))
	retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_nbruser)
	if tagErr_enc_nbruser != nil {
		return nil, fmt.Errorf("encoding nbrUser: %w", tagErr_enc_nbruser)
	}
	enc_nbruser = retagged_enc_nbruser
	children = append(children, enc_nbruser...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MCSSInfo6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MCSSInfo6 from BER/DER format.
func (v *MCSSInfo6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MCSSInfo6 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MCSSInfo6{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding MCSSInfo6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MCSSInfo6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ss-Code, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
		return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
	}
	decVal_sscode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sscode.Constructed, rawVal_sscode, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding ss-Code: %w", octetErr)
	}
	v.SsCode = SSCode6(decVal_sscode)
	if offset > len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_sscode
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode ss-Status
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Status")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for ss-Status, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ss-Status: %w", err)
	}
	if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 1 {
		return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
	}
	decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding ss-Status: %w", octetErr)
	}
	v.SsStatus = ExtSSStatus6(decVal_ssstatus)
	if offset < 0 || offset >
		len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_ssstatus
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 5 {
		if constraintErr := ber.CheckDecodedLength(opts, "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode nbrSB
	if offset >= len(content) {
		return fmt.Errorf("missing required field nbrSB")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for nbrSB, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	decodedTag_nbrsb, n_nbrsb, rawVal_nbrsb, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding nbrSB: %w", err)
	}
	if decodedTag_nbrsb.Class != tag.ClassContextSpecific || decodedTag_nbrsb.Number != 2 || decodedTag_nbrsb.Constructed != false {
		return fmt.Errorf("decoding nbrSB: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbrsb)
	}
	decVal_nbrsb, intErr := ber.DecodeIntegerValue(rawVal_nbrsb)
	if intErr != nil {
		return fmt.Errorf("decoding nbrSB: %w", intErr)
	}
	v.NbrSB = MaxMCBearers6(decVal_nbrsb)
	if offset < 0 || offset >
		len(content) || n_nbrsb < 0 || n_nbrsb > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_nbrsb
	if !(int64(v.NbrSB) >= 2 && int64(v.NbrSB) <= 7) {
		if constraintErr := ber.CheckDecodedValue(opts, "nbrSB", "(2..7)", fmt.Sprint(int64(v.NbrSB))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode nbrUser
	if offset >= len(content) {
		return fmt.Errorf("missing required field nbrUser")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for nbrUser, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding nbrUser: %w", err)
	}
	if decodedTag_nbruser.Class != tag.ClassContextSpecific || decodedTag_nbruser.Number != 3 || decodedTag_nbruser.Constructed != false {
		return fmt.Errorf("decoding nbrUser: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbruser)
	}
	decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
	if intErr != nil {
		return fmt.Errorf("decoding nbrUser: %w", intErr)
	}
	v.NbrUser = MCBearers6(decVal_nbruser)
	if offset < 0 || offset >
		len(content) || n_nbruser < 0 || n_nbruser > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_nbruser
	if !(int64(v.NbrUser) >= 1 && int64(v.NbrUser) <= 7) {
		if constraintErr := ber.CheckDecodedValue(opts, "nbrUser", "(1..7)", fmt.Sprint(int64(v.NbrUser))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer6
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MCSSInfo6", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MCSSInfo6", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
