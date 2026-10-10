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

	// MaxAddressLength3 is the integer constant for maxAddressLength.
	MaxAddressLength3 int64 = 20

	// MaxISDNAddressLength3 is the integer constant for maxISDN-AddressLength.
	MaxISDNAddressLength3 int64 = 9

	// MaxFTNAddressLength3 is the integer constant for maxFTN-AddressLength.
	MaxFTNAddressLength3 int64 = 15

	// MaxISDNSubaddressLength3 is the integer constant for maxISDN-SubaddressLength.
	MaxISDNSubaddressLength3 int64 = 21

	// MaxSignalInfoLength3 is the integer constant for maxSignalInfoLength.
	MaxSignalInfoLength3 int64 = 200

	// MaxLongSignalInfoLength3 is the integer constant for maxLongSignalInfoLength.
	MaxLongSignalInfoLength3 int64 = 2560

	// AlertingLevel03 is the octet string constant for alertingLevel-0.
	AlertingLevel03 = "\x00"

	// AlertingLevel13 is the octet string constant for alertingLevel-1.
	AlertingLevel13 = "\x01"

	// AlertingLevel23 is the octet string constant for alertingLevel-2.
	AlertingLevel23 = "\x02"

	// AlertingCategory13 is the octet string constant for alertingCategory-1.
	AlertingCategory13 = "\x04"

	// AlertingCategory23 is the octet string constant for alertingCategory-2.
	AlertingCategory23 = "\x05"

	// AlertingCategory33 is the octet string constant for alertingCategory-3.
	AlertingCategory33 = "\x06"

	// AlertingCategory43 is the octet string constant for alertingCategory-4.
	AlertingCategory43 = "\x07"

	// AlertingCategory53 is the octet string constant for alertingCategory-5.
	AlertingCategory53 = "\x08"

	// MaxNumOfHLRId3 is the integer constant for maxNumOfHLR-Id.
	MaxNumOfHLRId3 int64 = 50

	// EmergencyServices3 is the integer constant for emergencyServices.
	EmergencyServices3 int64 = 0

	// EmergencyAlertServices3 is the integer constant for emergencyAlertServices.
	EmergencyAlertServices3 int64 = 1

	// PersonTracking3 is the integer constant for personTracking.
	PersonTracking3 int64 = 2

	// FleetManagement3 is the integer constant for fleetManagement.
	FleetManagement3 int64 = 3

	// AssetManagement3 is the integer constant for assetManagement.
	AssetManagement3 int64 = 4

	// TrafficCongestionReporting3 is the integer constant for trafficCongestionReporting.
	TrafficCongestionReporting3 int64 = 5

	// RoadsideAssistance3 is the integer constant for roadsideAssistance.
	RoadsideAssistance3 int64 = 6

	// RoutingToNearestCommercialEnterprise3 is the integer constant for routingToNearestCommercialEnterprise.
	RoutingToNearestCommercialEnterprise3 int64 = 7

	// Navigation3 is the integer constant for navigation.
	Navigation3 int64 = 8

	// CitySightseeing3 is the integer constant for citySightseeing.
	CitySightseeing3 int64 = 9

	// LocalizedAdvertising3 is the integer constant for localizedAdvertising.
	LocalizedAdvertising3 int64 = 10

	// MobileYellowPages3 is the integer constant for mobileYellowPages.
	MobileYellowPages3 int64 = 11

	// TrafficAndPublicTransportationInfo3 is the integer constant for trafficAndPublicTransportationInfo.
	TrafficAndPublicTransportationInfo3 int64 = 12

	// Weather3 is the integer constant for weather.
	Weather3 int64 = 13

	// AssetAndServiceFinding3 is the integer constant for assetAndServiceFinding.
	AssetAndServiceFinding3 int64 = 14

	// Gaming3 is the integer constant for gaming.
	Gaming3 int64 = 15

	// FindYourFriend3 is the integer constant for findYourFriend.
	FindYourFriend3 int64 = 16

	// Dating3 is the integer constant for dating.
	Dating3 int64 = 17

	// Chatting3 is the integer constant for chatting.
	Chatting3 int64 = 18

	// RouteFinding3 is the integer constant for routeFinding.
	RouteFinding3 int64 = 19

	// WhereAmI3 is the integer constant for whereAmI.
	WhereAmI3 int64 = 20

	// Serv643 is the integer constant for serv64.
	Serv643 int64 = 64

	// Serv653 is the integer constant for serv65.
	Serv653 int64 = 65

	// Serv663 is the integer constant for serv66.
	Serv663 int64 = 66

	// Serv673 is the integer constant for serv67.
	Serv673 int64 = 67

	// Serv683 is the integer constant for serv68.
	Serv683 int64 = 68

	// Serv693 is the integer constant for serv69.
	Serv693 int64 = 69

	// Serv703 is the integer constant for serv70.
	Serv703 int64 = 70

	// Serv713 is the integer constant for serv71.
	Serv713 int64 = 71

	// Serv723 is the integer constant for serv72.
	Serv723 int64 = 72

	// Serv733 is the integer constant for serv73.
	Serv733 int64 = 73

	// Serv743 is the integer constant for serv74.
	Serv743 int64 = 74

	// Serv753 is the integer constant for serv75.
	Serv753 int64 = 75

	// Serv763 is the integer constant for serv76.
	Serv763 int64 = 76

	// Serv773 is the integer constant for serv77.
	Serv773 int64 = 77

	// Serv783 is the integer constant for serv78.
	Serv783 int64 = 78

	// Serv793 is the integer constant for serv79.
	Serv793 int64 = 79

	// Serv803 is the integer constant for serv80.
	Serv803 int64 = 80

	// Serv813 is the integer constant for serv81.
	Serv813 int64 = 81

	// Serv823 is the integer constant for serv82.
	Serv823 int64 = 82

	// Serv833 is the integer constant for serv83.
	Serv833 int64 = 83

	// Serv843 is the integer constant for serv84.
	Serv843 int64 = 84

	// Serv853 is the integer constant for serv85.
	Serv853 int64 = 85

	// Serv863 is the integer constant for serv86.
	Serv863 int64 = 86

	// Serv873 is the integer constant for serv87.
	Serv873 int64 = 87

	// Serv883 is the integer constant for serv88.
	Serv883 int64 = 88

	// Serv893 is the integer constant for serv89.
	Serv893 int64 = 89

	// Serv903 is the integer constant for serv90.
	Serv903 int64 = 90

	// Serv913 is the integer constant for serv91.
	Serv913 int64 = 91

	// Serv923 is the integer constant for serv92.
	Serv923 int64 = 92

	// Serv933 is the integer constant for serv93.
	Serv933 int64 = 93

	// Serv943 is the integer constant for serv94.
	Serv943 int64 = 94

	// Serv953 is the integer constant for serv95.
	Serv953 int64 = 95

	// Serv963 is the integer constant for serv96.
	Serv963 int64 = 96

	// Serv973 is the integer constant for serv97.
	Serv973 int64 = 97

	// Serv983 is the integer constant for serv98.
	Serv983 int64 = 98

	// Serv993 is the integer constant for serv99.
	Serv993 int64 = 99

	// Serv1003 is the integer constant for serv100.
	Serv1003 int64 = 100

	// Serv1013 is the integer constant for serv101.
	Serv1013 int64 = 101

	// Serv1023 is the integer constant for serv102.
	Serv1023 int64 = 102

	// Serv1033 is the integer constant for serv103.
	Serv1033 int64 = 103

	// Serv1043 is the integer constant for serv104.
	Serv1043 int64 = 104

	// Serv1053 is the integer constant for serv105.
	Serv1053 int64 = 105

	// Serv1063 is the integer constant for serv106.
	Serv1063 int64 = 106

	// Serv1073 is the integer constant for serv107.
	Serv1073 int64 = 107

	// Serv1083 is the integer constant for serv108.
	Serv1083 int64 = 108

	// Serv1093 is the integer constant for serv109.
	Serv1093 int64 = 109

	// Serv1103 is the integer constant for serv110.
	Serv1103 int64 = 110

	// Serv1113 is the integer constant for serv111.
	Serv1113 int64 = 111

	// Serv1123 is the integer constant for serv112.
	Serv1123 int64 = 112

	// Serv1133 is the integer constant for serv113.
	Serv1133 int64 = 113

	// Serv1143 is the integer constant for serv114.
	Serv1143 int64 = 114

	// Serv1153 is the integer constant for serv115.
	Serv1153 int64 = 115

	// Serv1163 is the integer constant for serv116.
	Serv1163 int64 = 116

	// Serv1173 is the integer constant for serv117.
	Serv1173 int64 = 117

	// Serv1183 is the integer constant for serv118.
	Serv1183 int64 = 118

	// Serv1193 is the integer constant for serv119.
	Serv1193 int64 = 119

	// Serv1203 is the integer constant for serv120.
	Serv1203 int64 = 120

	// Serv1213 is the integer constant for serv121.
	Serv1213 int64 = 121

	// Serv1223 is the integer constant for serv122.
	Serv1223 int64 = 122

	// Serv1233 is the integer constant for serv123.
	Serv1233 int64 = 123

	// Serv1243 is the integer constant for serv124.
	Serv1243 int64 = 124

	// Serv1253 is the integer constant for serv125.
	Serv1253 int64 = 125

	// Serv1263 is the integer constant for serv126.
	Serv1263 int64 = 126

	// Serv1273 is the integer constant for serv127.
	Serv1273 int64 = 127

	// PriorityLevelA3 is the integer constant for priorityLevelA.
	PriorityLevelA3 int64 = 6

	// PriorityLevelB3 is the integer constant for priorityLevelB.
	PriorityLevelB3 int64 = 5

	// PriorityLevel03 is the integer constant for priorityLevel0.
	PriorityLevel03 int64 = 0

	// PriorityLevel13 is the integer constant for priorityLevel1.
	PriorityLevel13 int64 = 1

	// PriorityLevel23 is the integer constant for priorityLevel2.
	PriorityLevel23 int64 = 2

	// PriorityLevel33 is the integer constant for priorityLevel3.
	PriorityLevel33 int64 = 3

	// PriorityLevel43 is the integer constant for priorityLevel4.
	PriorityLevel43 int64 = 4

	// MaxNumOfMCBearers3 is the integer constant for maxNumOfMC-Bearers.
	MaxNumOfMCBearers3 int64 = 7
)

// TBCDSTRING3 represents the ASN.1 type TBCD-STRING (OCTET_STRING).
type TBCDSTRING3 = []byte

// CommonDataTypesDiameterIdentity represents the ASN.1 type DiameterIdentity (OCTET_STRING).
type CommonDataTypesDiameterIdentity = []byte

// AddressString3 represents the ASN.1 type AddressString (OCTET_STRING).
type AddressString3 = []byte

// ISDNAddressString3 represents the ASN.1 type ISDN-AddressString (OCTET_STRING).
type ISDNAddressString3 = AddressString3

// FTNAddressString3 represents the ASN.1 type FTN-AddressString (OCTET_STRING).
type FTNAddressString3 = AddressString3

// ISDNSubaddressString3 represents the ASN.1 type ISDN-SubaddressString (OCTET_STRING).
type ISDNSubaddressString3 = []byte

// ExternalSignalInfo3 represents the ASN.1 type ExternalSignalInfo (SEQUENCE).
type ExternalSignalInfo3 struct {
	ProtocolId         ProtocolId3          `asn1:""`
	SignalInfo         SignalInfo3          `asn1:""`
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// SignalInfo3 represents the ASN.1 type SignalInfo (OCTET_STRING).
type SignalInfo3 = []byte

// ProtocolId3 represents the ASN.1 ENUMERATED type ProtocolId.
type ProtocolId3 int64

const (
	ProtocolId3Gsm0408    ProtocolId3 = 1
	ProtocolId3Gsm0806    ProtocolId3 = 2
	ProtocolId3GsmBSSMAP  ProtocolId3 = 3
	ProtocolId3Ets3001021 ProtocolId3 = 4
)

func (v ProtocolId3) String() string {
	switch v {
	case ProtocolId3Gsm0408:
		return "gsm-0408"
	case ProtocolId3Gsm0806:
		return "gsm-0806"
	case ProtocolId3GsmBSSMAP:
		return "gsm-BSSMAP"
	case ProtocolId3Ets3001021:
		return "ets-300102-1"
	default:
		return "unknown"
	}
}

// ExtExternalSignalInfo3 represents the ASN.1 type Ext-ExternalSignalInfo (SEQUENCE).
type ExtExternalSignalInfo3 struct {
	ExtProtocolId      ExtProtocolId3       `asn1:""`
	SignalInfo         SignalInfo3          `asn1:""`
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// ExtProtocolId3 represents the ASN.1 ENUMERATED type Ext-ProtocolId.
type ExtProtocolId3 int64

const (
	ExtProtocolId3Ets300356 ExtProtocolId3 = 1
)

func (v ExtProtocolId3) String() string {
	switch v {
	case ExtProtocolId3Ets300356:
		return "ets-300356"
	default:
		return "unknown"
	}
}

// AccessNetworkSignalInfo3 represents the ASN.1 type AccessNetworkSignalInfo (SEQUENCE).
type AccessNetworkSignalInfo3 struct {
	AccessNetworkProtocolId AccessNetworkProtocolId3 `asn1:""`
	SignalInfo              LongSignalInfo3          `asn1:""`
	ExtensionContainer      *ExtensionContainer3     `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
	berOriginal_            []byte                   `asn1:"-" json:"-"`
	berSnapshot_            []byte                   `asn1:"-" json:"-"`
}

// LongSignalInfo3 represents the ASN.1 type LongSignalInfo (OCTET_STRING).
type LongSignalInfo3 = []byte

// AccessNetworkProtocolId3 represents the ASN.1 ENUMERATED type AccessNetworkProtocolId.
type AccessNetworkProtocolId3 int64

const (
	AccessNetworkProtocolId3Ts3G48006 AccessNetworkProtocolId3 = 1
	AccessNetworkProtocolId3Ts3G25413 AccessNetworkProtocolId3 = 2
)

func (v AccessNetworkProtocolId3) String() string {
	switch v {
	case AccessNetworkProtocolId3Ts3G48006:
		return "ts3G-48006"
	case AccessNetworkProtocolId3Ts3G25413:
		return "ts3G-25413"
	default:
		return "unknown"
	}
}

// AlertingPattern3 represents the ASN.1 type AlertingPattern (OCTET_STRING).
type AlertingPattern3 = []byte

// CommonDataTypesGSNAddress represents the ASN.1 type GSN-Address (OCTET_STRING).
type CommonDataTypesGSNAddress = []byte

// CommonDataTypesTime represents the ASN.1 type Time (OCTET_STRING).
type CommonDataTypesTime = []byte

// IMSI3 represents the ASN.1 type IMSI (OCTET_STRING).
type IMSI3 = TBCDSTRING3

// Identity3 choice constants.
const (
	Identity3ChoiceImsi         = 1
	Identity3ChoiceImsiWithLMSI = 2
)

// Identity3 represents the ASN.1 CHOICE type Identity.
type Identity3 struct {
	Choice       int
	berOriginal_ []byte         `json:"-"`
	berSnapshot_ []byte         `json:"-"`
	Imsi         *IMSI3         `json:"Imsi,omitempty"`
	ImsiWithLMSI *IMSIWithLMSI3 `json:"ImsiWithLMSI,omitempty"`
}

// NewIdentity3Imsi creates a Identity3 with the imsi alternative.
func NewIdentity3Imsi(v IMSI3) Identity3 {
	return Identity3{
		Choice: Identity3ChoiceImsi,
		Imsi:   &v,
	}
}

// NewIdentity3ImsiWithLMSI creates a Identity3 with the imsi-WithLMSI alternative.
func NewIdentity3ImsiWithLMSI(v IMSIWithLMSI3) Identity3 {
	return Identity3{
		Choice:       Identity3ChoiceImsiWithLMSI,
		ImsiWithLMSI: &v,
	}
}

// IMSIWithLMSI3 represents the ASN.1 type IMSI-WithLMSI (SEQUENCE).
type IMSIWithLMSI3 struct {
	Imsi         IMSI3    `asn1:""`
	Lmsi         LMSI3    `asn1:""`
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// ASCICallReference3 represents the ASN.1 type ASCI-CallReference (OCTET_STRING).
type ASCICallReference3 = TBCDSTRING3

// TMSI3 represents the ASN.1 type TMSI (OCTET_STRING).
type TMSI3 = []byte

// SubscriberId3 choice constants.
const (
	SubscriberId3ChoiceImsi = 1
	SubscriberId3ChoiceTmsi = 2
)

// SubscriberId3 represents the ASN.1 CHOICE type SubscriberId.
type SubscriberId3 struct {
	Choice       int
	berOriginal_ []byte `json:"-"`
	berSnapshot_ []byte `json:"-"`
	Imsi         *IMSI3 `json:"Imsi,omitempty"`
	Tmsi         *TMSI3 `json:"Tmsi,omitempty"`
}

// NewSubscriberId3Imsi creates a SubscriberId3 with the imsi alternative.
func NewSubscriberId3Imsi(v IMSI3) SubscriberId3 {
	return SubscriberId3{
		Choice: SubscriberId3ChoiceImsi,
		Imsi:   &v,
	}
}

// NewSubscriberId3Tmsi creates a SubscriberId3 with the tmsi alternative.
func NewSubscriberId3Tmsi(v TMSI3) SubscriberId3 {
	return SubscriberId3{
		Choice: SubscriberId3ChoiceTmsi,
		Tmsi:   &v,
	}
}

// IMEI3 represents the ASN.1 type IMEI (OCTET_STRING).
type IMEI3 = TBCDSTRING3

// HLRId3 represents the ASN.1 type HLR-Id (OCTET_STRING).
type HLRId3 = IMSI3

// HLRList3 represents the ASN.1 type HLR-List (SEQUENCE_OF).
type HLRList3 struct {
	Values       []HLRId3 `json:"Values"`
	berOriginal_ []byte   `json:"-"`
	berSnapshot_ []byte   `json:"-"`
}

// LMSI3 represents the ASN.1 type LMSI (OCTET_STRING).
type LMSI3 = []byte

// GlobalCellId3 represents the ASN.1 type GlobalCellId (OCTET_STRING).
type GlobalCellId3 = []byte

// NetworkResource3 represents the ASN.1 ENUMERATED type NetworkResource.
type NetworkResource3 int64

const (
	NetworkResource3Plmn           NetworkResource3 = 0
	NetworkResource3Hlr            NetworkResource3 = 1
	NetworkResource3Vlr            NetworkResource3 = 2
	NetworkResource3Pvlr           NetworkResource3 = 3
	NetworkResource3ControllingMSC NetworkResource3 = 4
	NetworkResource3Vmsc           NetworkResource3 = 5
	NetworkResource3Eir            NetworkResource3 = 6
	NetworkResource3Rss            NetworkResource3 = 7
)

func (v NetworkResource3) String() string {
	switch v {
	case NetworkResource3Plmn:
		return "plmn"
	case NetworkResource3Hlr:
		return "hlr"
	case NetworkResource3Vlr:
		return "vlr"
	case NetworkResource3Pvlr:
		return "pvlr"
	case NetworkResource3ControllingMSC:
		return "controllingMSC"
	case NetworkResource3Vmsc:
		return "vmsc"
	case NetworkResource3Eir:
		return "eir"
	case NetworkResource3Rss:
		return "rss"
	default:
		return "unknown"
	}
}

// AdditionalNetworkResource3 represents the ASN.1 ENUMERATED type AdditionalNetworkResource.
type AdditionalNetworkResource3 int64

const (
	AdditionalNetworkResource3Sgsn   AdditionalNetworkResource3 = 0
	AdditionalNetworkResource3Ggsn   AdditionalNetworkResource3 = 1
	AdditionalNetworkResource3Gmlc   AdditionalNetworkResource3 = 2
	AdditionalNetworkResource3GsmSCF AdditionalNetworkResource3 = 3
	AdditionalNetworkResource3Nplr   AdditionalNetworkResource3 = 4
	AdditionalNetworkResource3Auc    AdditionalNetworkResource3 = 5
	AdditionalNetworkResource3Ue     AdditionalNetworkResource3 = 6
	AdditionalNetworkResource3Mme    AdditionalNetworkResource3 = 7
)

func (v AdditionalNetworkResource3) String() string {
	switch v {
	case AdditionalNetworkResource3Sgsn:
		return "sgsn"
	case AdditionalNetworkResource3Ggsn:
		return "ggsn"
	case AdditionalNetworkResource3Gmlc:
		return "gmlc"
	case AdditionalNetworkResource3GsmSCF:
		return "gsmSCF"
	case AdditionalNetworkResource3Nplr:
		return "nplr"
	case AdditionalNetworkResource3Auc:
		return "auc"
	case AdditionalNetworkResource3Ue:
		return "ue"
	case AdditionalNetworkResource3Mme:
		return "mme"
	default:
		return "unknown"
	}
}

// NAEAPreferredCI3 represents the ASN.1 type NAEA-PreferredCI (SEQUENCE).
type NAEAPreferredCI3 struct {
	NaeaPreferredCIC   NAEACIC3             `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionContainer3 `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// NAEACIC3 represents the ASN.1 type NAEA-CIC (OCTET_STRING).
type NAEACIC3 = []byte

// SubscriberIdentity3 choice constants.
const (
	SubscriberIdentity3ChoiceImsi   = 1
	SubscriberIdentity3ChoiceMsisdn = 2
)

// SubscriberIdentity3 represents the ASN.1 CHOICE type SubscriberIdentity.
type SubscriberIdentity3 struct {
	Choice       int
	berOriginal_ []byte              `json:"-"`
	berSnapshot_ []byte              `json:"-"`
	Imsi         *IMSI3              `json:"Imsi,omitempty"`
	Msisdn       *ISDNAddressString3 `json:"Msisdn,omitempty"`
}

// NewSubscriberIdentity3Imsi creates a SubscriberIdentity3 with the imsi alternative.
func NewSubscriberIdentity3Imsi(v IMSI3) SubscriberIdentity3 {
	return SubscriberIdentity3{
		Choice: SubscriberIdentity3ChoiceImsi,
		Imsi:   &v,
	}
}

// NewSubscriberIdentity3Msisdn creates a SubscriberIdentity3 with the msisdn alternative.
func NewSubscriberIdentity3Msisdn(v ISDNAddressString3) SubscriberIdentity3 {
	return SubscriberIdentity3{
		Choice: SubscriberIdentity3ChoiceMsisdn,
		Msisdn: &v,
	}
}

// LCSClientExternalID3 represents the ASN.1 type LCSClientExternalID (SEQUENCE).
type LCSClientExternalID3 struct {
	ExternalAddress    *ISDNAddressString3  `asn1:"tag:0,context,implicit,optional" json:"ExternalAddress,omitempty"`
	ExtensionContainer *ExtensionContainer3 `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// LCSClientInternalID3 represents the ASN.1 ENUMERATED type LCSClientInternalID.
type LCSClientInternalID3 int64

const (
	LCSClientInternalID3BroadcastService          LCSClientInternalID3 = 0
	LCSClientInternalID3OAndMHPLMN                LCSClientInternalID3 = 1
	LCSClientInternalID3OAndMVPLMN                LCSClientInternalID3 = 2
	LCSClientInternalID3AnonymousLocation         LCSClientInternalID3 = 3
	LCSClientInternalID3TargetMSsubscribedService LCSClientInternalID3 = 4
)

func (v LCSClientInternalID3) String() string {
	switch v {
	case LCSClientInternalID3BroadcastService:
		return "broadcastService"
	case LCSClientInternalID3OAndMHPLMN:
		return "o-andM-HPLMN"
	case LCSClientInternalID3OAndMVPLMN:
		return "o-andM-VPLMN"
	case LCSClientInternalID3AnonymousLocation:
		return "anonymousLocation"
	case LCSClientInternalID3TargetMSsubscribedService:
		return "targetMSsubscribedService"
	default:
		return "unknown"
	}
}

// LCSServiceTypeID3 represents the ASN.1 type LCSServiceTypeID (INTEGER).
type LCSServiceTypeID3 = int64

// PLMNId3 represents the ASN.1 type PLMN-Id (OCTET_STRING).
type PLMNId3 = []byte

// CommonDataTypesEUTRANCGI represents the ASN.1 type E-UTRAN-CGI (OCTET_STRING).
type CommonDataTypesEUTRANCGI = []byte

// CommonDataTypesNRCGI represents the ASN.1 type NR-CGI (OCTET_STRING).
type CommonDataTypesNRCGI = []byte

// CommonDataTypesTAId represents the ASN.1 type TA-Id (OCTET_STRING).
type CommonDataTypesTAId = []byte

// CommonDataTypesNRTAId represents the ASN.1 type NR-TA-Id (OCTET_STRING).
type CommonDataTypesNRTAId = []byte

// CommonDataTypesRAIdentity represents the ASN.1 type RAIdentity (OCTET_STRING).
type CommonDataTypesRAIdentity = []byte

// CommonDataTypesNetworkNodeDiameterAddress represents the ASN.1 type NetworkNodeDiameterAddress (SEQUENCE).
type CommonDataTypesNetworkNodeDiameterAddress struct {
	DiameterName  CommonDataTypesDiameterIdentity `asn1:"tag:0,context,implicit"`
	DiameterRealm CommonDataTypesDiameterIdentity `asn1:"tag:1,context,implicit"`
	berOriginal_  []byte                          `asn1:"-" json:"-"`
	berSnapshot_  []byte                          `asn1:"-" json:"-"`
}

// CellGlobalIdOrServiceAreaIdOrLAI3 choice constants.
const (
	CellGlobalIdOrServiceAreaIdOrLAI3ChoiceCellGlobalIdOrServiceAreaIdFixedLength = 1
	CellGlobalIdOrServiceAreaIdOrLAI3ChoiceLaiFixedLength                         = 2
)

// CellGlobalIdOrServiceAreaIdOrLAI3 represents the ASN.1 CHOICE type CellGlobalIdOrServiceAreaIdOrLAI.
type CellGlobalIdOrServiceAreaIdOrLAI3 struct {
	Choice                                 int
	berOriginal_                           []byte                                   `json:"-"`
	berSnapshot_                           []byte                                   `json:"-"`
	CellGlobalIdOrServiceAreaIdFixedLength *CellGlobalIdOrServiceAreaIdFixedLength3 `json:"CellGlobalIdOrServiceAreaIdFixedLength,omitempty"`
	LaiFixedLength                         *LAIFixedLength3                         `json:"LaiFixedLength,omitempty"`
}

// NewCellGlobalIdOrServiceAreaIdOrLAI3CellGlobalIdOrServiceAreaIdFixedLength creates a CellGlobalIdOrServiceAreaIdOrLAI3 with the cellGlobalIdOrServiceAreaIdFixedLength alternative.
func NewCellGlobalIdOrServiceAreaIdOrLAI3CellGlobalIdOrServiceAreaIdFixedLength(v CellGlobalIdOrServiceAreaIdFixedLength3) CellGlobalIdOrServiceAreaIdOrLAI3 {
	return CellGlobalIdOrServiceAreaIdOrLAI3{
		Choice:                                 CellGlobalIdOrServiceAreaIdOrLAI3ChoiceCellGlobalIdOrServiceAreaIdFixedLength,
		CellGlobalIdOrServiceAreaIdFixedLength: &v,
	}
}

// NewCellGlobalIdOrServiceAreaIdOrLAI3LaiFixedLength creates a CellGlobalIdOrServiceAreaIdOrLAI3 with the laiFixedLength alternative.
func NewCellGlobalIdOrServiceAreaIdOrLAI3LaiFixedLength(v LAIFixedLength3) CellGlobalIdOrServiceAreaIdOrLAI3 {
	return CellGlobalIdOrServiceAreaIdOrLAI3{
		Choice:         CellGlobalIdOrServiceAreaIdOrLAI3ChoiceLaiFixedLength,
		LaiFixedLength: &v,
	}
}

// CellGlobalIdOrServiceAreaIdFixedLength3 represents the ASN.1 type CellGlobalIdOrServiceAreaIdFixedLength (OCTET_STRING).
type CellGlobalIdOrServiceAreaIdFixedLength3 = []byte

// LAIFixedLength3 represents the ASN.1 type LAIFixedLength (OCTET_STRING).
type LAIFixedLength3 = []byte

// BasicServiceCode3 choice constants.
const (
	BasicServiceCode3ChoiceBearerService = 1
	BasicServiceCode3ChoiceTeleservice   = 2
)

// BasicServiceCode3 represents the ASN.1 CHOICE type BasicServiceCode.
type BasicServiceCode3 struct {
	Choice        int
	berOriginal_  []byte              `json:"-"`
	berSnapshot_  []byte              `json:"-"`
	BearerService *BearerServiceCode3 `json:"BearerService,omitempty"`
	Teleservice   *TeleserviceCode3   `json:"Teleservice,omitempty"`
}

// NewBasicServiceCode3BearerService creates a BasicServiceCode3 with the bearerService alternative.
func NewBasicServiceCode3BearerService(v BearerServiceCode3) BasicServiceCode3 {
	return BasicServiceCode3{
		Choice:        BasicServiceCode3ChoiceBearerService,
		BearerService: &v,
	}
}

// NewBasicServiceCode3Teleservice creates a BasicServiceCode3 with the teleservice alternative.
func NewBasicServiceCode3Teleservice(v TeleserviceCode3) BasicServiceCode3 {
	return BasicServiceCode3{
		Choice:      BasicServiceCode3ChoiceTeleservice,
		Teleservice: &v,
	}
}

// ExtBasicServiceCode3 choice constants.
const (
	ExtBasicServiceCode3ChoiceExtBearerService = 1
	ExtBasicServiceCode3ChoiceExtTeleservice   = 2
)

// ExtBasicServiceCode3 represents the ASN.1 CHOICE type Ext-BasicServiceCode.
type ExtBasicServiceCode3 struct {
	Choice           int
	berOriginal_     []byte                 `json:"-"`
	berSnapshot_     []byte                 `json:"-"`
	ExtBearerService *ExtBearerServiceCode3 `json:"ExtBearerService,omitempty"`
	ExtTeleservice   *ExtTeleserviceCode3   `json:"ExtTeleservice,omitempty"`
}

// NewExtBasicServiceCode3ExtBearerService creates a ExtBasicServiceCode3 with the ext-BearerService alternative.
func NewExtBasicServiceCode3ExtBearerService(v ExtBearerServiceCode3) ExtBasicServiceCode3 {
	return ExtBasicServiceCode3{
		Choice:           ExtBasicServiceCode3ChoiceExtBearerService,
		ExtBearerService: &v,
	}
}

// NewExtBasicServiceCode3ExtTeleservice creates a ExtBasicServiceCode3 with the ext-Teleservice alternative.
func NewExtBasicServiceCode3ExtTeleservice(v ExtTeleserviceCode3) ExtBasicServiceCode3 {
	return ExtBasicServiceCode3{
		Choice:         ExtBasicServiceCode3ChoiceExtTeleservice,
		ExtTeleservice: &v,
	}
}

// EMLPPInfo3 represents the ASN.1 type EMLPP-Info (SEQUENCE).
type EMLPPInfo3 struct {
	MaximumentitledPriority EMLPPPriority3       `asn1:""`
	DefaultPriority         EMLPPPriority3       `asn1:""`
	ExtensionContainer      *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                `asn1:"-" json:"-"`
	ExtPresent_             []bool               `asn1:"-" json:"-"`
	ExtData_                [][]byte             `asn1:"-" json:"-"`
	berOriginal_            []byte               `asn1:"-" json:"-"`
	berSnapshot_            []byte               `asn1:"-" json:"-"`
}

// EMLPPPriority3 represents the ASN.1 type EMLPP-Priority (INTEGER).
type EMLPPPriority3 = int64

// MCSSInfo3 represents the ASN.1 type MC-SS-Info (SEQUENCE).
type MCSSInfo3 struct {
	SsCode             SSCode3              `asn1:"tag:0,context,implicit"`
	SsStatus           ExtSSStatus3         `asn1:"tag:1,context,implicit"`
	NbrSB              MaxMCBearers3        `asn1:"tag:2,context,implicit"`
	NbrUser            MCBearers3           `asn1:"tag:3,context,implicit"`
	ExtensionContainer *ExtensionContainer3 `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// MaxMCBearers3 represents the ASN.1 type MaxMC-Bearers (INTEGER).
type MaxMCBearers3 = int64

// MCBearers3 represents the ASN.1 type MC-Bearers (INTEGER).
type MCBearers3 = int64

// ExtSSStatus3 represents the ASN.1 type Ext-SS-Status (OCTET_STRING).
type ExtSSStatus3 = []byte

// AgeOfLocationInformation3 represents the ASN.1 type AgeOfLocationInformation (INTEGER).
type AgeOfLocationInformation3 = int64

// MarshalBER encodes ExternalSignalInfo3 to BER format.
func (v *ExternalSignalInfo3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExternalSignalInfo3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExternalSignalInfo3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes ExternalSignalInfo3 to DER format.
func (v *ExternalSignalInfo3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExternalSignalInfo3 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ExternalSignalInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExternalSignalInfo3 from BER/DER format.
func (v *ExternalSignalInfo3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExternalSignalInfo3 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExternalSignalInfo3{}
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
		return fmt.Errorf("decoding ExternalSignalInfo3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExternalSignalInfo3", Cause: ber.ErrExtraData}
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
	v.ProtocolId = ProtocolId3(val_protocolid)
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
	v.SignalInfo = SignalInfo3(val_signalinfo)
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo3", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo3", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes ExtExternalSignalInfo3 to BER format.
func (v *ExtExternalSignalInfo3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtExternalSignalInfo3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtExternalSignalInfo3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes ExtExternalSignalInfo3 to DER format.
func (v *ExtExternalSignalInfo3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtExternalSignalInfo3 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ExtExternalSignalInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtExternalSignalInfo3 from BER/DER format.
func (v *ExtExternalSignalInfo3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtExternalSignalInfo3 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtExternalSignalInfo3{}
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
		return fmt.Errorf("decoding ExtExternalSignalInfo3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtExternalSignalInfo3", Cause: ber.ErrExtraData}
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
	v.ExtProtocolId = ExtProtocolId3(val_extprotocolid)
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
	v.SignalInfo = SignalInfo3(val_signalinfo)
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtExternalSignalInfo3", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExtExternalSignalInfo3", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes AccessNetworkSignalInfo3 to BER format.
func (v *AccessNetworkSignalInfo3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AccessNetworkSignalInfo3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AccessNetworkSignalInfo3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes AccessNetworkSignalInfo3 to DER format.
func (v *AccessNetworkSignalInfo3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AccessNetworkSignalInfo3 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding AccessNetworkSignalInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AccessNetworkSignalInfo3 from BER/DER format.
func (v *AccessNetworkSignalInfo3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AccessNetworkSignalInfo3 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AccessNetworkSignalInfo3{}
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
		return fmt.Errorf("decoding AccessNetworkSignalInfo3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AccessNetworkSignalInfo3", Cause: ber.ErrExtraData}
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
	v.AccessNetworkProtocolId = AccessNetworkProtocolId3(val_accessnetworkprotocolid)
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
	v.SignalInfo = LongSignalInfo3(val_signalinfo)
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "AccessNetworkSignalInfo3", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "AccessNetworkSignalInfo3", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes Identity3 to BER format.
func (v *Identity3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Identity3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Identity3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case Identity3ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice Identity3: imsi is nil", ber.ErrInvalidValue)
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
	case Identity3ChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice Identity3: imsi-WithLMSI is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ImsiWithLMSI.MarshalBER(ber.ChildEncodeOptions(opts, "imsi-WithLMSI")...)
		if err != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Identity3", v.Choice)
	}
}

// MarshalDER encodes Identity3 to DER format.
func (v *Identity3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Identity3 receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case Identity3ChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice Identity3: imsi-WithLMSI is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding Identity3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Identity3 from BER/DER format.
func (v *Identity3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Identity3 destination is nil", ber.ErrInvalidValue)
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
	*v = Identity3{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Identity3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Identity3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding Identity3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Identity3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = Identity3ChoiceImsi
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return fmt.Errorf("decoding imsi: %w", osErr)
		}
		tmp := IMSI3(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = Identity3ChoiceImsiWithLMSI
		var dec IMSIWithLMSI3
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "imsi-WithLMSI")...); unmErr != nil {
			return fmt.Errorf("decoding imsi-WithLMSI: %w", unmErr)
		}
		v.ImsiWithLMSI = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Identity3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes IMSIWithLMSI3 to BER format.
func (v *IMSIWithLMSI3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: IMSIWithLMSI3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IMSIWithLMSI3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes IMSIWithLMSI3 to DER format.
func (v *IMSIWithLMSI3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IMSIWithLMSI3 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding IMSIWithLMSI3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IMSIWithLMSI3 from BER/DER format.
func (v *IMSIWithLMSI3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IMSIWithLMSI3 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IMSIWithLMSI3{}
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
		return fmt.Errorf("decoding IMSIWithLMSI3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IMSIWithLMSI3", Cause: ber.ErrExtraData}
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
	v.Imsi = IMSI3(val_imsi)
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
	v.Lmsi = LMSI3(val_lmsi)
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
			return &ber.DecodeError{Offset: offset, TypeName: "IMSIWithLMSI3", Cause: extErr_}
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

// MarshalBER encodes SubscriberId3 to BER format.
func (v *SubscriberId3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberId3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SubscriberId3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SubscriberId3ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberId3: imsi is nil", ber.ErrInvalidValue)
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
	case SubscriberId3ChoiceTmsi:
		if v.Tmsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberId3: tmsi is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for SubscriberId3", v.Choice)
	}
}

// MarshalDER encodes SubscriberId3 to DER format.
func (v *SubscriberId3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberId3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberId3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberId3 from BER/DER format.
func (v *SubscriberId3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SubscriberId3 destination is nil", ber.ErrInvalidValue)
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
	*v = SubscriberId3{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberId3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberId3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberId3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberId3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberId3ChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding imsi: %w", octetErr)
		}
		tmp := IMSI3(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberId3ChoiceTmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding tmsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding tmsi: %w", octetErr)
		}
		tmp := TMSI3(decVal)
		v.Tmsi = &tmp
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberId3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBERHLRList3 encodes a HLRList3 list to BER.
func MarshalBERHLRList3(collection *HLRList3, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERHLRList3(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERHLRList3(collection *HLRList3, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(opts, "HLRList3", "SIZE (1..50)", len(list)); constraintErr != nil {
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

// MarshalDERHLRList3 encodes a HLRList3 list to DER.
func MarshalDERHLRList3(collection *HLRList3) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(nil, "HLRList3", "SIZE (1..50)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("encoding HLRList3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERHLRList3 decodes a HLRList3 list from BER.
func UnmarshalBERHLRList3(data []byte, opts ...ber.DecodeOption) (returnValue *HLRList3, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding HLRList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "HLRList3", Cause: ber.ErrExtraData}
	}
	var result []HLRId3
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
		result = append(result, HLRId3(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedLength(opts, "HLRList3", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &HLRList3{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERHLRList3(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes NAEAPreferredCI3 to BER format.
func (v *NAEAPreferredCI3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: NAEAPreferredCI3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NAEAPreferredCI3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes NAEAPreferredCI3 to DER format.
func (v *NAEAPreferredCI3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NAEAPreferredCI3 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding NAEAPreferredCI3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NAEAPreferredCI3 from BER/DER format.
func (v *NAEAPreferredCI3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NAEAPreferredCI3 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NAEAPreferredCI3{}
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
		return fmt.Errorf("decoding NAEAPreferredCI3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NAEAPreferredCI3", Cause: ber.ErrExtraData}
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
	v.NaeaPreferredCIC = NAEACIC3(decVal_naeapreferredcic)
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
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "NAEAPreferredCI3", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "NAEAPreferredCI3", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes SubscriberIdentity3 to BER format.
func (v *SubscriberIdentity3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberIdentity3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SubscriberIdentity3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SubscriberIdentity3ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberIdentity3: imsi is nil", ber.ErrInvalidValue)
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
	case SubscriberIdentity3ChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("%w: choice SubscriberIdentity3: msisdn is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for SubscriberIdentity3", v.Choice)
	}
}

// MarshalDER encodes SubscriberIdentity3 to DER format.
func (v *SubscriberIdentity3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberIdentity3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberIdentity3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberIdentity3 from BER/DER format.
func (v *SubscriberIdentity3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SubscriberIdentity3 destination is nil", ber.ErrInvalidValue)
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
	*v = SubscriberIdentity3{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberIdentity3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberIdentity3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberIdentity3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberIdentity3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberIdentity3ChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding imsi: %w", octetErr)
		}
		tmp := IMSI3(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberIdentity3ChoiceMsisdn
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding msisdn: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding msisdn: %w", octetErr)
		}
		tmp := ISDNAddressString3(decVal)
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
		return fmt.Errorf("unknown tag %s for SubscriberIdentity3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes LCSClientExternalID3 to BER format.
func (v *LCSClientExternalID3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSClientExternalID3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSClientExternalID3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes LCSClientExternalID3 to DER format.
func (v *LCSClientExternalID3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSClientExternalID3 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding LCSClientExternalID3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSClientExternalID3 from BER/DER format.
func (v *LCSClientExternalID3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSClientExternalID3 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSClientExternalID3{}
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
		return fmt.Errorf("decoding LCSClientExternalID3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSClientExternalID3", Cause: ber.ErrExtraData}
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
				tmp_externaladdress := ISDNAddressString3(decVal_externaladdress)
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
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSClientExternalID3", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSClientExternalID3", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes CommonDataTypesNetworkNodeDiameterAddress to BER format.
func (v *CommonDataTypesNetworkNodeDiameterAddress) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesNetworkNodeDiameterAddress receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CommonDataTypesNetworkNodeDiameterAddress) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.DiameterName) < 9 || len(v.DiameterName) > 255 {
		if constraintErr := ber.CheckEncodedLength(opts, "diameter-Name", "SIZE (9..255)", len(v.DiameterName)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_diametername, encodeErr_enc_diametername := ber.EncodeOctetString([]byte(v.DiameterName))
	if encodeErr_enc_diametername != nil {
		return nil, fmt.Errorf("encoding diameter-Name: %w", encodeErr_enc_diametername)
	}
	retagged_enc_diametername, tagErr_enc_diametername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_diametername)
	if tagErr_enc_diametername != nil {
		return nil, fmt.Errorf("encoding diameter-Name: %w", tagErr_enc_diametername)
	}
	enc_diametername = retagged_enc_diametername
	children = append(children, enc_diametername...)
	if len(v.DiameterRealm) < 9 || len(v.DiameterRealm) > 255 {
		if constraintErr := ber.CheckEncodedLength(opts, "diameter-Realm", "SIZE (9..255)", len(v.DiameterRealm)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_diameterrealm, encodeErr_enc_diameterrealm := ber.EncodeOctetString([]byte(v.DiameterRealm))
	if encodeErr_enc_diameterrealm != nil {
		return nil, fmt.Errorf("encoding diameter-Realm: %w", encodeErr_enc_diameterrealm)
	}
	retagged_enc_diameterrealm, tagErr_enc_diameterrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_diameterrealm)
	if tagErr_enc_diameterrealm != nil {
		return nil, fmt.Errorf("encoding diameter-Realm: %w", tagErr_enc_diameterrealm)
	}
	enc_diameterrealm = retagged_enc_diameterrealm
	children = append(children, enc_diameterrealm...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes CommonDataTypesNetworkNodeDiameterAddress to DER format.
func (v *CommonDataTypesNetworkNodeDiameterAddress) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CommonDataTypesNetworkNodeDiameterAddress receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.DiameterName) < 9 || len(v.DiameterName) > 255 {
		if constraintErr := ber.CheckEncodedLength(nil, "diameter-Name", "SIZE (9..255)", len(v.DiameterName)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_diametername, encodeErr_enc_diametername := ber.EncodeOctetString([]byte(v.DiameterName))
	if encodeErr_enc_diametername != nil {
		return nil, fmt.Errorf("encoding diameter-Name: %w", encodeErr_enc_diametername)
	}
	retagged_enc_diametername, tagErr_enc_diametername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_diametername)
	if tagErr_enc_diametername != nil {
		return nil, fmt.Errorf("encoding diameter-Name: %w", tagErr_enc_diametername)
	}
	enc_diametername = retagged_enc_diametername
	children = append(children, enc_diametername...)
	if len(v.DiameterRealm) < 9 || len(v.DiameterRealm) > 255 {
		if constraintErr := ber.CheckEncodedLength(nil, "diameter-Realm", "SIZE (9..255)", len(v.DiameterRealm)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_diameterrealm, encodeErr_enc_diameterrealm := ber.EncodeOctetString([]byte(v.DiameterRealm))
	if encodeErr_enc_diameterrealm != nil {
		return nil, fmt.Errorf("encoding diameter-Realm: %w", encodeErr_enc_diameterrealm)
	}
	retagged_enc_diameterrealm, tagErr_enc_diameterrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_diameterrealm)
	if tagErr_enc_diameterrealm != nil {
		return nil, fmt.Errorf("encoding diameter-Realm: %w", tagErr_enc_diameterrealm)
	}
	enc_diameterrealm = retagged_enc_diameterrealm
	children = append(children, enc_diameterrealm...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CommonDataTypesNetworkNodeDiameterAddress as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CommonDataTypesNetworkNodeDiameterAddress from BER/DER format.
func (v *CommonDataTypesNetworkNodeDiameterAddress) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CommonDataTypesNetworkNodeDiameterAddress destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CommonDataTypesNetworkNodeDiameterAddress{}
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
		return fmt.Errorf("decoding CommonDataTypesNetworkNodeDiameterAddress SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CommonDataTypesNetworkNodeDiameterAddress", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode diameter-Name
	if offset >= len(content) {
		return fmt.Errorf("missing required field diameter-Name")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for diameter-Name, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_diametername, n_diametername, rawVal_diametername, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding diameter-Name: %w", err)
	}
	if decodedTag_diametername.Class != tag.ClassContextSpecific || decodedTag_diametername.Number != 0 {
		return fmt.Errorf("decoding diameter-Name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_diametername)
	}
	decVal_diametername, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_diametername.Constructed, rawVal_diametername, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding diameter-Name: %w", octetErr)
	}
	v.DiameterName = CommonDataTypesDiameterIdentity(decVal_diametername)
	if offset > len(content) || n_diametername < 0 || n_diametername > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_diametername
	if len(v.DiameterName) < 9 || len(v.DiameterName) > 255 {
		if constraintErr := ber.CheckDecodedLength(opts, "diameter-Name", "SIZE (9..255)", len(v.DiameterName)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode diameter-Realm
	if offset >= len(content) {
		return fmt.Errorf("missing required field diameter-Realm")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for diameter-Realm, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_diameterrealm, n_diameterrealm, rawVal_diameterrealm, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding diameter-Realm: %w", err)
	}
	if decodedTag_diameterrealm.Class != tag.ClassContextSpecific || decodedTag_diameterrealm.Number != 1 {
		return fmt.Errorf("decoding diameter-Realm: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_diameterrealm)
	}
	decVal_diameterrealm, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_diameterrealm.Constructed, rawVal_diameterrealm, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding diameter-Realm: %w", octetErr)
	}
	v.DiameterRealm = CommonDataTypesDiameterIdentity(decVal_diameterrealm)
	if offset < 0 || offset >
		len(content) || n_diameterrealm < 0 || n_diameterrealm > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_diameterrealm
	if len(v.DiameterRealm) < 9 || len(v.DiameterRealm) > 255 {
		if constraintErr := ber.CheckDecodedLength(opts, "diameter-Realm", "SIZE (9..255)", len(v.DiameterRealm)); constraintErr != nil {
			return constraintErr
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesNetworkNodeDiameterAddress", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CellGlobalIdOrServiceAreaIdOrLAI3 to BER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CellGlobalIdOrServiceAreaIdOrLAI3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CellGlobalIdOrServiceAreaIdOrLAI3ChoiceCellGlobalIdOrServiceAreaIdFixedLength:
		if v.CellGlobalIdOrServiceAreaIdFixedLength == nil {
			return nil, fmt.Errorf("%w: choice CellGlobalIdOrServiceAreaIdOrLAI3: cellGlobalIdOrServiceAreaIdFixedLength is nil", ber.ErrInvalidValue)
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
	case CellGlobalIdOrServiceAreaIdOrLAI3ChoiceLaiFixedLength:
		if v.LaiFixedLength == nil {
			return nil, fmt.Errorf("%w: choice CellGlobalIdOrServiceAreaIdOrLAI3: laiFixedLength is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for CellGlobalIdOrServiceAreaIdOrLAI3", v.Choice)
	}
}

// MarshalDER encodes CellGlobalIdOrServiceAreaIdOrLAI3 to DER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CellGlobalIdOrServiceAreaIdOrLAI3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CellGlobalIdOrServiceAreaIdOrLAI3 from BER/DER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI3 destination is nil", ber.ErrInvalidValue)
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
	*v = CellGlobalIdOrServiceAreaIdOrLAI3{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CellGlobalIdOrServiceAreaIdOrLAI3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CellGlobalIdOrServiceAreaIdOrLAI3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding CellGlobalIdOrServiceAreaIdOrLAI3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CellGlobalIdOrServiceAreaIdOrLAI3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAI3ChoiceCellGlobalIdOrServiceAreaIdFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding cellGlobalIdOrServiceAreaIdFixedLength: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding cellGlobalIdOrServiceAreaIdFixedLength: %w", octetErr)
		}
		tmp := CellGlobalIdOrServiceAreaIdFixedLength3(decVal)
		v.CellGlobalIdOrServiceAreaIdFixedLength = &tmp
		if len(*v.CellGlobalIdOrServiceAreaIdFixedLength) < 7 || len(*v.CellGlobalIdOrServiceAreaIdFixedLength) > 7 {
			if constraintErr := ber.CheckDecodedLength(opts, "cellGlobalIdOrServiceAreaIdFixedLength", "SIZE (7)", len(*v.CellGlobalIdOrServiceAreaIdFixedLength)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAI3ChoiceLaiFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding laiFixedLength: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding laiFixedLength: %w", octetErr)
		}
		tmp := LAIFixedLength3(decVal)
		v.LaiFixedLength = &tmp
		if len(*v.LaiFixedLength) < 5 || len(*v.LaiFixedLength) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "laiFixedLength", "SIZE (5)", len(*v.LaiFixedLength)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for CellGlobalIdOrServiceAreaIdOrLAI3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes BasicServiceCode3 to BER format.
func (v *BasicServiceCode3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BasicServiceCode3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BasicServiceCode3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case BasicServiceCode3ChoiceBearerService:
		if v.BearerService == nil {
			return nil, fmt.Errorf("%w: choice BasicServiceCode3: bearerService is nil", ber.ErrInvalidValue)
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
	case BasicServiceCode3ChoiceTeleservice:
		if v.Teleservice == nil {
			return nil, fmt.Errorf("%w: choice BasicServiceCode3: teleservice is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for BasicServiceCode3", v.Choice)
	}
}

// MarshalDER encodes BasicServiceCode3 to DER format.
func (v *BasicServiceCode3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BasicServiceCode3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BasicServiceCode3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BasicServiceCode3 from BER/DER format.
func (v *BasicServiceCode3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BasicServiceCode3 destination is nil", ber.ErrInvalidValue)
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
	*v = BasicServiceCode3{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for BasicServiceCode3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for BasicServiceCode3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding BasicServiceCode3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "BasicServiceCode3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = BasicServiceCode3ChoiceBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding bearerService: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding bearerService: %w", octetErr)
		}
		tmp := BearerServiceCode3(decVal)
		v.BearerService = &tmp
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = BasicServiceCode3ChoiceTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding teleservice: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding teleservice: %w", octetErr)
		}
		tmp := TeleserviceCode3(decVal)
		v.Teleservice = &tmp
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for BasicServiceCode3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtBasicServiceCode3 to BER format.
func (v *ExtBasicServiceCode3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtBasicServiceCode3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtBasicServiceCode3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ExtBasicServiceCode3ChoiceExtBearerService:
		if v.ExtBearerService == nil {
			return nil, fmt.Errorf("%w: choice ExtBasicServiceCode3: ext-BearerService is nil", ber.ErrInvalidValue)
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
	case ExtBasicServiceCode3ChoiceExtTeleservice:
		if v.ExtTeleservice == nil {
			return nil, fmt.Errorf("%w: choice ExtBasicServiceCode3: ext-Teleservice is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for ExtBasicServiceCode3", v.Choice)
	}
}

// MarshalDER encodes ExtBasicServiceCode3 to DER format.
func (v *ExtBasicServiceCode3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtBasicServiceCode3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtBasicServiceCode3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtBasicServiceCode3 from BER/DER format.
func (v *ExtBasicServiceCode3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtBasicServiceCode3 destination is nil", ber.ErrInvalidValue)
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
	*v = ExtBasicServiceCode3{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtBasicServiceCode3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtBasicServiceCode3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding ExtBasicServiceCode3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtBasicServiceCode3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ExtBasicServiceCode3ChoiceExtBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-BearerService: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding ext-BearerService: %w", octetErr)
		}
		tmp := ExtBearerServiceCode3(decVal)
		v.ExtBearerService = &tmp
		if len(*v.ExtBearerService) < 1 || len(*v.ExtBearerService) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "ext-BearerService", "SIZE (1..5)", len(*v.ExtBearerService)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = ExtBasicServiceCode3ChoiceExtTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-Teleservice: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding ext-Teleservice: %w", octetErr)
		}
		tmp := ExtTeleserviceCode3(decVal)
		v.ExtTeleservice = &tmp
		if len(*v.ExtTeleservice) < 1 || len(*v.ExtTeleservice) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "ext-Teleservice", "SIZE (1..5)", len(*v.ExtTeleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for ExtBasicServiceCode3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EMLPPInfo3 to BER format.
func (v *EMLPPInfo3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: EMLPPInfo3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EMLPPInfo3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes EMLPPInfo3 to DER format.
func (v *EMLPPInfo3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EMLPPInfo3 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding EMLPPInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EMLPPInfo3 from BER/DER format.
func (v *EMLPPInfo3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EMLPPInfo3 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = EMLPPInfo3{}
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
		return fmt.Errorf("decoding EMLPPInfo3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EMLPPInfo3", Cause: ber.ErrExtraData}
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
	v.MaximumentitledPriority = EMLPPPriority3(val_maximumentitledpriority)
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
	v.DefaultPriority = EMLPPPriority3(val_defaultpriority)
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "EMLPPInfo3", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "EMLPPInfo3", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes MCSSInfo3 to BER format.
func (v *MCSSInfo3) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: MCSSInfo3 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MCSSInfo3) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes MCSSInfo3 to DER format.
func (v *MCSSInfo3) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MCSSInfo3 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding MCSSInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MCSSInfo3 from BER/DER format.
func (v *MCSSInfo3) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MCSSInfo3 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MCSSInfo3{}
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
		return fmt.Errorf("decoding MCSSInfo3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MCSSInfo3", Cause: ber.ErrExtraData}
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
	v.SsCode = SSCode3(decVal_sscode)
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
	v.SsStatus = ExtSSStatus3(decVal_ssstatus)
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
	v.NbrSB = MaxMCBearers3(decVal_nbrsb)
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
	v.NbrUser = MCBearers3(decVal_nbruser)
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
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "MCSSInfo3", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MCSSInfo3", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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
