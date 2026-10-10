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

	// MaxAddressLength5 is the integer constant for maxAddressLength.
	MaxAddressLength5 int64 = 20

	// MaxISDNAddressLength5 is the integer constant for maxISDN-AddressLength.
	MaxISDNAddressLength5 int64 = 9

	// MaxFTNAddressLength5 is the integer constant for maxFTN-AddressLength.
	MaxFTNAddressLength5 int64 = 15

	// MaxISDNSubaddressLength5 is the integer constant for maxISDN-SubaddressLength.
	MaxISDNSubaddressLength5 int64 = 21

	// MaxSignalInfoLength5 is the integer constant for maxSignalInfoLength.
	MaxSignalInfoLength5 int64 = 200

	// MaxLongSignalInfoLength5 is the integer constant for maxLongSignalInfoLength.
	MaxLongSignalInfoLength5 int64 = 2560

	// AlertingLevel05 is the octet string constant for alertingLevel-0.
	AlertingLevel05 = "\x00"

	// AlertingLevel15 is the octet string constant for alertingLevel-1.
	AlertingLevel15 = "\x01"

	// AlertingLevel25 is the octet string constant for alertingLevel-2.
	AlertingLevel25 = "\x02"

	// AlertingCategory15 is the octet string constant for alertingCategory-1.
	AlertingCategory15 = "\x04"

	// AlertingCategory25 is the octet string constant for alertingCategory-2.
	AlertingCategory25 = "\x05"

	// AlertingCategory35 is the octet string constant for alertingCategory-3.
	AlertingCategory35 = "\x06"

	// AlertingCategory45 is the octet string constant for alertingCategory-4.
	AlertingCategory45 = "\x07"

	// AlertingCategory55 is the octet string constant for alertingCategory-5.
	AlertingCategory55 = "\x08"

	// MaxNumOfHLRId5 is the integer constant for maxNumOfHLR-Id.
	MaxNumOfHLRId5 int64 = 50

	// EmergencyServices5 is the integer constant for emergencyServices.
	EmergencyServices5 int64 = 0

	// EmergencyAlertServices5 is the integer constant for emergencyAlertServices.
	EmergencyAlertServices5 int64 = 1

	// PersonTracking5 is the integer constant for personTracking.
	PersonTracking5 int64 = 2

	// FleetManagement5 is the integer constant for fleetManagement.
	FleetManagement5 int64 = 3

	// AssetManagement5 is the integer constant for assetManagement.
	AssetManagement5 int64 = 4

	// TrafficCongestionReporting5 is the integer constant for trafficCongestionReporting.
	TrafficCongestionReporting5 int64 = 5

	// RoadsideAssistance5 is the integer constant for roadsideAssistance.
	RoadsideAssistance5 int64 = 6

	// RoutingToNearestCommercialEnterprise5 is the integer constant for routingToNearestCommercialEnterprise.
	RoutingToNearestCommercialEnterprise5 int64 = 7

	// Navigation5 is the integer constant for navigation.
	Navigation5 int64 = 8

	// CitySightseeing5 is the integer constant for citySightseeing.
	CitySightseeing5 int64 = 9

	// LocalizedAdvertising5 is the integer constant for localizedAdvertising.
	LocalizedAdvertising5 int64 = 10

	// MobileYellowPages5 is the integer constant for mobileYellowPages.
	MobileYellowPages5 int64 = 11

	// TrafficAndPublicTransportationInfo5 is the integer constant for trafficAndPublicTransportationInfo.
	TrafficAndPublicTransportationInfo5 int64 = 12

	// Weather5 is the integer constant for weather.
	Weather5 int64 = 13

	// AssetAndServiceFinding5 is the integer constant for assetAndServiceFinding.
	AssetAndServiceFinding5 int64 = 14

	// Gaming5 is the integer constant for gaming.
	Gaming5 int64 = 15

	// FindYourFriend5 is the integer constant for findYourFriend.
	FindYourFriend5 int64 = 16

	// Dating5 is the integer constant for dating.
	Dating5 int64 = 17

	// Chatting5 is the integer constant for chatting.
	Chatting5 int64 = 18

	// RouteFinding5 is the integer constant for routeFinding.
	RouteFinding5 int64 = 19

	// WhereAmI5 is the integer constant for whereAmI.
	WhereAmI5 int64 = 20

	// Serv645 is the integer constant for serv64.
	Serv645 int64 = 64

	// Serv655 is the integer constant for serv65.
	Serv655 int64 = 65

	// Serv665 is the integer constant for serv66.
	Serv665 int64 = 66

	// Serv675 is the integer constant for serv67.
	Serv675 int64 = 67

	// Serv685 is the integer constant for serv68.
	Serv685 int64 = 68

	// Serv695 is the integer constant for serv69.
	Serv695 int64 = 69

	// Serv705 is the integer constant for serv70.
	Serv705 int64 = 70

	// Serv715 is the integer constant for serv71.
	Serv715 int64 = 71

	// Serv725 is the integer constant for serv72.
	Serv725 int64 = 72

	// Serv735 is the integer constant for serv73.
	Serv735 int64 = 73

	// Serv745 is the integer constant for serv74.
	Serv745 int64 = 74

	// Serv755 is the integer constant for serv75.
	Serv755 int64 = 75

	// Serv765 is the integer constant for serv76.
	Serv765 int64 = 76

	// Serv775 is the integer constant for serv77.
	Serv775 int64 = 77

	// Serv785 is the integer constant for serv78.
	Serv785 int64 = 78

	// Serv795 is the integer constant for serv79.
	Serv795 int64 = 79

	// Serv805 is the integer constant for serv80.
	Serv805 int64 = 80

	// Serv815 is the integer constant for serv81.
	Serv815 int64 = 81

	// Serv825 is the integer constant for serv82.
	Serv825 int64 = 82

	// Serv835 is the integer constant for serv83.
	Serv835 int64 = 83

	// Serv845 is the integer constant for serv84.
	Serv845 int64 = 84

	// Serv855 is the integer constant for serv85.
	Serv855 int64 = 85

	// Serv865 is the integer constant for serv86.
	Serv865 int64 = 86

	// Serv875 is the integer constant for serv87.
	Serv875 int64 = 87

	// Serv885 is the integer constant for serv88.
	Serv885 int64 = 88

	// Serv895 is the integer constant for serv89.
	Serv895 int64 = 89

	// Serv905 is the integer constant for serv90.
	Serv905 int64 = 90

	// Serv915 is the integer constant for serv91.
	Serv915 int64 = 91

	// Serv925 is the integer constant for serv92.
	Serv925 int64 = 92

	// Serv935 is the integer constant for serv93.
	Serv935 int64 = 93

	// Serv945 is the integer constant for serv94.
	Serv945 int64 = 94

	// Serv955 is the integer constant for serv95.
	Serv955 int64 = 95

	// Serv965 is the integer constant for serv96.
	Serv965 int64 = 96

	// Serv975 is the integer constant for serv97.
	Serv975 int64 = 97

	// Serv985 is the integer constant for serv98.
	Serv985 int64 = 98

	// Serv995 is the integer constant for serv99.
	Serv995 int64 = 99

	// Serv1005 is the integer constant for serv100.
	Serv1005 int64 = 100

	// Serv1015 is the integer constant for serv101.
	Serv1015 int64 = 101

	// Serv1025 is the integer constant for serv102.
	Serv1025 int64 = 102

	// Serv1035 is the integer constant for serv103.
	Serv1035 int64 = 103

	// Serv1045 is the integer constant for serv104.
	Serv1045 int64 = 104

	// Serv1055 is the integer constant for serv105.
	Serv1055 int64 = 105

	// Serv1065 is the integer constant for serv106.
	Serv1065 int64 = 106

	// Serv1075 is the integer constant for serv107.
	Serv1075 int64 = 107

	// Serv1085 is the integer constant for serv108.
	Serv1085 int64 = 108

	// Serv1095 is the integer constant for serv109.
	Serv1095 int64 = 109

	// Serv1105 is the integer constant for serv110.
	Serv1105 int64 = 110

	// Serv1115 is the integer constant for serv111.
	Serv1115 int64 = 111

	// Serv1125 is the integer constant for serv112.
	Serv1125 int64 = 112

	// Serv1135 is the integer constant for serv113.
	Serv1135 int64 = 113

	// Serv1145 is the integer constant for serv114.
	Serv1145 int64 = 114

	// Serv1155 is the integer constant for serv115.
	Serv1155 int64 = 115

	// Serv1165 is the integer constant for serv116.
	Serv1165 int64 = 116

	// Serv1175 is the integer constant for serv117.
	Serv1175 int64 = 117

	// Serv1185 is the integer constant for serv118.
	Serv1185 int64 = 118

	// Serv1195 is the integer constant for serv119.
	Serv1195 int64 = 119

	// Serv1205 is the integer constant for serv120.
	Serv1205 int64 = 120

	// Serv1215 is the integer constant for serv121.
	Serv1215 int64 = 121

	// Serv1225 is the integer constant for serv122.
	Serv1225 int64 = 122

	// Serv1235 is the integer constant for serv123.
	Serv1235 int64 = 123

	// Serv1245 is the integer constant for serv124.
	Serv1245 int64 = 124

	// Serv1255 is the integer constant for serv125.
	Serv1255 int64 = 125

	// Serv1265 is the integer constant for serv126.
	Serv1265 int64 = 126

	// Serv1275 is the integer constant for serv127.
	Serv1275 int64 = 127

	// PriorityLevelA5 is the integer constant for priorityLevelA.
	PriorityLevelA5 int64 = 6

	// PriorityLevelB5 is the integer constant for priorityLevelB.
	PriorityLevelB5 int64 = 5

	// PriorityLevel05 is the integer constant for priorityLevel0.
	PriorityLevel05 int64 = 0

	// PriorityLevel15 is the integer constant for priorityLevel1.
	PriorityLevel15 int64 = 1

	// PriorityLevel25 is the integer constant for priorityLevel2.
	PriorityLevel25 int64 = 2

	// PriorityLevel35 is the integer constant for priorityLevel3.
	PriorityLevel35 int64 = 3

	// PriorityLevel45 is the integer constant for priorityLevel4.
	PriorityLevel45 int64 = 4

	// MaxNumOfMCBearers5 is the integer constant for maxNumOfMC-Bearers.
	MaxNumOfMCBearers5 int64 = 7
)

// TBCDSTRING5 represents the ASN.1 type TBCD-STRING (OCTET_STRING).
type TBCDSTRING5 = []byte

// DiameterIdentity4 represents the ASN.1 type DiameterIdentity (OCTET_STRING).
type DiameterIdentity4 = []byte

// AddressString5 represents the ASN.1 type AddressString (OCTET_STRING).
type AddressString5 = []byte

// ISDNAddressString5 represents the ASN.1 type ISDN-AddressString (OCTET_STRING).
type ISDNAddressString5 = AddressString5

// FTNAddressString5 represents the ASN.1 type FTN-AddressString (OCTET_STRING).
type FTNAddressString5 = AddressString5

// ISDNSubaddressString5 represents the ASN.1 type ISDN-SubaddressString (OCTET_STRING).
type ISDNSubaddressString5 = []byte

// ExternalSignalInfo5 represents the ASN.1 type ExternalSignalInfo (SEQUENCE).
type ExternalSignalInfo5 struct {
	ProtocolId         ProtocolId5          `asn1:""`
	SignalInfo         SignalInfo5          `asn1:""`
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// SignalInfo5 represents the ASN.1 type SignalInfo (OCTET_STRING).
type SignalInfo5 = []byte

// ProtocolId5 represents the ASN.1 ENUMERATED type ProtocolId.
type ProtocolId5 int64

const (
	ProtocolId5Gsm0408    ProtocolId5 = 1
	ProtocolId5Gsm0806    ProtocolId5 = 2
	ProtocolId5GsmBSSMAP  ProtocolId5 = 3
	ProtocolId5Ets3001021 ProtocolId5 = 4
)

func (v ProtocolId5) String() string {
	switch v {
	case ProtocolId5Gsm0408:
		return "gsm-0408"
	case ProtocolId5Gsm0806:
		return "gsm-0806"
	case ProtocolId5GsmBSSMAP:
		return "gsm-BSSMAP"
	case ProtocolId5Ets3001021:
		return "ets-300102-1"
	default:
		return "unknown"
	}
}

// ExtExternalSignalInfo5 represents the ASN.1 type Ext-ExternalSignalInfo (SEQUENCE).
type ExtExternalSignalInfo5 struct {
	ExtProtocolId      ExtProtocolId5       `asn1:""`
	SignalInfo         SignalInfo5          `asn1:""`
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// ExtProtocolId5 represents the ASN.1 ENUMERATED type Ext-ProtocolId.
type ExtProtocolId5 int64

const (
	ExtProtocolId5Ets300356 ExtProtocolId5 = 1
)

func (v ExtProtocolId5) String() string {
	switch v {
	case ExtProtocolId5Ets300356:
		return "ets-300356"
	default:
		return "unknown"
	}
}

// AccessNetworkSignalInfo5 represents the ASN.1 type AccessNetworkSignalInfo (SEQUENCE).
type AccessNetworkSignalInfo5 struct {
	AccessNetworkProtocolId AccessNetworkProtocolId5 `asn1:""`
	SignalInfo              LongSignalInfo5          `asn1:""`
	ExtensionContainer      *ExtensionContainer5     `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
	berOriginal_            []byte                   `asn1:"-" json:"-"`
	berSnapshot_            []byte                   `asn1:"-" json:"-"`
}

// LongSignalInfo5 represents the ASN.1 type LongSignalInfo (OCTET_STRING).
type LongSignalInfo5 = []byte

// AccessNetworkProtocolId5 represents the ASN.1 ENUMERATED type AccessNetworkProtocolId.
type AccessNetworkProtocolId5 int64

const (
	AccessNetworkProtocolId5Ts3G48006 AccessNetworkProtocolId5 = 1
	AccessNetworkProtocolId5Ts3G25413 AccessNetworkProtocolId5 = 2
)

func (v AccessNetworkProtocolId5) String() string {
	switch v {
	case AccessNetworkProtocolId5Ts3G48006:
		return "ts3G-48006"
	case AccessNetworkProtocolId5Ts3G25413:
		return "ts3G-25413"
	default:
		return "unknown"
	}
}

// AlertingPattern5 represents the ASN.1 type AlertingPattern (OCTET_STRING).
type AlertingPattern5 = []byte

// GSNAddress5 represents the ASN.1 type GSN-Address (OCTET_STRING).
type GSNAddress5 = []byte

// Time4 represents the ASN.1 type Time (OCTET_STRING).
type Time4 = []byte

// IMSI5 represents the ASN.1 type IMSI (OCTET_STRING).
type IMSI5 = TBCDSTRING5

// Identity5 choice constants.
const (
	Identity5ChoiceImsi         = 1
	Identity5ChoiceImsiWithLMSI = 2
)

// Identity5 represents the ASN.1 CHOICE type Identity.
type Identity5 struct {
	Choice       int
	berOriginal_ []byte         `json:"-"`
	berSnapshot_ []byte         `json:"-"`
	Imsi         *IMSI5         `json:"Imsi,omitempty"`
	ImsiWithLMSI *IMSIWithLMSI5 `json:"ImsiWithLMSI,omitempty"`
}

// NewIdentity5Imsi creates a Identity5 with the imsi alternative.
func NewIdentity5Imsi(v IMSI5) Identity5 {
	return Identity5{
		Choice: Identity5ChoiceImsi,
		Imsi:   &v,
	}
}

// NewIdentity5ImsiWithLMSI creates a Identity5 with the imsi-WithLMSI alternative.
func NewIdentity5ImsiWithLMSI(v IMSIWithLMSI5) Identity5 {
	return Identity5{
		Choice:       Identity5ChoiceImsiWithLMSI,
		ImsiWithLMSI: &v,
	}
}

// IMSIWithLMSI5 represents the ASN.1 type IMSI-WithLMSI (SEQUENCE).
type IMSIWithLMSI5 struct {
	Imsi         IMSI5    `asn1:""`
	Lmsi         LMSI5    `asn1:""`
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// ASCICallReference5 represents the ASN.1 type ASCI-CallReference (OCTET_STRING).
type ASCICallReference5 = TBCDSTRING5

// TMSI5 represents the ASN.1 type TMSI (OCTET_STRING).
type TMSI5 = []byte

// SubscriberId5 choice constants.
const (
	SubscriberId5ChoiceImsi = 1
	SubscriberId5ChoiceTmsi = 2
)

// SubscriberId5 represents the ASN.1 CHOICE type SubscriberId.
type SubscriberId5 struct {
	Choice       int
	berOriginal_ []byte `json:"-"`
	berSnapshot_ []byte `json:"-"`
	Imsi         *IMSI5 `json:"Imsi,omitempty"`
	Tmsi         *TMSI5 `json:"Tmsi,omitempty"`
}

// NewSubscriberId5Imsi creates a SubscriberId5 with the imsi alternative.
func NewSubscriberId5Imsi(v IMSI5) SubscriberId5 {
	return SubscriberId5{
		Choice: SubscriberId5ChoiceImsi,
		Imsi:   &v,
	}
}

// NewSubscriberId5Tmsi creates a SubscriberId5 with the tmsi alternative.
func NewSubscriberId5Tmsi(v TMSI5) SubscriberId5 {
	return SubscriberId5{
		Choice: SubscriberId5ChoiceTmsi,
		Tmsi:   &v,
	}
}

// IMEI5 represents the ASN.1 type IMEI (OCTET_STRING).
type IMEI5 = TBCDSTRING5

// HLRId5 represents the ASN.1 type HLR-Id (OCTET_STRING).
type HLRId5 = IMSI5

// HLRList5 represents the ASN.1 type HLR-List (SEQUENCE_OF).
type HLRList5 struct {
	Values       []HLRId5 `json:"Values"`
	berOriginal_ []byte   `json:"-"`
	berSnapshot_ []byte   `json:"-"`
}

// LMSI5 represents the ASN.1 type LMSI (OCTET_STRING).
type LMSI5 = []byte

// GlobalCellId5 represents the ASN.1 type GlobalCellId (OCTET_STRING).
type GlobalCellId5 = []byte

// NetworkResource5 represents the ASN.1 ENUMERATED type NetworkResource.
type NetworkResource5 int64

const (
	NetworkResource5Plmn           NetworkResource5 = 0
	NetworkResource5Hlr            NetworkResource5 = 1
	NetworkResource5Vlr            NetworkResource5 = 2
	NetworkResource5Pvlr           NetworkResource5 = 3
	NetworkResource5ControllingMSC NetworkResource5 = 4
	NetworkResource5Vmsc           NetworkResource5 = 5
	NetworkResource5Eir            NetworkResource5 = 6
	NetworkResource5Rss            NetworkResource5 = 7
)

func (v NetworkResource5) String() string {
	switch v {
	case NetworkResource5Plmn:
		return "plmn"
	case NetworkResource5Hlr:
		return "hlr"
	case NetworkResource5Vlr:
		return "vlr"
	case NetworkResource5Pvlr:
		return "pvlr"
	case NetworkResource5ControllingMSC:
		return "controllingMSC"
	case NetworkResource5Vmsc:
		return "vmsc"
	case NetworkResource5Eir:
		return "eir"
	case NetworkResource5Rss:
		return "rss"
	default:
		return "unknown"
	}
}

// AdditionalNetworkResource5 represents the ASN.1 ENUMERATED type AdditionalNetworkResource.
type AdditionalNetworkResource5 int64

const (
	AdditionalNetworkResource5Sgsn   AdditionalNetworkResource5 = 0
	AdditionalNetworkResource5Ggsn   AdditionalNetworkResource5 = 1
	AdditionalNetworkResource5Gmlc   AdditionalNetworkResource5 = 2
	AdditionalNetworkResource5GsmSCF AdditionalNetworkResource5 = 3
	AdditionalNetworkResource5Nplr   AdditionalNetworkResource5 = 4
	AdditionalNetworkResource5Auc    AdditionalNetworkResource5 = 5
	AdditionalNetworkResource5Ue     AdditionalNetworkResource5 = 6
	AdditionalNetworkResource5Mme    AdditionalNetworkResource5 = 7
)

func (v AdditionalNetworkResource5) String() string {
	switch v {
	case AdditionalNetworkResource5Sgsn:
		return "sgsn"
	case AdditionalNetworkResource5Ggsn:
		return "ggsn"
	case AdditionalNetworkResource5Gmlc:
		return "gmlc"
	case AdditionalNetworkResource5GsmSCF:
		return "gsmSCF"
	case AdditionalNetworkResource5Nplr:
		return "nplr"
	case AdditionalNetworkResource5Auc:
		return "auc"
	case AdditionalNetworkResource5Ue:
		return "ue"
	case AdditionalNetworkResource5Mme:
		return "mme"
	default:
		return "unknown"
	}
}

// NAEAPreferredCI5 represents the ASN.1 type NAEA-PreferredCI (SEQUENCE).
type NAEAPreferredCI5 struct {
	NaeaPreferredCIC   NAEACIC5             `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionContainer5 `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// NAEACIC5 represents the ASN.1 type NAEA-CIC (OCTET_STRING).
type NAEACIC5 = []byte

// SubscriberIdentity5 choice constants.
const (
	SubscriberIdentity5ChoiceImsi   = 1
	SubscriberIdentity5ChoiceMsisdn = 2
)

// SubscriberIdentity5 represents the ASN.1 CHOICE type SubscriberIdentity.
type SubscriberIdentity5 struct {
	Choice       int
	berOriginal_ []byte              `json:"-"`
	berSnapshot_ []byte              `json:"-"`
	Imsi         *IMSI5              `json:"Imsi,omitempty"`
	Msisdn       *ISDNAddressString5 `json:"Msisdn,omitempty"`
}

// NewSubscriberIdentity5Imsi creates a SubscriberIdentity5 with the imsi alternative.
func NewSubscriberIdentity5Imsi(v IMSI5) SubscriberIdentity5 {
	return SubscriberIdentity5{
		Choice: SubscriberIdentity5ChoiceImsi,
		Imsi:   &v,
	}
}

// NewSubscriberIdentity5Msisdn creates a SubscriberIdentity5 with the msisdn alternative.
func NewSubscriberIdentity5Msisdn(v ISDNAddressString5) SubscriberIdentity5 {
	return SubscriberIdentity5{
		Choice: SubscriberIdentity5ChoiceMsisdn,
		Msisdn: &v,
	}
}

// LCSClientExternalID5 represents the ASN.1 type LCSClientExternalID (SEQUENCE).
type LCSClientExternalID5 struct {
	ExternalAddress    *ISDNAddressString5  `asn1:"tag:0,context,implicit,optional" json:"ExternalAddress,omitempty"`
	ExtensionContainer *ExtensionContainer5 `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// LCSClientInternalID5 represents the ASN.1 ENUMERATED type LCSClientInternalID.
type LCSClientInternalID5 int64

const (
	LCSClientInternalID5BroadcastService          LCSClientInternalID5 = 0
	LCSClientInternalID5OAndMHPLMN                LCSClientInternalID5 = 1
	LCSClientInternalID5OAndMVPLMN                LCSClientInternalID5 = 2
	LCSClientInternalID5AnonymousLocation         LCSClientInternalID5 = 3
	LCSClientInternalID5TargetMSsubscribedService LCSClientInternalID5 = 4
)

func (v LCSClientInternalID5) String() string {
	switch v {
	case LCSClientInternalID5BroadcastService:
		return "broadcastService"
	case LCSClientInternalID5OAndMHPLMN:
		return "o-andM-HPLMN"
	case LCSClientInternalID5OAndMVPLMN:
		return "o-andM-VPLMN"
	case LCSClientInternalID5AnonymousLocation:
		return "anonymousLocation"
	case LCSClientInternalID5TargetMSsubscribedService:
		return "targetMSsubscribedService"
	default:
		return "unknown"
	}
}

// LCSServiceTypeID5 represents the ASN.1 type LCSServiceTypeID (INTEGER).
type LCSServiceTypeID5 = int64

// PLMNId5 represents the ASN.1 type PLMN-Id (OCTET_STRING).
type PLMNId5 = []byte

// EUTRANCGI4 represents the ASN.1 type E-UTRAN-CGI (OCTET_STRING).
type EUTRANCGI4 = []byte

// TAId4 represents the ASN.1 type TA-Id (OCTET_STRING).
type TAId4 = []byte

// RAIdentity5 represents the ASN.1 type RAIdentity (OCTET_STRING).
type RAIdentity5 = []byte

// CellGlobalIdOrServiceAreaIdOrLAI5 choice constants.
const (
	CellGlobalIdOrServiceAreaIdOrLAI5ChoiceCellGlobalIdOrServiceAreaIdFixedLength = 1
	CellGlobalIdOrServiceAreaIdOrLAI5ChoiceLaiFixedLength                         = 2
)

// CellGlobalIdOrServiceAreaIdOrLAI5 represents the ASN.1 CHOICE type CellGlobalIdOrServiceAreaIdOrLAI.
type CellGlobalIdOrServiceAreaIdOrLAI5 struct {
	Choice                                 int
	berOriginal_                           []byte                                   `json:"-"`
	berSnapshot_                           []byte                                   `json:"-"`
	CellGlobalIdOrServiceAreaIdFixedLength *CellGlobalIdOrServiceAreaIdFixedLength5 `json:"CellGlobalIdOrServiceAreaIdFixedLength,omitempty"`
	LaiFixedLength                         *LAIFixedLength5                         `json:"LaiFixedLength,omitempty"`
}

// NewCellGlobalIdOrServiceAreaIdOrLAI5CellGlobalIdOrServiceAreaIdFixedLength creates a CellGlobalIdOrServiceAreaIdOrLAI5 with the cellGlobalIdOrServiceAreaIdFixedLength alternative.
func NewCellGlobalIdOrServiceAreaIdOrLAI5CellGlobalIdOrServiceAreaIdFixedLength(v CellGlobalIdOrServiceAreaIdFixedLength5) CellGlobalIdOrServiceAreaIdOrLAI5 {
	return CellGlobalIdOrServiceAreaIdOrLAI5{
		Choice:                                 CellGlobalIdOrServiceAreaIdOrLAI5ChoiceCellGlobalIdOrServiceAreaIdFixedLength,
		CellGlobalIdOrServiceAreaIdFixedLength: &v,
	}
}

// NewCellGlobalIdOrServiceAreaIdOrLAI5LaiFixedLength creates a CellGlobalIdOrServiceAreaIdOrLAI5 with the laiFixedLength alternative.
func NewCellGlobalIdOrServiceAreaIdOrLAI5LaiFixedLength(v LAIFixedLength5) CellGlobalIdOrServiceAreaIdOrLAI5 {
	return CellGlobalIdOrServiceAreaIdOrLAI5{
		Choice:         CellGlobalIdOrServiceAreaIdOrLAI5ChoiceLaiFixedLength,
		LaiFixedLength: &v,
	}
}

// CellGlobalIdOrServiceAreaIdFixedLength5 represents the ASN.1 type CellGlobalIdOrServiceAreaIdFixedLength (OCTET_STRING).
type CellGlobalIdOrServiceAreaIdFixedLength5 = []byte

// LAIFixedLength5 represents the ASN.1 type LAIFixedLength (OCTET_STRING).
type LAIFixedLength5 = []byte

// BasicServiceCode5 choice constants.
const (
	BasicServiceCode5ChoiceBearerService = 1
	BasicServiceCode5ChoiceTeleservice   = 2
)

// BasicServiceCode5 represents the ASN.1 CHOICE type BasicServiceCode.
type BasicServiceCode5 struct {
	Choice        int
	berOriginal_  []byte              `json:"-"`
	berSnapshot_  []byte              `json:"-"`
	BearerService *BearerServiceCode5 `json:"BearerService,omitempty"`
	Teleservice   *TeleserviceCode5   `json:"Teleservice,omitempty"`
}

// NewBasicServiceCode5BearerService creates a BasicServiceCode5 with the bearerService alternative.
func NewBasicServiceCode5BearerService(v BearerServiceCode5) BasicServiceCode5 {
	return BasicServiceCode5{
		Choice:        BasicServiceCode5ChoiceBearerService,
		BearerService: &v,
	}
}

// NewBasicServiceCode5Teleservice creates a BasicServiceCode5 with the teleservice alternative.
func NewBasicServiceCode5Teleservice(v TeleserviceCode5) BasicServiceCode5 {
	return BasicServiceCode5{
		Choice:      BasicServiceCode5ChoiceTeleservice,
		Teleservice: &v,
	}
}

// ExtBasicServiceCode5 choice constants.
const (
	ExtBasicServiceCode5ChoiceExtBearerService = 1
	ExtBasicServiceCode5ChoiceExtTeleservice   = 2
)

// ExtBasicServiceCode5 represents the ASN.1 CHOICE type Ext-BasicServiceCode.
type ExtBasicServiceCode5 struct {
	Choice           int
	berOriginal_     []byte                 `json:"-"`
	berSnapshot_     []byte                 `json:"-"`
	ExtBearerService *ExtBearerServiceCode5 `json:"ExtBearerService,omitempty"`
	ExtTeleservice   *ExtTeleserviceCode5   `json:"ExtTeleservice,omitempty"`
}

// NewExtBasicServiceCode5ExtBearerService creates a ExtBasicServiceCode5 with the ext-BearerService alternative.
func NewExtBasicServiceCode5ExtBearerService(v ExtBearerServiceCode5) ExtBasicServiceCode5 {
	return ExtBasicServiceCode5{
		Choice:           ExtBasicServiceCode5ChoiceExtBearerService,
		ExtBearerService: &v,
	}
}

// NewExtBasicServiceCode5ExtTeleservice creates a ExtBasicServiceCode5 with the ext-Teleservice alternative.
func NewExtBasicServiceCode5ExtTeleservice(v ExtTeleserviceCode5) ExtBasicServiceCode5 {
	return ExtBasicServiceCode5{
		Choice:         ExtBasicServiceCode5ChoiceExtTeleservice,
		ExtTeleservice: &v,
	}
}

// EMLPPInfo5 represents the ASN.1 type EMLPP-Info (SEQUENCE).
type EMLPPInfo5 struct {
	MaximumentitledPriority EMLPPPriority5       `asn1:""`
	DefaultPriority         EMLPPPriority5       `asn1:""`
	ExtensionContainer      *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                `asn1:"-" json:"-"`
	ExtPresent_             []bool               `asn1:"-" json:"-"`
	ExtData_                [][]byte             `asn1:"-" json:"-"`
	berOriginal_            []byte               `asn1:"-" json:"-"`
	berSnapshot_            []byte               `asn1:"-" json:"-"`
}

// EMLPPPriority5 represents the ASN.1 type EMLPP-Priority (INTEGER).
type EMLPPPriority5 = int64

// MCSSInfo5 represents the ASN.1 type MC-SS-Info (SEQUENCE).
type MCSSInfo5 struct {
	SsCode             SSCode5              `asn1:"tag:0,context,implicit"`
	SsStatus           ExtSSStatus5         `asn1:"tag:1,context,implicit"`
	NbrSB              MaxMCBearers5        `asn1:"tag:2,context,implicit"`
	NbrUser            MCBearers5           `asn1:"tag:3,context,implicit"`
	ExtensionContainer *ExtensionContainer5 `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// MaxMCBearers5 represents the ASN.1 type MaxMC-Bearers (INTEGER).
type MaxMCBearers5 = int64

// MCBearers5 represents the ASN.1 type MC-Bearers (INTEGER).
type MCBearers5 = int64

// ExtSSStatus5 represents the ASN.1 type Ext-SS-Status (OCTET_STRING).
type ExtSSStatus5 = []byte

// AgeOfLocationInformation5 represents the ASN.1 type AgeOfLocationInformation (INTEGER).
type AgeOfLocationInformation5 = int64

// MarshalBER encodes ExternalSignalInfo5 to BER format.
func (v *ExternalSignalInfo5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExternalSignalInfo5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExternalSignalInfo5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes ExternalSignalInfo5 to DER format.
func (v *ExternalSignalInfo5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExternalSignalInfo5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ExternalSignalInfo5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExternalSignalInfo5 from BER/DER format.
func (v *ExternalSignalInfo5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExternalSignalInfo5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExternalSignalInfo5{}
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
		return fmt.Errorf("decoding ExternalSignalInfo5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExternalSignalInfo5", Cause: ber.ErrExtraData}
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
	v.ProtocolId = ProtocolId5(val_protocolid)
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
	v.SignalInfo = SignalInfo5(val_signalinfo)
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
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo5", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo5", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes ExtExternalSignalInfo5 to BER format.
func (v *ExtExternalSignalInfo5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtExternalSignalInfo5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtExternalSignalInfo5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes ExtExternalSignalInfo5 to DER format.
func (v *ExtExternalSignalInfo5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtExternalSignalInfo5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ExtExternalSignalInfo5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtExternalSignalInfo5 from BER/DER format.
func (v *ExtExternalSignalInfo5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtExternalSignalInfo5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtExternalSignalInfo5{}
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
		return fmt.Errorf("decoding ExtExternalSignalInfo5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtExternalSignalInfo5", Cause: ber.ErrExtraData}
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
	v.ExtProtocolId = ExtProtocolId5(val_extprotocolid)
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
	v.SignalInfo = SignalInfo5(val_signalinfo)
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
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtExternalSignalInfo5", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExtExternalSignalInfo5", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes AccessNetworkSignalInfo5 to BER format.
func (v *AccessNetworkSignalInfo5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AccessNetworkSignalInfo5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AccessNetworkSignalInfo5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes AccessNetworkSignalInfo5 to DER format.
func (v *AccessNetworkSignalInfo5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AccessNetworkSignalInfo5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding AccessNetworkSignalInfo5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AccessNetworkSignalInfo5 from BER/DER format.
func (v *AccessNetworkSignalInfo5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AccessNetworkSignalInfo5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AccessNetworkSignalInfo5{}
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
		return fmt.Errorf("decoding AccessNetworkSignalInfo5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AccessNetworkSignalInfo5", Cause: ber.ErrExtraData}
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
	v.AccessNetworkProtocolId = AccessNetworkProtocolId5(val_accessnetworkprotocolid)
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
	v.SignalInfo = LongSignalInfo5(val_signalinfo)
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
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
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
			return &ber.DecodeError{Offset: offset, TypeName: "AccessNetworkSignalInfo5", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "AccessNetworkSignalInfo5", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes Identity5 to BER format.
func (v *Identity5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Identity5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Identity5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case Identity5ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice Identity5: imsi is nil", ber.ErrInvalidValue)
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
	case Identity5ChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice Identity5: imsi-WithLMSI is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ImsiWithLMSI.MarshalBER(ber.ChildEncodeOptions(opts, "imsi-WithLMSI")...)
		if err != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Identity5", v.Choice)
	}
}

// MarshalDER encodes Identity5 to DER format.
func (v *Identity5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Identity5 receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case Identity5ChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("%w: choice Identity5: imsi-WithLMSI is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding Identity5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Identity5 from BER/DER format.
func (v *Identity5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Identity5 destination is nil", ber.ErrInvalidValue)
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
	*v = Identity5{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Identity5 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Identity5: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding Identity5 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Identity5", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = Identity5ChoiceImsi
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return fmt.Errorf("decoding imsi: %w", osErr)
		}
		tmp := IMSI5(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = Identity5ChoiceImsiWithLMSI
		var dec IMSIWithLMSI5
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "imsi-WithLMSI")...); unmErr != nil {
			return fmt.Errorf("decoding imsi-WithLMSI: %w", unmErr)
		}
		v.ImsiWithLMSI = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Identity5 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes IMSIWithLMSI5 to BER format.
func (v *IMSIWithLMSI5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: IMSIWithLMSI5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IMSIWithLMSI5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes IMSIWithLMSI5 to DER format.
func (v *IMSIWithLMSI5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IMSIWithLMSI5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding IMSIWithLMSI5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IMSIWithLMSI5 from BER/DER format.
func (v *IMSIWithLMSI5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IMSIWithLMSI5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IMSIWithLMSI5{}
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
		return fmt.Errorf("decoding IMSIWithLMSI5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IMSIWithLMSI5", Cause: ber.ErrExtraData}
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
	v.Imsi = IMSI5(val_imsi)
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
	v.Lmsi = LMSI5(val_lmsi)
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
			return &ber.DecodeError{Offset: offset, TypeName: "IMSIWithLMSI5", Cause: extErr_}
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

// MarshalBER encodes SubscriberId5 to BER format.
func (v *SubscriberId5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberId5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SubscriberId5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SubscriberId5ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberId5: imsi is nil", ber.ErrInvalidValue)
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
	case SubscriberId5ChoiceTmsi:
		if v.Tmsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberId5: tmsi is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for SubscriberId5", v.Choice)
	}
}

// MarshalDER encodes SubscriberId5 to DER format.
func (v *SubscriberId5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberId5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberId5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberId5 from BER/DER format.
func (v *SubscriberId5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SubscriberId5 destination is nil", ber.ErrInvalidValue)
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
	*v = SubscriberId5{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberId5 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberId5: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberId5 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberId5", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberId5ChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding imsi: %w", octetErr)
		}
		tmp := IMSI5(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberId5ChoiceTmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding tmsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding tmsi: %w", octetErr)
		}
		tmp := TMSI5(decVal)
		v.Tmsi = &tmp
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberId5 CHOICE", peekTag)
	}
	return nil
}

// MarshalBERHLRList5 encodes a HLRList5 list to BER.
func MarshalBERHLRList5(collection *HLRList5, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERHLRList5(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERHLRList5(collection *HLRList5, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(opts, "HLRList5", "SIZE (1..50)", len(list)); constraintErr != nil {
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

// MarshalDERHLRList5 encodes a HLRList5 list to DER.
func MarshalDERHLRList5(collection *HLRList5) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(nil, "HLRList5", "SIZE (1..50)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("encoding HLRList5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERHLRList5 decodes a HLRList5 list from BER.
func UnmarshalBERHLRList5(data []byte, opts ...ber.DecodeOption) (returnValue *HLRList5, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding HLRList5: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "HLRList5", Cause: ber.ErrExtraData}
	}
	var result []HLRId5
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
		result = append(result, HLRId5(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedLength(opts, "HLRList5", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &HLRList5{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERHLRList5(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes NAEAPreferredCI5 to BER format.
func (v *NAEAPreferredCI5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: NAEAPreferredCI5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NAEAPreferredCI5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes NAEAPreferredCI5 to DER format.
func (v *NAEAPreferredCI5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NAEAPreferredCI5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding NAEAPreferredCI5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NAEAPreferredCI5 from BER/DER format.
func (v *NAEAPreferredCI5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NAEAPreferredCI5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NAEAPreferredCI5{}
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
		return fmt.Errorf("decoding NAEAPreferredCI5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NAEAPreferredCI5", Cause: ber.ErrExtraData}
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
	v.NaeaPreferredCIC = NAEACIC5(decVal_naeapreferredcic)
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
				var dec_extensioncontainer ExtensionContainer5
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
			return &ber.DecodeError{Offset: offset, TypeName: "NAEAPreferredCI5", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "NAEAPreferredCI5", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes SubscriberIdentity5 to BER format.
func (v *SubscriberIdentity5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberIdentity5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SubscriberIdentity5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SubscriberIdentity5ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberIdentity5: imsi is nil", ber.ErrInvalidValue)
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
	case SubscriberIdentity5ChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("%w: choice SubscriberIdentity5: msisdn is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for SubscriberIdentity5", v.Choice)
	}
}

// MarshalDER encodes SubscriberIdentity5 to DER format.
func (v *SubscriberIdentity5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberIdentity5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberIdentity5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberIdentity5 from BER/DER format.
func (v *SubscriberIdentity5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SubscriberIdentity5 destination is nil", ber.ErrInvalidValue)
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
	*v = SubscriberIdentity5{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberIdentity5 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberIdentity5: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberIdentity5 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberIdentity5", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberIdentity5ChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding imsi: %w", octetErr)
		}
		tmp := IMSI5(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberIdentity5ChoiceMsisdn
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding msisdn: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding msisdn: %w", octetErr)
		}
		tmp := ISDNAddressString5(decVal)
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
		return fmt.Errorf("unknown tag %s for SubscriberIdentity5 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes LCSClientExternalID5 to BER format.
func (v *LCSClientExternalID5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSClientExternalID5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSClientExternalID5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes LCSClientExternalID5 to DER format.
func (v *LCSClientExternalID5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSClientExternalID5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding LCSClientExternalID5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSClientExternalID5 from BER/DER format.
func (v *LCSClientExternalID5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSClientExternalID5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSClientExternalID5{}
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
		return fmt.Errorf("decoding LCSClientExternalID5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSClientExternalID5", Cause: ber.ErrExtraData}
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
				tmp_externaladdress := ISDNAddressString5(decVal_externaladdress)
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
				var dec_extensioncontainer ExtensionContainer5
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSClientExternalID5", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSClientExternalID5", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes CellGlobalIdOrServiceAreaIdOrLAI5 to BER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CellGlobalIdOrServiceAreaIdOrLAI5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CellGlobalIdOrServiceAreaIdOrLAI5ChoiceCellGlobalIdOrServiceAreaIdFixedLength:
		if v.CellGlobalIdOrServiceAreaIdFixedLength == nil {
			return nil, fmt.Errorf("%w: choice CellGlobalIdOrServiceAreaIdOrLAI5: cellGlobalIdOrServiceAreaIdFixedLength is nil", ber.ErrInvalidValue)
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
	case CellGlobalIdOrServiceAreaIdOrLAI5ChoiceLaiFixedLength:
		if v.LaiFixedLength == nil {
			return nil, fmt.Errorf("%w: choice CellGlobalIdOrServiceAreaIdOrLAI5: laiFixedLength is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for CellGlobalIdOrServiceAreaIdOrLAI5", v.Choice)
	}
}

// MarshalDER encodes CellGlobalIdOrServiceAreaIdOrLAI5 to DER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CellGlobalIdOrServiceAreaIdOrLAI5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CellGlobalIdOrServiceAreaIdOrLAI5 from BER/DER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CellGlobalIdOrServiceAreaIdOrLAI5 destination is nil", ber.ErrInvalidValue)
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
	*v = CellGlobalIdOrServiceAreaIdOrLAI5{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CellGlobalIdOrServiceAreaIdOrLAI5 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CellGlobalIdOrServiceAreaIdOrLAI5: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding CellGlobalIdOrServiceAreaIdOrLAI5 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CellGlobalIdOrServiceAreaIdOrLAI5", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAI5ChoiceCellGlobalIdOrServiceAreaIdFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding cellGlobalIdOrServiceAreaIdFixedLength: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding cellGlobalIdOrServiceAreaIdFixedLength: %w", octetErr)
		}
		tmp := CellGlobalIdOrServiceAreaIdFixedLength5(decVal)
		v.CellGlobalIdOrServiceAreaIdFixedLength = &tmp
		if len(*v.CellGlobalIdOrServiceAreaIdFixedLength) < 7 || len(*v.CellGlobalIdOrServiceAreaIdFixedLength) > 7 {
			if constraintErr := ber.CheckDecodedLength(opts, "cellGlobalIdOrServiceAreaIdFixedLength", "SIZE (7)", len(*v.CellGlobalIdOrServiceAreaIdFixedLength)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAI5ChoiceLaiFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding laiFixedLength: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding laiFixedLength: %w", octetErr)
		}
		tmp := LAIFixedLength5(decVal)
		v.LaiFixedLength = &tmp
		if len(*v.LaiFixedLength) < 5 || len(*v.LaiFixedLength) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "laiFixedLength", "SIZE (5)", len(*v.LaiFixedLength)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for CellGlobalIdOrServiceAreaIdOrLAI5 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes BasicServiceCode5 to BER format.
func (v *BasicServiceCode5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BasicServiceCode5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BasicServiceCode5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case BasicServiceCode5ChoiceBearerService:
		if v.BearerService == nil {
			return nil, fmt.Errorf("%w: choice BasicServiceCode5: bearerService is nil", ber.ErrInvalidValue)
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
	case BasicServiceCode5ChoiceTeleservice:
		if v.Teleservice == nil {
			return nil, fmt.Errorf("%w: choice BasicServiceCode5: teleservice is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for BasicServiceCode5", v.Choice)
	}
}

// MarshalDER encodes BasicServiceCode5 to DER format.
func (v *BasicServiceCode5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BasicServiceCode5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BasicServiceCode5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BasicServiceCode5 from BER/DER format.
func (v *BasicServiceCode5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BasicServiceCode5 destination is nil", ber.ErrInvalidValue)
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
	*v = BasicServiceCode5{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for BasicServiceCode5 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for BasicServiceCode5: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding BasicServiceCode5 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "BasicServiceCode5", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = BasicServiceCode5ChoiceBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding bearerService: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding bearerService: %w", octetErr)
		}
		tmp := BearerServiceCode5(decVal)
		v.BearerService = &tmp
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = BasicServiceCode5ChoiceTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding teleservice: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding teleservice: %w", octetErr)
		}
		tmp := TeleserviceCode5(decVal)
		v.Teleservice = &tmp
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for BasicServiceCode5 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtBasicServiceCode5 to BER format.
func (v *ExtBasicServiceCode5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtBasicServiceCode5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtBasicServiceCode5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ExtBasicServiceCode5ChoiceExtBearerService:
		if v.ExtBearerService == nil {
			return nil, fmt.Errorf("%w: choice ExtBasicServiceCode5: ext-BearerService is nil", ber.ErrInvalidValue)
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
	case ExtBasicServiceCode5ChoiceExtTeleservice:
		if v.ExtTeleservice == nil {
			return nil, fmt.Errorf("%w: choice ExtBasicServiceCode5: ext-Teleservice is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for ExtBasicServiceCode5", v.Choice)
	}
}

// MarshalDER encodes ExtBasicServiceCode5 to DER format.
func (v *ExtBasicServiceCode5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtBasicServiceCode5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtBasicServiceCode5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtBasicServiceCode5 from BER/DER format.
func (v *ExtBasicServiceCode5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtBasicServiceCode5 destination is nil", ber.ErrInvalidValue)
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
	*v = ExtBasicServiceCode5{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtBasicServiceCode5 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtBasicServiceCode5: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding ExtBasicServiceCode5 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtBasicServiceCode5", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ExtBasicServiceCode5ChoiceExtBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-BearerService: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding ext-BearerService: %w", octetErr)
		}
		tmp := ExtBearerServiceCode5(decVal)
		v.ExtBearerService = &tmp
		if len(*v.ExtBearerService) < 1 || len(*v.ExtBearerService) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "ext-BearerService", "SIZE (1..5)", len(*v.ExtBearerService)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = ExtBasicServiceCode5ChoiceExtTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-Teleservice: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding ext-Teleservice: %w", octetErr)
		}
		tmp := ExtTeleserviceCode5(decVal)
		v.ExtTeleservice = &tmp
		if len(*v.ExtTeleservice) < 1 || len(*v.ExtTeleservice) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, "ext-Teleservice", "SIZE (1..5)", len(*v.ExtTeleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for ExtBasicServiceCode5 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EMLPPInfo5 to BER format.
func (v *EMLPPInfo5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: EMLPPInfo5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EMLPPInfo5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes EMLPPInfo5 to DER format.
func (v *EMLPPInfo5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EMLPPInfo5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding EMLPPInfo5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EMLPPInfo5 from BER/DER format.
func (v *EMLPPInfo5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EMLPPInfo5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = EMLPPInfo5{}
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
		return fmt.Errorf("decoding EMLPPInfo5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EMLPPInfo5", Cause: ber.ErrExtraData}
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
	v.MaximumentitledPriority = EMLPPPriority5(val_maximumentitledpriority)
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
	v.DefaultPriority = EMLPPPriority5(val_defaultpriority)
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
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
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
			return &ber.DecodeError{Offset: offset, TypeName: "EMLPPInfo5", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "EMLPPInfo5", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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

// MarshalBER encodes MCSSInfo5 to BER format.
func (v *MCSSInfo5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: MCSSInfo5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MCSSInfo5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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

// MarshalDER encodes MCSSInfo5 to DER format.
func (v *MCSSInfo5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MCSSInfo5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding MCSSInfo5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MCSSInfo5 from BER/DER format.
func (v *MCSSInfo5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MCSSInfo5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MCSSInfo5{}
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
		return fmt.Errorf("decoding MCSSInfo5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MCSSInfo5", Cause: ber.ErrExtraData}
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
	v.SsCode = SSCode5(decVal_sscode)
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
	v.SsStatus = ExtSSStatus5(decVal_ssstatus)
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
	v.NbrSB = MaxMCBearers5(decVal_nbrsb)
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
	v.NbrUser = MCBearers5(decVal_nbruser)
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
				var dec_extensioncontainer ExtensionContainer5
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
			return &ber.DecodeError{Offset: offset, TypeName: "MCSSInfo5", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MCSSInfo5", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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
