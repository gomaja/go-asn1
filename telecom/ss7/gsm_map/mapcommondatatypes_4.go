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

	// MaxAddressLength4 is the integer constant for MaxAddressLength4.
	MaxAddressLength4 int64 = 20

	// MaxISDNAddressLength4 is the integer constant for MaxISDNAddressLength4.
	MaxISDNAddressLength4 int64 = 9

	// MaxFTNAddressLength4 is the integer constant for MaxFTNAddressLength4.
	MaxFTNAddressLength4 int64 = 15

	// MaxISDNSubaddressLength4 is the integer constant for MaxISDNSubaddressLength4.
	MaxISDNSubaddressLength4 int64 = 21

	// MaxSignalInfoLength4 is the integer constant for MaxSignalInfoLength4.
	MaxSignalInfoLength4 int64 = 200

	// MaxLongSignalInfoLength4 is the integer constant for MaxLongSignalInfoLength4.
	MaxLongSignalInfoLength4 int64 = 2560

	// AlertingLevel04 is the octet string constant for AlertingLevel04.
	AlertingLevel04 = "\x00"

	// AlertingLevel14 is the octet string constant for AlertingLevel14.
	AlertingLevel14 = "\x01"

	// AlertingLevel24 is the octet string constant for AlertingLevel24.
	AlertingLevel24 = "\x02"

	// AlertingCategory14 is the octet string constant for AlertingCategory14.
	AlertingCategory14 = "\x04"

	// AlertingCategory24 is the octet string constant for AlertingCategory24.
	AlertingCategory24 = "\x05"

	// AlertingCategory34 is the octet string constant for AlertingCategory34.
	AlertingCategory34 = "\x06"

	// AlertingCategory44 is the octet string constant for AlertingCategory44.
	AlertingCategory44 = "\x07"

	// AlertingCategory54 is the octet string constant for AlertingCategory54.
	AlertingCategory54 = "\x08"

	// MaxNumOfHLRId4 is the integer constant for MaxNumOfHLRId4.
	MaxNumOfHLRId4 int64 = 50

	// EmergencyServices4 is the integer constant for EmergencyServices4.
	EmergencyServices4 int64 = 0

	// EmergencyAlertServices4 is the integer constant for EmergencyAlertServices4.
	EmergencyAlertServices4 int64 = 1

	// PersonTracking4 is the integer constant for PersonTracking4.
	PersonTracking4 int64 = 2

	// FleetManagement4 is the integer constant for FleetManagement4.
	FleetManagement4 int64 = 3

	// AssetManagement4 is the integer constant for AssetManagement4.
	AssetManagement4 int64 = 4

	// TrafficCongestionReporting4 is the integer constant for TrafficCongestionReporting4.
	TrafficCongestionReporting4 int64 = 5

	// RoadsideAssistance4 is the integer constant for RoadsideAssistance4.
	RoadsideAssistance4 int64 = 6

	// RoutingToNearestCommercialEnterprise4 is the integer constant for RoutingToNearestCommercialEnterprise4.
	RoutingToNearestCommercialEnterprise4 int64 = 7

	// Navigation4 is the integer constant for Navigation4.
	Navigation4 int64 = 8

	// CitySightseeing4 is the integer constant for CitySightseeing4.
	CitySightseeing4 int64 = 9

	// LocalizedAdvertising4 is the integer constant for LocalizedAdvertising4.
	LocalizedAdvertising4 int64 = 10

	// MobileYellowPages4 is the integer constant for MobileYellowPages4.
	MobileYellowPages4 int64 = 11

	// TrafficAndPublicTransportationInfo4 is the integer constant for TrafficAndPublicTransportationInfo4.
	TrafficAndPublicTransportationInfo4 int64 = 12

	// Weather4 is the integer constant for Weather4.
	Weather4 int64 = 13

	// AssetAndServiceFinding4 is the integer constant for AssetAndServiceFinding4.
	AssetAndServiceFinding4 int64 = 14

	// Gaming4 is the integer constant for Gaming4.
	Gaming4 int64 = 15

	// FindYourFriend4 is the integer constant for FindYourFriend4.
	FindYourFriend4 int64 = 16

	// Dating4 is the integer constant for Dating4.
	Dating4 int64 = 17

	// Chatting4 is the integer constant for Chatting4.
	Chatting4 int64 = 18

	// RouteFinding4 is the integer constant for RouteFinding4.
	RouteFinding4 int64 = 19

	// WhereAmI4 is the integer constant for WhereAmI4.
	WhereAmI4 int64 = 20

	// Serv644 is the integer constant for Serv644.
	Serv644 int64 = 64

	// Serv654 is the integer constant for Serv654.
	Serv654 int64 = 65

	// Serv664 is the integer constant for Serv664.
	Serv664 int64 = 66

	// Serv674 is the integer constant for Serv674.
	Serv674 int64 = 67

	// Serv684 is the integer constant for Serv684.
	Serv684 int64 = 68

	// Serv694 is the integer constant for Serv694.
	Serv694 int64 = 69

	// Serv704 is the integer constant for Serv704.
	Serv704 int64 = 70

	// Serv714 is the integer constant for Serv714.
	Serv714 int64 = 71

	// Serv724 is the integer constant for Serv724.
	Serv724 int64 = 72

	// Serv734 is the integer constant for Serv734.
	Serv734 int64 = 73

	// Serv744 is the integer constant for Serv744.
	Serv744 int64 = 74

	// Serv754 is the integer constant for Serv754.
	Serv754 int64 = 75

	// Serv764 is the integer constant for Serv764.
	Serv764 int64 = 76

	// Serv774 is the integer constant for Serv774.
	Serv774 int64 = 77

	// Serv784 is the integer constant for Serv784.
	Serv784 int64 = 78

	// Serv794 is the integer constant for Serv794.
	Serv794 int64 = 79

	// Serv804 is the integer constant for Serv804.
	Serv804 int64 = 80

	// Serv814 is the integer constant for Serv814.
	Serv814 int64 = 81

	// Serv824 is the integer constant for Serv824.
	Serv824 int64 = 82

	// Serv834 is the integer constant for Serv834.
	Serv834 int64 = 83

	// Serv844 is the integer constant for Serv844.
	Serv844 int64 = 84

	// Serv854 is the integer constant for Serv854.
	Serv854 int64 = 85

	// Serv864 is the integer constant for Serv864.
	Serv864 int64 = 86

	// Serv874 is the integer constant for Serv874.
	Serv874 int64 = 87

	// Serv884 is the integer constant for Serv884.
	Serv884 int64 = 88

	// Serv894 is the integer constant for Serv894.
	Serv894 int64 = 89

	// Serv904 is the integer constant for Serv904.
	Serv904 int64 = 90

	// Serv914 is the integer constant for Serv914.
	Serv914 int64 = 91

	// Serv924 is the integer constant for Serv924.
	Serv924 int64 = 92

	// Serv934 is the integer constant for Serv934.
	Serv934 int64 = 93

	// Serv944 is the integer constant for Serv944.
	Serv944 int64 = 94

	// Serv954 is the integer constant for Serv954.
	Serv954 int64 = 95

	// Serv964 is the integer constant for Serv964.
	Serv964 int64 = 96

	// Serv974 is the integer constant for Serv974.
	Serv974 int64 = 97

	// Serv984 is the integer constant for Serv984.
	Serv984 int64 = 98

	// Serv994 is the integer constant for Serv994.
	Serv994 int64 = 99

	// Serv1004 is the integer constant for Serv1004.
	Serv1004 int64 = 100

	// Serv1014 is the integer constant for Serv1014.
	Serv1014 int64 = 101

	// Serv1024 is the integer constant for Serv1024.
	Serv1024 int64 = 102

	// Serv1034 is the integer constant for Serv1034.
	Serv1034 int64 = 103

	// Serv1044 is the integer constant for Serv1044.
	Serv1044 int64 = 104

	// Serv1054 is the integer constant for Serv1054.
	Serv1054 int64 = 105

	// Serv1064 is the integer constant for Serv1064.
	Serv1064 int64 = 106

	// Serv1074 is the integer constant for Serv1074.
	Serv1074 int64 = 107

	// Serv1084 is the integer constant for Serv1084.
	Serv1084 int64 = 108

	// Serv1094 is the integer constant for Serv1094.
	Serv1094 int64 = 109

	// Serv1104 is the integer constant for Serv1104.
	Serv1104 int64 = 110

	// Serv1114 is the integer constant for Serv1114.
	Serv1114 int64 = 111

	// Serv1124 is the integer constant for Serv1124.
	Serv1124 int64 = 112

	// Serv1134 is the integer constant for Serv1134.
	Serv1134 int64 = 113

	// Serv1144 is the integer constant for Serv1144.
	Serv1144 int64 = 114

	// Serv1154 is the integer constant for Serv1154.
	Serv1154 int64 = 115

	// Serv1164 is the integer constant for Serv1164.
	Serv1164 int64 = 116

	// Serv1174 is the integer constant for Serv1174.
	Serv1174 int64 = 117

	// Serv1184 is the integer constant for Serv1184.
	Serv1184 int64 = 118

	// Serv1194 is the integer constant for Serv1194.
	Serv1194 int64 = 119

	// Serv1204 is the integer constant for Serv1204.
	Serv1204 int64 = 120

	// Serv1214 is the integer constant for Serv1214.
	Serv1214 int64 = 121

	// Serv1224 is the integer constant for Serv1224.
	Serv1224 int64 = 122

	// Serv1234 is the integer constant for Serv1234.
	Serv1234 int64 = 123

	// Serv1244 is the integer constant for Serv1244.
	Serv1244 int64 = 124

	// Serv1254 is the integer constant for Serv1254.
	Serv1254 int64 = 125

	// Serv1264 is the integer constant for Serv1264.
	Serv1264 int64 = 126

	// Serv1274 is the integer constant for Serv1274.
	Serv1274 int64 = 127

	// PriorityLevelA4 is the integer constant for PriorityLevelA4.
	PriorityLevelA4 int64 = 6

	// PriorityLevelB4 is the integer constant for PriorityLevelB4.
	PriorityLevelB4 int64 = 5

	// PriorityLevel04 is the integer constant for PriorityLevel04.
	PriorityLevel04 int64 = 0

	// PriorityLevel14 is the integer constant for PriorityLevel14.
	PriorityLevel14 int64 = 1

	// PriorityLevel24 is the integer constant for PriorityLevel24.
	PriorityLevel24 int64 = 2

	// PriorityLevel34 is the integer constant for PriorityLevel34.
	PriorityLevel34 int64 = 3

	// PriorityLevel44 is the integer constant for PriorityLevel44.
	PriorityLevel44 int64 = 4

	// MaxNumOfMCBearers4 is the integer constant for MaxNumOfMCBearers4.
	MaxNumOfMCBearers4 int64 = 7
)

// TBCDSTRING4 represents the ASN.1 type TBCD-STRING (OCTET_STRING).
type TBCDSTRING4 = []byte

// DiameterIdentity3 represents the ASN.1 type DiameterIdentity (OCTET_STRING).
type DiameterIdentity3 = []byte

// AddressString4 represents the ASN.1 type AddressString (OCTET_STRING).
type AddressString4 = []byte

// ISDNAddressString4 represents the ASN.1 type ISDN-AddressString (OCTET_STRING).
type ISDNAddressString4 = AddressString4

// FTNAddressString4 represents the ASN.1 type FTN-AddressString (OCTET_STRING).
type FTNAddressString4 = AddressString4

// ISDNSubaddressString4 represents the ASN.1 type ISDN-SubaddressString (OCTET_STRING).
type ISDNSubaddressString4 = []byte

// ExternalSignalInfo4 represents the ASN.1 type ExternalSignalInfo (SEQUENCE).
type ExternalSignalInfo4 struct {
	ProtocolId         ProtocolId4          `asn1:""`
	SignalInfo         SignalInfo4          `asn1:""`
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SignalInfo4 represents the ASN.1 type SignalInfo (OCTET_STRING).
type SignalInfo4 = []byte

// ProtocolId4 represents the ASN.1 ENUMERATED type ProtocolId.
type ProtocolId4 int64

const (
	ProtocolId4Gsm0408    ProtocolId4 = 1
	ProtocolId4Gsm0806    ProtocolId4 = 2
	ProtocolId4GsmBSSMAP  ProtocolId4 = 3
	ProtocolId4Ets3001021 ProtocolId4 = 4
)

func (v ProtocolId4) String() string {
	switch v {
	case ProtocolId4Gsm0408:
		return "gsm-0408"
	case ProtocolId4Gsm0806:
		return "gsm-0806"
	case ProtocolId4GsmBSSMAP:
		return "gsm-BSSMAP"
	case ProtocolId4Ets3001021:
		return "ets-300102-1"
	default:
		return "unknown"
	}
}

// ExtExternalSignalInfo4 represents the ASN.1 type Ext-ExternalSignalInfo (SEQUENCE).
type ExtExternalSignalInfo4 struct {
	ExtProtocolId      ExtProtocolId4       `asn1:""`
	SignalInfo         SignalInfo4          `asn1:""`
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ExtProtocolId4 represents the ASN.1 ENUMERATED type Ext-ProtocolId.
type ExtProtocolId4 int64

const (
	ExtProtocolId4Ets300356 ExtProtocolId4 = 1
)

func (v ExtProtocolId4) String() string {
	switch v {
	case ExtProtocolId4Ets300356:
		return "ets-300356"
	default:
		return "unknown"
	}
}

// AccessNetworkSignalInfo4 represents the ASN.1 type AccessNetworkSignalInfo (SEQUENCE).
type AccessNetworkSignalInfo4 struct {
	AccessNetworkProtocolId AccessNetworkProtocolId4 `asn1:""`
	SignalInfo              LongSignalInfo4          `asn1:""`
	ExtensionContainer      *ExtensionContainer4     `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
}

// LongSignalInfo4 represents the ASN.1 type LongSignalInfo (OCTET_STRING).
type LongSignalInfo4 = []byte

// AccessNetworkProtocolId4 represents the ASN.1 ENUMERATED type AccessNetworkProtocolId.
type AccessNetworkProtocolId4 int64

const (
	AccessNetworkProtocolId4Ts3G48006 AccessNetworkProtocolId4 = 1
	AccessNetworkProtocolId4Ts3G25413 AccessNetworkProtocolId4 = 2
)

func (v AccessNetworkProtocolId4) String() string {
	switch v {
	case AccessNetworkProtocolId4Ts3G48006:
		return "ts3G-48006"
	case AccessNetworkProtocolId4Ts3G25413:
		return "ts3G-25413"
	default:
		return "unknown"
	}
}

// AlertingPattern4 represents the ASN.1 type AlertingPattern (OCTET_STRING).
type AlertingPattern4 = []byte

// GSNAddress4 represents the ASN.1 type GSN-Address (OCTET_STRING).
type GSNAddress4 = []byte

// Time3 represents the ASN.1 type Time (OCTET_STRING).
type Time3 = []byte

// IMSI4 represents the ASN.1 type IMSI (OCTET_STRING).
type IMSI4 = TBCDSTRING4

// Identity4 choice constants.
const (
	Identity4ChoiceImsi         = 1
	Identity4ChoiceImsiWithLMSI = 2
)

// Identity4 represents the ASN.1 CHOICE type Identity.
type Identity4 struct {
	Choice       int
	Imsi         *IMSI4         `json:"Imsi,omitempty"`
	ImsiWithLMSI *IMSIWithLMSI4 `json:"ImsiWithLMSI,omitempty"`
}

// NewIdentity4Imsi creates a Identity4 with the imsi alternative.
func NewIdentity4Imsi(v IMSI4) Identity4 {
	return Identity4{
		Choice: Identity4ChoiceImsi,
		Imsi:   &v,
	}
}

// NewIdentity4ImsiWithLMSI creates a Identity4 with the imsi-WithLMSI alternative.
func NewIdentity4ImsiWithLMSI(v IMSIWithLMSI4) Identity4 {
	return Identity4{
		Choice:       Identity4ChoiceImsiWithLMSI,
		ImsiWithLMSI: &v,
	}
}

// IMSIWithLMSI4 represents the ASN.1 type IMSI-WithLMSI (SEQUENCE).
type IMSIWithLMSI4 struct {
	Imsi        IMSI4    `asn1:""`
	Lmsi        LMSI4    `asn1:""`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// ASCICallReference4 represents the ASN.1 type ASCI-CallReference (OCTET_STRING).
type ASCICallReference4 = TBCDSTRING4

// TMSI4 represents the ASN.1 type TMSI (OCTET_STRING).
type TMSI4 = []byte

// SubscriberId4 choice constants.
const (
	SubscriberId4ChoiceImsi = 1
	SubscriberId4ChoiceTmsi = 2
)

// SubscriberId4 represents the ASN.1 CHOICE type SubscriberId.
type SubscriberId4 struct {
	Choice int
	Imsi   *IMSI4 `json:"Imsi,omitempty"`
	Tmsi   *TMSI4 `json:"Tmsi,omitempty"`
}

// NewSubscriberId4Imsi creates a SubscriberId4 with the imsi alternative.
func NewSubscriberId4Imsi(v IMSI4) SubscriberId4 {
	return SubscriberId4{
		Choice: SubscriberId4ChoiceImsi,
		Imsi:   &v,
	}
}

// NewSubscriberId4Tmsi creates a SubscriberId4 with the tmsi alternative.
func NewSubscriberId4Tmsi(v TMSI4) SubscriberId4 {
	return SubscriberId4{
		Choice: SubscriberId4ChoiceTmsi,
		Tmsi:   &v,
	}
}

// IMEI4 represents the ASN.1 type IMEI (OCTET_STRING).
type IMEI4 = TBCDSTRING4

// HLRId4 represents the ASN.1 type HLR-Id (OCTET_STRING).
type HLRId4 = IMSI4

// HLRList4 represents the ASN.1 type HLR-List (SEQUENCE_OF).
type HLRList4 = []HLRId4

// LMSI4 represents the ASN.1 type LMSI (OCTET_STRING).
type LMSI4 = []byte

// GlobalCellId4 represents the ASN.1 type GlobalCellId (OCTET_STRING).
type GlobalCellId4 = []byte

// NetworkResource4 represents the ASN.1 ENUMERATED type NetworkResource.
type NetworkResource4 int64

const (
	NetworkResource4Plmn           NetworkResource4 = 0
	NetworkResource4Hlr            NetworkResource4 = 1
	NetworkResource4Vlr            NetworkResource4 = 2
	NetworkResource4Pvlr           NetworkResource4 = 3
	NetworkResource4ControllingMSC NetworkResource4 = 4
	NetworkResource4Vmsc           NetworkResource4 = 5
	NetworkResource4Eir            NetworkResource4 = 6
	NetworkResource4Rss            NetworkResource4 = 7
)

func (v NetworkResource4) String() string {
	switch v {
	case NetworkResource4Plmn:
		return "plmn"
	case NetworkResource4Hlr:
		return "hlr"
	case NetworkResource4Vlr:
		return "vlr"
	case NetworkResource4Pvlr:
		return "pvlr"
	case NetworkResource4ControllingMSC:
		return "controllingMSC"
	case NetworkResource4Vmsc:
		return "vmsc"
	case NetworkResource4Eir:
		return "eir"
	case NetworkResource4Rss:
		return "rss"
	default:
		return "unknown"
	}
}

// AdditionalNetworkResource4 represents the ASN.1 ENUMERATED type AdditionalNetworkResource.
type AdditionalNetworkResource4 int64

const (
	AdditionalNetworkResource4Sgsn   AdditionalNetworkResource4 = 0
	AdditionalNetworkResource4Ggsn   AdditionalNetworkResource4 = 1
	AdditionalNetworkResource4Gmlc   AdditionalNetworkResource4 = 2
	AdditionalNetworkResource4GsmSCF AdditionalNetworkResource4 = 3
	AdditionalNetworkResource4Nplr   AdditionalNetworkResource4 = 4
	AdditionalNetworkResource4Auc    AdditionalNetworkResource4 = 5
	AdditionalNetworkResource4Ue     AdditionalNetworkResource4 = 6
	AdditionalNetworkResource4Mme    AdditionalNetworkResource4 = 7
)

func (v AdditionalNetworkResource4) String() string {
	switch v {
	case AdditionalNetworkResource4Sgsn:
		return "sgsn"
	case AdditionalNetworkResource4Ggsn:
		return "ggsn"
	case AdditionalNetworkResource4Gmlc:
		return "gmlc"
	case AdditionalNetworkResource4GsmSCF:
		return "gsmSCF"
	case AdditionalNetworkResource4Nplr:
		return "nplr"
	case AdditionalNetworkResource4Auc:
		return "auc"
	case AdditionalNetworkResource4Ue:
		return "ue"
	case AdditionalNetworkResource4Mme:
		return "mme"
	default:
		return "unknown"
	}
}

// NAEAPreferredCI4 represents the ASN.1 type NAEA-PreferredCI (SEQUENCE).
type NAEAPreferredCI4 struct {
	NaeaPreferredCIC   NAEACIC4             `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionContainer4 `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// NAEACIC4 represents the ASN.1 type NAEA-CIC (OCTET_STRING).
type NAEACIC4 = []byte

// SubscriberIdentity4 choice constants.
const (
	SubscriberIdentity4ChoiceImsi   = 1
	SubscriberIdentity4ChoiceMsisdn = 2
)

// SubscriberIdentity4 represents the ASN.1 CHOICE type SubscriberIdentity.
type SubscriberIdentity4 struct {
	Choice int
	Imsi   *IMSI4              `json:"Imsi,omitempty"`
	Msisdn *ISDNAddressString4 `json:"Msisdn,omitempty"`
}

// NewSubscriberIdentity4Imsi creates a SubscriberIdentity4 with the imsi alternative.
func NewSubscriberIdentity4Imsi(v IMSI4) SubscriberIdentity4 {
	return SubscriberIdentity4{
		Choice: SubscriberIdentity4ChoiceImsi,
		Imsi:   &v,
	}
}

// NewSubscriberIdentity4Msisdn creates a SubscriberIdentity4 with the msisdn alternative.
func NewSubscriberIdentity4Msisdn(v ISDNAddressString4) SubscriberIdentity4 {
	return SubscriberIdentity4{
		Choice: SubscriberIdentity4ChoiceMsisdn,
		Msisdn: &v,
	}
}

// LCSClientExternalID4 represents the ASN.1 type LCSClientExternalID (SEQUENCE).
type LCSClientExternalID4 struct {
	ExternalAddress    *ISDNAddressString4  `asn1:"tag:0,context,implicit,optional" json:"ExternalAddress,omitempty"`
	ExtensionContainer *ExtensionContainer4 `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// LCSClientInternalID4 represents the ASN.1 ENUMERATED type LCSClientInternalID.
type LCSClientInternalID4 int64

const (
	LCSClientInternalID4BroadcastService          LCSClientInternalID4 = 0
	LCSClientInternalID4OAndMHPLMN                LCSClientInternalID4 = 1
	LCSClientInternalID4OAndMVPLMN                LCSClientInternalID4 = 2
	LCSClientInternalID4AnonymousLocation         LCSClientInternalID4 = 3
	LCSClientInternalID4TargetMSsubscribedService LCSClientInternalID4 = 4
)

func (v LCSClientInternalID4) String() string {
	switch v {
	case LCSClientInternalID4BroadcastService:
		return "broadcastService"
	case LCSClientInternalID4OAndMHPLMN:
		return "o-andM-HPLMN"
	case LCSClientInternalID4OAndMVPLMN:
		return "o-andM-VPLMN"
	case LCSClientInternalID4AnonymousLocation:
		return "anonymousLocation"
	case LCSClientInternalID4TargetMSsubscribedService:
		return "targetMSsubscribedService"
	default:
		return "unknown"
	}
}

// LCSServiceTypeID4 represents the ASN.1 type LCSServiceTypeID (INTEGER).
type LCSServiceTypeID4 = int64

// PLMNId4 represents the ASN.1 type PLMN-Id (OCTET_STRING).
type PLMNId4 = []byte

// EUTRANCGI3 represents the ASN.1 type E-UTRAN-CGI (OCTET_STRING).
type EUTRANCGI3 = []byte

// TAId3 represents the ASN.1 type TA-Id (OCTET_STRING).
type TAId3 = []byte

// RAIdentity4 represents the ASN.1 type RAIdentity (OCTET_STRING).
type RAIdentity4 = []byte

// CellGlobalIdOrServiceAreaIdOrLAI4 choice constants.
const (
	CellGlobalIdOrServiceAreaIdOrLAI4ChoiceCellGlobalIdOrServiceAreaIdFixedLength = 1
	CellGlobalIdOrServiceAreaIdOrLAI4ChoiceLaiFixedLength                         = 2
)

// CellGlobalIdOrServiceAreaIdOrLAI4 represents the ASN.1 CHOICE type CellGlobalIdOrServiceAreaIdOrLAI.
type CellGlobalIdOrServiceAreaIdOrLAI4 struct {
	Choice                                 int
	CellGlobalIdOrServiceAreaIdFixedLength *CellGlobalIdOrServiceAreaIdFixedLength4 `json:"CellGlobalIdOrServiceAreaIdFixedLength,omitempty"`
	LaiFixedLength                         *LAIFixedLength4                         `json:"LaiFixedLength,omitempty"`
}

// NewCellGlobalIdOrServiceAreaIdOrLAI4CellGlobalIdOrServiceAreaIdFixedLength creates a CellGlobalIdOrServiceAreaIdOrLAI4 with the cellGlobalIdOrServiceAreaIdFixedLength alternative.
func NewCellGlobalIdOrServiceAreaIdOrLAI4CellGlobalIdOrServiceAreaIdFixedLength(v CellGlobalIdOrServiceAreaIdFixedLength4) CellGlobalIdOrServiceAreaIdOrLAI4 {
	return CellGlobalIdOrServiceAreaIdOrLAI4{
		Choice:                                 CellGlobalIdOrServiceAreaIdOrLAI4ChoiceCellGlobalIdOrServiceAreaIdFixedLength,
		CellGlobalIdOrServiceAreaIdFixedLength: &v,
	}
}

// NewCellGlobalIdOrServiceAreaIdOrLAI4LaiFixedLength creates a CellGlobalIdOrServiceAreaIdOrLAI4 with the laiFixedLength alternative.
func NewCellGlobalIdOrServiceAreaIdOrLAI4LaiFixedLength(v LAIFixedLength4) CellGlobalIdOrServiceAreaIdOrLAI4 {
	return CellGlobalIdOrServiceAreaIdOrLAI4{
		Choice:         CellGlobalIdOrServiceAreaIdOrLAI4ChoiceLaiFixedLength,
		LaiFixedLength: &v,
	}
}

// CellGlobalIdOrServiceAreaIdFixedLength4 represents the ASN.1 type CellGlobalIdOrServiceAreaIdFixedLength (OCTET_STRING).
type CellGlobalIdOrServiceAreaIdFixedLength4 = []byte

// LAIFixedLength4 represents the ASN.1 type LAIFixedLength (OCTET_STRING).
type LAIFixedLength4 = []byte

// BasicServiceCode4 choice constants.
const (
	BasicServiceCode4ChoiceBearerService = 1
	BasicServiceCode4ChoiceTeleservice   = 2
)

// BasicServiceCode4 represents the ASN.1 CHOICE type BasicServiceCode.
type BasicServiceCode4 struct {
	Choice        int
	BearerService *BearerServiceCode4 `json:"BearerService,omitempty"`
	Teleservice   *TeleserviceCode4   `json:"Teleservice,omitempty"`
}

// NewBasicServiceCode4BearerService creates a BasicServiceCode4 with the bearerService alternative.
func NewBasicServiceCode4BearerService(v BearerServiceCode4) BasicServiceCode4 {
	return BasicServiceCode4{
		Choice:        BasicServiceCode4ChoiceBearerService,
		BearerService: &v,
	}
}

// NewBasicServiceCode4Teleservice creates a BasicServiceCode4 with the teleservice alternative.
func NewBasicServiceCode4Teleservice(v TeleserviceCode4) BasicServiceCode4 {
	return BasicServiceCode4{
		Choice:      BasicServiceCode4ChoiceTeleservice,
		Teleservice: &v,
	}
}

// ExtBasicServiceCode4 choice constants.
const (
	ExtBasicServiceCode4ChoiceExtBearerService = 1
	ExtBasicServiceCode4ChoiceExtTeleservice   = 2
)

// ExtBasicServiceCode4 represents the ASN.1 CHOICE type Ext-BasicServiceCode.
type ExtBasicServiceCode4 struct {
	Choice           int
	ExtBearerService *ExtBearerServiceCode4 `json:"ExtBearerService,omitempty"`
	ExtTeleservice   *ExtTeleserviceCode4   `json:"ExtTeleservice,omitempty"`
}

// NewExtBasicServiceCode4ExtBearerService creates a ExtBasicServiceCode4 with the ext-BearerService alternative.
func NewExtBasicServiceCode4ExtBearerService(v ExtBearerServiceCode4) ExtBasicServiceCode4 {
	return ExtBasicServiceCode4{
		Choice:           ExtBasicServiceCode4ChoiceExtBearerService,
		ExtBearerService: &v,
	}
}

// NewExtBasicServiceCode4ExtTeleservice creates a ExtBasicServiceCode4 with the ext-Teleservice alternative.
func NewExtBasicServiceCode4ExtTeleservice(v ExtTeleserviceCode4) ExtBasicServiceCode4 {
	return ExtBasicServiceCode4{
		Choice:         ExtBasicServiceCode4ChoiceExtTeleservice,
		ExtTeleservice: &v,
	}
}

// EMLPPInfo4 represents the ASN.1 type EMLPP-Info (SEQUENCE).
type EMLPPInfo4 struct {
	MaximumentitledPriority EMLPPPriority4       `asn1:""`
	DefaultPriority         EMLPPPriority4       `asn1:""`
	ExtensionContainer      *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                `asn1:"-" json:"-"`
	ExtPresent_             []bool               `asn1:"-" json:"-"`
	ExtData_                [][]byte             `asn1:"-" json:"-"`
}

// EMLPPPriority4 represents the ASN.1 type EMLPP-Priority (INTEGER).
type EMLPPPriority4 = int64

// MCSSInfo4 represents the ASN.1 type MC-SS-Info (SEQUENCE).
type MCSSInfo4 struct {
	SsCode             SSCode4              `asn1:"tag:0,context,implicit"`
	SsStatus           ExtSSStatus4         `asn1:"tag:1,context,implicit"`
	NbrSB              MaxMCBearers4        `asn1:"tag:2,context,implicit"`
	NbrUser            MCBearers4           `asn1:"tag:3,context,implicit"`
	ExtensionContainer *ExtensionContainer4 `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// MaxMCBearers4 represents the ASN.1 type MaxMC-Bearers (INTEGER).
type MaxMCBearers4 = int64

// MCBearers4 represents the ASN.1 type MC-Bearers (INTEGER).
type MCBearers4 = int64

// ExtSSStatus4 represents the ASN.1 type Ext-SS-Status (OCTET_STRING).
type ExtSSStatus4 = []byte

// AgeOfLocationInformation4 represents the ASN.1 type AgeOfLocationInformation (INTEGER).
type AgeOfLocationInformation4 = int64

// MarshalBER encodes ExternalSignalInfo4 to BER format.
func (v *ExternalSignalInfo4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ExternalSignalInfo4 to DER format.
func (v *ExternalSignalInfo4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExternalSignalInfo4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExternalSignalInfo4 from BER/DER format.
func (v *ExternalSignalInfo4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExternalSignalInfo4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExternalSignalInfo4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field protocolId")
	}
	val_protocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding protocolId: %w", err)
	}
	v.ProtocolId = ProtocolId4(val_protocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo4(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ExtExternalSignalInfo4 to BER format.
func (v *ExtExternalSignalInfo4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_extprotocolid := ber.EncodeEnumerated(int64(v.ExtProtocolId))
	children = append(children, enc_extprotocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ExtExternalSignalInfo4 to DER format.
func (v *ExtExternalSignalInfo4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtExternalSignalInfo4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtExternalSignalInfo4 from BER/DER format.
func (v *ExtExternalSignalInfo4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExtExternalSignalInfo4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtExternalSignalInfo4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ext-ProtocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field ext-ProtocolId")
	}
	val_extprotocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ext-ProtocolId: %w", err)
	}
	v.ExtProtocolId = ExtProtocolId4(val_extprotocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo4(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtExternalSignalInfo4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AccessNetworkSignalInfo4 to BER format.
func (v *AccessNetworkSignalInfo4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_accessnetworkprotocolid := ber.EncodeEnumerated(int64(v.AccessNetworkProtocolId))
	children = append(children, enc_accessnetworkprotocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AccessNetworkSignalInfo4 to DER format.
func (v *AccessNetworkSignalInfo4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AccessNetworkSignalInfo4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AccessNetworkSignalInfo4 from BER/DER format.
func (v *AccessNetworkSignalInfo4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AccessNetworkSignalInfo4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AccessNetworkSignalInfo4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode accessNetworkProtocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field accessNetworkProtocolId")
	}
	val_accessnetworkprotocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding accessNetworkProtocolId: %w", err)
	}
	v.AccessNetworkProtocolId = AccessNetworkProtocolId4(val_accessnetworkprotocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = LongSignalInfo4(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AccessNetworkSignalInfo4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes Identity4 to BER format.
func (v *Identity4) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case Identity4ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("choice Identity4: imsi is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		return enc_0, nil
	case Identity4ChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("choice Identity4: imsi-WithLMSI is nil")
		}
		enc_1, err := v.ImsiWithLMSI.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Identity4", v.Choice)
	}
}

// MarshalDER encodes Identity4 to DER format.
func (v *Identity4) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case Identity4ChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("choice Identity4: imsi-WithLMSI is nil")
		}
		enc_der_1, err := v.ImsiWithLMSI.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI: %w", err)
		}
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding imsi-WithLMSI as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Identity4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Identity4 from BER/DER format.
func (v *Identity4) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Identity4 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Identity4: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Identity4 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Identity4", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = Identity4ChoiceImsi
		decVal, _, osErr := ber.DecodeOctetString(choiceData)
		if osErr != nil {
			return fmt.Errorf("decoding imsi: %w", osErr)
		}
		tmp := IMSI4(decVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = Identity4ChoiceImsiWithLMSI
		var dec IMSIWithLMSI4
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding imsi-WithLMSI: %w", unmErr)
		}
		v.ImsiWithLMSI = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Identity4 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes IMSIWithLMSI4 to BER format.
func (v *IMSIWithLMSI4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	children = append(children, enc_imsi...)
	enc_lmsi := ber.EncodeOctetString([]byte(v.Lmsi))
	children = append(children, enc_lmsi...)
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes IMSIWithLMSI4 to DER format.
func (v *IMSIWithLMSI4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IMSIWithLMSI4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IMSIWithLMSI4 from BER/DER format.
func (v *IMSIWithLMSI4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IMSIWithLMSI4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IMSIWithLMSI4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	val_imsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = IMSI4(val_imsi)
	offset += n
	// Decode lmsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field lmsi")
	}
	val_lmsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lmsi: %w", err)
	}
	v.Lmsi = LMSI4(val_lmsi)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IMSIWithLMSI4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubscriberId4 to BER format.
func (v *SubscriberId4) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SubscriberId4ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("choice SubscriberId4: imsi is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case SubscriberId4ChoiceTmsi:
		if v.Tmsi == nil {
			return nil, fmt.Errorf("choice SubscriberId4: tmsi is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.Tmsi))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SubscriberId4", v.Choice)
	}
}

// MarshalDER encodes SubscriberId4 to DER format.
func (v *SubscriberId4) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberId4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberId4 from BER/DER format.
func (v *SubscriberId4) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberId4 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberId4: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberId4 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberId4", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberId4ChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := IMSI4(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberId4ChoiceTmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding tmsi: %w", tlvErr)
		}
		tmp := TMSI4(rawVal)
		v.Tmsi = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberId4 CHOICE", peekTag)
	}
	return nil
}

// MarshalBERHLRList4 encodes a HLRList4 list to BER.
func MarshalBERHLRList4(list HLRList4) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERHLRList4 decodes a HLRList4 list from BER.
func UnmarshalBERHLRList4(data []byte) (HLRList4, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding HLRList4: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "HLRList4", Cause: ber.ErrExtraData}
	}
	var result HLRList4
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, HLRId4(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes NAEAPreferredCI4 to BER format.
func (v *NAEAPreferredCI4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_naeapreferredcic := ber.EncodeOctetString([]byte(v.NaeaPreferredCIC))
	enc_naeapreferredcic = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_naeapreferredcic)
	children = append(children, enc_naeapreferredcic...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes NAEAPreferredCI4 to DER format.
func (v *NAEAPreferredCI4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding NAEAPreferredCI4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NAEAPreferredCI4 from BER/DER format.
func (v *NAEAPreferredCI4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NAEAPreferredCI4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NAEAPreferredCI4", Cause: ber.ErrExtraData}
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
	decodedTag_naeapreferredcic, n_naeapreferredcic, rawVal_naeapreferredcic, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding naea-PreferredCIC: %w", err)
	}
	if decodedTag_naeapreferredcic.Class != tag.ClassContextSpecific || decodedTag_naeapreferredcic.Number != 0 {
		return fmt.Errorf("decoding naea-PreferredCIC: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naeapreferredcic)
	}
	v.NaeaPreferredCIC = NAEACIC4(rawVal_naeapreferredcic)
	offset += n_naeapreferredcic
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NAEAPreferredCI4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubscriberIdentity4 to BER format.
func (v *SubscriberIdentity4) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SubscriberIdentity4ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("choice SubscriberIdentity4: imsi is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case SubscriberIdentity4ChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("choice SubscriberIdentity4: msisdn is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.Msisdn))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SubscriberIdentity4", v.Choice)
	}
}

// MarshalDER encodes SubscriberIdentity4 to DER format.
func (v *SubscriberIdentity4) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberIdentity4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberIdentity4 from BER/DER format.
func (v *SubscriberIdentity4) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberIdentity4 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberIdentity4: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberIdentity4 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberIdentity4", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberIdentity4ChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := IMSI4(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberIdentity4ChoiceMsisdn
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msisdn: %w", tlvErr)
		}
		tmp := ISDNAddressString4(rawVal)
		v.Msisdn = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberIdentity4 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes LCSClientExternalID4 to BER format.
func (v *LCSClientExternalID4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExternalAddress != nil {
		enc_externaladdress := ber.EncodeOctetString([]byte(*v.ExternalAddress))
		enc_externaladdress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_externaladdress)
		children = append(children, enc_externaladdress...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes LCSClientExternalID4 to DER format.
func (v *LCSClientExternalID4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding LCSClientExternalID4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSClientExternalID4 from BER/DER format.
func (v *LCSClientExternalID4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSClientExternalID4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSClientExternalID4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode externalAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_externaladdress, n_externaladdress, rawVal_externaladdress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding externalAddress: %w", err)
				}
				if decodedTag_externaladdress.Class != tag.ClassContextSpecific || decodedTag_externaladdress.Number != 0 {
					return fmt.Errorf("decoding externalAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_externaladdress)
				}
				tmp_externaladdress := ISDNAddressString4(rawVal_externaladdress)
				v.ExternalAddress = &tmp_externaladdress
				offset += n_externaladdress
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSClientExternalID4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CellGlobalIdOrServiceAreaIdOrLAI4 to BER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI4) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CellGlobalIdOrServiceAreaIdOrLAI4ChoiceCellGlobalIdOrServiceAreaIdFixedLength:
		if v.CellGlobalIdOrServiceAreaIdFixedLength == nil {
			return nil, fmt.Errorf("choice CellGlobalIdOrServiceAreaIdOrLAI4: cellGlobalIdOrServiceAreaIdFixedLength is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.CellGlobalIdOrServiceAreaIdFixedLength))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case CellGlobalIdOrServiceAreaIdOrLAI4ChoiceLaiFixedLength:
		if v.LaiFixedLength == nil {
			return nil, fmt.Errorf("choice CellGlobalIdOrServiceAreaIdOrLAI4: laiFixedLength is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.LaiFixedLength))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CellGlobalIdOrServiceAreaIdOrLAI4", v.Choice)
	}
}

// MarshalDER encodes CellGlobalIdOrServiceAreaIdOrLAI4 to DER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI4) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CellGlobalIdOrServiceAreaIdOrLAI4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CellGlobalIdOrServiceAreaIdOrLAI4 from BER/DER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI4) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CellGlobalIdOrServiceAreaIdOrLAI4 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CellGlobalIdOrServiceAreaIdOrLAI4: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CellGlobalIdOrServiceAreaIdOrLAI4 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CellGlobalIdOrServiceAreaIdOrLAI4", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAI4ChoiceCellGlobalIdOrServiceAreaIdFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cellGlobalIdOrServiceAreaIdFixedLength: %w", tlvErr)
		}
		tmp := CellGlobalIdOrServiceAreaIdFixedLength4(rawVal)
		v.CellGlobalIdOrServiceAreaIdFixedLength = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAI4ChoiceLaiFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding laiFixedLength: %w", tlvErr)
		}
		tmp := LAIFixedLength4(rawVal)
		v.LaiFixedLength = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for CellGlobalIdOrServiceAreaIdOrLAI4 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes BasicServiceCode4 to BER format.
func (v *BasicServiceCode4) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case BasicServiceCode4ChoiceBearerService:
		if v.BearerService == nil {
			return nil, fmt.Errorf("choice BasicServiceCode4: bearerService is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.BearerService))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_0)
		return enc_0, nil
	case BasicServiceCode4ChoiceTeleservice:
		if v.Teleservice == nil {
			return nil, fmt.Errorf("choice BasicServiceCode4: teleservice is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.Teleservice))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for BasicServiceCode4", v.Choice)
	}
}

// MarshalDER encodes BasicServiceCode4 to DER format.
func (v *BasicServiceCode4) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BasicServiceCode4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BasicServiceCode4 from BER/DER format.
func (v *BasicServiceCode4) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for BasicServiceCode4 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for BasicServiceCode4: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding BasicServiceCode4 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "BasicServiceCode4", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = BasicServiceCode4ChoiceBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding bearerService: %w", tlvErr)
		}
		tmp := BearerServiceCode4(rawVal)
		v.BearerService = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = BasicServiceCode4ChoiceTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding teleservice: %w", tlvErr)
		}
		tmp := TeleserviceCode4(rawVal)
		v.Teleservice = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for BasicServiceCode4 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtBasicServiceCode4 to BER format.
func (v *ExtBasicServiceCode4) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ExtBasicServiceCode4ChoiceExtBearerService:
		if v.ExtBearerService == nil {
			return nil, fmt.Errorf("choice ExtBasicServiceCode4: ext-BearerService is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.ExtBearerService))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_0)
		return enc_0, nil
	case ExtBasicServiceCode4ChoiceExtTeleservice:
		if v.ExtTeleservice == nil {
			return nil, fmt.Errorf("choice ExtBasicServiceCode4: ext-Teleservice is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.ExtTeleservice))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ExtBasicServiceCode4", v.Choice)
	}
}

// MarshalDER encodes ExtBasicServiceCode4 to DER format.
func (v *ExtBasicServiceCode4) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtBasicServiceCode4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtBasicServiceCode4 from BER/DER format.
func (v *ExtBasicServiceCode4) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtBasicServiceCode4 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtBasicServiceCode4: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ExtBasicServiceCode4 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtBasicServiceCode4", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ExtBasicServiceCode4ChoiceExtBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-BearerService: %w", tlvErr)
		}
		tmp := ExtBearerServiceCode4(rawVal)
		v.ExtBearerService = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = ExtBasicServiceCode4ChoiceExtTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-Teleservice: %w", tlvErr)
		}
		tmp := ExtTeleserviceCode4(rawVal)
		v.ExtTeleservice = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for ExtBasicServiceCode4 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EMLPPInfo4 to BER format.
func (v *EMLPPInfo4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_maximumentitledpriority := ber.EncodeInteger(int64(v.MaximumentitledPriority))
	children = append(children, enc_maximumentitledpriority...)
	enc_defaultpriority := ber.EncodeInteger(int64(v.DefaultPriority))
	children = append(children, enc_defaultpriority...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes EMLPPInfo4 to DER format.
func (v *EMLPPInfo4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding EMLPPInfo4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EMLPPInfo4 from BER/DER format.
func (v *EMLPPInfo4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EMLPPInfo4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EMLPPInfo4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode maximumentitledPriority
	if offset >= len(content) {
		return fmt.Errorf("missing required field maximumentitledPriority")
	}
	val_maximumentitledpriority, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding maximumentitledPriority: %w", err)
	}
	v.MaximumentitledPriority = EMLPPPriority4(val_maximumentitledpriority)
	offset += n
	// Decode defaultPriority
	if offset >= len(content) {
		return fmt.Errorf("missing required field defaultPriority")
	}
	val_defaultpriority, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding defaultPriority: %w", err)
	}
	v.DefaultPriority = EMLPPPriority4(val_defaultpriority)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EMLPPInfo4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MCSSInfo4 to BER format.
func (v *MCSSInfo4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	enc_sscode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_sscode)
	children = append(children, enc_sscode...)
	enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	enc_ssstatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_ssstatus)
	children = append(children, enc_ssstatus...)
	enc_nbrsb := ber.EncodeInteger(int64(v.NbrSB))
	enc_nbrsb = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_nbrsb)
	children = append(children, enc_nbrsb...)
	enc_nbruser := ber.EncodeInteger(int64(v.NbrUser))
	enc_nbruser = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_nbruser)
	children = append(children, enc_nbruser...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes MCSSInfo4 to DER format.
func (v *MCSSInfo4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MCSSInfo4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MCSSInfo4 from BER/DER format.
func (v *MCSSInfo4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MCSSInfo4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MCSSInfo4", Cause: ber.ErrExtraData}
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
	decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
		return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
	}
	v.SsCode = SSCode4(rawVal_sscode)
	offset += n_sscode
	// Decode ss-Status
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Status")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for ss-Status, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Status: %w", err)
	}
	if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 1 {
		return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
	}
	v.SsStatus = ExtSSStatus4(rawVal_ssstatus)
	offset += n_ssstatus
	// Decode nbrSB
	if offset >= len(content) {
		return fmt.Errorf("missing required field nbrSB")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for nbrSB, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	decodedTag_nbrsb, n_nbrsb, rawVal_nbrsb, err := ber.DecodeTLV(content[offset:])
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
	v.NbrSB = MaxMCBearers4(decVal_nbrsb)
	offset += n_nbrsb
	// Decode nbrUser
	if offset >= len(content) {
		return fmt.Errorf("missing required field nbrUser")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for nbrUser, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:])
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
	v.NbrUser = MCBearers4(decVal_nbruser)
	offset += n_nbruser
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MCSSInfo4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
