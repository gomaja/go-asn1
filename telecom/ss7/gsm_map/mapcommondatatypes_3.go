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

	// MaxAddressLength3 is the integer constant for MaxAddressLength3.
	MaxAddressLength3 int64 = 20

	// MaxISDNAddressLength3 is the integer constant for MaxISDNAddressLength3.
	MaxISDNAddressLength3 int64 = 9

	// MaxFTNAddressLength3 is the integer constant for MaxFTNAddressLength3.
	MaxFTNAddressLength3 int64 = 15

	// MaxISDNSubaddressLength3 is the integer constant for MaxISDNSubaddressLength3.
	MaxISDNSubaddressLength3 int64 = 21

	// MaxSignalInfoLength3 is the integer constant for MaxSignalInfoLength3.
	MaxSignalInfoLength3 int64 = 200

	// MaxLongSignalInfoLength3 is the integer constant for MaxLongSignalInfoLength3.
	MaxLongSignalInfoLength3 int64 = 2560

	// AlertingLevel03 is the octet string constant for AlertingLevel03.
	AlertingLevel03 = "\x00"

	// AlertingLevel13 is the octet string constant for AlertingLevel13.
	AlertingLevel13 = "\x01"

	// AlertingLevel23 is the octet string constant for AlertingLevel23.
	AlertingLevel23 = "\x02"

	// AlertingCategory13 is the octet string constant for AlertingCategory13.
	AlertingCategory13 = "\x04"

	// AlertingCategory23 is the octet string constant for AlertingCategory23.
	AlertingCategory23 = "\x05"

	// AlertingCategory33 is the octet string constant for AlertingCategory33.
	AlertingCategory33 = "\x06"

	// AlertingCategory43 is the octet string constant for AlertingCategory43.
	AlertingCategory43 = "\x07"

	// AlertingCategory53 is the octet string constant for AlertingCategory53.
	AlertingCategory53 = "\x08"

	// MaxNumOfHLRId3 is the integer constant for MaxNumOfHLRId3.
	MaxNumOfHLRId3 int64 = 50

	// EmergencyServices3 is the integer constant for EmergencyServices3.
	EmergencyServices3 int64 = 0

	// EmergencyAlertServices3 is the integer constant for EmergencyAlertServices3.
	EmergencyAlertServices3 int64 = 1

	// PersonTracking3 is the integer constant for PersonTracking3.
	PersonTracking3 int64 = 2

	// FleetManagement3 is the integer constant for FleetManagement3.
	FleetManagement3 int64 = 3

	// AssetManagement3 is the integer constant for AssetManagement3.
	AssetManagement3 int64 = 4

	// TrafficCongestionReporting3 is the integer constant for TrafficCongestionReporting3.
	TrafficCongestionReporting3 int64 = 5

	// RoadsideAssistance3 is the integer constant for RoadsideAssistance3.
	RoadsideAssistance3 int64 = 6

	// RoutingToNearestCommercialEnterprise3 is the integer constant for RoutingToNearestCommercialEnterprise3.
	RoutingToNearestCommercialEnterprise3 int64 = 7

	// Navigation3 is the integer constant for Navigation3.
	Navigation3 int64 = 8

	// CitySightseeing3 is the integer constant for CitySightseeing3.
	CitySightseeing3 int64 = 9

	// LocalizedAdvertising3 is the integer constant for LocalizedAdvertising3.
	LocalizedAdvertising3 int64 = 10

	// MobileYellowPages3 is the integer constant for MobileYellowPages3.
	MobileYellowPages3 int64 = 11

	// TrafficAndPublicTransportationInfo3 is the integer constant for TrafficAndPublicTransportationInfo3.
	TrafficAndPublicTransportationInfo3 int64 = 12

	// Weather3 is the integer constant for Weather3.
	Weather3 int64 = 13

	// AssetAndServiceFinding3 is the integer constant for AssetAndServiceFinding3.
	AssetAndServiceFinding3 int64 = 14

	// Gaming3 is the integer constant for Gaming3.
	Gaming3 int64 = 15

	// FindYourFriend3 is the integer constant for FindYourFriend3.
	FindYourFriend3 int64 = 16

	// Dating3 is the integer constant for Dating3.
	Dating3 int64 = 17

	// Chatting3 is the integer constant for Chatting3.
	Chatting3 int64 = 18

	// RouteFinding3 is the integer constant for RouteFinding3.
	RouteFinding3 int64 = 19

	// WhereAmI3 is the integer constant for WhereAmI3.
	WhereAmI3 int64 = 20

	// Serv643 is the integer constant for Serv643.
	Serv643 int64 = 64

	// Serv653 is the integer constant for Serv653.
	Serv653 int64 = 65

	// Serv663 is the integer constant for Serv663.
	Serv663 int64 = 66

	// Serv673 is the integer constant for Serv673.
	Serv673 int64 = 67

	// Serv683 is the integer constant for Serv683.
	Serv683 int64 = 68

	// Serv693 is the integer constant for Serv693.
	Serv693 int64 = 69

	// Serv703 is the integer constant for Serv703.
	Serv703 int64 = 70

	// Serv713 is the integer constant for Serv713.
	Serv713 int64 = 71

	// Serv723 is the integer constant for Serv723.
	Serv723 int64 = 72

	// Serv733 is the integer constant for Serv733.
	Serv733 int64 = 73

	// Serv743 is the integer constant for Serv743.
	Serv743 int64 = 74

	// Serv753 is the integer constant for Serv753.
	Serv753 int64 = 75

	// Serv763 is the integer constant for Serv763.
	Serv763 int64 = 76

	// Serv773 is the integer constant for Serv773.
	Serv773 int64 = 77

	// Serv783 is the integer constant for Serv783.
	Serv783 int64 = 78

	// Serv793 is the integer constant for Serv793.
	Serv793 int64 = 79

	// Serv803 is the integer constant for Serv803.
	Serv803 int64 = 80

	// Serv813 is the integer constant for Serv813.
	Serv813 int64 = 81

	// Serv823 is the integer constant for Serv823.
	Serv823 int64 = 82

	// Serv833 is the integer constant for Serv833.
	Serv833 int64 = 83

	// Serv843 is the integer constant for Serv843.
	Serv843 int64 = 84

	// Serv853 is the integer constant for Serv853.
	Serv853 int64 = 85

	// Serv863 is the integer constant for Serv863.
	Serv863 int64 = 86

	// Serv873 is the integer constant for Serv873.
	Serv873 int64 = 87

	// Serv883 is the integer constant for Serv883.
	Serv883 int64 = 88

	// Serv893 is the integer constant for Serv893.
	Serv893 int64 = 89

	// Serv903 is the integer constant for Serv903.
	Serv903 int64 = 90

	// Serv913 is the integer constant for Serv913.
	Serv913 int64 = 91

	// Serv923 is the integer constant for Serv923.
	Serv923 int64 = 92

	// Serv933 is the integer constant for Serv933.
	Serv933 int64 = 93

	// Serv943 is the integer constant for Serv943.
	Serv943 int64 = 94

	// Serv953 is the integer constant for Serv953.
	Serv953 int64 = 95

	// Serv963 is the integer constant for Serv963.
	Serv963 int64 = 96

	// Serv973 is the integer constant for Serv973.
	Serv973 int64 = 97

	// Serv983 is the integer constant for Serv983.
	Serv983 int64 = 98

	// Serv993 is the integer constant for Serv993.
	Serv993 int64 = 99

	// Serv1003 is the integer constant for Serv1003.
	Serv1003 int64 = 100

	// Serv1013 is the integer constant for Serv1013.
	Serv1013 int64 = 101

	// Serv1023 is the integer constant for Serv1023.
	Serv1023 int64 = 102

	// Serv1033 is the integer constant for Serv1033.
	Serv1033 int64 = 103

	// Serv1043 is the integer constant for Serv1043.
	Serv1043 int64 = 104

	// Serv1053 is the integer constant for Serv1053.
	Serv1053 int64 = 105

	// Serv1063 is the integer constant for Serv1063.
	Serv1063 int64 = 106

	// Serv1073 is the integer constant for Serv1073.
	Serv1073 int64 = 107

	// Serv1083 is the integer constant for Serv1083.
	Serv1083 int64 = 108

	// Serv1093 is the integer constant for Serv1093.
	Serv1093 int64 = 109

	// Serv1103 is the integer constant for Serv1103.
	Serv1103 int64 = 110

	// Serv1113 is the integer constant for Serv1113.
	Serv1113 int64 = 111

	// Serv1123 is the integer constant for Serv1123.
	Serv1123 int64 = 112

	// Serv1133 is the integer constant for Serv1133.
	Serv1133 int64 = 113

	// Serv1143 is the integer constant for Serv1143.
	Serv1143 int64 = 114

	// Serv1153 is the integer constant for Serv1153.
	Serv1153 int64 = 115

	// Serv1163 is the integer constant for Serv1163.
	Serv1163 int64 = 116

	// Serv1173 is the integer constant for Serv1173.
	Serv1173 int64 = 117

	// Serv1183 is the integer constant for Serv1183.
	Serv1183 int64 = 118

	// Serv1193 is the integer constant for Serv1193.
	Serv1193 int64 = 119

	// Serv1203 is the integer constant for Serv1203.
	Serv1203 int64 = 120

	// Serv1213 is the integer constant for Serv1213.
	Serv1213 int64 = 121

	// Serv1223 is the integer constant for Serv1223.
	Serv1223 int64 = 122

	// Serv1233 is the integer constant for Serv1233.
	Serv1233 int64 = 123

	// Serv1243 is the integer constant for Serv1243.
	Serv1243 int64 = 124

	// Serv1253 is the integer constant for Serv1253.
	Serv1253 int64 = 125

	// Serv1263 is the integer constant for Serv1263.
	Serv1263 int64 = 126

	// Serv1273 is the integer constant for Serv1273.
	Serv1273 int64 = 127

	// PriorityLevelA3 is the integer constant for PriorityLevelA3.
	PriorityLevelA3 int64 = 6

	// PriorityLevelB3 is the integer constant for PriorityLevelB3.
	PriorityLevelB3 int64 = 5

	// PriorityLevel03 is the integer constant for PriorityLevel03.
	PriorityLevel03 int64 = 0

	// PriorityLevel13 is the integer constant for PriorityLevel13.
	PriorityLevel13 int64 = 1

	// PriorityLevel23 is the integer constant for PriorityLevel23.
	PriorityLevel23 int64 = 2

	// PriorityLevel33 is the integer constant for PriorityLevel33.
	PriorityLevel33 int64 = 3

	// PriorityLevel43 is the integer constant for PriorityLevel43.
	PriorityLevel43 int64 = 4

	// MaxNumOfMCBearers3 is the integer constant for MaxNumOfMCBearers3.
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
	Imsi        IMSI3    `asn1:""`
	Lmsi        LMSI3    `asn1:""`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
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
	Choice int
	Imsi   *IMSI3 `json:"Imsi,omitempty"`
	Tmsi   *TMSI3 `json:"Tmsi,omitempty"`
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
type HLRList3 = []HLRId3

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
	Choice int
	Imsi   *IMSI3              `json:"Imsi,omitempty"`
	Msisdn *ISDNAddressString3 `json:"Msisdn,omitempty"`
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

// CommonDataTypesTAId represents the ASN.1 type TA-Id (OCTET_STRING).
type CommonDataTypesTAId = []byte

// CommonDataTypesRAIdentity represents the ASN.1 type RAIdentity (OCTET_STRING).
type CommonDataTypesRAIdentity = []byte

// CommonDataTypesNetworkNodeDiameterAddress represents the ASN.1 type NetworkNodeDiameterAddress (SEQUENCE).
type CommonDataTypesNetworkNodeDiameterAddress struct {
	DiameterName  CommonDataTypesDiameterIdentity `asn1:"tag:0,context,implicit"`
	DiameterRealm CommonDataTypesDiameterIdentity `asn1:"tag:1,context,implicit"`
}

// CellGlobalIdOrServiceAreaIdOrLAI3 choice constants.
const (
	CellGlobalIdOrServiceAreaIdOrLAI3ChoiceCellGlobalIdOrServiceAreaIdFixedLength = 1
	CellGlobalIdOrServiceAreaIdOrLAI3ChoiceLaiFixedLength                         = 2
)

// CellGlobalIdOrServiceAreaIdOrLAI3 represents the ASN.1 CHOICE type CellGlobalIdOrServiceAreaIdOrLAI.
type CellGlobalIdOrServiceAreaIdOrLAI3 struct {
	Choice                                 int
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
func (v *ExternalSignalInfo3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ExternalSignalInfo3 to DER format.
func (v *ExternalSignalInfo3) MarshalDER() ([]byte, error) {
	var children []byte
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExternalSignalInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExternalSignalInfo3 from BER/DER format.
func (v *ExternalSignalInfo3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	val_protocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding protocolId: %w", err)
	}
	v.ProtocolId = ProtocolId3(val_protocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo3(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ExtExternalSignalInfo3 to BER format.
func (v *ExtExternalSignalInfo3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ExtExternalSignalInfo3 to DER format.
func (v *ExtExternalSignalInfo3) MarshalDER() ([]byte, error) {
	var children []byte
	enc_extprotocolid := ber.EncodeEnumerated(int64(v.ExtProtocolId))
	children = append(children, enc_extprotocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtExternalSignalInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtExternalSignalInfo3 from BER/DER format.
func (v *ExtExternalSignalInfo3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	val_extprotocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ext-ProtocolId: %w", err)
	}
	v.ExtProtocolId = ExtProtocolId3(val_extprotocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo3(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtExternalSignalInfo3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AccessNetworkSignalInfo3 to BER format.
func (v *AccessNetworkSignalInfo3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes AccessNetworkSignalInfo3 to DER format.
func (v *AccessNetworkSignalInfo3) MarshalDER() ([]byte, error) {
	var children []byte
	enc_accessnetworkprotocolid := ber.EncodeEnumerated(int64(v.AccessNetworkProtocolId))
	children = append(children, enc_accessnetworkprotocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AccessNetworkSignalInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AccessNetworkSignalInfo3 from BER/DER format.
func (v *AccessNetworkSignalInfo3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	val_accessnetworkprotocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding accessNetworkProtocolId: %w", err)
	}
	v.AccessNetworkProtocolId = AccessNetworkProtocolId3(val_accessnetworkprotocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = LongSignalInfo3(val_signalinfo)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "AccessNetworkSignalInfo3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes Identity3 to BER format.
func (v *Identity3) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case Identity3ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("choice Identity3: imsi is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		return enc_0, nil
	case Identity3ChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("choice Identity3: imsi-WithLMSI is nil")
		}
		enc_1, err := v.ImsiWithLMSI.MarshalBER()
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
	switch v.Choice {
	case Identity3ChoiceImsiWithLMSI:
		if v.ImsiWithLMSI == nil {
			return nil, fmt.Errorf("choice Identity3: imsi-WithLMSI is nil")
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
		return nil, fmt.Errorf("encoding Identity3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Identity3 from BER/DER format.
func (v *Identity3) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Identity3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Identity3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Identity3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Identity3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = Identity3ChoiceImsi
		decVal, _, osErr := ber.DecodeOctetString(choiceData)
		if osErr != nil {
			return fmt.Errorf("decoding imsi: %w", osErr)
		}
		tmp := IMSI3(decVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = Identity3ChoiceImsiWithLMSI
		var dec IMSIWithLMSI3
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding imsi-WithLMSI: %w", unmErr)
		}
		v.ImsiWithLMSI = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Identity3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes IMSIWithLMSI3 to BER format.
func (v *IMSIWithLMSI3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes IMSIWithLMSI3 to DER format.
func (v *IMSIWithLMSI3) MarshalDER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	children = append(children, enc_imsi...)
	enc_lmsi := ber.EncodeOctetString([]byte(v.Lmsi))
	children = append(children, enc_lmsi...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IMSIWithLMSI3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IMSIWithLMSI3 from BER/DER format.
func (v *IMSIWithLMSI3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	val_imsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = IMSI3(val_imsi)
	offset += n
	// Decode lmsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field lmsi")
	}
	val_lmsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lmsi: %w", err)
	}
	v.Lmsi = LMSI3(val_lmsi)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IMSIWithLMSI3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubscriberId3 to BER format.
func (v *SubscriberId3) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SubscriberId3ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("choice SubscriberId3: imsi is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SubscriberId3ChoiceTmsi:
		if v.Tmsi == nil {
			return nil, fmt.Errorf("choice SubscriberId3: tmsi is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.Tmsi))
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
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberId3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberId3 from BER/DER format.
func (v *SubscriberId3) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberId3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberId3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberId3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberId3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberId3ChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := IMSI3(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberId3ChoiceTmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding tmsi: %w", tlvErr)
		}
		tmp := TMSI3(rawVal)
		v.Tmsi = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberId3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBERHLRList3 encodes a HLRList3 list to BER.
func MarshalBERHLRList3(list HLRList3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDERHLRList3 encodes a HLRList3 list to DER.
func MarshalDERHLRList3(list HLRList3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding HLRList3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERHLRList3 decodes a HLRList3 list from BER.
func UnmarshalBERHLRList3(data []byte) (HLRList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding HLRList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "HLRList3", Cause: ber.ErrExtraData}
	}
	var result HLRList3
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, HLRId3(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes NAEAPreferredCI3 to BER format.
func (v *NAEAPreferredCI3) MarshalBER() ([]byte, error) {
	var children []byte
	enc_naeapreferredcic := ber.EncodeOctetString([]byte(v.NaeaPreferredCIC))
	retagged_enc_naeapreferredcic, tagErr_enc_naeapreferredcic := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naeapreferredcic)
	if tagErr_enc_naeapreferredcic != nil {
		return nil, fmt.Errorf("encoding naea-PreferredCIC: %w", tagErr_enc_naeapreferredcic)
	}
	enc_naeapreferredcic = retagged_enc_naeapreferredcic
	children = append(children, enc_naeapreferredcic...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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

// MarshalDER encodes NAEAPreferredCI3 to DER format.
func (v *NAEAPreferredCI3) MarshalDER() ([]byte, error) {
	var children []byte
	enc_naeapreferredcic := ber.EncodeOctetString([]byte(v.NaeaPreferredCIC))
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding NAEAPreferredCI3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NAEAPreferredCI3 from BER/DER format.
func (v *NAEAPreferredCI3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	decodedTag_naeapreferredcic, n_naeapreferredcic, rawVal_naeapreferredcic, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding naea-PreferredCIC: %w", err)
	}
	if decodedTag_naeapreferredcic.Class != tag.ClassContextSpecific || decodedTag_naeapreferredcic.Number != 0 {
		return fmt.Errorf("decoding naea-PreferredCIC: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naeapreferredcic)
	}
	v.NaeaPreferredCIC = NAEACIC3(rawVal_naeapreferredcic)
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
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "NAEAPreferredCI3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubscriberIdentity3 to BER format.
func (v *SubscriberIdentity3) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SubscriberIdentity3ChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("choice SubscriberIdentity3: imsi is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SubscriberIdentity3ChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("choice SubscriberIdentity3: msisdn is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.Msisdn))
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
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriberIdentity3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberIdentity3 from BER/DER format.
func (v *SubscriberIdentity3) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberIdentity3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberIdentity3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SubscriberIdentity3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberIdentity3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberIdentity3ChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := IMSI3(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberIdentity3ChoiceMsisdn
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msisdn: %w", tlvErr)
		}
		tmp := ISDNAddressString3(rawVal)
		v.Msisdn = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SubscriberIdentity3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes LCSClientExternalID3 to BER format.
func (v *LCSClientExternalID3) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExternalAddress != nil {
		enc_externaladdress := ber.EncodeOctetString([]byte(*v.ExternalAddress))
		retagged_enc_externaladdress, tagErr_enc_externaladdress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_externaladdress)
		if tagErr_enc_externaladdress != nil {
			return nil, fmt.Errorf("encoding externalAddress: %w", tagErr_enc_externaladdress)
		}
		enc_externaladdress = retagged_enc_externaladdress
		children = append(children, enc_externaladdress...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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

// MarshalDER encodes LCSClientExternalID3 to DER format.
func (v *LCSClientExternalID3) MarshalDER() ([]byte, error) {
	var children []byte
	if v.ExternalAddress != nil {
		enc_externaladdress := ber.EncodeOctetString([]byte(*v.ExternalAddress))
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding LCSClientExternalID3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSClientExternalID3 from BER/DER format.
func (v *LCSClientExternalID3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				decodedTag_externaladdress, n_externaladdress, rawVal_externaladdress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding externalAddress: %w", err)
				}
				if decodedTag_externaladdress.Class != tag.ClassContextSpecific || decodedTag_externaladdress.Number != 0 {
					return fmt.Errorf("decoding externalAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_externaladdress)
				}
				tmp_externaladdress := ISDNAddressString3(rawVal_externaladdress)
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
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSClientExternalID3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CommonDataTypesNetworkNodeDiameterAddress to BER format.
func (v *CommonDataTypesNetworkNodeDiameterAddress) MarshalBER() ([]byte, error) {
	var children []byte
	enc_diametername := ber.EncodeOctetString([]byte(v.DiameterName))
	retagged_enc_diametername, tagErr_enc_diametername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_diametername)
	if tagErr_enc_diametername != nil {
		return nil, fmt.Errorf("encoding diameter-Name: %w", tagErr_enc_diametername)
	}
	enc_diametername = retagged_enc_diametername
	children = append(children, enc_diametername...)
	enc_diameterrealm := ber.EncodeOctetString([]byte(v.DiameterRealm))
	retagged_enc_diameterrealm, tagErr_enc_diameterrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_diameterrealm)
	if tagErr_enc_diameterrealm != nil {
		return nil, fmt.Errorf("encoding diameter-Realm: %w", tagErr_enc_diameterrealm)
	}
	enc_diameterrealm = retagged_enc_diameterrealm
	children = append(children, enc_diameterrealm...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CommonDataTypesNetworkNodeDiameterAddress to DER format.
func (v *CommonDataTypesNetworkNodeDiameterAddress) MarshalDER() ([]byte, error) {
	var children []byte
	enc_diametername := ber.EncodeOctetString([]byte(v.DiameterName))
	retagged_enc_diametername, tagErr_enc_diametername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_diametername)
	if tagErr_enc_diametername != nil {
		return nil, fmt.Errorf("encoding diameter-Name: %w", tagErr_enc_diametername)
	}
	enc_diametername = retagged_enc_diametername
	children = append(children, enc_diametername...)
	enc_diameterrealm := ber.EncodeOctetString([]byte(v.DiameterRealm))
	retagged_enc_diameterrealm, tagErr_enc_diameterrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_diameterrealm)
	if tagErr_enc_diameterrealm != nil {
		return nil, fmt.Errorf("encoding diameter-Realm: %w", tagErr_enc_diameterrealm)
	}
	enc_diameterrealm = retagged_enc_diameterrealm
	children = append(children, enc_diameterrealm...)
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CommonDataTypesNetworkNodeDiameterAddress as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CommonDataTypesNetworkNodeDiameterAddress from BER/DER format.
func (v *CommonDataTypesNetworkNodeDiameterAddress) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	decodedTag_diametername, n_diametername, rawVal_diametername, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding diameter-Name: %w", err)
	}
	if decodedTag_diametername.Class != tag.ClassContextSpecific || decodedTag_diametername.Number != 0 {
		return fmt.Errorf("decoding diameter-Name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_diametername)
	}
	v.DiameterName = CommonDataTypesDiameterIdentity(rawVal_diametername)
	offset += n_diametername
	// Decode diameter-Realm
	if offset >= len(content) {
		return fmt.Errorf("missing required field diameter-Realm")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for diameter-Realm, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_diameterrealm, n_diameterrealm, rawVal_diameterrealm, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding diameter-Realm: %w", err)
	}
	if decodedTag_diameterrealm.Class != tag.ClassContextSpecific || decodedTag_diameterrealm.Number != 1 {
		return fmt.Errorf("decoding diameter-Realm: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_diameterrealm)
	}
	v.DiameterRealm = CommonDataTypesDiameterIdentity(rawVal_diameterrealm)
	offset += n_diameterrealm
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CommonDataTypesNetworkNodeDiameterAddress", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CellGlobalIdOrServiceAreaIdOrLAI3 to BER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI3) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CellGlobalIdOrServiceAreaIdOrLAI3ChoiceCellGlobalIdOrServiceAreaIdFixedLength:
		if v.CellGlobalIdOrServiceAreaIdFixedLength == nil {
			return nil, fmt.Errorf("choice CellGlobalIdOrServiceAreaIdOrLAI3: cellGlobalIdOrServiceAreaIdFixedLength is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.CellGlobalIdOrServiceAreaIdFixedLength))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding cellGlobalIdOrServiceAreaIdFixedLength: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case CellGlobalIdOrServiceAreaIdOrLAI3ChoiceLaiFixedLength:
		if v.LaiFixedLength == nil {
			return nil, fmt.Errorf("choice CellGlobalIdOrServiceAreaIdOrLAI3: laiFixedLength is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.LaiFixedLength))
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
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CellGlobalIdOrServiceAreaIdOrLAI3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CellGlobalIdOrServiceAreaIdOrLAI3 from BER/DER format.
func (v *CellGlobalIdOrServiceAreaIdOrLAI3) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CellGlobalIdOrServiceAreaIdOrLAI3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CellGlobalIdOrServiceAreaIdOrLAI3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CellGlobalIdOrServiceAreaIdOrLAI3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CellGlobalIdOrServiceAreaIdOrLAI3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAI3ChoiceCellGlobalIdOrServiceAreaIdFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cellGlobalIdOrServiceAreaIdFixedLength: %w", tlvErr)
		}
		tmp := CellGlobalIdOrServiceAreaIdFixedLength3(rawVal)
		v.CellGlobalIdOrServiceAreaIdFixedLength = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = CellGlobalIdOrServiceAreaIdOrLAI3ChoiceLaiFixedLength
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding laiFixedLength: %w", tlvErr)
		}
		tmp := LAIFixedLength3(rawVal)
		v.LaiFixedLength = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for CellGlobalIdOrServiceAreaIdOrLAI3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes BasicServiceCode3 to BER format.
func (v *BasicServiceCode3) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case BasicServiceCode3ChoiceBearerService:
		if v.BearerService == nil {
			return nil, fmt.Errorf("choice BasicServiceCode3: bearerService is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.BearerService))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding bearerService: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case BasicServiceCode3ChoiceTeleservice:
		if v.Teleservice == nil {
			return nil, fmt.Errorf("choice BasicServiceCode3: teleservice is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.Teleservice))
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
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BasicServiceCode3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BasicServiceCode3 from BER/DER format.
func (v *BasicServiceCode3) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for BasicServiceCode3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for BasicServiceCode3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding BasicServiceCode3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "BasicServiceCode3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = BasicServiceCode3ChoiceBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding bearerService: %w", tlvErr)
		}
		tmp := BearerServiceCode3(rawVal)
		v.BearerService = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = BasicServiceCode3ChoiceTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding teleservice: %w", tlvErr)
		}
		tmp := TeleserviceCode3(rawVal)
		v.Teleservice = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for BasicServiceCode3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtBasicServiceCode3 to BER format.
func (v *ExtBasicServiceCode3) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ExtBasicServiceCode3ChoiceExtBearerService:
		if v.ExtBearerService == nil {
			return nil, fmt.Errorf("choice ExtBasicServiceCode3: ext-BearerService is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.ExtBearerService))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding ext-BearerService: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ExtBasicServiceCode3ChoiceExtTeleservice:
		if v.ExtTeleservice == nil {
			return nil, fmt.Errorf("choice ExtBasicServiceCode3: ext-Teleservice is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.ExtTeleservice))
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
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtBasicServiceCode3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtBasicServiceCode3 from BER/DER format.
func (v *ExtBasicServiceCode3) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtBasicServiceCode3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtBasicServiceCode3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ExtBasicServiceCode3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtBasicServiceCode3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ExtBasicServiceCode3ChoiceExtBearerService
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-BearerService: %w", tlvErr)
		}
		tmp := ExtBearerServiceCode3(rawVal)
		v.ExtBearerService = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = ExtBasicServiceCode3ChoiceExtTeleservice
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ext-Teleservice: %w", tlvErr)
		}
		tmp := ExtTeleserviceCode3(rawVal)
		v.ExtTeleservice = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for ExtBasicServiceCode3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EMLPPInfo3 to BER format.
func (v *EMLPPInfo3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes EMLPPInfo3 to DER format.
func (v *EMLPPInfo3) MarshalDER() ([]byte, error) {
	var children []byte
	enc_maximumentitledpriority := ber.EncodeInteger(int64(v.MaximumentitledPriority))
	children = append(children, enc_maximumentitledpriority...)
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding EMLPPInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EMLPPInfo3 from BER/DER format.
func (v *EMLPPInfo3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	val_maximumentitledpriority, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding maximumentitledPriority: %w", err)
	}
	v.MaximumentitledPriority = EMLPPPriority3(val_maximumentitledpriority)
	offset += n
	// Decode defaultPriority
	if offset >= len(content) {
		return fmt.Errorf("missing required field defaultPriority")
	}
	val_defaultpriority, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding defaultPriority: %w", err)
	}
	v.DefaultPriority = EMLPPPriority3(val_defaultpriority)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "EMLPPInfo3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MCSSInfo3 to BER format.
func (v *MCSSInfo3) MarshalBER() ([]byte, error) {
	var children []byte
	enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	enc_nbrsb := ber.EncodeInteger(int64(v.NbrSB))
	retagged_enc_nbrsb, tagErr_enc_nbrsb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_nbrsb)
	if tagErr_enc_nbrsb != nil {
		return nil, fmt.Errorf("encoding nbrSB: %w", tagErr_enc_nbrsb)
	}
	enc_nbrsb = retagged_enc_nbrsb
	children = append(children, enc_nbrsb...)
	enc_nbruser := ber.EncodeInteger(int64(v.NbrUser))
	retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_nbruser)
	if tagErr_enc_nbruser != nil {
		return nil, fmt.Errorf("encoding nbrUser: %w", tagErr_enc_nbruser)
	}
	enc_nbruser = retagged_enc_nbruser
	children = append(children, enc_nbruser...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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

// MarshalDER encodes MCSSInfo3 to DER format.
func (v *MCSSInfo3) MarshalDER() ([]byte, error) {
	var children []byte
	enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	enc_nbrsb := ber.EncodeInteger(int64(v.NbrSB))
	retagged_enc_nbrsb, tagErr_enc_nbrsb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_nbrsb)
	if tagErr_enc_nbrsb != nil {
		return nil, fmt.Errorf("encoding nbrSB: %w", tagErr_enc_nbrsb)
	}
	enc_nbrsb = retagged_enc_nbrsb
	children = append(children, enc_nbrsb...)
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MCSSInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MCSSInfo3 from BER/DER format.
func (v *MCSSInfo3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
		return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
	}
	v.SsCode = SSCode3(rawVal_sscode)
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
	v.SsStatus = ExtSSStatus3(rawVal_ssstatus)
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
	v.NbrSB = MaxMCBearers3(decVal_nbrsb)
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
	v.NbrUser = MCBearers3(decVal_nbruser)
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
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "MCSSInfo3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
