// Code generated from ASN.1 module "PEDefinitions". DO NOT EDIT.

package sgp32

import (
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

// UICCCapability represents the ASN.1 type UICCCapability (BIT_STRING).
type UICCCapability = runtime.BitString

const (
	// UICCCapabilityContactlessSupport is position 0 of ASN.1 named bit contactlessSupport of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityContactlessSupport = 0
	// UICCCapabilityUsimSupport is position 1 of ASN.1 named bit usimSupport of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityUsimSupport = 1
	// UICCCapabilityIsimSupport is position 2 of ASN.1 named bit isimSupport of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityIsimSupport = 2
	// UICCCapabilityCsimSupport is position 3 of ASN.1 named bit csimSupport of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityCsimSupport = 3
	// UICCCapabilityAkaMilenage is position 4 of ASN.1 named bit akaMilenage of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityAkaMilenage = 4
	// UICCCapabilityAkaCave is position 5 of ASN.1 named bit akaCave of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityAkaCave = 5
	// UICCCapabilityAkaTuak128 is position 6 of ASN.1 named bit akaTuak128 of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityAkaTuak128 = 6
	// UICCCapabilityAkaTuak256 is position 7 of ASN.1 named bit akaTuak256 of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityAkaTuak256 = 7
	// UICCCapabilityUsimTestAlgorithm is position 8 of ASN.1 named bit usimTestAlgorithm of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityUsimTestAlgorithm = 8
	// UICCCapabilityRfu2 is position 9 of ASN.1 named bit rfu2 of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityRfu2 = 9
	// UICCCapabilityGbaAuthenUsim is position 10 of ASN.1 named bit gbaAuthenUsim of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityGbaAuthenUsim = 10
	// UICCCapabilityGbaAuthenISim is position 11 of ASN.1 named bit gbaAuthenISim of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityGbaAuthenISim = 11
	// UICCCapabilityMbmsAuthenUsim is position 12 of ASN.1 named bit mbmsAuthenUsim of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityMbmsAuthenUsim = 12
	// UICCCapabilityEapClient is position 13 of ASN.1 named bit eapClient of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityEapClient = 13
	// UICCCapabilityJavacard is position 14 of ASN.1 named bit javacard of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityJavacard = 14
	// UICCCapabilityMultos is position 15 of ASN.1 named bit multos of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityMultos = 15
	// UICCCapabilityMultipleUsimSupport is position 16 of ASN.1 named bit multipleUsimSupport of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityMultipleUsimSupport = 16
	// UICCCapabilityMultipleIsimSupport is position 17 of ASN.1 named bit multipleIsimSupport of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityMultipleIsimSupport = 17
	// UICCCapabilityMultipleCsimSupport is position 18 of ASN.1 named bit multipleCsimSupport of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityMultipleCsimSupport = 18
	// UICCCapabilityBerTlvFileSupport is position 19 of ASN.1 named bit berTlvFileSupport of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityBerTlvFileSupport = 19
	// UICCCapabilityDfLinkSupport is position 20 of ASN.1 named bit dfLinkSupport of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityDfLinkSupport = 20
	// UICCCapabilityCatTp is position 21 of ASN.1 named bit catTp of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityCatTp = 21
	// UICCCapabilityGetIdentity is position 22 of ASN.1 named bit getIdentity of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityGetIdentity = 22
	// UICCCapabilityProfileAX25519 is position 23 of ASN.1 named bit profile-a-x25519 of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityProfileAX25519 = 23
	// UICCCapabilityProfileBP256 is position 24 of ASN.1 named bit profile-b-p256 of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityProfileBP256 = 24
	// UICCCapabilitySuciCalculatorApi is position 25 of ASN.1 named bit suciCalculatorApi of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilitySuciCalculatorApi = 25
	// UICCCapabilityDnsResolution is position 26 of ASN.1 named bit dns-resolution of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityDnsResolution = 26
	// UICCCapabilityScp11ac is position 27 of ASN.1 named bit scp11ac of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityScp11ac = 27
	// UICCCapabilityScp11cAuthorizationMechanism is position 28 of ASN.1 named bit scp11c-authorization-mechanism of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityScp11cAuthorizationMechanism = 28
	// UICCCapabilityS16mode is position 29 of ASN.1 named bit s16mode of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityS16mode = 29
	// UICCCapabilityEaka is position 30 of ASN.1 named bit eaka of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityEaka = 30
	// UICCCapabilityIotminimal is position 31 of ASN.1 named bit iotminimal of UICCCapability (ITU-T X.680 (02/2021) §22).
	UICCCapabilityIotminimal = 31
)
