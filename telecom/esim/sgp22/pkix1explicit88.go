// Code generated from ASN.1 module "PKIX1Explicit88". DO NOT EDIT.

package sgp22

import (
	"fmt"
	"math/big"
	"time"

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

	// CommonNameValue is the integer constant for common-name.
	CommonNameValue int64 = 1

	// TeletexCommonNameValue is the integer constant for teletex-common-name.
	TeletexCommonNameValue int64 = 2

	// TeletexOrganizationNameValue is the integer constant for teletex-organization-name.
	TeletexOrganizationNameValue int64 = 3

	// TeletexPersonalNameValue is the integer constant for teletex-personal-name.
	TeletexPersonalNameValue int64 = 4

	// TeletexOrganizationalUnitNamesValue is the integer constant for teletex-organizational-unit-names.
	TeletexOrganizationalUnitNamesValue int64 = 5

	// PdsName is the integer constant for pds-name.
	PdsName int64 = 7

	// PhysicalDeliveryCountryNameValue is the integer constant for physical-delivery-country-name.
	PhysicalDeliveryCountryNameValue int64 = 8

	// PostalCodeValue is the integer constant for postal-code.
	PostalCodeValue int64 = 9

	// PhysicalDeliveryOfficeNameValue is the integer constant for physical-delivery-office-name.
	PhysicalDeliveryOfficeNameValue int64 = 10

	// PhysicalDeliveryOfficeNumberValue is the integer constant for physical-delivery-office-number.
	PhysicalDeliveryOfficeNumberValue int64 = 11

	// ExtensionORAddressComponentsValue is the integer constant for extension-OR-address-components.
	ExtensionORAddressComponentsValue int64 = 12

	// PhysicalDeliveryPersonalNameValue is the integer constant for physical-delivery-personal-name.
	PhysicalDeliveryPersonalNameValue int64 = 13

	// PhysicalDeliveryOrganizationNameValue is the integer constant for physical-delivery-organization-name.
	PhysicalDeliveryOrganizationNameValue int64 = 14

	// ExtensionPhysicalDeliveryAddressComponentsValue is the integer constant for extension-physical-delivery-address-components.
	ExtensionPhysicalDeliveryAddressComponentsValue int64 = 15

	// UnformattedPostalAddressValue is the integer constant for unformatted-postal-address.
	UnformattedPostalAddressValue int64 = 16

	// StreetAddressValue is the integer constant for street-address.
	StreetAddressValue int64 = 17

	// PostOfficeBoxAddressValue is the integer constant for post-office-box-address.
	PostOfficeBoxAddressValue int64 = 18

	// PosteRestanteAddressValue is the integer constant for poste-restante-address.
	PosteRestanteAddressValue int64 = 19

	// UniquePostalNameValue is the integer constant for unique-postal-name.
	UniquePostalNameValue int64 = 20

	// LocalPostalAttributesValue is the integer constant for local-postal-attributes.
	LocalPostalAttributesValue int64 = 21

	// ExtendedNetworkAddressValue is the integer constant for extended-network-address.
	ExtendedNetworkAddressValue int64 = 22

	// TerminalTypeValue is the integer constant for terminal-type.
	TerminalTypeValue int64 = 23

	// TeletexDomainDefinedAttributesValue is the integer constant for teletex-domain-defined-attributes.
	TeletexDomainDefinedAttributesValue int64 = 6

	// UbName is the integer constant for ub-name.
	UbName int64 = 32768

	// UbCommonName is the integer constant for ub-common-name.
	UbCommonName int64 = 64

	// UbLocalityName is the integer constant for ub-locality-name.
	UbLocalityName int64 = 128

	// UbStateName is the integer constant for ub-state-name.
	UbStateName int64 = 128

	// UbOrganizationName is the integer constant for ub-organization-name.
	UbOrganizationName int64 = 64

	// UbOrganizationalUnitName is the integer constant for ub-organizational-unit-name.
	UbOrganizationalUnitName int64 = 64

	// UbTitle is the integer constant for ub-title.
	UbTitle int64 = 64

	// UbSerialNumber is the integer constant for ub-serial-number.
	UbSerialNumber int64 = 64

	// UbMatch is the integer constant for ub-match.
	UbMatch int64 = 128

	// UbEmailaddressLength is the integer constant for ub-emailaddress-length.
	UbEmailaddressLength int64 = 255

	// UbCommonNameLength is the integer constant for ub-common-name-length.
	UbCommonNameLength int64 = 64

	// UbCountryNameAlphaLength is the integer constant for ub-country-name-alpha-length.
	UbCountryNameAlphaLength int64 = 2

	// UbCountryNameNumericLength is the integer constant for ub-country-name-numeric-length.
	UbCountryNameNumericLength int64 = 3

	// UbDomainDefinedAttributes is the integer constant for ub-domain-defined-attributes.
	UbDomainDefinedAttributes int64 = 4

	// UbDomainDefinedAttributeTypeLength is the integer constant for ub-domain-defined-attribute-type-length.
	UbDomainDefinedAttributeTypeLength int64 = 8

	// UbDomainDefinedAttributeValueLength is the integer constant for ub-domain-defined-attribute-value-length.
	UbDomainDefinedAttributeValueLength int64 = 128

	// UbDomainNameLength is the integer constant for ub-domain-name-length.
	UbDomainNameLength int64 = 16

	// UbExtensionAttributes is the integer constant for ub-extension-attributes.
	UbExtensionAttributes int64 = 256

	// UbE1634NumberLength is the integer constant for ub-e163-4-number-length.
	UbE1634NumberLength int64 = 15

	// UbE1634SubAddressLength is the integer constant for ub-e163-4-sub-address-length.
	UbE1634SubAddressLength int64 = 40

	// UbGenerationQualifierLength is the integer constant for ub-generation-qualifier-length.
	UbGenerationQualifierLength int64 = 3

	// UbGivenNameLength is the integer constant for ub-given-name-length.
	UbGivenNameLength int64 = 16

	// UbInitialsLength is the integer constant for ub-initials-length.
	UbInitialsLength int64 = 5

	// UbIntegerOptions is the integer constant for ub-integer-options.
	UbIntegerOptions int64 = 256

	// UbNumericUserIdLength is the integer constant for ub-numeric-user-id-length.
	UbNumericUserIdLength int64 = 32

	// UbOrganizationNameLength is the integer constant for ub-organization-name-length.
	UbOrganizationNameLength int64 = 64

	// UbOrganizationalUnitNameLength is the integer constant for ub-organizational-unit-name-length.
	UbOrganizationalUnitNameLength int64 = 32

	// UbOrganizationalUnits is the integer constant for ub-organizational-units.
	UbOrganizationalUnits int64 = 4

	// UbPdsNameLength is the integer constant for ub-pds-name-length.
	UbPdsNameLength int64 = 16

	// UbPdsParameterLength is the integer constant for ub-pds-parameter-length.
	UbPdsParameterLength int64 = 30

	// UbPdsPhysicalAddressLines is the integer constant for ub-pds-physical-address-lines.
	UbPdsPhysicalAddressLines int64 = 6

	// UbPostalCodeLength is the integer constant for ub-postal-code-length.
	UbPostalCodeLength int64 = 16

	// UbPseudonym is the integer constant for ub-pseudonym.
	UbPseudonym int64 = 128

	// UbSurnameLength is the integer constant for ub-surname-length.
	UbSurnameLength int64 = 40

	// UbTerminalIdLength is the integer constant for ub-terminal-id-length.
	UbTerminalIdLength int64 = 24

	// UbUnformattedAddressLength is the integer constant for ub-unformatted-address-length.
	UbUnformattedAddressLength int64 = 180

	// UbX121AddressLength is the integer constant for ub-x121-address-length.
	UbX121AddressLength int64 = 16
)

// IdPkix returns the OID value for id-pkix.
func IdPkix() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7} }

// IdPe returns the OID value for id-pe.
func IdPe() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1} }

// IdQt returns the OID value for id-qt.
func IdQt() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2} }

// IdKp returns the OID value for id-kp.
func IdKp() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3} }

// IdAd returns the OID value for id-ad.
func IdAd() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48} }

// IdQtCps returns the OID value for id-qt-cps.
func IdQtCps() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1} }

// IdQtUnotice returns the OID value for id-qt-unotice.
func IdQtUnotice() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}
}

// IdAdOcsp returns the OID value for id-ad-ocsp.
func IdAdOcsp() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1} }

// IdAdCaIssuers returns the OID value for id-ad-caIssuers.
func IdAdCaIssuers() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
}

// IdAdTimeStamping returns the OID value for id-ad-timeStamping.
func IdAdTimeStamping() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 3}
}

// IdAdCaRepository returns the OID value for id-ad-caRepository.
func IdAdCaRepository() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5}
}

// IdAt returns the OID value for id-at.
func IdAt() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4} }

// IdAtName returns the OID value for id-at-name.
func IdAtName() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 41} }

// IdAtSurname returns the OID value for id-at-surname.
func IdAtSurname() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 4} }

// IdAtGivenName returns the OID value for id-at-givenName.
func IdAtGivenName() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 42} }

// IdAtInitials returns the OID value for id-at-initials.
func IdAtInitials() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 43} }

// IdAtGenerationQualifier returns the OID value for id-at-generationQualifier.
func IdAtGenerationQualifier() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 44} }

// IdAtCommonName returns the OID value for id-at-commonName.
func IdAtCommonName() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 3} }

// IdAtLocalityName returns the OID value for id-at-localityName.
func IdAtLocalityName() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 7} }

// IdAtStateOrProvinceName returns the OID value for id-at-stateOrProvinceName.
func IdAtStateOrProvinceName() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 8} }

// IdAtOrganizationName returns the OID value for id-at-organizationName.
func IdAtOrganizationName() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 10} }

// IdAtOrganizationalUnitName returns the OID value for id-at-organizationalUnitName.
func IdAtOrganizationalUnitName() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{2, 5, 4, 11}
}

// IdAtTitle returns the OID value for id-at-title.
func IdAtTitle() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 12} }

// IdAtDnQualifier returns the OID value for id-at-dnQualifier.
func IdAtDnQualifier() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 46} }

// IdAtCountryName returns the OID value for id-at-countryName.
func IdAtCountryName() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 6} }

// IdAtSerialNumber returns the OID value for id-at-serialNumber.
func IdAtSerialNumber() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 5} }

// IdAtPseudonym returns the OID value for id-at-pseudonym.
func IdAtPseudonym() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{2, 5, 4, 65} }

// IdDomainComponent returns the OID value for id-domainComponent.
func IdDomainComponent() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
}

// Pkcs9 returns the OID value for pkcs-9.
func Pkcs9() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{1, 2, 840, 113549, 1, 9} }

// IdEmailAddress returns the OID value for id-emailAddress.
func IdEmailAddress() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
}

// Attribute represents the ASN.1 type Attribute (SEQUENCE).
type Attribute struct {
	Type         AttributeType   `asn1:""`
	Values       AttributeValues `asn1:""`
	ValuesIndef_ bool            `asn1:"-" json:"-"`
}

// AttributeType represents the ASN.1 type AttributeType (OBJECT_IDENTIFIER).
type AttributeType = runtime.ObjectIdentifier

// AttributeValue represents the ASN.1 type AttributeValue (ANY).
type AttributeValue = runtime.RawValue

// AttributeTypeAndValue represents the ASN.1 type AttributeTypeAndValue (SEQUENCE).
type AttributeTypeAndValue struct {
	Type  AttributeType    `asn1:""`
	Value runtime.RawValue `asn1:""`
}

// X520name choice constants.
const (
	X520nameChoiceTeletexString   = 1
	X520nameChoicePrintableString = 2
	X520nameChoiceUniversalString = 3
	X520nameChoiceUtf8String      = 4
	X520nameChoiceBmpString       = 5
)

// X520name represents the ASN.1 CHOICE type X520name.
type X520name struct {
	Choice          int
	TeletexString   *string `json:"TeletexString,omitempty"`
	PrintableString *string `json:"PrintableString,omitempty"`
	UniversalString *string `json:"UniversalString,omitempty"`
	Utf8String      *string `json:"Utf8String,omitempty"`
	BmpString       *string `json:"BmpString,omitempty"`
}

// NewX520nameTeletexString creates a X520name with the teletexString alternative.
func NewX520nameTeletexString(v string) X520name {
	return X520name{
		Choice:        X520nameChoiceTeletexString,
		TeletexString: &v,
	}
}

// NewX520namePrintableString creates a X520name with the printableString alternative.
func NewX520namePrintableString(v string) X520name {
	return X520name{
		Choice:          X520nameChoicePrintableString,
		PrintableString: &v,
	}
}

// NewX520nameUniversalString creates a X520name with the universalString alternative.
func NewX520nameUniversalString(v string) X520name {
	return X520name{
		Choice:          X520nameChoiceUniversalString,
		UniversalString: &v,
	}
}

// NewX520nameUtf8String creates a X520name with the utf8String alternative.
func NewX520nameUtf8String(v string) X520name {
	return X520name{
		Choice:     X520nameChoiceUtf8String,
		Utf8String: &v,
	}
}

// NewX520nameBmpString creates a X520name with the bmpString alternative.
func NewX520nameBmpString(v string) X520name {
	return X520name{
		Choice:    X520nameChoiceBmpString,
		BmpString: &v,
	}
}

// X520CommonName choice constants.
const (
	X520CommonNameChoiceTeletexString   = 1
	X520CommonNameChoicePrintableString = 2
	X520CommonNameChoiceUniversalString = 3
	X520CommonNameChoiceUtf8String      = 4
	X520CommonNameChoiceBmpString       = 5
)

// X520CommonName represents the ASN.1 CHOICE type X520CommonName.
type X520CommonName struct {
	Choice          int
	TeletexString   *string `json:"TeletexString,omitempty"`
	PrintableString *string `json:"PrintableString,omitempty"`
	UniversalString *string `json:"UniversalString,omitempty"`
	Utf8String      *string `json:"Utf8String,omitempty"`
	BmpString       *string `json:"BmpString,omitempty"`
}

// NewX520CommonNameTeletexString creates a X520CommonName with the teletexString alternative.
func NewX520CommonNameTeletexString(v string) X520CommonName {
	return X520CommonName{
		Choice:        X520CommonNameChoiceTeletexString,
		TeletexString: &v,
	}
}

// NewX520CommonNamePrintableString creates a X520CommonName with the printableString alternative.
func NewX520CommonNamePrintableString(v string) X520CommonName {
	return X520CommonName{
		Choice:          X520CommonNameChoicePrintableString,
		PrintableString: &v,
	}
}

// NewX520CommonNameUniversalString creates a X520CommonName with the universalString alternative.
func NewX520CommonNameUniversalString(v string) X520CommonName {
	return X520CommonName{
		Choice:          X520CommonNameChoiceUniversalString,
		UniversalString: &v,
	}
}

// NewX520CommonNameUtf8String creates a X520CommonName with the utf8String alternative.
func NewX520CommonNameUtf8String(v string) X520CommonName {
	return X520CommonName{
		Choice:     X520CommonNameChoiceUtf8String,
		Utf8String: &v,
	}
}

// NewX520CommonNameBmpString creates a X520CommonName with the bmpString alternative.
func NewX520CommonNameBmpString(v string) X520CommonName {
	return X520CommonName{
		Choice:    X520CommonNameChoiceBmpString,
		BmpString: &v,
	}
}

// X520LocalityName choice constants.
const (
	X520LocalityNameChoiceTeletexString   = 1
	X520LocalityNameChoicePrintableString = 2
	X520LocalityNameChoiceUniversalString = 3
	X520LocalityNameChoiceUtf8String      = 4
	X520LocalityNameChoiceBmpString       = 5
)

// X520LocalityName represents the ASN.1 CHOICE type X520LocalityName.
type X520LocalityName struct {
	Choice          int
	TeletexString   *string `json:"TeletexString,omitempty"`
	PrintableString *string `json:"PrintableString,omitempty"`
	UniversalString *string `json:"UniversalString,omitempty"`
	Utf8String      *string `json:"Utf8String,omitempty"`
	BmpString       *string `json:"BmpString,omitempty"`
}

// NewX520LocalityNameTeletexString creates a X520LocalityName with the teletexString alternative.
func NewX520LocalityNameTeletexString(v string) X520LocalityName {
	return X520LocalityName{
		Choice:        X520LocalityNameChoiceTeletexString,
		TeletexString: &v,
	}
}

// NewX520LocalityNamePrintableString creates a X520LocalityName with the printableString alternative.
func NewX520LocalityNamePrintableString(v string) X520LocalityName {
	return X520LocalityName{
		Choice:          X520LocalityNameChoicePrintableString,
		PrintableString: &v,
	}
}

// NewX520LocalityNameUniversalString creates a X520LocalityName with the universalString alternative.
func NewX520LocalityNameUniversalString(v string) X520LocalityName {
	return X520LocalityName{
		Choice:          X520LocalityNameChoiceUniversalString,
		UniversalString: &v,
	}
}

// NewX520LocalityNameUtf8String creates a X520LocalityName with the utf8String alternative.
func NewX520LocalityNameUtf8String(v string) X520LocalityName {
	return X520LocalityName{
		Choice:     X520LocalityNameChoiceUtf8String,
		Utf8String: &v,
	}
}

// NewX520LocalityNameBmpString creates a X520LocalityName with the bmpString alternative.
func NewX520LocalityNameBmpString(v string) X520LocalityName {
	return X520LocalityName{
		Choice:    X520LocalityNameChoiceBmpString,
		BmpString: &v,
	}
}

// X520StateOrProvinceName choice constants.
const (
	X520StateOrProvinceNameChoiceTeletexString   = 1
	X520StateOrProvinceNameChoicePrintableString = 2
	X520StateOrProvinceNameChoiceUniversalString = 3
	X520StateOrProvinceNameChoiceUtf8String      = 4
	X520StateOrProvinceNameChoiceBmpString       = 5
)

// X520StateOrProvinceName represents the ASN.1 CHOICE type X520StateOrProvinceName.
type X520StateOrProvinceName struct {
	Choice          int
	TeletexString   *string `json:"TeletexString,omitempty"`
	PrintableString *string `json:"PrintableString,omitempty"`
	UniversalString *string `json:"UniversalString,omitempty"`
	Utf8String      *string `json:"Utf8String,omitempty"`
	BmpString       *string `json:"BmpString,omitempty"`
}

// NewX520StateOrProvinceNameTeletexString creates a X520StateOrProvinceName with the teletexString alternative.
func NewX520StateOrProvinceNameTeletexString(v string) X520StateOrProvinceName {
	return X520StateOrProvinceName{
		Choice:        X520StateOrProvinceNameChoiceTeletexString,
		TeletexString: &v,
	}
}

// NewX520StateOrProvinceNamePrintableString creates a X520StateOrProvinceName with the printableString alternative.
func NewX520StateOrProvinceNamePrintableString(v string) X520StateOrProvinceName {
	return X520StateOrProvinceName{
		Choice:          X520StateOrProvinceNameChoicePrintableString,
		PrintableString: &v,
	}
}

// NewX520StateOrProvinceNameUniversalString creates a X520StateOrProvinceName with the universalString alternative.
func NewX520StateOrProvinceNameUniversalString(v string) X520StateOrProvinceName {
	return X520StateOrProvinceName{
		Choice:          X520StateOrProvinceNameChoiceUniversalString,
		UniversalString: &v,
	}
}

// NewX520StateOrProvinceNameUtf8String creates a X520StateOrProvinceName with the utf8String alternative.
func NewX520StateOrProvinceNameUtf8String(v string) X520StateOrProvinceName {
	return X520StateOrProvinceName{
		Choice:     X520StateOrProvinceNameChoiceUtf8String,
		Utf8String: &v,
	}
}

// NewX520StateOrProvinceNameBmpString creates a X520StateOrProvinceName with the bmpString alternative.
func NewX520StateOrProvinceNameBmpString(v string) X520StateOrProvinceName {
	return X520StateOrProvinceName{
		Choice:    X520StateOrProvinceNameChoiceBmpString,
		BmpString: &v,
	}
}

// X520OrganizationName choice constants.
const (
	X520OrganizationNameChoiceTeletexString   = 1
	X520OrganizationNameChoicePrintableString = 2
	X520OrganizationNameChoiceUniversalString = 3
	X520OrganizationNameChoiceUtf8String      = 4
	X520OrganizationNameChoiceBmpString       = 5
)

// X520OrganizationName represents the ASN.1 CHOICE type X520OrganizationName.
type X520OrganizationName struct {
	Choice          int
	TeletexString   *string `json:"TeletexString,omitempty"`
	PrintableString *string `json:"PrintableString,omitempty"`
	UniversalString *string `json:"UniversalString,omitempty"`
	Utf8String      *string `json:"Utf8String,omitempty"`
	BmpString       *string `json:"BmpString,omitempty"`
}

// NewX520OrganizationNameTeletexString creates a X520OrganizationName with the teletexString alternative.
func NewX520OrganizationNameTeletexString(v string) X520OrganizationName {
	return X520OrganizationName{
		Choice:        X520OrganizationNameChoiceTeletexString,
		TeletexString: &v,
	}
}

// NewX520OrganizationNamePrintableString creates a X520OrganizationName with the printableString alternative.
func NewX520OrganizationNamePrintableString(v string) X520OrganizationName {
	return X520OrganizationName{
		Choice:          X520OrganizationNameChoicePrintableString,
		PrintableString: &v,
	}
}

// NewX520OrganizationNameUniversalString creates a X520OrganizationName with the universalString alternative.
func NewX520OrganizationNameUniversalString(v string) X520OrganizationName {
	return X520OrganizationName{
		Choice:          X520OrganizationNameChoiceUniversalString,
		UniversalString: &v,
	}
}

// NewX520OrganizationNameUtf8String creates a X520OrganizationName with the utf8String alternative.
func NewX520OrganizationNameUtf8String(v string) X520OrganizationName {
	return X520OrganizationName{
		Choice:     X520OrganizationNameChoiceUtf8String,
		Utf8String: &v,
	}
}

// NewX520OrganizationNameBmpString creates a X520OrganizationName with the bmpString alternative.
func NewX520OrganizationNameBmpString(v string) X520OrganizationName {
	return X520OrganizationName{
		Choice:    X520OrganizationNameChoiceBmpString,
		BmpString: &v,
	}
}

// X520OrganizationalUnitName choice constants.
const (
	X520OrganizationalUnitNameChoiceTeletexString   = 1
	X520OrganizationalUnitNameChoicePrintableString = 2
	X520OrganizationalUnitNameChoiceUniversalString = 3
	X520OrganizationalUnitNameChoiceUtf8String      = 4
	X520OrganizationalUnitNameChoiceBmpString       = 5
)

// X520OrganizationalUnitName represents the ASN.1 CHOICE type X520OrganizationalUnitName.
type X520OrganizationalUnitName struct {
	Choice          int
	TeletexString   *string `json:"TeletexString,omitempty"`
	PrintableString *string `json:"PrintableString,omitempty"`
	UniversalString *string `json:"UniversalString,omitempty"`
	Utf8String      *string `json:"Utf8String,omitempty"`
	BmpString       *string `json:"BmpString,omitempty"`
}

// NewX520OrganizationalUnitNameTeletexString creates a X520OrganizationalUnitName with the teletexString alternative.
func NewX520OrganizationalUnitNameTeletexString(v string) X520OrganizationalUnitName {
	return X520OrganizationalUnitName{
		Choice:        X520OrganizationalUnitNameChoiceTeletexString,
		TeletexString: &v,
	}
}

// NewX520OrganizationalUnitNamePrintableString creates a X520OrganizationalUnitName with the printableString alternative.
func NewX520OrganizationalUnitNamePrintableString(v string) X520OrganizationalUnitName {
	return X520OrganizationalUnitName{
		Choice:          X520OrganizationalUnitNameChoicePrintableString,
		PrintableString: &v,
	}
}

// NewX520OrganizationalUnitNameUniversalString creates a X520OrganizationalUnitName with the universalString alternative.
func NewX520OrganizationalUnitNameUniversalString(v string) X520OrganizationalUnitName {
	return X520OrganizationalUnitName{
		Choice:          X520OrganizationalUnitNameChoiceUniversalString,
		UniversalString: &v,
	}
}

// NewX520OrganizationalUnitNameUtf8String creates a X520OrganizationalUnitName with the utf8String alternative.
func NewX520OrganizationalUnitNameUtf8String(v string) X520OrganizationalUnitName {
	return X520OrganizationalUnitName{
		Choice:     X520OrganizationalUnitNameChoiceUtf8String,
		Utf8String: &v,
	}
}

// NewX520OrganizationalUnitNameBmpString creates a X520OrganizationalUnitName with the bmpString alternative.
func NewX520OrganizationalUnitNameBmpString(v string) X520OrganizationalUnitName {
	return X520OrganizationalUnitName{
		Choice:    X520OrganizationalUnitNameChoiceBmpString,
		BmpString: &v,
	}
}

// X520Title choice constants.
const (
	X520TitleChoiceTeletexString   = 1
	X520TitleChoicePrintableString = 2
	X520TitleChoiceUniversalString = 3
	X520TitleChoiceUtf8String      = 4
	X520TitleChoiceBmpString       = 5
)

// X520Title represents the ASN.1 CHOICE type X520Title.
type X520Title struct {
	Choice          int
	TeletexString   *string `json:"TeletexString,omitempty"`
	PrintableString *string `json:"PrintableString,omitempty"`
	UniversalString *string `json:"UniversalString,omitempty"`
	Utf8String      *string `json:"Utf8String,omitempty"`
	BmpString       *string `json:"BmpString,omitempty"`
}

// NewX520TitleTeletexString creates a X520Title with the teletexString alternative.
func NewX520TitleTeletexString(v string) X520Title {
	return X520Title{
		Choice:        X520TitleChoiceTeletexString,
		TeletexString: &v,
	}
}

// NewX520TitlePrintableString creates a X520Title with the printableString alternative.
func NewX520TitlePrintableString(v string) X520Title {
	return X520Title{
		Choice:          X520TitleChoicePrintableString,
		PrintableString: &v,
	}
}

// NewX520TitleUniversalString creates a X520Title with the universalString alternative.
func NewX520TitleUniversalString(v string) X520Title {
	return X520Title{
		Choice:          X520TitleChoiceUniversalString,
		UniversalString: &v,
	}
}

// NewX520TitleUtf8String creates a X520Title with the utf8String alternative.
func NewX520TitleUtf8String(v string) X520Title {
	return X520Title{
		Choice:     X520TitleChoiceUtf8String,
		Utf8String: &v,
	}
}

// NewX520TitleBmpString creates a X520Title with the bmpString alternative.
func NewX520TitleBmpString(v string) X520Title {
	return X520Title{
		Choice:    X520TitleChoiceBmpString,
		BmpString: &v,
	}
}

// X520dnQualifier represents the ASN.1 type X520dnQualifier (PrintableString).
type X520dnQualifier = string

// X520countryName represents the ASN.1 type X520countryName (PrintableString).
type X520countryName = string

// X520SerialNumber represents the ASN.1 type X520SerialNumber (PrintableString).
type X520SerialNumber = string

// X520Pseudonym choice constants.
const (
	X520PseudonymChoiceTeletexString   = 1
	X520PseudonymChoicePrintableString = 2
	X520PseudonymChoiceUniversalString = 3
	X520PseudonymChoiceUtf8String      = 4
	X520PseudonymChoiceBmpString       = 5
)

// X520Pseudonym represents the ASN.1 CHOICE type X520Pseudonym.
type X520Pseudonym struct {
	Choice          int
	TeletexString   *string `json:"TeletexString,omitempty"`
	PrintableString *string `json:"PrintableString,omitempty"`
	UniversalString *string `json:"UniversalString,omitempty"`
	Utf8String      *string `json:"Utf8String,omitempty"`
	BmpString       *string `json:"BmpString,omitempty"`
}

// NewX520PseudonymTeletexString creates a X520Pseudonym with the teletexString alternative.
func NewX520PseudonymTeletexString(v string) X520Pseudonym {
	return X520Pseudonym{
		Choice:        X520PseudonymChoiceTeletexString,
		TeletexString: &v,
	}
}

// NewX520PseudonymPrintableString creates a X520Pseudonym with the printableString alternative.
func NewX520PseudonymPrintableString(v string) X520Pseudonym {
	return X520Pseudonym{
		Choice:          X520PseudonymChoicePrintableString,
		PrintableString: &v,
	}
}

// NewX520PseudonymUniversalString creates a X520Pseudonym with the universalString alternative.
func NewX520PseudonymUniversalString(v string) X520Pseudonym {
	return X520Pseudonym{
		Choice:          X520PseudonymChoiceUniversalString,
		UniversalString: &v,
	}
}

// NewX520PseudonymUtf8String creates a X520Pseudonym with the utf8String alternative.
func NewX520PseudonymUtf8String(v string) X520Pseudonym {
	return X520Pseudonym{
		Choice:     X520PseudonymChoiceUtf8String,
		Utf8String: &v,
	}
}

// NewX520PseudonymBmpString creates a X520Pseudonym with the bmpString alternative.
func NewX520PseudonymBmpString(v string) X520Pseudonym {
	return X520Pseudonym{
		Choice:    X520PseudonymChoiceBmpString,
		BmpString: &v,
	}
}

// DomainComponent represents the ASN.1 type DomainComponent (IA5String).
type DomainComponent = string

// EmailAddress represents the ASN.1 type EmailAddress (IA5String).
type EmailAddress = string

// Name choice constants.
const (
	NameChoiceRdnSequence = 1
)

// Name represents the ASN.1 CHOICE type Name.
type Name struct {
	Choice      int
	RdnSequence RDNSequence `json:"RdnSequence,omitempty"`
}

// NewNameRdnSequence creates a Name with the rdnSequence alternative.
func NewNameRdnSequence(v RDNSequence) Name {
	return Name{
		Choice:      NameChoiceRdnSequence,
		RdnSequence: v,
	}
}

// RDNSequence represents the ASN.1 type RDNSequence (SEQUENCE_OF).
type RDNSequence = []RelativeDistinguishedName

// DistinguishedName represents the ASN.1 type DistinguishedName (SEQUENCE_OF).
type DistinguishedName = RDNSequence

// RelativeDistinguishedName represents the ASN.1 type RelativeDistinguishedName (SET_OF).
type RelativeDistinguishedName = []AttributeTypeAndValue

// DirectoryString choice constants.
const (
	DirectoryStringChoiceTeletexString   = 1
	DirectoryStringChoicePrintableString = 2
	DirectoryStringChoiceUniversalString = 3
	DirectoryStringChoiceUtf8String      = 4
	DirectoryStringChoiceBmpString       = 5
)

// DirectoryString represents the ASN.1 CHOICE type DirectoryString.
type DirectoryString struct {
	Choice          int
	TeletexString   *string `json:"TeletexString,omitempty"`
	PrintableString *string `json:"PrintableString,omitempty"`
	UniversalString *string `json:"UniversalString,omitempty"`
	Utf8String      *string `json:"Utf8String,omitempty"`
	BmpString       *string `json:"BmpString,omitempty"`
}

// NewDirectoryStringTeletexString creates a DirectoryString with the teletexString alternative.
func NewDirectoryStringTeletexString(v string) DirectoryString {
	return DirectoryString{
		Choice:        DirectoryStringChoiceTeletexString,
		TeletexString: &v,
	}
}

// NewDirectoryStringPrintableString creates a DirectoryString with the printableString alternative.
func NewDirectoryStringPrintableString(v string) DirectoryString {
	return DirectoryString{
		Choice:          DirectoryStringChoicePrintableString,
		PrintableString: &v,
	}
}

// NewDirectoryStringUniversalString creates a DirectoryString with the universalString alternative.
func NewDirectoryStringUniversalString(v string) DirectoryString {
	return DirectoryString{
		Choice:          DirectoryStringChoiceUniversalString,
		UniversalString: &v,
	}
}

// NewDirectoryStringUtf8String creates a DirectoryString with the utf8String alternative.
func NewDirectoryStringUtf8String(v string) DirectoryString {
	return DirectoryString{
		Choice:     DirectoryStringChoiceUtf8String,
		Utf8String: &v,
	}
}

// NewDirectoryStringBmpString creates a DirectoryString with the bmpString alternative.
func NewDirectoryStringBmpString(v string) DirectoryString {
	return DirectoryString{
		Choice:    DirectoryStringChoiceBmpString,
		BmpString: &v,
	}
}

// Certificate represents the ASN.1 type Certificate (SEQUENCE).
type Certificate struct {
	TbsCertificate     TBSCertificate      `asn1:""`
	SignatureAlgorithm AlgorithmIdentifier `asn1:""`
	Signature          runtime.BitString   `asn1:""`
}

// TBSCertificate represents the ASN.1 type TBSCertificate (SEQUENCE).
type TBSCertificate struct {
	Version              *Version                `asn1:"tag:0,context,explicit,optional" json:"Version,omitempty"`
	SerialNumber         CertificateSerialNumber `asn1:""`
	Signature            AlgorithmIdentifier     `asn1:""`
	Issuer               Name                    `asn1:""`
	Validity             Validity                `asn1:""`
	Subject              Name                    `asn1:""`
	SubjectPublicKeyInfo SubjectPublicKeyInfo    `asn1:""`
	IssuerUniqueID       *UniqueIdentifier       `asn1:"tag:1,context,implicit,optional" json:"IssuerUniqueID,omitempty"`
	SubjectUniqueID      *UniqueIdentifier       `asn1:"tag:2,context,implicit,optional" json:"SubjectUniqueID,omitempty"`
	Extensions           Extensions              `asn1:"tag:3,context,explicit,optional" json:"Extensions,omitempty"`
	ExtensionsIndef_     bool                    `asn1:"-" json:"-"`
}

// Version represents the ASN.1 INTEGER type Version with named numbers.
type Version int64

const (
	VersionV1 Version = 0
	VersionV2 Version = 1
	VersionV3 Version = 2
)

func (v Version) String() string {
	switch v {
	case VersionV1:
		return "v1"
	case VersionV2:
		return "v2"
	case VersionV3:
		return "v3"
	default:
		return "unknown"
	}
}

// CertificateSerialNumber represents the ASN.1 type CertificateSerialNumber (INTEGER).
type CertificateSerialNumber = *big.Int

// Validity represents the ASN.1 type Validity (SEQUENCE).
type Validity struct {
	NotBefore Time `asn1:""`
	NotAfter  Time `asn1:""`
}

// Time choice constants.
const (
	TimeChoiceUtcTime     = 1
	TimeChoiceGeneralTime = 2
)

// Time represents the ASN.1 CHOICE type Time.
type Time struct {
	Choice      int
	UtcTime     *time.Time `json:"UtcTime,omitempty"`
	GeneralTime *time.Time `json:"GeneralTime,omitempty"`
}

// NewTimeUtcTime creates a Time with the utcTime alternative.
func NewTimeUtcTime(v time.Time) Time {
	return Time{
		Choice:  TimeChoiceUtcTime,
		UtcTime: &v,
	}
}

// NewTimeGeneralTime creates a Time with the generalTime alternative.
func NewTimeGeneralTime(v time.Time) Time {
	return Time{
		Choice:      TimeChoiceGeneralTime,
		GeneralTime: &v,
	}
}

// UniqueIdentifier represents the ASN.1 type UniqueIdentifier (BIT_STRING).
type UniqueIdentifier = runtime.BitString

// SubjectPublicKeyInfo represents the ASN.1 type SubjectPublicKeyInfo (SEQUENCE).
type SubjectPublicKeyInfo struct {
	Algorithm        AlgorithmIdentifier `asn1:""`
	SubjectPublicKey runtime.BitString   `asn1:""`
}

// Extensions represents the ASN.1 type Extensions (SEQUENCE_OF).
type Extensions = []Extension

// Extension represents the ASN.1 type Extension (SEQUENCE).
type Extension struct {
	ExtnID       runtime.ObjectIdentifier `asn1:""`
	Critical     *bool                    `asn1:",optional" json:"Critical,omitempty"`
	CriticalRaw_ byte                     `asn1:"-" json:"-"`
	ExtnValue    []byte                   `asn1:""`
}

// CertificateList represents the ASN.1 type CertificateList (SEQUENCE).
type CertificateList struct {
	TbsCertList        TBSCertList         `asn1:""`
	SignatureAlgorithm AlgorithmIdentifier `asn1:""`
	Signature          runtime.BitString   `asn1:""`
}

// TBSCertList represents the ASN.1 type TBSCertList (SEQUENCE).
type TBSCertList struct {
	Version                   *Version                       `asn1:",optional" json:"Version,omitempty"`
	Signature                 AlgorithmIdentifier            `asn1:""`
	Issuer                    Name                           `asn1:""`
	ThisUpdate                Time                           `asn1:""`
	NextUpdate                *Time                          `asn1:",optional" json:"NextUpdate,omitempty"`
	RevokedCertificates       TBSCertListRevokedCertificates `asn1:",optional" json:"RevokedCertificates,omitempty"`
	RevokedCertificatesIndef_ bool                           `asn1:"-" json:"-"`
	CrlExtensions             Extensions                     `asn1:"tag:0,context,explicit,optional" json:"CrlExtensions,omitempty"`
	CrlExtensionsIndef_       bool                           `asn1:"-" json:"-"`
}

// AlgorithmIdentifier represents the ASN.1 type AlgorithmIdentifier (SEQUENCE).
type AlgorithmIdentifier struct {
	Algorithm  runtime.ObjectIdentifier `asn1:""`
	Parameters *runtime.RawValue        `asn1:",optional" json:"Parameters,omitempty"`
}

// ORAddress represents the ASN.1 type ORAddress (SEQUENCE).
type ORAddress struct {
	BuiltInStandardAttributes            BuiltInStandardAttributes      `asn1:""`
	BuiltInDomainDefinedAttributes       BuiltInDomainDefinedAttributes `asn1:",optional" json:"BuiltInDomainDefinedAttributes,omitempty"`
	BuiltInDomainDefinedAttributesIndef_ bool                           `asn1:"-" json:"-"`
	ExtensionAttributes                  ExtensionAttributes            `asn1:",optional" json:"ExtensionAttributes,omitempty"`
	ExtensionAttributesIndef_            bool                           `asn1:"-" json:"-"`
}

// BuiltInStandardAttributes represents the ASN.1 type BuiltInStandardAttributes (SEQUENCE).
type BuiltInStandardAttributes struct {
	CountryName                   *CountryName              `asn1:",optional" json:"CountryName,omitempty"`
	AdministrationDomainName      *AdministrationDomainName `asn1:",optional" json:"AdministrationDomainName,omitempty"`
	NetworkAddress                *NetworkAddress           `asn1:"tag:0,context,implicit,optional" json:"NetworkAddress,omitempty"`
	TerminalIdentifier            *TerminalIdentifier       `asn1:"tag:1,context,implicit,optional" json:"TerminalIdentifier,omitempty"`
	PrivateDomainName             *PrivateDomainName        `asn1:"tag:2,context,explicit,optional" json:"PrivateDomainName,omitempty"`
	OrganizationName              *OrganizationName         `asn1:"tag:3,context,implicit,optional" json:"OrganizationName,omitempty"`
	NumericUserIdentifier         *NumericUserIdentifier    `asn1:"tag:4,context,implicit,optional" json:"NumericUserIdentifier,omitempty"`
	PersonalName                  *PersonalName             `asn1:"tag:5,context,implicit,optional" json:"PersonalName,omitempty"`
	OrganizationalUnitNames       OrganizationalUnitNames   `asn1:"tag:6,context,implicit,optional" json:"OrganizationalUnitNames,omitempty"`
	OrganizationalUnitNamesIndef_ bool                      `asn1:"-" json:"-"`
}

// CountryName choice constants.
const (
	CountryNameChoiceX121DccCode       = 1
	CountryNameChoiceIso3166Alpha2Code = 2
)

// CountryName represents the ASN.1 CHOICE type CountryName.
type CountryName struct {
	Choice            int
	X121DccCode       *string `json:"X121DccCode,omitempty"`
	Iso3166Alpha2Code *string `json:"Iso3166Alpha2Code,omitempty"`
}

// NewCountryNameX121DccCode creates a CountryName with the x121-dcc-code alternative.
func NewCountryNameX121DccCode(v string) CountryName {
	return CountryName{
		Choice:      CountryNameChoiceX121DccCode,
		X121DccCode: &v,
	}
}

// NewCountryNameIso3166Alpha2Code creates a CountryName with the iso-3166-alpha2-code alternative.
func NewCountryNameIso3166Alpha2Code(v string) CountryName {
	return CountryName{
		Choice:            CountryNameChoiceIso3166Alpha2Code,
		Iso3166Alpha2Code: &v,
	}
}

// AdministrationDomainName choice constants.
const (
	AdministrationDomainNameChoiceNumeric   = 1
	AdministrationDomainNameChoicePrintable = 2
)

// AdministrationDomainName represents the ASN.1 CHOICE type AdministrationDomainName.
type AdministrationDomainName struct {
	Choice    int
	Numeric   *string `json:"Numeric,omitempty"`
	Printable *string `json:"Printable,omitempty"`
}

// NewAdministrationDomainNameNumeric creates a AdministrationDomainName with the numeric alternative.
func NewAdministrationDomainNameNumeric(v string) AdministrationDomainName {
	return AdministrationDomainName{
		Choice:  AdministrationDomainNameChoiceNumeric,
		Numeric: &v,
	}
}

// NewAdministrationDomainNamePrintable creates a AdministrationDomainName with the printable alternative.
func NewAdministrationDomainNamePrintable(v string) AdministrationDomainName {
	return AdministrationDomainName{
		Choice:    AdministrationDomainNameChoicePrintable,
		Printable: &v,
	}
}

// NetworkAddress represents the ASN.1 type NetworkAddress (NumericString).
type NetworkAddress = X121Address

// X121Address represents the ASN.1 type X121Address (NumericString).
type X121Address = string

// TerminalIdentifier represents the ASN.1 type TerminalIdentifier (PrintableString).
type TerminalIdentifier = string

// PrivateDomainName choice constants.
const (
	PrivateDomainNameChoiceNumeric   = 1
	PrivateDomainNameChoicePrintable = 2
)

// PrivateDomainName represents the ASN.1 CHOICE type PrivateDomainName.
type PrivateDomainName struct {
	Choice    int
	Numeric   *string `json:"Numeric,omitempty"`
	Printable *string `json:"Printable,omitempty"`
}

// NewPrivateDomainNameNumeric creates a PrivateDomainName with the numeric alternative.
func NewPrivateDomainNameNumeric(v string) PrivateDomainName {
	return PrivateDomainName{
		Choice:  PrivateDomainNameChoiceNumeric,
		Numeric: &v,
	}
}

// NewPrivateDomainNamePrintable creates a PrivateDomainName with the printable alternative.
func NewPrivateDomainNamePrintable(v string) PrivateDomainName {
	return PrivateDomainName{
		Choice:    PrivateDomainNameChoicePrintable,
		Printable: &v,
	}
}

// OrganizationName represents the ASN.1 type OrganizationName (PrintableString).
type OrganizationName = string

// NumericUserIdentifier represents the ASN.1 type NumericUserIdentifier (NumericString).
type NumericUserIdentifier = string

// PersonalName represents the ASN.1 type PersonalName (SET).
type PersonalName struct {
	Surname             string  `asn1:"tag:0,context,implicit"`
	GivenName           *string `asn1:"tag:1,context,implicit,optional" json:"GivenName,omitempty"`
	Initials            *string `asn1:"tag:2,context,implicit,optional" json:"Initials,omitempty"`
	GenerationQualifier *string `asn1:"tag:3,context,implicit,optional" json:"GenerationQualifier,omitempty"`
}

// OrganizationalUnitNames represents the ASN.1 type OrganizationalUnitNames (SEQUENCE_OF).
type OrganizationalUnitNames = []OrganizationalUnitName

// OrganizationalUnitName represents the ASN.1 type OrganizationalUnitName (PrintableString).
type OrganizationalUnitName = string

// BuiltInDomainDefinedAttributes represents the ASN.1 type BuiltInDomainDefinedAttributes (SEQUENCE_OF).
type BuiltInDomainDefinedAttributes = []BuiltInDomainDefinedAttribute

// BuiltInDomainDefinedAttribute represents the ASN.1 type BuiltInDomainDefinedAttribute (SEQUENCE).
type BuiltInDomainDefinedAttribute struct {
	Type  string `asn1:""`
	Value string `asn1:""`
}

// ExtensionAttributes represents the ASN.1 type ExtensionAttributes (SET_OF).
type ExtensionAttributes = []ExtensionAttribute

// ExtensionAttribute represents the ASN.1 type ExtensionAttribute (SEQUENCE).
type ExtensionAttribute struct {
	ExtensionAttributeType  int64            `asn1:"tag:0,context,implicit"`
	ExtensionAttributeValue runtime.RawValue `asn1:"tag:1,context,explicit"`
}

// CommonName represents the ASN.1 type CommonName (PrintableString).
type CommonName = string

// TeletexCommonName represents the ASN.1 type TeletexCommonName (T61String).
type TeletexCommonName = string

// TeletexOrganizationName represents the ASN.1 type TeletexOrganizationName (T61String).
type TeletexOrganizationName = string

// TeletexPersonalName represents the ASN.1 type TeletexPersonalName (SET).
type TeletexPersonalName struct {
	Surname             string  `asn1:"tag:0,context,implicit"`
	GivenName           *string `asn1:"tag:1,context,implicit,optional" json:"GivenName,omitempty"`
	Initials            *string `asn1:"tag:2,context,implicit,optional" json:"Initials,omitempty"`
	GenerationQualifier *string `asn1:"tag:3,context,implicit,optional" json:"GenerationQualifier,omitempty"`
}

// TeletexOrganizationalUnitNames represents the ASN.1 type TeletexOrganizationalUnitNames (SEQUENCE_OF).
type TeletexOrganizationalUnitNames = []TeletexOrganizationalUnitName

// TeletexOrganizationalUnitName represents the ASN.1 type TeletexOrganizationalUnitName (T61String).
type TeletexOrganizationalUnitName = string

// PDSName represents the ASN.1 type PDSName (PrintableString).
type PDSName = string

// PhysicalDeliveryCountryName choice constants.
const (
	PhysicalDeliveryCountryNameChoiceX121DccCode       = 1
	PhysicalDeliveryCountryNameChoiceIso3166Alpha2Code = 2
)

// PhysicalDeliveryCountryName represents the ASN.1 CHOICE type PhysicalDeliveryCountryName.
type PhysicalDeliveryCountryName struct {
	Choice            int
	X121DccCode       *string `json:"X121DccCode,omitempty"`
	Iso3166Alpha2Code *string `json:"Iso3166Alpha2Code,omitempty"`
}

// NewPhysicalDeliveryCountryNameX121DccCode creates a PhysicalDeliveryCountryName with the x121-dcc-code alternative.
func NewPhysicalDeliveryCountryNameX121DccCode(v string) PhysicalDeliveryCountryName {
	return PhysicalDeliveryCountryName{
		Choice:      PhysicalDeliveryCountryNameChoiceX121DccCode,
		X121DccCode: &v,
	}
}

// NewPhysicalDeliveryCountryNameIso3166Alpha2Code creates a PhysicalDeliveryCountryName with the iso-3166-alpha2-code alternative.
func NewPhysicalDeliveryCountryNameIso3166Alpha2Code(v string) PhysicalDeliveryCountryName {
	return PhysicalDeliveryCountryName{
		Choice:            PhysicalDeliveryCountryNameChoiceIso3166Alpha2Code,
		Iso3166Alpha2Code: &v,
	}
}

// PostalCode choice constants.
const (
	PostalCodeChoiceNumericCode   = 1
	PostalCodeChoicePrintableCode = 2
)

// PostalCode represents the ASN.1 CHOICE type PostalCode.
type PostalCode struct {
	Choice        int
	NumericCode   *string `json:"NumericCode,omitempty"`
	PrintableCode *string `json:"PrintableCode,omitempty"`
}

// NewPostalCodeNumericCode creates a PostalCode with the numeric-code alternative.
func NewPostalCodeNumericCode(v string) PostalCode {
	return PostalCode{
		Choice:      PostalCodeChoiceNumericCode,
		NumericCode: &v,
	}
}

// NewPostalCodePrintableCode creates a PostalCode with the printable-code alternative.
func NewPostalCodePrintableCode(v string) PostalCode {
	return PostalCode{
		Choice:        PostalCodeChoicePrintableCode,
		PrintableCode: &v,
	}
}

// PhysicalDeliveryOfficeName represents the ASN.1 type PhysicalDeliveryOfficeName (SET).
type PhysicalDeliveryOfficeName = PDSParameter

// PhysicalDeliveryOfficeNumber represents the ASN.1 type PhysicalDeliveryOfficeNumber (SET).
type PhysicalDeliveryOfficeNumber = PDSParameter

// ExtensionORAddressComponents represents the ASN.1 type ExtensionORAddressComponents (SET).
type ExtensionORAddressComponents = PDSParameter

// PhysicalDeliveryPersonalName represents the ASN.1 type PhysicalDeliveryPersonalName (SET).
type PhysicalDeliveryPersonalName = PDSParameter

// PhysicalDeliveryOrganizationName represents the ASN.1 type PhysicalDeliveryOrganizationName (SET).
type PhysicalDeliveryOrganizationName = PDSParameter

// ExtensionPhysicalDeliveryAddressComponents represents the ASN.1 type ExtensionPhysicalDeliveryAddressComponents (SET).
type ExtensionPhysicalDeliveryAddressComponents = PDSParameter

// UnformattedPostalAddress represents the ASN.1 type UnformattedPostalAddress (SET).
type UnformattedPostalAddress struct {
	PrintableAddress       UnformattedPostalAddressPrintableAddress `asn1:",optional" json:"PrintableAddress,omitempty"`
	PrintableAddressIndef_ bool                                     `asn1:"-" json:"-"`
	TeletexString          *string                                  `asn1:",optional" json:"TeletexString,omitempty"`
}

// StreetAddress represents the ASN.1 type StreetAddress (SET).
type StreetAddress = PDSParameter

// PostOfficeBoxAddress represents the ASN.1 type PostOfficeBoxAddress (SET).
type PostOfficeBoxAddress = PDSParameter

// PosteRestanteAddress represents the ASN.1 type PosteRestanteAddress (SET).
type PosteRestanteAddress = PDSParameter

// UniquePostalName represents the ASN.1 type UniquePostalName (SET).
type UniquePostalName = PDSParameter

// LocalPostalAttributes represents the ASN.1 type LocalPostalAttributes (SET).
type LocalPostalAttributes = PDSParameter

// PDSParameter represents the ASN.1 type PDSParameter (SET).
type PDSParameter struct {
	PrintableString *string `asn1:",optional" json:"PrintableString,omitempty"`
	TeletexString   *string `asn1:",optional" json:"TeletexString,omitempty"`
}

// ExtendedNetworkAddress choice constants.
const (
	ExtendedNetworkAddressChoiceE1634Address = 1
	ExtendedNetworkAddressChoicePsapAddress  = 2
)

// ExtendedNetworkAddress represents the ASN.1 CHOICE type ExtendedNetworkAddress.
type ExtendedNetworkAddress struct {
	Choice       int
	E1634Address *ExtendedNetworkAddressE1634Address `json:"E1634Address,omitempty"`
	PsapAddress  *PresentationAddress                `json:"PsapAddress,omitempty"`
}

// NewExtendedNetworkAddressE1634Address creates a ExtendedNetworkAddress with the e163-4-address alternative.
func NewExtendedNetworkAddressE1634Address(v ExtendedNetworkAddressE1634Address) ExtendedNetworkAddress {
	return ExtendedNetworkAddress{
		Choice:       ExtendedNetworkAddressChoiceE1634Address,
		E1634Address: &v,
	}
}

// NewExtendedNetworkAddressPsapAddress creates a ExtendedNetworkAddress with the psap-address alternative.
func NewExtendedNetworkAddressPsapAddress(v PresentationAddress) ExtendedNetworkAddress {
	return ExtendedNetworkAddress{
		Choice:      ExtendedNetworkAddressChoicePsapAddress,
		PsapAddress: &v,
	}
}

// PresentationAddress represents the ASN.1 type PresentationAddress (SEQUENCE).
type PresentationAddress struct {
	PSelector        []byte                        `asn1:"tag:0,context,explicit,optional" json:"PSelector,omitempty"`
	SSelector        []byte                        `asn1:"tag:1,context,explicit,optional" json:"SSelector,omitempty"`
	TSelector        []byte                        `asn1:"tag:2,context,explicit,optional" json:"TSelector,omitempty"`
	NAddresses       PresentationAddressNAddresses `asn1:"tag:3,context,explicit"`
	NAddressesIndef_ bool                          `asn1:"-" json:"-"`
}

// TerminalType represents the ASN.1 INTEGER type TerminalType with named numbers.
type TerminalType int64

const (
	TerminalTypeTelex       TerminalType = 3
	TerminalTypeTeletex     TerminalType = 4
	TerminalTypeG3Facsimile TerminalType = 5
	TerminalTypeG4Facsimile TerminalType = 6
	TerminalTypeIa5Terminal TerminalType = 7
	TerminalTypeVideotex    TerminalType = 8
)

func (v TerminalType) String() string {
	switch v {
	case TerminalTypeTelex:
		return "telex"
	case TerminalTypeTeletex:
		return "teletex"
	case TerminalTypeG3Facsimile:
		return "g3-facsimile"
	case TerminalTypeG4Facsimile:
		return "g4-facsimile"
	case TerminalTypeIa5Terminal:
		return "ia5-terminal"
	case TerminalTypeVideotex:
		return "videotex"
	default:
		return "unknown"
	}
}

// TeletexDomainDefinedAttributes represents the ASN.1 type TeletexDomainDefinedAttributes (SEQUENCE_OF).
type TeletexDomainDefinedAttributes = []TeletexDomainDefinedAttribute

// TeletexDomainDefinedAttribute represents the ASN.1 type TeletexDomainDefinedAttribute (SEQUENCE).
type TeletexDomainDefinedAttribute struct {
	Type  string `asn1:""`
	Value string `asn1:""`
}

// AttributeValues represents the ASN.1 type Attribute-values (SET_OF).
type AttributeValues = []AttributeValue

// TBSCertListRevokedCertificatesElem represents the ASN.1 type TBSCertList-revokedCertificates-Elem (SEQUENCE).
type TBSCertListRevokedCertificatesElem struct {
	UserCertificate          CertificateSerialNumber `asn1:""`
	RevocationDate           Time                    `asn1:""`
	CrlEntryExtensions       Extensions              `asn1:",optional" json:"CrlEntryExtensions,omitempty"`
	CrlEntryExtensionsIndef_ bool                    `asn1:"-" json:"-"`
}

// TBSCertListRevokedCertificates represents the ASN.1 type TBSCertList-revokedCertificates (SEQUENCE_OF).
type TBSCertListRevokedCertificates = []TBSCertListRevokedCertificatesElem

// UnformattedPostalAddressPrintableAddress represents the ASN.1 type UnformattedPostalAddress-printable-address (SEQUENCE_OF).
type UnformattedPostalAddressPrintableAddress = []string

// ExtendedNetworkAddressE1634Address represents the ASN.1 type ExtendedNetworkAddress-e163-4-address (SEQUENCE).
type ExtendedNetworkAddressE1634Address struct {
	Number     string  `asn1:"tag:0,context,implicit"`
	SubAddress *string `asn1:"tag:1,context,implicit,optional" json:"SubAddress,omitempty"`
}

// PresentationAddressNAddresses represents the ASN.1 type PresentationAddress-nAddresses (SET_OF).
type PresentationAddressNAddresses = [][]byte

// MarshalBER encodes Attribute to BER format.
func (v *Attribute) MarshalBER() ([]byte, error) {
	var children []byte
	enc_type := ber.EncodeObjectIdentifier([]uint64(v.Type))
	children = append(children, enc_type...)
	enc_values, err := MarshalBERAttributeValues(v.Values)
	if err != nil {
		return nil, fmt.Errorf("encoding values: %w", err)
	}
	children = append(children, enc_values...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Attribute to DER format.
func (v *Attribute) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Attribute from BER/DER format.
func (v *Attribute) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Attribute SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Attribute", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode type
	if offset >= len(content) {
		return fmt.Errorf("missing required field type")
	}
	val_type, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding type: %w", err)
	}
	v.Type = runtime.ObjectIdentifier(val_type)
	offset += n
	// Decode values
	if offset >= len(content) {
		return fmt.Errorf("missing required field values")
	}
	// Decode nested SET_OF (AttributeValues)
	_, n_values, _, tlvErr_values := ber.DecodeTLV(content[offset:])
	if tlvErr_values != nil {
		return fmt.Errorf("decoding values: %w", tlvErr_values)
	}
	dec_values, unmErr := UnmarshalBERAttributeValues(content[offset : offset+n_values])
	if unmErr != nil {
		return fmt.Errorf("decoding values: %w", unmErr)
	}
	v.Values = dec_values
	offset += n_values
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Attribute", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AttributeTypeAndValue to BER format.
func (v *AttributeTypeAndValue) MarshalBER() ([]byte, error) {
	var children []byte
	enc_type := ber.EncodeObjectIdentifier([]uint64(v.Type))
	children = append(children, enc_type...)
	enc_value := v.Value.Bytes
	children = append(children, enc_value...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AttributeTypeAndValue to DER format.
func (v *AttributeTypeAndValue) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AttributeTypeAndValue from BER/DER format.
func (v *AttributeTypeAndValue) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AttributeTypeAndValue SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AttributeTypeAndValue", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode type
	if offset >= len(content) {
		return fmt.Errorf("missing required field type")
	}
	val_type, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding type: %w", err)
	}
	v.Type = runtime.ObjectIdentifier(val_type)
	offset += n
	// Decode value
	if offset >= len(content) {
		return fmt.Errorf("missing required field value")
	}
	_, n_value, _, tlvErr_value := ber.DecodeTLV(content[offset:])
	if tlvErr_value != nil {
		return fmt.Errorf("decoding value: %w", tlvErr_value)
	}
	v.Value = runtime.RawValue{Bytes: content[offset : offset+n_value]}
	offset += n_value
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AttributeTypeAndValue", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes X520name to BER format.
func (v *X520name) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case X520nameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("choice X520name: teletexString is nil")
		}
		enc_0 := ber.EncodeStringTag(20, *v.TeletexString)
		return enc_0, nil
	case X520nameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("choice X520name: printableString is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.PrintableString)
		return enc_1, nil
	case X520nameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("choice X520name: universalString is nil")
		}
		enc_2 := ber.EncodeStringTag(28, *v.UniversalString)
		return enc_2, nil
	case X520nameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("choice X520name: utf8String is nil")
		}
		enc_3 := ber.EncodeStringTag(12, *v.Utf8String)
		return enc_3, nil
	case X520nameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("choice X520name: bmpString is nil")
		}
		enc_4 := ber.EncodeStringTag(30, *v.BmpString)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520name", v.Choice)
	}
}

// MarshalDER encodes X520name to DER format.
func (v *X520name) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes X520name from BER/DER format.
func (v *X520name) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520name CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520name: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520name CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520name", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520nameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520nameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520nameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520nameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520nameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for X520name CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520CommonName to BER format.
func (v *X520CommonName) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case X520CommonNameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("choice X520CommonName: teletexString is nil")
		}
		enc_0 := ber.EncodeStringTag(20, *v.TeletexString)
		return enc_0, nil
	case X520CommonNameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("choice X520CommonName: printableString is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.PrintableString)
		return enc_1, nil
	case X520CommonNameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("choice X520CommonName: universalString is nil")
		}
		enc_2 := ber.EncodeStringTag(28, *v.UniversalString)
		return enc_2, nil
	case X520CommonNameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("choice X520CommonName: utf8String is nil")
		}
		enc_3 := ber.EncodeStringTag(12, *v.Utf8String)
		return enc_3, nil
	case X520CommonNameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("choice X520CommonName: bmpString is nil")
		}
		enc_4 := ber.EncodeStringTag(30, *v.BmpString)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520CommonName", v.Choice)
	}
}

// MarshalDER encodes X520CommonName to DER format.
func (v *X520CommonName) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes X520CommonName from BER/DER format.
func (v *X520CommonName) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520CommonName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520CommonName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520CommonName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520CommonName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520CommonNameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520CommonNameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520CommonNameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520CommonNameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520CommonNameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for X520CommonName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520LocalityName to BER format.
func (v *X520LocalityName) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case X520LocalityNameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("choice X520LocalityName: teletexString is nil")
		}
		enc_0 := ber.EncodeStringTag(20, *v.TeletexString)
		return enc_0, nil
	case X520LocalityNameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("choice X520LocalityName: printableString is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.PrintableString)
		return enc_1, nil
	case X520LocalityNameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("choice X520LocalityName: universalString is nil")
		}
		enc_2 := ber.EncodeStringTag(28, *v.UniversalString)
		return enc_2, nil
	case X520LocalityNameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("choice X520LocalityName: utf8String is nil")
		}
		enc_3 := ber.EncodeStringTag(12, *v.Utf8String)
		return enc_3, nil
	case X520LocalityNameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("choice X520LocalityName: bmpString is nil")
		}
		enc_4 := ber.EncodeStringTag(30, *v.BmpString)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520LocalityName", v.Choice)
	}
}

// MarshalDER encodes X520LocalityName to DER format.
func (v *X520LocalityName) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes X520LocalityName from BER/DER format.
func (v *X520LocalityName) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520LocalityName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520LocalityName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520LocalityName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520LocalityName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520LocalityNameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520LocalityNameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520LocalityNameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520LocalityNameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520LocalityNameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for X520LocalityName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520StateOrProvinceName to BER format.
func (v *X520StateOrProvinceName) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case X520StateOrProvinceNameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("choice X520StateOrProvinceName: teletexString is nil")
		}
		enc_0 := ber.EncodeStringTag(20, *v.TeletexString)
		return enc_0, nil
	case X520StateOrProvinceNameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("choice X520StateOrProvinceName: printableString is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.PrintableString)
		return enc_1, nil
	case X520StateOrProvinceNameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("choice X520StateOrProvinceName: universalString is nil")
		}
		enc_2 := ber.EncodeStringTag(28, *v.UniversalString)
		return enc_2, nil
	case X520StateOrProvinceNameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("choice X520StateOrProvinceName: utf8String is nil")
		}
		enc_3 := ber.EncodeStringTag(12, *v.Utf8String)
		return enc_3, nil
	case X520StateOrProvinceNameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("choice X520StateOrProvinceName: bmpString is nil")
		}
		enc_4 := ber.EncodeStringTag(30, *v.BmpString)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520StateOrProvinceName", v.Choice)
	}
}

// MarshalDER encodes X520StateOrProvinceName to DER format.
func (v *X520StateOrProvinceName) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes X520StateOrProvinceName from BER/DER format.
func (v *X520StateOrProvinceName) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520StateOrProvinceName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520StateOrProvinceName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520StateOrProvinceName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520StateOrProvinceName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520StateOrProvinceNameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520StateOrProvinceNameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520StateOrProvinceNameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520StateOrProvinceNameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520StateOrProvinceNameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for X520StateOrProvinceName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520OrganizationName to BER format.
func (v *X520OrganizationName) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case X520OrganizationNameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("choice X520OrganizationName: teletexString is nil")
		}
		enc_0 := ber.EncodeStringTag(20, *v.TeletexString)
		return enc_0, nil
	case X520OrganizationNameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("choice X520OrganizationName: printableString is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.PrintableString)
		return enc_1, nil
	case X520OrganizationNameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("choice X520OrganizationName: universalString is nil")
		}
		enc_2 := ber.EncodeStringTag(28, *v.UniversalString)
		return enc_2, nil
	case X520OrganizationNameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("choice X520OrganizationName: utf8String is nil")
		}
		enc_3 := ber.EncodeStringTag(12, *v.Utf8String)
		return enc_3, nil
	case X520OrganizationNameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("choice X520OrganizationName: bmpString is nil")
		}
		enc_4 := ber.EncodeStringTag(30, *v.BmpString)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520OrganizationName", v.Choice)
	}
}

// MarshalDER encodes X520OrganizationName to DER format.
func (v *X520OrganizationName) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes X520OrganizationName from BER/DER format.
func (v *X520OrganizationName) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520OrganizationName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520OrganizationName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520OrganizationName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520OrganizationName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520OrganizationNameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520OrganizationNameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520OrganizationNameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520OrganizationNameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520OrganizationNameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for X520OrganizationName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520OrganizationalUnitName to BER format.
func (v *X520OrganizationalUnitName) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case X520OrganizationalUnitNameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("choice X520OrganizationalUnitName: teletexString is nil")
		}
		enc_0 := ber.EncodeStringTag(20, *v.TeletexString)
		return enc_0, nil
	case X520OrganizationalUnitNameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("choice X520OrganizationalUnitName: printableString is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.PrintableString)
		return enc_1, nil
	case X520OrganizationalUnitNameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("choice X520OrganizationalUnitName: universalString is nil")
		}
		enc_2 := ber.EncodeStringTag(28, *v.UniversalString)
		return enc_2, nil
	case X520OrganizationalUnitNameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("choice X520OrganizationalUnitName: utf8String is nil")
		}
		enc_3 := ber.EncodeStringTag(12, *v.Utf8String)
		return enc_3, nil
	case X520OrganizationalUnitNameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("choice X520OrganizationalUnitName: bmpString is nil")
		}
		enc_4 := ber.EncodeStringTag(30, *v.BmpString)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520OrganizationalUnitName", v.Choice)
	}
}

// MarshalDER encodes X520OrganizationalUnitName to DER format.
func (v *X520OrganizationalUnitName) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes X520OrganizationalUnitName from BER/DER format.
func (v *X520OrganizationalUnitName) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520OrganizationalUnitName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520OrganizationalUnitName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520OrganizationalUnitName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520OrganizationalUnitName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520OrganizationalUnitNameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520OrganizationalUnitNameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520OrganizationalUnitNameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520OrganizationalUnitNameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520OrganizationalUnitNameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for X520OrganizationalUnitName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520Title to BER format.
func (v *X520Title) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case X520TitleChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("choice X520Title: teletexString is nil")
		}
		enc_0 := ber.EncodeStringTag(20, *v.TeletexString)
		return enc_0, nil
	case X520TitleChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("choice X520Title: printableString is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.PrintableString)
		return enc_1, nil
	case X520TitleChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("choice X520Title: universalString is nil")
		}
		enc_2 := ber.EncodeStringTag(28, *v.UniversalString)
		return enc_2, nil
	case X520TitleChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("choice X520Title: utf8String is nil")
		}
		enc_3 := ber.EncodeStringTag(12, *v.Utf8String)
		return enc_3, nil
	case X520TitleChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("choice X520Title: bmpString is nil")
		}
		enc_4 := ber.EncodeStringTag(30, *v.BmpString)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520Title", v.Choice)
	}
}

// MarshalDER encodes X520Title to DER format.
func (v *X520Title) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes X520Title from BER/DER format.
func (v *X520Title) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520Title CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520Title: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520Title CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520Title", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520TitleChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520TitleChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520TitleChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520TitleChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520TitleChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for X520Title CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520Pseudonym to BER format.
func (v *X520Pseudonym) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case X520PseudonymChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("choice X520Pseudonym: teletexString is nil")
		}
		enc_0 := ber.EncodeStringTag(20, *v.TeletexString)
		return enc_0, nil
	case X520PseudonymChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("choice X520Pseudonym: printableString is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.PrintableString)
		return enc_1, nil
	case X520PseudonymChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("choice X520Pseudonym: universalString is nil")
		}
		enc_2 := ber.EncodeStringTag(28, *v.UniversalString)
		return enc_2, nil
	case X520PseudonymChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("choice X520Pseudonym: utf8String is nil")
		}
		enc_3 := ber.EncodeStringTag(12, *v.Utf8String)
		return enc_3, nil
	case X520PseudonymChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("choice X520Pseudonym: bmpString is nil")
		}
		enc_4 := ber.EncodeStringTag(30, *v.BmpString)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520Pseudonym", v.Choice)
	}
}

// MarshalDER encodes X520Pseudonym to DER format.
func (v *X520Pseudonym) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes X520Pseudonym from BER/DER format.
func (v *X520Pseudonym) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520Pseudonym CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520Pseudonym: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520Pseudonym CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520Pseudonym", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520PseudonymChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520PseudonymChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520PseudonymChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520PseudonymChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520PseudonymChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for X520Pseudonym CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Name to BER format.
func (v *Name) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case NameChoiceRdnSequence:
		if v.RdnSequence == nil {
			return nil, fmt.Errorf("choice Name: rdnSequence is nil")
		}
		enc_0, err := MarshalBERRDNSequence(v.RdnSequence)
		if err != nil {
			return nil, fmt.Errorf("encoding rdnSequence: %w", err)
		}
		return enc_0, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Name", v.Choice)
	}
}

// MarshalDER encodes Name to DER format.
func (v *Name) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes Name from BER/DER format.
func (v *Name) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Name CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Name: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Name CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Name", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = NameChoiceRdnSequence
		dec, unmErr := UnmarshalBERRDNSequence(choiceData)
		if unmErr != nil {
			return fmt.Errorf("decoding rdnSequence: %w", unmErr)
		}
		v.RdnSequence = dec
	} else {
		return fmt.Errorf("unknown tag %s for Name CHOICE", peekTag)
	}
	return nil
}

// MarshalBERRDNSequence encodes a RDNSequence list to BER.
func MarshalBERRDNSequence(list RDNSequence) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := MarshalBERRelativeDistinguishedName(elem)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERRDNSequence decodes a RDNSequence list from BER.
func UnmarshalBERRDNSequence(data []byte) (RDNSequence, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RDNSequence: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RDNSequence", Cause: ber.ErrExtraData}
	}
	var result RDNSequence
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		elem, unmErr := UnmarshalBERRelativeDistinguishedName(content[offset : offset+n])
		if unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBERRelativeDistinguishedName encodes a RelativeDistinguishedName list to BER.
func MarshalBERRelativeDistinguishedName(list RelativeDistinguishedName) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSet(children), nil
}

// UnmarshalBERRelativeDistinguishedName decodes a RelativeDistinguishedName list from BER.
func UnmarshalBERRelativeDistinguishedName(data []byte) (RelativeDistinguishedName, error) {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RelativeDistinguishedName: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding RelativeDistinguishedName: %w: expected SET, got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RelativeDistinguishedName", Cause: ber.ErrExtraData}
	}
	var result RelativeDistinguishedName
	offset := 0
	for offset < len(content) {
		var elem AttributeTypeAndValue
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes DirectoryString to BER format.
func (v *DirectoryString) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case DirectoryStringChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("choice DirectoryString: teletexString is nil")
		}
		enc_0 := ber.EncodeStringTag(20, *v.TeletexString)
		return enc_0, nil
	case DirectoryStringChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("choice DirectoryString: printableString is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.PrintableString)
		return enc_1, nil
	case DirectoryStringChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("choice DirectoryString: universalString is nil")
		}
		enc_2 := ber.EncodeStringTag(28, *v.UniversalString)
		return enc_2, nil
	case DirectoryStringChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("choice DirectoryString: utf8String is nil")
		}
		enc_3 := ber.EncodeStringTag(12, *v.Utf8String)
		return enc_3, nil
	case DirectoryStringChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("choice DirectoryString: bmpString is nil")
		}
		enc_4 := ber.EncodeStringTag(30, *v.BmpString)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DirectoryString", v.Choice)
	}
}

// MarshalDER encodes DirectoryString to DER format.
func (v *DirectoryString) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes DirectoryString from BER/DER format.
func (v *DirectoryString) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for DirectoryString CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DirectoryString: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding DirectoryString CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DirectoryString", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = DirectoryStringChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = DirectoryStringChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = DirectoryStringChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = DirectoryStringChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = DirectoryStringChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for DirectoryString CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Certificate to BER format.
func (v *Certificate) MarshalBER() ([]byte, error) {
	var children []byte
	enc_tbscertificate, err := v.TbsCertificate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding tbsCertificate: %w", err)
	}
	children = append(children, enc_tbscertificate...)
	enc_signaturealgorithm, err := v.SignatureAlgorithm.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding signatureAlgorithm: %w", err)
	}
	children = append(children, enc_signaturealgorithm...)
	enc_signature := ber.EncodeBitString(v.Signature.Bytes, (8-(v.Signature.BitLength%8))%8)
	children = append(children, enc_signature...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Certificate to DER format.
func (v *Certificate) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Certificate from BER/DER format.
func (v *Certificate) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Certificate SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Certificate", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode tbsCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field tbsCertificate")
	}
	// Decode nested SEQUENCE (TBSCertificate)
	_, n_tbscertificate, _, tlvErr_tbscertificate := ber.DecodeTLV(content[offset:])
	if tlvErr_tbscertificate != nil {
		return fmt.Errorf("decoding tbsCertificate: %w", tlvErr_tbscertificate)
	}
	if unmErr := v.TbsCertificate.UnmarshalBER(content[offset : offset+n_tbscertificate]); unmErr != nil {
		return fmt.Errorf("decoding tbsCertificate: %w", unmErr)
	}
	offset += n_tbscertificate
	// Decode signatureAlgorithm
	if offset >= len(content) {
		return fmt.Errorf("missing required field signatureAlgorithm")
	}
	// Decode nested SEQUENCE (AlgorithmIdentifier)
	_, n_signaturealgorithm, _, tlvErr_signaturealgorithm := ber.DecodeTLV(content[offset:])
	if tlvErr_signaturealgorithm != nil {
		return fmt.Errorf("decoding signatureAlgorithm: %w", tlvErr_signaturealgorithm)
	}
	if unmErr := v.SignatureAlgorithm.UnmarshalBER(content[offset : offset+n_signaturealgorithm]); unmErr != nil {
		return fmt.Errorf("decoding signatureAlgorithm: %w", unmErr)
	}
	offset += n_signaturealgorithm
	// Decode signature
	if offset >= len(content) {
		return fmt.Errorf("missing required field signature")
	}
	bsBytes_signature, bsUnused_signature, n, err := ber.DecodeBitString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	v.Signature = runtime.BitString{Bytes: bsBytes_signature, BitLength: len(bsBytes_signature)*8 - bsUnused_signature}
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Certificate", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TBSCertificate to BER format.
func (v *TBSCertificate) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Version != nil {
		enc_version := ber.EncodeInteger(int64(*v.Version))
		enc_version = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_version)
		children = append(children, enc_version...)
	}
	if v.SerialNumber == nil {
		return nil, fmt.Errorf("encoding serialNumber: required INTEGER is nil")
	}
	enc_serialnumber := ber.EncodeBigInt(v.SerialNumber)
	children = append(children, enc_serialnumber...)
	enc_signature, err := v.Signature.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding signature: %w", err)
	}
	children = append(children, enc_signature...)
	enc_issuer, err := v.Issuer.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding issuer: %w", err)
	}
	children = append(children, enc_issuer...)
	enc_validity, err := v.Validity.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding validity: %w", err)
	}
	children = append(children, enc_validity...)
	enc_subject, err := v.Subject.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding subject: %w", err)
	}
	children = append(children, enc_subject...)
	enc_subjectpublickeyinfo, err := v.SubjectPublicKeyInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding subjectPublicKeyInfo: %w", err)
	}
	children = append(children, enc_subjectpublickeyinfo...)
	if v.IssuerUniqueID != nil {
		enc_issueruniqueid := ber.EncodeBitString(v.IssuerUniqueID.Bytes, (8-(v.IssuerUniqueID.BitLength%8))%8)
		enc_issueruniqueid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_issueruniqueid)
		children = append(children, enc_issueruniqueid...)
	}
	if v.SubjectUniqueID != nil {
		enc_subjectuniqueid := ber.EncodeBitString(v.SubjectUniqueID.Bytes, (8-(v.SubjectUniqueID.BitLength%8))%8)
		enc_subjectuniqueid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_subjectuniqueid)
		children = append(children, enc_subjectuniqueid...)
	}
	if v.Extensions != nil {
		enc_extensions, err := MarshalBERExtensions(v.Extensions)
		if err != nil {
			return nil, fmt.Errorf("encoding extensions: %w", err)
		}
		enc_extensions = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensions)
		children = append(children, enc_extensions...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes TBSCertificate to DER format.
func (v *TBSCertificate) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TBSCertificate from BER/DER format.
func (v *TBSCertificate) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TBSCertificate SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TBSCertificate", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode version
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_version, innerData_version, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding version: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				val_version, _, err := ber.DecodeInteger(innerData_version)
				if err != nil {
					return fmt.Errorf("decoding version: %w", err)
				}
				tmp_version := Version(val_version)
				v.Version = &tmp_version
				offset += n_version
			}
		}
	}
	// Decode serialNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field serialNumber")
	}
	val_serialnumber, n, err := ber.DecodeBigInt(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serialNumber: %w", err)
	}
	v.SerialNumber = val_serialnumber
	offset += n
	// Decode signature
	if offset >= len(content) {
		return fmt.Errorf("missing required field signature")
	}
	// Decode nested SEQUENCE (AlgorithmIdentifier)
	_, n_signature, _, tlvErr_signature := ber.DecodeTLV(content[offset:])
	if tlvErr_signature != nil {
		return fmt.Errorf("decoding signature: %w", tlvErr_signature)
	}
	if unmErr := v.Signature.UnmarshalBER(content[offset : offset+n_signature]); unmErr != nil {
		return fmt.Errorf("decoding signature: %w", unmErr)
	}
	offset += n_signature
	// Decode issuer
	if offset >= len(content) {
		return fmt.Errorf("missing required field issuer")
	}
	// Decode nested CHOICE (Name)
	_, n_issuer, _, tlvErr_issuer := ber.DecodeTLV(content[offset:])
	if tlvErr_issuer != nil {
		return fmt.Errorf("decoding issuer: %w", tlvErr_issuer)
	}
	if unmErr := v.Issuer.UnmarshalBER(content[offset : offset+n_issuer]); unmErr != nil {
		return fmt.Errorf("decoding issuer: %w", unmErr)
	}
	offset += n_issuer
	// Decode validity
	if offset >= len(content) {
		return fmt.Errorf("missing required field validity")
	}
	// Decode nested SEQUENCE (Validity)
	_, n_validity, _, tlvErr_validity := ber.DecodeTLV(content[offset:])
	if tlvErr_validity != nil {
		return fmt.Errorf("decoding validity: %w", tlvErr_validity)
	}
	if unmErr := v.Validity.UnmarshalBER(content[offset : offset+n_validity]); unmErr != nil {
		return fmt.Errorf("decoding validity: %w", unmErr)
	}
	offset += n_validity
	// Decode subject
	if offset >= len(content) {
		return fmt.Errorf("missing required field subject")
	}
	// Decode nested CHOICE (Name)
	_, n_subject, _, tlvErr_subject := ber.DecodeTLV(content[offset:])
	if tlvErr_subject != nil {
		return fmt.Errorf("decoding subject: %w", tlvErr_subject)
	}
	if unmErr := v.Subject.UnmarshalBER(content[offset : offset+n_subject]); unmErr != nil {
		return fmt.Errorf("decoding subject: %w", unmErr)
	}
	offset += n_subject
	// Decode subjectPublicKeyInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field subjectPublicKeyInfo")
	}
	// Decode nested SEQUENCE (SubjectPublicKeyInfo)
	_, n_subjectpublickeyinfo, _, tlvErr_subjectpublickeyinfo := ber.DecodeTLV(content[offset:])
	if tlvErr_subjectpublickeyinfo != nil {
		return fmt.Errorf("decoding subjectPublicKeyInfo: %w", tlvErr_subjectpublickeyinfo)
	}
	if unmErr := v.SubjectPublicKeyInfo.UnmarshalBER(content[offset : offset+n_subjectpublickeyinfo]); unmErr != nil {
		return fmt.Errorf("decoding subjectPublicKeyInfo: %w", unmErr)
	}
	offset += n_subjectpublickeyinfo
	// Decode issuerUniqueID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_issueruniqueid, rawVal_issueruniqueid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding issuerUniqueID: %w", err)
				}
				bsBytes_issueruniqueid, bsUnused_issueruniqueid, bsErr := ber.DecodeBitStringValue(rawVal_issueruniqueid)
				if bsErr != nil {
					return fmt.Errorf("decoding issuerUniqueID: %w", bsErr)
				}
				tmp_issueruniqueid := runtime.BitString{Bytes: bsBytes_issueruniqueid, BitLength: len(bsBytes_issueruniqueid)*8 - bsUnused_issueruniqueid}
				v.IssuerUniqueID = &tmp_issueruniqueid
				offset += n_issueruniqueid
			}
		}
	}
	// Decode subjectUniqueID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_subjectuniqueid, rawVal_subjectuniqueid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding subjectUniqueID: %w", err)
				}
				bsBytes_subjectuniqueid, bsUnused_subjectuniqueid, bsErr := ber.DecodeBitStringValue(rawVal_subjectuniqueid)
				if bsErr != nil {
					return fmt.Errorf("decoding subjectUniqueID: %w", bsErr)
				}
				tmp_subjectuniqueid := runtime.BitString{Bytes: bsBytes_subjectuniqueid, BitLength: len(bsBytes_subjectuniqueid)*8 - bsUnused_subjectuniqueid}
				v.SubjectUniqueID = &tmp_subjectuniqueid
				offset += n_subjectuniqueid
			}
		}
	}
	// Decode extensions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_extensions, innerData_extensions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensions: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				dec_extensions, unmErr := UnmarshalBERExtensions(innerData_extensions)
				if unmErr != nil {
					return fmt.Errorf("decoding extensions: %w", unmErr)
				}
				v.Extensions = dec_extensions
				offset += n_extensions
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TBSCertificate", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Validity to BER format.
func (v *Validity) MarshalBER() ([]byte, error) {
	var children []byte
	enc_notbefore, err := v.NotBefore.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding notBefore: %w", err)
	}
	children = append(children, enc_notbefore...)
	enc_notafter, err := v.NotAfter.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding notAfter: %w", err)
	}
	children = append(children, enc_notafter...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Validity to DER format.
func (v *Validity) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Validity from BER/DER format.
func (v *Validity) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Validity SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Validity", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode notBefore
	if offset >= len(content) {
		return fmt.Errorf("missing required field notBefore")
	}
	// Decode nested CHOICE (Time)
	_, n_notbefore, _, tlvErr_notbefore := ber.DecodeTLV(content[offset:])
	if tlvErr_notbefore != nil {
		return fmt.Errorf("decoding notBefore: %w", tlvErr_notbefore)
	}
	if unmErr := v.NotBefore.UnmarshalBER(content[offset : offset+n_notbefore]); unmErr != nil {
		return fmt.Errorf("decoding notBefore: %w", unmErr)
	}
	offset += n_notbefore
	// Decode notAfter
	if offset >= len(content) {
		return fmt.Errorf("missing required field notAfter")
	}
	// Decode nested CHOICE (Time)
	_, n_notafter, _, tlvErr_notafter := ber.DecodeTLV(content[offset:])
	if tlvErr_notafter != nil {
		return fmt.Errorf("decoding notAfter: %w", tlvErr_notafter)
	}
	if unmErr := v.NotAfter.UnmarshalBER(content[offset : offset+n_notafter]); unmErr != nil {
		return fmt.Errorf("decoding notAfter: %w", unmErr)
	}
	offset += n_notafter
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Validity", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Time to BER format.
func (v *Time) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case TimeChoiceUtcTime:
		if v.UtcTime == nil {
			return nil, fmt.Errorf("choice Time: utcTime is nil")
		}
		enc_0 := ber.EncodeUTCTime(*v.UtcTime)
		return enc_0, nil
	case TimeChoiceGeneralTime:
		if v.GeneralTime == nil {
			return nil, fmt.Errorf("choice Time: generalTime is nil")
		}
		enc_1 := ber.EncodeGeneralizedTime(*v.GeneralTime)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Time", v.Choice)
	}
}

// MarshalDER encodes Time to DER format.
func (v *Time) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes Time from BER/DER format.
func (v *Time) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Time CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Time: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Time CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Time", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 23 {
		v.Choice = TimeChoiceUtcTime
		decVal, _, timeErr := ber.DecodeUTCTime(choiceData)
		if timeErr != nil {
			return fmt.Errorf("decoding utcTime: %w", timeErr)
		}
		v.UtcTime = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 24 {
		v.Choice = TimeChoiceGeneralTime
		decVal, _, timeErr := ber.DecodeGeneralizedTime(choiceData)
		if timeErr != nil {
			return fmt.Errorf("decoding generalTime: %w", timeErr)
		}
		v.GeneralTime = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for Time CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SubjectPublicKeyInfo to BER format.
func (v *SubjectPublicKeyInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_algorithm, err := v.Algorithm.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding algorithm: %w", err)
	}
	children = append(children, enc_algorithm...)
	enc_subjectpublickey := ber.EncodeBitString(v.SubjectPublicKey.Bytes, (8-(v.SubjectPublicKey.BitLength%8))%8)
	children = append(children, enc_subjectpublickey...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SubjectPublicKeyInfo to DER format.
func (v *SubjectPublicKeyInfo) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SubjectPublicKeyInfo from BER/DER format.
func (v *SubjectPublicKeyInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SubjectPublicKeyInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SubjectPublicKeyInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode algorithm
	if offset >= len(content) {
		return fmt.Errorf("missing required field algorithm")
	}
	// Decode nested SEQUENCE (AlgorithmIdentifier)
	_, n_algorithm, _, tlvErr_algorithm := ber.DecodeTLV(content[offset:])
	if tlvErr_algorithm != nil {
		return fmt.Errorf("decoding algorithm: %w", tlvErr_algorithm)
	}
	if unmErr := v.Algorithm.UnmarshalBER(content[offset : offset+n_algorithm]); unmErr != nil {
		return fmt.Errorf("decoding algorithm: %w", unmErr)
	}
	offset += n_algorithm
	// Decode subjectPublicKey
	if offset >= len(content) {
		return fmt.Errorf("missing required field subjectPublicKey")
	}
	bsBytes_subjectpublickey, bsUnused_subjectpublickey, n, err := ber.DecodeBitString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding subjectPublicKey: %w", err)
	}
	v.SubjectPublicKey = runtime.BitString{Bytes: bsBytes_subjectpublickey, BitLength: len(bsBytes_subjectpublickey)*8 - bsUnused_subjectpublickey}
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SubjectPublicKeyInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERExtensions encodes a Extensions list to BER.
func MarshalBERExtensions(list Extensions) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERExtensions decodes a Extensions list from BER.
func UnmarshalBERExtensions(data []byte) (Extensions, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding Extensions: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "Extensions", Cause: ber.ErrExtraData}
	}
	var result Extensions
	offset := 0
	for offset < len(content) {
		var elem Extension
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes Extension to BER format.
func (v *Extension) MarshalBER() ([]byte, error) {
	var children []byte
	enc_extnid := ber.EncodeObjectIdentifier([]uint64(v.ExtnID))
	children = append(children, enc_extnid...)
	if v.Critical != nil {
		var enc_critical []byte
		if v.CriticalRaw_ != 0 {
			enc_critical = ber.EncodeBooleanRaw(v.CriticalRaw_)
		} else {
			enc_critical = ber.EncodeBoolean(*v.Critical)
		}
		children = append(children, enc_critical...)
	}
	enc_extnvalue := ber.EncodeOctetString(v.ExtnValue)
	children = append(children, enc_extnvalue...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Extension to DER format.
func (v *Extension) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Extension from BER/DER format.
func (v *Extension) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Extension SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Extension", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extnID
	if offset >= len(content) {
		return fmt.Errorf("missing required field extnID")
	}
	val_extnid, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding extnID: %w", err)
	}
	v.ExtnID = runtime.ObjectIdentifier(val_extnid)
	offset += n
	// Decode critical
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 1 {
				val_critical, raw_critical, n, err := ber.DecodeBoolean(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding critical: %w", err)
				}
				v.Critical = &val_critical
				v.CriticalRaw_ = raw_critical
				offset += n
			}
		}
	}
	// Decode extnValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field extnValue")
	}
	val_extnvalue, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding extnValue: %w", err)
	}
	v.ExtnValue = val_extnvalue
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Extension", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CertificateList to BER format.
func (v *CertificateList) MarshalBER() ([]byte, error) {
	var children []byte
	enc_tbscertlist, err := v.TbsCertList.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding tbsCertList: %w", err)
	}
	children = append(children, enc_tbscertlist...)
	enc_signaturealgorithm, err := v.SignatureAlgorithm.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding signatureAlgorithm: %w", err)
	}
	children = append(children, enc_signaturealgorithm...)
	enc_signature := ber.EncodeBitString(v.Signature.Bytes, (8-(v.Signature.BitLength%8))%8)
	children = append(children, enc_signature...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CertificateList to DER format.
func (v *CertificateList) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CertificateList from BER/DER format.
func (v *CertificateList) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CertificateList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CertificateList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode tbsCertList
	if offset >= len(content) {
		return fmt.Errorf("missing required field tbsCertList")
	}
	// Decode nested SEQUENCE (TBSCertList)
	_, n_tbscertlist, _, tlvErr_tbscertlist := ber.DecodeTLV(content[offset:])
	if tlvErr_tbscertlist != nil {
		return fmt.Errorf("decoding tbsCertList: %w", tlvErr_tbscertlist)
	}
	if unmErr := v.TbsCertList.UnmarshalBER(content[offset : offset+n_tbscertlist]); unmErr != nil {
		return fmt.Errorf("decoding tbsCertList: %w", unmErr)
	}
	offset += n_tbscertlist
	// Decode signatureAlgorithm
	if offset >= len(content) {
		return fmt.Errorf("missing required field signatureAlgorithm")
	}
	// Decode nested SEQUENCE (AlgorithmIdentifier)
	_, n_signaturealgorithm, _, tlvErr_signaturealgorithm := ber.DecodeTLV(content[offset:])
	if tlvErr_signaturealgorithm != nil {
		return fmt.Errorf("decoding signatureAlgorithm: %w", tlvErr_signaturealgorithm)
	}
	if unmErr := v.SignatureAlgorithm.UnmarshalBER(content[offset : offset+n_signaturealgorithm]); unmErr != nil {
		return fmt.Errorf("decoding signatureAlgorithm: %w", unmErr)
	}
	offset += n_signaturealgorithm
	// Decode signature
	if offset >= len(content) {
		return fmt.Errorf("missing required field signature")
	}
	bsBytes_signature, bsUnused_signature, n, err := ber.DecodeBitString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	v.Signature = runtime.BitString{Bytes: bsBytes_signature, BitLength: len(bsBytes_signature)*8 - bsUnused_signature}
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CertificateList", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TBSCertList to BER format.
func (v *TBSCertList) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Version != nil {
		enc_version := ber.EncodeInteger(int64(*v.Version))
		children = append(children, enc_version...)
	}
	enc_signature, err := v.Signature.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding signature: %w", err)
	}
	children = append(children, enc_signature...)
	enc_issuer, err := v.Issuer.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding issuer: %w", err)
	}
	children = append(children, enc_issuer...)
	enc_thisupdate, err := v.ThisUpdate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding thisUpdate: %w", err)
	}
	children = append(children, enc_thisupdate...)
	if v.NextUpdate != nil {
		enc_nextupdate, err := v.NextUpdate.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding nextUpdate: %w", err)
		}
		children = append(children, enc_nextupdate...)
	}
	if v.RevokedCertificates != nil {
		enc_revokedcertificates, err := MarshalBERTBSCertListRevokedCertificates(v.RevokedCertificates)
		if err != nil {
			return nil, fmt.Errorf("encoding revokedCertificates: %w", err)
		}
		children = append(children, enc_revokedcertificates...)
	}
	if v.CrlExtensions != nil {
		enc_crlextensions, err := MarshalBERExtensions(v.CrlExtensions)
		if err != nil {
			return nil, fmt.Errorf("encoding crlExtensions: %w", err)
		}
		enc_crlextensions = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_crlextensions)
		children = append(children, enc_crlextensions...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes TBSCertList to DER format.
func (v *TBSCertList) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TBSCertList from BER/DER format.
func (v *TBSCertList) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TBSCertList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TBSCertList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode version
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				val_version, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding version: %w", err)
				}
				tmp_version := Version(val_version)
				v.Version = &tmp_version
				offset += n
			}
		}
	}
	// Decode signature
	if offset >= len(content) {
		return fmt.Errorf("missing required field signature")
	}
	// Decode nested SEQUENCE (AlgorithmIdentifier)
	_, n_signature, _, tlvErr_signature := ber.DecodeTLV(content[offset:])
	if tlvErr_signature != nil {
		return fmt.Errorf("decoding signature: %w", tlvErr_signature)
	}
	if unmErr := v.Signature.UnmarshalBER(content[offset : offset+n_signature]); unmErr != nil {
		return fmt.Errorf("decoding signature: %w", unmErr)
	}
	offset += n_signature
	// Decode issuer
	if offset >= len(content) {
		return fmt.Errorf("missing required field issuer")
	}
	// Decode nested CHOICE (Name)
	_, n_issuer, _, tlvErr_issuer := ber.DecodeTLV(content[offset:])
	if tlvErr_issuer != nil {
		return fmt.Errorf("decoding issuer: %w", tlvErr_issuer)
	}
	if unmErr := v.Issuer.UnmarshalBER(content[offset : offset+n_issuer]); unmErr != nil {
		return fmt.Errorf("decoding issuer: %w", unmErr)
	}
	offset += n_issuer
	// Decode thisUpdate
	if offset >= len(content) {
		return fmt.Errorf("missing required field thisUpdate")
	}
	// Decode nested CHOICE (Time)
	_, n_thisupdate, _, tlvErr_thisupdate := ber.DecodeTLV(content[offset:])
	if tlvErr_thisupdate != nil {
		return fmt.Errorf("decoding thisUpdate: %w", tlvErr_thisupdate)
	}
	if unmErr := v.ThisUpdate.UnmarshalBER(content[offset : offset+n_thisupdate]); unmErr != nil {
		return fmt.Errorf("decoding thisUpdate: %w", unmErr)
	}
	offset += n_thisupdate
	// Decode nextUpdate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 23) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 24) {
				// Decode nested CHOICE (Time)
				_, n_nextupdate, _, tlvErr_nextupdate := ber.DecodeTLV(content[offset:])
				if tlvErr_nextupdate != nil {
					return fmt.Errorf("decoding nextUpdate: %w", tlvErr_nextupdate)
				}
				var dec_nextupdate Time
				if unmErr := dec_nextupdate.UnmarshalBER(content[offset : offset+n_nextupdate]); unmErr != nil {
					return fmt.Errorf("decoding nextUpdate: %w", unmErr)
				}
				v.NextUpdate = &dec_nextupdate
				offset += n_nextupdate
			}
		}
	}
	// Decode revokedCertificates
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (TBSCertListRevokedCertificates)
				_, n_revokedcertificates, _, tlvErr_revokedcertificates := ber.DecodeTLV(content[offset:])
				if tlvErr_revokedcertificates != nil {
					return fmt.Errorf("decoding revokedCertificates: %w", tlvErr_revokedcertificates)
				}
				dec_revokedcertificates, unmErr := UnmarshalBERTBSCertListRevokedCertificates(content[offset : offset+n_revokedcertificates])
				if unmErr != nil {
					return fmt.Errorf("decoding revokedCertificates: %w", unmErr)
				}
				v.RevokedCertificates = dec_revokedcertificates
				offset += n_revokedcertificates
			}
		}
	}
	// Decode crlExtensions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_crlextensions, innerData_crlextensions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding crlExtensions: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				dec_crlextensions, unmErr := UnmarshalBERExtensions(innerData_crlextensions)
				if unmErr != nil {
					return fmt.Errorf("decoding crlExtensions: %w", unmErr)
				}
				v.CrlExtensions = dec_crlextensions
				offset += n_crlextensions
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TBSCertList", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AlgorithmIdentifier to BER format.
func (v *AlgorithmIdentifier) MarshalBER() ([]byte, error) {
	var children []byte
	enc_algorithm := ber.EncodeObjectIdentifier([]uint64(v.Algorithm))
	children = append(children, enc_algorithm...)
	if v.Parameters != nil {
		enc_parameters := v.Parameters.Bytes
		children = append(children, enc_parameters...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AlgorithmIdentifier to DER format.
func (v *AlgorithmIdentifier) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AlgorithmIdentifier from BER/DER format.
func (v *AlgorithmIdentifier) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AlgorithmIdentifier SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AlgorithmIdentifier", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode algorithm
	if offset >= len(content) {
		return fmt.Errorf("missing required field algorithm")
	}
	val_algorithm, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding algorithm: %w", err)
	}
	v.Algorithm = runtime.ObjectIdentifier(val_algorithm)
	offset += n
	// Decode parameters
	if offset < len(content) {
		_, n_parameters, _, tlvErr_parameters := ber.DecodeTLV(content[offset:])
		if tlvErr_parameters != nil {
			return fmt.Errorf("decoding parameters: %w", tlvErr_parameters)
		}
		tmp_parameters := runtime.RawValue{Bytes: content[offset : offset+n_parameters]}
		v.Parameters = &tmp_parameters
		offset += n_parameters
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AlgorithmIdentifier", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ORAddress to BER format.
func (v *ORAddress) MarshalBER() ([]byte, error) {
	var children []byte
	enc_builtinstandardattributes, err := v.BuiltInStandardAttributes.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding built-in-standard-attributes: %w", err)
	}
	children = append(children, enc_builtinstandardattributes...)
	if v.BuiltInDomainDefinedAttributes != nil {
		enc_builtindomaindefinedattributes, err := MarshalBERBuiltInDomainDefinedAttributes(v.BuiltInDomainDefinedAttributes)
		if err != nil {
			return nil, fmt.Errorf("encoding built-in-domain-defined-attributes: %w", err)
		}
		children = append(children, enc_builtindomaindefinedattributes...)
	}
	if v.ExtensionAttributes != nil {
		enc_extensionattributes, err := MarshalBERExtensionAttributes(v.ExtensionAttributes)
		if err != nil {
			return nil, fmt.Errorf("encoding extension-attributes: %w", err)
		}
		children = append(children, enc_extensionattributes...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ORAddress to DER format.
func (v *ORAddress) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ORAddress from BER/DER format.
func (v *ORAddress) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ORAddress SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ORAddress", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode built-in-standard-attributes
	if offset >= len(content) {
		return fmt.Errorf("missing required field built-in-standard-attributes")
	}
	// Decode nested SEQUENCE (BuiltInStandardAttributes)
	_, n_builtinstandardattributes, _, tlvErr_builtinstandardattributes := ber.DecodeTLV(content[offset:])
	if tlvErr_builtinstandardattributes != nil {
		return fmt.Errorf("decoding built-in-standard-attributes: %w", tlvErr_builtinstandardattributes)
	}
	if unmErr := v.BuiltInStandardAttributes.UnmarshalBER(content[offset : offset+n_builtinstandardattributes]); unmErr != nil {
		return fmt.Errorf("decoding built-in-standard-attributes: %w", unmErr)
	}
	offset += n_builtinstandardattributes
	// Decode built-in-domain-defined-attributes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (BuiltInDomainDefinedAttributes)
				_, n_builtindomaindefinedattributes, _, tlvErr_builtindomaindefinedattributes := ber.DecodeTLV(content[offset:])
				if tlvErr_builtindomaindefinedattributes != nil {
					return fmt.Errorf("decoding built-in-domain-defined-attributes: %w", tlvErr_builtindomaindefinedattributes)
				}
				dec_builtindomaindefinedattributes, unmErr := UnmarshalBERBuiltInDomainDefinedAttributes(content[offset : offset+n_builtindomaindefinedattributes])
				if unmErr != nil {
					return fmt.Errorf("decoding built-in-domain-defined-attributes: %w", unmErr)
				}
				v.BuiltInDomainDefinedAttributes = dec_builtindomaindefinedattributes
				offset += n_builtindomaindefinedattributes
			}
		}
	}
	// Decode extension-attributes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 17 {
				// Decode nested SET_OF (ExtensionAttributes)
				_, n_extensionattributes, _, tlvErr_extensionattributes := ber.DecodeTLV(content[offset:])
				if tlvErr_extensionattributes != nil {
					return fmt.Errorf("decoding extension-attributes: %w", tlvErr_extensionattributes)
				}
				dec_extensionattributes, unmErr := UnmarshalBERExtensionAttributes(content[offset : offset+n_extensionattributes])
				if unmErr != nil {
					return fmt.Errorf("decoding extension-attributes: %w", unmErr)
				}
				v.ExtensionAttributes = dec_extensionattributes
				offset += n_extensionattributes
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ORAddress", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes BuiltInStandardAttributes to BER format.
func (v *BuiltInStandardAttributes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CountryName != nil {
		enc_countryname, err := v.CountryName.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding country-name: %w", err)
		}
		children = append(children, enc_countryname...)
	}
	if v.AdministrationDomainName != nil {
		enc_administrationdomainname, err := v.AdministrationDomainName.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding administration-domain-name: %w", err)
		}
		children = append(children, enc_administrationdomainname...)
	}
	if v.NetworkAddress != nil {
		enc_networkaddress := ber.EncodeStringTag(18, string(*v.NetworkAddress))
		enc_networkaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_networkaddress)
		children = append(children, enc_networkaddress...)
	}
	if v.TerminalIdentifier != nil {
		enc_terminalidentifier := ber.EncodeStringTag(19, string(*v.TerminalIdentifier))
		enc_terminalidentifier = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_terminalidentifier)
		children = append(children, enc_terminalidentifier...)
	}
	if v.PrivateDomainName != nil {
		enc_privatedomainname, err := v.PrivateDomainName.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding private-domain-name: %w", err)
		}
		enc_privatedomainname = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_privatedomainname)
		children = append(children, enc_privatedomainname...)
	}
	if v.OrganizationName != nil {
		enc_organizationname := ber.EncodeStringTag(19, string(*v.OrganizationName))
		enc_organizationname = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_organizationname)
		children = append(children, enc_organizationname...)
	}
	if v.NumericUserIdentifier != nil {
		enc_numericuseridentifier := ber.EncodeStringTag(18, string(*v.NumericUserIdentifier))
		enc_numericuseridentifier = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_numericuseridentifier)
		children = append(children, enc_numericuseridentifier...)
	}
	if v.PersonalName != nil {
		enc_personalname, err := v.PersonalName.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding personal-name: %w", err)
		}
		enc_personalname = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_personalname)
		children = append(children, enc_personalname...)
	}
	if v.OrganizationalUnitNames != nil {
		enc_organizationalunitnames, err := MarshalBEROrganizationalUnitNames(v.OrganizationalUnitNames)
		if err != nil {
			return nil, fmt.Errorf("encoding organizational-unit-names: %w", err)
		}
		if v.OrganizationalUnitNamesIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_organizationalunitnames)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_organizationalunitnames = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 6}, seqContent_)
		} else {
			enc_organizationalunitnames = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_organizationalunitnames)
		}
		children = append(children, enc_organizationalunitnames...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes BuiltInStandardAttributes to DER format.
func (v *BuiltInStandardAttributes) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes BuiltInStandardAttributes from BER/DER format.
func (v *BuiltInStandardAttributes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding BuiltInStandardAttributes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BuiltInStandardAttributes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode country-name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 18) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 19) {
				// Decode nested CHOICE (CountryName)
				_, n_countryname, _, tlvErr_countryname := ber.DecodeTLV(content[offset:])
				if tlvErr_countryname != nil {
					return fmt.Errorf("decoding country-name: %w", tlvErr_countryname)
				}
				var dec_countryname CountryName
				if unmErr := dec_countryname.UnmarshalBER(content[offset : offset+n_countryname]); unmErr != nil {
					return fmt.Errorf("decoding country-name: %w", unmErr)
				}
				v.CountryName = &dec_countryname
				offset += n_countryname
			}
		}
	}
	// Decode administration-domain-name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 18) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 19) {
				// Decode nested CHOICE (AdministrationDomainName)
				_, n_administrationdomainname, _, tlvErr_administrationdomainname := ber.DecodeTLV(content[offset:])
				if tlvErr_administrationdomainname != nil {
					return fmt.Errorf("decoding administration-domain-name: %w", tlvErr_administrationdomainname)
				}
				var dec_administrationdomainname AdministrationDomainName
				if unmErr := dec_administrationdomainname.UnmarshalBER(content[offset : offset+n_administrationdomainname]); unmErr != nil {
					return fmt.Errorf("decoding administration-domain-name: %w", unmErr)
				}
				v.AdministrationDomainName = &dec_administrationdomainname
				offset += n_administrationdomainname
			}
		}
	}
	// Decode network-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_networkaddress, rawVal_networkaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding network-address: %w", err)
				}
				decVal_networkaddress := ber.DecodeStringValue(rawVal_networkaddress)
				v.NetworkAddress = &decVal_networkaddress
				offset += n_networkaddress
			}
		}
	}
	// Decode terminal-identifier
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_terminalidentifier, rawVal_terminalidentifier, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding terminal-identifier: %w", err)
				}
				decVal_terminalidentifier := ber.DecodeStringValue(rawVal_terminalidentifier)
				v.TerminalIdentifier = &decVal_terminalidentifier
				offset += n_terminalidentifier
			}
		}
	}
	// Decode private-domain-name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_privatedomainname, innerData_privatedomainname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding private-domain-name: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_privatedomainname PrivateDomainName
				if unmErr := dec_privatedomainname.UnmarshalBER(innerData_privatedomainname); unmErr != nil {
					return fmt.Errorf("decoding private-domain-name: %w", unmErr)
				}
				v.PrivateDomainName = &dec_privatedomainname
				offset += n_privatedomainname
			}
		}
	}
	// Decode organization-name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_organizationname, rawVal_organizationname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding organization-name: %w", err)
				}
				decVal_organizationname := ber.DecodeStringValue(rawVal_organizationname)
				v.OrganizationName = &decVal_organizationname
				offset += n_organizationname
			}
		}
	}
	// Decode numeric-user-identifier
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_numericuseridentifier, rawVal_numericuseridentifier, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding numeric-user-identifier: %w", err)
				}
				decVal_numericuseridentifier := ber.DecodeStringValue(rawVal_numericuseridentifier)
				v.NumericUserIdentifier = &decVal_numericuseridentifier
				offset += n_numericuseridentifier
			}
		}
	}
	// Decode personal-name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_personalname, rawVal_personalname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding personal-name: %w", err)
				}
				reconstructed_personalname := ber.EncodeSet(rawVal_personalname)
				var dec_personalname PersonalName
				if unmErr := dec_personalname.UnmarshalBER(reconstructed_personalname); unmErr != nil {
					return fmt.Errorf("decoding personal-name: %w", unmErr)
				}
				v.PersonalName = &dec_personalname
				offset += n_personalname
			}
		}
	}
	// Decode organizational-unit-names
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_organizationalunitnames, rawVal_organizationalunitnames, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding organizational-unit-names: %w", err)
				}
				reconstructed_organizationalunitnames := ber.EncodeSequence(rawVal_organizationalunitnames)
				dec_organizationalunitnames, unmErr := UnmarshalBEROrganizationalUnitNames(reconstructed_organizationalunitnames)
				if unmErr != nil {
					return fmt.Errorf("decoding organizational-unit-names: %w", unmErr)
				}
				v.OrganizationalUnitNames = dec_organizationalunitnames
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OrganizationalUnitNamesIndef_ = true
					}
				}
				offset += n_organizationalunitnames
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "BuiltInStandardAttributes", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CountryName to BER format.
func (v *CountryName) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CountryNameChoiceX121DccCode:
		if v.X121DccCode == nil {
			return nil, fmt.Errorf("choice CountryName: x121-dcc-code is nil")
		}
		enc_0 := ber.EncodeStringTag(18, *v.X121DccCode)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 1, enc_0)
		return enc_0, nil
	case CountryNameChoiceIso3166Alpha2Code:
		if v.Iso3166Alpha2Code == nil {
			return nil, fmt.Errorf("choice CountryName: iso-3166-alpha2-code is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.Iso3166Alpha2Code)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 1, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CountryName", v.Choice)
	}
}

// MarshalDER encodes CountryName to DER format.
func (v *CountryName) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes CountryName from BER/DER format.
func (v *CountryName) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CountryName CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding CountryName CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 1 || !decodedTag.Constructed {
		return fmt.Errorf("decoding CountryName CHOICE: %w: expected tag [APPLICATION 1], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CountryName", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for CountryName CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CountryName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CountryName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CountryName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 18 {
		v.Choice = CountryNameChoiceX121DccCode
		decVal, _, strErr := ber.DecodeString(choiceData, 18)
		if strErr != nil {
			return fmt.Errorf("decoding x121-dcc-code: %w", strErr)
		}
		v.X121DccCode = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = CountryNameChoiceIso3166Alpha2Code
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding iso-3166-alpha2-code: %w", strErr)
		}
		v.Iso3166Alpha2Code = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for CountryName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AdministrationDomainName to BER format.
func (v *AdministrationDomainName) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AdministrationDomainNameChoiceNumeric:
		if v.Numeric == nil {
			return nil, fmt.Errorf("choice AdministrationDomainName: numeric is nil")
		}
		enc_0 := ber.EncodeStringTag(18, *v.Numeric)
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 2, enc_0)
		return enc_0, nil
	case AdministrationDomainNameChoicePrintable:
		if v.Printable == nil {
			return nil, fmt.Errorf("choice AdministrationDomainName: printable is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.Printable)
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 2, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AdministrationDomainName", v.Choice)
	}
}

// MarshalDER encodes AdministrationDomainName to DER format.
func (v *AdministrationDomainName) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes AdministrationDomainName from BER/DER format.
func (v *AdministrationDomainName) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AdministrationDomainName CHOICE")
	}
	choiceData := data
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AdministrationDomainName CHOICE: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 2 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AdministrationDomainName CHOICE: %w: expected tag [APPLICATION 2], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AdministrationDomainName", Cause: ber.ErrExtraData}
	}
	if len(content) == 0 {
		return fmt.Errorf("empty content for AdministrationDomainName CHOICE")
	}
	choiceData = content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AdministrationDomainName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AdministrationDomainName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AdministrationDomainName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 18 {
		v.Choice = AdministrationDomainNameChoiceNumeric
		decVal, _, strErr := ber.DecodeString(choiceData, 18)
		if strErr != nil {
			return fmt.Errorf("decoding numeric: %w", strErr)
		}
		v.Numeric = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = AdministrationDomainNameChoicePrintable
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printable: %w", strErr)
		}
		v.Printable = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for AdministrationDomainName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes PrivateDomainName to BER format.
func (v *PrivateDomainName) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case PrivateDomainNameChoiceNumeric:
		if v.Numeric == nil {
			return nil, fmt.Errorf("choice PrivateDomainName: numeric is nil")
		}
		enc_0 := ber.EncodeStringTag(18, *v.Numeric)
		return enc_0, nil
	case PrivateDomainNameChoicePrintable:
		if v.Printable == nil {
			return nil, fmt.Errorf("choice PrivateDomainName: printable is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.Printable)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PrivateDomainName", v.Choice)
	}
}

// MarshalDER encodes PrivateDomainName to DER format.
func (v *PrivateDomainName) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes PrivateDomainName from BER/DER format.
func (v *PrivateDomainName) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for PrivateDomainName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PrivateDomainName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding PrivateDomainName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PrivateDomainName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 18 {
		v.Choice = PrivateDomainNameChoiceNumeric
		decVal, _, strErr := ber.DecodeString(choiceData, 18)
		if strErr != nil {
			return fmt.Errorf("decoding numeric: %w", strErr)
		}
		v.Numeric = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = PrivateDomainNameChoicePrintable
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printable: %w", strErr)
		}
		v.Printable = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for PrivateDomainName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes PersonalName to BER format.
func (v *PersonalName) MarshalBER() ([]byte, error) {
	var children []byte
	enc_surname := ber.EncodeStringTag(19, v.Surname)
	enc_surname = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_surname)
	children = append(children, enc_surname...)
	if v.GivenName != nil {
		enc_givenname := ber.EncodeStringTag(19, *v.GivenName)
		enc_givenname = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_givenname)
		children = append(children, enc_givenname...)
	}
	if v.Initials != nil {
		enc_initials := ber.EncodeStringTag(19, *v.Initials)
		enc_initials = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_initials)
		children = append(children, enc_initials...)
	}
	if v.GenerationQualifier != nil {
		enc_generationqualifier := ber.EncodeStringTag(19, *v.GenerationQualifier)
		enc_generationqualifier = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_generationqualifier)
		children = append(children, enc_generationqualifier...)
	}
	return ber.EncodeSet(children), nil
}

// MarshalDER encodes PersonalName to DER format.
func (v *PersonalName) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PersonalName from BER/DER format.
func (v *PersonalName) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PersonalName SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PersonalName", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode surname
	if offset >= len(content) {
		return fmt.Errorf("missing required field surname")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for surname, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_surname, rawVal_surname, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding surname: %w", err)
	}
	decVal_surname := ber.DecodeStringValue(rawVal_surname)
	v.Surname = decVal_surname
	offset += n_surname
	// Decode given-name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_givenname, rawVal_givenname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding given-name: %w", err)
				}
				decVal_givenname := ber.DecodeStringValue(rawVal_givenname)
				v.GivenName = &decVal_givenname
				offset += n_givenname
			}
		}
	}
	// Decode initials
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_initials, rawVal_initials, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding initials: %w", err)
				}
				decVal_initials := ber.DecodeStringValue(rawVal_initials)
				v.Initials = &decVal_initials
				offset += n_initials
			}
		}
	}
	// Decode generation-qualifier
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_generationqualifier, rawVal_generationqualifier, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding generation-qualifier: %w", err)
				}
				decVal_generationqualifier := ber.DecodeStringValue(rawVal_generationqualifier)
				v.GenerationQualifier = &decVal_generationqualifier
				offset += n_generationqualifier
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PersonalName", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBEROrganizationalUnitNames encodes a OrganizationalUnitNames list to BER.
func MarshalBEROrganizationalUnitNames(list OrganizationalUnitNames) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeStringTag(19, string(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEROrganizationalUnitNames decodes a OrganizationalUnitNames list from BER.
func UnmarshalBEROrganizationalUnitNames(data []byte) (OrganizationalUnitNames, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding OrganizationalUnitNames: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OrganizationalUnitNames", Cause: ber.ErrExtraData}
	}
	var result OrganizationalUnitNames
	offset := 0
	for offset < len(content) {
		val, n, strErr := ber.DecodeString(content[offset:], 19)
		if strErr != nil {
			return nil, fmt.Errorf("decoding element: %w", strErr)
		}
		result = append(result, OrganizationalUnitName(val))
		offset += n
	}
	return result, nil
}

// MarshalBERBuiltInDomainDefinedAttributes encodes a BuiltInDomainDefinedAttributes list to BER.
func MarshalBERBuiltInDomainDefinedAttributes(list BuiltInDomainDefinedAttributes) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERBuiltInDomainDefinedAttributes decodes a BuiltInDomainDefinedAttributes list from BER.
func UnmarshalBERBuiltInDomainDefinedAttributes(data []byte) (BuiltInDomainDefinedAttributes, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding BuiltInDomainDefinedAttributes: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BuiltInDomainDefinedAttributes", Cause: ber.ErrExtraData}
	}
	var result BuiltInDomainDefinedAttributes
	offset := 0
	for offset < len(content) {
		var elem BuiltInDomainDefinedAttribute
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes BuiltInDomainDefinedAttribute to BER format.
func (v *BuiltInDomainDefinedAttribute) MarshalBER() ([]byte, error) {
	var children []byte
	enc_type := ber.EncodeStringTag(19, v.Type)
	children = append(children, enc_type...)
	enc_value := ber.EncodeStringTag(19, v.Value)
	children = append(children, enc_value...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes BuiltInDomainDefinedAttribute to DER format.
func (v *BuiltInDomainDefinedAttribute) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes BuiltInDomainDefinedAttribute from BER/DER format.
func (v *BuiltInDomainDefinedAttribute) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding BuiltInDomainDefinedAttribute SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BuiltInDomainDefinedAttribute", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode type
	if offset >= len(content) {
		return fmt.Errorf("missing required field type")
	}
	val_type, n, err := ber.DecodeString(content[offset:], 19)
	if err != nil {
		return fmt.Errorf("decoding type: %w", err)
	}
	v.Type = val_type
	offset += n
	// Decode value
	if offset >= len(content) {
		return fmt.Errorf("missing required field value")
	}
	val_value, n, err := ber.DecodeString(content[offset:], 19)
	if err != nil {
		return fmt.Errorf("decoding value: %w", err)
	}
	v.Value = val_value
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "BuiltInDomainDefinedAttribute", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERExtensionAttributes encodes a ExtensionAttributes list to BER.
func MarshalBERExtensionAttributes(list ExtensionAttributes) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSet(children), nil
}

// UnmarshalBERExtensionAttributes decodes a ExtensionAttributes list from BER.
func UnmarshalBERExtensionAttributes(data []byte) (ExtensionAttributes, error) {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ExtensionAttributes: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding ExtensionAttributes: %w: expected SET, got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ExtensionAttributes", Cause: ber.ErrExtraData}
	}
	var result ExtensionAttributes
	offset := 0
	for offset < len(content) {
		var elem ExtensionAttribute
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes ExtensionAttribute to BER format.
func (v *ExtensionAttribute) MarshalBER() ([]byte, error) {
	var children []byte
	enc_extensionattributetype := ber.EncodeInteger(int64(v.ExtensionAttributeType))
	enc_extensionattributetype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_extensionattributetype)
	children = append(children, enc_extensionattributetype...)
	enc_extensionattributevalue := v.ExtensionAttributeValue.Bytes
	enc_extensionattributevalue = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensionattributevalue)
	children = append(children, enc_extensionattributevalue...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ExtensionAttribute to DER format.
func (v *ExtensionAttribute) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ExtensionAttribute from BER/DER format.
func (v *ExtensionAttribute) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExtensionAttribute SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionAttribute", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extension-attribute-type
	if offset >= len(content) {
		return fmt.Errorf("missing required field extension-attribute-type")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for extension-attribute-type, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_extensionattributetype, rawVal_extensionattributetype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding extension-attribute-type: %w", err)
	}
	decVal_extensionattributetype, intErr := ber.DecodeIntegerValue(rawVal_extensionattributetype)
	if intErr != nil {
		return fmt.Errorf("decoding extension-attribute-type: %w", intErr)
	}
	v.ExtensionAttributeType = decVal_extensionattributetype
	offset += n_extensionattributetype
	// Decode extension-attribute-value
	if offset >= len(content) {
		return fmt.Errorf("missing required field extension-attribute-value")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for extension-attribute-value, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_extensionattributevalue, innerData_extensionattributevalue, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding extension-attribute-value: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	v.ExtensionAttributeValue = runtime.RawValue{Bytes: innerData_extensionattributevalue}
	offset += n_extensionattributevalue
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExtensionAttribute", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TeletexPersonalName to BER format.
func (v *TeletexPersonalName) MarshalBER() ([]byte, error) {
	var children []byte
	enc_surname := ber.EncodeStringTag(20, v.Surname)
	enc_surname = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_surname)
	children = append(children, enc_surname...)
	if v.GivenName != nil {
		enc_givenname := ber.EncodeStringTag(20, *v.GivenName)
		enc_givenname = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_givenname)
		children = append(children, enc_givenname...)
	}
	if v.Initials != nil {
		enc_initials := ber.EncodeStringTag(20, *v.Initials)
		enc_initials = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_initials)
		children = append(children, enc_initials...)
	}
	if v.GenerationQualifier != nil {
		enc_generationqualifier := ber.EncodeStringTag(20, *v.GenerationQualifier)
		enc_generationqualifier = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_generationqualifier)
		children = append(children, enc_generationqualifier...)
	}
	return ber.EncodeSet(children), nil
}

// MarshalDER encodes TeletexPersonalName to DER format.
func (v *TeletexPersonalName) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TeletexPersonalName from BER/DER format.
func (v *TeletexPersonalName) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TeletexPersonalName SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TeletexPersonalName", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode surname
	if offset >= len(content) {
		return fmt.Errorf("missing required field surname")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for surname, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_surname, rawVal_surname, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding surname: %w", err)
	}
	decVal_surname := ber.DecodeStringValue(rawVal_surname)
	v.Surname = decVal_surname
	offset += n_surname
	// Decode given-name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_givenname, rawVal_givenname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding given-name: %w", err)
				}
				decVal_givenname := ber.DecodeStringValue(rawVal_givenname)
				v.GivenName = &decVal_givenname
				offset += n_givenname
			}
		}
	}
	// Decode initials
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_initials, rawVal_initials, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding initials: %w", err)
				}
				decVal_initials := ber.DecodeStringValue(rawVal_initials)
				v.Initials = &decVal_initials
				offset += n_initials
			}
		}
	}
	// Decode generation-qualifier
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_generationqualifier, rawVal_generationqualifier, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding generation-qualifier: %w", err)
				}
				decVal_generationqualifier := ber.DecodeStringValue(rawVal_generationqualifier)
				v.GenerationQualifier = &decVal_generationqualifier
				offset += n_generationqualifier
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TeletexPersonalName", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERTeletexOrganizationalUnitNames encodes a TeletexOrganizationalUnitNames list to BER.
func MarshalBERTeletexOrganizationalUnitNames(list TeletexOrganizationalUnitNames) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeStringTag(20, string(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERTeletexOrganizationalUnitNames decodes a TeletexOrganizationalUnitNames list from BER.
func UnmarshalBERTeletexOrganizationalUnitNames(data []byte) (TeletexOrganizationalUnitNames, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding TeletexOrganizationalUnitNames: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TeletexOrganizationalUnitNames", Cause: ber.ErrExtraData}
	}
	var result TeletexOrganizationalUnitNames
	offset := 0
	for offset < len(content) {
		val, n, strErr := ber.DecodeString(content[offset:], 20)
		if strErr != nil {
			return nil, fmt.Errorf("decoding element: %w", strErr)
		}
		result = append(result, TeletexOrganizationalUnitName(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes PhysicalDeliveryCountryName to BER format.
func (v *PhysicalDeliveryCountryName) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case PhysicalDeliveryCountryNameChoiceX121DccCode:
		if v.X121DccCode == nil {
			return nil, fmt.Errorf("choice PhysicalDeliveryCountryName: x121-dcc-code is nil")
		}
		enc_0 := ber.EncodeStringTag(18, *v.X121DccCode)
		return enc_0, nil
	case PhysicalDeliveryCountryNameChoiceIso3166Alpha2Code:
		if v.Iso3166Alpha2Code == nil {
			return nil, fmt.Errorf("choice PhysicalDeliveryCountryName: iso-3166-alpha2-code is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.Iso3166Alpha2Code)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PhysicalDeliveryCountryName", v.Choice)
	}
}

// MarshalDER encodes PhysicalDeliveryCountryName to DER format.
func (v *PhysicalDeliveryCountryName) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes PhysicalDeliveryCountryName from BER/DER format.
func (v *PhysicalDeliveryCountryName) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for PhysicalDeliveryCountryName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PhysicalDeliveryCountryName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding PhysicalDeliveryCountryName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PhysicalDeliveryCountryName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 18 {
		v.Choice = PhysicalDeliveryCountryNameChoiceX121DccCode
		decVal, _, strErr := ber.DecodeString(choiceData, 18)
		if strErr != nil {
			return fmt.Errorf("decoding x121-dcc-code: %w", strErr)
		}
		v.X121DccCode = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = PhysicalDeliveryCountryNameChoiceIso3166Alpha2Code
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding iso-3166-alpha2-code: %w", strErr)
		}
		v.Iso3166Alpha2Code = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for PhysicalDeliveryCountryName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes PostalCode to BER format.
func (v *PostalCode) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case PostalCodeChoiceNumericCode:
		if v.NumericCode == nil {
			return nil, fmt.Errorf("choice PostalCode: numeric-code is nil")
		}
		enc_0 := ber.EncodeStringTag(18, *v.NumericCode)
		return enc_0, nil
	case PostalCodeChoicePrintableCode:
		if v.PrintableCode == nil {
			return nil, fmt.Errorf("choice PostalCode: printable-code is nil")
		}
		enc_1 := ber.EncodeStringTag(19, *v.PrintableCode)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PostalCode", v.Choice)
	}
}

// MarshalDER encodes PostalCode to DER format.
func (v *PostalCode) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes PostalCode from BER/DER format.
func (v *PostalCode) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for PostalCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PostalCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding PostalCode CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PostalCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 18 {
		v.Choice = PostalCodeChoiceNumericCode
		decVal, _, strErr := ber.DecodeString(choiceData, 18)
		if strErr != nil {
			return fmt.Errorf("decoding numeric-code: %w", strErr)
		}
		v.NumericCode = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = PostalCodeChoicePrintableCode
		decVal, _, strErr := ber.DecodeString(choiceData, 19)
		if strErr != nil {
			return fmt.Errorf("decoding printable-code: %w", strErr)
		}
		v.PrintableCode = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for PostalCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes UnformattedPostalAddress to BER format.
func (v *UnformattedPostalAddress) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrintableAddress != nil {
		enc_printableaddress, err := MarshalBERUnformattedPostalAddressPrintableAddress(v.PrintableAddress)
		if err != nil {
			return nil, fmt.Errorf("encoding printable-address: %w", err)
		}
		children = append(children, enc_printableaddress...)
	}
	if v.TeletexString != nil {
		enc_teletexstring := ber.EncodeStringTag(20, *v.TeletexString)
		children = append(children, enc_teletexstring...)
	}
	return ber.EncodeSet(children), nil
}

// MarshalDER encodes UnformattedPostalAddress to DER format.
func (v *UnformattedPostalAddress) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes UnformattedPostalAddress from BER/DER format.
func (v *UnformattedPostalAddress) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnformattedPostalAddress SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnformattedPostalAddress", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode printable-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (UnformattedPostalAddressPrintableAddress)
				_, n_printableaddress, _, tlvErr_printableaddress := ber.DecodeTLV(content[offset:])
				if tlvErr_printableaddress != nil {
					return fmt.Errorf("decoding printable-address: %w", tlvErr_printableaddress)
				}
				dec_printableaddress, unmErr := UnmarshalBERUnformattedPostalAddressPrintableAddress(content[offset : offset+n_printableaddress])
				if unmErr != nil {
					return fmt.Errorf("decoding printable-address: %w", unmErr)
				}
				v.PrintableAddress = dec_printableaddress
				offset += n_printableaddress
			}
		}
	}
	// Decode teletex-string
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
				val_teletexstring, n, err := ber.DecodeString(content[offset:], 20)
				if err != nil {
					return fmt.Errorf("decoding teletex-string: %w", err)
				}
				v.TeletexString = &val_teletexstring
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "UnformattedPostalAddress", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PDSParameter to BER format.
func (v *PDSParameter) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrintableString != nil {
		enc_printablestring := ber.EncodeStringTag(19, *v.PrintableString)
		children = append(children, enc_printablestring...)
	}
	if v.TeletexString != nil {
		enc_teletexstring := ber.EncodeStringTag(20, *v.TeletexString)
		children = append(children, enc_teletexstring...)
	}
	return ber.EncodeSet(children), nil
}

// MarshalDER encodes PDSParameter to DER format.
func (v *PDSParameter) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PDSParameter from BER/DER format.
func (v *PDSParameter) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PDSParameter SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PDSParameter", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode printable-string
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
				val_printablestring, n, err := ber.DecodeString(content[offset:], 19)
				if err != nil {
					return fmt.Errorf("decoding printable-string: %w", err)
				}
				v.PrintableString = &val_printablestring
				offset += n
			}
		}
	}
	// Decode teletex-string
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
				val_teletexstring, n, err := ber.DecodeString(content[offset:], 20)
				if err != nil {
					return fmt.Errorf("decoding teletex-string: %w", err)
				}
				v.TeletexString = &val_teletexstring
				offset += n
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PDSParameter", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ExtendedNetworkAddress to BER format.
func (v *ExtendedNetworkAddress) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ExtendedNetworkAddressChoiceE1634Address:
		if v.E1634Address == nil {
			return nil, fmt.Errorf("choice ExtendedNetworkAddress: e163-4-address is nil")
		}
		enc_0, err := v.E1634Address.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding e163-4-address: %w", err)
		}
		return enc_0, nil
	case ExtendedNetworkAddressChoicePsapAddress:
		if v.PsapAddress == nil {
			return nil, fmt.Errorf("choice ExtendedNetworkAddress: psap-address is nil")
		}
		enc_1, err := v.PsapAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding psap-address: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ExtendedNetworkAddress", v.Choice)
	}
}

// MarshalDER encodes ExtendedNetworkAddress to DER format.
func (v *ExtendedNetworkAddress) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes ExtendedNetworkAddress from BER/DER format.
func (v *ExtendedNetworkAddress) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtendedNetworkAddress CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtendedNetworkAddress: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ExtendedNetworkAddress CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtendedNetworkAddress", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = ExtendedNetworkAddressChoiceE1634Address
		var dec ExtendedNetworkAddressE1634Address
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding e163-4-address: %w", unmErr)
		}
		v.E1634Address = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = ExtendedNetworkAddressChoicePsapAddress
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding psap-address: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec PresentationAddress
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding psap-address: %w", unmErr)
		}
		v.PsapAddress = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ExtendedNetworkAddress CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes PresentationAddress to BER format.
func (v *PresentationAddress) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PSelector != nil {
		enc_pselector := ber.EncodeOctetString(v.PSelector)
		enc_pselector = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_pselector)
		children = append(children, enc_pselector...)
	}
	if v.SSelector != nil {
		enc_sselector := ber.EncodeOctetString(v.SSelector)
		enc_sselector = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sselector)
		children = append(children, enc_sselector...)
	}
	if v.TSelector != nil {
		enc_tselector := ber.EncodeOctetString(v.TSelector)
		enc_tselector = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tselector)
		children = append(children, enc_tselector...)
	}
	enc_naddresses, err := MarshalBERPresentationAddressNAddresses(v.NAddresses)
	if err != nil {
		return nil, fmt.Errorf("encoding nAddresses: %w", err)
	}
	enc_naddresses = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_naddresses)
	children = append(children, enc_naddresses...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PresentationAddress to DER format.
func (v *PresentationAddress) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PresentationAddress from BER/DER format.
func (v *PresentationAddress) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PresentationAddress SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PresentationAddress", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode pSelector
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_pselector, innerData_pselector, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pSelector: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				val_pselector, _, err := ber.DecodeOctetString(innerData_pselector)
				if err != nil {
					return fmt.Errorf("decoding pSelector: %w", err)
				}
				tmp_pselector := val_pselector
				v.PSelector = tmp_pselector
				offset += n_pselector
			}
		}
	}
	// Decode sSelector
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_sselector, innerData_sselector, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sSelector: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				val_sselector, _, err := ber.DecodeOctetString(innerData_sselector)
				if err != nil {
					return fmt.Errorf("decoding sSelector: %w", err)
				}
				tmp_sselector := val_sselector
				v.SSelector = tmp_sselector
				offset += n_sselector
			}
		}
	}
	// Decode tSelector
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_tselector, innerData_tselector, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding tSelector: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				val_tselector, _, err := ber.DecodeOctetString(innerData_tselector)
				if err != nil {
					return fmt.Errorf("decoding tSelector: %w", err)
				}
				tmp_tselector := val_tselector
				v.TSelector = tmp_tselector
				offset += n_tselector
			}
		}
	}
	// Decode nAddresses
	if offset >= len(content) {
		return fmt.Errorf("missing required field nAddresses")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for nAddresses, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_naddresses, innerData_naddresses, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding nAddresses: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	dec_naddresses, unmErr := UnmarshalBERPresentationAddressNAddresses(innerData_naddresses)
	if unmErr != nil {
		return fmt.Errorf("decoding nAddresses: %w", unmErr)
	}
	v.NAddresses = dec_naddresses
	offset += n_naddresses
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PresentationAddress", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERTeletexDomainDefinedAttributes encodes a TeletexDomainDefinedAttributes list to BER.
func MarshalBERTeletexDomainDefinedAttributes(list TeletexDomainDefinedAttributes) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERTeletexDomainDefinedAttributes decodes a TeletexDomainDefinedAttributes list from BER.
func UnmarshalBERTeletexDomainDefinedAttributes(data []byte) (TeletexDomainDefinedAttributes, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding TeletexDomainDefinedAttributes: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TeletexDomainDefinedAttributes", Cause: ber.ErrExtraData}
	}
	var result TeletexDomainDefinedAttributes
	offset := 0
	for offset < len(content) {
		var elem TeletexDomainDefinedAttribute
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes TeletexDomainDefinedAttribute to BER format.
func (v *TeletexDomainDefinedAttribute) MarshalBER() ([]byte, error) {
	var children []byte
	enc_type := ber.EncodeStringTag(20, v.Type)
	children = append(children, enc_type...)
	enc_value := ber.EncodeStringTag(20, v.Value)
	children = append(children, enc_value...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes TeletexDomainDefinedAttribute to DER format.
func (v *TeletexDomainDefinedAttribute) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TeletexDomainDefinedAttribute from BER/DER format.
func (v *TeletexDomainDefinedAttribute) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TeletexDomainDefinedAttribute SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TeletexDomainDefinedAttribute", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode type
	if offset >= len(content) {
		return fmt.Errorf("missing required field type")
	}
	val_type, n, err := ber.DecodeString(content[offset:], 20)
	if err != nil {
		return fmt.Errorf("decoding type: %w", err)
	}
	v.Type = val_type
	offset += n
	// Decode value
	if offset >= len(content) {
		return fmt.Errorf("missing required field value")
	}
	val_value, n, err := ber.DecodeString(content[offset:], 20)
	if err != nil {
		return fmt.Errorf("decoding value: %w", err)
	}
	v.Value = val_value
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TeletexDomainDefinedAttribute", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERAttributeValues encodes a AttributeValues list to BER.
func MarshalBERAttributeValues(list AttributeValues) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSet(children), nil
}

// UnmarshalBERAttributeValues decodes a AttributeValues list from BER.
func UnmarshalBERAttributeValues(data []byte) (AttributeValues, error) {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AttributeValues: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding AttributeValues: %w: expected SET, got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AttributeValues", Cause: ber.ErrExtraData}
	}
	var result AttributeValues
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: content[offset : offset+n]})
		offset += n
	}
	return result, nil
}

// MarshalBER encodes TBSCertListRevokedCertificatesElem to BER format.
func (v *TBSCertListRevokedCertificatesElem) MarshalBER() ([]byte, error) {
	var children []byte
	if v.UserCertificate == nil {
		return nil, fmt.Errorf("encoding userCertificate: required INTEGER is nil")
	}
	enc_usercertificate := ber.EncodeBigInt(v.UserCertificate)
	children = append(children, enc_usercertificate...)
	enc_revocationdate, err := v.RevocationDate.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding revocationDate: %w", err)
	}
	children = append(children, enc_revocationdate...)
	if v.CrlEntryExtensions != nil {
		enc_crlentryextensions, err := MarshalBERExtensions(v.CrlEntryExtensions)
		if err != nil {
			return nil, fmt.Errorf("encoding crlEntryExtensions: %w", err)
		}
		children = append(children, enc_crlentryextensions...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes TBSCertListRevokedCertificatesElem to DER format.
func (v *TBSCertListRevokedCertificatesElem) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TBSCertListRevokedCertificatesElem from BER/DER format.
func (v *TBSCertListRevokedCertificatesElem) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TBSCertListRevokedCertificatesElem SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TBSCertListRevokedCertificatesElem", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode userCertificate
	if offset >= len(content) {
		return fmt.Errorf("missing required field userCertificate")
	}
	val_usercertificate, n, err := ber.DecodeBigInt(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding userCertificate: %w", err)
	}
	v.UserCertificate = val_usercertificate
	offset += n
	// Decode revocationDate
	if offset >= len(content) {
		return fmt.Errorf("missing required field revocationDate")
	}
	// Decode nested CHOICE (Time)
	_, n_revocationdate, _, tlvErr_revocationdate := ber.DecodeTLV(content[offset:])
	if tlvErr_revocationdate != nil {
		return fmt.Errorf("decoding revocationDate: %w", tlvErr_revocationdate)
	}
	if unmErr := v.RevocationDate.UnmarshalBER(content[offset : offset+n_revocationdate]); unmErr != nil {
		return fmt.Errorf("decoding revocationDate: %w", unmErr)
	}
	offset += n_revocationdate
	// Decode crlEntryExtensions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (Extensions)
				_, n_crlentryextensions, _, tlvErr_crlentryextensions := ber.DecodeTLV(content[offset:])
				if tlvErr_crlentryextensions != nil {
					return fmt.Errorf("decoding crlEntryExtensions: %w", tlvErr_crlentryextensions)
				}
				dec_crlentryextensions, unmErr := UnmarshalBERExtensions(content[offset : offset+n_crlentryextensions])
				if unmErr != nil {
					return fmt.Errorf("decoding crlEntryExtensions: %w", unmErr)
				}
				v.CrlEntryExtensions = dec_crlentryextensions
				offset += n_crlentryextensions
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TBSCertListRevokedCertificatesElem", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERTBSCertListRevokedCertificates encodes a TBSCertListRevokedCertificates list to BER.
func MarshalBERTBSCertListRevokedCertificates(list TBSCertListRevokedCertificates) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERTBSCertListRevokedCertificates decodes a TBSCertListRevokedCertificates list from BER.
func UnmarshalBERTBSCertListRevokedCertificates(data []byte) (TBSCertListRevokedCertificates, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding TBSCertListRevokedCertificates: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TBSCertListRevokedCertificates", Cause: ber.ErrExtraData}
	}
	var result TBSCertListRevokedCertificates
	offset := 0
	for offset < len(content) {
		var elem TBSCertListRevokedCertificatesElem
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBERUnformattedPostalAddressPrintableAddress encodes a UnformattedPostalAddressPrintableAddress list to BER.
func MarshalBERUnformattedPostalAddressPrintableAddress(list UnformattedPostalAddressPrintableAddress) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeStringTag(19, elem)...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERUnformattedPostalAddressPrintableAddress decodes a UnformattedPostalAddressPrintableAddress list from BER.
func UnmarshalBERUnformattedPostalAddressPrintableAddress(data []byte) (UnformattedPostalAddressPrintableAddress, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding UnformattedPostalAddressPrintableAddress: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "UnformattedPostalAddressPrintableAddress", Cause: ber.ErrExtraData}
	}
	var result UnformattedPostalAddressPrintableAddress
	offset := 0
	for offset < len(content) {
		val, n, strErr := ber.DecodeString(content[offset:], 19)
		if strErr != nil {
			return nil, fmt.Errorf("decoding element: %w", strErr)
		}
		result = append(result, val)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes ExtendedNetworkAddressE1634Address to BER format.
func (v *ExtendedNetworkAddressE1634Address) MarshalBER() ([]byte, error) {
	var children []byte
	enc_number := ber.EncodeStringTag(18, v.Number)
	enc_number = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_number)
	children = append(children, enc_number...)
	if v.SubAddress != nil {
		enc_subaddress := ber.EncodeStringTag(18, *v.SubAddress)
		enc_subaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_subaddress)
		children = append(children, enc_subaddress...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ExtendedNetworkAddressE1634Address to DER format.
func (v *ExtendedNetworkAddressE1634Address) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ExtendedNetworkAddressE1634Address from BER/DER format.
func (v *ExtendedNetworkAddressE1634Address) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExtendedNetworkAddressE1634Address SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtendedNetworkAddressE1634Address", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode number
	if offset >= len(content) {
		return fmt.Errorf("missing required field number")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for number, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_number, rawVal_number, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding number: %w", err)
	}
	decVal_number := ber.DecodeStringValue(rawVal_number)
	v.Number = decVal_number
	offset += n_number
	// Decode sub-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_subaddress, rawVal_subaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sub-address: %w", err)
				}
				decVal_subaddress := ber.DecodeStringValue(rawVal_subaddress)
				v.SubAddress = &decVal_subaddress
				offset += n_subaddress
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExtendedNetworkAddressE1634Address", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERPresentationAddressNAddresses encodes a PresentationAddressNAddresses list to BER.
func MarshalBERPresentationAddressNAddresses(list PresentationAddressNAddresses) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString(elem)...)
	}
	return ber.EncodeSet(children), nil
}

// UnmarshalBERPresentationAddressNAddresses decodes a PresentationAddressNAddresses list from BER.
func UnmarshalBERPresentationAddressNAddresses(data []byte) (PresentationAddressNAddresses, error) {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding PresentationAddressNAddresses: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding PresentationAddressNAddresses: %w: expected SET, got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PresentationAddressNAddresses", Cause: ber.ErrExtraData}
	}
	var result PresentationAddressNAddresses
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, val)
		offset += n
	}
	return result, nil
}
