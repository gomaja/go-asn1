// Code generated from ASN.1 module "PKIX1Explicit88". DO NOT EDIT.

package sgp32

import (
	"fmt"
	"math/big"

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
	Type         AttributeType    `asn1:""`
	Values       *AttributeValues `asn1:""`
	ValuesIndef_ bool             `asn1:"-" json:"-"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// AttributeType represents the ASN.1 type AttributeType (OBJECT_IDENTIFIER).
type AttributeType = runtime.ObjectIdentifier

// asn1c:raw-preserve
// AttributeValue represents the ASN.1 type AttributeValue (ANY).
type AttributeValue = runtime.RawValue

// AttributeTypeAndValue represents the ASN.1 type AttributeTypeAndValue (SEQUENCE).
type AttributeTypeAndValue struct {
	Type         AttributeType    `asn1:""`
	Value        runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
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
	berOriginal_    []byte  `json:"-"`
	berSnapshot_    []byte  `json:"-"`
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
	berOriginal_    []byte  `json:"-"`
	berSnapshot_    []byte  `json:"-"`
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
	berOriginal_    []byte  `json:"-"`
	berSnapshot_    []byte  `json:"-"`
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
	berOriginal_    []byte  `json:"-"`
	berSnapshot_    []byte  `json:"-"`
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
	berOriginal_    []byte  `json:"-"`
	berSnapshot_    []byte  `json:"-"`
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
	berOriginal_    []byte  `json:"-"`
	berSnapshot_    []byte  `json:"-"`
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
	berOriginal_    []byte  `json:"-"`
	berSnapshot_    []byte  `json:"-"`
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
	berOriginal_    []byte  `json:"-"`
	berSnapshot_    []byte  `json:"-"`
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
	Choice       int
	berOriginal_ []byte       `json:"-"`
	berSnapshot_ []byte       `json:"-"`
	RdnSequence  *RDNSequence `json:"RdnSequence,omitempty"`
}

// NewNameRdnSequence creates a Name with the rdnSequence alternative.
func NewNameRdnSequence(v *RDNSequence) Name {
	return Name{
		Choice:      NameChoiceRdnSequence,
		RdnSequence: v,
	}
}

// RDNSequence represents the ASN.1 type RDNSequence (SEQUENCE_OF).
type RDNSequence struct {
	Values       []*RelativeDistinguishedName `json:"Values"`
	berOriginal_ []byte                       `json:"-"`
	berSnapshot_ []byte                       `json:"-"`
}

// DistinguishedName represents the ASN.1 type DistinguishedName (SEQUENCE_OF).
type DistinguishedName = RDNSequence

// RelativeDistinguishedName represents the ASN.1 type RelativeDistinguishedName (SET_OF).
type RelativeDistinguishedName struct {
	Values       []AttributeTypeAndValue `json:"Values"`
	berOriginal_ []byte                  `json:"-"`
	berSnapshot_ []byte                  `json:"-"`
}

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
	berOriginal_    []byte  `json:"-"`
	berSnapshot_    []byte  `json:"-"`
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
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
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
	Extensions           *Extensions             `asn1:"tag:3,context,explicit,optional" json:"Extensions,omitempty"`
	ExtensionsIndef_     bool                    `asn1:"-" json:"-"`
	berOriginal_         []byte                  `asn1:"-" json:"-"`
	berSnapshot_         []byte                  `asn1:"-" json:"-"`
}

// Version represents the arbitrary-width ASN.1 INTEGER type Version with named numbers.
type Version struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	VersionV1Decimal = "0"
	VersionV1        = 0
	VersionV2Decimal = "1"
	VersionV2        = 1
	VersionV3Decimal = "2"
	VersionV3        = 2
)

// NewVersion returns an immutable Version containing value.
func NewVersion(value *big.Int) Version {
	return Version{value: runtime.CloneBigInt(value)}
}

// NewVersionInt64 returns a Version containing value.
func NewVersionInt64(value int64) Version {
	return NewVersion(big.NewInt(value))
}

// VersionV1Value returns the named value v1.
func VersionV1Value() Version {
	return NewVersion(runtime.MustParseBigIntDecimal(VersionV1Decimal))
}

// VersionV2Value returns the named value v2.
func VersionV2Value() Version {
	return NewVersion(runtime.MustParseBigIntDecimal(VersionV2Decimal))
}

// VersionV3Value returns the named value v3.
func VersionV3Value() Version {
	return NewVersion(runtime.MustParseBigIntDecimal(VersionV3Decimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v Version) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v Version) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v Version) Name() (string, bool) {
	switch v.BigInt().String() {
	case VersionV1Decimal:
		return "v1", true
	case VersionV2Decimal:
		return "v2", true
	case VersionV3Decimal:
		return "v3", true
	default:
		return "", false
	}
}

func (v Version) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v Version) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *Version) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal Version into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewVersion(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v Version) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *Version) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal Version into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewVersion(value)
	return nil
}

// CertificateSerialNumber represents the ASN.1 type CertificateSerialNumber (INTEGER).
type CertificateSerialNumber = *big.Int

// Validity represents the ASN.1 type Validity (SEQUENCE).
type Validity struct {
	NotBefore    Time   `asn1:""`
	NotAfter     Time   `asn1:""`
	berOriginal_ []byte `asn1:"-" json:"-"`
	berSnapshot_ []byte `asn1:"-" json:"-"`
}

// Time choice constants.
const (
	TimeChoiceUtcTime     = 1
	TimeChoiceGeneralTime = 2
)

// Time represents the ASN.1 CHOICE type Time.
type Time struct {
	Choice       int
	berOriginal_ []byte                   `json:"-"`
	berSnapshot_ []byte                   `json:"-"`
	UtcTime      *runtime.UTCTime         `json:"UtcTime,omitempty"`
	GeneralTime  *runtime.GeneralizedTime `json:"GeneralTime,omitempty"`
}

// NewTimeUtcTime creates a Time with the utcTime alternative.
func NewTimeUtcTime(v runtime.UTCTime) Time {
	return Time{
		Choice:  TimeChoiceUtcTime,
		UtcTime: &v,
	}
}

// NewTimeGeneralTime creates a Time with the generalTime alternative.
func NewTimeGeneralTime(v runtime.GeneralizedTime) Time {
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
	berOriginal_     []byte              `asn1:"-" json:"-"`
	berSnapshot_     []byte              `asn1:"-" json:"-"`
}

// Extensions represents the ASN.1 type Extensions (SEQUENCE_OF).
type Extensions struct {
	Values       []Extension `json:"Values"`
	berOriginal_ []byte      `json:"-"`
	berSnapshot_ []byte      `json:"-"`
}

// Extension represents the ASN.1 type Extension (SEQUENCE).
type Extension struct {
	ExtnID       runtime.ObjectIdentifier `asn1:""`
	Critical     *bool                    `asn1:",optional" json:"Critical,omitempty"`
	CriticalRaw_ byte                     `asn1:"-" json:"-"`
	ExtnValue    []byte                   `asn1:""`
	berOriginal_ []byte                   `asn1:"-" json:"-"`
	berSnapshot_ []byte                   `asn1:"-" json:"-"`
}

// CertificateList represents the ASN.1 type CertificateList (SEQUENCE).
type CertificateList struct {
	TbsCertList        TBSCertList         `asn1:""`
	SignatureAlgorithm AlgorithmIdentifier `asn1:""`
	Signature          runtime.BitString   `asn1:""`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// TBSCertList represents the ASN.1 type TBSCertList (SEQUENCE).
type TBSCertList struct {
	Version                   *Version                        `asn1:",optional" json:"Version,omitempty"`
	Signature                 AlgorithmIdentifier             `asn1:""`
	Issuer                    Name                            `asn1:""`
	ThisUpdate                Time                            `asn1:""`
	NextUpdate                *Time                           `asn1:",optional" json:"NextUpdate,omitempty"`
	RevokedCertificates       *TBSCertListRevokedCertificates `asn1:",optional" json:"RevokedCertificates,omitempty"`
	RevokedCertificatesIndef_ bool                            `asn1:"-" json:"-"`
	CrlExtensions             *Extensions                     `asn1:"tag:0,context,explicit,optional" json:"CrlExtensions,omitempty"`
	CrlExtensionsIndef_       bool                            `asn1:"-" json:"-"`
	berOriginal_              []byte                          `asn1:"-" json:"-"`
	berSnapshot_              []byte                          `asn1:"-" json:"-"`
}

// AlgorithmIdentifier represents the ASN.1 type AlgorithmIdentifier (SEQUENCE).
type AlgorithmIdentifier struct {
	Algorithm    runtime.ObjectIdentifier `asn1:""`
	Parameters   *runtime.RawValue        `asn1:",optional" json:"Parameters,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                   `asn1:"-" json:"-"`
	berSnapshot_ []byte                   `asn1:"-" json:"-"`
}

// ORAddress represents the ASN.1 type ORAddress (SEQUENCE).
type ORAddress struct {
	BuiltInStandardAttributes            BuiltInStandardAttributes       `asn1:""`
	BuiltInDomainDefinedAttributes       *BuiltInDomainDefinedAttributes `asn1:",optional" json:"BuiltInDomainDefinedAttributes,omitempty"`
	BuiltInDomainDefinedAttributesIndef_ bool                            `asn1:"-" json:"-"`
	ExtensionAttributes                  *ExtensionAttributes            `asn1:",optional" json:"ExtensionAttributes,omitempty"`
	ExtensionAttributesIndef_            bool                            `asn1:"-" json:"-"`
	berOriginal_                         []byte                          `asn1:"-" json:"-"`
	berSnapshot_                         []byte                          `asn1:"-" json:"-"`
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
	OrganizationalUnitNames       *OrganizationalUnitNames  `asn1:"tag:6,context,implicit,optional" json:"OrganizationalUnitNames,omitempty"`
	OrganizationalUnitNamesIndef_ bool                      `asn1:"-" json:"-"`
	berOriginal_                  []byte                    `asn1:"-" json:"-"`
	berSnapshot_                  []byte                    `asn1:"-" json:"-"`
}

// CountryName choice constants.
const (
	CountryNameChoiceX121DccCode       = 1
	CountryNameChoiceIso3166Alpha2Code = 2
)

// CountryName represents the ASN.1 CHOICE type CountryName.
type CountryName struct {
	Choice            int
	berOriginal_      []byte  `json:"-"`
	berSnapshot_      []byte  `json:"-"`
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
	Choice       int
	berOriginal_ []byte  `json:"-"`
	berSnapshot_ []byte  `json:"-"`
	Numeric      *string `json:"Numeric,omitempty"`
	Printable    *string `json:"Printable,omitempty"`
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
	Choice       int
	berOriginal_ []byte  `json:"-"`
	berSnapshot_ []byte  `json:"-"`
	Numeric      *string `json:"Numeric,omitempty"`
	Printable    *string `json:"Printable,omitempty"`
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
	berOriginal_        []byte  `asn1:"-" json:"-"`
	berSnapshot_        []byte  `asn1:"-" json:"-"`
}

// OrganizationalUnitNames represents the ASN.1 type OrganizationalUnitNames (SEQUENCE_OF).
type OrganizationalUnitNames struct {
	Values       []OrganizationalUnitName `json:"Values"`
	berOriginal_ []byte                   `json:"-"`
	berSnapshot_ []byte                   `json:"-"`
}

// OrganizationalUnitName represents the ASN.1 type OrganizationalUnitName (PrintableString).
type OrganizationalUnitName = string

// BuiltInDomainDefinedAttributes represents the ASN.1 type BuiltInDomainDefinedAttributes (SEQUENCE_OF).
type BuiltInDomainDefinedAttributes struct {
	Values       []BuiltInDomainDefinedAttribute `json:"Values"`
	berOriginal_ []byte                          `json:"-"`
	berSnapshot_ []byte                          `json:"-"`
}

// BuiltInDomainDefinedAttribute represents the ASN.1 type BuiltInDomainDefinedAttribute (SEQUENCE).
type BuiltInDomainDefinedAttribute struct {
	Type         string `asn1:""`
	Value        string `asn1:""`
	berOriginal_ []byte `asn1:"-" json:"-"`
	berSnapshot_ []byte `asn1:"-" json:"-"`
}

// ExtensionAttributes represents the ASN.1 type ExtensionAttributes (SET_OF).
type ExtensionAttributes struct {
	Values       []ExtensionAttribute `json:"Values"`
	berOriginal_ []byte               `json:"-"`
	berSnapshot_ []byte               `json:"-"`
}

// ExtensionAttribute represents the ASN.1 type ExtensionAttribute (SEQUENCE).
type ExtensionAttribute struct {
	ExtensionAttributeType  int64            `asn1:"tag:0,context,implicit"`
	ExtensionAttributeValue runtime.RawValue `asn1:"tag:1,context,explicit" asn1c:"raw-preserve"`
	berOriginal_            []byte           `asn1:"-" json:"-"`
	berSnapshot_            []byte           `asn1:"-" json:"-"`
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
	berOriginal_        []byte  `asn1:"-" json:"-"`
	berSnapshot_        []byte  `asn1:"-" json:"-"`
}

// TeletexOrganizationalUnitNames represents the ASN.1 type TeletexOrganizationalUnitNames (SEQUENCE_OF).
type TeletexOrganizationalUnitNames struct {
	Values       []TeletexOrganizationalUnitName `json:"Values"`
	berOriginal_ []byte                          `json:"-"`
	berSnapshot_ []byte                          `json:"-"`
}

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
	berOriginal_      []byte  `json:"-"`
	berSnapshot_      []byte  `json:"-"`
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
	berOriginal_  []byte  `json:"-"`
	berSnapshot_  []byte  `json:"-"`
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
	PrintableAddress       *UnformattedPostalAddressPrintableAddress `asn1:",optional" json:"PrintableAddress,omitempty"`
	PrintableAddressIndef_ bool                                      `asn1:"-" json:"-"`
	TeletexString          *string                                   `asn1:",optional" json:"TeletexString,omitempty"`
	berOriginal_           []byte                                    `asn1:"-" json:"-"`
	berSnapshot_           []byte                                    `asn1:"-" json:"-"`
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
	berOriginal_    []byte  `asn1:"-" json:"-"`
	berSnapshot_    []byte  `asn1:"-" json:"-"`
}

// ExtendedNetworkAddress choice constants.
const (
	ExtendedNetworkAddressChoiceE1634Address = 1
	ExtendedNetworkAddressChoicePsapAddress  = 2
)

// ExtendedNetworkAddress represents the ASN.1 CHOICE type ExtendedNetworkAddress.
type ExtendedNetworkAddress struct {
	Choice       int
	berOriginal_ []byte                              `json:"-"`
	berSnapshot_ []byte                              `json:"-"`
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
	PSelector        []byte                         `asn1:"tag:0,context,explicit,optional" json:"PSelector,omitzero"`
	SSelector        []byte                         `asn1:"tag:1,context,explicit,optional" json:"SSelector,omitzero"`
	TSelector        []byte                         `asn1:"tag:2,context,explicit,optional" json:"TSelector,omitzero"`
	NAddresses       *PresentationAddressNAddresses `asn1:"tag:3,context,explicit"`
	NAddressesIndef_ bool                           `asn1:"-" json:"-"`
	berOriginal_     []byte                         `asn1:"-" json:"-"`
	berSnapshot_     []byte                         `asn1:"-" json:"-"`
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
type TeletexDomainDefinedAttributes struct {
	Values       []TeletexDomainDefinedAttribute `json:"Values"`
	berOriginal_ []byte                          `json:"-"`
	berSnapshot_ []byte                          `json:"-"`
}

// TeletexDomainDefinedAttribute represents the ASN.1 type TeletexDomainDefinedAttribute (SEQUENCE).
type TeletexDomainDefinedAttribute struct {
	Type         string `asn1:""`
	Value        string `asn1:""`
	berOriginal_ []byte `asn1:"-" json:"-"`
	berSnapshot_ []byte `asn1:"-" json:"-"`
}

// asn1c:raw-preserve
// AttributeValues represents the ASN.1 type Attribute-values (SET_OF).
type AttributeValues struct {
	Values       []AttributeValue `json:"Values"`
	berOriginal_ []byte           `json:"-"`
	berSnapshot_ []byte           `json:"-"`
}

// TBSCertListRevokedCertificatesElem represents the ASN.1 type TBSCertList-revokedCertificates-Elem (SEQUENCE).
type TBSCertListRevokedCertificatesElem struct {
	UserCertificate          CertificateSerialNumber `asn1:""`
	RevocationDate           Time                    `asn1:""`
	CrlEntryExtensions       *Extensions             `asn1:",optional" json:"CrlEntryExtensions,omitempty"`
	CrlEntryExtensionsIndef_ bool                    `asn1:"-" json:"-"`
	berOriginal_             []byte                  `asn1:"-" json:"-"`
	berSnapshot_             []byte                  `asn1:"-" json:"-"`
}

// TBSCertListRevokedCertificates represents the ASN.1 type TBSCertList-revokedCertificates (SEQUENCE_OF).
type TBSCertListRevokedCertificates struct {
	Values       []TBSCertListRevokedCertificatesElem `json:"Values"`
	berOriginal_ []byte                               `json:"-"`
	berSnapshot_ []byte                               `json:"-"`
}

// UnformattedPostalAddressPrintableAddress represents the ASN.1 type UnformattedPostalAddress-printable-address (SEQUENCE_OF).
type UnformattedPostalAddressPrintableAddress struct {
	Values       []string `json:"Values"`
	berOriginal_ []byte   `json:"-"`
	berSnapshot_ []byte   `json:"-"`
}

// ExtendedNetworkAddressE1634Address represents the ASN.1 type ExtendedNetworkAddress-e163-4-address (SEQUENCE).
type ExtendedNetworkAddressE1634Address struct {
	Number       string  `asn1:"tag:0,context,implicit"`
	SubAddress   *string `asn1:"tag:1,context,implicit,optional" json:"SubAddress,omitempty"`
	berOriginal_ []byte  `asn1:"-" json:"-"`
	berSnapshot_ []byte  `asn1:"-" json:"-"`
}

// PresentationAddressNAddresses represents the ASN.1 type PresentationAddress-nAddresses (SET_OF).
type PresentationAddressNAddresses struct {
	Values       [][]byte `json:"Values"`
	berOriginal_ []byte   `json:"-"`
	berSnapshot_ []byte   `json:"-"`
}

// MarshalBER encodes Attribute to BER format.
func (v *Attribute) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Attribute receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Attribute) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_type, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.Type))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding type: %w", oidErr)
	}
	children = append(children, enc_type...)
	if v.Values == nil {
		return nil, fmt.Errorf("encoding values: %w: required collection is nil", ber.ErrInvalidValue)
	}
	enc_values, err := MarshalBERAttributeValues(v.Values, ber.ChildEncodeOptions(opts, "values")...)
	if err != nil {
		return nil, fmt.Errorf("encoding values: %w", err)
	}
	children = append(children, enc_values...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes Attribute to DER format.
func (v *Attribute) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Attribute receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_type, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.Type))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding type: %w", oidErr)
	}
	children = append(children, enc_type...)
	if v.Values == nil {
		return nil, fmt.Errorf("encoding values: %w: required collection is nil", ber.ErrInvalidValue)
	}
	enc_values, err := MarshalDERAttributeValues(v.Values)
	if err != nil {
		return nil, fmt.Errorf("encoding values: %w", err)
	}
	children = append(children, enc_values...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Attribute as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Attribute from BER/DER format.
func (v *Attribute) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Attribute destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = Attribute{}
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
	val_type, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding type: %w", err)
	}
	v.Type = runtime.ObjectIdentifier(val_type)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode values
	if offset >= len(content) {
		return fmt.Errorf("missing required field values")
	}
	v.ValuesIndef_ = false
	// Decode nested SET_OF (AttributeValues)
	_, n_values, _, tlvErr_values := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_values != nil {
		return fmt.Errorf("decoding values: %w", tlvErr_values)
	}
	if offset < 0 || offset >
		len(content) || n_values < 0 || n_values > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	tlv_values := content[offset : offset+n_values]
	{
		_, tagSz_, _ := ber.DecodeTag(tlv_values)
		if tagSz_ < len(tlv_values) && tlv_values[tagSz_] == 0x80 {
			v.ValuesIndef_ = true
		}
	}
	dec_values, unmErr := UnmarshalBERAttributeValues(tlv_values, ber.ChildDecodeOptions(opts, "values")...)
	if unmErr != nil {
		return fmt.Errorf("decoding values: %w", unmErr)
	}
	v.Values = dec_values
	if offset < 0 || offset >
		len(content) || n_values < 0 || n_values > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_values
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Attribute", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AttributeTypeAndValue to BER format.
func (v *AttributeTypeAndValue) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AttributeTypeAndValue receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AttributeTypeAndValue) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_type, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.Type))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding type: %w", oidErr)
	}
	children = append(children, enc_type...)
	enc_value := v.Value.Bytes
	children = append(children, enc_value...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AttributeTypeAndValue to DER format.
func (v *AttributeTypeAndValue) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AttributeTypeAndValue receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_type, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.Type))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding type: %w", oidErr)
	}
	children = append(children, enc_type...)
	enc_value := v.Value.Bytes
	children = append(children, enc_value...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AttributeTypeAndValue as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AttributeTypeAndValue from BER/DER format.
func (v *AttributeTypeAndValue) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AttributeTypeAndValue destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AttributeTypeAndValue{}
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
	val_type, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding type: %w", err)
	}
	v.Type = runtime.ObjectIdentifier(val_type)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode value
	if offset >= len(content) {
		return fmt.Errorf("missing required field value")
	}
	_, n_value, _, tlvErr_value := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_value != nil {
		return fmt.Errorf("decoding value: %w", tlvErr_value)
	}
	if offset < 0 || offset >
		len(content) || n_value < 0 || n_value > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	v.Value = runtime.RawValue{Bytes: content[offset : offset+n_value]}
	if offset < 0 || offset >
		len(content) || n_value < 0 || n_value > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_value
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AttributeTypeAndValue", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes X520name to BER format.
func (v *X520name) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: X520name receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *X520name) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case X520nameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("%w: choice X520name: teletexString is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletexString: %w", stringErr)
		}
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 32768 {
			if constraintErr := ber.CheckEncodedLength(opts, "teletexString", "SIZE (1..32768)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case X520nameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("%w: choice X520name: printableString is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printableString: %w", stringErr)
		}
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 32768 {
			if constraintErr := ber.CheckEncodedLength(opts, "printableString", "SIZE (1..32768)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	case X520nameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("%w: choice X520name: universalString is nil", ber.ErrInvalidValue)
		}
		enc_2, stringErr := ber.EncodeStringTagChecked(28, *v.UniversalString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding universalString: %w", stringErr)
		}
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 32768 {
			if constraintErr := ber.CheckEncodedLength(opts, "universalString", "SIZE (1..32768)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_2, nil
	case X520nameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("%w: choice X520name: utf8String is nil", ber.ErrInvalidValue)
		}
		enc_3, stringErr := ber.EncodeStringTagChecked(12, *v.Utf8String)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding utf8String: %w", stringErr)
		}
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 32768 {
			if constraintErr := ber.CheckEncodedLength(opts, "utf8String", "SIZE (1..32768)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_3, nil
	case X520nameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("%w: choice X520name: bmpString is nil", ber.ErrInvalidValue)
		}
		enc_4, stringErr := ber.EncodeStringTagChecked(30, *v.BmpString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding bmpString: %w", stringErr)
		}
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 32768 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmpString", "SIZE (1..32768)", len([]rune(*v.BmpString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520name", v.Choice)
	}
}

// MarshalDER encodes X520name to DER format.
func (v *X520name) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: X520name receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding X520name as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes X520name from BER/DER format.
func (v *X520name) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: X520name destination is nil", ber.ErrInvalidValue)
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
	*v = X520name{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520name CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520name: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520name CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520name", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520nameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 32768 {
			if constraintErr := ber.CheckDecodedLength(opts, "teletexString", "SIZE (1..32768)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520nameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 32768 {
			if constraintErr := ber.CheckDecodedLength(opts, "printableString", "SIZE (1..32768)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520nameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 32768 {
			if constraintErr := ber.CheckDecodedLength(opts, "universalString", "SIZE (1..32768)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520nameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 32768 {
			if constraintErr := ber.CheckDecodedLength(opts, "utf8String", "SIZE (1..32768)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520nameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 32768 {
			if constraintErr := ber.CheckDecodedLength(opts, "bmpString", "SIZE (1..32768)", len([]rune(*v.BmpString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for X520name CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520CommonName to BER format.
func (v *X520CommonName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: X520CommonName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *X520CommonName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case X520CommonNameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("%w: choice X520CommonName: teletexString is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletexString: %w", stringErr)
		}
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "teletexString", "SIZE (1..64)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case X520CommonNameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("%w: choice X520CommonName: printableString is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printableString: %w", stringErr)
		}
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "printableString", "SIZE (1..64)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	case X520CommonNameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("%w: choice X520CommonName: universalString is nil", ber.ErrInvalidValue)
		}
		enc_2, stringErr := ber.EncodeStringTagChecked(28, *v.UniversalString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding universalString: %w", stringErr)
		}
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "universalString", "SIZE (1..64)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_2, nil
	case X520CommonNameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("%w: choice X520CommonName: utf8String is nil", ber.ErrInvalidValue)
		}
		enc_3, stringErr := ber.EncodeStringTagChecked(12, *v.Utf8String)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding utf8String: %w", stringErr)
		}
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "utf8String", "SIZE (1..64)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_3, nil
	case X520CommonNameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("%w: choice X520CommonName: bmpString is nil", ber.ErrInvalidValue)
		}
		enc_4, stringErr := ber.EncodeStringTagChecked(30, *v.BmpString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding bmpString: %w", stringErr)
		}
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmpString", "SIZE (1..64)", len([]rune(*v.BmpString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520CommonName", v.Choice)
	}
}

// MarshalDER encodes X520CommonName to DER format.
func (v *X520CommonName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: X520CommonName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding X520CommonName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes X520CommonName from BER/DER format.
func (v *X520CommonName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: X520CommonName destination is nil", ber.ErrInvalidValue)
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
	*v = X520CommonName{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520CommonName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520CommonName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520CommonName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520CommonName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520CommonNameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "teletexString", "SIZE (1..64)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520CommonNameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "printableString", "SIZE (1..64)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520CommonNameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "universalString", "SIZE (1..64)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520CommonNameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "utf8String", "SIZE (1..64)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520CommonNameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "bmpString", "SIZE (1..64)", len([]rune(*v.BmpString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for X520CommonName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520LocalityName to BER format.
func (v *X520LocalityName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: X520LocalityName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *X520LocalityName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case X520LocalityNameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("%w: choice X520LocalityName: teletexString is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletexString: %w", stringErr)
		}
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "teletexString", "SIZE (1..128)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case X520LocalityNameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("%w: choice X520LocalityName: printableString is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printableString: %w", stringErr)
		}
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "printableString", "SIZE (1..128)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	case X520LocalityNameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("%w: choice X520LocalityName: universalString is nil", ber.ErrInvalidValue)
		}
		enc_2, stringErr := ber.EncodeStringTagChecked(28, *v.UniversalString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding universalString: %w", stringErr)
		}
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "universalString", "SIZE (1..128)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_2, nil
	case X520LocalityNameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("%w: choice X520LocalityName: utf8String is nil", ber.ErrInvalidValue)
		}
		enc_3, stringErr := ber.EncodeStringTagChecked(12, *v.Utf8String)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding utf8String: %w", stringErr)
		}
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "utf8String", "SIZE (1..128)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_3, nil
	case X520LocalityNameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("%w: choice X520LocalityName: bmpString is nil", ber.ErrInvalidValue)
		}
		enc_4, stringErr := ber.EncodeStringTagChecked(30, *v.BmpString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding bmpString: %w", stringErr)
		}
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmpString", "SIZE (1..128)", len([]rune(*v.BmpString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520LocalityName", v.Choice)
	}
}

// MarshalDER encodes X520LocalityName to DER format.
func (v *X520LocalityName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: X520LocalityName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding X520LocalityName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes X520LocalityName from BER/DER format.
func (v *X520LocalityName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: X520LocalityName destination is nil", ber.ErrInvalidValue)
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
	*v = X520LocalityName{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520LocalityName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520LocalityName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520LocalityName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520LocalityName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520LocalityNameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "teletexString", "SIZE (1..128)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520LocalityNameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "printableString", "SIZE (1..128)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520LocalityNameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "universalString", "SIZE (1..128)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520LocalityNameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "utf8String", "SIZE (1..128)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520LocalityNameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "bmpString", "SIZE (1..128)", len([]rune(*v.BmpString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for X520LocalityName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520StateOrProvinceName to BER format.
func (v *X520StateOrProvinceName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: X520StateOrProvinceName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *X520StateOrProvinceName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case X520StateOrProvinceNameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("%w: choice X520StateOrProvinceName: teletexString is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletexString: %w", stringErr)
		}
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "teletexString", "SIZE (1..128)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case X520StateOrProvinceNameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("%w: choice X520StateOrProvinceName: printableString is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printableString: %w", stringErr)
		}
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "printableString", "SIZE (1..128)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	case X520StateOrProvinceNameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("%w: choice X520StateOrProvinceName: universalString is nil", ber.ErrInvalidValue)
		}
		enc_2, stringErr := ber.EncodeStringTagChecked(28, *v.UniversalString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding universalString: %w", stringErr)
		}
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "universalString", "SIZE (1..128)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_2, nil
	case X520StateOrProvinceNameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("%w: choice X520StateOrProvinceName: utf8String is nil", ber.ErrInvalidValue)
		}
		enc_3, stringErr := ber.EncodeStringTagChecked(12, *v.Utf8String)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding utf8String: %w", stringErr)
		}
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "utf8String", "SIZE (1..128)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_3, nil
	case X520StateOrProvinceNameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("%w: choice X520StateOrProvinceName: bmpString is nil", ber.ErrInvalidValue)
		}
		enc_4, stringErr := ber.EncodeStringTagChecked(30, *v.BmpString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding bmpString: %w", stringErr)
		}
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmpString", "SIZE (1..128)", len([]rune(*v.BmpString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520StateOrProvinceName", v.Choice)
	}
}

// MarshalDER encodes X520StateOrProvinceName to DER format.
func (v *X520StateOrProvinceName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: X520StateOrProvinceName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding X520StateOrProvinceName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes X520StateOrProvinceName from BER/DER format.
func (v *X520StateOrProvinceName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: X520StateOrProvinceName destination is nil", ber.ErrInvalidValue)
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
	*v = X520StateOrProvinceName{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520StateOrProvinceName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520StateOrProvinceName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520StateOrProvinceName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520StateOrProvinceName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520StateOrProvinceNameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "teletexString", "SIZE (1..128)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520StateOrProvinceNameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "printableString", "SIZE (1..128)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520StateOrProvinceNameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "universalString", "SIZE (1..128)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520StateOrProvinceNameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "utf8String", "SIZE (1..128)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520StateOrProvinceNameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "bmpString", "SIZE (1..128)", len([]rune(*v.BmpString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for X520StateOrProvinceName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520OrganizationName to BER format.
func (v *X520OrganizationName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: X520OrganizationName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *X520OrganizationName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case X520OrganizationNameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("%w: choice X520OrganizationName: teletexString is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletexString: %w", stringErr)
		}
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "teletexString", "SIZE (1..64)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case X520OrganizationNameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("%w: choice X520OrganizationName: printableString is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printableString: %w", stringErr)
		}
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "printableString", "SIZE (1..64)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	case X520OrganizationNameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("%w: choice X520OrganizationName: universalString is nil", ber.ErrInvalidValue)
		}
		enc_2, stringErr := ber.EncodeStringTagChecked(28, *v.UniversalString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding universalString: %w", stringErr)
		}
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "universalString", "SIZE (1..64)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_2, nil
	case X520OrganizationNameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("%w: choice X520OrganizationName: utf8String is nil", ber.ErrInvalidValue)
		}
		enc_3, stringErr := ber.EncodeStringTagChecked(12, *v.Utf8String)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding utf8String: %w", stringErr)
		}
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "utf8String", "SIZE (1..64)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_3, nil
	case X520OrganizationNameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("%w: choice X520OrganizationName: bmpString is nil", ber.ErrInvalidValue)
		}
		enc_4, stringErr := ber.EncodeStringTagChecked(30, *v.BmpString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding bmpString: %w", stringErr)
		}
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmpString", "SIZE (1..64)", len([]rune(*v.BmpString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520OrganizationName", v.Choice)
	}
}

// MarshalDER encodes X520OrganizationName to DER format.
func (v *X520OrganizationName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: X520OrganizationName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding X520OrganizationName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes X520OrganizationName from BER/DER format.
func (v *X520OrganizationName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: X520OrganizationName destination is nil", ber.ErrInvalidValue)
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
	*v = X520OrganizationName{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520OrganizationName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520OrganizationName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520OrganizationName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520OrganizationName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520OrganizationNameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "teletexString", "SIZE (1..64)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520OrganizationNameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "printableString", "SIZE (1..64)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520OrganizationNameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "universalString", "SIZE (1..64)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520OrganizationNameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "utf8String", "SIZE (1..64)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520OrganizationNameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "bmpString", "SIZE (1..64)", len([]rune(*v.BmpString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for X520OrganizationName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520OrganizationalUnitName to BER format.
func (v *X520OrganizationalUnitName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: X520OrganizationalUnitName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *X520OrganizationalUnitName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case X520OrganizationalUnitNameChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("%w: choice X520OrganizationalUnitName: teletexString is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletexString: %w", stringErr)
		}
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "teletexString", "SIZE (1..64)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case X520OrganizationalUnitNameChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("%w: choice X520OrganizationalUnitName: printableString is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printableString: %w", stringErr)
		}
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "printableString", "SIZE (1..64)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	case X520OrganizationalUnitNameChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("%w: choice X520OrganizationalUnitName: universalString is nil", ber.ErrInvalidValue)
		}
		enc_2, stringErr := ber.EncodeStringTagChecked(28, *v.UniversalString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding universalString: %w", stringErr)
		}
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "universalString", "SIZE (1..64)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_2, nil
	case X520OrganizationalUnitNameChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("%w: choice X520OrganizationalUnitName: utf8String is nil", ber.ErrInvalidValue)
		}
		enc_3, stringErr := ber.EncodeStringTagChecked(12, *v.Utf8String)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding utf8String: %w", stringErr)
		}
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "utf8String", "SIZE (1..64)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_3, nil
	case X520OrganizationalUnitNameChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("%w: choice X520OrganizationalUnitName: bmpString is nil", ber.ErrInvalidValue)
		}
		enc_4, stringErr := ber.EncodeStringTagChecked(30, *v.BmpString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding bmpString: %w", stringErr)
		}
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmpString", "SIZE (1..64)", len([]rune(*v.BmpString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520OrganizationalUnitName", v.Choice)
	}
}

// MarshalDER encodes X520OrganizationalUnitName to DER format.
func (v *X520OrganizationalUnitName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: X520OrganizationalUnitName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding X520OrganizationalUnitName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes X520OrganizationalUnitName from BER/DER format.
func (v *X520OrganizationalUnitName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: X520OrganizationalUnitName destination is nil", ber.ErrInvalidValue)
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
	*v = X520OrganizationalUnitName{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520OrganizationalUnitName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520OrganizationalUnitName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520OrganizationalUnitName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520OrganizationalUnitName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520OrganizationalUnitNameChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "teletexString", "SIZE (1..64)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520OrganizationalUnitNameChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "printableString", "SIZE (1..64)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520OrganizationalUnitNameChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "universalString", "SIZE (1..64)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520OrganizationalUnitNameChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "utf8String", "SIZE (1..64)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520OrganizationalUnitNameChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "bmpString", "SIZE (1..64)", len([]rune(*v.BmpString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for X520OrganizationalUnitName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520Title to BER format.
func (v *X520Title) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: X520Title receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *X520Title) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case X520TitleChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("%w: choice X520Title: teletexString is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletexString: %w", stringErr)
		}
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "teletexString", "SIZE (1..64)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case X520TitleChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("%w: choice X520Title: printableString is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printableString: %w", stringErr)
		}
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "printableString", "SIZE (1..64)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	case X520TitleChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("%w: choice X520Title: universalString is nil", ber.ErrInvalidValue)
		}
		enc_2, stringErr := ber.EncodeStringTagChecked(28, *v.UniversalString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding universalString: %w", stringErr)
		}
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "universalString", "SIZE (1..64)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_2, nil
	case X520TitleChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("%w: choice X520Title: utf8String is nil", ber.ErrInvalidValue)
		}
		enc_3, stringErr := ber.EncodeStringTagChecked(12, *v.Utf8String)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding utf8String: %w", stringErr)
		}
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "utf8String", "SIZE (1..64)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_3, nil
	case X520TitleChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("%w: choice X520Title: bmpString is nil", ber.ErrInvalidValue)
		}
		enc_4, stringErr := ber.EncodeStringTagChecked(30, *v.BmpString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding bmpString: %w", stringErr)
		}
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmpString", "SIZE (1..64)", len([]rune(*v.BmpString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520Title", v.Choice)
	}
}

// MarshalDER encodes X520Title to DER format.
func (v *X520Title) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: X520Title receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding X520Title as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes X520Title from BER/DER format.
func (v *X520Title) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: X520Title destination is nil", ber.ErrInvalidValue)
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
	*v = X520Title{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520Title CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520Title: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520Title CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520Title", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520TitleChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "teletexString", "SIZE (1..64)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520TitleChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "printableString", "SIZE (1..64)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520TitleChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "universalString", "SIZE (1..64)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520TitleChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "utf8String", "SIZE (1..64)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520TitleChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 64 {
			if constraintErr := ber.CheckDecodedLength(opts, "bmpString", "SIZE (1..64)", len([]rune(*v.BmpString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for X520Title CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes X520Pseudonym to BER format.
func (v *X520Pseudonym) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: X520Pseudonym receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *X520Pseudonym) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case X520PseudonymChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("%w: choice X520Pseudonym: teletexString is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletexString: %w", stringErr)
		}
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "teletexString", "SIZE (1..128)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case X520PseudonymChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("%w: choice X520Pseudonym: printableString is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printableString: %w", stringErr)
		}
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "printableString", "SIZE (1..128)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	case X520PseudonymChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("%w: choice X520Pseudonym: universalString is nil", ber.ErrInvalidValue)
		}
		enc_2, stringErr := ber.EncodeStringTagChecked(28, *v.UniversalString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding universalString: %w", stringErr)
		}
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "universalString", "SIZE (1..128)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_2, nil
	case X520PseudonymChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("%w: choice X520Pseudonym: utf8String is nil", ber.ErrInvalidValue)
		}
		enc_3, stringErr := ber.EncodeStringTagChecked(12, *v.Utf8String)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding utf8String: %w", stringErr)
		}
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "utf8String", "SIZE (1..128)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_3, nil
	case X520PseudonymChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("%w: choice X520Pseudonym: bmpString is nil", ber.ErrInvalidValue)
		}
		enc_4, stringErr := ber.EncodeStringTagChecked(30, *v.BmpString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding bmpString: %w", stringErr)
		}
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 128 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmpString", "SIZE (1..128)", len([]rune(*v.BmpString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for X520Pseudonym", v.Choice)
	}
}

// MarshalDER encodes X520Pseudonym to DER format.
func (v *X520Pseudonym) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: X520Pseudonym receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding X520Pseudonym as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes X520Pseudonym from BER/DER format.
func (v *X520Pseudonym) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: X520Pseudonym destination is nil", ber.ErrInvalidValue)
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
	*v = X520Pseudonym{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for X520Pseudonym CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for X520Pseudonym: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding X520Pseudonym CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "X520Pseudonym", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = X520PseudonymChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "teletexString", "SIZE (1..128)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = X520PseudonymChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "printableString", "SIZE (1..128)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = X520PseudonymChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
		if len([]rune(*v.UniversalString)) < 1 || len([]rune(*v.UniversalString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "universalString", "SIZE (1..128)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = X520PseudonymChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
		if len([]rune(*v.Utf8String)) < 1 || len([]rune(*v.Utf8String)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "utf8String", "SIZE (1..128)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = X520PseudonymChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
		if len([]rune(*v.BmpString)) < 1 || len([]rune(*v.BmpString)) > 128 {
			if constraintErr := ber.CheckDecodedLength(opts, "bmpString", "SIZE (1..128)", len([]rune(*v.BmpString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for X520Pseudonym CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Name to BER format.
func (v *Name) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Name receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Name) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case NameChoiceRdnSequence:
		enc_0, err := MarshalBERRDNSequence(v.RdnSequence, ber.ChildEncodeOptions(opts, "rdnSequence")...)
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
	if v == nil {
		return nil, fmt.Errorf("%w: Name receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case NameChoiceRdnSequence:
		enc_der_0, err := MarshalDERRDNSequence(v.RdnSequence)
		if err != nil {
			return nil, fmt.Errorf("encoding rdnSequence: %w", err)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding rdnSequence as DER: %w", derErr)
		}
		return enc_der_0, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Name as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Name from BER/DER format.
func (v *Name) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Name destination is nil", ber.ErrInvalidValue)
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
	*v = Name{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Name CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Name: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding Name CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Name", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = NameChoiceRdnSequence
		dec, unmErr := UnmarshalBERRDNSequence(choiceData, ber.ChildDecodeOptions(opts, "rdnSequence")...)
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
func MarshalBERRDNSequence(collection *RDNSequence, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERRDNSequence(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERRDNSequence(collection *RDNSequence, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		enc, err := MarshalBERRelativeDistinguishedName(elem, ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERRDNSequence encodes a RDNSequence list to DER.
func MarshalDERRDNSequence(collection *RDNSequence) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for _, elem := range list {
		enc, err := MarshalDERRelativeDistinguishedName(elem)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RDNSequence as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERRDNSequence decodes a RDNSequence list from BER.
func UnmarshalBERRDNSequence(data []byte, opts ...ber.DecodeOption) (returnValue *RDNSequence, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding RDNSequence: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RDNSequence", Cause: ber.ErrExtraData}
	}
	var result []*RelativeDistinguishedName
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		elem, unmErr := UnmarshalBERRelativeDistinguishedName(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...)
		if unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	decoded := &RDNSequence{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERRDNSequence(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERRelativeDistinguishedName encodes a RelativeDistinguishedName list to BER.
func MarshalBERRelativeDistinguishedName(collection *RelativeDistinguishedName, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERRelativeDistinguishedName(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERRelativeDistinguishedName(collection *RelativeDistinguishedName, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "RelativeDistinguishedName", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSet(children)
}

// MarshalDERRelativeDistinguishedName encodes a RelativeDistinguishedName list to DER.
func MarshalDERRelativeDistinguishedName(collection *RelativeDistinguishedName) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "RelativeDistinguishedName", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeDERSetOf(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RelativeDistinguishedName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERRelativeDistinguishedName decodes a RelativeDistinguishedName list from BER.
func UnmarshalBERRelativeDistinguishedName(data []byte, opts ...ber.DecodeOption) (returnValue *RelativeDistinguishedName, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding RelativeDistinguishedName: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding RelativeDistinguishedName: %w: expected SET, got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RelativeDistinguishedName", Cause: ber.ErrExtraData}
	}
	var result []AttributeTypeAndValue
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem AttributeTypeAndValue
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "RelativeDistinguishedName", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &RelativeDistinguishedName{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERRelativeDistinguishedName(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes DirectoryString to BER format.
func (v *DirectoryString) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DirectoryString receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DirectoryString) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case DirectoryStringChoiceTeletexString:
		if v.TeletexString == nil {
			return nil, fmt.Errorf("%w: choice DirectoryString: teletexString is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletexString: %w", stringErr)
		}
		if len([]rune(*v.TeletexString)) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "teletexString", "SIZE (1..MAX)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case DirectoryStringChoicePrintableString:
		if v.PrintableString == nil {
			return nil, fmt.Errorf("%w: choice DirectoryString: printableString is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printableString: %w", stringErr)
		}
		if len([]rune(*v.PrintableString)) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "printableString", "SIZE (1..MAX)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	case DirectoryStringChoiceUniversalString:
		if v.UniversalString == nil {
			return nil, fmt.Errorf("%w: choice DirectoryString: universalString is nil", ber.ErrInvalidValue)
		}
		enc_2, stringErr := ber.EncodeStringTagChecked(28, *v.UniversalString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding universalString: %w", stringErr)
		}
		if len([]rune(*v.UniversalString)) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "universalString", "SIZE (1..MAX)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_2, nil
	case DirectoryStringChoiceUtf8String:
		if v.Utf8String == nil {
			return nil, fmt.Errorf("%w: choice DirectoryString: utf8String is nil", ber.ErrInvalidValue)
		}
		enc_3, stringErr := ber.EncodeStringTagChecked(12, *v.Utf8String)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding utf8String: %w", stringErr)
		}
		if len([]rune(*v.Utf8String)) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "utf8String", "SIZE (1..MAX)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_3, nil
	case DirectoryStringChoiceBmpString:
		if v.BmpString == nil {
			return nil, fmt.Errorf("%w: choice DirectoryString: bmpString is nil", ber.ErrInvalidValue)
		}
		enc_4, stringErr := ber.EncodeStringTagChecked(30, *v.BmpString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding bmpString: %w", stringErr)
		}
		if len([]rune(*v.BmpString)) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmpString", "SIZE (1..MAX)", len([]rune(*v.BmpString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DirectoryString", v.Choice)
	}
}

// MarshalDER encodes DirectoryString to DER format.
func (v *DirectoryString) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DirectoryString receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DirectoryString as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DirectoryString from BER/DER format.
func (v *DirectoryString) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DirectoryString destination is nil", ber.ErrInvalidValue)
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
	*v = DirectoryString{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for DirectoryString CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DirectoryString: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding DirectoryString CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DirectoryString", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
		v.Choice = DirectoryStringChoiceTeletexString
		decVal, _, strErr := ber.DecodeString(choiceData, 20, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding teletexString: %w", strErr)
		}
		v.TeletexString = &decVal
		if len([]rune(*v.TeletexString)) < 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "teletexString", "SIZE (1..MAX)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = DirectoryStringChoicePrintableString
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printableString: %w", strErr)
		}
		v.PrintableString = &decVal
		if len([]rune(*v.PrintableString)) < 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "printableString", "SIZE (1..MAX)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 28 {
		v.Choice = DirectoryStringChoiceUniversalString
		decVal, _, strErr := ber.DecodeString(choiceData, 28, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding universalString: %w", strErr)
		}
		v.UniversalString = &decVal
		if len([]rune(*v.UniversalString)) < 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "universalString", "SIZE (1..MAX)", len([]rune(*v.UniversalString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 12 {
		v.Choice = DirectoryStringChoiceUtf8String
		decVal, _, strErr := ber.DecodeString(choiceData, 12, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding utf8String: %w", strErr)
		}
		v.Utf8String = &decVal
		if len([]rune(*v.Utf8String)) < 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "utf8String", "SIZE (1..MAX)", len([]rune(*v.Utf8String))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 30 {
		v.Choice = DirectoryStringChoiceBmpString
		decVal, _, strErr := ber.DecodeString(choiceData, 30, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding bmpString: %w", strErr)
		}
		v.BmpString = &decVal
		if len([]rune(*v.BmpString)) < 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "bmpString", "SIZE (1..MAX)", len([]rune(*v.BmpString))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for DirectoryString CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Certificate to BER format.
func (v *Certificate) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Certificate receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Certificate) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_tbscertificate, err := v.TbsCertificate.MarshalBER(ber.ChildEncodeOptions(opts, "tbsCertificate")...)
	if err != nil {
		return nil, fmt.Errorf("encoding tbsCertificate: %w", err)
	}
	children = append(children, enc_tbscertificate...)
	enc_signaturealgorithm, err := v.SignatureAlgorithm.MarshalBER(ber.ChildEncodeOptions(opts, "signatureAlgorithm")...)
	if err != nil {
		return nil, fmt.Errorf("encoding signatureAlgorithm: %w", err)
	}
	children = append(children, enc_signaturealgorithm...)
	if bitStringErr := ber.ValidateBitStringLength(v.Signature.Bytes, v.Signature.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "signature", bitStringErr)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:550
	if v.Signature.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	enc_signature, encodeErr_enc_signature := ber.EncodeBitString(v.Signature.Bytes, (8-(v.Signature.BitLength%8))%8)
	if encodeErr_enc_signature != nil {
		return nil, fmt.Errorf("encoding signature: %w", encodeErr_enc_signature)
	}
	children = append(children, enc_signature...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes Certificate to DER format.
func (v *Certificate) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Certificate receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_tbscertificate, err := v.TbsCertificate.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding tbsCertificate: %w", err)
	}
	children = append(children, enc_tbscertificate...)
	enc_signaturealgorithm, err := v.SignatureAlgorithm.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding signatureAlgorithm: %w", err)
	}
	children = append(children, enc_signaturealgorithm...)
	if bitStringErr := ber.ValidateBitStringLength(v.Signature.Bytes, v.Signature.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "signature", bitStringErr)
	}
	if bitStringErr := ber.ValidateDERBitString(v.Signature.Bytes, v.Signature.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "signature", bitStringErr)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:550
	if v.Signature.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	enc_signature, encodeErr_enc_signature := ber.EncodeBitString(v.Signature.Bytes, (8-(v.Signature.BitLength%8))%8)
	if encodeErr_enc_signature != nil {
		return nil, fmt.Errorf("encoding signature: %w", encodeErr_enc_signature)
	}
	children = append(children, enc_signature...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Certificate as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Certificate from BER/DER format.
func (v *Certificate) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Certificate destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = Certificate{}
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
	_, n_tbscertificate, _, tlvErr_tbscertificate := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_tbscertificate != nil {
		return fmt.Errorf("decoding tbsCertificate: %w", tlvErr_tbscertificate)
	}
	if offset > len(content) || n_tbscertificate < 0 || n_tbscertificate > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.TbsCertificate.UnmarshalBER(content[offset:offset+n_tbscertificate], ber.ChildDecodeOptions(opts, "tbsCertificate")...); unmErr != nil {
		return fmt.Errorf("decoding tbsCertificate: %w", unmErr)
	}
	if offset > len(content) || n_tbscertificate < 0 || n_tbscertificate > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_tbscertificate
	// Decode signatureAlgorithm
	if offset >= len(content) {
		return fmt.Errorf("missing required field signatureAlgorithm")
	}
	// Decode nested SEQUENCE (AlgorithmIdentifier)
	_, n_signaturealgorithm, _, tlvErr_signaturealgorithm := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_signaturealgorithm != nil {
		return fmt.Errorf("decoding signatureAlgorithm: %w", tlvErr_signaturealgorithm)
	}
	if offset < 0 || offset >
		len(content) || n_signaturealgorithm < 0 || n_signaturealgorithm >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.SignatureAlgorithm.UnmarshalBER(content[offset:offset+n_signaturealgorithm], ber.ChildDecodeOptions(opts, "signatureAlgorithm")...); unmErr != nil {
		return fmt.Errorf("decoding signatureAlgorithm: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_signaturealgorithm < 0 || n_signaturealgorithm >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_signaturealgorithm
	// Decode signature
	if offset >= len(content) {
		return fmt.Errorf("missing required field signature")
	}
	bsBytes_signature, bsUnused_signature, n, err := ber.DecodeBitString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	bsBitLength_signature, bsLenErr_signature := ber.BitStringBitLength(len(bsBytes_signature), bsUnused_signature)
	if bsLenErr_signature != nil {
		return fmt.Errorf("decoding signature: %w", bsLenErr_signature)
	}
	v.Signature = runtime.BitString{Bytes: bsBytes_signature, BitLength: bsBitLength_signature}
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Certificate", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TBSCertificate to BER format.
func (v *TBSCertificate) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TBSCertificate receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TBSCertificate) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Version != nil {
		enc_version, encodeErr_enc_version := ber.EncodeBigInt((*v.Version).BigInt())
		if encodeErr_enc_version != nil {
			return nil, fmt.Errorf("encoding version: %w", encodeErr_enc_version)
		}
		{
			var encodeErr error
			enc_version, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_version)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding version: %w", encodeErr)
			}
		}
		children = append(children, enc_version...)
	}
	if v.SerialNumber == nil {
		return nil, fmt.Errorf("encoding serialNumber: %w: required INTEGER is nil", ber.ErrInvalidValue)
	}
	enc_serialnumber, encodeErr_enc_serialnumber := ber.EncodeBigInt(v.SerialNumber)
	if encodeErr_enc_serialnumber != nil {
		return nil, fmt.Errorf("encoding serialNumber: %w", encodeErr_enc_serialnumber)
	}
	children = append(children, enc_serialnumber...)
	enc_signature, err := v.Signature.MarshalBER(ber.ChildEncodeOptions(opts, "signature")...)
	if err != nil {
		return nil, fmt.Errorf("encoding signature: %w", err)
	}
	children = append(children, enc_signature...)
	enc_issuer, err := v.Issuer.MarshalBER(ber.ChildEncodeOptions(opts, "issuer")...)
	if err != nil {
		return nil, fmt.Errorf("encoding issuer: %w", err)
	}
	children = append(children, enc_issuer...)
	enc_validity, err := v.Validity.MarshalBER(ber.ChildEncodeOptions(opts, "validity")...)
	if err != nil {
		return nil, fmt.Errorf("encoding validity: %w", err)
	}
	children = append(children, enc_validity...)
	enc_subject, err := v.Subject.MarshalBER(ber.ChildEncodeOptions(opts, "subject")...)
	if err != nil {
		return nil, fmt.Errorf("encoding subject: %w", err)
	}
	children = append(children, enc_subject...)
	enc_subjectpublickeyinfo, err := v.SubjectPublicKeyInfo.MarshalBER(ber.ChildEncodeOptions(opts, "subjectPublicKeyInfo")...)
	if err != nil {
		return nil, fmt.Errorf("encoding subjectPublicKeyInfo: %w", err)
	}
	children = append(children, enc_subjectpublickeyinfo...)
	if v.IssuerUniqueID != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.IssuerUniqueID.Bytes, v.IssuerUniqueID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "issuerUniqueID", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:550
		if v.IssuerUniqueID.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_issueruniqueid, encodeErr_enc_issueruniqueid := ber.EncodeBitString(v.IssuerUniqueID.Bytes, (8-(v.IssuerUniqueID.BitLength%8))%8)
		if encodeErr_enc_issueruniqueid != nil {
			return nil, fmt.Errorf("encoding issuerUniqueID: %w", encodeErr_enc_issueruniqueid)
		}
		retagged_enc_issueruniqueid, tagErr_enc_issueruniqueid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_issueruniqueid)
		if tagErr_enc_issueruniqueid != nil {
			return nil, fmt.Errorf("encoding issuerUniqueID: %w", tagErr_enc_issueruniqueid)
		}
		enc_issueruniqueid = retagged_enc_issueruniqueid
		children = append(children, enc_issueruniqueid...)
	}
	if v.SubjectUniqueID != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SubjectUniqueID.Bytes, v.SubjectUniqueID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "subjectUniqueID", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:550
		if v.SubjectUniqueID.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_subjectuniqueid, encodeErr_enc_subjectuniqueid := ber.EncodeBitString(v.SubjectUniqueID.Bytes, (8-(v.SubjectUniqueID.BitLength%8))%8)
		if encodeErr_enc_subjectuniqueid != nil {
			return nil, fmt.Errorf("encoding subjectUniqueID: %w", encodeErr_enc_subjectuniqueid)
		}
		retagged_enc_subjectuniqueid, tagErr_enc_subjectuniqueid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_subjectuniqueid)
		if tagErr_enc_subjectuniqueid != nil {
			return nil, fmt.Errorf("encoding subjectUniqueID: %w", tagErr_enc_subjectuniqueid)
		}
		enc_subjectuniqueid = retagged_enc_subjectuniqueid
		children = append(children, enc_subjectuniqueid...)
	}
	if v.Extensions != nil {
		if len((v.Extensions).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "extensions", "SIZE (1..MAX)", len((v.Extensions).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_extensions, err := MarshalBERExtensions(v.Extensions, ber.ChildEncodeOptions(opts, "extensions")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensions: %w", err)
		}
		{
			var encodeErr error
			enc_extensions, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensions)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding extensions: %w", encodeErr)
			}
		}
		children = append(children, enc_extensions...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TBSCertificate to DER format.
func (v *TBSCertificate) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TBSCertificate receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Version != nil {
		enc_version, encodeErr_enc_version := ber.EncodeBigInt((*v.Version).BigInt())
		if encodeErr_enc_version != nil {
			return nil, fmt.Errorf("encoding version: %w", encodeErr_enc_version)
		}
		if string(enc_version) != "\x02\x01\x00" {
			{
				var encodeErr error
				enc_version, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_version)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding version: %w", encodeErr)
				}
			}
			children = append(children, enc_version...)
		}
	}
	if v.SerialNumber == nil {
		return nil, fmt.Errorf("encoding serialNumber: %w: required INTEGER is nil", ber.ErrInvalidValue)
	}
	enc_serialnumber, encodeErr_enc_serialnumber := ber.EncodeBigInt(v.SerialNumber)
	if encodeErr_enc_serialnumber != nil {
		return nil, fmt.Errorf("encoding serialNumber: %w", encodeErr_enc_serialnumber)
	}
	children = append(children, enc_serialnumber...)
	enc_signature, err := v.Signature.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding signature: %w", err)
	}
	children = append(children, enc_signature...)
	enc_issuer, err := v.Issuer.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding issuer: %w", err)
	}
	children = append(children, enc_issuer...)
	enc_validity, err := v.Validity.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding validity: %w", err)
	}
	children = append(children, enc_validity...)
	enc_subject, err := v.Subject.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding subject: %w", err)
	}
	children = append(children, enc_subject...)
	enc_subjectpublickeyinfo, err := v.SubjectPublicKeyInfo.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding subjectPublicKeyInfo: %w", err)
	}
	children = append(children, enc_subjectpublickeyinfo...)
	if v.IssuerUniqueID != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.IssuerUniqueID.Bytes, v.IssuerUniqueID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "issuerUniqueID", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.IssuerUniqueID.Bytes, v.IssuerUniqueID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "issuerUniqueID", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:550
		if v.IssuerUniqueID.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_issueruniqueid, encodeErr_enc_issueruniqueid := ber.EncodeBitString(v.IssuerUniqueID.Bytes, (8-(v.IssuerUniqueID.BitLength%8))%8)
		if encodeErr_enc_issueruniqueid != nil {
			return nil, fmt.Errorf("encoding issuerUniqueID: %w", encodeErr_enc_issueruniqueid)
		}
		retagged_enc_issueruniqueid, tagErr_enc_issueruniqueid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_issueruniqueid)
		if tagErr_enc_issueruniqueid != nil {
			return nil, fmt.Errorf("encoding issuerUniqueID: %w", tagErr_enc_issueruniqueid)
		}
		enc_issueruniqueid = retagged_enc_issueruniqueid
		children = append(children, enc_issueruniqueid...)
	}
	if v.SubjectUniqueID != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SubjectUniqueID.Bytes, v.SubjectUniqueID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "subjectUniqueID", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SubjectUniqueID.Bytes, v.SubjectUniqueID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "subjectUniqueID", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:550
		if v.SubjectUniqueID.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_subjectuniqueid, encodeErr_enc_subjectuniqueid := ber.EncodeBitString(v.SubjectUniqueID.Bytes, (8-(v.SubjectUniqueID.BitLength%8))%8)
		if encodeErr_enc_subjectuniqueid != nil {
			return nil, fmt.Errorf("encoding subjectUniqueID: %w", encodeErr_enc_subjectuniqueid)
		}
		retagged_enc_subjectuniqueid, tagErr_enc_subjectuniqueid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_subjectuniqueid)
		if tagErr_enc_subjectuniqueid != nil {
			return nil, fmt.Errorf("encoding subjectUniqueID: %w", tagErr_enc_subjectuniqueid)
		}
		enc_subjectuniqueid = retagged_enc_subjectuniqueid
		children = append(children, enc_subjectuniqueid...)
	}
	if v.Extensions != nil {
		if len((v.Extensions).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "extensions", "SIZE (1..MAX)", len((v.Extensions).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_extensions, err := MarshalDERExtensions(v.Extensions)
		if err != nil {
			return nil, fmt.Errorf("encoding extensions: %w", err)
		}
		{
			var encodeErr error
			enc_extensions, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensions)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding extensions: %w", encodeErr)
			}
		}
		children = append(children, enc_extensions...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TBSCertificate as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TBSCertificate from BER/DER format.
func (v *TBSCertificate) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TBSCertificate destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TBSCertificate{}
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
				decodedTag_version, n_version, innerData_version, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding version: %w", err)
				}
				if decodedTag_version.Class != tag.ClassContextSpecific || decodedTag_version.Number != 0 || decodedTag_version.Constructed != true {
					return fmt.Errorf("decoding version: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_version)
				}
				_, innerUsed_version, _, innerErr_version := ber.DecodeTLV(innerData_version, opts...)
				if innerErr_version != nil {
					return fmt.Errorf("decoding version: %w", innerErr_version)
				}
				if innerUsed_version != len(innerData_version) {
					return fmt.Errorf("decoding version: %w", ber.ErrExtraData)
				}
				// Decode inner value from explicit tag wrapper
				val_version, _, err := ber.DecodeBigInt(innerData_version, opts...)
				if err != nil {
					return fmt.Errorf("decoding version: %w", err)
				}
				var named_version Version
				if namedErr := named_version.UnmarshalText([]byte(val_version.String())); namedErr != nil {
					return fmt.Errorf("decoding version: %w", namedErr)
				}
				v.Version = &named_version
				if offset > len(content) || n_version < 0 || n_version > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_version
			}
		}
	}
	// Decode serialNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field serialNumber")
	}
	val_serialnumber, n, err := ber.DecodeBigInt(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding serialNumber: %w", err)
	}
	v.SerialNumber = val_serialnumber
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode signature
	if offset >= len(content) {
		return fmt.Errorf("missing required field signature")
	}
	// Decode nested SEQUENCE (AlgorithmIdentifier)
	_, n_signature, _, tlvErr_signature := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_signature != nil {
		return fmt.Errorf("decoding signature: %w", tlvErr_signature)
	}
	if offset < 0 || offset >
		len(content) || n_signature < 0 || n_signature > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.Signature.UnmarshalBER(content[offset:offset+n_signature], ber.ChildDecodeOptions(opts, "signature")...); unmErr != nil {
		return fmt.Errorf("decoding signature: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_signature < 0 || n_signature > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_signature
	// Decode issuer
	if offset >= len(content) {
		return fmt.Errorf("missing required field issuer")
	}
	// Decode nested CHOICE (Name)
	_, n_issuer, _, tlvErr_issuer := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_issuer != nil {
		return fmt.Errorf("decoding issuer: %w", tlvErr_issuer)
	}
	if offset < 0 || offset >
		len(content) || n_issuer < 0 || n_issuer > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.Issuer.UnmarshalBER(content[offset:offset+n_issuer], ber.ChildDecodeOptions(opts, "issuer")...); unmErr != nil {
		return fmt.Errorf("decoding issuer: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_issuer < 0 || n_issuer > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_issuer
	// Decode validity
	if offset >= len(content) {
		return fmt.Errorf("missing required field validity")
	}
	// Decode nested SEQUENCE (Validity)
	_, n_validity, _, tlvErr_validity := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_validity != nil {
		return fmt.Errorf("decoding validity: %w", tlvErr_validity)
	}
	if offset < 0 || offset >
		len(content) || n_validity < 0 || n_validity > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.Validity.UnmarshalBER(content[offset:offset+n_validity], ber.ChildDecodeOptions(opts, "validity")...); unmErr != nil {
		return fmt.Errorf("decoding validity: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_validity < 0 || n_validity > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_validity
	// Decode subject
	if offset >= len(content) {
		return fmt.Errorf("missing required field subject")
	}
	// Decode nested CHOICE (Name)
	_, n_subject, _, tlvErr_subject := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_subject != nil {
		return fmt.Errorf("decoding subject: %w", tlvErr_subject)
	}
	if offset < 0 || offset >
		len(content) || n_subject < 0 || n_subject > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.Subject.UnmarshalBER(content[offset:offset+n_subject], ber.ChildDecodeOptions(opts, "subject")...); unmErr != nil {
		return fmt.Errorf("decoding subject: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_subject < 0 || n_subject > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_subject
	// Decode subjectPublicKeyInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field subjectPublicKeyInfo")
	}
	// Decode nested SEQUENCE (SubjectPublicKeyInfo)
	_, n_subjectpublickeyinfo, _, tlvErr_subjectpublickeyinfo := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_subjectpublickeyinfo != nil {
		return fmt.Errorf("decoding subjectPublicKeyInfo: %w", tlvErr_subjectpublickeyinfo)
	}
	if offset < 0 || offset >
		len(content) || n_subjectpublickeyinfo < 0 || n_subjectpublickeyinfo >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.SubjectPublicKeyInfo.UnmarshalBER(content[offset:offset+n_subjectpublickeyinfo], ber.ChildDecodeOptions(opts, "subjectPublicKeyInfo")...); unmErr != nil {
		return fmt.Errorf("decoding subjectPublicKeyInfo: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_subjectpublickeyinfo < 0 || n_subjectpublickeyinfo >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_subjectpublickeyinfo
	// Decode issuerUniqueID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_issueruniqueid, n_issueruniqueid, rawVal_issueruniqueid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding issuerUniqueID: %w", err)
				}
				if decodedTag_issueruniqueid.Class != tag.ClassContextSpecific || decodedTag_issueruniqueid.Number != 1 {
					return fmt.Errorf("decoding issuerUniqueID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_issueruniqueid)
				}
				bsBytes_issueruniqueid, bsUnused_issueruniqueid, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_issueruniqueid.Constructed, rawVal_issueruniqueid, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding issuerUniqueID: %w", bsErr)
				}
				bsBitLength_issueruniqueid, bsLenErr_issueruniqueid := ber.BitStringBitLength(len(bsBytes_issueruniqueid), bsUnused_issueruniqueid)
				if bsLenErr_issueruniqueid != nil {
					return fmt.Errorf("decoding issuerUniqueID: %w", bsLenErr_issueruniqueid)
				}
				tmp_issueruniqueid := runtime.BitString{Bytes: bsBytes_issueruniqueid, BitLength: bsBitLength_issueruniqueid}
				v.IssuerUniqueID = &tmp_issueruniqueid
				if offset < 0 || offset >
					len(content) || n_issueruniqueid < 0 || n_issueruniqueid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_issueruniqueid
			}
		}
	}
	// Decode subjectUniqueID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_subjectuniqueid, n_subjectuniqueid, rawVal_subjectuniqueid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding subjectUniqueID: %w", err)
				}
				if decodedTag_subjectuniqueid.Class != tag.ClassContextSpecific || decodedTag_subjectuniqueid.Number != 2 {
					return fmt.Errorf("decoding subjectUniqueID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_subjectuniqueid)
				}
				bsBytes_subjectuniqueid, bsUnused_subjectuniqueid, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_subjectuniqueid.Constructed, rawVal_subjectuniqueid, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding subjectUniqueID: %w", bsErr)
				}
				bsBitLength_subjectuniqueid, bsLenErr_subjectuniqueid := ber.BitStringBitLength(len(bsBytes_subjectuniqueid), bsUnused_subjectuniqueid)
				if bsLenErr_subjectuniqueid != nil {
					return fmt.Errorf("decoding subjectUniqueID: %w", bsLenErr_subjectuniqueid)
				}
				tmp_subjectuniqueid := runtime.BitString{Bytes: bsBytes_subjectuniqueid, BitLength: bsBitLength_subjectuniqueid}
				v.SubjectUniqueID = &tmp_subjectuniqueid
				if offset < 0 || offset >
					len(content) || n_subjectuniqueid < 0 || n_subjectuniqueid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_subjectuniqueid
			}
		}
	}
	// Decode extensions
	v.ExtensionsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_extensions, n_extensions, innerData_extensions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensions: %w", err)
				}
				if decodedTag_extensions.Class != tag.ClassContextSpecific || decodedTag_extensions.Number != 3 || decodedTag_extensions.Constructed != true {
					return fmt.Errorf("decoding extensions: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensions)
				}
				_, innerUsed_extensions, _, innerErr_extensions := ber.DecodeTLV(innerData_extensions, opts...)
				if innerErr_extensions != nil {
					return fmt.Errorf("decoding extensions: %w", innerErr_extensions)
				}
				if innerUsed_extensions != len(innerData_extensions) {
					return fmt.Errorf("decoding extensions: %w", ber.ErrExtraData)
				}
				// Decode inner value from explicit tag wrapper
				dec_extensions, unmErr := UnmarshalBERExtensions(innerData_extensions, ber.ChildDecodeOptions(opts, "extensions")...)
				if unmErr != nil {
					return fmt.Errorf("decoding extensions: %w", unmErr)
				}
				v.Extensions = dec_extensions
				if offset < 0 || offset >
					len(content) || n_extensions < 0 || n_extensions > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensions
				if len((v.Extensions).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "extensions", "SIZE (1..MAX)", len((v.Extensions).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TBSCertificate", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Validity to BER format.
func (v *Validity) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Validity receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Validity) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_notbefore, err := v.NotBefore.MarshalBER(ber.ChildEncodeOptions(opts, "notBefore")...)
	if err != nil {
		return nil, fmt.Errorf("encoding notBefore: %w", err)
	}
	children = append(children, enc_notbefore...)
	enc_notafter, err := v.NotAfter.MarshalBER(ber.ChildEncodeOptions(opts, "notAfter")...)
	if err != nil {
		return nil, fmt.Errorf("encoding notAfter: %w", err)
	}
	children = append(children, enc_notafter...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes Validity to DER format.
func (v *Validity) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Validity receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_notbefore, err := v.NotBefore.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding notBefore: %w", err)
	}
	children = append(children, enc_notbefore...)
	enc_notafter, err := v.NotAfter.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding notAfter: %w", err)
	}
	children = append(children, enc_notafter...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Validity as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Validity from BER/DER format.
func (v *Validity) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Validity destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = Validity{}
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
	_, n_notbefore, _, tlvErr_notbefore := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_notbefore != nil {
		return fmt.Errorf("decoding notBefore: %w", tlvErr_notbefore)
	}
	if offset > len(content) || n_notbefore < 0 || n_notbefore > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.NotBefore.UnmarshalBER(content[offset:offset+n_notbefore], ber.ChildDecodeOptions(opts, "notBefore")...); unmErr != nil {
		return fmt.Errorf("decoding notBefore: %w", unmErr)
	}
	if offset > len(content) || n_notbefore < 0 || n_notbefore > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_notbefore
	// Decode notAfter
	if offset >= len(content) {
		return fmt.Errorf("missing required field notAfter")
	}
	// Decode nested CHOICE (Time)
	_, n_notafter, _, tlvErr_notafter := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_notafter != nil {
		return fmt.Errorf("decoding notAfter: %w", tlvErr_notafter)
	}
	if offset < 0 || offset >
		len(content) || n_notafter < 0 || n_notafter > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.NotAfter.UnmarshalBER(content[offset:offset+n_notafter], ber.ChildDecodeOptions(opts, "notAfter")...); unmErr != nil {
		return fmt.Errorf("decoding notAfter: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_notafter < 0 || n_notafter > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_notafter
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Validity", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Time to BER format.
func (v *Time) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Time receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Time) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TimeChoiceUtcTime:
		if v.UtcTime == nil {
			return nil, fmt.Errorf("%w: choice Time: utcTime is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeUTCTime(*v.UtcTime)
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding utcTime: %w", encodeErr_enc_0)
		}
		return enc_0, nil
	case TimeChoiceGeneralTime:
		if v.GeneralTime == nil {
			return nil, fmt.Errorf("%w: choice Time: generalTime is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeGeneralizedTime(*v.GeneralTime)
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding generalTime: %w", encodeErr_enc_1)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Time", v.Choice)
	}
}

// MarshalDER encodes Time to DER format.
func (v *Time) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Time receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case TimeChoiceUtcTime:
		if v.UtcTime == nil {
			return nil, fmt.Errorf("%w: choice Time: utcTime is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := ber.EncodeUTCTimeDER(*v.UtcTime)
		if err != nil {
			return nil, fmt.Errorf("encoding utcTime: %w", err)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding utcTime as DER: %w", derErr)
		}
		return enc_der_0, nil
	case TimeChoiceGeneralTime:
		if v.GeneralTime == nil {
			return nil, fmt.Errorf("%w: choice Time: generalTime is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := ber.EncodeGeneralizedTimeDER(*v.GeneralTime)
		if err != nil {
			return nil, fmt.Errorf("encoding generalTime: %w", err)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding generalTime as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Time as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Time from BER/DER format.
func (v *Time) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Time destination is nil", ber.ErrInvalidValue)
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
	*v = Time{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Time CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Time: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding Time CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Time", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 23 {
		v.Choice = TimeChoiceUtcTime
		decVal, _, timeErr := ber.DecodeUTCTime(choiceData, opts...)
		if timeErr != nil {
			return fmt.Errorf("decoding utcTime: %w", timeErr)
		}
		v.UtcTime = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 24 {
		v.Choice = TimeChoiceGeneralTime
		decVal, _, timeErr := ber.DecodeGeneralizedTime(choiceData, opts...)
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
func (v *SubjectPublicKeyInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SubjectPublicKeyInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SubjectPublicKeyInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_algorithm, err := v.Algorithm.MarshalBER(ber.ChildEncodeOptions(opts, "algorithm")...)
	if err != nil {
		return nil, fmt.Errorf("encoding algorithm: %w", err)
	}
	children = append(children, enc_algorithm...)
	if bitStringErr := ber.ValidateBitStringLength(v.SubjectPublicKey.Bytes, v.SubjectPublicKey.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "subjectPublicKey", bitStringErr)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:550
	if v.SubjectPublicKey.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	enc_subjectpublickey, encodeErr_enc_subjectpublickey := ber.EncodeBitString(v.SubjectPublicKey.Bytes, (8-(v.SubjectPublicKey.BitLength%8))%8)
	if encodeErr_enc_subjectpublickey != nil {
		return nil, fmt.Errorf("encoding subjectPublicKey: %w", encodeErr_enc_subjectpublickey)
	}
	children = append(children, enc_subjectpublickey...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SubjectPublicKeyInfo to DER format.
func (v *SubjectPublicKeyInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubjectPublicKeyInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_algorithm, err := v.Algorithm.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding algorithm: %w", err)
	}
	children = append(children, enc_algorithm...)
	if bitStringErr := ber.ValidateBitStringLength(v.SubjectPublicKey.Bytes, v.SubjectPublicKey.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "subjectPublicKey", bitStringErr)
	}
	if bitStringErr := ber.ValidateDERBitString(v.SubjectPublicKey.Bytes, v.SubjectPublicKey.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "subjectPublicKey", bitStringErr)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:550
	if v.SubjectPublicKey.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	enc_subjectpublickey, encodeErr_enc_subjectpublickey := ber.EncodeBitString(v.SubjectPublicKey.Bytes, (8-(v.SubjectPublicKey.BitLength%8))%8)
	if encodeErr_enc_subjectpublickey != nil {
		return nil, fmt.Errorf("encoding subjectPublicKey: %w", encodeErr_enc_subjectpublickey)
	}
	children = append(children, enc_subjectpublickey...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubjectPublicKeyInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubjectPublicKeyInfo from BER/DER format.
func (v *SubjectPublicKeyInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SubjectPublicKeyInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SubjectPublicKeyInfo{}
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
	_, n_algorithm, _, tlvErr_algorithm := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_algorithm != nil {
		return fmt.Errorf("decoding algorithm: %w", tlvErr_algorithm)
	}
	if offset > len(content) || n_algorithm < 0 || n_algorithm > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.Algorithm.UnmarshalBER(content[offset:offset+n_algorithm], ber.ChildDecodeOptions(opts, "algorithm")...); unmErr != nil {
		return fmt.Errorf("decoding algorithm: %w", unmErr)
	}
	if offset > len(content) || n_algorithm < 0 || n_algorithm > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_algorithm
	// Decode subjectPublicKey
	if offset >= len(content) {
		return fmt.Errorf("missing required field subjectPublicKey")
	}
	bsBytes_subjectpublickey, bsUnused_subjectpublickey, n, err := ber.DecodeBitString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding subjectPublicKey: %w", err)
	}
	bsBitLength_subjectpublickey, bsLenErr_subjectpublickey := ber.BitStringBitLength(len(bsBytes_subjectpublickey), bsUnused_subjectpublickey)
	if bsLenErr_subjectpublickey != nil {
		return fmt.Errorf("decoding subjectPublicKey: %w", bsLenErr_subjectpublickey)
	}
	v.SubjectPublicKey = runtime.BitString{Bytes: bsBytes_subjectpublickey, BitLength: bsBitLength_subjectpublickey}
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SubjectPublicKeyInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERExtensions encodes a Extensions list to BER.
func MarshalBERExtensions(collection *Extensions, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERExtensions(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERExtensions(collection *Extensions, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "Extensions", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERExtensions encodes a Extensions list to DER.
func MarshalDERExtensions(collection *Extensions) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "Extensions", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Extensions as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERExtensions decodes a Extensions list from BER.
func UnmarshalBERExtensions(data []byte, opts ...ber.DecodeOption) (returnValue *Extensions, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding Extensions: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "Extensions", Cause: ber.ErrExtraData}
	}
	var result []Extension
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem Extension
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "Extensions", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &Extensions{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERExtensions(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes Extension to BER format.
func (v *Extension) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Extension receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Extension) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_extnid, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ExtnID))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding extnID: %w", oidErr)
	}
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
	enc_extnvalue, encodeErr_enc_extnvalue := ber.EncodeOctetString(v.ExtnValue)
	if encodeErr_enc_extnvalue != nil {
		return nil, fmt.Errorf("encoding extnValue: %w", encodeErr_enc_extnvalue)
	}
	children = append(children, enc_extnvalue...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes Extension to DER format.
func (v *Extension) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Extension receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_extnid, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ExtnID))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding extnID: %w", oidErr)
	}
	children = append(children, enc_extnid...)
	if v.Critical != nil {
		enc_critical := ber.EncodeBoolean(*v.Critical)
		if string(enc_critical) != "\x01\x01\x00" {
			children = append(children, enc_critical...)
		}
	}
	enc_extnvalue, encodeErr_enc_extnvalue := ber.EncodeOctetString(v.ExtnValue)
	if encodeErr_enc_extnvalue != nil {
		return nil, fmt.Errorf("encoding extnValue: %w", encodeErr_enc_extnvalue)
	}
	children = append(children, enc_extnvalue...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Extension as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Extension from BER/DER format.
func (v *Extension) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Extension destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = Extension{}
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
	val_extnid, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding extnID: %w", err)
	}
	v.ExtnID = runtime.ObjectIdentifier(val_extnid)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode critical
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 1 {
				val_critical, raw_critical, n, err := ber.DecodeBoolean(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding critical: %w", err)
				}
				v.Critical = &val_critical
				v.CriticalRaw_ = raw_critical
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	// Decode extnValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field extnValue")
	}
	val_extnvalue, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding extnValue: %w", err)
	}
	v.ExtnValue = val_extnvalue
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Extension", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CertificateList to BER format.
func (v *CertificateList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CertificateList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CertificateList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_tbscertlist, err := v.TbsCertList.MarshalBER(ber.ChildEncodeOptions(opts, "tbsCertList")...)
	if err != nil {
		return nil, fmt.Errorf("encoding tbsCertList: %w", err)
	}
	children = append(children, enc_tbscertlist...)
	enc_signaturealgorithm, err := v.SignatureAlgorithm.MarshalBER(ber.ChildEncodeOptions(opts, "signatureAlgorithm")...)
	if err != nil {
		return nil, fmt.Errorf("encoding signatureAlgorithm: %w", err)
	}
	children = append(children, enc_signaturealgorithm...)
	if bitStringErr := ber.ValidateBitStringLength(v.Signature.Bytes, v.Signature.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "signature", bitStringErr)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:550
	if v.Signature.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	enc_signature, encodeErr_enc_signature := ber.EncodeBitString(v.Signature.Bytes, (8-(v.Signature.BitLength%8))%8)
	if encodeErr_enc_signature != nil {
		return nil, fmt.Errorf("encoding signature: %w", encodeErr_enc_signature)
	}
	children = append(children, enc_signature...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes CertificateList to DER format.
func (v *CertificateList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CertificateList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_tbscertlist, err := v.TbsCertList.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding tbsCertList: %w", err)
	}
	children = append(children, enc_tbscertlist...)
	enc_signaturealgorithm, err := v.SignatureAlgorithm.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding signatureAlgorithm: %w", err)
	}
	children = append(children, enc_signaturealgorithm...)
	if bitStringErr := ber.ValidateBitStringLength(v.Signature.Bytes, v.Signature.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "signature", bitStringErr)
	}
	if bitStringErr := ber.ValidateDERBitString(v.Signature.Bytes, v.Signature.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "signature", bitStringErr)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:550
	if v.Signature.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	enc_signature, encodeErr_enc_signature := ber.EncodeBitString(v.Signature.Bytes, (8-(v.Signature.BitLength%8))%8)
	if encodeErr_enc_signature != nil {
		return nil, fmt.Errorf("encoding signature: %w", encodeErr_enc_signature)
	}
	children = append(children, enc_signature...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CertificateList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CertificateList from BER/DER format.
func (v *CertificateList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CertificateList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CertificateList{}
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
	_, n_tbscertlist, _, tlvErr_tbscertlist := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_tbscertlist != nil {
		return fmt.Errorf("decoding tbsCertList: %w", tlvErr_tbscertlist)
	}
	if offset > len(content) || n_tbscertlist < 0 || n_tbscertlist > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.TbsCertList.UnmarshalBER(content[offset:offset+n_tbscertlist], ber.ChildDecodeOptions(opts, "tbsCertList")...); unmErr != nil {
		return fmt.Errorf("decoding tbsCertList: %w", unmErr)
	}
	if offset > len(content) || n_tbscertlist < 0 || n_tbscertlist > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_tbscertlist
	// Decode signatureAlgorithm
	if offset >= len(content) {
		return fmt.Errorf("missing required field signatureAlgorithm")
	}
	// Decode nested SEQUENCE (AlgorithmIdentifier)
	_, n_signaturealgorithm, _, tlvErr_signaturealgorithm := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_signaturealgorithm != nil {
		return fmt.Errorf("decoding signatureAlgorithm: %w", tlvErr_signaturealgorithm)
	}
	if offset < 0 || offset >
		len(content) || n_signaturealgorithm < 0 || n_signaturealgorithm >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.SignatureAlgorithm.UnmarshalBER(content[offset:offset+n_signaturealgorithm], ber.ChildDecodeOptions(opts, "signatureAlgorithm")...); unmErr != nil {
		return fmt.Errorf("decoding signatureAlgorithm: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_signaturealgorithm < 0 || n_signaturealgorithm >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_signaturealgorithm
	// Decode signature
	if offset >= len(content) {
		return fmt.Errorf("missing required field signature")
	}
	bsBytes_signature, bsUnused_signature, n, err := ber.DecodeBitString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	bsBitLength_signature, bsLenErr_signature := ber.BitStringBitLength(len(bsBytes_signature), bsUnused_signature)
	if bsLenErr_signature != nil {
		return fmt.Errorf("decoding signature: %w", bsLenErr_signature)
	}
	v.Signature = runtime.BitString{Bytes: bsBytes_signature, BitLength: bsBitLength_signature}
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CertificateList", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TBSCertList to BER format.
func (v *TBSCertList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TBSCertList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TBSCertList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Version != nil {
		enc_version, encodeErr_enc_version := ber.EncodeBigInt((*v.Version).BigInt())
		if encodeErr_enc_version != nil {
			return nil, fmt.Errorf("encoding version: %w", encodeErr_enc_version)
		}
		children = append(children, enc_version...)
	}
	enc_signature, err := v.Signature.MarshalBER(ber.ChildEncodeOptions(opts, "signature")...)
	if err != nil {
		return nil, fmt.Errorf("encoding signature: %w", err)
	}
	children = append(children, enc_signature...)
	enc_issuer, err := v.Issuer.MarshalBER(ber.ChildEncodeOptions(opts, "issuer")...)
	if err != nil {
		return nil, fmt.Errorf("encoding issuer: %w", err)
	}
	children = append(children, enc_issuer...)
	enc_thisupdate, err := v.ThisUpdate.MarshalBER(ber.ChildEncodeOptions(opts, "thisUpdate")...)
	if err != nil {
		return nil, fmt.Errorf("encoding thisUpdate: %w", err)
	}
	children = append(children, enc_thisupdate...)
	if v.NextUpdate != nil {
		enc_nextupdate, err := v.NextUpdate.MarshalBER(ber.ChildEncodeOptions(opts, "nextUpdate")...)
		if err != nil {
			return nil, fmt.Errorf("encoding nextUpdate: %w", err)
		}
		children = append(children, enc_nextupdate...)
	}
	if v.RevokedCertificates != nil {
		enc_revokedcertificates, err := MarshalBERTBSCertListRevokedCertificates(v.RevokedCertificates, ber.ChildEncodeOptions(opts, "revokedCertificates")...)
		if err != nil {
			return nil, fmt.Errorf("encoding revokedCertificates: %w", err)
		}
		children = append(children, enc_revokedcertificates...)
	}
	if v.CrlExtensions != nil {
		if len((v.CrlExtensions).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "crlExtensions", "SIZE (1..MAX)", len((v.CrlExtensions).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_crlextensions, err := MarshalBERExtensions(v.CrlExtensions, ber.ChildEncodeOptions(opts, "crlExtensions")...)
		if err != nil {
			return nil, fmt.Errorf("encoding crlExtensions: %w", err)
		}
		{
			var encodeErr error
			enc_crlextensions, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_crlextensions)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding crlExtensions: %w", encodeErr)
			}
		}
		children = append(children, enc_crlextensions...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TBSCertList to DER format.
func (v *TBSCertList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TBSCertList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Version != nil {
		enc_version, encodeErr_enc_version := ber.EncodeBigInt((*v.Version).BigInt())
		if encodeErr_enc_version != nil {
			return nil, fmt.Errorf("encoding version: %w", encodeErr_enc_version)
		}
		children = append(children, enc_version...)
	}
	enc_signature, err := v.Signature.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding signature: %w", err)
	}
	children = append(children, enc_signature...)
	enc_issuer, err := v.Issuer.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding issuer: %w", err)
	}
	children = append(children, enc_issuer...)
	enc_thisupdate, err := v.ThisUpdate.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding thisUpdate: %w", err)
	}
	children = append(children, enc_thisupdate...)
	if v.NextUpdate != nil {
		enc_nextupdate, err := v.NextUpdate.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding nextUpdate: %w", err)
		}
		children = append(children, enc_nextupdate...)
	}
	if v.RevokedCertificates != nil {
		enc_revokedcertificates, err := MarshalDERTBSCertListRevokedCertificates(v.RevokedCertificates)
		if err != nil {
			return nil, fmt.Errorf("encoding revokedCertificates: %w", err)
		}
		children = append(children, enc_revokedcertificates...)
	}
	if v.CrlExtensions != nil {
		if len((v.CrlExtensions).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "crlExtensions", "SIZE (1..MAX)", len((v.CrlExtensions).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_crlextensions, err := MarshalDERExtensions(v.CrlExtensions)
		if err != nil {
			return nil, fmt.Errorf("encoding crlExtensions: %w", err)
		}
		{
			var encodeErr error
			enc_crlextensions, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_crlextensions)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding crlExtensions: %w", encodeErr)
			}
		}
		children = append(children, enc_crlextensions...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TBSCertList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TBSCertList from BER/DER format.
func (v *TBSCertList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TBSCertList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TBSCertList{}
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
				val_version, n, err := ber.DecodeBigInt(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding version: %w", err)
				}
				var named_version Version
				if namedErr := named_version.UnmarshalText([]byte(val_version.String())); namedErr != nil {
					return fmt.Errorf("decoding version: %w", namedErr)
				}
				v.Version = &named_version
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	// Decode signature
	if offset >= len(content) {
		return fmt.Errorf("missing required field signature")
	}
	// Decode nested SEQUENCE (AlgorithmIdentifier)
	_, n_signature, _, tlvErr_signature := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_signature != nil {
		return fmt.Errorf("decoding signature: %w", tlvErr_signature)
	}
	if offset < 0 || offset >
		len(content) || n_signature < 0 || n_signature > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.Signature.UnmarshalBER(content[offset:offset+n_signature], ber.ChildDecodeOptions(opts, "signature")...); unmErr != nil {
		return fmt.Errorf("decoding signature: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_signature < 0 || n_signature > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_signature
	// Decode issuer
	if offset >= len(content) {
		return fmt.Errorf("missing required field issuer")
	}
	// Decode nested CHOICE (Name)
	_, n_issuer, _, tlvErr_issuer := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_issuer != nil {
		return fmt.Errorf("decoding issuer: %w", tlvErr_issuer)
	}
	if offset < 0 || offset >
		len(content) || n_issuer < 0 || n_issuer > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.Issuer.UnmarshalBER(content[offset:offset+n_issuer], ber.ChildDecodeOptions(opts, "issuer")...); unmErr != nil {
		return fmt.Errorf("decoding issuer: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_issuer < 0 || n_issuer > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_issuer
	// Decode thisUpdate
	if offset >= len(content) {
		return fmt.Errorf("missing required field thisUpdate")
	}
	// Decode nested CHOICE (Time)
	_, n_thisupdate, _, tlvErr_thisupdate := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_thisupdate != nil {
		return fmt.Errorf("decoding thisUpdate: %w", tlvErr_thisupdate)
	}
	if offset < 0 || offset >
		len(content) || n_thisupdate < 0 || n_thisupdate > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.ThisUpdate.UnmarshalBER(content[offset:offset+n_thisupdate], ber.ChildDecodeOptions(opts, "thisUpdate")...); unmErr != nil {
		return fmt.Errorf("decoding thisUpdate: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_thisupdate < 0 || n_thisupdate > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_thisupdate
	// Decode nextUpdate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 23) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 24) {
				// Decode nested CHOICE (Time)
				_, n_nextupdate, _, tlvErr_nextupdate := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_nextupdate != nil {
					return fmt.Errorf("decoding nextUpdate: %w", tlvErr_nextupdate)
				}
				var dec_nextupdate Time
				if offset < 0 || offset >
					len(content) || n_nextupdate < 0 || n_nextupdate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_nextupdate.UnmarshalBER(content[offset:offset+n_nextupdate], ber.ChildDecodeOptions(opts, "nextUpdate")...); unmErr != nil {
					return fmt.Errorf("decoding nextUpdate: %w", unmErr)
				}
				v.NextUpdate = &dec_nextupdate
				if offset < 0 || offset >
					len(content) || n_nextupdate < 0 || n_nextupdate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nextupdate
			}
		}
	}
	// Decode revokedCertificates
	v.RevokedCertificatesIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (TBSCertListRevokedCertificates)
				_, n_revokedcertificates, _, tlvErr_revokedcertificates := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_revokedcertificates != nil {
					return fmt.Errorf("decoding revokedCertificates: %w", tlvErr_revokedcertificates)
				}
				if offset < 0 || offset >
					len(content) || n_revokedcertificates < 0 || n_revokedcertificates >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_revokedcertificates := content[offset : offset+n_revokedcertificates]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_revokedcertificates)
					if tagSz_ < len(tlv_revokedcertificates) && tlv_revokedcertificates[tagSz_] == 0x80 {
						v.RevokedCertificatesIndef_ = true
					}
				}
				dec_revokedcertificates, unmErr := UnmarshalBERTBSCertListRevokedCertificates(tlv_revokedcertificates, ber.ChildDecodeOptions(opts, "revokedCertificates")...)
				if unmErr != nil {
					return fmt.Errorf("decoding revokedCertificates: %w", unmErr)
				}
				v.RevokedCertificates = dec_revokedcertificates
				if offset < 0 || offset >
					len(content) || n_revokedcertificates < 0 || n_revokedcertificates >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_revokedcertificates
			}
		}
	}
	// Decode crlExtensions
	v.CrlExtensionsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_crlextensions, n_crlextensions, innerData_crlextensions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding crlExtensions: %w", err)
				}
				if decodedTag_crlextensions.Class != tag.ClassContextSpecific || decodedTag_crlextensions.Number != 0 || decodedTag_crlextensions.Constructed != true {
					return fmt.Errorf("decoding crlExtensions: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_crlextensions)
				}
				_, innerUsed_crlextensions, _, innerErr_crlextensions := ber.DecodeTLV(innerData_crlextensions, opts...)
				if innerErr_crlextensions != nil {
					return fmt.Errorf("decoding crlExtensions: %w", innerErr_crlextensions)
				}
				if innerUsed_crlextensions != len(innerData_crlextensions) {
					return fmt.Errorf("decoding crlExtensions: %w", ber.ErrExtraData)
				}
				// Decode inner value from explicit tag wrapper
				dec_crlextensions, unmErr := UnmarshalBERExtensions(innerData_crlextensions, ber.ChildDecodeOptions(opts, "crlExtensions")...)
				if unmErr != nil {
					return fmt.Errorf("decoding crlExtensions: %w", unmErr)
				}
				v.CrlExtensions = dec_crlextensions
				if offset < 0 || offset >
					len(content) || n_crlextensions < 0 || n_crlextensions >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_crlextensions
				if len((v.CrlExtensions).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "crlExtensions", "SIZE (1..MAX)", len((v.CrlExtensions).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TBSCertList", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AlgorithmIdentifier to BER format.
func (v *AlgorithmIdentifier) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AlgorithmIdentifier receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AlgorithmIdentifier) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_algorithm, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.Algorithm))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding algorithm: %w", oidErr)
	}
	children = append(children, enc_algorithm...)
	if v.Parameters != nil {
		enc_parameters := v.Parameters.Bytes
		children = append(children, enc_parameters...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AlgorithmIdentifier to DER format.
func (v *AlgorithmIdentifier) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AlgorithmIdentifier receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_algorithm, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.Algorithm))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding algorithm: %w", oidErr)
	}
	children = append(children, enc_algorithm...)
	if v.Parameters != nil {
		enc_parameters := v.Parameters.Bytes
		children = append(children, enc_parameters...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AlgorithmIdentifier as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AlgorithmIdentifier from BER/DER format.
func (v *AlgorithmIdentifier) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AlgorithmIdentifier destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AlgorithmIdentifier{}
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
	val_algorithm, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding algorithm: %w", err)
	}
	v.Algorithm = runtime.ObjectIdentifier(val_algorithm)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode parameters
	if offset < len(content) {
		_, n_parameters, _, tlvErr_parameters := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_parameters != nil {
			return fmt.Errorf("decoding parameters: %w", tlvErr_parameters)
		}
		if offset < 0 || offset >
			len(content) || n_parameters < 0 || n_parameters > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_parameters := runtime.RawValue{Bytes: content[offset : offset+n_parameters]}
		v.Parameters = &tmp_parameters
		if offset < 0 || offset >
			len(content) || n_parameters < 0 || n_parameters > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_parameters
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AlgorithmIdentifier", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ORAddress to BER format.
func (v *ORAddress) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ORAddress receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ORAddress) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_builtinstandardattributes, err := v.BuiltInStandardAttributes.MarshalBER(ber.ChildEncodeOptions(opts, "built-in-standard-attributes")...)
	if err != nil {
		return nil, fmt.Errorf("encoding built-in-standard-attributes: %w", err)
	}
	children = append(children, enc_builtinstandardattributes...)
	if v.BuiltInDomainDefinedAttributes != nil {
		if len((v.BuiltInDomainDefinedAttributes).Values) < 1 || len((v.BuiltInDomainDefinedAttributes).Values) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "built-in-domain-defined-attributes", "SIZE (1..4)", len((v.BuiltInDomainDefinedAttributes).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_builtindomaindefinedattributes, err := MarshalBERBuiltInDomainDefinedAttributes(v.BuiltInDomainDefinedAttributes, ber.ChildEncodeOptions(opts, "built-in-domain-defined-attributes")...)
		if err != nil {
			return nil, fmt.Errorf("encoding built-in-domain-defined-attributes: %w", err)
		}
		children = append(children, enc_builtindomaindefinedattributes...)
	}
	if v.ExtensionAttributes != nil {
		if len((v.ExtensionAttributes).Values) < 1 || len((v.ExtensionAttributes).Values) > 256 {
			if constraintErr := ber.CheckEncodedLength(opts, "extension-attributes", "SIZE (1..256)", len((v.ExtensionAttributes).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_extensionattributes, err := MarshalBERExtensionAttributes(v.ExtensionAttributes, ber.ChildEncodeOptions(opts, "extension-attributes")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extension-attributes: %w", err)
		}
		children = append(children, enc_extensionattributes...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ORAddress to DER format.
func (v *ORAddress) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ORAddress receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_builtinstandardattributes, err := v.BuiltInStandardAttributes.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding built-in-standard-attributes: %w", err)
	}
	children = append(children, enc_builtinstandardattributes...)
	if v.BuiltInDomainDefinedAttributes != nil {
		if len((v.BuiltInDomainDefinedAttributes).Values) < 1 || len((v.BuiltInDomainDefinedAttributes).Values) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "built-in-domain-defined-attributes", "SIZE (1..4)", len((v.BuiltInDomainDefinedAttributes).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_builtindomaindefinedattributes, err := MarshalDERBuiltInDomainDefinedAttributes(v.BuiltInDomainDefinedAttributes)
		if err != nil {
			return nil, fmt.Errorf("encoding built-in-domain-defined-attributes: %w", err)
		}
		children = append(children, enc_builtindomaindefinedattributes...)
	}
	if v.ExtensionAttributes != nil {
		if len((v.ExtensionAttributes).Values) < 1 || len((v.ExtensionAttributes).Values) > 256 {
			if constraintErr := ber.CheckEncodedLength(nil, "extension-attributes", "SIZE (1..256)", len((v.ExtensionAttributes).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_extensionattributes, err := MarshalDERExtensionAttributes(v.ExtensionAttributes)
		if err != nil {
			return nil, fmt.Errorf("encoding extension-attributes: %w", err)
		}
		children = append(children, enc_extensionattributes...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ORAddress as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ORAddress from BER/DER format.
func (v *ORAddress) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ORAddress destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ORAddress{}
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
	_, n_builtinstandardattributes, _, tlvErr_builtinstandardattributes := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_builtinstandardattributes != nil {
		return fmt.Errorf("decoding built-in-standard-attributes: %w", tlvErr_builtinstandardattributes)
	}
	if offset > len(content) || n_builtinstandardattributes < 0 || n_builtinstandardattributes >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.BuiltInStandardAttributes.UnmarshalBER(content[offset:offset+n_builtinstandardattributes], ber.ChildDecodeOptions(opts, "built-in-standard-attributes")...); unmErr != nil {
		return fmt.Errorf("decoding built-in-standard-attributes: %w", unmErr)
	}
	if offset > len(content) || n_builtinstandardattributes < 0 || n_builtinstandardattributes >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_builtinstandardattributes
	// Decode built-in-domain-defined-attributes
	v.BuiltInDomainDefinedAttributesIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (BuiltInDomainDefinedAttributes)
				_, n_builtindomaindefinedattributes, _, tlvErr_builtindomaindefinedattributes := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_builtindomaindefinedattributes != nil {
					return fmt.Errorf("decoding built-in-domain-defined-attributes: %w", tlvErr_builtindomaindefinedattributes)
				}
				if offset < 0 || offset >
					len(content) || n_builtindomaindefinedattributes <
					0 || n_builtindomaindefinedattributes > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_builtindomaindefinedattributes := content[offset : offset+n_builtindomaindefinedattributes]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_builtindomaindefinedattributes)
					if tagSz_ < len(tlv_builtindomaindefinedattributes) && tlv_builtindomaindefinedattributes[tagSz_] == 0x80 {
						v.BuiltInDomainDefinedAttributesIndef_ = true
					}
				}
				dec_builtindomaindefinedattributes, unmErr := UnmarshalBERBuiltInDomainDefinedAttributes(tlv_builtindomaindefinedattributes, ber.ChildDecodeOptions(opts, "built-in-domain-defined-attributes")...)
				if unmErr != nil {
					return fmt.Errorf("decoding built-in-domain-defined-attributes: %w", unmErr)
				}
				v.BuiltInDomainDefinedAttributes = dec_builtindomaindefinedattributes
				if offset < 0 || offset >
					len(content) || n_builtindomaindefinedattributes <
					0 || n_builtindomaindefinedattributes > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_builtindomaindefinedattributes
				if len((v.BuiltInDomainDefinedAttributes).Values) < 1 || len((v.BuiltInDomainDefinedAttributes).Values) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "built-in-domain-defined-attributes", "SIZE (1..4)", len((v.BuiltInDomainDefinedAttributes).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extension-attributes
	v.ExtensionAttributesIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 17 {
				// Decode nested SET_OF (ExtensionAttributes)
				_, n_extensionattributes, _, tlvErr_extensionattributes := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensionattributes != nil {
					return fmt.Errorf("decoding extension-attributes: %w", tlvErr_extensionattributes)
				}
				if offset < 0 || offset >
					len(content) || n_extensionattributes < 0 || n_extensionattributes >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_extensionattributes := content[offset : offset+n_extensionattributes]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_extensionattributes)
					if tagSz_ < len(tlv_extensionattributes) && tlv_extensionattributes[tagSz_] == 0x80 {
						v.ExtensionAttributesIndef_ = true
					}
				}
				dec_extensionattributes, unmErr := UnmarshalBERExtensionAttributes(tlv_extensionattributes, ber.ChildDecodeOptions(opts, "extension-attributes")...)
				if unmErr != nil {
					return fmt.Errorf("decoding extension-attributes: %w", unmErr)
				}
				v.ExtensionAttributes = dec_extensionattributes
				if offset < 0 || offset >
					len(content) || n_extensionattributes < 0 || n_extensionattributes >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensionattributes
				if len((v.ExtensionAttributes).Values) < 1 || len((v.ExtensionAttributes).Values) > 256 {
					if constraintErr := ber.CheckDecodedLength(opts, "extension-attributes", "SIZE (1..256)", len((v.ExtensionAttributes).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ORAddress", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes BuiltInStandardAttributes to BER format.
func (v *BuiltInStandardAttributes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BuiltInStandardAttributes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BuiltInStandardAttributes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CountryName != nil {
		enc_countryname, err := v.CountryName.MarshalBER(ber.ChildEncodeOptions(opts, "country-name")...)
		if err != nil {
			return nil, fmt.Errorf("encoding country-name: %w", err)
		}
		children = append(children, enc_countryname...)
	}
	if v.AdministrationDomainName != nil {
		enc_administrationdomainname, err := v.AdministrationDomainName.MarshalBER(ber.ChildEncodeOptions(opts, "administration-domain-name")...)
		if err != nil {
			return nil, fmt.Errorf("encoding administration-domain-name: %w", err)
		}
		children = append(children, enc_administrationdomainname...)
	}
	if v.NetworkAddress != nil {
		if len([]rune(*v.NetworkAddress)) < 1 || len([]rune(*v.NetworkAddress)) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "network-address", "SIZE (1..16)", len([]rune(*v.NetworkAddress))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_networkaddress, stringErr := ber.EncodeStringTagChecked(18, string(*v.NetworkAddress))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding network-address: %w", stringErr)
		}
		retagged_enc_networkaddress, tagErr_enc_networkaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_networkaddress)
		if tagErr_enc_networkaddress != nil {
			return nil, fmt.Errorf("encoding network-address: %w", tagErr_enc_networkaddress)
		}
		enc_networkaddress = retagged_enc_networkaddress
		children = append(children, enc_networkaddress...)
	}
	if v.TerminalIdentifier != nil {
		if len([]rune(*v.TerminalIdentifier)) < 1 || len([]rune(*v.TerminalIdentifier)) > 24 {
			if constraintErr := ber.CheckEncodedLength(opts, "terminal-identifier", "SIZE (1..24)", len([]rune(*v.TerminalIdentifier))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_terminalidentifier, stringErr := ber.EncodeStringTagChecked(19, string(*v.TerminalIdentifier))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding terminal-identifier: %w", stringErr)
		}
		retagged_enc_terminalidentifier, tagErr_enc_terminalidentifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_terminalidentifier)
		if tagErr_enc_terminalidentifier != nil {
			return nil, fmt.Errorf("encoding terminal-identifier: %w", tagErr_enc_terminalidentifier)
		}
		enc_terminalidentifier = retagged_enc_terminalidentifier
		children = append(children, enc_terminalidentifier...)
	}
	if v.PrivateDomainName != nil {
		enc_privatedomainname, err := v.PrivateDomainName.MarshalBER(ber.ChildEncodeOptions(opts, "private-domain-name")...)
		if err != nil {
			return nil, fmt.Errorf("encoding private-domain-name: %w", err)
		}
		{
			var encodeErr error
			enc_privatedomainname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_privatedomainname)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding private-domain-name: %w", encodeErr)
			}
		}
		children = append(children, enc_privatedomainname...)
	}
	if v.OrganizationName != nil {
		if len([]rune(*v.OrganizationName)) < 1 || len([]rune(*v.OrganizationName)) > 64 {
			if constraintErr := ber.CheckEncodedLength(opts, "organization-name", "SIZE (1..64)", len([]rune(*v.OrganizationName))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_organizationname, stringErr := ber.EncodeStringTagChecked(19, string(*v.OrganizationName))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding organization-name: %w", stringErr)
		}
		retagged_enc_organizationname, tagErr_enc_organizationname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_organizationname)
		if tagErr_enc_organizationname != nil {
			return nil, fmt.Errorf("encoding organization-name: %w", tagErr_enc_organizationname)
		}
		enc_organizationname = retagged_enc_organizationname
		children = append(children, enc_organizationname...)
	}
	if v.NumericUserIdentifier != nil {
		if len([]rune(*v.NumericUserIdentifier)) < 1 || len([]rune(*v.NumericUserIdentifier)) > 32 {
			if constraintErr := ber.CheckEncodedLength(opts, "numeric-user-identifier", "SIZE (1..32)", len([]rune(*v.NumericUserIdentifier))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numericuseridentifier, stringErr := ber.EncodeStringTagChecked(18, string(*v.NumericUserIdentifier))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding numeric-user-identifier: %w", stringErr)
		}
		retagged_enc_numericuseridentifier, tagErr_enc_numericuseridentifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_numericuseridentifier)
		if tagErr_enc_numericuseridentifier != nil {
			return nil, fmt.Errorf("encoding numeric-user-identifier: %w", tagErr_enc_numericuseridentifier)
		}
		enc_numericuseridentifier = retagged_enc_numericuseridentifier
		children = append(children, enc_numericuseridentifier...)
	}
	if v.PersonalName != nil {
		enc_personalname, err := v.PersonalName.MarshalBER(ber.ChildEncodeOptions(opts, "personal-name")...)
		if err != nil {
			return nil, fmt.Errorf("encoding personal-name: %w", err)
		}
		retagged_enc_personalname, tagErr_enc_personalname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_personalname)
		if tagErr_enc_personalname != nil {
			return nil, fmt.Errorf("encoding personal-name: %w", tagErr_enc_personalname)
		}
		enc_personalname = retagged_enc_personalname
		children = append(children, enc_personalname...)
	}
	if v.OrganizationalUnitNames != nil {
		if len((v.OrganizationalUnitNames).Values) < 1 || len((v.OrganizationalUnitNames).Values) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "organizational-unit-names", "SIZE (1..4)", len((v.OrganizationalUnitNames).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_organizationalunitnames, err := MarshalBEROrganizationalUnitNames(v.OrganizationalUnitNames, ber.ChildEncodeOptions(opts, "organizational-unit-names")...)
		if err != nil {
			return nil, fmt.Errorf("encoding organizational-unit-names: %w", err)
		}
		if v.OrganizationalUnitNamesIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_organizationalunitnames)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_organizationalunitnames, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 6}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding organizational-unit-names: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_organizationalunitnames, tagErr_enc_organizationalunitnames := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_organizationalunitnames)
			if tagErr_enc_organizationalunitnames != nil {
				return nil, fmt.Errorf("encoding organizational-unit-names: %w", tagErr_enc_organizationalunitnames)
			}
			enc_organizationalunitnames = retagged_enc_organizationalunitnames
		}
		children = append(children, enc_organizationalunitnames...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes BuiltInStandardAttributes to DER format.
func (v *BuiltInStandardAttributes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BuiltInStandardAttributes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CountryName != nil {
		enc_countryname, err := v.CountryName.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding country-name: %w", err)
		}
		children = append(children, enc_countryname...)
	}
	if v.AdministrationDomainName != nil {
		enc_administrationdomainname, err := v.AdministrationDomainName.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding administration-domain-name: %w", err)
		}
		children = append(children, enc_administrationdomainname...)
	}
	if v.NetworkAddress != nil {
		if len([]rune(*v.NetworkAddress)) < 1 || len([]rune(*v.NetworkAddress)) > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "network-address", "SIZE (1..16)", len([]rune(*v.NetworkAddress))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_networkaddress, stringErr := ber.EncodeStringTagChecked(18, string(*v.NetworkAddress))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding network-address: %w", stringErr)
		}
		retagged_enc_networkaddress, tagErr_enc_networkaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_networkaddress)
		if tagErr_enc_networkaddress != nil {
			return nil, fmt.Errorf("encoding network-address: %w", tagErr_enc_networkaddress)
		}
		enc_networkaddress = retagged_enc_networkaddress
		children = append(children, enc_networkaddress...)
	}
	if v.TerminalIdentifier != nil {
		if len([]rune(*v.TerminalIdentifier)) < 1 || len([]rune(*v.TerminalIdentifier)) > 24 {
			if constraintErr := ber.CheckEncodedLength(nil, "terminal-identifier", "SIZE (1..24)", len([]rune(*v.TerminalIdentifier))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_terminalidentifier, stringErr := ber.EncodeStringTagChecked(19, string(*v.TerminalIdentifier))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding terminal-identifier: %w", stringErr)
		}
		retagged_enc_terminalidentifier, tagErr_enc_terminalidentifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_terminalidentifier)
		if tagErr_enc_terminalidentifier != nil {
			return nil, fmt.Errorf("encoding terminal-identifier: %w", tagErr_enc_terminalidentifier)
		}
		enc_terminalidentifier = retagged_enc_terminalidentifier
		children = append(children, enc_terminalidentifier...)
	}
	if v.PrivateDomainName != nil {
		enc_privatedomainname, err := v.PrivateDomainName.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding private-domain-name: %w", err)
		}
		{
			var encodeErr error
			enc_privatedomainname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_privatedomainname)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding private-domain-name: %w", encodeErr)
			}
		}
		children = append(children, enc_privatedomainname...)
	}
	if v.OrganizationName != nil {
		if len([]rune(*v.OrganizationName)) < 1 || len([]rune(*v.OrganizationName)) > 64 {
			if constraintErr := ber.CheckEncodedLength(nil, "organization-name", "SIZE (1..64)", len([]rune(*v.OrganizationName))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_organizationname, stringErr := ber.EncodeStringTagChecked(19, string(*v.OrganizationName))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding organization-name: %w", stringErr)
		}
		retagged_enc_organizationname, tagErr_enc_organizationname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_organizationname)
		if tagErr_enc_organizationname != nil {
			return nil, fmt.Errorf("encoding organization-name: %w", tagErr_enc_organizationname)
		}
		enc_organizationname = retagged_enc_organizationname
		children = append(children, enc_organizationname...)
	}
	if v.NumericUserIdentifier != nil {
		if len([]rune(*v.NumericUserIdentifier)) < 1 || len([]rune(*v.NumericUserIdentifier)) > 32 {
			if constraintErr := ber.CheckEncodedLength(nil, "numeric-user-identifier", "SIZE (1..32)", len([]rune(*v.NumericUserIdentifier))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numericuseridentifier, stringErr := ber.EncodeStringTagChecked(18, string(*v.NumericUserIdentifier))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding numeric-user-identifier: %w", stringErr)
		}
		retagged_enc_numericuseridentifier, tagErr_enc_numericuseridentifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_numericuseridentifier)
		if tagErr_enc_numericuseridentifier != nil {
			return nil, fmt.Errorf("encoding numeric-user-identifier: %w", tagErr_enc_numericuseridentifier)
		}
		enc_numericuseridentifier = retagged_enc_numericuseridentifier
		children = append(children, enc_numericuseridentifier...)
	}
	if v.PersonalName != nil {
		enc_personalname, err := v.PersonalName.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding personal-name: %w", err)
		}
		retagged_enc_personalname, tagErr_enc_personalname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_personalname)
		if tagErr_enc_personalname != nil {
			return nil, fmt.Errorf("encoding personal-name: %w", tagErr_enc_personalname)
		}
		enc_personalname = retagged_enc_personalname
		children = append(children, enc_personalname...)
	}
	if v.OrganizationalUnitNames != nil {
		if len((v.OrganizationalUnitNames).Values) < 1 || len((v.OrganizationalUnitNames).Values) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "organizational-unit-names", "SIZE (1..4)", len((v.OrganizationalUnitNames).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_organizationalunitnames, err := MarshalDEROrganizationalUnitNames(v.OrganizationalUnitNames)
		if err != nil {
			return nil, fmt.Errorf("encoding organizational-unit-names: %w", err)
		}
		retagged_enc_organizationalunitnames, tagErr_enc_organizationalunitnames := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_organizationalunitnames)
		if tagErr_enc_organizationalunitnames != nil {
			return nil, fmt.Errorf("encoding organizational-unit-names: %w", tagErr_enc_organizationalunitnames)
		}
		enc_organizationalunitnames = retagged_enc_organizationalunitnames
		children = append(children, enc_organizationalunitnames...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BuiltInStandardAttributes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BuiltInStandardAttributes from BER/DER format.
func (v *BuiltInStandardAttributes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BuiltInStandardAttributes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = BuiltInStandardAttributes{}
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
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 1 && peekTag.Constructed == true {
				// Decode nested CHOICE (CountryName)
				_, n_countryname, _, tlvErr_countryname := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_countryname != nil {
					return fmt.Errorf("decoding country-name: %w", tlvErr_countryname)
				}
				var dec_countryname CountryName
				if offset > len(content) || n_countryname < 0 || n_countryname > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_countryname.UnmarshalBER(content[offset:offset+n_countryname], ber.ChildDecodeOptions(opts, "country-name")...); unmErr != nil {
					return fmt.Errorf("decoding country-name: %w", unmErr)
				}
				v.CountryName = &dec_countryname
				if offset > len(content) || n_countryname < 0 || n_countryname > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_countryname
			}
		}
	}
	// Decode administration-domain-name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 2 && peekTag.Constructed == true {
				// Decode nested CHOICE (AdministrationDomainName)
				_, n_administrationdomainname, _, tlvErr_administrationdomainname := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_administrationdomainname != nil {
					return fmt.Errorf("decoding administration-domain-name: %w", tlvErr_administrationdomainname)
				}
				var dec_administrationdomainname AdministrationDomainName
				if offset < 0 || offset >
					len(content) || n_administrationdomainname < 0 || n_administrationdomainname >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_administrationdomainname.UnmarshalBER(content[offset:offset+n_administrationdomainname], ber.ChildDecodeOptions(opts, "administration-domain-name")...); unmErr != nil {
					return fmt.Errorf("decoding administration-domain-name: %w", unmErr)
				}
				v.AdministrationDomainName = &dec_administrationdomainname
				if offset < 0 || offset >
					len(content) || n_administrationdomainname < 0 || n_administrationdomainname >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_administrationdomainname
			}
		}
	}
	// Decode network-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_networkaddress, n_networkaddress, rawVal_networkaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding network-address: %w", err)
				}
				if decodedTag_networkaddress.Class != tag.ClassContextSpecific || decodedTag_networkaddress.Number != 0 {
					return fmt.Errorf("decoding network-address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networkaddress)
				}
				decVal_networkaddress, stringErr := ber.DecodeImplicitStringValue(18, decodedTag_networkaddress.Constructed, rawVal_networkaddress, opts...)
				if stringErr != nil {
					return fmt.Errorf("decoding network-address: %w", stringErr)
				}
				v.NetworkAddress = &decVal_networkaddress
				if offset < 0 || offset >
					len(content) || n_networkaddress < 0 || n_networkaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_networkaddress
				if len([]rune(*v.NetworkAddress)) < 1 || len([]rune(*v.NetworkAddress)) > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "network-address", "SIZE (1..16)", len([]rune(*v.NetworkAddress))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode terminal-identifier
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_terminalidentifier, n_terminalidentifier, rawVal_terminalidentifier, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding terminal-identifier: %w", err)
				}
				if decodedTag_terminalidentifier.Class != tag.ClassContextSpecific || decodedTag_terminalidentifier.Number != 1 {
					return fmt.Errorf("decoding terminal-identifier: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_terminalidentifier)
				}
				decVal_terminalidentifier, stringErr := ber.DecodeImplicitStringValue(19, decodedTag_terminalidentifier.Constructed, rawVal_terminalidentifier, opts...)
				if stringErr != nil {
					return fmt.Errorf("decoding terminal-identifier: %w", stringErr)
				}
				v.TerminalIdentifier = &decVal_terminalidentifier
				if offset < 0 || offset >
					len(content) || n_terminalidentifier < 0 || n_terminalidentifier >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_terminalidentifier
				if len([]rune(*v.TerminalIdentifier)) < 1 || len([]rune(*v.TerminalIdentifier)) > 24 {
					if constraintErr := ber.CheckDecodedLength(opts, "terminal-identifier", "SIZE (1..24)", len([]rune(*v.TerminalIdentifier))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode private-domain-name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_privatedomainname, n_privatedomainname, innerData_privatedomainname, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding private-domain-name: %w", err)
				}
				if decodedTag_privatedomainname.Class != tag.ClassContextSpecific || decodedTag_privatedomainname.Number != 2 || decodedTag_privatedomainname.Constructed != true {
					return fmt.Errorf("decoding private-domain-name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privatedomainname)
				}
				_, innerUsed_privatedomainname, _, innerErr_privatedomainname := ber.DecodeTLV(innerData_privatedomainname, opts...)
				if innerErr_privatedomainname != nil {
					return fmt.Errorf("decoding private-domain-name: %w", innerErr_privatedomainname)
				}
				if innerUsed_privatedomainname != len(innerData_privatedomainname) {
					return fmt.Errorf("decoding private-domain-name: %w", ber.ErrExtraData)
				}
				// Decode inner value from explicit tag wrapper
				var dec_privatedomainname PrivateDomainName
				if unmErr := dec_privatedomainname.UnmarshalBER(innerData_privatedomainname, ber.ChildDecodeOptions(opts, "private-domain-name")...); unmErr != nil {
					return fmt.Errorf("decoding private-domain-name: %w", unmErr)
				}
				v.PrivateDomainName = &dec_privatedomainname
				if offset < 0 || offset >
					len(content) || n_privatedomainname < 0 || n_privatedomainname > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privatedomainname
			}
		}
	}
	// Decode organization-name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_organizationname, n_organizationname, rawVal_organizationname, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding organization-name: %w", err)
				}
				if decodedTag_organizationname.Class != tag.ClassContextSpecific || decodedTag_organizationname.Number != 3 {
					return fmt.Errorf("decoding organization-name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_organizationname)
				}
				decVal_organizationname, stringErr := ber.DecodeImplicitStringValue(19, decodedTag_organizationname.Constructed, rawVal_organizationname, opts...)
				if stringErr != nil {
					return fmt.Errorf("decoding organization-name: %w", stringErr)
				}
				v.OrganizationName = &decVal_organizationname
				if offset < 0 || offset >
					len(content) || n_organizationname < 0 || n_organizationname > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_organizationname
				if len([]rune(*v.OrganizationName)) < 1 || len([]rune(*v.OrganizationName)) > 64 {
					if constraintErr := ber.CheckDecodedLength(opts, "organization-name", "SIZE (1..64)", len([]rune(*v.OrganizationName))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode numeric-user-identifier
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_numericuseridentifier, n_numericuseridentifier, rawVal_numericuseridentifier, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding numeric-user-identifier: %w", err)
				}
				if decodedTag_numericuseridentifier.Class != tag.ClassContextSpecific || decodedTag_numericuseridentifier.Number != 4 {
					return fmt.Errorf("decoding numeric-user-identifier: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_numericuseridentifier)
				}
				decVal_numericuseridentifier, stringErr := ber.DecodeImplicitStringValue(18, decodedTag_numericuseridentifier.Constructed, rawVal_numericuseridentifier, opts...)
				if stringErr != nil {
					return fmt.Errorf("decoding numeric-user-identifier: %w", stringErr)
				}
				v.NumericUserIdentifier = &decVal_numericuseridentifier
				if offset < 0 || offset >
					len(content) || n_numericuseridentifier < 0 || n_numericuseridentifier >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_numericuseridentifier
				if len([]rune(*v.NumericUserIdentifier)) < 1 || len([]rune(*v.NumericUserIdentifier)) > 32 {
					if constraintErr := ber.CheckDecodedLength(opts, "numeric-user-identifier", "SIZE (1..32)", len([]rune(*v.NumericUserIdentifier))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode personal-name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_personalname, n_personalname, rawVal_personalname, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding personal-name: %w", err)
				}
				if decodedTag_personalname.Class != tag.ClassContextSpecific || decodedTag_personalname.Number != 5 || decodedTag_personalname.Constructed != true {
					return fmt.Errorf("decoding personal-name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_personalname)
				}
				reconstructed_personalname, reconstructionErr_personalname := ber.EncodeSet(rawVal_personalname)
				if reconstructionErr_personalname != nil {
					return fmt.Errorf("decoding personal-name: %w", reconstructionErr_personalname)
				}
				var dec_personalname PersonalName
				if unmErr := dec_personalname.UnmarshalBER(reconstructed_personalname, ber.ChildDecodeOptions(opts, "personal-name")...); unmErr != nil {
					return fmt.Errorf("decoding personal-name: %w", unmErr)
				}
				v.PersonalName = &dec_personalname
				if offset < 0 || offset >
					len(content) || n_personalname < 0 || n_personalname > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_personalname
			}
		}
	}
	// Decode organizational-unit-names
	v.OrganizationalUnitNamesIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_organizationalunitnames, n_organizationalunitnames, rawVal_organizationalunitnames, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding organizational-unit-names: %w", err)
				}
				if decodedTag_organizationalunitnames.Class != tag.ClassContextSpecific || decodedTag_organizationalunitnames.Number != 6 || decodedTag_organizationalunitnames.Constructed != true {
					return fmt.Errorf("decoding organizational-unit-names: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_organizationalunitnames)
				}
				reconstructed_organizationalunitnames, reconstructionErr_organizationalunitnames := ber.EncodeSequence(rawVal_organizationalunitnames)
				if reconstructionErr_organizationalunitnames != nil {
					return fmt.Errorf("decoding organizational-unit-names: %w", reconstructionErr_organizationalunitnames)
				}
				dec_organizationalunitnames, unmErr := UnmarshalBEROrganizationalUnitNames(reconstructed_organizationalunitnames, ber.ChildDecodeOptions(opts, "organizational-unit-names")...)
				if unmErr != nil {
					return fmt.Errorf("decoding organizational-unit-names: %w", unmErr)
				}
				v.OrganizationalUnitNames = dec_organizationalunitnames
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OrganizationalUnitNamesIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_organizationalunitnames < 0 || n_organizationalunitnames >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_organizationalunitnames
				if len((v.OrganizationalUnitNames).Values) < 1 || len((v.OrganizationalUnitNames).Values) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "organizational-unit-names", "SIZE (1..4)", len((v.OrganizationalUnitNames).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "BuiltInStandardAttributes", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes CountryName to BER format.
func (v *CountryName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CountryName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CountryName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CountryNameChoiceX121DccCode:
		if v.X121DccCode == nil {
			return nil, fmt.Errorf("%w: choice CountryName: x121-dcc-code is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(18, *v.X121DccCode)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding x121-dcc-code: %w", stringErr)
		}
		if len([]rune(*v.X121DccCode)) < 3 || len([]rune(*v.X121DccCode)) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "x121-dcc-code", "SIZE (3)", len([]rune(*v.X121DccCode))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		{
			var encodeErr error
			enc_0, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 1, enc_0)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding x121-dcc-code: %w", encodeErr)
			}
		}
		return enc_0, nil
	case CountryNameChoiceIso3166Alpha2Code:
		if v.Iso3166Alpha2Code == nil {
			return nil, fmt.Errorf("%w: choice CountryName: iso-3166-alpha2-code is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.Iso3166Alpha2Code)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding iso-3166-alpha2-code: %w", stringErr)
		}
		if len([]rune(*v.Iso3166Alpha2Code)) < 2 || len([]rune(*v.Iso3166Alpha2Code)) > 2 {
			if constraintErr := ber.CheckEncodedLength(opts, "iso-3166-alpha2-code", "SIZE (2)", len([]rune(*v.Iso3166Alpha2Code))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		{
			var encodeErr error
			enc_1, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 1, enc_1)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding iso-3166-alpha2-code: %w", encodeErr)
			}
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CountryName", v.Choice)
	}
}

// MarshalDER encodes CountryName to DER format.
func (v *CountryName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CountryName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CountryName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CountryName from BER/DER format.
func (v *CountryName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CountryName destination is nil", ber.ErrInvalidValue)
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
	*v = CountryName{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CountryName CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
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
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CountryName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding CountryName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CountryName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 18 {
		v.Choice = CountryNameChoiceX121DccCode
		decVal, _, strErr := ber.DecodeString(choiceData, 18, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding x121-dcc-code: %w", strErr)
		}
		v.X121DccCode = &decVal
		if len([]rune(*v.X121DccCode)) < 3 || len([]rune(*v.X121DccCode)) > 3 {
			if constraintErr := ber.CheckDecodedLength(opts, "x121-dcc-code", "SIZE (3)", len([]rune(*v.X121DccCode))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = CountryNameChoiceIso3166Alpha2Code
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding iso-3166-alpha2-code: %w", strErr)
		}
		v.Iso3166Alpha2Code = &decVal
		if len([]rune(*v.Iso3166Alpha2Code)) < 2 || len([]rune(*v.Iso3166Alpha2Code)) > 2 {
			if constraintErr := ber.CheckDecodedLength(opts, "iso-3166-alpha2-code", "SIZE (2)", len([]rune(*v.Iso3166Alpha2Code))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for CountryName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AdministrationDomainName to BER format.
func (v *AdministrationDomainName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AdministrationDomainName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AdministrationDomainName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case AdministrationDomainNameChoiceNumeric:
		if v.Numeric == nil {
			return nil, fmt.Errorf("%w: choice AdministrationDomainName: numeric is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(18, *v.Numeric)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding numeric: %w", stringErr)
		}
		if len([]rune(*v.Numeric)) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "numeric", "SIZE (0..16)", len([]rune(*v.Numeric))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		{
			var encodeErr error
			enc_0, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 2, enc_0)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding numeric: %w", encodeErr)
			}
		}
		return enc_0, nil
	case AdministrationDomainNameChoicePrintable:
		if v.Printable == nil {
			return nil, fmt.Errorf("%w: choice AdministrationDomainName: printable is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.Printable)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printable: %w", stringErr)
		}
		if len([]rune(*v.Printable)) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "printable", "SIZE (0..16)", len([]rune(*v.Printable))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		{
			var encodeErr error
			enc_1, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 2, enc_1)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding printable: %w", encodeErr)
			}
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AdministrationDomainName", v.Choice)
	}
}

// MarshalDER encodes AdministrationDomainName to DER format.
func (v *AdministrationDomainName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AdministrationDomainName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AdministrationDomainName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AdministrationDomainName from BER/DER format.
func (v *AdministrationDomainName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AdministrationDomainName destination is nil", ber.ErrInvalidValue)
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
	*v = AdministrationDomainName{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for AdministrationDomainName CHOICE")
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
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
	choiceData := content
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AdministrationDomainName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding AdministrationDomainName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AdministrationDomainName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 18 {
		v.Choice = AdministrationDomainNameChoiceNumeric
		decVal, _, strErr := ber.DecodeString(choiceData, 18, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding numeric: %w", strErr)
		}
		v.Numeric = &decVal
		if len([]rune(*v.Numeric)) > 16 {
			if constraintErr := ber.CheckDecodedLength(opts, "numeric", "SIZE (0..16)", len([]rune(*v.Numeric))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = AdministrationDomainNameChoicePrintable
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printable: %w", strErr)
		}
		v.Printable = &decVal
		if len([]rune(*v.Printable)) > 16 {
			if constraintErr := ber.CheckDecodedLength(opts, "printable", "SIZE (0..16)", len([]rune(*v.Printable))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for AdministrationDomainName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes PrivateDomainName to BER format.
func (v *PrivateDomainName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PrivateDomainName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PrivateDomainName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case PrivateDomainNameChoiceNumeric:
		if v.Numeric == nil {
			return nil, fmt.Errorf("%w: choice PrivateDomainName: numeric is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(18, *v.Numeric)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding numeric: %w", stringErr)
		}
		if len([]rune(*v.Numeric)) < 1 || len([]rune(*v.Numeric)) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "numeric", "SIZE (1..16)", len([]rune(*v.Numeric))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case PrivateDomainNameChoicePrintable:
		if v.Printable == nil {
			return nil, fmt.Errorf("%w: choice PrivateDomainName: printable is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.Printable)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printable: %w", stringErr)
		}
		if len([]rune(*v.Printable)) < 1 || len([]rune(*v.Printable)) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "printable", "SIZE (1..16)", len([]rune(*v.Printable))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PrivateDomainName", v.Choice)
	}
}

// MarshalDER encodes PrivateDomainName to DER format.
func (v *PrivateDomainName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrivateDomainName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PrivateDomainName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrivateDomainName from BER/DER format.
func (v *PrivateDomainName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PrivateDomainName destination is nil", ber.ErrInvalidValue)
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
	*v = PrivateDomainName{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for PrivateDomainName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PrivateDomainName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding PrivateDomainName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PrivateDomainName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 18 {
		v.Choice = PrivateDomainNameChoiceNumeric
		decVal, _, strErr := ber.DecodeString(choiceData, 18, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding numeric: %w", strErr)
		}
		v.Numeric = &decVal
		if len([]rune(*v.Numeric)) < 1 || len([]rune(*v.Numeric)) > 16 {
			if constraintErr := ber.CheckDecodedLength(opts, "numeric", "SIZE (1..16)", len([]rune(*v.Numeric))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = PrivateDomainNameChoicePrintable
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printable: %w", strErr)
		}
		v.Printable = &decVal
		if len([]rune(*v.Printable)) < 1 || len([]rune(*v.Printable)) > 16 {
			if constraintErr := ber.CheckDecodedLength(opts, "printable", "SIZE (1..16)", len([]rune(*v.Printable))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for PrivateDomainName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes PersonalName to BER format.
func (v *PersonalName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PersonalName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PersonalName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len([]rune(v.Surname)) < 1 || len([]rune(v.Surname)) > 40 {
		if constraintErr := ber.CheckEncodedLength(opts, "surname", "SIZE (1..40)", len([]rune(v.Surname))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_surname, stringErr := ber.EncodeStringTagChecked(19, v.Surname)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding surname: %w", stringErr)
	}
	retagged_enc_surname, tagErr_enc_surname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_surname)
	if tagErr_enc_surname != nil {
		return nil, fmt.Errorf("encoding surname: %w", tagErr_enc_surname)
	}
	enc_surname = retagged_enc_surname
	children = append(children, enc_surname...)
	if v.GivenName != nil {
		if len([]rune(*v.GivenName)) < 1 || len([]rune(*v.GivenName)) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "given-name", "SIZE (1..16)", len([]rune(*v.GivenName))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_givenname, stringErr := ber.EncodeStringTagChecked(19, *v.GivenName)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding given-name: %w", stringErr)
		}
		retagged_enc_givenname, tagErr_enc_givenname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_givenname)
		if tagErr_enc_givenname != nil {
			return nil, fmt.Errorf("encoding given-name: %w", tagErr_enc_givenname)
		}
		enc_givenname = retagged_enc_givenname
		children = append(children, enc_givenname...)
	}
	if v.Initials != nil {
		if len([]rune(*v.Initials)) < 1 || len([]rune(*v.Initials)) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "initials", "SIZE (1..5)", len([]rune(*v.Initials))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_initials, stringErr := ber.EncodeStringTagChecked(19, *v.Initials)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding initials: %w", stringErr)
		}
		retagged_enc_initials, tagErr_enc_initials := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_initials)
		if tagErr_enc_initials != nil {
			return nil, fmt.Errorf("encoding initials: %w", tagErr_enc_initials)
		}
		enc_initials = retagged_enc_initials
		children = append(children, enc_initials...)
	}
	if v.GenerationQualifier != nil {
		if len([]rune(*v.GenerationQualifier)) < 1 || len([]rune(*v.GenerationQualifier)) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "generation-qualifier", "SIZE (1..3)", len([]rune(*v.GenerationQualifier))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_generationqualifier, stringErr := ber.EncodeStringTagChecked(19, *v.GenerationQualifier)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding generation-qualifier: %w", stringErr)
		}
		retagged_enc_generationqualifier, tagErr_enc_generationqualifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_generationqualifier)
		if tagErr_enc_generationqualifier != nil {
			return nil, fmt.Errorf("encoding generation-qualifier: %w", tagErr_enc_generationqualifier)
		}
		enc_generationqualifier = retagged_enc_generationqualifier
		children = append(children, enc_generationqualifier...)
	}
	return ber.EncodeSet(children)
}

// MarshalDER encodes PersonalName to DER format.
func (v *PersonalName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PersonalName receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len([]rune(v.Surname)) < 1 || len([]rune(v.Surname)) > 40 {
		if constraintErr := ber.CheckEncodedLength(nil, "surname", "SIZE (1..40)", len([]rune(v.Surname))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_surname, stringErr := ber.EncodeStringTagChecked(19, v.Surname)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding surname: %w", stringErr)
	}
	retagged_enc_surname, tagErr_enc_surname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_surname)
	if tagErr_enc_surname != nil {
		return nil, fmt.Errorf("encoding surname: %w", tagErr_enc_surname)
	}
	enc_surname = retagged_enc_surname
	children = append(children, enc_surname...)
	if v.GivenName != nil {
		if len([]rune(*v.GivenName)) < 1 || len([]rune(*v.GivenName)) > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "given-name", "SIZE (1..16)", len([]rune(*v.GivenName))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_givenname, stringErr := ber.EncodeStringTagChecked(19, *v.GivenName)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding given-name: %w", stringErr)
		}
		retagged_enc_givenname, tagErr_enc_givenname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_givenname)
		if tagErr_enc_givenname != nil {
			return nil, fmt.Errorf("encoding given-name: %w", tagErr_enc_givenname)
		}
		enc_givenname = retagged_enc_givenname
		children = append(children, enc_givenname...)
	}
	if v.Initials != nil {
		if len([]rune(*v.Initials)) < 1 || len([]rune(*v.Initials)) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, "initials", "SIZE (1..5)", len([]rune(*v.Initials))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_initials, stringErr := ber.EncodeStringTagChecked(19, *v.Initials)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding initials: %w", stringErr)
		}
		retagged_enc_initials, tagErr_enc_initials := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_initials)
		if tagErr_enc_initials != nil {
			return nil, fmt.Errorf("encoding initials: %w", tagErr_enc_initials)
		}
		enc_initials = retagged_enc_initials
		children = append(children, enc_initials...)
	}
	if v.GenerationQualifier != nil {
		if len([]rune(*v.GenerationQualifier)) < 1 || len([]rune(*v.GenerationQualifier)) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, "generation-qualifier", "SIZE (1..3)", len([]rune(*v.GenerationQualifier))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_generationqualifier, stringErr := ber.EncodeStringTagChecked(19, *v.GenerationQualifier)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding generation-qualifier: %w", stringErr)
		}
		retagged_enc_generationqualifier, tagErr_enc_generationqualifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_generationqualifier)
		if tagErr_enc_generationqualifier != nil {
			return nil, fmt.Errorf("encoding generation-qualifier: %w", tagErr_enc_generationqualifier)
		}
		enc_generationqualifier = retagged_enc_generationqualifier
		children = append(children, enc_generationqualifier...)
	}
	encoded, setErr := ber.EncodeDERSet(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PersonalName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PersonalName from BER/DER format.
func (v *PersonalName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PersonalName destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	if err := ber.MarkBERSetOrder(data, func(candidate tag.Tag) int {
		if candidate.Class == tag.ClassContextSpecific && candidate.Number == 0 {
			return 0
		}
		if candidate.Class == tag.ClassContextSpecific && candidate.Number == 1 {
			return 1
		}
		if candidate.Class == tag.ClassContextSpecific && candidate.Number == 2 {
			return 2
		}
		if candidate.Class == tag.ClassContextSpecific && candidate.Number == 3 {
			return 3
		}
		return -1
	}, opts...); err != nil {
		return err
	}
	*v = PersonalName{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding PersonalName SET: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return fmt.Errorf("decoding PersonalName SET: %w: got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PersonalName", Cause: ber.ErrExtraData}
	}
	seen_surname := false
	seen_givenname := false
	seen_initials := false
	seen_generationqualifier := false
	offset := 0
	for offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PersonalName", Cause: peekErr}
		}
		if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
			if seen_surname {
				return &ber.DecodeError{Offset: offset, TypeName: "PersonalName", Field: "surname", Cause: ber.ErrInvalidValue}
			}
			decodedTag_surname, n_surname, rawVal_surname, err := ber.DecodeTLV(content[offset:], opts...)
			if err != nil {
				return fmt.Errorf("decoding surname: %w", err)
			}
			if decodedTag_surname.Class != tag.ClassContextSpecific || decodedTag_surname.Number != 0 {
				return fmt.Errorf("decoding surname: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_surname)
			}
			decVal_surname, stringErr := ber.DecodeImplicitStringValue(19, decodedTag_surname.Constructed, rawVal_surname, opts...)
			if stringErr != nil {
				return fmt.Errorf("decoding surname: %w", stringErr)
			}
			v.Surname = decVal_surname
			if offset < 0 || offset >
				len(content) || n_surname < 0 || n_surname > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n_surname
			if len([]rune(v.Surname)) < 1 || len([]rune(v.Surname)) > 40 {
				if constraintErr := ber.CheckDecodedLength(opts, "surname", "SIZE (1..40)", len([]rune(v.Surname))); constraintErr != nil {
					return constraintErr
				}
			}
			seen_surname = true
		} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
			if seen_givenname {
				return &ber.DecodeError{Offset: offset, TypeName: "PersonalName", Field: "given-name", Cause: ber.ErrInvalidValue}
			}
			decodedTag_givenname, n_givenname, rawVal_givenname, err := ber.DecodeTLV(content[offset:], opts...)
			if err != nil {
				return fmt.Errorf("decoding given-name: %w", err)
			}
			if decodedTag_givenname.Class != tag.ClassContextSpecific || decodedTag_givenname.Number != 1 {
				return fmt.Errorf("decoding given-name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_givenname)
			}
			decVal_givenname, stringErr := ber.DecodeImplicitStringValue(19, decodedTag_givenname.Constructed, rawVal_givenname, opts...)
			if stringErr != nil {
				return fmt.Errorf("decoding given-name: %w", stringErr)
			}
			v.GivenName = &decVal_givenname
			if offset < 0 || offset >
				len(content) || n_givenname < 0 || n_givenname > len(
				content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n_givenname
			if len([]rune(*v.GivenName)) < 1 || len([]rune(*v.GivenName)) > 16 {
				if constraintErr := ber.CheckDecodedLength(opts, "given-name", "SIZE (1..16)", len([]rune(*v.GivenName))); constraintErr != nil {
					return constraintErr
				}
			}
			seen_givenname = true
		} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
			if seen_initials {
				return &ber.DecodeError{Offset: offset, TypeName: "PersonalName", Field: "initials", Cause: ber.ErrInvalidValue}
			}
			decodedTag_initials, n_initials, rawVal_initials, err := ber.DecodeTLV(content[offset:], opts...)
			if err != nil {
				return fmt.Errorf("decoding initials: %w", err)
			}
			if decodedTag_initials.Class != tag.ClassContextSpecific || decodedTag_initials.Number != 2 {
				return fmt.Errorf("decoding initials: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_initials)
			}
			decVal_initials, stringErr := ber.DecodeImplicitStringValue(19, decodedTag_initials.Constructed, rawVal_initials, opts...)
			if stringErr != nil {
				return fmt.Errorf("decoding initials: %w", stringErr)
			}
			v.Initials = &decVal_initials
			if offset < 0 || offset >
				len(content) || n_initials < 0 || n_initials > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n_initials
			if len([]rune(*v.Initials)) < 1 || len([]rune(*v.Initials)) > 5 {
				if constraintErr := ber.CheckDecodedLength(opts, "initials", "SIZE (1..5)", len([]rune(*v.Initials))); constraintErr != nil {
					return constraintErr
				}
			}
			seen_initials = true
		} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
			if seen_generationqualifier {
				return &ber.DecodeError{Offset: offset, TypeName: "PersonalName", Field: "generation-qualifier", Cause: ber.ErrInvalidValue}
			}
			decodedTag_generationqualifier, n_generationqualifier, rawVal_generationqualifier, err := ber.DecodeTLV(content[offset:], opts...)
			if err != nil {
				return fmt.Errorf("decoding generation-qualifier: %w", err)
			}
			if decodedTag_generationqualifier.Class != tag.ClassContextSpecific || decodedTag_generationqualifier.Number != 3 {
				return fmt.Errorf("decoding generation-qualifier: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_generationqualifier)
			}
			decVal_generationqualifier, stringErr := ber.DecodeImplicitStringValue(19, decodedTag_generationqualifier.Constructed, rawVal_generationqualifier, opts...)
			if stringErr != nil {
				return fmt.Errorf("decoding generation-qualifier: %w", stringErr)
			}
			v.GenerationQualifier = &decVal_generationqualifier
			if offset < 0 || offset >
				len(content) || n_generationqualifier < 0 || n_generationqualifier >
				len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n_generationqualifier
			if len([]rune(*v.GenerationQualifier)) < 1 || len([]rune(*v.GenerationQualifier)) > 3 {
				if constraintErr := ber.CheckDecodedLength(opts, "generation-qualifier", "SIZE (1..3)", len([]rune(*v.GenerationQualifier))); constraintErr != nil {
					return constraintErr
				}
			}
			seen_generationqualifier = true
		} else {
			return &ber.DecodeError{Offset: offset, TypeName: "PersonalName", Cause: fmt.Errorf("%w: unknown SET component tag %s", ber.ErrInvalidTag, peekTag)}
		}
	}
	if !seen_surname {
		return fmt.Errorf("missing required field surname")
	}
	return nil
}

// MarshalBEROrganizationalUnitNames encodes a OrganizationalUnitNames list to BER.
func MarshalBEROrganizationalUnitNames(collection *OrganizationalUnitNames, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBEROrganizationalUnitNames(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBEROrganizationalUnitNames(collection *OrganizationalUnitNames, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "OrganizationalUnitNames", "SIZE (1..4)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len([]rune(elem)) < 1 || len([]rune(elem)) > 32 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..32)", len([]rune(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, stringErr := ber.EncodeStringTagChecked(19, string(elem))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding element: %w", stringErr)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDEROrganizationalUnitNames encodes a OrganizationalUnitNames list to DER.
func MarshalDEROrganizationalUnitNames(collection *OrganizationalUnitNames) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "OrganizationalUnitNames", "SIZE (1..4)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len([]rune(elem)) < 1 || len([]rune(elem)) > 32 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..32)", len([]rune(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, stringErr := ber.EncodeStringTagChecked(19, string(elem))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding element: %w", stringErr)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding OrganizationalUnitNames as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBEROrganizationalUnitNames decodes a OrganizationalUnitNames list from BER.
func UnmarshalBEROrganizationalUnitNames(data []byte, opts ...ber.DecodeOption) (returnValue *OrganizationalUnitNames, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding OrganizationalUnitNames: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OrganizationalUnitNames", Cause: ber.ErrExtraData}
	}
	var result []OrganizationalUnitName
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, strErr := ber.DecodeString(elementData, 19, opts...)
		if strErr != nil {
			return nil, fmt.Errorf("decoding element: %w", strErr)
		}
		if len([]rune(val)) < 1 || len([]rune(val)) > 32 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1..32)", len([]rune(val))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, OrganizationalUnitName(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 4 {
		if constraintErr := ber.CheckDecodedLength(opts, "OrganizationalUnitNames", "SIZE (1..4)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &OrganizationalUnitNames{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBEROrganizationalUnitNames(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERBuiltInDomainDefinedAttributes encodes a BuiltInDomainDefinedAttributes list to BER.
func MarshalBERBuiltInDomainDefinedAttributes(collection *BuiltInDomainDefinedAttributes, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERBuiltInDomainDefinedAttributes(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERBuiltInDomainDefinedAttributes(collection *BuiltInDomainDefinedAttributes, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "BuiltInDomainDefinedAttributes", "SIZE (1..4)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERBuiltInDomainDefinedAttributes encodes a BuiltInDomainDefinedAttributes list to DER.
func MarshalDERBuiltInDomainDefinedAttributes(collection *BuiltInDomainDefinedAttributes) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "BuiltInDomainDefinedAttributes", "SIZE (1..4)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BuiltInDomainDefinedAttributes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERBuiltInDomainDefinedAttributes decodes a BuiltInDomainDefinedAttributes list from BER.
func UnmarshalBERBuiltInDomainDefinedAttributes(data []byte, opts ...ber.DecodeOption) (returnValue *BuiltInDomainDefinedAttributes, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding BuiltInDomainDefinedAttributes: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BuiltInDomainDefinedAttributes", Cause: ber.ErrExtraData}
	}
	var result []BuiltInDomainDefinedAttribute
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem BuiltInDomainDefinedAttribute
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 4 {
		if constraintErr := ber.CheckDecodedLength(opts, "BuiltInDomainDefinedAttributes", "SIZE (1..4)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &BuiltInDomainDefinedAttributes{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERBuiltInDomainDefinedAttributes(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes BuiltInDomainDefinedAttribute to BER format.
func (v *BuiltInDomainDefinedAttribute) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BuiltInDomainDefinedAttribute receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BuiltInDomainDefinedAttribute) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len([]rune(v.Type)) < 1 || len([]rune(v.Type)) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "type", "SIZE (1..8)", len([]rune(v.Type))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_type, stringErr := ber.EncodeStringTagChecked(19, v.Type)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding type: %w", stringErr)
	}
	children = append(children, enc_type...)
	if len([]rune(v.Value)) < 1 || len([]rune(v.Value)) > 128 {
		if constraintErr := ber.CheckEncodedLength(opts, "value", "SIZE (1..128)", len([]rune(v.Value))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, stringErr := ber.EncodeStringTagChecked(19, v.Value)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding value: %w", stringErr)
	}
	children = append(children, enc_value...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes BuiltInDomainDefinedAttribute to DER format.
func (v *BuiltInDomainDefinedAttribute) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BuiltInDomainDefinedAttribute receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len([]rune(v.Type)) < 1 || len([]rune(v.Type)) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "type", "SIZE (1..8)", len([]rune(v.Type))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_type, stringErr := ber.EncodeStringTagChecked(19, v.Type)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding type: %w", stringErr)
	}
	children = append(children, enc_type...)
	if len([]rune(v.Value)) < 1 || len([]rune(v.Value)) > 128 {
		if constraintErr := ber.CheckEncodedLength(nil, "value", "SIZE (1..128)", len([]rune(v.Value))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, stringErr := ber.EncodeStringTagChecked(19, v.Value)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding value: %w", stringErr)
	}
	children = append(children, enc_value...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BuiltInDomainDefinedAttribute as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BuiltInDomainDefinedAttribute from BER/DER format.
func (v *BuiltInDomainDefinedAttribute) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BuiltInDomainDefinedAttribute destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = BuiltInDomainDefinedAttribute{}
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
	val_type, n, err := ber.DecodeString(content[offset:], 19, opts...)
	if err != nil {
		return fmt.Errorf("decoding type: %w", err)
	}
	v.Type = val_type
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len([]rune(v.Type)) < 1 || len([]rune(v.Type)) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "type", "SIZE (1..8)", len([]rune(v.Type))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode value
	if offset >= len(content) {
		return fmt.Errorf("missing required field value")
	}
	val_value, n, err := ber.DecodeString(content[offset:], 19, opts...)
	if err != nil {
		return fmt.Errorf("decoding value: %w", err)
	}
	v.Value = val_value
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len([]rune(v.Value)) < 1 || len([]rune(v.Value)) > 128 {
		if constraintErr := ber.CheckDecodedLength(opts, "value", "SIZE (1..128)", len([]rune(v.Value))); constraintErr != nil {
			return constraintErr
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "BuiltInDomainDefinedAttribute", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERExtensionAttributes encodes a ExtensionAttributes list to BER.
func MarshalBERExtensionAttributes(collection *ExtensionAttributes, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERExtensionAttributes(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERExtensionAttributes(collection *ExtensionAttributes, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 256 {
		if constraintErr := ber.CheckEncodedLength(opts, "ExtensionAttributes", "SIZE (1..256)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSet(children)
}

// MarshalDERExtensionAttributes encodes a ExtensionAttributes list to DER.
func MarshalDERExtensionAttributes(collection *ExtensionAttributes) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 256 {
		if constraintErr := ber.CheckEncodedLength(nil, "ExtensionAttributes", "SIZE (1..256)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeDERSetOf(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtensionAttributes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERExtensionAttributes decodes a ExtensionAttributes list from BER.
func UnmarshalBERExtensionAttributes(data []byte, opts ...ber.DecodeOption) (returnValue *ExtensionAttributes, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding ExtensionAttributes: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding ExtensionAttributes: %w: expected SET, got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ExtensionAttributes", Cause: ber.ErrExtraData}
	}
	var result []ExtensionAttribute
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem ExtensionAttribute
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 256 {
		if constraintErr := ber.CheckDecodedLength(opts, "ExtensionAttributes", "SIZE (1..256)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &ExtensionAttributes{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERExtensionAttributes(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes ExtensionAttribute to BER format.
func (v *ExtensionAttribute) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionAttribute receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtensionAttribute) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.ExtensionAttributeType) >= 0 && int64(v.ExtensionAttributeType) <= 256) {
		if constraintErr := ber.CheckEncodedValue(opts, "extension-attribute-type", "(0..256)", fmt.Sprint(int64(v.ExtensionAttributeType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_extensionattributetype := ber.EncodeInteger(int64(v.ExtensionAttributeType))
	retagged_enc_extensionattributetype, tagErr_enc_extensionattributetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_extensionattributetype)
	if tagErr_enc_extensionattributetype != nil {
		return nil, fmt.Errorf("encoding extension-attribute-type: %w", tagErr_enc_extensionattributetype)
	}
	enc_extensionattributetype = retagged_enc_extensionattributetype
	children = append(children, enc_extensionattributetype...)
	enc_extensionattributevalue := v.ExtensionAttributeValue.Bytes
	{
		var encodeErr error
		enc_extensionattributevalue, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensionattributevalue)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding extension-attribute-value: %w", encodeErr)
		}
	}
	children = append(children, enc_extensionattributevalue...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ExtensionAttribute to DER format.
func (v *ExtensionAttribute) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionAttribute receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.ExtensionAttributeType) >= 0 && int64(v.ExtensionAttributeType) <= 256) {
		if constraintErr := ber.CheckEncodedValue(nil, "extension-attribute-type", "(0..256)", fmt.Sprint(int64(v.ExtensionAttributeType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_extensionattributetype := ber.EncodeInteger(int64(v.ExtensionAttributeType))
	retagged_enc_extensionattributetype, tagErr_enc_extensionattributetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_extensionattributetype)
	if tagErr_enc_extensionattributetype != nil {
		return nil, fmt.Errorf("encoding extension-attribute-type: %w", tagErr_enc_extensionattributetype)
	}
	enc_extensionattributetype = retagged_enc_extensionattributetype
	children = append(children, enc_extensionattributetype...)
	enc_extensionattributevalue := v.ExtensionAttributeValue.Bytes
	{
		var encodeErr error
		enc_extensionattributevalue, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensionattributevalue)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding extension-attribute-value: %w", encodeErr)
		}
	}
	children = append(children, enc_extensionattributevalue...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtensionAttribute as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensionAttribute from BER/DER format.
func (v *ExtensionAttribute) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtensionAttribute destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtensionAttribute{}
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
	decodedTag_extensionattributetype, n_extensionattributetype, rawVal_extensionattributetype, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding extension-attribute-type: %w", err)
	}
	if decodedTag_extensionattributetype.Class != tag.ClassContextSpecific || decodedTag_extensionattributetype.Number != 0 || decodedTag_extensionattributetype.Constructed != false {
		return fmt.Errorf("decoding extension-attribute-type: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensionattributetype)
	}
	decVal_extensionattributetype, intErr := ber.DecodeIntegerValue(rawVal_extensionattributetype)
	if intErr != nil {
		return fmt.Errorf("decoding extension-attribute-type: %w", intErr)
	}
	v.ExtensionAttributeType = decVal_extensionattributetype
	if offset > len(content) || n_extensionattributetype < 0 || n_extensionattributetype >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_extensionattributetype
	if !(int64(v.ExtensionAttributeType) >= 0 && int64(v.ExtensionAttributeType) <= 256) {
		if constraintErr := ber.CheckDecodedValue(opts, "extension-attribute-type", "(0..256)", fmt.Sprint(int64(v.ExtensionAttributeType))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extension-attribute-value
	if offset >= len(content) {
		return fmt.Errorf("missing required field extension-attribute-value")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for extension-attribute-value, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_extensionattributevalue, n_extensionattributevalue, innerData_extensionattributevalue, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding extension-attribute-value: %w", err)
	}
	if decodedTag_extensionattributevalue.Class != tag.ClassContextSpecific || decodedTag_extensionattributevalue.Number != 1 || decodedTag_extensionattributevalue.Constructed != true {
		return fmt.Errorf("decoding extension-attribute-value: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensionattributevalue)
	}
	_, innerUsed_extensionattributevalue, _, innerErr_extensionattributevalue := ber.DecodeTLV(innerData_extensionattributevalue, opts...)
	if innerErr_extensionattributevalue != nil {
		return fmt.Errorf("decoding extension-attribute-value: %w", innerErr_extensionattributevalue)
	}
	if innerUsed_extensionattributevalue != len(innerData_extensionattributevalue) {
		return fmt.Errorf("decoding extension-attribute-value: %w", ber.ErrExtraData)
	}
	// Decode inner value from explicit tag wrapper
	v.ExtensionAttributeValue = runtime.RawValue{Bytes: innerData_extensionattributevalue}
	if offset < 0 || offset >
		len(content) || n_extensionattributevalue < 0 || n_extensionattributevalue >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_extensionattributevalue
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExtensionAttribute", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TeletexPersonalName to BER format.
func (v *TeletexPersonalName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TeletexPersonalName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TeletexPersonalName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len([]rune(v.Surname)) < 1 || len([]rune(v.Surname)) > 40 {
		if constraintErr := ber.CheckEncodedLength(opts, "surname", "SIZE (1..40)", len([]rune(v.Surname))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_surname, stringErr := ber.EncodeStringTagChecked(20, v.Surname)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding surname: %w", stringErr)
	}
	retagged_enc_surname, tagErr_enc_surname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_surname)
	if tagErr_enc_surname != nil {
		return nil, fmt.Errorf("encoding surname: %w", tagErr_enc_surname)
	}
	enc_surname = retagged_enc_surname
	children = append(children, enc_surname...)
	if v.GivenName != nil {
		if len([]rune(*v.GivenName)) < 1 || len([]rune(*v.GivenName)) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "given-name", "SIZE (1..16)", len([]rune(*v.GivenName))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_givenname, stringErr := ber.EncodeStringTagChecked(20, *v.GivenName)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding given-name: %w", stringErr)
		}
		retagged_enc_givenname, tagErr_enc_givenname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_givenname)
		if tagErr_enc_givenname != nil {
			return nil, fmt.Errorf("encoding given-name: %w", tagErr_enc_givenname)
		}
		enc_givenname = retagged_enc_givenname
		children = append(children, enc_givenname...)
	}
	if v.Initials != nil {
		if len([]rune(*v.Initials)) < 1 || len([]rune(*v.Initials)) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "initials", "SIZE (1..5)", len([]rune(*v.Initials))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_initials, stringErr := ber.EncodeStringTagChecked(20, *v.Initials)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding initials: %w", stringErr)
		}
		retagged_enc_initials, tagErr_enc_initials := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_initials)
		if tagErr_enc_initials != nil {
			return nil, fmt.Errorf("encoding initials: %w", tagErr_enc_initials)
		}
		enc_initials = retagged_enc_initials
		children = append(children, enc_initials...)
	}
	if v.GenerationQualifier != nil {
		if len([]rune(*v.GenerationQualifier)) < 1 || len([]rune(*v.GenerationQualifier)) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "generation-qualifier", "SIZE (1..3)", len([]rune(*v.GenerationQualifier))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_generationqualifier, stringErr := ber.EncodeStringTagChecked(20, *v.GenerationQualifier)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding generation-qualifier: %w", stringErr)
		}
		retagged_enc_generationqualifier, tagErr_enc_generationqualifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_generationqualifier)
		if tagErr_enc_generationqualifier != nil {
			return nil, fmt.Errorf("encoding generation-qualifier: %w", tagErr_enc_generationqualifier)
		}
		enc_generationqualifier = retagged_enc_generationqualifier
		children = append(children, enc_generationqualifier...)
	}
	return ber.EncodeSet(children)
}

// MarshalDER encodes TeletexPersonalName to DER format.
func (v *TeletexPersonalName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TeletexPersonalName receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len([]rune(v.Surname)) < 1 || len([]rune(v.Surname)) > 40 {
		if constraintErr := ber.CheckEncodedLength(nil, "surname", "SIZE (1..40)", len([]rune(v.Surname))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_surname, stringErr := ber.EncodeStringTagChecked(20, v.Surname)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding surname: %w", stringErr)
	}
	retagged_enc_surname, tagErr_enc_surname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_surname)
	if tagErr_enc_surname != nil {
		return nil, fmt.Errorf("encoding surname: %w", tagErr_enc_surname)
	}
	enc_surname = retagged_enc_surname
	children = append(children, enc_surname...)
	if v.GivenName != nil {
		if len([]rune(*v.GivenName)) < 1 || len([]rune(*v.GivenName)) > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "given-name", "SIZE (1..16)", len([]rune(*v.GivenName))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_givenname, stringErr := ber.EncodeStringTagChecked(20, *v.GivenName)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding given-name: %w", stringErr)
		}
		retagged_enc_givenname, tagErr_enc_givenname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_givenname)
		if tagErr_enc_givenname != nil {
			return nil, fmt.Errorf("encoding given-name: %w", tagErr_enc_givenname)
		}
		enc_givenname = retagged_enc_givenname
		children = append(children, enc_givenname...)
	}
	if v.Initials != nil {
		if len([]rune(*v.Initials)) < 1 || len([]rune(*v.Initials)) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, "initials", "SIZE (1..5)", len([]rune(*v.Initials))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_initials, stringErr := ber.EncodeStringTagChecked(20, *v.Initials)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding initials: %w", stringErr)
		}
		retagged_enc_initials, tagErr_enc_initials := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_initials)
		if tagErr_enc_initials != nil {
			return nil, fmt.Errorf("encoding initials: %w", tagErr_enc_initials)
		}
		enc_initials = retagged_enc_initials
		children = append(children, enc_initials...)
	}
	if v.GenerationQualifier != nil {
		if len([]rune(*v.GenerationQualifier)) < 1 || len([]rune(*v.GenerationQualifier)) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, "generation-qualifier", "SIZE (1..3)", len([]rune(*v.GenerationQualifier))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_generationqualifier, stringErr := ber.EncodeStringTagChecked(20, *v.GenerationQualifier)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding generation-qualifier: %w", stringErr)
		}
		retagged_enc_generationqualifier, tagErr_enc_generationqualifier := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_generationqualifier)
		if tagErr_enc_generationqualifier != nil {
			return nil, fmt.Errorf("encoding generation-qualifier: %w", tagErr_enc_generationqualifier)
		}
		enc_generationqualifier = retagged_enc_generationqualifier
		children = append(children, enc_generationqualifier...)
	}
	encoded, setErr := ber.EncodeDERSet(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TeletexPersonalName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TeletexPersonalName from BER/DER format.
func (v *TeletexPersonalName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TeletexPersonalName destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	if err := ber.MarkBERSetOrder(data, func(candidate tag.Tag) int {
		if candidate.Class == tag.ClassContextSpecific && candidate.Number == 0 {
			return 0
		}
		if candidate.Class == tag.ClassContextSpecific && candidate.Number == 1 {
			return 1
		}
		if candidate.Class == tag.ClassContextSpecific && candidate.Number == 2 {
			return 2
		}
		if candidate.Class == tag.ClassContextSpecific && candidate.Number == 3 {
			return 3
		}
		return -1
	}, opts...); err != nil {
		return err
	}
	*v = TeletexPersonalName{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding TeletexPersonalName SET: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return fmt.Errorf("decoding TeletexPersonalName SET: %w: got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TeletexPersonalName", Cause: ber.ErrExtraData}
	}
	seen_surname := false
	seen_givenname := false
	seen_initials := false
	seen_generationqualifier := false
	offset := 0
	for offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TeletexPersonalName", Cause: peekErr}
		}
		if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
			if seen_surname {
				return &ber.DecodeError{Offset: offset, TypeName: "TeletexPersonalName", Field: "surname", Cause: ber.ErrInvalidValue}
			}
			decodedTag_surname, n_surname, rawVal_surname, err := ber.DecodeTLV(content[offset:], opts...)
			if err != nil {
				return fmt.Errorf("decoding surname: %w", err)
			}
			if decodedTag_surname.Class != tag.ClassContextSpecific || decodedTag_surname.Number != 0 {
				return fmt.Errorf("decoding surname: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_surname)
			}
			decVal_surname, stringErr := ber.DecodeImplicitStringValue(20, decodedTag_surname.Constructed, rawVal_surname, opts...)
			if stringErr != nil {
				return fmt.Errorf("decoding surname: %w", stringErr)
			}
			v.Surname = decVal_surname
			if offset < 0 || offset >
				len(content) || n_surname < 0 || n_surname > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n_surname
			if len([]rune(v.Surname)) < 1 || len([]rune(v.Surname)) > 40 {
				if constraintErr := ber.CheckDecodedLength(opts, "surname", "SIZE (1..40)", len([]rune(v.Surname))); constraintErr != nil {
					return constraintErr
				}
			}
			seen_surname = true
		} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
			if seen_givenname {
				return &ber.DecodeError{Offset: offset, TypeName: "TeletexPersonalName", Field: "given-name", Cause: ber.ErrInvalidValue}
			}
			decodedTag_givenname, n_givenname, rawVal_givenname, err := ber.DecodeTLV(content[offset:], opts...)
			if err != nil {
				return fmt.Errorf("decoding given-name: %w", err)
			}
			if decodedTag_givenname.Class != tag.ClassContextSpecific || decodedTag_givenname.Number != 1 {
				return fmt.Errorf("decoding given-name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_givenname)
			}
			decVal_givenname, stringErr := ber.DecodeImplicitStringValue(20, decodedTag_givenname.Constructed, rawVal_givenname, opts...)
			if stringErr != nil {
				return fmt.Errorf("decoding given-name: %w", stringErr)
			}
			v.GivenName = &decVal_givenname
			if offset < 0 || offset >
				len(content) || n_givenname < 0 || n_givenname > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n_givenname
			if len([]rune(*v.GivenName)) < 1 || len([]rune(*v.GivenName)) > 16 {
				if constraintErr := ber.CheckDecodedLength(opts, "given-name", "SIZE (1..16)", len([]rune(*v.GivenName))); constraintErr != nil {
					return constraintErr
				}
			}
			seen_givenname = true
		} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
			if seen_initials {
				return &ber.DecodeError{Offset: offset, TypeName: "TeletexPersonalName", Field: "initials", Cause: ber.ErrInvalidValue}
			}
			decodedTag_initials, n_initials, rawVal_initials, err := ber.DecodeTLV(content[offset:], opts...)
			if err != nil {
				return fmt.Errorf("decoding initials: %w", err)
			}
			if decodedTag_initials.Class != tag.ClassContextSpecific || decodedTag_initials.Number != 2 {
				return fmt.Errorf("decoding initials: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_initials)
			}
			decVal_initials, stringErr := ber.DecodeImplicitStringValue(20, decodedTag_initials.Constructed, rawVal_initials, opts...)
			if stringErr != nil {
				return fmt.Errorf("decoding initials: %w", stringErr)
			}
			v.Initials = &decVal_initials
			if offset < 0 || offset >
				len(content) || n_initials < 0 || n_initials > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n_initials
			if len([]rune(*v.Initials)) < 1 || len([]rune(*v.Initials)) > 5 {
				if constraintErr := ber.CheckDecodedLength(opts, "initials", "SIZE (1..5)", len([]rune(*v.Initials))); constraintErr != nil {
					return constraintErr
				}
			}
			seen_initials = true
		} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
			if seen_generationqualifier {
				return &ber.DecodeError{Offset: offset, TypeName: "TeletexPersonalName", Field: "generation-qualifier", Cause: ber.ErrInvalidValue}
			}
			decodedTag_generationqualifier, n_generationqualifier, rawVal_generationqualifier, err := ber.DecodeTLV(content[offset:], opts...)
			if err != nil {
				return fmt.Errorf("decoding generation-qualifier: %w", err)
			}
			if decodedTag_generationqualifier.Class != tag.ClassContextSpecific || decodedTag_generationqualifier.Number != 3 {
				return fmt.Errorf("decoding generation-qualifier: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_generationqualifier)
			}
			decVal_generationqualifier, stringErr := ber.DecodeImplicitStringValue(20, decodedTag_generationqualifier.Constructed, rawVal_generationqualifier, opts...)
			if stringErr != nil {
				return fmt.Errorf("decoding generation-qualifier: %w", stringErr)
			}
			v.GenerationQualifier = &decVal_generationqualifier
			if offset < 0 || offset >
				len(content) || n_generationqualifier < 0 || n_generationqualifier >
				len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n_generationqualifier
			if len([]rune(*v.GenerationQualifier)) < 1 || len([]rune(*v.GenerationQualifier)) > 3 {
				if constraintErr := ber.CheckDecodedLength(opts, "generation-qualifier", "SIZE (1..3)", len([]rune(*v.GenerationQualifier))); constraintErr != nil {
					return constraintErr
				}
			}
			seen_generationqualifier = true
		} else {
			return &ber.DecodeError{Offset: offset, TypeName: "TeletexPersonalName", Cause: fmt.Errorf("%w: unknown SET component tag %s", ber.ErrInvalidTag, peekTag)}
		}
	}
	if !seen_surname {
		return fmt.Errorf("missing required field surname")
	}
	return nil
}

// MarshalBERTeletexOrganizationalUnitNames encodes a TeletexOrganizationalUnitNames list to BER.
func MarshalBERTeletexOrganizationalUnitNames(collection *TeletexOrganizationalUnitNames, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERTeletexOrganizationalUnitNames(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERTeletexOrganizationalUnitNames(collection *TeletexOrganizationalUnitNames, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "TeletexOrganizationalUnitNames", "SIZE (1..4)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len([]rune(elem)) < 1 || len([]rune(elem)) > 32 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..32)", len([]rune(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, stringErr := ber.EncodeStringTagChecked(20, string(elem))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding element: %w", stringErr)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERTeletexOrganizationalUnitNames encodes a TeletexOrganizationalUnitNames list to DER.
func MarshalDERTeletexOrganizationalUnitNames(collection *TeletexOrganizationalUnitNames) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "TeletexOrganizationalUnitNames", "SIZE (1..4)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len([]rune(elem)) < 1 || len([]rune(elem)) > 32 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..32)", len([]rune(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, stringErr := ber.EncodeStringTagChecked(20, string(elem))
		if stringErr != nil {
			return nil, fmt.Errorf("encoding element: %w", stringErr)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TeletexOrganizationalUnitNames as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERTeletexOrganizationalUnitNames decodes a TeletexOrganizationalUnitNames list from BER.
func UnmarshalBERTeletexOrganizationalUnitNames(data []byte, opts ...ber.DecodeOption) (returnValue *TeletexOrganizationalUnitNames, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding TeletexOrganizationalUnitNames: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TeletexOrganizationalUnitNames", Cause: ber.ErrExtraData}
	}
	var result []TeletexOrganizationalUnitName
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, strErr := ber.DecodeString(elementData, 20, opts...)
		if strErr != nil {
			return nil, fmt.Errorf("decoding element: %w", strErr)
		}
		if len([]rune(val)) < 1 || len([]rune(val)) > 32 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1..32)", len([]rune(val))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, TeletexOrganizationalUnitName(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 4 {
		if constraintErr := ber.CheckDecodedLength(opts, "TeletexOrganizationalUnitNames", "SIZE (1..4)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &TeletexOrganizationalUnitNames{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERTeletexOrganizationalUnitNames(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes PhysicalDeliveryCountryName to BER format.
func (v *PhysicalDeliveryCountryName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PhysicalDeliveryCountryName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PhysicalDeliveryCountryName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case PhysicalDeliveryCountryNameChoiceX121DccCode:
		if v.X121DccCode == nil {
			return nil, fmt.Errorf("%w: choice PhysicalDeliveryCountryName: x121-dcc-code is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(18, *v.X121DccCode)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding x121-dcc-code: %w", stringErr)
		}
		if len([]rune(*v.X121DccCode)) < 3 || len([]rune(*v.X121DccCode)) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "x121-dcc-code", "SIZE (3)", len([]rune(*v.X121DccCode))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case PhysicalDeliveryCountryNameChoiceIso3166Alpha2Code:
		if v.Iso3166Alpha2Code == nil {
			return nil, fmt.Errorf("%w: choice PhysicalDeliveryCountryName: iso-3166-alpha2-code is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.Iso3166Alpha2Code)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding iso-3166-alpha2-code: %w", stringErr)
		}
		if len([]rune(*v.Iso3166Alpha2Code)) < 2 || len([]rune(*v.Iso3166Alpha2Code)) > 2 {
			if constraintErr := ber.CheckEncodedLength(opts, "iso-3166-alpha2-code", "SIZE (2)", len([]rune(*v.Iso3166Alpha2Code))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PhysicalDeliveryCountryName", v.Choice)
	}
}

// MarshalDER encodes PhysicalDeliveryCountryName to DER format.
func (v *PhysicalDeliveryCountryName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PhysicalDeliveryCountryName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PhysicalDeliveryCountryName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PhysicalDeliveryCountryName from BER/DER format.
func (v *PhysicalDeliveryCountryName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PhysicalDeliveryCountryName destination is nil", ber.ErrInvalidValue)
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
	*v = PhysicalDeliveryCountryName{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for PhysicalDeliveryCountryName CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PhysicalDeliveryCountryName: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding PhysicalDeliveryCountryName CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PhysicalDeliveryCountryName", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 18 {
		v.Choice = PhysicalDeliveryCountryNameChoiceX121DccCode
		decVal, _, strErr := ber.DecodeString(choiceData, 18, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding x121-dcc-code: %w", strErr)
		}
		v.X121DccCode = &decVal
		if len([]rune(*v.X121DccCode)) < 3 || len([]rune(*v.X121DccCode)) > 3 {
			if constraintErr := ber.CheckDecodedLength(opts, "x121-dcc-code", "SIZE (3)", len([]rune(*v.X121DccCode))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = PhysicalDeliveryCountryNameChoiceIso3166Alpha2Code
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding iso-3166-alpha2-code: %w", strErr)
		}
		v.Iso3166Alpha2Code = &decVal
		if len([]rune(*v.Iso3166Alpha2Code)) < 2 || len([]rune(*v.Iso3166Alpha2Code)) > 2 {
			if constraintErr := ber.CheckDecodedLength(opts, "iso-3166-alpha2-code", "SIZE (2)", len([]rune(*v.Iso3166Alpha2Code))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for PhysicalDeliveryCountryName CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes PostalCode to BER format.
func (v *PostalCode) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PostalCode receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PostalCode) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case PostalCodeChoiceNumericCode:
		if v.NumericCode == nil {
			return nil, fmt.Errorf("%w: choice PostalCode: numeric-code is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeStringTagChecked(18, *v.NumericCode)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding numeric-code: %w", stringErr)
		}
		if len([]rune(*v.NumericCode)) < 1 || len([]rune(*v.NumericCode)) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "numeric-code", "SIZE (1..16)", len([]rune(*v.NumericCode))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case PostalCodeChoicePrintableCode:
		if v.PrintableCode == nil {
			return nil, fmt.Errorf("%w: choice PostalCode: printable-code is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableCode)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printable-code: %w", stringErr)
		}
		if len([]rune(*v.PrintableCode)) < 1 || len([]rune(*v.PrintableCode)) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "printable-code", "SIZE (1..16)", len([]rune(*v.PrintableCode))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PostalCode", v.Choice)
	}
}

// MarshalDER encodes PostalCode to DER format.
func (v *PostalCode) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PostalCode receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PostalCode as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PostalCode from BER/DER format.
func (v *PostalCode) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PostalCode destination is nil", ber.ErrInvalidValue)
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
	*v = PostalCode{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for PostalCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PostalCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding PostalCode CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PostalCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 18 {
		v.Choice = PostalCodeChoiceNumericCode
		decVal, _, strErr := ber.DecodeString(choiceData, 18, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding numeric-code: %w", strErr)
		}
		v.NumericCode = &decVal
		if len([]rune(*v.NumericCode)) < 1 || len([]rune(*v.NumericCode)) > 16 {
			if constraintErr := ber.CheckDecodedLength(opts, "numeric-code", "SIZE (1..16)", len([]rune(*v.NumericCode))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = PostalCodeChoicePrintableCode
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return fmt.Errorf("decoding printable-code: %w", strErr)
		}
		v.PrintableCode = &decVal
		if len([]rune(*v.PrintableCode)) < 1 || len([]rune(*v.PrintableCode)) > 16 {
			if constraintErr := ber.CheckDecodedLength(opts, "printable-code", "SIZE (1..16)", len([]rune(*v.PrintableCode))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for PostalCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes UnformattedPostalAddress to BER format.
func (v *UnformattedPostalAddress) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnformattedPostalAddress receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnformattedPostalAddress) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrintableAddress != nil {
		if len((v.PrintableAddress).Values) < 1 || len((v.PrintableAddress).Values) > 6 {
			if constraintErr := ber.CheckEncodedLength(opts, "printable-address", "SIZE (1..6)", len((v.PrintableAddress).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_printableaddress, err := MarshalBERUnformattedPostalAddressPrintableAddress(v.PrintableAddress, ber.ChildEncodeOptions(opts, "printable-address")...)
		if err != nil {
			return nil, fmt.Errorf("encoding printable-address: %w", err)
		}
		children = append(children, enc_printableaddress...)
	}
	if v.TeletexString != nil {
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 180 {
			if constraintErr := ber.CheckEncodedLength(opts, "teletex-string", "SIZE (1..180)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teletexstring, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletex-string: %w", stringErr)
		}
		children = append(children, enc_teletexstring...)
	}
	return ber.EncodeSet(children)
}

// MarshalDER encodes UnformattedPostalAddress to DER format.
func (v *UnformattedPostalAddress) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnformattedPostalAddress receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrintableAddress != nil {
		if len((v.PrintableAddress).Values) < 1 || len((v.PrintableAddress).Values) > 6 {
			if constraintErr := ber.CheckEncodedLength(nil, "printable-address", "SIZE (1..6)", len((v.PrintableAddress).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_printableaddress, err := MarshalDERUnformattedPostalAddressPrintableAddress(v.PrintableAddress)
		if err != nil {
			return nil, fmt.Errorf("encoding printable-address: %w", err)
		}
		children = append(children, enc_printableaddress...)
	}
	if v.TeletexString != nil {
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 180 {
			if constraintErr := ber.CheckEncodedLength(nil, "teletex-string", "SIZE (1..180)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teletexstring, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletex-string: %w", stringErr)
		}
		children = append(children, enc_teletexstring...)
	}
	encoded, setErr := ber.EncodeDERSet(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UnformattedPostalAddress as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnformattedPostalAddress from BER/DER format.
func (v *UnformattedPostalAddress) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnformattedPostalAddress destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	if err := ber.MarkBERSetOrder(data, func(candidate tag.Tag) int {
		if candidate.Class == tag.ClassUniversal && candidate.Number == 16 && candidate.Constructed == true {
			return 0
		}
		if candidate.Class == tag.ClassUniversal && candidate.Number == 20 {
			return 1
		}
		return -1
	}, opts...); err != nil {
		return err
	}
	*v = UnformattedPostalAddress{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding UnformattedPostalAddress SET: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return fmt.Errorf("decoding UnformattedPostalAddress SET: %w: got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnformattedPostalAddress", Cause: ber.ErrExtraData}
	}
	seen_printableaddress := false
	seen_teletexstring := false
	offset := 0
	for offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnformattedPostalAddress", Cause: peekErr}
		}
		if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
			if seen_printableaddress {
				return &ber.DecodeError{Offset: offset, TypeName: "UnformattedPostalAddress", Field: "printable-address", Cause: ber.ErrInvalidValue}
			}
			v.PrintableAddressIndef_ = false
			// Decode nested SEQUENCE_OF (UnformattedPostalAddressPrintableAddress)
			_, n_printableaddress, _, tlvErr_printableaddress := ber.DecodeTLV(content[offset:], opts...)
			if tlvErr_printableaddress != nil {
				return fmt.Errorf("decoding printable-address: %w", tlvErr_printableaddress)
			}
			if offset < 0 || offset >
				len(content) || n_printableaddress < 0 || n_printableaddress > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			tlv_printableaddress := content[offset : offset+n_printableaddress]
			{
				_, tagSz_, _ := ber.DecodeTag(tlv_printableaddress)
				if tagSz_ < len(tlv_printableaddress) && tlv_printableaddress[tagSz_] == 0x80 {
					v.PrintableAddressIndef_ = true
				}
			}
			dec_printableaddress, unmErr := UnmarshalBERUnformattedPostalAddressPrintableAddress(tlv_printableaddress, ber.ChildDecodeOptions(opts, "printable-address")...)
			if unmErr != nil {
				return fmt.Errorf("decoding printable-address: %w", unmErr)
			}
			v.PrintableAddress = dec_printableaddress
			if offset < 0 || offset >
				len(content) || n_printableaddress < 0 || n_printableaddress > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n_printableaddress
			if len((v.PrintableAddress).Values) < 1 || len((v.PrintableAddress).Values) > 6 {
				if constraintErr := ber.CheckDecodedLength(opts, "printable-address", "SIZE (1..6)", len((v.PrintableAddress).Values)); constraintErr != nil {
					return constraintErr
				}
			}
			seen_printableaddress = true
		} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
			if seen_teletexstring {
				return &ber.DecodeError{Offset: offset, TypeName: "UnformattedPostalAddress", Field: "teletex-string", Cause: ber.ErrInvalidValue}
			}
			val_teletexstring, n, err := ber.DecodeString(content[offset:], 20, opts...)
			if err != nil {
				return fmt.Errorf("decoding teletex-string: %w", err)
			}
			v.TeletexString = &val_teletexstring
			if offset < 0 || offset >
				len(content) || n < 0 || n > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n
			if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 180 {
				if constraintErr := ber.CheckDecodedLength(opts, "teletex-string", "SIZE (1..180)", len([]rune(*v.TeletexString))); constraintErr != nil {
					return constraintErr
				}
			}
			seen_teletexstring = true
		} else {
			return &ber.DecodeError{Offset: offset, TypeName: "UnformattedPostalAddress", Cause: fmt.Errorf("%w: unknown SET component tag %s", ber.ErrInvalidTag, peekTag)}
		}
	}
	return nil
}

// MarshalBER encodes PDSParameter to BER format.
func (v *PDSParameter) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PDSParameter receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PDSParameter) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrintableString != nil {
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 30 {
			if constraintErr := ber.CheckEncodedLength(opts, "printable-string", "SIZE (1..30)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_printablestring, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printable-string: %w", stringErr)
		}
		children = append(children, enc_printablestring...)
	}
	if v.TeletexString != nil {
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 30 {
			if constraintErr := ber.CheckEncodedLength(opts, "teletex-string", "SIZE (1..30)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teletexstring, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletex-string: %w", stringErr)
		}
		children = append(children, enc_teletexstring...)
	}
	return ber.EncodeSet(children)
}

// MarshalDER encodes PDSParameter to DER format.
func (v *PDSParameter) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PDSParameter receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrintableString != nil {
		if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 30 {
			if constraintErr := ber.CheckEncodedLength(nil, "printable-string", "SIZE (1..30)", len([]rune(*v.PrintableString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_printablestring, stringErr := ber.EncodeStringTagChecked(19, *v.PrintableString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding printable-string: %w", stringErr)
		}
		children = append(children, enc_printablestring...)
	}
	if v.TeletexString != nil {
		if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 30 {
			if constraintErr := ber.CheckEncodedLength(nil, "teletex-string", "SIZE (1..30)", len([]rune(*v.TeletexString))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teletexstring, stringErr := ber.EncodeStringTagChecked(20, *v.TeletexString)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding teletex-string: %w", stringErr)
		}
		children = append(children, enc_teletexstring...)
	}
	encoded, setErr := ber.EncodeDERSet(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PDSParameter as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PDSParameter from BER/DER format.
func (v *PDSParameter) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PDSParameter destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	if err := ber.MarkBERSetOrder(data, func(candidate tag.Tag) int {
		if candidate.Class == tag.ClassUniversal && candidate.Number == 19 {
			return 0
		}
		if candidate.Class == tag.ClassUniversal && candidate.Number == 20 {
			return 1
		}
		return -1
	}, opts...); err != nil {
		return err
	}
	*v = PDSParameter{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding PDSParameter SET: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return fmt.Errorf("decoding PDSParameter SET: %w: got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PDSParameter", Cause: ber.ErrExtraData}
	}
	seen_printablestring := false
	seen_teletexstring := false
	offset := 0
	for offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PDSParameter", Cause: peekErr}
		}
		if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
			if seen_printablestring {
				return &ber.DecodeError{Offset: offset, TypeName: "PDSParameter", Field: "printable-string", Cause: ber.ErrInvalidValue}
			}
			val_printablestring, n, err := ber.DecodeString(content[offset:], 19, opts...)
			if err != nil {
				return fmt.Errorf("decoding printable-string: %w", err)
			}
			v.PrintableString = &val_printablestring
			if offset < 0 || offset >
				len(content) || n < 0 || n > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n
			if len([]rune(*v.PrintableString)) < 1 || len([]rune(*v.PrintableString)) > 30 {
				if constraintErr := ber.CheckDecodedLength(opts, "printable-string", "SIZE (1..30)", len([]rune(*v.PrintableString))); constraintErr != nil {
					return constraintErr
				}
			}
			seen_printablestring = true
		} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 20 {
			if seen_teletexstring {
				return &ber.DecodeError{Offset: offset, TypeName: "PDSParameter", Field: "teletex-string", Cause: ber.ErrInvalidValue}
			}
			val_teletexstring, n, err := ber.DecodeString(content[offset:], 20, opts...)
			if err != nil {
				return fmt.Errorf("decoding teletex-string: %w", err)
			}
			v.TeletexString = &val_teletexstring
			if offset < 0 || offset >
				len(content) || n < 0 || n > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			offset += n
			if len([]rune(*v.TeletexString)) < 1 || len([]rune(*v.TeletexString)) > 30 {
				if constraintErr := ber.CheckDecodedLength(opts, "teletex-string", "SIZE (1..30)", len([]rune(*v.TeletexString))); constraintErr != nil {
					return constraintErr
				}
			}
			seen_teletexstring = true
		} else {
			return &ber.DecodeError{Offset: offset, TypeName: "PDSParameter", Cause: fmt.Errorf("%w: unknown SET component tag %s", ber.ErrInvalidTag, peekTag)}
		}
	}
	return nil
}

// MarshalBER encodes ExtendedNetworkAddress to BER format.
func (v *ExtendedNetworkAddress) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtendedNetworkAddress receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtendedNetworkAddress) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ExtendedNetworkAddressChoiceE1634Address:
		if v.E1634Address == nil {
			return nil, fmt.Errorf("%w: choice ExtendedNetworkAddress: e163-4-address is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.E1634Address.MarshalBER(ber.ChildEncodeOptions(opts, "e163-4-address")...)
		if err != nil {
			return nil, fmt.Errorf("encoding e163-4-address: %w", err)
		}
		return enc_0, nil
	case ExtendedNetworkAddressChoicePsapAddress:
		if v.PsapAddress == nil {
			return nil, fmt.Errorf("%w: choice ExtendedNetworkAddress: psap-address is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.PsapAddress.MarshalBER(ber.ChildEncodeOptions(opts, "psap-address")...)
		if err != nil {
			return nil, fmt.Errorf("encoding psap-address: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding psap-address: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ExtendedNetworkAddress", v.Choice)
	}
}

// MarshalDER encodes ExtendedNetworkAddress to DER format.
func (v *ExtendedNetworkAddress) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtendedNetworkAddress receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ExtendedNetworkAddressChoiceE1634Address:
		if v.E1634Address == nil {
			return nil, fmt.Errorf("%w: choice ExtendedNetworkAddress: e163-4-address is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.E1634Address.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding e163-4-address: %w", err)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding e163-4-address as DER: %w", derErr)
		}
		return enc_der_0, nil
	case ExtendedNetworkAddressChoicePsapAddress:
		if v.PsapAddress == nil {
			return nil, fmt.Errorf("%w: choice ExtendedNetworkAddress: psap-address is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.PsapAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding psap-address: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding psap-address: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding psap-address as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtendedNetworkAddress as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtendedNetworkAddress from BER/DER format.
func (v *ExtendedNetworkAddress) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtendedNetworkAddress destination is nil", ber.ErrInvalidValue)
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
	*v = ExtendedNetworkAddress{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtendedNetworkAddress CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtendedNetworkAddress: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding ExtendedNetworkAddress CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtendedNetworkAddress", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = ExtendedNetworkAddressChoiceE1634Address
		var dec ExtendedNetworkAddressE1634Address
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "e163-4-address")...); unmErr != nil {
			return fmt.Errorf("decoding e163-4-address: %w", unmErr)
		}
		v.E1634Address = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = ExtendedNetworkAddressChoicePsapAddress
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding psap-address: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec PresentationAddress
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "psap-address")...); unmErr != nil {
			return fmt.Errorf("decoding psap-address: %w", unmErr)
		}
		v.PsapAddress = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ExtendedNetworkAddress CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes PresentationAddress to BER format.
func (v *PresentationAddress) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PresentationAddress receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PresentationAddress) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PSelector != nil {
		enc_pselector, encodeErr_enc_pselector := ber.EncodeOctetString(v.PSelector)
		if encodeErr_enc_pselector != nil {
			return nil, fmt.Errorf("encoding pSelector: %w", encodeErr_enc_pselector)
		}
		{
			var encodeErr error
			enc_pselector, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_pselector)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding pSelector: %w", encodeErr)
			}
		}
		children = append(children, enc_pselector...)
	}
	if v.SSelector != nil {
		enc_sselector, encodeErr_enc_sselector := ber.EncodeOctetString(v.SSelector)
		if encodeErr_enc_sselector != nil {
			return nil, fmt.Errorf("encoding sSelector: %w", encodeErr_enc_sselector)
		}
		{
			var encodeErr error
			enc_sselector, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sselector)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding sSelector: %w", encodeErr)
			}
		}
		children = append(children, enc_sselector...)
	}
	if v.TSelector != nil {
		enc_tselector, encodeErr_enc_tselector := ber.EncodeOctetString(v.TSelector)
		if encodeErr_enc_tselector != nil {
			return nil, fmt.Errorf("encoding tSelector: %w", encodeErr_enc_tselector)
		}
		{
			var encodeErr error
			enc_tselector, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tselector)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding tSelector: %w", encodeErr)
			}
		}
		children = append(children, enc_tselector...)
	}
	if v.NAddresses == nil {
		return nil, fmt.Errorf("encoding nAddresses: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.NAddresses).Values) < 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "nAddresses", "SIZE (1..MAX)", len((v.NAddresses).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_naddresses, err := MarshalBERPresentationAddressNAddresses(v.NAddresses, ber.ChildEncodeOptions(opts, "nAddresses")...)
	if err != nil {
		return nil, fmt.Errorf("encoding nAddresses: %w", err)
	}
	{
		var encodeErr error
		enc_naddresses, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_naddresses)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding nAddresses: %w", encodeErr)
		}
	}
	children = append(children, enc_naddresses...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PresentationAddress to DER format.
func (v *PresentationAddress) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PresentationAddress receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PSelector != nil {
		enc_pselector, encodeErr_enc_pselector := ber.EncodeOctetString(v.PSelector)
		if encodeErr_enc_pselector != nil {
			return nil, fmt.Errorf("encoding pSelector: %w", encodeErr_enc_pselector)
		}
		{
			var encodeErr error
			enc_pselector, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_pselector)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding pSelector: %w", encodeErr)
			}
		}
		children = append(children, enc_pselector...)
	}
	if v.SSelector != nil {
		enc_sselector, encodeErr_enc_sselector := ber.EncodeOctetString(v.SSelector)
		if encodeErr_enc_sselector != nil {
			return nil, fmt.Errorf("encoding sSelector: %w", encodeErr_enc_sselector)
		}
		{
			var encodeErr error
			enc_sselector, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sselector)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding sSelector: %w", encodeErr)
			}
		}
		children = append(children, enc_sselector...)
	}
	if v.TSelector != nil {
		enc_tselector, encodeErr_enc_tselector := ber.EncodeOctetString(v.TSelector)
		if encodeErr_enc_tselector != nil {
			return nil, fmt.Errorf("encoding tSelector: %w", encodeErr_enc_tselector)
		}
		{
			var encodeErr error
			enc_tselector, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tselector)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding tSelector: %w", encodeErr)
			}
		}
		children = append(children, enc_tselector...)
	}
	if v.NAddresses == nil {
		return nil, fmt.Errorf("encoding nAddresses: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.NAddresses).Values) < 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "nAddresses", "SIZE (1..MAX)", len((v.NAddresses).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_naddresses, err := MarshalDERPresentationAddressNAddresses(v.NAddresses)
	if err != nil {
		return nil, fmt.Errorf("encoding nAddresses: %w", err)
	}
	{
		var encodeErr error
		enc_naddresses, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_naddresses)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding nAddresses: %w", encodeErr)
		}
	}
	children = append(children, enc_naddresses...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PresentationAddress as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PresentationAddress from BER/DER format.
func (v *PresentationAddress) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PresentationAddress destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PresentationAddress{}
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
				decodedTag_pselector, n_pselector, innerData_pselector, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding pSelector: %w", err)
				}
				if decodedTag_pselector.Class != tag.ClassContextSpecific || decodedTag_pselector.Number != 0 || decodedTag_pselector.Constructed != true {
					return fmt.Errorf("decoding pSelector: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pselector)
				}
				_, innerUsed_pselector, _, innerErr_pselector := ber.DecodeTLV(innerData_pselector, opts...)
				if innerErr_pselector != nil {
					return fmt.Errorf("decoding pSelector: %w", innerErr_pselector)
				}
				if innerUsed_pselector != len(innerData_pselector) {
					return fmt.Errorf("decoding pSelector: %w", ber.ErrExtraData)
				}
				// Decode inner value from explicit tag wrapper
				val_pselector, _, err := ber.DecodeOctetString(innerData_pselector, opts...)
				if err != nil {
					return fmt.Errorf("decoding pSelector: %w", err)
				}
				tmp_pselector := val_pselector
				v.PSelector = tmp_pselector
				if offset > len(content) || n_pselector < 0 || n_pselector > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_pselector
			}
		}
	}
	// Decode sSelector
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_sselector, n_sselector, innerData_sselector, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sSelector: %w", err)
				}
				if decodedTag_sselector.Class != tag.ClassContextSpecific || decodedTag_sselector.Number != 1 || decodedTag_sselector.Constructed != true {
					return fmt.Errorf("decoding sSelector: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sselector)
				}
				_, innerUsed_sselector, _, innerErr_sselector := ber.DecodeTLV(innerData_sselector, opts...)
				if innerErr_sselector != nil {
					return fmt.Errorf("decoding sSelector: %w", innerErr_sselector)
				}
				if innerUsed_sselector != len(innerData_sselector) {
					return fmt.Errorf("decoding sSelector: %w", ber.ErrExtraData)
				}
				// Decode inner value from explicit tag wrapper
				val_sselector, _, err := ber.DecodeOctetString(innerData_sselector, opts...)
				if err != nil {
					return fmt.Errorf("decoding sSelector: %w", err)
				}
				tmp_sselector := val_sselector
				v.SSelector = tmp_sselector
				if offset < 0 || offset >
					len(content) || n_sselector < 0 || n_sselector > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sselector
			}
		}
	}
	// Decode tSelector
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_tselector, n_tselector, innerData_tselector, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding tSelector: %w", err)
				}
				if decodedTag_tselector.Class != tag.ClassContextSpecific || decodedTag_tselector.Number != 2 || decodedTag_tselector.Constructed != true {
					return fmt.Errorf("decoding tSelector: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tselector)
				}
				_, innerUsed_tselector, _, innerErr_tselector := ber.DecodeTLV(innerData_tselector, opts...)
				if innerErr_tselector != nil {
					return fmt.Errorf("decoding tSelector: %w", innerErr_tselector)
				}
				if innerUsed_tselector != len(innerData_tselector) {
					return fmt.Errorf("decoding tSelector: %w", ber.ErrExtraData)
				}
				// Decode inner value from explicit tag wrapper
				val_tselector, _, err := ber.DecodeOctetString(innerData_tselector, opts...)
				if err != nil {
					return fmt.Errorf("decoding tSelector: %w", err)
				}
				tmp_tselector := val_tselector
				v.TSelector = tmp_tselector
				if offset < 0 || offset >
					len(content) || n_tselector < 0 || n_tselector > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
	v.NAddressesIndef_ = false
	decodedTag_naddresses, n_naddresses, innerData_naddresses, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding nAddresses: %w", err)
	}
	if decodedTag_naddresses.Class != tag.ClassContextSpecific || decodedTag_naddresses.Number != 3 || decodedTag_naddresses.Constructed != true {
		return fmt.Errorf("decoding nAddresses: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naddresses)
	}
	_, innerUsed_naddresses, _, innerErr_naddresses := ber.DecodeTLV(innerData_naddresses, opts...)
	if innerErr_naddresses != nil {
		return fmt.Errorf("decoding nAddresses: %w", innerErr_naddresses)
	}
	if innerUsed_naddresses != len(innerData_naddresses) {
		return fmt.Errorf("decoding nAddresses: %w", ber.ErrExtraData)
	}
	// Decode inner value from explicit tag wrapper
	dec_naddresses, unmErr := UnmarshalBERPresentationAddressNAddresses(innerData_naddresses, ber.ChildDecodeOptions(opts, "nAddresses")...)
	if unmErr != nil {
		return fmt.Errorf("decoding nAddresses: %w", unmErr)
	}
	v.NAddresses = dec_naddresses
	if offset < 0 || offset >
		len(content) || n_naddresses < 0 || n_naddresses > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_naddresses
	if len((v.NAddresses).Values) < 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "nAddresses", "SIZE (1..MAX)", len((v.NAddresses).Values)); constraintErr != nil {
			return constraintErr
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PresentationAddress", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERTeletexDomainDefinedAttributes encodes a TeletexDomainDefinedAttributes list to BER.
func MarshalBERTeletexDomainDefinedAttributes(collection *TeletexDomainDefinedAttributes, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERTeletexDomainDefinedAttributes(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERTeletexDomainDefinedAttributes(collection *TeletexDomainDefinedAttributes, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "TeletexDomainDefinedAttributes", "SIZE (1..4)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERTeletexDomainDefinedAttributes encodes a TeletexDomainDefinedAttributes list to DER.
func MarshalDERTeletexDomainDefinedAttributes(collection *TeletexDomainDefinedAttributes) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "TeletexDomainDefinedAttributes", "SIZE (1..4)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TeletexDomainDefinedAttributes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERTeletexDomainDefinedAttributes decodes a TeletexDomainDefinedAttributes list from BER.
func UnmarshalBERTeletexDomainDefinedAttributes(data []byte, opts ...ber.DecodeOption) (returnValue *TeletexDomainDefinedAttributes, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding TeletexDomainDefinedAttributes: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TeletexDomainDefinedAttributes", Cause: ber.ErrExtraData}
	}
	var result []TeletexDomainDefinedAttribute
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem TeletexDomainDefinedAttribute
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 4 {
		if constraintErr := ber.CheckDecodedLength(opts, "TeletexDomainDefinedAttributes", "SIZE (1..4)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &TeletexDomainDefinedAttributes{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERTeletexDomainDefinedAttributes(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes TeletexDomainDefinedAttribute to BER format.
func (v *TeletexDomainDefinedAttribute) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TeletexDomainDefinedAttribute receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TeletexDomainDefinedAttribute) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len([]rune(v.Type)) < 1 || len([]rune(v.Type)) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "type", "SIZE (1..8)", len([]rune(v.Type))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_type, stringErr := ber.EncodeStringTagChecked(20, v.Type)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding type: %w", stringErr)
	}
	children = append(children, enc_type...)
	if len([]rune(v.Value)) < 1 || len([]rune(v.Value)) > 128 {
		if constraintErr := ber.CheckEncodedLength(opts, "value", "SIZE (1..128)", len([]rune(v.Value))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, stringErr := ber.EncodeStringTagChecked(20, v.Value)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding value: %w", stringErr)
	}
	children = append(children, enc_value...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TeletexDomainDefinedAttribute to DER format.
func (v *TeletexDomainDefinedAttribute) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TeletexDomainDefinedAttribute receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len([]rune(v.Type)) < 1 || len([]rune(v.Type)) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "type", "SIZE (1..8)", len([]rune(v.Type))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_type, stringErr := ber.EncodeStringTagChecked(20, v.Type)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding type: %w", stringErr)
	}
	children = append(children, enc_type...)
	if len([]rune(v.Value)) < 1 || len([]rune(v.Value)) > 128 {
		if constraintErr := ber.CheckEncodedLength(nil, "value", "SIZE (1..128)", len([]rune(v.Value))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, stringErr := ber.EncodeStringTagChecked(20, v.Value)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding value: %w", stringErr)
	}
	children = append(children, enc_value...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TeletexDomainDefinedAttribute as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TeletexDomainDefinedAttribute from BER/DER format.
func (v *TeletexDomainDefinedAttribute) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TeletexDomainDefinedAttribute destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TeletexDomainDefinedAttribute{}
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
	val_type, n, err := ber.DecodeString(content[offset:], 20, opts...)
	if err != nil {
		return fmt.Errorf("decoding type: %w", err)
	}
	v.Type = val_type
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len([]rune(v.Type)) < 1 || len([]rune(v.Type)) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "type", "SIZE (1..8)", len([]rune(v.Type))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode value
	if offset >= len(content) {
		return fmt.Errorf("missing required field value")
	}
	val_value, n, err := ber.DecodeString(content[offset:], 20, opts...)
	if err != nil {
		return fmt.Errorf("decoding value: %w", err)
	}
	v.Value = val_value
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len([]rune(v.Value)) < 1 || len([]rune(v.Value)) > 128 {
		if constraintErr := ber.CheckDecodedLength(opts, "value", "SIZE (1..128)", len([]rune(v.Value))); constraintErr != nil {
			return constraintErr
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TeletexDomainDefinedAttribute", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERAttributeValues encodes a AttributeValues list to BER.
func MarshalBERAttributeValues(collection *AttributeValues, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERAttributeValues(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERAttributeValues(collection *AttributeValues, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSet(children)
}

// MarshalDERAttributeValues encodes a AttributeValues list to DER.
func MarshalDERAttributeValues(collection *AttributeValues) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for _, elem := range list {
		if err := ber.ValidateDEREncodedElement(elem.Bytes); err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, elem.Bytes...)
	}
	encoded, setErr := ber.EncodeDERSetOf(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AttributeValues as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERAttributeValues decodes a AttributeValues list from BER.
func UnmarshalBERAttributeValues(data []byte, opts ...ber.DecodeOption) (returnValue *AttributeValues, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding AttributeValues: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding AttributeValues: %w: expected SET, got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AttributeValues", Cause: ber.ErrExtraData}
	}
	var result []AttributeValue
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: elementData[:n]})
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	decoded := &AttributeValues{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERAttributeValues(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes TBSCertListRevokedCertificatesElem to BER format.
func (v *TBSCertListRevokedCertificatesElem) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TBSCertListRevokedCertificatesElem receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TBSCertListRevokedCertificatesElem) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.UserCertificate == nil {
		return nil, fmt.Errorf("encoding userCertificate: %w: required INTEGER is nil", ber.ErrInvalidValue)
	}
	enc_usercertificate, encodeErr_enc_usercertificate := ber.EncodeBigInt(v.UserCertificate)
	if encodeErr_enc_usercertificate != nil {
		return nil, fmt.Errorf("encoding userCertificate: %w", encodeErr_enc_usercertificate)
	}
	children = append(children, enc_usercertificate...)
	enc_revocationdate, err := v.RevocationDate.MarshalBER(ber.ChildEncodeOptions(opts, "revocationDate")...)
	if err != nil {
		return nil, fmt.Errorf("encoding revocationDate: %w", err)
	}
	children = append(children, enc_revocationdate...)
	if v.CrlEntryExtensions != nil {
		if len((v.CrlEntryExtensions).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "crlEntryExtensions", "SIZE (1..MAX)", len((v.CrlEntryExtensions).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_crlentryextensions, err := MarshalBERExtensions(v.CrlEntryExtensions, ber.ChildEncodeOptions(opts, "crlEntryExtensions")...)
		if err != nil {
			return nil, fmt.Errorf("encoding crlEntryExtensions: %w", err)
		}
		children = append(children, enc_crlentryextensions...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TBSCertListRevokedCertificatesElem to DER format.
func (v *TBSCertListRevokedCertificatesElem) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TBSCertListRevokedCertificatesElem receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.UserCertificate == nil {
		return nil, fmt.Errorf("encoding userCertificate: %w: required INTEGER is nil", ber.ErrInvalidValue)
	}
	enc_usercertificate, encodeErr_enc_usercertificate := ber.EncodeBigInt(v.UserCertificate)
	if encodeErr_enc_usercertificate != nil {
		return nil, fmt.Errorf("encoding userCertificate: %w", encodeErr_enc_usercertificate)
	}
	children = append(children, enc_usercertificate...)
	enc_revocationdate, err := v.RevocationDate.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding revocationDate: %w", err)
	}
	children = append(children, enc_revocationdate...)
	if v.CrlEntryExtensions != nil {
		if len((v.CrlEntryExtensions).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "crlEntryExtensions", "SIZE (1..MAX)", len((v.CrlEntryExtensions).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_crlentryextensions, err := MarshalDERExtensions(v.CrlEntryExtensions)
		if err != nil {
			return nil, fmt.Errorf("encoding crlEntryExtensions: %w", err)
		}
		children = append(children, enc_crlentryextensions...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TBSCertListRevokedCertificatesElem as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TBSCertListRevokedCertificatesElem from BER/DER format.
func (v *TBSCertListRevokedCertificatesElem) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TBSCertListRevokedCertificatesElem destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TBSCertListRevokedCertificatesElem{}
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
	val_usercertificate, n, err := ber.DecodeBigInt(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding userCertificate: %w", err)
	}
	v.UserCertificate = val_usercertificate
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode revocationDate
	if offset >= len(content) {
		return fmt.Errorf("missing required field revocationDate")
	}
	// Decode nested CHOICE (Time)
	_, n_revocationdate, _, tlvErr_revocationdate := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_revocationdate != nil {
		return fmt.Errorf("decoding revocationDate: %w", tlvErr_revocationdate)
	}
	if offset < 0 || offset >
		len(content) || n_revocationdate < 0 || n_revocationdate > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.RevocationDate.UnmarshalBER(content[offset:offset+n_revocationdate], ber.ChildDecodeOptions(opts, "revocationDate")...); unmErr != nil {
		return fmt.Errorf("decoding revocationDate: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_revocationdate < 0 || n_revocationdate > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_revocationdate
	// Decode crlEntryExtensions
	v.CrlEntryExtensionsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (Extensions)
				_, n_crlentryextensions, _, tlvErr_crlentryextensions := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_crlentryextensions != nil {
					return fmt.Errorf("decoding crlEntryExtensions: %w", tlvErr_crlentryextensions)
				}
				if offset < 0 || offset >
					len(content) || n_crlentryextensions < 0 || n_crlentryextensions > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_crlentryextensions := content[offset : offset+n_crlentryextensions]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_crlentryextensions)
					if tagSz_ < len(tlv_crlentryextensions) && tlv_crlentryextensions[tagSz_] == 0x80 {
						v.CrlEntryExtensionsIndef_ = true
					}
				}
				dec_crlentryextensions, unmErr := UnmarshalBERExtensions(tlv_crlentryextensions, ber.ChildDecodeOptions(opts, "crlEntryExtensions")...)
				if unmErr != nil {
					return fmt.Errorf("decoding crlEntryExtensions: %w", unmErr)
				}
				v.CrlEntryExtensions = dec_crlentryextensions
				if offset < 0 || offset >
					len(content) || n_crlentryextensions < 0 || n_crlentryextensions > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_crlentryextensions
				if len((v.CrlEntryExtensions).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "crlEntryExtensions", "SIZE (1..MAX)", len((v.CrlEntryExtensions).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TBSCertListRevokedCertificatesElem", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERTBSCertListRevokedCertificates encodes a TBSCertListRevokedCertificates list to BER.
func MarshalBERTBSCertListRevokedCertificates(collection *TBSCertListRevokedCertificates, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERTBSCertListRevokedCertificates(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERTBSCertListRevokedCertificates(collection *TBSCertListRevokedCertificates, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERTBSCertListRevokedCertificates encodes a TBSCertListRevokedCertificates list to DER.
func MarshalDERTBSCertListRevokedCertificates(collection *TBSCertListRevokedCertificates) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TBSCertListRevokedCertificates as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERTBSCertListRevokedCertificates decodes a TBSCertListRevokedCertificates list from BER.
func UnmarshalBERTBSCertListRevokedCertificates(data []byte, opts ...ber.DecodeOption) (returnValue *TBSCertListRevokedCertificates, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding TBSCertListRevokedCertificates: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TBSCertListRevokedCertificates", Cause: ber.ErrExtraData}
	}
	var result []TBSCertListRevokedCertificatesElem
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem TBSCertListRevokedCertificatesElem
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	decoded := &TBSCertListRevokedCertificates{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERTBSCertListRevokedCertificates(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERUnformattedPostalAddressPrintableAddress encodes a UnformattedPostalAddressPrintableAddress list to BER.
func MarshalBERUnformattedPostalAddressPrintableAddress(collection *UnformattedPostalAddressPrintableAddress, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERUnformattedPostalAddressPrintableAddress(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERUnformattedPostalAddressPrintableAddress(collection *UnformattedPostalAddressPrintableAddress, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 6 {
		if constraintErr := ber.CheckEncodedLength(opts, "UnformattedPostalAddressPrintableAddress", "SIZE (1..6)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len([]rune(elem)) < 1 || len([]rune(elem)) > 30 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..30)", len([]rune(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, stringErr := ber.EncodeStringTagChecked(19, elem)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding element: %w", stringErr)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERUnformattedPostalAddressPrintableAddress encodes a UnformattedPostalAddressPrintableAddress list to DER.
func MarshalDERUnformattedPostalAddressPrintableAddress(collection *UnformattedPostalAddressPrintableAddress) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 6 {
		if constraintErr := ber.CheckEncodedLength(nil, "UnformattedPostalAddressPrintableAddress", "SIZE (1..6)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len([]rune(elem)) < 1 || len([]rune(elem)) > 30 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..30)", len([]rune(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, stringErr := ber.EncodeStringTagChecked(19, elem)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding element: %w", stringErr)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UnformattedPostalAddressPrintableAddress as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERUnformattedPostalAddressPrintableAddress decodes a UnformattedPostalAddressPrintableAddress list from BER.
func UnmarshalBERUnformattedPostalAddressPrintableAddress(data []byte, opts ...ber.DecodeOption) (returnValue *UnformattedPostalAddressPrintableAddress, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding UnformattedPostalAddressPrintableAddress: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "UnformattedPostalAddressPrintableAddress", Cause: ber.ErrExtraData}
	}
	var result []string
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, strErr := ber.DecodeString(elementData, 19, opts...)
		if strErr != nil {
			return nil, fmt.Errorf("decoding element: %w", strErr)
		}
		if len([]rune(val)) < 1 || len([]rune(val)) > 30 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1..30)", len([]rune(val))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, val)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 6 {
		if constraintErr := ber.CheckDecodedLength(opts, "UnformattedPostalAddressPrintableAddress", "SIZE (1..6)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &UnformattedPostalAddressPrintableAddress{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERUnformattedPostalAddressPrintableAddress(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes ExtendedNetworkAddressE1634Address to BER format.
func (v *ExtendedNetworkAddressE1634Address) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtendedNetworkAddressE1634Address receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtendedNetworkAddressE1634Address) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len([]rune(v.Number)) < 1 || len([]rune(v.Number)) > 15 {
		if constraintErr := ber.CheckEncodedLength(opts, "number", "SIZE (1..15)", len([]rune(v.Number))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_number, stringErr := ber.EncodeStringTagChecked(18, v.Number)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding number: %w", stringErr)
	}
	retagged_enc_number, tagErr_enc_number := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_number)
	if tagErr_enc_number != nil {
		return nil, fmt.Errorf("encoding number: %w", tagErr_enc_number)
	}
	enc_number = retagged_enc_number
	children = append(children, enc_number...)
	if v.SubAddress != nil {
		if len([]rune(*v.SubAddress)) < 1 || len([]rune(*v.SubAddress)) > 40 {
			if constraintErr := ber.CheckEncodedLength(opts, "sub-address", "SIZE (1..40)", len([]rune(*v.SubAddress))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_subaddress, stringErr := ber.EncodeStringTagChecked(18, *v.SubAddress)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding sub-address: %w", stringErr)
		}
		retagged_enc_subaddress, tagErr_enc_subaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_subaddress)
		if tagErr_enc_subaddress != nil {
			return nil, fmt.Errorf("encoding sub-address: %w", tagErr_enc_subaddress)
		}
		enc_subaddress = retagged_enc_subaddress
		children = append(children, enc_subaddress...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ExtendedNetworkAddressE1634Address to DER format.
func (v *ExtendedNetworkAddressE1634Address) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtendedNetworkAddressE1634Address receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len([]rune(v.Number)) < 1 || len([]rune(v.Number)) > 15 {
		if constraintErr := ber.CheckEncodedLength(nil, "number", "SIZE (1..15)", len([]rune(v.Number))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_number, stringErr := ber.EncodeStringTagChecked(18, v.Number)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding number: %w", stringErr)
	}
	retagged_enc_number, tagErr_enc_number := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_number)
	if tagErr_enc_number != nil {
		return nil, fmt.Errorf("encoding number: %w", tagErr_enc_number)
	}
	enc_number = retagged_enc_number
	children = append(children, enc_number...)
	if v.SubAddress != nil {
		if len([]rune(*v.SubAddress)) < 1 || len([]rune(*v.SubAddress)) > 40 {
			if constraintErr := ber.CheckEncodedLength(nil, "sub-address", "SIZE (1..40)", len([]rune(*v.SubAddress))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_subaddress, stringErr := ber.EncodeStringTagChecked(18, *v.SubAddress)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding sub-address: %w", stringErr)
		}
		retagged_enc_subaddress, tagErr_enc_subaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_subaddress)
		if tagErr_enc_subaddress != nil {
			return nil, fmt.Errorf("encoding sub-address: %w", tagErr_enc_subaddress)
		}
		enc_subaddress = retagged_enc_subaddress
		children = append(children, enc_subaddress...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtendedNetworkAddressE1634Address as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtendedNetworkAddressE1634Address from BER/DER format.
func (v *ExtendedNetworkAddressE1634Address) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtendedNetworkAddressE1634Address destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtendedNetworkAddressE1634Address{}
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
	decodedTag_number, n_number, rawVal_number, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding number: %w", err)
	}
	if decodedTag_number.Class != tag.ClassContextSpecific || decodedTag_number.Number != 0 {
		return fmt.Errorf("decoding number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_number)
	}
	decVal_number, stringErr := ber.DecodeImplicitStringValue(18, decodedTag_number.Constructed, rawVal_number, opts...)
	if stringErr != nil {
		return fmt.Errorf("decoding number: %w", stringErr)
	}
	v.Number = decVal_number
	if offset > len(content) || n_number < 0 || n_number > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_number
	if len([]rune(v.Number)) < 1 || len([]rune(v.Number)) > 15 {
		if constraintErr := ber.CheckDecodedLength(opts, "number", "SIZE (1..15)", len([]rune(v.Number))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode sub-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_subaddress, n_subaddress, rawVal_subaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sub-address: %w", err)
				}
				if decodedTag_subaddress.Class != tag.ClassContextSpecific || decodedTag_subaddress.Number != 1 {
					return fmt.Errorf("decoding sub-address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_subaddress)
				}
				decVal_subaddress, stringErr := ber.DecodeImplicitStringValue(18, decodedTag_subaddress.Constructed, rawVal_subaddress, opts...)
				if stringErr != nil {
					return fmt.Errorf("decoding sub-address: %w", stringErr)
				}
				v.SubAddress = &decVal_subaddress
				if offset < 0 || offset >
					len(content) || n_subaddress < 0 || n_subaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_subaddress
				if len([]rune(*v.SubAddress)) < 1 || len([]rune(*v.SubAddress)) > 40 {
					if constraintErr := ber.CheckDecodedLength(opts, "sub-address", "SIZE (1..40)", len([]rune(*v.SubAddress))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExtendedNetworkAddressE1634Address", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERPresentationAddressNAddresses encodes a PresentationAddressNAddresses list to BER.
func MarshalBERPresentationAddressNAddresses(collection *PresentationAddressNAddresses, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERPresentationAddressNAddresses(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERPresentationAddressNAddresses(collection *PresentationAddressNAddresses, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "PresentationAddressNAddresses", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString(elem)
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSet(children)
}

// MarshalDERPresentationAddressNAddresses encodes a PresentationAddressNAddresses list to DER.
func MarshalDERPresentationAddressNAddresses(collection *PresentationAddressNAddresses) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "PresentationAddressNAddresses", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString(elem)
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeDERSetOf(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PresentationAddressNAddresses as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERPresentationAddressNAddresses decodes a PresentationAddressNAddresses list from BER.
func UnmarshalBERPresentationAddressNAddresses(data []byte, opts ...ber.DecodeOption) (returnValue *PresentationAddressNAddresses, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding PresentationAddressNAddresses: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != tag.TagSet || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding PresentationAddressNAddresses: %w: expected SET, got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PresentationAddressNAddresses", Cause: ber.ErrExtraData}
	}
	var result [][]byte
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, val)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "PresentationAddressNAddresses", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &PresentationAddressNAddresses{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERPresentationAddressNAddresses(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}
