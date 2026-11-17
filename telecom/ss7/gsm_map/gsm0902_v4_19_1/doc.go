// Code generated from GSM 09.02 V4.19.1. DO NOT EDIT.

// Package gsm0902_v4_19_1 implements the source edition GSM 09.02 V4.19.1.
// Its BER profile is GSM 09.02 V4.19.1 §14.1.1 (ETS 300 599 ed.9):
// short definite lengths below 128, minimum long-form length octets,
// primitive OCTET STRING and BIT STRING, and permitted empty constructors.
// “OCTET STRING values and BIT STRING values must be encoded in a primitive form.”
// Q.773 (06/1997) §3.1 governs its native OPERATION and ERROR catalogue.
// Procedure version comments do not remove fields from the grammar.
// VERSION-COMMENTS.json lists those comments with their official ASN.1.txt line ranges.
// Its ASN.1 rules use X.208 and X.209 (11/1988), as specified by
// GSM 09.02 V4.19.1 §§14.1–14.1.1 and references [93]–[94].
// Extension-marker rules retain X.680/X.690 (02/2021) citations: §14.1.4
// adopts them from ISO 8824-1/PDAM 3.2, which has no 1988 counterpart.
// IA5 escape-sequence exception: retain ITU-T X.690 (02/2021) §8.23.5.3.
// X.209 (11/1988) §23.5.3 begins: "Certain character string types shall not
// contain explicit escape sequences in their encodings; in all other cases,
// any escape allowed by § 23.5.1 can appear at any time, including at the start of the encoding."
// X.690 (02/2021) §8.23.5.3 begins: "Certain character string types shall not
// contain explicit escape sequences in their encodings; in all other cases,
// any escape sequence allowed by 8.23.5.1 can appear at any time, including at the start of the encoding."
// These clauses state the same rule. The identifier stays because the
// shared runtime selects its escape-sequence policy by this RuleRef;
// replacing it would change accepted values and tolerance records.
// DER citations retain X.690 (02/2021); X.209 (11/1988) has no DER.
// Shared runtime structural diagnostics retain their modern citations;
// see the shared runtime citation concordance below.
//
// # Shared runtime citation concordance
//
// The shared runtime retains its modern citations. The clauses below describe the corresponding
// historical rules. Generic runtime routines also cover types absent from these historical
// editions. Runtime behavior follows the existing shared runtime policy.
//
// X.690 (02/2021) §8.23.5.3/Table 3 -> X.209 (11/1988) §23.5.3/Table 2.
// IA5String forbids explicit escape sequences. The encoded-value check selects the modern rule
// identifier to apply the shared runtime escape-sequence policy.
//
// X.690 (02/2021) §8.23.10; ISO/IEC 10646:2003 §15 where cited -> no 1988 counterpart.
// UTF8String is absent from X.208 §31/Table 6. X.209 §23 encodes the character-string types
// defined by X.208; it has no UTF-8 scalar, shortest-form, Unicode noncharacter or Unicode
// code-extension rule. The encoded-value check selects this rule for UTF8String.
//
// X.690 (02/2021) §8.8.1 -> X.209 (11/1988) §13.1.
// Primitive NULL encoding.
//
// X.690 (02/2021) §8.3.1 -> X.209 (11/1988) §8.1.
// INTEGER contents contain at least one octet; encoding is primitive.
//
// X.690 (02/2021) §8.3.2 -> X.209 (11/1988) §8.2.
// The redundant initial sign octet is forbidden.
//
// X.680 (02/2021) §41.15; X.690 (02/2021) §8.23.8 for BMPString repertoire, §§8.23.8–8.23.9 for
// whole character values -> no 1988 counterpart.
// BMPString is absent from X.208 §31/Table 6; X.209 has no whole two-octet UCS encoding rule.
//
// X.680 (02/2021) §41.6; ISO/IEC 10646:2003 §§7 a), 8; X.690 (02/2021) §8.23.7 for
// UniversalString repertoire, §§8.23.7, 8.23.9 for whole character values -> no 1988
// counterpart.
// UniversalString is absent from X.208 §31/Table 6; X.209 has no whole four-octet UCS encoding
// rule.
//
// X.680 (02/2021) §51.5 -> X.208 (11/1988) §37.4.
// SIZE value-set length and unit correspond. Modern named-bit normalization and historical exact
// received/supplied bit lengths have different semantics, described by X.208 §§17.10,
// 37.4.3–37.4.4 and X.209 §11.2.
//
// X.680 (02/2021) §41.2/Table 9; X.690 (02/2021) §8.23.4 -> X.208 (11/1988) §31.3/Table 4; X.209
// (11/1988) §23.4.
// NumericString contains digits and space, encoded using the VisibleString octets for the same
// characters.
//
// X.680 (02/2021) §41.4/Table 10; X.690 (02/2021) §8.23.4 -> X.208 (11/1988) §31.4/Table 5;
// X.209 (11/1988) §23.4.
// PrintableString alphabet and corresponding VisibleString octets.
//
// X.680 (02/2021) Table 8; X.690 (02/2021) §8.23.5/Table 3 -> X.208 (11/1988) §31.2/Table 6;
// X.209 (11/1988) §23.5/Table 2.
// IA5String uses registered sets 1 and 2 plus SPACE and DELETE; VisibleString uses registered
// set 2 plus SPACE. Both forbid explicit escape sequences.
//
// X.680 (02/2021) §§46.3, 47.3; X.690 (02/2021) §8.25 -> X.208 (11/1988) §§32.3, 33.3; X.209
// (11/1988) §24.
// GeneralizedTime and UTCTime syntax and encoding through their ASN.1 useful-type definitions.
//
// X.690 (02/2021) §§8.23.4–8.23.5 -> X.209 (11/1988) §§23.4–23.5.
// NumericString and PrintableString use §8.23.4; the other supported restricted alphabets use
// §8.23.5. The corresponding X.208 repertoire is in §31/Tables 4–6.
//
// X.680 (02/2021) §§41.6, 41.15–41.16; ISO/IEC 10646:2003 §§7 a), 8 -> no 1988 counterpart.
// UniversalString, BMPString and UTF8String, and permanently reserved Unicode noncharacter
// cells, are absent from X.208.
//
// X.690 (02/2021) §§8.23.5.3, 8.23.9–8.23.10 -> X.209 (11/1988) §23.5.3/Table 2 for IA5String;
// no 1988 counterpart for BMPString/UniversalString/UTF8String.
// The runtime message covers IA5 escape restrictions and Unicode code-extension restrictions.
// The historical clause covers only the IA5String branch; the Unicode branches have no 1988
// counterpart.
//
// X.680 (02/2021) §51 -> X.208 (11/1988) §36.
// Subtype constraints: values must belong to the specified subtype value set. X.208 §37
// specifies the individual value-set forms.
//
// X.690 (02/2021) primitive universal-form rule -> X.209 (11/1988) §§7.1, 8.1, 9.1, 10.1, 13.1,
// 22.1 for BOOLEAN, INTEGER, ENUMERATED, REAL, NULL, OBJECT IDENTIFIER; no 1988 counterpart for
// RELATIVE-OID, OID-IRI, RELATIVE-OID-IRI, TIME, DATE, TIME-OF-DAY, DATE-TIME, DURATION.
// The modern message has no printed clause and covers multiple types. X.208 lacks the listed
// later types; GeneralizedTime and UTCTime are separate useful types and are not substitutes for
// the later TIME family.
//
// X.690 (02/2021) constructed universal-form rule -> X.209 (11/1988) §§14.1, 15.1, 16.1, 17.1,
// 24; X.208 (11/1988) §34.4 for EXTERNAL; no 1988 counterpart for EMBEDDED PDV or CHARACTER
// STRING.
// SEQUENCE, SEQUENCE OF, SET and SET OF require constructed form; EXTERNAL is defined as an
// implicitly tagged SEQUENCE. The later unrestricted CHARACTER STRING type is distinct from the
// restricted character-string types of X.208 §31.
//
// X.690 (02/2021) §11.7.1 -> no 1988 counterpart.
// DER requires GeneralizedTime to terminate with Z. X.209 specifies BER and has no DER. X.208
// §32.3 explicitly permits local time without Z, UTC with Z, and local differential forms.
//
// # Runtime sites
//
// Site: ber/constraints.go, CheckEncodedValue
// IA5String escape sequences; UTF8String encoding and controls.
//
// Site: ber/string_controls_encode.go, checkEncodedIA5Controls
// IA5String escape sequences.
//
// Site: ber/string_controls.go, stringControlConstraint
// IA5String escape sequences; UTF8String encoding and controls.
//
// Site: ber/opaque.go, opaqueUTF8EncodeError
// UTF8String encoding and controls.
//
// Site: ber/string_reporting.go, reportStringContents
// UTF8String encoding and controls.
//
// Site: ber/utf8_encode.go, checkEncodedUTF8String
// UTF8String encoding and controls.
//
// Site: ber/decoder.go, DecodeNull
// primitive NULL encoding.
//
// Site: ber/decoder.go, validateMinimalIntegerContents
// INTEGER contents and primitive form; redundant INTEGER sign octets.
//
// Site: ber/encoder.go, encodeStringValueTag
// BMPString repertoire and whole character values; UniversalString repertoire and whole
// character values.
//
// Site: ber/restricted_string.go, finish
// BMPString repertoire and whole character values; UniversalString repertoire and whole
// character values; GeneralizedTime and UTCTime syntax and encoding.
//
// Site: ber/named_bit_encoding.go, namedBitSizeViolation
// SIZE value-set length and unit.
//
// Site: ber/restricted_string.go, alphabetRule
// NumericString alphabet and encoding; PrintableString alphabet and encoding; IA5String and
// VisibleString alphabets and encoding.
//
// Site: ber/restricted_tolerance.go, alphabetRuleRef
// restricted-alphabet encoding.
//
// Site: ber/string_controls.go, package
// Unicode repertoires and noncharacters.
//
// Site: ber/string_controls.go, invalidStringControl
// string code-extension controls.
//
// Site: ber/validation.go, identifyViolation
// subtype value sets.
//
// Site: ber/work.go, checkUniversalForm
// primitive universal forms; constructed universal forms.
//
// Site: time.go, Canonical
// DER GeneralizedTime termination.
package gsm0902_v4_19_1
