# go-asn1

Compiled ASN.1 specifications as native Go packages with generated marshal/unmarshal codecs.

## Installation

```bash
go get github.com/gomaja/go-asn1@main
```

No releases are published. Depend on the `main` branch and update with
`go get github.com/gomaja/go-asn1@main`.

All earlier tagged versions (v0.1.0–v0.4.2) are retracted. The `v0.5.0` tag
exists only to publish that retraction and is retracted too; do not depend on
any tagged version.

## Usage

```go
import "github.com/gomaja/go-asn1/telecom/lte/x2ap"

// Decode an X2AP PDU from APER bytes
var pdu x2ap.X2APPDU
err := pdu.UnmarshalAPER(data)

// Re-encode (byte-exact round-trip)
encoded, err := pdu.MarshalAPER()
```

## Codec limits

Generated codecs check the exact permitted lengths of `SIZE` constraints on
encode and decode. PER length fields use the effective constraint: for
`SIZE (1..5 EXCEPT 1)`, lengths 2 through 5 are valid, while the wire length
field uses the pre-exclusion 1 through 5 range (ITU-T X.680 (02/2021)
§51.5.3; X.691 (02/2021) §10.3.21). The compiler rejects legal `SIZE`
intersections at its pycrate frontend and extensible disjoint `SIZE` unions
at PER preflight; neither form is silently widened.

Extension-addition bitmaps of 16,384 bits or more require the fragmented form
in X.691 (02/2021) §11.9.3.8. Encode and decode return
`per.ErrUnsupportedFragmentedNormallySmallLength` for that form.

A fresh extension-bearing SEQUENCE or SET emits all n extension-presence
bits, where n is the number of additions in its source version (X.691
(02/2021) §19.7 and its NOTE, §§19.8 and 11.9). A decoded value replays its
received bitmap width, even when another version sent fewer or more bits.
Edits within that boundary retain it; an addition beyond it expands the
bitmap to at least the current source width, preserving unknown additions.
CHOICE extensions have an index instead of this bitmap.

BER decode depth, element-count, aggregate-work and decimal REAL digit
budgets return `ber.ErrResourceLimit`, distinct from `ber.ErrInvalidValue`.
Decimal REAL digits are unlimited by default. Set
`ber.WithDecodeLimits(ber.DecodeLimits{MaxRealDecimalDigits: 1000})` at a
runtime or generated decoder entry point to cap the combined mantissa and
exponent digits before conversion, including leading zeros. Implicitly
tagged REALs use the same budget. DER validation checks decimal REAL
canonical spelling directly, without big-number conversion.

### APER character strings and bit strings

In the ALIGNED variant, each character of an IA5String, VisibleString or
PrintableString takes B2 = 8 bits, the smallest power of two not below the
7 bits its alphabet needs (ITU-T X.691 (02/2021) §30.5.2). Earlier releases
used 7 bits, so the APER string IEs were encoded and decoded wrongly: S1AP
`ENBname` and `MMEname`, the S1AP `URI-Address` of TraceActivation extension
325, and the X2AP `URI-Address` of TraceActivation extension 405. A
conforming `ENBname` "ab" (`00806162`) decoded as "0X". These IEs now match
the standard, and encodings of them written by earlier releases no longer
decode. A known-multiplier string is aligned as §§30.5.6 and 30.5.7
require, and NumericString and PER-visible `FROM` alphabets use
canonical-order indexes where §30.5.4 requires them. No release package has
a NumericString or a PER-visible `FROM` alphabet.

A BIT STRING or OCTET STRING whose size is not fixed is octet-aligned in
APER whatever its upper bound, and nothing follows a zero length (§§16.11,
17.8, 11.9.3.3). No release package has a variable-size BIT STRING with an
upper bound of 16 bits or less, or an OCTET STRING of at most 2 octets, so
their wire output is unchanged. In both variants, a root length received in
extension form is rejected on decode (§§16.6, 17.3).

### BER constraints and trace tolerance

BER decoding and encoding enforce resolved INTEGER, ENUMERATED, REAL, and
`SIZE` constraints by default. Constraint failures return
`*ber.ConstraintError`. For trace inspection, an explicit tolerance option
admits representable out-of-constraint values and records each field path,
constraint, and observed value or length. Pass the option to both decode and
encode when preserving such a value. DER remains strict (ITU-T X.680
(02/2021) §§49–51; X.690 (02/2021) §§8.1.3, 8.7).

```go
package main

import (
    "log"

    "github.com/gomaja/go-asn1/runtime/ber"
    "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

func replayBER(wire []byte) ([]byte, error) {
    var value tcap.TCMessage
    var violations ber.ViolationLog
    option := ber.WithConstraintTolerance(&violations)
    if err := value.UnmarshalBER(wire, option); err != nil {
        return nil, err
    }
    for _, violation := range violations.Snapshot() {
        if violation.ObservedLength != nil {
            log.Printf("%s: %s, length %d", violation.Path,
                violation.Constraint, *violation.ObservedLength)
        } else {
            log.Printf("%s: %s, value %s", violation.Path,
                violation.Constraint, violation.ObservedValue)
        }
    }
    encoded, err := value.MarshalBER(option)
    violations.Reset()
    return encoded, err
}
```

`ber.ViolationLog` can be shared across concurrent decodes; `Snapshot`
returns independent records. A report's `Path` is built from the ASN.1
component identifiers of the source module, with a zero-based `element[i]`
step inside a SEQUENCE OF or SET OF, for example
`subscriberInfo.mnpInfoRes.routeingNumber` or `eplmn-List.element[1]`.
Decoding and tolerant encoding report the same paths, and both record their
violations. Reports are transactional: a call publishes them only when it
succeeds, so a decode or encode that fails after tolerating a violation adds
nothing to the log. Tolerance cannot represent a negative BER
INTEGER in a generated `uint64` field or a value wider than a generated
`int64` field: decoding returns `ber.ErrInvalidValue` without substituting
raw bytes. Source value `EXCEPT` and collection-element unions that the
frontend cannot resolve remain fail closed (ITU-T X.680 (02/2021) §§49.7,
50–51).

#### Preserved BER forms and DER

Strict and tolerant decoders retain received BER bytes only when an unchanged
value would otherwise lose a valid noncanonical form, such as a constructed
string, an indefinite length, a nonminimal length, a non-normalised REAL, or
the received component order of an extensible SET, and, in tolerant mode, when
it carries a tolerated constraint violation. Canonical input takes no
received-byte snapshot. Changing a typed field makes BER encoding use its
current value. Out-of-constraint values still require the tolerance option
when encoding.

`MarshalDER` encodes typed values in DER form and never re-emits preserved BER
bytes: REAL values take their distinguished form, SET components are sorted,
a SEQUENCE or SET component equal to its `DEFAULT` is omitted, and a named
BIT STRING loses its trailing zero bits (ITU-T X.690 (02/2021) §8.5.7 NOTE 1,
§§10.3, 11.2.2, 11.3.1, 11.5). The named BIT STRING rule changes the DER of
such values in GSM MAP, TCAP (`protocol-version`), SGP.22 and SGP.32 when they
end in zero bits. When decoding, a named BIT STRING shorter than its `SIZE`
lower bound is first extended with trailing zero bits, which X.680 (02/2021)
§22.7 permits, before the constraint is checked. Open-type contents are
emitted as carried.
An unchanged valid BER REAL whose normalized exponent cannot fit the 255-octet
encoding limit can still be re-encoded as BER; `MarshalDER` returns
`ber.ErrInvalidValue` (X.690 §§8.5.7.4, 11.3.1).

A SEQUENCE OF or SET OF whose element type carries its own tag, IMPLICIT or
EXPLICIT, directly or through a tagged type reference, decodes and encodes
each element with that effective tag (ITU-T X.680 (02/2021) §31; X.690
(02/2021) §§8.10, 8.12, 8.14). This is what makes the tagged segment lists of
the SGP.22 and SGP.32 `BoundProfilePackage` decode; earlier releases checked
the element type's universal tag instead and could not decode a
`BoundProfilePackage`.

Constraint tolerance does not admit invalid encodings. Both modes reject:

- INTEGER and ENUMERATED encodings with redundant sign octets, including
  under implicit tags, with `ber.ErrInvalidValue` (X.690 §§8.3.2, 8.4);
- a constructed NULL, including under an implicit tag (X.690 §8.8.1);
- any component encoding inside a non-extensible SEQUENCE or SET that has no
  components, with a `*ber.DecodeError` naming the type and wrapping
  `ber.ErrExtraData` (X.690 §§8.9.2, 8.11.2). Extensible empty types keep
  their extensions.

#### Time values

UTCTime and GeneralizedTime fields are `runtime.UTCTime` and
`runtime.GeneralizedTime`, held by pointer when OPTIONAL. A value holds the
validated lexical form it was decoded or parsed from, so every form of ITU-T
X.680 (02/2021) §46.3 and §47.3 decodes: hour or minute accuracy, fractions
of the last unit to any number of digits, comma or full stop, a local time
with no differential, and `+hh` or `+hhmm` differentials. Build values with
`runtime.ParseUTCTime`, `runtime.ParseGeneralizedTime`,
`runtime.UTCTimeFromTime` or `runtime.GeneralizedTimeFromTime`; the last two
produce the canonical form. The zero value means "not set", and every encoder
rejects it with `runtime.ErrTimeNotSet`.

- **BER** writes the lexical form verbatim, so an unchanged value re-encodes
  byte for byte (X.690 (02/2021) §8.25). A constructed time encoding is kept
  by the preserved BER bytes of the enclosing value until that value changes.
- **DER and PER** compute the X.690 (02/2021) §11.7/§11.8 form exactly: UTC
  with `Z`, seconds present, a full stop and no trailing fraction zeros, so
  `"2026010112,5Z"` becomes `"20260101123000Z"` and `"8201020700-0500"`
  becomes `"820102120000Z"`. X.691 (02/2021) §10.6.5 applies the same form
  to PER. A local time of day, or a value whose UTC equivalent falls outside
  the type's years, has no such form: `MarshalDER`, the PER encoders,
  `ber.EncodeUTCTimeDER`, `ber.EncodeGeneralizedTimeDER` and `Canonical`
  return `runtime.ErrNoCanonicalTime`, wrapped in `ber.ErrInvalidValue` or
  `per.ErrInvalidValue`. PER decoding accepts only the canonical form.
- **Instants.** `Time()` returns the instant, in UTC for `Z` and in a fixed
  zone for a differential. A local time of day fixes no instant: `Time()`
  returns `runtime.ErrLocalTime`, and `TimeIn(loc)` reads it as a wall-clock
  time in `loc`. Digits finer than a nanosecond are truncated in `Time()` and
  kept in the value.
- **Century.** UTCTime reads `YY` with the RFC 5280 §4.1.2.5.1 window, 50–99
  as 1950–1999 and 00–49 as 2000–2049, in every package, including LPP and
  UMTS RRC; X.680 §47.3 defines no century. RFC 5280 §4.1.2.5 requires
  GeneralizedTime for certificate validity dates in 2050 or later, and
  `UTCTimeFromTime` returns `runtime.ErrTimeRange` outside the window.
  RFC 5280 §4.1.2.5.2 also forbids fractional seconds in certificates.
- **Comparison.** `==` compares the spelling. `Equal` compares the abstract
  value: it ignores the decimal sign and the spelling of a whole-hour
  differential (X.690 §11.9.1 a), b)) but not the accuracy or the zone kind
  (X.680 §46.3 NOTE 3).
- **JSON** and text carry the exact lexical string, for example
  `"NotBefore":"19920722132100.30"`; an unset required field is `""`.
  RFC 3339 input is rejected with `runtime.ErrTimeSyntax`.

### UPER trace tolerance

By default, UPER decoding accepts after a complete encoding only the one to
seven bits that pad it to an octet boundary (ITU-T X.691 (02/2021)
§§11.1.3.1, 11.2.1). This applies to the top-level value, to a value inside
an `OCTET STRING (CONTAINING ...)` and to each open type. The sender must set
those bits to zero, but the decoder accepts them whatever their value and
keeps nonzero ones, so the input re-encodes unchanged. Zero padding is what an
encoder writes anyway, so it is not kept. The default decode rejects a
longer suffix after the top-level value or a contained value, and any bit
after a value inside a `BIT STRING (CONTAINING ...)`, where §11.1.3.2 allows
no padding.

3GPP-conformant RRC decoding (TS 36.331 §8.1, TS 25.331 §12.1.3) requires
enabling `TrailingBitsTolerance`. TS 36.331 V19.4.0 §8.1 requires RRC decoders
never to report an error for extraneous zero or non-zero bits at the end of a
PDU, or of a `BIT STRING` or `OCTET STRING` constrained with `CONTAINING`; TS
25.331 V19.0.1 §12.1.3 requires UMTS receivers to accept any bit string in the
extension and padding parts of a PDU. The default stays strict X.691, so a
receiver passes a `per.ToleranceLog` in
`per.DecodeOptions{TrailingBitsTolerance}`. Tolerance then accepts any suffix
of more than seven bits after the top-level value or after a value inside an
`OCTET STRING (CONTAINING ...)`, and any zero or non-zero bits after a value
inside a `BIT STRING (CONTAINING ...)`. Each accepted run is recorded with its
field path, kind, offset and bits, so no walk of the decoded value is needed.
Nonzero bits within the padding the default decode accepts are kept but never
recorded.

```go
package main

import (
    "log"

    "github.com/gomaja/go-asn1/runtime/per"
    umts "github.com/gomaja/go-asn1/telecom/umts/rrc"
)

func replayUPER(wire []byte) ([]byte, error) {
    var tolerated per.ToleranceLog
    var value umts.InterRATHandoverInfo
    options := per.DecodeOptions{TrailingBitsTolerance: &tolerated}
    if err := value.UnmarshalUPERWithOptions(wire, options); err != nil {
        return nil, err
    }
    for _, record := range tolerated.Snapshot() {
        log.Printf("%s: %s, %d bits at offset %d", record.Path, record.Kind,
            record.Bits.BitLength, record.Offset)
    }
    tolerated.Reset()
    return value.MarshalUPER()
}
```

Top-level SEQUENCE and CHOICE values, and SEQUENCE OF values through their
`<List>Complete` wrapper, take the same options. A record from inside a list
element is rooted at the list type and carries the element's index, as in
`<List>.Value[1].<Field>`; a list inside a SEQUENCE gives
`<Type>.<ListField>[1].<Field>`.
A log may be shared by concurrent decodes. A successful decode appends all of
its records together; a failed decode appends none. The decoded value keeps the accepted
bits, so `MarshalUPER` reproduces the input octets:

- A suffix after the top-level value, or after a value inside an
  `OCTET STRING (CONTAINING ...)`, is kept in that value's `PERPadding_`, a
  `per.FinalPadding` (see `Trailing()`). That field is one pointer wide and
  does not allocate for ordinary 0–7 padding bits.
- Bits after a value inside a `BIT STRING (CONTAINING ...)` are kept in the
  host SEQUENCE's `<Field>PERPadding_`, also a `per.FinalPadding`.

The single zero octet of an empty top-level value, and the single zero bit of
an empty contained value, are part of the complete encoding (X.691 (02/2021)
§§11.1.3.1, 11.1.3.2, 11.1.4). They are never recorded as tolerances; a
nonzero mandated octet or bit, or a missing one, is rejected in both modes.

### Editing decoded PER values

A decoded UPER or APER value can be edited and encoded again. Each complete
encoding decides for itself what it keeps: the top-level value, a value
inside an `OCTET STRING` or `BIT STRING (CONTAINING ...)`, and each open
type. Its kept bits are reproduced only while they still belong to its new
encoding:

- A tolerated suffix, or bits after a value inside a
  `BIT STRING (CONTAINING ...)`, is reproduced only after the value encoding
  it followed, bit for bit. An edit of that value drops it: the value is
  encoded as a new one would be, with zero padding after a complete encoding
  (X.691 (02/2021) §§11.1.3.1, 11.1.4) and nothing after a value inside a
  `BIT STRING` (§11.1.3.2).
- Nonzero padding is kept while it still fills the final octet exactly;
  otherwise the edited value gets zero padding. Nonzero padding comes only
  from a non-conformant sender, since §§11.1.3.1 and 11.1.4 require zero
  bits. Only its width is kept, so an edit that leaves the bit length
  unchanged, or changes it by a multiple of eight, keeps it. Padding carries
  no value, so it does not affect decoding.

```go
var value rrc.RRCConnectionSetupCompleteV8a0IEs
if err := value.UnmarshalUPER([]byte{0x00}); err != nil {
    return err
}
value.NonCriticalExtension = &rrc.RRCConnectionSetupCompleteV1020IEs{}
wire, err := value.MarshalUPER() // 40, as for a newly built value
```

Editing an enclosing value does not touch the bits kept by an unchanged value
inside it: that value still reproduces its received suffix. A tolerantly
decoded message whose nested values kept tolerated bits therefore still needs
tolerance to decode after an edit elsewhere, and differs from a fresh
encoding. To get a fresh, strictly decodable encoding, reset the padding
fields (`PERPadding_`, `<Field>PERPadding_`, `PERExtPadding_`,
`PEROpenTypePadding_`) of the value and of every value inside it. Also reset
`ExtCount_` and `ExtPresent_` for fresh extension bitmaps. To encode only
the current source version, also clear `ExtData_`; this deliberately drops
unknown additions. Keep their data if they must survive, which may require
a wider bitmap. Alternatively, build the value anew.

### Deferred contained values

UPER decoding decodes a value carried in a `BIT STRING (CONTAINING ...)` or
`OCTET STRING (CONTAINING ...)` together with its enclosing value. TS 36.331
V19.4.0 §8.1 and TS 38.331 V19.4.0 §8.1 recommend otherwise for RRC
receivers: "errors in the decoding of the contained type should not cause the
decoding of the entire RRC message PDU to fail", and the contained value is
best decoded "as a separate step". `per.DecodeOptions.ContainedDecoding`
selects the behaviour:

| Mode | Contained value that decodes | Contained value that fails |
|---|---|---|
| `per.Eager` (default) | typed | fails the whole decode |
| `per.DeferOnError` | typed | kept raw with its error; the rest decodes |
| `per.DeferAll` | kept raw, not decoded | kept raw, not decoded |

The affected values are the 39 contained `OCTET STRING`s of `lte/rrc`, and
the 57 contained `BIT STRING`s and 13 contained `OCTET STRING`s of
`umts/rrc`, one of them `InterRATHandoverInfo`'s `ue-CapabilityContainer`
(TS 25.331 V19.0.1 §11.2). No other package has one.

`DeferOnError` applies at every nesting level: a contained value inside one
that decodes is itself decoded or deferred. `DeferAll` keeps the outermost
contained values raw, and anything nested in them is part of their raw
contents. Only the contained value's own decode, including its final or
trailing bits, is deferred. The enclosing `BIT STRING` or `OCTET STRING` is
decoded and checked first, so a bad length determinant fails the decode in
every mode, as does any other component. TS 25.331 V19.0.1 has no rule for
contained values; the modes still apply to `umts/rrc`. They are independent
of `TrailingBitsTolerance`, which RRC receivers need as well.
Both deferring modes require a `per.DeferralLog` in `DecodeOptions.Deferrals`;
a decode that defers without one fails. A successful decode appends one
record per deferred value, in decode order and in the same commit as its
tolerance records; a failed decode appends none:
```go
var tolerated per.ToleranceLog
var deferred per.DeferralLog
options := per.DecodeOptions{
    TrailingBitsTolerance: &tolerated,
    ContainedDecoding:     per.DeferOnError,
    Deferrals:             &deferred,
}
var message rrc.ULDCCHMessage
if err := message.UnmarshalUPERWithOptions(wire, options); err != nil {
    return err
}
for _, record := range deferred.Snapshot() {
    log.Printf("%s: %v of %d bits kept raw: %v", record.Path, record.Kind,
        record.BitLength, record.Err)
}
```

`Path` is the field path from the top-level type, as for tolerance records.
`Err` is nil under `DeferAll`; under `DeferOnError` it carries the same full
path. For a value that is not nested in another contained value, it reads as
the error an Eager decode reports when that value is the first to fail.

A deferred value stays in place with its Go type: an OPTIONAL field stays
non-nil, a CHOICE keeps its alternative, and a mandatory field stays set. The
value is a shell, the zero value of its type, whose `PERPadding_` holds the
raw state. `PERPadding_.Deferred()` returns that state, or nil for any other
value, with `Kind()`, `Bytes()` (a copy), the exact `BitLength()` and
`Err()`. No field is added to any type, and an Eager decode allocates exactly
as before.

A deferred value is decoded later through the normal entry points. The
contents of an `OCTET STRING` are a complete encoding; those of a
`BIT STRING` are read from a buffer bounded to their bit length, and the bits
after the value go to the host's `<Field>PERPadding_`:

```go
// lte/rrc: an OCTET STRING (CONTAINING ...) OPTIONAL.
if ies.LateNonCriticalExtension != nil {
    if d := ies.LateNonCriticalExtension.PERPadding_.Deferred(); d != nil {
        var later rrc.RRCConnectionSetupCompleteV8x0IEs
        if err := later.UnmarshalUPERWithOptions(d.Bytes(), options); err != nil {
            return err
        }
        ies.LateNonCriticalExtension = &later
    }
}

// umts/rrc: a BIT STRING (CONTAINING ...) OPTIONAL.
if ext.UeCapabilityContainer != nil {
    if d := ext.UeCapabilityContainer.PERPadding_.Deferred(); d != nil {
        bb, err := d.BitBuffer(options)
        if err != nil {
            return err
        }
        var later umts.UECapabilityContainerIEs
        if err := later.UnmarshalUPERFrom(bb); err != nil {
            return err
        }
        padding, err := per.CaptureDeferredBits(bb, "UECapabilityContainerIEs")
        if err != nil {
            return err
        }
        ext.UeCapabilityContainer, ext.UeCapabilityContainerPERPadding_ = &later, padding
    }
}
```

An unchanged deferred value is encoded as its raw bits, so `MarshalUPER`
reproduces the input, padding included, and edits elsewhere leave it alone.

The edit check looks at the shell's state, not at assignments: every typed
field other than `PERPadding_` must still hold its zero value. A shell with a
nonzero typed field fails the encode with `per.ErrEditedDeferred` instead of
dropping either the edit or the raw bits. A zero value assigned to a field
(`shell.Level = 0`, a nil slice) leaves the shell indistinguishable from an
unedited one, so its raw bits are encoded again. Any intended replacement,
including one made of zero values, therefore takes an explicit step: assign a
new value to the field, or reset the shell with
`shell.PERPadding_ = per.FinalPadding{}`, which discards the raw bits so that
the shell's typed fields are encoded.

Placement is checked by container kind and encode entry point, not by field
identity. A value deferred from an `OCTET STRING` holds a complete encoding:
its own `MarshalUPER` returns those raw bytes wherever the value is, ordinary
value copies included, so a copy placed in another
`OCTET STRING (CONTAINING ...)` of the same type is encoded from them. A
value deferred from a `BIT STRING` is written as its exact raw bits by a
`BIT STRING (CONTAINING ...)` of the same type. Anywhere else the encode
fails with `per.ErrMisplacedDeferred`: in a component, list element or
alternative that is not a contained string (all of them encode through
`MarshalUPERTo`), an `OCTET STRING` value in a `BIT STRING`, and a
`BIT STRING` value in an `OCTET STRING` or passed to its own `MarshalUPER`.

JSON stays the semantic typed shape: a deferred value appears as its zero
shell, and its raw state is not in the document. JSON is therefore not a
wire-preserving format; the deferral log and `Deferred()` carry the raw
contents.

Deferral is UPER only. The APER packages take no decode options and decode
contained values eagerly; none of them has a contained value.

### Present empty values

An OPTIONAL component is absent when its Go value is nil. A present empty
`OCTET STRING`, `BIT STRING` or `SEQUENCE OF` decodes to a non-nil empty value
and is encoded again, in UPER, APER, BER and DER. JSON keeps the difference
too: an OPTIONAL slice-typed field is tagged `omitzero`, so an absent one is
omitted and a present empty one is written as `""` or `[]`. Pointer-typed
fields keep `omitempty`, which already omits only nil.

### Lone extension additions

In UPER and APER, an extension addition written on its own after the
extension marker, outside `[[ ]]`, is encoded as an open type holding the
component's own encoding, with no presence bitmap (ITU-T X.691 (02/2021)
§19.9). A bracketed group, even of one component, keeps its bitmap. Earlier
releases read and wrote a group bitmap inside the open type of a lone
addition, so its value was misread on decode: a present empty value came back
absent and other values were decoded from the wrong bits. Received encodings
still replayed byte-exactly, which hid the loss. These values now decode
correctly in the `lateNonCriticalExtension` of LTE RRC
`SystemInformationBlockType2` to `Type11` and
`SystemInformationBlockType26-r15`, in seven LPP types, in LPPa
`NPRSSubframePartB` and in S1AP `HOReport.candidatePCIList`. BER is not
affected, because each BER extension addition carries its own tag.

### DEFAULT components

In UPER and APER, a SEQUENCE or SET component marked `DEFAULT` is nil when
absent, like an OPTIONAL one. A new value leaves out a component of a simple type that
holds its default value, as ITU-T X.691 (02/2021) §19.5 requires: setting
LTE RRC `MeasObjectEUTRA.OffsetFreq` to `rrc.QOffsetRangeDB0` sends the same
octets as leaving it nil. Simple types are those that are not composite
(§3.7.25): INTEGER, ENUMERATED, BOOLEAN, BIT STRING, OCTET STRING, the
character strings, NULL, OBJECT IDENTIFIER and UTCTime. Equality follows the
abstract value. Trailing zero bits of a BIT STRING with named bits do not
count (X.680 (02/2021) §22.7), and a UTCTime is compared in the form PER
transmits (X.691 §10.6.5, X.690 §11.8). A component of a composite type, such
as a SEQUENCE, SEQUENCE OF or CHOICE, is sent whenever it is set, which §19.5
leaves to the sender. Inside an extension addition group the rule applies to
each component, and the group stays present while it holds a value (§19.9). A
lone extension addition that holds its default is left out.

This applies to 35 components in 31 LTE RRC types, 173 components in 90 UMTS
RRC types and 2 LPP components. S1AP, X2AP and LPPa have no DEFAULT
components. In APER, only a SEQUENCE or SET with such a component carries
its `PERPadding_` as the pointer-wide `per.FinalPadding`, to hold the record
described below. Other APER types keep the two-byte `per.CompletePadding`.

Decoders accept a DEFAULT component of a simple type that carries its
default value explicitly, as some senders do although §19.5 forbids it. The
rule for such a component is:
- a freshly built value always leaves it out while it holds its default
  (§19.5);
- an unchanged received value re-encodes exactly as received, including a
  non-conforming explicit default, so byte-exact replay holds. The decoded
  value records the explicit default in its `PERPadding_` for this;
- a component edited to another value is sent as it now is, and a component
  received with another value and then set to its default is left out.

Replaying the explicit default is a deliberate exception to §19.5, of the
same kind as the replay of nonzero padding and of a received extension
bitmap width. A composite DEFAULT component has no record: it is sent
whenever it is set. The record adds no field. Recording the first eight such
components of a type allocates nothing, and a record that includes a later
one allocates once; every LTE RRC and LPP type has at most three.

The record shares that `per.FinalPadding` with the final bits of a complete
encoding and with the raw state of a deferred contained value, and each is
kept alongside the others. A deferred value was not decoded, so it has no
record until it is decoded later. Resetting `PERPadding_` drops those three
records and nothing else. For a fresh encoding of a decoded value, also reset
its extension metadata (`ExtCount_`, `ExtPresent_`, `ExtData_`,
`PERExtPadding_`), in the value and in every value inside it. Otherwise a
lone extension addition received explicitly at its default leaves its
received, now empty, extension bitmap behind.

## Available Protocols

Protocols marked with **[compiled]** have generated Go code. Others have placeholder directories ready for future compilation.

### `telecom/` — Telecommunications

#### `telecom/lte/` — 3GPP LTE (4G)

| Package | Spec | Interface | Encoding | Status |
|---------|------|-----------|----------|--------|
| `lte/s1ap` | S1AP | S1 (eNB ↔ MME) | APER | **[compiled]** |
| `lte/x2ap` | X2AP | X2 (eNB ↔ eNB) | APER | **[compiled]** |
| `lte/rrc` | LTE-RRC | Uu (UE ↔ eNB) | UPER | **[compiled]** |
| `lte/m2ap` | M2AP | M2 (MCE ↔ eNB) | APER | planned |
| `lte/m3ap` | M3AP | M3 (MCE ↔ MME) | APER | planned |
| `lte/lpp` | LPP, 3GPP TS 37.355 V19.3.0 | LTE-Uu (UE ↔ E-SMLC) | UPER | **[compiled]** |
| `lte/lppa` | LPPa | SLs (eNB ↔ E-SMLC) | APER | **[compiled]** |
| `lte/lppe` | LPPe | LTE-Uu (UE ↔ location server) | — | planned |
| `lte/lcsap` | LCS-AP | SLg (MME ↔ E-SMLC) | APER | planned |
| `lte/sabp` | SABP | Iu-BC (RNC ↔ CBC) | APER | planned |
| `lte/sbc_ap` | SBc-AP | SBc (MME ↔ CBC) | APER | planned |
| `lte/pcap` | PCAP | Iupc (RNC ↔ SAS) | APER | planned |

In LTE RRC `LocationInfo-r10`, the location coordinates, horizontal velocity,
GNSS time of day, and vertical velocity fields carry LPP values as octets.
Their generated field comments name the matching `lte/lpp` type or constrained
integer decoder (3GPP TS 36.331 V19.4.0 §6.3.5; TS 37.355 V19.3.0 §6.4.1 for the
location and velocity types, §6.5.2.6 for `gnss-TOD-msec`).

LTE RRC is generated from the formal ASN.1 in the official 3GPP TS 36.331
V19.4.0 archive (`36331-j40.zip`).
S1AP and X2AP likewise use the official TS 36.413 V19.2.0 and TS 36.423
V19.1.0 archives (`36413-j20.zip` and `36423-j10.zip`).

#### `telecom/nr/` — 3GPP NR (5G)

| Package | Spec | Interface | Encoding | Status |
|---------|------|-----------|----------|--------|
| `nr/ngap` | NGAP | NG (gNB ↔ AMF) | APER | planned |
| `nr/xnap` | XnAP | Xn (gNB ↔ gNB) | APER | planned |
| `nr/e1ap` | E1AP | E1 (CU-CP ↔ CU-UP) | APER | planned |
| `nr/e2ap` | E2AP | E2 (near-RT RIC ↔ RAN) | APER | planned |
| `nr/f1ap` | F1AP | F1 (CU ↔ DU) | APER | planned |
| `nr/rrc` | NR-RRC | NR-Uu (UE ↔ gNB) | UPER | planned |
| `nr/nrppa` | NRPPa | NRPPa (gNB ↔ LMF) | APER | planned |
| `nr/kpm_v2` | KPM v2 | E2 (O-RAN KPM service) | — | planned |
| `nr/rc_v3` | RC v3 | E2 (O-RAN RC service) | — | planned |

#### `telecom/umts/` — 3GPP UMTS (3G)

| Package | Spec | Interface | Encoding | Status |
|---------|------|-----------|----------|--------|
| `umts/ranap` | RANAP | Iu (RNC ↔ CN) | APER | planned |
| `umts/rnsap` | RNSAP | Iur (RNC ↔ RNC) | APER | planned |
| `umts/rrc` | UMTS-RRC | Uu (UE ↔ Node B) | UPER | **[compiled]** |
| `umts/hnbap` | HNBAP | Iuh (HNB ↔ HNB-GW) | APER | planned |
| `umts/rua` | RUA | Iuh (HNB ↔ HNB-GW) | APER | planned |
| `umts/nbap` | NBAP | Iub (Node B ↔ RNC) | APER | planned |
| `umts/sabp` | SABP | Iu-BC (RNC ↔ CBC) | APER | planned |

Compiling `telecom/umts/rrc` needs about 4 GB in one Go compiler process.
On small CI runners, set `GOFLAGS=-p=2` or lower to limit concurrent builds.

#### `telecom/gsm/` — 2G

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `gsm/rrlp` | RRLP | Um (MS ↔ SMLC) | planned |

#### `telecom/ss7/` — SS7 / Intelligent Network

| Package | Spec | Interface | Encoding | Status |
|---------|------|-----------|----------|--------|
| `ss7/tcap` | TCAP | MTP3/SCCP (transaction layer) | BER | **[compiled]** |
| `ss7/ansi_tcap` | ANSI TCAP | MTP3/SCCP (ANSI variant) | BER | planned |
| `ss7/gsm_map` | GSM MAP | C/D/E/Gr (HLR/VLR/MSC) | BER | **[compiled]** |
| `ss7/camel` | CAMEL | gsmSSF ↔ gsmSCF | BER | planned |
| `ss7/inap` | INAP | SSF ↔ SCF (IN CS-1/CS-2) | BER | planned |
| `ss7/ain` | AIN | SSP ↔ SCP (N. America) | BER | planned |
| `ss7/charging_ase` | Charging ASE | CAP/MAP (charging extension) | BER | planned |
| `ss7/ros` | ROS | — (Remote Operations base) | BER | planned |
| `ss7/ansi_map` | ANSI MAP | A/B/D (IS-41 ANSI variant) | BER | planned |
| `ss7/isdn_sup` | ISDN supplementary | DSS1 (Q.931/Q.932) | BER | planned |
| `ss7/q932` | Q.932 | DSS1 (generic procedures) | BER | planned |
| `ss7/q932_ros` | Q.932 ROS | DSS1 (facility IE) | BER | planned |
| `ss7/qsig` | QSIG | QSIG (PBX ↔ PBX) | BER | planned |
| `ss7/lnpdqp` | LNPDQP | NPDB (number portability query) | BER | planned |

#### `telecom/esim/` — eSIM Provisioning

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `esim/sgp22` | SGP.22 | ES9+ (LPA ↔ SM-DP+) | **[compiled]** |
| `esim/sgp32` | SGP.32 | ES2+ (SM-DP+ ↔ SM-DS, IoT) | **[compiled]** |

#### `telecom/li/` — Lawful Interception

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `li/HI2Operations` | HI2 | HI2 (MF ↔ LEMF) | planned |
| `li/lix2` | LI-X2 | X2 (IRI-POI ↔ MF) | planned |

#### `telecom/charging/` — 3GPP Charging

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `charging/gprscdr` | GPRS CDR | Ga (CDF ↔ CGF) | planned |

#### `telecom/atn/` — Aeronautical Telecommunications

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `atn/atn_cm` | ATN Context Management | air-ground (aircraft ↔ ATC) | planned |
| `atn/atn_cpdlc` | ATN CPDLC | air-ground (pilot ↔ controller) | planned |
| `atn/atn_ulcs` | ATN Upper Layer | air-ground (ATN upper layer) | planned |

#### `telecom/tetra/` — TETRA

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `tetra/tetra` | TETRA | Um (MS ↔ SwMI) | planned |

### `security/` — Security & PKI

#### `security/x509/` — X.509 & Certificate Extensions

| Package | Spec | Status |
|---------|------|--------|
| `x509/x509af` | X.509 Authentication Framework | planned |
| `x509/x509ce` | X.509 Certificate Extensions | planned |
| `x509/x509if` | X.509 Information Framework | planned |
| `x509/x509sat` | X.509 Selected Attribute Types | planned |
| `x509/pkix1explicit` | PKIX1 Explicit | planned |
| `x509/pkix1implicit` | PKIX1 Implicit | planned |
| `x509/pkixac` | PKIX Attribute Certificate | planned |
| `x509/pkixalgs` | PKIX Algorithms | planned |
| `x509/pkixproxy` | PKIX Proxy Certificate | planned |
| `x509/pkixqualified` | PKIX Qualified Certificates | planned |
| `x509/pkixtsp` | PKIX Timestamp | planned |
| `x509/pkcs10` | PKCS#10 (CSR) | planned |
| `x509/pkcs12` | PKCS#12 (key store) | planned |
| `x509/ocsp` | OCSP | planned |
| `x509/logotypecertextn` | Logotype Certificate Ext | planned |
| `x509/wlancertextn` | WLAN Certificate Ext | planned |
| `x509/ns_cert_exts` | Netscape Certificate Ext | planned |
| `x509/cbrs_oids` | CBRS OIDs | planned |
| `x509/nist_csor` | NIST CSOR | planned |
| `x509/novell_pkis` | Novell PKIS | planned |
| `x509/tcg_cp_oids` | TCG CP OIDs | planned |

#### `security/cms/` — Cryptographic Message Syntax

| Package | Spec | Status |
|---------|------|--------|
| `cms/cms` | CMS (RFC 5652) | planned |
| `cms/ess` | ESS (RFC 2634) | planned |
| `cms/cmp` | CMP (RFC 9810) | planned |
| `cms/crmf` | CRMF (RFC 4211) | planned |

#### `security/auth/` — Authentication

| Package | Spec | Status |
|---------|------|--------|
| `auth/kerberos` | Kerberos (RFC 4120) | planned |
| `auth/pkinit` | PKINIT | planned |
| `auth/spnego` | SPNEGO | planned |
| `auth/credssp` | CredSSP | planned |

### `directory/` — X.500 / LDAP

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `directory/ldap` | LDAP | TCP/IP (client ↔ directory) | planned |
| `directory/dap` | DAP | DUA ↔ DSA | planned |
| `directory/dsp` | DSP | DSA ↔ DSA (chaining) | planned |
| `directory/disp` | DISP | DSA ↔ DSA (shadow replication) | planned |
| `directory/dop` | DOP | DSA ↔ DSA (operational binding) | planned |
| `directory/x721` | X.721 | manager ↔ agent (managed objects) | planned |

### `voip/` — Voice over IP (H.323 family)

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `voip/h225` | H.225 | RAS: EP ↔ GK; Q.931: EP ↔ EP | planned |
| `voip/h235` | H.235 | — (security framework for H.323) | planned |
| `voip/h245` | H.245 | EP ↔ EP (media control channel) | planned |
| `voip/h248` | H.248/Megaco | MGC ↔ MG (media gateway control) | planned |
| `voip/h282` | H.282 | FECC (far-end camera control) | planned |
| `voip/h283` | H.283 | LCT (logical channel transport) | planned |
| `voip/h323` | H.323 | — (umbrella signaling) | planned |
| `voip/h450` | H.450 | EP ↔ EP (supplementary services) | planned |
| `voip/h450_ros` | H.450 ROS | EP ↔ EP (remote operations) | planned |
| `voip/h460` | H.460 | EP ↔ GK (NAT/firewall traversal) | planned |
| `voip/h501` | H.501 | PE ↔ PE (address resolution) | planned |
| `voip/t124` | T.124 | GCC (conference control) | planned |
| `voip/t125` | T.125 | MCS (multipoint communication) | planned |
| `voip/t38` | T.38 | GW ↔ GW (fax over IP) | planned |

### `network/` — Network Management

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `network/snmp` | SNMP | manager ↔ agent (UDP/161) | planned |
| `network/cmip` | CMIP | manager ↔ agent (OSI stack) | planned |

### `messaging/` — X.400 Messaging

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `messaging/p1` | P1 | MTA ↔ MTA (message transfer) | planned |
| `messaging/p7` | P7 | UA ↔ MS (message store access) | planned |
| `messaging/p22` | P22 | UA ↔ UA (interpersonal messaging) | planned |
| `messaging/p772` | P772 | MMHS (military messaging) | planned |
| `messaging/smrse` | SMRSE | SMSC ↔ SMSC (SMS relay) | planned |

### `osi/` — OSI Protocols

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `osi/acse` | ACSE | — (association control, layer 7) | planned |
| `osi/pres` | Presentation Layer | — (OSI layer 6) | planned |
| `osi/rtse` | RTSE | — (reliable transfer, layer 7) | planned |
| `osi/ftam` | FTAM | — (file transfer, layer 7) | planned |

### `transport/` — Transport & Location

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `transport/ieee1609dot2` | IEEE 1609.2 | DSRC/C-V2X (V2X security) | planned |
| `transport/its` | ITS | ETSI ITS-G5 (vehicle ↔ infra) | planned |
| `transport/ulp` | ULP | SET ↔ SLP (SUPL user plane) | planned |
| `transport/ilp` | ILP | SPC ↔ SLC (SUPL internal) | planned |

### `energy/` — Power Grid (IEC 61850)

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `energy/goose` | GOOSE | IED ↔ IED (multicast events) | planned |
| `energy/sv` | Sampled Values | MU ↔ IED (multicast samples) | planned |
| `energy/mms` | MMS | client ↔ server (IEC 61850 MMS) | planned |

### `metering/` — Smart Metering

| Package | Spec | Interface | Status |
|---------|------|-----------|--------|
| `metering/cosem` | DLMS/COSEM | client ↔ meter (smart metering) | planned |

### `other/` — Miscellaneous

| Package | Spec | Status |
|---------|------|--------|
| `other/z3950` | Z39.50 (library search) | planned |
| `other/c1222` | C12.22 (metering) | planned |
| `other/cdt` | CDT | planned |
| `other/gdt` | GDT | planned |
| `other/glow` | Ember+ Glow | planned |
| `other/akp` | AKP | planned |
| `other/acp133` | ACP 133 (military dir) | planned |
| `other/idmp` | IDMP | planned |
| `other/mpeg_audio` | MPEG Audio | planned |
| `other/mpeg_pes` | MPEG PES | planned |
| `other/mudurl` | MUD URL | planned |
| `other/llc_v1` | LLC v1 | planned |

## Encoding Rules

| Encoding | Description | Used by |
|----------|-------------|---------|
| **APER** | Aligned PER | S1AP, X2AP, NGAP, RANAP, and most 3GPP signaling |
| **UPER** | Unaligned PER | LTE-RRC, NR-RRC, and radio interface protocols |
| **BER/DER** | Basic/Distinguished Encoding Rules | TCAP, MAP, CAMEL, X.509, LDAP, SNMP |
| **OER** | Octet Encoding Rules | Some ITS specs |

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for the
attribution of the third-party specifications from which the packages are generated.
