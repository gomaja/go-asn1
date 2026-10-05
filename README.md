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
returns independent records. Tolerance cannot represent a negative BER
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
bytes: REAL values take their distinguished form and SET components are
sorted (ITU-T X.690 (02/2021) §8.5.7 NOTE 1, §§10.3, 11.3.1). Its open-type
contents are emitted as carried, and it does not yet omit components equal to
their `DEFAULT` ([go-asn1#85](https://github.com/gomaja/go-asn1/issues/85)).
An unchanged valid BER REAL whose normalized exponent cannot fit the 255-octet
encoding limit can still be re-encoded as BER; `MarshalDER` returns
`ber.ErrInvalidValue` (X.690 §§8.5.7.4, 11.3.1).

Constraint tolerance does not admit invalid encodings. Both modes reject:

- INTEGER and ENUMERATED encodings with redundant sign octets, including
  under implicit tags, with `ber.ErrInvalidValue` (X.690 §§8.3.2, 8.4);
- a constructed NULL, including under an implicit tag (X.690 §8.8.1);
- any component encoding inside a non-extensible SEQUENCE or SET that has no
  components, with a `*ber.DecodeError` naming the type and wrapping
  `ber.ErrExtraData` (X.690 §§8.9.2, 8.11.2). Extensible empty types keep
  their extensions.

GeneralizedTime encoding retains sub-second precision and omits trailing
fractional zeros (ITU-T X.690 (02/2021) §11.7.3). This changes the output for
values with fractional seconds: they previously encoded at whole-second
precision. Certificate profiles governed by RFC 5280 §4.1.2.5.2 forbid
fractional seconds, so callers building certificates must first use
`t.Truncate(time.Second)` on those time values. The typed time decoders do not
yet accept UTCTime with minute precision and a UTC offset, or GeneralizedTime
with a fractional hour (X.680 (02/2021) §§46.3, 47.3); this is tracked in
[go-asn1#86](https://github.com/gomaja/go-asn1/issues/86).

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
`PEROpenTypePadding_`) of the value and of every value inside it, or build
the value anew.

### Present empty values

An OPTIONAL component is absent when its Go value is nil. A present empty
`OCTET STRING`, `BIT STRING` or `SEQUENCE OF` decodes to a non-nil empty value
and is encoded again, in UPER, APER, BER and DER. JSON keeps the difference
too: an OPTIONAL slice-typed field is tagged `omitzero`, so an absent one is
omitted and a present empty one is written as `""` or `[]`. Pointer-typed
fields keep `omitempty`, which already omits only nil.

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
