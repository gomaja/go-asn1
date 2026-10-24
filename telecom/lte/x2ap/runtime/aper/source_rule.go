// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/source_rule.go; SHA-256 b0026cc49d95a62c0aadb22ac0819483a4ce287842c093e0baf804cfc6810042.
package aper

// SourceAssignment identifies one ASN.1 assignment in the pinned source.
type SourceAssignment struct {
	Module     string
	Assignment string
	Row        string
}

// SourceRule identifies the clause and source row for a generated rule.
// 3GPP TS 36.423 V19.1.0 §§9.3.3–9.3.5 define the X2AP class tables,
// and §10 adopts the abstract-syntax handling of TS 36.413 §10.
type SourceRule struct {
	Document     string
	Edition      string
	Clause       string
	CorrectionID string
	Assignment   SourceAssignment
}
