// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/source_rule.go; SHA-256 fd4005130abaf23673a72307afd89df6a70011d9a87cad28f7c7e927b33bd5be.
package aper

// SourceAssignment identifies one ASN.1 assignment in the pinned source.
type SourceAssignment struct {
	Module     string
	Assignment string
	Row        string
}

// SourceRule identifies the clause and source row for a generated rule.
// 3GPP TS 36.455 V19.0.0 §§9.3.3–9.3.5 define the LPPa class tables,
// and §10 adopts the abstract-syntax handling of TS 36.413 §10.
type SourceRule struct {
	Document     string
	Edition      string
	Clause       string
	CorrectionID string
	Assignment   SourceAssignment
}
