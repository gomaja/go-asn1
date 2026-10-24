// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/source_rule.go; SHA-256 3bbd67a99833e9365d8102193d0fff3d13196d1cb8a019d65749abbd38f68679.
package aper

// SourceAssignment identifies one ASN.1 assignment in the pinned source.
type SourceAssignment struct {
	Module     string
	Assignment string
	Row        string
}

// SourceRule identifies the clause and source row for a generated rule.
// 3GPP TS 36.413 V19.2.0 §§9.3.2–9.3.4 define the S1AP class tables,
// and §10 defines abstract-syntax handling.
type SourceRule struct {
	Document     string
	Edition      string
	Clause       string
	CorrectionID string
	Assignment   SourceAssignment
}
