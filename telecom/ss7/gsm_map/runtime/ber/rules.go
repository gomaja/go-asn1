// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/rules.go; SHA-256 355b2a0222933d8b4bcc618c1a37d2948a170213d68ebb1e25bc16ceec9e0848.
package ber

// ruleOption carries the rule selected by the source generator. It does not
// enable tolerance or change validation, received-form or resource policy.
type ruleOption struct {
	source string
	rule   RuleRef
}

func (option ruleOption) applyDecode(config *decodeConfig) error {
	config.rule = option.rule
	config.ruleSource = option.source
	return nil
}
func (option ruleOption) applyEncode(config *encodeConfig) error {
	config.rule = option.rule
	config.source = option.source
	return nil
}

// DecodeRule identifies a source constraint at its generated check. Rules are
// metadata, never inferred from received values or diagnostic text.
func DecodeRule(options []DecodeOption, source string, rule RuleRef) []DecodeOption {
	return append(options[:len(options):len(options)], ruleOption{source, rule})
}

// EncodeRule identifies the source of a fresh-value constraint failure.
func EncodeRule(options []EncodeOption, source string, rule RuleRef) []EncodeOption {
	return append(options[:len(options):len(options)], ruleOption{source, rule})
}
