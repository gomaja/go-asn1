// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/option_resolution_fast_path_test.go; SHA-256 b7b53600526bf54be4045f148208905200876c08830f2b39640de00642bac3a2.
package ber

import (
	"testing"
)

var (
	resolvedDecodeConfigSink decodeConfig
	resolvedEncodeConfigSink encodeConfig
)

// Generated codecs resolve the same built-in path and form options for every
// nested element. This catches a heap allocation in that common case.
func TestBuiltInOptionResolutionDoesNotAllocate(t *testing.T) {
	form := new(berFormState)
	decode := []DecodeOption{berFormOption{state: form}, constraintPathOption("child"), parentCollectionSizeOption{}}
	encode := []EncodeOption{constraintPathOption("child"), withoutBERReplayOption{}, parentCollectionSizeOption{}}
	if got := testing.AllocsPerRun(1000, func() {
		config, err := decodeOptions(decode)
		if err != nil {
			panic(err)
		}
		resolvedDecodeConfigSink = config
	}); got != 0 {
		t.Errorf("decode options allocated %.1f times", got)
	}
	if got := testing.AllocsPerRun(1000, func() {
		config, err := encodeOptions(encode)
		if err != nil {
			panic(err)
		}
		resolvedEncodeConfigSink = config
	}); got != 0 {
		t.Errorf("encode options allocated %.1f times", got)
	}
}
