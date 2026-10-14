package ber

import "testing"

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
