// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/form_options_concurrency_test.go; SHA-256 0b32b73dba547b881c87f3cfe8cba034596e1efb29a0d86ca78a9ee041f0538f.
package ber

import (
	"sync"
	"testing"
)

func TestFormOptionsConcurrentRootDecodes(t *testing.T) {
	for _, track := range []func([]DecodeOption) []DecodeOption{TrackBERForm, TrackMAPForm} {
		options := track(nil)
		var wg sync.WaitGroup
		failures := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Go(func() {
				for range 3 {
					if err := decodeReuseRoot([]byte{0x30, 3, 2, 1, 1}, options, true); err != nil {
						failures <- err
						return
					}
				}
			})
		}
		wg.Wait()
		close(failures)
		for err := range failures {
			t.Error(err)
		}
	}
}
