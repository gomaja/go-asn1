package validation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
	tcapber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// Synthetic Begin messages: one Invoke each.
var tcapFormInputs = []string{
	"620d4801016c08a10602010102012d",
	"620d4801026c08a10602010102012d",
}

// go-asn1 #195: one TrackTCAPForm slice shared between goroutines; run with -race.
func TestTCAPFormOptionsSharedAcrossGoroutines(t *testing.T) {
	opts := tcapber.TrackTCAPForm(nil)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for round := 0; round < 50; round++ {
				wire, err := hex.DecodeString(tcapFormInputs[(g+round)%2])
				if err != nil {
					errs <- err
					return
				}
				var m tcap.TCMessage
				if err := m.UnmarshalBER(wire, opts...); err != nil {
					errs <- err
					return
				}
				if out, err := m.MarshalBER(); err != nil || !bytes.Equal(out, wire) {
					errs <- errors.New("shared options changed the replay")
					return
				}
				if err := tcapber.ValidateBERElement(wire, opts...); err != nil {
					errs <- err
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
