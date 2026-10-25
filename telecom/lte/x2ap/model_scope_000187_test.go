// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
)

func successfulOutcomefreshMust(value s19.SuccessfulOutcome, err error) s19.SuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return value
}
