// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
)

func successfulOutcomeapiMust(v s18.SuccessfulOutcome, err error) s18.SuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return v
}
