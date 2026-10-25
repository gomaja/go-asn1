// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
)

func successfulOutcomeapiMust(v s19.SuccessfulOutcome, err error) s19.SuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return v
}
