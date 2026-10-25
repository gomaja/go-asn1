// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
)

func causeapiMust(v s00.Cause, err error) s00.Cause {
	if err != nil {
		panic(err)
	}
	return v
}
