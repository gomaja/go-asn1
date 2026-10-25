// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
)

func errorIndicationapiMust(v s20.ErrorIndication, err error) s20.ErrorIndication {
	if err != nil {
		panic(err)
	}
	return v
}
