// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
)

func replayBoundMakeOps(r replayBoundInput, raw []byte) (replayBoundOps, []byte) {
	switch r.Set {
	case "HandoverRequest-IEs":
		if r.Selector == 15 {
			return uEHistoryInformationreplayBoundCodecOps(s18.HandoverRequestIEs().UEHistoryInformation().Codec(), raw), raw
		}
		return uEX2APIDreplayBoundCodecOps(s18.HandoverRequestIEs().OldENBUEX2APID().Codec(), raw), raw
	case "E-RABs-ToBeSetup-ItemIEs":
		wire := replayBoundWrap(raw, r.Selector)
		return eRABsToBeSetupItemIEFieldreplayBoundCodecOps(eRABsToBeSetupItemIEValuereplayBoundFieldCodec(), wire), wire
	case "E-RABs-Admitted-Item-ExtIEs":
		if r.Selector == 366 {
			return dAPSResponseInforeplayBoundCodecOps(s06.ERABsAdmittedItemExtIEs().DAPSResponseInfo().Codec(), raw), raw
		}
		wire := replayBoundWrap(raw, r.Selector)
		return eRABsAdmittedItemExtIEsExtFieldreplayBoundCodecOps(eRABsAdmittedItemExtIEsValuereplayBoundExtensionFieldCodec(), wire), wire
	}
	switch r.Type {
	case "X2APPDU":
		var v s20.X2APPDU
		_, _ = v.UnmarshalAPER(raw)
		return replayBoundOps{decode: func() error { var v s20.X2APPDU; _, err := v.UnmarshalAPER(raw); return err }, encode: func() ([]byte, error) { return v.MarshalAPER() }}, raw
	case "ProtocolIEField":
		return errorIndicationIEFieldreplayBoundCodecOps(errorIndicationIEValuereplayBoundFieldCodec(), raw), raw
	case "GlobalGNBID":
		return globalGNBIDreplayBoundCodecOps(s11.GlobalGNBIDCodec(), raw), raw
	case "ERABsToBeSetupItem":
		return eRABsToBeSetupItemreplayBoundCodecOps(s11.ERABsToBeSetupItemCodec(), raw), raw
	case "ERABsAdmittedItem":
		return eRABsAdmittedItemreplayBoundCodecOps(s09.ERABsAdmittedItemCodec(), raw), raw
	case "AccessAndMobilityIndication":
		return accessAndMobilityIndicationreplayBoundCodecOps(s20.AccessAndMobilityIndicationCodec(), raw), raw
	case "SuccessfulOutcome":
		return successfulOutcomereplayBoundCodecOps(s19.SuccessfulOutcomeCodec(), raw), raw
	}
	panic(r.Type)
}
