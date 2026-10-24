package lppa

import (
	"bufio"
	"bytes"
	"encoding/hex"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"math/big"
	"os"
	"strings"
	"testing"
)

// Each body is freshly assembled through its source table bindings and
// checked constructors. The golden encodings are independently produced by
// pycrate from the locked TS 36.455 V19.0.0 ASN.1 (§§9.3.3–9.3.5).
func TestFreshConstructionAllProcedureBodies(t *testing.T) {
	file, err := os.Open("testdata/fresh_body_oracle.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	golden := make(map[string][]byte)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			t.Fatalf("bad oracle row: %q", line)
		}
		wire, err := hex.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		golden[parts[0]] = wire
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	type item struct {
		name string
		pdu  LPPAPDU
	}
	var cases []item
	add := func(name string, pdu LPPAPDU) { cases = append(cases, item{name, pdu}) }
	id1 := func() *big.Int { return big.NewInt(1) }
	id2 := func() *big.Int { return big.NewInt(2) }
	cause := func() Cause { return causeFreshMust(NewCauseRadioNetwork(CauseRadioNetworkUnspecified)) }
	measurementResult := func() ECIDMeasurementResult {
		return ECIDMeasurementResult{ServingCellID: ECGI{PLMNIdentity: []byte{0, 0, 0}, EUTRANcellIdentifier: runtime.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 28}}, ServingCellTAC: []byte{0, 0}}
	}

	add("errorIndication.initiating", errorIndicationFreshInitiating(t, ErrorIndicationProcedure().Initiating(), errorIndicationFreshMust(NewErrorIndication(nil))))
	{
		id := privateIEIDFreshMust(NewPrivateIEIDLocal(1))
		field := privateMessageIEsValuePrivateIEFieldFreshMust(PrivateMessageIEs().NewOpaque(id, CriticalityIgnore, []byte{0x00}))
		add("privateMessage.initiating", privateMessageFreshInitiating(t, PrivateMessageProcedure().Initiating(), privateMessageFreshMust(NewPrivateMessage(PrivateMessageIEsValuePrivateIEContainer{field}))))
	}
	{
		table := ECIDMeasurementInitiationRequestIEs()
		inner := measurementQuantitiesItemIEFieldFreshMust(MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().New(MeasurementQuantitiesItem{MeasurementQuantitiesValue: MeasurementQuantitiesValueCellID}))
		body := eCIDMeasurementInitiationRequestFreshMust(NewECIDMeasurementInitiationRequest(ECIDMeasurementInitiationRequestIEContainer{eCIDMeasurementInitiationRequestIEFieldFreshMust(table.ESMLCUEMeasurementID().New(id1())), eCIDMeasurementInitiationRequestIEFieldFreshMust(table.ReportCharacteristics().New(ReportCharacteristicsOnDemand)), eCIDMeasurementInitiationRequestIEFieldFreshMust(table.MeasurementQuantities().New(MeasurementQuantities{inner}))}))
		add("ecidInitiation.initiating", eCIDMeasurementInitiationRequestFreshInitiating(t, ECIDMeasurementInitiationProcedure().Initiating(), body))
	}
	{
		table := ECIDMeasurementInitiationResponseIEs()
		body := eCIDMeasurementInitiationResponseFreshMust(NewECIDMeasurementInitiationResponse(ECIDMeasurementInitiationResponseIEContainer{eCIDMeasurementInitiationResponseIEFieldFreshMust(table.ESMLCUEMeasurementID().New(id1())), eCIDMeasurementInitiationResponseIEFieldFreshMust(table.ENBUEMeasurementID().New(id2()))}))
		add("ecidInitiation.successful", eCIDMeasurementInitiationResponseFreshSuccessful(t, ECIDMeasurementInitiationProcedure().Successful(), body))
	}
	{
		table := ECIDMeasurementInitiationFailureIEs()
		body := eCIDMeasurementInitiationFailureFreshMust(NewECIDMeasurementInitiationFailure(ECIDMeasurementInitiationFailureIEContainer{eCIDMeasurementInitiationFailureIEFieldFreshMust(table.ESMLCUEMeasurementID().New(id1())), eCIDMeasurementInitiationFailureIEFieldFreshMust(table.Cause().New(cause()))}))
		add("ecidInitiation.unsuccessful", eCIDMeasurementInitiationFailureFreshUnsuccessful(t, ECIDMeasurementInitiationProcedure().Unsuccessful(), body))
	}
	{
		table := ECIDMeasurementFailureIndicationIEs()
		body := eCIDMeasurementFailureIndicationFreshMust(NewECIDMeasurementFailureIndication(ECIDMeasurementFailureIndicationIEContainer{eCIDMeasurementFailureIndicationIEFieldFreshMust(table.ESMLCUEMeasurementID().New(id1())), eCIDMeasurementFailureIndicationIEFieldFreshMust(table.ENBUEMeasurementID().New(id2())), eCIDMeasurementFailureIndicationIEFieldFreshMust(table.Cause().New(cause()))}))
		add("ecidFailure.initiating", eCIDMeasurementFailureIndicationFreshInitiating(t, ECIDMeasurementFailureIndicationProcedure().Initiating(), body))
	}
	{
		table := ECIDMeasurementReportIEs()
		body := eCIDMeasurementReportFreshMust(NewECIDMeasurementReport(ECIDMeasurementReportIEContainer{eCIDMeasurementReportIEFieldFreshMust(table.ESMLCUEMeasurementID().New(id1())), eCIDMeasurementReportIEFieldFreshMust(table.ENBUEMeasurementID().New(id2())), eCIDMeasurementReportIEFieldFreshMust(table.ECIDMeasurementResult().New(measurementResult()))}))
		add("ecidReport.initiating", eCIDMeasurementReportFreshInitiating(t, ECIDMeasurementReportProcedure().Initiating(), body))
	}
	{
		table := ECIDMeasurementTerminationCommandIEs()
		body := eCIDMeasurementTerminationCommandFreshMust(NewECIDMeasurementTerminationCommand(ECIDMeasurementTerminationCommandIEContainer{eCIDMeasurementTerminationCommandIEFieldFreshMust(table.ESMLCUEMeasurementID().New(id1())), eCIDMeasurementTerminationCommandIEFieldFreshMust(table.ENBUEMeasurementID().New(id2()))}))
		add("ecidTermination.initiating", eCIDMeasurementTerminationCommandFreshInitiating(t, ECIDMeasurementTerminationProcedure().Initiating(), body))
	}
	{
		inner := oTDOAInformationTypeIEFieldFreshMust(OTDOAInformationTypeIEs().OTDOAInformationTypeItem().New(OTDOAInformationTypeItem{OTDOAInformationTypeItem: OTDOAInformationItemPci}))
		table := OTDOAInformationRequestIEs()
		body := oTDOAInformationRequestFreshMust(NewOTDOAInformationRequest(OTDOAInformationRequestIEContainer{oTDOAInformationRequestIEFieldFreshMust(table.OTDOAInformationTypeGroup().New(OTDOAInformationType{inner}))}))
		add("otdoaExchange.initiating", oTDOAInformationRequestFreshInitiating(t, OTDOAInformationExchangeProcedure().Initiating(), body))
	}
	{
		cell := oTDOACellInformationItemFreshMust(NewOTDOACellInformationItemPCI(big.NewInt(0)))
		value := OTDOACells{OTDOACellsElem{OTDOACellInfo: OTDOACellInformation{cell}}}
		table := OTDOAInformationResponseIEs()
		body := oTDOAInformationResponseFreshMust(NewOTDOAInformationResponse(OTDOAInformationResponseIEContainer{oTDOAInformationResponseIEFieldFreshMust(table.OTDOACells().New(value))}))
		add("otdoaExchange.successful", oTDOAInformationResponseFreshSuccessful(t, OTDOAInformationExchangeProcedure().Successful(), body))
	}
	{
		table := OTDOAInformationFailureIEs()
		body := oTDOAInformationFailureFreshMust(NewOTDOAInformationFailure(OTDOAInformationFailureIEContainer{oTDOAInformationFailureIEFieldFreshMust(table.Cause().New(cause()))}))
		add("otdoaExchange.unsuccessful", oTDOAInformationFailureFreshUnsuccessful(t, OTDOAInformationExchangeProcedure().Unsuccessful(), body))
	}
	add("utdoaExchange.initiating", uTDOAInformationRequestFreshInitiating(t, UTDOAInformationExchangeProcedure().Initiating(), uTDOAInformationRequestFreshMust(NewUTDOAInformationRequest(nil))))
	{
		srs := SRSConfigurationForOneCell{Pci: big.NewInt(0), UlEarfcn: big.NewInt(0), SfnInitialisationTime: runtime.BitString{Bytes: make([]byte, 8), BitLength: 64}}
		value := ULConfiguration{Pci: big.NewInt(0), UlEarfcn: big.NewInt(0), NumberOfTransmissions: big.NewInt(0), SrsConfiguration: SRSConfigurationForAllCells{srs}}
		table := UTDOAInformationResponseIEs()
		body := uTDOAInformationResponseFreshMust(NewUTDOAInformationResponse(UTDOAInformationResponseIEContainer{uTDOAInformationResponseIEFieldFreshMust(table.ULConfiguration().New(value))}))
		add("utdoaExchange.successful", uTDOAInformationResponseFreshSuccessful(t, UTDOAInformationExchangeProcedure().Successful(), body))
	}
	{
		table := UTDOAInformationFailureIEs()
		body := uTDOAInformationFailureFreshMust(NewUTDOAInformationFailure(UTDOAInformationFailureIEContainer{uTDOAInformationFailureIEFieldFreshMust(table.Cause().New(cause()))}))
		add("utdoaExchange.unsuccessful", uTDOAInformationFailureFreshUnsuccessful(t, UTDOAInformationExchangeProcedure().Unsuccessful(), body))
	}
	add("utdoaUpdate.initiating", uTDOAInformationUpdateFreshInitiating(t, UTDOAInformationUpdateProcedure().Initiating(), uTDOAInformationUpdateFreshMust(NewUTDOAInformationUpdate(nil))))
	add("assistanceControl.initiating", assistanceInformationControlFreshInitiating(t, AssistanceInformationControlProcedure().Initiating(), assistanceInformationControlFreshMust(NewAssistanceInformationControl(nil))))
	add("assistanceFeedback.initiating", assistanceInformationFeedbackFreshInitiating(t, AssistanceInformationFeedbackProcedure().Initiating(), assistanceInformationFeedbackFreshMust(NewAssistanceInformationFeedback(nil))))
	if len(cases) != 17 || len(golden) != 17 {
		t.Fatalf("fresh body count = %d, oracle count = %d", len(cases), len(golden))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := ValidateMessage(&tc.pdu)
			if err != nil || len(report.Issues) != 0 {
				t.Fatalf("validation = %+v, %v", report, err)
			}
			wire, err := tc.pdu.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			want, ok := golden[tc.name]
			if !ok {
				t.Fatalf("missing oracle for %s", tc.name)
			}
			if !bytes.Equal(wire, want) {
				t.Fatalf("wire = %x, pycrate oracle = %x", wire, want)
			}
		})
	}
}
