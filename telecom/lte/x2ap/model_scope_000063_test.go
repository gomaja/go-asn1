// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	s15 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	testing "testing"
)

func TestEveryChoiceTableSelector(t *testing.T) {
	t.Run("ProcedureStageChoice/ChoiceExtension", func(t *testing.T) {
		row := procedureStageChoiceExtIEFieldapiMust(s08.ProcedureStageChoiceExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s06.ProcedureStageChoice
		value.Choice = s00.ProcedureStageChoiceChoiceChoiceExtension
		value.ChoiceExtension = &row
		selected := value.ChoiceExtension
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s13.X2apInternalWalkValidationProcedureStageChoice(&value, &report, "ProcedureStageChoice", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("InitiatingNodeTypeEndcX2Setup/InitENB", func(t *testing.T) {
		row := eNBENDCX2SetupReqIEFieldapiMust(s17.ENBENDCX2SetupReqIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s18.InitiatingNodeTypeEndcX2Setup
		value.Choice = s00.InitiatingNodeTypeEndcX2SetupChoiceInitENB
		value.InitENB = append(value.InitENB, row)
		selected := &value.InitENB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s18.X2apInternalWalkValidationInitiatingNodeTypeEndcX2Setup(&value, &report, "InitiatingNodeTypeEndcX2Setup", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("InitiatingNodeTypeEndcX2Setup/InitEnGNB", func(t *testing.T) {
		row := enGNBENDCX2SetupReqIEFieldapiMust(s18.EnGNBENDCX2SetupReqIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s18.InitiatingNodeTypeEndcX2Setup
		value.Choice = s00.InitiatingNodeTypeEndcX2SetupChoiceInitEnGNB
		value.InitEnGNB = append(value.InitEnGNB, row)
		selected := &value.InitEnGNB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s18.X2apInternalWalkValidationInitiatingNodeTypeEndcX2Setup(&value, &report, "InitiatingNodeTypeEndcX2Setup", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("RespondingNodeTypeEndcX2Setup/RespondENB", func(t *testing.T) {
		row := eNBENDCX2SetupReqAckIEFieldapiMust(s17.ENBENDCX2SetupReqAckIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s18.RespondingNodeTypeEndcX2Setup
		value.Choice = s00.RespondingNodeTypeEndcX2SetupChoiceRespondENB
		value.RespondENB = append(value.RespondENB, row)
		selected := &value.RespondENB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s18.X2apInternalWalkValidationRespondingNodeTypeEndcX2Setup(&value, &report, "RespondingNodeTypeEndcX2Setup", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("RespondingNodeTypeEndcX2Setup/RespondEnGNB", func(t *testing.T) {
		row := enGNBENDCX2SetupReqAckIEFieldapiMust(s18.EnGNBENDCX2SetupReqAckIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s18.RespondingNodeTypeEndcX2Setup
		value.Choice = s00.RespondingNodeTypeEndcX2SetupChoiceRespondEnGNB
		value.RespondEnGNB = append(value.RespondEnGNB, row)
		selected := &value.RespondEnGNB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s18.X2apInternalWalkValidationRespondingNodeTypeEndcX2Setup(&value, &report, "RespondingNodeTypeEndcX2Setup", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("InitiatingNodeTypeEndcConfigUpdate/InitENB", func(t *testing.T) {
		row := eNBENDCConfigUpdateIEFieldapiMust(s17.ENBENDCConfigUpdateIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s18.InitiatingNodeTypeEndcConfigUpdate
		value.Choice = s00.InitiatingNodeTypeEndcConfigUpdateChoiceInitENB
		value.InitENB = append(value.InitENB, row)
		selected := &value.InitENB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s18.X2apInternalWalkValidationInitiatingNodeTypeEndcConfigUpdate(&value, &report, "InitiatingNodeTypeEndcConfigUpdate", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("InitiatingNodeTypeEndcConfigUpdate/InitEnGNB", func(t *testing.T) {
		row := enGNBENDCConfigUpdateIEFieldapiMust(s18.EnGNBENDCConfigUpdateIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s18.InitiatingNodeTypeEndcConfigUpdate
		value.Choice = s00.InitiatingNodeTypeEndcConfigUpdateChoiceInitEnGNB
		value.InitEnGNB = append(value.InitEnGNB, row)
		selected := &value.InitEnGNB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s18.X2apInternalWalkValidationInitiatingNodeTypeEndcConfigUpdate(&value, &report, "InitiatingNodeTypeEndcConfigUpdate", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("RespondingNodeTypeEndcConfigUpdate/RespondENB", func(t *testing.T) {
		row := eNBENDCConfigUpdateAckIEFieldapiMust(s06.ENBENDCConfigUpdateAckIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s18.RespondingNodeTypeEndcConfigUpdate
		value.Choice = s00.RespondingNodeTypeEndcConfigUpdateChoiceRespondENB
		value.RespondENB = append(value.RespondENB, row)
		selected := &value.RespondENB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s18.X2apInternalWalkValidationRespondingNodeTypeEndcConfigUpdate(&value, &report, "RespondingNodeTypeEndcConfigUpdate", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("RespondingNodeTypeEndcConfigUpdate/RespondEnGNB", func(t *testing.T) {
		row := enGNBENDCConfigUpdateAckIEFieldapiMust(s18.EnGNBENDCConfigUpdateAckIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s18.RespondingNodeTypeEndcConfigUpdate
		value.Choice = s00.RespondingNodeTypeEndcConfigUpdateChoiceRespondEnGNB
		value.RespondEnGNB = append(value.RespondEnGNB, row)
		selected := &value.RespondEnGNB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s18.X2apInternalWalkValidationRespondingNodeTypeEndcConfigUpdate(&value, &report, "RespondingNodeTypeEndcConfigUpdate", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("InitiatingNodeTypeEutranrCellResourceCoordination/InitiateENB", func(t *testing.T) {
		row := eNBEUTRANRCellResourceCoordinationReqIEFieldapiMust(s15.ENBEUTRANRCellResourceCoordinationReqIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s15.InitiatingNodeTypeEutranrCellResourceCoordination
		value.Choice = s00.InitiatingNodeTypeEutranrCellResourceCoordinationChoiceInitiateENB
		value.InitiateENB = append(value.InitiateENB, row)
		selected := &value.InitiateENB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s16.X2apInternalWalkValidationInitiatingNodeTypeEutranrCellResourceCoordination(&value, &report, "InitiatingNodeTypeEutranrCellResourceCoordination", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("InitiatingNodeTypeEutranrCellResourceCoordination/InitiateEnGNB", func(t *testing.T) {
		row := enGNBEUTRANRCellResourceCoordinationReqIEFieldapiMust(s15.EnGNBEUTRANRCellResourceCoordinationReqIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s15.InitiatingNodeTypeEutranrCellResourceCoordination
		value.Choice = s00.InitiatingNodeTypeEutranrCellResourceCoordinationChoiceInitiateEnGNB
		value.InitiateEnGNB = append(value.InitiateEnGNB, row)
		selected := &value.InitiateEnGNB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s16.X2apInternalWalkValidationInitiatingNodeTypeEutranrCellResourceCoordination(&value, &report, "InitiatingNodeTypeEutranrCellResourceCoordination", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("RespondingNodeTypeEutranrCellResourceCoordination/RespondENB", func(t *testing.T) {
		row := eNBEUTRANRCellResourceCoordinationReqAckIEFieldapiMust(s15.ENBEUTRANRCellResourceCoordinationReqAckIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s16.RespondingNodeTypeEutranrCellResourceCoordination
		value.Choice = s00.RespondingNodeTypeEutranrCellResourceCoordinationChoiceRespondENB
		value.RespondENB = append(value.RespondENB, row)
		selected := &value.RespondENB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s16.X2apInternalWalkValidationRespondingNodeTypeEutranrCellResourceCoordination(&value, &report, "RespondingNodeTypeEutranrCellResourceCoordination", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("RespondingNodeTypeEutranrCellResourceCoordination/RespondEnGNB", func(t *testing.T) {
		row := enGNBEUTRANRCellResourceCoordinationReqAckIEFieldapiMust(s16.EnGNBEUTRANRCellResourceCoordinationReqAckIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s16.RespondingNodeTypeEutranrCellResourceCoordination
		value.Choice = s00.RespondingNodeTypeEutranrCellResourceCoordinationChoiceRespondEnGNB
		value.RespondEnGNB = append(value.RespondEnGNB, row)
		selected := &value.RespondEnGNB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s16.X2apInternalWalkValidationRespondingNodeTypeEutranrCellResourceCoordination(&value, &report, "RespondingNodeTypeEutranrCellResourceCoordination", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("InitiatingNodeTypeEndcX2Removal/InitENB", func(t *testing.T) {
		row := eNBENDCX2RemovalReqIEFieldapiMust(s06.ENBENDCX2RemovalReqIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s07.InitiatingNodeTypeEndcX2Removal
		value.Choice = s00.InitiatingNodeTypeEndcX2RemovalChoiceInitENB
		value.InitENB = append(value.InitENB, row)
		selected := &value.InitENB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s13.X2apInternalWalkValidationInitiatingNodeTypeEndcX2Removal(&value, &report, "InitiatingNodeTypeEndcX2Removal", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("InitiatingNodeTypeEndcX2Removal/InitEnGNB", func(t *testing.T) {
		row := enGNBENDCX2RemovalReqIEFieldapiMust(s07.EnGNBENDCX2RemovalReqIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s07.InitiatingNodeTypeEndcX2Removal
		value.Choice = s00.InitiatingNodeTypeEndcX2RemovalChoiceInitEnGNB
		value.InitEnGNB = append(value.InitEnGNB, row)
		selected := &value.InitEnGNB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s13.X2apInternalWalkValidationInitiatingNodeTypeEndcX2Removal(&value, &report, "InitiatingNodeTypeEndcX2Removal", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("RespondingNodeTypeEndcX2Removal/RespondENB", func(t *testing.T) {
		row := eNBENDCX2RemovalReqAckIEFieldapiMust(s06.ENBENDCX2RemovalReqAckIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s07.RespondingNodeTypeEndcX2Removal
		value.Choice = s00.RespondingNodeTypeEndcX2RemovalChoiceRespondENB
		value.RespondENB = append(value.RespondENB, row)
		selected := &value.RespondENB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s13.X2apInternalWalkValidationRespondingNodeTypeEndcX2Removal(&value, &report, "RespondingNodeTypeEndcX2Removal", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("RespondingNodeTypeEndcX2Removal/RespondEnGNB", func(t *testing.T) {
		row := enGNBENDCX2RemovalReqAckIEFieldapiMust(s07.EnGNBENDCX2RemovalReqAckIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s07.RespondingNodeTypeEndcX2Removal
		value.Choice = s00.RespondingNodeTypeEndcX2RemovalChoiceRespondEnGNB
		value.RespondEnGNB = append(value.RespondEnGNB, row)
		selected := &value.RespondEnGNB[0]
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s13.X2apInternalWalkValidationRespondingNodeTypeEndcX2Removal(&value, &report, "RespondingNodeTypeEndcX2Removal", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("GlobalRANNODEID/ChoiceExtension", func(t *testing.T) {
		row := globalRANNODEIDExtIEFieldapiMust(s08.GlobalRANNODEIDExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s05.GlobalRANNODEID
		value.Choice = s00.GlobalRANNODEIDChoiceChoiceExtension
		value.ChoiceExtension = &row
		selected := value.ChoiceExtension
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s13.X2apInternalWalkValidationGlobalRANNODEID(&value, &report, "GlobalRANNODEID", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("SensorNameConfig/ChoiceExtension", func(t *testing.T) {
		row := sensorNameConfigExtIEFieldapiMust(s08.SensorNameConfigExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s05.SensorNameConfig
		value.Choice = s00.SensorNameConfigChoiceChoiceExtension
		value.ChoiceExtension = &row
		selected := value.ChoiceExtension
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s13.X2apInternalWalkValidationSensorNameConfig(&value, &report, "SensorNameConfig", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
	t.Run("SSBPositionsInBurst/ChoiceExtension", func(t *testing.T) {
		row := sSBPositionsInBurstExtIEFieldapiMust(s08.SSBPositionsInBurstExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
		var value s05.SSBPositionsInBurst
		value.Choice = s00.SSBPositionsInBurstChoiceChoiceExtension
		value.ChoiceExtension = &row
		selected := value.ChoiceExtension
		if _, err := value.MarshalAPER(); err != nil {
			t.Fatal(err)
		}
		selected.Id--
		_, err := value.MarshalAPER()
		apiRefused(t, err)
		report := s12.ValidationReport{Complete: true}
		s13.X2apInternalWalkValidationSSBPositionsInBurst(&value, &report, "SSBPositionsInBurst", false)
		apiHas(t, report, s00.ValueIDMismatch)
	})
}
