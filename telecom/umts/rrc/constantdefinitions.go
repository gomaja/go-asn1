// Code generated from ASN.1 module "Constant-definitions". DO NOT EDIT.

package rrc

import (
	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = per.NewBitBuffer
)

const (

	// HiPDSCHidentities is the integer constant for hiPDSCHidentities.
	HiPDSCHidentities int64 = 64

	// HiPUSCHidentities is the integer constant for hiPUSCHidentities.
	HiPUSCHidentities int64 = 64

	// HiRM is the integer constant for hiRM.
	HiRM int64 = 256

	// MaxAC is the integer constant for maxAC.
	MaxAC int64 = 16

	// MaxAdditionalMeas is the integer constant for maxAdditionalMeas.
	MaxAdditionalMeas int64 = 4

	// MaxAddPos is the integer constant for maxAddPos.
	MaxAddPos int64 = 8

	// MaxASC is the integer constant for maxASC.
	MaxASC int64 = 8

	// MaxASCmap is the integer constant for maxASCmap.
	MaxASCmap int64 = 7

	// MaxASCpersist is the integer constant for maxASCpersist.
	MaxASCpersist int64 = 6

	// MaxBeacons is the integer constant for maxBeacons.
	MaxBeacons int64 = 64

	// MaxBTs is the integer constant for maxBTs.
	MaxBTs int64 = 32

	// MaxCCTrCH is the integer constant for maxCCTrCH.
	MaxCCTrCH int64 = 8

	// MaxCellMeas is the integer constant for maxCellMeas.
	MaxCellMeas int64 = 32

	// MaxCellMeasExt is the integer constant for maxCellMeas-ext.
	MaxCellMeasExt int64 = 80

	// MaxCellMeasExt2 is the integer constant for maxCellMeas-ext2.
	MaxCellMeasExt2 int64 = 48

	// MaxCellMeasOnSecULFreq is the integer constant for maxCellMeasOnSecULFreq.
	MaxCellMeasOnSecULFreq int64 = 32

	// MaxCellMeas1 is the integer constant for maxCellMeas-1.
	MaxCellMeas1 int64 = 31

	// MaxCellMeasExt1 is the integer constant for maxCellMeas-ext-1.
	MaxCellMeasExt1 int64 = 79

	// MaxCellMeasOnSecULFreq1 is the integer constant for maxCellMeasOnSecULFreq-1.
	MaxCellMeasOnSecULFreq1 int64 = 31

	// MaxCNdomains is the integer constant for maxCNdomains.
	MaxCNdomains int64 = 4

	// MaxCommonHRNTI is the integer constant for maxCommonHRNTI.
	MaxCommonHRNTI int64 = 4

	// MaxCommonQueueID is the integer constant for maxCommonQueueID.
	MaxCommonQueueID int64 = 2

	// MaxCPCHsets is the integer constant for maxCPCHsets.
	MaxCPCHsets int64 = 16

	// MaxDedicatedCSGFreq is the integer constant for maxDedicatedCSGFreq.
	MaxDedicatedCSGFreq int64 = 4

	// MaxDPCHDLchan is the integer constant for maxDPCH-DLchan.
	MaxDPCHDLchan int64 = 8

	// MaxDPDCHUL is the integer constant for maxDPDCH-UL.
	MaxDPDCHUL int64 = 6

	// MaxDRACclasses is the integer constant for maxDRACclasses.
	MaxDRACclasses int64 = 8

	// MaxExcludedDetectedSetCells is the integer constant for maxExcludedDetectedSetCells.
	MaxExcludedDetectedSetCells int64 = 64

	// MaxEDCHMACdFlow is the integer constant for maxE-DCHMACdFlow.
	MaxEDCHMACdFlow int64 = 8

	// MaxEDCHMACdFlow1 is the integer constant for maxE-DCHMACdFlow-1.
	MaxEDCHMACdFlow1 int64 = 7

	// MaxMultipleFrequencyBandsFDD is the integer constant for maxMultipleFrequencyBandsFDD.
	MaxMultipleFrequencyBandsFDD int64 = 8

	// MaxMultipleFrequencyBandsEUTRA is the integer constant for maxMultipleFrequencyBandsEUTRA.
	MaxMultipleFrequencyBandsEUTRA int64 = 8

	// MaxEUTRACellPerFreq is the integer constant for maxEUTRACellPerFreq.
	MaxEUTRACellPerFreq int64 = 16

	// MaxEUTRATargetFreqs is the integer constant for maxEUTRATargetFreqs.
	MaxEUTRATargetFreqs int64 = 8

	// MaxEDCHRL is the integer constant for maxEDCHRL.
	MaxEDCHRL int64 = 4

	// MaxEDCHRL1 is the integer constant for maxEDCHRL-1.
	MaxEDCHRL1 int64 = 3

	// MaxEDCHs is the integer constant for maxEDCHs.
	MaxEDCHs int64 = 32

	// MaxEDCHs1 is the integer constant for maxEDCHs-1.
	MaxEDCHs1 int64 = 31

	// MaxEDCHTxPatternTDD128 is the integer constant for maxEDCHTxPattern-TDD128.
	MaxEDCHTxPatternTDD128 int64 = 4

	// MaxEDCHTxPatternTDD1281 is the integer constant for maxEDCHTxPattern-TDD128-1.
	MaxEDCHTxPatternTDD1281 int64 = 3

	// MaxERNTIgroup is the integer constant for maxERNTIgroup.
	MaxERNTIgroup int64 = 32

	// MaxERNTIperGroup is the integer constant for maxERNTIperGroup.
	MaxERNTIperGroup int64 = 2

	// MaxERUCCH is the integer constant for maxERUCCH.
	MaxERUCCH int64 = 256

	// MaxFACHPCH is the integer constant for maxFACHPCH.
	MaxFACHPCH int64 = 8

	// MaxFreq is the integer constant for maxFreq.
	MaxFreq int64 = 8

	// MaxFreqBandsEUTRA is the integer constant for maxFreqBandsEUTRA.
	MaxFreqBandsEUTRA int64 = 16

	// MaxFreqBandsEUTRAExt is the integer constant for maxFreqBandsEUTRA-ext.
	MaxFreqBandsEUTRAExt int64 = 48

	// MaxFreqBandsFDD is the integer constant for maxFreqBandsFDD.
	MaxFreqBandsFDD int64 = 8

	// MaxFreqBandsFDD2 is the integer constant for maxFreqBandsFDD2.
	MaxFreqBandsFDD2 int64 = 22

	// MaxFreqBandsFDD3 is the integer constant for maxFreqBandsFDD3.
	MaxFreqBandsFDD3 int64 = 86

	// MaxFreqBandsFDDExt is the integer constant for maxFreqBandsFDD-ext.
	MaxFreqBandsFDDExt int64 = 15

	// MaxFreqBandsFDDExt2 is the integer constant for maxFreqBandsFDD-ext2.
	MaxFreqBandsFDDExt2 int64 = 64

	// MaxFreqBandsFDDExt3 is the integer constant for maxFreqBandsFDD-ext3.
	MaxFreqBandsFDDExt3 int64 = 78

	// MaxFreqBandsIndicatorSupport is the integer constant for maxFreqBandsIndicatorSupport.
	MaxFreqBandsIndicatorSupport int64 = 2

	// MaxFreqBandsTDD is the integer constant for maxFreqBandsTDD.
	MaxFreqBandsTDD int64 = 4

	// MaxFreqBandsTDDExt is the integer constant for maxFreqBandsTDD-ext.
	MaxFreqBandsTDDExt int64 = 16

	// MaxFreqBandsGSM is the integer constant for maxFreqBandsGSM.
	MaxFreqBandsGSM int64 = 16

	// MaxFreqMeasWithoutCM is the integer constant for maxFreqMeasWithoutCM.
	MaxFreqMeasWithoutCM int64 = 2

	// MaxGANSS is the integer constant for maxGANSS.
	MaxGANSS int64 = 8

	// MaxGANSS1 is the integer constant for maxGANSS-1.
	MaxGANSS1 int64 = 7

	// MaxGANSSSat is the integer constant for maxGANSSSat.
	MaxGANSSSat int64 = 64

	// MaxGANSSSat1 is the integer constant for maxGANSSSat-1.
	MaxGANSSSat1 int64 = 63

	// MaxGERANSI is the integer constant for maxGERAN-SI.
	MaxGERANSI int64 = 8

	// MaxGSMTargetCells is the integer constant for maxGSMTargetCells.
	MaxGSMTargetCells int64 = 32

	// MaxHNBNameSize is the integer constant for maxHNBNameSize.
	MaxHNBNameSize int64 = 48

	// MaxHProcesses is the integer constant for maxHProcesses.
	MaxHProcesses int64 = 8

	// MaxHSSCCHLessTrBlk is the integer constant for maxHS-SCCHLessTrBlk.
	MaxHSSCCHLessTrBlk int64 = 4

	// MaxHSDSCHTBIndex is the integer constant for maxHSDSCHTBIndex.
	MaxHSDSCHTBIndex int64 = 64

	// MaxHSDSCHTBIndexTdd384 is the integer constant for maxHSDSCHTBIndex-tdd384.
	MaxHSDSCHTBIndexTdd384 int64 = 512

	// MaxHSSCCHs is the integer constant for maxHSSCCHs.
	MaxHSSCCHs int64 = 4

	// MaxHSSCCHs1 is the integer constant for maxHSSCCHs-1.
	MaxHSSCCHs1 int64 = 3

	// MaxHSSICHTDD128 is the integer constant for maxHSSICH-TDD128.
	MaxHSSICHTDD128 int64 = 4

	// MaxHSSICHTDD1281 is the integer constant for maxHSSICH-TDD128-1.
	MaxHSSICHTDD1281 int64 = 3

	// MaxIGPInfo is the integer constant for maxIGPInfo.
	MaxIGPInfo int64 = 320

	// MaxInterSysMessages is the integer constant for maxInterSysMessages.
	MaxInterSysMessages int64 = 4

	// MaxLoCHperRLC is the integer constant for maxLoCHperRLC.
	MaxLoCHperRLC int64 = 2

	// MaxLoggedMeasReport is the integer constant for maxLoggedMeasReport.
	MaxLoggedMeasReport int64 = 128

	// MaxMACDPDUsizes is the integer constant for maxMAC-d-PDUsizes.
	MaxMACDPDUsizes int64 = 8

	// MaxMBMSCommonCCTrCh is the integer constant for maxMBMS-CommonCCTrCh.
	MaxMBMSCommonCCTrCh int64 = 32

	// MaxMBMSCommonPhyCh is the integer constant for maxMBMS-CommonPhyCh.
	MaxMBMSCommonPhyCh int64 = 32

	// MaxMBMSCommonRB is the integer constant for maxMBMS-CommonRB.
	MaxMBMSCommonRB int64 = 32

	// MaxMBMSCommonTrCh is the integer constant for maxMBMS-CommonTrCh.
	MaxMBMSCommonTrCh int64 = 32

	// MaxMBMSFreq is the integer constant for maxMBMS-Freq.
	MaxMBMSFreq int64 = 4

	// MaxMBMSL1CP is the integer constant for maxMBMS-L1CP.
	MaxMBMSL1CP int64 = 4

	// MaxMBMSservCount is the integer constant for maxMBMSservCount.
	MaxMBMSservCount int64 = 8

	// MaxMBMSservModif is the integer constant for maxMBMSservModif.
	MaxMBMSservModif int64 = 32

	// MaxMBMSservSched is the integer constant for maxMBMSservSched.
	MaxMBMSservSched int64 = 16

	// MaxMBMSservSelect is the integer constant for maxMBMSservSelect.
	MaxMBMSservSelect int64 = 8

	// MaxMBMSservUnmodif is the integer constant for maxMBMSservUnmodif.
	MaxMBMSservUnmodif int64 = 64

	// MaxMBMSTransmis is the integer constant for maxMBMSTransmis.
	MaxMBMSTransmis int64 = 4

	// MaxMBSFNClusters is the integer constant for maxMBSFNClusters.
	MaxMBSFNClusters int64 = 16

	// MaxMeasCSGRange is the integer constant for maxMeasCSGRange.
	MaxMeasCSGRange int64 = 4

	// MaxMeasEvent is the integer constant for maxMeasEvent.
	MaxMeasEvent int64 = 8

	// MaxMeasEventOnSecULFreq is the integer constant for maxMeasEventOnSecULFreq.
	MaxMeasEventOnSecULFreq int64 = 8

	// MaxMeasIdentity is the integer constant for maxMeasIdentity.
	MaxMeasIdentity int64 = 32

	// MaxMeasIntervals is the integer constant for maxMeasIntervals.
	MaxMeasIntervals int64 = 3

	// MaxMeasOccasionPattern is the integer constant for maxMeasOccasionPattern.
	MaxMeasOccasionPattern int64 = 5

	// MaxMeasOccasionPattern1 is the integer constant for maxMeasOccasionPattern-1.
	MaxMeasOccasionPattern1 int64 = 4

	// MaxMeasParEvent is the integer constant for maxMeasParEvent.
	MaxMeasParEvent int64 = 2

	// MaxNonContiguousMultiCellCombinations is the integer constant for maxNonContiguousMultiCellCombinations.
	MaxNonContiguousMultiCellCombinations int64 = 3

	// MaxNumAccessGroups is the integer constant for maxNumAccessGroups.
	MaxNumAccessGroups int64 = 16

	// MaxNumAcdcCategory is the integer constant for maxNumAcdcCategory.
	MaxNumAcdcCategory int64 = 16

	// MaxNumCDMA2000Freqs is the integer constant for maxNumCDMA2000Freqs.
	MaxNumCDMA2000Freqs int64 = 8

	// MaxNumEAGCH is the integer constant for maxNumE-AGCH.
	MaxNumEAGCH int64 = 4

	// MaxNumEHICH is the integer constant for maxNumE-HICH.
	MaxNumEHICH int64 = 4

	// MaxNumEUTRAFreqs is the integer constant for maxNumEUTRAFreqs.
	MaxNumEUTRAFreqs int64 = 8

	// MaxNumEUTRAFreqsFACH is the integer constant for maxNumEUTRAFreqs-FACH.
	MaxNumEUTRAFreqsFACH int64 = 4

	// MaxNumEUTRAFreqsFACHExt is the integer constant for maxNumEUTRAFreqs-FACH-ext.
	MaxNumEUTRAFreqsFACHExt int64 = 8

	// MaxNumGSMCellGroup is the integer constant for maxNumGSMCellGroup.
	MaxNumGSMCellGroup int64 = 16

	// MaxNumGSMFreqRanges is the integer constant for maxNumGSMFreqRanges.
	MaxNumGSMFreqRanges int64 = 32

	// MaxNumFDDFreqs is the integer constant for maxNumFDDFreqs.
	MaxNumFDDFreqs int64 = 8

	// MaxNumANRLoggedItems is the integer constant for maxNumANRLoggedItems.
	MaxNumANRLoggedItems int64 = 4

	// MaxnumLoggedMeas is the integer constant for maxnumLoggedMeas.
	MaxnumLoggedMeas int64 = 8

	// MaxNumMDTPLMN is the integer constant for maxNumMDTPLMN.
	MaxNumMDTPLMN int64 = 15

	// MaxNumTDDFreqs is the integer constant for maxNumTDDFreqs.
	MaxNumTDDFreqs int64 = 8

	// MaxNoOfMeas is the integer constant for maxNoOfMeas.
	MaxNoOfMeas int64 = 16

	// MaxOtherRAT is the integer constant for maxOtherRAT.
	MaxOtherRAT int64 = 15

	// MaxOtherRAT16 is the integer constant for maxOtherRAT-16.
	MaxOtherRAT16 int64 = 16

	// MaxPage1 is the integer constant for maxPage1.
	MaxPage1 int64 = 8

	// MaxPCPCHAPsig is the integer constant for maxPCPCH-APsig.
	MaxPCPCHAPsig int64 = 16

	// MaxPCPCHAPsubCh is the integer constant for maxPCPCH-APsubCh.
	MaxPCPCHAPsubCh int64 = 12

	// MaxPCPCHCDsig is the integer constant for maxPCPCH-CDsig.
	MaxPCPCHCDsig int64 = 16

	// MaxPCPCHCDsubCh is the integer constant for maxPCPCH-CDsubCh.
	MaxPCPCHCDsubCh int64 = 12

	// MaxPCPCHSF is the integer constant for maxPCPCH-SF.
	MaxPCPCHSF int64 = 7

	// MaxPCPCHs is the integer constant for maxPCPCHs.
	MaxPCPCHs int64 = 64

	// MaxPDCPAlgoType is the integer constant for maxPDCPAlgoType.
	MaxPDCPAlgoType int64 = 8

	// MaxPDSCH is the integer constant for maxPDSCH.
	MaxPDSCH int64 = 8

	// MaxPDSCHTFCIgroups is the integer constant for maxPDSCH-TFCIgroups.
	MaxPDSCHTFCIgroups int64 = 256

	// MaxPRACH is the integer constant for maxPRACH.
	MaxPRACH int64 = 16

	// MaxPRACHEUL is the integer constant for maxPRACH-EUL.
	MaxPRACHEUL int64 = 4

	// MaxPRACHFPACH is the integer constant for maxPRACH-FPACH.
	MaxPRACHFPACH int64 = 8

	// MaxPredefConfig is the integer constant for maxPredefConfig.
	MaxPredefConfig int64 = 16

	// MaxOtherStateConfig is the integer constant for maxOtherStateConfig.
	MaxOtherStateConfig int64 = 4

	// MaxOtherStateConfig1 is the integer constant for maxOtherStateConfig-1.
	MaxOtherStateConfig1 int64 = 3

	// MaxPrio is the integer constant for maxPrio.
	MaxPrio int64 = 8

	// MaxPrio1 is the integer constant for maxPrio-1.
	MaxPrio1 int64 = 7

	// MaxPrioExt is the integer constant for maxPrio-ext.
	MaxPrioExt int64 = 16

	// MaxPUSCH is the integer constant for maxPUSCH.
	MaxPUSCH int64 = 8

	// MaxQueueIDs is the integer constant for maxQueueIDs.
	MaxQueueIDs int64 = 8

	// MaxRABsetup is the integer constant for maxRABsetup.
	MaxRABsetup int64 = 16

	// MaxRAT is the integer constant for maxRAT.
	MaxRAT int64 = 16

	// MaxRB is the integer constant for maxRB.
	MaxRB int64 = 32

	// MaxRBallRABs is the integer constant for maxRBallRABs.
	MaxRBallRABs int64 = 27

	// MaxRBMuxOptions is the integer constant for maxRBMuxOptions.
	MaxRBMuxOptions int64 = 8

	// MaxRBperRAB is the integer constant for maxRBperRAB.
	MaxRBperRAB int64 = 8

	// MaxRBperTrCh is the integer constant for maxRBperTrCh.
	MaxRBperTrCh int64 = 16

	// MaxReportedEUTRACellPerFreq is the integer constant for maxReportedEUTRACellPerFreq.
	MaxReportedEUTRACellPerFreq int64 = 4

	// MaxReportedEUTRAFreqs is the integer constant for maxReportedEUTRAFreqs.
	MaxReportedEUTRAFreqs int64 = 4

	// MaxReportedEUTRAFreqsExt is the integer constant for maxReportedEUTRAFreqs-ext.
	MaxReportedEUTRAFreqsExt int64 = 8

	// MaxReportedGSMCells is the integer constant for maxReportedGSMCells.
	MaxReportedGSMCells int64 = 8

	// MaxRetrievConfig is the integer constant for maxRetrievConfig.
	MaxRetrievConfig int64 = 8

	// MaxRetrievConfig1 is the integer constant for maxRetrievConfig-1.
	MaxRetrievConfig1 int64 = 7

	// MaxRL is the integer constant for maxRL.
	MaxRL int64 = 8

	// MaxRL1 is the integer constant for maxRL-1.
	MaxRL1 int64 = 7

	// MaxRLCPDUsizePerLogChan is the integer constant for maxRLCPDUsizePerLogChan.
	MaxRLCPDUsizePerLogChan int64 = 32

	// MaxRMPfrequencies is the integer constant for maxRMPfrequencies.
	MaxRMPfrequencies int64 = 8

	// MaxRFC3095CID is the integer constant for maxRFC3095-CID.
	MaxRFC3095CID int64 = 16384

	// MaxROHCPacketSizesR4 is the integer constant for maxROHC-PacketSizes-r4.
	MaxROHCPacketSizesR4 int64 = 16

	// MaxROHCProfileR4 is the integer constant for maxROHC-Profile-r4.
	MaxROHCProfileR4 int64 = 8

	// MaxRxPatternForHSDSCHTDD128 is the integer constant for maxRxPatternForHSDSCH-TDD128.
	MaxRxPatternForHSDSCHTDD128 int64 = 4

	// MaxRxPatternForHSDSCHTDD1281 is the integer constant for maxRxPatternForHSDSCH-TDD128-1.
	MaxRxPatternForHSDSCHTDD1281 int64 = 3

	// MaxSat is the integer constant for maxSat.
	MaxSat int64 = 16

	// MaxSatClockModels is the integer constant for maxSatClockModels.
	MaxSatClockModels int64 = 4

	// MaxSCCPCH is the integer constant for maxSCCPCH.
	MaxSCCPCH int64 = 16

	// MaxSgnType is the integer constant for maxSgnType.
	MaxSgnType int64 = 8

	// MaxSIB is the integer constant for maxSIB.
	MaxSIB int64 = 32

	// MaxSIB2 is the integer constant for maxSIB2.
	MaxSIB2 int64 = 64

	// MaxSIBFACH is the integer constant for maxSIB-FACH.
	MaxSIBFACH int64 = 8

	// MaxSIBperMsg is the integer constant for maxSIBperMsg.
	MaxSIBperMsg int64 = 16

	// MaxSIrequest is the integer constant for maxSIrequest.
	MaxSIrequest int64 = 4

	// MaxSRBsetup is the integer constant for maxSRBsetup.
	MaxSRBsetup int64 = 8

	// MaxSystemCapability is the integer constant for maxSystemCapability.
	MaxSystemCapability int64 = 16

	// MaxTDD128Carrier is the integer constant for maxTDD128Carrier.
	MaxTDD128Carrier int64 = 6

	// MaxTDD128Carrier1 is the integer constant for maxTDD128Carrier-1.
	MaxTDD128Carrier1 int64 = 5

	// MaxTbsForHSDSCHTDD128 is the integer constant for maxTbsForHSDSCH-TDD128.
	MaxTbsForHSDSCHTDD128 int64 = 4

	// MaxTbsForHSDSCHTDD1281 is the integer constant for maxTbsForHSDSCH-TDD128-1.
	MaxTbsForHSDSCHTDD1281 int64 = 3

	// MaxTF is the integer constant for maxTF.
	MaxTF int64 = 32

	// MaxTFCPCH is the integer constant for maxTF-CPCH.
	MaxTFCPCH int64 = 16

	// MaxTFC is the integer constant for maxTFC.
	MaxTFC int64 = 1024

	// MaxTFCsub is the integer constant for maxTFCsub.
	MaxTFCsub int64 = 1024

	// MaxTFCI2Combs is the integer constant for maxTFCI-2-Combs.
	MaxTFCI2Combs int64 = 512

	// MaxTGPS is the integer constant for maxTGPS.
	MaxTGPS int64 = 6

	// MaxTrCH is the integer constant for maxTrCH.
	MaxTrCH int64 = 32

	// MaxTrCHConcat is the integer constant for maxTrCHConcat.
	MaxTrCHConcat int64 = 3

	// MaxTrCHpreconf is the integer constant for maxTrCHpreconf.
	MaxTrCHpreconf int64 = 32

	// MaxTS is the integer constant for maxTS.
	MaxTS int64 = 14

	// MaxTS1 is the integer constant for maxTS-1.
	MaxTS1 int64 = 13

	// MaxTS2 is the integer constant for maxTS-2.
	MaxTS2 int64 = 12

	// MaxTSLCR is the integer constant for maxTS-LCR.
	MaxTSLCR int64 = 6

	// MaxTSLCR1 is the integer constant for maxTS-LCR-1.
	MaxTSLCR1 int64 = 5

	// MaxURA is the integer constant for maxURA.
	MaxURA int64 = 8

	// MaxURNTIGroup is the integer constant for maxURNTI-Group.
	MaxURNTIGroup int64 = 8

	// MaxWLANID is the integer constant for maxWLANID.
	MaxWLANID int64 = 16

	// MaxWLANs is the integer constant for maxWLANs.
	MaxWLANs int64 = 64
)
