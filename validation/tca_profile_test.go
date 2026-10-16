package validation

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/esim/sgp22"
	"github.com/gomaja/go-asn1/telecom/esim/sgp32"
)

// TCA eUICC Profile Package V3.4.1 §8.2.2, PEDefinitions UICCCapability;
// ITU-T X.680 (02/2021) §22.4 and X.690 (02/2021) §§8.6.2, 11.2.2.
func TestTCAUICCCapabilityBit39(t *testing.T) {
	wire, err := hex.DecodeString("bf222781030304018203020700830301000084008506000000000001880100a900aa0004030100000c00")
	if err != nil {
		t.Fatal(err)
	}
	if sgp22.UICCCapabilityUsatAppPairing != 39 || sgp32.UICCCapabilityUsatAppPairing != 39 {
		t.Fatalf("usatAppPairing positions: SGP.22=%d SGP.32=%d", sgp22.UICCCapabilityUsatAppPairing, sgp32.UICCCapabilityUsatAppPairing)
	}
	for _, tc := range []struct {
		name  string
		check func(*testing.T)
	}{
		{"SGP.22", func(t *testing.T) {
			var v sgp22.EUICCInfo2
			if err := v.UnmarshalBER(wire); err != nil {
				t.Fatal(err)
			}
			if !v.UiccCapability.Has(sgp22.UICCCapabilityUsatAppPairing) || v.UiccCapability.Has(sgp22.UICCCapabilityGbauApi) || v.UiccCapability.BitLength != 40 {
				t.Fatalf("UICCCapability = %+v", v.UiccCapability)
			}
			checkTCAWire(t, wire, func() ([]byte, error) { return v.MarshalBER() }, v.MarshalDER)
			fresh, err := v.MarshalBER(ber.WithoutBERReplay())
			if err != nil || !bytes.Equal(fresh, wire) {
				t.Fatalf("fresh BER = %x, %v; want %x", fresh, err, wire)
			}
		}},
		{"SGP.32", func(t *testing.T) {
			var v sgp32.EUICCInfo2
			if err := v.UnmarshalBER(wire); err != nil {
				t.Fatal(err)
			}
			if !v.UiccCapability.Has(sgp32.UICCCapabilityUsatAppPairing) || v.UiccCapability.Has(sgp32.UICCCapabilityGbauApi) || v.UiccCapability.BitLength != 40 {
				t.Fatalf("UICCCapability = %+v", v.UiccCapability)
			}
			checkTCAWire(t, wire, func() ([]byte, error) { return v.MarshalBER() }, v.MarshalDER)
			fresh, err := v.MarshalBER(ber.WithoutBERReplay())
			if err != nil || !bytes.Equal(fresh, wire) {
				t.Fatalf("fresh BER = %x, %v; want %x", fresh, err, wire)
			}
		}},
	} {
		t.Run(tc.name, tc.check)
	}
}

func checkTCAWire(t *testing.T, want []byte, ber func() ([]byte, error), der func() ([]byte, error)) {
	t.Helper()
	got, err := ber()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("BER = %x, %v; want %x", got, err, want)
	}
	got, err = der()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("DER = %x, %v; want %x", got, err, want)
	}
}

// TCA eUICC Profile Package V3.4.1 PEDefinitions PE-AKAParameter;
// ITU-T X.690 (02/2021) §11.5 requires DEFAULT-valued components to be omitted in DER.
func TestPEAKAParameterDERDefaults(t *testing.T) {
	// The two required fields are a [0] PEHeader and an explicitly tagged [1]
	// mapping choice; [6] carries the present, empty SSIM parameters.
	expectedDER, err := hex.DecodeString("3015a003810101a10ca00a80010081050102030405a600")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("SGP.22", func(t *testing.T) {
		fresh := func() sgp22.PEAKAParameter {
			return sgp22.PEAKAParameter{
				AkaHeader: sgp22.PEHeader{Identification: 1},
				AlgoConfiguration: sgp22.NewPEAKAParameterAlgoConfigurationMappingParameter(sgp22.MappingParameter{
					MappingOptions: []byte{0}, MappingSource: []byte{1, 2, 3, 4, 5},
				}),
				SsimParameters: &sgp22.PEAKAParameterSsimParameters{},
			}
		}
		absent := fresh()
		want, err := absent.MarshalDER()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, expectedDER) {
			t.Fatalf("DER = %x; want %x", want, expectedDER)
		}
		present := fresh()
		present.SqnOptions = []byte{2}
		present.SqnDelta = []byte{0, 0, 0x10, 0, 0, 0}
		present.SqnAgeLimit = []byte{0, 0, 0x10, 0, 0, 0}
		zeros := make([][]byte, 32)
		for i := range zeros {
			zeros[i] = make([]byte, 6)
		}
		present.SqnInit = &sgp22.PEAKAParameterSqnInit{Values: zeros}
		present.SsimParameters.KeyDerivationFunctions = &sgp22.PEAKAParameterSsimParametersKeyDerivationFunctions{Values: [][]byte{{1}}}
		got, err := present.MarshalDER()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("equal DEFAULT DER = %x, %v; want %x", got, err, want)
		}
		wire, err := present.MarshalBER()
		if err != nil {
			t.Fatal(err)
		}
		var decoded sgp22.PEAKAParameter
		if err := decoded.UnmarshalBER(wire); err != nil {
			t.Fatal(err)
		}
		if decoded.SqnOptions == nil || decoded.SqnDelta == nil || decoded.SqnAgeLimit == nil || decoded.SqnInit == nil || decoded.SsimParameters == nil || decoded.SsimParameters.KeyDerivationFunctions == nil {
			t.Fatal("BER decode lost present DEFAULT components")
		}
		canonical, err := decoded.MarshalDER()
		if err != nil || !bytes.Equal(canonical, want) {
			t.Fatalf("decoded DEFAULT DER = %x, %v; want %x", canonical, err, want)
		}
		replay, err := decoded.MarshalBER()
		if err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("BER replay = %x, %v; want %x", replay, err, wire)
		}
		present.SqnOptions[0] = 3
		got, err = present.MarshalDER()
		if err != nil || bytes.Equal(got, want) {
			t.Fatalf("nondefault sqnOptions DER = %x, %v; want different from %x", got, err, want)
		}
		present.SqnOptions[0] = 2
		present.SqnDelta[2] = 0x11
		got, err = present.MarshalDER()
		if err != nil || bytes.Equal(got, want) {
			t.Fatalf("nondefault sqnDelta DER = %x, %v; want different from %x", got, err, want)
		}
		present.SqnDelta[2] = 0x10
		present.SqnAgeLimit[2] = 0x11
		got, err = present.MarshalDER()
		if err != nil || bytes.Equal(got, want) {
			t.Fatalf("nondefault sqnAgeLimit DER = %x, %v; want different from %x", got, err, want)
		}
		present.SqnAgeLimit[2] = 0x10
		present.SqnInit.Values[31][5] = 1
		got, err = present.MarshalDER()
		if err != nil || bytes.Equal(got, want) {
			t.Fatalf("nondefault sqnInit DER = %x, %v; want different from %x", got, err, want)
		}
		present.SqnInit.Values[31][5] = 0
		present.SsimParameters.KeyDerivationFunctions.Values[0][0] = 2
		got, err = present.MarshalDER()
		if err != nil || bytes.Equal(got, want) {
			t.Fatalf("nondefault keyDerivationFunctions DER = %x, %v; want different from %x", got, err, want)
		}
	})
	t.Run("SGP.32", func(t *testing.T) {
		fresh := func() sgp32.PEAKAParameter {
			return sgp32.PEAKAParameter{
				AkaHeader: sgp32.PEHeader{Identification: 1},
				AlgoConfiguration: sgp32.NewPEAKAParameterAlgoConfigurationMappingParameter(sgp32.MappingParameter{
					MappingOptions: []byte{0}, MappingSource: []byte{1, 2, 3, 4, 5},
				}),
				SsimParameters: &sgp32.PEAKAParameterSsimParameters{},
			}
		}
		absent := fresh()
		want, err := absent.MarshalDER()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, expectedDER) {
			t.Fatalf("DER = %x; want %x", want, expectedDER)
		}
		present := fresh()
		present.SqnOptions = []byte{2}
		present.SqnDelta = []byte{0, 0, 0x10, 0, 0, 0}
		present.SqnAgeLimit = []byte{0, 0, 0x10, 0, 0, 0}
		zeros := make([][]byte, 32)
		for i := range zeros {
			zeros[i] = make([]byte, 6)
		}
		present.SqnInit = &sgp32.PEAKAParameterSqnInit{Values: zeros}
		present.SsimParameters.KeyDerivationFunctions = &sgp32.PEAKAParameterSsimParametersKeyDerivationFunctions{Values: [][]byte{{1}}}
		got, err := present.MarshalDER()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("equal DEFAULT DER = %x, %v; want %x", got, err, want)
		}
		wire, err := present.MarshalBER()
		if err != nil {
			t.Fatal(err)
		}
		var decoded sgp32.PEAKAParameter
		if err := decoded.UnmarshalBER(wire); err != nil {
			t.Fatal(err)
		}
		if decoded.SqnOptions == nil || decoded.SqnDelta == nil || decoded.SqnAgeLimit == nil || decoded.SqnInit == nil || decoded.SsimParameters == nil || decoded.SsimParameters.KeyDerivationFunctions == nil {
			t.Fatal("BER decode lost present DEFAULT components")
		}
		canonical, err := decoded.MarshalDER()
		if err != nil || !bytes.Equal(canonical, want) {
			t.Fatalf("decoded DEFAULT DER = %x, %v; want %x", canonical, err, want)
		}
		replay, err := decoded.MarshalBER()
		if err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("BER replay = %x, %v; want %x", replay, err, wire)
		}
		present.SqnOptions[0] = 3
		got, err = present.MarshalDER()
		if err != nil || bytes.Equal(got, want) {
			t.Fatalf("nondefault sqnOptions DER = %x, %v; want different from %x", got, err, want)
		}
		present.SqnOptions[0] = 2
		present.SqnDelta[2] = 0x11
		got, err = present.MarshalDER()
		if err != nil || bytes.Equal(got, want) {
			t.Fatalf("nondefault sqnDelta DER = %x, %v; want different from %x", got, err, want)
		}
		present.SqnDelta[2] = 0x10
		present.SqnAgeLimit[2] = 0x11
		got, err = present.MarshalDER()
		if err != nil || bytes.Equal(got, want) {
			t.Fatalf("nondefault sqnAgeLimit DER = %x, %v; want different from %x", got, err, want)
		}
		present.SqnAgeLimit[2] = 0x10
		present.SqnInit.Values[31][5] = 1
		got, err = present.MarshalDER()
		if err != nil || bytes.Equal(got, want) {
			t.Fatalf("nondefault sqnInit DER = %x, %v; want different from %x", got, err, want)
		}
		present.SqnInit.Values[31][5] = 0
		present.SsimParameters.KeyDerivationFunctions.Values[0][0] = 2
		got, err = present.MarshalDER()
		if err != nil || bytes.Equal(got, want) {
			t.Fatalf("nondefault keyDerivationFunctions DER = %x, %v; want different from %x", got, err, want)
		}
	})
}
