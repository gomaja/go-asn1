package ber

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/tag"
)

func mustUTCTime(s string) runtime.UTCTime {
	value, err := runtime.ParseUTCTime(s)
	if err != nil {
		panic(err)
	}
	return value
}

func mustGeneralizedTime(s string) runtime.GeneralizedTime {
	value, err := runtime.ParseGeneralizedTime(s)
	if err != nil {
		panic(err)
	}
	return value
}

func mustTimeTLV(encoded []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return encoded
}

func primitiveTime(number int, contents string) []byte {
	return encodeFixedTLV(tag.Tag{Class: tag.ClassUniversal, Number: number}, []byte(contents))
}

// constructedTime splits contents into OCTET STRING fragments of at most
// size octets (X.690 (02/2021) §8.23.6, §8.25).
func constructedTime(number int, contents string, size int) []byte {
	var children []byte
	for len(contents) > 0 {
		part := contents[:min(size, len(contents))]
		contents = contents[len(part):]
		children = append(children, mustTimeTLV(EncodeOctetString([]byte(part)))...)
	}
	return mustTimeTLV(EncodeConstructed(tag.Tag{Class: tag.ClassUniversal, Number: number, Constructed: true}, children))
}

// BER keeps every X.680 (02/2021) §46.3/§47.3 form byte for byte; DER and
// the X.690 (02/2021) §11.7/§11.8 encoder compute the canonical form or
// fail with ErrNoCanonicalTime. Expected values are worked from the clauses.
var berTimeForms = []struct {
	number int
	in     string
	der    string // "" when no canonical form exists
}{
	{tag.TagUTCTime, "2601011200Z", "260101120000Z"},
	{tag.TagUTCTime, "2601011200+0100", "260101110000Z"},
	{tag.TagUTCTime, "8201020700-0500", "820102120000Z"},
	{tag.TagUTCTime, "260101120000-0000", "260101120000Z"},
	{tag.TagUTCTime, "491231230000-0100", ""},
	{tag.TagUTCTime, "920722132100Z", "920722132100Z"},
	{tag.TagGeneralizedTime, "202601011200Z", "20260101120000Z"},
	{tag.TagGeneralizedTime, "2026010112Z", "20260101120000Z"},
	{tag.TagGeneralizedTime, "2026010112,5Z", "20260101123000Z"},
	{tag.TagGeneralizedTime, "202601011230.5Z", "20260101123030Z"},
	{tag.TagGeneralizedTime, "20260101120000+01", "20260101110000Z"},
	{tag.TagGeneralizedTime, "20260101120000.25", ""},
	{tag.TagGeneralizedTime, "19851106210627.3", ""},
	{tag.TagGeneralizedTime, "19851106210627.3-0500", "19851107020627.3Z"},
	{tag.TagGeneralizedTime, "1985110621.14159Z", "19851106210829.724Z"},
	{tag.TagGeneralizedTime, "19920622123421.0Z", "19920622123421Z"},
	{tag.TagGeneralizedTime, "19920722132100.30Z", "19920722132100.3Z"},
	{tag.TagGeneralizedTime, "20260101120000,5Z", "20260101120000.5Z"},
	{tag.TagGeneralizedTime, "20260101120000.1234567891Z", "20260101120000.1234567891Z"},
	{tag.TagGeneralizedTime, "20260101003000+0100", "20251231233000Z"},
	{tag.TagGeneralizedTime, "99991231235959Z", "99991231235959Z"},
	{tag.TagGeneralizedTime, "99991231235959-0100", ""},
}

func decodeTimeElement(number int, data []byte, options ...DecodeOption) (string, int, func() ([]byte, error), func() ([]byte, error), error) {
	if number == tag.TagUTCTime {
		value, n, err := DecodeUTCTime(data, options...)
		return value.String(), n, func() ([]byte, error) { return EncodeUTCTime(value) }, func() ([]byte, error) { return EncodeUTCTimeDER(value) }, err
	}
	value, n, err := DecodeGeneralizedTime(data, options...)
	return value.String(), n, func() ([]byte, error) { return EncodeGeneralizedTime(value) }, func() ([]byte, error) { return EncodeGeneralizedTimeDER(value) }, err
}

func TestBERTimeLexicalRoundTrip(t *testing.T) {
	for _, form := range berTimeForms {
		t.Run(form.in, func(t *testing.T) {
			wire := primitiveTime(form.number, form.in)
			options := TrackBERForm(nil)
			text, n, encode, encodeDER, err := decodeTimeElement(form.number, wire, options...)
			if err != nil || n != len(wire) || text != form.in {
				t.Fatalf("decode = %q, %d, %v", text, n, err)
			}
			// A noncanonical lexical form is part of the value, so the
			// whole-element BER preservation is not needed.
			if BERNeedsPreservation(options) {
				t.Fatal("lexical form marked for preservation")
			}
			ber, err := encode()
			if err != nil || !bytes.Equal(ber, wire) {
				t.Fatalf("BER = %x, %v; want %x", ber, err, wire)
			}
			der, err := encodeDER()
			if form.der == "" {
				if !errors.Is(err, ErrInvalidValue) || !errors.Is(err, runtime.ErrNoCanonicalTime) {
					t.Fatalf("DER = %x, %v; want ErrNoCanonicalTime", der, err)
				}
			} else {
				if want := primitiveTime(form.number, form.der); err != nil || !bytes.Equal(der, want) {
					t.Fatalf("DER = %x, %v; want %x", der, err, want)
				}
				if err := ValidateDERElement(der); err != nil {
					t.Fatalf("DER validation: %v", err)
				}
			}
			if err := ValidateDERElement(wire); (err == nil) != (form.der == form.in) {
				t.Fatalf("DER validation of %q = %v", form.in, err)
			}

			// Constructed: decoded verbatim, marked for preservation, and
			// re-encoded primitive when the value is encoded on its own.
			constructed := constructedTime(form.number, form.in, 4)
			options = TrackBERForm(nil)
			text, n, encode, _, err = decodeTimeElement(form.number, constructed, options...)
			if err != nil || n != len(constructed) || text != form.in || !BERNeedsPreservation(options) {
				t.Fatalf("constructed decode = %q, %d, %v, preserve=%v", text, n, err, BERNeedsPreservation(options))
			}
			if ber, err := encode(); err != nil || !bytes.Equal(ber, wire) {
				t.Fatalf("constructed re-encode = %x, %v", ber, err)
			}
			if err := ValidateDERElement(constructed); err == nil {
				t.Fatal("constructed time accepted as DER")
			}
		})
	}
}

func TestTimeLexicalFormNeedsNoPreservation(t *testing.T) {
	for _, form := range berTimeForms {
		wire := primitiveTime(form.number, form.in)
		validated := TrackBERForm(nil)
		if err := ValidateBERElement(wire, validated...); err != nil || BERNeedsPreservation(validated) {
			t.Errorf("ValidateBERElement(%q) = %v, preserve=%v", form.in, err, BERNeedsPreservation(validated))
		}
	}
	implicit := TrackBERForm(nil)
	if _, err := DecodeImplicitGeneralizedTimeValue(false, []byte("19920722132100.30Z"), implicit...); err != nil || BERNeedsPreservation(implicit) {
		t.Fatalf("implicit primitive = %v, preserve=%v", err, BERNeedsPreservation(implicit))
	}
	_, _, contents, err := DecodeTLV(constructedTime(tag.TagUTCTime, "2601011200+0100", 5))
	if err != nil {
		t.Fatal(err)
	}
	implicit = TrackBERForm(nil)
	value, err := DecodeImplicitUTCTimeValue(true, contents, implicit...)
	if err != nil || value.String() != "2601011200+0100" || !BERNeedsPreservation(implicit) {
		t.Fatalf("implicit constructed = %q, %v, preserve=%v", value, err, BERNeedsPreservation(implicit))
	}
}

func TestTimeCodecErrors(t *testing.T) {
	if _, err := EncodeUTCTime(runtime.UTCTime{}); !errors.Is(err, ErrInvalidValue) || !errors.Is(err, runtime.ErrTimeNotSet) {
		t.Fatal(err)
	}
	if _, err := EncodeGeneralizedTime(runtime.GeneralizedTime{}); !errors.Is(err, ErrInvalidValue) || !errors.Is(err, runtime.ErrTimeNotSet) {
		t.Fatal(err)
	}
	if _, err := EncodeUTCTimeDER(runtime.UTCTime{}); !errors.Is(err, ErrInvalidValue) || !errors.Is(err, runtime.ErrTimeNotSet) {
		t.Fatal(err)
	}
	if _, err := EncodeGeneralizedTimeDER(runtime.GeneralizedTime{}); !errors.Is(err, ErrInvalidValue) || !errors.Is(err, runtime.ErrTimeNotSet) {
		t.Fatal(err)
	}
	for _, wire := range [][]byte{
		primitiveTime(tag.TagUTCTime, "260101120000"),            // §47.3 c): no zone
		primitiveTime(tag.TagGeneralizedTime, "20260101240000Z"), // §46.2 a): no midnight at the end of a day
	} {
		var err error
		if wire[0] == tag.TagUTCTime {
			_, _, err = DecodeUTCTime(wire)
		} else {
			_, _, err = DecodeGeneralizedTime(wire)
		}
		if !errors.Is(err, ErrInvalidValue) || !errors.Is(err, runtime.ErrTimeSyntax) {
			t.Errorf("%x: %v", wire, err)
		}
	}
}

// DER accepts only X.690 (02/2021) §11.7/§11.8 forms.
func TestValidateDERTimeForms(t *testing.T) {
	for _, c := range []struct {
		number int
		text   string
		valid  bool
	}{
		{tag.TagUTCTime, "920521000000Z", true},
		{tag.TagUTCTime, "500101000000Z", true},
		{tag.TagUTCTime, "491231235959Z", true},
		{tag.TagUTCTime, "920520240000Z", false}, // §11.8.5
		{tag.TagUTCTime, "9207221321Z", false},   // §11.8.5
		{tag.TagUTCTime, "920722132100+0000", false},
		{tag.TagUTCTime, "920722132100-0000", false},
		{tag.TagGeneralizedTime, "19920521000000Z", true},
		{tag.TagGeneralizedTime, "19920722132100.3Z", true},
		{tag.TagGeneralizedTime, "00000101000000Z", true},
		{tag.TagGeneralizedTime, "19920520240000Z", false},    // §11.7.5
		{tag.TagGeneralizedTime, "19920622123421.0Z", false},  // §11.7.3
		{tag.TagGeneralizedTime, "19920722132100.30Z", false}, // §11.7.3
		{tag.TagGeneralizedTime, "19920722132100,3Z", false},  // §11.7.4
		{tag.TagGeneralizedTime, "199207221321Z", false},      // §11.7.2
		{tag.TagGeneralizedTime, "19920722132100", false},     // §11.7.1
		{tag.TagGeneralizedTime, "19920722132100+0000", false},
		{tag.TagGeneralizedTime, "19920722132100.Z", false},
	} {
		err := ValidateDERElement(primitiveTime(c.number, c.text))
		if (err == nil) != c.valid {
			t.Errorf("%q: %v", c.text, err)
		}
		if err != nil && !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%q: %v does not wrap ErrInvalidValue", c.text, err)
		}
	}
}

func checkBERTimeElement(t *testing.T, number int, data []byte) {
	t.Helper()
	options := TrackBERForm(nil)
	text, n, encode, encodeDER, err := decodeTimeElement(number, data, options...)
	if err != nil {
		return
	}
	element := data[:n]
	ber, err := encode()
	if err != nil {
		t.Fatalf("%x: decoded %q but BER encode failed: %v", element, text, err)
	}
	if !BERNeedsPreservation(options) {
		if !bytes.Equal(ber, element) {
			t.Fatalf("%x: BER re-encode %x is not byte-exact", element, ber)
		}
	} else if !bytes.Equal(ber, primitiveTime(number, text)) {
		t.Fatalf("%x: BER re-encode %x does not carry %q", element, ber, text)
	}
	der, derErr := encodeDER()
	derValid := ValidateDERElement(element) == nil
	if derErr != nil {
		if !errors.Is(derErr, ErrInvalidValue) || !errors.Is(derErr, runtime.ErrNoCanonicalTime) || derValid {
			t.Fatalf("%x: DER encode of %q: %v (input DER-valid=%v)", element, text, derErr, derValid)
		}
		return
	}
	if err := ValidateDERElement(der); err != nil {
		t.Fatalf("%x: DER encode %x invalid: %v", element, der, err)
	}
	if derValid && !bytes.Equal(der, element) {
		t.Fatalf("%x: valid DER re-encoded as %x", element, der)
	}
	derText, _, _, _, err := decodeTimeElement(number, der)
	if err != nil {
		t.Fatalf("%x: DER %x does not decode: %v", element, der, err)
	}
	if number == tag.TagUTCTime {
		a, errA := mustUTCTime(text).Time()
		b, errB := mustUTCTime(derText).Time()
		if errA != nil || errB != nil || !a.Equal(b) {
			t.Fatalf("%q: DER %q is a different instant", text, derText)
		}
	} else {
		a, errA := mustGeneralizedTime(text).Time()
		b, errB := mustGeneralizedTime(derText).Time()
		if errA != nil || errB != nil || !a.Equal(b) {
			t.Fatalf("%q: DER %q is a different instant", text, derText)
		}
	}
}

// FuzzBERTimeRoundTrip checks, for any input, that a decoded time
// re-encodes byte-exact through BER (or carries the same text when the
// received element needs preservation), and that DER either produces a
// valid canonical element with the same instant or fails with
// ErrNoCanonicalTime.
func FuzzBERTimeRoundTrip(f *testing.F) {
	for _, form := range berTimeForms {
		f.Add(primitiveTime(form.number, form.in))
		f.Add(constructedTime(form.number, form.in, 3))
		if form.der != "" {
			f.Add(primitiveTime(form.number, form.der))
		}
	}
	f.Add([]byte{0x17, 0x81, 0x0d, '9', '9', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z'})
	f.Add([]byte{0x38, 0x80, 0x04, 0x02, '2', '0', 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		checkBERTimeElement(t, tag.TagUTCTime, data)
		checkBERTimeElement(t, tag.TagGeneralizedTime, data)
	})
}
