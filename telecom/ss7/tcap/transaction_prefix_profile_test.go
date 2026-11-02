package tcap

import (
	"encoding/hex"
	"errors"
	"testing"

	ber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// Q.773 (06/1997) §4.1.1 applies equally to a decoded transaction ID
// and to the leading IDs retained when decoding fails at the message.
func TestTransactionPrefixFieldProfile(t *testing.T) {
	for _, tc := range []struct {
		wire, path, otid, dtid string
		want                   error
	}{
		{"62820005488200010101", "begin", "", "", ber.ErrInvalidValue},
		{"62810448810101", "begin", "", "", ber.ErrInvalidValue},
		{"6582000a48820001014982000102", "continue", "", "", ber.ErrInvalidValue},
		{"62064881010202", "TCMessage", "", "", ber.ErrTruncated},
		{"6205488200010101", "begin.otid", "", "", ber.ErrInvalidValue},
		{"6282000348010101", "begin", "01", "", ber.ErrInvalidValue},
		{"7f1f0448810101", "TCMessage", "01", "", ber.ErrUnexpectedElement},
		{"64810449810101", "end", "", "", ber.ErrInvalidValue},
		{"67810449810101", "abort", "", "", ber.ErrInvalidValue},
		{"65810748010149810102", "continue", "01", "", ber.ErrInvalidValue},
	} {
		t.Run(tc.wire, func(t *testing.T) {
			data, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			for _, options := range [][]ber.DecodeOption{nil, ber.TrackTCAPForm(nil)} {
				var value TCMessage
				err = value.UnmarshalBER(data, options...)
				var de *DecodeError
				if !errors.As(err, &de) {
					t.Fatalf("no DecodeError: %v", err)
				}
				checkProfileSentinels(t, err, tc.want)
				otid, dtid := "", ""
				if de.Prefix.Otid != nil {
					otid = hex.EncodeToString([]byte(*de.Prefix.Otid))
				}
				if de.Prefix.Dtid != nil {
					dtid = hex.EncodeToString([]byte(*de.Prefix.Dtid))
				}
				if de.Path != tc.path || otid != tc.otid || dtid != tc.dtid {
					t.Errorf("path/prefix: %s %s/%s, want %s %s/%s", de.Path, otid, dtid, tc.path, tc.otid, tc.dtid)
				}
			}
			scanErr := ber.ValidateBERElement(data, ber.TrackTCAPForm(nil)...)
			want := tc.want
			if tc.want == ber.ErrUnexpectedElement {
				want = nil
			}
			checkProfileSentinels(t, scanErr, want)
			var profile *ber.ValidationError
			if want == ber.ErrInvalidValue && (!errors.As(scanErr, &profile) || profile.Path != tc.path) {
				t.Errorf("scan path: %+v want %s", profile, tc.path)
			}
		})
	}
}

func TestUnadmittedMessageClassProfile(t *testing.T) {
	for _, wire := range []string{"638103480101", "308103480101", "a28103480101", "e28103480101", "428103480101"} {
		t.Run(wire, func(t *testing.T) {
			data, err := hex.DecodeString(wire)
			if err != nil {
				t.Fatal(err)
			}
			var value TCMessage
			err = value.UnmarshalBER(data)
			var de *DecodeError
			if !errors.As(err, &de) {
				t.Fatalf("no DecodeError: %v", err)
			}
			want := ber.ErrUnexpectedElement
			path := "TCMessage"
			if wire == "428103480101" {
				want = ber.ErrInvalidValue
				path = "begin"
			}
			checkProfileSentinels(t, err, want)
			otid := ""
			if de.Prefix.Otid != nil {
				otid = hex.EncodeToString([]byte(*de.Prefix.Otid))
			}
			expectedOtid := ""
			if wire == "638103480101" {
				expectedOtid = "01"
			}
			if otid != expectedOtid || de.Prefix.Dtid != nil {
				t.Errorf("prefix=%+v want OTID %s", de.Prefix, expectedOtid)
			}
			if de.Path != path {
				t.Errorf("path=%s want %s", de.Path, path)
			}
			scanErr := ber.ValidateBERElement(data, ber.TrackTCAPForm(nil)...)
			want = nil
			if wire == "428103480101" {
				want = ber.ErrInvalidValue
			}
			checkProfileSentinels(t, scanErr, want)
		})
	}
}

func checkProfileSentinels(t *testing.T, err, want error) {
	t.Helper()
	if (err == nil) != (want == nil) {
		t.Fatalf("got %v want %v", err, want)
	}
	for _, sentinel := range []error{ber.ErrTruncated, ber.ErrInvalidTag, ber.ErrUnexpectedElement, ber.ErrInvalidLength, ber.ErrIndefiniteLength, ber.ErrExtraData, ber.ErrInvalidValue, ber.ErrUnsupported, ber.ErrResourceLimit} {
		if errors.Is(err, sentinel) != (want == sentinel) {
			t.Errorf("%v: errors.Is(%v)=%t want %t", err, sentinel, errors.Is(err, sentinel), want == sentinel)
		}
	}
}
