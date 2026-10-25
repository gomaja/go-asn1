// Code generated from the locked X2AP source closure. DO NOT EDIT.

// Package x2ap contains generated APER codecs. Complete decoders reject non-zero
// terminal padding and consume zero padding without retaining its bits or width
// (ITU-T X.691 (02/2021) §11.1.4). Encoders emit zero terminal padding, and
// unchanged decoded values can replay their received bytes exactly.
//
// An XxxComplete wrapper for a named SEQUENCE OF or SET OF stores the list in
// its Value field. MarshalAPERXxx and UnmarshalAPERXxx use that wrapper.
// Its private state records received framing for replay, not non-zero padding.
// Known open-type values are decoded as complete encodings (X.691 (02/2021)
// §11.2.1).
//
// Each type is an alias of its definition in an internal package, where its
// methods and fields are documented.
package x2ap
