// Code generated from ASN.1. DO NOT EDIT.

// Package x2ap contains generated APER codecs. Complete decoders accept and retain
// observed terminal padding bits for byte-exact re-encoding; newly constructed
// values emit zero terminal padding (ITU-T X.691 (02/2021) 11.1.3.1, 11.1.4).
//
// A named SEQUENCE OF or SET OF has a corresponding XxxComplete value. Its Value
// field is the list, and its private padding state survives complete decode and
// encode. MarshalAPERXxx and UnmarshalAPERXxx use that wrapper. The XxxTo and
// XxxFrom helpers operate on embedded values without a complete boundary.
// Open types keep their complete padding in the enclosing value; OCTET STRING
// CONTAINING a list uses the contained XxxComplete value.
package x2ap
