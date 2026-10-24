// Code generated from the locked X2AP source closure. DO NOT EDIT.

// Package x2ap contains generated APER codecs. Complete decoders accept and retain
// observed terminal padding bits for byte-exact re-encoding; newly constructed
// values emit zero terminal padding (ITU-T X.691 (02/2021) 11.1.4),
// as do edited values whose retained bits no longer fit their encoding.
//
// A named SEQUENCE OF or SET OF has a corresponding XxxComplete value. Its Value
// field is the list, and its private padding state survives complete decode and
// encode. MarshalAPERXxx and UnmarshalAPERXxx use that wrapper.
// Open types keep their complete padding in the enclosing value; OCTET STRING
// CONTAINING a list uses the contained XxxComplete value.
//
// Each type is an alias of its definition in an internal package, where its
// methods and fields are documented.
package x2ap
