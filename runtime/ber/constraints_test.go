package ber

import (
	"errors"
	"sync"
	"testing"
)

func TestConstraintTolerancePolicy(t *testing.T) {
	var strict *ConstraintError
	if err := CheckDecodedLength(nil, "field", "SIZE (1..3)", 4); !errors.As(err, &strict) {
		t.Fatalf("strict decode error = %v", err)
	}
	if strict.Path != "field" || strict.ObservedLength == nil || *strict.ObservedLength != 4 {
		t.Fatalf("strict decode violation = %+v", strict)
	}
	if err := CheckEncodedValue(nil, "field", "(1 | 3)", "2"); !errors.As(err, &strict) {
		t.Fatalf("strict encode error = %v", err)
	}
	var log ViolationLog
	option := WithConstraintTolerance(&log)
	child := ChildDecodeOptions([]DecodeOption{option}, "parent")
	if err := CheckDecodedValue(child, "field", "(1 | 3)", "2"); err != nil {
		t.Fatal(err)
	}
	reports := log.Snapshot()
	if len(reports) != 1 || reports[0].Path != "parent.field" || reports[0].ObservedValue != "2" {
		t.Fatalf("tolerant reports = %+v", reports)
	}
	if err := CheckEncodedValue([]EncodeOption{option}, "field", "(1 | 3)", "2"); err != nil {
		t.Fatal(err)
	}
	if err := CheckDecodedValue([]DecodeOption{WithConstraintTolerance(nil)}, "field", "(1 | 3)", "2"); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil report destination error = %v", err)
	}
	reports[0].Path = "altered"
	if log.Snapshot()[0].Path != "parent.field" {
		t.Fatal("snapshot exposes mutable log storage")
	}
	if err := ValidateEncodeOptions(option, option); err == nil {
		t.Fatal("accepted duplicate tolerance option")
	}
}

func TestConstraintToleranceSharedLog(t *testing.T) {
	var log ViolationLog
	option := WithConstraintTolerance(&log)
	const workers, reportsPerWorker = 32, 1000
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := 0; i < reportsPerWorker; i++ {
				if err := CheckDecodedLength([]DecodeOption{option}, "field", "SIZE (1)", 2); err != nil {
					t.Errorf("tolerant decode: %v", err)
					return
				}
			}
		}()
	}
	group.Wait()
	if got := len(log.Snapshot()); got != workers*reportsPerWorker {
		t.Fatalf("reports = %d, want %d", got, workers*reportsPerWorker)
	}
}

func TestViolationLogSnapshotOwnsObservedLengths(t *testing.T) {
	var log ViolationLog
	if err := CheckDecodedLength([]DecodeOption{WithConstraintTolerance(&log)}, "field", "SIZE (1)", 2); err != nil {
		t.Fatal(err)
	}
	snapshot := log.Snapshot()
	if len(snapshot) != 1 || snapshot[0].ObservedLength == nil {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	*snapshot[0].ObservedLength = 99
	if got := *log.Snapshot()[0].ObservedLength; got != 2 {
		t.Fatalf("snapshot changed log length to %d", got)
	}
	*log.records[0].ObservedLength = 3
	if got := *snapshot[0].ObservedLength; got != 99 {
		t.Fatalf("log changed snapshot length to %d", got)
	}
}

func TestViolationLogSnapshotConcurrentMutation(t *testing.T) {
	var log ViolationLog
	if err := CheckDecodedLength([]DecodeOption{WithConstraintTolerance(&log)}, "field", "SIZE (1)", 2); err != nil {
		t.Fatal(err)
	}
	snapshot := log.Snapshot()
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		for i := 0; i < 1000; i++ {
			*snapshot[0].ObservedLength = i
		}
	}()
	go func() {
		defer group.Done()
		for i := 0; i < 1000; i++ {
			_ = log.Snapshot()[0].ObservedLength
		}
	}()
	group.Wait()
}
