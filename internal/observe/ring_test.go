package observe

import (
	"sync"
	"testing"
)

func TestRing_OrderingNewestFirst(t *testing.T) {
	r := NewRing(5)
	for i := 0; i < 3; i++ {
		r.Record(Event{Alias: string(rune('a' + i))})
	}
	got := r.Recent(3)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	want := []string{"c", "b", "a"}
	for i, e := range got {
		if e.Alias != want[i] {
			t.Errorf("Recent()[%d].Alias = %q, want %q", i, e.Alias, want[i])
		}
	}
}

func TestRing_WrapOverwritesOldestAndBumpsDropped(t *testing.T) {
	r := NewRing(3)
	for i := 0; i < 5; i++ { // 2 more than capacity
		r.Record(Event{Alias: string(rune('a' + i))})
	}

	if got := r.Dropped(); got != 2 {
		t.Errorf("Dropped() = %d, want 2", got)
	}
	if got := r.Len(); got != 3 {
		t.Errorf("Len() = %d, want 3", got)
	}

	got := r.Recent(10) // more than held
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	want := []string{"e", "d", "c"} // a, b were overwritten
	for i, e := range got {
		if e.Alias != want[i] {
			t.Errorf("Recent()[%d].Alias = %q, want %q", i, e.Alias, want[i])
		}
	}
}

func TestRing_SeqMonotonicAcrossWrap(t *testing.T) {
	r := NewRing(2)
	for i := 0; i < 5; i++ {
		r.Record(Event{})
	}
	got := r.Recent(2)
	// Newest first: seq 5, then seq 4.
	if got[0].Seq != 5 || got[1].Seq != 4 {
		t.Errorf("Recent() seqs = %d, %d; want 5, 4", got[0].Seq, got[1].Seq)
	}
}

func TestRing_RecentClamps(t *testing.T) {
	r := NewRing(10)
	for i := 0; i < 4; i++ {
		r.Record(Event{})
	}

	if got := r.Recent(0); len(got) != 4 {
		t.Errorf("Recent(0) len = %d, want 4 (all held)", len(got))
	}
	if got := r.Recent(-5); len(got) != 4 {
		t.Errorf("Recent(-5) len = %d, want 4 (all held)", len(got))
	}
	if got := r.Recent(1000); len(got) != 4 {
		t.Errorf("Recent(1000) len = %d, want 4 (all held)", len(got))
	}
	if got := r.Recent(2); len(got) != 2 {
		t.Errorf("Recent(2) len = %d, want 2", len(got))
	}
}

func TestRing_RecentReturnsCopy(t *testing.T) {
	r := NewRing(5)
	r.Record(Event{Alias: "original"})

	got := r.Recent(1)
	got[0].Alias = "mutated"

	again := r.Recent(1)
	if again[0].Alias != "original" {
		t.Errorf("stored event was mutated via returned slice: got %q, want %q", again[0].Alias, "original")
	}
}

func TestRing_ConcurrentRecord(t *testing.T) {
	const goroutines = 50
	const perGoroutine = 100
	r := NewRing(37) // odd capacity, smaller than total writes, to force wraps

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				r.Record(Event{Alias: "x"})
				r.Recent(5) // exercise concurrent reads too
				r.Dropped()
			}
		}()
	}
	wg.Wait()

	if got := r.Len(); got != 37 {
		t.Errorf("Len() = %d, want 37 (capacity, since total writes > capacity)", got)
	}
	totalWrites := uint64(goroutines * perGoroutine)
	wantDropped := totalWrites - 37
	if got := r.Dropped(); got != wantDropped {
		t.Errorf("Dropped() = %d, want %d", got, wantDropped)
	}
}

func TestNewRing_DefaultCapacity(t *testing.T) {
	r := NewRing(0)
	for i := 0; i < defaultCapacity+10; i++ {
		r.Record(Event{})
	}
	if got := r.Len(); got != defaultCapacity {
		t.Errorf("Len() = %d, want default capacity %d", got, defaultCapacity)
	}

	r2 := NewRing(-3)
	for i := 0; i < defaultCapacity+10; i++ {
		r2.Record(Event{})
	}
	if got := r2.Len(); got != defaultCapacity {
		t.Errorf("negative capacity: Len() = %d, want default capacity %d", got, defaultCapacity)
	}
}
