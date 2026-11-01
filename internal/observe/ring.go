package observe

import "sync"

// defaultCapacity is used when a caller asks for a non-positive capacity.
// 200 events is enough history for a single debugging session without
// holding onto an unbounded amount of memory.
const defaultCapacity = 200

// Ring is a fixed-size, concurrency-safe history of recent Events. It
// implements Recorder so it can sit directly in the request path: Record
// never blocks on I/O and never grows the buffer, so it is safe to call from
// every request's hot path.
//
// Once the ring fills, the oldest Event is overwritten and Dropped is
// incremented, so a reader can tell the difference between "nothing else
// happened" and "history rolled off the end".
type Ring struct {
	mu      sync.Mutex
	buf     []Event
	next    int    // index the next Record will write to
	count   int    // number of valid entries currently held (<= len(buf))
	seq     uint64 // next Seq to assign
	dropped uint64
}

// NewRing creates a Ring that holds up to capacity events. A non-positive
// capacity falls back to defaultCapacity rather than producing a useless
// zero-size (or panicking) ring.
func NewRing(capacity int) *Ring {
	if capacity <= 0 {
		capacity = defaultCapacity
	}
	return &Ring{buf: make([]Event, capacity)}
}

// Record implements Recorder. It assigns the next monotonic Seq, stores a
// copy of the event, and overwrites the oldest slot once the ring is full.
func (r *Ring) Record(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.seq++
	e.Seq = r.seq

	if r.count == len(r.buf) {
		// Buffer is full: the slot we're about to overwrite held a real
		// event, so history just lost one entry.
		r.dropped++
	} else {
		r.count++
	}

	r.buf[r.next] = e
	r.next = (r.next + 1) % len(r.buf)
}

// Recent returns up to n events, newest-first. n <= 0 or n > the number of
// held events returns everything currently held. The returned slice is a
// fresh copy: callers can mutate it freely without affecting the ring.
func (r *Ring) Recent(n int) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	if n <= 0 || n > r.count {
		n = r.count
	}

	out := make([]Event, n)
	// r.next is the index that will be written next, so the newest entry
	// (if the ring has wrapped at least once) sits at r.next-1.
	idx := r.next - 1
	for i := 0; i < n; i++ {
		if idx < 0 {
			idx = len(r.buf) - 1
		}
		out[i] = r.buf[idx]
		idx--
	}
	return out
}

// Len reports how many events are currently held (<= capacity).
func (r *Ring) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// Dropped reports how many events have been overwritten by wraparound,
// so a reader knows the held history is incomplete and by how much.
func (r *Ring) Dropped() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}
