package observe

import (
	"fmt"
	"io"
	"sync"
)

// Logger writes one human-readable line per Event.
//
// Allowlist, not blocklist: Printf's format line names each Event field
// explicitly, and nothing else. There is no generic "dump headers" or
// "dump map" path. A blocklist approach (log everything except X) silently
// starts leaking the day an upstream response adds a new header or the
// request struct grows a field — this package never has that failure mode
// because it only ever knows how to print the fields Event already
// declares safe.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewLogger wraps w. w is typically os.Stdout or a log file; any io.Writer
// works.
func NewLogger(w io.Writer) *Logger {
	return &Logger{w: w}
}

// Record implements Recorder, so a Logger can be composed with other
// Recorders via Tee.
func (l *Logger) Record(e Event) {
	auth := "no"
	if e.Injected {
		auth = "yes"
	}

	errSuffix := ""
	if e.Error != "" {
		errSuffix = "  err=" + e.Error
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %-8s %-6s %s -> %d  %dms  %s auth=%s%s\n",
		e.At.Format("15:04:05"),
		e.Alias,
		e.Method,
		e.InPath,
		e.Status,
		e.DurationMS,
		humanBytes(e.RespBytes),
		auth,
		errSuffix,
	)
}

// Printf writes a lifecycle message (e.g. "listening on :8080") through the
// same writer and mutex as Record, so log lines never interleave mid-line.
func (l *Logger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, format, args...)
	if len(format) == 0 || format[len(format)-1] != '\n' {
		fmt.Fprintln(l.w)
	}
}

// humanBytes renders a byte count the way a person skimming a log wants to
// see it (e.g. "1.2kB"), never anything more precise than that — this is a
// display helper, not a size calculation other code depends on.
func humanBytes(n int64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%dB", n)
	case n < 1_000_000:
		return fmt.Sprintf("%.1fkB", float64(n)/1000)
	default:
		return fmt.Sprintf("%.1fMB", float64(n)/1_000_000)
	}
}

// Tee fans a single Event out to multiple Recorders, e.g. so the serve
// command can both log to stdout and keep an in-memory Ring for the
// /_proxy/requests endpoint. Nil entries are skipped, so callers can pass a
// Recorder that might be nil (e.g. "logging disabled") without a branch at
// the call site.
func Tee(recorders ...Recorder) Recorder {
	// Copy defensively: the caller's slice could be mutated after this call.
	rs := make([]Recorder, 0, len(recorders))
	for _, r := range recorders {
		if r != nil {
			rs = append(rs, r)
		}
	}
	return teeRecorder(rs)
}

type teeRecorder []Recorder

func (t teeRecorder) Record(e Event) {
	for _, r := range t {
		r.Record(e)
	}
}
