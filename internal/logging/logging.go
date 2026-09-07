// Package logging builds the process-wide logger.
package logging

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

// New returns a logger writing to stderr. Structured output is line-delimited JSON, which is what
// log shippers want; the default is a human readable console format.
func New(debug, structured bool) zerolog.Logger {
	level := zerolog.InfoLevel
	if debug {
		level = zerolog.DebugLevel
	}

	if structured {
		return zerolog.New(os.Stderr).Level(level).With().Timestamp().Logger()
	}

	w := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}

	return zerolog.New(w).Level(level).With().Timestamp().Logger()
}
