// Copyright 2022 OnMetal authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/go-logr/logr"
)

func NewLogger(w io.Writer, verbosity int) logr.Logger {
	return logr.New(NewSink(w, verbosity))
}

func NewSink(w io.Writer, verbosity int) logr.LogSink {
	return &sink{
		w:         w,
		verbosity: verbosity,
	}
}

type sink struct {
	w         io.Writer
	verbosity int

	prefix string
	values []interface{}
}

func (s sink) Init(info logr.RuntimeInfo) {}

func (s sink) Enabled(level int) bool {
	return s.verbosity >= level
}

var bold = color.New(color.Bold)

func (s sink) write(msg string, keysAndValues []interface{}, err error) {
	var sb strings.Builder
	if s.prefix != "" {
		_, _ = bold.Fprint(&sb, s.prefix)
		sb.WriteString(": ")
	}
	sb.WriteString(msg)

	if len(keysAndValues) > 0 || err != nil {
		_, _ = bold.Fprint(&sb, " |")
	}

	for i := 0; i < len(keysAndValues); i += 2 {
		k, v := keysAndValues[i], keysAndValues[i+1]
		sb.WriteString(" ")

		_, _ = bold.Fprintf(&sb, "%v", k)
		sb.WriteString(" = ")
		_, _ = fmt.Fprintf(&sb, "%v", v)
	}

	if err != nil {
		sb.WriteString(" error = ")
		_, _ = fmt.Fprintf(&sb, "%v", err)
	}
	_, _ = fmt.Fprintln(&sb)

	_, _ = fmt.Fprint(s.w, sb.String())
}

func (s sink) Info(level int, msg string, keysAndValues ...interface{}) {
	s.write(msg, keysAndValues, nil)
}

func (s sink) Error(err error, msg string, keysAndValues ...interface{}) {
	s.write(msg, keysAndValues, err)
}

func (s sink) WithValues(keysAndValues ...interface{}) logr.LogSink {
	newValues := make([]interface{}, len(s.values), len(s.values)+len(keysAndValues))
	copy(newValues, s.values)
	copy(newValues[len(s.values):], keysAndValues)
	s.values = newValues
	return &s
}

func (s sink) WithName(name string) logr.LogSink {
	if s.prefix == "" {
		s.prefix = name
	} else {
		s.prefix = fmt.Sprintf("%s.%s", s.prefix, name)
	}
	return s
}
