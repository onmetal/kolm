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
	l := &logger{
		w:         w,
		verbosity: verbosity,
	}
	return logr.New(l)
}

type logger struct {
	w         io.Writer
	verbosity int

	prefix string
	values []interface{}
}

func (l logger) Init(info logr.RuntimeInfo) {}

func (l logger) Enabled(level int) bool {
	return l.verbosity >= level
}

var bold = color.New(color.Bold)

func (l logger) write(msg string, keysAndValues []interface{}, err error) {
	var sb strings.Builder
	if l.prefix != "" {
		_, _ = bold.Fprint(&sb, l.prefix)
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

	_, _ = fmt.Fprint(l.w, sb.String())
}

func (l logger) Info(level int, msg string, keysAndValues ...interface{}) {
	l.write(msg, keysAndValues, nil)
}

func (l logger) Error(err error, msg string, keysAndValues ...interface{}) {
	l.write(msg, keysAndValues, err)
}

func (l logger) WithValues(keysAndValues ...interface{}) logr.LogSink {
	newValues := make([]interface{}, len(l.values), len(l.values)+len(keysAndValues))
	copy(newValues, l.values)
	copy(newValues[len(l.values):], keysAndValues)
	l.values = newValues
	return &l
}

func (l logger) WithName(name string) logr.LogSink {
	if l.prefix == "" {
		l.prefix = name
	} else {
		l.prefix = fmt.Sprintf("%s.%s", l.prefix, name)
	}
	return l
}
