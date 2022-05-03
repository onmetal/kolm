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
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/go-logr/logr"
)

var klogRegex = regexp.MustCompile(`^([A-Z])(\d*) (\d{2}:\d{2}:\d{2}\.\d{6})\s+(\d+)\s+([a-zA-Z.].*):(\d+)]\s(.*)$`)

type KLogEntry struct {
	LogLevel rune
	LogCode  int32
	Time     time.Time
	ThreadID int32
	Source   Source
	Message  string
}

type Source struct {
	Filename string
	Line     int32
}

func ParseKLogEntry(s string) (*KLogEntry, error) {
	match := klogRegex.FindStringSubmatch(s)
	if match == nil {
		return nil, fmt.Errorf("no klog string")
	}

	logLevel := match[1][0]

	logCode, err := strconv.ParseInt(match[2], 10, 32)
	if err != nil {
		return nil, err
	}

	t, err := time.Parse("15:04:05.000000", match[3])
	if err != nil {
		return nil, err
	}

	threadID, err := strconv.ParseInt(match[4], 10, 32)
	if err != nil {
		return nil, err
	}

	filename := match[5]

	line, err := strconv.ParseInt(match[6], 10, 32)
	if err != nil {
		return nil, err
	}

	msg := match[7]

	return &KLogEntry{
		LogLevel: int32(logLevel),
		LogCode:  int32(logCode),
		Time:     t,
		ThreadID: int32(threadID),
		Source: Source{
			Filename: filename,
			Line:     int32(line),
		},
		Message: msg,
	}, nil
}

type klogLogWriter struct {
	logger logr.Logger
}

func (w klogLogWriter) Write(p []byte) (n int, err error) {
	s := bufio.NewScanner(bytes.NewReader(p))
	for s.Scan() {
		line := s.Text()
		if entry, err := ParseKLogEntry(line); err == nil {
			w.logger.Info(entry.Message)
		} else {
			w.logger.Info(line)
		}
	}
	return len(p), nil
}

func NewKLogLogWriter(log logr.Logger) io.Writer {
	return &klogLogWriter{log}
}

type logWriter struct {
	logger logr.Logger
}

func (w logWriter) Write(p []byte) (n int, err error) {
	s := bufio.NewScanner(bytes.NewReader(p))
	for s.Scan() {
		line := s.Text()
		w.logger.Info(line)
	}
	return len(p), nil
}

func NewLogWriter(log logr.Logger) io.Writer {
	return logWriter{log}
}

type jsonLogWriter struct {
	logger logr.Logger
}

func NewJSONLogWriter(logger logr.Logger) io.Writer {
	return &jsonLogWriter{logger}
}

type JSONLogEntry struct {
	Ts     string
	Level  string
	Msg    string
	Caller string
	Error  string
	Values map[string]interface{}
}

func (j *JSONLogEntry) UnmarshalJSON(data []byte) error {
	type typedEntry struct {
		Ts     string `json:"ts"`
		Level  string `json:"level"`
		Msg    string `json:"msg"`
		Caller string `json:"caller,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	var e typedEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return err
	}

	var values map[string]interface{}
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}

	delete(values, "ts")
	delete(values, "level")
	delete(values, "msg")
	delete(values, "caller")
	delete(values, "error")

	*j = JSONLogEntry{
		Level:  e.Level,
		Msg:    e.Msg,
		Caller: e.Caller,
		Error:  e.Error,
		Values: values,
	}
	return nil
}

func (j *JSONLogEntry) MarshalJSON() ([]byte, error) {
	values := make(map[string]interface{}, len(j.Values)+4)
	for k, v := range j.Values {
		values[k] = v
	}
	values["ts"] = j.Ts
	values["level"] = j.Level
	values["msg"] = j.Msg
	values["caller"] = j.Caller
	values["error"] = j.Error
	return json.Marshal(values)
}

func (j *JSONLogEntry) KeysAndValues() []interface{} {
	if len(j.Values) == 0 {
		return nil
	}

	keys := make([]string, 0, len(j.Values))
	for k := range j.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	res := make([]interface{}, 0, len(j.Values))
	for _, k := range keys {
		res = append(res, k, j.Values[k])
	}
	return res
}

func (w jsonLogWriter) Write(p []byte) (n int, err error) {
	s := bufio.NewScanner(bytes.NewReader(p))
	for s.Scan() {
		line := s.Text()
		var entry JSONLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			if entry.Error != "" {
				w.logger.Error(errors.New(entry.Error), entry.Msg, entry.KeysAndValues()...)
			} else {
				w.logger.Info(entry.Msg, entry.KeysAndValues()...)
			}
		} else {
			w.logger.Info(line)
		}
	}
	return len(p), nil
}
