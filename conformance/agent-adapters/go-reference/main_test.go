package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestPF003ExternalGoAgentPassesFramedLiveConformance(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"capabilities":["agent.event.capture"],"challenge":"challenge-1","kind":"agent","manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","package_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","protocol":"1.0","schema_version":1}`)
	input := bytes.NewBuffer(make([]byte, 4, len(payload)+4))
	binary.BigEndian.PutUint32(input.Bytes(), uint32(len(payload))) // #nosec G115 -- static fixture.
	input.Write(payload)
	var output bytes.Buffer
	if err := run(input, &output); err != nil {
		t.Fatal(err)
	}
	header := output.Next(4)
	if len(header) != 4 || int(binary.BigEndian.Uint32(header)) != output.Len() {
		t.Fatal("response frame length did not bind payload")
	}
	var response map[string]any
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["challenge"] != "challenge-1" || response["status"] != "passed" || response["protocol"] != "1.0" {
		t.Fatal("adapter substituted conformance identity")
	}
}

func TestPF003ExternalGoAgentRejectsOversizedFrame(t *testing.T) {
	t.Parallel()
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, maximumFrame+1)
	if err := run(bytes.NewReader(header), &bytes.Buffer{}); err == nil {
		t.Fatal("oversized frame was accepted")
	}
}
