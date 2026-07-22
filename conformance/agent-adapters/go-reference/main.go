// Command go-reference-agent is an external-language PF-003 conformance adapter.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"

	adapter "github.com/rickyseezy/AgentMemory/sdk/go/adapter"
)

const maximumFrame = 64 * 1024

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}

func run(input io.Reader, output io.Writer) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(input, header); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header)
	if length == 0 || length > maximumFrame {
		return errors.New("probe frame length is invalid")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(input, payload); err != nil {
		return err
	}
	request, err := adapter.DecodeProbeRequest(payload)
	if err != nil {
		return err
	}
	response, err := json.Marshal(request.Response())
	if err != nil {
		return err
	}
	// Response is produced from one frame capped at maximumFrame and contains only echoed fields.
	binary.BigEndian.PutUint32(header, uint32(len(response))) // #nosec G115 -- bounded above.
	if _, err := output.Write(header); err != nil {
		return err
	}
	_, err = output.Write(response)
	return err
}
