// Command go-reference is the second-language PRO-002 framed-stdio adapter.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"os"
)

const maxFrame = 8 * 1024 * 1024

type request struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  struct {
		OperationID string   `json:"operation_id"`
		ContentIDs  []string `json:"content_ids"`
		Payload     struct {
			Texts []string `json:"texts"`
		} `json:"payload"`
	} `json:"params"`
}

type item struct {
	ContentID string    `json:"content_id"`
	Vector    []float32 `json:"vector,omitempty"`
	Score     *float64  `json:"score,omitempty"`
}
type result struct {
	OperationID   string            `json:"operation_id"`
	ContentIDs    []string          `json:"content_ids"`
	Items         []item            `json:"items"`
	Dimensions    uint32            `json:"dimensions"`
	Usage         map[string]uint64 `json:"usage"`
	ModelRevision string            `json:"model_revision"`
}
type response struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Result  result `json:"result"`
}

func vector(text string) []float32 {
	digest := sha256.Sum256([]byte(text))
	values := make([]float32, 8)
	norm := float64(0)
	for index := range values {
		values[index] = (float32(digest[index]) - 127.5) / 127.5
		norm += float64(values[index] * values[index])
	}
	norm = math.Sqrt(norm)
	for index := range values {
		values[index] /= float32(norm)
	}
	return values
}

func handle(value request) response {
	items := make([]item, len(value.Params.ContentIDs))
	dimensions := uint32(0)
	for index, id := range value.Params.ContentIDs {
		items[index].ContentID = id
		text := ""
		if index < len(value.Params.Payload.Texts) {
			text = value.Params.Payload.Texts[index]
		}
		switch value.Method {
		case "embed_documents", "embed_queries", "probe":
			items[index].Vector = vector(text)
			dimensions = 8
		case "rerank":
			score := float64(len(text))
			items[index].Score = &score
		}
	}
	return response{"2.0", value.ID, result{value.Params.OperationID, value.Params.ContentIDs, items, dimensions, map[string]uint64{"input_tokens": 0, "output_tokens": 0, "billable_units": 0}, "agentmemory-reference-sha256-v1"}}
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	for {
		var length uint32
		if binary.Read(reader, binary.BigEndian, &length) != nil {
			return
		}
		if length == 0 || length > maxFrame {
			os.Exit(2)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			os.Exit(2)
		}
		var input request
		if json.Unmarshal(payload, &input) != nil {
			os.Exit(2)
		}
		output, err := json.Marshal(handle(input))
		if err != nil {
			os.Exit(2)
		}
		if len(output) > maxFrame {
			os.Exit(2)
		}
		_ = binary.Write(writer, binary.BigEndian, uint32(len(output))) //nolint:gosec // G115: checked against maxFrame immediately above.
		_, _ = writer.Write(output)
		_ = writer.Flush()
		if input.Method == "shutdown" {
			return
		}
	}
}
