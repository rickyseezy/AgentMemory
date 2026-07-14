package setuphttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
)

type sessionRequestDocument struct {
	ContractVersion uint8 `json:"contractVersion"`
}

type commandDocument struct {
	ContractVersion uint8  `json:"contractVersion"`
	Decision        string `json:"decision"`
	IdempotencyKey  string `json:"idempotencyKey"`
	PlanDigest      string `json:"planDigest"`
}

type sessionDocument struct {
	SessionToken string          `json:"sessionToken"`
	CSRFToken    string          `json:"csrfToken"`
	Snapshot     json.RawMessage `json:"snapshot"`
}

func readCanonicalBody(request *http.Request, target any) error {
	if request == nil || request.Body == nil || request.ContentLength < 0 ||
		request.ContentLength > maximumDynamicBytes {
		return errors.New("setup request body framing is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumDynamicBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumDynamicBytes || int64(len(body)) != request.ContentLength {
		return errors.New("setup request body is invalid")
	}
	if err := decodeCanonicalJSON(body, target); err != nil {
		return err
	}
	return nil
}

func decodeCanonicalJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > maximumDynamicBytes || target == nil {
		return errors.New("setup JSON bound is invalid")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return errors.New("setup JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("setup JSON has trailing data")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, data) {
		return errors.New("setup JSON is not canonical")
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	values := uint32(0)
	if err := consumeJSONValue(decoder, 0, &values); err != nil {
		return errors.New("setup JSON is ambiguous")
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return errors.New("setup JSON has trailing data")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth uint8, values *uint32) error {
	if depth > 16 || *values >= 256 {
		return errors.New("setup JSON complexity exceeds its bound")
	}
	*values++
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			key, ok := keyToken.(string)
			if keyError != nil || !ok || key == "" || len(key) > 64 {
				return errors.New("setup JSON object key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("setup JSON object key is duplicated")
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1, values); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim('}') {
			return errors.New("setup JSON object is incomplete")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1, values); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim(']') {
			return errors.New("setup JSON array is incomplete")
		}
	default:
		return errors.New("setup JSON delimiter is invalid")
	}
	return nil
}

func parseContentLengthValues(values []string, contentLength int64) error {
	if contentLength < 0 || contentLength > maximumDynamicBytes || len(values) > 1 {
		return errors.New("setup Content-Length is invalid")
	}
	if len(values) == 0 {
		return nil
	}
	value, err := strconv.ParseUint(values[0], 10, 32)
	if err != nil || strconv.FormatUint(value, 10) != values[0] || value > maximumDynamicBytes ||
		int64(value) != contentLength {
		return errors.New("setup Content-Length is invalid")
	}
	return nil
}

func parseAfter(value string) (uint64, error) {
	if value == "" || len(value) > 16 || len(value) > 1 && value[0] == '0' {
		return 0, errors.New("setup event cursor is invalid")
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value || parsed > setupprogressapp.MaximumSafeInteger {
		return 0, errors.New("setup event cursor is invalid")
	}
	return parsed, nil
}

func exactSingleHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && !strings.ContainsAny(returnValue, "\r\n")
}
