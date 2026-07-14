package releaseverifyadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	maximumEvidenceDocumentBytes = 16 * 1024 * 1024
	maximumEvidenceJSONDepth     = 64
)

var (
	errEvidenceMalformed    = errors.New("release evidence JSON is malformed")
	errEvidenceDuplicateKey = errors.New("release evidence JSON contains a duplicate key")
	errEvidenceUnknownField = errors.New("release evidence JSON contains an unknown field")
	errEvidenceNonCanonical = errors.New("release evidence JSON is not canonical")
	errEvidenceContent      = errors.New("release evidence content binding is invalid")
)

func adapterContextError(ctx context.Context) error {
	if adapterNil(ctx) {
		return application.ErrDependencyUnavailable
	}
	return ctx.Err()
}

// readEvidence reads one immutable resource without a network or command
// capability and rechecks its signed size and digest at the use boundary. This
// closes the digest-check/parse TOCTOU window.
func readEvidence(
	ctx context.Context,
	source ResourceContentSource,
	resource releaseinventory.Resource,
) ([]byte, error) {
	if err := adapterContextError(ctx); err != nil {
		return nil, err
	}
	if adapterNil(source) || resource.Size() == 0 || resource.Size() > maximumEvidenceDocumentBytes {
		return nil, errEvidenceContent
	}
	reader, err := source.OpenResource(ctx, resource)
	if err != nil {
		if contextError := adapterContextError(ctx); contextError != nil {
			return nil, contextError
		}
		return nil, errors.Join(application.ErrResourceUnavailable, err)
	}
	if adapterNil(reader) {
		return nil, application.ErrResourceUnavailable
	}

	//nolint:gosec // G115: resource.Size is bounded above by 16 MiB above.
	limited := io.LimitReader(reader, int64(resource.Size())+1)
	raw, readError := io.ReadAll(limited)
	closeError := reader.Close()
	if contextError := adapterContextError(ctx); contextError != nil {
		return nil, contextError
	}
	if readError != nil || closeError != nil {
		return nil, errors.Join(application.ErrResourceUnavailable, readError, closeError)
	}
	if uint64(len(raw)) != resource.Size() || sha256.Sum256(raw) != resource.Digest() {
		return nil, errEvidenceContent
	}
	return raw, nil
}

// decodeCanonicalJSON accepts only one bounded, duplicate-free object whose
// exact bytes equal the deterministic encoding of the understood schema.
func decodeCanonicalJSON(raw []byte, destination any) error {
	if len(raw) == 0 || len(raw) > maximumEvidenceDocumentBytes || adapterNil(destination) {
		return errEvidenceMalformed
	}
	if err := rejectDuplicateEvidenceKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return errEvidenceUnknownField
		}
		return errEvidenceMalformed
	}
	if err := requireEvidenceJSONEOF(decoder); err != nil {
		return err
	}
	canonical, err := json.Marshal(destination)
	if err != nil {
		return fmt.Errorf("%w: encode understood schema", errEvidenceMalformed)
	}
	if !bytes.Equal(raw, canonical) {
		return errEvidenceNonCanonical
	}
	return nil
}

func rejectDuplicateEvidenceKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanEvidenceJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireEvidenceJSONEOF(decoder)
}

func scanEvidenceJSONValue(decoder *json.Decoder, depth uint32) error {
	if depth > maximumEvidenceJSONDepth {
		return errEvidenceMalformed
	}
	token, err := decoder.Token()
	if err != nil {
		return errEvidenceMalformed
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyError := decoder.Token()
			if keyError != nil {
				return errEvidenceMalformed
			}
			key, ok := keyToken.(string)
			if !ok {
				return errEvidenceMalformed
			}
			if _, duplicate := seen[key]; duplicate {
				return errEvidenceDuplicateKey
			}
			seen[key] = struct{}{}
			if err := scanEvidenceJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim('}') {
			return errEvidenceMalformed
		}
	case '[':
		for decoder.More() {
			if err := scanEvidenceJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeError := decoder.Token()
		if closeError != nil || closing != json.Delim(']') {
			return errEvidenceMalformed
		}
	default:
		return errEvidenceMalformed
	}
	return nil
}

func requireEvidenceJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errEvidenceMalformed
}

func exactUniqueStrings(values []string, requireSorted bool) bool {
	seen := make(map[string]struct{}, len(values))
	previous := ""
	for index, value := range values {
		if value == "" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		if requireSorted && index > 0 && value <= previous {
			return false
		}
		seen[value] = struct{}{}
		previous = value
	}
	return true
}

func validSafeEvidenceText(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '\\' || character == '"' {
			return false
		}
	}
	return true
}
