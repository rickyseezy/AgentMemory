package releasepublication

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
)

func TestPF001PublishedPublicationSchemaMatchesClosedDomainVocabulary(t *testing.T) {
	t.Parallel()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../../.."))
	raw, err := os.ReadFile(filepath.Join(root, "contracts/jsonschema/release-publication/v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode publication schema: %v", err)
	}
	definitions := publicationSchemaObject(t, schema, "$defs")
	artifact := publicationSchemaObject(t, definitions, "artifact")
	properties := publicationSchemaObject(t, artifact, "properties")
	assertPublicationSchemaEnum(t, publicationSchemaObject(t, properties, "format"), []string{
		string(FormatPKG), string(FormatMSI), string(FormatDEB), string(FormatRPM), string(FormatTarZstd),
	})
	assertPublicationSchemaEnum(t, publicationSchemaObject(t, properties, "kind"), []string{
		string(ArtifactKindNativePackage), string(ArtifactKindOfflineBundle),
	})
	assertPublicationSchemaEnum(t, publicationSchemaObject(t, properties, "native_publisher_policy"), []string{
		string(PublisherPolicyAppleNotarized), string(PublisherPolicyMicrosoftAuthenticode),
		string(PublisherPolicyLinuxPackage), string(PublisherPolicyManifestOnly),
	})
}

func assertPublicationSchemaEnum(t *testing.T, schema map[string]any, expected []string) {
	t.Helper()
	values, ok := schema["enum"].([]any)
	if !ok {
		t.Fatal("schema enum is not an array")
	}
	actual := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatal("schema enum contains a non-string")
		}
		actual = append(actual, text)
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("schema enum=%v, want %v", actual, expected)
	}
}

func publicationSchemaObject(t *testing.T, parent map[string]any, field string) map[string]any {
	t.Helper()
	value, ok := parent[field].(map[string]any)
	if !ok {
		t.Fatalf("schema field %q is not an object", field)
	}
	return value
}
