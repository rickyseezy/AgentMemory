package releaseinventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
)

func TestPF001PublishedReleaseSchemaMatchesCanonicalResourceContract(t *testing.T) {
	t.Parallel()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../../.."))
	raw, err := os.ReadFile(filepath.Join(root, "contracts/jsonschema/release-manifest/v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode release schema: %v", err)
	}
	resource := schemaObject(t, schema, "$defs", "resource")
	required := schemaStrings(t, resource, "required")
	if !containsSchemaValue(required, "expanded_target") {
		t.Fatal("resource.required omits canonical expanded_target")
	}
	properties := schemaObject(t, resource, "properties")
	expanded := schemaObject(t, properties, "expanded_target")
	if reference, _ := expanded["$ref"].(string); reference != "#/$defs/expandedTarget" {
		t.Fatalf("expanded_target schema reference = %q", reference)
	}

	wantKinds := []string{
		string(ResourceKindLauncher), string(ResourceKindHelper), string(ResourceKindComposeBundle),
		string(ResourceKindOCIImage), string(ResourceKindOCIIndex), string(ResourceKindSchema),
		string(ResourceKindMigration), string(ResourceKindSetupUI), string(ResourceKindVerifier),
		string(ResourceKindModel), string(ResourceKindTokenizer), string(ResourceKindTemplate),
		string(ResourceKindInstallPlanTemplate), string(ResourceKindProductManifest),
		string(ResourceKindOfflineComponent), string(ResourceKindRuntimeCatalog),
		string(ResourceKindRuntimeInstaller), string(ResourceKindRuntimeDistribution),
		string(ResourceKindCycloneDXSBOM), string(ResourceKindSPDXSBOM),
		string(ResourceKindProvenance), string(ResourceKindLicense),
		string(ResourceKindVulnerabilityReport),
	}
	wantPurposes := []string{
		string(ResourcePurposeNativeLauncher), string(ResourcePurposeNativeHelper),
		string(ResourcePurposeComposeLock), string(ResourcePurposeOCIPlatformManifest),
		string(ResourcePurposeOCIIndex), string(ResourcePurposeContractBundle),
		string(ResourcePurposeMigrationSet), string(ResourcePurposeSetupUI),
		string(ResourcePurposeOfflineVerifier), string(ResourcePurposeModelWeights),
		string(ResourcePurposeTokenizer), string(ResourcePurposePromptTemplate),
		string(ResourcePurposeInstallPlanTemplate), string(ResourcePurposeProductManifest),
		string(ResourcePurposeOfflineComponent), string(ResourcePurposeRuntimeCatalog),
		string(ResourcePurposeRuntimeInstaller), string(ResourcePurposeRuntimeDistribution),
		string(ResourcePurposeCycloneDXSBOM), string(ResourcePurposeSPDXSBOM),
		string(ResourcePurposeSLSAProvenance), string(ResourcePurposeLicenseEvaluation),
		string(ResourcePurposeVulnerabilityReport),
	}
	wantMediaTypes := []string{
		MediaTypeNativeExecutable, MediaTypeComposeLock, MediaTypeOCIManifest, MediaTypeOCIIndex,
		MediaTypeContractBundle, MediaTypeMigrationSet, MediaTypeSetupUI, MediaTypeModelWeights,
		MediaTypeTokenizer, MediaTypePromptTemplate, MediaTypeInstallPlanTemplate,
		MediaTypeProductManifest, MediaTypeOfflineComponent, MediaTypeRuntimeCatalog,
		MediaTypeRuntimeInstaller, MediaTypeRuntimeDistribution, MediaTypeCycloneDX,
		MediaTypeSPDX, MediaTypeSLSAProvenance, MediaTypeLicenseEvaluation,
		MediaTypeVulnerabilityEvaluation,
	}
	assertSchemaEnum(t, schemaObject(t, properties, "kind"), wantKinds)
	assertSchemaEnum(t, schemaObject(t, properties, "purpose"), wantPurposes)
	assertSchemaEnum(t, schemaObject(t, properties, "media_type"), wantMediaTypes)
}

func assertSchemaEnum(t *testing.T, schema map[string]any, expected []string) {
	t.Helper()
	actual := schemaStrings(t, schema, "enum")
	sort.Strings(actual)
	sort.Strings(expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("schema enum = %v, want %v", actual, expected)
	}
}

func schemaObject(t *testing.T, parent map[string]any, path ...string) map[string]any {
	t.Helper()
	current := parent
	for _, field := range path {
		value, ok := current[field].(map[string]any)
		if !ok {
			t.Fatalf("schema field %q is not an object", field)
		}
		current = value
	}
	return current
}

func schemaStrings(t *testing.T, parent map[string]any, field string) []string {
	t.Helper()
	values, ok := parent[field].([]any)
	if !ok {
		t.Fatalf("schema field %q is not an array", field)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("schema field %q contains a non-string", field)
		}
		result = append(result, text)
	}
	return result
}

func containsSchemaValue(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
