package releasefile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

func TestPF001PublishedReleaseSchemaMatchesCanonicalResourceContract(t *testing.T) {
	t.Parallel()
	schema := readSchema(t, "contracts/jsonschema/release-manifest/v1.json")
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
		string(releaseinventory.ResourceKindLauncher), string(releaseinventory.ResourceKindHelper),
		string(releaseinventory.ResourceKindComposeBundle), string(releaseinventory.ResourceKindOCIImage),
		string(releaseinventory.ResourceKindOCIIndex), string(releaseinventory.ResourceKindSchema),
		string(releaseinventory.ResourceKindMigration), string(releaseinventory.ResourceKindSetupUI),
		string(releaseinventory.ResourceKindVerifier), string(releaseinventory.ResourceKindModel),
		string(releaseinventory.ResourceKindTokenizer), string(releaseinventory.ResourceKindTemplate),
		string(releaseinventory.ResourceKindInstallPlanTemplate), string(releaseinventory.ResourceKindProductManifest),
		string(releaseinventory.ResourceKindOfflineComponent), string(releaseinventory.ResourceKindRuntimeCatalog),
		string(releaseinventory.ResourceKindRuntimeInstaller), string(releaseinventory.ResourceKindRuntimeDistribution),
		string(releaseinventory.ResourceKindCycloneDXSBOM), string(releaseinventory.ResourceKindSPDXSBOM),
		string(releaseinventory.ResourceKindProvenance), string(releaseinventory.ResourceKindLicense),
		string(releaseinventory.ResourceKindVulnerabilityReport),
	}
	wantPurposes := []string{
		string(releaseinventory.ResourcePurposeNativeLauncher), string(releaseinventory.ResourcePurposeNativeHelper),
		string(releaseinventory.ResourcePurposeComposeLock), string(releaseinventory.ResourcePurposeOCIPlatformManifest),
		string(releaseinventory.ResourcePurposeOCIIndex), string(releaseinventory.ResourcePurposeContractBundle),
		string(releaseinventory.ResourcePurposeMigrationSet), string(releaseinventory.ResourcePurposeSetupUI),
		string(releaseinventory.ResourcePurposeOfflineVerifier), string(releaseinventory.ResourcePurposeModelWeights),
		string(releaseinventory.ResourcePurposeTokenizer), string(releaseinventory.ResourcePurposePromptTemplate),
		string(releaseinventory.ResourcePurposeInstallPlanTemplate), string(releaseinventory.ResourcePurposeProductManifest),
		string(releaseinventory.ResourcePurposeOfflineComponent), string(releaseinventory.ResourcePurposeRuntimeCatalog),
		string(releaseinventory.ResourcePurposeRuntimeInstaller), string(releaseinventory.ResourcePurposeRuntimeDistribution),
		string(releaseinventory.ResourcePurposeCycloneDXSBOM), string(releaseinventory.ResourcePurposeSPDXSBOM),
		string(releaseinventory.ResourcePurposeSLSAProvenance), string(releaseinventory.ResourcePurposeLicenseEvaluation),
		string(releaseinventory.ResourcePurposeVulnerabilityReport),
	}
	wantMediaTypes := []string{
		releaseinventory.MediaTypeNativeExecutable, releaseinventory.MediaTypeComposeLock,
		releaseinventory.MediaTypeOCIManifest, releaseinventory.MediaTypeOCIIndex,
		releaseinventory.MediaTypeContractBundle, releaseinventory.MediaTypeMigrationSet,
		releaseinventory.MediaTypeSetupUI, releaseinventory.MediaTypeModelWeights,
		releaseinventory.MediaTypeTokenizer, releaseinventory.MediaTypePromptTemplate,
		releaseinventory.MediaTypeInstallPlanTemplate, releaseinventory.MediaTypeProductManifest,
		releaseinventory.MediaTypeOfflineComponent, releaseinventory.MediaTypeRuntimeCatalog,
		releaseinventory.MediaTypeRuntimeInstaller, releaseinventory.MediaTypeRuntimeDistribution,
		releaseinventory.MediaTypeCycloneDX, releaseinventory.MediaTypeSPDX,
		releaseinventory.MediaTypeSLSAProvenance, releaseinventory.MediaTypeLicenseEvaluation,
		releaseinventory.MediaTypeVulnerabilityEvaluation,
	}
	assertSchemaEnum(t, schemaObject(t, properties, "kind"), wantKinds)
	assertSchemaEnum(t, schemaObject(t, properties, "purpose"), wantPurposes)
	assertSchemaEnum(t, schemaObject(t, properties, "media_type"), wantMediaTypes)
}

func TestPF001PublishedPublicationSchemaMatchesClosedDomainVocabulary(t *testing.T) {
	t.Parallel()
	schema := readSchema(t, "contracts/jsonschema/release-publication/v1.json")
	definitions := schemaObject(t, schema, "$defs")
	artifact := schemaObject(t, definitions, "artifact")
	properties := schemaObject(t, artifact, "properties")
	assertSchemaEnum(t, schemaObject(t, properties, "format"), []string{
		string(releasepublication.FormatPKG), string(releasepublication.FormatMSI),
		string(releasepublication.FormatDEB), string(releasepublication.FormatRPM),
		string(releasepublication.FormatTarZstd),
	})
	assertSchemaEnum(t, schemaObject(t, properties, "kind"), []string{
		string(releasepublication.ArtifactKindNativePackage), string(releasepublication.ArtifactKindOfflineBundle),
	})
	assertSchemaEnum(t, schemaObject(t, properties, "native_publisher_policy"), []string{
		string(releasepublication.PublisherPolicyAppleNotarized),
		string(releasepublication.PublisherPolicyMicrosoftAuthenticode),
		string(releasepublication.PublisherPolicyLinuxPackage),
		string(releasepublication.PublisherPolicyManifestOnly),
	})
}

func readSchema(t *testing.T, relative string) map[string]any {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../../.."))
	// #nosec G304 -- relative is a closed test-owned schema path rooted at the repository.
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode release schema: %v", err)
	}
	return schema
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
