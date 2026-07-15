package releaseinventory

import "testing"

func TestPF001WindowsOfflineRuntimeResourcesAreDistinctAndFullyQualified(t *testing.T) {
	t.Parallel()
	platform := mustPlatform(t, "windows", "amd64")
	installerInput := fixtureSubjectInput(
		"wsl-msi", ResourceKindRuntimeInstaller, platform, digestText("wsl-msi"), 4096,
	)
	installerInput.CycloneDXSBOMResourceID = "wsl-msi-cyclonedx"
	installerInput.SPDXSBOMResourceID = "wsl-msi-spdx"
	installerInput.ProvenanceResourceID = "wsl-msi-provenance"
	installerInput.LicenseResourceID = "wsl-msi-license"
	installerInput.VulnerabilityResourceID = "wsl-msi-vulnerability"
	installer, err := NewResource(installerInput)
	if err != nil || installer.Purpose() != ResourcePurposeRuntimeInstaller ||
		installer.MediaType() != MediaTypeRuntimeInstaller || installer.NativePublisherIdentity() == "" {
		t.Fatalf("installer=%+v error=%v", installer, err)
	}
	distributionInput := fixtureSubjectInput(
		"ubuntu-wsl", ResourceKindRuntimeDistribution, platform, digestText("ubuntu-wsl"), 8192,
	)
	distributionInput.CycloneDXSBOMResourceID = "ubuntu-wsl-cyclonedx"
	distributionInput.SPDXSBOMResourceID = "ubuntu-wsl-spdx"
	distributionInput.ProvenanceResourceID = "ubuntu-wsl-provenance"
	distributionInput.LicenseResourceID = "ubuntu-wsl-license"
	distributionInput.VulnerabilityResourceID = "ubuntu-wsl-vulnerability"
	distribution, err := NewResource(distributionInput)
	if err != nil || distribution.Purpose() != ResourcePurposeRuntimeDistribution ||
		distribution.MediaType() != MediaTypeRuntimeDistribution || distribution.NativePublisherIdentity() != "" {
		t.Fatalf("distribution=%+v error=%v", distribution, err)
	}
	for name, mutate := range map[string]func(*ResourceInput){
		"installer missing publisher": func(input *ResourceInput) { input.NativePublisherIdentity = "" },
		"distribution publisher": func(input *ResourceInput) {
			input.NativePublisherIdentity = "microsoft.publisher"
			input.NativePublisherPolicyID = "microsoft-native"
		},
		"installer any platform": func(input *ResourceInput) { input.Platform = Platform{} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := installerInput
			if name == "distribution publisher" {
				candidate = distributionInput
			}
			mutate(&candidate)
			if resource, err := NewResource(candidate); err == nil || resource.ID() != "" {
				t.Fatalf("resource=%+v error=%v", resource, err)
			}
		})
	}
}
