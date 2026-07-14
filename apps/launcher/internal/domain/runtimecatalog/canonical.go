package runtimecatalog

type canonicalManifest struct {
	Artifact         canonicalArtifact        `json:"artifact"`
	CapabilityProbes []CapabilityProbe        `json:"capability_probes"`
	CatalogID        string                   `json:"catalog_id"`
	CatalogSequence  uint64                   `json:"catalog_sequence"`
	Install          canonicalInstall         `json:"install"`
	LinuxExecution   *canonicalLinuxExecution `json:"linux_execution,omitempty"`
	Platform         canonicalPlatform        `json:"platform"`
	Prerequisites    []canonicalPrerequisite  `json:"prerequisites"`
	Runtime          canonicalRuntime         `json:"runtime"`
	SchemaVersion    uint32                   `json:"schema_version"`
	SigningKeyID     string                   `json:"signing_key_id"`
	SupportExpiresAt int64                    `json:"support_expires_at"`
	Terms            canonicalTerms           `json:"terms"`
}

type canonicalPlatform struct {
	Architecture           Architecture `json:"architecture"`
	Distribution           string       `json:"distribution"`
	Edition                string       `json:"edition"`
	MaximumBuild           uint64       `json:"maximum_build"`
	MaximumOSVersion       string       `json:"maximum_os_version"`
	MinimumBuild           uint64       `json:"minimum_build"`
	MinimumCPUCores        uint32       `json:"minimum_cpu_cores"`
	MinimumFreeDiskBytes   uint64       `json:"minimum_free_disk_bytes"`
	MinimumMemoryBytes     uint64       `json:"minimum_memory_bytes"`
	MinimumOSVersion       string       `json:"minimum_os_version"`
	OperatingSystem        OSKind       `json:"operating_system"`
	VirtualizationRequired bool         `json:"virtualization_required"`
}

type canonicalRuntime struct {
	Channel        RuntimeChannel              `json:"channel"`
	Components     []canonicalRuntimeComponent `json:"components"`
	ComposeVersion string                      `json:"compose_version"`
	Product        RuntimeProduct              `json:"product"`
	Version        string                      `json:"version"`
}

type canonicalRuntimeComponent struct {
	Name    ComponentName `json:"name"`
	Version string        `json:"version"`
}

type canonicalArtifact struct {
	DownloadBytes           uint64             `json:"download_bytes"`
	ExpandedBytes           uint64             `json:"expanded_bytes"`
	OfflinePolicy           OfflinePolicy      `json:"offline_policy"`
	ProxyMode               ProxyMode          `json:"proxy_mode"`
	Publisher               canonicalPublisher `json:"publisher"`
	RedistributionPermitted bool               `json:"redistribution_permitted"`
	ReserveBytes            uint64             `json:"reserve_bytes"`
	SHA256                  string             `json:"sha256"`
	Sources                 []canonicalSource  `json:"sources"`
}

type canonicalPublisher struct {
	Identity           string             `json:"identity"`
	PackageIdentity    string             `json:"package_identity"`
	SigningKeyIdentity string             `json:"signing_key_identity"`
	Verification       NativeVerification `json:"verification"`
}

type canonicalLinuxExecution struct {
	AcquisitionSafetyBytes    uint64                   `json:"acquisition_safety_bytes"`
	CapabilityPolicyDigest    string                   `json:"capability_policy_digest"`
	Codename                  string                   `json:"codename"`
	MinimumAvailableMemory    uint64                   `json:"minimum_available_memory"`
	MinimumKernel             string                   `json:"minimum_kernel"`
	PackageManager            LinuxPackageManager      `json:"package_manager"`
	PackageManagerVersion     string                   `json:"package_manager_version"`
	PackageSetDigest          string                   `json:"package_set_digest"`
	Packages                  []canonicalLinuxPackage  `json:"packages"`
	ProbeContractVersion      string                   `json:"probe_contract_version"`
	ProbeImage                string                   `json:"probe_image"`
	ProbeImageDigest          string                   `json:"probe_image_digest"`
	Repository                canonicalLinuxRepository `json:"repository"`
	RollbackHeadroomBytes     uint64                   `json:"rollback_headroom_bytes"`
	RootlessToolDigest        string                   `json:"rootless_tool_digest"`
	RootlessToolPath          string                   `json:"rootless_tool_path"`
	SELinuxEnforcingSupported bool                     `json:"selinux_enforcing_supported"`
	ServiceID                 string                   `json:"service_id"`
	ServiceUnitDigest         string                   `json:"service_unit_digest"`
	SubordinateIDCount        uint32                   `json:"subordinate_id_count"`
}

type canonicalLinuxRepository struct {
	Component             string          `json:"component"`
	ConfigurationDigest   string          `json:"configuration_digest"`
	ID                    string          `json:"id"`
	MetadataDigest        string          `json:"metadata_digest"`
	SigningKeyDigest      string          `json:"signing_key_digest"`
	SigningKeyFingerprint string          `json:"signing_key_fingerprint"`
	Suite                 string          `json:"suite"`
	URL                   canonicalSource `json:"url"`
}

type canonicalLinuxPackage struct {
	DownloadBytes uint64              `json:"download_bytes"`
	Name          string              `json:"name"`
	Purpose       LinuxPackagePurpose `json:"purpose"`
	ReceiptDigest string              `json:"receipt_digest"`
	SHA256        string              `json:"sha256"`
	Source        canonicalSource     `json:"source"`
	Version       string              `json:"version"`
}

type canonicalSource struct {
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix"`
	Scheme     string `json:"scheme"`
}

type canonicalInstall struct {
	Arguments         []canonicalArgument `json:"arguments"`
	Executable        InstallerExecutable `json:"executable"`
	OwnershipChanges  []string            `json:"ownership_changes"`
	RebootExitCodes   []uint32            `json:"reboot_exit_codes"`
	RollbackStrategy  RollbackStrategy    `json:"rollback_strategy"`
	ServiceIdentity   string              `json:"service_identity"`
	VendorUIMandatory bool                `json:"vendor_ui_mandatory"`
}

type canonicalArgument struct {
	Kind  ArgumentKind `json:"kind"`
	Value string       `json:"value"`
}

type canonicalPrerequisite struct {
	FeatureID          string                `json:"feature_id"`
	Operation          PrerequisiteOperation `json:"operation"`
	PackageIDs         []string              `json:"package_ids"`
	RepositoryID       string                `json:"repository_id"`
	ServiceID          string                `json:"service_id"`
	SubordinateIDCount uint32                `json:"subordinate_id_count"`
}

type canonicalTerms struct {
	Digest       string            `json:"digest"`
	ID           string            `json:"id"`
	Presentation TermsPresentation `json:"presentation"`
	URL          canonicalSource   `json:"url"`
	Version      string            `json:"version"`
}

func canonicalFromManifest(manifest Manifest) canonicalManifest {
	components := make([]canonicalRuntimeComponent, 0, len(manifest.runtime.components))
	for _, component := range manifest.runtime.components {
		components = append(components, canonicalRuntimeComponent{Name: component.name, Version: component.version})
	}
	sources := make([]canonicalSource, 0, len(manifest.artifact.sources))
	for _, source := range manifest.artifact.sources {
		sources = append(sources, canonicalSource{
			Host: source.host, PathPrefix: source.pathPrefix, Scheme: source.scheme,
		})
	}
	arguments := make([]canonicalArgument, 0, len(manifest.install.arguments))
	for _, argument := range manifest.install.arguments {
		arguments = append(arguments, canonicalArgument{Kind: argument.kind, Value: argument.value})
	}
	prerequisites := make([]canonicalPrerequisite, 0, len(manifest.prerequisites))
	for _, prerequisite := range manifest.prerequisites {
		prerequisites = append(prerequisites, canonicalPrerequisite{
			FeatureID: prerequisite.featureID, Operation: prerequisite.operation,
			PackageIDs:   append([]string(nil), prerequisite.packageIDs...),
			RepositoryID: prerequisite.repositoryID, ServiceID: prerequisite.serviceID,
			SubordinateIDCount: prerequisite.subordinateIDCount,
		})
	}
	var linuxExecution *canonicalLinuxExecution
	if manifest.linuxExecution != nil {
		packages := make([]canonicalLinuxPackage, 0, len(manifest.linuxExecution.packages))
		for _, pkg := range manifest.linuxExecution.packages {
			packages = append(packages, canonicalLinuxPackage{
				DownloadBytes: pkg.downloadBytes, Name: pkg.name, Purpose: pkg.purpose,
				ReceiptDigest: pkg.nativeReceiptDigest.Hex(), SHA256: pkg.sha256.Hex(),
				Source:  canonicalSource{Scheme: pkg.source.scheme, Host: pkg.source.host, PathPrefix: pkg.source.pathPrefix},
				Version: pkg.version,
			})
		}
		policy := manifest.linuxExecution
		linuxExecution = &canonicalLinuxExecution{
			AcquisitionSafetyBytes: policy.acquisitionSafetyBytes,
			CapabilityPolicyDigest: policy.capabilityPolicyDigest.Hex(), Codename: policy.codename,
			MinimumAvailableMemory: policy.minimumAvailableMemory, MinimumKernel: policy.minimumKernel,
			PackageManager: policy.packageManager, PackageManagerVersion: policy.packageManagerVersion,
			PackageSetDigest: policy.packageSetDigest.Hex(), Packages: packages,
			ProbeContractVersion: policy.probeContractVersion, ProbeImage: policy.probeImage,
			ProbeImageDigest: policy.probeImageDigest.Hex(),
			Repository: canonicalLinuxRepository{
				Component: policy.repository.component, ConfigurationDigest: policy.repository.configurationDigest.Hex(),
				ID: policy.repository.id, MetadataDigest: policy.repository.metadataDigest.Hex(),
				SigningKeyDigest:      policy.repository.signingKeyDigest.Hex(),
				SigningKeyFingerprint: policy.repository.signingKeyFingerprint, Suite: policy.repository.suite,
				URL: canonicalSource{Scheme: policy.repository.url.scheme, Host: policy.repository.url.host, PathPrefix: policy.repository.url.pathPrefix},
			},
			RollbackHeadroomBytes: policy.rollbackHeadroomBytes,
			RootlessToolDigest:    policy.rootlessToolDigest.Hex(), RootlessToolPath: policy.rootlessToolPath,
			SELinuxEnforcingSupported: policy.selinuxEnforcingSupported, ServiceID: policy.serviceID,
			ServiceUnitDigest: policy.serviceUnitDigest.Hex(), SubordinateIDCount: policy.subordinateIDCount,
		}
	}
	return canonicalManifest{
		Artifact: canonicalArtifact{
			DownloadBytes: manifest.artifact.downloadBytes, ExpandedBytes: manifest.artifact.expandedBytes,
			OfflinePolicy: manifest.artifact.offlinePolicy, ProxyMode: manifest.artifact.proxyMode,
			Publisher: canonicalPublisher{
				Identity:           manifest.artifact.publisher.identity,
				PackageIdentity:    manifest.artifact.publisher.packageIdentity,
				SigningKeyIdentity: manifest.artifact.publisher.signingKeyIdentity,
				Verification:       manifest.artifact.publisher.verification,
			},
			RedistributionPermitted: manifest.artifact.redistributionPermitted,
			ReserveBytes:            manifest.artifact.reserveBytes, SHA256: manifest.artifact.sha256.Hex(), Sources: sources,
		},
		CapabilityProbes: append([]CapabilityProbe(nil), manifest.capabilityProbes...),
		CatalogID:        manifest.catalogID,
		CatalogSequence:  manifest.sequence,
		Install: canonicalInstall{
			Arguments: arguments, Executable: manifest.install.executable,
			OwnershipChanges:  append([]string(nil), manifest.install.ownershipChanges...),
			RebootExitCodes:   append([]uint32(nil), manifest.install.rebootExitCodes...),
			RollbackStrategy:  manifest.install.rollbackStrategy,
			ServiceIdentity:   manifest.install.serviceIdentity,
			VendorUIMandatory: manifest.install.vendorUIMandatory,
		},
		LinuxExecution: linuxExecution,
		Platform: canonicalPlatform{
			Architecture: manifest.platform.architecture, Distribution: manifest.platform.distribution,
			Edition: manifest.platform.edition, MaximumBuild: manifest.platform.maximumBuild,
			MaximumOSVersion: manifest.platform.maximumOSVersion, MinimumBuild: manifest.platform.minimumBuild,
			MinimumCPUCores:        manifest.platform.minimumCPUCores,
			MinimumFreeDiskBytes:   manifest.platform.minimumFreeDiskBytes,
			MinimumMemoryBytes:     manifest.platform.minimumMemoryBytes,
			MinimumOSVersion:       manifest.platform.minimumOSVersion,
			OperatingSystem:        manifest.platform.operatingSystem,
			VirtualizationRequired: manifest.platform.virtualizationRequired,
		},
		Prerequisites: prerequisites,
		Runtime: canonicalRuntime{
			Channel: manifest.runtime.channel, Components: components,
			ComposeVersion: manifest.runtime.composeVersion,
			Product:        manifest.runtime.product, Version: manifest.runtime.version,
		},
		SchemaVersion:    manifest.schemaVersion,
		SigningKeyID:     manifest.signingKeyID,
		SupportExpiresAt: manifest.supportExpiresAt.UnixMicro(),
		Terms: canonicalTerms{
			Digest: manifest.terms.digest.Hex(), ID: manifest.terms.id,
			Presentation: manifest.terms.presentation,
			URL: canonicalSource{
				Host: manifest.terms.url.host, PathPrefix: manifest.terms.url.pathPrefix,
				Scheme: manifest.terms.url.scheme,
			},
			Version: manifest.terms.version,
		},
	}
}
