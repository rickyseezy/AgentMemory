package runtimecatalog

import "sort"

// ArgumentTemplateInput declares one typed immutable installer argument.
type ArgumentTemplateInput struct {
	Kind  ArgumentKind
	Value string
}

// ArgumentTemplate is one closed installer argument slot.
type ArgumentTemplate struct {
	kind  ArgumentKind
	value string
}

// Kind returns the typed argument kind.
func (a ArgumentTemplate) Kind() ArgumentKind { return a.kind }

// Value returns the signed literal, or empty for a typed runtime placeholder.
func (a ArgumentTemplate) Value() string { return a.value }

func newArgumentTemplate(input ArgumentTemplateInput) (ArgumentTemplate, error) {
	if !input.Kind.valid() || input.Kind == ArgumentKindLiteral && !validSafeToken(input.Value, 512) ||
		input.Kind != ArgumentKindLiteral && input.Value != "" {
		return ArgumentTemplate{}, ErrManifestIntegrity
	}
	return ArgumentTemplate{kind: input.Kind, value: input.Value}, nil
}

// InstallerPolicyInput declares the only runtime installer invocation and compensation boundary.
type InstallerPolicyInput struct {
	Executable        InstallerExecutable
	Arguments         []ArgumentTemplateInput
	RebootExitCodes   []uint32
	ServiceIdentity   string
	RollbackStrategy  RollbackStrategy
	OwnershipChanges  []string
	VendorUIMandatory bool
}

// InstallerPolicy is immutable execution authority interpreted by a platform adapter.
type InstallerPolicy struct {
	executable        InstallerExecutable
	arguments         []ArgumentTemplate
	rebootExitCodes   []uint32
	serviceIdentity   string
	rollbackStrategy  RollbackStrategy
	ownershipChanges  []string
	vendorUIMandatory bool
}

func newInstallerPolicy(input InstallerPolicyInput, platform OSKind) (InstallerPolicy, error) {
	if !input.Executable.valid() || len(input.Arguments) == 0 || len(input.Arguments) > 64 ||
		!validIdentifier(input.ServiceIdentity) || !input.RollbackStrategy.valid() ||
		len(input.OwnershipChanges) == 0 || len(input.OwnershipChanges) > 64 ||
		len(input.RebootExitCodes) > 16 || !installerMatchesPlatform(input.Executable, platform) {
		return InstallerPolicy{}, ErrManifestIntegrity
	}
	arguments := make([]ArgumentTemplate, 0, len(input.Arguments))
	artifactPath := false
	planDigest := false
	for _, candidate := range input.Arguments {
		argument, err := newArgumentTemplate(candidate)
		if err != nil {
			return InstallerPolicy{}, ErrManifestIntegrity
		}
		if argument.kind == ArgumentKindArtifactPath {
			if artifactPath {
				return InstallerPolicy{}, ErrManifestIntegrity
			}
			artifactPath = true
		}
		if argument.kind == ArgumentKindPlanDigest {
			if planDigest {
				return InstallerPolicy{}, ErrManifestIntegrity
			}
			planDigest = true
		}
		arguments = append(arguments, argument)
	}
	if !artifactPath || !planDigest {
		return InstallerPolicy{}, ErrManifestIntegrity
	}
	rebootExitCodes := append([]uint32(nil), input.RebootExitCodes...)
	for index, code := range rebootExitCodes {
		if code == 0 || index > 0 && rebootExitCodes[index-1] >= code {
			return InstallerPolicy{}, ErrManifestIntegrity
		}
	}
	ownershipChanges := append([]string(nil), input.OwnershipChanges...)
	if !sort.StringsAreSorted(ownershipChanges) {
		return InstallerPolicy{}, ErrManifestIntegrity
	}
	for index, change := range ownershipChanges {
		if !validOwnershipChange(change) || index > 0 && ownershipChanges[index-1] == change {
			return InstallerPolicy{}, ErrManifestIntegrity
		}
	}
	return InstallerPolicy{
		executable: input.Executable, arguments: arguments, rebootExitCodes: rebootExitCodes,
		serviceIdentity: input.ServiceIdentity, rollbackStrategy: input.RollbackStrategy,
		ownershipChanges: ownershipChanges, vendorUIMandatory: input.VendorUIMandatory,
	}, nil
}

func installerMatchesPlatform(executable InstallerExecutable, platform OSKind) bool {
	switch platform {
	case OSKindMacOS:
		return executable == InstallerExecutableMacOSInstaller
	case OSKindWindows:
		return executable == InstallerExecutableWindowsHelper
	case OSKindLinux:
		return executable == InstallerExecutableAPT || executable == InstallerExecutableDNF ||
			executable == InstallerExecutableRootlessSetup
	default:
		return false
	}
}

// Executable returns the semantic installer capability.
func (p InstallerPolicy) Executable() InstallerExecutable { return p.executable }

// Arguments returns a defensive copy of the closed argument template.
func (p InstallerPolicy) Arguments() []ArgumentTemplate {
	return append([]ArgumentTemplate(nil), p.arguments...)
}

// RebootExitCodes returns sorted vendor codes that require verified continuation.
func (p InstallerPolicy) RebootExitCodes() []uint32 {
	return append([]uint32(nil), p.rebootExitCodes...)
}

// ServiceIdentity returns the exact installed service identity.
func (p InstallerPolicy) ServiceIdentity() string { return p.serviceIdentity }

// RollbackStrategy returns the maximum catalog-authorized compensation.
func (p InstallerPolicy) RollbackStrategy() RollbackStrategy { return p.rollbackStrategy }

// OwnershipChanges returns a defensive copy of declared host ownership changes.
func (p InstallerPolicy) OwnershipChanges() []string {
	return append([]string(nil), p.ownershipChanges...)
}

// VendorUIMandatory reports whether the vendor UI must remain in the flow.
func (p InstallerPolicy) VendorUIMandatory() bool { return p.vendorUIMandatory }

func (p InstallerPolicy) valid(platform OSKind) bool {
	arguments := make([]ArgumentTemplateInput, 0, len(p.arguments))
	for _, argument := range p.arguments {
		arguments = append(arguments, ArgumentTemplateInput{Kind: argument.kind, Value: argument.value})
	}
	validated, err := newInstallerPolicy(InstallerPolicyInput{
		Executable: p.executable, Arguments: arguments,
		RebootExitCodes: append([]uint32(nil), p.rebootExitCodes...),
		ServiceIdentity: p.serviceIdentity, RollbackStrategy: p.rollbackStrategy,
		OwnershipChanges:  append([]string(nil), p.ownershipChanges...),
		VendorUIMandatory: p.vendorUIMandatory,
	}, platform)
	return err == nil && len(validated.arguments) == len(p.arguments)
}

func validOwnershipChange(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	separator := -1
	for index, character := range value {
		if character == ':' {
			if separator >= 0 || index == 0 || index == len(value)-1 {
				return false
			}
			separator = index
			continue
		}
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return separator > 0
}

// PrerequisiteInput contains operation-specific typed fields. Fields not used
// by the selected operation must remain their zero value.
type PrerequisiteInput struct {
	Operation          PrerequisiteOperation
	FeatureID          string
	PackageIDs         []string
	RepositoryID       string
	ServiceID          string
	SubordinateIDCount uint32
}

// Prerequisite is one immutable semantic privilege operation.
type Prerequisite struct {
	operation          PrerequisiteOperation
	featureID          string
	packageIDs         []string
	repositoryID       string
	serviceID          string
	subordinateIDCount uint32
}

func newPrerequisite(input PrerequisiteInput) (Prerequisite, error) {
	if !input.Operation.valid() || len(input.PackageIDs) > 32 {
		return Prerequisite{}, ErrManifestIntegrity
	}
	packages := append([]string(nil), input.PackageIDs...)
	if !sort.StringsAreSorted(packages) {
		return Prerequisite{}, ErrManifestIntegrity
	}
	for index, packageID := range packages {
		if !validIdentifier(packageID) || index > 0 && packages[index-1] == packageID {
			return Prerequisite{}, ErrManifestIntegrity
		}
	}
	valid := false
	switch input.Operation {
	case PrerequisiteConfigureOfficialRepository:
		valid = validIdentifier(input.RepositoryID) && input.FeatureID == "" && len(packages) == 0 &&
			input.ServiceID == "" && input.SubordinateIDCount == 0
	case PrerequisiteEnableWSLFeature:
		valid = validIdentifier(input.FeatureID) && len(packages) == 0 && input.RepositoryID == "" &&
			input.ServiceID == "" && input.SubordinateIDCount == 0
	case PrerequisiteInstallVerifiedPackage, PrerequisiteInstallWSLKernelUpdate:
		valid = len(packages) > 0 && input.FeatureID == "" && input.RepositoryID == "" &&
			input.ServiceID == "" && input.SubordinateIDCount == 0
	case PrerequisiteConfigureSubordinateIDs:
		valid = input.SubordinateIDCount >= 65536 && input.FeatureID == "" && len(packages) == 0 &&
			input.RepositoryID == "" && input.ServiceID == ""
	case PrerequisiteEnableUserService:
		valid = validIdentifier(input.ServiceID) && input.FeatureID == "" && len(packages) == 0 &&
			input.RepositoryID == "" && input.SubordinateIDCount == 0
	default:
	}
	if !valid {
		return Prerequisite{}, ErrManifestIntegrity
	}
	return Prerequisite{
		operation: input.Operation, featureID: input.FeatureID, packageIDs: packages,
		repositoryID: input.RepositoryID, serviceID: input.ServiceID,
		subordinateIDCount: input.SubordinateIDCount,
	}, nil
}

// Operation returns the typed privilege operation.
func (p Prerequisite) Operation() PrerequisiteOperation { return p.operation }

// FeatureID returns the fixed Windows feature for its matching operation.
func (p Prerequisite) FeatureID() string { return p.featureID }

// PackageIDs returns the exact package identities for a package operation.
func (p Prerequisite) PackageIDs() []string { return append([]string(nil), p.packageIDs...) }

// RepositoryID returns the official repository identity for its matching operation.
func (p Prerequisite) RepositoryID() string { return p.repositoryID }

// ServiceID returns the user service identity for its matching operation.
func (p Prerequisite) ServiceID() string { return p.serviceID }

// SubordinateIDCount returns the required rootless ID allocation size.
func (p Prerequisite) SubordinateIDCount() uint32 { return p.subordinateIDCount }
