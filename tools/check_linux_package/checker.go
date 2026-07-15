// Package main verifies the closed Linux native-package security contract.
package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	packageConfigPath = "packaging/linux/nfpm.yaml"
	policyPath        = "packaging/linux/polkit/com.rickyseezy.agentmemory.runtime-helper.policy"
	tmpfilesPath      = "packaging/linux/tmpfiles/agentmemory-runtime-helper.conf"
	postinstallPath   = "packaging/linux/scripts/postinstall.sh"
	preremovePath     = "packaging/linux/scripts/preremove.sh"

	helperPath = "/usr/libexec/agentmemory/agentmemory-runtime-helper"
)

var expectedPostinstall = `#!/bin/sh
set -eu

if command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create agentmemory-runtime-helper.conf
else
  install -d -m 0755 -o root -g root /var/lib/agentmemory
  install -d -m 0755 -o root -g root /var/lib/agentmemory/runtime-helper
fi

exit 0
`

var expectedPreremove = `#!/bin/sh
set -eu

# The helper state contains the machine receipt identity and rollback journals.
# Ordinary removal and upgrade must preserve it. An explicit product-level
# purge flow will remove it only after uninstall ownership is authenticated.
exit 0
`

var expectedPolicy = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
  "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>AgentMemory</vendor>
  <vendor_url>https://github.com/rickyseezy/AgentMemory</vendor_url>
  <action id="com.rickyseezy.agentmemory.runtime-helper">
    <description>Prepare AgentMemory's local container runtime</description>
    <message>Administrator approval is required to prepare AgentMemory's local container runtime for $(user).</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/libexec/agentmemory/agentmemory-runtime-helper</annotate>
    <annotate key="org.freedesktop.policykit.exec.argv1">--request-stdin</annotate>
  </action>
</policyconfig>
`

// Options identifies the repository whose package inputs are checked.
type Options struct {
	RepositoryRoot string
}

// Check validates every security-sensitive Linux package input.
func Check(options Options) []error {
	root := options.RepositoryRoot
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return []error{fmt.Errorf("resolve repository root: %w", err)}
	}

	checks := []struct {
		path     string
		validate func([]byte) error
	}{
		{packageConfigPath, validatePackageConfig},
		{policyPath, validatePolicy},
		{tmpfilesPath, validateTmpfiles},
		{postinstallPath, func(content []byte) error {
			return validateScript(content, expectedPostinstall)
		}},
		{preremovePath, func(content []byte) error {
			return validateScript(content, expectedPreremove)
		}},
	}

	violations := make([]error, 0)
	for _, check := range checks {
		path := filepath.Join(absRoot, filepath.FromSlash(check.path))
		content, readErr := readRegularFile(path)
		if readErr != nil {
			violations = append(violations, fmt.Errorf("%s: %w", check.path, readErr))
			continue
		}
		if validateErr := check.validate(content); validateErr != nil {
			violations = append(violations, fmt.Errorf("%s: %w", check.path, validateErr))
		}
	}

	for _, script := range []string{postinstallPath, preremovePath} {
		info, statErr := os.Lstat(filepath.Join(absRoot, filepath.FromSlash(script)))
		if statErr != nil {
			continue
		}
		// readRegularFile already reports non-regular objects. Symlink permission
		// bits are platform-defined (0777 on Linux and commonly 0755 on macOS),
		// so a second mode violation would make this closed checker depend on the
		// host used to execute it rather than the package contract.
		if !info.Mode().IsRegular() {
			continue
		}
		if info.Mode().Perm() != 0o755 {
			violations = append(violations, fmt.Errorf("%s: mode is %04o, want 0755", script, info.Mode().Perm()))
		}
	}

	sort.Slice(violations, func(i, j int) bool { return violations[i].Error() < violations[j].Error() })
	return violations
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("must be a regular file, got mode %s", info.Mode())
	}
	// #nosec G304 -- path is rooted beneath the repository and selected only from the closed constant list above.
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return content, nil
}

type packageConfig struct {
	Name          string                 `yaml:"name"`
	Arch          string                 `yaml:"arch"`
	Platform      string                 `yaml:"platform"`
	Version       string                 `yaml:"version"`
	VersionSchema string                 `yaml:"version_schema"`
	Release       string                 `yaml:"release"`
	Section       string                 `yaml:"section"`
	Priority      string                 `yaml:"priority"`
	Maintainer    string                 `yaml:"maintainer"`
	Description   string                 `yaml:"description"`
	Vendor        string                 `yaml:"vendor"`
	Homepage      string                 `yaml:"homepage"`
	License       string                 `yaml:"license"`
	Umask         int                    `yaml:"umask"`
	Scripts       packageScripts         `yaml:"scripts"`
	Contents      []packageContent       `yaml:"contents"`
	Overrides     map[string]packageDeps `yaml:"overrides"`
	RPM           packageRPM             `yaml:"rpm"`
	Deb           packageDeb             `yaml:"deb"`
}

type packageScripts struct {
	Postinstall string `yaml:"postinstall"`
	Preremove   string `yaml:"preremove"`
}

type packageContent struct {
	Source   string           `yaml:"src"`
	Target   string           `yaml:"dst"`
	Type     string           `yaml:"type,omitempty"`
	Expand   bool             `yaml:"expand,omitempty"`
	FileInfo *packageFileInfo `yaml:"file_info,omitempty"`
}

type packageFileInfo struct {
	Mode  int    `yaml:"mode"`
	Owner string `yaml:"owner"`
	Group string `yaml:"group"`
}

type packageDeps struct {
	Depends []string `yaml:"depends"`
}

type packageRPM struct {
	Compression string `yaml:"compression"`
	Group       string `yaml:"group"`
}

type packageDeb struct {
	Compression string `yaml:"compression"`
}

func validatePackageConfig(content []byte) error {
	var config packageConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(content)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return fmt.Errorf("decode strict nFPM YAML: %w", err)
	}

	wantScalars := map[string][2]string{
		"name":           {config.Name, "agentmemory"},
		"arch":           {config.Arch, "${AGENTMEMORY_PACKAGE_ARCH}"},
		"platform":       {config.Platform, "linux"},
		"version":        {config.Version, "${AGENTMEMORY_PACKAGE_VERSION}"},
		"version_schema": {config.VersionSchema, "semver"},
		"release":        {config.Release, "${AGENTMEMORY_PACKAGE_RELEASE}"},
		"section":        {config.Section, "utils"},
		"priority":       {config.Priority, "optional"},
		"vendor":         {config.Vendor, "AgentMemory"},
		"homepage":       {config.Homepage, "https://github.com/rickyseezy/AgentMemory"},
		"license":        {config.License, "Proprietary"},
	}
	for field, values := range wantScalars {
		if values[0] != values[1] {
			return fmt.Errorf("%s is %q, want %q", field, values[0], values[1])
		}
	}
	if config.Maintainer != "AgentMemory Authors <rickyseezy@users.noreply.github.com>" || config.Description == "" {
		return fmt.Errorf("maintainer identity and description must be the reviewed values")
	}
	if config.Umask != 0o022 {
		return fmt.Errorf("umask is %04o, want 0022", config.Umask)
	}
	if config.Scripts != (packageScripts{Postinstall: postinstallPath, Preremove: preremovePath}) {
		return fmt.Errorf("maintainer scripts are not the closed reviewed pair")
	}
	if config.RPM != (packageRPM{Compression: "zstd:19", Group: "Applications/System"}) {
		return fmt.Errorf("rpm settings are not the reviewed deterministic settings")
	}
	if config.Deb != (packageDeb{Compression: "xz"}) {
		return fmt.Errorf("debian settings are not the reviewed deterministic settings")
	}
	wantOverrides := map[string]packageDeps{
		"deb": {Depends: []string{"pkexec", "systemd"}},
		"rpm": {Depends: []string{"polkit", "systemd"}},
	}
	if !reflect.DeepEqual(config.Overrides, wantOverrides) {
		return fmt.Errorf("dependency overrides are %#v, want %#v", config.Overrides, wantOverrides)
	}
	return validatePackageContents(config.Contents)
}

func validatePackageContents(contents []packageContent) error {
	want := []packageContent{
		{Source: "${AGENTMEMORY_PACKAGE_STAGE}/agentmemory", Target: "/usr/libexec/agentmemory/agentmemory", Expand: true, FileInfo: executableRootFile()},
		{Source: "${AGENTMEMORY_PACKAGE_STAGE}/agentmemory-runtime-helper", Target: helperPath, Expand: true, FileInfo: executableRootFile()},
		{Source: "${AGENTMEMORY_PACKAGE_STAGE}/bundle/", Target: "/usr/libexec/agentmemory/resources/bundle", Type: "tree", Expand: true},
		{Source: "/usr/libexec/agentmemory/agentmemory", Target: "/usr/bin/agentmemory", Type: "symlink"},
		{Source: policyPath, Target: "/usr/share/polkit-1/actions/com.rickyseezy.agentmemory.runtime-helper.policy", FileInfo: readableRootFile()},
		{Source: tmpfilesPath, Target: "/usr/lib/tmpfiles.d/agentmemory-runtime-helper.conf", FileInfo: readableRootFile()},
		{Source: "README.md", Target: "/usr/share/doc/agentmemory/README.md", FileInfo: readableRootFile()},
	}
	if !reflect.DeepEqual(contents, want) {
		return fmt.Errorf("contents do not equal the closed seven-entry payload")
	}
	if contents[2].FileInfo != nil {
		return fmt.Errorf("bundle tree must preserve staged directory/file modes")
	}
	return nil
}

func executableRootFile() *packageFileInfo {
	return &packageFileInfo{Mode: 0o755, Owner: "root", Group: "root"}
}

func readableRootFile() *packageFileInfo {
	return &packageFileInfo{Mode: 0o644, Owner: "root", Group: "root"}
}

type policyConfig struct {
	XMLName   xml.Name       `xml:"policyconfig"`
	Vendor    string         `xml:"vendor"`
	VendorURL string         `xml:"vendor_url"`
	Actions   []policyAction `xml:"action"`
}

type policyAction struct {
	ID          string             `xml:"id,attr"`
	Description string             `xml:"description"`
	Message     string             `xml:"message"`
	Defaults    policyDefaults     `xml:"defaults"`
	Annotations []policyAnnotation `xml:"annotate"`
}

type policyDefaults struct {
	AllowAny      string `xml:"allow_any"`
	AllowInactive string `xml:"allow_inactive"`
	AllowActive   string `xml:"allow_active"`
}

type policyAnnotation struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

func validatePolicy(content []byte) error {
	var policy policyConfig
	if err := xml.Unmarshal(content, &policy); err != nil {
		return fmt.Errorf("decode policy XML: %w", err)
	}
	if policy.XMLName.Local != "policyconfig" || policy.Vendor != "AgentMemory" || policy.VendorURL != "https://github.com/rickyseezy/AgentMemory" {
		return fmt.Errorf("policy identity is not the reviewed AgentMemory identity")
	}
	if len(policy.Actions) != 1 {
		return fmt.Errorf("policy has %d actions, want exactly one", len(policy.Actions))
	}
	action := policy.Actions[0]
	if action.ID != "com.rickyseezy.agentmemory.runtime-helper" || action.Description == "" || action.Message == "" {
		return fmt.Errorf("policy action identity or user-facing text is invalid")
	}
	wantDefaults := policyDefaults{AllowAny: "no", AllowInactive: "auth_admin", AllowActive: "auth_admin"}
	if action.Defaults != wantDefaults {
		return fmt.Errorf("policy defaults are %#v, want %#v", action.Defaults, wantDefaults)
	}
	wantAnnotations := []policyAnnotation{
		{Key: "org.freedesktop.policykit.exec.path", Value: helperPath},
		{Key: "org.freedesktop.policykit.exec.argv1", Value: "--request-stdin"},
	}
	if !reflect.DeepEqual(action.Annotations, wantAnnotations) {
		return fmt.Errorf("policy annotations do not bind the exact helper and first argument")
	}
	// Polkit's XML grammar can gain additional directives whose semantics are
	// unknown to this release. Exact bytes make the reviewed action closed and
	// prevent an ignored-by-this-decoder element from widening authorization.
	if string(content) != expectedPolicy {
		return fmt.Errorf("policy differs from the exact reviewed closed action")
	}
	return nil
}

func validateTmpfiles(content []byte) error {
	want := "d /var/lib/agentmemory 0755 root root -\n" +
		"d /var/lib/agentmemory/runtime-helper 0755 root root -\n"
	if string(content) != want {
		return fmt.Errorf("tmpfiles contract must create only the two reviewed root-owned 0755 directories")
	}
	return nil
}

func validateScript(content []byte, want string) error {
	if string(content) != want {
		return fmt.Errorf("maintainer script differs from the reviewed fail-closed implementation")
	}
	return nil
}
