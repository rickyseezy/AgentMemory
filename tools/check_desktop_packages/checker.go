// Package main verifies the exact reviewed macOS and Windows package inputs.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	darwinDistributionAMD64Path = "packaging/darwin/distribution-amd64.xml"
	darwinDistributionARM64Path = "packaging/darwin/distribution-arm64.xml"
	darwinDistributionPath      = darwinDistributionAMD64Path
	darwinLauncherEntitlements  = "packaging/darwin/launcher.entitlements"
	darwinHelperEntitlements    = "packaging/darwin/runtime-helper.entitlements"
	darwinPostinstallPath       = "packaging/darwin/scripts/postinstall"
	darwinSignScriptPath        = "packaging/darwin/sign-binaries.sh"
	darwinBuildScriptPath       = "packaging/darwin/build-package.sh"
	windowsPackagePath          = "packaging/windows/Package.wxs"
	windowsSignScriptPath       = "packaging/windows/Sign-Binaries.ps1"
	windowsBuildScriptPath      = "packaging/windows/Build-Package.ps1"
)

type packageContract struct {
	mode   os.FileMode
	sha256 string
}

var reviewedPackageContracts = map[string]packageContract{
	darwinDistributionAMD64Path: {mode: 0o644, sha256: "5f2c10d126e4bf799e11ec413938c528f8d7f419ed8c67abed3a4b65c90f9dd1"},
	darwinDistributionARM64Path: {mode: 0o644, sha256: "db76744298e0a803bb0e748d1f182fdc1babad7b7d15651010e83607950c4d8a"},
	darwinLauncherEntitlements:  {mode: 0o644, sha256: "c706e295c8d105efa39a488b2fb7da1256f5652721633b37da9077c1d9145e32"},
	darwinHelperEntitlements:    {mode: 0o644, sha256: "c706e295c8d105efa39a488b2fb7da1256f5652721633b37da9077c1d9145e32"},
	darwinPostinstallPath:       {mode: 0o755, sha256: "7e0e631bea327d71536ed6982c16ed2ceb28dada593c58af32b208260aac727f"},
	darwinSignScriptPath:        {mode: 0o755, sha256: "bc21c4911e7030f2faefe2a787c1b44a8d1dc4567dc83d914f9f2e3dd1637e0e"},
	darwinBuildScriptPath:       {mode: 0o755, sha256: "8c7dccf344de72fc65c0d27ab651b6ff001c6e03345262ce08add091501a207a"},
	windowsPackagePath:          {mode: 0o644, sha256: "d06bae68e41ae0431dbe47927597363b839e4348ccf80873d291b9ebd08d667b"},
	windowsSignScriptPath:       {mode: 0o644, sha256: "aa655147a54a29e5998a6aa17761c6c93cff80235aaa331e1e8525d6a0f75f13"},
	windowsBuildScriptPath:      {mode: 0o644, sha256: "061309740ce22c284525079b55a9dc7f1054b0e9bc6ff6d865504e1937620f7e"},
}

// Options identifies the repository whose package contracts are checked.
type Options struct{ RepositoryRoot string }

// Check rejects links, special files, mode drift, and every byte-level change
// to a security-reviewed package or signing definition.
func Check(options Options) []error {
	root := options.RepositoryRoot
	if root == "" {
		root = "."
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return []error{fmt.Errorf("resolve repository root: %w", err)}
	}
	violations := make([]error, 0)
	for path, contract := range reviewedPackageContracts {
		absolutePath := filepath.Join(absolute, filepath.FromSlash(path))
		info, statErr := os.Lstat(absolutePath)
		if statErr != nil {
			violations = append(violations, fmt.Errorf("%s: inspect: %w", path, statErr))
			continue
		}
		if !info.Mode().IsRegular() {
			violations = append(violations, fmt.Errorf("%s: must be a regular file, got %s", path, info.Mode()))
			continue
		}
		if info.Mode().Perm() != contract.mode {
			violations = append(violations, fmt.Errorf("%s: mode is %04o, want %04o", path, info.Mode().Perm(), contract.mode))
			continue
		}
		// #nosec G304 -- path is selected exclusively from the closed reviewed map above.
		content, readErr := os.ReadFile(absolutePath)
		if readErr != nil {
			violations = append(violations, fmt.Errorf("%s: read: %w", path, readErr))
			continue
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != contract.sha256 {
			violations = append(violations, fmt.Errorf("%s: content differs from the reviewed contract", path))
		}
	}
	sort.Slice(violations, func(i, j int) bool { return violations[i].Error() < violations[j].Error() })
	return violations
}

func packageContractFiles() map[string]os.FileMode {
	files := make(map[string]os.FileMode, len(reviewedPackageContracts))
	for path, contract := range reviewedPackageContracts {
		files[path] = contract.mode
	}
	return files
}
