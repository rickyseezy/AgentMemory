package runtimeprovision

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func TestCatalogSignatureVerifierAuthenticatesExactCanonicalManifest(t *testing.T) {
	t.Parallel()
	manifest := catalogSignatureManifest(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := runtimecatalog.NewSignedManifest(
		manifest, manifest.SigningKeyID(), ed25519.Sign(private, manifest.CanonicalBytes()),
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCatalogSignatureVerifier(map[string]ed25519.PublicKey{manifest.SigningKeyID(): public})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyManifestSignature(t.Context(), signed); err != nil {
		t.Fatal(err)
	}
	copy(public, make([]byte, len(public)))
	if err := verifier.VerifyManifestSignature(t.Context(), signed); err != nil {
		t.Fatalf("verifier aliases caller key: %v", err)
	}
}

func TestCatalogSignatureVerifierRejectsUnknownInvalidAndCancelledAuthority(t *testing.T) {
	t.Parallel()
	manifest := catalogSignatureManifest(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, manifest.CanonicalBytes())
	signed, _ := runtimecatalog.NewSignedManifest(manifest, manifest.SigningKeyID(), signature)
	foreignPublic, _, _ := ed25519.GenerateKey(nil)
	unknown, _ := NewCatalogSignatureVerifier(map[string]ed25519.PublicKey{"foreign": foreignPublic})
	if err := unknown.VerifyManifestSignature(t.Context(), signed); !errors.Is(err, runtimecatalogapp.ErrUntrustedSigner) {
		t.Fatalf("unknown signer error=%v", err)
	}
	trusted, _ := NewCatalogSignatureVerifier(map[string]ed25519.PublicKey{manifest.SigningKeyID(): public})
	tampered := append([]byte(nil), signature...)
	tampered[0] ^= 0xff
	bad, _ := runtimecatalog.NewSignedManifest(manifest, manifest.SigningKeyID(), tampered)
	if err := trusted.VerifyManifestSignature(t.Context(), bad); !errors.Is(err, runtimecatalogapp.ErrSignatureInvalid) {
		t.Fatalf("tampered signature error=%v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := trusted.VerifyManifestSignature(cancelled, signed); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	if verifier, err := NewCatalogSignatureVerifier(nil); verifier != nil || err == nil {
		t.Fatalf("empty keys=(%v,%v)", verifier, err)
	}
}

func catalogSignatureManifest(t testing.TB) runtimecatalog.Manifest {
	t.Helper()
	manifest, err := runtimecatalog.DecodeManifestV1([]byte(catalogSignatureCanonical))
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

const catalogSignatureCanonical = `{"artifact":{"download_bytes":700000000,"expanded_bytes":2000000000,"offline_policy":"bundled","proxy_mode":"system_proxy","publisher":{"identity":"developer-id-application-docker-inc-9bnsxjn65r","package_identity":"com.docker.docker","signing_key_identity":"apple-developer-id-9bnsxjn65r","verification":"apple_developer_id_notarized"},"redistribution_permitted":true,"reserve_bytes":3000000000,"sha256":"f9b04f64ff588edfd7b2ca52274aeb1ded968431fdd4f2464ec58e76f5dd39e2","sources":[{"host":"desktop.docker.com","path_prefix":"/mac/main/arm64/","scheme":"https"}]},"capability_probes":["bind_read_only","compose_version","engine_api","linux_containers","local_endpoint","network_isolation","no_tcp_listener","security_mode","volume_persistence"],"catalog_id":"docker-desktop-macos-arm64","catalog_sequence":42,"desktop_execution":{"acquisition_safety_bytes":100000000,"artifact_file_name":"Docker.dmg","capability_policy_digest":"f02358660cb228481d25e3c8975847afae97368c66517da53f498405428a0e1b","compose_plugin_sha256":"f44dec9f62e513f27dc704cbabb52dc2016f6a630d8b3f77aac4697f6edd9bf3","docker_cli_sha256":"8a4c49635bb164e5d37e646b47e658a297f884ee30bd378d377f9cb1d5c2f589","minimum_available_memory":4000000000,"minimum_wsl_version":"","wsl_distribution_name":"","probe_contract_version":"1","probe_image":"docker.io/rickyseezy/agentmemory-runtime-probe@sha256:bdd2f88588818fcb0dcf6e15f70c690a529e2517d0e3261eb2f823e7ea58c042","probe_image_digest":"bdd2f88588818fcb0dcf6e15f70c690a529e2517d0e3261eb2f823e7ea58c042","rollback_headroom_bytes":200000000},"install":{"arguments":[{"kind":"literal","value":"install"},{"kind":"artifact_path","value":""},{"kind":"plan_digest","value":""}],"executable":"macos_installer","ownership_changes":["application:com.docker.docker","service:com.docker.backend"],"reboot_exit_codes":null,"rollback_strategy":"preserve_runtime","service_identity":"com.docker.backend","vendor_ui_mandatory":false},"platform":{"architecture":"arm64","distribution":"macos","edition":"desktop","maximum_build":25000,"maximum_os_version":"15.9.9","minimum_build":23000,"minimum_cpu_cores":4,"minimum_free_disk_bytes":32212254720,"minimum_memory_bytes":8589934592,"minimum_os_version":"14.0.0","operating_system":"macos","virtualization_required":true},"prerequisites":[{"feature_id":"","operation":"install_verified_package","package_ids":["com.docker.docker"],"repository_id":"","service_id":"","subordinate_id_count":0}],"runtime":{"channel":"stable","components":[{"name":"engine","version":"28.3.2"},{"name":"cli","version":"28.3.2"},{"name":"containerd","version":"1.7.27"},{"name":"buildx","version":"0.25.0"},{"name":"compose","version":"2.39.1"}],"compose_version":"2.39.1","product":"docker_desktop","version":"28.3.2"},"schema_version":1,"signing_key_id":"agentmemory-runtime-root-2026","support_expires_at":1814400000000000,"terms":{"digest":"8e0049eb64e55e33cc6efffe478472ac3ca4585d7e2b05bfedb76e59de97fbce","id":"docker-subscription-service-agreement","presentation":"agentmemory","url":{"host":"www.docker.com","path_prefix":"/legal/docker-subscription-service-agreement","scheme":"https"},"version":"2025.07.02"}}`
