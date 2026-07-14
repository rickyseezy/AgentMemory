// Package secretprojector implements the closed, one-shot protected-file
// projection helper used by the local production stack.
package secretprojector

import "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/composeplan"

const (
	inputRoot  = "/run/inputs"
	outputRoot = "/run/outputs"

	purposeCore       = "protected-core"
	purposeMigrate    = "protected-migrate"
	purposeNeo4j      = "protected-neo4j"
	purposeEmbedding  = "protected-embedding"
	purposeReranking  = "protected-reranking"
	purposeExtraction = "protected-extraction"

	projectedMode                 = uint32(0o400)
	maximumAttestationBytes       = uint64(64 * 1024)
	exactCryptographicSecretBytes = uint64(32)
)

type fileContract struct {
	name     string
	userID   uint32
	groupID  uint32
	maxBytes uint64
}

type volumeContract struct {
	purpose string
	files   []fileContract
}

func protected(name string, uid uint32, gid uint32) fileContract {
	maximum := exactCryptographicSecretBytes
	if name == composeplan.SecretEgressAttestation {
		maximum = maximumAttestationBytes
	}
	return fileContract{name: name, userID: uid, groupID: gid, maxBytes: maximum}
}

func defaultContract() []volumeContract {
	coreNames := []string{
		composeplan.SecretInstallationRootKey,
		composeplan.SecretAPICredential,
		composeplan.SecretAttestationHMACKey,
		composeplan.SecretNeo4jPassword,
		composeplan.SecretEmbeddingCapability,
		composeplan.SecretRerankingCapability,
		composeplan.SecretExtractionCapability,
		composeplan.SecretEgressAttestation,
	}
	coreFiles := make([]fileContract, 0, len(coreNames))
	for _, name := range coreNames {
		coreFiles = append(coreFiles, protected(name, 10_001, 10_001))
	}
	return []volumeContract{
		{purpose: purposeCore, files: coreFiles},
		{purpose: purposeMigrate, files: []fileContract{protected(composeplan.SecretNeo4jPassword, 10_001, 10_001)}},
		{purpose: purposeNeo4j, files: []fileContract{protected(composeplan.SecretNeo4jPassword, 7474, 7474)}},
		{purpose: purposeEmbedding, files: []fileContract{protected(composeplan.SecretEmbeddingCapability, 10_001, 10_001)}},
		{purpose: purposeReranking, files: []fileContract{protected(composeplan.SecretRerankingCapability, 10_001, 10_001)}},
		{purpose: purposeExtraction, files: []fileContract{protected(composeplan.SecretExtractionCapability, 10_001, 10_001)}},
	}
}

func inputPath(name string) string { return inputRoot + "/" + name }

func outputPath(purpose string) string { return outputRoot + "/" + purpose }
