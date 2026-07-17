// Command mutation_targets assigns Go production sources to one exact native
// build configuration and emits deterministic, non-empty mutation-test shards.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

type matrixCell struct {
	Name       string `json:"name"`
	Owner      string `json:"owner"`
	Runner     string `json:"runner"`
	CgoEnabled string `json:"cgo_enabled"`
	ShardIndex int    `json:"shard_index"`
	ShardCount int    `json:"shard_count"`
}

type githubMatrix struct {
	Include []matrixCell `json:"include"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mutation-targets", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "apps/launcher/internal/adapters", "production Go source root")
	emitMatrix := flags.Bool("emit-github-matrix", false, "emit the native GitHub Actions matrix")
	maximumFiles := flags.Int("max-files-per-shard", 8, "maximum source files assigned to one generated shard")
	ownerName := flags.String("owner", "", "exact generated build owner")
	shardIndex := flags.Int("shard-index", -1, "zero-based shard index")
	shardCount := flags.Int("shard-count", 0, "total shards for the selected owner")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *maximumFiles <= 0 {
		_, _ = fmt.Fprintln(stderr, "mutation target arguments are invalid")
		return 2
	}
	targets, err := classifyTargets(*root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mutation target classification failed: %v\n", err)
		return 1
	}
	if *emitMatrix {
		if *ownerName != "" || *shardIndex != -1 || *shardCount != 0 {
			_, _ = fmt.Fprintln(stderr, "matrix generation does not accept shard selection")
			return 2
		}
		matrix := buildMatrix(targets.ByOwner, *maximumFiles)
		if len(matrix.Include) == 0 {
			_, _ = fmt.Fprintln(stderr, "mutation target matrix is empty")
			return 1
		}
		encoded, err := json.Marshal(matrix)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "encode mutation matrix: %v\n", err)
			return 1
		}
		if _, err := fmt.Fprintln(stdout, string(encoded)); err != nil {
			return 1
		}
		return 0
	}
	if _, known := ownerByName(*ownerName); !known {
		_, _ = fmt.Fprintln(stderr, "mutation target owner is invalid")
		return 2
	}
	selected, err := selectShard(targets.ByOwner[*ownerName], *shardIndex, *shardCount)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mutation target selection failed: %v\n", err)
		return 1
	}
	for _, path := range selected {
		if _, err := fmt.Fprintln(stdout, path); err != nil {
			return 1
		}
	}
	return 0
}

func buildMatrix(filesByOwner map[string][]string, maximumFiles int) githubMatrix {
	matrix := githubMatrix{}
	for _, owner := range supportedBuildOwners {
		files := filesByOwner[owner.Name]
		if len(files) == 0 {
			continue
		}
		shardCount := (len(files) + maximumFiles - 1) / maximumFiles
		for index := 0; index < shardCount; index++ {
			cgoEnabled := "0"
			if owner.CgoEnabled {
				cgoEnabled = "1"
			}
			matrix.Include = append(matrix.Include, matrixCell{
				Name: fmt.Sprintf("%s-%02d", owner.Name, index), Owner: owner.Name,
				Runner: owner.Runner, CgoEnabled: cgoEnabled, ShardIndex: index, ShardCount: shardCount,
			})
		}
	}
	return matrix
}
