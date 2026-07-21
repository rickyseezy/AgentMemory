# IDX-001 semantic code indexing runbook

## Healthy state

- Core reports Ready at relational head `0026_idx001_code_entities`.
- The Core image contains `/opt/agentmemory/grammars` as read-only files and sets
  `AGENTMEMORY_GRAMMAR_CACHE` to that directory.
- `scip --version` inside the Core image reports `0.9.0`.
- The installed language lock is `deploy/indexing-language-lock.v1.json`; its grammar revisions,
  query hashes, package versions, and platform bundle digests match the running release.
- A successful snapshot has one `FileRevision` per discovered source file. Recovered and failed
  files remain visible and do not prevent sibling files from committing.
- No `source_snapshots`, `source_files`, or semantic table contains an absolute host path or source
  content.

## Capture and index a repository snapshot

The local agent/MCP adapter resolves the current workspace to one authorized Brain, Project, and
Repository before indexing. It supplies a unique operation ID, optional commit ID, deterministic
working-tree digest, and UTC capture time to `IndexRepositorySnapshotCommand`. The workspace itself
is exposed through the installer-managed local mount; users do not configure Docker or parser
paths.

The source adapter ignores symlinks and standard VCS, dependency, cache, and build directories. It
fails closed if the workspace exceeds configured file/byte bounds or changes during capture. The
application creates the immutable snapshot before reading files, processes files in sorted relative
path order, and commits each file independently. Retry the same operation ID after an interrupted
response. Exact replay is safe; never invent a new operation ID to bypass a conflict.

Interpret file status as follows:

- `succeeded`: parser completed with no syntax error node;
- `recovered`: structure was emitted and `syntax_recovered` evidence records parser errors;
- `lexical_only`: valid UTF-8 has no certified semantic grammar and no symbols are fabricated;
- `failed`: binary/unsupported encoding, source limit, detector/descriptor failure, native parser
  crash, malformed parser output, or another content-free failure code.

Do not retry one deterministic syntax failure repeatedly. A parser crash may be retried once after
checking image health; the process pool replaces a failed worker automatically. Repeated crashes
for one language require collecting only the language, parser/grammar/query versions, file digest,
byte length, and failure code—never source text or the absolute path.

## Import precise SCIP evidence

Generate `index.scip` with a language-specific indexer outside AgentMemory. The local adapter passes
the bounded protobuf to the image-pinned SCIP CLI using fixed argv. The converter selects the exact
repository-relative document and emits normalized JSON for `ImportScipCommand`. The command also
requires the exact source bytes whose digest matches the existing `FileRevision`; a digest mismatch
is rejected before persistence.

Successful import appends SCIP symbols, definition revisions, references, imports, and
implementation relationships. It does not delete or rewrite Tree-sitter rows. Queries select the
highest compatible semantic priority while retaining both provenance sources. Retry the exact
import after an interrupted response; evidence identities make the append idempotent. Reject or
quarantine an index with duplicate keys, unknown fields, an unspecified position encoding, an
out-of-bounds range, a missing document, or output beyond the configured limit.

## Failure and recovery

- authorization failure: resolve a fresh current scope for the exact Project and Repository; never
  broaden to global scope as a workaround;
- immutable conflict: compare operation ID, commit/working digest, scope fingerprint, parser pins,
  and content digest; do not edit stored rows;
- grammar unavailable: the image is incomplete or its read-only grammar cache was not mounted from
  the image; reinstall the signed release rather than enabling network downloads;
- parser timeout/crash: preserve failure evidence, verify memory/CPU pressure, and retry once with
  the same operation;
- SCIP conversion failure: verify the producing indexer, pinned CLI version, document path, and
  explicit UTF position encoding;
- SQLite dependency failure: stop indexing, preserve the database, run integrity/foreign-key
  checks, and follow signed backup recovery before retrying.

Never update/delete append-only IDX-001 tables, disable immutable triggers, download grammars at
runtime, run an unpinned SCIP binary from `PATH`, persist temporary SCIP JSON, or include source,
absolute paths, parser stderr, credentials, SQL, or hidden reasoning in support bundles.
