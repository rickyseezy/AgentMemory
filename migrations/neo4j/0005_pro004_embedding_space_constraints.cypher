// PRO-004 global semantic identity and UUID-derived physical-name isolation.
CYPHER 25
CREATE CONSTRAINT am_embedding_space_brain_fingerprint IF NOT EXISTS
FOR (space:EmbeddingSpace)
REQUIRE (space.brain_id, space.immutable_fingerprint) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_index_generation_label IF NOT EXISTS
FOR (generation:IndexGeneration)
REQUIRE generation.generated_label IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_index_generation_vector_index IF NOT EXISTS
FOR (generation:IndexGeneration)
REQUIRE generation.vector_index_name IS UNIQUE;

CYPHER 25
MATCH (schema:AgentMemorySchema {brain_id: 'installation', id: 'singleton'})
WHERE schema.version = '0004_gra003_materialized_edge_indexes'
SET schema.version = '0005_pro004_embedding_space_constraints',
    schema.schema_version = 5,
    schema.updated_at = datetime()
RETURN schema.version;
