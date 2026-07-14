// agentmemory-neo4j-migration: 0001_pf001_core_schema
CYPHER 25
CREATE CONSTRAINT am_schema_identity IF NOT EXISTS
FOR (schema:AgentMemorySchema)
REQUIRE (schema.brain_id, schema.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_vector_record_identity IF NOT EXISTS
FOR (record:VectorRecord)
REQUIRE (record.brain_id, record.id) IS UNIQUE;

CYPHER 25
CREATE VECTOR INDEX am_pf001_vectors IF NOT EXISTS
FOR (record:VectorRecord)
ON record.embedding
WITH [record.brain_id, record.generation_id, record.classification, record.status]
OPTIONS {indexConfig: {
  `vector.dimensions`: 1024,
  `vector.similarity_function`: 'cosine'
}};

CYPHER 25
MERGE (schema:AgentMemorySchema {brain_id: 'installation', id: 'singleton'})
ON CREATE SET schema.version = '0001_pf001_core_schema',
              schema.schema_version = 1,
              schema.entity_type = 'schema',
              schema.classification = 'internal',
              schema.created_at = datetime(),
              schema.recorded_from = datetime(),
              schema.recorded_to = null
ON MATCH SET schema.version = '0001_pf001_core_schema';
