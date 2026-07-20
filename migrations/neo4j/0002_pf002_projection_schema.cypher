// agentmemory-neo4j-migration: 0002_pf002_projection_schema
CYPHER 25
CREATE CONSTRAINT am_projection_generation_identity IF NOT EXISTS
FOR (generation:ProjectionGeneration)
REQUIRE (generation.brain_id, generation.projection_type, generation.generation_id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_projection_record_identity IF NOT EXISTS
FOR (record:ProjectionRecord)
REQUIRE (record.brain_id, record.projection_type, record.generation_id, record.stable_id) IS UNIQUE;

CYPHER 25
CREATE INDEX am_projection_record_lineage IF NOT EXISTS
FOR (record:ProjectionRecord)
ON (record.source_event_id, record.source_sequence);

CYPHER 25
MERGE (schema:AgentMemorySchema {brain_id: 'installation', id: 'singleton'})
ON MATCH SET schema.version = '0002_pf002_projection_schema',
             schema.schema_version = 2;
