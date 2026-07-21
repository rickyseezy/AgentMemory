// agentmemory-neo4j-migration: 0004_gra003_materialized_edge_indexes
CYPHER 25
CREATE INDEX am_calls_assertion_projection IF NOT EXISTS
FOR ()-[edge:CALLS]-()
ON (edge.brain_id, edge.assertion_id, edge.generation_id, edge.projection_status, edge.quarantined);

CYPHER 25
CREATE INDEX am_imports_assertion_projection IF NOT EXISTS
FOR ()-[edge:IMPORTS]-()
ON (edge.brain_id, edge.assertion_id, edge.generation_id, edge.projection_status, edge.quarantined);

CYPHER 25
CREATE INDEX am_consumes_assertion_projection IF NOT EXISTS
FOR ()-[edge:CONSUMES]-()
ON (edge.brain_id, edge.assertion_id, edge.generation_id, edge.projection_status, edge.quarantined);

CYPHER 25
CREATE INDEX am_implements_assertion_projection IF NOT EXISTS
FOR ()-[edge:IMPLEMENTS]-()
ON (edge.brain_id, edge.assertion_id, edge.generation_id, edge.projection_status, edge.quarantined);

CYPHER 25
CREATE INDEX am_depends_on_assertion_projection IF NOT EXISTS
FOR ()-[edge:DEPENDS_ON]-()
ON (edge.brain_id, edge.assertion_id, edge.generation_id, edge.projection_status, edge.quarantined);

CYPHER 25
CREATE INDEX am_produces_assertion_projection IF NOT EXISTS
FOR ()-[edge:PRODUCES]-()
ON (edge.brain_id, edge.assertion_id, edge.generation_id, edge.projection_status, edge.quarantined);

CYPHER 25
CREATE INDEX am_deployed_as_assertion_projection IF NOT EXISTS
FOR ()-[edge:DEPLOYED_AS]-()
ON (edge.brain_id, edge.assertion_id, edge.generation_id, edge.projection_status, edge.quarantined);

CYPHER 25
MATCH (schema:AgentMemorySchema {brain_id: 'installation', id: 'singleton'})
SET schema.version = '0004_gra003_materialized_edge_indexes',
    schema.schema_version = 4,
    schema.materialized_edge_guard = 'canonical_assertion+integrity_quarantine',
    schema.required_materialized_edge_properties = ['id', 'assertion_id', 'assertion_revision_id', 'revision_id', 'source_event_id', 'brain_id', 'project_id', 'repository_id', 'relationship_type', 'subject_id', 'object_id', 'classification', 'valid_from', 'valid_to', 'recorded_from', 'recorded_to', 'created_at', 'aggregate_version', 'projection_status', 'generation_id', 'schema_version', 'projected_at', 'content_fingerprint', 'projection_digest', 'quarantined'];
