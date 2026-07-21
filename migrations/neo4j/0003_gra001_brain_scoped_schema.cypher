// agentmemory-neo4j-migration: 0003_gra001_brain_scoped_schema
CYPHER 25
CREATE CONSTRAINT am_graph_entity_identity IF NOT EXISTS
FOR (entity:GraphEntity)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_brain_identity IF NOT EXISTS
FOR (entity:Brain)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_project_identity IF NOT EXISTS
FOR (entity:Project)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_repository_identity IF NOT EXISTS
FOR (entity:Repository)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_checkout_identity IF NOT EXISTS
FOR (entity:Checkout)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_branch_identity IF NOT EXISTS
FOR (entity:Branch)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_commit_identity IF NOT EXISTS
FOR (entity:Commit)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_agent_identity IF NOT EXISTS
FOR (entity:Agent)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_session_identity IF NOT EXISTS
FOR (entity:Session)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_task_identity IF NOT EXISTS
FOR (entity:Task)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_turn_identity IF NOT EXISTS
FOR (entity:Turn)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_event_identity IF NOT EXISTS
FOR (entity:Event)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_artifact_identity IF NOT EXISTS
FOR (entity:Artifact)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_file_identity IF NOT EXISTS
FOR (entity:File)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_file_revision_identity IF NOT EXISTS
FOR (entity:FileRevision)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_symbol_identity IF NOT EXISTS
FOR (entity:Symbol)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_symbol_revision_identity IF NOT EXISTS
FOR (entity:SymbolRevision)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_package_identity IF NOT EXISTS
FOR (entity:Package)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_service_identity IF NOT EXISTS
FOR (entity:Service)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_endpoint_identity IF NOT EXISTS
FOR (entity:Endpoint)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_contract_identity IF NOT EXISTS
FOR (entity:Contract)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_dependency_identity IF NOT EXISTS
FOR (entity:Dependency)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_environment_identity IF NOT EXISTS
FOR (entity:Environment)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_memory_identity IF NOT EXISTS
FOR (entity:Memory)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_decision_identity IF NOT EXISTS
FOR (entity:Decision)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_constraint_identity IF NOT EXISTS
FOR (entity:Constraint)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_preference_identity IF NOT EXISTS
FOR (entity:Preference)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_procedure_identity IF NOT EXISTS
FOR (entity:Procedure)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_lesson_identity IF NOT EXISTS
FOR (entity:Lesson)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_failure_identity IF NOT EXISTS
FOR (entity:Failure)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_outcome_identity IF NOT EXISTS
FOR (entity:Outcome)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_assertion_identity IF NOT EXISTS
FOR (entity:Assertion)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_evidence_identity IF NOT EXISTS
FOR (entity:Evidence)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_contradiction_identity IF NOT EXISTS
FOR (entity:Contradiction)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_causal_hypothesis_identity IF NOT EXISTS
FOR (entity:CausalHypothesis)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_evaluation_identity IF NOT EXISTS
FOR (entity:Evaluation)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_procedure_revision_identity IF NOT EXISTS
FOR (entity:ProcedureRevision)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_deployment_identity IF NOT EXISTS
FOR (entity:Deployment)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_embedding_space_identity IF NOT EXISTS
FOR (entity:EmbeddingSpace)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_index_generation_identity IF NOT EXISTS
FOR (entity:IndexGeneration)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_vector_record_identity IF NOT EXISTS
FOR (entity:VectorRecord)
REQUIRE (entity.brain_id, entity.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_subject_of_identity IF NOT EXISTS
FOR ()-[relationship:SUBJECT_OF]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_object_of_identity IF NOT EXISTS
FOR ()-[relationship:OBJECT_OF]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_supported_by_identity IF NOT EXISTS
FOR ()-[relationship:SUPPORTED_BY]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_contradicted_by_identity IF NOT EXISTS
FOR ()-[relationship:CONTRADICTED_BY]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_invalidated_by_identity IF NOT EXISTS
FOR ()-[relationship:INVALIDATED_BY]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_calls_identity IF NOT EXISTS
FOR ()-[relationship:CALLS]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_imports_identity IF NOT EXISTS
FOR ()-[relationship:IMPORTS]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_consumes_identity IF NOT EXISTS
FOR ()-[relationship:CONSUMES]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_implements_identity IF NOT EXISTS
FOR ()-[relationship:IMPLEMENTS]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_depends_on_identity IF NOT EXISTS
FOR ()-[relationship:DEPENDS_ON]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_produces_identity IF NOT EXISTS
FOR ()-[relationship:PRODUCES]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
CREATE CONSTRAINT am_deployed_as_identity IF NOT EXISTS
FOR ()-[relationship:DEPLOYED_AS]-()
REQUIRE (relationship.brain_id, relationship.id) IS UNIQUE;

CYPHER 25
MERGE (schema:AgentMemorySchema {brain_id: 'installation', id: 'singleton'})
ON MATCH SET schema.version = '0003_gra001_brain_scoped_schema',
             schema.schema_version = 3,
             schema.community_property_guard = 'repository+startup_integrity',
             schema.required_node_properties = ['id', 'brain_id', 'entity_type', 'schema_version', 'created_at', 'recorded_from', 'recorded_to', 'classification'],
             schema.required_relationship_properties = ['id', 'brain_id', 'relationship_type', 'schema_version', 'created_at', 'recorded_from', 'recorded_to', 'classification'];
