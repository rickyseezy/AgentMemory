package io.agentmemory.container;

import java.util.concurrent.TimeUnit;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Config;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.Logging;
import org.neo4j.driver.Session;
import org.neo4j.driver.SessionConfig;

public final class Neo4jHealthcheck {
    private Neo4jHealthcheck() {}

    public static void main(String[] ignored) {
        try (Neo4jSecret.Password password = Neo4jSecret.readPassword()) {
            Config configuration = Config.builder()
                    .withConnectionTimeout(3, TimeUnit.SECONDS)
                    .withMaxConnectionPoolSize(1)
                    .withLogging(Logging.none())
                    .withTelemetryDisabled(true)
                    .build();
            try (Driver driver = GraphDatabase.driver(
                            "bolt://127.0.0.1:7687",
                            AuthTokens.basic("neo4j", password.value()),
                            configuration);
                    Session session = driver.session(SessionConfig.forDatabase("neo4j"))) {
                long ready = session.run("RETURN 1 AS ready").single().get("ready").asLong();
                if (ready != 1) {
                    throw new IllegalStateException("Neo4j readiness result is invalid");
                }
            }
        } catch (Exception error) {
            System.exit(1);
        }
    }
}
