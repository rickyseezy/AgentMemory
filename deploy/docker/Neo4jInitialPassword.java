package io.agentmemory.container;

import java.nio.file.Path;
import java.util.Arrays;
import org.neo4j.cli.AdminTool;
import org.neo4j.cli.ExecutionContext;

public final class Neo4jInitialPassword {
    private Neo4jInitialPassword() {}

    public static void main(String[] ignored) {
        int result = 1;
        String[] command = null;
        try (Neo4jSecret.Password password = Neo4jSecret.readPassword()) {
            command = new String[] {
                "dbms", "set-initial-password", password.value(),
                "--require-password-change=false"
            };
            ExecutionContext context = new ExecutionContext(
                    Path.of("/var/lib/neo4j"), Path.of("/var/lib/neo4j/conf"));
            result = AdminTool.execute(context, command);
        } catch (Exception error) {
            System.err.println("Neo4j initial credential setup failed");
        } finally {
            if (command != null) {
                Arrays.fill(command, null);
            }
        }
        if (result != 0) {
            System.exit(1);
        }
    }
}
