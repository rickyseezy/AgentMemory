package io.agentmemory.container;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;

final class Neo4jSecret {
    private static final Path PASSWORD_FILE =
            Path.of("/run/secrets/agentmemory_neo4j_password");
    private static final int KEY_BYTES = 32;

    private Neo4jSecret() {}

    static Password readPassword() throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(
                PASSWORD_FILE, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile() || attributes.isSymbolicLink()
                || attributes.size() != KEY_BYTES) {
            throw new IOException("Neo4j password secret is invalid");
        }
        Set<OpenOption> options = Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        byte[] raw = new byte[KEY_BYTES];
        try (SeekableByteChannel channel = Files.newByteChannel(PASSWORD_FILE, options)) {
            ByteBuffer buffer = ByteBuffer.wrap(raw);
            while (buffer.hasRemaining() && channel.read(buffer) >= 0) {
                // Continue until the exact fixed-length value has been read.
            }
            if (buffer.hasRemaining() || channel.read(ByteBuffer.allocate(1)) != -1) {
                throw new IOException("Neo4j password secret length changed");
            }
        } catch (IOException error) {
            Arrays.fill(raw, (byte) 0);
            throw error;
        }
        boolean allZero = true;
        for (byte value : raw) {
            allZero &= value == 0;
        }
        if (allZero) {
            Arrays.fill(raw, (byte) 0);
            throw new IOException("Neo4j password secret is invalid");
        }
        String value = HexFormat.of().formatHex(raw);
        Arrays.fill(raw, (byte) 0);
        return new Password(value);
    }

    static final class Password implements AutoCloseable {
        private String value;

        Password(String value) {
            this.value = value;
        }

        String value() {
            if (value == null) {
                throw new IllegalStateException("password has been released");
            }
            return value;
        }

        @Override
        public void close() {
            value = null;
        }
    }
}
