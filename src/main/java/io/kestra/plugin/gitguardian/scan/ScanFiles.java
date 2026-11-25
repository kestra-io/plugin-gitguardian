package io.kestra.plugin.gitguardian.scan;

import io.kestra.core.runners.RunContext;

import java.net.URI;
import java.nio.charset.StandardCharsets;

/** Loads internal storage files for the scan tasks, refusing anything over the size limit before buffering it all. */
final class ScanFiles {
    private ScanFiles() {
    }

    record File(String name, String body) {
    }

    static File read(RunContext runContext, String file, int maxBytes) throws Exception {
        var uri = URI.create(file);
        var name = fileName(uri);
        try (var inputStream = runContext.storage().getFile(uri)) {
            // One byte past the limit is enough to know the file is too large, without reading it whole.
            var bytes = inputStream.readNBytes(maxBytes + 1);
            if (bytes.length > maxBytes) {
                throw new IllegalArgumentException("File '%s' is larger than %d bytes, the limit for a single GitGuardian document. Split the content or scan a smaller file.".formatted(name, maxBytes));
            }
            return new File(name, new String(bytes, StandardCharsets.UTF_8));
        }
    }

    private static String fileName(URI uri) {
        var path = uri.getPath();
        if (path == null || path.isBlank()) {
            return "content";
        }
        var name = path.substring(path.lastIndexOf('/') + 1);
        return name.isBlank() ? "content" : name;
    }
}
