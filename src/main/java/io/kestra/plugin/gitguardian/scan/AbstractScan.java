package io.kestra.plugin.gitguardian.scan;

import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.AbstractGitGuardianTask;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.util.ArrayList;
import java.util.List;

/** Base for the tasks that scan inline content and internal storage files: the shared inputs and their loading. */
@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractScan extends AbstractGitGuardianTask {
    @Schema(title = "Inline content to scan", description = "Scanned as one document named after `filename`. Use `files` to scan files from internal storage instead of, or in addition to, inline content.")
    @PluginProperty(group = "main")
    protected Property<String> content;

    @Schema(title = "File name for the inline content", description = "Helps GitGuardian detectors that rely on file context (for example `.env` or `id_rsa`). Defaults to `content`.")
    @Builder.Default
    @PluginProperty(group = "main")
    protected Property<String> filename = Property.ofValue("content");

    @Schema(title = "Internal storage files to scan", description = "List of `kestra://` URIs, typically outputs of previous tasks. Each file is scanned as one document named after the last segment of its URI and must be at most 1 MB.")
    @PluginProperty(group = "main")
    protected Property<List<String>> files;

    /** Inline content first, then each file; fails on a file above {@code maxBytes} and when there is nothing to scan. */
    List<ScanFiles.File> inputs(RunContext runContext, int maxBytes) throws Exception {
        var inputs = new ArrayList<ScanFiles.File>();

        var rContent = runContext.render(content).as(String.class).orElse(null);
        if (rContent != null) {
            inputs.add(new ScanFiles.File(runContext.render(filename).as(String.class).orElse("content"), rContent));
        }
        for (var file : runContext.render(files).asList(String.class)) {
            inputs.add(ScanFiles.read(runContext, file, maxBytes));
        }
        if (inputs.isEmpty()) {
            throw new IllegalArgumentException("Nothing to scan: set content, files, or both.");
        }
        return inputs;
    }

    static int policyBreakCount(List<ScanResult> results) {
        return results.stream().mapToInt(result -> result.getPolicyBreakCount() != null ? result.getPolicyBreakCount() : 0).sum();
    }
}
