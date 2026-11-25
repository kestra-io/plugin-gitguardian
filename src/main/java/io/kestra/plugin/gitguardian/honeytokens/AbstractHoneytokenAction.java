package io.kestra.plugin.gitguardian.honeytokens;

import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.AbstractGitGuardianTask;
import io.kestra.plugin.gitguardian.GitGuardianClient;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

/** Base for the tasks that fetch or change one existing honeytoken: renders `honeytokenId`, calls the API and guards an empty response. */
@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractHoneytokenAction extends AbstractGitGuardianTask {
    @Schema(title = "Honeytoken ID")
    @NotNull
    @PluginProperty(group = "main")
    protected Property<String> honeytokenId;

    @FunctionalInterface
    protected interface Call {
        Honeytoken execute(GitGuardianClient client, String honeytokenPath) throws Exception;
    }

    /** {@code action} is the infinitive used in messages, for example {@code revoke}. */
    protected Honeytoken perform(RunContext runContext, String action, Call call) throws Exception {
        var rId = runContext.render(honeytokenId).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("honeytokenId is required to %s a GitGuardian honeytoken.".formatted(action)));

        runContext.logger().info("Calling GitGuardian to {} honeytoken {}", action, rId);

        try (var client = client(runContext)) {
            var honeytoken = call.execute(client, "/honeytokens/%s".formatted(GitGuardianClient.segment(rId)));
            if (honeytoken == null) {
                throw new IllegalStateException("Empty response from the GitGuardian API when trying to %s honeytoken %s.".formatted(action, rId));
            }
            return honeytoken;
        }
    }
}
