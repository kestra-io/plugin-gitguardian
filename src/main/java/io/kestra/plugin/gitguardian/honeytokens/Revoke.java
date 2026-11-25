package io.kestra.plugin.gitguardian.honeytokens;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Revoke a GitGuardian honeytoken",
    description = """
        Revokes an active or triggered honeytoken via `POST /v1/honeytokens/{id}/revoke` and closes its \
        events, for example when the environment it was placed in is decommissioned. Requires the \
        `honeytokens:write` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Revoke the honeytoken of a torn-down environment",
            full = true,
            code = """
                id: gitguardian_revoke_honeytoken
                namespace: company.security

                inputs:
                  - id: honeytoken_id
                    type: STRING

                tasks:
                  - id: revoke
                    type: io.kestra.plugin.gitguardian.honeytokens.Revoke
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    honeytokenId: "{{ inputs.honeytoken_id }}"
                """
        )
    }
)
public class Revoke extends AbstractHoneytokenAction implements RunnableTask<Revoke.Output> {
    private static final String SCOPE = "honeytokens:write";

    @Override
    public Output run(RunContext runContext) throws Exception {
        var honeytoken = perform(runContext, "revoke", (client, path) -> client.post("%s/revoke".formatted(path), null, SCOPE, Honeytoken.class));
        return Output.builder().honeytoken(honeytoken).build();
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The revoked honeytoken")
        private final Honeytoken honeytoken;
    }
}
