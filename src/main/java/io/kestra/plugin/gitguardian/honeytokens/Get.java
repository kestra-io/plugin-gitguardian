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
    title = "Get a GitGuardian honeytoken",
    description = """
        Fetches one honeytoken by ID from `GET /v1/honeytokens/{id}`, without its value. Requires the \
        `honeytokens:read` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Fetch the honeytoken behind an event",
            full = true,
            code = """
                id: gitguardian_honeytoken_details
                namespace: company.security

                tasks:
                  - id: each_event
                    type: io.kestra.plugin.core.flow.Loop
                    values: "{{ trigger.events }}"
                    tasks:
                      - id: get
                        type: io.kestra.plugin.gitguardian.honeytokens.Get
                        apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                        honeytokenId: "{{ fromJson(item.value).honeytokenId }}"

                triggers:
                  - id: on_event
                    type: io.kestra.plugin.gitguardian.honeytokens.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                """
        )
    }
)
public class Get extends AbstractHoneytokenAction implements RunnableTask<Get.Output> {
    private static final String SCOPE = "honeytokens:read";

    @Override
    public Output run(RunContext runContext) throws Exception {
        var honeytoken = perform(runContext, "fetch", (client, path) -> client.get(path, null, SCOPE, Honeytoken.class));
        return Output.builder().honeytoken(honeytoken).build();
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "The honeytoken, without its value")
        private final Honeytoken honeytoken;
    }
}
