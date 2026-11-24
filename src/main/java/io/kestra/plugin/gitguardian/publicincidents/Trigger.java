package io.kestra.plugin.gitguardian.publicincidents;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.TriggerOutput;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.AbstractIncidentTrigger;
import io.kestra.plugin.gitguardian.incidents.IncidentStatus;
import io.kestra.plugin.gitguardian.incidents.Severity;
import io.kestra.plugin.gitguardian.incidents.Validity;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Trigger a flow when GitGuardian Public Monitoring finds a leaked secret",
    description = """
        Polls `GET /v1/public-incidents/secrets` at `interval` and starts one execution per poll carrying the new (or \
        re-triggered) public incidents, oldest first, in `trigger.incidents`, at most `maxItemsPerPoll` (default 100) \
        at a time; the rest fire on the next polls. Same watermark \
        mechanics as the internal incidents trigger: state in the namespace KV store, baseline seeded on the first \
        poll without firing. Requires the `incidents:read` scope and a Public Monitoring subscription.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Escalate every valid public leak to the security channel",
            full = true,
            code = """
                id: gitguardian_public_leak_alert
                namespace: company.security

                tasks:
                  - id: each_incident
                    type: io.kestra.plugin.core.flow.Loop
                    values: "{{ trigger.incidents }}"
                    tasks:
                      - id: notify
                        type: io.kestra.plugin.slack.SlackIncomingWebhook
                        url: "{{ secret('SLACK_WEBHOOK') }}"
                        messageText: ":warning: Secret leaked publicly: {{ fromJson(item.value).incidentName }} ({{ fromJson(item.value).occurrencesCount }} occurrence(s)) {{ fromJson(item.value).gitguardianUrl }}"

                triggers:
                  - id: on_public_leak
                    type: io.kestra.plugin.gitguardian.publicincidents.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    interval: PT2M
                    validity: VALID
                """
        )
    }
)
public class Trigger extends AbstractIncidentTrigger<PublicIncident> implements TriggerOutput<Trigger.Output> {

    @Schema(title = "Only incidents in this status")
    @PluginProperty(group = "processing")
    private Property<IncidentStatus> status;

    @Schema(title = "Only incidents at this severity")
    @PluginProperty(group = "processing")
    private Property<Severity> severity;

    @Schema(title = "Only incidents with this secret validity")
    @PluginProperty(group = "processing")
    private Property<Validity> validity;

    @Schema(title = "Only incidents with this declarative secret status", description = "For example `not_declared` or `mine`.")
    @PluginProperty(group = "processing")
    private Property<String> declarativeSecretStatus;

    @Schema(title = "Only incidents from this detector group")
    @PluginProperty(group = "processing")
    private Property<String> detectorGroupName;

    @Schema(title = "Minimum risk score, from 0 to 100")
    @PluginProperty(group = "processing")
    private Property<@Min(0) @Max(100) Integer> riskScoreMin;

    @Override
    protected String path() {
        return "/public-incidents/secrets";
    }

    @Override
    protected String keyPrefix() {
        return "gitguardian_publicincidents";
    }

    @Override
    protected Class<PublicIncident> itemType() {
        return PublicIncident.class;
    }

    @Override
    protected Instant dateOf(PublicIncident incident) {
        return incident.getDate();
    }

    @Override
    protected String idOf(PublicIncident incident) {
        return String.valueOf(incident.getId());
    }

    @Override
    protected io.kestra.core.models.tasks.Output output(java.util.List<PublicIncident> batch) {
        return Output.builder().incidents(batch).count(batch.size()).build();
    }

    @Override
    protected Map<String, Object> filters(RunContext runContext) throws Exception {
        var filters = new LinkedHashMap<String, Object>();
        filters.put("status", runContext.render(status).as(IncidentStatus.class).map(IncidentStatus::apiValue).orElse(null));
        filters.put("severity", runContext.render(severity).as(Severity.class).map(Severity::apiValue).orElse(null));
        filters.put("validity", runContext.render(validity).as(Validity.class).map(Validity::apiValue).orElse(null));
        filters.put("declarative_secret_status", runContext.render(declarativeSecretStatus).as(String.class).orElse(null));
        filters.put("detector_group_name", runContext.render(detectorGroupName).as(String.class).orElse(null));
        filters.put("risk_score_min", runContext.render(riskScoreMin).as(Integer.class).orElse(null));
        filters.values().removeIf(value -> value == null);
        return filters;
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "New public incidents since the previous poll, oldest first", description = "At most `maxItemsPerPoll` per execution.")
        private final java.util.List<PublicIncident> incidents;

        @Schema(title = "Number of incidents in this execution")
        private final Integer count;
    }
}
