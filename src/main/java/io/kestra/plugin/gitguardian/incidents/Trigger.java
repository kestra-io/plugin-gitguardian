package io.kestra.plugin.gitguardian.incidents;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.conditions.ConditionContext;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.TriggerContext;
import io.kestra.core.models.triggers.TriggerEvaluationResult;
import io.kestra.core.models.triggers.TriggerOutput;
import io.kestra.core.models.triggers.TriggerService;
import io.kestra.core.runners.RunContext;
import io.kestra.plugin.gitguardian.AbstractGitGuardianTrigger;
import io.kestra.plugin.gitguardian.GitGuardianClient;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Trigger a flow when GitGuardian detects a secret incident",
    description = """
        Polls `GET /v1/incidents/secrets` at `interval` and starts one execution per poll carrying the incidents whose \
        last trigger date (`date`) is newer than the recorded watermark, oldest first (`trigger.incidents`), at most \
        `maxItemsPerPoll` (default 100) at a time; the rest fire on the next polls. GitGuardian bumps \
        `date` when a resolved or ignored incident is triggered again, so regressions fire too; check \
        `regression` on each incident if they should be handled differently. Filters (`status`, `severity`, \
        `validity`, `detectorGroupName`, `tags`, `riskScoreMin`) are applied server-side. The watermark (newest \
        delivered `date` plus the IDs sharing it) lives in the flow namespace KV store, so nothing is re-fired \
        after a restart. On the very first poll only the current baseline is recorded and nothing fires, which \
        avoids flooding the flow with the existing backlog when the trigger is enabled. Requires the \
        `incidents:read` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Notify Slack and assign the on-call for every new valid critical incident",
            full = true,
            code = """
                id: gitguardian_incident_response
                namespace: company.security

                tasks:
                  - id: each_incident
                    type: io.kestra.plugin.core.flow.ForEach
                    values: "{{ trigger.incidents }}"
                    tasks:
                      - id: notify
                        type: io.kestra.plugin.slack.SlackIncomingWebhook
                        url: "{{ secret('SLACK_WEBHOOK') }}"
                        payload: |
                          {"text": ":rotating_light: {{ fromJson(taskrun.value).incidentName }} ({{ fromJson(taskrun.value).severity }}, {{ fromJson(taskrun.value).validity }}) {{ fromJson(taskrun.value).gitguardianUrl }}"}

                      - id: assign
                        type: io.kestra.plugin.gitguardian.incidents.Assign
                        apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                        incidentId: "{{ fromJson(taskrun.value).id }}"
                        assigneeEmail: security-oncall@company.com

                triggers:
                  - id: on_incident
                    type: io.kestra.plugin.gitguardian.incidents.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    interval: PT1M
                    severity: CRITICAL
                    validity: VALID
                """
        ),
        @Example(
            title = "Open a Jira ticket for every new incident on the EU region",
            full = true,
            code = """
                id: gitguardian_incident_to_jira
                namespace: company.security

                tasks:
                  - id: each_incident
                    type: io.kestra.plugin.core.flow.ForEach
                    values: "{{ trigger.incidents }}"
                    tasks:
                      - id: ticket
                        type: io.kestra.plugin.jira.issues.Create
                        baseUrl: https://company.atlassian.net
                        username: "{{ secret('JIRA_USER') }}"
                        password: "{{ secret('JIRA_TOKEN') }}"
                        projectKey: SEC
                        summary: "Leaked secret: {{ fromJson(taskrun.value).incidentName }}"
                        description: "{{ fromJson(taskrun.value).gitguardianUrl }}"

                triggers:
                  - id: on_incident
                    type: io.kestra.plugin.gitguardian.incidents.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    apiUrl: https://api.eu1.gitguardian.com
                """
        )
    }
)
public class Trigger extends AbstractGitGuardianTrigger implements TriggerOutput<Trigger.Output> {
    private static final String SCOPE = "incidents:read";
    private static final int PAGE_SIZE = 100;
    /** GitGuardian's `date_after` bound has second granularity; overlapping by one second and de-duplicating client-side never skips a tie. */
    private static final Duration OVERLAP = Duration.ofSeconds(1);

    @Schema(title = "Only incidents in this status", description = "`TRIGGERED`, `ASSIGNED`, `RESOLVED`, or `IGNORED`. Any status when omitted.")
    @PluginProperty(group = "processing")
    private Property<IncidentStatus> status;

    @Schema(title = "Only incidents at this severity", description = "`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `UNKNOWN`. Any severity when omitted.")
    @PluginProperty(group = "processing")
    private Property<Severity> severity;

    @Schema(title = "Only incidents with this secret validity", description = "`VALID`, `INVALID`, `FAILED_TO_CHECK`, `NO_CHECKER`, or `UNKNOWN`.")
    @PluginProperty(group = "processing")
    private Property<Validity> validity;

    @Schema(title = "Only incidents from this detector group", description = "For example `aws_iam`.")
    @PluginProperty(group = "processing")
    private Property<String> detectorGroupName;

    @Schema(title = "Only incidents carrying all of these GitGuardian tags", description = "For example `PUBLICLY_EXPOSED`.")
    @PluginProperty(group = "processing")
    private Property<java.util.List<String>> tags;

    @Schema(title = "Minimum risk score, from 0 to 100")
    @PluginProperty(group = "processing")
    private Property<@Min(0) @Max(100) Integer> riskScoreMin;

    @Override
    public Optional<TriggerEvaluationResult> eval(ConditionContext conditionContext, TriggerContext context) throws Exception {
        var runContext = conditionContext.getRunContext();
        var logger = runContext.logger();
        var kv = runContext.namespaceKv(context.getNamespace());
        var key = watermarkKey("gitguardian_incidents", context.getFlowId(), context.getTriggerId());
        var filters = filters(runContext);

        try (var client = client(runContext)) {
            var watermark = readWatermark(kv, key).orElse(null);
            if (watermark == null) {
                var newest = newest(client, filters);
                var baseline = newest != null ? new Watermark(newest.getDate(), Set.of(String.valueOf(newest.getId()))) : new Watermark(Instant.now(), Set.of());
                persistWatermark(kv, key, baseline);
                logger.info("GitGuardian incidents trigger initialized; baseline {}. Only incidents triggered after it will fire.", baseline.getTimestamp());
                return Optional.empty();
            }

            var query = new LinkedHashMap<String, Object>(filters);
            query.put("ordering", "date");
            query.put("per_page", PAGE_SIZE);
            query.put("date_after", watermark.getTimestamp().minus(OVERLAP).toString());
            var cap = runContext.render(maxItemsPerPoll).as(Integer.class).orElse(DEFAULT_MAX_ITEMS_PER_POLL);
            var undelivered = collectUndelivered(client, "/incidents/secrets", query, SCOPE, Incident.class, watermark, cap, Incident::getDate, incident -> String.valueOf(incident.getId()), logger);
            if (undelivered.isEmpty()) {
                return Optional.empty();
            }

            var batch = oldest(undelivered, cap, Incident::getDate, incident -> String.valueOf(incident.getId()));
            persistWatermark(kv, key, advance(watermark, batch, Incident::getDate, incident -> String.valueOf(incident.getId())));
            return Optional.of(TriggerService.generateEvaluationResult(this, conditionContext, Output.builder().incidents(batch).count(batch.size()).build()));
        }
    }

    private Incident newest(GitGuardianClient client, Map<String, Object> filters) throws Exception {
        var query = new LinkedHashMap<String, Object>(filters);
        query.put("ordering", "-date");
        query.put("per_page", 1);
        var page = client.getPage("/incidents/secrets", query, null, SCOPE, Incident.class);
        return page.items().isEmpty() ? null : page.items().getFirst();
    }

    private Map<String, Object> filters(RunContext runContext) throws Exception {
        var filters = new LinkedHashMap<String, Object>();
        filters.put("status", runContext.render(status).as(IncidentStatus.class).map(IncidentStatus::apiValue).orElse(null));
        filters.put("severity", runContext.render(severity).as(Severity.class).map(Severity::apiValue).orElse(null));
        filters.put("validity", runContext.render(validity).as(Validity.class).map(Validity::apiValue).orElse(null));
        filters.put("detector_group_name", runContext.render(detectorGroupName).as(String.class).orElse(null));
        var rTags = runContext.render(tags).asList(String.class);
        filters.put("tags", rTags.isEmpty() ? null : rTags);
        filters.put("risk_score_min", runContext.render(riskScoreMin).as(Integer.class).orElse(null));
        filters.values().removeIf(value -> value == null);
        return filters;
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "New incidents since the previous poll, oldest first", description = "At most `maxItemsPerPoll` per execution.")
        private final java.util.List<Incident> incidents;

        @Schema(title = "Number of incidents in this execution")
        private final Integer count;
    }
}
