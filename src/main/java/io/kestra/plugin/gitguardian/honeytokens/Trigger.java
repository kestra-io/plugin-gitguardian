package io.kestra.plugin.gitguardian.honeytokens;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.conditions.ConditionContext;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.TriggerContext;
import io.kestra.core.models.triggers.TriggerEvaluationResult;
import io.kestra.core.models.triggers.TriggerOutput;
import io.kestra.core.models.triggers.TriggerService;
import io.kestra.plugin.gitguardian.AbstractGitGuardianTrigger;
import io.kestra.plugin.gitguardian.GitGuardianClient;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Trigger a flow when a GitGuardian honeytoken is used",
    description = """
        Polls `GET /v1/honeytokens_events` at `interval` and starts one execution per poll carrying the new events, \
        oldest first, in `trigger.events` (at most `maxItemsPerPoll`, default 100; the rest fire on the next polls), \
        and the honeytokens they belong to in `trigger.honeytokens`, keyed by honeytoken ID (without their value). A honeytoken firing means someone used a decoy credential: treat it as an active \
        intrusion signal. The watermark is kept in the flow namespace KV store and seeded at the current time on the \
        first poll. The events endpoint has no date filter and can only be read newest first, so each poll reads the \
        events back to the watermark, then delivers the oldest ones. Requires the `honeytokens:read` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Alert security and open a ticket when a honeytoken fires",
            full = true,
            code = """
                id: gitguardian_honeytoken_alert
                namespace: company.security

                tasks:
                  - id: each_event
                    type: io.kestra.plugin.core.flow.Loop
                    values: "{{ trigger.events }}"
                    tasks:
                      - id: alert
                        type: io.kestra.plugin.slack.SlackIncomingWebhook
                        url: "{{ secret('SLACK_WEBHOOK') }}"
                        messageText: ":rotating_light: Honeytoken {{ trigger.honeytokens[fromJson(item.value).honeytokenId].name ?? fromJson(item.value).honeytokenId }} used from {{ fromJson(item.value).ipAddress }} ({{ fromJson(item.value).action }})"

                      - id: ticket
                        type: io.kestra.plugin.jira.issues.Create
                        baseUrl: https://company.atlassian.net
                        username: "{{ secret('JIRA_USER') }}"
                        password: "{{ secret('JIRA_TOKEN') }}"
                        projectKey: SEC
                        summary: "Honeytoken triggered: {{ trigger.honeytokens[fromJson(item.value).honeytokenId].name ?? fromJson(item.value).honeytokenId }}"
                        description: "{{ fromJson(item.value).gitguardianUrl }}"

                triggers:
                  - id: on_honeytoken_event
                    type: io.kestra.plugin.gitguardian.honeytokens.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    interval: PT1M
                """
        )
    }
)
public class Trigger extends AbstractGitGuardianTrigger implements TriggerOutput<Trigger.Output> {
    private static final String SCOPE = "honeytokens:read";
    private static final int PAGE_SIZE = 100;
    private static final Duration OVERLAP = Duration.ofSeconds(1);

    @Schema(title = "Only events of this honeytoken ID", description = "All honeytokens when omitted.")
    @PluginProperty(group = "processing")
    private Property<String> honeytokenId;

    @Override
    public Optional<TriggerEvaluationResult> eval(ConditionContext conditionContext, TriggerContext context) throws Exception {
        var runContext = conditionContext.getRunContext();
        var kv = runContext.namespaceKv(context.getNamespace());
        var key = watermarkKey("gitguardian_honeytokens", context.getFlowId(), context.getTriggerId());

        var watermark = readWatermark(kv, key).orElse(null);
        if (watermark == null) {
            persistWatermark(kv, key, new Watermark(Instant.now(), Set.of()));
            runContext.logger().info("GitGuardian honeytokens trigger initialized; only events after now will fire.");
            return Optional.empty();
        }

        try (var client = client(runContext)) {
            var pending = new ArrayList<HoneytokenEvent>();
            var query = new LinkedHashMap<String, Object>();
            query.put("honeytoken_id", runContext.render(honeytokenId).as(String.class).orElse(null));
            query.put("status", "open");
            query.put("ordering", "-triggered_at");
            query.put("per_page", PAGE_SIZE);
            query.values().removeIf(value -> value == null);
            // The events endpoint has no date filter; newest first lets the walk stop at the first event older than the watermark.
            var cutoff = watermark.getTimestamp().minus(OVERLAP);
            client.walk("/honeytokens_events", query, SCOPE, HoneytokenEvent.class, page -> {
                for (var event : page) {
                    if (event.getTriggeredAt() == null) {
                        runContext.logger().warn("Honeytoken event {} has no triggered_at date and cannot be delivered", event.getId());
                        continue;
                    }
                    if (event.getTriggeredAt().isBefore(cutoff)) {
                        return false;
                    }
                    if (!watermark.isDelivered(event.getTriggeredAt(), event.getId())) {
                        pending.add(event);
                    }
                }
                return true;
            });
            if (pending.isEmpty()) {
                return Optional.empty();
            }

            var cap = runContext.render(maxItemsPerPoll).as(Integer.class).orElse(DEFAULT_MAX_ITEMS_PER_POLL);
            var batch = oldest(pending, cap, HoneytokenEvent::getTriggeredAt, HoneytokenEvent::getId);

            var honeytokens = new LinkedHashMap<String, Honeytoken>();
            for (var honeytokenId : batch.stream().map(HoneytokenEvent::getHoneytokenId).filter(Objects::nonNull).distinct().toList()) {
                try {
                    honeytokens.put(honeytokenId, client.get("/honeytokens/" + GitGuardianClient.segment(honeytokenId), Map.of("show_token", false), SCOPE, Honeytoken.class));
                } catch (Exception e) {
                    runContext.logger().warn("Honeytoken {} fires without honeytoken details: {}", honeytokenId, e.getMessage());
                }
            }

            persistWatermark(kv, key, advance(watermark, batch, HoneytokenEvent::getTriggeredAt, HoneytokenEvent::getId));
            return Optional.of(TriggerService.generateEvaluationResult(this, conditionContext, Output.builder().events(batch).count(batch.size()).honeytokens(honeytokens).build()));
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "New honeytoken events since the previous poll, oldest first", description = "At most `maxItemsPerPoll` per execution.")
        private final java.util.List<HoneytokenEvent> events;

        @Schema(title = "Number of events in this execution")
        private final Integer count;

        @Schema(title = "The honeytokens that were used, keyed by honeytoken ID, without their value", description = "A honeytoken that could not be fetched is missing from the map.")
        private final Map<String, Honeytoken> honeytokens;
    }
}
