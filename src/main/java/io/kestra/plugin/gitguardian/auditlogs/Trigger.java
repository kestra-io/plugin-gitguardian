package io.kestra.plugin.gitguardian.auditlogs;

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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Optional;
import java.util.Set;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Trigger a flow on new GitGuardian audit log events",
    description = """
        Polls `GET /v1/audit_logs` at `interval` and starts one execution per poll carrying the new events since \
        the last poll (`trigger.events`), so a burst of activity produces one execution, not one per event. A poll \
        carries at most `maxItemsPerPoll` events (default 100) to keep the output small; the rest fire on the next polls. \
        The API cannot sort audit logs, so each poll reads every event of a window of at most one day after the \
        watermark, then delivers the oldest ones. A longer backlog is caught up one window per poll. \
        Optionally restrict to `eventNames`. The watermark (newest delivered date plus the IDs sharing it) is kept \
        in the flow namespace KV store; on the first poll it is seeded at the current time and nothing fires. \
        Requires the `audit_logs:read` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Alert when an incident is ignored or an API token is created",
            full = true,
            code = """
                id: gitguardian_sensitive_actions
                namespace: company.security

                tasks:
                  - id: alert
                    type: io.kestra.plugin.slack.SlackIncomingWebhook
                    url: "{{ secret('SLACK_WEBHOOK') }}"
                    messageText: |
                      GitGuardian: {{ trigger.count }} sensitive action(s)
                      {% for event in trigger.events %}- {{ event.eventName }} by {{ event.memberEmail ?? event.apiTokenId }}
                      {% endfor %}

                triggers:
                  - id: on_audit_event
                    type: io.kestra.plugin.gitguardian.auditlogs.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    interval: PT5M
                    eventNames:
                      - incident.ignored
                      - api_token.created
                """
        )
    }
)
public class Trigger extends AbstractGitGuardianTrigger implements TriggerOutput<Trigger.Output> {
    private static final String SCOPE = "audit_logs:read";
    private static final int PAGE_SIZE = 100;
    private static final Duration OVERLAP = Duration.ofSeconds(1);
    private static final Duration MAX_WINDOW = Duration.ofDays(1);

    @Schema(title = "Only these event names", description = "For example `incident.ignored`. All events when omitted. Filtered server-side one name at a time.")
    @PluginProperty(group = "processing")
    private Property<java.util.List<String>> eventNames;

    @Override
    public Optional<TriggerEvaluationResult> eval(ConditionContext conditionContext, TriggerContext context) throws Exception {
        var runContext = conditionContext.getRunContext();
        var kv = runContext.namespaceKv(context.getNamespace());
        var key = watermarkKey("gitguardian_auditlogs", context.getFlowId(), context.getTriggerId());
        var rEventNames = runContext.render(eventNames).asList(String.class);

        var watermark = readWatermark(kv, key).orElse(null);
        if (watermark == null) {
            persistWatermark(kv, key, new Watermark(Instant.now(), Set.of()));
            runContext.logger().info("GitGuardian audit logs trigger initialized; only events after now will fire.");
            return Optional.empty();
        }

        var now = Instant.now();
        var windowEnd = watermark.getTimestamp().plus(MAX_WINDOW);
        var windowed = windowEnd.isBefore(now.minus(getInterval()));
        var rMaxItemsPerPoll = runContext.render(maxItemsPerPoll).as(Integer.class).orElse(DEFAULT_MAX_ITEMS_PER_POLL);
        var undelivered = new ArrayList<AuditLog>();
        try (var client = client(runContext)) {
            var names = rEventNames.isEmpty() ? Collections.<String>singletonList(null) : rEventNames;
            for (var name : names) {
                var query = new LinkedHashMap<String, Object>();
                query.put("event_name", name);
                query.put("per_page", PAGE_SIZE);
                query.put("date_after", watermark.getTimestamp().minus(OVERLAP).toString());
                if (windowed) {
                    query.put("date_before", windowEnd.toString());
                }
                query.values().removeIf(value -> value == null);
                // The endpoint has no ordering parameter, so the cap cannot stop the walk: it may list newest first.
                undelivered.addAll(collectUndelivered(client, "/audit_logs", query, SCOPE, AuditLog.class, watermark, Integer.MAX_VALUE, AuditLog::getDate, event -> String.valueOf(event.getId()), runContext.logger()));
            }
        }

        if (undelivered.isEmpty()) {
            if (windowed) {
                // Keep the overlap so an event dated just before windowEnd, or listed late, is still read next poll.
                persistWatermark(kv, key, new Watermark(windowEnd.minus(OVERLAP), Set.of()));
            }
            return Optional.empty();
        }
        var batch = oldest(undelivered, rMaxItemsPerPoll, AuditLog::getDate, event -> String.valueOf(event.getId()));
        persistWatermark(kv, key, advance(watermark, batch, AuditLog::getDate, event -> String.valueOf(event.getId())));

        return Optional.of(TriggerService.generateEvaluationResult(this, conditionContext, Output.builder().events(batch).count(batch.size()).build()));
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "New audit log events since the previous poll, oldest first", description = "At most `maxItemsPerPoll` per execution.")
        private final java.util.List<AuditLog> events;

        @Schema(title = "Number of new events")
        private final Integer count;
    }
}
