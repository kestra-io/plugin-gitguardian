package io.kestra.plugin.gitguardian.healthchecks;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Trigger a flow when a GitGuardian integration starts failing",
    description = """
        Polls `GET /v1/health-checks` at `interval` for integration instances whose latest run has one of `statuses` \
        (default `FAIL`) and starts one execution per poll listing the instances that entered that state since the \
        previous poll (`trigger.checks`), at most `maxItemsPerPoll` (default 100) at a time. An integration that keeps \
        failing does not re-fire: the trigger remembers each delivered `instance@firstStartedAt` pair, where \
        `firstStartedAt` is the start of the current streak, so only new streaks fire. Tracking delivered pairs rather \
        than a time watermark means a long-running check that reports its failure late is still delivered. On the first \
        poll the failures already present are recorded and nothing fires. Requires the `health_checks:read` scope.
        """
)
@Plugin(
    examples = {
        @Example(
            title = "Page the platform team when a GitHub or GitLab integration breaks",
            full = true,
            code = """
                id: gitguardian_integration_down
                namespace: company.security

                tasks:
                  - id: page
                    type: io.kestra.plugin.pagerduty.PagerDutyAlert
                    url: "https://events.pagerduty.com/v2/enqueue"
                    payload: |
                      {
                        "routing_key": "{{ secret('PAGERDUTY_KEY') }}",
                        "event_action": "trigger",
                        "payload": {
                          "summary": "GitGuardian integration failing: {{ trigger.checks | jq('[.[].instance.name]') | first }}",
                          "source": "kestra",
                          "severity": "error"
                        }
                      }

                triggers:
                  - id: on_failure
                    type: io.kestra.plugin.gitguardian.healthchecks.Trigger
                    apiKey: "{{ secret('GITGUARDIAN_API_KEY') }}"
                    interval: PT10M
                    types:
                      - github-installation
                      - gitlab-installation
                """
        )
    }
)
public class Trigger extends AbstractGitGuardianTrigger implements TriggerOutput<Trigger.Output> {
    private static final String SCOPE = "health_checks:read";
    private static final int PAGE_SIZE = 100;

    @Schema(title = "Statuses that fire", description = "Any of `FAIL`, `WARN`, `PASS`. Defaults to `FAIL` only.")
    @Builder.Default
    @PluginProperty(group = "processing")
    private Property<java.util.List<HealthCheckStatus>> statuses = Property.ofValue(java.util.List.of(HealthCheckStatus.FAIL));

    @Schema(title = "Only these integration types", description = "For example `github-installation`. All types when omitted.")
    @PluginProperty(group = "processing")
    private Property<java.util.List<String>> types;

    @Override
    public Optional<TriggerEvaluationResult> eval(ConditionContext conditionContext, TriggerContext context) throws Exception {
        var runContext = conditionContext.getRunContext();
        var kv = runContext.namespaceKv(context.getNamespace());
        var key = watermarkKey("gitguardian_healthchecks_delivered", context.getFlowId(), context.getTriggerId());
        var rStatuses = runContext.render(statuses).asList(HealthCheckStatus.class);
        var rTypes = runContext.render(types).asList(String.class);

        var state = readState(kv, key, DeliveredChecks.class).orElse(null);
        var cap = runContext.render(maxItemsPerPoll).as(Integer.class).orElse(DEFAULT_MAX_ITEMS_PER_POLL);

        var current = new LinkedHashMap<String, HealthCheck>();
        try (var client = client(runContext)) {
            for (var status : rStatuses.isEmpty() ? java.util.List.of(HealthCheckStatus.FAIL) : rStatuses) {
                var query = new LinkedHashMap<String, Object>();
                query.put("status", status.apiValue());
                query.put("per_page", PAGE_SIZE);
                client.walk("/health-checks", query, SCOPE, HealthCheck.class, page -> {
                    for (var check : page) {
                        if (streakStart(check) != null && (rTypes.isEmpty() || rTypes.contains(check.getType()))) {
                            current.put(streakKey(check), check);
                        }
                    }
                    return true;
                });
            }
        }

        if (state == null) {
            persistState(kv, key, new DeliveredChecks(new TreeSet<>(current.keySet())));
            runContext.logger().info("GitGuardian health checks trigger initialized; {} failure(s) already present will not fire.", current.size());
            return Optional.empty();
        }

        var delivered = state.getKeys() != null ? state.getKeys() : Set.<String>of();
        var undelivered = current.entrySet().stream().filter(entry -> !delivered.contains(entry.getKey())).toList();
        var batch = undelivered.stream()
            .sorted(Map.Entry.comparingByValue(Comparator.comparing(Trigger::streakStart)))
            .limit(cap)
            .toList();

        // A new streak gets a new firstStartedAt, so forgetting keys of ended streaks is safe.
        var remembered = new TreeSet<String>();
        delivered.stream().filter(current::containsKey).forEach(remembered::add);
        batch.forEach(entry -> remembered.add(entry.getKey()));
        persistState(kv, key, new DeliveredChecks(remembered));

        if (batch.isEmpty()) {
            return Optional.empty();
        }
        var checks = batch.stream().map(Map.Entry::getValue).toList();
        return Optional.of(TriggerService.generateEvaluationResult(this, conditionContext, Output.builder().checks(checks).count(checks.size()).build()));
    }

    private static Instant streakStart(HealthCheck check) {
        return check.getFirstStartedAt() != null ? check.getFirstStartedAt() : check.getStartedAt();
    }

    private static String streakKey(HealthCheck check) {
        var instanceId = check.getInstance() != null ? check.getInstance().getId() : check.getId();
        return check.getType() + ":" + instanceId + "@" + streakStart(check);
    }

    /** Delivered `type:instanceId@firstStartedAt` keys of streaks still listed as matching. */
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class DeliveredChecks {
        private Set<String> keys;
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "Integration instances that entered a matching status since the previous poll")
        private final java.util.List<HealthCheck> checks;

        @Schema(title = "Number of instances")
        private final Integer count;
    }
}
