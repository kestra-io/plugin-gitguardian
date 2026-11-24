package io.kestra.plugin.gitguardian;

import io.kestra.core.models.conditions.ConditionContext;
import io.kestra.core.models.tasks.Output;
import io.kestra.core.models.triggers.TriggerContext;
import io.kestra.core.models.triggers.TriggerEvaluationResult;
import io.kestra.core.models.triggers.TriggerService;
import io.kestra.core.runners.RunContext;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Polling flow shared by the secret incident and public incident triggers: both endpoints sort by `date`. */
@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractIncidentTrigger<T> extends AbstractGitGuardianTrigger {
    private static final String SCOPE = "incidents:read";
    private static final int PAGE_SIZE = 100;
    // The `date_after` bound has second granularity: overlap by one second and de-duplicate client-side.
    private static final Duration OVERLAP = Duration.ofSeconds(1);

    protected abstract String path();

    protected abstract String keyPrefix();

    protected abstract Class<T> itemType();

    protected abstract Instant dateOf(T incident);

    protected abstract String idOf(T incident);

    protected abstract Map<String, Object> filters(RunContext runContext) throws Exception;

    protected abstract Output output(List<T> batch);

    @Override
    public Optional<TriggerEvaluationResult> eval(ConditionContext conditionContext, TriggerContext context) throws Exception {
        var runContext = conditionContext.getRunContext();
        var logger = runContext.logger();
        var kv = runContext.namespaceKv(context.getNamespace());
        var key = watermarkKey(keyPrefix(), context.getFlowId(), context.getTriggerId());
        var filters = filters(runContext);

        try (var client = client(runContext)) {
            var watermark = readWatermark(kv, key).orElse(null);
            if (watermark == null) {
                var newest = newest(client, filters);
                var baseline = newest != null ? new Watermark(dateOf(newest), Set.of(idOf(newest))) : new Watermark(Instant.now(), Set.of());
                persistWatermark(kv, key, baseline);
                logger.info("GitGuardian trigger on {} initialized; baseline {}. Only incidents triggered after it will fire.", path(), baseline.getTimestamp());
                return Optional.empty();
            }

            var query = new LinkedHashMap<String, Object>(filters);
            query.put("ordering", "date");
            query.put("per_page", PAGE_SIZE);
            query.put("date_after", watermark.getTimestamp().minus(OVERLAP).toString());
            var cap = runContext.render(maxItemsPerPoll).as(Integer.class).orElse(DEFAULT_MAX_ITEMS_PER_POLL);
            var undelivered = collectUndelivered(client, path(), query, SCOPE, itemType(), watermark, cap, this::dateOf, this::idOf, logger);
            if (undelivered.isEmpty()) {
                return Optional.empty();
            }

            var batch = oldest(undelivered, cap, this::dateOf, this::idOf);
            persistWatermark(kv, key, advance(watermark, batch, this::dateOf, this::idOf));
            return Optional.of(TriggerService.generateEvaluationResult(this, conditionContext, output(batch)));
        }
    }

    private T newest(GitGuardianClient client, Map<String, Object> filters) throws Exception {
        var query = new LinkedHashMap<String, Object>(filters);
        query.put("ordering", "-date");
        query.put("per_page", 1);
        var page = client.getPage(path(), query, null, SCOPE, itemType());
        return page.items().isEmpty() ? null : page.items().getFirst();
    }
}
