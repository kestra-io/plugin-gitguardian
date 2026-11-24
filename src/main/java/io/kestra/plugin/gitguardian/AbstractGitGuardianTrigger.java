package io.kestra.plugin.gitguardian;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.kestra.core.http.client.HttpClient;
import io.kestra.core.http.client.configurations.HttpConfiguration;
import io.kestra.core.http.client.configurations.TimeoutConfiguration;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.AbstractTrigger;
import io.kestra.core.models.triggers.PollingTriggerInterface;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;
import io.kestra.core.storages.kv.KVMetadata;
import io.kestra.core.storages.kv.KVStore;
import io.kestra.core.storages.kv.KVValueAndMetadata;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import org.slf4j.Logger;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/** Base class for GitGuardian polling triggers: connection properties (duplicated from {@link AbstractGitGuardianTask}, a trigger cannot extend {@code Task}) and the watermark persistence every poller shares so a delivered item is never re-fired. */
@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractGitGuardianTrigger extends AbstractTrigger implements PollingTriggerInterface, GitGuardianConnectionInterface {
    protected static final int DEFAULT_MAX_ITEMS_PER_POLL = 100;
    private static final ObjectMapper MAPPER = JacksonMapper.ofJson();

    @Schema(title = API_URL_TITLE, description = API_URL_DESCRIPTION)
    @Builder.Default
    @PluginProperty(group = "connection")
    protected Property<String> apiUrl = Property.ofValue(DEFAULT_API_URL);

    @Schema(title = API_KEY_TITLE, description = API_KEY_DESCRIPTION)
    @NotNull
    @PluginProperty(secret = true, group = "connection")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    protected Property<String> apiKey;

    @Schema(title = "Polling interval", description = "How often to poll the GitGuardian API. Defaults to `PT5M`.")
    @Builder.Default
    @PluginProperty(group = "execution")
    protected Duration interval = Duration.ofMinutes(5);

    @Schema(
        title = "Maximum items delivered per poll",
        description = """
            Caps how many new items one execution carries, from 1 to 1000. Defaults to `100`. Items beyond the cap \
            are not lost: the watermark only advances past delivered items, so they fire on the next polls, oldest first.\
            """
    )
    @Builder.Default
    @PluginProperty(group = "processing")
    protected Property<@Min(1) @Max(1000) Integer> maxItemsPerPoll = Property.ofValue(DEFAULT_MAX_ITEMS_PER_POLL);

    protected GitGuardianClient client(RunContext runContext) throws Exception {
        var rApiUrl = runContext.render(apiUrl).as(String.class).orElse(DEFAULT_API_URL);
        var rApiKey = runContext.render(apiKey).as(String.class)
            .orElseThrow(() -> new IllegalArgumentException("apiKey is required to authenticate with the GitGuardian API."));

        var httpClient = HttpClient.builder()
            .runContext(runContext)
            .configuration(HttpConfiguration.builder()
                .timeout(TimeoutConfiguration.builder()
                    .connectTimeout(Property.ofValue(AbstractGitGuardianTask.HTTP_CONNECT_TIMEOUT))
                    .readIdleTimeout(Property.ofValue(AbstractGitGuardianTask.HTTP_READ_IDLE_TIMEOUT))
                    .build())
                .build())
            .build();
        return new GitGuardianClient(httpClient, rApiUrl, rApiKey);
    }

    /** Length-prefixed so distinct (flowId, triggerId) pairs never produce the same key. */
    protected String watermarkKey(String prefix, String flowId, String triggerId) {
        return prefix + "_watermark_" + flowId.length() + "_" + flowId + "_" + triggerId.length() + "_" + triggerId;
    }

    protected Optional<Watermark> readWatermark(KVStore kv, String key) {
        return readState(kv, key, Watermark.class);
    }

    protected void persistWatermark(KVStore kv, String key, Watermark watermark) {
        persistState(kv, key, watermark);
    }

    /** A read failure is never treated as "no state yet": that would silently re-seed the baseline and drop every item accumulated since the last successful poll. */
    protected <T> Optional<T> readState(KVStore kv, String key, Class<T> type) {
        try {
            return kv.getValue(key).map(value -> parse(String.valueOf(value.value()), type));
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read GitGuardian trigger state '%s' from the namespace KV store: %s. Refusing to treat this as a first poll, which would drop the backlog.".formatted(key, e.getMessage()), e);
        }
    }

    /** A write failure must fail the poll loudly, otherwise the next poll re-delivers the same item. */
    protected void persistState(KVStore kv, String key, Object state) {
        try {
            kv.put(key, new KVValueAndMetadata(new KVMetadata(null, (Instant) null), MAPPER.writeValueAsString(state)));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot persist GitGuardian trigger state '%s': %s. The next poll would otherwise re-deliver the same item.".formatted(key, e.getMessage()), e);
        }
    }

    /** Walks a date-ascending endpoint and stops as soon as {@code cap} undelivered items are collected, so a backlog is drained over several polls instead of being fully read on each one. */
    protected <T> List<T> collectUndelivered(GitGuardianClient client, String path, Map<String, Object> query, String scope, Class<T> itemType, Watermark watermark, int cap, Function<T, Instant> timestampOf, Function<T, String> idOf, Logger logger) throws Exception {
        var pending = new ArrayList<T>();
        client.walk(path, query, scope, itemType, page -> {
            for (var item : page) {
                var timestamp = timestampOf.apply(item);
                if (timestamp == null) {
                    logger.warn("GitGuardian item {} from {} has no date and cannot be delivered", idOf.apply(item), path);
                } else if (!watermark.isDelivered(timestamp, idOf.apply(item))) {
                    pending.add(item);
                }
            }
            return pending.size() < cap;
        });
        return pending;
    }

    /** The {@code cap} oldest items, ordered oldest first. */
    protected <T> List<T> oldest(List<T> items, int cap, Function<T, Instant> timestampOf, Function<T, String> idOf) {
        var sorted = new ArrayList<>(items);
        sorted.sort(Comparator.comparing(timestampOf).thenComparing(idOf));
        return List.copyOf(sorted.subList(0, Math.min(cap, sorted.size())));
    }

    protected <T> Watermark advance(Watermark watermark, List<T> delivered, Function<T, Instant> timestampOf, Function<T, String> idOf) {
        var next = watermark;
        for (var item : delivered) {
            next = next.advance(timestampOf.apply(item), idOf.apply(item));
        }
        return next;
    }

    private <T> T parse(String raw, Class<T> type) {
        try {
            return MAPPER.readValue(raw, type);
        } catch (Exception e) {
            throw new IllegalStateException("Unparseable GitGuardian trigger state '%s': %s. Delete the KV entry to re-seed the baseline deliberately.".formatted(raw, e.getMessage()), e);
        }
    }

    /** Newest delivered timestamp plus every delivered ID sharing that exact timestamp, so items that tie on the boundary are neither skipped nor re-fired. */
    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Watermark {
        private Instant timestamp;
        private Set<String> boundaryIds;

        public boolean isDelivered(Instant itemTimestamp, String itemId) {
            if (itemTimestamp == null || timestamp == null) {
                return false;
            }
            if (itemTimestamp.isBefore(timestamp)) {
                return true;
            }
            return itemTimestamp.equals(timestamp) && boundaryIds != null && boundaryIds.contains(itemId);
        }

        public Watermark advance(Instant itemTimestamp, String itemId) {
            if (timestamp != null && itemTimestamp.equals(timestamp)) {
                var merged = new HashSet<>(boundaryIds != null ? boundaryIds : Set.<String>of());
                merged.add(itemId);
                return new Watermark(timestamp, merged);
            }
            return new Watermark(itemTimestamp, Set.of(itemId));
        }
    }
}
