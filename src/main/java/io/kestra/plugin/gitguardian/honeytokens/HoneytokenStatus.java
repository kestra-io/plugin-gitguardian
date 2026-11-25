package io.kestra.plugin.gitguardian.honeytokens;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Locale;

/** Lifecycle status of a honeytoken, serialized in the lowercase form the GitGuardian API uses. */
public enum HoneytokenStatus {
    ACTIVE,
    TRIGGERED,
    REVOKED;

    @JsonValue
    public String apiValue() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** Case-insensitive, so flows may write {@code TRIGGERED} or {@code triggered}. */
    @JsonCreator
    public static HoneytokenStatus fromString(String value) {
        if (value == null) {
            return null;
        }
        for (var status : values()) {
            if (status.name().equalsIgnoreCase(value.trim())) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unknown honeytoken status '%s', expected one of active, triggered, revoked.".formatted(value));
    }
}
