package io.kestra.plugin.gitguardian.incidents;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Locale;

/** Reason recorded when ignoring a secret incident, serialized in the lowercase form the GitGuardian API uses. */
public enum IgnoreReason {
    TEST_CREDENTIAL,
    FALSE_POSITIVE,
    LOW_RISK,
    INVALID;

    @JsonValue
    public String apiValue() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** Case-insensitive, so flows may write {@code TEST_CREDENTIAL} or {@code test_credential}. */
    @JsonCreator
    public static IgnoreReason fromString(String value) {
        if (value == null) {
            return null;
        }
        for (var reason : values()) {
            if (reason.name().equalsIgnoreCase(value)) {
                return reason;
            }
        }
        throw new IllegalArgumentException("Unknown ignoreReason '%s', expected one of test_credential, false_positive, low_risk, invalid.".formatted(value));
    }
}
