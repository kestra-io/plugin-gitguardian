package io.kestra.plugin.gitguardian.incidents;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.kestra.plugin.gitguardian.Orderings;

/** Sort order of secret incident lists. Accepts the API form ({@code -date}) or the constant name in any casing ({@code DATE_DESC}). */
public enum IncidentOrdering {
    DATE,
    DATE_DESC,
    RESOLVED_AT,
    RESOLVED_AT_DESC,
    IGNORED_AT,
    IGNORED_AT_DESC,
    RISK_SCORE,
    RISK_SCORE_DESC;

    @JsonValue
    public String apiValue() {
        return Orderings.apiValue(this);
    }

    @JsonCreator
    public static IncidentOrdering fromString(String value) {
        return Orderings.parse(IncidentOrdering.class, value);
    }
}
