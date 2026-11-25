package io.kestra.plugin.gitguardian.honeytokens;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.kestra.plugin.gitguardian.Orderings;

/** Sort order of honeytoken lists. Accepts the API form ({@code -date}) or the constant name in any casing ({@code DATE_DESC}). */
public enum HoneytokenOrdering {
    CREATED_AT,
    CREATED_AT_DESC,
    TRIGGERED_AT,
    TRIGGERED_AT_DESC,
    REVOKED_AT,
    REVOKED_AT_DESC,
    NAME,
    NAME_DESC;

    @JsonValue
    public String apiValue() {
        return Orderings.apiValue(this);
    }

    @JsonCreator
    public static HoneytokenOrdering fromString(String value) {
        return Orderings.parse(HoneytokenOrdering.class, value);
    }
}
