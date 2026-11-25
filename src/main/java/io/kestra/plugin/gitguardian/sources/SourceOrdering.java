package io.kestra.plugin.gitguardian.sources;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.kestra.plugin.gitguardian.Orderings;

/** Sort order of source lists. Accepts the API form ({@code -date}) or the constant name in any casing ({@code DATE_DESC}). */
public enum SourceOrdering {
    LAST_SCAN_DATE,
    LAST_SCAN_DATE_DESC;

    @JsonValue
    public String apiValue() {
        return Orderings.apiValue(this);
    }

    @JsonCreator
    public static SourceOrdering fromString(String value) {
        return Orderings.parse(SourceOrdering.class, value);
    }
}
