package io.kestra.plugin.gitguardian.members;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.kestra.plugin.gitguardian.Orderings;

/** Sort order of member lists. Accepts the API form ({@code -date}) or the constant name in any casing ({@code DATE_DESC}). */
public enum MemberOrdering {
    CREATED_AT,
    CREATED_AT_DESC,
    LAST_LOGIN,
    LAST_LOGIN_DESC;

    @JsonValue
    public String apiValue() {
        return Orderings.apiValue(this);
    }

    @JsonCreator
    public static MemberOrdering fromString(String value) {
        return Orderings.parse(MemberOrdering.class, value);
    }
}
