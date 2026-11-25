package io.kestra.plugin.gitguardian;

import java.util.Arrays;
import java.util.Locale;

import static java.util.stream.Collectors.joining;

/** Maps ordering enum constants such as {@code RISK_SCORE_DESC} to the API form {@code -risk_score}, and back. */
public final class Orderings {
    private static final String DESCENDING_SUFFIX = "_DESC";

    private Orderings() {
    }

    public static String apiValue(Enum<?> ordering) {
        var name = ordering.name();
        if (name.endsWith(DESCENDING_SUFFIX)) {
            return "-%s".formatted(name.substring(0, name.length() - DESCENDING_SUFFIX.length()).toLowerCase(Locale.ROOT));
        }
        return name.toLowerCase(Locale.ROOT);
    }

    public static <E extends Enum<E>> E parse(Class<E> type, String value) {
        if (value == null) {
            return null;
        }
        var trimmed = value.trim();
        var constantName = trimmed.startsWith("-") ? trimmed.substring(1) + DESCENDING_SUFFIX : trimmed;
        for (var constant : type.getEnumConstants()) {
            if (constant.name().equalsIgnoreCase(constantName)) {
                return constant;
            }
        }
        var expected = Arrays.stream(type.getEnumConstants()).map(Orderings::apiValue).collect(joining(", "));
        throw new IllegalArgumentException("Unknown ordering '%s', expected one of %s.".formatted(value, expected));
    }
}
