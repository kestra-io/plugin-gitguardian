package io.kestra.plugin.gitguardian;

import io.kestra.plugin.gitguardian.incidents.IncidentOrdering;
import io.kestra.plugin.gitguardian.sources.SourceOrdering;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OrderingsTest {
    @Test
    void serializesDescendingConstantsToTheApiForm() {
        assertThat(IncidentOrdering.RISK_SCORE_DESC.apiValue(), is("-risk_score"));
        assertThat(IncidentOrdering.DATE.apiValue(), is("date"));
        assertThat(SourceOrdering.LAST_SCAN_DATE_DESC.apiValue(), is("-last_scan_date"));
    }

    @Test
    void parsesApiFormAndConstantNameInAnyCasing() {
        assertThat(IncidentOrdering.fromString("-date"), is(IncidentOrdering.DATE_DESC));
        assertThat(IncidentOrdering.fromString("date_desc"), is(IncidentOrdering.DATE_DESC));
        assertThat(IncidentOrdering.fromString("RISK_SCORE"), is(IncidentOrdering.RISK_SCORE));
        assertThat(IncidentOrdering.fromString(null), nullValue());
    }

    @Test
    void rejectsUnknownOrderingWithTheValidValues() {
        var exception = assertThrows(IllegalArgumentException.class, () -> IncidentOrdering.fromString("-name"));

        assertThat(exception.getMessage(), containsString("-risk_score"));
    }
}
