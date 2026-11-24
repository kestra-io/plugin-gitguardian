package io.kestra.plugin.gitguardian.auditlogs;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.common.FetchType;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import io.kestra.core.utils.TestsUtils;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

@KestraTest
@WireMockTest
class AuditLogsTest {
    @Inject
    private RunContextFactory runContextFactory;

    static String event(long id, String date, String name) {
        return """
            {"id":%d,"date":"%s","event_name":"%s","action_type":"update","member_email":"alice@company.com","member_id":5,"ip_address":"10.0.0.1","target_ids":[42],"data":{"reason":"false_positive"}}
            """.formatted(id, date, name);
    }

    @Test
    void listFiltersAndMaps(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/audit_logs"))
            .withQueryParam("event_name", equalTo("incident.ignored"))
            .withQueryParam("member_email", equalTo("alice@company.com"))
            .willReturn(okJson("[" + event(1, "2026-09-01T10:00:00Z", "incident.ignored") + "]")));

        var output = List.builder()
            .id(IdUtils.create()).type(List.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .eventName(Property.ofValue("incident.ignored"))
            .memberEmail(Property.ofValue("alice@company.com"))
            .fetchType(Property.ofValue(FetchType.FETCH))
            .build()
            .run(runContextFactory.of(Map.of()));

        assertThat(output.getSize(), is(1L));
        var entry = output.getRows().getFirst();
        assertThat(entry.getEventName(), is("incident.ignored"));
        assertThat(entry.getMemberId(), is(5L));
        assertThat(entry.getData().get("reason"), is("false_positive"));
    }

    @Test
    void triggerSeedsThenFiresOneExecutionWithAllNewEvents(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/audit_logs"))
            .willReturn(okJson("[" + event(1, "2099-01-01T10:00:00Z", "incident.ignored") + "," + event(2, "2099-01-01T10:00:00Z", "api_token.created") + "," + event(3, "2099-01-01T10:05:00Z", "incident.resolved") + "]")));

        var trigger = Trigger.builder()
            .id(IdUtils.create()).type(Trigger.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .interval(Duration.ofMinutes(5))
            .build();
        var ctx = TestsUtils.mockTrigger(runContextFactory, trigger);

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));

        var fired = trigger.eval(ctx.getKey(), ctx.getValue().context());
        assertThat(fired.isPresent(), is(true));
        assertThat(fired.get().trigger().getVariables().get("count"), is(3));
        assertThat((java.util.List<?>) fired.get().trigger().getVariables().get("events"), hasSize(3));

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
    }

    @Test
    void triggerCapsEventsPerPollAndDeliversTheRestNext(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/audit_logs"))
            .willReturn(okJson("[" + event(1, "2099-01-01T10:00:00Z", "incident.ignored") + "," + event(2, "2099-01-01T10:01:00Z", "incident.ignored") + "," + event(3, "2099-01-01T10:02:00Z", "incident.ignored") + "]")));

        var trigger = Trigger.builder()
            .id(IdUtils.create()).type(Trigger.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .maxItemsPerPoll(Property.ofValue(2))
            .interval(Duration.ofMinutes(5))
            .build();
        var ctx = TestsUtils.mockTrigger(runContextFactory, trigger);

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));

        var first = trigger.eval(ctx.getKey(), ctx.getValue().context());
        assertThat(first.get().trigger().getVariables().get("count"), is(2));
        var second = trigger.eval(ctx.getKey(), ctx.getValue().context());
        assertThat(second.get().trigger().getVariables().get("count"), is(1));
        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
    }

    @Test
    void triggerLosesNoEventWhenTheApiListsNewestFirstAcrossPages(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/audit_logs"))
            .withQueryParam("cursor", absent())
            .willReturn(okJson("[" + event(4, "2099-01-01T10:03:00Z", "incident.ignored") + "," + event(3, "2099-01-01T10:02:00Z", "incident.ignored") + "]")
                .withHeader("Link", "<" + wireMock.getHttpBaseUrl() + "/v1/audit_logs?cursor=next>; rel=\"next\"")));
        stubFor(get(urlPathEqualTo("/v1/audit_logs"))
            .withQueryParam("cursor", equalTo("next"))
            .willReturn(okJson("[" + event(2, "2099-01-01T10:01:00Z", "incident.ignored") + "," + event(1, "2099-01-01T10:00:00Z", "incident.ignored") + "]")));

        var trigger = Trigger.builder()
            .id(IdUtils.create()).type(Trigger.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .maxItemsPerPoll(Property.ofValue(2))
            .interval(Duration.ofMinutes(5))
            .build();
        var ctx = TestsUtils.mockTrigger(runContextFactory, trigger);

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));

        var delivered = new ArrayList<Long>();
        for (var poll = 0; poll < 2; poll++) {
            var fired = trigger.eval(ctx.getKey(), ctx.getValue().context());
            assertThat(fired.isPresent(), is(true));
            ((java.util.List<?>) fired.get().trigger().getVariables().get("events"))
                .forEach(event -> delivered.add(((Number) ((Map<?, ?>) event).get("id")).longValue()));
        }

        assertThat(delivered, contains(1L, 2L, 3L, 4L));
        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
    }
}
