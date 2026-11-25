package io.kestra.plugin.gitguardian.incidents;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.TriggerEvaluationResult;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import io.kestra.core.utils.TestsUtils;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;

@KestraTest
@WireMockTest
class TriggerTest {
    @Inject
    private RunContextFactory runContextFactory;

    private Trigger trigger(WireMockRuntimeInfo wireMock) {
        return trigger(wireMock, 100);
    }

    private Trigger trigger(WireMockRuntimeInfo wireMock, int maxItemsPerPoll) {
        return Trigger.builder()
            .maxItemsPerPoll(Property.ofValue(maxItemsPerPoll))
            .id(IdUtils.create())
            .type(Trigger.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl()))
            .apiKey(Property.ofValue("k"))
            .severity(Property.ofValue(Severity.CRITICAL))
            .interval(Duration.ofMinutes(1))
            .build();
    }

    @Test
    void firstPollSeedsBaselineFromNewestIncidentAndDoesNotFire(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .withQueryParam("ordering", equalTo("-date"))
            .withQueryParam("per_page", equalTo("1"))
            .withQueryParam("severity", equalTo("critical"))
            .willReturn(okJson("[" + ListTest.incident(10, "2026-09-01T10:00:00Z") + "]")));

        var trigger = trigger(wireMock);
        var ctx = TestsUtils.mockTrigger(runContextFactory, trigger);

        var result = trigger.eval(ctx.getKey(), ctx.getValue().context());

        assertThat(result.isPresent(), is(false));
        verify(1, getRequestedFor(urlPathEqualTo("/v1/incidents/secrets")));
    }

    private static void stubBacklog() {
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .withQueryParam("ordering", equalTo("-date"))
            .willReturn(okJson("[" + ListTest.incident(10, "2026-09-01T10:00:00Z") + "]")));
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .withQueryParam("ordering", equalTo("date"))
            .withQueryParam("date_after", matching("2026-09-01T09:59:59Z"))
            .willReturn(okJson("["
                + ListTest.incident(10, "2026-09-01T10:00:00Z") + ","
                + ListTest.incident(11, "2026-09-01T10:00:00Z") + ","
                + ListTest.incident(12, "2026-09-01T10:05:00Z") + "]")));
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .withQueryParam("ordering", equalTo("date"))
            .withQueryParam("date_after", matching("2026-09-01T10:04:59Z"))
            .willReturn(okJson("[" + ListTest.incident(12, "2026-09-01T10:05:00Z") + "]")));
    }

    private static List<Long> ids(Optional<TriggerEvaluationResult> result) {
        return ((List<?>) result.get().trigger().getVariables().get("incidents")).stream()
            .map(incident -> (Long) ((Map<?, ?>) incident).get("id"))
            .toList();
    }

    @Test
    void firesEveryNewIncidentInOneExecutionAndNeverRefires(WireMockRuntimeInfo wireMock) throws Exception {
        stubBacklog();

        var trigger = trigger(wireMock);
        var ctx = TestsUtils.mockTrigger(runContextFactory, trigger);

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));

        var second = trigger.eval(ctx.getKey(), ctx.getValue().context());
        assertThat(second.isPresent(), is(true));
        assertThat(ids(second), contains(11L, 12L));
        assertThat(second.get().trigger().getVariables().get("count"), is(2));

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
    }

    @Test
    void capsTheBatchAndDrainsTheBacklogOverSeveralPolls(WireMockRuntimeInfo wireMock) throws Exception {
        stubBacklog();

        var trigger = trigger(wireMock, 1);
        var ctx = TestsUtils.mockTrigger(runContextFactory, trigger);

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
        assertThat(ids(trigger.eval(ctx.getKey(), ctx.getValue().context())), contains(11L));
        assertThat(ids(trigger.eval(ctx.getKey(), ctx.getValue().context())), contains(12L));
        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
    }

    @Test
    void stopsWalkingPagesOnceTheCapIsReached(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .withQueryParam("ordering", equalTo("-date"))
            .willReturn(okJson("[" + ListTest.incident(10, "2026-09-01T10:00:00Z") + "]")));
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .withQueryParam("ordering", equalTo("date"))
            .withQueryParam("cursor", absent())
            .willReturn(okJson("[" + ListTest.incident(11, "2026-09-01T10:01:00Z") + "," + ListTest.incident(12, "2026-09-01T10:02:00Z") + "]")
                .withHeader("Link", "<" + wireMock.getHttpBaseUrl() + "/v1/incidents/secrets?cursor=next>; rel=\"next\"")));
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets"))
            .withQueryParam("cursor", equalTo("next"))
            .willReturn(okJson("[" + ListTest.incident(13, "2026-09-01T10:03:00Z") + "]")));

        var trigger = trigger(wireMock, 2);
        var ctx = TestsUtils.mockTrigger(runContextFactory, trigger);

        trigger.eval(ctx.getKey(), ctx.getValue().context());
        assertThat(ids(trigger.eval(ctx.getKey(), ctx.getValue().context())), contains(11L, 12L));

        verify(0, getRequestedFor(urlPathEqualTo("/v1/incidents/secrets")).withQueryParam("cursor", equalTo("next")));
    }

    @Test
    void emptyWorkspaceSeedsBaselineAtNow(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/incidents/secrets")).willReturn(okJson("[]")));

        var trigger = trigger(wireMock);
        var ctx = TestsUtils.mockTrigger(runContextFactory, trigger);

        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
        assertThat(trigger.eval(ctx.getKey(), ctx.getValue().context()).isPresent(), is(false));
    }
}
