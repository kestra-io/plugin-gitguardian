package io.kestra.plugin.gitguardian;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.IdUtils;
import io.kestra.plugin.gitguardian.teams.List;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.moreThanOrExactly;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

@KestraTest
@WireMockTest
class GitGuardianClientTest {
    private static final String TEAMS = "[{\"id\":3,\"name\":\"platform\",\"is_global\":false}]";

    @Inject
    private RunContextFactory runContextFactory;

    private List task(WireMockRuntimeInfo wireMock) {
        return List.builder()
            .id(IdUtils.create()).type(List.class.getName())
            .apiUrl(Property.ofValue(wireMock.getHttpBaseUrl())).apiKey(Property.ofValue("k"))
            .build();
    }

    /** The underlying Apache client already retries a 429 once; the second 429 only gets through to the plugin's own retry loop. */
    @Test
    void retriesAfterRateLimitHonouringRetryAfter(WireMockRuntimeInfo wireMock) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/teams")).inScenario("rate-limit").whenScenarioStateIs(Scenario.STARTED)
            .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "1")).willSetStateTo("second"));
        stubFor(get(urlPathEqualTo("/v1/teams")).inScenario("rate-limit").whenScenarioStateIs("second")
            .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "1").withBody("{\"detail\":\"Too many requests\"}")).willSetStateTo("recovered"));
        stubFor(get(urlPathEqualTo("/v1/teams")).inScenario("rate-limit").whenScenarioStateIs("recovered")
            .willReturn(okJson(TEAMS)));

        var start = System.nanoTime();
        var output = task(wireMock).run(runContextFactory.of(Map.of()));
        var elapsedMillis = (System.nanoTime() - start) / 1_000_000;

        assertThat(output.getRows().getFirst().getId(), is(3L));
        assertThat("each retry must wait for Retry-After", elapsedMillis, greaterThanOrEqualTo(2000L));
        verify(3, getRequestedFor(urlPathEqualTo("/v1/teams")));
    }

    @Test
    void givesUpWithAnActionableErrorWhenRateLimitPersists(WireMockRuntimeInfo wireMock) {
        stubFor(get(urlPathEqualTo("/v1/teams"))
            .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "0").withBody("{\"detail\":\"Too many requests\"}")));

        var exception = assertThrows(GitGuardianApiException.class, () -> task(wireMock).run(runContextFactory.of(Map.of())));

        assertThat(exception.getMessage(), containsString("HTTP 429"));
        assertThat(exception.getMessage(), containsString("rate limit"));
        verify(moreThanOrExactly(4), getRequestedFor(urlPathEqualTo("/v1/teams")));
    }
}
