package io.kestra.plugin.gitguardian.incidents;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

@KestraTest
class IgnoreReasonTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Test
    void acceptsAnyCaseLikeAFlowWould() throws Exception {
        var runContext = runContextFactory.of();

        for (var value : new String[]{"TEST_CREDENTIAL", "test_credential", "Test_Credential"}) {
            var reason = runContext.render(Property.<IgnoreReason>ofExpression("{{ '" + value + "' }}")).as(IgnoreReason.class).orElseThrow();
            assertThat(reason, is(IgnoreReason.TEST_CREDENTIAL));
        }
    }

    @Test
    void rejectsUnknownValue() {
        assertThrows(IllegalArgumentException.class, () -> IgnoreReason.fromString("nope"));
    }
}
