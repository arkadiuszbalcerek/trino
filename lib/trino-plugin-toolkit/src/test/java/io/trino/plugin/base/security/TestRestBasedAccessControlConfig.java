/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.base.security;

import com.google.common.collect.ImmutableMap;
import com.google.inject.ConfigurationException;
import io.airlift.configuration.ConfigurationFactory;
import io.airlift.units.Duration;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static io.airlift.configuration.testing.ConfigAssertions.assertFullMapping;
import static io.airlift.configuration.testing.ConfigAssertions.assertRecordedDefaults;
import static io.airlift.configuration.testing.ConfigAssertions.recordDefaults;
import static io.trino.plugin.base.security.RestBasedAccessControlConfig.SECURITY_CONFIG_URL;
import static io.trino.plugin.base.security.RestBasedAccessControlConfig.SECURITY_JSON_POINTER;
import static io.trino.plugin.base.security.RestBasedAccessControlConfig.SECURITY_REST_REFRESH_PERIOD;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class TestRestBasedAccessControlConfig
{
    @Test
    public void testDefaults()
    {
        assertRecordedDefaults(recordDefaults(RestBasedAccessControlConfig.class)
                .setRestUrl(null)
                .setJsonPointer("")
                .setRefreshPeriod(null));
    }

    @Test
    public void testExplicitPropertyMappings()
    {
        Map<String, String> properties = ImmutableMap.<String, String>builder()
                .put(SECURITY_CONFIG_URL, "http://test:1234/example")
                .put(SECURITY_JSON_POINTER, "/data")
                .put(SECURITY_REST_REFRESH_PERIOD, "1s")
                .buildOrThrow();

        RestBasedAccessControlConfig expected = new RestBasedAccessControlConfig()
                .setRestUrl("http://test:1234/example")
                .setJsonPointer("/data")
                .setRefreshPeriod(new Duration(1, TimeUnit.SECONDS));

        assertFullMapping(properties, expected);
    }

    @Test
    public void testValidation()
            throws IOException
    {
        Path securityConfigFile = Files.createTempFile(null, null);

        assertThatThrownBy(() -> newInstance(ImmutableMap.of(SECURITY_REST_REFRESH_PERIOD, "1ms")))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("security.config-url: must not be empty ");

        assertThatThrownBy(() -> newInstance(ImmutableMap.of(
                SECURITY_CONFIG_URL, securityConfigFile.toString(),
                SECURITY_REST_REFRESH_PERIOD, "1us")))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("Invalid configuration property security.refresh-period");

        newInstance(ImmutableMap.of(SECURITY_CONFIG_URL, securityConfigFile.toString()));
    }

    private static RestBasedAccessControlConfig newInstance(Map<String, String> properties)
    {
        ConfigurationFactory configurationFactory = new ConfigurationFactory(properties);
        return configurationFactory.build(RestBasedAccessControlConfig.class);
    }
}
