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
import static io.trino.plugin.base.security.LocalFileBasedAccessControlConfig.SECURITY_CONFIG_FILE;
import static io.trino.plugin.base.security.LocalFileBasedAccessControlConfig.SECURITY_REFRESH_PERIOD;
import static io.trino.plugin.base.security.LocalFileBasedAccessControlConfig.SECURITY_REST_FLAG;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class TestLocalFileBasedAccessControlConfig
{
    @Test
    public void testDefaults()
    {
        assertRecordedDefaults(recordDefaults(LocalFileBasedAccessControlConfig.class)
                .setConfigFile(null)
                .setRefreshPeriod(null)
                .setRest(false));
    }

    @Test
    public void testExplicitPropertyMappingsWithLocalFile()
            throws IOException
    {
        Path securityConfigFile = Files.createTempFile(null, null);

        Map<String, String> properties = ImmutableMap.<String, String>builder()
                .put(SECURITY_CONFIG_FILE, securityConfigFile.toString())
                .put(SECURITY_REFRESH_PERIOD, "1s")
                .put(SECURITY_REST_FLAG, "true")
                .buildOrThrow();

        LocalFileBasedAccessControlConfig expected = (LocalFileBasedAccessControlConfig) new LocalFileBasedAccessControlConfig()
                .setConfigFile(securityConfigFile.toFile())
                .setRefreshPeriod(new Duration(1, TimeUnit.SECONDS))
                .setRest(true);

        assertFullMapping(properties, expected);
    }

    @Test
    public void testValidation()
            throws IOException
    {
        Path securityConfigFile = Files.createTempFile(null, null);

        assertThatThrownBy(() -> newInstance(ImmutableMap.of(SECURITY_REFRESH_PERIOD, "1ms")))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("security.config-file: may not be null ");

        assertThatThrownBy(() -> newInstance(ImmutableMap.of(
                SECURITY_CONFIG_FILE, securityConfigFile.toString(),
                SECURITY_REFRESH_PERIOD, "1us")))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("Invalid configuration property security.refresh-period");

        newInstance(ImmutableMap.of(SECURITY_CONFIG_FILE, securityConfigFile.toString()));
    }

    private static LocalFileBasedAccessControlConfig newInstance(Map<String, String> properties)
    {
        ConfigurationFactory configurationFactory = new ConfigurationFactory(properties);
        return configurationFactory.build(LocalFileBasedAccessControlConfig.class);
    }
}
