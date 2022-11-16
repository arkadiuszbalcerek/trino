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
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemSecurityContext;
import org.testng.annotations.Test;

import java.io.File;

import static com.google.common.io.Files.copy;
import static io.trino.plugin.base.security.FileBasedAccessControlConfig.SECURITY_CONFIG_FILE;
import static io.trino.plugin.base.security.FileBasedAccessControlConfig.SECURITY_REFRESH_PERIOD;
import static java.lang.Thread.sleep;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.util.Files.newTemporaryFile;

public class TestFileBasedSystemAccessControl
        extends SystemAccessControlBaseTest
{
    @Test
    public void testRefreshing()
            throws Exception
    {
        File configFile = newTemporaryFile();
        configFile.deleteOnExit();
        copy(new File(getResourcePath("file-based-system-catalog.json")), configFile);

        SystemAccessControl accessControl = newSystemAccessControl(ImmutableMap.of(
                SECURITY_CONFIG_FILE, configFile.getAbsolutePath(),
                SECURITY_REFRESH_PERIOD, "1ms"));

        SystemSecurityContext alice = new SystemSecurityContext(SystemAccessControlBaseTest.alice, queryId);
        accessControl.checkCanCreateView(alice, aliceView);
        accessControl.checkCanCreateView(alice, aliceView);
        accessControl.checkCanCreateView(alice, aliceView);

        copy(new File(getResourcePath("file-based-system-security-config-file-with-unknown-rules.json")), configFile);
        sleep(2);

        assertThatThrownBy(() -> accessControl.checkCanCreateView(alice, aliceView))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("Invalid JSON file");

        // test if file based cached control was not cached somewhere
        assertThatThrownBy(() -> accessControl.checkCanCreateView(alice, aliceView))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("Invalid JSON file");

        copy(new File(getResourcePath("file-based-system-catalog.json")), configFile);
        sleep(2);

        accessControl.checkCanCreateView(alice, aliceView);
    }

    @Test
    public void parseUnknownRules()
    {
        assertThatThrownBy(() -> newSystemAccessControl("file-based-system-security-config-file-with-unknown-rules.json"))
                .hasMessageContaining("Invalid JSON");
    }

    @Override
    protected SystemAccessControl newSystemAccessControl(String resourceName)
    {
        return newSystemAccessControl(ImmutableMap.of("security.config-file", getResourcePath(resourceName)));
    }

    @Override
    protected SystemAccessControl newSystemAccessControl(File rulesFile)
    {
        return newSystemAccessControl(ImmutableMap.of("security.config-file", rulesFile.getAbsolutePath()));
    }

    private SystemAccessControl newSystemAccessControl(ImmutableMap<String, String> config)
    {
        return new FileBasedSystemAccessControlFactory().create(config);
    }
}
