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
import io.trino.plugin.base.util.TestingHttpServer;
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemSecurityContext;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static io.trino.plugin.base.security.RestBasedAccessControlConfig.SECURITY_CONFIG_URL;
import static io.trino.plugin.base.security.RestBasedAccessControlConfig.SECURITY_REST_REFRESH_PERIOD;
import static java.lang.Thread.sleep;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class TestRestBasedSystemAccessControl
        extends SystemAccessControlBaseTest
{
    private static int httpPort = 2002;
    private static String httpConfigUrl = "http://localhost:" + httpPort + "/test";
    private TestingHttpServer testingHttpServer;

    @BeforeClass
    public void setup()
            throws IOException
    {
        testingHttpServer = new TestingHttpServer(httpPort);
    }

    @AfterClass(alwaysRun = true)
    public void teardown() throws Exception
    {
        testingHttpServer.shutdown();
    }

    @Test
    public void testRefreshing()
            throws Exception
    {
        byte[] response = readJsonFile(Path.of(getResourcePath("file-based-system-catalog.json")));
        testingHttpServer.addResponse(response);

        SystemAccessControl accessControl = newSystemAccessControl(ImmutableMap.of(
                SECURITY_CONFIG_URL, httpConfigUrl,
                SECURITY_REST_REFRESH_PERIOD, "1ms"));

        SystemSecurityContext alice = new SystemSecurityContext(SystemAccessControlBaseTest.alice, queryId);
        accessControl.checkCanCreateView(alice, aliceView);
        accessControl.checkCanCreateView(alice, aliceView);
        accessControl.checkCanCreateView(alice, aliceView);

        response = readJsonFile(Path.of(getResourcePath("file-based-system-security-config-file-with-unknown-rules.json")));
        testingHttpServer.addResponse(response);
        sleep(2);

        assertThatThrownBy(() -> accessControl.checkCanCreateView(alice, aliceView))
                .hasMessageStartingWith("Failed to convert JSON tree node");

        // test if file based cached control was not cached somewhere
        assertThatThrownBy(() -> accessControl.checkCanCreateView(alice, aliceView))
                .hasMessageStartingWith("Failed to convert JSON tree node");

        response = readJsonFile(Path.of(getResourcePath("file-based-system-catalog.json")));
        testingHttpServer.addResponse(response);
        sleep(2);

        accessControl.checkCanCreateView(alice, aliceView);
    }

    @Test
    public void parseUnknownRules()
    {
        assertThatThrownBy(() -> newSystemAccessControl("file-based-system-security-config-file-with-unknown-rules.json"))
                .hasMessageContaining("Failed to convert JSON tree node");
    }

    @Override
    protected SystemAccessControl newSystemAccessControl(String resourceName)
    {
        return newSystemAccessControl(Path.of(getResourcePath(resourceName)));
    }

    @Override
    protected SystemAccessControl newSystemAccessControl(File rulesFile)
    {
        return newSystemAccessControl(rulesFile.toPath());
    }

    private SystemAccessControl newSystemAccessControl(Path rulesFile)
    {
        byte[] response = readJsonFile(rulesFile);
        testingHttpServer.addResponse(response);
        return newSystemAccessControl(ImmutableMap.of("security.config-url", httpConfigUrl));
    }

    private byte[] readJsonFile(Path rulesFile)
    {
        try {
            return Files.readAllBytes(rulesFile);
        }
        catch (IOException e) {
            throw new RuntimeException("Error while reading json", e);
        }
    }

    private SystemAccessControl newSystemAccessControl(ImmutableMap<String, String> config)
    {
        return new RestBasedSystemAccessControlFactory().create(config);
    }
}
