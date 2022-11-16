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
import com.google.inject.Injector;
import io.airlift.bootstrap.Bootstrap;
import io.trino.plugin.base.CatalogNameModule;
import io.trino.plugin.base.util.TestingHttpServer;
import io.trino.spi.connector.ConnectorAccessControl;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.google.common.io.Resources.getResource;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class TestRestBasedAccessControl
        extends AccessControlBaseTest
{
    private static int httpPort = 2003;
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
    public void testInvalidRules()
    {
        assertThatThrownBy(() -> createAccessControl("invalid.json"))
                .hasMessageContaining("Failed to convert JSON tree node");
    }

    @Override
    protected ConnectorAccessControl createAccessControl(String fileName)
    {
        byte[] response = readJsonFile(getResource(fileName));
        testingHttpServer.addResponse(response);

        Bootstrap bootstrap = new Bootstrap(new CatalogNameModule("test_catalog"), new RestBasedAccessControlModule());
        Injector injector = bootstrap
                .doNotInitializeLogging()
                .setRequiredConfigurationProperties(ImmutableMap.of("security.config-url", httpConfigUrl))
                .initialize();
        return injector.getInstance(ConnectorAccessControl.class);
    }

    private byte[] readJsonFile(URL rulesFile)
    {
        try {
            return Files.readAllBytes(Path.of(rulesFile.toURI()));
        }
        catch (IOException | URISyntaxException e) {
            throw new RuntimeException("Error while reading json", e);
        }
    }
}
