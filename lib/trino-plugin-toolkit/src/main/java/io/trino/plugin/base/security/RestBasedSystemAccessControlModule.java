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

import com.google.inject.Binder;
import com.google.inject.Inject;
import com.google.inject.Provides;
import io.airlift.configuration.AbstractConfigurationAwareModule;
import io.airlift.configuration.ConfigurationFactory;
import io.airlift.http.client.HttpClient;
import io.airlift.http.client.HttpClientConfig;
import io.airlift.log.Logger;
import io.airlift.units.Duration;
import io.trino.spi.security.SystemAccessControl;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Suppliers.memoizeWithExpiration;
import static io.airlift.configuration.ConfigBinder.configBinder;
import static io.airlift.http.client.HttpClientBinder.httpClientBinder;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

public class RestBasedSystemAccessControlModule
        extends AbstractConfigurationAwareModule
{
    private static final Logger log = Logger.get(RestBasedSystemAccessControlModule.class);
    private static final String HTTP_CLIENT_NAME = "access-control";

    public RestBasedSystemAccessControlModule()
    {
        super();
    }

    public RestBasedSystemAccessControlModule(Map<String, String> config)
    {
        super();
        this.setConfigurationFactory(new ConfigurationFactory(config));
    }

    @Override
    public void setup(Binder binder)
    {
        configBinder(binder).bindConfig(RestBasedAccessControlConfig.class);
        httpClientBinder(binder).bindHttpClient(HTTP_CLIENT_NAME, ForAccessControlRules.class)
                .withConfigDefaults(config -> config
                        .setRequestTimeout(Duration.succinctDuration(10, TimeUnit.SECONDS))
                        .setSelectorCount(1)
                        .setMinThreads(1));
        configBinder(binder).bindConfig(HttpClientConfig.class, HTTP_CLIENT_NAME);
    }

    @Inject
    @Provides
    public SystemAccessControl getSystemAccessControl(RestBasedAccessControlConfig config,
                                                      @ForAccessControlRules HttpClient httpClient)
    {
        String restUrl = config.getRestUrl();
        URI configUri = URI.create(restUrl);

        if (config.getRefreshPeriod() != null) {
            return ForwardingSystemAccessControl.of(memoizeWithExpiration(
                () -> {
                    log.info("Refreshing system access control from %s", restUrl);
                    return create(httpClient, configUri, config.getJsonPointer());
                },
                config.getRefreshPeriod().toMillis(),
                MILLISECONDS));
        }
        return create(httpClient, configUri, config.getJsonPointer());
    }

    private SystemAccessControl create(HttpClient httpClient, URI configUri, String jsonPointer)
    {
        AccessControlRulesRestExtractor<FileBasedSystemAccessControlRules> rulesRestExtractor = new AccessControlRulesRestExtractor<>(
                httpClient, configUri, jsonPointer, FileBasedSystemAccessControlRules.class);
        FileBasedSystemAccessControlRules rules = rulesRestExtractor.extract();
        return new SystemAccessControlFactory(rules).create();
    }
}
