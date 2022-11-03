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
import io.airlift.http.client.HttpClient;
import io.airlift.log.Logger;
import io.airlift.units.Duration;
import io.trino.plugin.base.CatalogName;
import io.trino.spi.connector.ConnectorAccessControl;

import java.net.URI;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Suppliers.memoizeWithExpiration;
import static io.airlift.configuration.ConfigBinder.configBinder;
import static io.airlift.http.client.HttpClientBinder.httpClientBinder;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

public class RestBasedAccessControlModule
        extends AbstractConfigurationAwareModule
{
    private static final Logger log = Logger.get(RestBasedAccessControlModule.class);

    @Override
    public void setup(Binder binder)
    {
        configBinder(binder).bindConfig(RestBasedAccessControlConfig.class);
        httpClientBinder(binder).bindHttpClient("security-http-client", ForAccessControlRules.class)
                .withConfigDefaults(config -> config
                        .setRequestTimeout(Duration.succinctDuration(10, TimeUnit.SECONDS))
                        .setSelectorCount(1)
                        .setMinThreads(1));
    }

    @Inject
    @Provides
    public ConnectorAccessControl getConnectorAccessControl(
            CatalogName catalogName,
            @ForAccessControlRules HttpClient httpClient,
            RestBasedAccessControlConfig config)
    {
        String restUrl = config.getRestUrl();
        URI configUri = URI.create(restUrl);

        if (config.getRefreshPeriod() != null) {
            return ForwardingConnectorAccessControl.of(memoizeWithExpiration(
                    () -> {
                        log.info("Refreshing access control for catalog '%s' from: %s", catalogName, restUrl);
                        return create(catalogName, httpClient, configUri, config.getJsonPointer());
                    },
                    config.getRefreshPeriod().toMillis(),
                    MILLISECONDS));
        }
        return create(catalogName, httpClient, configUri, config.getJsonPointer());
    }

    private RulesBasedAccessControl create(CatalogName catalogName, HttpClient httpClient, URI configUri, String jsonPointer)
    {
        AccessControlRulesRestExtractor<AccessControlRules> rulesRestExtractor = new AccessControlRulesRestExtractor<>(
                httpClient, configUri, jsonPointer, AccessControlRules.class);
        AccessControlRules controlRules = rulesRestExtractor.extract();
        return new RulesBasedAccessControl(catalogName, controlRules);
    }
}
