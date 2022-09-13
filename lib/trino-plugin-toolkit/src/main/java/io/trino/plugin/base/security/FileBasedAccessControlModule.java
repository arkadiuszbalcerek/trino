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
import com.google.inject.Scopes;
import com.google.inject.TypeLiteral;
import io.airlift.configuration.AbstractConfigurationAwareModule;
import io.airlift.log.Logger;
import io.airlift.units.Duration;
import io.trino.plugin.base.CatalogName;
import io.trino.spi.connector.ConnectorAccessControl;

import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static com.google.common.base.Suppliers.memoizeWithExpiration;
import static io.airlift.configuration.ConditionalModule.conditionalModule;
import static io.airlift.configuration.ConfigBinder.configBinder;
import static io.airlift.http.client.HttpClientBinder.httpClientBinder;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

public class FileBasedAccessControlModule
        extends AbstractConfigurationAwareModule
{
    private static final Logger log = Logger.get(FileBasedAccessControlModule.class);

    @Override
    public void setup(Binder binder)
    {
        bindRules(binder);
        configBinder(binder).bindConfig(FileBasedAccessControlConfig.class);
    }

    private void bindRules(Binder binder)
    {
        FileBasedAccessControlConfig configuration = buildConfigObject(FileBasedAccessControlConfig.class);
        install(conditionalModule(
                FileBasedAccessControlConfig.class,
                config -> config.isRest(),
                innerBinder -> {
                    innerBinder.bind(new TypeLiteral<Supplier<AccessControlRules>>() {})
                            .to(RestFileBasedAccessControlRulesProvider.class)
                            .in(Scopes.SINGLETON);
                    httpClientBinder(innerBinder).bindHttpClient("security-http-client", ForAccessControlRules.class)
                            .withConfigDefaults(config -> config
                                    .setRequestTimeout(Duration.succinctDuration(10, TimeUnit.SECONDS))
                                    .setSelectorCount(1)
                                    .setMinThreads(1));
                }));
        install(conditionalModule(
                FileBasedAccessControlConfig.class,
                config -> !config.isRest(),
                innerBinder -> {
                    innerBinder.bind(new TypeLiteral<Supplier<AccessControlRules>>() {})
                            .toProvider(() -> new LocalFileAccessControlRulesProvider<>(configuration, AccessControlRules.class))
                            .in(Scopes.SINGLETON);
                }));
    }

    @Inject
    @Provides
    public ConnectorAccessControl getConnectorAccessControl(
            CatalogName catalogName,
            FileBasedAccessControlConfig config,
            Supplier<AccessControlRules> rulesProvider)
    {
        String configFilePath = config.getConfigFilePath();
        if (config.getRefreshPeriod() != null) {
            return ForwardingConnectorAccessControl.of(memoizeWithExpiration(
                    () -> {
                        log.info("Refreshing access control for catalog '%s' from: %s", catalogName, configFilePath);
                        return new FileBasedAccessControl(catalogName, rulesProvider);
                    },
                    config.getRefreshPeriod().toMillis(),
                    MILLISECONDS));
        }
        return new FileBasedAccessControl(catalogName, rulesProvider);
    }
}
