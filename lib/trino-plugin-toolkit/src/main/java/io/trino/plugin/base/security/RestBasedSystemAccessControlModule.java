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
import com.google.inject.Module;
import com.google.inject.Provides;
import io.airlift.log.Logger;
import io.airlift.units.Duration;
import io.trino.spi.security.SystemAccessControl;

import java.util.concurrent.TimeUnit;

import static com.google.common.base.Suppliers.memoizeWithExpiration;
import static io.airlift.configuration.ConfigBinder.configBinder;
import static io.airlift.http.client.HttpClientBinder.httpClientBinder;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

public class RestBasedSystemAccessControlModule
        implements Module
{
    private static final Logger log = Logger.get(RestBasedSystemAccessControlModule.class);
    private static final String HTTP_CLIENT_NAME = "system-access-control";

    @Override
    public void configure(Binder binder)
    {
        configBinder(binder).bindConfig(RestBasedAccessControlConfig.class);
        httpClientBinder(binder).bindHttpClient(HTTP_CLIENT_NAME, ForAccessControlRules.class)
                .withConfigDefaults(config -> config
                        .setRequestTimeout(Duration.succinctDuration(10, TimeUnit.SECONDS))
                        .setSelectorCount(1)
                        .setMinThreads(1));
        binder.bind(AccessControlRulesRestExtractor.class);
    }

    @Inject
    @Provides
    public SystemAccessControl getSystemAccessControl(RestBasedAccessControlConfig config,
                                                      AccessControlRulesRestExtractor rulesRestExtractor)
    {
        if (config.getRefreshPeriod() != null) {
            return ForwardingSystemAccessControl.of(memoizeWithExpiration(
                () -> {
                    log.info("Refreshing system access control from %s", config.getRestUrl());
                    return create(rulesRestExtractor);
                },
                config.getRefreshPeriod().toMillis(),
                MILLISECONDS));
        }
        return create(rulesRestExtractor);
    }

    private SystemAccessControl create(AccessControlRulesRestExtractor rulesRestExtractor)
    {
        SystemAccessControlRules rules = rulesRestExtractor.extract(SystemAccessControlRules.class);
        return new SystemAccessControlFactory(rules).create();
    }
}
