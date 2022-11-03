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
import io.airlift.log.Logger;
import io.trino.spi.security.SystemAccessControl;

import java.nio.file.Paths;
import java.util.Map;

import static com.google.common.base.Suppliers.memoizeWithExpiration;
import static io.airlift.configuration.ConfigBinder.configBinder;
import static io.trino.plugin.base.util.JsonUtils.parseJson;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

public class LocalFileBasedSystemAccessControlModule
        extends AbstractConfigurationAwareModule
{
    private static final Logger log = Logger.get(LocalFileBasedSystemAccessControlModule.class);

    public LocalFileBasedSystemAccessControlModule()
    {
        super();
    }

    public LocalFileBasedSystemAccessControlModule(Map<String, String> config)
    {
        super();
        this.setConfigurationFactory(new ConfigurationFactory(config));
    }

    @Override
    public void setup(Binder binder)
    {
        configBinder(binder).bindConfig(LocalFileBasedAccessControlConfig.class);
    }

    @Inject
    @Provides
    public SystemAccessControl getSystemAccessControl(LocalFileBasedAccessControlConfig config)
    {
        String configFilePath = config.getConfigFile().getPath();

        if (config.getRefreshPeriod() != null) {
            return ForwardingSystemAccessControl.of(memoizeWithExpiration(
                () -> {
                    log.info("Refreshing system access control from %s", configFilePath);
                    return create(configFilePath);
                },
                config.getRefreshPeriod().toMillis(),
                MILLISECONDS));
        }
        return create(configFilePath);
    }

    private SystemAccessControl create(String configFileName)
    {
        FileBasedSystemAccessControlRules rules = parseJson(Paths.get(configFileName), FileBasedSystemAccessControlRules.class);
        return new SystemAccessControlFactory(rules).create();
    }
}
