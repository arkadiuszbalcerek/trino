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
import io.trino.spi.security.SystemAccessControl;

import java.nio.file.Paths;

import static com.google.common.base.Suppliers.memoizeWithExpiration;
import static io.airlift.configuration.ConfigBinder.configBinder;
import static io.trino.plugin.base.util.JsonUtils.parseJson;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

public class FileBasedSystemAccessControlModule
        implements Module
{
    private static final Logger log = Logger.get(FileBasedSystemAccessControlModule.class);

    @Override
    public void configure(Binder binder)
    {
        configBinder(binder).bindConfig(FileBasedAccessControlConfig.class);
    }

    @Inject
    @Provides
    public SystemAccessControl getSystemAccessControl(FileBasedAccessControlConfig config)
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
        SystemAccessControlRules rules = parseJson(Paths.get(configFileName), SystemAccessControlRules.class);
        return new SystemAccessControlFactory(rules).create();
    }
}
