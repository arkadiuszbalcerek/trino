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

import io.airlift.configuration.Config;
import io.airlift.configuration.ConfigDescription;
import io.airlift.units.Duration;
import io.airlift.units.MinDuration;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

public class RestBasedAccessControlConfig
{
    public static final String SECURITY_CONFIG_URL = "security.config-url";
    public static final String SECURITY_REST_REFRESH_PERIOD = "security.refresh-period";
    public static final String SECURITY_JSON_POINTER = "security.json-pointer";

    private String restUrl;
    private Duration refreshPeriod;
    private String jsonPointer = "";

    @NotEmpty
    public String getRestUrl()
    {
        return restUrl;
    }

    @Config(SECURITY_CONFIG_URL)
    public RestBasedAccessControlConfig setRestUrl(String restUrl)
    {
        this.restUrl = restUrl;
        return this;
    }

    @MinDuration("1ms")
    public Duration getRefreshPeriod()
    {
        return refreshPeriod;
    }

    @Config(SECURITY_REST_REFRESH_PERIOD)
    public RestBasedAccessControlConfig setRefreshPeriod(Duration refreshPeriod)
    {
        this.refreshPeriod = refreshPeriod;
        return this;
    }

    @NotNull
    public String getJsonPointer()
    {
        return jsonPointer;
    }

    @Config(SECURITY_JSON_POINTER)
    @ConfigDescription("JSON pointer (RFC 6901) to mappings inside JSON config")
    public RestBasedAccessControlConfig setJsonPointer(String jsonPointer)
    {
        this.jsonPointer = jsonPointer;
        return this;
    }
}
