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

import com.fasterxml.jackson.databind.JsonNode;
import io.trino.plugin.base.util.JsonUtils;

public final class FileBasedAccessControlUtils
{
    private FileBasedAccessControlUtils()
    {
    }

    public static boolean isRest(FileBasedAccessControlConfig config)
    {
        return config.getConfigFilePath().startsWith("https://") || config.getConfigFilePath().startsWith("http://");
    }

    public static <R> R parseJSONString(String jsonString, String jsonPointer, Class<R> clazz)
    {
        JsonNode node = JsonUtils.parseJson(jsonString);
        JsonNode mappingsNode = node.at(jsonPointer);
        return JsonUtils.jsonTreeToValue(mappingsNode, clazz);
    }
}