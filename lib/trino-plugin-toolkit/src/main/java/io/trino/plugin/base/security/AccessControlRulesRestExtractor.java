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
import io.airlift.http.client.HttpClient;
import io.airlift.http.client.HttpStatus;
import io.airlift.http.client.Request;
import io.airlift.http.client.StringResponseHandler;
import io.trino.plugin.base.util.JsonUtils;

import java.net.URI;

import static io.airlift.http.client.Request.Builder.prepareGet;
import static io.airlift.http.client.StringResponseHandler.createStringResponseHandler;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

public class AccessControlRulesRestExtractor<R>
{
    private final HttpClient httpClient;
    private final URI configUri;
    private final String jsonPointer;
    private final Class<R> clazz;

    public AccessControlRulesRestExtractor(final HttpClient httpClient, final URI configUri, final String jsonPointer, Class<R> clazz)
    {
        this.httpClient = requireNonNull(httpClient);
        this.configUri = requireNonNull(configUri);
        this.jsonPointer = requireNonNull(jsonPointer);
        this.clazz = requireNonNull(clazz);
    }

    public R extract()
    {
        String body = getRawJsonString();
        return parseJSONString(body);
    }

    private String getRawJsonString()
    {
        Request request = prepareGet().setUri(configUri).build();
        StringResponseHandler.StringResponse response = httpClient.execute(request, createStringResponseHandler());
        int status = response.getStatusCode();
        if (status != HttpStatus.OK.code()) {
            throw new IllegalStateException(format("Request to '%s' returned unexpected status code: '%d'", configUri, status));
        }
        return response.getBody();
    }

    private R parseJSONString(String jsonString)
    {
        JsonNode node = JsonUtils.parseJson(jsonString, JsonNode.class);
        JsonNode mappingsNode = node.at(jsonPointer);
        return JsonUtils.jsonTreeToValue(mappingsNode, clazz);
    }
}
