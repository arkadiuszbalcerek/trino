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
package io.trino.plugin.base.util;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;

public class TestingHttpServer
{
    private final HttpServer httpServer;

    public TestingHttpServer(int port)
            throws IOException
    {
        httpServer = HttpServer.create(new InetSocketAddress(port), 0);
        httpServer.createContext("/test");
        httpServer.start();
    }

    public void addResponse(byte[] response)
    {
        httpServer.removeContext("/test");
        httpServer.createContext("/test", exchange ->
        {
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
    }

    public void shutdown()
            throws Exception
    {
        httpServer.stop(0);
    }
}
