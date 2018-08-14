/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.eaas;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.fge.jackson.JsonLoader;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.stream.BufferedReadWriteStream;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.SimpleReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequestContent;
import io.gravitee.policy.eaas.configuration.EncryptionPolicyConfiguration;
import io.gravitee.policy.eaas.configuration.VaultProperties;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import org.gravitee.encryption.springboot.sample.api.EnhancedJsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class EncryptionService {

    private final static Logger logger = LoggerFactory.getLogger(EncryptionService.class);

    private static final String HTTPS_SCHEME = "https";

    private static final int GLOBAL_TIMEOUT = 10000;

    private EncryptionPolicyConfiguration policyConfiguration;

    private AsyncVaultEngine encryptEngine;

    private ObjectMapper objectMapper = new ObjectMapper();

    private HttpClientOptions options;

    private  VaultProperties properties;

    public EncryptionService(EncryptionPolicyConfiguration policyConfiguration) {
        this.policyConfiguration = policyConfiguration;
        properties = new VaultProperties();
        options = new HttpClientOptions()
                .setSsl(false)
                .setTrustAll(true)
                .setMaxPoolSize(1)
                .setKeepAlive(false)
                .setTcpKeepAlive(false)
                .setConnectTimeout(GLOBAL_TIMEOUT)
                .setDefaultHost(properties.getHost())
                .setDefaultPort(properties.getPort());
    }

    @OnRequestContent
    public ReadWriteStream onRequestContent(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        logger.debug("Execute json encryption on request {}", request.id());

        return new BufferedReadWriteStream() {

            Buffer buffer = Buffer.buffer();

            @Override
            public SimpleReadWriteStream<Buffer> write(Buffer content) {
                buffer.appendBuffer(content);
                return this;
            }

            @Override
            public void end() {
                try {
                    JsonNode jsonNode = JsonLoader.fromString(buffer.toString());
                    EnhancedJsonNode enhancedJsonNode = new EnhancedJsonNode(jsonNode);
                    List<String> resolvedPointers = enhancedJsonNode.getResolvedPointers(policyConfiguration.getPointers());
                    Vertx vertx = executionContext.getComponent(Vertx.class);
                    HttpClient httpClient = vertx.createHttpClient(options);
                    VertxVaultDriver vaultDriver = new VertxVaultDriver(objectMapper, httpClient, properties);
                    encryptEngine = new AsyncVaultEngine(vaultDriver);

                    encryptEngine.encrypt(enhancedJsonNode, resolvedPointers, vaultResponse -> {
                        try {
                            String content = objectMapper.writeValueAsString(enhancedJsonNode.getJsonNode());
                            request.headers().set(HttpHeaders.CONTENT_LENGTH, Integer.toString(content.length()));
                            super.write(Buffer.buffer(content));
                            super.end();
                        } catch (JsonProcessingException e) {
                            handleError(request, e, policyChain, HttpStatusCode.INTERNAL_SERVER_ERROR_500);
                        }
                    }, e ->handleError(request, e, policyChain, HttpStatusCode.BAD_REQUEST_400));
                } catch (Exception e) {
                    handleError(request, e, policyChain, HttpStatusCode.INTERNAL_SERVER_ERROR_500);
                }
            }
        };
    }

    private void handleError(Request request, Exception e, PolicyChain policyChain, int httpStatus) {
        request.metrics().setMessage(e.getMessage());
        policyChain.streamFailWith(PolicyResult.failure(httpStatus, e.getMessage()));
    }
}
