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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.policy.eaas.configuration.EncryptionPolicyConfiguration;
import io.gravitee.policy.eaas.configuration.VaultProperties;
import io.vertx.core.http.HttpClient;
import org.gravitee.encryption.api.AsyncVaultDriver;
import org.gravitee.encryption.api.jackson.EncryptVaultRequest;
import org.gravitee.encryption.api.jackson.EncryptVaultResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.function.Consumer;

public class VertxVaultDriver implements AsyncVaultDriver {

    private final static Logger logger = LoggerFactory.getLogger(VertxVaultDriver.class);

    private ObjectMapper objectMapper;

    private HttpClient httpClient;

    private EncryptionPolicyConfiguration configuration;

    private VaultProperties properties;

    public VertxVaultDriver(ObjectMapper objectMapper, HttpClient httpClient, EncryptionPolicyConfiguration configuration, VaultProperties properties) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.configuration = configuration;
    }

    @Override
    public void encrypt(EncryptVaultRequest request, Consumer<EncryptVaultResponse> onResponse, Consumer<Exception> onError) throws Exception {
        String requestStr = objectMapper.writeValueAsString(request);
        httpClient.post(String.join("/", properties.getEncryptionUrl(), configuration.getKey()), clientResponse -> clientResponse.bodyHandler(totalBuffer -> {
            String responseBuffer = totalBuffer.getString(0, totalBuffer.length());
            logger.debug("response :" + clientResponse.statusCode() + "; " + responseBuffer);
            if (clientResponse.statusCode() == HttpStatusCode.OK_200) {
                EncryptVaultResponse vaultResponse;
                try {
                    vaultResponse = objectMapper.readValue(responseBuffer, EncryptVaultResponse.class);
                    onResponse.accept(vaultResponse);
                } catch (IOException e) {
                    onError.accept(e);
                }
            } else {
                onError.accept(new IllegalStateException());
            }
        })).exceptionHandler(ex -> {
            onError.accept(new IllegalStateException(ex));
        }).putHeader("X-Vault-Token", properties.getToken()).end(requestStr);
    }

}
