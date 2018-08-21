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
package io.gravitee.policy.eaas.configuration;

import com.github.fabmrc.eaas.api.VaultProperties;

public class GraviteeVaultProperties implements VaultProperties {

    private String token = "ef1054f3-076f-6869-4c77-84286e9d1ace";

    private String key;

    private String host = "192.168.50.11";

    private String encryptionUrl = "/v1/transit/encrypt";

    private String decryptionUrl = "/v1/transit/decrypt";

    private int port = 8200;

    public GraviteeVaultProperties(String key) {
        this.key = key;
    }

    @Override
    public String getKey() {
        return key;
    }

    @Override
    public String getDecryptionUrl() {
        return decryptionUrl;
    }

    @Override
    public String getEncryptionUrl() {
        return encryptionUrl;
    }

    @Override
    public int getPort() {
        return port;
    }

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public String getHost() {
        return host;
    }

}
