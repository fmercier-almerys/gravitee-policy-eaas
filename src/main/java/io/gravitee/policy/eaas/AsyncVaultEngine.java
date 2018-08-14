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

import org.gravitee.encryption.springboot.sample.api.EnhancedJsonNode;
import org.gravitee.encryption.springboot.sample.jackson.EncryptVaultRequest;
import org.gravitee.encryption.springboot.sample.jackson.EncryptVaultResponse;

import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class AsyncVaultEngine {

    public VertxVaultDriver vaultDriver;

    public  AsyncVaultEngine(VertxVaultDriver vaultDriver) {
        this.vaultDriver = vaultDriver;
    }

    public void encrypt(EnhancedJsonNode jsonNode, List<String> pointers, Consumer<EncryptVaultResponse> onSuccess, Consumer<Exception> onError) throws Exception {
        List<String> values = jsonNode.getValues(pointers);
        EncryptVaultRequest request = buildEncryptRequest(values);
        vaultDriver.encrypt(request, vaultResponse -> {
            jsonNode.replaceValues(pointers, vaultResponse.getCipheredValues());
            onSuccess.accept(vaultResponse);
        }, exception -> {
            onError.accept(exception);
        });
    }

    private EncryptVaultRequest buildEncryptRequest(List<String> values) {
        List<EncryptVaultRequest.EncryptBatchInput> batchInputs = values.stream().map(EncryptVaultRequest.EncryptBatchInput::new).collect(Collectors.toList());
        return new EncryptVaultRequest(batchInputs);
    }
}
