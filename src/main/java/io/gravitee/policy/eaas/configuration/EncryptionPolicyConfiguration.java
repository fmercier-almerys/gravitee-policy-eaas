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

import io.gravitee.policy.api.PolicyConfiguration;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;

import static org.springframework.util.Assert.isTrue;

public class EncryptionPolicyConfiguration implements PolicyConfiguration {

    private String key;

    private List<String> pointers;

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public List<String> getPointers() {
        return pointers;
    }

    public void setPointers(String pointers) {
        isTrue(!StringUtils.isEmpty(pointers), "pointers must not be empty or null");
        String[] pointerArray = pointers.split(",");
        Arrays.stream(pointerArray).map(String::trim);
        this.pointers = Arrays.asList(pointerArray);
    }
}
