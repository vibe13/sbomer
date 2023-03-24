/**
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.redhat.sbomer.generator;

import javax.enterprise.context.ApplicationScoped;
import javax.json.Json;

import org.redhat.sbomer.errors.ApplicationException;

/**
 * Implementation responsible for running the Maven CycloneDX generator.
 */
@CycloneDX
@ApplicationScoped
public class TektonCycloneDXSbomGenerator extends AbstractTektonSbomGenerator {

    @Override
    public void generate(String buildId) throws ApplicationException {
        var config = Json.createObjectBuilder()
                .add("version", "2.7.5")
                .add("additional-args", "--batch-mode --no-transfer-progress --quiet")
                .build();

        runTektonTask("sbomer-generate-cyclonedx", buildId, config);
    }
}
