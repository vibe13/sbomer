/*
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
package org.jboss.sbomer.service.feature.sbom.features.umb.consumer;

import java.util.Objects;

import org.jboss.pnc.api.enums.ProgressStatus;
import org.jboss.pnc.common.Strings;
import org.jboss.sbomer.service.feature.sbom.config.features.UmbConfig;
import org.jboss.sbomer.service.feature.sbom.config.features.UmbConfig.UmbConsumerTrigger;
import org.jboss.sbomer.service.feature.sbom.features.umb.consumer.model.PncDelAnalysisNotificationMessageBody;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationType;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequest;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequestBuilder;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.client.KubernetesClient;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;

/**
 * Handler for PNC deliverable analysis notifications.
 *
 * @author Andrea Vibelli
 */
@ApplicationScoped
@Slf4j
public class PncDelAnalysisNotificationHandler {

    @Inject
    UmbConfig config;

    @Inject
    KubernetesClient kubernetesClient;

    /**
     * Handles a particular message received from PNC after the deliverable analysis is finished.
     *
     * @param messageBody the body of the PNC build notification.
     */
    public void handle(PncDelAnalysisNotificationMessageBody messageBody) {
        if (messageBody == null) {
            log.warn("Received message does not contain body, ignoring");
            return;
        }

        if (Strings.isEmpty(messageBody.getOperationId())) {
            log.warn("Received message without PNC Operation ID specified");
            return;
        }

        if (Objects.equals(config.consumer().trigger().orElse(null), UmbConsumerTrigger.NONE)) {
            log.warn(
                    "The UMB consumer configuration is set to NONE, skipping SBOM generation for PNC Deliverable Analysis '{}'",
                    messageBody.getOperationId());
            return;
        }

        if (isFinishedAnalysis(messageBody)) {

            log.info("Triggering automated SBOM generation for PNC build '{}'' ...", messageBody.getOperationId());
            GenerationRequest req = new GenerationRequestBuilder()
                    .withNewDefaultMetadata(messageBody.getOperationId(), SbomGenerationType.OPERATION)
                    .endMetadata()
                    .withOperationId(messageBody.getOperationId())
                    .withStatus(SbomGenerationStatus.NEW)
                    .build();

            log.debug("ConfigMap to create: '{}'", req);

            ConfigMap cm = kubernetesClient.configMaps().resource(req).create();

            log.info("Request created: {}", cm.getMetadata().getName());
        }
    }

    public boolean isFinishedAnalysis(PncDelAnalysisNotificationMessageBody msgBody) {
        log.info(
                "Received UMB message notification operation {}, with status {} and deliverable urls {}",
                msgBody.getOperationId(),
                msgBody.getStatus(),
                String.join(";", msgBody.getDeliverablesUrls()));

        if (ProgressStatus.FINISHED.equals(msgBody.getStatus())) {
            return true;
        }

        return false;
    }
}
