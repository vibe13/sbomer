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
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.microprofile.reactive.messaging.Incoming;
import org.eclipse.microprofile.reactive.messaging.Message;
import org.eclipse.microprofile.reactive.messaging.Metadata;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.service.feature.sbom.config.features.UmbConfig;
import org.jboss.sbomer.service.feature.sbom.features.umb.consumer.model.PncBuildNotificationMessageBody;
import org.jboss.sbomer.service.feature.sbom.features.umb.consumer.model.PncDelAnalysisNotificationMessageBody;

import com.fasterxml.jackson.core.JsonProcessingException;

import io.quarkus.arc.Unremovable;
import io.quarkus.runtime.StartupEvent;
import io.smallrye.reactive.messaging.amqp.IncomingAmqpMetadata;
import io.smallrye.reactive.messaging.annotations.Blocking;
import io.vertx.core.json.JsonObject;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;

/**
 * An UMB message consumer that utilizes the SmallRye Reactive messaging support with the AMQ connector.
 *
 * @author Marek Goldmann
 */
@ApplicationScoped
@Unremovable
@Slf4j
public class AmqpMessageConsumer {

    @Inject
    UmbConfig umbConfig;

    @Inject
    PncBuildNotificationHandler buildNotificationHandler;

    @Inject
    PncDelAnalysisNotificationHandler delAnalysisNotificationHandler;

    private AtomicInteger receivedMessages = new AtomicInteger(0);
    private AtomicInteger processedMessages = new AtomicInteger(0);

    public void init(@Observes StartupEvent ev) {
        if (!umbConfig.isEnabled()) {
            log.info("UMB support is disabled");
            return;
        }

        log.info("Will use the reactive AMQP message consumer");

        if (!umbConfig.isEnabled()) {
            log.warn(
                    "UMB feature is disabled, but this setting will be ignored because the 'sbomer.features.umb.reactive' is set to true");
            return;
        }

        if (!umbConfig.consumer().isEnabled()) {
            log.info(
                    "UMB feature to consume messages is disabled, but this setting will be ignored because the 'sbomer.features.umb.reactive' is set to true");
            return;
        }
    }

    @Incoming("builds")
    @Blocking(ordered = false, value = "build-processor-pool")
    public CompletionStage<Void> process(Message<String> message) {
        receivedMessages.incrementAndGet();

        log.debug("Received new message via the AMQP consumer");
        log.debug("Message content: {}", message.getPayload());

        // Checking whether there is some additional metadata attached to the message
        Optional<IncomingAmqpMetadata> metadata = message.getMetadata(IncomingAmqpMetadata.class);

        AtomicBoolean isBuildStateChange = new AtomicBoolean(false);
        AtomicBoolean isDelAnalysisChange = new AtomicBoolean(false);

        metadata.ifPresent(meta -> {
            JsonObject properties = meta.getProperties();

            log.debug("Message properties: {}", properties.toString());

            if (Objects.equals(properties.getString("type"), "BuildStateChange")) {
                isBuildStateChange.set(true);
            } else if (Objects.equals(properties.getString("type"), "DeliverableAnalysisStateChange")) {
                isDelAnalysisChange.set(true);
            }
        });

        // This shouldn't happen anymore because we use a selector to filter messages
        if (!isBuildStateChange.get() && !isDelAnalysisChange.get()) {
            log.warn("Received a message that is not BuildStateChange nor DeliverableAnalysisStateChange, ignoring it");
            return message.ack();
        }

        if (isBuildStateChange.get()) {
            PncBuildNotificationMessageBody body = null;

            try {
                body = ObjectMapperProvider.json()
                        .readValue(message.getPayload(), PncBuildNotificationMessageBody.class);
            } catch (JsonProcessingException e) {
                log.error("Unable to deserialize PNC build finished message, this is unexpected", e);
                return message.nack(e);
            }

            log.debug("Message of type 'BuildStateChange' properly deserialized");

            buildNotificationHandler.handle(body);
        } else {
            PncDelAnalysisNotificationMessageBody body = null;

            try {
                body = ObjectMapperProvider.json()
                        .readValue(message.getPayload(), PncDelAnalysisNotificationMessageBody.class);
            } catch (JsonProcessingException e) {
                log.error("Unable to deserialize PNC deliverable analysis finished message, this is unexpected", e);
                return message.nack(e);
            }

            log.debug("Message of type 'DeliverableAnalysisStateChange' properly deserialized");
            delAnalysisNotificationHandler.handle(body);
        }

        processedMessages.getAndIncrement();

        return message.ack();
    }

    public int getProcessedMessages() {
        return processedMessages.get();
    }

    public int getReceivedMessages() {
        return receivedMessages.get();
    }
}
