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
package org.jboss.sbomer.service.feature.sbom.kerberos;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class ServiceTicketCache {

    private final ConcurrentMap<String, SgtTicket> serviceTicketCache = new ConcurrentHashMap<>();

    public SgtTicket getServiceTicket(String serviceName) {
        return serviceTicketCache.get(serviceName);
    }

    public void cacheServiceTicket(String serviceName, SgtTicket serviceTicket) {
        serviceTicketCache.put(serviceName, serviceTicket);
    }

    public void invalidateServiceTicket(String serviceName) {
        serviceTicketCache.remove(serviceName);
    }
}
