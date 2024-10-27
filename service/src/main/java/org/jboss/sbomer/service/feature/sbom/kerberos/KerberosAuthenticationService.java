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

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.sbomer.core.errors.ApplicationException;

import io.quarkus.runtime.configuration.ConfigurationException;

import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;

@ApplicationScoped
@Slf4j
public class KerberosAuthenticationService {

    private CustomKrbClient krbClient;

    @Inject
    private TicketCache ticketCache;

    @Inject
    private ServiceTicketCache serviceTicketCache;

    private final String completeUserPrincipalName;
    private final String servicePrincipalName;
    private final File keytabFile;
    private final File configFile;

    public KerberosAuthenticationService() {
        String userPrincipalName = ConfigProvider.getConfig()
                .getOptionalValue("kerberos.client.user.principal.name", String.class)
                .orElse(null);
        if (userPrincipalName == null) {
            throw new ConfigurationException(
                    "Kerberos user principal name is missing! Authentication with Kerberos will not work.");
        }

        // If the realm is not provided in the user principal name, find it separately
        if (!userPrincipalName.contains("@")) {
            String userPrincipalRealm = ConfigProvider.getConfig()
                    .getOptionalValue("kerberos.client.user.principal.realm", String.class)
                    .orElse(null);
            if (userPrincipalRealm == null) {
                throw new ConfigurationException(
                        "Kerberos user principal realm is missing! Authentication with Kerberos will not work.");
            }
            completeUserPrincipalName = userPrincipalName + "@" + userPrincipalRealm;
        } else {
            completeUserPrincipalName = userPrincipalName;
        }

        log.debug("Using use principal name: {}", completeUserPrincipalName);

        servicePrincipalName = ConfigProvider.getConfig()
                .getOptionalValue("kerberos.client.service.principal.name", String.class)
                .orElse(null);
        if (servicePrincipalName == null) {
            throw new ConfigurationException(
                    "Kerberos service principal name is missing! Authentication with Kerberos will not work.");
        }

        log.debug("Using service principal name: {}", servicePrincipalName);

        String keyTabPath = ConfigProvider.getConfig()
                .getOptionalValue("kerberos.client.keytab.path", String.class)
                .orElse(null);
        if (keyTabPath == null) {
            throw new ConfigurationException(
                    "Kerberos keytab path is missing! Authentication with Kerberos will not work.");
        }

        log.debug("Using Kerberos keytab path: {}", keyTabPath);
        Path keytabFilePath = Paths.get(keyTabPath);
        if (!Files.exists(keytabFilePath)) {
            throw new ConfigurationException(
                    "Kerberos keytab file is not available at " + keytabFilePath.toAbsolutePath().toString());
        }
        keytabFile = keytabFilePath.toFile();

        String kerberosConfigPath = ConfigProvider.getConfig()
                .getOptionalValue("kerberos.config.path", String.class)
                .orElse(null);
        // If the path from "kerberos.config.path" is not available, fall back to the system property
        if (kerberosConfigPath == null || kerberosConfigPath.isEmpty()) {
            kerberosConfigPath = System.getProperty("java.security.krb5.conf");
        }
        if (kerberosConfigPath == null) {
            throw new ConfigurationException(
                    "Kerberos config path is missing! Authentication with Kerberos will not work.");
        }

        log.debug("Using Kerberos config path: {}", kerberosConfigPath);
        Path configFilePath = Paths.get(kerberosConfigPath);
        if (!Files.exists(configFilePath)) {
            throw new ConfigurationException(
                    "Kerberos config file is not available at " + configFilePath.toAbsolutePath().toString());
        }
        configFile = configFilePath.toFile();

        try {
            krbClient = new CustomKrbClient(configFile);
            krbClient.init();
        } catch (KrbException e) {
            throw new ApplicationException("Unable to create the Kerberos client", e);
        }
    }

    public TgtTicket authenticate() throws KrbException {
        TgtTicket tgt = ticketCache.getTgt(completeUserPrincipalName);
        if (tgt == null || !isTgtValid(tgt)) {
            log.debug("TgtTicket was null or expired, requesting a new one!");
            tgt = krbClient.requestTgt(completeUserPrincipalName, keytabFile);
            ticketCache.cacheTgt(completeUserPrincipalName, tgt);
        }
        return tgt;
    }

    public SgtTicket getServiceTicket(TgtTicket tgt) throws KrbException {
        SgtTicket serviceTicket = serviceTicketCache.getServiceTicket(servicePrincipalName);
        if (serviceTicket == null || !isSgtValid(serviceTicket)) {
            log.debug("SgtTicket was null or expired, requesting a new one!");
            serviceTicket = krbClient.requestSgt(tgt, servicePrincipalName);
            serviceTicketCache.cacheServiceTicket(servicePrincipalName, serviceTicket);
        }
        return serviceTicket;
    }

    public static boolean isTgtValid(TgtTicket tgtTicket) {
        EncKdcRepPart encPart = tgtTicket.getEncKdcRepPart();
        return KerberosTime.now().lessThan(encPart.getEndTime());
    }

    public static boolean isSgtValid(SgtTicket sgtTicket) {
        EncKdcRepPart encPart = sgtTicket.getEncKdcRepPart();
        return KerberosTime.now().lessThan(encPart.getEndTime());
    }

}
