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

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

import jakarta.inject.Inject;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;

public class Krb5ClientRequestFilter implements ClientRequestFilter {

    private static final String AUTHORIZATION = "Authorization";
    private static final String ACCEPT = "Accept";
    private static final String NEGOTIATE = "Negotiate";

    @Inject
    KerberosAuthenticationService kerberosAuthenticationService;

    @Override
    public void filter(ClientRequestContext requestContext) {
        try {
            // Authenticate with keytab and get TGT
            TgtTicket tgtTicket = kerberosAuthenticationService.authenticate();

            System.out.println("\n=====\ntgtTicket.getClientPrincipal(): " + tgtTicket.getClientPrincipal());
            System.out.println("tgtTicket.getSessionKey(): " + tgtTicket.getSessionKey().getKeyType());
            System.out.println("tgtTicket.getSname: " + tgtTicket.getEncKdcRepPart().getSname());
            System.out.println("tgtTicket.getAuthTime: " + tgtTicket.getEncKdcRepPart().getAuthTime());
            System.out.println("tgtTicket.getEndTime: " + tgtTicket.getEncKdcRepPart().getEndTime());
            System.out.println("tgtTicket.getRenewTill: " + tgtTicket.getEncKdcRepPart().getRenewTill());
            System.out.println("tgtTicket.getStartTime: " + tgtTicket.getEncKdcRepPart().getStartTime() + "\n=====\n");

            // Request service ticket
            SgtTicket sgtTicket = kerberosAuthenticationService.getServiceTicket(tgtTicket);

            System.out.println("\n=====\nserviceTicket.getClientPrincipal(): " + sgtTicket.getClientPrincipal());
            System.out.println("serviceTicket.getSessionKey(): " + sgtTicket.getSessionKey().getKeyType());
            System.out.println("serviceTicket.getKey(): " + sgtTicket.getEncKdcRepPart().getKey().getKeyType());
            System.out.println("serviceTicket.getTicket().getSname(): " + sgtTicket.getTicket().getSname());
            System.out.println("serviceTicket.getSrealm(): " + sgtTicket.getEncKdcRepPart().getSrealm());
            System.out.println("serviceTicket.getFlags(): " + sgtTicket.getEncKdcRepPart().getFlags());
            System.out.println("serviceTicket.getValue(): " + sgtTicket.getEncKdcRepPart().getValue());

            EncryptedData encryptedData = sgtTicket.getTicket().getEncryptedEncPart();
            System.out.println("\nencryptedData.getEType(): " + encryptedData.getEType());
            System.out.println("encryptedData.getKvno(): " + encryptedData.getKvno());

            System.out.println("serviceTicket.getKeyType(): " + sgtTicket.getEncKdcRepPart().getKey().getKeyType());
            System.out.println("serviceTicket.getAuthTime: " + sgtTicket.getEncKdcRepPart().getAuthTime());
            System.out.println("serviceTicket.getEndTime: " + sgtTicket.getEncKdcRepPart().getEndTime());
            System.out.println("serviceTicket.getKeyExpiration: " + sgtTicket.getEncKdcRepPart().getKeyExpiration());
            System.out.println("serviceTicket.getRenewTill: " + sgtTicket.getEncKdcRepPart().getRenewTill());
            System.out.println("serviceTicket.getStartTime: " + sgtTicket.getEncKdcRepPart().getStartTime());
            System.out.println("serviceTicket.getSname: " + sgtTicket.getEncKdcRepPart().getSname());

            // Convert service ticket to base64 string for the Authorization header
            byte[] ticketBytes = sgtTicket.getTicket().encode();
            String base64Token = Base64.getEncoder().encodeToString(ticketBytes);
            System.out.println("Base64.getEncoder().encodeToString(ticketBytes): " + base64Token);

            requestContext.getHeaders().add(AUTHORIZATION, NEGOTIATE + " " + base64Token);

            for (Map.Entry<String, List<Object>> header : requestContext.getHeaders().entrySet()) {
                System.out.println(header.getKey() + ": " + header.getValue());
            }

            System.out.println("\n*********");

        } catch (KrbException | IOException e) {
            throw new RuntimeException("Kerberos Authentication failed", e);
        }
    }

}