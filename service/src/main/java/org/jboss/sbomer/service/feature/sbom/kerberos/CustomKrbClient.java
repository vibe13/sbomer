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

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.client.KrbClientBase;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbKdcOption;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

public class CustomKrbClient extends KrbClientBase {

    private CustomInternalKrbClient innerClient;

    /**
     * Construct with prepared KrbConfig.
     *
     * @param krbConfig The krb config
     */
    public CustomKrbClient(KrbConfig krbConfig) {
        super(krbConfig);
    }

    /**
     * Constructor with conf dir
     *
     * @param confDir The conf dir
     * @throws KrbException e
     */
    public CustomKrbClient(File confDir) throws KrbException {
        super(confDir);
    }

    /**
     * Init the client.
     *
     * @throws KrbException e
     */
    public void init() throws KrbException {
        innerClient = new CustomInternalKrbClient(getSetting());
        innerClient.init();
    }

    /**
     * Request a TGT with user plain credential
     *
     * @param principal The principal
     * @param keytabFile The keytab file
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt(String principal, File keytabFile) throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.CLIENT_PRINCIPAL, principal);
        requestOptions.add(KrbOption.USE_KEYTAB, true);
        requestOptions.add(KrbOption.KEYTAB_FILE, keytabFile);
        return requestTgt(requestOptions);
    }

    /**
     * Request a TGT with using well prepared requestOptions.
     *
     * @param requestOptions The request options
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt(KOptions requestOptions) throws KrbException {
        if (requestOptions == null) {
            throw new IllegalArgumentException("Null requestOptions specified");
        }

        return innerClient.requestTgt(requestOptions);
    }

    /**
     * Request a service ticket with a TGT targeting for a server
     *
     * @param tgt The tgt ticket
     * @param serverPrincipal The server principal
     * @return Service ticket
     * @throws KrbException e
     */
    public SgtTicket requestSgt(TgtTicket tgt, String serverPrincipal) throws KrbException {
        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.USE_TGT, tgt);
        requestOptions.add(KrbOption.SERVER_PRINCIPAL, serverPrincipal);
        return innerClient.requestSgt(requestOptions);
    }

    /**
     * Request a service ticket provided request options
     *
     * @param requestOptions The request options
     * @return service ticket
     * @throws KrbException e
     */
    public SgtTicket requestSgt(KOptions requestOptions) throws KrbException {
        return innerClient.requestSgt(requestOptions);
    }

    /**
     * Request a service ticket
     *
     * @param ccFile The credential cache file
     * @param servicePrincipal The service principal
     * @return service ticket
     * @throws KrbException e
     */
    public SgtTicket requestSgt(File ccFile, String servicePrincipal) throws KrbException {
        Credential credential = getCredentialFromFile(ccFile);
        TgtTicket tgt = getTgtTicketFromCredential(credential);
        KOptions requestOptions = new KOptions();

        // Renew ticket if argument named servicePrincipal is null
        if (servicePrincipal == null) {
            requestOptions.add(KrbKdcOption.RENEW);
            servicePrincipal = credential.getServicePrincipal().getName();
        }

        requestOptions.add(KrbOption.USE_TGT, tgt);
        requestOptions.add(KrbOption.SERVER_PRINCIPAL, servicePrincipal);
        SgtTicket sgtTicket = innerClient.requestSgt(requestOptions);
        sgtTicket.setClientPrincipal(tgt.getClientPrincipal());
        return sgtTicket;
    }

}
