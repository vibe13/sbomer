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

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.KrbSetting;
import org.apache.kerby.kerberos.kerb.client.PkinitOption;
import org.apache.kerby.kerberos.kerb.client.TokenOption;
import org.apache.kerby.kerberos.kerb.client.impl.DefaultInternalKrbClient;
import org.apache.kerby.kerberos.kerb.client.request.AsRequest;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithCert;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithPasswd;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithToken;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

public class CustomInternalKrbClient extends DefaultInternalKrbClient {

    public CustomInternalKrbClient(KrbSetting krbSetting) {
        super(krbSetting);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TgtTicket requestTgt(KOptions requestOptions) throws KrbException {
        AsRequest asRequest = null;
        PrincipalName clientPrincipalName = null;

        if (requestOptions.contains(KrbOption.USE_PASSWD)) {
            asRequest = new AsRequestWithPasswd(getContext());
        } else if (requestOptions.contains(KrbOption.USE_KEYTAB)) {
            asRequest = new CustomAsRequestWithKeytab(getContext());
        } else if (requestOptions.contains(PkinitOption.USE_ANONYMOUS)) {
            asRequest = new AsRequestWithCert(getContext());
        } else if (requestOptions.contains(PkinitOption.USE_PKINIT)) {
            asRequest = new AsRequestWithCert(getContext());
        } else if (requestOptions.contains(TokenOption.USE_TOKEN)) {
            asRequest = new AsRequestWithToken(getContext());
        } else if (requestOptions.contains(TokenOption.USER_ID_TOKEN)) {
            asRequest = new AsRequestWithToken(getContext());
        }

        if (asRequest == null) {
            throw new IllegalArgumentException("No valid krb client request option found");
        }

        if (requestOptions.contains(KrbOption.CLIENT_PRINCIPAL)) {
            String clientPrincipalString = requestOptions.getStringOption(KrbOption.CLIENT_PRINCIPAL);
            clientPrincipalString = fixPrincipal(clientPrincipalString);
            clientPrincipalName = new PrincipalName(clientPrincipalString);
            if (requestOptions.contains(PkinitOption.USE_ANONYMOUS)) {
                clientPrincipalName.setNameType(NameType.NT_WELLKNOWN);
            }
            asRequest.setClientPrincipal(clientPrincipalName);
        }

        if (requestOptions.contains(KrbOption.SERVER_PRINCIPAL)) {
            String serverPrincipalString = requestOptions.getStringOption(KrbOption.SERVER_PRINCIPAL);
            serverPrincipalString = fixPrincipal(serverPrincipalString);
            PrincipalName serverPrincipalName = new PrincipalName(serverPrincipalString, NameType.NT_PRINCIPAL);
            asRequest.setServerPrincipal(serverPrincipalName);
        } else if (clientPrincipalName != null) {
            String realm = clientPrincipalName.getRealm();
            PrincipalName serverPrincipalName = KrbUtil.makeTgsPrincipal(realm);
            asRequest.setServerPrincipal(serverPrincipalName);
        }

        asRequest.setRequestOptions(requestOptions);

        return doRequestTgt(asRequest);
    }
}
