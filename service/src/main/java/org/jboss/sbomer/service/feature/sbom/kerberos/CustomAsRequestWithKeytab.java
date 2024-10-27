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
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithKeytab;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;

public class CustomAsRequestWithKeytab extends AsRequestWithKeytab {

    private Keytab keytab;

    public CustomAsRequestWithKeytab(KrbContext context) {
        super(context);
    }

    private Keytab loadKeytab() {
        File keytabFile = null;
        KOptions kOptions = getRequestOptions();

        if (kOptions.contains(KrbOption.KEYTAB_FILE)) {
            keytabFile = kOptions.getFileOption(KrbOption.KEYTAB_FILE);
        }

        if (kOptions.contains(KrbOption.USE_DFT_KEYTAB)) {
            final String clientKeytabEnv = System.getenv("KRB5_CLIENT_KTNAME");
            final String clientKeytabDft = getContext().getConfig().getString("default_client_keytab_name");
            if (clientKeytabEnv != null) {
                keytabFile = new File(clientKeytabEnv);
            } else if (clientKeytabDft != null) {
                keytabFile = new File(clientKeytabDft);
            } else {
                System.err.println("Default client keytab file not found.");
            }
        }

        Keytab keytab = null;
        try {
            keytab = Keytab.loadKeytab(keytabFile);
        } catch (IOException e) {
            String path = keytabFile != null ? keytabFile.getAbsolutePath() : "";
            System.err.println("Can not load keytab from file" + path);
        }

        /*
         * Remove the entries from the keytab which have null keys (might not be recognized by Apache Kerby)
         */
        removeEntriesWithNullKeys(keytab);
        return keytab;
    }

    private Keytab getKeytab() {
        if (keytab == null) {
            keytab = loadKeytab();
        }
        return keytab;
    }

    private void removeEntriesWithNullKeys(Keytab keytab) {
        if (keytab == null) {
            System.err.println("Keytab is null, skipping null key entry removal.");
            return;
        }

        // Collect entries with null keys
        List<KeytabEntry> entriesToRemove = keytab.getPrincipals()
                .stream()
                .flatMap(principal -> keytab.getKeytabEntries(principal).stream())
                .filter(entry -> entry.getKey() == null)
                .collect(Collectors.toList());

        // Remove entries with null keys in one batch operation
        entriesToRemove.forEach(keytab::removeKeytabEntry);
    }

    @Override
    public EncryptionKey getClientKey() throws KrbException {
        EncryptionKey tmpKey = getKeytab().getKey(getClientPrincipal(), getChosenEncryptionType());
        setClientKey(tmpKey);
        return super.getClientKey();
    }

}
