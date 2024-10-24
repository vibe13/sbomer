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
package org.redhat.sbomer.errors;

import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.slf4j.helpers.MessageFormatter;

@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ApplicationException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final Object[] params;

    private String formattedMessage;

    public ApplicationException(String msg, Object... params) {
        super(msg, MessageFormatter.getThrowableCandidate(params));
        this.params = params;
    }

    public Error toError() {
        return new Error(this.getMessage());
    }

    @Override
    public synchronized String getMessage() {
        if (formattedMessage == null) {
            formattedMessage = MessageFormatter.arrayFormat(super.getMessage(), params).getMessage();
        }
        return formattedMessage;
    }
}
