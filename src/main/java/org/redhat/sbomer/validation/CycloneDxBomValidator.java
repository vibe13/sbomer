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
package org.redhat.sbomer.validation;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.cyclonedx.CycloneDxSchema.Version;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.JsonParser;
import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import static org.redhat.sbomer.utils.SbomUtils.schemaVersion;

public class CycloneDxBomValidator implements ConstraintValidator<CycloneDxBom, JsonNode> {

    @Override
    public boolean isValid(JsonNode value, ConstraintValidatorContext context) {
        if (value == null) {
            context.unwrap(HibernateConstraintValidatorContext.class).addMessageParameter("errors", "missing BOM");
            return false;
        }

        List<ParseException> exceptions = Collections.emptyList();

        try {
            if (value instanceof ObjectNode) {
                exceptions = new JsonParser().validate(value, schemaVersion());
            } else {
                exceptions = new JsonParser().validate(value.textValue().getBytes(), schemaVersion());
            }

            if (exceptions.isEmpty()) {
                return true;
            }

        } catch (IOException e) {
            context.unwrap(HibernateConstraintValidatorContext.class)
                    .addMessageParameter("errors", "unable to parse object");

            return false;
        }

        context.unwrap(HibernateConstraintValidatorContext.class)
                .addMessageParameter(
                        "errors",
                        exceptions.stream()
                                .map(cv -> "bom" + cv.getMessage().substring(1))
                                .toList()
                                .stream()
                                .collect(Collectors.joining(", ")));

        return false;
    }

}
