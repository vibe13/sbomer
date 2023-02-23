package org.redhat.sbomer.validation.exceptions;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.validation.ConstraintViolation;

import org.cyclonedx.exception.ParseException;

import lombok.Getter;

@Getter
public class ValidationException extends RuntimeException {
    List<String> messages;

    public ValidationException(String message) {
        super(message);
        this.messages = Collections.singletonList(message);
    }

    /**
     * Converts Hibernate Validator violations in a readable list of messages.
     *
     * @param violations
     */
    public ValidationException(Set<? extends ConstraintViolation<?>> violations) {
        messages = violations.stream().map(cv -> cv.getPropertyPath() + ": " + cv.getMessage()).toList();
    }

    /**
     * Converts CycloneDX validation exceptions in a readable list of messages.
     *
     * @param violations
     */
    public ValidationException(List<ParseException> violations) {
        messages = violations.stream().map(cv -> "bom" + cv.getMessage().substring(1)).toList();
    }

}
