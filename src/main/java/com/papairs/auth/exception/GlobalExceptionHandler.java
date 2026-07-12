package com.papairs.auth.exception;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.List;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {

        List<String> details = ex.getBindingResult().getAllErrors().stream()
                .map(error -> error instanceof FieldError fieldError
                        ? fieldError.getField() + ": " + fieldError.getDefaultMessage()
                        : error.getDefaultMessage())
                .toList();

        ProblemDetail body = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Request validation failed");
        body.setProperty("details", details);

        return handleExceptionInternal(ex, body, headers, status, request);
    }

    /**
     * Handle authentication failures
     * @param e exception
     * @return ResponseEntity (401 Unauthorized)
     */
    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail handleAuthException(AuthenticationException e) {
        return ProblemDetail.forStatusAndDetail(
                HttpStatus.UNAUTHORIZED,
                e.getMessage()
        );
    }

    /**
     * Handle attempts to register with an existing username/email
     * @param e exception
     * @return ResponseEntity 409 (Conflict)
     */
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ProblemDetail handleUserExists(UserAlreadyExistsException e) {
        return ProblemDetail.forStatusAndDetail(
                HttpStatus.CONFLICT,
                e.getMessage()
        );
    }

    /**
     * Handle deactivated user login attempts
     * @param e exception
     * @return ResponseEntity (403 Forbidden)
     */
    @ExceptionHandler(UserDeactivatedException.class)
    public ProblemDetail handleUserDeactivated(UserDeactivatedException e) {
        return ProblemDetail.forStatusAndDetail(
                HttpStatus.FORBIDDEN,
                e.getMessage()
        );
    }

    /**
     * Handle invalid or expired tokens
     * @param e exception
     * @return ResponseEntity (401 Unauthorized)
     */
    @ExceptionHandler(InvalidTokenException.class)
    public ProblemDetail handleInvalidToken(InvalidTokenException e) {
        return ProblemDetail.forStatusAndDetail(
                HttpStatus.UNAUTHORIZED,
                e.getMessage()
        );
    }

    /**
     * Handle missing or malformed Authorization header
     * @param e exception
     * @return ResponseEntity (400 Bad Request)
     */
    @ExceptionHandler(InvalidAuthHeaderException.class)
    public ProblemDetail handleInvalidHeader(InvalidAuthHeaderException e) {
        return ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST,
                e.getMessage()
        );
    }

    /**
     * Handle exceptions for NullPointerException and IllegalArgumentException
     * @param e exception
     * @return ResponseEntity (500 Internal Server Error)
     */
    @ExceptionHandler({NullPointerException.class, IllegalArgumentException.class})
    public ProblemDetail handleCommonExceptions(Exception e) {
        return ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR,
                e.getMessage()
        );
    }
}
