package io.kestra.plugin.gitguardian;

/** Failed GitGuardian API call; the status code is null when it was not an HTTP error. */
public class GitGuardianApiException extends Exception {
    private final Integer statusCode;

    public GitGuardianApiException(String message) {
        this(message, null, null);
    }

    public GitGuardianApiException(String message, Throwable cause) {
        this(message, null, cause);
    }

    public GitGuardianApiException(String message, Integer statusCode) {
        this(message, statusCode, null);
    }

    public GitGuardianApiException(String message, Integer statusCode, Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
    }

    public Integer getStatusCode() {
        return statusCode;
    }
}
