package pl.artur.zaczek.fitauthapp.rest.error;

import lombok.Getter;

@Getter
public abstract class BaseApiError extends RuntimeException{
    protected String code;
    protected String details;

    public BaseApiError(String message, String code) {
        super(message);
        this.code = code;
    }

    public BaseApiError(String message, String code, String details) {
        super(message);
        this.code = code;
        this.details = details;
    }
}
