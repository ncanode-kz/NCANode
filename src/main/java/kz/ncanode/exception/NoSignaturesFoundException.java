package kz.ncanode.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when a PDF document has no digital signatures
 */
public class NoSignaturesFoundException extends ApplicationException {
	public NoSignaturesFoundException(String message) {
		super(message);
	}

	public NoSignaturesFoundException(String message, Throwable cause) {
		super(message, cause);
	}

	@Override
	public Integer getStatus() {
		return HttpStatus.NOT_FOUND.value();
	}
}
