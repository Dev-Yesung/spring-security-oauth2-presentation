package onepoint.security.jwt;

public record ErrorResponse(
	String status,
	String message
) {
}
