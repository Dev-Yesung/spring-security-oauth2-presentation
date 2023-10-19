package onepoint.user;

public record AuthResponse(
	String username,
	String accessToken,
	String refreshToken,
	String authority
) {
}
