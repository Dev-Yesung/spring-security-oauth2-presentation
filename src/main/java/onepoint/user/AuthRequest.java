package onepoint.user;

public record AuthRequest(
	String email,
	String password
) {
}
