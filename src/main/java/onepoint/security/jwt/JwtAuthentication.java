package onepoint.security.jwt;

/**
 * 로그인에 성공한 후에 인증된 사용자를 표현하기 위한 클래스
 * JwtAuthenticationToken의 principal 필드에 입력되기 위한 용도
 */
public class JwtAuthentication {

	private final String username;
	private final String accessToken;
	private final String refreshToken;

	public JwtAuthentication(String username, String accessToken, String refreshToken) {
		this.username = username;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}

	public String getUsername() {
		return username;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}
}
