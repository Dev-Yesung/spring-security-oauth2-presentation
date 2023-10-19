package onepoint.security.jwt;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

// principal은 사용자의 로그인 아이디
// credential은 사용자의 로그인 비밀번호
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

	private final Object principal;
	private String credentials;

	public JwtAuthenticationToken(
		String principal,
		String credentials
	) {
		super(null);
		super.setAuthenticated(false);

		this.principal = principal;
		this.credentials = credentials;
	}

	public JwtAuthenticationToken(
		Object principal,
		String credentials,
		Collection<? extends GrantedAuthority> authorities
	) {
		super(authorities);
		super.setAuthenticated(true);

		this.principal = principal;
		this.credentials = credentials;
	}

	@Override
	public Object getPrincipal() {
		return principal;
	}

	@Override
	public Object getCredentials() {
		return credentials;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		if (authenticated) {
			// authenticated가 true가 되는 경우는 오직 생성자를 통해서만 가능
			throw new IllegalArgumentException("Authenticated 값을 true로 변경할 수 없습니다.");
		}
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		credentials = null;
	}
}
