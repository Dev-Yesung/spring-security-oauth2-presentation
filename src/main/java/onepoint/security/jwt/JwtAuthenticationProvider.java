package onepoint.security.jwt;

import static org.springframework.util.ClassUtils.*;

import java.util.Collections;

import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import onepoint.user.User;
import onepoint.user.UserAuthService;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

	private final Jwt jwt;
	private final UserAuthService userAuthService;

	public JwtAuthenticationProvider(
		Jwt jwt,
		UserAuthService userAuthService
	) {
		this.jwt = jwt;
		this.userAuthService = userAuthService;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return isAssignable(JwtAuthenticationToken.class, authentication);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		JwtAuthenticationToken jwtAuthentication = (JwtAuthenticationToken)authentication;
		try {
			String principal = (String)jwtAuthentication.getPrincipal();
			String credentials = (String)jwtAuthentication.getCredentials();
			User user = userAuthService.login(principal, credentials);
			String authority = user.getRole().name();

			String accessToken = jwt.createAccessToken(authentication, authority);
			String refreshToken = jwt.createRefreshToken(authentication, authority);

			JwtAuthenticationToken authenticated =
				new JwtAuthenticationToken(new JwtAuthentication(accessToken, refreshToken, user.getUsername()), null,
					Collections.singletonList(new SimpleGrantedAuthority(authority)));
			authenticated.setDetails(user);

			return authenticated;
		} catch (IllegalArgumentException e) {
			throw new BadCredentialsException(e.getMessage());
		} catch (DataAccessException e) {
			throw new AuthenticationServiceException(e.getMessage(), e);
		}
	}
}
