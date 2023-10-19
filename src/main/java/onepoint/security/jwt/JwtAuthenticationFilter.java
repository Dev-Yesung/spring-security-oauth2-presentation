package onepoint.security.jwt;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 일반회원 로그인 시나리오<br>
 * <br>
 * [토큰이 헤더에 존재하는 경우]<br>
 * 1) 사용자가 사이트에 접속한다.<br>
 * 2) HTTP 요청 메시지의 헤더에 JWT 토큰이 있는지 확인한다<br>
 * 3) 토큰의 유효성을 검증하고 디코딩해서 사용자 정보를 추출한다.<br>
 * 4) 추출한 정보로 DB를 통해 사용자 정보를 찾는다.<br>
 * 5) username, roles 데이터를 추출하고, UsernameAuthenticationToken 생성한다<br>
 * 6) 만들어진 UsernameAuthenticationToken를 JwtAuthenticationFilter에서 SecurityContext에 넣는다.<br>
 * <br>
 * [토큰이 헤더에 존재하지 않는 경우]<br>
 * 1) 사용자가 로그인/비밀번호 정보를 입력하여 제출한다<br>
 * 2) 로그인 정보를 바탕으로 사용자 정보를 찾는다.<br>
 * 3) 등록된 사용자라면, 액세스토큰과 리플래시 토큰을 발급하여 리턴한다.<br>
 * 이후 과정은 토큰이 헤더에 존재하는 경우와 일치...<br>
 */

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final Logger log = LoggerFactory.getLogger(getClass());
	private final Jwt jwt;

	public JwtAuthenticationFilter(Jwt jwt) {
		this.jwt = jwt;
	}

	@Override
	protected void doFilterInternal(
		HttpServletRequest request,
		HttpServletResponse response,
		FilterChain filterChain
	) throws ServletException, IOException {
		// 회원인증이 이미 진행된 경우 getAuthentication()은 null이 아닙니다.
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			//
			String accessToken = jwt.parseAccessTokenFromHeader(request);
			if (accessToken != null && jwt.validateAccessToken(accessToken)) {
				try {
					JwtAuthentication authentication = getAuthentication(accessToken);
					Collection<? extends GrantedAuthority> authorities = getAuthorities(accessToken);

					JwtAuthenticationToken authenticationToken
						= new JwtAuthenticationToken(authentication, null, authorities);
					authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
				} catch (Exception e) {
					log.warn("Jwt 처리에 실패했습니다: {}", e.getMessage());
				}
			}
		} else {
			log.debug("SecurityContextHolder에 이미 인증정보가 존재합니다: '{}'",
				SecurityContextHolder.getContext().getAuthentication());
		}

		filterChain.doFilter(request, response);
	}

	private JwtAuthentication getAuthentication(String token) {
		String accessTokenSubject = jwt.getAccessTokenSubject(token);

		return new JwtAuthentication(token, null, accessTokenSubject);
	}

	private Collection<? extends GrantedAuthority> getAuthorities(String token) {
		String accessTokenAuthority = jwt.getAccessTokenAuthority(token);

		return Collections.singletonList(new SimpleGrantedAuthority(accessTokenAuthority));
	}
}
