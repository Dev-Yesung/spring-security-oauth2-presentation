package onepoint.security.oauth2;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import onepoint.security.jwt.Jwt;
import onepoint.user.AuthResponse;
import onepoint.user.UserAuthService;
import onepoint.user.UserInfoResponse;

// OAuth2 인증이 완료되었을 때 호출되는 핸들러
@Component
public class OAuth2AuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	private final Logger log = LoggerFactory.getLogger(getClass());
	private final Jwt jwt;
	private final UserAuthService userAuthService;

	public OAuth2AuthenticationSuccessHandler(Jwt jwt, UserAuthService userAuthService) {
		this.jwt = jwt;
		this.userAuthService = userAuthService;
	}

	@Override
	public void onAuthenticationSuccess(
		HttpServletRequest request,
		HttpServletResponse response,
		Authentication authentication
	) throws ServletException, IOException {
		if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
			String authority = getAuthority(oauth2Token);
			String authSuccessJson = createAuthenticationSuccessResponse(oauth2Token, authority);

			writeToHttpServletResponse(response, authSuccessJson);
		} else {
			super.onAuthenticationSuccess(request, response, authentication);
		}
	}

	private String getAuthority(OAuth2AuthenticationToken oauth2Token) {
		OAuth2User principal = oauth2Token.getPrincipal();
		String registrationId = oauth2Token.getAuthorizedClientRegistrationId();
		UserInfoResponse response = userAuthService.join(principal, registrationId);

		return response.authority();
	}

	private String createAuthenticationSuccessResponse(
		OAuth2AuthenticationToken oauth2Token,
		String authority
	) throws JsonProcessingException {
		String username = oauth2Token.getPrincipal().getName();
		String accessToken = jwt.createAccessToken(oauth2Token, authority);
		String refreshToken = jwt.createRefreshToken(oauth2Token, authority);
		AuthResponse authResponse = new AuthResponse(username, accessToken, refreshToken, authority);

		return new ObjectMapper().writeValueAsString(authResponse);
	}

	private void writeToHttpServletResponse(HttpServletResponse response, String authSuccessJson) throws IOException {
		response.setContentType("application/json;charset=UTF-8");
		response.setContentLength(authSuccessJson.getBytes(StandardCharsets.UTF_8).length);
		response.getWriter().write(authSuccessJson);
	}
}
