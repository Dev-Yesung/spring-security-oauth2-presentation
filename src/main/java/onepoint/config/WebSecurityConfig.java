package onepoint.config;

import java.util.Arrays;
import java.util.Collections;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import onepoint.security.jwt.ErrorResponse;
import onepoint.security.jwt.JwtAuthenticationFilter;
import onepoint.security.jwt.JwtAuthenticationProvider;
import onepoint.security.oauth2.OAuth2AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	private final Logger log = LoggerFactory.getLogger(getClass());
	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final JwtAuthenticationProvider jwtAuthenticationProvider;
	private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
	private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
	private final JdbcOperations jdbcOperations;
	private final ClientRegistrationRepository clientRegistrationRepository;

	public WebSecurityConfig(
		JwtAuthenticationFilter jwtAuthenticationFilter,
		JwtAuthenticationProvider jwtAuthenticationProvider,
		OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
		AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository,
		JdbcOperations jdbcOperations,
		ClientRegistrationRepository clientRegistrationRepository
	) {
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
		this.jwtAuthenticationProvider = jwtAuthenticationProvider;
		this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
		this.authorizationRequestRepository = authorizationRequestRepository;
		this.jdbcOperations = jdbcOperations;
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Bean
	public PasswordEncoder BCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager() {
		return new ProviderManager(Collections.singletonList(jwtAuthenticationProvider));
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder builder) throws Exception {
		builder.authenticationProvider(jwtAuthenticationProvider);
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		return (request, response, e) -> {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			Object principal = authentication != null ? authentication.getPrincipal() : null;
			log.warn("{} is denied", principal, e);
			ErrorResponse errorResponse = new ErrorResponse("403", "접근 권한이 없습니다.");
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.setContentType("application/json;charset=UTF-8");
			String accessDenialJsonResponse = new ObjectMapper()
				.writeValueAsString(errorResponse);
			response.getWriter().write(accessDenialJsonResponse);
			response.getWriter().flush();
			response.getWriter().close();
		};
	}

	@Bean
	public OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository() {
		JdbcOAuth2AuthorizedClientService jdbcOAuth2AuthorizedClientService
			= new JdbcOAuth2AuthorizedClientService(jdbcOperations, clientRegistrationRepository);

		return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(jdbcOAuth2AuthorizedClientService);
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
			.headers().disable()
			.csrf().disable()
			.httpBasic().disable()
			// form login/logout 기능 사용 X
			.formLogin().disable()
			.logout().disable()
			// rememberMe 기능 사용 X
			.rememberMe().disable()
			// Session 사용 X
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			// OAuth2 설정
			.oauth2Login()
			.authorizationEndpoint()
			.authorizationRequestRepository(authorizationRequestRepository)
			.and()
			.successHandler(oAuth2AuthenticationSuccessHandler)
			.authorizedClientRepository(oAuth2AuthorizedClientRepository())
			.and()
			// accessDenied(403) 발생시 예외를 처리하는 핸들러 등록
			.exceptionHandling().accessDeniedHandler(accessDeniedHandler())
			.and()
			// JWT 필터
			.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
			.build();
	}
}
