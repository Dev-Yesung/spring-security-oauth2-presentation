package onepoint.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import onepoint.security.jwt.JwtAuthentication;
import onepoint.security.jwt.JwtAuthenticationToken;

@RestController
public class UserAuthController {

	private final Logger log = LoggerFactory.getLogger(getClass());

	private final UserAuthService userAuthService;
	private final AuthenticationManager authenticationManager;

	public UserAuthController(
		UserAuthService userAuthService,
		AuthenticationManager authenticationManager
	) {
		this.userAuthService = userAuthService;
		this.authenticationManager = authenticationManager;
	}

	@PostMapping("/signup")
	public ResponseEntity<UserInfoResponse> signup(@RequestBody AuthRequest request) {
		UserInfoResponse response = userAuthService.join(request);

		return ResponseEntity
			.status(HttpStatus.CREATED)
			.body(response);
	}

	@PostMapping("/user/login")
	public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
		JwtAuthenticationToken authToken = new JwtAuthenticationToken(request.email(), request.password());
		Authentication resultToken = authenticationManager.authenticate(authToken);
		JwtAuthentication authentication = (JwtAuthentication)resultToken.getPrincipal();
		User user = (User)resultToken.getDetails();

		AuthResponse response = new AuthResponse(
			authentication.getUsername(), authentication.getAccessToken(),
			authentication.getRefreshToken(), user.getRole().name()
		);

		return ResponseEntity.ok(response);
	}

	@GetMapping("/me")
	public void me(@AuthenticationPrincipal JwtAuthentication authentication) {
		log.info("username: {}, accessToken: {}, refreshToken: {}",
			authentication.getUsername(), authentication.getAccessToken(), authentication.getRefreshToken());
	}
}
