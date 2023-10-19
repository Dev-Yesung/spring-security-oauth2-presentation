package onepoint.user;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import onepoint.security.jwt.JwtAuthentication;
import onepoint.security.jwt.JwtAuthenticationToken;

@RestController
public class UserAuthController {

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

	@PostMapping(path = "/user/login")
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
}
