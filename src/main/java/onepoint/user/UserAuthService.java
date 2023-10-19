package onepoint.user;

import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@Service
public class UserAuthService {

	private final Logger log = LoggerFactory.getLogger(getClass());
	private final UserRepository userRepository;

	public UserAuthService(
		UserRepository userRepository
	) {
		this.userRepository = userRepository;
	}

	@Transactional
	public UserInfoResponse join(AuthRequest request) {
		String email = request.email();
		String password = request.password();

		User user = new User(
			email, password, Roles.ROLE_USER,
			null, null, null
		);

		User savedUser = userRepository.save(user);

		return UserInfoResponse.of(savedUser);
	}

	@Transactional
	public UserInfoResponse join(
		OAuth2User oAuth2User,
		String authorizedClientRegistrationId
	) {
		String providerId = oAuth2User.getName();

		return findByProviderAndProviderId(authorizedClientRegistrationId, providerId)
			.map(user -> {
				log.warn("Already exists: user for (provider: {}, providerId: {})",
					authorizedClientRegistrationId, providerId);
				return UserInfoResponse.of(user);
			})
			.orElseGet(() -> {
				Map<String, Object> attributes = oAuth2User.getAttributes();
				@SuppressWarnings("unchecked")
				Map<String, Object> properties = (Map<String, Object>)attributes.get("properties");
				String email = (String)properties.get("email");
				String profileImage = (String)properties.get("profile_image");
				User user = new User(
					email, null, Roles.ROLE_USER,
					authorizedClientRegistrationId, providerId,
					profileImage
				);
				User savedUser = userRepository.save(user);

				return UserInfoResponse.of(savedUser);
			});
	}

	public Optional<User> findByProviderAndProviderId(String provider, String providerId) {
		return userRepository.findByProviderAndProviderId(provider, providerId);
	}

	public User login(String username, String password) {
		User user = userRepository.findByUsername(username)
			.orElseThrow(() -> new NoSuchElementException("유저가 존재하지 않습니다"));

		return user;
	}
}
