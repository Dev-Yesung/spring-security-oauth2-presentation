package onepoint.user;

import java.util.Optional;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.springframework.security.crypto.password.PasswordEncoder;

@Entity
@Table(name = "users")
public class User {

	// DB테이블에 저장되는 INDEX
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;

	@Column(name = "username")
	// 로그인에 필요한 ID를 의미 ex) Email Address
	private String username;

	@Column(name = "password")
	// 비밀번호
	private String password;

	@Column(name = "role")
	@Enumerated(EnumType.STRING)
	// Authority를 의미합니다. ROLE_USER와 ROLE_ADMIN이 있습니다.
	// 필요하시면 One To Many, Many To One 매핑으로 풀어 여러 Authority을 주실 수 있습니다.
	private Roles role;

	@Column(name = "provider")
	// OAuth 인증을 진행하는 주체를 의미합니다.
	// 대표적으로 구글, 카카오, 네이버가 있겠네요.
	private String provider;

	@Column(name = "provider_id")
	// OAuth 인증된 사용자의 고유 식별키입니다.
	// 예를들어, 카카오의 사용자 번호입니다.(사용자 이메일이 아닙니다)
	private String providerId;

	@Column(name = "profile_image")
	// OAuth 서버로부터 가져온 정보를 저장하는 곳입니다.
	// 필요한 컬럼을 추가해서 사용하면 됩니다!
	private String profileImage;

	protected User() {/*no-op*/}

	public User(
		String username, String password, Roles role,
		String provider, String providerId, String profileImage
	) {
		this.username = username;
		this.password = password;
		this.role = role;
		this.provider = provider;
		this.providerId = providerId;
		this.profileImage = profileImage;
	}

	public Long getId() {
		return id;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public Roles getRole() {
		return role;
	}

	public String getProvider() {
		return provider;
	}

	public String getProviderId() {
		return providerId;
	}

	public Optional<String> getProfileImage() {
		return Optional.ofNullable(profileImage);
	}

	public void validatePassword(String password, PasswordEncoder passwordEncoder) {
		if (!passwordEncoder.matches(this.password, password)) {
			throw new IllegalArgumentException("잘못된 비밀번호를 입력하셨습니다");
		}
	}
}
