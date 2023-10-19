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

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;

	// 로그인 ID를 의미
	@Column(name = "username")
	private String username;

	@Column(name = "password")
	private String password;

	@Column(name = "role")
	@Enumerated(EnumType.STRING)
	private Roles role;

	@Column(name = "provider")
	private String provider;

	@Column(name = "provider_id")
	private String providerId;

	@Column(name = "profile_image")
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
