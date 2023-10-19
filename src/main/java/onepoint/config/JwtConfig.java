package onepoint.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {
	private String issuer;
	private String accessTokenSecret;
	private String refreshTokenSecret;
	private Long accessTokenExpirySeconds;
	private Long refreshTokenExpirySeconds;

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getAccessTokenSecret() {
		return accessTokenSecret;
	}

	public void setAccessTokenSecret(String accessTokenSecret) {
		this.accessTokenSecret = accessTokenSecret;
	}

	public String getRefreshTokenSecret() {
		return refreshTokenSecret;
	}

	public void setRefreshTokenSecret(String refreshTokenSecret) {
		this.refreshTokenSecret = refreshTokenSecret;
	}

	public Long getAccessTokenExpirySeconds() {
		return accessTokenExpirySeconds;
	}

	public void setAccessTokenExpirySeconds(Long accessTokenExpirySeconds) {
		this.accessTokenExpirySeconds = accessTokenExpirySeconds;
	}

	public Long getRefreshTokenExpirySeconds() {
		return refreshTokenExpirySeconds;
	}

	public void setRefreshTokenExpirySeconds(Long refreshTokenExpirySeconds) {
		this.refreshTokenExpirySeconds = refreshTokenExpirySeconds;
	}
}
