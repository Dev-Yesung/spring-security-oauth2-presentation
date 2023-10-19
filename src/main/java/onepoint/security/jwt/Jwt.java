package onepoint.security.jwt;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import onepoint.config.JwtConfig;

@Component
public class Jwt {

	private final Logger log = LoggerFactory.getLogger(getClass());
	private final String issuer;
	private final String accessTokenSecret;
	private final String refreshTokenSecret;
	private final Long accessTokenExpirySeconds;
	private final Long refreshTokenExpirySeconds;

	public Jwt(JwtConfig jwtConfig) {
		this.issuer = jwtConfig.getIssuer();
		this.accessTokenSecret = jwtConfig.getAccessTokenSecret();
		this.refreshTokenSecret = jwtConfig.getRefreshTokenSecret();
		this.accessTokenExpirySeconds = jwtConfig.getAccessTokenExpirySeconds();
		this.refreshTokenExpirySeconds = jwtConfig.getRefreshTokenExpirySeconds();
	}

	public String createAccessToken(Authentication authentication, String authority) {
		return createToken(authentication, accessTokenSecret, accessTokenExpirySeconds, authority);
	}

	public String createRefreshToken(Authentication authentication, String authority) {
		return createToken(authentication, refreshTokenSecret, refreshTokenExpirySeconds, authority);
	}

	public String getAccessTokenSubject(String jwt) {
		return getSubject(jwt, accessTokenSecret);
	}

	public String getRefreshTokenSubject(String jwt) {
		return getSubject(jwt, refreshTokenSecret);
	}

	public String getAccessTokenAuthority(String jwt) {
		return getSubject(jwt, accessTokenSecret);
	}

	public String getRefreshTokenAuthority(String jwt) {
		return getSubject(jwt, refreshTokenSecret);
	}

	public String parseAccessTokenFromHeader(HttpServletRequest request) {
		// HTTP Header의 Authorization에서 jwt 가져옵니다.
		String jwtWithBearer = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (StringUtils.hasText(jwtWithBearer) && jwtWithBearer.startsWith("Bearer ")) {
			// Jwt가 Header의 Authorization 필드에 존재하면 Bearer를 제거합니다.
			return jwtWithBearer.substring(7);
		}

		return null;
	}

	public boolean validateAccessToken(String accessToken) {
		return validateToken(accessToken, accessTokenSecret);
	}

	public boolean validateRefreshToken(String refreshToken) {
		return validateToken(refreshToken, refreshTokenSecret);
	}

	private String createToken(
		Authentication authentication,
		String jwtSecret,
		Long expirySeconds,
		String authority
	) {
		String userPrincipal;
		if (authentication instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken) {
			userPrincipal = oAuth2AuthenticationToken.getPrincipal().getName();
		} else {
			userPrincipal = (String)authentication.getPrincipal();
		}
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + expirySeconds);

		return Jwts.builder()
			.setSubject(userPrincipal)
			.setIssuer(issuer)
			.setIssuedAt(now)
			.setExpiration(expiryDate)
			.claim("authority", authority)
			.signWith(SignatureAlgorithm.HS256, jwtSecret)
			.compact();
	}

	private boolean validateToken(String jwt, String jwtSecret) {
		try {
			Jwts.parser()
				.setSigningKey(jwtSecret)
				.parseClaimsJws(jwt);

			return true;
		} catch (SignatureException ex) {
			log.error("Invalid JWT signature");
		} catch (MalformedJwtException ex) {
			log.error("Invalid JWT token");
		} catch (ExpiredJwtException ex) {
			log.error("Expired JWT token");
		} catch (UnsupportedJwtException ex) {
			log.error("Unsupported JWT token");
		} catch (IllegalArgumentException ex) {
			log.error("JWT claims string is empty.");
		}

		return false;
	}

	private String getSubject(String jwt, String jwtSecretKey) {
		Claims claims = Jwts.parser()
			.setSigningKey(jwtSecretKey)
			.parseClaimsJws(jwt)
			.getBody();

		return claims.getSubject();
	}

	private String getAuthority(String jwt, String jwtSecretKey) {
		Claims claims = Jwts.parser()
			.setSigningKey(jwtSecretKey)
			.parseClaimsJws(jwt)
			.getBody();

		return claims.get("Authority", String.class);
	}
}
