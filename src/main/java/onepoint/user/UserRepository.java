package onepoint.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByUsername(String username);

	@Query("""
		SELECT u FROM User u
		WHERE u.provider = :provider AND u.providerId = :providerId
		""")
	Optional<User> findByProviderAndProviderId(String provider, String providerId);
}
