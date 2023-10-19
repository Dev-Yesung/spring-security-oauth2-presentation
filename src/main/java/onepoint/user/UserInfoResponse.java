package onepoint.user;

import java.util.Optional;

public record UserInfoResponse(
	String username,
	String profileImage,
	String authority
) {
	public static UserInfoResponse of(User user) {
		String username = user.getUsername();
		String profileImage;
		if (user.getProfileImage().isPresent()) {
			profileImage = user.getProfileImage().get();
		} else {
			profileImage = null;
		}
		String authority = user.getRole().name();

		return new UserInfoResponse(username, profileImage, authority);
	}
}
