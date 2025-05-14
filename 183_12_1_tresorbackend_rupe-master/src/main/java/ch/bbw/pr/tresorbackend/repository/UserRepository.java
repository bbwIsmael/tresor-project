package ch.bbw.pr.tresorbackend.repository;

import ch.bbw.pr.tresorbackend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * UserRepository
 * @author Peter Rutschmann
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    /**
     * Find a user by their email address
     * @param email The email address to search for
     * @return Optional containing the user if found, empty otherwise
     */
   Optional<User> findByEmail(String email);
}
