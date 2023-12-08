package pl.artur.zaczek.fitauthapp.jpa.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import pl.artur.zaczek.fitauthapp.jpa.entity.User;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    @Query(value = """
            SELECT EXISTS(
              SELECT 1
              FROM User u
              WHERE u.email = :email
            )
            """)
    boolean checkIfUserExistsByEmail(String email);
}
