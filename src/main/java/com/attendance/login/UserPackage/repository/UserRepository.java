package com.attendance.login.UserPackage.repository;

import java.util.Optional;

import com.attendance.login.UserPackage.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;

@Transactional
@Repository
public interface UserRepository extends JpaRepository<User, String> {
  Optional<User> findByUsername(String username);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);

    User getByEmail(String email);

    void deleteByUsername(String username);
}
