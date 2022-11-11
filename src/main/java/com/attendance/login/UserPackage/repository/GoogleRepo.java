package com.attendance.login.UserPackage.repository;

import com.attendance.login.UserPackage.models.Google;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface GoogleRepo extends JpaRepository<Google,String> {
    boolean existsByUsername(String username);

    Google getByUsername(String username);

    <T> Optional<T> findByUsername(String username);
}
