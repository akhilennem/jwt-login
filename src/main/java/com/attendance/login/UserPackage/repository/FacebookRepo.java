package com.attendance.login.UserPackage.repository;

import com.attendance.login.UserPackage.models.Facebook;
import org.springframework.data.repository.CrudRepository;

public interface FacebookRepo extends CrudRepository<Facebook,Integer> {
    boolean existsByIdentity(String identity);
}
