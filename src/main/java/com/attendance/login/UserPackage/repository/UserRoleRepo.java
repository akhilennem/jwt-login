package com.attendance.login.UserPackage.repository;

import com.attendance.login.UserPackage.models.UserRoles;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;

@Transactional
@Repository

public interface UserRoleRepo extends JpaRepository<UserRoles,String> {
    void deleteByUserid(String email);
}
