package com.attendance.login.UserPackage.repository;

import com.attendance.login.UserPackage.models.UserDetailTable;
import org.springframework.data.repository.CrudRepository;

public interface DetailRepository extends CrudRepository<UserDetailTable,String> {
}
