package com.attendance.login.UserPackage.models;

import lombok.Data;

import javax.persistence.*;

@Entity
@Data
@Table(name = "user_roles")
public class UserRoles {

    @Id
    public String userid;
    public int role_id;

}
