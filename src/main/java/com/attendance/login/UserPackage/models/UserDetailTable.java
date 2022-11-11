package com.attendance.login.UserPackage.models;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Table(name = "details")
@Entity
@Data
public class UserDetailTable {
    @Id
    public String email;
    public String name;
    public String phone;

    public UserDetailTable(String email, String name, String phone) {
        this.email = email;
        this.name = name;
        this.phone = phone;
    }

    public UserDetailTable() {

    }
}
