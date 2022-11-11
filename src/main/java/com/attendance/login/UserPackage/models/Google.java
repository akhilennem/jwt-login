package com.attendance.login.UserPackage.models;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Collections;
import java.util.Set;

@Data
@Entity
@Table(name = "google")
@NoArgsConstructor
public class Google  {
@Id
public String username;
public String name;
public String imageurl;

    public Google(String email, String name, String imageurl) {
        this.username=email;
        this.name=name;
        this.imageurl=imageurl;
    }
}
