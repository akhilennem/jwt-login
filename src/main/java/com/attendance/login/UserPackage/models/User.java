package com.attendance.login.UserPackage.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;
import javax.transaction.Transactional;
import javax.validation.constraints.Email;
import javax.validation.constraints.Size;
@Data
@Transactional
@Entity
@Table(name = "users",
       uniqueConstraints = {
           @UniqueConstraint(columnNames = "username"),
           @UniqueConstraint(columnNames = "email")
       })
@Component
@NoArgsConstructor
@AllArgsConstructor
public class User {
  @Id
  //@Email
  @Size(max = 50)
  private String username;
//  @Email
  @Size(max = 50)
  private String email;
  @Size(max = 120)
  private String password;


  public User(String username, String email, String password) {
    this.username=username;
    this.email=email;
    this.password=password;

  }


  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(name = "user_roles", 
             joinColumns = @JoinColumn(name = "userid"),
             inverseJoinColumns = @JoinColumn(name = "role_id"))
  private Set<Role> roles = new HashSet<>();


}
