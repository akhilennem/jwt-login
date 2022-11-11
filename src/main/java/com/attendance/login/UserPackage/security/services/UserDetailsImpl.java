package com.attendance.login.UserPackage.security.services;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import com.attendance.login.UserPackage.models.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class UserDetailsImpl implements UserDetails {
  private static final long serialVersionUID = 1L;



  public String username;

  private String email;
  private String phone;
  private String name;

  @JsonIgnore
  private String password;

  private Collection<? extends GrantedAuthority> authorities;

  public UserDetailsImpl(String username, String email, String password,
      Collection<? extends GrantedAuthority> authorities) {

    this.username = username;
    this.email = email;
    this.password = password;
    this.authorities = authorities;
  }

  public static UserDetailsImpl build(User user) {
    List<GrantedAuthority> authorities = user.getRoles().stream()
        .map(role -> new SimpleGrantedAuthority(role.getName().name()))
        .collect(Collectors.toList());

    return new UserDetailsImpl(

        user.getUsername(), 
        user.getEmail(),
        user.getPassword(), 
        authorities);
  }

//  public static UserDetailsImpl googleBuild(User user) {
//    List<GrantedAuthority> authorities = user.getRoles().stream()
//            .map(role -> new SimpleGrantedAuthority(role.getName().name()))
//            .collect(Collectors.toList());
//
//    return new UserDetailsImpl(
//
//            user.getUsername(),
//            user.getEmail(),
//            user.getPassword(),
//            authorities);
//  }


  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities;
  }



  public String getEmail() {
    return email;
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  //  @Override
//  public boolean equals(Object o) {
//    if (this == o)
//      return true;
//    if (o == null || getClass() != o.getClass())
//      return false;
//    UserDetailsImpl user = (UserDetailsImpl) o;
//    return Objects.equals(id, user.id);
//  }
}
