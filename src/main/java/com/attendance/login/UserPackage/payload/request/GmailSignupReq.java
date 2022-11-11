package com.attendance.login.UserPackage.payload.request;

import lombok.Data;

import java.util.Set;

@Data
public class GmailSignupReq {

public String name;
public String username;
public String email;
public String imageurl;
public String password="noPassword";
public Set<String> role;
public String phone;




}
