package com.attendance.login.UserPackage.payload.request;

import lombok.Data;

import java.util.Set;

import javax.validation.constraints.*;

@Data

public class SignupRequest {

    @Size(max = 50)
    @Email
    public String username;
    public String identity;
 

    @Size(max = 50)
    @Email
    public String email;

    public Set<String> role;
    

    @Size(min = 6, max = 40)
    public String password;


    public  String name;

    public String phone;
    public String imageurl;


}
