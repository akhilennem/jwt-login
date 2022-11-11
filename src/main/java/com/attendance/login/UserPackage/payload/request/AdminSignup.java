package com.attendance.login.UserPackage.payload.request;

import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.Set;
@Data
public class AdminSignup {

    @NotBlank
    @Size(max = 50)
    @Email
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    public String email;

    private Set<String> role;

    @NotBlank
    @Size(min = 6, max = 40)
    private String password;
}
