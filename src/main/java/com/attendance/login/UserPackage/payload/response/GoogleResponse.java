package com.attendance.login.UserPackage.payload.response;

public class GoogleResponse {
    public String email;
    public String name;
    public String imageurl;
   public String jwt;

    public GoogleResponse(String email, String name, String imageurl) {
        this.email=email;
        this.name=name;
        this.imageurl=imageurl;
        this.jwt=jwt;

    }
}
