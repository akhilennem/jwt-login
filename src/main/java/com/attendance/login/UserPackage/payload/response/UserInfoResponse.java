package com.attendance.login.UserPackage.payload.response;

import lombok.Data;
import org.springframework.http.ResponseCookie;

import java.util.List;
@Data
public class UserInfoResponse {

	private String username;
	private String email;
	private List<String> roles;
private String phone;
private String name;
ResponseCookie jwtCookie;

	public UserInfoResponse(String username, String email, List<String> roles, String phone, String name, ResponseCookie jwtCookie) {
//		this.id = id;
		this.username = username;
		this.email = email;
		this.roles = roles;
		this.phone=phone;
		this.name=name;
		this.jwtCookie=jwtCookie;

	}

    public UserInfoResponse(String username, String email, List<String> roles, ResponseCookie jwtCookie) {
		this.username = username;
		this.email = email;
		this.roles = roles;
		this.jwtCookie=jwtCookie;
    }

    public UserInfoResponse(String username, String email, ResponseCookie jwtCookie) {
		this.username=username;
		this.email=email;
		this.jwtCookie=jwtCookie;
    }

//	public UserInfoResponse(String username, String email, List<String> roles,String phone,String name,String ) {
////		this.id = id;
//		this.username = username;
//		this.email = email;
//		this.roles = roles;
//		this.phone=phone;
//		this.name=name;
//
//	}

//	public Long getId() {
//		return id;
//	}
//
//	public void setId(Long id) {
//		this.id = id;
//	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public List<String> getRoles() {
		return roles;
	}
}
