package com.attendance.login.UserPackage.controllers;

import com.attendance.login.UserPackage.models.*;
import com.attendance.login.UserPackage.payload.request.GmailSignupReq;
import com.attendance.login.UserPackage.payload.request.SignupRequest;
import com.attendance.login.UserPackage.payload.response.GoogleResponse;
import com.attendance.login.UserPackage.payload.response.MessageResponse;
import com.attendance.login.UserPackage.repository.DetailRepository;
import com.attendance.login.UserPackage.repository.GoogleRepo;

import com.attendance.login.UserPackage.repository.RoleRepository;
import com.attendance.login.UserPackage.repository.UserRepository;
import com.attendance.login.UserPackage.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

@CrossOrigin
@RestController
@RequestMapping("api/google")
public class GoogleController {

    @Autowired
    public GoogleRepo googleRepo;
    @Autowired
    JwtUtils jwtUtils;
   // @Autowired
    UserRepository userRepository;

    @Value("${attendance.app.jwtSecret}")
    private String jwtSecret;

    @Value("${attendance.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${attendance.app.jwtCookieName}")
    private String jwtCookie;
//    @Autowired
//    private User signupRequest;


    private SignupRequest signupRequest;

    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
            AuthController  authController;
    @Autowired
    RoleRepository roleRepository;



  ERole eRole;

    @PostMapping("/signup")
    public ResponseEntity google(@RequestBody Google google){


        if (googleRepo.existsByUsername(google.username)){
            Google google1=googleRepo.getByUsername(google.username);
            System.out.println(google1.username);

            System.out.println("if condition");

            return ResponseEntity.ok().header(String.valueOf(HttpStatus.OK))
                    .body(new GoogleResponse(
                            google.getUsername(),google1.getName(),google1.getImageurl()));
        }else {

            googleRepo.save(google);
            System.out.println("saved");
            return new ResponseEntity<>(HttpStatus.CREATED);
        }
    }


}
