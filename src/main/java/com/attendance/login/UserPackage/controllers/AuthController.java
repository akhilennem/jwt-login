package com.attendance.login.UserPackage.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import com.attendance.login.UserPackage.models.*;
import com.attendance.login.UserPackage.payload.request.AdminSignup;
import com.attendance.login.UserPackage.payload.response.UserInfoResponse;
import com.attendance.login.UserPackage.repository.*;
import com.attendance.login.UserPackage.security.jwt.JwtUtils;
import com.attendance.login.UserPackage.security.services.UserDetailsImpl;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.attendance.login.UserPackage.payload.request.LoginRequest;
import com.attendance.login.UserPackage.payload.request.SignupRequest;
import com.attendance.login.UserPackage.payload.response.MessageResponse;
import org.springframework.web.client.RestTemplate;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
@NoArgsConstructor
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;


//  @Autowired
//  Details details;


  @Autowired
  UserRepository userRepository;



  @Autowired
  UserRoleRepo userRoleRepo;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;
@Autowired
RestTemplate restTemplate;
@Autowired
DetailRepository detailRepository;

  public String stats;
  @Autowired
  FacebookRepo facebookRepo;

  @PostMapping("/signin")
  public ResponseEntity<UserInfoResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {


    Authentication authentication = authenticationManager
            .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    System.out.println("Authentication   ...........  "+ authentication);
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

    List<String> roles = userDetails.getAuthorities().stream()
            .map(item -> item.getAuthority())
            .collect(Collectors.toList());
   User user =userRepository.getByEmail(loginRequest.getUsername());
    if (roles.toString().equals("[ROLE_USER]")){
      System.out.println("..........................................................................");
      System.out.println(jwtCookie.toString());
      return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString(), String.valueOf(HttpStatus.OK))
              .body(new UserInfoResponse(
                      userDetails.getUsername(),
                      userDetails.getEmail(),
                      roles,jwtCookie));
    } else if (roles.toString().equals("[ROLE_ADMIN]")) {
      return new ResponseEntity<>(HttpStatus.ALREADY_REPORTED);

    }

    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString(), String.valueOf(HttpStatus.OK))
            .body(new UserInfoResponse(
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles,jwtCookie));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.unprocessableEntity().body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity.unprocessableEntity().body(new MessageResponse("Error: Email is already in use!"));
    }
    User user = new User(signUpRequest.getUsername(),
            signUpRequest.getEmail(),
            encoder.encode(signUpRequest.getPassword()));
    System.out.println(signUpRequest.getPhone());
    UserDetailTable userDetailTable=new UserDetailTable(signUpRequest.email,signUpRequest.name,signUpRequest.phone);
detailRepository.save(userDetailTable);
    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(adminRole);

            break;
          case "mod":
            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(modRole);

            break;
          default:
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

  @PostMapping("/signout")
  public ResponseEntity<?> logoutUser() {
    ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
            .body(new MessageResponse("You've been signed out!"));
  }

  @PostMapping("/add-role")
  public Role addrole(Role role) {
    return roleRepository.save(role);
  }


  @PostMapping("/admin-signup")
  public ResponseEntity<?> registerAdmin(@Valid @RequestBody AdminSignup adminSignup) {
    if (userRepository.existsByUsername(adminSignup.getUsername())) {
      return ResponseEntity.unprocessableEntity().body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(adminSignup.getEmail())) {
      return ResponseEntity.unprocessableEntity().body(new MessageResponse("Error: Email is already in use!"));
    }
String psw=adminSignup.getPassword();
    // Create new user's account
    User user = new User(adminSignup.getUsername(),
            adminSignup.getEmail(),
            encoder.encode(adminSignup.getPassword()));

    Set<String> strRoles = adminSignup.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(adminRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "user":
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);

            break;
          case "mod":
            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(modRole);

            break;
          default:
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(adminRole);
        }
      });
    }
    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("Registered successfully!"));
  }


  @PostMapping("/delete-account")
  public ResponseEntity<UserInfoResponse> password(@Valid @RequestBody LoginRequest loginRequest) {


    Authentication authentication = authenticationManager
            .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

    List<String> roles = userDetails.getAuthorities().stream()
            .map(item -> item.getAuthority())
            .collect(Collectors.toList());


    String email=loginRequest.getUsername();
    userRoleRepo.deleteByUserid(email);
    userRepository.deleteByUsername(loginRequest.getUsername());

    return new ResponseEntity(HttpStatus.FORBIDDEN);

  }

@Autowired
    GoogleRepo googleRepo;


  @RequestMapping("/delete-user")
public ResponseEntity dlt(@RequestBody String email) {
  String username = email;
//  detailRepository.deleteByEmail(email);
  userRoleRepo.deleteByUserid(email);
  userRepository.deleteByUsername(username);

  return new ResponseEntity(HttpStatus.OK);
}
    @RequestMapping("/delete-admin")
  public ResponseEntity dltadmin(@RequestBody String email) {
    String username = email;
//    detailRepository.deleteByEmail(email);
    userRoleRepo.deleteByUserid(email);
    userRepository.deleteByUsername(username);

    return new ResponseEntity(HttpStatus.CONTINUE);
  }


      @PostMapping("/google-signin")
    public ResponseEntity<?> google(@RequestBody SignupRequest signUpRequest) {
          if (googleRepo.existsByUsername(signUpRequest.username)) {

              Authentication authentication = authenticationManager
                      .authenticate(new UsernamePasswordAuthenticationToken(signUpRequest.getUsername(),
                              signUpRequest.getPassword()));

              SecurityContextHolder.getContext().setAuthentication(authentication);
              System.out.println("Authentication   ...........  "+ authentication);
              UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
              ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
              return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString(), String.valueOf(HttpStatus.CREATED))
                      .body(new UserInfoResponse(
                              userDetails.getUsername(),
                              userDetails.getEmail(),jwtCookie));

          } else {
              if (userRepository.existsByUsername(signUpRequest.getUsername())) {
                  return ResponseEntity.unprocessableEntity().body(new MessageResponse("Error: Username is already taken!"));
              }
              //System.out.println("encoding "+encoder.encode("noPassword"));
              System.out.println(signUpRequest.getUsername());
              String email = signUpRequest.getUsername();
              if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                  return ResponseEntity.unprocessableEntity().body(new MessageResponse("Error: Email is already in use!"));
              }
              User user = new User(signUpRequest.getUsername(),
                      email,
                      encoder.encode(signUpRequest.password));
              System.out.println("password.............");
              System.out.println(encoder.encode(signUpRequest.password));

              Google google = new Google(signUpRequest.getUsername(), signUpRequest.name, signUpRequest.imageurl);
              Set<String> strRoles = signUpRequest.getRole();
              Set<Role> roles = new HashSet<>();

              if (strRoles == null) {
                  Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                  roles.add(userRole);
              } else {
                  strRoles.forEach(role -> {
                      switch (role) {
                          case "admin":
                              Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                      .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                              roles.add(adminRole);

                              break;
                          case "mod":
                              Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                      .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                              roles.add(modRole);

                              break;
                          default:
                              Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                      .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                              roles.add(userRole);
                      }
                  });
              }

              user.setRoles(roles);
              userRepository.save(user);
              googleRepo.save(google);
              Authentication authentication = authenticationManager
                      .authenticate(new UsernamePasswordAuthenticationToken(signUpRequest.getUsername(),
                              signUpRequest.getPassword()));

              SecurityContextHolder.getContext().setAuthentication(authentication);
              System.out.println("Authentication   ...........  "+ authentication);
              UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
              ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
              return ResponseEntity.accepted().header(HttpHeaders.SET_COOKIE, jwtCookie.toString(), String.valueOf(HttpStatus.CREATED))
                      .body(new UserInfoResponse(
                              userDetails.getUsername(),
                              userDetails.getEmail(),jwtCookie));
          }
      }


//     @PostMapping("/fb-signin")
//     public ResponseEntity<?> facebook(@RequestBody SignupRequest signUpRequest) {
//         if (facebookRepo.existsByIdentity(signUpRequest.identity)) {

//             Authentication authentication = authenticationManager
//                     .authenticate(new UsernamePasswordAuthenticationToken(signUpRequest.getUsername(),
//                             signUpRequest.getPassword()));

//             SecurityContextHolder.getContext().setAuthentication(authentication);
//             System.out.println("Authentication   ...........  "+ authentication);
//             UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//             ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
//             return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString(), String.valueOf(HttpStatus.CREATED))
//                     .body(new UserInfoResponse(
//                             userDetails.getUsername(),
//                             userDetails.getEmail(),jwtCookie));

// //            return new ResponseEntity<>(HttpStatus.OK);
//         } else {
//             if (userRepository.existsByUsername(signUpRequest.getUsername())) {
//                 return ResponseEntity.unprocessableEntity().body(new MessageResponse("Error: Username is already taken!"));
//             }
//             //System.out.println("encoding "+encoder.encode("noPassword"));
//             System.out.println(signUpRequest.getUsername());
//             String email = signUpRequest.getUsername();
//             if (userRepository.existsByEmail(signUpRequest.getEmail())) {
//                 return ResponseEntity.unprocessableEntity().body(new MessageResponse("Error: Email is already in use!"));
//             }
//             User user = new User(signUpRequest.getUsername(),
//                     email,
//                     encoder.encode(signUpRequest.password));
//             System.out.println("password.............");
//             System.out.println(encoder.encode(signUpRequest.password));

//            Facebook facebook=new Facebook(signUpRequest.identity,signUpRequest.name,signUpRequest.imageurl);
//             Set<String> strRoles = signUpRequest.getRole();
//             Set<Role> roles = new HashSet<>();

//             if (strRoles == null) {
//                 Role userRole = roleRepository.findByName(ERole.ROLE_USER)
//                         .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                 roles.add(userRole);
//             } else {
//                 strRoles.forEach(role -> {
//                     switch (role) {
//                         case "admin":
//                             Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
//                                     .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                             roles.add(adminRole);

//                             break;
//                         case "mod":
//                             Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
//                                     .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                             roles.add(modRole);

//                             break;
//                         default:
//                             Role userRole = roleRepository.findByName(ERole.ROLE_USER)
//                                     .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                             roles.add(userRole);
//                     }
//                 });
//             }

//             user.setRoles(roles);
//             userRepository.save(user);
//             facebookRepo.save(facebook);
//             Authentication authentication = authenticationManager
//                     .authenticate(new UsernamePasswordAuthenticationToken(signUpRequest.getUsername(),
//                             signUpRequest.getPassword()));

//             SecurityContextHolder.getContext().setAuthentication(authentication);
//             System.out.println("Authentication   ...........  "+ authentication);
//             UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//             ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
//             return ResponseEntity.accepted().header(HttpHeaders.SET_COOKIE, jwtCookie.toString(), String.valueOf(HttpStatus.OK))
//                     .body(new UserInfoResponse(
//                             userDetails.getUsername(),
//                             userDetails.getEmail(),jwtCookie));
//         }
//     }
  
  
  @PostMapping("/fb-signin")
    public ResponseEntity<?> facebook(@RequestBody SignupRequest signUpRequest) {
        if (facebookRepo.existsByIdentity(signUpRequest.identity)) {

            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(signUpRequest.getUsername(),
                            signUpRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("Authentication   ...........  "+ authentication);
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString(), String.valueOf(HttpStatus.CREATED))
                    .body(new UserInfoResponse(
                            userDetails.getUsername(),
                            userDetails.getEmail(),jwtCookie));

//            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            if (userRepository.existsByUsername(signUpRequest.getUsername())) {
                return ResponseEntity.unprocessableEntity().body(new MessageResponse("Error: Username is already taken!"));
            }
            //System.out.println("encoding "+encoder.encode("noPassword"));
            System.out.println(signUpRequest.getUsername());
            String email = signUpRequest.getUsername();
            if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                return ResponseEntity.unprocessableEntity().body(new MessageResponse("Error: Email is already in use!"));
            }
            User user = new User(signUpRequest.getUsername(),
                    email,
                    encoder.encode(signUpRequest.password));
            System.out.println("password.............");
            System.out.println(encoder.encode(signUpRequest.password));

           Facebook facebook=new Facebook(signUpRequest.identity,signUpRequest.name,signUpRequest.imageurl);
            Set<String> strRoles = signUpRequest.getRole();
            Set<Role> roles = new HashSet<>();

            if (strRoles == null) {
                Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(userRole);
            } else {
                strRoles.forEach(role -> {
                    switch (role) {
                        case "admin":
                            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                            roles.add(adminRole);

                            break;
                        case "mod":
                            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                            roles.add(modRole);

                            break;
                        default:
                            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                            roles.add(userRole);
                    }
                });
            }

            user.setRoles(roles);
            userRepository.save(user);
            facebookRepo.save(facebook);
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(signUpRequest.getUsername(),
                            signUpRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("Authentication   ...........  "+ authentication);
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
            return ResponseEntity.accepted().header(HttpHeaders.SET_COOKIE, jwtCookie.toString(), String.valueOf(HttpStatus.OK))
                    .body(new UserInfoResponse(
                            userDetails.getUsername(),
                            userDetails.getEmail(),jwtCookie));
        }
    }







}

  

