package com.tpe.controller;

import com.tpe.dto.LoginUser;
import com.tpe.dto.RegisterUser;
import com.tpe.security.JWTUtils;
import com.tpe.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;


    //localhost:8080/register + JSON + POST
    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegisterUser registerUser){

        userService.saveUser(registerUser);

        return new ResponseEntity<>("User is registered sucessfully...", HttpStatus.CREATED);
    }


    //localhost:8080/login + JSON + POST
    //response:token
    @PostMapping("/login")
    public ResponseEntity<String> login(@Valid @RequestBody LoginUser loginUser){

        Authentication authentication =
                authenticationManager.
                        authenticate(
                                new UsernamePasswordAuthenticationToken
                                        (loginUser.getUserName(),loginUser.getPassword()));

        String token=jwtUtils.generateToken(authentication);

        return new ResponseEntity<>(token,HttpStatus.CREATED);
    }

    @GetMapping("/goodbye")
    //@PreAuthorize("hasRole('STUDENT')")
    @PreAuthorize("hasAnyRole('STUDENT','ADMIN')")
    public ResponseEntity<String> goodbye(){
        return ResponseEntity.ok("Goodbye Spring Security:)");
    }

}