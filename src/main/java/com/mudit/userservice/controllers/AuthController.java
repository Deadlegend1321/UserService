package com.mudit.userservice.controllers;

import com.mudit.userservice.dtos.LoginRequestDto;
import com.mudit.userservice.dtos.LogoutRequestDto;
import com.mudit.userservice.dtos.SignUpRequestDto;
import com.mudit.userservice.dtos.UserDto;
import com.mudit.userservice.services.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<UserDto> login(@RequestBody LoginRequestDto loginRequestDto) {

        return authService.login(loginRequestDto.getEmail(), loginRequestDto.getPassword());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequestDto logoutRequestDto) {
        return authService.logout(logoutRequestDto.getToken(), logoutRequestDto.getUserId());
    }

    @PostMapping("/signup")
    public ResponseEntity<UserDto> signup(@RequestBody SignUpRequestDto signUpRequestDto) {
        UserDto userDto = authService.signup(signUpRequestDto.getEmail(), signUpRequestDto.getPassword());
        return new ResponseEntity<>(userDto, HttpStatus.OK);
    }
}
