package com.bonnieapps.springsecurityapp2.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class UsernameAndPasswordAuthenticationRequest {

    private String username;
    private String password;
}
