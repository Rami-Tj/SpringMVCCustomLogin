package com.rusko.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface SecurityService {

  void autoLogin(String username, String password);

  Authentication attemptAuthentication(String username, String password, HttpServletRequest request) throws AuthenticationException;

  void updateSessionStrategy(Authentication authentication, HttpServletRequest request, HttpServletResponse response);

  void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException;

  void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException;
}
