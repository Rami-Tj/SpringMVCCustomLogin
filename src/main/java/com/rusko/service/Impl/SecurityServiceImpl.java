package com.rusko.service.Impl;

import com.rusko.config.CustomAuthenticationFailureHandler;
import com.rusko.service.SecurityService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Service
public class SecurityServiceImpl implements SecurityService {

  @Autowired
  @Qualifier("authenticationManager")
  private AuthenticationManager authenticationManager;

  @Autowired
  private UserDetailsService userDetailsService;

  @Autowired
  @Qualifier(value = "customAuthenticationFailureHandler")
  private AuthenticationFailureHandler failureHandler;

  private final Log logger = LogFactory.getLog(this.getClass());
  private AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource = new WebAuthenticationDetailsSource();
  private SessionAuthenticationStrategy sessionStrategy = new NullAuthenticatedSessionStrategy();
  private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();

  @Override
  public void autoLogin(String username, String password) {
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());

    authenticationManager.authenticate(usernamePasswordAuthenticationToken);

    if (usernamePasswordAuthenticationToken.isAuthenticated()) {
      SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
      logger.debug(String.format("Auto login %s successfully!", username));
    }
  }

  @Override
  public Authentication attemptAuthentication(String username, String password, HttpServletRequest request) throws AuthenticationException {
    logger.debug("attempting to authenticated, manually ... ");
    if (username == null) {
      username = "";
    }

    if (password == null) {
      password = "";
    }
    UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
    this.setDetails(request, authRequest);
    return authenticationManager.authenticate(authRequest);
  }

  @Override
  public void updateSessionStrategy(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
    this.sessionStrategy.onAuthentication(authentication, request, response);
  }

  @Override
  public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
    SecurityContextHolder.clearContext();
    if (this.logger.isDebugEnabled()) {
      this.logger.debug("Authentication request failed: " + failed.toString(), failed);
      this.logger.debug("Updated SecurityContextHolder to contain null Authentication");
      this.logger.debug("Delegating to authentication failure handler " + this.failureHandler);
    }

    this.failureHandler.onAuthenticationFailure(request, response, failed);
  }

  @Override
  public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    if (this.logger.isDebugEnabled()) {
      this.logger.debug("Authentication success. Updating SecurityContextHolder to contain: " + authentication);
    }

//    SecurityContextHolder.getContext().setAuthentication(authentication);
    SecurityContext sc = SecurityContextHolder.getContext();
    sc.setAuthentication(authentication);
    HttpSession session = request.getSession(true);
    session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, sc);
//    this.rememberMeServices.loginSuccess(request, response, authentication);
//    if (this.eventPublisher != null) {
//      this.eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authentication, this.getClass()));
//    }

    this.successHandler.onAuthenticationSuccess(request, response, authentication);
  }


  private void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
    authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
  }
}
