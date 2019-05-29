package com.rusko.config;

import com.rusko.config.exception.InvalidTokenException;
import com.rusko.service.MailService;
import com.rusko.service.UserService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;


public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
  protected final Log logger = LogFactory.getLog(this.getClass());
  private String defaultFailureUrl;
  private boolean forwardToDestination = false;
  private boolean allowSessionCreation = true;
  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  @Autowired
  private UserCache userCache;

  @Autowired
  private UserService userService;

  @Autowired
  private MailService mailService;

  public CustomAuthenticationFailureHandler() {
  }

  public CustomAuthenticationFailureHandler(String defaultFailureUrl) {
    this.setDefaultFailureUrl(defaultFailureUrl);
  }

  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
    if (this.defaultFailureUrl == null) {
      this.logger.debug("No failure URL set, sending 401 Unauthorized error");
      response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
    } else {
      this.saveException(request, exception);
      if (this.forwardToDestination) {
        this.logger.debug("Forwarding to " + this.defaultFailureUrl);
        request.getRequestDispatcher(this.defaultFailureUrl).forward(request, response);
      } else if (exception instanceof InvalidTokenException) {
        String username = exception.getMessage();
        if (username != null) {
          UserPrincipal user = (UserPrincipal) this.userCache.getUserFromCache(username);
          logger.info("cached user fetched from userCache: " + user.getUser().getEmail());
          String email = user.getUser().getEmail();
          if (email != null) {
            int code = userService.generateRandomCode(user.getUser().getUsername());
            mailService.sendVerificationCodeMail(email, code);
          }
        }
        String encodedUsername = Base64.getEncoder().encodeToString(username.getBytes());
        String verificationUrl = "/verification?token=" + encodedUsername;
        this.logger.debug("Redirecting to " + verificationUrl);
        this.redirectStrategy.sendRedirect(request, response, verificationUrl);
      } else {
        this.logger.debug("Redirecting to " + this.defaultFailureUrl);
        this.redirectStrategy.sendRedirect(request, response, this.defaultFailureUrl);
      }
    }

  }

  public void setDefaultFailureUrl(String defaultFailureUrl) {
    Assert.isTrue(UrlUtils.isValidRedirectUrl(defaultFailureUrl), () -> {
      return "'" + defaultFailureUrl + "' is not a valid redirect URL";
    });
    this.defaultFailureUrl = defaultFailureUrl;
  }

  protected boolean isUseForward() {
    return this.forwardToDestination;
  }

  public void setUseForward(boolean forwardToDestination) {
    this.forwardToDestination = forwardToDestination;
  }

  public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
    this.redirectStrategy = redirectStrategy;
  }

  protected RedirectStrategy getRedirectStrategy() {
    return this.redirectStrategy;
  }

  protected boolean isAllowSessionCreation() {
    return this.allowSessionCreation;
  }

  public void setAllowSessionCreation(boolean allowSessionCreation) {
    this.allowSessionCreation = allowSessionCreation;
  }
}
