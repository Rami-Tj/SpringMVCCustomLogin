package com.rusko.controllers;

import com.rusko.domain.Role;
import com.rusko.domain.User;
import com.rusko.dto.UserDto;
import com.rusko.dto.VerificationCodeDto;
import com.rusko.repository.RoleRepository;
import com.rusko.service.SecurityService;
import com.rusko.service.UserService;
import com.rusko.validator.UserValidator;
import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static java.util.stream.Collectors.joining;

@Controller
@RequestMapping("/")
public class MainController {
  private static final Log logger = LogFactory.getLog(MainController.class);

  @Autowired
  private UserValidator userValidator;

  @Autowired
  private RoleRepository roleRepository;

  @Autowired
  private BCryptPasswordEncoder bCryptPasswordEncoder;

  @Autowired
  private UserService userService;

  @Autowired
  private SecurityService securityService;

  @Autowired
  private CacheManager cacheManager;

  @Autowired
  @Qualifier("authenticationManager")
  private AuthenticationManager authenticationManager;

  @RequestMapping(value = {"/", "/home"}, method = RequestMethod.GET)
  public String index(Model m) {
    m.addAttribute("message", "Hello World");
    return "index";
  }

  @RequestMapping(value = "/login", method = RequestMethod.GET)
  public String login(Model model, String error, String logout) {
    if (error != null)
      model.addAttribute("error", "Your username and password is invalid.");

    if (logout != null)
      model.addAttribute("message", "You have been logged out successfully.");

    return "login";
  }

  @RequestMapping(value = "/registration", method = RequestMethod.GET)
  public String registration(Model model) {
    model.addAttribute("userForm", new UserDto());

    return "registration";
  }

  @RequestMapping(value = "/registration", method = RequestMethod.POST)
  public String registration(@ModelAttribute("userForm") UserDto userForm, BindingResult bindingResult, Model model) {
    userValidator.validate(userForm, bindingResult);

    if (bindingResult.hasErrors()) {
      return "registration";
    }

    User user = userForm.convert();
    final Role userRole = roleRepository.findByRole("USER");
    user.setRoles(Set.of(userRole));
    user.setPassword(bCryptPasswordEncoder.encode(userForm.getPassword()));
    userService.save(user);

//    securityService.autoLogin(userForm.getUsername(), userForm.getPasswordConfirm());
    return "redirect:/doAutoLogin?username=" + userForm.getUsername() + "&password=" + userForm.getPasswordConfirm();
  }

  @RequestMapping(value = "/verification", method = RequestMethod.GET)
  public String verification(Model model) {

    if (cacheManager.getCacheNames() != null) {
      for (String cacheName : cacheManager.getCacheNames()) {
        Cache cache = cacheManager.getCache(cacheName);
        for (Object object : cache.getKeys()) {
          if (object instanceof String) {
            String key = object.toString();
            logger.info("cached user: " + cache.get(key));
          }
        }
      }
    }

    model.addAttribute("message", "verification work!");
    model.addAttribute("verificationCode", new VerificationCodeDto());
    return "verification";
  }

  @RequestMapping(value = "/verification", method = RequestMethod.POST)
  public String verification(@RequestParam("token") String token, @ModelAttribute("verificationCode") VerificationCodeDto verificationCode, BindingResult bindingResult, Model model) {
    logger.info(verificationCode.getCode());
    logger.info(token);

    //TODO add code validation
    if (bindingResult.hasErrors()) {
      return "verification";
    }

    String username = new String(Base64.getDecoder().decode(token));

    List<String> cachedUsers = new ArrayList<String>();
    Cache cache = cacheManager.getCache("userCache");
    for (Object object : cache.getKeys()) {
      if (object instanceof String) {
        String key = object.toString();
        logger.info("cached user: " + cache.get(key));
        cachedUsers.add(cache.get(key).getObjectKey().toString());
      }
    }

    if (cachedUsers.contains(username)) {
      User user = userService.findByUsername(username);
      logger.info(user.getRawPassword());

      user = userService.generateAccessToken(username);

      String encodedURL = getEncodedParams(username, user.getRawPassword());

//      securityService.autoLogin(username, user.getRawPassword());
      return "redirect:" + encodedURL;
    }

    return null;
  }

  private String getEncodedParams(String username, String rawPaasword) {
    Map<String, String> requestParams = new HashMap<>();
    requestParams.put("username", username);
    requestParams.put("password", rawPaasword);

    String encodedURL = requestParams.keySet().stream()
            .map(key -> {
              String expression = null;
              try {
                expression = key + "=" + encodeValue(requestParams.get(key));
              } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
              }
              return expression;
            })
            .collect(joining("&", "/doAutoLogin?", ""));
    return encodedURL;
  }

  private String encodeValue(String value) throws UnsupportedEncodingException {
    return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
  }

  @RequestMapping(value = "/doAutoLogin", method = RequestMethod.GET)
  void autoLogin(HttpServletRequest request, HttpServletResponse response, @RequestParam("username") String username, @RequestParam("password") String password) throws IOException, ServletException {
    logger.info(username + " " + password);
    logger.info(request.getParameter("username"));
    logger.info(request.getParameter("password"));
    Authentication authentication;
    try {
      logger.debug("Request is to process authentication");
      logger.debug("attempting to authenticated, manually ... ");
      authentication = securityService.attemptAuthentication(username, password, request);
//      authenticate(username, password, request);
      securityService.updateSessionStrategy(authentication, request, response);
//    } catch (BadCredentialsException bce) {
//      logger.debug("Authentication failure: bad credentials");
//      bce.printStackTrace();
//      return "systemError"; // assume a low-level error, since the registration
//    }
    } catch (InternalAuthenticationServiceException var8) {
      logger.error("An internal error occurred while trying to authenticate the user.", var8);
      securityService.unsuccessfulAuthentication(request, response, var8);
      return;
    } catch (AuthenticationException var9) {
      securityService.unsuccessfulAuthentication(request, response, var9);
      return;
    }
    securityService.successfulAuthentication(request, response, authentication);
  }

  private void authenticate(String username, String password, HttpServletRequest request) throws BadCredentialsException {
    logger.debug("attempting to authenticated, manually ... ");

    // create and populate the token
    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

    // This call returns an authentication object, which holds principle and user credentials
    Authentication authentication = this.authenticationManager.authenticate(authToken);

    // Updating our security context holder with the new authentication object
    SecurityContext sc = SecurityContextHolder.getContext();
    sc.setAuthentication(authentication);

    // the most important part of the manual authentication process!!
    // create and save a new session that contains our new security context
    // by saving it, the first filter (SecurityContextPersistenceFilter) of spring security filter chain will recognize us
    HttpSession session = request.getSession(true);
    session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, sc);

    logger.debug("User should now be authenticated.");
  }

}
