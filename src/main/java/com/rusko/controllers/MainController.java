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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

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

    securityService.autoLogin(userForm.getUsername(), userForm.getPasswordConfirm());
    return "redirect:/home";
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
}
