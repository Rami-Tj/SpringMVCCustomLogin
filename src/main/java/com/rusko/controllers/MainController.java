package com.rusko.controllers;

import com.rusko.domain.Role;
import com.rusko.domain.User;
import com.rusko.dto.UserDto;
import com.rusko.repository.RoleRepository;
import com.rusko.service.SecurityService;
import com.rusko.service.UserService;
import com.rusko.validator.UserValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.Set;

@Controller
@RequestMapping("/")
public class MainController {

  @Autowired
  private UserValidator userValidator;

  @Autowired
  private RoleRepository roleRepository;

  @Autowired
  private UserService userService;

  @Autowired
  private SecurityService securityService;

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

    userService.save(user);

    securityService.autoLogin(userForm.getUsername(), userForm.getPasswordConfirm());

    return "redirect:/home";
  }
}
