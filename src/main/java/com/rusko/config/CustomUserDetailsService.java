package com.rusko.config;

import com.rusko.domain.User;
import com.rusko.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

  @Autowired
  private UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user;
    user = userRepository.findByUsername(username);
    if (user == null) {
      throw new UsernameNotFoundException("No user Found with the username" + username);
    }
    return new UserPrincipal(user);
  }

}