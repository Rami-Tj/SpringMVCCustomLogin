package com.rusko.service;

import com.rusko.domain.User;

public interface UserService {
  void save(User user);

  User findByUsername(String username);

  int generateRandomCode(String username);

  User generateAccessToken(String username);

  User saveRawPassword(String username, String presentedPassword);
}
