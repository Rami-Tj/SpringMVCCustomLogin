package com.rusko.service.Impl;

import com.rusko.domain.User;
import com.rusko.repository.UserRepository;
import com.rusko.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Random;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {

  @Autowired
  private UserRepository userRepository;

  @Override
  public void save(User user) {
    userRepository.save(user);
  }

  @Override
  public User findByUsername(String username) {
    return userRepository.findByUsername(username);
  }

  @Override
  public int generateRandomCode(String username) {
    Random generator = new Random();
    int code = generator.nextInt(899999) + 100000;

    User user = findByUsername(username);
    user.setVerificationCode(code);
    userRepository.save(user);
    return code;
  }

  @Override
  public User generateAccessToken(String username) {
    String token = UUID.randomUUID().toString();

    User user = findByUsername(username);
    user.setVerificationToken(token);
    user.setVerificationTokenCreationDate(new Date());

    return userRepository.save(user);
  }

  @Override
  public User saveRawPassword(String username, String presentedPassword) {
    User user = findByUsername(username);
    user.setRawPassword(presentedPassword);
    return userRepository.save(user);
  }
}
