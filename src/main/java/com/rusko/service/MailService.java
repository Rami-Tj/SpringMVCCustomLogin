package com.rusko.service;

public interface MailService {
  void sendVerificationCodeMail(String email, int code);
}
