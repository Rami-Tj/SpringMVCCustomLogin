package com.rusko.service.Impl;

import com.rusko.service.MailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.stereotype.Service;

import javax.mail.internet.MimeMessage;

@Service
public class MailServiceImpl implements MailService {

  @Autowired
  private JavaMailSender mailSender;

  @Override
  public void sendVerificationCodeMail(String email, int code) {
    mailSender.send(new MimeMessagePreparator() {
      public void prepare(MimeMessage mimeMessage) throws Exception {

        MimeMessageHelper mimeMsgHelperObj = new MimeMessageHelper(mimeMessage, true, "UTF-8");
        mimeMsgHelperObj.setTo(email);
        mimeMsgHelperObj.setFrom("noreply@aderivatives.com");
        mimeMsgHelperObj.setText("Your verification code is: " + code);
        mimeMsgHelperObj.setSubject("Verification Code");

//        Determine If There Is An File Upload.If Yes, Attach It To The Client Email
//        if ((attachFileObj != null) && (attachFileObj.getSize() > 0) && (!attachFileObj.equals(""))) {
//          System.out.println("\nAttachment Name?= " + attachFileObj.getOriginalFilename() + "\n");
//          mimeMsgHelperObj.addAttachment(attachFileObj.getOriginalFilename(), new InputStreamSource() {
//            public InputStream getInputStream() throws IOException {
//              return attachFileObj.getInputStream();
//            }
//          });
//        } else {
//          System.out.println("\nNo Attachment Is Selected By The User. Sending Text Email!\n");
//        }
      }
    });
  }
}
