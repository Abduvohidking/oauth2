package uz.rsa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import uz.rsa.entity.User;
import uz.rsa.security.TokenGenerator;
import uz.rsa.upload.RegisterDto;

import java.util.Collections;

@RestController
@RequestMapping("api/auth")
public class AuthController {
    @Autowired
    UserDetailsManager userDetailsManager;

    @Autowired
    TokenGenerator tokenGenerator;

    @PostMapping("/register")
    public HttpEntity<?> register(@RequestBody RegisterDto dto) {
        User user = new User(dto.getUsername(), dto.getPassword(), dto.getEmail(), dto.getFullName());
        userDetailsManager.createUser(user);
        Authentication authentication =
                UsernamePasswordAuthenticationToken.authenticated(user,
                        dto.getPassword(),
                        Collections.EMPTY_LIST);
        return ResponseEntity.ok(tokenGenerator.createTokenDto(authentication));
    }

}
