package uz.rsa.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import uz.rsa.entity.User;

import java.util.Collections;

@Component
public class JwtToUserConvert implements Converter<Jwt, UsernamePasswordAuthenticationToken> {

    @Override
    public UsernamePasswordAuthenticationToken convert(Jwt jwt) {
        User user = new User();
        user.setId(Long.valueOf(jwt.getSubject()));
        return new UsernamePasswordAuthenticationToken(user,jwt, Collections.EMPTY_LIST);
    }
}
