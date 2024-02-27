package uz.rsa.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;
import uz.rsa.entity.User;
import uz.rsa.upload.TokenDto;

import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.chrono.ChronoPeriod;
import java.time.temporal.ChronoUnit;

@Component
public class TokenGenerator {

    @Autowired
    JwtEncoder accessTokenEncoder;

    @Autowired
    @Qualifier("jwtRefreshTokenEncoder")
    JwtEncoder refreshTokenEncoder;

    private String createAccessToken(Authentication authentication){
        User user = (User) authentication.getPrincipal();
        Instant now = Instant.now();
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("myApp")
                .issuedAt(now)
                .expiresAt(now.plus(5, ChronoUnit.MINUTES))
                .subject(String.valueOf(user.getId()))
                .build();
        return accessTokenEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }

    private String createRefreshToken(Authentication authentication){
        User user = (User) authentication.getPrincipal();
        Instant now = Instant.now();
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("myApp")
                .issuedAt(now)
                .expiresAt(now.plus(30, ChronoUnit.DAYS))
                .subject(String.valueOf(user.getId()))
                .build();
        return refreshTokenEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }

    public TokenDto createTokenDto(Authentication authentication){
        if(! (authentication.getPrincipal() instanceof  User user)){
            throw new BadCredentialsException(MessageFormat.format("principal {0} is not of User type", authentication.getPrincipal()));
        }
        TokenDto tokenDto = new TokenDto();
        tokenDto.setId(user.getId());
        tokenDto.setAccessToken(createAccessToken(authentication));
        String refreshToken;
        if(authentication.getCredentials() instanceof Jwt jwt){
            Instant now = Instant.now();
            Instant expireAt = jwt.getExpiresAt();
            Duration duration = Duration.between(now, expireAt);
            long daysUtilsExpires = duration.toDays();
            if(daysUtilsExpires < 7){
                refreshToken = createRefreshToken(authentication);
            }else {
                refreshToken = jwt.getTokenValue();
            }
        }else {
            refreshToken = createRefreshToken(authentication);
        }
        tokenDto.setRefreshToken(refreshToken);
        return tokenDto;
    }


}
