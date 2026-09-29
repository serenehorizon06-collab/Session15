package com.rikkei.identity.service;

import com.rikkei.identity.dto.LoginRequest;
import com.rikkei.identity.dto.RefreshTokenRequest;
import com.rikkei.identity.dto.TokenResponse;
import com.rikkei.identity.model.RefreshToken;
import com.rikkei.identity.model.UserAccount;
import com.rikkei.identity.repository.RefreshTokenRepository;
import com.rikkei.identity.repository.UserAccountRepository;
import com.rikkei.identity.security.JwtService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {
    private final UserAccountRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthService(UserAccountRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public TokenResponse login(LoginRequest request) {
        UserAccount user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new BadCredentialsException("Sai tài khoản hoặc mật khẩu"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BadCredentialsException("Sai tài khoản hoặc mật khẩu");
        }

        String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String refreshToken = UUID.randomUUID().toString();
        refreshTokenRepository.save(new RefreshToken(
                refreshToken,
                user.getUsername(),
                Instant.now().plus(7, ChronoUnit.DAYS)));

        return new TokenResponse(accessToken, refreshToken);
    }

    @Transactional
    public TokenResponse refresh(RefreshTokenRequest request) {
        RefreshToken oldToken = refreshTokenRepository.findByToken(request.refreshToken())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.FORBIDDEN, "Refresh Token không hợp lệ"));

        if (oldToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(oldToken);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Refresh Token đã hết hạn");
        }

        UserAccount user = userRepository.findByUsername(oldToken.getUsername())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.FORBIDDEN, "Người dùng không tồn tại"));

        refreshTokenRepository.delete(oldToken);

        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole());
        String newRefreshToken = UUID.randomUUID().toString();
        refreshTokenRepository.save(new RefreshToken(
                newRefreshToken,
                user.getUsername(),
                Instant.now().plus(7, ChronoUnit.DAYS)));

        return new TokenResponse(newAccessToken, newRefreshToken);
    }
}
