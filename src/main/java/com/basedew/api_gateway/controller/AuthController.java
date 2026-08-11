package com.basedew.api_gateway.controller;

import com.basedew.api_gateway.model.User;
import com.basedew.api_gateway.repository.UserRepository;
import com.basedew.api_gateway.security.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public Mono<ResponseEntity<String>> register(@RequestBody User user) { //TODO integrate User with postgres db schema
        return userRepository.findByUsername(user.getUsername())
                .flatMap(_ -> Mono.just(
                        ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User with this name already exists")
                ))
                .switchIfEmpty(Mono.defer(() -> {
                    user.setPassword(passwordEncoder.encode(user.getPassword()));
                    return userRepository.save(user)
                            .map(savedUser -> ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully"));
                }));
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<Map<String, String>>> login(@RequestBody User loginRequest) {
        return userRepository.findByUsername(loginRequest.getUsername())
                .flatMap(user -> {
                    if (passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                        Map<String, Object> extraClaims = Map.of("userId", user.getId());
                        String token = jwtService.generateToken(user.getUsername(), extraClaims);
                        return Mono.just(ResponseEntity.ok(Map.of("token", token)));
                    } else {
                        return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Incorrect username or password")));
                    }
                })
                .switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Incorrect username or password"))));
    }
}
