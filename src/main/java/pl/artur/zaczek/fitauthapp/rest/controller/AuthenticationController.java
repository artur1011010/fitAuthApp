package pl.artur.zaczek.fitauthapp.rest.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import pl.artur.zaczek.fitauthapp.rest.model.AuthenticationRequest;
import pl.artur.zaczek.fitauthapp.rest.model.AuthenticationDto;
import pl.artur.zaczek.fitauthapp.rest.model.AuthorizationDto;
import pl.artur.zaczek.fitauthapp.rest.model.RegisterRequest;
import pl.artur.zaczek.fitauthapp.service.AuthenticationService;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "http://localhost:3000")
public class AuthenticationController {
    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationDto> register(@Validated @RequestBody final RegisterRequest request) {
        log.info("POST /register:\n{}", request);
        final AuthenticationDto response = service.register(request);
        log.info("returning: {}", response);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/token")
    public ResponseEntity<AuthenticationDto> authenticate(@RequestBody final AuthenticationRequest request) {
        log.info("POST /authenticate:\n{}", request);
        return ResponseEntity.ok(service.token(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        log.info("POST /refresh-token:\n{}", request);
        service.refreshToken(request, response);
    }

    @GetMapping("/authorize")
    public ResponseEntity<AuthorizationDto> authorize(@RequestHeader(name = "Authorization") final String token) {
        log.info("POST /authorize, token = {}", token);
        final AuthorizationDto authenticationResponse = service.authenticate(token);
        log.info("returning: {}", authenticationResponse);
        return ResponseEntity.ok(authenticationResponse);
    }
}