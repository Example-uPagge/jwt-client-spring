package dev.struchkov.example.jwt.client.one.controller;

import lombok.RequiredArgsConstructor;
import dev.struchkov.example.jwt.client.one.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api")
@RequiredArgsConstructor
public class Controller {

    private final AuthService authService;

    @PreAuthorize("hasAuthority('USER')")
    @GetMapping("hello/user")
    public ResponseEntity<String> helloUser() {
        return ResponseEntity.ok("Hello user "+ authService.getAuthentication().getPrincipal() + "!");
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("hello/admin")
    public ResponseEntity<String> helloAdmin() {
        return ResponseEntity.ok("Hello admin "+ authService.getAuthentication().getPrincipal() + "!");
    }

}
