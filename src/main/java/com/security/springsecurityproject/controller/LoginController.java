package com.security.springsecurityproject.controller;

import com.security.springsecurityproject.model.SecurityUser;
import com.security.springsecurityproject.model.Usuario;
import com.security.springsecurityproject.model.usuarioRepository;
import com.security.springsecurityproject.security.DTO.DatosJWTToken;
import com.security.springsecurityproject.security.DTO.LoginRequest;
import com.security.springsecurityproject.security.service.JWTService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@EnableMethodSecurity
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTService tokenService;

    @Autowired
    private usuarioRepository repo;

    @PostMapping("/login")
    public ResponseEntity autenticarUsuario(@RequestBody LoginRequest datosAutenticacionUsuario) {
        // Crear el token de autenticación
        Authentication authToken = new UsernamePasswordAuthenticationToken(
                datosAutenticacionUsuario.username(),
                datosAutenticacionUsuario.password()
        );

        System.out.println(authToken.getPrincipal());

        // Autenticar al usuario
        var usuarioAutenticado = authenticationManager.authenticate(authToken);

        // Obtener el objeto SecurityUser
        SecurityUser securityUser  = (SecurityUser ) usuarioAutenticado.getPrincipal();

        // Obtener el objeto Usuario desde SecurityUser
        Usuario usuario = securityUser.getUser(); // Obtén el objeto Usuario

        // Generar el token JWT
        var JWTtoken = tokenService.generarToken(usuario);

        // Retornar el token JWT
        return ResponseEntity.ok(new DatosJWTToken(JWTtoken));
    }

    @PostMapping("admin/home")
    @PreAuthorize("hasAuthority('admin')")
    public String adminHome() {
        return "admin home";
    }

    @GetMapping("/home")
    public List<Usuario> home() {
        return repo.findAll();
    }
}
