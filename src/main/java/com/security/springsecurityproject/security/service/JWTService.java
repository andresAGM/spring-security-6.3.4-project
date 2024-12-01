package com.security.springsecurityproject.security.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.security.springsecurityproject.model.Usuario;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JWTService {
    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    public String generarToken(Usuario usuario) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            return JWT.create()
                    .withIssuer("spring security") // quien crea el token
                    .withSubject(usuario.getEmail()) //
                    .withClaim("id", usuario.getId())
                    .withExpiresAt(new Date(System.currentTimeMillis() + jwtExpiration))
                    .sign(algorithm);
        } catch (JWTCreationException exception){
            throw new RuntimeException();
        }
    }

    public String getSubject(String token) {
        // Verificar si el token es nulo
        if (token == null) {
            throw new RuntimeException("Token nulo");
        }

        DecodedJWT decodedJWT = null; // Inicializar la variable

        try {
            // Crear el algoritmo de verificación
            Algorithm algorithm = Algorithm.HMAC256(secretKey); // validando firma
            // Verificar el token
            decodedJWT = JWT.require(algorithm)
                    .withIssuer("spring security")
                    .build()
                    .verify(token);
        } catch (JWTVerificationException exception) {
            // Manejo de excepciones: el token no es válido
            System.out.println("Token inválido: " + exception.getMessage());
            throw new RuntimeException("Token inválido", exception); // Lanza una excepción con un mensaje claro
        }

        // Verificar si el sujeto es nulo
        if (decodedJWT.getSubject() == null) {
            throw new RuntimeException("El sujeto del token es nulo");
        }

        // Retornar el sujeto
        return decodedJWT.getSubject();
    }
}
