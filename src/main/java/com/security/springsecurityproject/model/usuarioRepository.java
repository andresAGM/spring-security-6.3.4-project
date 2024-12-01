package com.security.springsecurityproject.model;

import org.springframework.data.jpa.repository.JpaRepository;

public interface usuarioRepository extends JpaRepository<Usuario, Integer> {
    Usuario findByEmail(String username);
}
