package com.security.springsecurityproject.security.service;

import com.security.springsecurityproject.model.SecurityUser;
import com.security.springsecurityproject.model.Usuario;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.security.springsecurityproject.model.usuarioRepository;
import org.springframework.stereotype.Service;


@Service
@AllArgsConstructor
public class AutenticationService implements UserDetailsService {

    private usuarioRepository usuarioRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario user = usuarioRepository.findByEmail(username);

        if (user == null) {
            throw new UsernameNotFoundException("Usuario no encontrado");
        }

        return new SecurityUser(user);
    }
}
