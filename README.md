# spring-security-6.3.4-project

## Descripción
Sistema de autenticación y autorización basado en Spring Security con JWT para proteger las rutas de la API. Utiliza JPA para la persistencia de datos y MySQL como base de datos relacional. Incluye manejo de roles para restringir accesos y endpoints para registro, login y gestión de usuarios. 

## Dependencias

```XML
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>com.mysql</groupId>
    <artifactId>mysql-connector-j</artifactId>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <scope>annotationProcessor</scope>
</dependency>
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>4.2.1</version>
</dependency>

```
## Base de datos
Creamos una base de datos, dentro de esta base de datos cremos una tabla llamada: <strong>Users</strong>

```SQL
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255 UNIQUE NOT NULL)
    rol_user VARCHAR(20) NOT NULL
);

```

Insertamos dos usuarios en la tabla verificando que el campo <strong>PASSWORD</strong> tenga una contraseña encriptada.

[Pagina para encriptar contraseñas](https://bcrypt-generator.com/)

```SQL
INSERT INTO users (nombre, email, password, rol_user) VALUES 
('Admin User', 'admin@example.com', 'password', 'admin'), /* pass: admin */
('Regular User', 'user@example.com', 'password', 'user'); /* pass: user */
```

## Clase de configuración de Spring Security
El archivo de configuración principal se encuentra en:

`security/config/SecurityConfig.java`

Este archivo define las configuraciones de seguridad, como los filtros, las políticas de acceso y la integración con JWT.

La clase `SecurityConfig` está anotada con `@Configuration`, lo que indica que es una clase de configuración para Spring. Contiene un método con la anotación `@Bean` que registra un `SecurityFilterChain`. Este filtro es esencial para manejar las configuraciones de seguridad en tu aplicación.

[Documentacion Username/Password Autentication](https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/index.html#servlet-authentication-unpwd)


```JAVA
@Configuration // Marca esta clase como una clase de configuración para Spring.
public class SecurityConfig {

    @Bean // Declara que este método crea un bean administrado por Spring
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Aquí puedes agregar las configuraciones de seguridad
        return http.build();
    }
}
```

> [!NOTE]
> - Basic Authenticacion Filter: Valida si el usr y pw son correctos o no
> - Authentcation Manager: Coordinador que valida el tipo de autenticación si es (usr/pw, Autho0, LDAP…)
> - Authentication Provider: Es capaz de validar la autenticación de usr/pw por el método DaoAuthenticationProvider.
> - User Details Service: En este punto se valida si la contraseña del usuario corresponde a la que se recibió a través de la petición.

Desabilitamos la protección CSRF porque usaremos sesiones sin estado `STATELESS`
Autorizamos las peticiones HTTP

```JAVA
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // desabilitamos la protección csrf

                // Configuración de autorizaciones para las solicitudes HTTP
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated() // todas las rutas necesitan autenticación
                )
        return http.build();
    }
}
```

## Cors Configuration

```JAVA
@Configuration
public class CorsConfig {
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        corsConfiguration.setAllowedOrigins(Arrays.asList("http://localhost:4200"));
        corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        corsConfiguration.setAllowedHeaders(Arrays.asList("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);

        return source;
    }
}
```

## Aplicando reglas de autorización a las rutas (Request Matchers)
`Request Matchers` nos permite gestionar los permisos de peticiones `GET POST PUT DELETE` en rutas especificas o generales

Ejemplos de uso: 
- `.permitAll()`
- `.hasRole("ROLE")`
- `.hasAnyRole("ROLE1", "ROLE2")`
- `.hasAuthotity("PRIVILEGIOS")` Se usa al implementar `UserDetails` a la clase `Usuarios`
- `.denyAll()` Denegar todas las peticiones a una ruta en especifico ya sea `GET POST PUT DELETE`

```JAVA
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // desabilitamos la protección csrf

                // Configuración de autorizaciones para las solicitudes HTTP
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(HttpMethod.GET, "/home").permitAll() // permitimos las peticiones get a la ruta home
                        .requestMatchers(HttpMethod.POST, "/admin/home").hasAuthority("admin") // permitimos las peticiones a administradores
                        .requestMatchers(HttpMethod.POST, "/login").permitAll() // permitimos las peticiones post a login
                        .anyRequest().authenticated() // todas las rutas necesitan autenticación
                )
        return http.build();
    }
}
```

## Crear usuarios en memorio (Opcional)

```JAVA
@Bean
public InMemoryUserDetailsManager userDetailsManager() {
    return new InMemoryUserDetailsManager(
            User.withUsername("admin")
                    .password(passwordEncoder().encode("admin"))
                    .roles("ADMIN")
                    .build()
    );
}
```

## Password Encoder


```JAVA
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```



