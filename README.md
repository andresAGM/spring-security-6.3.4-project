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

## Usar los usuarios de nuestra base de datos

Creamos la entidad Usuario

Ubicación del archivo: `model/Usuario`

```JAVA
@Table(name = "users")
@Entity
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Setter
public class Usuario implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, length = 50)
    private String nombre;

    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(name = "rol_user", nullable = false, length = 20)
    private String rolUser;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(rolUser)); // autoridad basado en el rol_user campo de nuestra tabla users
    }

    @Override
    public String getUsername() {
        return email;
    }
}
```

Creamos el repositorio

Ubicación del archivo: `model/usuarioReposiroty`

```JAVA
public interface usuarioRepository extends JpaRepository<Usuario, Integer> {
    Usuario findByEmail(String username);
}
```

Implementamos la interfaz `UserDetailsService` en un clace `AutenticationService`
Ubicación del archivo: `security/service/AutenticacionService`
Hacemos uso del metodo `loadUserByUsername`, aqui buscamos el usuario en la base de datos por medio del repositorio

```JAVA
@Service
@AllArgsConstructor
public class AutenticationService implements UserDetailsService {

    // instancia del reposirotio
    private usuarioRepository usuarioRepository; 

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario user = usuarioRepository.findByEmail(username); // buscamos el usuario por email

        if (user == null) {  // retornamos error si es null
            throw new UsernameNotFoundException("Usuario no encontrado");
        }

        // retornamos el usuario usando la clase SecurityUser que implementa UserDetails
        return new SecurityUser(user);
    }
}

```

Opcion numero 1: Crear una clase que implemente UserDetails

```JAVA
@AllArgsConstructor
@NoArgsConstructor
public class SecurityUser implements UserDetails {
    private Usuario user;

    public Usuario getUser () {
        return user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(user.getRolUser()));
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }
}
```

Opcion numero 2: Usar directamente UserDetails

```JAVA
@Override
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Usuario user = usuarioRepository.findByEmail(username);

    if (user == null) {
        throw new UsernameNotFoundException("Usuario no encontrado");
    }

    return User.builder()
            .username(user.getUsername()) // obtenemos el email
            .password(user.getPassword()) // obtenemos la contraseña
            .roles(user.getRolUser()) // obtenemos el rol del usuario
            .build()
}
```

## Controlar metodos con Method Security

En nuestra clase de configuracion agregamos `@EnableMethosSecurity`, y a cada metodo en nuestro controlador le agregamos `@Secured("ROLE_ADMIN")` para las rutas que solo pueden acceder los administradores.

o usar `@PreAuthorize("hasAuthority('admin')")`

## Creando servicio JWT
Ubicación del archivo `security/service/JWTSetvice`
En este servicio utilizaremos la libreia de JWT para generar los tokens.

Primero creamos el metodo generar token

```JAVA
@Service
public class JWTService {
    @Value("${security.jwt.secret-key}")
    private String secretKey;  // clave secreta ubicada en application.properties
    
    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

public String generarToken(Usuario usuario) {
    try {
        // creamos un algoritmo para firmar el token
        Algorithm algorithm = Algorithm.HMAC256(secretKey);

        // usamos el metodo create de JWT para crear el token
        return JWT.create()
                .withIssuer("spring security") // quien crea el toke
                .withSubject(usuario.getEmail()) // asunto siempre sera el usuario
                .withClaim("id", usuario.getId()) 
                .withExpiresAt(new Date(System.currentTimeMillis() + jwtExpiration)) // cuando expira el token
                .sign(algorithm); // firma del token usando el algoritmo

    } catch (JWTCreationException exception){
        throw new RuntimeException();
    }
}

```

## Controlador de autenticacion

Creamos el autentication manager en la clase de configuraci+on

```JAVA
@Bean
public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
        throws Exception {
    return configuration.getAuthenticationManager();
}

```

Configuramos el metodo de login donde usamos el autenticationManager y el metodo para generar el token

```JAVA
@Autowired
private AuthenticationManager authenticationManager;

@Autowired
private JWTService tokenService;

@PostMapping("/login")
public ResponseEntity autenticarUsuario(@RequestBody LoginRequest datosAutenticacionUsuario) {
    // Crear el token de autenticación
    Authentication authToken = new UsernamePasswordAuthenticationToken(
            datosAutenticacionUsuario.username(),
            datosAutenticacionUsuario.password()
    );

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

```

Permitimos las peticiones post a login en el filterChain `.requestMatchers(HttpMethod.POST, "/login").permitAll()`

filtro jwt

inyectar el filtro a la clase de configuracion 

agregamos en el filterchain `.addFilterBefore(jwtAutenticationFilter, UsernamePasswordAuthenticationFilter.class);`

agregamos sesionagement stateless


