# spring-security-6.3.4-project

## Descripción
Proyecto vacío con Spring Security configurado.

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
<p>Creamos una base de datos, dentro de esta base de datos cremoa una tabla llamada: <strong>Users</strong></p>

```SQL
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255 UNIQUE NOT NULL)
    rol_user VARCHAR(20) NOT NULL
);

```

<p>Insertamos dos usuarios en la tabla verificando que el campo <strong>PASSWORD</strong> tenga una contraseña encriptada. <small><a target="_blank" href="https://bcrypt-generator.com/">Pagina para encriptar</a></small></p>

```SQL
INSERT INTO users (nombre, email, password, rol_user) VALUES 
('Admin User', 'admin@example.com', 'password', 'admin'), /* pass: admin */
('Regular User', 'user@example.com', 'password', 'user'); /* pass: user */
```
