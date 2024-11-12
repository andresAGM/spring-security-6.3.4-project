# spring-security-6.3.4-project
Proyecto vacío con Spring Security configurado.
<hr/>
<p>Instalar depencencias: spring security, spring web, jpa, driver mysql.</p>
<h3>Base de datos</h3>

```SQL
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255 UNIQUE NOT NULL)
    rol_user VARCHAR(20) NOT NULL
);

```

```SQL
INSERT INTO users (nombre, email, password, rol_user) VALUES 
('Admin User', 'admin@example.com', 'password', 'admin'), /* pass: admin */
('Regular User', 'user@example.com', 'password', 'user'); /* pass: user */
```
