# Secure Auth System — Backend

API educativa con Express 5, SQLite, JWT HS256 y bcrypt. Cliente: [auth-app-frontend](https://github.com/rrobertf/auth-app-frontend).

## Setup

Node.js 22.12+ y npm. SQLite puede necesitar herramientas de compilación si tu plataforma no tiene binario precompilado.

```bash
npm ci
cp .env.example .env
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Copia el secreto generado a `JWT_SECRET` en `.env`; se rechazan valores menores de 32 bytes antes de abrir SQLite. Configura `PORT` (5001), `DB_PATH` (`auth.db`) y `FRONTEND_ORIGIN` (`http://localhost:3000`). No pongas secretos en el frontend ni en Git.

```bash
npm start
npm run dev  # Node --watch, sin nodemon
npm test
npm audit
```

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/auth/register` | `{ username, email, password }`; devuelve token y usuario |
| POST | `/api/auth/login` | `{ email, password }`; devuelve token y usuario |
| GET | `/api/auth/me` | Usuario actual validado contra SQLite |
| GET | `/api/auth/profile` | Perfil, incluida fecha de creación |
| POST | `/api/auth/logout` | Mensaje de cierre del cliente; no revoca JWT |

Rutas protegidas: `Authorization: Bearer <token>`. Usuario de respuesta: `id, username, email, role`; nunca se devuelve el hash. Roles se leen de la base, sin aceptar privilegios del registro o confiar en roles obsoletos del token.

Registro: nombre de 2–80 caracteres, email válido de hasta 254 caracteres y contraseña de al menos 8 caracteres / máximo 72 bytes UTF-8. bcrypt asíncrono con coste 12. Tokens nuevos duran una hora; tokens antiguos firmados con el mismo secreto siguen sujetos a su expiración original. Eliminar un usuario invalida su acceso a `/me` y `/profile`.

Registro y login comparten 30 solicitudes por IP cada 15 minutos (429); cuentas duplicadas devuelven 409; entradas inválidas 400; credenciales/tokens inválidos 401. JSON limitado a 16 KB. Errores de servidor devuelven un mensaje genérico. CORS solo permite el origen configurado; no es una barrera de autenticación para clientes ajenos al navegador.

## Compatibilidad y datos

No se cambia el esquema `users(id, username, email, password, role, created_at)` ni se borran usuarios. El email mantiene coincidencia exacta para conservar cuentas anteriores con mayúsculas. Los hashes y contraseñas anteriores de seis caracteres siguen funcionando en login. Las contraseñas que superen 72 bytes deben restablecerse mediante un proceso administrativo confiable; no se acepta el truncamiento silencioso de bcrypt.

Antes de actualizar, detén el servidor y respalda `auth.db` fuera del repositorio con SQLite `.backup`. Mantén `DB_PATH` apuntando a la base existente. `.gitignore` incluye secretos y archivos SQLite auxiliares. Las pruebas usan bases en memoria.

## Alcance de seguridad

Proyecto de aprendizaje, sin 2FA, recuperación por correo ni revocación de tokens. Cerrar sesión solo borra el token del cliente: uno copiado sigue válido hasta expirar. HTTPS, cookies HttpOnly y una política de revocación requieren trabajo adicional para un despliegue público. El limitador actual es por proceso; múltiples instancias necesitan almacenamiento compartido y una configuración de proxy confiable.

`npm test` cubre registro/login/perfil, hashing, datos malformados, límites de bcrypt, tokens expirados, usuarios eliminados, compatibilidad de cuentas antiguas, CORS y throttling. CI ejecuta la suite en cada PR.
