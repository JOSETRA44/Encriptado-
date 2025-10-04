# 🔐 Cifrador de API Keys con PIN (Python)

Este proyecto permite **cifrar tus llaves API o contraseñas sensibles** usando un **PIN personal de 6 dígitos**.
El objetivo es evitar que tus claves reales queden expuestas en tu código fuente.

---

## 🚀 Características

* Derivación de clave segura con **PBKDF2-HMAC (SHA-256, 600,000 iteraciones)**.
* Cifrado simétrico autenticado con **Fernet (AES-CBC + HMAC)**.
* Sal criptográfica aleatoria generada automáticamente.
* Interfaz por consola simple y amigable.
* No guarda el PIN ni la clave real.

---

## ⚙️ Requisitos

* Python 3.8 o superior
* Librería `cryptography`

Instálala con:

```bash
pip install cryptography
```

---

## 🧩 Uso

1. Ejecuta el script:

   ```bash
   python cifrador.py
   ```
2. Pega tu API Key (por ejemplo, la de Google).
3. Ingresa un **PIN de 6 dígitos** que será tu contraseña de cifrado.
4. El programa generará dos líneas como estas:

   ```
   ENCRYPTED_API_KEY = "gAAAAABm..."
   API_KEY_SALT = "sdfY9ns8sdf8nsdf..."
   ```
5. Copia ambas y pégalas en la parte superior de tu archivo que necesite la clave (por ejemplo, `keylogger.py`).

---

## 🔓 Descifrado (en tu otro script)

Para descifrar la clave (si quieres implementarlo tú mismo):

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

def derive_key(password: str, salt_b64: str) -> bytes:
    salt = base64.b64decode(salt_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def decrypt_api_key(encrypted_b64: str, salt_b64: str, pin: str) -> str:
    key = derive_key(pin, salt_b64)
    f = Fernet(key)
    decrypted = f.decrypt(base64.b64decode(encrypted_b64))
    return decrypted.decode()

# Ejemplo:
# api_key = decrypt_api_key(ENCRYPTED_API_KEY, API_KEY_SALT, "123456")
```

---

## ⚠️ Advertencia de seguridad

* **Nunca subas** tu PIN ni tus API Keys reales a GitHub.
* No compartas el `ENCRYPTED_API_KEY` junto con el PIN.
* La herramienta es educativa y sirve para proteger datos locales o de desarrollo.

---

## 🪪 Licencia

MIT License — libre para uso y modificación, con atribución al autor original.

---

## 💡 Créditos

Creado por [TuNombre] — inspirado en buenas prácticas de seguridad aplicadas a desarrollo local.
