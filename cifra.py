from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64


def derive_key(password: str, salt: bytes) -> bytes:
    """Deriva una clave criptográfica a partir de una contraseña y una sal."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,  # Iteraciones aumentadas para mayor seguridad
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_api_key():
    """Interfaz para que el usuario cifre su API Key de Google con un PIN."""
    print("--- Herramienta de Cifrado de API Key ---")
    print("Esta herramienta generará una versión cifrada de tu API Key para el proyecto.")

    # Obtener la API Key del usuario
    api_key = input("Pega tu API Key de Google Geolocation: ").strip()
    if not api_key.startswith("AIza"):
        print("\n(!) Advertencia: La API Key no parece tener el formato correcto. Asegúrate de que sea válida.")
        return

    # Obtener el PIN de 6 dígitos del usuario
    pin = input("Introduce un PIN de 6 dígitos que usarás como contraseña: ").strip()
    if not (pin.isdigit() and len(pin) == 6):
        print("\n(!) Error: El PIN debe ser un número de 6 dígitos.")
        return

    # Generar una sal criptográfica nueva
    salt = os.urandom(16)

    # Derivar la clave de cifrado a partir del PIN y la sal
    encryption_key = derive_key(pin, salt)

    # Crear una instancia de Fernet y cifrar la API Key
    f = Fernet(encryption_key)
    encrypted_token_bytes = f.encrypt(api_key.encode())

    # Codificar los bytes en base64 para poder copiarlos como texto
    encrypted_token_b64 = base64.b64encode(encrypted_token_bytes).decode('utf-8')
    salt_b64 = base64.b64encode(salt).decode('utf-8')

    print("\n" + "=" * 50)
    print("¡CIFRADO COMPLETADO!")
    print("Copia EXACTAMENTE las siguientes 2 líneas y pégalas en la parte superior de tu archivo `keylogger.py`:")
    print("=" * 50 + "\n")
    print(f'ENCRYPTED_API_KEY = "{encrypted_token_b64}"')
    print(f'API_KEY_SALT = "{salt_b64}"')
    print("\n" + "=" * 50)


if __name__ == "__main__":
    encrypt_api_key()

