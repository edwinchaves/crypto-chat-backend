from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from tinyec import registry
import secrets
from Crypto.Cipher import AES
import hashlib
from typing import Generic, TypeVar

# ELLIPTIC CURVE FUNCTIONS -------------------------------------

def point_to_256_bit_key(point):
    """
    Convierte la coordenada x de un punto en una clave secreta de 256 bits usando SHA-256.
    """
    return hashlib.sha256(point.x.to_bytes(32, 'big')).digest()

def encrypt_ECIES(msg, public_key):
    """
    Encripta un mensaje usando la clave pública del receptor.

    Se genera una clave efímera, se calcula el punto compartido (multiplicación de puntos)
    y se deriva una clave simétrica para cifrar el mensaje con AES-GCM.
    """
    curve = public_key.curve
    # Generar número aleatorio para la clave efímera
    ephemeral_key = secrets.randbelow(curve.field.n)
    # Calcular la clave pública efímera
    ephemeral_public_key = ephemeral_key * curve.g
    # Calcular el punto compartido: clave efímera * clave pública del receptor
    shared_point = ephemeral_key * public_key
    # Derivar la clave simétrica
    shared_key = point_to_256_bit_key(shared_point)
    # Encriptar el mensaje con AES-GCM
    aes_cipher = AES.new(shared_key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(msg.encode())
    return (ciphertext, tag, aes_cipher.nonce, ephemeral_public_key)

def decrypt_ECIES(encrypted_msg, private_key):
    """
    Desencripta el mensaje cifrado usando la clave privada del receptor.

    Se recupera el punto compartido (clave privada * clave pública efímera),
    se deriva la clave simétrica y se descifra el mensaje con AES-GCM.
    """
    ciphertext, tag, nonce, ephemeral_public_key = encrypted_msg
    # Calcular el punto compartido: clave privada * clave pública efímera
    shared_point = private_key * ephemeral_public_key
    # Derivar la clave simétrica
    shared_key = point_to_256_bit_key(shared_point)
    # Desencriptar y verificar el mensaje
    aes_cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# ---------------------------------------------------------------

app = FastAPI()

T = TypeVar("T")  # Tipo de dato genérico

# Pydantic model for item data
class User(BaseModel):
    username: str
    private_key: T

class Message(BaseModel):
    message: T
    receiver: str
    sender: str


chat = {}
users = {}
public_keys = {}

curve = registry.get_curve('secp256r1')


@app.post("/user/")
async def create_user(username: str):
    if username in users:
        return {"message": "User already exists"}
    
    
    user = User(username=username, private_key=secrets.randbelow(curve.field.n))
    public_keys[username] = user.private_key*curve.g
    users[username] = user

    return {"message": "User created"}

# Create an item
@app.post("/message/", response_model=Message)
async def send_message(data: Message):
    if data.receiver not in chat:
        chat[data.receiver] = []
    if data.sender not in chat:
        chat[data.sender] = []

    if data.receiver not in users or data.sender not in users:
        raise HTTPException(status_code=404, detail="User not found")

    # Encriptar los mensajes
    encrypted_message = encrypt_ECIES(data.message, public_keys[data.receiver])

    # Guardar mensajes en la bd

    chat[data.receiver].append({"message": encrypted_message, "sender": data.sender, "receiver": data.receiver, "encrypted": True})
    chat[data.sender].append({"message": data.message, "sender": data.sender, "receiver": data.receiver, "encrypted": False})

    message_object = Message(message=data.message, receiver=data.receiver, sender=data.sender) 
    return message_object
    

# Create an item
@app.get("/chat/")
async def get_chat(username: str, friend: str):
    print("Mensaje del chat entre ", username, " y ", friend)
    print(chat[username])
    
    if username not in chat:
        return {"message": "No messages"}
    
    user_chat = []
    for message in chat[username]:
        if message["sender"] == username:
            user_chat.append({"mensaje": message["message"], "sender": username})

        elif message["sender"] == friend:
            decrypted_message = decrypt_ECIES(message["message"], users[username].private_key)
            user_chat.append({"mensaje": decrypted_message, "sender": friend})
    return user_chat
    

# Create an item
@app.get("/friends/")
async def get_users_chat(username: str):
    print(f"Usuarios con chats con {username}")

    friends = set()
    for message in chat[username]:
        if message["sender"] != username:
            friends.add(message["sender"])
        elif message["receiver"] != username:
            friends.add(message["receiver"])
    return list(friends)
        


