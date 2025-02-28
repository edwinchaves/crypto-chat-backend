from fastapi import FastAPI, HTTPException
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


chats = {}
users = {}
public_keys = {}

curve = registry.get_curve('secp256r1')

@app.get("/")
def first_example():
    return {"GFG Example": "FastAPI"}

@app.post("/user/")
async def create_user(username: str):
    if username in users:
        return {"message": "User already exists"}
    
    public_keys[username] = secrets.randbelow(curve.field.n)
    user = User(username=username, private_key=public_keys[username]*curve.g)
    users[username] = user

    return {"message": "User created"}

# Create an item
@app.post("/message/", response_model=Message)
async def send_message(message: str, receiver: str, sender: str):
    if receiver not in chats:
        chats[receiver] = []

    if receiver not in users or sender not in users:
        raise HTTPException(status_code=404, detail="User not found")

    encrypted_message = encrypt_ECIES(message, public_keys[receiver]*curve.g)
    chats[receiver].append({"message": encrypted_message, "sender": sender, "receiver": receiver})
    if sender not in chats:
        chats[sender] = []
    chats[sender].append({"message": encrypted_message, "sender": sender, "receiver": receiver})

    message_object = Message(message=message, receiver=receiver, sender=sender) 
    return message_object
    

# Create an item
@app.get("/chat/")
async def get_chat(username: str, friend: str):
    print(chats)
    if username not in chats.keys():
        return {"message": "No messages"}
    
    user_chat = []
    for message in chats[username]:
        if message["sender"] == friend or message["receiver"] == friend:
            user_chat.append(message)
    return user_chat
    


