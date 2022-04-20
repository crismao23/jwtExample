from fastapi import Body, Depends, APIRouter, Response, status
from schemas.usuario import Usuario, UserLoginSchema
from auth.auth_bearer import JWTBearer
from auth.auth_handler import signJWT
from typing import List
from config.db import conn
from models.usuario import usuarios
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
load_dotenv()

key=os.getenv('FERNET_KEY')
f = Fernet(key)

usuario = APIRouter()

# route handlers

@usuario.post("/usuarios/signup", tags=["user"])
async def create_usuario(usuario: Usuario = Body(...)):
    new_user={"nombre": usuario.nombre, "email": usuario.email}
    new_user["password"] = f.encrypt(usuario.password.encode("utf-8"))
    result = conn.execute(usuarios.insert().values(new_user))
    conn.execute(usuarios.select().where(usuarios.columns.id_usuario == result.lastrowid)).first()    
    return signJWT(usuario.email)


@usuario.post("/usuarios/login", tags=["user"])
async def user_login(user: UserLoginSchema = Body(...)):
    exist_email = conn.execute(usuarios.select().where(usuarios.columns.email == user.email)).first()
    
    if exist_email != None:
        input_pass = bytes(user.password, 'utf-8')
        pass_db = bytes(exist_email[3], 'utf-8')
        db_decrypted = f.decrypt(pass_db)
        if input_pass == db_decrypted:
            print('Logueado')
            return signJWT(user.email)
        else:
            print('PassIncorrect')
            return Response(status_code=400)
    else:
        print('usuario inexistente')
        return {"error": "Wrong login details!"}