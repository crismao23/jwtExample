from sqlalchemy import Table, Column
from sqlalchemy.sql.sqltypes import Integer, String
from config.db import meta, engine


usuarios = Table("usuarios", meta, Column(
    "id_usuario", Integer, primary_key=True), 
    Column("nombre", String(255)), 
    Column("email", String(255)),
    Column("password",String(255)))

meta.create_all(engine)