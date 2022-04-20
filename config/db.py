from sqlalchemy import create_engine, MetaData
import os
from dotenv import load_dotenv
load_dotenv()


dbHost = os.getenv('DB_HOST')
dbName = os.getenv('DB_NAME')
dbUser = os.getenv('DB_USER')
dbPassw = os.getenv('DB_PASS')

engine = create_engine(f'mysql+pymysql://{dbUser}:{dbPassw}@{dbHost}/{dbName}')

meta = MetaData()
conn = engine.connect()


