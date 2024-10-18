from pysqlitecipher import sqlitewrapper
from os import getenv
from dotenv import load_dotenv
import pandas as pd

"""
Script para realizar pruebas de consumo en la base de datos
"""

load_dotenv()

obj = sqlitewrapper.SqliteCipher(dataBasePath="app/Models/appChat_messages.db" , checkSameThread=False , password=getenv('DB_KEY'))
data = obj.getDataFromTable("mensajes", raiseConversionError = True , omitID = False)
data = pd.DataFrame(data[1:][0], columns=data[0]).set_index('ID')
print(data.where(data.username == "HOLA").index.array)