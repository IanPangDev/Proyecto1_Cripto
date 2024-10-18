from pysqlitecipher import sqlitewrapper
import pandas as pd
from os import getenv

"""
Script que maneja la base de datos
"""

def store_message(message_info):
    """
    Almacenamiento de los mensajes

    Args:
        message_info: Un diccionario con la informacion del mensaje enviado
    """
    obj = sqlitewrapper.SqliteCipher(dataBasePath="app/Models/appChat_messages.db" , checkSameThread=False , password=getenv('DB_KEY'))
    obj.insertIntoTable("mensajes", [i for i in message_info.values()] , commit = True)

def delete_messages(username):
    """
    Eliminacion de los mensajes

    Args:
        username: El nombre del usuario del cual eliminaremos sus mensajes
    """
    obj = sqlitewrapper.SqliteCipher(dataBasePath="app/Models/appChat_messages.db" , checkSameThread=False , password=getenv('DB_KEY'))
    data = obj.getDataFromTable("mensajes", raiseConversionError = True , omitID = False)
    data = pd.DataFrame(data[1:][0], columns=data[0]).set_index('ID')
    indices_a_borrar = data.where(data.username == username).index.array

    for i, index in enumerate(indices_a_borrar):
        es_ultimo = (i == len(indices_a_borrar) - 1)
        update_id = es_ultimo
        obj.deleteDataInTable("mensajes", index, commit=True, raiseError=True, updateId=update_id)