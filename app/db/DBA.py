from pysqlitecipher import sqlitewrapper
import pandas as pd
from os import getenv
from Cryptodome.PublicKey import RSA
from utilities.cryptography import *
import pandas as pd

"""
Script que maneja la base de datos
"""

def store_message(message_info):
    """
    Almacenamiento de los mensajes

    Args:
        message_info: Un diccionario con la informacion del mensaje enviado
    """
    obj = sqlitewrapper.SqliteCipher(dataBasePath="app/db/appChat_messages.db" , checkSameThread=False , password=getenv('DB_KEY'))
    obj.insertIntoTable("mensajes", [i for i in message_info.values()] , commit = True)

def delete_messages(username):
    """
    Eliminacion de los mensajes

    Args:
        username: El nombre del usuario del cual eliminaremos sus mensajes
    """
    obj = sqlitewrapper.SqliteCipher(dataBasePath="app/db/appChat_messages.db" , checkSameThread=False , password=getenv('DB_KEY'))
    data = obj.getDataFromTable("mensajes", raiseConversionError = True , omitID = False)
    data = pd.DataFrame(data[1:][0], columns=data[0]).set_index('ID')
    indices_a_borrar = data.where((data.username == username) | (data.recipient == username)).index.array

    for i, index in enumerate(indices_a_borrar):
        es_ultimo = (i == len(indices_a_borrar) - 1)
        update_id = es_ultimo
        obj.deleteDataInTable("mensajes", index, commit=True, raiseError=True, updateId=update_id)
    
def get_messages(username, private_key):
    """
    Obtencion de los mensajes

    Args:
        username: El nombre del usuario del cual eliminaremos sus mensajes
    """
    obj = sqlitewrapper.SqliteCipher(dataBasePath="app/db/appChat_messages.db" , checkSameThread=False , password=getenv('DB_KEY'))
    data = obj.getDataFromTable("mensajes", raiseConversionError = True , omitID = False)
    data = pd.DataFrame(data[1:][0], columns=data[0]).set_index('ID')
    mensajes = []
    for registro in data.where((data.recipient == username) | (data.username == username)).dropna().iloc:
        if registro.recipient == username:
            mensajes.append([registro.username,
                                registro.recipient,
                                decrypt_message(registro.to_dict(), private_key)])
        else:
            mensajes.append([registro.username,
                                registro.recipient,
                                decrypt_asymmetric(base64.b64decode(registro.ciphertext_me), private_key).decode("utf-8")])
    return mensajes