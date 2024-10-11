#Script para cambiar a formato de python plantilla html
import re

path = 'C:\\Users\\Ian\\Desktop\\Proyecto_cripto\\app\\templates\\login.html'

#Abrimos el archivo html
try:
    f = open(path).read()
    rutas = re.findall(r"href=\"[\w/|\w\.\w|\.\w]+\"|src=\"[\w/|\w\.\w|\.\w]+\"", f, re.IGNORECASE)
    for ruta in rutas:
        url = re.findall(r"\"[\w/|\w\.\w|\.\w]+\"", ruta)[0]
        f = f.replace(url, "\"{{ url_for('static', filename="+url+")}}\"")
    w = open(path, "w")
    w.write(f)
    print("Exitoso")
except:
    print("No se pudo abrir el archivo")