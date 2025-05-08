from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from typing import Dict, List

app = FastAPI(
    title="Actividad Formativa 4",
    description="API para gestionar la orquestación de servicios",
    version="1.0.0",
)

# Define el esquema de autenticación OAuth2 basado en tokens Bearer.
# `tokenUrl` indica la ruta que generará los tokens (debe ser la misma del login)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/autenticar-usuario")

# Parametros para la Base de Datos
users_db = {

    "admin": {
        "password": "admin123",
        "role": "Administrador"
    },

    "orq": {
        "password": "orq123", 
        "role": "Orquestador"
    },

    "user": {
        "password": "user123", 
        "role": "Usuario"
    }
}

tokens_db = {}
services_db = {}
rules_db = {}

# --- Modelos de datos (para validación y documentación automática) ---

# Modelo para registrar servicios
class Servicio(BaseModel):
    nombre:         str
    descripcion:    str
    endpoints:      List[str]

# Modelo para actualizar reglas de orquestación
class ReglasOrquestacion(BaseModel):
    reglas:         Dict[str, str]

# Modelo para realizar una solicitud de orquestación
class SolicitudOrquestar(BaseModel):
    servicio_destino:       str
    parametros_adicionales: Dict[str, str]

# Modelo alternativo de credenciales (no se usa con OAuth2PasswordRequestForm)
class Credenciales(BaseModel):
    nombre_usuario: str
    contrasena:     str

# Modelo para solicitudes de autorización
class SolicitudAutorizacion(BaseModel):
    recursos:       List[str]
    rol_usuario:    str

# --- Utilidades ---

# Función para generar un token ficticio basado en el nombre de usuario
def generar_token(username: str) -> str:
    return f"token-{username}"

# Función que obtiene el usuario actual a partir del token recibido
def get_current_user(token: str = Depends(oauth2_scheme)):
    username = tokens_db.get(token) # Busca el usuario segun token
    if not username:
        raise HTTPException(status_code=401, detail="Token inválido")
    return {"username": username, "role": users_db[username]["role"]}

# Decorador para proteger rutas según roles específicos
def require_roles(*roles):
    def role_checker(user=Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="No autorizado")
        return user
    return role_checker

# --- Endpoints ---

# Con tags=["???"] se clasifican los endpoints

# Endpoint de autenticación de usuarios (login)
@app.post("/autenticar-usuario", tags=["Autenticación"])
def autenticar_usuario(form_data: OAuth2PasswordRequestForm = Depends()):

    # Busca el usuario ingresado
    usuario = users_db.get(form_data.username)
    # Verifica que exista y que la contraseña coincida
    if not usuario or usuario["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    # Genera y almacena un token asociado al usuario
    token = generar_token(form_data.username)
    tokens_db[token] = form_data.username
    # Retorna el token en el formato esperado por OAuth2
    return {"access_token": token, "token_type": "bearer"}


# Endpoint para autorizar el acceso a recursos (solo roles Admin y Orquestador)
@app.post("/autorizar-acceso", tags=["Autorización"])
def autorizar_acceso(solicitud: SolicitudAutorizacion, user=Depends(require_roles("Administrador", "Orquestador"))):
    # Simula una respuesta positiva de autorización para los recursos solicitados
    return {
        "autorizado": True,
        "rol_usuario": solicitud.rol_usuario,
        "recursos_autorizados": solicitud.recursos
    }


# Obtiene información de un servicio específico (requiere estar autenticado)
@app.get("/informacion-servicio/{id}", tags=["Servicios"])
def obtener_info_servicio(id: str, user=Depends(get_current_user)):
    servicio = services_db.get(id)
    if not servicio:
        raise HTTPException(status_code=404, detail="Servicio no encontrado")
    return {"id": id, "datos": servicio}


# Registra un nuevo servicio (solo para Administradores)
@app.post("/registrar-servicio", tags=["Servicios"])
def registrar_servicio(servicio: Servicio, user=Depends(require_roles("Administrador"))):
    # Crea un ID para el servicio basado en su nombre
    servicio_id = servicio.nombre.lower().replace(" ", "_")
    services_db[servicio_id] = servicio
    return {"mensaje": "Servicio registrado correctamente", "id": servicio_id}


# Actualiza las reglas de orquestación (solo para Orquestadores)
@app.put("/actualizar-reglas-orquestacion", tags=["Orquestación"])
def actualizar_reglas(reglas: ReglasOrquestacion, user=Depends(require_roles("Orquestador"))):
    # Actualiza el diccionario de reglas con las nuevas reglas recibidas
    rules_db.update(reglas.reglas)
    return {"mensaje": "Reglas actualizadas", "reglas": rules_db}


# Realiza la orquestación de servicios (solo para Admins y Orquestadores)
@app.post("/orquestar", tags=["Orquestación"])
def orquestar(solicitud: SolicitudOrquestar, user=Depends(require_roles("Administrador", "Orquestador"))):
    # Verifica si el servicio destino existe
    if solicitud.servicio_destino not in services_db:
        raise HTTPException(status_code=404, detail="Servicio de destino no encontrado")
    # Simula la ejecución de una orquestación
    return {
        "mensaje":               "Orquestación exitosa",
        "servicio_destino":      solicitud.servicio_destino,
        "parametros_enviados":   solicitud.parametros_adicionales
    }