"""
BusPasse API — Backend de autenticação (MariaDB / XAMPP)
Requisitos: fastapi, uvicorn, mysql-connector-python, bcrypt, python-jose, python-dotenv
Execute: uvicorn main:app --reload
"""

import os
from datetime import datetime, timedelta, timezone

import bcrypt
import mysql.connector
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from pydantic import BaseModel

load_dotenv()

# ── CONFIGURAÇÃO ──────────────────────────────────────────────────────────────
SECRET_KEY        = os.getenv("JWT_SECRET", "troque-isso-por-um-segredo-forte-aleatorio")
ALGORITHM         = "HS256"
TOKEN_EXPIRE_DAYS = 7

DB_CONFIG = {
    "host":     os.getenv("DB_HOST",     "localhost"),
    "database": os.getenv("DB_NAME",     "buspass"),
    "user":     os.getenv("DB_USER",     "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "port":     int(os.getenv("DB_PORT", "3306")),
}

# ── APLICAÇÃO ─────────────────────────────────────────────────────────────────
app = FastAPI(title="BusPasse API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Em produção: especifique o domínio do frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── BANCO DE DADOS ────────────────────────────────────────────────────────────
def get_conn():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as e:
        raise HTTPException(status_code=503, detail=f"Banco de dados indisponível: {e}")

# ── JWT ───────────────────────────────────────────────────────────────────────
def criar_token(user_id: int, nome: str) -> str:
    payload = {
        "sub": str(user_id),
        "nome": nome,
        "exp": datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verificar_token(authorization: str = Header(...)) -> dict:
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Formato inválido. Use: Bearer <token>")
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

# ── SCHEMAS ───────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    senha: str

class CadastroRequest(BaseModel):
    cpf:         str
    nome:        str
    email:       str
    senha:       str
    celular:     str | None = None
    cep:         str | None = None
    cidade:      str | None = None
    bairro:      str | None = None
    rua:         str | None = None
    numero:      str | None = None
    complemento: str | None = None

# ── ROTAS ─────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "ok", "api": "BusPasse API", "versao": "1.0.0"}


@app.post("/login")
def login(data: LoginRequest):
    """Autentica usuário por email + senha e retorna JWT."""
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            "SELECT id, nome, senha_hash FROM usuarios WHERE email = %s",
            (data.email.lower().strip(),),
        )
        row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=401, detail="Email ou senha incorretos")

        user_id, nome, senha_hash = row

        if not bcrypt.checkpw(data.senha.encode(), senha_hash.encode()):
            raise HTTPException(status_code=401, detail="Email ou senha incorretos")

        token = criar_token(user_id, nome)
        return {"token": token, "nome": nome, "id": user_id}
    finally:
        cur.close()
        conn.close()


@app.post("/cadastro", status_code=201)
def cadastro(data: CadastroRequest):
    """Cria novo usuário e retorna JWT (já loga ao cadastrar)."""
    cpf_limpo = "".join(filter(str.isdigit, data.cpf))
    if len(cpf_limpo) != 11:
        raise HTTPException(status_code=422, detail="CPF inválido — informe 11 dígitos")

    if len(data.senha) < 6:
        raise HTTPException(status_code=422, detail="Senha deve ter pelo menos 6 caracteres")

    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT 1 FROM usuarios WHERE email = %s", (data.email.lower().strip(),))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Este email já está cadastrado")

        cur.execute("SELECT 1 FROM usuarios WHERE cpf = %s", (cpf_limpo,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Este CPF já está cadastrado")

        senha_hash = bcrypt.hashpw(data.senha.encode(), bcrypt.gensalt()).decode()

        cur.execute(
            """
            INSERT INTO usuarios
                (cpf, nome, email, senha_hash, celular, cep, cidade, bairro, rua, numero, complemento)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                cpf_limpo,
                data.nome.strip(),
                data.email.lower().strip(),
                senha_hash,
                data.celular,
                data.cep,
                data.cidade,
                data.bairro,
                data.rua,
                data.numero,
                data.complemento,
            ),
        )
        user_id = cur.lastrowid   # MariaDB: ID gerado pelo AUTO_INCREMENT
        conn.commit()

        token = criar_token(user_id, data.nome.strip())
        return {"token": token, "nome": data.nome.strip(), "id": user_id}

    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Erro interno: {e}")
    finally:
        cur.close()
        conn.close()


@app.get("/me")
def me(payload: dict = Depends(verificar_token)):
    """Retorna dados do usuário autenticado (requer Bearer token)."""
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            """
            SELECT id, nome, email, tipo_usuario, saldo, passes_disponiveis
            FROM usuarios WHERE id = %s
            """,
            (int(payload["sub"]),),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        user_id, nome, email, tipo, saldo, passes = row
        return {
            "id":                 user_id,
            "nome":               nome,
            "email":              email,
            "tipo_usuario":       tipo,
            "saldo":              float(saldo),
            "passes_disponiveis": float(passes),
        }
    finally:
        cur.close()
        conn.close()