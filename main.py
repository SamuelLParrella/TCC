
import json
import os
import random
import re
import secrets
import unicodedata
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import bcrypt
import mysql.connector
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
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

# Chave Pix estática da empresa/beneficiário que recebe as recargas.
# Sem um PSP (Mercado Pago, Efí, etc.) o backend não recebe webhook de
# confirmação automática — por isso o app confirma o pagamento manualmente
# via POST /recarga/{id}/confirmar (ver docstring do endpoint).
PIX_KEY           = os.getenv("PIX_KEY", "")
PIX_MERCHANT_NAME = os.getenv("PIX_MERCHANT_NAME", "BUSPASSE LTDA")
PIX_MERCHANT_CITY = os.getenv("PIX_MERCHANT_CITY", "SAO PAULO")
PRECO_PASSAGEM    = float(os.getenv("PRECO_PASSAGEM", "5.75"))

# Envio de email para confirmação de cadastro/login, via API HTTP da Brevo
# (https://api.brevo.com/v3/smtp/email) em vez de SMTP — hospedagens
# gratuitas como o Render costumam bloquear/travar a porta de SMTP (587),
# mas a API HTTP passa pela porta 443, que nunca é bloqueada.
BREVO_API_KEY           = os.getenv("BREVO_API_KEY", "")
BREVO_FROM_EMAIL        = os.getenv("BREVO_FROM_EMAIL", "")
CODIGO_VALIDADE_MINUTOS = 15

# URL pública da própria API — usada para montar os links de aprovar/recusar
# no email mandado pra escola (POST /tipo-usuario/solicitar-estudante).
API_BASE_URL = os.getenv("API_BASE_URL", "https://tcc-82gl.onrender.com")

# Pagamento por aproximação com o celular (NFC). O app pede um token de uso
# único e vida curta, o celular entrega esse token ao leitor do ônibus e o
# leitor confirma na API (POST /nfc/validar). Não dá pra identificar o celular
# pelo UID como no cartão físico: o Android muda de UID a cada aproximação
# quando emula um cartão (HCE).
NFC_TOKEN_VALIDADE_SEGUNDOS = 120
NFC_TOKEN_REGEX             = re.compile(r"^[0-9a-f]{16}$")

# Tipos que não pagam tarifa (isenção prevista em lei para idosos e, em regra,
# pessoas com deficiência no transporte coletivo municipal).
TIPOS_GRATUITOS = {"idoso", "pcd"}

def tarifa_do_usuario(tipo_usuario: str) -> float:
    """Retorna o valor da passagem para o tipo de usuário: comum paga cheio,
    estudante paga metade, idoso/PCD não pagam."""
    if tipo_usuario == "estudante":
        return round(PRECO_PASSAGEM / 2, 2)
    if tipo_usuario in TIPOS_GRATUITOS:
        return 0.0
    return PRECO_PASSAGEM

# ── APLICAÇÃO ─────────────────────────────────────────────────────────────────
app = FastAPI(title="BusPasse API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Em produção: especifique o domínio do frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_conn():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as e:
        raise HTTPException(status_code=503, detail=f"Banco de dados indisponível: {e}")

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

def exigir_admin(payload: dict = Depends(verificar_token)) -> dict:
    """Dependência extra pras rotas /admin/*: confere se o usuário do token tem admin=TRUE."""
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT admin FROM usuarios WHERE id = %s", (int(payload["sub"]),))
        row = cur.fetchone()
        if not row or not row[0]:
            raise HTTPException(status_code=403, detail="Acesso restrito a administradores")
        return payload
    finally:
        cur.close()
        conn.close()

class LoginRequest(BaseModel):
    email: str
    senha: str

# ── PIX (BR CODE ESTÁTICO) ────────────────────────────────────────────────────
def _tlv(id_: str, valor: str) -> str:
    """Codifica um campo no formato TLV (ID + tamanho de 2 dígitos + valor) do EMV/BR Code."""
    return f"{id_}{len(valor):02d}{valor}"

def _crc16_ccitt(payload: str) -> str:
    """CRC16-CCITT (poly 0x1021, init 0xFFFF) exigido no final do BR Code Pix."""
    crc = 0xFFFF
    for byte in payload.encode("utf-8"):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return format(crc, "04X")

def _ascii_upper(texto: str) -> str:
    """Remove acentos e caracteres fora da tabela ASCII aceita pelo padrão Pix."""
    return unicodedata.normalize("NFKD", texto).encode("ASCII", "ignore").decode("ASCII").upper().strip()


def cpf_valido(cpf: str) -> bool:
    """Confere os dois dígitos verificadores do CPF (algoritmo mod-11 da Receita Federal)."""
    cpf = "".join(filter(str.isdigit, cpf))
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False

    def digito_verificador(parcial: str) -> str:
        soma = sum(int(d) * peso for d, peso in zip(parcial, range(len(parcial) + 1, 1, -1)))
        resto = (soma * 10) % 11
        return str(resto if resto < 10 else 0)

    d1 = digito_verificador(cpf[:9])
    d2 = digito_verificador(cpf[:9] + d1)
    return cpf[-2:] == d1 + d2


# ── EMAIL DE CONFIRMAÇÃO ───────────────────────────────────────────────────────
def gerar_codigo_verificacao() -> str:
    """Gera um código numérico de 6 dígitos para confirmar email."""
    return f"{random.randint(0, 999999):06d}"

def enviar_email(destinatario: str, assunto: str, corpo: str) -> None:
    """Envia um email transacional via API HTTP da Brevo. Se não estiver
    configurado no servidor (variáveis de ambiente ausentes), levanta 503 em
    vez de falhar silenciosamente — assim fica claro que falta configurar."""
    if not BREVO_API_KEY or not BREVO_FROM_EMAIL:
        raise HTTPException(status_code=503, detail="Serviço de email não configurado no servidor")

    payload = json.dumps({
        "sender": {"email": BREVO_FROM_EMAIL, "name": "BusPasse"},
        "to": [{"email": destinatario}],
        "subject": assunto,
        "textContent": corpo,
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=payload,
        method="POST",
        headers={
            "accept": "application/json",
            "api-key": BREVO_API_KEY,
            "content-type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        detalhe = e.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=502, detail=f"Falha ao enviar email: {detalhe}")
    except urllib.error.URLError as e:
        raise HTTPException(status_code=502, detail=f"Falha ao enviar email: {e.reason}")


def gerar_payload_pix(chave: str, nome: str, cidade: str, valor: float, txid: str) -> str:
    """Monta o Pix Copia e Cola (BR Code) estático para uma chave Pix + valor fixo."""
    nome   = _ascii_upper(nome)[:25] or "BUSPASSE"
    cidade = _ascii_upper(cidade)[:15] or "BRASIL"
    txid   = re.sub(r"[^A-Za-z0-9]", "", txid)[:25] or "***"

    conta_pix = _tlv("00", "br.gov.bcb.pix") + _tlv("01", chave)
    payload = (
        _tlv("00", "01")             # Payload Format Indicator
        + _tlv("26", conta_pix)      # Merchant Account Information (Pix)
        + _tlv("52", "0000")         # Merchant Category Code
        + _tlv("53", "986")          # Moeda: Real (BRL)
        + _tlv("54", f"{valor:.2f}") # Valor da transação
        + _tlv("58", "BR")           # País
        + _tlv("59", nome)           # Nome do beneficiário
        + _tlv("60", cidade)         # Cidade do beneficiário
        + _tlv("62", _tlv("05", txid))  # Additional Data Field (txid de referência)
    )
    payload += "6304"  # ID + tamanho do campo CRC16 que vem a seguir
    return payload + _crc16_ccitt(payload)


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

class RecargaRequest(BaseModel):
    valor: float

class SenhaRequest(BaseModel):
    senha_atual: str
    senha_nova:  str

class AtualizarPerfilRequest(BaseModel):
    nome:        str | None = None
    email:       str | None = None
    celular:     str | None = None
    cep:         str | None = None
    cidade:      str | None = None
    bairro:      str | None = None
    rua:         str | None = None
    numero:      str | None = None
    complemento: str | None = None

class TipoUsuarioRequest(BaseModel):
    tipo_usuario: str

class VerificarEmailRequest(BaseModel):
    email:  str
    codigo: str

class ReenviarCodigoRequest(BaseModel):
    email: str

class VerificarCartaoRequest(BaseModel):
    uid_cartao: str

class ValidarNfcRequest(BaseModel):
    token_nfc: str

@app.get("/")
def root():
    return {"status": "ok", "api": "BusPasse API", "versao": "1.0.0"}


# ── LEITOR DO ÔNIBUS (ESP32 + RC522) ──────────────────────────────────────────
@app.post("/cartao/verificar")
def verificar_cartao(data: VerificarCartaoRequest):
    """Verifica se o cartão está cadastrado e se está bloqueado. Chamado pelo leitor (ESP32)."""

    uid = re.sub(r"[\s:-]", "", data.uid_cartao).upper()

    if uid.startswith("0X"):
        uid = uid[2:]

    if not uid or not re.fullmatch(r"[0-9A-F]+", uid):
        raise HTTPException(
            status_code=422,
            detail="UID do cartão inválido"
        )

    conn = get_conn()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT id, cartao_bloqueado
            FROM usuarios
            WHERE REPLACE(
                REPLACE(
                    REPLACE(
                        REPLACE(UPPER(uid_cartao), ' ', ''),
                        ':', ''
                    ),
                    '-', ''
                ),
                '0X', ''
            ) = %s
            LIMIT 1
            """,
            (uid,),
        )

        usuario = cur.fetchone()

        # Cartão não cadastrado
        if usuario is None:
            return {
                "cadastrado": False,
                "cartao_bloqueado": None,
                "autorizado": False,
                "mensagem": "Cartao nao cadastrado"
            }

        # Dados encontrados no banco
        usuario_id, bloqueado = usuario
        bloqueado = bool(bloqueado)

        # Cartão cadastrado, mas bloqueado
        if bloqueado:
            return {
                "cadastrado": True,
                "cartao_bloqueado": True,
                "autorizado": False,
                "mensagem": "Cartao bloqueado"
            }

        # Cartão cadastrado e liberado
        return {
            "cadastrado": True,
            "cartao_bloqueado": False,
            "autorizado": True,
            "mensagem": "Cartao liberado"
        }

    finally:
        cur.close()
        conn.close()



@app.post("/login")
def login(data: LoginRequest):
    """Autentica usuário por email + senha e retorna JWT."""
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            "SELECT id, nome, senha_hash, email_verificado FROM usuarios WHERE email = %s",
            (data.email.lower().strip(),),
        )
        row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=401, detail="Email ou senha incorretos")

        user_id, nome, senha_hash, verificado = row

        if not bcrypt.checkpw(data.senha.encode(), senha_hash.encode()):
            raise HTTPException(status_code=401, detail="Email ou senha incorretos")

        if not verificado:
            raise HTTPException(status_code=403, detail="Confirme seu email antes de entrar. Verifique sua caixa de entrada.")

        token = criar_token(user_id, nome)
        return {"token": token, "nome": nome, "id": user_id}
    finally:
        cur.close()
        conn.close()


EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CEP_REGEX   = re.compile(r"^\d{5}-?\d{3}$")

@app.post("/cadastro", status_code=201)
def cadastro(data: CadastroRequest):
    """Cria novo usuário e retorna JWT (já loga ao cadastrar)."""
    cpf_limpo = "".join(filter(str.isdigit, data.cpf))
    if not cpf_valido(cpf_limpo):
        raise HTTPException(status_code=422, detail="CPF inválido")

    email_limpo = data.email.lower().strip()
    if not EMAIL_REGEX.match(email_limpo):
        raise HTTPException(status_code=422, detail="Email inválido")

    if data.cep and not CEP_REGEX.match(data.cep.strip()):
        raise HTTPException(status_code=422, detail="CEP inválido. Use o formato 00000-000")

    if len(data.senha) < 6:
        raise HTTPException(status_code=422, detail="Senha deve ter pelo menos 6 caracteres")

    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT 1 FROM usuarios WHERE email = %s", (email_limpo,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Este email já está cadastrado")

        cur.execute("SELECT 1 FROM usuarios WHERE cpf = %s", (cpf_limpo,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Este CPF já está cadastrado")

        senha_hash = bcrypt.hashpw(data.senha.encode(), bcrypt.gensalt()).decode()
        codigo           = gerar_codigo_verificacao()
        codigo_expira_em = datetime.utcnow() + timedelta(minutes=CODIGO_VALIDADE_MINUTOS)

        cur.execute(
            """
            INSERT INTO usuarios
                (cpf, nome, email, senha_hash, celular, cep, cidade, bairro, rua, numero, complemento,
                 email_verificado, codigo_verificacao, codigo_expira_em)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, %s, %s)
            """,
            (
                cpf_limpo,
                data.nome.strip(),
                email_limpo,
                senha_hash,
                data.celular,
                data.cep,
                data.cidade,
                data.bairro,
                data.rua,
                data.numero,
                data.complemento,
                codigo,
                codigo_expira_em,
            ),
        )
        user_id = cur.lastrowid
        conn.commit()

        # A conta já existe nesse ponto — se o envio do email falhar (ex.:
        # SMTP fora do ar), o usuário pode pedir um novo código depois via
        # POST /reenviar-codigo, sem precisar recadastrar.
        enviar_email(
            email_limpo,
            "Confirme seu cadastro — BusPasse",
            f"Seu código de confirmação é {codigo}. Ele expira em {CODIGO_VALIDADE_MINUTOS} minutos.",
        )

        return {"precisa_verificar": True, "email": email_limpo}

    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Erro interno: {e}")
    finally:
        cur.close()
        conn.close()


@app.post("/verificar-email")
def verificar_email(data: VerificarEmailRequest):
    """Confirma o código de 6 dígitos enviado por email e já retorna o JWT (login automático)."""
    email = data.email.lower().strip()
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            "SELECT id, nome, codigo_verificacao, codigo_expira_em, email_verificado FROM usuarios WHERE email = %s",
            (email,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        user_id, nome, codigo_salvo, expira_em, verificado = row
        if verificado:
            raise HTTPException(status_code=409, detail="Este email já foi confirmado")

        codigo_expirado = not expira_em or datetime.utcnow() > expira_em
        if not codigo_salvo or codigo_expirado or data.codigo.strip() != codigo_salvo:
            raise HTTPException(status_code=422, detail="Código inválido ou expirado")

        cur.execute(
            "UPDATE usuarios SET email_verificado = TRUE, codigo_verificacao = NULL, codigo_expira_em = NULL WHERE id = %s",
            (user_id,),
        )
        conn.commit()

        token = criar_token(user_id, nome)
        return {"token": token, "nome": nome, "id": user_id}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


@app.post("/reenviar-codigo")
def reenviar_codigo(data: ReenviarCodigoRequest):
    """Gera um novo código de confirmação e reenvia por email (cadastro ainda não confirmado)."""
    email = data.email.lower().strip()
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT id, email_verificado FROM usuarios WHERE email = %s", (email,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        user_id, verificado = row
        if verificado:
            raise HTTPException(status_code=409, detail="Este email já foi confirmado")

        codigo           = gerar_codigo_verificacao()
        codigo_expira_em = datetime.utcnow() + timedelta(minutes=CODIGO_VALIDADE_MINUTOS)
        cur.execute(
            "UPDATE usuarios SET codigo_verificacao = %s, codigo_expira_em = %s WHERE id = %s",
            (codigo, codigo_expira_em, user_id),
        )
        conn.commit()

        enviar_email(
            email,
            "Novo código de confirmação — BusPasse",
            f"Seu novo código de confirmação é {codigo}. Ele expira em {CODIGO_VALIDADE_MINUTOS} minutos.",
        )
        return {"status": "ok"}
    except HTTPException:
        conn.rollback()
        raise
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
            SELECT id, cpf, nome, email, tipo_usuario, saldo, cartao_bloqueado,
                   celular, cep, cidade, bairro, rua, numero, complemento,
                   admin, verificacao_estudante_status
            FROM usuarios WHERE id = %s
            """,
            (int(payload["sub"]),),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        (user_id, cpf, nome, email, tipo, saldo, bloqueado,
         celular, cep, cidade, bairro, rua, numero, complemento,
         admin, verificacao_estudante_status) = row
        saldo   = float(saldo)
        tarifa  = tarifa_do_usuario(tipo)
        # passes_disponiveis é sempre calculado a partir do saldo (quantas
        # passagens o saldo atual cobre); para idoso/PCD, que não pagam, não
        # há um número de passes limitado pelo saldo.
        passes = None if tarifa == 0 else round(saldo / tarifa, 1)
        return {
            "id":                 user_id,
            "cpf":                cpf,
            "nome":               nome,
            "email":              email,
            "tipo_usuario":       tipo,
            "saldo":              saldo,
            "tarifa_atual":       tarifa,
            "passes_disponiveis": passes,
            "cartao_bloqueado":   bool(bloqueado),
            "celular":            celular,
            "cep":                cep,
            "cidade":             cidade,
            "bairro":             bairro,
            "rua":                rua,
            "numero":             numero,
            "complemento":        complemento,
            "admin":              bool(admin),
            "verificacao_estudante_status": verificacao_estudante_status,
        }
    finally:
        cur.close()
        conn.close()


@app.put("/me")
def atualizar_perfil(data: AtualizarPerfilRequest, payload: dict = Depends(verificar_token)):
    """Atualiza campos editáveis do perfil (CPF não pode ser alterado)."""
    user_id = int(payload["sub"])
    campos_permitidos = {"nome", "email", "celular", "cep", "cidade", "bairro", "rua", "numero", "complemento"}
    campos = {k: v for k, v in data.model_dump(exclude_unset=True).items() if k in campos_permitidos}

    if not campos:
        raise HTTPException(status_code=422, detail="Nenhum campo para atualizar")

    conn = get_conn()
    cur  = conn.cursor()
    try:
        if campos.get("nome") is not None:
            campos["nome"] = campos["nome"].strip()
            if not campos["nome"]:
                raise HTTPException(status_code=422, detail="Nome não pode ser vazio")

        if campos.get("email") is not None:
            email_novo = campos["email"].lower().strip()
            if not EMAIL_REGEX.match(email_novo):
                raise HTTPException(status_code=422, detail="Email inválido")
            cur.execute("SELECT 1 FROM usuarios WHERE email = %s AND id != %s", (email_novo, user_id))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Este email já está em uso")
            campos["email"] = email_novo

        if campos.get("cep") and not CEP_REGEX.match(campos["cep"].strip()):
            raise HTTPException(status_code=422, detail="CEP inválido. Use o formato 00000-000")

        set_clause = ", ".join(f"{campo} = %s" for campo in campos)
        cur.execute(f"UPDATE usuarios SET {set_clause} WHERE id = %s", [*campos.values(), user_id])
        conn.commit()

        cur.execute(
            """
            SELECT id, cpf, nome, email, celular, cep, cidade, bairro, rua, numero, complemento
            FROM usuarios WHERE id = %s
            """,
            (user_id,),
        )
        (uid, cpf, nome, email, celular, cep, cidade, bairro, rua, numero, complemento) = cur.fetchone()
        return {
            "id": uid, "cpf": cpf, "nome": nome, "email": email, "celular": celular,
            "cep": cep, "cidade": cidade, "bairro": bairro, "rua": rua,
            "numero": numero, "complemento": complemento,
        }
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Erro interno: {e}")
    finally:
        cur.close()
        conn.close()


@app.put("/senha")
def alterar_senha(data: SenhaRequest, payload: dict = Depends(verificar_token)):
    """Altera a senha do usuário autenticado, exigindo a senha atual."""
    if len(data.senha_nova) < 6:
        raise HTTPException(status_code=422, detail="A nova senha deve ter pelo menos 6 caracteres")

    user_id = int(payload["sub"])
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT senha_hash FROM usuarios WHERE id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        if not bcrypt.checkpw(data.senha_atual.encode(), row[0].encode()):
            raise HTTPException(status_code=401, detail="Senha atual incorreta")

        novo_hash = bcrypt.hashpw(data.senha_nova.encode(), bcrypt.gensalt()).decode()
        cur.execute("UPDATE usuarios SET senha_hash = %s WHERE id = %s", (novo_hash, user_id))
        conn.commit()
        return {"status": "ok"}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


@app.put("/tipo-usuario")
def atualizar_tipo_usuario(data: TipoUsuarioRequest, payload: dict = Depends(verificar_token)):
    """Atualiza o tipo de usuário (comum/estudante/pcd/idoso), usado para calcular a tarifa."""
    tipo = data.tipo_usuario.strip().lower()
    tipos_validos = {"comum", "estudante", "pcd", "idoso"}
    if tipo not in tipos_validos:
        raise HTTPException(status_code=422, detail="Tipo de usuário inválido")

    user_id = int(payload["sub"])
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("UPDATE usuarios SET tipo_usuario = %s WHERE id = %s", (tipo, user_id))
        conn.commit()
        return {"tipo_usuario": tipo}
    finally:
        cur.close()
        conn.close()


# ── VERIFICAÇÃO DE ESTUDANTE ───────────────────────────────────────────────────
# Duas formas de aprovar a mesma solicitação: a escola clica num link recebido
# por email (fluxo "oficial"), ou um administrador aprova pelo painel interno
# do app (mais confiável de demonstrar, já que não depende de alguém de fora
# responder o email na hora). As duas caem na mesma função de resolução.
class SolicitarEstudanteRequest(BaseModel):
    escola_nome: str
    escola_email: str

class ResolverSolicitacaoRequest(BaseModel):
    aprovar: bool

def _resolver_verificacao_estudante(cur, conn, user_id: int, aprovado: bool) -> str:
    if aprovado:
        cur.execute(
            """UPDATE usuarios
               SET tipo_usuario = 'estudante', verificacao_estudante_status = 'aprovado',
                   verificacao_estudante_token = NULL
               WHERE id = %s""",
            (user_id,),
        )
    else:
        cur.execute(
            """UPDATE usuarios
               SET verificacao_estudante_status = 'rejeitado', verificacao_estudante_token = NULL
               WHERE id = %s""",
            (user_id,),
        )
    conn.commit()

    cur.execute("SELECT nome, email FROM usuarios WHERE id = %s", (user_id,))
    nome, email = cur.fetchone()
    try:
        if aprovado:
            enviar_email(
                email,
                "Matrícula confirmada — BusPasse",
                f"Boa notícia, {nome}! Sua escola confirmou sua matrícula e sua tarifa de estudante já está ativa.",
            )
        else:
            enviar_email(
                email,
                "Solicitação de estudante recusada — BusPasse",
                f"Olá, {nome}. Sua escola não confirmou sua matrícula, então sua conta continua com a tarifa comum. Você pode tentar de novo com os dados corretos.",
            )
    except HTTPException:
        pass  # não deixa a aprovação falhar só porque o aviso ao aluno não foi enviado
    return nome


@app.post("/tipo-usuario/solicitar-estudante")
def solicitar_estudante(data: SolicitarEstudanteRequest, payload: dict = Depends(verificar_token)):
    """Inicia a verificação de matrícula: manda um email pra escola com links de aprovar/recusar."""
    escola_email = data.escola_email.strip().lower()
    if not EMAIL_REGEX.match(escola_email):
        raise HTTPException(status_code=422, detail="Email da escola inválido")
    escola_nome = data.escola_nome.strip()
    if not escola_nome:
        raise HTTPException(status_code=422, detail="Informe o nome da escola")

    user_id = int(payload["sub"])
    token = secrets.token_urlsafe(32)
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            """UPDATE usuarios
               SET escola_nome = %s, escola_email = %s,
                   verificacao_estudante_status = 'pendente',
                   verificacao_estudante_token = %s
               WHERE id = %s""",
            (escola_nome, escola_email, token, user_id),
        )
        conn.commit()

        cur.execute("SELECT nome FROM usuarios WHERE id = %s", (user_id,))
        nome_aluno = cur.fetchone()[0]

        link_aprovar  = f"{API_BASE_URL}/tipo-usuario/confirmar/{token}?decisao=aprovar"
        link_rejeitar = f"{API_BASE_URL}/tipo-usuario/confirmar/{token}?decisao=rejeitar"
        enviar_email(
            escola_email,
            "Confirmação de matrícula — BusPasse",
            (
                f"O aluno {nome_aluno} solicitou o benefício de tarifa de estudante no aplicativo BusPasse, "
                f"informando \"{escola_nome}\" como instituição de ensino.\n\n"
                f"Para CONFIRMAR a matrícula, acesse: {link_aprovar}\n\n"
                f"Para RECUSAR, acesse: {link_rejeitar}"
            ),
        )
        return {"status": "pendente"}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


@app.get("/tipo-usuario/confirmar/{token}")
def confirmar_estudante(token: str, decisao: str):
    """
    Rota pública (sem login) — é aberta direto no navegador quando a escola
    clica no link recebido por email, por isso devolve uma página HTML
    simples em vez de JSON.
    """
    if decisao not in ("aprovar", "rejeitar"):
        return HTMLResponse("<h1>Link inválido.</h1>", status_code=400)

    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            "SELECT id, verificacao_estudante_status FROM usuarios WHERE verificacao_estudante_token = %s",
            (token,),
        )
        row = cur.fetchone()
        if not row:
            return HTMLResponse("<h1>Link inválido ou já utilizado.</h1>", status_code=404)

        user_id, status_atual = row
        if status_atual != "pendente":
            return HTMLResponse("<h1>Essa solicitação já foi respondida anteriormente.</h1>")

        nome = _resolver_verificacao_estudante(cur, conn, user_id, aprovado=(decisao == "aprovar"))
        mensagem = "Matrícula confirmada" if decisao == "aprovar" else "Solicitação recusada"
        return HTMLResponse(f"<h1>{mensagem} para {nome}. Obrigado!</h1>")
    finally:
        cur.close()
        conn.close()


# ── PAINEL ADMINISTRATIVO ──────────────────────────────────────────────────────
@app.get("/admin/solicitacoes-estudante")
def listar_solicitacoes_estudante(payload: dict = Depends(exigir_admin)):
    """Lista pedidos de verificação de estudante pendentes (uso do painel administrativo)."""
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            """SELECT id, nome, email, escola_nome, escola_email
               FROM usuarios
               WHERE verificacao_estudante_status = 'pendente'
               ORDER BY id"""
        )
        rows = cur.fetchall()
        return [
            {"id": r[0], "nome": r[1], "email": r[2], "escola_nome": r[3], "escola_email": r[4]}
            for r in rows
        ]
    finally:
        cur.close()
        conn.close()


@app.post("/admin/solicitacoes-estudante/{user_id}")
def resolver_solicitacao_estudante(user_id: int, data: ResolverSolicitacaoRequest, payload: dict = Depends(exigir_admin)):
    """Aprova ou recusa uma solicitação pendente pelo painel administrativo."""
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT verificacao_estudante_status FROM usuarios WHERE id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        if row[0] != "pendente":
            raise HTTPException(status_code=409, detail="Essa solicitação já foi respondida")

        _resolver_verificacao_estudante(cur, conn, user_id, aprovado=data.aprovar)
        return {"status": "ok"}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


# ── RECARGA (PIX) ─────────────────────────────────────────────────────────────
@app.post("/recarga", status_code=201)
def criar_recarga(data: RecargaRequest, payload: dict = Depends(verificar_token)):
    """Cria uma recarga pendente e gera o Pix Copia e Cola correspondente."""
    if data.valor <= 0:
        raise HTTPException(status_code=422, detail="O valor deve ser maior que zero")
    if data.valor > 500:
        raise HTTPException(status_code=422, detail="Valor máximo de recarga é R$ 500,00")
    if not PIX_KEY:
        raise HTTPException(status_code=503, detail="Chave Pix não configurada no servidor")

    user_id = int(payload["sub"])
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT cartao_bloqueado FROM usuarios WHERE id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        if row[0]:
            raise HTTPException(status_code=423, detail="Cartão bloqueado. Desbloqueie para fazer recarga.")

        cur.execute(
            """
            INSERT INTO transacoes (usuario_id, tipo, valor, descricao, status)
            VALUES (%s, 'credito', %s, 'Recarga via Pix', 'pendente')
            """,
            (user_id, data.valor),
        )
        transacao_id = cur.lastrowid

        txid = f"BUSPASSE{transacao_id:017d}"[:25]
        cur.execute("UPDATE transacoes SET pix_txid = %s WHERE id = %s", (txid, transacao_id))
        conn.commit()

        pix_copia_cola = gerar_payload_pix(PIX_KEY, PIX_MERCHANT_NAME, PIX_MERCHANT_CITY, data.valor, txid)

        return {
            "id":              transacao_id,
            "valor":           data.valor,
            "status":          "pendente",
            "pix_copia_cola":  pix_copia_cola,
            "chave_pix":       PIX_KEY,
            "beneficiario":    PIX_MERCHANT_NAME,
        }
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Erro interno: {e}")
    finally:
        cur.close()
        conn.close()


@app.get("/recarga/{recarga_id}")
def status_recarga(recarga_id: int, payload: dict = Depends(verificar_token)):
    """Consulta o status de uma recarga (usado pelo app para checar se já foi paga)."""
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            "SELECT status, valor FROM transacoes WHERE id = %s AND usuario_id = %s",
            (recarga_id, int(payload["sub"])),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Recarga não encontrada")
        status, valor = row
        return {"id": recarga_id, "status": status, "valor": float(valor)}
    finally:
        cur.close()
        conn.close()


@app.post("/recarga/{recarga_id}/confirmar")
def confirmar_recarga(recarga_id: int, payload: dict = Depends(verificar_token)):
    """
    Confirma que o Pix foi pago e credita saldo/passes do usuário.

    Este projeto usa uma chave Pix estática (sem contrato com um PSP/gateway
    de pagamento), então o backend não recebe um webhook automático de
    confirmação do banco. Por isso essa confirmação é acionada pelo próprio
    app (botão "Já paguei") após o usuário efetuar o Pix — é uma simulação
    adequada para fins de demonstração do TCC, mas não substitui uma
    confirmação bancária real de produção.
    """
    user_id = int(payload["sub"])
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT cartao_bloqueado FROM usuarios WHERE id = %s FOR UPDATE", (user_id,))
        user_row = cur.fetchone()
        if not user_row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        if user_row[0]:
            raise HTTPException(status_code=423, detail="Cartão bloqueado. Desbloqueie para fazer recarga.")

        cur.execute(
            "SELECT status, valor FROM transacoes WHERE id = %s AND usuario_id = %s FOR UPDATE",
            (recarga_id, user_id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Recarga não encontrada")
        status, valor = row
        if status == "pago":
            raise HTTPException(status_code=409, detail="Esta recarga já foi confirmada")

        valor = float(valor)

        cur.execute(
            "UPDATE transacoes SET status = 'pago', pago_em = NOW() WHERE id = %s",
            (recarga_id,),
        )
        cur.execute(
            "UPDATE usuarios SET saldo = saldo + %s WHERE id = %s",
            (valor, user_id),
        )
        conn.commit()

        cur.execute("SELECT saldo, tipo_usuario FROM usuarios WHERE id = %s", (user_id,))
        saldo, tipo = cur.fetchone()
        saldo  = float(saldo)
        tarifa = tarifa_do_usuario(tipo)
        passes = None if tarifa == 0 else round(saldo / tarifa, 1)
        return {"status": "pago", "saldo": saldo, "passes_disponiveis": passes}
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Erro interno: {e}")
    finally:
        cur.close()
        conn.close()


@app.get("/extrato")
def extrato(payload: dict = Depends(verificar_token)):
    """Lista as transações pagas do usuário (recargas e passagens), mais recentes primeiro."""
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            """
            SELECT id, tipo, valor, descricao, criado_em, pago_em
            FROM transacoes
            WHERE usuario_id = %s AND status = 'pago'
            ORDER BY COALESCE(pago_em, criado_em) DESC
            LIMIT 100
            """,
            (int(payload["sub"]),),
        )
        rows = cur.fetchall()
        return [
            {
                "id":        r[0],
                "tipo":      r[1],
                "valor":     float(r[2]),
                "descricao": r[3],
                "data":      (r[5] or r[4]).isoformat(),
            }
            for r in rows
        ]
    finally:
        cur.close()
        conn.close()


# ── PASSAGEM ──────────────────────────────────────────────────────────────────
@app.post("/passagem/usar", status_code=201)
def usar_passagem(payload: dict = Depends(verificar_token)):
    """
    Simula a validação de uma passagem (ex.: leitura do cartão na catraca do
    ônibus). A tarifa debitada depende do tipo de usuário: comum paga cheio,
    estudante paga metade, idoso/PCD não pagam. Cartão bloqueado impede o uso.
    """
    user_id = int(payload["sub"])
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            "SELECT saldo, tipo_usuario, cartao_bloqueado FROM usuarios WHERE id = %s FOR UPDATE",
            (user_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        saldo, tipo, bloqueado = row
        saldo = float(saldo)

        if bloqueado:
            raise HTTPException(status_code=423, detail="Cartão bloqueado. Desbloqueie para usar o passe.")

        tarifa = tarifa_do_usuario(tipo)
        if tarifa > 0 and saldo < tarifa:
            raise HTTPException(status_code=422, detail="Saldo insuficiente. Faça uma recarga.")

        if tarifa > 0:
            cur.execute("UPDATE usuarios SET saldo = saldo - %s WHERE id = %s", (tarifa, user_id))

        descricao = "Passagem utilizada" if tarifa > 0 else "Passagem utilizada (gratuita)"
        cur.execute(
            """
            INSERT INTO transacoes (usuario_id, tipo, valor, descricao, status, pago_em)
            VALUES (%s, 'debito', %s, %s, 'pago', NOW())
            """,
            (user_id, tarifa, descricao),
        )
        conn.commit()

        cur.execute("SELECT saldo FROM usuarios WHERE id = %s", (user_id,))
        saldo_novo = float(cur.fetchone()[0])
        passes = None if tarifa == 0 else round(saldo_novo / tarifa, 1)
        return {"saldo": saldo_novo, "passes_disponiveis": passes}
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Erro interno: {e}")
    finally:
        cur.close()
        conn.close()


# ── CARTÃO ────────────────────────────────────────────────────────────────────
@app.post("/cartao/bloquear")
def bloquear_cartao(payload: dict = Depends(verificar_token)):
    """Bloqueia o cartão do usuário autenticado."""
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("UPDATE usuarios SET cartao_bloqueado = TRUE WHERE id = %s", (int(payload["sub"]),))
        conn.commit()
        return {"cartao_bloqueado": True}
    finally:
        cur.close()
        conn.close()


@app.post("/cartao/desbloquear")
def desbloquear_cartao(payload: dict = Depends(verificar_token)):
    """Desbloqueia o cartão do usuário autenticado."""
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("UPDATE usuarios SET cartao_bloqueado = FALSE WHERE id = %s", (int(payload["sub"]),))
        conn.commit()
        return {"cartao_bloqueado": False}
    finally:
        cur.close()
        conn.close()


# ── NFC: CELULAR COMO CARTÃO ──────────────────────────────────────────────────
# Fluxo: o app chama POST /nfc/token → o celular entrega o token ao leitor por
# NFC → o leitor chama POST /nfc/validar → o app descobre o resultado em
# GET /nfc/status. O token vale NFC_TOKEN_VALIDADE_SEGUNDOS e só pode ser usado
# uma vez.
@app.post("/nfc/token")
def gerar_token_nfc(payload: dict = Depends(verificar_token)):
    """
    Gera o token que o celular vai entregar ao leitor. Só emite se o cartão não
    estiver bloqueado e houver saldo para a tarifa do usuário. O leitor confere
    tudo de novo na hora (POST /nfc/validar); essa checagem aqui só evita o
    usuário aproximar o celular à toa. Cada novo token invalida o anterior.
    """
    user_id = int(payload["sub"])
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            "SELECT saldo, tipo_usuario, cartao_bloqueado FROM usuarios WHERE id = %s",
            (user_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        saldo, tipo, bloqueado = row

        if bloqueado:
            raise HTTPException(status_code=423, detail="Cartão bloqueado. Desbloqueie para usar o passe.")

        tarifa = tarifa_do_usuario(tipo)
        if tarifa > 0 and float(saldo) < tarifa:
            raise HTTPException(status_code=422, detail="Saldo insuficiente. Faça uma recarga.")

        token     = secrets.token_hex(8)  # 16 caracteres hexadecimais
        expira_em = datetime.utcnow() + timedelta(seconds=NFC_TOKEN_VALIDADE_SEGUNDOS)
        cur.execute(
            """UPDATE usuarios
               SET nfc_token = %s, nfc_token_expira_em = %s, nfc_resultado = NULL
               WHERE id = %s""",
            (token, expira_em, user_id),
        )
        conn.commit()
        return {"token": token, "validade_segundos": NFC_TOKEN_VALIDADE_SEGUNDOS}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


@app.get("/nfc/status")
def status_token_nfc(payload: dict = Depends(verificar_token)):
    """
    Situação do token NFC do usuário. O app consulta a cada poucos segundos
    para saber se o leitor já respondeu. "resultado" fica nulo enquanto o
    leitor não tentou validar; depois vira "ok" ou o motivo da recusa
    (cartao_bloqueado, saldo_insuficiente, token_expirado).
    """
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            "SELECT nfc_token, nfc_token_expira_em, nfc_resultado FROM usuarios WHERE id = %s",
            (int(payload["sub"]),),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        token, expira_em, resultado = row
        ativo = bool(token) and expira_em is not None and datetime.utcnow() <= expira_em
        return {"ativo": ativo, "resultado": resultado}
    finally:
        cur.close()
        conn.close()


@app.post("/nfc/cancelar")
def cancelar_token_nfc(payload: dict = Depends(verificar_token)):
    """Invalida o token NFC atual (o app chama ao cancelar ou sair da tela)."""
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            "UPDATE usuarios SET nfc_token = NULL, nfc_token_expira_em = NULL WHERE id = %s",
            (int(payload["sub"]),),
        )
        conn.commit()
        return {"status": "ok"}
    finally:
        cur.close()
        conn.close()


@app.post("/nfc/validar")
def validar_nfc(data: ValidarNfcRequest):
    """
    Chamado pelo leitor do ônibus (ESP32) com o token lido do celular. Aplica
    as mesmas regras do /passagem/usar (cartão bloqueado, saldo, tarifa por
    tipo de usuário) e, se tudo estiver certo, debita a passagem. O token é de
    uso único: qualquer tentativa (aprovada ou recusada) o consome.

    Responde sempre 200 com {"cadastrado": bool, "motivo": ...}. O campo
    "cadastrado" é o mesmo que o leitor já entende em /cartao/verificar, então
    o leitor só precisa decidir entre acender o LED verde ou o vermelho.
    """
    token = data.token_nfc.strip().lower()
    if not NFC_TOKEN_REGEX.match(token):
        return {"cadastrado": False, "motivo": "token_invalido"}

    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute(
            """SELECT id, saldo, tipo_usuario, cartao_bloqueado, nfc_token_expira_em
               FROM usuarios WHERE nfc_token = %s FOR UPDATE""",
            (token,),
        )
        row = cur.fetchone()
        if not row:
            return {"cadastrado": False, "motivo": "token_invalido"}

        user_id, saldo, tipo, bloqueado, expira_em = row
        saldo  = float(saldo)
        tarifa = tarifa_do_usuario(tipo)

        if not expira_em or datetime.utcnow() > expira_em:
            motivo = "token_expirado"
        elif bloqueado:
            motivo = "cartao_bloqueado"
        elif tarifa > 0 and saldo < tarifa:
            motivo = "saldo_insuficiente"
        else:
            motivo = "ok"

        if motivo == "ok":
            if tarifa > 0:
                cur.execute("UPDATE usuarios SET saldo = saldo - %s WHERE id = %s", (tarifa, user_id))
                saldo = round(saldo - tarifa, 2)
            descricao = "Passagem utilizada (celular NFC)" if tarifa > 0 else "Passagem utilizada (celular NFC, gratuita)"
            cur.execute(
                """
                INSERT INTO transacoes (usuario_id, tipo, valor, descricao, status, pago_em)
                VALUES (%s, 'debito', %s, %s, 'pago', NOW())
                """,
                (user_id, tarifa, descricao),
            )

        cur.execute(
            """UPDATE usuarios
               SET nfc_token = NULL, nfc_token_expira_em = NULL, nfc_resultado = %s
               WHERE id = %s""",
            (motivo, user_id),
        )
        conn.commit()
        return {"cadastrado": motivo == "ok", "motivo": motivo, "saldo": saldo, "tarifa": tarifa}
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Erro interno: {e}")
    finally:
        cur.close()
        conn.close()
