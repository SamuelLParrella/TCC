
import os
import re
import unicodedata
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

# Chave Pix estática da empresa/beneficiário que recebe as recargas.
# Sem um PSP (Mercado Pago, Efí, etc.) o backend não recebe webhook de
# confirmação automática — por isso o app confirma o pagamento manualmente
# via POST /recarga/{id}/confirmar (ver docstring do endpoint).
PIX_KEY           = os.getenv("PIX_KEY", "")
PIX_MERCHANT_NAME = os.getenv("PIX_MERCHANT_NAME", "BUSPASSE LTDA")
PIX_MERCHANT_CITY = os.getenv("PIX_MERCHANT_CITY", "SAO PAULO")
PRECO_PASSAGEM    = float(os.getenv("PRECO_PASSAGEM", "5.75"))

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

        cur.execute(
            """
            INSERT INTO usuarios
                (cpf, nome, email, senha_hash, celular, cep, cidade, bairro, rua, numero, complemento)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            ),
        )
        user_id = cur.lastrowid   
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
            SELECT id, cpf, nome, email, tipo_usuario, saldo, cartao_bloqueado,
                   celular, cep, cidade, bairro, rua, numero, complemento
            FROM usuarios WHERE id = %s
            """,
            (int(payload["sub"]),),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        (user_id, cpf, nome, email, tipo, saldo, bloqueado,
         celular, cep, cidade, bairro, rua, numero, complemento) = row
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
