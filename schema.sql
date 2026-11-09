CREATE TABLE IF NOT EXISTS usuarios (
    id                  INT             AUTO_INCREMENT PRIMARY KEY,
    cpf                 VARCHAR(11)     UNIQUE NOT NULL,
    nome                VARCHAR(255)    NOT NULL,
    email               VARCHAR(255)    UNIQUE NOT NULL,
    senha_hash          TEXT            NOT NULL,
    celular             VARCHAR(20),
    cep                 VARCHAR(10),
    cidade              VARCHAR(100),
    bairro              VARCHAR(100),
    rua                 VARCHAR(255),
    numero              VARCHAR(20),
    complemento         VARCHAR(255),
    tipo_usuario        VARCHAR(20)     NOT NULL DEFAULT 'comum',
    saldo               DECIMAL(10, 2)  NOT NULL DEFAULT 0.00,
    passes_disponiveis  DECIMAL(5, 1)   NOT NULL DEFAULT 0.0,
    cartao_bloqueado    BOOLEAN         NOT NULL DEFAULT FALSE,
    email_verificado              BOOLEAN      NOT NULL DEFAULT TRUE,
    codigo_verificacao            VARCHAR(6),
    codigo_expira_em              DATETIME,
    admin                         BOOLEAN      NOT NULL DEFAULT FALSE,
    escola_nome                   VARCHAR(255),
    escola_email                  VARCHAR(255),
    verificacao_estudante_status  VARCHAR(20),  
    verificacao_estudante_token   VARCHAR(64),
    criado_em           TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
);
 
CREATE INDEX idx_usuarios_email ON usuarios(email);
CREATE INDEX idx_usuarios_cpf   ON usuarios(cpf);

CREATE TABLE IF NOT EXISTS transacoes (
    id           INT             AUTO_INCREMENT PRIMARY KEY,
    usuario_id   INT             NOT NULL,
    tipo         VARCHAR(10)     NOT NULL,               
    valor        DECIMAL(10, 2)  NOT NULL,
    descricao    VARCHAR(255)    NOT NULL,
    status       VARCHAR(10)     NOT NULL DEFAULT 'pago', 
    pix_txid     VARCHAR(35),
    criado_em    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    pago_em      TIMESTAMP       NULL,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

CREATE INDEX idx_transacoes_usuario ON transacoes(usuario_id);

ALTER TABLE usuarios
ADD COLUMN uid_cartao VARCHAR(50) NULL;

-- Celular como cartão (NFC): o app pede um token de uso único (POST /nfc/token),
-- o celular entrega ao leitor e o leitor confirma em POST /nfc/validar.
-- nfc_resultado guarda o desfecho da última tentativa ('ok' ou o motivo da
-- recusa) para o app mostrar na tela.
ALTER TABLE usuarios
ADD COLUMN nfc_token           VARCHAR(32) NULL,
ADD COLUMN nfc_token_expira_em DATETIME    NULL,
ADD COLUMN nfc_resultado       VARCHAR(30) NULL;

CREATE INDEX idx_usuarios_nfc_token ON usuarios(nfc_token);
