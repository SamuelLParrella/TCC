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
    criado_em           TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
);
 
CREATE INDEX idx_usuarios_email ON usuarios(email);
CREATE INDEX idx_usuarios_cpf   ON usuarios(cpf);

CREATE TABLE IF NOT EXISTS transacoes (
    id           INT             AUTO_INCREMENT PRIMARY KEY,
    usuario_id   INT             NOT NULL,
    tipo         VARCHAR(10)     NOT NULL,               -- 'credito' | 'debito'
    valor        DECIMAL(10, 2)  NOT NULL,
    descricao    VARCHAR(255)    NOT NULL,
    status       VARCHAR(10)     NOT NULL DEFAULT 'pago', -- 'pendente' | 'pago'
    pix_txid     VARCHAR(35),
    criado_em    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    pago_em      TIMESTAMP       NULL,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

CREATE INDEX idx_transacoes_usuario ON transacoes(usuario_id);
