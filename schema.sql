-- ============================================================
-- BusPasse — schema do banco de dados (MariaDB / XAMPP)
-- ============================================================
-- No phpMyAdmin (XAMPP):
--   1. Clique em "Novo" no painel esquerdo
--   2. Nome do banco: buspass → clique em Criar
--   3. Clique no banco buspass → aba SQL
--   4. Cole este conteúdo e clique em Executar
-- ============================================================

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
    criado_em           DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    atualizado_em       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email);
CREATE INDEX IF NOT EXISTS idx_usuarios_cpf   ON usuarios(cpf);
