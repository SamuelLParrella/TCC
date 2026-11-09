SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";

CREATE TABLE `transacoes` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) NOT NULL,
  `tipo` varchar(10) NOT NULL,
  `valor` decimal(10,2) NOT NULL,
  `descricao` varchar(255) NOT NULL,
  `status` varchar(10) NOT NULL DEFAULT 'pago',
  `pix_txid` varchar(35) DEFAULT NULL,
  `criado_em` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `pago_em` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE `usuarios` (
  `id` int(11) NOT NULL,
  `cpf` varchar(11) NOT NULL,
  `nome` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `senha_hash` text NOT NULL,
  `celular` varchar(20) DEFAULT NULL,
  `cep` varchar(10) DEFAULT NULL,
  `cidade` varchar(100) DEFAULT NULL,
  `bairro` varchar(100) DEFAULT NULL,
  `rua` varchar(255) DEFAULT NULL,
  `numero` varchar(20) DEFAULT NULL,
  `complemento` varchar(255) DEFAULT NULL,
  `tipo_usuario` varchar(20) NOT NULL DEFAULT 'comum',
  `saldo` decimal(10,2) NOT NULL DEFAULT '0.00',
  `passes_disponiveis` decimal(5,1) NOT NULL DEFAULT '0.0',
  `cartao_bloqueado` tinyint(1) NOT NULL DEFAULT '0',
  `email_verificado` tinyint(1) NOT NULL DEFAULT '1',
  `codigo_verificacao` varchar(6) DEFAULT NULL,
  `codigo_expira_em` datetime DEFAULT NULL,
  `admin` tinyint(1) NOT NULL DEFAULT '0',
  `escola_nome` varchar(255) DEFAULT NULL,
  `escola_email` varchar(255) DEFAULT NULL,
  `verificacao_estudante_status` varchar(20) DEFAULT NULL,
  `verificacao_estudante_token` varchar(64) DEFAULT NULL,
  `criado_em` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `uid_cartao` varchar(50) DEFAULT NULL,
  `nfc_token` varchar(32) DEFAULT NULL,
  `nfc_token_expira_em` datetime DEFAULT NULL,
  `nfc_resultado` varchar(30) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


INSERT INTO `usuarios` (`id`, `cpf`, `nome`, `email`, `senha_hash`, `celular`, `cep`, `cidade`, `bairro`, `rua`, `numero`, `complemento`, `tipo_usuario`, `saldo`, `passes_disponiveis`, `cartao_bloqueado`, `email_verificado`, `codigo_verificacao`, `codigo_expira_em`, `admin`, `escola_nome`, `escola_email`, `verificacao_estudante_status`, `verificacao_estudante_token`, `criado_em`, `uid_cartao`, `nfc_token`, `nfc_token_expira_em`, `nfc_resultado`) VALUES
(1, '46551308813', 'Samuel', 'parrellasamuel@gmail.com', '$2b$12$n5EdgfZE6RqPmWP0QJI8S.DXmRXI1YmjKDVt7E1MBS5/4DN1UoiGW', '14991759012', '17017510', 'Bauru', 'Jd America', 'Marilia', '270', NULL, 'comum', '0.00', '0.0', 0, 1, NULL, NULL, 0, NULL, NULL, NULL, NULL, '2026-11-09 02:20:47', 'A3:45:0C:12', NULL, NULL, NULL);


ALTER TABLE `transacoes`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_transacoes_usuario` (`usuario_id`);


ALTER TABLE `usuarios`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `cpf` (`cpf`),
  ADD UNIQUE KEY `email` (`email`),
  ADD KEY `idx_usuarios_email` (`email`),
  ADD KEY `idx_usuarios_cpf` (`cpf`),
  ADD KEY `idx_usuarios_nfc_token` (`nfc_token`);


ALTER TABLE `transacoes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `usuarios`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

ALTER TABLE `transacoes`
  ADD CONSTRAINT `transacoes_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`);
COMMIT;


