#include <SPI.h>
#include <MFRC522.h>
#include <Wire.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <LiquidCrystal_I2C.h>
#include <ArduinoJson.h>

// ==========================
// WIFI E API
// ==========================

const char* ssid = "ATA";
const char* password = "12345678";

// Cartao fisico (por UID): a API confere cadastro, bloqueio e saldo
// e desconta a passagem do saldo.
const char* apiURL =
  "https://tcc-82gl.onrender.com/cartao/verificar";

// Celular com o app BusPasse (por token NFC): mesma regra do cartao,
// mas identificando o usuario pelo token que o app gerou.
const char* apiURLNfc =
  "https://tcc-82gl.onrender.com/nfc/validar";

// ==========================
// RC522
// ==========================

#define SS_PIN 5
#define RST_PIN 4

MFRC522 rfid(SS_PIN, RST_PIN);

// ==========================
// CELULAR (NFC) - AID do BusPasse
//
// Precisa ser igual ao AID do app
// (modules/buspass-hce): F0 + "BUSPASS".
//
// Comando SELECT: 00 A4 04 00 08 <AID> 00
// ==========================

const byte SELECT_BUSPASS[] = {
  0x00, 0xA4, 0x04, 0x00, 0x08,
  0xF0, 0x42, 0x55, 0x53, 0x50, 0x41, 0x53, 0x53,
  0x00
};

// Numero do bloco ISO-DEP (alterna 0/1 a cada I-block)
byte blocoAtual = 0;

// ==========================
// LCD I2C
// ==========================

LiquidCrystal_I2C lcd(0x27, 16, 2);

// ==========================
// LEDS
// ==========================

#define LED_VERMELHO 32
#define LED_BRANCO 33
#define LED_VERDE 25

// ==========================
// RESULTADOS DA CONSULTA
// ==========================

const int RES_LIBERADO       = 1;  // passagem cobrada
const int RES_NAO_CADASTRADO = 0;  // cartao nao cadastrado
const int RES_BLOQUEADO      = 2;  // cartao bloqueado
const int RES_SEM_SALDO      = 3;  // saldo menor que a passagem
const int RES_CODIGO         = 4;  // celular: codigo invalido ou vencido
const int RES_ERRO           = -1; // erro de conexao/API

// ==========================
// ESTADOS DOS LEDS
// ==========================

void ledAguardando() {
  digitalWrite(LED_VERMELHO, LOW);
  digitalWrite(LED_BRANCO, HIGH);
  digitalWrite(LED_VERDE, LOW);
}

void ledValido() {
  digitalWrite(LED_VERMELHO, LOW);
  digitalWrite(LED_BRANCO, LOW);
  digitalWrite(LED_VERDE, HIGH);
}

void ledInvalido() {
  digitalWrite(LED_VERMELHO, HIGH);
  digitalWrite(LED_BRANCO, LOW);
  digitalWrite(LED_VERDE, LOW);
}

// ==========================
// TELA INICIAL
// ==========================

void telaInicial() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("   QUICKPASS");
  lcd.setCursor(0, 1);
  lcd.print("Aproxime cartao");
}

// ==========================
// CONSULTA A API (comum ao cartao e ao celular)
//
// Envia o JSON e interpreta a resposta.
// Retorna true somente com HTTP 200 e JSON valido.
// ==========================

bool consultarAPI(const char* url, const String &corpo, JsonDocument &doc) {

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Wi-Fi desconectado.");
    return false;
  }

  WiFiClientSecure cliente;

  // Apenas para prototipo.
  // Em producao, valide o certificado HTTPS.
  cliente.setInsecure();

  HTTPClient https;

  if (!https.begin(cliente, url)) {
    Serial.println("Falha ao iniciar HTTPS.");
    return false;
  }

  https.setTimeout(15000);
  https.addHeader("Content-Type", "application/json");

  int codigoHTTP = https.POST(corpo);
  String resposta = "";

  if (codigoHTTP > 0) {
    resposta = https.getString();

    Serial.printf("HTTP: %d\n", codigoHTTP);
    Serial.println("Resposta da API:");
    Serial.println(resposta);
  } else {
    Serial.println(https.errorToString(codigoHTTP));
  }

  https.end();

  // Somente HTTP 200 e JSON valido podem autorizar
  if (codigoHTTP != 200) {
    Serial.println("Erro na resposta HTTP.");
    return false;
  }

  DeserializationError erro =
    deserializeJson(doc, resposta);

  if (erro) {
    Serial.println("JSON invalido.");
    return false;
  }

  return true;
}

// ==========================
// CARTAO: CONSULTA A API PELO UID
//
// A API confere o cadastro e o bloqueio e, se estiver tudo certo,
// desconta a passagem do saldo (tarifa conforme o tipo de usuario).
//
// Retorno: RES_LIBERADO, RES_NAO_CADASTRADO, RES_BLOQUEADO,
//          RES_SEM_SALDO ou RES_ERRO.
// saldo e tarifa vem da API (saldo ja com a passagem descontada).
// ==========================

int verificarCartaoNaAPI(String uid, float &saldo, float &tarifa) {

  saldo = 0;
  tarifa = 0;

  // Monta o JSON enviado para a API
  JsonDocument envio;
  envio["uid_cartao"] = uid;

  String corpo;
  serializeJson(envio, corpo);

  Serial.println("Consultando API QUICKPASS...");
  Serial.println("UID enviado: " + uid);

  JsonDocument doc;

  if (!consultarAPI(apiURL, corpo, doc)) {
    return RES_ERRO;
  }

  // Confere se o campo cadastrado existe e e booleano
  if (!doc["cadastrado"].is<bool>()) {
    Serial.println("Campo cadastrado ausente ou invalido.");
    return RES_ERRO;
  }

  bool cadastrado = doc["cadastrado"].as<bool>();

  if (!cadastrado) {
    return RES_NAO_CADASTRADO;
  }

  // Para cartao cadastrado, os dois campos sao obrigatorios
  if (!doc["cartao_bloqueado"].is<bool>() ||
      !doc["autorizado"].is<bool>()) {
    Serial.println("Dados de autorizacao invalidos.");
    return RES_ERRO;
  }

  bool bloqueado = doc["cartao_bloqueado"].as<bool>();
  bool autorizado = doc["autorizado"].as<bool>();

  saldo = doc["saldo"] | 0.0f;
  tarifa = doc["tarifa"] | 0.0f;

  if (bloqueado) {
    return RES_BLOQUEADO;
  }

  if (autorizado) {
    return RES_LIBERADO;
  }

  // Cartao liberado, mas a API nao autorizou: confere o motivo
  const char* motivo = doc["motivo"] | "";

  if (strcmp(motivo, "saldo_insuficiente") == 0) {
    return RES_SEM_SALDO;
  }

  // Qualquer resposta inconsistente nega o acesso
  return RES_ERRO;
}

// ==========================
// CELULAR: VALIDA O TOKEN NA API
//
// A API confere o token (uso unico, vale 2 minutos), o bloqueio
// e o saldo, e desconta a passagem.
//
// Retorno: RES_LIBERADO, RES_BLOQUEADO, RES_SEM_SALDO,
//          RES_CODIGO, RES_NAO_CADASTRADO (negado por outro motivo)
//          ou RES_ERRO.
// ==========================

int validarTokenNaAPI(String token, float &saldo, float &tarifa) {

  saldo = 0;
  tarifa = 0;

  JsonDocument envio;
  envio["token_nfc"] = token;

  String corpo;
  serializeJson(envio, corpo);

  Serial.println("Consultando API QUICKPASS (celular)...");
  Serial.println("Token enviado: " + token);

  JsonDocument doc;

  if (!consultarAPI(apiURLNfc, corpo, doc)) {
    return RES_ERRO;
  }

  if (!doc["cadastrado"].is<bool>()) {
    Serial.println("Campo cadastrado ausente ou invalido.");
    return RES_ERRO;
  }

  saldo = doc["saldo"] | 0.0f;
  tarifa = doc["tarifa"] | 0.0f;

  if (doc["cadastrado"].as<bool>()) {
    return RES_LIBERADO;
  }

  const char* motivo = doc["motivo"] | "";

  if (strcmp(motivo, "saldo_insuficiente") == 0) return RES_SEM_SALDO;
  if (strcmp(motivo, "cartao_bloqueado") == 0) return RES_BLOQUEADO;
  if (strcmp(motivo, "token_expirado") == 0 ||
      strcmp(motivo, "token_invalido") == 0) return RES_CODIGO;

  return RES_NAO_CADASTRADO;
}

// ==========================
// CELULAR: LEITURA POR NFC (ISO-DEP)
//
// O celular com o app BusPasse se comporta como um
// cartao ISO 14443-4. O fluxo e:
//   1. RATS  -> o celular responde com o ATS
//   2. SELECT do AID do BusPasse (I-block)
//   3. O celular responde "BP1:" + token + 90 00
//   4. DESELECT
//
// Tudo e feito com as funcoes basicas da MFRC522
// (PCD_TransceiveData + CRC calculado a mao).
// ==========================

void imprimirHex(const char* rotulo, const byte* dados, byte tamanho) {
  Serial.print(rotulo);
  for (byte i = 0; i < tamanho; i++) {
    if (dados[i] < 0x10) Serial.print("0");
    Serial.print(dados[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

// Envia um quadro (acrescenta o CRC_A) e recebe a resposta (sem o CRC_A).
// Retorna true se deu certo.
bool trocarQuadro(const byte* envio, byte envioTam, byte* resposta, byte* respostaTam) {

  byte buf[64];
  if (envioTam > sizeof(buf) - 2) return false;

  memcpy(buf, envio, envioTam);

  byte status = rfid.PCD_CalculateCRC(buf, envioTam, &buf[envioTam]);
  if (status != MFRC522::STATUS_OK) return false;

  byte recebidos = *respostaTam;

  status = rfid.PCD_TransceiveData(buf, envioTam + 2, resposta, &recebidos, nullptr, 0, true);
  if (status != MFRC522::STATUS_OK) {
    Serial.print("Falha na troca de quadro, status ");
    Serial.println(status);
    return false;
  }

  if (recebidos < 2) return false;

  *respostaTam = recebidos - 2; // tira o CRC_A
  return true;
}

// RATS: pede ao celular para entrar no modo ISO-DEP.
bool enviarRATS() {

  const byte rats[] = { 0xE0, 0x50 }; // FSDI = 5 (64 bytes), CID = 0
  byte ats[32];
  byte atsTam = sizeof(ats);

  if (!trocarQuadro(rats, sizeof(rats), ats, &atsTam)) return false;
  if (atsTam < 1) return false;

  imprimirHex("ATS: ", ats, atsTam);

  // Se o celular pediu um tempo de guarda antes do primeiro comando
  // (SFGI no TB1 do ATS), respeita.
  byte t0 = (atsTam >= 2) ? ats[1] : 0;
  byte indice = 2;
  if (t0 & 0x10) indice++;                       // TA1
  if ((t0 & 0x20) && indice < atsTam) {          // TB1
    byte sfgi = ats[indice] & 0x0F;
    if (sfgi > 0 && sfgi < 15) {
      delay((302UL << sfgi) / 1000UL + 1);
    }
  }

  return true;
}

// Envia um APDU dentro de um I-block e devolve os dados da resposta.
bool trocarAPDU(const byte* apdu, byte apduTam, byte* resposta, byte* respostaTam) {

  byte envio[64];
  if (apduTam > sizeof(envio) - 1) return false;

  envio[0] = 0x02 | (blocoAtual & 0x01); // I-block, sem CID/NAD
  memcpy(&envio[1], apdu, apduTam);

  byte buf[64];
  byte tam = sizeof(buf);

  if (!trocarQuadro(envio, apduTam + 1, buf, &tam)) return false;

  // O celular pode pedir mais tempo (S-block WTX): responde e espera de novo.
  for (byte i = 0; i < 3 && tam >= 2 && (buf[0] & 0xF7) == 0xF2; i++) {
    byte wtx[2] = { buf[0], buf[1] };
    tam = sizeof(buf);
    if (!trocarQuadro(wtx, sizeof(wtx), buf, &tam)) return false;
  }

  // Precisa ser um I-block
  if (tam < 1 || (buf[0] & 0xE2) != 0x02) {
    Serial.println("Resposta nao e um I-block.");
    return false;
  }

  blocoAtual ^= 1;

  byte dados = tam - 1;
  if (dados > *respostaTam) return false;

  memcpy(resposta, &buf[1], dados);
  *respostaTam = dados;
  return true;
}

// Encerra a sessao ISO-DEP (S-block DESELECT).
void deselecionar() {
  const byte deselect[] = { 0xC2 };
  byte resp[8];
  byte tam = sizeof(resp);
  trocarQuadro(deselect, sizeof(deselect), resp, &tam);
}

// Tenta ler o token do celular. Retorna true e preenche `token` se der certo.
bool lerTokenDoCelular(String &token) {

  token = "";
  blocoAtual = 0;

  if (!enviarRATS()) {
    Serial.println("RATS falhou.");
    return false;
  }

  byte resp[48];
  byte respTam = sizeof(resp);

  if (!trocarAPDU(SELECT_BUSPASS, sizeof(SELECT_BUSPASS), resp, &respTam)) {
    Serial.println("SELECT do BusPasse falhou.");
    deselecionar();
    return false;
  }

  deselecionar();

  imprimirHex("Resposta: ", resp, respTam);

  // Esperado: "BP1:" + 16 caracteres + 90 00
  if (respTam != 4 + 16 + 2) {
    Serial.println("Tamanho de resposta inesperado (celular sem token armado?).");
    return false;
  }

  if (resp[respTam - 2] != 0x90 || resp[respTam - 1] != 0x00) {
    Serial.println("Celular recusou (SW diferente de 90 00).");
    return false;
  }

  if (resp[0] != 'B' || resp[1] != 'P' || resp[2] != '1' || resp[3] != ':') {
    Serial.println("Prefixo do token invalido.");
    return false;
  }

  for (byte i = 4; i < 4 + 16; i++) {
    token += (char)resp[i];
  }

  return true;
}

// Reinicia o campo de RF e seleciona o cartao/celular de novo (para tentar outra vez).
bool reselecionar() {
  rfid.PCD_AntennaOff();
  delay(40);
  rfid.PCD_AntennaOn();
  delay(40);

  if (!rfid.PICC_IsNewCardPresent()) return false;
  if (!rfid.PICC_ReadCardSerial()) return false;
  return true;
}

// ==========================
// MOSTRAR O RESULTADO NO LCD E NOS LEDS
// ==========================

// Valor com virgula, para o LCD (ex.: 4.25 -> "4,25")
String dinheiro(float valor) {
  char texto[16];
  snprintf(texto, sizeof(texto), "%.2f", valor);
  String formatado = String(texto);
  formatado.replace(".", ",");
  return formatado;
}

void mostrarResultado(int resultado, bool celular, float saldo, float tarifa) {

  lcd.clear();
  lcd.setCursor(0, 0);

  // ==========================
  // LIBERADO (passagem cobrada)
  // ==========================

  if (resultado == RES_LIBERADO) {

    Serial.println(celular ? "CELULAR LIBERADO" : "CARTAO LIBERADO");

    ledValido();

    lcd.print(celular ? "CELULAR VALIDO" : "CARTAO VALIDO");
    lcd.setCursor(0, 1);

    if (tarifa > 0) {
      lcd.print("Saldo R$ " + dinheiro(saldo));
    } else {
      lcd.print("Passagem gratis");
    }
  }

  // ==========================
  // CARTAO NAO CADASTRADO
  // ==========================

  else if (resultado == RES_NAO_CADASTRADO) {

    Serial.println(celular ? "CELULAR NEGADO" : "CARTAO NAO CADASTRADO");

    ledInvalido();

    lcd.print(celular ? "ACESSO NEGADO" : "CARTAO INVALIDO");
    lcd.setCursor(0, 1);
    lcd.print(celular ? "Tente novamente" : "Acesso negado");
  }

  // ==========================
  // CARTAO BLOQUEADO
  // ==========================

  else if (resultado == RES_BLOQUEADO) {

    Serial.println("CARTAO BLOQUEADO");

    ledInvalido();

    lcd.print("CARTAO BLOQUEADO");
    lcd.setCursor(0, 1);
    lcd.print("Acesso negado");
  }

  // ==========================
  // SALDO INSUFICIENTE
  // ==========================

  else if (resultado == RES_SEM_SALDO) {

    Serial.println("SALDO INSUFICIENTE");

    ledInvalido();

    lcd.print("SALDO INSUFIC.");
    lcd.setCursor(0, 1);
    lcd.print("Saldo R$ " + dinheiro(saldo));
  }

  // ==========================
  // CELULAR: CODIGO INVALIDO OU VENCIDO
  // ==========================

  else if (resultado == RES_CODIGO) {

    Serial.println("CODIGO DO CELULAR INVALIDO OU VENCIDO");

    ledInvalido();

    lcd.print("CODIGO INVALIDO");
    lcd.setCursor(0, 1);
    lcd.print("Ative no app");
  }

  // ==========================
  // ERRO NA API OU CONEXAO
  // ==========================

  else {

    Serial.println("ERRO NA CONSULTA API");

    // Nao libera acesso quando nao consegue validar
    ledInvalido();

    lcd.print("Erro na consulta");
    lcd.setCursor(0, 1);
    lcd.print("Tente novamente");
  }
}

// ==========================
// CONFIGURACAO INICIAL
// ==========================

void setup() {

  Serial.begin(115200);

  // Configura os LEDs
  pinMode(LED_VERMELHO, OUTPUT);
  pinMode(LED_BRANCO, OUTPUT);
  pinMode(LED_VERDE, OUTPUT);

  ledAguardando();

  // Inicializa o LCD
  Wire.begin(21, 22);
  lcd.begin(16, 2);
  lcd.backlight();

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("   QUICKPASS");
  lcd.setCursor(0, 1);
  lcd.print("Conectando WiFi");

  // Conecta ao Wi-Fi
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  Serial.print("Conectando ao Wi-Fi");

  unsigned long inicio = millis();

  while (WiFi.status() != WL_CONNECTED &&
         millis() - inicio < 15000) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("Wi-Fi conectado!");
    Serial.print("IP: ");
    Serial.println(WiFi.localIP());

    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("WiFi conectado");
  } else {
    Serial.println("Falha ao conectar Wi-Fi.");

    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("Falha no WiFi");
    lcd.setCursor(0, 1);
    lcd.print("Verifique rede");

    ledInvalido();
    delay(2000);
  }

  // Inicializa o RC522
  SPI.begin();
  rfid.PCD_Init();

  // Se o celular nao for detectado com facilidade, tire as barras da linha
  // abaixo (aumenta a sensibilidade de recepcao do RC522):
  // rfid.PCD_SetAntennaGain(rfid.RxGain_max);

  Serial.println("RC522 inicializado.");

  telaInicial();
  ledAguardando();
}

// ==========================
// LOOP PRINCIPAL
// ==========================

void loop() {

  // Aguarda um cartao ou celular
  if (!rfid.PICC_IsNewCardPresent()) {
    return;
  }

  if (!rfid.PICC_ReadCardSerial()) {
    return;
  }

  // ==========================
  // CELULAR COM O APP BUSPASSE
  //
  // SAK com o bit 0x20 = ISO-DEP (14443-4). Celulares Android que
  // emulam cartao aparecem assim, com UID aleatorio (comeca com 08).
  // Se nao for um celular do BusPasse e nao for UID aleatorio
  // (ex.: outro cartao ISO-DEP), segue para o fluxo normal por UID.
  // ==========================

  if (rfid.uid.sak & 0x20) {

    bool uidAleatorio = (rfid.uid.size == 4 && rfid.uid.uidByte[0] == 0x08);

    // Nada de LCD aqui: o RATS precisa sair logo depois da selecao,
    // antes de qualquer outra coisa demorada.
    Serial.println();
    Serial.println("Dispositivo ISO-DEP detectado (celular?)");

    String token = "";
    bool lido = false;

    for (byte tentativa = 1; tentativa <= 3 && !lido; tentativa++) {

      if (tentativa > 1) {
        Serial.print("Tentativa ");
        Serial.println(tentativa);

        if (!reselecionar()) {
          break;
        }
      }

      lido = lerTokenDoCelular(token);
    }

    if (lido) {

      lcd.clear();
      lcd.setCursor(0, 0);
      lcd.print("Verificando...");
      lcd.setCursor(0, 1);
      lcd.print("Aguarde");

      float saldo = 0;
      float tarifa = 0;

      int resultado = validarTokenNaAPI(token, saldo, tarifa);

      mostrarResultado(resultado, true, saldo, tarifa);

      delay(3000);

      ledAguardando();
      telaInicial();
      return;
    }

    if (uidAleatorio) {

      // Parece um celular, mas nao entregou o token
      Serial.println("CELULAR NAO LIDO");

      ledInvalido();

      lcd.clear();
      lcd.setCursor(0, 0);
      lcd.print("Celular nao lido");
      lcd.setCursor(0, 1);
      lcd.print("Ative no app");

      delay(3000);

      ledAguardando();
      telaInicial();
      return;
    }

    // Nao era celular: segue como cartao fisico. A sessao ISO-DEP pode
    // ter sido desfeita, entao seleciona o cartao de novo.
    if (!reselecionar()) {
      ledAguardando();
      telaInicial();
      return;
    }
  }

  // ==========================
  // LEITURA DO UID (CARTAO FISICO)
  // ==========================

  String uid = "";

  for (byte i = 0; i < rfid.uid.size; i++) {

    if (rfid.uid.uidByte[i] < 0x10) {
      uid += "0";
    }

    String parte =
      String(rfid.uid.uidByte[i], HEX);

    parte.toUpperCase();
    uid += parte;
  }

  Serial.println();
  Serial.println("Cartao detectado!");
  Serial.println("UID: " + uid);

  // Encerra a comunicacao com o cartao
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();

  // ==========================
  // CONSULTA
  // ==========================

  ledAguardando();

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Verificando...");
  lcd.setCursor(0, 1);
  lcd.print("Aguarde");

  float saldo = 0;
  float tarifa = 0;

  int resultado = verificarCartaoNaAPI(uid, saldo, tarifa);

  mostrarResultado(resultado, false, saldo, tarifa);

  // Mantem o resultado visivel por 3 segundos
  delay(3000);

  // Volta ao estado de espera
  ledAguardando();
  telaInicial();
}
