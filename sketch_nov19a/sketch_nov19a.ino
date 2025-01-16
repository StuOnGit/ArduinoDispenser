#include <String.h>
#include <WiFiNINA.h>
#include <SPI.h>
#include <EEPROM.h>
#include <AESLib.h>
#include <ArduinoECCX08.h>
#include <Stepper.h>
#include <ArduinoJson.h>

#define SIGNATURE_ADDRESS 0  // Indirizzo della firma
#define SIGNATURE_VALUE 0xA5 // Valore della firma
#define PIN_RESET 7 // Pin a cui è collegato il PULSTANTE RESET(TE)
#define PIN_RED 6 // Pin del led rosso
#define TEMPKEY_SLOT 0xFFFF

static const char *HTTP_RES = "HTTP/1.0 200 OK\r\n"
                              "Connection: close\r\n"
                              "Content-Length: 62\r\n"
                              "Content-Type: text/html; charset=iso-8859-1\r\n"
                              "\r\n"
                              "<html>\r\n"
                              "<body>\r\n"
                              "<p>Hello from ESP8266!</p>\r\n"
                              "</body>\r\n"
                              "</html>\r\n";

// AesLib per crittografia simmetrica
AESLib aesLib;

// Config. del server
const int serverPort = 69;
WiFiServer server(serverPort);


//Config. del jsonParser
StaticJsonDocument<200> doc;

// Config. del WIFI
char ssid[64]; 
char password[64];
char encrypted_ssid_and_pass[129]; // + 1 per il terminatore
int status = WL_IDLE_STATUS;

// Chiave simmetrica per WIFI / Anche per nonce di hmac
char key[33];

// Config. SHA256 per HMAC
byte mySHA[32];

// Config. per lo stepper
const int stepsPerRevolution = 2048;
Stepper stepper = Stepper(stepsPerRevolution, 2,3,4,5);


void initHMAC(){
  if (!ECCX08.begin()) {
    Serial.println("Failed to communicate with ECC508/ECC608!");
    while (1);
  }

  // if (!ECCX08.locked()) {
  //   Serial.println("The ECC508/ECC608 is not locked!");
  //   while (1);
  // }

 
}



void doHMAC(String message, byte out[]){
  byte messageBytes[message.length()];
  message.getBytes(messageBytes, message.length()+1);

  Serial.print("Message length: ");
  Serial.println(message.length());
  Serial.print("Message bytes: ");
  for(int i=0; i<sizeof(messageBytes); i++){
    printHex(messageBytes[i]);
    Serial.print(" ");
  }

  // byte resultHMAC[32];
  byte byteKey[32];
  if(strlen(key) > 0){
    hexStringToByteArray(key, byteKey);
      // Perform nonce
    if (!ECCX08.nonce(byteKey))
    {
        Serial.println("Failed to perform nonce.");
        while (1);
    }

    if (!ECCX08.beginHMAC(TEMPKEY_SLOT)) {
          Serial.println("Failed to start HMAC operation.");
          while (1);
    }
    int dataLength = sizeof(messageBytes);
    if (!ECCX08.updateHMAC(messageBytes, dataLength)) {
      Serial.println("Failed to update HMAC operation.");
      while (1);
    }
    if (!ECCX08.endHMAC(out)) {
      Serial.println("Failed to end HMAC operation");
      while (1);
    }

    Serial.print("HMAC result: ");
    for (int i = 0; i < 32 ; i++) { // 32 bytes per l'HMAC
          char hexChar[2];
          sprintf(hexChar, "%02X", out[i]);
          Serial.print(hexChar);
          Serial.print(" ");
    }
  }else {
     Serial.println("Failed to extract key in HMAC operation.");
      while (1);
  }

}

void clearEncryptionData(){
  clearEncryptedCredentialsSignature();
  clearEncryptedCredentials();
}


void clearEncryptedCredentialsSignature() {
  EEPROM.write(SIGNATURE_ADDRESS, 0xFF); // Resetta la firma
}


void clearEncryptedCredentials() {
  for(int i = 0; i < sizeof(encrypted_ssid_and_pass); i++) {
    EEPROM.write(SIGNATURE_ADDRESS + 1 + i, 0xFF); // Resetta la firma
  }
}


bool encryptedCredentialsAreSaved() {
  return EEPROM.read(SIGNATURE_ADDRESS) == SIGNATURE_VALUE;
}


void saveEncryptedCredentialsSignature() {
  EEPROM.write(SIGNATURE_ADDRESS, SIGNATURE_VALUE);
}

void printHex(uint8_t num) {
  char hexCar[2];

  sprintf(hexCar, "%02X", num);
  Serial.print(hexCar);
}

void requestEncryptedWifiAndPassword() {
  Serial.println("First part of Encrypted SSID_and_Password (max 64 bytes):");
  char temp1[65] = {0}; // Inizializza con 0
  secureReadInput64byte(temp1, sizeof(temp1));

  Serial.println("Second part of Encrypted SSID_and_Password (max 64 bytes):");
  char temp2[65] = {0}; // Inizializza con 0
  secureReadInput64byte(temp2, sizeof(temp2));

  // Verifica la lunghezza dei due buffer prima di concatenarli
  if (strlen(temp1) + strlen(temp2) >= sizeof(encrypted_ssid_and_pass)) {
    Serial.println("Errore: Buffer concatenato troppo lungo!");
    return;
  }

  // Concatenazione sicura
  snprintf(encrypted_ssid_and_pass, sizeof(encrypted_ssid_and_pass), "%s%s", temp1, temp2);

  Serial.print("Concatenato: ");
  Serial.println(encrypted_ssid_and_pass);
}



void saveEncryptedCredentialsToEEPROM(){
  Serial.println("Starting the saving encription credentials for WIFI..");
  requestEncryptedWifiAndPassword();

  int dataAddress = SIGNATURE_ADDRESS + 1; 
  
  
 // Serial.println(encrypted_ssid_and_pass);
  EEPROM.put(dataAddress, encrypted_ssid_and_pass);
  saveEncryptedCredentialsSignature(); // Salva la firma
  Serial.println("Credentials Saved");
}


void decriptedToCredentials() {
  if (strlen(key) > 0) {
    char encriptedCredentials[129] = {0};
    String credentials;

    readFromEEPROM(SIGNATURE_ADDRESS + 1, sizeof(encrypted_ssid_and_pass), encriptedCredentials);
    
    byte aes_key[16];
    hexStringToByteArray(key, aes_key);
    
    credentials = decrypt_impl(String(encriptedCredentials), aes_key);

    int separatorPos = credentials.indexOf(',');
    int endPos = credentials.indexOf('.');
     if (separatorPos != -1) {
      // Estrai SSID e password
      credentials.substring(0, separatorPos).toCharArray(ssid, 64);
      credentials.substring(separatorPos + 1, endPos).toCharArray(password, 64);


      Serial.println("Decryption successful!");
      Serial.println((String)"Credentials length: " + credentials.length());
      Serial.println((String)"SSID length: " + strlen(ssid));
      Serial.print("SSID:");
      Serial.println(ssid);
      Serial.println((String)"Password length: " + strlen(password));
      Serial.print("PASSWORD:");
      Serial.println(password);
    } else {
      Serial.println("Error: Invalid credentials format");
    }
  } else {
    Serial.println("ERRORE: Chiave non valida!");
  }
}
    
// Verifica se un HMAC è valido
bool verifyHMAC(const String message, byte receivedHMAC[]) {
  byte out[32];
  doHMAC(message, out);
  if (strcmp(receivedHMAC, out) == 0){
    return true;
  }else{
    return false;
  }
}


void readFromEEPROM(int address, int length, char* out){
  if(length < EEPROM.length()){
    char value;
    for(int i = 0; i < length-1; i++){
      value = EEPROM.read(address+i);
      out[i] = value;
    }
    out[length] = "\0";
    Serial.print("Read from EEPROM:");
    Serial.print("\t");
    Serial.println(out);
  }else{
    Serial.println("EEPROM Error: Length too big.");
  }
}


void readKey(){
  Serial.println("Enter the key:");
  secureReadInput64byte(key, sizeof(key));
  Serial.println(key);
  delay(100);
  Serial.println("Key saved");
}


void connectToWiFi() {
  Serial.println("\n========\n");
  Serial.println("Configuring the  WiFi...");
  IPAddress localIP(192, 168, 1, 100); // IP statico desiderato
  IPAddress gateway(192, 168, 1, 1);   // Gateway (di solito l'indirizzo del router)
  IPAddress subnet(255, 255, 255, 0);  // Subnet mask
  WiFi.config(localIP, gateway, subnet);
  Serial.println("\n========\n");
  Serial.println("Connecting to WiFi...");
  if(!encryptedCredentialsAreSaved()){
    saveEncryptedCredentialsToEEPROM(); 
  }else{
    Serial.println("Credentials already saved..");
  }

  readKey(); // save the key
  decriptedToCredentials(); // use the key and puts the values in ssid and password

  status = WiFi.begin(ssid, password);
  int timerExit = 4;
  while(status != WL_CONNECTED && timerExit > 0){
    delay(1000);
    Serial.println("...");
    Serial.println("Connessione WiFi fallita");
    Serial.println((String)"Error value: " + status);
    Serial.println("Riprovo...");
    status = WiFi.begin(ssid, password);
    timerExit--;
  }
  if (status != WL_CONNECTED) {
    Serial.println("Connessione WiFi fallita");
    Serial.println((String)"Error value: " + status);
    Serial.println("Riprovo...");
    connectToWiFi();
  } else {
    Serial.println("Connessione WiFi riuscita");
    Serial.println(WiFi.localIP());
    server.begin();
  }
}

void clearSerialBuffer() {
  while (Serial.available() > 0) {
    Serial.read();
    delay(10); // Piccola pausa per garantire che tutti i dati vengano letti
  }
}


void secureReadInput64byte(char* buffer, int length) {
  // Svuota il buffer seriale prima di leggere
  clearSerialBuffer();

  int index = 0;

  while (index < length-1) {
    while (Serial.available() > 0) {
      char ch = Serial.read();

      if (ch != '\n' && ch != '\r') {
        buffer[index] = ch;
        index++;
      } else {
        // Fine del messaggio
        buffer[index] = '\0';
        return;
      }
    }
    delay(20);  // Piccolo ritardo per sincronizzazione
  }
  Serial.println(buffer);
  buffer[index-1]  = '\0';  // Assicura che il messaggio termini
}

void hexStringToByteArray(const char* hexString, byte* byteArray) {
    // Calcola la lunghezza effettiva della stringa hex
    int hexLength = strlen(hexString);
    
    // Processa due caratteri hex alla volta
    for (int i = 0; i < hexLength; i += 2) {
        // Crea un buffer temporaneo per i due caratteri hex
        char hexByte[3];
        hexByte[0] = hexString[i];
        hexByte[1] = (i + 1 < hexLength) ? hexString[i + 1] : '0';  // Se la lunghezza è dispari, aggiungi '0'
        hexByte[2] = '\0';
        
        // Converti i due caratteri hex in un byte
        byteArray[i/2] = (byte)strtol(hexByte, NULL, 16);
    }
}

String decrypt_impl(const String& msg, byte aes_key[]) {
  int msgLen = msg.length();
  if (msg.length() < N_BLOCK * 2) {
    return "";
  }
  byte iv[N_BLOCK];

  for (int i = 0; i < N_BLOCK; i++) {
    iv[i] = strtol(msg.substring(i * 2, i * 2 + 2).c_str(), NULL, 16);
  }
  //Stampa correttamente i bytes..!
  String ciphertext = msg.substring(N_BLOCK * 2);
  int ciphertextLength = ciphertext.length() / 2;
  char decrypted[ciphertextLength + 1] = {0}; 

  byte encryptedBytes[ciphertextLength];
  for (int i = 0; i < ciphertextLength; i++) {
    encryptedBytes[i] = strtol(ciphertext.substring(i * 2, i * 2 + 2).c_str(), NULL, 16);
  }
  delay(1000);
  aesLib.decrypt((const char*)encryptedBytes, ciphertextLength, (byte*)decrypted, aes_key, 16, iv);
  
  return String(decrypted);
}

void initAes(){
  Serial.flush();

  delay(1000);

  Serial.println("\n========\n");

  Serial.println("\nAES INIT... paddingMode::ZeroLength");
  aesLib.set_paddingmode(paddingMode::ZeroLength);

}

void waitForCommand() {
  WiFiClient client = server.available();
  if (client) {
    Serial.println("Nuova connessione!");
    String request = "";
    String body = "";

    // Leggi i dati dalla richiesta HTTP
    while (client.connected()) {
      if (client.available()) {
        char c = client.read();
        request += c;
        // Controlla se siamo nel corpo del messaggio POST
        if (request.endsWith("\r\n\r\n")) {
          while (client.available()) {
            body += (char)client.read();
          }
          break;
        }
      }
    }

    Serial.println("Richiesta completa:");
    Serial.println(request);
    Serial.println("Body ricevuto:");
    Serial.println(body);

    // Analizza il JSON ricevuto
    StaticJsonDocument<200> doc;
    DeserializationError error = deserializeJson(doc, body);

    if (error) {
      Serial.print("Errore nel parsing JSON: ");
      Serial.println(error.f_str());
      client.println("HTTP/1.1 400 Bad Request");
      client.println("Content-Type: text/plain");
      client.println();
      client.println("Errore nel parsing JSON");
    } else {
      const char* hmac = doc["HMAC"];
      const char* command = doc["Command"];
      Serial.print("HMAC: ");
      Serial.println(hmac);
      Serial.print("Command: ");
      Serial.println(command);

      // Verifica delle stringhe

       // if(verifyHMAC("giveFood", receivedHMAC) == true){
      //   String command = doc["Command"];
      //   if (command.equals("giveFood")){
      //     giveFood();
      //   }
      // }else{
      //   Serial.println("HMAC Not verified");
      // }

      
      if (strcmp(command, "giveFood") == 0 && verifyHMAC(command, hmac)== 0) {
        client.println("HTTP/1.1 200 OK");
        client.println("Content-Type: application/json");
        client.println();
        client.println("{\"status\":\"success\"}");

        giveFood();
      } else {
        client.println("HTTP/1.1 400 Bad Request");
        client.println("Content-Type: application/json");
        client.println();
        client.println("{\"status\":\"error\",\"message\":\"Valori non validi\"}");
      }
    }
    // Chiudi la connessione
    client.stop();
    Serial.println("Connessione chiusa.");
  }  
}


//TODO: Implementare la verifica della firma
bool isACorrectMessage(String HMAC, String command){
  //if(verifyHMAC(command, ))
}

void giveFood(){
  Serial.println("Giving food");
  stepper.step(stepsPerRevolution);
  delay(1000);
  Serial.println("Food given");
}


void setup() {
  Serial.begin(115200);
  pinMode(PIN_RED, OUTPUT);
  pinMode(PIN_RESET, INPUT_PULLUP);
  stepper.setSpeed(5);
  while(!Serial){}
  if (digitalRead(PIN_RESET) == HIGH) {
    digitalWrite (PIN_RED, HIGH);
    Serial.println("Resetting.. Data bye bye");
    clearEncryptionData();
    Serial.println("Data gone..");
    delay(2000);
    digitalWrite (PIN_RED, LOW);
  } else {
    Serial.print("Normal ");
  }
  Serial.println("Starting..");
  initAes();
  initHMAC();
  connectToWiFi();
 
}
void loop() {
  waitForCommand();
  delay(1000);
}

