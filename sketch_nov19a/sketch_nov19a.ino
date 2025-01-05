#include <String.h>
#include <WiFiNINA.h>
#include <SPI.h>
#include <EEPROM.h>
#include <AESLib.h>


#define SIGNATURE_ADDRESS 0  // Indirizzo della firma
#define SIGNATURE_VALUE 0xA5 // Valore della firma
#define PIN_RESET 7 // Pin a cui è collegato il PULSTANTE RESET(TE)
#define PIN_RED 6 // Pin del led rosso

AESLib aesLib;
WiFiServer server(80);
const unsigned int MAX_LENGTH = 256;
//TIM-88839994, d4U7hf5kDUKt6ThHud9RHuCQ
char  ssid[64];
char password[64];
char encrypted_ssid_and_pass[129]; // + 1 per il terminatore
char key[33];
// char pin[6]; // PIN per autorizzare l'accesso
int status = WL_IDLE_STATUS;

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
     if (separatorPos != -1) {
      // Estrai SSID e password
      credentials.substring(0, separatorPos).toCharArray(ssid, 64);
      credentials.substring(separatorPos + 1).toCharArray(password, 64);
      
      Serial.println("Decryption successful!");
      Serial.print("SSID:");
      Serial.println(ssid);
      Serial.print("PASSWORD:");
      Serial.println(password);
    } else {
      Serial.println("Error: Invalid credentials format");
    }
  } else {
    Serial.println("ERRORE: Chiave non valida!");
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

void aesInit(){
  Serial.flush();

  delay(1000);

  Serial.println("\n========\n");

  Serial.println("\nAES INIT... paddingMode::ZeroLength");
  aesLib.set_paddingmode(paddingMode::ZeroLength);

}

void waitForCommand(){
  WiFiClient client = server.available();
  if(client) {
    Serial.println("\n========\n");
    Serial.println("New client");
    if (!authenticateClient(client)){
      Serial.println("Client not authenticated");
      client.stop();
      return;
    }
    while (client.connected()) {
      if (client.available()) {
        String request = client.readStringUntil('\r');
        Serial.println(request);
        if(request.equals("something")) {
          giveFood();
        }
      }
    }
    client.stop();
    Serial.println("Client disconnected");
  }
}

bool authenticateClient(WiFiClient& client){
  return true;
}

void giveFood(){
  Serial.println("Giving food");
  delay(1000);
  Serial.println("Food given");
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_RED, OUTPUT);
  pinMode(PIN_RESET, INPUT_PULLUP);
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
  aesInit();
  connectToWiFi();
}
void loop() {
  waitForCommand();
  delay(100);
}

