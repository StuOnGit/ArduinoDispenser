#include <String.h>
#include <WiFiNINA.h>
#include <SPI.h>
#include <ArduinoECCX08.h>
#include <EEPROM.h>
#include <AESLib.h>

#define SIGNATURE_ADDRESS 0  // Indirizzo della firma
#define SIGNATURE_VALUE 0xA5 // Valore della firma
#define PIN_RESET 7 // Pin a cui è collegato il PULSTANTE RESET(TE)
#define PIN_RED 6 // Pin del led rosso
#define AES_BLOCKLEN 16 


const unsigned int MAX_LENGTH = 256;
//TIM-88839994, d4U7hf5kDUKt6ThHud9RHuCQ
char ssid[64];
char password[64];
char encrypted_ssid_and_pass[129]; // + 1 per il terminatore
char key[33];
// char pin[6]; // PIN per autorizzare l'accesso
int status = WL_IDLE_STATUS;
int resetState = 0;

int connectionStatus = WL_IDLE_STATUS;
unsigned int triesToConnection = 3;


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


void hexStringToByteArray(const char *hexString, byte *byteArray, size_t arraySize) {
  for (size_t i = 0; i < arraySize; i++) {
    sscanf(&hexString[i * 2], "%2hhx", &byteArray[i]);
  }
}


void decryptAES(const char* encryptedHex, const char* keyHex, char* out){
  byte aesKey[MAX_LENGTH];  
  byte encryptedData[MAX_LENGTH];
  byte iv[AES_BLOCKLEN]; // Vettore di inizializzazione

  // Converti i dati esadecimali in array di byte
  hexStringToByteArray(keyHex, aesKey, MAX_LENGTH);
  hexStringToByteArray(encryptedHex, encryptedData, MAX_LENGTH);

  // Estrai IV e messaggio cifrato
  memcpy(iv, encryptedData, AES_BLOCKLEN); // I primi 16 byte sono l'IV
  byte ciphertext[MAX_LENGTH - AES_BLOCKLEN];
  memcpy(ciphertext, encryptedData + AES_BLOCKLEN, MAX_LENGTH - AES_BLOCKLEN);

  // Configura AES
  AESLib aesLib;
  aesLib.gen_iv(iv); // Usa il vettore di inizializzazione estratto
  aesLib.set_paddingmode((paddingMode)0); // Nessun padding (adatta al tuo schema)

  // Decripta
  aesLib.decrypt((char *)ciphertext, out, MAX_LENGTH - AES_BLOCKLEN, (char *)aesKey, MAX_LENGTH, iv);
  out[MAX_LENGTH - AES_BLOCKLEN] = '\0'; // Aggiungi il terminatore

}


void decriptedToCredentials() {
  if (strlen(key) > 0) {
    char encriptedCredentials[129] = {0};
    char credentials[128] = {0}; // Adatta la dimensione al massimo previsto

    readFromEEPROM(SIGNATURE_ADDRESS + 1, sizeof(encrypted_ssid_and_pass), encriptedCredentials);
    decryptAES(encriptedCredentials, key, credentials);

    Serial.println("Decriptato:");
    Serial.println(credentials);
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
    Serial.print(out);
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
  Serial.println("Connecting to WiFi...");
  // Vedere se e' gia salvata
  if(!encryptedCredentialsAreSaved()){
    // salva il cifrato
    saveEncryptedCredentialsToEEPROM(); 
  }else{
    Serial.println("Credentials already saved..");
  }

  
 
  readKey(); // save the key
  decriptedToCredentials(); // use the key and puts the values in ssid and password


  // inserisci quindi in ssid e password e connettiti

/*
  status = WiFi.begin(ssid, password);
  int timerExit = 4;
  while(status != WL_CONNECTED || timerExit == 0){
    delay(1000);
    Serial.println("...");
    timerExit--;
  }
  Serial.println("\nConnesso!");
  //DEBUG
  Serial.println(WiFi.localIP());
  */
}

/***
 TODO: renderlo veramente sicuro
 - Controlli sulla lunghezza
 - Controlli sui termini speciali e non
 ***/

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



void initializeSecureElement(){
   if (!ECCX08.begin()) {
    Serial.println("Errore: Secure Element non trovato!");
    while (true);
  }
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

  connectToWiFi();
}
void loop() {
  delay(100);
}

