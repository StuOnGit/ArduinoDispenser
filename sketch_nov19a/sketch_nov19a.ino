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


const unsigned int MAX_LENGTH = 128;
//TIM-88839994, d4U7hf5kDUKt6ThHud9RHuCQ
char ssid[MAX_LENGTH];
char password[MAX_LENGTH];
char encrypted_ssid_and_pass[MAX_LENGTH];
char key[MAX_LENGTH];
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


// TODO: da cambiare in booleano o stringa [vedere se è sicuro] per gestione di errore
void requestWifiCredentials(){
    Serial.println("SSID:");
    // Evitare attacchi tipo DoS etc
    secureReadInput(ssid, sizeof(ssid));
    Serial.println("PASSWORD:");
    // Evitare attacchi tipo DoS etc
    secureReadInput(password, sizeof(password));
}


void requestEncryptedWifiAndPassword(){
  Serial.println("Encrypted SSID_and_Password:");
  secureReadInput(encrypted_ssid_and_pass, sizeof(encrypted_ssid_and_pass));
}


void requestKey(){
  Serial.println("KEY:");
  secureReadInput(key, sizeof(key));
}


void saveEncryptedCredentialsToEEPROM(){
  Serial.println("Starting the saving encription credentials for WIFI..");
  requestEncryptedWifiAndPassword();

  int dataAddress = SIGNATURE_ADDRESS + 1; 
  
  Serial.println(encrypted_ssid_and_pass);
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


void decriptedToCredentials(){ // the standard is 'SSID,PASSWORD'

}


char* readFromEEPROM(int address, int length){
  if(length < EEPROM.length()){
    char value;
    char retString[length+1];
    for(int i = 0; i < length; i++){
      value = EEPROM.read(address+i);
      retString[i] = value;
    }
    retString[length] = '\0';
    Serial.print("Read from EEPROM:");
    Serial.print("\t");
    Serial.print(retString);
  }else{
    Serial.println("EEPROM Error: Length too big.");
  }
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

  // prendi il cifrato e decifralo con la chiave
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
void secureReadInput(char* buffer, int length){
  while (Serial.available() == 0){/*aspetta l'input*/}
  int index = 0;
    while(Serial.available() && index < length-1){
      char ch = Serial.read();
        if(ch != "\n" && ch != "\r"){
          buffer[index] = ch;
          index++;
        }else if(ch == "\n" || ch == "\r"){
          buffer[index]= "\0";
        }
        delay(10); // serve per scrivere altrimenti non funziona
    }
}
void initializeSecureElement(){
   if (!ECCX08.begin()) {
    Serial.println("Errore: Secure Element non trovato!");
    while (true);
  }
}

void setup() {
  Serial.begin(9600);
  pinMode(PIN_RED, OUTPUT);
  pinMode(PIN_RESET, INPUT_PULLUP);
  while(!Serial){}
  if (digitalRead(PIN_RESET) == HIGH) {
    digitalWrite (PIN_RED, HIGH);
    Serial.println("Resetting.. Data bye bye");
    clearEncryptionData();
    Serial.println("Data gone..");
    delay(4000);
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

