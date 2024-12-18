#include <WiFiNINA.h>
#include <SPI.h>
#include <ArduinoECCX08.h>

#define SLOT_SSID 0    // Slot per salvare SSID
#define SLOT_PASS 1    // Slot per salvare password

unsigned int indexSSID = 0;
unsigned int indexPassw = 0;
const unsigned int MAX_LENGTH = 32;
//TIM-88839994, d4U7hf5kDUKt6ThHud9RHuCQ
char ssid[MAX_LENGTH];
char password[MAX_LENGTH];
// char pin[6]; // PIN per autorizzare l'accesso
int status = WL_IDLE_STATUS;

enum wifi_type{
  TYPE_SSID,
  TYPE_PASSWORD
};

int connectionStatus = WL_IDLE_STATUS;
unsigned int triesToConnection = 3;

// TODO: da cambiare in booleano o stringa [vedere se è sicuro] per gestione di errore
void requestWifiCredentials(){
    Serial.println("SSID:");
    // Evitare attacchi tipo DoS etc
    secureReadInput(TYPE_SSID, ssid, sizeof(ssid));
    Serial.println("PASSWORD:");
    // Evitare attacchi tipo DoS etc
    secureReadInput(TYPE_PASSWORD, password, sizeof(password));
}

void connectToWiFi() {
  Serial.println("Connessione al Wifi...");
  status = WiFi.begin(ssid, password);
  while(status != WL_CONNECTED){
    delay(500);
    Serial.println("...");
  }
  Serial.println("\nConnesso!");
  //DEBUG
  Serial.println(WiFi.localIP());
}

/***
 TODO: renderlo veramente sicuro
 - Controlli sulla lunghezza
 - Controlli sui termini speciali e non
 ***/
void secureReadInput(wifi_type wifi_type, char* buffer, int length){
  while (Serial.available() == 0){/*aspetta l'input*/}
  if (wifi_type == TYPE_SSID){
    while(Serial.available() && indexSSID < length-1){
      char ch = Serial.read();
        if(ch != "\n" && ch != "\r"){
          buffer[indexSSID] = ch;
          indexSSID++;
        }else if(ch == "\n" || ch == "\r"){
          Serial.println("Trovato");
          buffer[indexSSID]= "\0";
        }
        delay(10); // serve per scrivere altrimenti non funziona

     
    }
  }else if(wifi_type == TYPE_PASSWORD){
    while(Serial.available() && (indexPassw < length-1)){
      char ch = Serial.read();
      if(ch != "\n"){
        buffer[indexPassw] = ch;
        indexPassw++;
      }else if(ch == "\n"){
        buffer[indexPassw]= "\0";
      }
      delay(10);  // serve per scrivere altrimenti non funziona
    }
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
  while(!Serial){}
  initializeSecureElement();
  requestWifiCredentials();
  //se va a buon fine
  connectToWiFi();
  //se va a buon fine tutto a posto!

}
void loop() {

  delay(1000);
}

