#include <iostream> // cout(), cerr(), string(), strtol(), exit()
#include <getopt.h> // Zpracovani argumentu.
#include <cstring> // strcpy()
#include <fstream> // Prace se soubourem.
#include <netdb.h> // getaddrinfo()
#include <arpa/inet.h> // inet_ntoa()
#include <regex>
#include <unistd.h> // close()
#include <openssl/ssl.h> // SSL
#include <dirent.h> //DIR


using namespace std;

struct allFlags {
    int dFlag = 0; // Mazani zprav.
    int nFlag = 0; // Nove zpravy.
    int sFlag = 0; // Nesifrovane spojeni s prejitim do sifrovaneho.
    int tFlag = 0; // Sifrovane spojeni.
    int cFlag = 0; // Soubor s certifikaty.
    int bigcFlag = 0; // Slozka s certifikaty.
    int portNumber = 110; // Cislo portu.
    string authUser; // Username.
    string authPass; // Password
    string ip; // IP adresa.
    string outDir; // Adresa vystupu.
    string certFile; // Cesta k certifikatu (xxx.pem).
    string certAddr; // Adresar s certiikaty.
    int ipKind = 2; // ipv4 = 2, ipv6 = 10.
    struct sockaddr_in  myServer;
    struct sockaddr_in6 myServer6;
    int mySocket;
    SSL *myssl;
} f;

void procAuth(string *authAddr); // Analyza autentizacniho souboru.
int dns(string hostname , string & ip); // Preklad domenoveho jmena na ip adresu.
void kindOfServerAddr(string address); // Zjisteni typu ip adresy.
void connectToServer(); // Vytvorereni socketu a navazani spojeni se serverem.
void communication(); // Komunikace se serverem.
void processingMessage(int list); // Stahovani a Mazani zprav.
string receive_message(); // Prijem jednoradkovych zprav.
string receive_retr_message(); // Prijem viceradkovych zprav.
string getMessageId(string message, int i); //Vraci Message-ID emailu.
void sendMessage(string message); // Odesilani pozadavku na server.
void secure(); // Zajisteni sifrovane komunikace.
int findInFolder(string *ID); // Hledani zprav ve slozce.


int main(int argc, char *argv[]) {

    int aFlag = 0; // Autentizace.
    int pFlag = 0; // Cislo portu.
    int oFlag = 0; // Vystupni adresar.
    int hFlag = 0; // Napoveda.
    int addrFlag = 0; // Nazev serveru.
    string address; // Adresa serveru/
    string authAddr; // Cesta k autentizacnimu souboru.


// Zpracovani Argumentu
    int c;
    while ((c = getopt(argc, argv, "p:TSc:C:dna:o:h")) != -1) {
        switch (c) {

            case 'p': // Cislo portu.
                if(!pFlag) {
                    pFlag = 1;
                    f.portNumber = (int) strtol(optarg, (char **) nullptr, 10);
                    break;
                }else{
                    cerr << "Invalid argument. -p is used twice.\n";
                    exit(1);
                }

            case 'T': // Sifrovani cele komunikace.
                if(!f.tFlag) {
                    if (f.sFlag) {
                        cerr << "Invalid argument. Use -T with -S.\n";
                        exit(1);
                    }
                    f.tFlag = 1;
                    break;
                }else{
                    cerr << "Invalid argument. -T is used twice.\n";
                    exit(1);
                }

            case 'S': // Nesifrovane spojeni s prejitim do sifrovaneho.
                if(!f.sFlag) {
                    if (f.tFlag) {
                        cerr << "Invalid argument. Use -T with -S.\n";
                        exit(1);
                    }
                    f.sFlag = 1;
                    break;
                }else{
                    cerr << "Invalid argument. -S is used twice.\n";
                    exit(1);
                }

            case 'c': // Soubor s certifikaty.
                if(!f.cFlag) {
                    f.cFlag = 1;
                    f.certFile = optarg;
                    break;
                }else{
                    cerr << "Invalid argument. -c is used twice.\n";
                    exit(1);
                }

            case 'C': // Slozka s certifikaty.
                if(!f.bigcFlag) {
                    f.bigcFlag = 1;
                    f.certAddr = optarg;
                    break;
                }else{
                    cerr << "Invalid argument. -C is used twice.\n";
                    exit(1);
                }

            case 'd': // Mazani zprav.
                if(!f.dFlag) {
                    f.dFlag = 1;
                    break;
                }else{
                    cerr << "Invalid argument. -d is used twice.\n";
                    exit(1);
                }

            case 'n': // Pracuje s novyma zpravama.
                if(!f.nFlag) {
                    f.nFlag = 1;
                    break;
                }else{
                    cerr << "Invalid argument. -n is used twice.\n";
                    exit(1);
                }

            case 'a': // Autentizace.
                if(!aFlag) {
                    aFlag = 1;
                    //strcpy(authAddr, optarg);
                    authAddr = optarg;
                    break;
                }else{
                    cerr << "Invalid argument. -a is used twice.\n";
                    exit(1);
                }

            case 'o': // Vystupni adresar.
                if(!oFlag) {
                    oFlag = 1;
                    f.outDir = optarg;
                    break;
                }else{
                    cerr << "Invalid argument. -o is used twice.\n";
                    exit(1);
                }
            case 'h': // Napoveda.
                if(!hFlag) {
                    hFlag = 1;
                    break;
                }else{
                    cerr << "Invalid argument. -h is used twice.\n";
                    exit(1);
                }
            default:
                cerr << "Invalid argument. -h for help.\n";
                exit(1);
        }
    }
    int index = 0;
    for (index = optind; index < argc; index++) { // Server.
        if (!addrFlag) {
            addrFlag = 1;
            address = argv[index];
        } else {
            cerr << "Invalid argument.\n";
            exit(1);
        }
    }

// Napoveda.
    if(hFlag and (argc > 2)){
        cerr << "Invalid argument. -h can not be used with other parameters.\n";
        exit(1);
    }else if(hFlag){
        cout << "\nABOUT:\n\n";
        cout << "POP3 POP3 Reader with pop3s extensions.\n\n\n";
        cout << "USE:\n\n";
        cout << "popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> ";
        cout << "-o <out_dir>\n\n\n";
        cout << "Parameters:\n\n";
        cout << "<server>  -  Mandatory  - Required is the <server> name (IP address or domain name) of the";
        cout << "requested resource.\n\n";
        cout << "[-p <port>]  -  Optional  - Specifies the port number <port> on the server.\n\n";
        cout << "-T  -  Optional  - Establishes encryption of the entire communication.\n\n";
        cout << "-S  -  Optional  -  Establishes an unencrypted connection to the server and switches to an encrypted";
        cout << " protocol variant.\n\n";
        cout << "[-c <certfile>]  -  Optional  -  Defines the <certfile> certificate file to be used to validate the";
        cout << " SSL / TLS certificate validity submitted by the server (use only with -T or -S).\n\n";
        cout << "[-C <certaddr>]  -  Optional  -  Specifies the <certaddr> directory in which to search for the";
        cout << " certificates to be used to validate the SSL / TLS certificate validity submitted by the server";
        cout << " (use only with -T or -S).\n\n";
        cout << "[-d]  -  Optional  - Deleting messages on the server.\n\n";
        cout << "[-n]  -  Optional  - Work only with new messages.\n\n";
        cout << "-a <auth_file>  -  Mandatory  -  Authentication file.\n\nusername = XXX\npassword = YYY\n\n";
        cout << "-o <out_dir>  -  Mandatory  - Output directory <out_dir> to which the downloaded message program has to";
        cout << "be saved.\n\n";
        exit(0);
    }

// Osetreni pouzitych argumentu.
    if ((f.bigcFlag or f.cFlag) and !(f.sFlag or f.tFlag)) {
        cerr << "Invalid argument. -C or -c can be used only with -S or -T.\n";
        exit(1);
    }else if(!aFlag){
        cerr << "Invalid argument. -a is not used.\n";
        exit(1);
    }else if(!oFlag){
        cerr << "Invalid argument. -o is not used.\n";
        exit(1);
    }else if(!addrFlag){
        cerr << "Invalid argument. Server name is missing.\n";
        exit(1);
    }

// Osetreni portu zadaneho uzivatelem.
    if(f.portNumber != 110 and f.portNumber != 995 ){
        cerr << "Invalid port number. For non-encrypted: 110. For Secure: 995.\n";
        exit(1);
    }
    if(f.sFlag and f.portNumber == 995){
        cerr << "Invalid port number. TLS you can use only with port number 110\n";
        exit(1);
    }
    if(f.portNumber == 995 and !f.tFlag){
        cerr << "Invalid port number\n";
        exit(1);
     }

// Osetreni lomitka na konci f.outDir.
    char lastChar = f.outDir.back();
    if(lastChar != 47){
        f.outDir += (char)47;
    }

// Zpracovani autentizacniho souboru.
    procAuth(&authAddr);

// Zpracovani adresy serveru.
    kindOfServerAddr(address);

// Nastaveni portNumber.
    if(f.tFlag){
        f.portNumber = 995;
    }


// Vytvoreni socketu, inicializace a pripojeni na server.
    connectToServer();

    if(f.tFlag){ // Ciste sifrovane spojeni.
        secure();
        communication();
    }else {
        communication(); // Nesifrovane spojeni a TLS.
    }

    return 0;
}

//-----------------------------------------------------------------
//---------------Zpracovani autentizacniho souboru-----------------

void procAuth(string *authAddr){

    ifstream myFile;
    myFile.open (*authAddr); // Otevreni souboru pro cteni.
    string line;

    if (myFile.is_open()) {
        getline(myFile, line);
        line.append("\n");
        unsigned long endOfLine = line.find('\n');
        if(endOfLine <=11){
            cerr << "Invalid format in authentication file.\n";
            exit(1);
        }
        f.authUser = line.substr(11, endOfLine - 11);

        getline(myFile, line);
        line.append("\n");
        unsigned long endOfLine2 = line.find('\n');
        if(endOfLine2 <=11){
            cerr << "Invalid format in authentication file.\n";
            exit(1);
        }
        f.authPass = line.substr(11, endOfLine2 - 11);

        myFile.close();
    }else {
        cerr << "Unable to open file.\n";
        exit(1);
    }
}

//-----------------------------------------------------------------
//------------------Rozpoznani domenoveho jmena--------------------

int dns(string hostname , string & ip)
{
    struct hostent *name;
    struct in_addr **addr_list;

    if ( (name = gethostbyname( hostname.c_str() ) ) == nullptr) {
        cerr << "Can't recognize domain name.\n";
        exit(1);
    }
    addr_list = (struct in_addr **) name->h_addr_list;
    if (addr_list[0] != nullptr){
        ip = inet_ntoa(*addr_list[0]);
        return 0;
    }
    return 1;
}

//-----------------------------------------------------------------
//----------------------Zjisteni typu IP --------------------------

void kindOfServerAddr(string address){
    // ipv4 identifikator.
    regex fiterIPv4("^[0-9]?[0-9]?[0-9].[0-9]?[0-9]?[0-9].[0-9]?[0-9]?[0-9].[0-9]?[0-9]?[0-9]");
    if(regex_match(address, fiterIPv4) == 1){
        f.ipKind = 2;
        f.ip = address;
        return;
    }

    // ipv6 identifikator.
    string tmp6;
    int count6 = 0;

    for(unsigned int i = 0; i < address.length(); i++){
        tmp6 = address.substr(i,1);
        if(":" == tmp6){
            count6++;
        }
    }
    if(count6 > 2){
        f.ipKind = 10;
        f.ip = address;
        return;
    }

    // Prevod domenoveho jmena na ip adresu.
    if (dns(address,f.ip)){
        cerr << "Error translation domain name to ip address.\n";
        exit(1);
    }
}

//-----------------------------------------------------------------
//----------------Propojeni klienta ze servrem---------------------

void connectToServer() {
    stringstream mystream;

    if(f.ipKind == 10){ // IPv6

        if ((f.mySocket = socket(AF_INET6 ,SOCK_STREAM , 0)) == -1){
            cerr << "Failed to create a socket.\n";
            exit(1);
        }

        // Inicializace
        f.myServer6.sin6_family = AF_INET6;
        f.myServer6.sin6_port = htons((uint16_t)f.portNumber);
        f.myServer6.sin6_addr = in6addr_any;
        inet_pton(AF_INET6, f.ip.c_str(), (void*)&f.myServer6.sin6_addr.s6_addr);

        // Pripojeni na server
        if (connect(f.mySocket , (struct sockaddr *)&f.myServer6 , sizeof(f.myServer6)) < 0){
            cerr << "Connection failed.\n";
            exit(1);
        }
    }else{ // IPv4

        if ((f.mySocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            cerr << "Failed to create a socket.\n";
            exit(1);
        }

        // Inicializace
        f.myServer.sin_family = AF_INET;
        f.myServer.sin_port = htons((uint16_t) f.portNumber);
        f.myServer.sin_addr.s_addr = inet_addr(f.ip.c_str());

        // Pripojeni na server
        if (connect(f.mySocket, (struct sockaddr *) &f.myServer, sizeof(f.myServer)) < 0) {
            cerr << "Connection failed.\n";
            exit(1);
        }
    }
}

//-----------------------------------------------------------------
//----------------Prijmani jednoradkovych zprav--------------------

string receive_message(){
    string mystream;
    long read_block = 0;
    char s_rBuff[512];
    //bff

    if(!f.tFlag) {
        if ((read_block = recv(f.mySocket, s_rBuff, 511, 0)) <= 0) {
            cerr << "Reading from socket failed.\n";
            exit(1);
        }
    }else{
        if ((read_block = SSL_read(f.myssl, s_rBuff, 511)) <= 0){
            cerr << "Reading from socket failed.\n";
            exit(1);
        }
    }
    s_rBuff[read_block] = '\0';
    mystream += s_rBuff;

    //cisteni
    return mystream;
}

//-----------------------------------------------------------------
//-------------------Prijmani multi-line zprav---------------------

string receive_retr_message(){

    long rc = 0;
    stringstream all;
    char oob_data[512] = "";

    size_t i;
    while(true) {
        if(!f.tFlag) {
            rc = recv(f.mySocket, &oob_data, 512, 0);
        }else{
            rc = SSL_read(f.myssl,&oob_data,512);
        }
        if (rc >= 0) {
            all << oob_data;
        }
        i = all.str().find("\r\n.\r\n");
        if (i != string::npos) {
            return all.str();
        }
        memset(oob_data, '\0', sizeof(oob_data));
    }

}

//-----------------------------------------------------------------
//----------------Odesilani pozadavku na server--------------------

void sendMessage(string message){
    if(!f.tFlag){
        send(f.mySocket, message.c_str(), (int)message.length(), 0);
    }else{
        SSL_write(f.myssl,message.c_str(),(int)message.length());
    }
}

//-----------------------------------------------------------------
//-----------------Komunikace ze serverem--------------------------

void communication(){

    string message; // Prijata zprava ze serveru.
    string request; // Pozadavek odeslany serveru.

    message = receive_message(); // Overeni spojeni.
    if(message.substr(0, 4) == "-ERR"){
        cerr << "Username Error.\n";
        exit(1);
    }

    // TLS
    if(f.sFlag){

        // SEND - STLS
        request = "STLS\r\n";
        sendMessage(request);

        message = receive_message();
        string tmpSTLS = message.substr(0,3);
        if(tmpSTLS == "+OK"){
            f.tFlag = 1;
            secure();
        }else{
            cerr << "TLS connection failed.\n";
            exit(1);
        }
    }

    // SEND - USER XXXXXX
    request = "USER ";
    request.append(f.authUser);
    request.append("\r\n");
    sendMessage(request);

    message = receive_message();
    if(message.substr(0, 4) == "-ERR"){
        cerr << "Username Error.\n";
        exit(1);
    }

    //SEND - PASS XXXXX
    request = "PASS ";
    request.append(f.authPass);
    request.append("\r\n");
    sendMessage(request);

    message = receive_message();
    if(message.substr(0, 4) == "-ERR"){
        cerr << "Password Error.\n";
        exit(1);
    }

    //SEND - STAT
    request = "STAT\r\n";
    sendMessage(request);

    message = receive_message();
    if(message.substr(0, 4) == "-ERR"){
        cerr << "Error.\n";
        exit(1);
    }

    // Pocet emailu na serveru
    unsigned long LastSpace = message.find_last_of(" ");
    int list;
    try {
        list = stoi(message.substr(4,LastSpace-4));
    }
    catch (const std::invalid_argument& ia) {
        cerr << "Error. Out of range.\n";
        exit(1);
    }


    // Zpracovani zprav.
    processingMessage(list);

    // SEND - QUIT
    request = "QUIT ";
    request.append("\r\n");
    sendMessage(request);

    message = receive_message();

    // Ukoncení spojeni.
    close(f.mySocket);
}


//-----------------------------------------------------------------
//-----------Zpracovani zprav ze serveru---------------------------

void processingMessage(int list){

    int downloadCount = 0; // Urcuje pocet stahnutych/smazanych emailu.
    string request; // Pozadavek odesleny na server.
    string message; // Zprava prijata ze serveru.


    if(!f.dFlag) { // Stahovani emailu ze serveru.
        for (int i = 1; i <= list; i++) {

            //SEND - RETR X
            request = "RETR ";
            request += to_string(i);
            request.append("\r\n");
            sendMessage(request);

            message = receive_retr_message(); //Prijata zprava

            if (message.substr(0, 4) == "-ERR") {
                cerr << "Downloading emails failed.\n";
                exit(1);
            }

            // Odriznuti prebytecnych casti prijate zpravy.
            unsigned long messageIND = message.find("\r\n"); // Zacatek zpravy.
            messageIND = messageIND + 2;
            unsigned long messageIND2 = message.find("\r\n.\r\n"); // Konec zpravy.
            messageIND2 = messageIND2 + 2;

            message = message.substr(messageIND, messageIND2 - messageIND);

            // Zjisteni Message-ID.
            string messageID = getMessageId(message, i);


            if (f.nFlag) { // Stahuji se pouze nove zpravy.
                if (findInFolder(&messageID)) {
                    ofstream os(f.outDir + messageID);
                    if (!os) {
                        cerr << "Error writing to output DIR.\n";
                        exit(1);
                    }
                    else {
                        // Uprava zdvojenych tecek.
                        regex e ("\r\n\\.\\.");
                        message = regex_replace (message,e,"\r\n\\.");
                        // Ulozeni do souboru.
                        os << message;
                        downloadCount++;

                    }
                } else {
                    continue;
                }
            }else{ // Stahuji se vsechny zpravy.
                ofstream os(f.outDir + messageID);
                if (!os) {
                    cerr << "Error writing to output DIR.\n";
                    exit(1);
                }
                else {
                    // Uprava zdvojenych tecek.
                    regex e ("\r\n\\.");
                    message = regex_replace (message,e,"\r\n");
                    // Ulozeni do souboru.
                    os << message;
                    downloadCount++;
                }
            }
        }

        // Vypis zprav.
        if(downloadCount == 1){
            cout << "Stazena " << to_string(downloadCount) << " zprava.\r\n";
        }else if((downloadCount == 2) or (downloadCount == 3) or (downloadCount == 4)){
            cout << "Stazeny " << to_string(downloadCount) << " zpravy.\r\n";
        }else{
            cout << "Stazeno " << to_string(downloadCount) << " zprav.\r\n";
        }


    }else{ // Mazani emailu
        for(int i = 1; i <= list; i++){

            if(f.nFlag){ // Ze serveru se mazou prectene zpravy.

                //SEND - RETR X
                request = "RETR ";
                request += to_string(i);
                request.append("\r\n");
                sendMessage(request);

                message = receive_retr_message();
                if (message.substr(0, 4) == "-ERR") {
                    cerr << "Downloading emails failed.\n";
                    exit(1);
                }

                // Zjisteni Message-ID.
                string messageID = getMessageId(message, i);

                if (!findInFolder(&messageID)) {

                    //SEND - DELE XXXXX
                    request = "DELE ";
                    request += to_string(i);
                    request.append("\r\n");
                    sendMessage(request);

                    message = receive_message();
                    if (message.substr(0, 4) == "-ERR") {
                        cerr << "Password Error.\n";
                        exit(1);
                    }
                } else {
                    continue;
                }

            }else { // Ze serveru se mazou vsechny zpravy.

                //SEND - DELE XXXXX
                request = "DELE ";
                request += to_string(i);
                request.append("\r\n");
                sendMessage(request);

                message = receive_message();
                if (message.substr(0, 4) == "-ERR") {
                    cerr << "Password Error.\n";
                    exit(1);
                }
            }
            downloadCount++;
        }

        // Mazani zprav.
        if(downloadCount == 1){
            cout << "Smazana " << to_string(downloadCount) << " zprava.\r\n";
        }else if((downloadCount == 2) or (downloadCount == 3) or (downloadCount == 4)){
            cout << "Smazany " << to_string(downloadCount) << " zpravy.\r\n";
        }else{
            cout << "Smazano " << to_string(downloadCount) << " zprav.\r\n";
        }

    }
}

//-----------------------------------------------------------------
//--------------------------Nastaveni SSL--------------------------

void secure() {

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *meth;
    SSL_CTX *ctx;

    meth = SSLv23_client_method();

    // Vytvoreni noveho bloku.
    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        cerr << "Error creating the context.\n";
        exit(1);
    }

    f.myssl = SSL_new(ctx);

    // Pouziti certifikatu. Parametry '-c' a '-C'.

    if (f.cFlag) { // Certifikacni soubour.
        if(!SSL_CTX_load_verify_locations(ctx,f.certFile.c_str(), nullptr)){
            if(f.bigcFlag){ // Pokud je pouzit -C, tak prohleda i slozku s certifikaty.
                if(! SSL_CTX_load_verify_locations(ctx, nullptr, f.certAddr.c_str()))
                {
                    cerr << "Certificate Failed.\n";
                    exit(1);
                }
            }else {
                cerr << "Certificate Failed.\n";
                exit(1);
            }
        }
    }

    if (f.bigcFlag and !f.cFlag){ // Pokud se prohledava pouze slozka s certifikaty.
        if(! SSL_CTX_load_verify_locations(ctx, nullptr, f.certAddr.c_str())) // "/etc/ssl/certs"
        {
            cerr << "Certificate Failed.\n";
            exit(1);
        }

    }

    if(!f.cFlag and !f.bigcFlag) { // Bez prepinace '-c'/'-C'.
        if(!SSL_CTX_set_default_verify_paths(ctx)){
            cerr << "Certificate Failed.\n";
            exit(1);
        }
    }


    //
    SSL_set_fd(f.myssl, f.mySocket);

    if (!(SSL_connect(f.myssl))) {
        cerr << "SSL connection failed.\n";
        exit(1);
    }

    X509 * server_cert = nullptr;
    server_cert = SSL_get_peer_certificate(f.myssl);
    if (server_cert == nullptr) {
        cerr << "Attribution of the certificate failed.\n";
        exit(1);
    } else {
        X509_free(server_cert);
    }

    if (SSL_get_verify_result(f.myssl) != X509_V_OK)
    {
        cerr << "SSL Failed.\n";
        exit(1);
    }
}

//-----------------------------------------------------------------
//--------------------Vyhledavani v adresari-----------------------

int findInFolder(string *ID){

    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir (f.outDir.c_str())) != nullptr) {

        while ((ent = readdir (dir)) != nullptr) {
            string myID = ent->d_name;
            if (*ID == myID ){
                closedir (dir);
                return 0; //Shoda
            }
        }
        closedir (dir);
        return 1;
    } else {
        cerr << "Could not open directory.\n";
        exit(1);
    }
}

//-----------------------------------------------------------------
//---------------------Identifikace zpravy-------------------------

string getMessageId(string message, int i){

    string uidlMessage; // Zprava ze serveru.
    string ID; // Vysledny identifikator zpravy.

    // UIDL
    string request = "UIDL ";
    request += to_string(i);
    request.append("\r\n");
    sendMessage(request);

    //mystream.str("");
    uidlMessage = receive_message();
    if (uidlMessage.substr(0, 3) == "+OK") {
        unsigned long tmpStart = uidlMessage.find_last_of(" ");
        unsigned long tmpEnd = uidlMessage.find("\r\n");
        ID = uidlMessage.substr(tmpStart+1,(tmpEnd-tmpStart)-1);
        return ID;
    }

// Message ID
    int messageTMP;
    smatch matchResult; // Shoda
    string regExprId("message-id: <.+>"); // Regularni vyraz pro message-id.
    regex idRegex(regExprId, regex_constants::icase); // Nastaveni Case insensitive.
    messageTMP = regex_search(message, matchResult, idRegex);

    if (messageTMP == 0) { // Zprava nema Message-ID.
        ID = "WithoutID";
        ID += to_string(i);
    } else { // Zprava ma Message-ID.
        ID = matchResult.str().substr(13, matchResult.str().length() - 14);
    }

    return ID;
}
