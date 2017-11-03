#include <iostream> // cout(), cerr(), string(), strtol(), exit()
#include <getopt.h> // Zpracovani argumentu.
#include <cstring> // strcpy()
#include <fstream> // Prace se soubourem.
#include <netdb.h> // getaddrinfo()
#include <arpa/inet.h> // inet_ntoa()
#include <regex>
#include <unistd.h> // close()
#include <openssl/ssl.h>
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
    string outDir; // Adresa vystupu
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
void connectToServer(); // Vytvoreni socketu a navazani spojeni se serverem.
void communication(); // Komunikace se serverem.
string receive_message(); // Prijem jednoradkovych zprav.
string receive_retr_message(); // Prijem viceradkovych zprav.
void sendMessage(string message); // Odesilani pozadavku na server.
void secure();
int findInFolder(string *ID);

int main(int argc, char *argv[]) {

    int aFlag = 0; // Autentizace.
    int pFlag = 0; // Cislo portu.
    int oFlag = 0; // Vystupni adresar.
    int hFlag = 0; // Napoveda.
    int addrFlag = 0; // Nazev serveru.
    string address; // Adresa serveru/
    string authAddr; // Cesta k autentizacnimu souboru.


//-----------------------------------------------------------------
//------------------------ARGUMENTY--------------------------------
// Zpracovani
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

            case 'C': // Slozka s certifikaty
                if(!f.bigcFlag) {
                    f.bigcFlag = 1;
                    f.certAddr = optarg;
                    break;
                }else{
                    cerr << "Invalid argument. -C is used twice.\n";
                    exit(1);
                }

            case 'd': //
                if(!f.dFlag) {
                    f.dFlag = 1;
                    break;
                }else{
                    cerr << "Invalid argument. -d is used twice.\n";
                    exit(1);
                }

            case 'n': // TODO  Nove zpravy. Muze byt pouzit s parametrem -d?
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
                cerr << "Invalid argument\n";
                exit(1);
        }
    }
    int index = 0;
    for (index = optind; index < argc; index++) { // Server.
        if (!addrFlag) {
            addrFlag = 1;
            address = argv[index];
        } else {
            cerr << "Invalid argument. Server name is used twice.\n";
            exit(1);
        }
    }

// Napoveda.
 if(hFlag and (argc > 2)){
    cerr << "Invalid argument. -h can not be used with other parameters.\n";
    exit(1);
 }else if(hFlag){
     cout << "Napoveda\n";
     cout << "Parametr jak vinko\n"; // TODO handle napoveda
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

// Zpracovani autentizacniho souboru.
    procAuth(&authAddr);

// Zpracovani adresy serveru.
    kindOfServerAddr(address);

// Nastaveni portNumber.
    if(f.tFlag){
        f.portNumber = 995;
    }

//-----------------------------------------------------------------
//-----------------------------KOMUNIKACE--------------------------

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
//-------------------------POMOCNE FUNKCE--------------------------

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

void connectToServer() {
    //int mySocket;
    stringstream mystream;

    if(f.ipKind == 10){ //ipv6 //TODO otestuj ipv6

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
    }else{ // ipv4

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


void sendMessage(string message){
    // Odesilani pozadavku na server.
    if(!f.tFlag){
        //TODO dodelat nesifrovanou
    }else{
        SSL_write(f.myssl,message.c_str(),(int)message.length());
    }
}


void communication(){

    stringstream mystream;
    mystream.str("");
    mystream << receive_message();
    cout << mystream.str();
    if(mystream.str().substr(0, 4) == "-ERR"){
        cerr << "Username Error.\n";
        exit(1);
    }

    string request;

    if(f.sFlag){

        // SEND - STLS
        request = "STLS\r\n";
        sendMessage(request);

        mystream.str("");
        mystream << receive_message();
        string tmpSTLS = mystream.str().substr(0,3);
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

    mystream.str("");
    mystream << receive_message();
    cout << mystream.str();
    if(mystream.str().substr(0, 4) == "-ERR"){
        cerr << "Username Error.\n";
        exit(1);
    }


    //SEND - PASS XXXXX
    request = "PASS ";
    request.append(f.authPass);
    request.append("\r\n");
    sendMessage(request);

    mystream.str("");
    mystream << receive_message();
    cout << mystream.str();
    if(mystream.str().substr(0, 4) == "-ERR"){
        cerr << "Password Error.\n";
        exit(1);
    }

    //SEND - STAT
    request = "STAT\r\n";
    sendMessage(request);

    mystream.str("");
    mystream << receive_message();
    cout << mystream.str();
    if(mystream.str().substr(0, 4) == "-ERR"){
        cerr << "Error.\n";
        exit(1);
    }


    int list = stoi(mystream.str().substr(4,1)); //pocet emailu
    int downloadCount = 0;

    if(!f.dFlag) { // Stahovani emailu
        for (int i = 1; i <= list; i++) {

            //SEND - RETR X
            request = "RETR ";
            request += to_string(i);
            request.append("\r\n");
            sendMessage(request);

            mystream.str("");
            mystream << receive_retr_message();
            if (mystream.str().substr(0, 4) == "-ERR") {
                cerr << "Downloading emails failed.\n";
                exit(1);
            }

            string message = mystream.str();
            unsigned long messageIND = message.find("\r\n"); //zacatek zpravy
            unsigned long messageIND2 = message.find("\r\n.\r\n"); //konec zpravy
            message = message.substr(messageIND, messageIND2 - messageIND);

            int iii; //TODO prejmenovat
            smatch matchResult; // Shoda
            string regExprId("message-id: <.+>"); // Regularni vyraz pro message-id.
            regex idRegex(regExprId, regex_constants::icase); // Nastaveni Case insensitive.
            iii = regex_search(message, matchResult, idRegex);
            string messageID;
            if (iii == 0) {
                messageID = "WithoutID";
                messageID += to_string(i);
            } else {
                messageID = matchResult.str().substr(13, matchResult.str().length() - 14);
            }

            if (f.nFlag) {
                if (findInFolder(&messageID)) {
                    ofstream os(f.outDir + messageID); //TODO opravit kdyz chyby lomitko, nebo to popsat v man
                    if (!os) { cerr << "Error writing to ..." << endl; } //TODO opravit kdyz neni slozka tak ji vytvor.
                    else {
                        os << message;
                        downloadCount++;
                    }
                } else {
                    continue;
                }
            }else{
                ofstream os(f.outDir + messageID); //TODO opravit kdyz chyby lomitko, nebo to popsat v man
                if (!os) { cerr << "Error writing to ..." << endl; } //TODO opravit kdyz neni slozka tak ji vytvor.
                else {
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

            //SEND - DELE XXXXX
            request = "DELE ";
            request += to_string(i);
            request.append("\r\n");
            sendMessage(request);

            mystream.str("");
            mystream << receive_message();
            cout << mystream.str();


        }
        // Mazani zprav. //TODO downloadCount
        if(list == 1){
            cout << "Smazana " << to_string(list) << " zprava.\r\n";
        }else if((list == 2) or (list == 3) or (list == 4)){
            cout << "Smazany " << to_string(list) << " zpravy.\r\n";
        }else{
            cout << "Smazano " << to_string(list) << " zprav.\r\n";
        }

    }

    //SEND - QUIT
    request = "QUIT ";
    request.append("\r\n");
    sendMessage(request);

    mystream.str("");
    mystream << receive_message();
    cout << mystream.str();
    //Ukončení spojení
    close(f.mySocket);
}

void secure() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    //SSL
    const SSL_METHOD *meth;
    SSL_CTX *ctx;

    meth = SSLv23_client_method();

    //Create a new context block
    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        cerr << "Error creating the context.\n";
        exit(1);
    }

    f.myssl = SSL_new(ctx);


 //----------------------------------------------
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
        SSL_CTX_set_default_verify_paths(ctx); //TODO handle err
    }
//-------------------------------------------------

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

int findInFolder(string *ID){
    //https://stackoverflow.com/questions/612097/how-can-i-get-the-list-of-files-in-a-directory-using-c-or-c
    DIR *dir;
    struct dirent *ent;
    string outputFolder = f.outDir; // TODO zkusit poslat rovnou do opendir
    if ((dir = opendir (outputFolder.c_str())) != nullptr) {
        // print all the files and directories within directory
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
        printf("Could not open directory.\n"); //TODO otestovat
        exit(1);
    }
}