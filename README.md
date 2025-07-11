# SCHOOL PROJECT

Description:
Popcl program that allows you to read e-mail via POP3. The program will download after startup
the messages stored on the server and saves them to the specified directory and displays the number of downloaded messages on the standard output.
Using additional parameters will change the functionality of the program.


Extension:
Combination of parameters '-n' and '-d'. Removes messages from the server that are not stored in the output directory.


Example:
popcl <server> [-p <port>] [-T/-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <authfile> -o <outdir>
popcl pop3.seznam.cz -a ./auth -o ./out -n -d -p 110 
 
Parameters:
<server>  -  Mandatory  - Required is the <server> name (IP address or domain name) of the requested resource.

[-p <port>]  -  Optional  - Specifies the port number <port> on the server.

-T  -  Optional  - Establishes encryption of the entire communication.

-S  -  Optional  -  Establishes an unencrypted connection to the server and switches to an encrypted protocol variant.

[-c <certfile>]  -  Optional  -  Defines the <certfile> certificate file to be used to validate the SSL / TLS certificate validity submitted by the server (use only with -T or -S).

[-C <certaddr>]  -  Optional  -  Specifies the <certaddr> directory in which to search for the certificates to be used to validate the SSL / TLS certificate validity submitted by the server (use only with -T or -S).

[-d]  -  Optional  - Deleting messages on the server.

[-n]  -  Optional  - Work only with new messages.

-a <auth_file>  -  Mandatory  -  Authentication file.
username = XXX
password = YYY

-o <out_dir>  -  Mandatory  - Output directory <out_dir> to which the downloaded message program has to be saved.


All files:
Makefile
main.cpp
manual.pdf

Author:
Rostislav Navratil - xnavra57
