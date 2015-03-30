#TLS Client/Server - 4180 Homework 2
### Miguel A. Yanez - may2114
Program was implemented using Python with the following dependencies:
`pycrypto`, `pyopenssl`, `requests`, `ushlex`. `pycrypto` is used for AES encrytion/decryption. `pyopenssl` is used for TLS/SSL sockets. `requests` is used for `HTTP` protocol handling. `ushlex` is used for command parsing.

##HOW TO RUN

Included are 4 `Makefiles`.

1. Run `make` in the top level directory. This will install the required dependencies.
2. Go to the `certs` directory and run `make ca-cert`, `make server-cert`, `make client-cert`. This will then walk you through the certificate creation process.
3. Run `make` in both the `client` and `server` directories in two separate terminal windows. These will run both the client and server with default values. You may use this to test.

##Structure
The program uses the `HTTP` protocol to communicate over `TLS`. This allows one to focus on the `TLS` portion of the communication without having to deal with basic protocol handling. The server enhances Python's built in `BaseHTTPServer` to support the required functionality. Similarly, the client takes advantage of the `requests` library to communicate using `HTTP`.

##Certificates
Certificates where generated using `openssl`. There are various make targets inside the `certs` directory that generate the required certificates.

##Documentation
Run `make docs` in the top-level directory.