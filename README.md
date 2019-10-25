![fast-ca logo](https://wille.io/fast-ca.png "fast-ca logo")
# fast-ca

fast-ca is a minimalistic tool to create a local certificate authority and signed certificates in one simple command.
Use fast-ca to ... :

  - rapid prototype a public key encryption protected network
  - create a production ready secured private network with sane default options
  - have your websites in your own network encrypted to prevent password theft
  - and my more ...

### Sane defaults

fast-ca creates private keys with RSA and 4096 bits. The CA's certificate is hashed with SHA-256.
Common name and the DNS field are set to the FQDN, making the generated certificated usable in every (modern) browser.

### Installation

fast-ca requires [botan-2](https://botan.randombit.net/) to compile & run.
Use the one-line compilation script to generate the fast-ca executable:

```sh
$ ./compile.sh
```

### Usage

To create a certificate for a FQDN, just run fast-ca with the FQDN as parameter.

```sh
$ ./fastca test.example.com
```

If you run fast-ca for the first time, a new CA certificate including its corresponding private key is generated prior to generating the client certificate. For the CA private key generation, fast-ca aks for a password to encrypt the private key.

License
----

MIT
