#include <botan/x509_ca.h>
#include <botan/x509cert.h>
#include <botan/x509self.h>
#include <botan/rsa.h>
#include <botan/pk_keys.h>
#include <botan/bigint.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h> // bug: botan 2.12.1 does a sizeof for (unknown) PK_Signer when using X509CA
#include <botan/pkcs8.h>

#include <sys/stat.h> // mkdir
#include <stdio.h>
#include <string>
#include <memory>
#include <vector>
#include <unistd.h> // grr..


using namespace Botan;


int main(int argc, char **argv)
{
  puts("fast-ca");


#warning TODO: !
  std::string pwd = "test123"; 



  if (access("ca.crt", F_OK) == -1)
  {
    AutoSeeded_RNG rng;

    puts("creating root keys ...");
    RSA_PrivateKey rootCertPrivKey(rng, 4096);


    std::vector<uint8_t> rootCertPrivKeyData = PKCS8::BER_encode(rootCertPrivKey, rng, pwd);//, "PBES2(CIPHER,PBKDF)");

    FILE *f = fopen("./ca.pem", "w");

    if (!f)
    {
      puts("writing root keys failed!");
      return -1;
    }

    
    size_t wrote = fwrite(rootCertPrivKeyData.data(), 1, rootCertPrivKeyData.size(), f);

    //printf("wrote %zu bytes\n", wrote);

    fclose(f);



    X509_Cert_Options opts("");

    opts.common_name = "fast-ca Root Certificate";
    opts.country = "TODO";
    //opts.dns
    //opts.set_padding_scheme()
    opts.CA_key(1);

    puts("creating root certificate ...");
    X509_Certificate rootCert = X509::create_self_signed_cert(opts, rootCertPrivKey, "SHA-256", rng);


    puts("writing root certificate ...");
    std::vector<uint8_t> rootCertData(rootCert.BER_encode());


    f = fopen("./ca.crt", "w");

    if (!f)
    {
      puts("writing ca certificate failed!");
      return -1;
    }

    //size_t wrote = 
    fwrite(rootCertData.data(), 1, rootCertData.size(), f);

    //printf("wrote %zu bytes\n", wrote);

    fclose(f);

    puts("CA initialized");
  }
  


  if (argc < 2)
  {
    printf("usage: %s <fqdn>\n", argv[0]);
    return -1;
  }


  
  puts("loading ca certificate ...");
  X509_Certificate caCert = X509_Certificate("./ca.crt");

  AutoSeeded_RNG rng;
  puts("loading ca keys ...");
  Private_Key *caPrivKey = PKCS8::load_key("./ca.pem", rng, pwd);


  puts("initializing ca ...");
  X509_CA ca = X509_CA(caCert, *caPrivKey, "SHA-256", rng);

  // TODO: free caPrivKey


  puts("creating client keys ...");
  RSA_PrivateKey privKey = RSA_PrivateKey(rng, 4096);




  std::string fqdn(argv[1]);

  secure_vector<uint8_t> privKeyData = PKCS8::BER_encode(privKey);

  int status = mkdir(argv[1], S_IRWXU | S_IRWXG);
  printf("mkdir status: %d\n", status);

  std::string privKeyDataPath("./" + fqdn + "/" + fqdn + ".pem");
  FILE *f = fopen(privKeyDataPath.c_str(), "w");

  if (!f)
  {
    puts("writing client keys failed!");
    return -1;
  }
  
  puts("writing client keys ...");
  size_t wrote = fwrite(privKeyData.data(), 1, privKeyData.size(), f);

  //printf("wrote %zu bytes\n", wrote);

  fclose(f);





  puts("creating client certificate request ...");

  X509_Cert_Options opts("");
  
  // TODO: !
  opts.common_name = "TODO";
  opts.country = "TODO";
  opts.dns = "test.wille.io";

  PKCS10_Request request = X509::create_cert_req(opts, privKey, "SHA-256", rng);


  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();


  puts("creating client certificate ...");
  X509_Certificate cert = ca.sign_request(request, rng, X509_Time(now), 
                          X509_Time(now + std::chrono::hours(8760)));
  std::vector<uint8_t> certData = cert.BER_encode();



  std::string certDataPath("./" + fqdn + "/" + fqdn + ".crt");
  f = fopen(certDataPath.c_str(), "w");

  if (!f)
  {
    puts("writing client certificate failed!");
    return -1;
  }
  
  puts("writing client certificate ...");
  wrote = fwrite(certData.data(), 1, certData.size(), f);

  //printf("wrote %zu bytes\n", wrote);

  fclose(f);                        


  puts("done!");




  return 0;
}