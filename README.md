# Personalize a OPTIGA™ Trust X for Amazon AWS IoT Core

## Introduction to AWS IoT Thing Registration

Amazon AWS IoT Core provides secure, bi-directional communication between Internet-connected devices such as sensors, actuators, embedded micro-controllers, or smart appliances and the AWS Cloud. This enables collection of telemetry data from multiple devices, and store and analyze the data.

A "Thing" is added to the AWS IoT registry through a registration process.
This process consists of the following steps.
1. Create a Thing in the AWS IoT Core registry
2. Attach a digital certificate to the Thing
3. Attach a policy to the Thing or certificate.

The most important part of the "Thing" registration process is the credential registration. AWS IoT uses Public Key Cryptography for authentication and encrypting its communication channel. Each "Thing" must store their Private Key **securely**. The matching Public key must be registered with AWS IoT Core. AWS provides a method known as "Create with CSR". Using this method, a digital certificate is signed by AWS CA after verification that Public key matches the CSR digital signature. Using this process, it proves that Thing's owner indeed owns the private key without sending it over the internet.

## Trust X Personalization
Trust X can be used to securely store the AWS credential. This process is known as personalization.  
The private and public key pair is generated internally within Trust X and private key **never** leaves the secure vault.

This process can be performed using several methods:
1. [Windows](#Personalization-in-Windows-Environment)
2. [Linux (TBD)](#Personalization-in-Linux-Environment)
3. [MacOS (TBD)](#Personalization-in-MacOS-Environment)


## Personalization in Windows Environment

### Hardware and Software
* FTDI FT260S USB to I2C convertor.
* FTDI D2XX Driver [Driver for Windows](https://www.ftdichip.com/Drivers/D2XX.htm)
* An unlocked OPTIGA™ Trust X
* Windows 7 and above. Note: Windows XP not supported.

Download and run the installer [Msys2 "i686" for 32-bit Windows](https://www.msys2.org/)
*Note: Even for a 64-bit system, it is recommended to get the 32-bit installer for a better user experience.*

MSYS2 is based on Cygwin (POSIX compatibility layer) which enables Linux tools and software to be executed in Windows environment.

```Softwareinstallation
# Synchronize, download a fresh copy of the master package database and update all packages
$ pacman -Syu
```

**Note:**<br>
Likely you will see this message and will need to restart the Msys2 application.
warning: terminate MSYS2 without returning to shell and check for updates again
warning: for example close your terminal window instead of calling exit

```Softwareinstallation
# Synchronize and update all packages
$ pacman -Su

# Software tools installation
$ pacman -S base-devel gcc vim cmake git python2
```

[Install PIP instruction](https://docs.aws.amazon.com/cli/latest/userguide/install-linux.html)

```Git
# Get the latest source code from GitHub
$ git clone --recursive https://github.com/Infineon/personalize-optiga-trust-x
```

<details>
<summary>Potential error message and workaround</summary>

```console
Error Message:
$ git clone --recursive https://github.com/Infineon/personalize-optiga-trust-x
Cloning into 'personalize-optiga-trust-x'...
remote: Enumerating objects: 1087, done.
remote: Total 1087 (delta 0), reused 0 (delta 0), pack-reused 1087
Receiving objects: 100% (1087/1087), 4.59 MiB | 1.72 MiB/s, done.
Resolving deltas: 100% (365/365), done.
Checking out files: 100% (839/839), done.
Submodule 'source/optiga_trust_x' (https://github.com/Infineon/optiga-trust-x) registered for path 'source/optiga_trust_x'
Cloning into '/home/OptigaTrust/personalize-optiga-trust-x/source/optiga_trust_x'...
      1 [main] git-remote-https 3328 child_info_fork::abort: C:\msys32\usr\bin\msys-unistring-2.dll: Loaded to different address: parent(0x840000) != child(0x800000)
error: cannot fork() for fetch-pack: Resource temporarily unavailable
fatal: clone of 'https://github.com/Infineon/optiga-trust-x' into submodule path '/home/OptigaTrust/personalize-optiga-trust-x/source/optiga_trust_x' failed
Failed to clone 'source/optiga_trust_x'. Retry scheduled
Cloning into '/home/OptigaTrust/personalize-optiga-trust-x/source/optiga_trust_x'...
      1 [main] git-remote-https 3912 child_info_fork::abort: C:\msys32\usr\bin\msys-unistring-2.dll: Loaded to different address: parent(0x5B0000) != child(0x800000)
error: cannot fork() for fetch-pack: Resource temporarily unavailable
fatal: clone of 'https://github.com/Infineon/optiga-trust-x' into submodule path '/home/OptigaTrust/personalize-optiga-trust-x/source/optiga_trust_x' failed
Failed to clone 'source/optiga_trust_x' a second time, aborting

Workaround:
Close all Msys2 programs.
Execute the autorebase.bat in msys32 folder.
Re-run the git clone command.
```
</details>

## Building the Sources

```console
# Remove the pre-built binary
$ rm -Rf ../bin/libusb_win_x86/

# build the source codes
$ cd personalize-optiga-trust-x/source
$ make libusb
```


During building you should observe something similar
<details>
  <summary> Expected output of Trust X compilation</summary>

```console
$ make libusb
mkdir -p ./build
mkdir -p ./../bin/libusb_win_x86
make -C ./mbedtls-2.6.0/ no_test
make[1]: Entering directory '/home/OptigaTrust/personalize-optiga-trust-x/source/mbedtls-2.6.0'
make[2]: Entering directory '/home/OptigaTrust/personalize-optiga-trust-x/source/mbedtls-2.6.0/library'
  CC    aes.c
  CC    aesni.c
  CC    arc4.c
  CC    asn1parse.c
  CC    asn1write.c
  CC    base64.c
  CC    bignum.c
  CC    blowfish.c
  CC    camellia.c
  CC    ccm.c
  CC    cipher.c
  CC    cipher_wrap.c
  CC    cmac.c
  CC    ctr_drbg.c
  CC    des.c
  CC    dhm.c
  CC    ecdh.c
  CC    ecdsa.c
  CC    ecjpake.c
  CC    ecp.c
  CC    ecp_curves.c
  CC    entropy.c
  CC    entropy_poll.c
  CC    error.c
  CC    gcm.c
  CC    havege.c
  CC    hmac_drbg.c
  CC    md.c
  CC    md2.c
  CC    md4.c
  CC    md5.c
  CC    md_wrap.c
  CC    memory_buffer_alloc.c
  CC    oid.c
  CC    padlock.c
  CC    pem.c
  CC    pk.c
  CC    pk_wrap.c
  CC    pkcs12.c
  CC    pkcs5.c
  CC    pkparse.c
  CC    pkwrite.c
  CC    platform.c
  CC    ripemd160.c
  CC    rsa.c
  CC    sha1.c
  CC    sha256.c
  CC    sha512.c
  CC    threading.c
  CC    timing.c
  CC    version.c
  CC    version_features.c
  CC    xtea.c
  AR    libmbedcrypto.a
  RL    libmbedcrypto.a
  CC    certs.c
  CC    pkcs11.c
  CC    x509.c
  CC    x509_create.c
  CC    x509_crl.c
  CC    x509_crt.c
  CC    x509_csr.c
  CC    x509write_crt.c
  CC    x509write_csr.c
  AR    libmbedx509.a
  RL    libmbedx509.a
  CC    debug.c
  CC    net_sockets.c
  CC    ssl_cache.c
  CC    ssl_ciphersuites.c
  CC    ssl_cli.c
  CC    ssl_cookie.c
  CC    ssl_srv.c
  CC    ssl_ticket.c
  CC    ssl_tls.c
  AR    libmbedtls.a
  RL    libmbedtls.a
make[2]: Leaving directory '/home/OptigaTrust/personalize-optiga-trust-x/source/mbedtls-2.6.0/library'
make[2]: Entering directory '/home/OptigaTrust/personalize-optiga-trust-x/source/mbedtls-2.6.0/programs'
  CC    aes/aescrypt2.c
  CC    aes/crypt_and_hash.c
  CC    hash/hello.c
  CC    hash/generic_sum.c
  CC    pkey/dh_client.c
  CC    pkey/dh_genprime.c
  CC    pkey/dh_server.c
  CC    pkey/ecdh_curve25519.c
  CC    pkey/ecdsa.c
  CC    pkey/gen_key.c
  CC    pkey/key_app.c
  CC    pkey/key_app_writer.c
  CC    pkey/mpi_demo.c
  CC    pkey/pk_decrypt.c
  CC    pkey/pk_encrypt.c
  CC    pkey/pk_sign.c
  CC    pkey/pk_verify.c
  CC    pkey/rsa_genkey.c
  CC    pkey/rsa_decrypt.c
  CC    pkey/rsa_encrypt.c
  CC    pkey/rsa_sign.c
  CC    pkey/rsa_verify.c
  CC    pkey/rsa_sign_pss.c
  CC    pkey/rsa_verify_pss.c
  CC    ssl/dtls_client.c
  CC    ssl/dtls_server.c
  CC    ssl/ssl_client1.c
  CC    ssl/ssl_client2.c
  CC    ssl/ssl_server.c
  CC    ssl/ssl_server2.c
  CC    ssl/ssl_fork_server.c
  CC    ssl/mini_client.c
  CC    ssl/ssl_mail_client.c
  CC    random/gen_entropy.c
  CC    random/gen_random_havege.c
  CC    random/gen_random_ctr_drbg.c
  CC    test/ssl_cert_test.c
  CC    test/benchmark.c
  CC    test/selftest.c
  CC    test/udp_proxy.c
  CC    util/pem2der.c
  CC    util/strerror.c
  CC    x509/cert_app.c
  CC    x509/crl_app.c
  CC    x509/cert_req.c
  CC    x509/cert_write.c
  CC    x509/req_app.c
make[2]: Leaving directory '/home/OptigaTrust/personalize-optiga-trust-x/source/mbedtls-2.6.0/programs'
make[1]: Leaving directory '/home/OptigaTrust/personalize-optiga-trust-x/source/mbedtls-2.6.0'
Compiling optiga_trust_x/optiga/crypt/optiga_crypt.c
Compiling optiga_trust_x/optiga/util/optiga_util.c
Compiling optiga_trust_x/optiga/cmd/CommandLib.c
Compiling optiga_trust_x/optiga/common/Logger.c
Compiling optiga_trust_x/optiga/common/Util.c
Compiling optiga_trust_x/optiga/comms/ifx_i2c/ifx_i2c.c
Compiling optiga_trust_x/optiga/comms/ifx_i2c/ifx_i2c_config.c
Compiling optiga_trust_x/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c
Compiling optiga_trust_x/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c
Compiling optiga_trust_x/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c
Compiling json_parser/cJSON.c
Compiling json_parser/JSON_parser.c
Compiling optiga_trust_x/pal/libusb/optiga_comms_ifx_i2c_usb.c
Compiling optiga_trust_x/pal/libusb/pal_common.c
Compiling optiga_trust_x/pal/libusb/pal.c
optiga_trust_x/pal/libusb/pal.c: In function ‘pal_init’:
optiga_trust_x/pal/libusb/pal.c:84:16: warning: unused variable ‘strDesc’ [-Wunused-variable]
  unsigned char strDesc[256];
                ^~~~~~~
optiga_trust_x/pal/libusb/pal.c:83:18: warning: unused variable ‘devs’ [-Wunused-variable]
  libusb_device **devs; //pointer to pointer of device, used to retrieve a list of devices
                  ^~~~
optiga_trust_x/pal/libusb/pal.c:82:6: warning: unused variable ‘ftdi_dev’ [-Wunused-variable]
  int ftdi_dev;
      ^~~~~~~~
optiga_trust_x/pal/libusb/pal.c:81:6: warning: unused variable ‘ftdi_dev_num’ [-Wunused-variable]
  int ftdi_dev_num = 0;
      ^~~~~~~~~~~~
optiga_trust_x/pal/libusb/pal.c:80:10: warning: unused variable ‘k’ [-Wunused-variable]
  ssize_t k; //for iterating through the list
          ^
optiga_trust_x/pal/libusb/pal.c:79:10: warning: unused variable ‘number_of_connected_devices’ [-Wunused-variable]
  ssize_t number_of_connected_devices; //holding number of devices in list
          ^~~~~~~~~~~~~~~~~~~~~~~~~~~
optiga_trust_x/pal/libusb/pal.c:77:37: warning: unused variable ‘dev_desc’ [-Wunused-variable]
     struct libusb_device_descriptor dev_desc;
                                     ^~~~~~~~
Compiling optiga_trust_x/pal/libusb/pal_gpio.c
Compiling optiga_trust_x/pal/libusb/pal_i2c.c
Compiling optiga_trust_x/pal/libusb/pal_ifx_usb_config.c
Compiling optiga_trust_x/pal/libusb/pal_os_event.c
Compiling optiga_trust_x/pal/libusb/pal_os_lock.c
Compiling optiga_trust_x/pal/libusb/pal_os_timer.c
Compiling optiga_generate_csr.c
Linking build/optiga_generate_csr
Compiling optiga_upload_crt.c
optiga_upload_crt.c:426:13: warning: ‘__print_hex’ defined but not used [-Wunused-function]
 static void __print_hex (uint8_t *t)
             ^~~~~~~~~~~
Linking build/optiga_upload_crt
cp ./optiga_trust_x/pal/libusb/include/libusb-1.0.dll  ./../bin/libusb_win_x86/
cp ./build/optiga_generate_csr  ./../bin/libusb_win_x86/
cp ./build/optiga_upload_crt  ./../bin/libusb_win_x86/
```
</details>


## Creating the CSR using Trust X

```console
# Generates a CSR using Trust X secret key. The parameters of the CSR can be found in config.jsn
$ ../bin/libusb_win_x86/optiga_generate_csr -o ../IO_files/optiga.csr -i ../IO_files/config.jsn
```
* `-f /dev/i2c-1` Path to the i2c device to which # Infineon's OPTIGA&trade; Trust X is connected
* `-o optiga.csr` Path to a file where a generated Certificate Signing Request will be stored
* `-i ../IO_file/config.jsn` JSON configuration file to define your own Distinguished Name for the End-Device Certificate

Example `config.jsn`:

```json
{
	"CN":	"AWS IoT Certificate",
	"O":	"Infineon Technologies AG",
	"C":	"DE",
	"ST":	"Germany"
}
```

<details>
<summary>Expected output</summary>

```expectedoutput
$ ../bin/libusb_win_x86/optiga_generate_csr -o ../IO_files/optiga.csr -i ../IO_files/config.jsn
Data read:
{
        "CN":   "AWS IoT Certificate",
        "O":    "Infineon Technologies AG",
        "C":    "DE",
        "ST":   "Germany"
}
CN=AWS IoT Certificate,O=Infineon Technologies AG,C=DE,ST=Germany
OPTIGA(TM) Trust X initialized.
Keypair generated.
Public key is
04FC84C0634328AD8F4CA5F95F1286B01882B1EA0C26F2B7D6399B2726C009E16BC82B479CB797CF781A75AF2D57450616EB676DC493FF91DFCE1906019
  . Seeding the random number generator...
  . Checking subject name...
  . Loading the private key ...
  . Writing the certificate request ...
OPTIGA(TM) Trust X Signature generation
3045022048904CCB0A9F4E9FB42E6DFDF6138995D38720F306D77C29F3DDD0D11189AAA2022100827382A7F703C21DC9B41B9F28424D644913DC07BB45Bize 71
ok

```
</details>

<details>
<summary>Potential Error Message and Workaround</summary>

```error
$ ../bin/libusb_win_x86/optiga_generate_csr -o ../IO_files/optiga.csr -i ../IO_files/config.jsn
      4 [main] optiga_generate_csr (12728) C:\msys32\home\limtsesi\personalize-optiga-trust-x\bin\libusb_win_x86\optiga_gental error - cygheap base mismatch detected - 0x6129C408/0x612A5410.
This problem is probably due to using incompatible versions of the cygwin DLL.
Search for cygwin1.dll using the Windows Start->Find/Search facility
and delete all but the most recent version.  The most recent version *should*
reside in x:\cygwin\bin, where 'x' is the drive on which you have
installed the cygwin distribution.  Rebooting is also suggested if you
are unable to find another cygwin DLL.

Workaround:
Delete the output folder and rebuild the source code.
```
</details>


```console
# Verfies the CSR.
$ openssl req -text -noout -verify -in optiga.csr
```

<details>
<summary>Expected Output</summary>

```expected_csr
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: CN=AWS IoT Certificate, O=Infineon Technologies AG, C=DE, ST=Germany
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:fc:84:c0:63:43:28:ad:8f:4c:a5:f9:5f:12:86:
                    b0:18:82:b1:ea:0c:26:f2:b7:d6:39:9b:27:26:c0:
                    09:e1:6b:c8:2b:47:9c:b7:97:cf:78:1a:75:af:2d:
                    57:45:06:16:eb:67:6d:c4:93:ff:91:df:ce:19:06:
                    01:95:19:16:ea
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        Attributes:
        Requested Extensions:
            X509v3 Key Usage:
                Digital Signature
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:48:90:4c:cb:0a:9f:4e:9f:b4:2e:6d:fd:f6:13:
         89:95:d3:87:20:f3:06:d7:7c:29:f3:dd:d0:d1:11:89:aa:a2:
         02:21:00:82:73:82:a7:f7:03:c2:1d:c9:b4:1b:9f:28:42:4d:
         64:49:13:dc:07:bb:45:b7:4b:4e:da:5f:ba:62:31:1c:4e
verify OK

```
</details>


## Personalized Trust X

The CSR is uploaded to AWS IoT. The CSR contains a newly generated Public Key with matching Secret Key which is stored in Trust X. The AWS IoT Core will receive the CSR and verify it against the signature. Once, the AWS IoT Core verified the signature, it will uses the AWS CA to generate a digital certificate. Trust X will store this certificate in its Certificate slot.

Checks the version of the AWS CLI to make sure that it has been installed.
```console
$ aws --version
aws-cli/1.15.78 Python/2.7.14 Windows/10 botocore/1.10.77
```

Checks the current endpoint address
```console
$ aws iot describe-endpoint
{
    "endpointAddress": "a26ch0cchp0v7h.iot.us-west-2.amazonaws.com"
}
```

Gets the certificate ARN. Record the ARN locally. ARN uniquely identifies the uploaded certificate.
$ aws iot create-certificate-from-csr --region us-west-2 --certificate-signing-request file://optiga.csr --set-as-active --le optiga.pem --query certificateArn > optiga.aws_arn

```console
# Upload the CSR, retrieve the digital certificate signed by AWS CA and stored in Trust X
$ ../bin/libusb_win_x86/optiga_upload_crt.exe -f /dev/i2c-0 -c optiga.pem
```
* `-f /dev/i2c-1` Path to the i2c device to which # Infineon's OPTIGA&trade; Trust X is connected
* `-c certificate_in_pem.pem` PEM encoded certificate which you want to upload to the device
* `-0 0xE0E1` Optional parameter which defines in which Object ID to write the given certificate

<details>
<summary>Expected Output</summary>

```output
OPTIGA(TM) Trust X initialized.

********************    Parsing certificate     ********************
cert. version     : 3
serial number     : 46:90:F7:C5:84:90:6E:2C:07:51:4F:E0:D1:AA:4F:F5:2D:2A:3F:8E
issuer name       : OU=Amazon Web Services O=Amazon.com Inc. L=Seattle ST=Washington C=US
subject name      : CN=AWS IoT Certificate, O=Infineon Technologies AG, C=DE, ST=Germany
issued  on        : 2019-04-11 08:22:11
expires on        : 2049-12-31 23:59:59
signed using      : RSA with SHA-256
EC key size       : 256 bits
basic constraints : CA=false
key usage         : Digital Signature

********************    Certificate read        ********************
-----BEGIN CERTIFICATE-----
MIIC0DCCAbigAwIBAgIURpD3xYSQbiwHUU/g0apP9S0qP44wDQYJKoZIhvcNAQEL
BQAwTTFLMEkGA1UECwxCQW1hem9uIFdlYiBTZXJ2aWNlcyBPPUFtYXpvbi5jb20g
SW5jLiBMPVNlYXR0bGUgU1Q9V2FzaGluZ3RvbiBDPVVTMB4XDTE5MDQxMTA4MjIx
MVoXDTQ5MTIzMTIzNTk1OVowYDEcMBoGA1UEAxMTQVdTIElvVCBDZXJ0aWZpY2F0
ZTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHR2VybWFueTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPyE
wGNDKK2PTKX5XxKGsBiCseoMJvK31jmbJybACeFryCtHnLeXz3gada8tV0UGFutn
bcST/5HfzhkGAZUZFuqjYDBeMB8GA1UdIwQYMBaAFFVvnDHFMzD/EWP61GAF60/y
nNypMB0GA1UdDgQWBBTDVQAi4jLHfu0x2HRmPVzRo+VNdzAMBgNVHRMBAf8EAjAA
MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAXiLp+A4EY6hNBxEi
7XxKuGD9Vu9k56F141unPu5DRfp99zMt3Lu95Zryuzwkmu55NJpoo7lWobLMvgH5
REIf2LTDXnSwxfiR2ir0gEY9gGZC8T5HIAtahyH1Wk0C4ETHAD9Ro0TUpoFTFsQv
ZDog9D16k8Gh3Tk9AHdJs1k7PNHvdL1VspEo1kMLE0PDAdztj1+fKu9LZizRke8/
BDxNaa212j7YkIw001/2n37WVr1+9vMenvaWD/2z/OqWgR5LBfC9sfzgXCmvZQIQ
EePEgxPTJFE99K/WQFPcZOPovuZgD5twn/xp0vc/8RhhdPob6gU67npJyf5yxUgW
TiTNmw==
-----END CERTIFICATE-----


********************    Writing certificate     ********************
0x000000: c0 02 da 00 02 d7 00 02 d4 30 82 02 d0 30 82 01 .........0...0..
0x000010: b8 a0 03 02 01 02 02 14 46 90 f7 c5 84 90 6e 2c ........F.....n,
0x000020: 07 51 4f e0 d1 aa 4f f5 2d 2a 3f 8e 30 0d 06 09 .QO...O.-*?.0...
0x000030: 2a 86 48 86 f7 0d 01 01 0b 05 00 30 4d 31 4b 30 *.H........0M1K0
0x000040: 49 06 03 55 04 0b 0c 42 41 6d 61 7a 6f 6e 20 57 I..U...BAmazon W
0x000050: 65 62 20 53 65 72 76 69 63 65 73 20 4f 3d 41 6d eb Services O=Am
0x000060: 61 7a 6f 6e 2e 63 6f 6d 20 49 6e 63 2e 20 4c 3d azon.com Inc. L=
0x000070: 53 65 61 74 74 6c 65 20 53 54 3d 57 61 73 68 69 Seattle ST=Washi
0x000080: 6e 67 74 6f 6e 20 43 3d 55 53 30 1e 17 0d 31 39 ngton C=US0...19
0x000090: 30 34 31 31 30 38 32 32 31 31 5a 17 0d 34 39 31 0411082211Z..491
0x0000a0: 32 33 31 32 33 35 39 35 39 5a 30 60 31 1c 30 1a 231235959Z0`1.0.
0x0000b0: 06 03 55 04 03 13 13 41 57 53 20 49 6f 54 20 43 ..U....AWS IoT C
0x0000c0: 65 72 74 69 66 69 63 61 74 65 31 21 30 1f 06 03 ertificate1!0...
0x0000d0: 55 04 0a 13 18 49 6e 66 69 6e 65 6f 6e 20 54 65 U....Infineon Te
0x0000e0: 63 68 6e 6f 6c 6f 67 69 65 73 20 41 47 31 0b 30 chnologies AG1.0
0x0000f0: 09 06 03 55 04 06 13 02 44 45 31 10 30 0e 06 03 ...U....DE1.0...
0x000100: 55 04 08 13 07 47 65 72 6d 61 6e 79 30 59 30 13 U....Germany0Y0.
0x000110: 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d ..*.H.=....*.H.=
0x000120: 03 01 07 03 42 00 04 fc 84 c0 63 43 28 ad 8f 4c ....B.....cC(..L
0x000130: a5 f9 5f 12 86 b0 18 82 b1 ea 0c 26 f2 b7 d6 39 .._........&...9
0x000140: 9b 27 26 c0 09 e1 6b c8 2b 47 9c b7 97 cf 78 1a .'&...k.+G....x.
0x000150: 75 af 2d 57 45 06 16 eb 67 6d c4 93 ff 91 df ce u.-WE...gm......
0x000160: 19 06 01 95 19 16 ea a3 60 30 5e 30 1f 06 03 55 ........`0^0...U
0x000170: 1d 23 04 18 30 16 80 14 55 6f 9c 31 c5 33 30 ff .#..0...Uo.1.30.
0x000180: 11 63 fa d4 60 05 eb 4f f2 9c dc a9 30 1d 06 03 .c..`..O....0...
0x000190: 55 1d 0e 04 16 04 14 c3 55 00 22 e2 32 c7 7e ed U.......U.".2.~.
0x0001a0: 31 d8 74 66 3d 5c d1 a3 e5 4d 77 30 0c 06 03 55 1.tf=\...Mw0...U
0x0001b0: 1d 13 01 01 ff 04 02 30 00 30 0e 06 03 55 1d 0f .......0.0...U..
0x0001c0: 01 01 ff 04 04 03 02 07 80 30 0d 06 09 2a 86 48 .........0...*.H
0x0001d0: 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 5e 22 e9 .............^".
0x0001e0: f8 0e 04 63 a8 4d 07 11 22 ed 7c 4a b8 60 fd 56 ...c.M..".|J.`.V
0x0001f0: ef 64 e7 a1 75 e3 5b a7 3e ee 43 45 fa 7d f7 33 .d..u.[.>.CE.}.3
0x000200: 2d dc bb bd e5 9a f2 bb 3c 24 9a ee 79 34 9a 68 -.......<$..y4.h
0x000210: a3 b9 56 a1 b2 cc be 01 f9 44 42 1f d8 b4 c3 5e ..V......DB....^
0x000220: 74 b0 c5 f8 91 da 2a f4 80 46 3d 80 66 42 f1 3e t.....*..F=.fB.>
0x000230: 47 20 0b 5a 87 21 f5 5a 4d 02 e0 44 c7 00 3f 51 G .Z.!.ZM..D..?Q
0x000240: a3 44 d4 a6 81 53 16 c4 2f 64 3a 20 f4 3d 7a 93 .D...S../d: .=z.
0x000250: c1 a1 dd 39 3d 00 77 49 b3 59 3b 3c d1 ef 74 bd ...9=.wI.Y;<..t.
0x000260: 55 b2 91 28 d6 43 0b 13 43 c3 01 dc ed 8f 5f 9f U..(.C..C....._.
0x000270: 2a ef 4b 66 2c d1 91 ef 3f 04 3c 4d 69 ad b5 da *.Kf,...?.<Mi...
0x000280: 3e d8 90 8c 34 d3 5f f6 9f 7e d6 56 bd 7e f6 f3 >...4._..~.V.~..
0x000290: 1e 9e f6 96 0f fd b3 fc ea 96 81 1e 4b 05 f0 bd ............K...
0x0002a0: b1 fc e0 5c 29 af 65 02 10 11 e3 c4 83 13 d3 24 ...\).e........$
0x0002b0: 51 3d f4 af d6 40 53 dc 64 e3 e8 be e6 60 0f 9b Q=...@S.d....`..
0x0002c0: 70 9f fc 69 d2 f7 3f f1 18 61 74 fa 1b ea 05 3a p..i..?..at....:
0x0002d0: ee 7a 49 c9 fe 72 c5 48 16 4e 24 cd 9b          .zI..r.H.N$..

Certificate successfully written

```
</details>

<br>
At this stage, Trust X has completed the personalization process.

[Continues the AWS Thing registration using AWS CLI](#Thing-Registration-using-AWS-CLI)

## Personalization in Linux Environment
TBD

## Personalization in MacOS Environment
TBD

## Thing Registration using AWS CLI
Creates a Thing called “IoT_Object_With_Trust_X” and register on AWS IoT Core Registry

```create_thing
$ aws iot create-thing --thing-name "IoT_Object_With_Trust_X"
{
    "thingArn": "arn:aws:iot:us-west-2:065398228892:thing/IoT_Object_With_Trust_X",
    "thingName": "IoT_Object_With_Trust_X",
    "thingId": "9208211e-9657-4e6c-84f5-56e1f26c9704"
}
```

Creates a temporary variable that stores the ARN.
Attach the Thing to the certificate.

```attach_thing
$ cd ../IO_files

$ export AWS_ARN=$(sed 's/.//;s/.$//' optiga.aws_arn)

$ echo $AWS_ARN
arn:aws:iot:us-west-2:065398228892:cert/8f2989f94682a7ed15f0a5e6d9e18479fc2c5dd07365dfb0aefbe91e291584aa

$ aws iot attach-thing-principal --thing-name "IoT_Object_With_Trust_X" --principal $AWS_ARN

```

A rather dumb method to attach the policy using the console.<br>
**Note:** This is a very insecure policy and should be improved.

```policy
$ echo "{" >> IoT_Thing_Weak_Policy&&
> echo "  \"Version\": \"2012-10-17\",">> IoT_Thing_Weak_Policy&&
> echo "  \"Statement\": [">> IoT_Thing_Weak_Policy&&
> echo "    {">> IoT_Thing_Weak_Policy&&
> echo "      \"Effect\": \"Allow\",">> IoT_Thing_Weak_Policy&&
> echo "      \"Action\": \"iot:*\",">> IoT_Thing_Weak_Policy&&
> echo "      \"Resource\": \"*\"">> IoT_Thing_Weak_Policy&&
> echo "    }">> IoT_Thing_Weak_Policy&&
> echo "  ]">> IoT_Thing_Weak_Policy&&
> echo "}">> IoT_Thing_Weak_Policy

$ aws iot create-policy --policy-name IoT_Thing_Weak_Policy --policy-document file://IoT_Thing_Weak_Policy
{
    "policyName": "IoT_Thing_Weak_Policy",
    "policyArn": "arn:aws:iot:us-west-2:065398228892:policy/IoT_Thing_Weak_Policy",
    "policyDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"  }\n  ]\n}\n",
    "policyVersionId": "1"
}

$ aws iot attach-principal-policy --policy-name "IoT_Thing_Weak_Policy" --principal $AWS_ARN

```

## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
