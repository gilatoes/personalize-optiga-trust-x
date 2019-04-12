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
$ pacman -S base-devel gcc vim cmake git
```

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
pi@raspberrypi:~/personalize-optiga-trust-x/executables $ ./optiga_upload_crt -f /dev/i2c-1 -c certificate_in_der.der -o 0xE0E1
```
* `-f /dev/i2c-1` Path to the i2c device to which # Infineon's OPTIGA&trade; Trust X is connected
* `-c certificate_in_der.der` DER encoded certificate which you want to upload to the device
* `-0 0xE0E1` Optional parameter which defines in which Obejct ID to write the given certificate

In order to convert PEM encoded certificate into DER encoded certificate you can use the following command

```console
pi@raspberrypi:~/personalize-optiga-trust-x/executables $ openssl x509 -in certificate_in_pem.pem -inform PEM -out certificate_in_der.der -outform DER

```

## Personalization in Linux Environment
TBD

## Personalization in MacOS Environment
TBD

## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
