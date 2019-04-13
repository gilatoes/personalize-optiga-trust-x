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

### Hardware
* FTDI FT260S USB to I2C convertor.
* FTDI D2XX Driver [Driver for Windows](https://www.ftdichip.com/Drivers/D2XX.htm)
* An unlocked OPTIGA™ Trust X
* Windows 7 and above. Note: Windows XP not supported.

### Preparing the Software Environment within MSYS2

Download and run the installer [Msys2 "i686" for 32-bit Windows](https://www.msys2.org/)
*Note: Even for a 64-bit system, it is recommended to get the 32-bit installer for a better user experience.*

MSYS2 is based on Cygwin (POSIX compatibility layer) which enables Linux tools and software to be executed in Windows environment.<br>

In the following instruction, "#" is the comments within the console which explains the meaning of the following command. Meanwhile, "$" is the command prompt followed by the console command. Note that the "$" is not required to be entered as the command.  

```Installation
# Synchronize, download a fresh copy of the master package database and update all packages
$ pacman -Syu
```

**Note:**<br>
Refers to the output and you will need to restart the Msys2 application.

<details>
<summary>Expected Output</summary>

```console
$ pacman -Syu
:: Synchronizing package databases...
 mingw32                                  542.1 KiB   45
 mingw32.sig                              119.0   B  0.0
 mingw64                                  543.0 KiB   97
 mingw64.sig                              119.0   B  0.0
 msys                                     180.4 KiB  187
 msys.sig                                 119.0   B  0.0
:: Starting core system upgrade...
warning: terminate other MSYS2 programs before proceedin
resolving dependencies...
looking for conflicting packages...

Packages (6) bash-4.4.023-1  filesystem-2018.12-1  mintt
             pacman-mirrors-20180604-2

Total Download Size:   20.37 MiB
Total Installed Size:  69.39 MiB
Net Upgrade Size:      13.06 MiB

:: Proceed with installation? [Y/n] Y
:: Retrieving packages...
 msys2-runtime-2.11.2-1-i686                2.4 MiB   69
 bash-4.4.023-1-i686                     1931.4 KiB   48
 filesystem-2018.12-1-i686                 37.8 KiB  4.6
 mintty-1~2.9.5-1-i686                    285.5 KiB   56
 pacman-mirrors-20180604-2-any             10.7 KiB  3.4
 pacman-5.1.2-2-i686       15.8 MiB   324K/s 00:50 100%9
(6/6) checking keys in keyring                     100%
(6/6) checking package integrity                   100%
(6/6) loading package files                        100%
(6/6) checking for file conflicts                  100%
(6/6) checking available disk space                100%
warning: could not get file information for opt/
:: Processing package changes...
(1/6) upgrading msys2-runtime                      100%
(2/6) upgrading bash                               100%
(3/6) upgrading filesystem                         100%
(4/6) upgrading mintty                             100%
(5/6) upgrading pacman-mirrors                     100%
(6/6) upgrading pacman                             100%
warning: terminate MSYS2 without returning to shell and check for updates again
warning: for example close your terminal window instead of calling exit

```
</details>

---

```Installation
# Synchronize and update all packages
$ pacman -Su
```
<details>
<summary>Expected Output</summary>

```console
$$ pacman -Su
:: Starting core system upgrade...
 there is nothing to do
:: Starting full system upgrade...
resolving dependencies...
looking for conflicting packages...

Packages (62) bash-completion-2.8-2  brotli-1.0.7-1  bsdcpio-3.3.3-3  bsdtar-3.3.3-3
              ca-certificates-20180409-1  coreutils-8.30-1  curl-7.64.0-2  dash-0.5.10.2-1  dtc-1.4.7-1
              glib2-2.54.3-1  gnupg-2.2.13-1  gzip-1.10-1  heimdal-libs-7.5.0-3  icu-62.1-1  info-6.5-2
              less-530-1  libarchive-3.3.3-3  libargp-20110921-2  libassuan-2.5.3-1  libcrypt-2.1-2
              libcurl-7.64.0-2  libexpat-2.2.6-1  libffi-3.2.1-3  libgcrypt-1.8.4-1  libgnutls-3.6.6-2
              libgpg-error-1.35-1  libgpgme-1.12.0-1  libhogweed-3.4.1-1  libidn2-2.1.1a-1  libksba-1.3.5-1
              liblz4-1.8.3-1  liblzma-5.2.4-1  liblzo2-2.10-2  libnettle-3.4.1-1  libnghttp2-1.36.0-1
              libnpth-1.6-1  libopenssl-1.1.1.b-1  libp11-kit-0.23.15-1  libpcre-8.43-1  libpcre16-8.43-1
              libpcre32-8.43-1  libpcrecpp-8.43-1  libpcreposix-8.43-1  libpsl-0.20.2-3  libreadline-7.0.005-1
              libsqlite-3.21.0-4  libssh2-1.8.0-2  libunistring-0.9.10-1  libutil-linux-2.32.1-1
              libxml2-2.9.9-2  libxslt-1.1.33-2  mpfr-4.0.2-1  ncurses-6.1.20180908-1  nettle-3.4.1-1
              openssl-1.1.1.b-1  p11-kit-0.23.15-1  pcre-8.43-1  pinentry-1.1.0-2  rebase-4.4.4-1  time-1.9-1
              util-linux-2.32.1-1  xz-5.2.4-1

Total Download Size:    33.18 MiB
Total Installed Size:  188.92 MiB
Net Upgrade Size:       61.26 MiB

:: Proceed with installation? [Y/n] Y
:: Retrieving packages...
 bash-completion-2.8-2-any                190.0 KiB   195K/s 00:01 [####################################] 100%
 libexpat-2.2.6-1-i686                     63.1 KiB   120K/s 00:01 [####################################] 100%
 liblzma-5.2.4-1-i686                      82.1 KiB   153K/s 00:01 [####################################] 100%
 liblz4-1.8.3-1-i686                       57.3 KiB   207K/s 00:00 [####################################] 100%
 liblzo2-2.10-2-i686                       70.4 KiB   249K/s 00:00 [####################################] 100%
 libhogweed-3.4.1-1-i686                  140.4 KiB   186K/s 00:01 [####################################] 100%
 libnettle-3.4.1-1-i686                   106.8 KiB   205K/s 00:01 [####################################] 100%
 coreutils-8.30-1-i686                      2.3 MiB   122K/s 00:20 [####################################] 100%
 icu-62.1-1-i686                            7.6 MiB   449K/s 00:17 [####################################] 100%
 ncurses-6.1.20180908-1-i686             1310.9 KiB  1351K/s 00:01 [####################################] 100%
 libreadline-7.0.005-1-i686               267.0 KiB   220K/s 00:01 [####################################] 100%
 libxml2-2.9.9-2-i686                     508.8 KiB   189K/s 00:03 [####################################] 100%
 bsdcpio-3.3.3-3-i686                     814.4 KiB   379K/s 00:02 [####################################] 100%
 bsdtar-3.3.3-3-i686                      855.5 KiB   584K/s 00:01 [####################################] 100%
 libopenssl-1.1.1.b-1-i686               1079.3 KiB   751K/s 00:01 [####################################] 100%
 openssl-1.1.1.b-1-i686                     2.8 MiB   660K/s 00:04 [####################################] 100%
 libffi-3.2.1-3-i686                       35.3 KiB  4.31M/s 00:00 [####################################] 100%
 libgpg-error-1.35-1-i686                 150.0 KiB  4.31M/s 00:00 [####################################] 100%
 libgcrypt-1.8.4-1-i686                   432.3 KiB   587K/s 00:01 [####################################] 100%
 libxslt-1.1.33-2-i686                    139.9 KiB   569K/s 00:00 [####################################] 100%
 libpcre-8.43-1-i686                       93.3 KiB  3.65M/s 00:00 [####################################] 100%
 glib2-2.54.3-1-i686                     1895.7 KiB   614K/s 00:03 [####################################] 100%
 libcrypt-2.1-2-i686                       29.5 KiB  2.88M/s 00:00 [####################################] 100%
 less-530-1-i686                          104.0 KiB  5.35M/s 00:00 [####################################] 100%
 gzip-1.10-1-i686                          91.1 KiB  3.71M/s 00:00 [####################################] 100%
 info-6.5-2-i686                          172.5 KiB   719K/s 00:00 [####################################] 100%
 libp11-kit-0.23.15-1-i686                140.8 KiB   589K/s 00:00 [####################################] 100%
 p11-kit-0.23.15-1-i686                   220.3 KiB   831K/s 00:00 [####################################] 100%
 ca-certificates-20180409-1-any           345.0 KiB   704K/s 00:00 [####################################] 100%
 brotli-1.0.7-1-i686                      277.9 KiB  1037K/s 00:00 [####################################] 100%
 libsqlite-3.21.0-4-i686                  589.8 KiB   789K/s 00:01 [####################################] 100%
 heimdal-libs-7.5.0-3-i686                767.9 KiB   773K/s 00:01 [####################################] 100%
 libunistring-0.9.10-1-i686               526.9 KiB   735K/s 00:01 [####################################] 100%
 libidn2-2.1.1a-1-i686                     93.3 KiB  4.34M/s 00:00 [####################################] 100%
 libnghttp2-1.36.0-1-i686                  66.7 KiB  4.35M/s 00:00 [####################################] 100%
 libpsl-0.20.2-3-i686                      70.4 KiB  3.82M/s 00:00 [####################################] 100%
 libssh2-1.8.0-2-i686                     172.5 KiB   722K/s 00:00 [####################################] 100%
 libcurl-7.64.0-2-i686                    249.0 KiB   973K/s 00:00 [####################################] 100%
 curl-7.64.0-2-i686                       782.5 KiB   818K/s 00:01 [####################################] 100%
 dash-0.5.10.2-1-i686                      78.2 KiB  3.82M/s 00:00 [####################################] 100%
 dtc-1.4.7-1-i686                          88.5 KiB  3.46M/s 00:00 [####################################] 100%
 libassuan-2.5.3-1-i686                    96.4 KiB  4.71M/s 00:00 [####################################] 100%
 libgnutls-3.6.6-2-i686                  1150.1 KiB   954K/s 00:01 [####################################] 100%
 libksba-1.3.5-1-i686                     114.2 KiB  3.60M/s 00:00 [####################################] 100%
 libnpth-1.6-1-i686                        15.6 KiB  7.60M/s 00:00 [####################################] 100%
 nettle-3.4.1-1-i686                       90.6 KiB  4.43M/s 00:00 [####################################] 100%
 pinentry-1.1.0-2-i686                     52.5 KiB  3.01M/s 00:00 [####################################] 100%
 gnupg-2.2.13-1-i686                     1948.8 KiB   797K/s 00:02 [####################################] 100%
 libarchive-3.3.3-3-i686                  809.7 KiB   805K/s 00:01 [####################################] 100%
 libargp-20110921-2-i686                   43.5 KiB  5.31M/s 00:00 [####################################] 100%
 libgpgme-1.12.0-1-i686                   337.0 KiB   649K/s 00:01 [####################################] 100%
 libpcre16-8.43-1-i686                     90.4 KiB  4.41M/s 00:00 [####################################] 100%
 libpcre32-8.43-1-i686                     85.3 KiB  4.63M/s 00:00 [####################################] 100%
 libpcrecpp-8.43-1-i686                    22.6 KiB  5.53M/s 00:00 [####################################] 100%
 libpcreposix-8.43-1-i686                  15.3 KiB  4.97M/s 00:00 [####################################] 100%
 libutil-linux-2.32.1-1-i686              253.2 KiB   530K/s 00:00 [####################################] 100%
 mpfr-4.0.2-1-i686                        285.1 KiB   401K/s 00:01 [####################################] 100%
 pcre-8.43-1-i686                         587.5 KiB   492K/s 00:01 [####################################] 100%
 rebase-4.4.4-1-i686                      245.1 KiB   518K/s 00:00 [####################################] 100%
 time-1.9-1-i686                           32.2 KiB  3.94M/s 00:00 [####################################] 100%
 util-linux-2.32.1-1-i686                1360.8 KiB   476K/s 00:03 [####################################] 100%
 xz-5.2.4-1-i686                          145.4 KiB   593K/s 00:00 [####################################] 100%
(62/62) checking keys in keyring                                   [####################################] 100%
(62/62) checking package integrity                                 [####################################] 100%
(62/62) loading package files                                      [####################################] 100%
(62/62) checking for file conflicts                                [####################################] 100%
(62/62) checking available disk space                              [####################################] 100%
warning: could not get file information for autorebasebase1st.bat
:: Processing package changes...
( 1/62) upgrading bash-completion                                  [####################################] 100%
( 2/62) upgrading libexpat                                         [####################################] 100%
( 3/62) upgrading liblzma                                          [####################################] 100%
( 4/62) installing liblz4                                          [####################################] 100%
( 5/62) upgrading liblzo2                                          [####################################] 100%
( 6/62) installing libhogweed                                      [####################################] 100%
( 7/62) upgrading libnettle                                        [####################################] 100%
( 8/62) upgrading coreutils                                        [####################################] 100%
( 9/62) upgrading icu                                              [####################################] 100%
(10/62) upgrading ncurses                                          [####################################] 100%
(11/62) upgrading libreadline                                      [####################################] 100%
(12/62) upgrading libxml2                                          [####################################] 100%
(13/62) upgrading bsdcpio                                          [####################################] 100%
(14/62) upgrading bsdtar                                           [####################################] 100%
(15/62) upgrading libopenssl                                       [####################################] 100%
(16/62) upgrading openssl                                          [####################################] 100%
(17/62) upgrading libffi                                           [####################################] 100%
(18/62) upgrading libgpg-error                                     [####################################] 100%
(19/62) upgrading libgcrypt                                        [####################################] 100%
(20/62) upgrading libxslt                                          [####################################] 100%
(21/62) upgrading libpcre                                          [####################################] 100%
(22/62) upgrading glib2                                            [####################################] 100%
(23/62) upgrading libcrypt                                         [####################################] 100%
(24/62) upgrading less                                             [####################################] 100%
(25/62) upgrading gzip                                             [####################################] 100%
(26/62) upgrading info                                             [####################################] 100%
(27/62) upgrading libp11-kit                                       [####################################] 100%
(28/62) upgrading p11-kit                                          [####################################] 100%
(29/62) upgrading ca-certificates                                  [####################################] 100%
(30/62) installing brotli                                          [####################################] 100%
(31/62) upgrading libsqlite                                        [####################################] 100%
(32/62) upgrading heimdal-libs                                     [####################################] 100%
(33/62) upgrading libunistring                                     [####################################] 100%
(34/62) upgrading libidn2                                          [####################################] 100%
(35/62) upgrading libnghttp2                                       [####################################] 100%
(36/62) upgrading libpsl                                           [####################################] 100%
(37/62) upgrading libssh2                                          [####################################] 100%
(38/62) upgrading libcurl                                          [####################################] 100%
(39/62) upgrading curl                                             [####################################] 100%
(40/62) upgrading dash                                             [####################################] 100%
(41/62) upgrading dtc                                              [####################################] 100%
(42/62) upgrading libassuan                                        [####################################] 100%
(43/62) installing libgnutls                                       [####################################] 100%
(44/62) installing libksba                                         [####################################] 100%
(45/62) installing libnpth                                         [####################################] 100%
(46/62) installing nettle                                          [####################################] 100%
(47/62) installing pinentry                                        [####################################] 100%
(48/62) upgrading gnupg                                            [####################################] 100%
==> Appending keys from msys2.gpg...
gpg: Warning: using insecure memory!
gpg: starting migration from earlier GnuPG versions
gpg: porting secret keys from '/etc/pacman.d/gnupg/secring.gpg' to gpg-agent
gpg: migration succeeded
==> Locally signing trusted keys in keyring...
  -> Locally signing key D55E7A6D7CE9BA1587C0ACACF40D263ECA25678A...
  -> Locally signing key 123D4D51A1793859C2BE916BBBE514E53E0D0813...
  -> Locally signing key B91BCF3303284BF90CC043CA9F418C233E652008...
  -> Locally signing key 9DD0D4217D75A33B896159E6DA7EF2ABAEEA755C...
==> Importing owner trust values...
gpg: Warning: using insecure memory!
==> Updating trust database...
gpg: Warning: using insecure memory!
gpg: no need for a trustdb check
(49/62) upgrading libarchive                                       [####################################] 100%
(50/62) upgrading libargp                                          [####################################] 100%
(51/62) upgrading libgpgme                                         [####################################] 100%
(52/62) upgrading libpcre16                                        [####################################] 100%
(53/62) upgrading libpcre32                                        [####################################] 100%
(54/62) upgrading libpcrecpp                                       [####################################] 100%
(55/62) upgrading libpcreposix                                     [####################################] 100%
(56/62) upgrading libutil-linux                                    [####################################] 100%
(57/62) upgrading mpfr                                             [####################################] 100%
(58/62) upgrading pcre                                             [####################################] 100%
(59/62) upgrading rebase                                           [####################################] 100%
(60/62) upgrading time                                             [####################################] 100%
(61/62) upgrading util-linux                                       [####################################] 100%
(62/62) upgrading xz                                               [####################################] 100%

```
</details>

---

```Installation
# Toolchain installation
$ pacman -S base-devel gcc vim cmake git python2
```
---

[Install PIP instruction](https://docs.aws.amazon.com/cli/latest/userguide/install-linux.html)

<a href="https://docs.aws.amazon.com/cli/latest/userguide/install-linux.html" target="_blank">Install Python and PIP</a>

---


```GitHub
# Get the latest source code from GitHub
$ git clone --recursive https://github.com/Infineon/personalize-optiga-trust-x
```

<details>
<summary>Potential error message and workaround</summary>

```console
Error Message:
$ git clone --recursive https://github.com/Infineon/personalize-optiga-trust-x
Cloning into 'personalize-optiga-trust-x'...
      1 [main] git-remote-https 14880 child_info_fork::abort: C:\msys32\usr\bin\msys-unistring-2.dll: Loaded to different address: parent(0xFD0000) != child(0x1020000)
error: cannot fork() for fetch-pack: Resource temporarily unavailable

Workaround:
Close all Msys2 programs.
Execute(double-click) the autorebase.bat in msys32 folder.
Launch the MSYS2 and re-run the git clone command.
```
</details>

---

## Building the Trust X source code

Remove the pre-build binaries.

```console
# Go to the starting directory
$ cd personalize-optiga-trust-x/source

# Remove the pre-built binary
$ rm -Rf ../bin/libusb_win_x86/

# build the source codes
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
Remove the pre-built binary from GitHub is removed.
Rebuild the source code.
```
</details>


```console
# Verfies the CSR.
$ openssl req -text -noout -verify -in ../IO_files/optiga.csr
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
