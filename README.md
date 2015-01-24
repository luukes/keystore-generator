# Keystore/certificate generator
Generate a java keystore including a key pair in one step and obfuscating the password for jetty.

Generating the cert and keystore can be done of course with the Java keytool -
reasons for me to write this script have been:
 * figure out how to do this inside an application
 * keytool doesn't support a keylength of 4096bit
 * try out groovy CliBuilder
 * print out the password obfuscated for jetty (OBF)

You just need groovy to start this script. The dependencies are downloaded via grape.
```
luk@luktop:~/workspace/keystore-generator$ groovy keystore-generator.groovy
error: Missing required options: c, st, l, o, ou, cn
usage: keystore-generator [options] <keystore-file>
 -b,--bits <bits>            Keylenth in bits (2048 or 4096)
 -c,--country <country>      Country code (2 letter code)
 -cn,--cname <cname>         Common name (FQDN)
 -h,--help                   This help
 -l,--location <location>    Location/City
 -o,--org <org>              Organization
 -ou,--orgunit <ounit>       Organizational unit
 -ow,--overwrite             Overwrite keystore if exists
 -p,--password <password>    Keystore password
 -sa,--sigalg <sigalg>       Signature algorithm: default now is SHA256
                             (use SHA1 for legacy certs)
 -st,--province <province>   Province
 -y,--years <years>          Expire in years
 ```
