/**
 * Generate a java SSL/TLS keystore with a key pair.
 *
 * Generating the cert and keystore can be done of course with the Java keytool -
 * reasons for me to write this script
 * - figure out how to do this inside an java application
 * - keytool doesn't support keylengths of 4096bit
 * - try out groovy CliBuilder
 * - print out jetty obfuscated passwords (OBF)
 *
 * Copyright (c) 2015 luukes@posteo.net
 * License: Apache 2 License
 */

@Grapes([
        @Grab(group='org.bouncycastle', module='bcprov-jdk15on', version='1.51'),
        @Grab(group='org.bouncycastle', module='bcpkix-jdk15on', version='1.51'),
        @Grab(group='org.eclipse.jetty', module='jetty-util', version='9.2.7.v20150116')
])

import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import javax.security.auth.x500.X500Principal
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Security

import org.eclipse.jetty.util.security.Password
import org.eclipse.jetty.util.security.UnixCrypt

final long ONEDAY_MILLIS = 24*60*60*1000

def log = { msg ->
    println " - $msg"
}

def cli = new CliBuilder(usage : 'keystore-generator [options] <keystore-file>')
cli.h(  longOpt: 'help',      required: false, 'This help')
cli.b(  longOpt: 'bits',      required: false, 'Keylenth in bits (2048 or 4096)', args: 1, argName: 'bits')
cli.sa( longOpt: 'sigalg',    required: false, 'Signature algorithm: default now is SHA256 (use SHA1 for legacy certs)', args: 1, argName: 'sigalg')
cli.c(  longOpt: 'country',   required: true,  'Country code (2 letter code)', args: 1, argName: 'country')
cli.st( longOpt: 'province',  required: true,  'Province', args: 1, argName: 'province')
cli.l(  longOpt: 'location',  required: true,  'Location/City', args: 1, argName: 'location')
cli.o(  longOpt: 'org',       required: true,  'Organization', args: 1, argName: 'org')
cli.ou( longOpt: 'orgunit',   required: true,  'Organizational unit', args: 1, argName: 'ounit')
cli.cn( longOpt: 'cname',     required: true,  'Common name (FQDN)', args: 1, argName: 'cname')
cli.y(  longOpt: 'years',     required: false, 'Expire in years', args: 1, argName: 'years')
cli.p(  longOpt: 'password',  required: false, 'Keystore password', args: 1, argName: 'password')
cli.a(  longOpt: 'alias',     required: false, 'Alias', args: 1, argName: 'alias')
cli.ow( longOpt: 'overwrite', required: false, 'Overwrite keystore if exists')
def opts = cli.parse(args)
// cli.parse shows the usage and returns null if there are params missing
if (!opts) return 1

// print usage if -h, --help, or no argument is given  
if (opts.h || opts.arguments().isEmpty()) {
    cli.usage()
    return 1
}

try {
    log('Start keystore/cert generation ...')

    // defaults
    int bits = opts.b ? Integer.parseInt(opts.b) : 2048
    int expiresInYears = opts.years ? Integer.parseInt(opts.years) : 5
    String alias = opts.a ? opts.a : 'localhost'

    File keystore = new File(opts.arguments()[0])
    log("Use keystore file [$keystore]")
    if (keystore.exists()) {
        if (opts.ow) {
            log("Overwrite keystore file $keystore")
            keystore.delete()
        } else {
            log('*** Keystore file exists (use -ow to overwrite)')
            return 2
        }
    }
    Security.addProvider(new BouncyCastleProvider())
    
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance('RSA', 'BC')
    kpGen.initialize(bits, new SecureRandom())

    KeyPair pair = kpGen.generateKeyPair()
    String subject = "C=${opts.c}, ST=${opts.st}, L=${opts.l}, O=${opts.o}, OU=${opts.ou}, CN=${opts.cn}"
    log("Use subject [$subject]")
    X500Principal principal = new X500Principal(subject)
    long now = System.currentTimeMillis()
    Date startDate = new Date(now - ONEDAY_MILLIS)
    Date endDate = new Date(now + expiresInYears * ONEDAY_MILLIS*365)
    BigInteger serial = BigInteger.valueOf(now)
    X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(principal, serial, startDate, endDate, principal, pair.getPublic())
    
    // Signature algorithm
    def sigalg = ''
    switch(opts.sigalg) {
        case 'SHA1':
            sigalg = 'SHA1WithRSAEncryption'
            log('*** WARNING SHA1 is "deprecated" for this purpose! Use SHA256 instead.')
        case 'SHA256':
            // fall through
        default:
            sigalg = 'SHA256WithRSAEncryption'
    }
    ContentSigner sigGen = new JcaContentSignerBuilder(sigalg).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pair.getPrivate())
    X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certGen.build(sigGen))
    cert.checkValidity( new Date() )
    cert.verify( cert.getPublicKey() )

    log("Use keylength: $bits | sign: $sigalg | expire in: $expiresInYears years | alias: $alias")

    KeyStore store = KeyStore.getInstance('JKS')
    // if no password is given create a random one
    String pwd = ''
    SecureRandom sr = new SecureRandom()
    if (opts.p) {
        pwd = opts.p
    } else {
        byte[] bytes = new byte[16];
        sr.nextBytes(bytes);
        pwd = bytes.encodeHex().toString()
        log("Keystore password [$pwd]")
    }
    // Output a obfuscated password for jetty
    def jettyPwd = Password.obfuscate(pwd)
    log("Keystore password for jetty obfuscated: $jettyPwd")

    // Output the crypted version of the password too
    // FIXME not tested yet
    byte[] salt = new byte[16];
    sr.nextBytes(salt);
    jettyPwd = UnixCrypt.crypt(pwd, new String(salt.encodeHex().toString()))
    log("Keystore password for jetty crypted   : Crypt=$jettyPwd")
    def ksPwd = (pwd).toCharArray()

    // Finally save keys in a keystore
    KeyStore.LoadStoreParameter lsp = null
    store.load(lsp)
    def certArray = [ cert ].toArray()
    store.setKeyEntry(alias, pair.getPrivate(), ksPwd, certArray as Certificate[])
    FileOutputStream fos = new FileOutputStream(keystore)
    store.store(fos, ksPwd)
    fos.close()
    log('done')
} catch (Exception ex) {
    log('*** Failed to generate self-signed certificate!')
    ex.printStackTrace()
    return 3
}

return 0
