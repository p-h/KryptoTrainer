package kryptotrainer;

import mybiginteger.BigInteger;

import java.util.concurrent.ThreadLocalRandom;

/**
 * <p>Title: KryptoTrainer</p>
 * <p>Description: Übungsumgebung für das Wahlfach Kryptologie</p>
 * <p>Copyright: Copyright (c) 2006 / Samuel Beer</p>
 * <p>Company: Zürcher Hochschule Winterthur</p>
 *
 * @author Samuel Beer
 * @version 1.0
 */

public class ElGamal {

    int bitLengthPublicKey;          // Länge der Primzahl p in Bits

    BigInteger[] publicKeyAlice;     // Öffentlicher Schlüssel (p,g,A) von Alice

    BigInteger privateKeyAlice;      // Privater Schlüssel a von Alice

    BigInteger plainText;            // Klartext Bob -> Alice

    BigInteger[] cipheredText;       // Chiffrat (B,c) Bob -> Alice

    BigInteger decipheredText;       // Dechiffrierter Text Bob -> Alice


    /************************************************************************
     ************************************************************************
     * Methoden, die ausprogrammiert werden müssen.
     ************************************************************************
     ************************************************************************/

    /************************************************************************
     ************************************************************************
     * Methoden, die fertig vorgegeben sind.
     ************************************************************************
     ************************************************************************/

    public ElGamal() {
    }

    /**
     * Öffentlichen Schlüssel (p,g,A) und privaten Schlüssel (a) für Alice
     * generieren und in publicKeyAlice bzw. privateKeyAlice speichern.
     */
    public void generateKeyPair() {
        BigInteger p = BigInteger.myProbableSecurePrime(this.bitLengthPublicKey, 10, ThreadLocalRandom.current());
        BigInteger foo = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        BigInteger g;
        do {
            g = new BigInteger(bitLengthPublicKey, ThreadLocalRandom.current());
        } while (0 <= p.compareTo(g) && g.modPow(foo, p).equals(BigInteger.ONE));

        BigInteger a = BigInteger.randomNumberBellow(p.subtract(BigInteger.ONE));

        BigInteger A = g.modPow(a, p);

        publicKeyAlice = new BigInteger[]{p, g, A};
        privateKeyAlice = a;
    }

    /**
     * Chiffrat (B,c) Bob -> Alice erstellen und in cipheredText abspeichern.
     */
    public void createCipheredText() {
        BigInteger p = publicKeyAlice[0];
        BigInteger g = publicKeyAlice[1];
        BigInteger A = publicKeyAlice[2];
        BigInteger b = BigInteger.randomNumberBellow(p.subtract(BigInteger.ONE));
        BigInteger B = g.modPow(b, p);
        BigInteger c = A.modPow(b, p).multiply(plainText).mod(p);

        cipheredText = new BigInteger[]{B, c};
    }

    /**
     * Dechiffrierten Text Bob -> Alice erstellen und in decipheredText abspeichern.
     */
    public void createDecipheredText() {
        BigInteger B = cipheredText[0];
        BigInteger c = cipheredText[1];

        BigInteger p = publicKeyAlice[0];
        BigInteger a = privateKeyAlice;

        BigInteger m = c.multiply(B.modPow(a.negate(), p)).mod(p);

        decipheredText = m;
    }

    public void setBitLength(int len) {
        bitLengthPublicKey = len;
    }

    public void setPlainText(BigInteger plain) {
        plainText = plain;
    }

    public BigInteger[] getCipheredText() {
        return cipheredText;
    }

    public BigInteger getDecipheredText() {
        return decipheredText;
    }

    public BigInteger[] getPublicKey() {
        return publicKeyAlice;
    }

    public BigInteger getPrivateKey() {
        return privateKeyAlice;
    }
}
