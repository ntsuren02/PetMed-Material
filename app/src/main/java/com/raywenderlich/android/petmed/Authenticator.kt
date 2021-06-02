package com.raywenderlich.android.petmed

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

class Authenticator {

    private val publicKey: PublicKey
    private val privateKey: PrivateKey

    init {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC") // 1
        keyPairGenerator.initialize(256) // 2
        val keyPair = keyPairGenerator.genKeyPair() // 3

        // 4
        publicKey = keyPair.public
        privateKey = keyPair.private
    }

    fun sign(data: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA512withECDSA")
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    fun verify(signature: ByteArray, data: ByteArray): Boolean {
        val verifySignature = Signature.getInstance("SHA512withECDSA")
        verifySignature.initVerify(publicKey)
        verifySignature.update(data)
        return verifySignature.verify(signature)
    }

    fun verify(
        signature: ByteArray,
        data: ByteArray,
        publicKeyString: String
    ): Boolean {
        val verifySignature = Signature.getInstance("SHA512withECDSA")
        val bytes = android.util.Base64.decode(publicKeyString,
            android.util.Base64.DEFAULT)
        val publicKey =
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes))
        verifySignature.initVerify(publicKey)
        verifySignature.update(data)
        return verifySignature.verify(signature)
    }

}
