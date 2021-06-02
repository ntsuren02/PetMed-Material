/*
 * Copyright (c) 2020 Razeware LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * Notwithstanding the foregoing, you may not use, copy, modify, merge, publish,
 * distribute, sublicense, create a derivative work, and/or sell copies of the
 * Software in any work that is designed, intended, or marketed for pedagogical or
 * instructional purposes related to programming, coding, application development,
 * or information technology.  Permission for such use, copying, modification,
 * merger, publication, distribution, sublicensing, creation of derivative works,
 * or sale is expressly withheld.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.raywenderlich.android.petmed

import android.app.Activity
import android.content.Context
import android.util.Base64
import android.util.Log
import com.babylon.certificatetransparency.certificateTransparencyHostnameVerifier
import com.datatheorem.android.trustkit.TrustKit
import com.google.gson.Gson
import com.google.gson.JsonParser
import kotlinx.coroutines.Dispatchers.Default
import kotlinx.coroutines.Dispatchers.Main
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.URL
import javax.net.ssl.HttpsURLConnection

private const val SERVER_PUBLIC_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZmhp0EzuDRq0FK0AcV/10RzrTYp+HiGU457hCNgcn0uun0gYz1rmhsAZaieQoiqubCgXwP/XkVKYKOZ8CHGkWA=="

class PetRequester(listeningActivity: Activity) {

  interface RequestManagerResponse {
    fun receivedNewPets(results: PetResults)
  }

  private val responseListener: RequestManagerResponse
  private val context: Context

  init {
    responseListener = listeningActivity as RequestManagerResponse
    context = listeningActivity.applicationContext
  }

  fun retrievePets() {
    val connection =
        URL("https://kolinsturt.github.io/posts.json").openConnection() as HttpsURLConnection
      connection.hostnameVerifier = // 1
          certificateTransparencyHostnameVerifier(connection.hostnameVerifier) {
              // Enable for the provided hosts
              +"*.github.io" // 2

              // Exclude specific hosts
              //-"kolinsturt.github.io" // 3
          }
      val authenticator = Authenticator()
      val bytesToSign = connection.url.toString().toByteArray(Charsets.UTF_8) // 1
      val signedData = authenticator.sign(bytesToSign) // 2
      val requestSignature = Base64.encodeToString(signedData, Base64.DEFAULT) // 3
      Log.d("PetRequester", "signature for request : $requestSignature")
      bytesToSign[bytesToSign.size - 1] = 0

      val signingSuccess = authenticator.verify(signedData, bytesToSign)
      Log.d("PetRequester", "success : $signingSuccess")

      connection.sslSocketFactory = TrustKit.getInstance().getSSLSocketFactory(connection.url.host)

    GlobalScope.launch(Default) {
        val json = connection.inputStream.bufferedReader().readText()
        connection.disconnect()

        withContext(Main) {
// Verify received signature
// 1
            val jsonElement = JsonParser.parseString(json)
            val jsonObject = jsonElement.asJsonObject
            val result = jsonObject.get("items").toString()
            val resultBytes = result.toByteArray(Charsets.UTF_8)

            resultBytes[resultBytes.size - 1] = 0

// 2
            val signature = jsonObject.get("signature").toString()
            val signatureBytes = Base64.decode(signature, Base64.DEFAULT)

// 3
            val success = authenticator.verify(signatureBytes, resultBytes, SERVER_PUBLIC_KEY)

// 4
            if (success) {
                // Process data
                val receivedPets = Gson().fromJson(json, PetResults::class.java)
                responseListener.receivedNewPets(receivedPets)
            }
        }
    }
  }
}