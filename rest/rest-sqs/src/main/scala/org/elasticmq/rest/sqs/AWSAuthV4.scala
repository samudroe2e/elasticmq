/*
 * Copyright 2022 SoftwareMill
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.elasticmq.rest.sqs
import org.apache.pekko.http.scaladsl.model.HttpRequest

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

trait AWSAuthV4Module {
  private val ALGORITHM = "AWS4-HMAC-SHA256"
  private val BASIC_DATE_FORMAT = DateTimeFormatter.ofPattern("yyyyMMdd")
  private val X_AMZ_DATE_FORMAT = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")

  private def sign(key: Array[Byte], msg: String): Array[Byte] = {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(key, "HmacSHA256"))
    mac.doFinal(msg.getBytes(StandardCharsets.UTF_8))
  }

  private def toHex(bytes: Array[Byte]): String = {
    val formatter = new java.util.Formatter()
    bytes.foreach(b => formatter.format("%02x", new Integer(b & 0xff)))
    formatter.toString
  }
  def sha256Hex(bytes: Array[Byte]): String = {
    val digest = MessageDigest.getInstance("SHA-256")
    toHex(digest.digest(bytes))
  }

  object CanonicalRequest {
    def from(request: HttpRequest, signedHeaders: String, payloadHash: String): String = {
      val signedHeadersSet = signedHeaders.split(";").toSet
      val headers = request.headers
        .filter(h => signedHeadersSet.contains(h.lowercaseName()))
        .map(h => h.lowercaseName() -> h.value)
        .sortBy(_._1)

      s"""${request.method.value}
         |${request.uri.path.toString()}
         |${request.uri.rawQueryString.getOrElse("")}
         |${headers.map(h => h._1 + ":" + h._2).mkString("\n")}
         |
         |$signedHeaders
         |$payloadHash""".stripMargin
    }
  }

  object StringToSignBuilder {
    def forAWS4(canonicalRequest: String, requestTimestamp: ZonedDateTime, region: String, service: String): String = {
      val CREDS_SCOPE_TERMINATOR = "aws4_request"
      val timestamp = requestTimestamp.format(X_AMZ_DATE_FORMAT)
      val date = requestTimestamp.format(BASIC_DATE_FORMAT)
      val scope = s"$date/$region/$service/$CREDS_SCOPE_TERMINATOR"

      val hashedRequest = sha256Hex(canonicalRequest.getBytes)
      s"$ALGORITHM\n$timestamp\n$scope\n$hashedRequest"
    }
  }

  class AWSV4Signer(
      awsSecretKey: String,
      region: String,
      service: String
  ) {

    def getSignatureKey(date: ZonedDateTime): Array[Byte] = {
      var key = ("AWS4" + awsSecretKey).getBytes(StandardCharsets.UTF_8)
      key = sign(key, date.format(BASIC_DATE_FORMAT))
      key = sign(key, region)
      key = sign(key, service)
      sign(key, "aws4_request")
    }

    def calculateSignature(
        requestTimestamp: ZonedDateTime,
        stringToSign: String
    ): String = {
      val signingKey = getSignatureKey(requestTimestamp)
      toHex(sign(signingKey, stringToSign))
    }

  }
}
