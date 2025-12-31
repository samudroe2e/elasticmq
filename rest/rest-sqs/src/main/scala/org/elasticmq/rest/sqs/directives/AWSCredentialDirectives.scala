package org.elasticmq.rest.sqs.directives

import org.apache.pekko.http.scaladsl.server.{Directive0, Directives}
import org.apache.pekko.http.scaladsl.server.Directives._
import org.apache.pekko.http.scaladsl.model._
import org.elasticmq.rest.sqs.{AWSCredentialsModule, AWSProtocol, SQSException}
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.time.format.DateTimeFormatter
import java.time.{LocalDateTime, ZoneId}
import java.security.MessageDigest
import scala.collection.immutable.Seq
import scala.concurrent.duration._

trait AWSCredentialDirectives extends Directives {
  this: AWSCredentialsModule with ElasticMQDirectives =>

  private val AuthRegex =
    """AWS4-HMAC-SHA256 Credential=([^/]+)/([^/]+)/([^/]+)/([^,]+), SignedHeaders=([^,]+), Signature=(.+)""".r

  private val aws4Request = "aws4_request"

  def verifyAWSSigV4(protocol: AWSProtocol): Directive0 =
    extractRequest.flatMap { req =>
      if (awsCredentials.accessKey.isEmpty) pass
      else {
        optionalHeaderValueByName("Authorization").flatMap {
          case Some(AuthRegex(accessKey, date, region, service, signedHeaders, signature)) =>
            if (accessKey != awsCredentials.accessKey) completeInvalid()
            else if (service != "sqs") completeInvalid() // mimic AWS SQS
            else validateSignature(req, date, region, service, signedHeaders, signature)
          case _ =>
            completeInvalid()
        }
      }
    }

  private def validateSignature(
      req: HttpRequest,
      date: String,
      region: String,
      service: String,
      signedHeaders: String,
      signature: String
  ): Directive0 =
    extractRequestEntity.flatMap { entity =>
      onSuccess(entity.toStrict(5.seconds)).flatMap { strict =>
        val bodyBytes = strict.data.toArray
        val bodyHash  = sha256Hex(bodyBytes)

        val canonicalRequest = buildCanonicalRequest(req, signedHeaders, bodyHash)
        val stringToSign     = buildStringToSign(date, region, service, canonicalRequest)
        val computedSig      = sign(awsCredentials.secretKey, date, region, service, stringToSign)

        if (computedSig == signature) pass else completeInvalid()
      }
    }

  private def completeInvalid(): Directive0 =
    complete(
      SQSException.invalidClientTokenId(
        "The security token included in the request is invalid."
      )
    )

  private def buildCanonicalRequest(req: HttpRequest, signedHeaders: String, payloadHash: String): String = {
    val method       = req.method.value
    val uri          = req.uri
    val canonicalUri = uri.path.toString()

    val canonicalQuery = uri.rawQueryString.getOrElse("")

    val signedHeaderList = signedHeaders.split(";").toList
    val canonicalHeaders = signedHeaderList
      .flatMap(h => req.headers.find(_.name.equalsIgnoreCase(h)).map(h -> _.value.toLowerCase))
      .sortBy(_._1)
      .map { case (k, v) => s"${k.toLowerCase}:${v.trim}\n" }
      .mkString

    s"$method\n$canonicalUri\n$canonicalQuery\n$canonicalHeaders\n$signedHeaders\n$payloadHash"
  }

  private def buildStringToSign(date: String, region: String, service: String, canonical: String): String = {
    val dateTimeLong = date + "T000000Z" // no timestamp → assume midnight
    val scope        = s"$date/$region/$service/$aws4Request"
    s"AWS4-HMAC-SHA256\n$dateTimeLong\n$scope\n${sha256Hex(canonical.getBytes("UTF-8"))}"
  }

  private def sign(secret: String, date: String, region: String, service: String, data: String): String = {
    def hmac(key: Array[Byte], data: String): Array[Byte] = {
      val mac = Mac.getInstance("HmacSHA256")
      mac.init(new SecretKeySpec(key, "HmacSHA256"))
      mac.doFinal(data.getBytes("UTF-8"))
    }

    val kSecret  = ("AWS4" + secret).getBytes("UTF-8")
    val kDate    = hmac(kSecret, date)
    val kRegion  = hmac(kDate, region)
    val kService = hmac(kRegion, service)
    val kSign    = hmac(kService, aws4Request)

    hmac(kSign, data).map("%02x".format(_)).mkString
  }

  private def sha256Hex(bytes: Array[Byte]): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).map("%02x".format(_)).mkString
}
