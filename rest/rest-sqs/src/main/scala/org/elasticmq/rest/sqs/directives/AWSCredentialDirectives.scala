package org.elasticmq.rest.sqs.directives

import org.apache.pekko.http.scaladsl.model.HttpMethods
import org.apache.pekko.http.scaladsl.server.directives.Credentials
import org.apache.pekko.http.scaladsl.server.{Directive, Directive0, Directives}
import org.elasticmq.rest.sqs.{AWSAuthV4Module, AWSCredentialsModule, AWSProtocol, SQSException}
import org.joda.time.DateTime

import scala.util.matching.Regex

trait AWSCredentialDirectives extends Directives with AWSAuthV4Module with DirectiveUtils {
  this: AWSCredentialsModule with ElasticMQDirectives with AnyParamDirectives =>

  private val accessKeyRegex = "Credential=([^/]+)/".r

  def verifyAWSCredentials(protocol: AWSProtocol): Directive0 = {
    if (awsCredentials.secretKey.isDefined) {
      verifyAWSSignature(awsCredentials.accessKey, awsCredentials.secretKey.get)
    } else {
      verifyAWSAccessKeyId(protocol)
    }
  }

  def verifyAWSAccessKeyId(protocol: AWSProtocol): Directive0 = {
    if (awsCredentials.accessKey.nonEmpty) {
      // Optional header in case it's missing
      optionalHeaderValueByName("Authorization").flatMap {
        case Some(authHeader) =>
          accessKeyRegex.findFirstMatchIn(authHeader) match {
            case Some(m) if m.group(1) == awsCredentials.accessKey =>
              pass
            case _ =>
              // Must return a Directive0 here
              complete(
                SQSException.invalidClientTokenId(
                  "The security token included in the request is invalid."
                )
              )
          }
        case None =>
          complete(
            SQSException.invalidClientTokenId(
              "The security token included in the request is invalid."
            )
          )
      }
    } else {
      pass
    }
  }

  private val aws4authorizationHeaderRegex: Regex =
    ("AWS4-HMAC-SHA256 Credential=([^/]+)/([0-9]{8})/([^/]+)/([^/]+)/aws4_request, SignedHeaders=([^,]+), Signature=(.+)").r

  private val AwsPattern = aws4authorizationHeaderRegex.pattern

  def verifyAWSSignature(accessKey: String, secretKey: String): Directive0 = {
    extractStrictEntity.flatMap { entity =>
      extractRequest.flatMap { req =>
        req.method match {
          case HttpMethods.POST =>
            val authHeader = req.headers.find(_.is("authorization"))
            authHeader match {
              case Some(header) =>
                val amzDate =
                  req.headers.find(_.is("x-amz-date")).map(_.value()).getOrElse(req.headers.find(_.is("date")).get.value())
                val requestTimestamp = new DateTime(amzDate)

                val matcher = AwsPattern.matcher(header.value())
                if (matcher.matches()) {
                  val credential = matcher.group(1)
                  val date = matcher.group(2)
                  val region = matcher.group(3)
                  val service = matcher.group(4)
                  val signedHeaders = matcher.group(5)
                  val signature = matcher.group(6)

                  if (credential != accessKey)
                    complete(
                      SQSException.invalidClientTokenId(
                        "The security token included in the request is invalid."
                      )
                    )
                  else {

                    val awsAuthV4Signer = new AWSV4Signer(secretKey, region, service)

                    val payload = entity.getData().toArray
                    val payloadHash = sha256Hex(payload)

                    val canonicalRequest = CanonicalRequest.from(req, signedHeaders, payloadHash)
                    val stringToSign =
                      StringToSignBuilder.forAWS4(canonicalRequest, requestTimestamp, region, service)
                    val calculatedSignature = awsAuthV4Signer.calculateSignature(
                      requestTimestamp,
                      stringToSign
                    )

                    if (calculatedSignature == signature)
                      pass
                    else
                      complete(
                        SQSException.invalidClientTokenId(
                          "The security token included in the request is invalid."
                        )
                      )
                  }
                } else
                  complete(
                    SQSException.invalidClientTokenId(
                      "The security token included in the request is invalid."
                    )
                  )
              case _ =>
                complete(
                  SQSException.invalidClientTokenId(
                    "The security token included in the request is invalid."
                  )
                )
            }
          /*
          Handle GET requests as well
           */
          case HttpMethods.GET => pass
          case _               => pass
        }
      }

    }
  }
}
