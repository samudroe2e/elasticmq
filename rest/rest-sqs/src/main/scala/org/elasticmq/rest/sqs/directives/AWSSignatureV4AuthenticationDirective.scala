package org.elasticmq.rest.sqs.directives

import org.apache.pekko.http.scaladsl.model.headers.{Authorization, GenericHttpCredentials}
import org.apache.pekko.http.scaladsl.model.{HttpRequest, StatusCodes}
import org.apache.pekko.http.scaladsl.server.Directives._
import org.apache.pekko.http.scaladsl.server.{AuthenticationFailedRejection, Directive0, MalformedHeaderRejection}
import org.apache.pekko.util.ByteString
import org.elasticmq.rest.sqs.config.SQSAuthConfig
import software.amazon.awssdk.auth.credentials.{AwsBasicCredentials, StaticCredentialsProvider}
import software.amazon.awssdk.auth.signer.Aws4Signer
import software.amazon.awssdk.auth.signer.params.Aws4SignerParams
import software.amazon.awssdk.core.interceptor.ExecutionAttributes
import software.amazon.awssdk.http.{SdkHttpFullRequest, SdkHttpMethod}

import java.io.ByteArrayInputStream
import java.net.{URI, URLDecoder}
import java.nio.charset.StandardCharsets
import scala.collection.JavaConverters._
import scala.compat.java8.FutureConverters._
import scala.concurrent.duration.DurationInt

trait AWSSignatureV4AuthenticationDirective {

  def verifyAWSSignatureV4(authConfig: SQSAuthConfig): Directive0 = {
    if (!authConfig.enabled) {
      pass
    } else {
      extractRequest.flatMap { request =>
        val authorizationHeader = request.header[Authorization]

        val clientAccessKey = authorizationHeader match {
          case Some(Authorization(GenericHttpCredentials("AWS4-HMAC-SHA256", params))) =>
            params.get("Credential").map(_.split("/")(0))
          case _ => None
        }

        if (clientAccessKey.isEmpty) {
          reject(AuthenticationFailedRejection(AuthenticationFailedRejection.CredentialsMissing, scaladsl.challenge))
        } else if (clientAccessKey.get != authConfig.accessKey) {
          reject(AuthenticationFailedRejection(AuthenticationFailedRejection.CredentialsRejected, scaladsl.challenge))
        } else {
          pass
        }
      }
    }
  }

  private val scaladsl = org.apache.pekko.http.scaladsl.server.directives.Credentials.Provided
}
