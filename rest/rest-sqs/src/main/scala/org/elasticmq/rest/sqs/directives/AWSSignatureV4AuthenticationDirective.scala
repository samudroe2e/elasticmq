package org.elasticmq.rest.sqs.directives

import org.apache.pekko.http.scaladsl.model.headers.{Authorization, OAuth2BearerToken, GenericHttpCredentials}
import org.apache.pekko.http.scaladsl.server.{Directive0, AuthenticationFailedRejection}
import org.apache.pekko.http.scaladsl.server.Directives._
import org.apache.pekko.http.scaladsl.model.headers.HttpChallenges
import org.elasticmq.rest.sqs.config.SQSAuthConfig

trait AWSSignatureV4AuthenticationDirective {

  def verifyAWSSignatureV4(authConfig: SQSAuthConfig): Directive0 = {
    if (!authConfig.enabled) {
      pass
    } else {
      extractRequest.flatMap { request =>
        val authorizationHeader = request.header[Authorization]

        val clientAccessKey: Option[String] = authorizationHeader.flatMap {
          case Authorization(creds: GenericHttpCredentials)
            if creds.scheme == "AWS4-HMAC-SHA256" =>
              creds.params.get("Credential").map(_.split("/")(0))
          case _ => None
        }

        clientAccessKey match {
          case None =>
            reject(
              AuthenticationFailedRejection(
                AuthenticationFailedRejection.CredentialsMissing,
                HttpChallenges.basic("AWS SQS")
              )
            )

          case Some(key) if key != authConfig.accessKey =>
            reject(
              AuthenticationFailedRejection(
                AuthenticationFailedRejection.CredentialsRejected,
                HttpChallenges.basic("AWS SQS")
              )
            )

          case Some(_) =>
            pass
        }
      }
    }
  }
}
