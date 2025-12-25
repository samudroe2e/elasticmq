package org.elasticmq.rest.sqs.config

import com.typesafe.config.Config
import pureconfig.generic.auto._
import pureconfig.ConfigSource

case class SQSAuthConfig(enabled: Boolean, accessKey: String, secretKey: String, region: String)

object SQSAuthConfig {
  def from(config: Config): SQSAuthConfig = {
    ConfigSource.fromConfig(config).at("rest-sqs.auth").loadOrThrow[SQSAuthConfig]
  }
}
