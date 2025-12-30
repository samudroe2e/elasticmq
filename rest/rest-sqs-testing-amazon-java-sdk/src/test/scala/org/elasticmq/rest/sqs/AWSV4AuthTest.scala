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
import com.amazonaws.auth.{AWSStaticCredentialsProvider, BasicAWSCredentials}
import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration
import com.amazonaws.services.sqs.{AmazonSQS, AmazonSQSClientBuilder}
import com.typesafe.config.{Config, ConfigFactory}
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.{BeforeAndAfter, Suite}

import scala.util.Try

class AWSV4AuthTest extends AnyFlatSpec with Matchers with BeforeAndAfter with Suite {

  var server: SQSRestServer = _
  var client: AmazonSQS = _
  var invalidClient: AmazonSQS = _

  val config: Config = ConfigFactory.load("test-with-auth.conf")
  val accessKey = config.getString("rest-sqs.aws-access-key-id")
  val secretKey = config.getString("rest-sqs.aws-secret-access-key")

  before {
    server = SQSRestServerBuilder
      .withInterface("localhost")
      .withPort(9321)
      .withAWSRegion("us-east-1")
      .start()
    server.waitUntilStarted()
    client = AmazonSQSClientBuilder
      .standard()
      .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(accessKey, secretKey)))
      .withEndpointConfiguration(new EndpointConfiguration("http://localhost:9321", "us-east-1"))
      .build()

    invalidClient = AmazonSQSClientBuilder
      .standard()
      .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials("invalid", "invalid")))
      .withEndpointConfiguration(new EndpointConfiguration("http://localhost:9321", "us-east-1"))
      .build()
  }

  after {
    server.stopAndWait()
  }

  "SQSRestServer" should "return success on valid credentials" in {
    // when
    val result = Try(client.createQueue("test"))

    // then
    result.isSuccess should be(true)
  }

  "SQSRestServer" should "return error on invalid credentials" in {
    // when
    val result = Try(invalidClient.createQueue("test"))

    // then
    result.isFailure should be(true)
  }

}
