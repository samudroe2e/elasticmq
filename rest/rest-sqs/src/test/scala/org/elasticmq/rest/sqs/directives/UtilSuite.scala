package org.elasticmq.rest.sqs.directives

import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import java.time.ZonedDateTime

class UtilSuite extends AnyFunSuite with Matchers {

  test("should parse a valid AWS date") {
    val dateString = "20251230T131350Z"
    val expectedDateTime = ZonedDateTime.parse("2025-12-30T13:13:50Z")
    val parsedDate = Util.parseDate(dateString)
    parsedDate shouldBe expectedDateTime
  }
}
