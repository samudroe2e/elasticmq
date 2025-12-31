package org.elasticmq.rest.sqs.directives

import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.ZonedDateTime

object Util {
  private val awsDateFormat = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC)
  def parseDate(date: String): ZonedDateTime = {
    ZonedDateTime.parse(date, awsDateFormat)
  }
}
