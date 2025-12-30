package org.elasticmq.rest.sqs.directives

import org.elasticmq.rest.sqs.SQSException
import org.joda.time.format.ISODateTimeFormat
import org.joda.time.DateTime

import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import scala.util.{Failure, Success, Try}

object Util {
  def parseDate(dateString: String): ZonedDateTime = {
    // ZonedDateTime supports parsing ISO8601 by default
    Try(ZonedDateTime.parse(dateString)) match {
      case Failure(_) =>
        // Fallback for other formats if necessary
        val formatter = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
        ZonedDateTime.parse(dateString, formatter)
      case Success(value) => value
    }
  }
}
