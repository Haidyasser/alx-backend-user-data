#!/usr/bin/env python3
"""
a module that contains a function that filters out
sensitive information from a log message
"""

from typing import List, Tuple
import re
import logging
import os
import mysql.connector
from mysql.connector.connection import MySQLConnection


PII_FIELDS: Tuple[str] = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    function that returns the log message obfuscated
    """
    for field in fields:
        message = re.sub(rf'{field}=.+?{separator}',
                         f'{field}={redaction}{separator}', message)
    return message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """ Constructor method """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Filters values in incoming log records """
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)


def get_logger() -> logging.Logger:
    """ Returns a logging object """
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)

    return logger


def get_db() -> MySQLConnection:
    """ Returns a connector to a database """
    connector = mysql.connector.connect(
        user=os.getenv('PERSONAL_DATA_DB_USERNAME', 'root'),
        password=os.getenv('PERSONAL_DATA_DB_PASSWORD', ''),
        host=os.getenv('PERSONAL_DATA_DB_HOST', 'localhost'),
        database=os.getenv('PERSONAL_DATA_DB_NAME', '')
    )
    return connector


def get_db() -> MySQLConnection:
    """
    Returns a connector to the MySQL database using credentials
    from environment variables.
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    database = os.getenv("PERSONAL_DATA_DB_NAME")

    if not database:
        raise ValueError(
            "The database name must be set in PERSONAL_DATA_DB_NAME")

    connection = mysql.connector.connect(
        host=host,
        user=username,
        password=password,
        database=database
    )

    return connection


def main() -> None:
    """
    Main function that retrieves and logs rows from the users table
    """
    logger = get_logger()
    db = get_db()
    cursor = db.cursor()

    # Fetch all rows from the users table
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()

    # Get column names to format the log
    column_names = [desc[0] for desc in cursor.description]

    # Process and log each row
    for row in rows:
        message = "; ".join(
            f"{column}={value}" for column, value in zip(column_names, row))
        + ";"
        logger.info(message)

    # Close the database connection
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
