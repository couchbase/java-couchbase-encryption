# Java Field-Level Encryption Benchmark

Uses the JMH benchmarking harness to measure performance of the Couchbase encryption library.

## Prerequisites

* Java JDK 8 or later (JVM version may affect performance)
* Maven

## One-time setup

Build the benchmark JAR with this command:

    mvn clean package

## Run the benchmark

With default field sizes (32 bytes, 512 bytes, and 4096 bytes):

    java -jar target/benchmarks.jar

With custom field size (96 bytes, for example):

    java -jar target/benchmarks.jar -p fieldSizeInBytes=96

## Advanced options

To see the full list of command-line options supported by JMH:

    java -jar target/benchmarks.jar -h

## Interpreting the results

Encryption and decryption are measured separately.
By default, JMH reports throughput in operations per second,
where an "operation" is encrypting (or decrypting) a single field.
