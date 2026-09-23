# DNS Client

A Python DNS client developed as a collaborative computer networking project. The program constructs DNS queries, sends them over UDP, and parses DNS responses without relying on a high-level DNS lookup library.

## Features

- Constructs DNS query packets manually
- Sends DNS requests using UDP sockets
- Parses DNS response headers and records
- Validates DNS transaction IDs and response flags
- Handles request timeouts and retries
- Extracts IPv4 addresses from DNS A records

## Networking Concepts

This project demonstrates:

- DNS message formatting
- UDP socket programming
- Binary packet construction and parsing
- DNS headers, questions, and resource records
- Network byte order
- Timeout and retry handling

## Usage

Run the client with a hostname:

    python3 my-dns-client.py <hostname>

Example:

    python3 my-dns-client.py gmu.edu

## Project Files

- `my-dns-client.py` — DNS client implementation
- `sample-output.txt` — sample output from the client

## Contributors

- Juan Carlos Garcia Solis
- Emily Marie Hansen

This project was completed collaboratively as part of a university computer networking course.
