#!/usr/bin/env python3
"""
Very very naïve DNS server that only knows how to answer SOA queries, with
results consistently corresponding to the query for the purposes of testing
`check_soa_serials`.

Specific zones can be mapped to alternative results to simulate SOA serial drift
"""
import argparse
import logging
import multiprocessing
import socket
import sys
from dataclasses import dataclass
from typing import cast, Dict, Iterable, Optional, Tuple, Union
from warnings import filterwarnings

# pylint: disable=wrong-import-position
filterwarnings("ignore", module="scapy")  # Just for testing it's fine
from scapy.layers.dns import DNS, DNSRR  # type:ignore

# pylint: enable=wrong-import-position


@dataclass
class SOAFields:
    """Fields for SOA record"""

    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


def _encode_soa_response(soa_fields: SOAFields) -> bytes:
    """
    Scapy encodes some `rdata` for some responses, but not for `SOA`! So we
    must do it ourselves.

    Here are the relevant sections of RFC 1035 for reference

    ---
    3. DOMAIN NAME SPACE AND RR DEFINITIONS

    3.1. Name space definitions

    Domain names in messages are expressed in terms of a sequence of labels.
    Each label is represented as a one octet length field followed by that
    number of octets.  Since every domain name ends with the null label of
    the root, a domain name is terminated by a length byte of zero.  The
    high order two bits of every length octet must be zero, and the
    remaining six bits of the length field limit the label to 63 octets or
    less.

    ---
    3.3.13. SOA RDATA format

        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        /                     MNAME                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        /                     RNAME                     /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    SERIAL                     |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    REFRESH                    |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     RETRY                     |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    EXPIRE                     |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    MINIMUM                    |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    where:

    MNAME           The <domain-name> of the name server that was the
                    original or primary source of data for this zone.

    RNAME           A <domain-name> which specifies the mailbox of the
                    person responsible for this zone.

    SERIAL          The unsigned 32 bit version number of the original copy
                    of the zone.  Zone transfers preserve this value.  This
                    value wraps and should be compared using sequence space
                    arithmetic.

    REFRESH         A 32 bit time interval before the zone should be
                    refreshed.

    RETRY           A 32 bit time interval that should elapse before a
                    failed refresh should be retried.

    EXPIRE          A 32 bit time value that specifies the upper limit on
                    the time interval that can elapse before the zone is no
                    longer authoritative.
    """

    def encode_dns_name(name: str) -> bytes:
        encoded = b"".join(
            bytes([len(part)]) + part.encode() for part in name.split(".") if part
        )
        return encoded + b"\x00"  # fin with null

    return (
        encode_dns_name(soa_fields.mname)
        + encode_dns_name(soa_fields.rname)
        + soa_fields.serial.to_bytes(4, "big")
        + soa_fields.refresh.to_bytes(4, "big")
        + soa_fields.retry.to_bytes(4, "big")
        + soa_fields.expire.to_bytes(4, "big")
        + soa_fields.minimum.to_bytes(4, "big")
    )


# pylint: disable=too-few-public-methods
class SOAResponse:
    """
    Return a `scapy.layers.dns.DNS` object with a direct SOA response to the
    given query
    """

    DEFAULT_SOA = 1507  # ZeroCool

    def __new__(
        cls, request: DNS = None, zone_soa_mappings: Optional[Dict[str, int]] = None
    ) -> DNS:
        """
        `__new__` instead of making a subclass to avoid getting more complicated
        with Typing
        """
        logging.info("Request: %s", request)
        qname: str = request.qd.qname.decode()
        # DNS names always end in `.` but user is not expected to provide the
        # mapping that way
        bare_qname = qname[:-1]

        desired_soa: int
        if zone_soa_mappings and zone_soa_mappings.get(bare_qname, None):
            desired_soa = zone_soa_mappings[bare_qname]
        else:
            desired_soa = cls.DEFAULT_SOA

        fields = SOAFields(
            mname=f"dns.{qname}",
            rname=f"postmaster.{qname}",
            serial=desired_soa,
            refresh=10800,
            retry=3600,
            expire=604800,
            minimum=86400,
        )
        logging.info("SOA response: %s", fields)
        rdata: bytes = _encode_soa_response(fields)
        dnsrr: DNSRR = DNSRR(
            rrname=qname,
            type="SOA",
            rdata=rdata,
        )
        return DNS(
            id=request.id,  # must match request
            qr=1,  # 0=query, 1=response
            aa=1,  # authoritative=yes
            an=dnsrr,
            qd=request.qd,
        )


class BaseDNSServer:
    """Base"""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 53,
        zone_soa_mappings: Optional[Dict[str, int]] = None,
        request_history: Optional[list] = None,
    ):
        self.host = host
        self.port = port
        self.zone_soa_mappings = zone_soa_mappings
        self.request_history = request_history if request_history is not None else []

    def run(self) -> None:
        """Must be implemented by subclass"""
        raise NotImplementedError


class TCPDNSServer(BaseDNSServer):
    """TCP listen/respond loop"""

    def run(self) -> None:
        """TCP Server"""

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen()
            while True:
                conn, addr = sock.accept()
                logging.info("Connection from addr %s", addr)
                with conn:
                    data: bytes = conn.recv(2048)
                    request: DNS = DNS(
                        # Strip first two bytes which are the length field for
                        # DNS over TCP
                        data[2:]
                    )
                    try:
                        response = SOAResponse(
                            request=request, zone_soa_mappings=self.zone_soa_mappings
                        )
                        logging.debug("Response: %s", response)
                        raw_response = bytes(cast(bytes, response))
                        logging.debug("Raw Response: %s", raw_response)
                        self.request_history.append(("tcp", request.qd.qname.decode()))
                    except ValueError:
                        continue

                    # For TCP DNS, prepend packet with data length
                    tcp_len = len(raw_response)
                    data_len = tcp_len.to_bytes(2, byteorder="big")

                    tcp_response = data_len + raw_response
                    logging.info("Sending response to %s", addr)
                    conn.sendall(tcp_response)


class UDPDNSServer(BaseDNSServer):
    """UDP listen/respond loop"""

    def run(self) -> None:
        """TCP Server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))

        while True:
            data: bytes
            addr: Tuple[str, int]
            data, addr = sock.recvfrom(1024)
            logging.info("Packet from addr %s", addr)
            request: DNS = DNS(data)
            try:
                response = SOAResponse(
                    request=request, zone_soa_mappings=self.zone_soa_mappings
                )
                logging.debug("Response: %s", response)
                raw_response = bytes(cast(bytes, response))
                logging.debug("Raw Response: %s", raw_response)
                self.request_history.append(("udp", request.qd.qname.decode()))
            except ValueError:
                continue
            logging.info("Sending response to %s", addr)
            sock.sendto(raw_response, addr)


# pylint: enable=too-few-public-methods


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    """Parse args"""

    descr: str = __doc__
    parser = argparse.ArgumentParser(
        description=descr,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--proto",
        choices=["tcp", "udp"],
        default="udp",
        help=("Protocol"),
        type=str.lower,
    )

    parser.add_argument(
        "--port",
        "-p",
        default=5053,
        help=("Port to listen on"),
        type=int,
    )

    parser.add_argument(
        "--host",
        "-H",
        default="localhost",
        help=("Host to listen on"),
        type=str,
    )

    parser.add_argument(
        "--zone-soa-map",
        action="append",
        dest="zone_soa_mappings_lists",
        help=(
            "A pair of a zone and its desired SOA serial. Can be used multiple times."
        ),
        nargs=2,
        type=str,
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        dest="verbosity",
        help="Set output verbosity (-v=warning, -vv=debug)",
    )

    args: argparse.Namespace = (
        parser.parse_args(argv) if argv else parser.parse_args([])
    )
    print(args)

    if args.zone_soa_mappings_lists:
        remap: Iterable = [(k, int(v)) for k, v in args.zone_soa_mappings_lists]
        zone_soa_mappings: argparse.Namespace = argparse.Namespace(
            zone_soa_mappings=dict(remap)
        )
    else:
        zone_soa_mappings = argparse.Namespace(zone_soa_mappings=None)
    args = argparse.Namespace(**vars(args), **vars(zone_soa_mappings))
    del args.zone_soa_mappings_lists

    print(args)

    if args.verbosity >= 2:
        log_level = logging.DEBUG
    elif args.verbosity >= 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level)

    return args


def main(argv: list) -> None:
    """main"""
    args = parse_args(argv)
    logging.debug("Argparse results: %s", args)
    srv: Union[TCPDNSServer, UDPDNSServer]
    zone_soa_mappings = args.zone_soa_mappings if args.zone_soa_mappings else {}
    if args.proto == "tcp":
        logging.info("Running TCP SOA server")
        srv = TCPDNSServer(
            host=args.host, port=args.port, zone_soa_mappings=zone_soa_mappings
        )
    else:
        logging.info("Running UDP SOA server")
        srv = UDPDNSServer(
            host=args.host, port=args.port, zone_soa_mappings=zone_soa_mappings
        )
    srv.run()


if __name__ == "__main__":
    main(sys.argv[1:])
