""" End-to-end tests """

import logging
import multiprocessing
import socket
from multiprocessing.managers import ListProxy
from typing import Generator
from warnings import filterwarnings

import pytest  # type:ignore

# pylint: disable=wrong-import-position
filterwarnings("ignore", module="scapy")  # Just for testing it's fine
from scapy.layers.dns import DNS  # type:ignore

# pylint: enable=wrong-import-position

import check_soa_serials.__main__ as program  # type:ignore
from tests.soaserver import TCPDNSServer, UDPDNSServer


logger = logging.getLogger(__name__)

SRV_HOST: str = "localhost"


def unused_port() -> int:
    """Get an open port"""
    sock = socket.socket()
    sock.bind(("", 0))
    return sock.getsockname()[1]


SRV_PORT_1: int = unused_port()
SRV_PORT_2: int = unused_port()
logger.debug("Found unused port for server #1: `%s`", SRV_PORT_1)
logger.debug("Found unused port for server #2: `%s`", SRV_PORT_2)


@pytest.fixture(name="request_history", scope="function")
def fixture_request_history() -> ListProxy:
    """
    For new empty histories that the dummy servers (TCP, UDP) will fill with
    the requests it receives
    """
    return multiprocessing.Manager().list()


@pytest.fixture(scope="function")
def dummy_server(request: DNS, request_history: list) -> Generator:
    """
    Respond to any queries with an SOA because that's all we are testing
    """
    port = request.param["port"]
    zone_soa_mappings = request.param.get("zone_soa_mappings", None)

    logger.debug("Initializing SOA-only TCP DNS server on port `%s`", port)
    tcp_server = TCPDNSServer(
        host=SRV_HOST,
        port=port,
        zone_soa_mappings=zone_soa_mappings,
        request_history=request_history,
    )
    logger.debug("Initializing SOA-only UDP DNS server on port `%s`", port)
    udp_server = UDPDNSServer(
        host=SRV_HOST,
        port=port,
        zone_soa_mappings=zone_soa_mappings,
        request_history=request_history,
    )
    tcp_proc = multiprocessing.Process(target=tcp_server.run)
    udp_proc = multiprocessing.Process(target=udp_server.run)
    tcp_proc.start()
    udp_proc.start()
    yield request_history
    tcp_proc.terminate()
    udp_proc.terminate()


# As the tool we are testing must compare the results from two servers
dummy_server_1 = dummy_server
dummy_server_2 = dummy_server


test_cases: list = [
    # <server 1 params>, <server 2 params>, <program args>, <expected results>
    (
        # OK with default thresholds and check precise output
        {
            "port": SRV_PORT_1,
        },
        {
            "port": SRV_PORT_2,
        },
        [
            "--zone",
            "domain.tld",
            f"localhost:{SRV_PORT_1}",
            f"localhost:{SRV_PORT_2}",
        ],
        {
            "returncode": 0,
            "output": "SOASERIALS OK - zones_not_ok is 0 | zones_not_ok=0;0;0",
            "request_history": [
                ("udp", "domain.tld."),
            ],
        },
    ),
    (
        # OK with default thresholds over TCP
        {
            "port": SRV_PORT_1,
        },
        {
            "port": SRV_PORT_2,
        },
        [
            "--zone",
            "domain.tld",
            "--proto=tcp",
            f"localhost:{SRV_PORT_1}",
            f"localhost:{SRV_PORT_2}",
        ],
        {
            "returncode": 0,
            "output": "OK",
            "request_history": [
                ("tcp", "domain.tld."),
            ],
        },
    ),
    (
        # WARN instead of CRIT and check precise output
        {
            "port": SRV_PORT_1,
            "zone_soa_mappings": {
                "domain.tld": 1,
            },
        },
        {
            "port": SRV_PORT_2,
            "zone_soa_mappings": {
                "domain.tld": 2,
            },
        },
        [
            "--zone",
            "domain.tld",
            # Crit if number of bad zones is outside -inf:inf which is
            # impossible,  thus only WARN
            "--critical=~:",
            f"localhost:{SRV_PORT_1}",
            f"localhost:{SRV_PORT_2}",
        ],
        {
            "returncode": 1,
            "output": (
                "SOASERIALS WARNING - zones_not_ok is 1: domain.tld (outside "
                "range 0:0) | zones_not_ok=1;0;~:"
            ),
            "request_history": [
                ("udp", "domain.tld."),
            ],
        },
    ),
    (
        # CRIT and check precise output
        {
            "port": SRV_PORT_1,
            "zone_soa_mappings": {
                "domain.tld": 1,
            },
        },
        {
            "port": SRV_PORT_2,
            "zone_soa_mappings": {
                "domain.tld": 5,
            },
        },
        [
            "--zone",
            "domain.tld",
            f"localhost:{SRV_PORT_1}",
            f"localhost:{SRV_PORT_2}",
        ],
        {
            "returncode": 2,
            "output": (
                "SOASERIALS CRITICAL - zones_not_ok is 1: domain.tld (outside range "
                "0:0) | zones_not_ok=1;0;0"
            ),
            "request_history": [
                ("udp", "domain.tld."),
            ],
        },
    ),
]


# pylint: disable=unused-argument
# pylint: disable=redefined-outer-name
@pytest.mark.parametrize(
    "dummy_server_1,dummy_server_2,args,expected",
    test_cases,
    indirect=["dummy_server_1", "dummy_server_2"],
    ids=[
        "OK with default thresholds and check precise output",
        "OK with default thresholds over TCP",
        "WARN instead of CRIT and check precise output",
        "CRIT and check precise output",
    ],
)
def test_end_to_end(
    capsys: pytest.CaptureFixture,
    dummy_server_1: list,
    dummy_server_2: list,
    args: list,
    expected: dict,
) -> None:
    """Test"""
    with pytest.raises(SystemExit) as excinfo:
        program.main(argv=args)
    assert excinfo.value.code == expected["returncode"]
    output = capsys.readouterr().out.rstrip("\n")  # type:ignore
    logging.debug(output)
    assert expected["output"] in output
    for request in expected["request_history"]:
        assert request in dummy_server_1
        assert request in dummy_server_2


# pylint: enable=unused-argument
# pylint: enable=redefined-outer-name
