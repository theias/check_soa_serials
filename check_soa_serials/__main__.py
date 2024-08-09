#!/usr/bin/env python3
"""
Icinga2/Nagios plugin which compares the SOA serial numbers for the same DNS
zone(s) from two different servers to ensure they are in sync
"""
import argparse
import logging
import sys
from typing import List, Generator, Optional, TypeVar

import dns.resolver
import nagiosplugin  # type:ignore
from dns.exception import DNSException

U = TypeVar("U", bound=nagiosplugin.Metric)

logger = logging.getLogger(__name__)

DEFAULT_PORT = 53


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    """Parse args"""

    usage_examples: str = """examples:

        # Description

        %(prog)s <args>

        # For more on how to set warning and critical ranges, see Nagios
        # Plugin Development Guidelines:
        #
        # https://nagios-plugins.org/doc/guidelines.html#THRESHOLDFORMAT

    """
    descr: str = __doc__
    parser = argparse.ArgumentParser(
        description=descr,
        epilog=usage_examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--proto",
        choices=["tcp", "udp"],
        default="udp",
        help=("Protocol to use for DNS queries"),
        type=str.lower,
    )

    def read_lines(filepath: str) -> List[str]:
        lines: List[str] = []
        with open(filepath, "r", encoding="utf-8") as fileh:
            lines.append(fileh.readline().lower().strip())
        return lines

    parser.add_argument(
        "--zones-file",
        "-f",
        dest="zones_from_file",
        help=(
            "A file from which to pull DNS zones to compare the serials for between "
            "DNS hosts (one per line)"
        ),
        metavar="zones_file",
        type=read_lines,
    )

    parser.add_argument(
        "--critical",
        "-c",
        default="0",
        help=("Critical range for the number of SOA serials that are not OK"),
        type=str,
    )

    parser.add_argument(
        "--warning",
        "-w",
        default="0",
        help=("Warning range for the number of SOA serials that are not OK"),
        type=str,
    )

    parser.add_argument(
        "--zone",
        "-z",
        action="append",
        dest="zones_from_args",
        help=("A zone to compare the serials for between DNS hosts"),
        type=str.lower,
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        dest="verbosity",
        help="Set output verbosity (-v=warning, -vv=debug)",
    )

    parser.add_argument(
        "hosts",
        help=(
            "The hosts to compare all the SOA serials between, optionally as "
            "`host:port`"
        ),
        metavar="host",
        nargs=2,
        type=str,
    )

    if len(sys.argv) == 0:
        parser.print_help()
        raise SystemExit(1)

    args: argparse.Namespace = (
        parser.parse_args(argv) if argv else parser.parse_args([])
    )

    if args.zones_from_file is None and args.zones_from_args is None:
        raise argparse.ArgumentTypeError(
            "At least one of `--zone` or `--zone-file` are required"
        )
    # Combine zones lists from multiple sources into one field
    combo: argparse.Namespace = argparse.Namespace(
        # Combine all zone sources and remove dupes
        zones=list(set(args.zones_from_file or [] + args.zones_from_args or []))
    )
    args = argparse.Namespace(**vars(args), **vars(combo))
    del args.zones_from_args
    del args.zones_from_file

    if args.verbosity >= 2:
        log_level = logging.DEBUG
    elif args.verbosity >= 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level)

    return args


# pylint: disable=too-few-public-methods
class SOASerials(nagiosplugin.Resource):
    """
    Checking SOA serial results from two different servers
    """

    def __init__(
        self,
        *,
        hosts: List[str],
        proto: str,
        zones: List[str],
        warn_range: str,
        crit_range: str,
    ):
        """
        hosts: list of strings of hostnames with optional `:<port>`
        proto: tcp|udp
        zones: list of zones to check
        """
        # Save these as instance vars so they are accessible to the `Range`
        # objs' formatters later
        self.crit_range = nagiosplugin.Range(crit_range)
        self.warn_range = nagiosplugin.Range(warn_range)
        self.resolvers: List[dns.resolver.Resolver] = []
        for host in hosts:
            # Sort out ports which may not be present
            elements = host.split(":")
            host_addr: str = "127.0.0.1" if elements[0] == "localhost" else elements[0]
            port: int
            if len(elements) > 1:
                port = int(elements[1])
            else:
                port = DEFAULT_PORT

            # Add to resolvers
            resolver: dns.resolver.Resolver = dns.resolver.Resolver()
            resolver.nameservers = [host_addr]
            resolver.nameserver_ports = {host_addr: port}
            self.resolvers.append(resolver)
        self.tcp = proto == "tcp"
        self.zones = zones

        self.warn_zones: List[str] = []
        self.crit_zones: List[str] = []

    def probe(self) -> Generator[nagiosplugin.Metric, None, None]:
        """
        Run the check itself
        """
        warn_zones_c: int = 0
        crit_zones_c: int = 0
        for zone in self.zones:
            logger.debug("Processing zone `%s`", zone)
            vals: List[int] = []
            for resolver in self.resolvers:
                try:
                    soa_serial = resolver.resolve(zone, "SOA", tcp=self.tcp)[0].serial
                except DNSException as err:
                    raise nagiosplugin.CheckError from err
                vals.append(int(soa_serial))
            diff = abs(vals[0] - vals[1])
            if diff not in self.crit_range:
                logger.debug(
                    "Zone `%s` serial diff `%s` in critical range (`%s`)",
                    zone,
                    diff,
                    "0",
                )
                self.crit_zones.append(zone)
                crit_zones_c += 1
            elif diff not in self.warn_range:
                logger.debug(
                    "Zone `%s` serial diff `%s` in warning range (`%s`)",
                    zone,
                    diff,
                    "0",
                )
                self.warn_zones.append(zone)
                warn_zones_c += 1
            else:
                logger.debug(
                    "Zone `%s` serial diff `%s` OK in range (`%s`)",
                    zone,
                    diff,
                    self.warn_range,
                )
                logger.debug("Zone `%s` serial OK", zone)
        yield nagiosplugin.Metric(
            "zones_not_ok",
            crit_zones_c + warn_zones_c,
            context="zones_not_ok",
        )


# pylint: enable=too-few-public-methods


# pylint: disable-next=unused-argument
def formatter(metric: nagiosplugin.Metric, context: nagiosplugin.Context) -> str:
    """
    Formatter for the plugin output before the perfdata to avoid getting too long
    """
    zone_list: List[str] = (metric.resource.crit_zones + metric.resource.warn_zones)[:5]
    zones_str: str = ",".join(zone_list)
    msg: str = f"{metric.name} is {metric.value}{': ' if zones_str else ''}{zones_str}"

    # pylint: disable-next=consider-using-f-string
    return "{:.45}{}".format(msg, f"{'…' if len(msg) > 44 else ''}")


@nagiosplugin.guarded
def main(
    argv: list,
) -> None:
    """Main"""
    args = parse_args(argv)
    logger.debug("Argparse results: %s", args)

    soa_serials: SOASerials = SOASerials(
        zones=args.zones,
        hosts=args.hosts,
        proto=args.proto,
        warn_range=args.warning,
        crit_range=args.critical,
    )
    context_alterting = nagiosplugin.ScalarContext(
        "zones_not_ok",
        critical=args.critical,
        warning=args.warning,
        fmt_metric=formatter,
    )
    check = nagiosplugin.Check(soa_serials, context_alterting)
    check.main(args.verbosity)


if __name__ == "__main__":
    main(sys.argv[1:])
