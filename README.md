check_soa_serials
===========

check_soa_serials is a [Nagios]/[Icinga2] plugin that compares the SOA serial numbers for the same DNS zone(s) from two different servers to ensure they are in sync

Requires Python 3.6+

# Installation

You can install with [pip]:

```sh
python3 -m pip install check_soa_serials
```

Or install from source:

```sh
git clone <url>
pip install check_soa_serials
```

# Usage

```sh
usage: check_soa_serials [-h] [--proto {tcp,udp}] [--zones-file zones_file] [--critical CRITICAL] [--warning WARNING] [--zone ZONES_FROM_ARGS] [--verbose] host host
```

The simplest case:

```sh
# Check that the SOA serial for the zone `myzone.domain.tld` is the same on
both `dnsserver1.domain.tld` and `dnsserver2.domain.tld.
# Alert critical if they are not the same.
check_soa_serials --zone myzone.domain.tld dnsserver1.domain.tld dnsserver2.domain.tld
```

The same as the preceding example, but WARNING instead of CRITICAL by altering the critical threshold to be impossible to match:

```sh
check_soa_serials --zone myzone.domain.tld --critical=~: dnsserver1.domain.tld dnsserver2.domain.tld
```

Allow some leeway for the SOA serials to be a value of `99` apart before alerting:

```sh
check_soa_serials --zone myzone.domain.tld --critical=99 --warning=99 dnsserver1.domain.tld dnsserver2.domain.tld
```

For more on Nagios plugin ranges, thresholds, perfdata, and return codes, see [Nagios Plugin Development Guidelines].

## Using the `--warning` and `--critical` flags

When setting the `--warning` and `--critical` flags, you should know how your DNS servers increase their SOA serial values when setting warning or critical ranges.

The DNS standards require only ([RFC 1982]) that a server increase the value by a reasonable interval that avoids wrapping around in a way that would confuse secondary servers. The rest is up to the implementation to decide.

Most(?) implementations follow the recommendation of [RFC 1912] and use what amounts to a timestamp and revision field:

`YYYYMMDDnn (YYYY=year, MM=month, DD=day, nn=revision number)`.

With a reasonable implementation (e.g. [bind]), the default threshold values (any nonzero value will alert) could be fine in a quiet environment.

In a busy DNS environment with constantly-updating zones you might need to set the values higher to avoid getting alerts about every single zone transfer before it completes.

## Icinga2

Here is an Icinga2 `CheckCommand` object for this plugin:

```
object CheckCommand "soa_serials" {
  command = [ PluginDir + "/check_soa_serials", ]
  arguments = {
    "--critical" = {
      description = "Critical range for number of zones not in sync"
      key = "--critical"
      value = "$soa_serials_critical$"
    }
    "--proto" = {
      description = "Protocol to use for DNS queries"
      key = "--proto"
      value = "$soa_serials_proto$"
    }
    "--warning" = {
      description = "Warning range for number of zones not in sync"
      key = "--warning"
      value = "$soa_serials_warning$"
    }
    "--zone" = {
      description = "A zone to compare the serials for between DNS hosts"
      key = "--zone"
      repeat_key = true
      value = "$soa_serials_zone$"
    }
    "--zones-file" = {
      description = "Protocol to use for DNS queries"
      key = "--zones-file"
      value = "$soa_serials_zones_file$"
    }
    secondary = {
      description = "DNS host to check"
      required = true
      skip_key = true
      value = "$soa_serials_secondary$"
    }
    primary = {
      description = "DNS host to check against"
      required = true
      skip_key = true
      value = "$soa_serials_primary$"
    }
  }
  vars.soa_serials_secondary = "$address$"
}
```

And a minimal example Icinga Service:

```
object Service "host.domain.tld_check_soa" {
  import "generic-service"
  display_name = "DNS Zone SOA serials in sync"
  host_name = "host.domain.tld"
  check_command = "soa_serials"
  notes = "`check_soa_serials` is a custom plugin which compares the SOA serial numbers for the same DNS zone from two different servers to ensure they are in sync"
  notes_url = "https://github.com/theias/check_soa_serials"
  vars.soa_serials_primary = "primarydns.domain.tld"
  vars.zone = "_dnszone.domain.tld"
}
```

Note on the command path: the above Icinga2 configuration object points to the command in Icinga2's configured `PluginDir`, but this can be configured however you like. For instance:

* point it to wherever it is installed by its full path
* symlink from the specified path to the actual script.

Up to you!

# Limitations

DNSSEC is not supported, but it could be.

Run-time could be decreased by running multiple checks concurrently. My use case did not call for this, but I'm open to the idea.

# Contributing

Merge requests are welcome. For major changes, open an issue first to discuss what you want to change.

To run the test suite:

```bash
# Dependent targets create venv and install dependencies
make
```

Please make sure to update tests along with any changes.

# License

License :: OSI Approved :: MIT License


[Icinga2]: https://en.wikipedia.org/wiki/Icinga
[Nagios Plugin Development Guidelines]: https://nagios-plugins.org/doc/guidelines.html
[Nagios]: https://en.wikipedia.org/wiki/Nagios
[RFC 1912]: https://datatracker.ietf.org/doc/html/rfc1912
[RFC 1982]: https://datatracker.ietf.org/doc/html/rfc1982
[bind]: https://en.wikipedia.org/wiki/BIND
[pip]: https://pip.pypa.io/en/stable/
