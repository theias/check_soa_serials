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
usage: check_soa_serials [-h] [--proto {tcp,udp}] [--file ZONES_FROM_FILE] [--critical CRITICAL] [--warning WARNING] [--zone ZONES_FROM_ARGS] [--verbose] host host
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

For more on Nagios plugin ranges, thresholds, perfdata, and return codes, see [Nagios Plugin Development Guidelines].

## Icinga2

Here is an Icinga2 `CheckCommand` object for this plugin:

```
object CheckCommand "check_soa_serials" {
  command = [ PluginDir + "/check_soa_serials", ]
  arguments = {
    "--critical" = {
      description = "Critical range for number of zones not in sync"
      key = "--critical"
      set_if = "$soa_serials_critical$"
      value = "$soa_serials_critical$"
    }
    "--warning" = {
      description = "Warning range for number of zones not in sync"
      key = "--warning"
      set_if = "$soa_serials_warning$"
      value = "$soa_serials_warning$"
    }
    "--proto" = {
      description = "Protocol to use for DNS queries"
      key = "--proto"
      set_if = "$soa_serials_proto$"
      value = "$soa_serials_proto$"
    }
    "--zones-file" = {
      description = "Protocol to use for DNS queries"
      key = "--zones-file"
      set_if = "$soa_serials_zones_file"
      value = "$soa_serials_zones_file"
    }
    "--zone" = {
      description = "A zone to compare the serials for between DNS hosts"
      key = "--zone"
      repeat_key = true
      set_if = "$soa_serials_zone"
      value = "$soa_serials_zone"
    }
    host1 = {
      description = "DNS host 1"
      required = true
      skip_key = true
      value = "$check_soa_serials_host1$"
    }
    host2 = {
      description = "DNS host 2"
      required = true
      skip_key = true
      value = "$check_soa_serials_host2$"
    }
  }
}
```

And a minimal example Icinga Service:

```
object Service "host.domain.tld_check" {
  import "generic-service"
  display_name = "SOA Zones in sync"
  host_name = "host.domain.tld"
  check_command = "check_soa_serials"
  notes = "The `check_soa_serials` command is a custom plugin that compares the SOA serial numbers for the same DNS zones from two different servers to ensure they are in sync."
  notes_url = "https://gitlab.com/theias/check_soa_serials"
  vars.host1 = "$address$"
  vars.host2 = "otherdns.domain.tld"
}
```

Note on the command path: the above Icinga2 configuration object points to the command in Icinga2's configured `PluginDir`, but this can be configured however you like. For instance:

* point it to wherever it is installed by its full path
* symlink from the specified path to the actual script.
* or take the kludge route, leave it as-is, and copy `__main__.py` from this repo into `PluginDir/`

Up to you!

# Limitations

DNSSEC is not supported, but it could be.

# Contributing

Merge requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

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
[pip]: https://pip.pypa.io/en/stable/
