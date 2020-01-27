% FLAME(1) 0.9 | Flamethrower
% 
% Februrary 6, 2019

# NAME

flame -- DNS performance and functional testing utility

# SYNOPSIS

flame [*options*] *target* [*generator-options*]

flame \--help

flame \--version

# DESCRIPTION

Flamethrower is a small, fast, configurable tool for functional testing, benchmarking, 
and stress testing DNS servers and networks. It supports IPv4, IPv6, UDP, TCP, and DoT and 
has a modular system for generating queries used in the tests.

Originally built as an alternative to dnsperf (https://github.com/DNS-OARC/dnsperf), 
many of the command line options are compatible.

## Target

Target can be either an IP address or host name which will be resolved first.

## Options

-b *BIND_IP*
: IP address to bind to. Default is 0.0.0.0 for inet or ::0 for inet6.

-q *QCOUNT*
: Number of queries to send every *DELAY_MS* interval. Default is 10.

-c *TCOUNT*
: Number of concurrent traffic generators per process. Default is 10.

-p *PORT*
: Which port to flame. Default is 53.

-d *DELAY_MS*
: Delay between each traffic generator's run in milliseconds. Default is 1.

-r *RECORD*
: The base record to use as the query for generators. Default is test.com.

-T *QTYPE*
: The query type to use for generators. Default is A.

-o *FILE*
: Metrics output file in JSON format.

-l *LIMIT_SECS*
: Traffic generation limit in seconds. 0 for unlimited. Default is 0.

-t *TIMEOUT*
: Query timeout in seconds. Default is 3.

-F ( inet | inet6 )
: Internet family. Default is inet.

-f *FILE*
: Read records from a file, one per row, QNAME and QTYPE. Used with the file generator.

-n *LOOP*
: Number of loops in the record list, 0 is unlimited. Default is 1.

-R
: Randomize the query list before sending. Default is false.

-P ( udp | tcp | dot )
: Protocol to use. Default is udp.

-M ( GET | POST)
: HTTP method to use for DNS over HTTPS. Default is GET.

-Q *QPS*
: Rate limit to a maximum queries per second, 0 is unlimited. Default is 0.

-g *GENERATOR*
: Query generator to use. The generators and their options are described in a
separate section. Default is static.

-v *VERBOSITY*
: Output verbosity, 0 is silent. Default is 1.

\--dnssec
: Send queries with DNSSEC OK flag set. Default is false.

\--class *CLASS*
: Send queries with given DNS class. Default is IN.

\--qps-flow
: Change rate limit over time, format: QPS,MS;QPS,MS;...


# Generators

Flamethrower uses a modular system for generating queries. Each module may
include its own list of configuration options which can be set via
*KEY*=*VALUE* pairs on the command line via *generator-options*.

## static

The generator sends the same query for a QNAME and QTYPE specified via the
*-r* and *-t* options. It doesn't use generator options.

## file

The generator reads dnsperf-compatible input file containing QNAME and QTYPE
pairs on individual lines. The name and type is separated by a space. The input
file is specified via the *-f* option. File generator doesn't use generator
options.

## numberqname

The generator sends queries to one-label subdomain with a number for a record
specified with -*r*. The generator uses following generator options:

- *low* - Lowest numeric value to write into the label. Default is 0.
- *high* - Highest number value to write into the label. Default is 100000.

## randompkt

The generator sends random chunks of data and uses following generator options:

- *count* - number of chunks (packets) to generate. Default is 1000.
- *size* - maximal size of the chunk in bytes. Default is 600.

## randomqname

The generator sends queries to random subdomains of the record specified with
*-r*. The subdomains may contain binary (non-printable characters) including
zero byte. The following generator options are available:

- *count* - number of queries to generate. Default is 100.
- *size* - maximum length of the added label(s). Default is 255.

## randomlabel

The generator sends queries to random subdomains of the record specified with
*-r*. The subdomains may contain only characters valid in a DNS names. The
following generator options are available:

- *count* - number of queries to generate. Default is 1000.
- *lblsize* - maximum length of a single added label. Default is 10.
- *lblcount* - maximum number of labels to add. Default is 5.

# EXAMPLES

Flame localhost over IPv4 on UDP port 53, use default static generator sending
test.com/A queries, no QPS limit, terminate after 10 seconds:

    $ flame -l 10 localhost

Flame target.example.test over IPv6 on TCP port 5300 with default generator and
no QPS limit:

    $ flame -p 5300 -P tcp -F inet6 target.example.test

Flame target.example.test over IPv4 on UDP port 53 with 10 q/s limit, send AAAA
type queries for random one-label subdomains of example.test, limit the query
speed to 10 q/s, terminate after 1000 queries:

    $ flame -Q 10 -r example.test -t AAAA -g randomlabel target.example.test lblsize=10 lblcount=1 count=1000

# AUTHORS

[NS1](https://ns1.com)

# BUGS

[Flamethrower at GitHub](https://github.com/DNS-OARC/flamethrower/issues)

# COPYRIGHT

Copyright 2019, NSONE, Inc.

