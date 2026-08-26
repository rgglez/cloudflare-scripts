#!/usr/bin/env perl

#    Cloudflare Bulk Domain/Zone Creation Script (Perl)
#    Copyright (C) 2026 Rodolfo González González
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Usage: ./cf-add-domains.pl --file <path> [options]
# Example: ./cf-add-domains.pl --file domains.txt --account <account_id>

# NOTE: everything here is the Cloudflare REST API. Wrangler has no `zone`
# command (it manages Workers resources: kv/r2/d1/queues/...), and `whoami` maps
# to GET /user/tokens/verify + GET /accounts. So Node.js is not a dependency.
# --require-wrangler re-adds the binary check for anyone who wants it enforced.

use strict;
use warnings;
use utf8;                     # source holds ✔ ✗ ─ literals
use Getopt::Long qw(GetOptions);
use HTTP::Tiny;
use JSON::PP qw(encode_json decode_json);
use Pod::Usage;

binmode STDOUT, ':encoding(UTF-8)';
binmode STDERR, ':encoding(UTF-8)';

use constant API => 'https://api.cloudflare.com/client/v4';

# The DNS scan is asynchronous: poll the review list this many times, waiting
# this long between attempts, before concluding it found nothing.
our $SCAN_POLLS    = 5;
our $SCAN_INTERVAL = 2;

my $PROG = 'cf-add-domains.pl';

my $http = HTTP::Tiny->new(
    agent   => "$PROG/1.0",
    timeout => 30,
);

# ── colour ──────────────────────────────────────────────────────────────────
my $C = -t STDOUT ? 1 : 0;
sub c { my ($code, $s) = @_; $C ? "\e[${code}m${s}\e[0m" : $s }
sub bold  { c('1',    $_[0]) }
sub green { c('32',   $_[0]) }
sub red   { c('31',   $_[0]) }
sub yellow{ c('33',   $_[0]) }
sub dim   { c('2',    $_[0]) }
sub cyan  { c('36',   $_[0]) }

sub err { print STDERR red('error') . ": $_[0]\n" }
sub die_usage { err($_[0]); print STDERR "\nTry: $PROG --help\n"; exit 2 }

# ── options ─────────────────────────────────────────────────────────────────
my ($file, $output, $whoami, $account, $dry, $help, $man, $selftest, $need_wrangler);
my ($scan, $import, $proxied, $activate, $pending);
GetOptions(
    'file|f=s'          => \$file,
    'output|o=s'        => \$output,
    'whoami|w'          => \$whoami,
    'account|a=s'       => \$account,
    'dry-run|n'         => \$dry,
    'scan|s'            => \$scan,
    'import|i=s'        => \$import,
    'proxied'           => \$proxied,
    'activate'          => \$activate,
    'pending'           => \$pending,
    'require-wrangler'  => \$need_wrangler,
    'self-test'         => \$selftest,
    'help|h|?'          => \$help,
    'man'               => \$man,
) or die_usage('bad options');

if ($help) { usage(); exit 0 }
if ($man)  { pod2usage(-exitval => 0, -verbose => 2) }
if ($selftest) { exit self_test() }

sub usage {
    print <<"USAGE";
@{[ bold("$PROG") ]} — add domains to Cloudflare, get their nameservers.

@{[ bold('USAGE') ]}
  $PROG -f <file>        add every domain in <file>
  $PROG -w               show which Cloudflare account you are on
  $PROG -f <file> -n     validate the file, change nothing
  $PROG -f <file> -o out.csv   also save the nameservers as CSV

@{[ bold('OPTIONS') ]}
  -f, --file <path>      file with one domain per line (# comments, blanks ok)
  -o, --output <path>    also write "domain","ns1","ns2" rows to a CSV file
  -w, --whoami           show token status + visible accounts, then exit
  -a, --account <id>     account id (default: \$CLOUDFLARE_ACCOUNT_ID, or the
                         only account the token can see)
  -n, --dry-run          parse and validate, make no changes
  -s, --scan             after creating a zone, run Cloudflare's DNS quick scan
  -i, --import <path>    import BIND zone files: a directory holding
                         <domain>.zone, or one file for a single domain
      --proxied          with --import, put imported A/AAAA/CNAME behind the
                         proxy (default: DNS-only)
      --pending          list zones awaiting activation, then exit
      --activate         ask Cloudflare to re-check every pending zone, exit
      --require-wrangler fail unless the wrangler binary is in PATH
  -h, --help, -?         this text
      --man              full documentation (POD)

@{[ bold('ENVIRONMENT') ]}
  CLOUDFLARE_API_TOKEN   required. Needs Zone:Edit + Account:Read.
  CLOUDFLARE_ACCOUNT_ID  optional default for --account

@{[ bold('DEPENDENCIES') ]}
  Perl core only (Getopt::Long, HTTP::Tiny, JSON::PP). No Node.js, no wrangler.

@{[ bold('EXIT') ]}
  0 all ok    1 one or more domains failed    2 usage/precondition failure

@{[ bold('NOTE') ]}
  Creating a zone does NOT copy your DNS records. A zone starts empty, so
  delegating the nameservers before populating it takes the domain offline.
  Use --import (best) or --scan (best-effort), then verify, then delegate.

  Cloudflare caps how many zones may sit PENDING at once (API error 1118).
  A large list therefore lands in batches: add what fits, delegate those at
  the registrar, and the cap frees up as they activate. On hitting it this
  script stops, writes the remainder to <file>.remaining, and tells you.
USAGE
}

# ── preconditions ───────────────────────────────────────────────────────────
sub have_wrangler {
    for my $dir (split /:/, ($ENV{PATH} // '')) {
        return 1 if -x "$dir/wrangler";
    }
    return 0;
}

# Token is the only hard requirement: every call this script makes is REST.
my $TOKEN = $ENV{CLOUDFLARE_API_TOKEN};
unless (defined $TOKEN && length $TOKEN) {
    err('CLOUDFLARE_API_TOKEN is not set');
    print STDERR "  export CLOUDFLARE_API_TOKEN=...   (Zone:Edit + Account:Read)\n";
    exit 2;
}

# A token pasted with surrounding quotes, whitespace, or a stray newline is the
# most common cause of a bogus "Invalid API Token" — the value never reaches the
# API intact. Strip that here and warn, rather than blaming the credential.
{
    my $raw = $TOKEN;
    $TOKEN =~ s/\A\s+|\s+\z//g;
    $TOKEN =~ s/\A(['"])(.*)\1\z/$2/s;
    if ($TOKEN ne $raw) {
        print STDERR yellow('warning') . ": CLOUDFLARE_API_TOKEN had surrounding quotes/whitespace; trimmed\n";
    }
    if ($TOKEN =~ /([^\x21-\x7e])/) {
        my $bad = sprintf('0x%02x', ord($1));
        err("CLOUDFLARE_API_TOKEN contains a non-printable character ($bad)");
        print STDERR "  re-export it without line breaks:  export CLOUDFLARE_API_TOKEN='...'\n";
        exit 2;
    }
}

# wrangler is optional; --require-wrangler restores the hard check for setups
# that want the CLI guaranteed present.
if ($need_wrangler && !have_wrangler()) {
    err('wrangler not found in PATH (required by --require-wrangler)');
    print STDERR "  install it:  npm install -g wrangler\@latest\n";
    exit 2;
}

# ── domain parsing ──────────────────────────────────────────────────────────
sub valid_domain {
    my ($d) = @_;
    return 0 unless defined $d && length $d && length($d) <= 253;
    return 0 if $d =~ /\.\./;
    return $d =~ /
        ^(?: [a-z0-9] (?: [a-z0-9-]{0,61} [a-z0-9] )? \. )+
          (?: [a-z]{2,63} | xn--[a-z0-9-]{2,59} )\z
    /xi ? 1 : 0;
}

# Returns (\@good, \@bad). Strips comments, blanks, trailing dot, scheme, case.
sub parse_domains {
    my ($lines) = @_;
    my (@good, @bad, %seen);
    my $n = 0;
    for my $raw (@$lines) {
        $n++;
        my $d = $raw;
        $d =~ s/#.*//;
        $d =~ s/^\s+|\s+$//g;
        next unless length $d;
        $d =~ s{^https?://}{}i;
        $d =~ s{/.*$}{};
        $d =~ s/\.$//;
        $d = lc $d;
        if (!valid_domain($d)) { push @bad, [ $n, $raw ]; next }
        next if $seen{$d}++;
        push @good, $d;
    }
    return (\@good, \@bad);
}

# ── API ─────────────────────────────────────────────────────────────────────

# Returns ($data_or_undef, $error_string_or_undef)
sub api {
    my ($method, $path, $body) = @_;
    my %opt = (headers => {
        'Authorization' => "Bearer $TOKEN",
        'Content-Type'  => 'application/json',
    });
    $opt{content} = encode_json($body) if defined $body;

    my $res = $http->request($method, API . $path, \%opt);

    # Transport failure: HTTP::Tiny reports status 599 with the reason in content.
    if ($res->{status} == 599) {
        my $why = $res->{content} // 'network error';
        $why =~ s/\s+$//;
        return (undef, "network: $why");
    }

    my $data = eval { decode_json($res->{content} // '') };
    if (!$data) {
        return (undef, "HTTP $res->{status}: non-JSON response from API");
    }
    if (!$data->{success}) {
        my @msg = map { "$_->{message}" . (defined $_->{code} ? " [$_->{code}]" : '') }
                  @{ $data->{errors} || [] };
        @msg = ("HTTP $res->{status}") unless @msg;
        return ($data, join('; ', @msg));
    }
    return ($data, undef);
}

# Cloudflare caps how many zones may sit in "pending" at once (error 1118).
# The cap is per account and scales with account standing, so it is discovered,
# never assumed: the script reacts to the code rather than hardcoding a number.
use constant ERR_ZONE_LIMIT => 1118;

# Count zones by status, so the limit can be explained with real numbers.
sub count_zones {
    my ($account_id, $status) = @_;
    my ($data, $e) = api('GET', "/zones?account.id=$account_id&status=$status&per_page=1");
    return undef if $e;
    my $ri = $data->{result_info} || {};
    return $ri->{total_count};
}

# PUT /zones/{id}/activation_check — asks Cloudflare to re-check delegation for
# a PENDING zone. Rate limited upstream: every 5 min on paid plans, hourly on
# free. It cannot activate a zone whose nameservers are not yet delegated; it
# only makes Cloudflare look again, sooner than its own schedule would.
sub activation_check {
    my ($zone_id) = @_;
    my (undef, $e) = api('PUT', "/zones/$zone_id/activation_check");
    return $e ? { ok => 0, error => $e } : { ok => 1 };
}

sub api_error_codes {
    my ($data) = @_;
    return () unless $data && $data->{errors};
    return map { $_->{code} // 0 } @{ $data->{errors} };
}

sub resolve_account {
    return $account if defined $account && length $account;
    return $ENV{CLOUDFLARE_ACCOUNT_ID}
        if defined $ENV{CLOUDFLARE_ACCOUNT_ID} && length $ENV{CLOUDFLARE_ACCOUNT_ID};

    my ($data, $e) = api('GET', '/accounts?per_page=50');
    if ($e) { err("cannot list accounts: $e"); exit 2 }

    my @acc = @{ $data->{result} || [] };
    if (!@acc) { err('token can see no accounts'); exit 2 }
    if (@acc > 1) {
        err('token sees ' . scalar(@acc) . ' accounts; pick one with --account <id>');
        print STDERR "  $_->{id}  $_->{name}\n" for @acc;
        exit 2;
    }
    return $acc[0]{id};
}

# ── whoami (pure REST, no wrangler) ─────────────────────────────────────────
# GET /user/tokens/verify  — works for any API token, unlike /user which needs
# User:Read and fails outright on scoped tokens.
sub do_whoami {
    print "\n" . bold('Cloudflare identity') . "\n";
    print dim('─' x 60) . "\n";

    # /user/tokens/verify only answers for USER-owned tokens. An account-owned
    # token is perfectly valid yet returns 1000 here, so a failure is a hint,
    # never a verdict. /accounts is the real proof the credential works.
    my ($v, $ve) = api('GET', '/user/tokens/verify');
    if (!$ve) {
        my $r = $v->{result} || {};
        printf "%s user token %s\n", green('✔'), green($r->{status} // 'active');
        printf "     %s\n", dim("id: $r->{id}") if $r->{id};
        printf "     %s\n", dim("expires: $r->{expires_on}") if $r->{expires_on};
    } else {
        printf "%s %s\n", yellow('•'), dim("user-token verify: $ve");
        printf "     %s\n", dim('(normal for an account-owned token — checking accounts instead)');
    }

    # The authoritative check: can this credential actually see anything?
    my ($a, $ae) = api('GET', '/accounts?per_page=50');
    print "\n" . bold('Accounts') . "\n";

    if ($ae) {
        print "     " . red("cannot list accounts: $ae") . "\n";
        if ($ve) {
            # Both calls failed: the credential really is unusable.
            print "\n" . red('✗') . " token rejected by both /user/tokens/verify and /accounts\n";
            print "     " . dim('check: not expired, not a Global API Key, has Account:Read') . "\n\n";
            return 1;
        }
        print "     " . dim('(token lacks Account:Read — zone creation still works with --account)') . "\n";
    } else {
        my @acc = @{ $a->{result} || [] };
        if (!@acc) {
            print "     " . yellow('none visible to this token') . "\n";
        }
        for my $x (@acc) {
            printf "  %s %s\n", cyan($x->{id}), bold($x->{name} // '?');
        }
        printf "\n%s token works (%d account%s visible)\n",
            green('✔'), scalar(@acc), (@acc == 1 ? '' : 's');
        print dim('More than one account: pass --account <id> when adding zones.') . "\n"
            if @acc > 1;
    }

    my $env_acc = $ENV{CLOUDFLARE_ACCOUNT_ID};
    print "\n" . dim("CLOUDFLARE_ACCOUNT_ID: " . ($env_acc // 'unset')) . "\n";
    print dim('wrangler: ' . (have_wrangler() ? 'present' : 'absent (not needed)')) . "\n\n";
    return 0;
}

if ($whoami) { exit do_whoami() }

# ── pending zones / activation ──────────────────────────────────────────────
# Both of these operate on the account's existing pending zones, so neither
# needs --file.

sub list_pending {
    my ($account_id) = @_;
    my (@z, $page);
    $page = 1;
    while (1) {
        my ($data, $e) = api('GET',
            "/zones?account.id=$account_id&status=pending&per_page=50&page=$page");
        if ($e) { err("cannot list pending zones: $e"); exit 2 }
        my @batch = @{ $data->{result} || [] };
        push @z, @batch;
        my $ri = $data->{result_info} || {};
        last unless @batch && defined $ri->{total_count} && @z < $ri->{total_count};
        $page++;
    }
    return @z;
}

sub do_pending {
    my $account_id = resolve_account();
    my @z = list_pending($account_id);

    print "\n" . bold('Pending zones') . dim("  (account $account_id)") . "\n";
    print dim('─' x 60) . "\n";

    unless (@z) {
        print green('✔') . " no zones awaiting activation\n\n";
        return 0;
    }

    for my $z (@z) {
        printf "%s %s\n", yellow('•'), bold($z->{name});
        printf "     %s\n", cyan($_) for @{ $z->{name_servers} || [] };
    }
    printf "\n%d zone(s) awaiting activation.\n", scalar(@z);
    print dim("Delegate these nameservers at the registrar, then: $PROG --activate\n\n");
    return 0;
}

sub do_activate {
    my $account_id = resolve_account();
    my @z = list_pending($account_id);

    print "\n" . bold('Re-checking activation') . dim("  (account $account_id)") . "\n";
    print dim('─' x 60) . "\n";

    unless (@z) {
        print green('✔') . " no pending zones to check\n\n";
        return 0;
    }

    my $failed = 0;
    for my $z (@z) {
        my $r = activation_check($z->{id});
        if ($r->{ok}) {
            printf "%s %s %s\n", green('✔'), bold($z->{name}), dim('check requested');
        } else {
            $failed++;
            printf "%s %s\n", red('✗'), bold($z->{name});
            err("$z->{name}: $r->{error}");
        }
    }

    print "\n" . dim('Cloudflare rate-limits this: every 5 min on paid plans, hourly on free.') . "\n";
    print dim("A zone activates only once its nameservers actually point at Cloudflare.\n\n");
    return $failed ? 1 : 0;
}

if ($pending)  { exit do_pending() }
if ($activate) { exit do_activate() }

die_usage('--file is required (or use --whoami)') unless defined $file;

# Fail before touching the API rather than halfway through a batch.
if (defined $import && !-e $import) {
    err("--import path does not exist: $import");
    exit 2;
}
if ($proxied && !defined $import) {
    die_usage('--proxied only applies together with --import');
}
if ($scan && defined $import) {
    print STDERR yellow('warning')
        . ": --scan and --import both given; importing first, scanning only if the import found nothing\n";
}

# ── CSV ─────────────────────────────────────────────────────────────────────
# RFC 4180: every field quoted, embedded quotes doubled. Nameservers never
# contain commas or quotes, but the domain column comes from a user file.
sub csv_row {
    my @f = map { my $v = defined $_ ? $_ : ''; $v =~ s/"/""/g; qq{"$v"} } @_;
    return join(',', @f) . "\r\n";
}

# ponytail: opened once before the run, not reopened per row.
sub open_csv {
    my ($path) = @_;
    open(my $out, '>:encoding(UTF-8)', $path)
        or do { err("cannot write $path: $!"); exit 2 };
    print {$out} csv_row('domain', 'ns1', 'ns2');
    return $out;
}

# Zone already there? Fetch it so re-runs still print nameservers.
sub existing_zone {
    my ($domain) = @_;
    my ($data, $e) = api('GET', "/zones?name=$domain&per_page=1");
    return undef if $e;
    return ($data->{result} || [])->[0];
}

sub add_zone {
    my ($domain, $account_id) = @_;
    my ($data, $e) = api('POST', '/zones', {
        name    => $domain,
        account => { id => $account_id },
        type    => 'full',
    });

    if (!$e) {
        return {
            ok => 1, id => $data->{result}{id},
            ns => $data->{result}{name_servers} || [],
            status => $data->{result}{status},
        };
    }

    # 1061 = zone already exists in this account. Not a failure for a batch re-run.
    if (grep { $_ == 1061 } api_error_codes($data)) {
        my $z = existing_zone($domain);
        return {
            ok => 1, existed => 1, id => $z->{id},
            ns => $z->{name_servers} || [], status => $z->{status},
        } if $z;
    }

    # 1118 = too many pending zones. This is an account-wide condition, not a
    # property of this domain: every remaining domain will hit it too. Flag it
    # so the caller can stop instead of printing the same error N more times.
    if (grep { $_ == ERR_ZONE_LIMIT } api_error_codes($data)) {
        return { ok => 0, error => $e, limit_hit => 1 };
    }

    return { ok => 0, error => $e };
}

# ── populating a new zone ───────────────────────────────────────────────────
# POST /zones creates an EMPTY zone: unlike the dashboard onboarding flow, the
# API performs no DNS discovery. Delegating an empty zone takes the domain
# offline, so the record set has to arrive by one of the two routes below.

# Cloudflare's quick scan: it queries the currently authoritative nameservers
# and probes a list of common hostnames. Best-effort by nature — anything not
# publicly resolvable, or not a name it guesses, is simply missed.
#
# Verified against the Cloudflare OpenAPI schema: the old one-shot
# POST /dns_records/scan is deprecated there, and its replacement is a
# three-step asynchronous flow:
#
#   POST /dns_records/scan/trigger  starts the scan; adds NOTHING by itself
#   GET  /dns_records/scan/review   lists the provisional finds
#   POST /dns_records/scan/review   {accepts:[...]} commits them
#
# Records stay temporary until accepted, and the scan keeps discovering in the
# background, so a review taken immediately after the trigger can be partial.
sub scan_zone {
    my ($zone_id) = @_;

    my (undef, $te) = api('POST', "/zones/$zone_id/dns_records/scan/trigger", {});
    return { ok => 0, error => "trigger: $te" } if $te;

    # The scan is asynchronous. Poll the review list rather than assuming the
    # results are ready the instant the trigger returns.
    my @found;
    for my $attempt (1 .. $SCAN_POLLS) {
        sleep $SCAN_INTERVAL if $attempt > 1;
        my ($rev, $re) = api('GET', "/zones/$zone_id/dns_records/scan/review");
        return { ok => 0, error => "review: $re" } if $re;
        @found = @{ $rev->{result} || [] };
        last if @found;
    }

    return { ok => 1, added => 0, found => 0 } unless @found;

    # Nothing is in the zone until it is accepted. A trigger without this step
    # is exactly the empty-zone trap this script exists to warn about.
    my @accepts = map { { id => $_->{id} } } grep { defined $_->{id} } @found;
    return { ok => 1, added => 0, found => scalar(@found) } unless @accepts;

    my ($acc, $ae) = api('POST', "/zones/$zone_id/dns_records/scan/review",
                         { accepts => \@accepts });
    return { ok => 0, error => "accept: $ae" } if $ae;

    my $added = scalar @{ ($acc->{result} || {})->{accepts} || [] };
    return { ok => 1, added => $added, found => scalar(@found) };
}

# multipart/form-data by hand: HTTP::Tiny has no encoder, and pulling in
# HTTP::Request::Common would break the "core Perl only" promise.
sub multipart_body {
    my ($boundary, $fields, $file_field, $filename, $content) = @_;
    my $b = '';
    for my $k (sort keys %$fields) {
        $b .= "--$boundary\r\n"
            . qq{Content-Disposition: form-data; name="$k"\r\n\r\n}
            . $fields->{$k} . "\r\n";
    }
    $b .= "--$boundary\r\n"
        . qq{Content-Disposition: form-data; name="$file_field"; filename="$filename"\r\n}
        . "Content-Type: text/plain\r\n\r\n"
        . $content . "\r\n"
        . "--$boundary--\r\n";
    return $b;
}

# POST /zones/{id}/dns_records/import — takes a BIND zone file. This is the
# authoritative route: it reproduces exactly what the source zone held, instead
# of guessing at it.
sub import_zone {
    my ($zone_id, $path) = @_;

    open(my $in, '<:raw', $path) or return { ok => 0, error => "cannot read $path: $!" };
    my $content = do { local $/; <$in> };
    close $in;
    return { ok => 0, error => "$path is empty" } unless defined $content && length $content;

    my $boundary = 'cfaddomains' . sprintf('%08x%08x', int(rand(2**32)), time);
    my $body = multipart_body(
        $boundary,
        { proxied => ($proxied ? 'true' : 'false') },
        'file', 'import.txt', $content,
    );

    my $res = $http->request('POST', API . "/zones/$zone_id/dns_records/import", {
        headers => {
            'Authorization' => "Bearer $TOKEN",
            'Content-Type'  => "multipart/form-data; boundary=$boundary",
        },
        content => $body,
    });

    if ($res->{status} == 599) {
        my $why = $res->{content} // 'network error';
        $why =~ s/\s+$//;
        return { ok => 0, error => "network: $why" };
    }

    my $data = eval { decode_json($res->{content} // '') };
    return { ok => 0, error => "HTTP $res->{status}: non-JSON response from API" } unless $data;

    if (!$data->{success}) {
        my @msg = map { "$_->{message}" . (defined $_->{code} ? " [$_->{code}]" : '') }
                  @{ $data->{errors} || [] };
        @msg = ("HTTP $res->{status}") unless @msg;
        return { ok => 0, error => join('; ', @msg) };
    }

    my $r = $data->{result} || {};
    return { ok => 1, added => $r->{recs_added} // 0, parsed => $r->{total_records_parsed} };
}

# --import takes either a directory of <domain>.zone files or, for a single
# domain, one file. Returns the path to use for $domain, or undef.
sub import_path_for {
    my ($domain) = @_;
    return undef unless defined $import;
    return $import if -f $import && !-d $import;
    for my $ext (qw(zone txt db)) {
        my $p = "$import/$domain.$ext";
        return $p if -f $p;
    }
    return undef;
}

# ── run ─────────────────────────────────────────────────────────────────────
open(my $fh, '<', $file) or do { err("cannot read $file: $!"); exit 2 };
my @lines = <$fh>;
close $fh;

my ($domains, $bad) = parse_domains(\@lines);

# A single --import file with several domains would load the same records into
# every zone. Refuse rather than corrupt a batch.
if (defined $import && -f $import && !-d $import && @$domains > 1) {
    err("--import points at one file but $file holds " . scalar(@$domains) . ' domains');
    print STDERR "  use a directory containing <domain>.zone files instead\n";
    exit 2;
}

for my $b (@$bad) {
    my $text = $b->[1]; $text =~ s/\s+$//;
    err("$file line $b->[0]: not a domain: '$text'");
}

unless (@$domains) { err('no valid domains in file'); exit 2 }

print "\n" . bold('Cloudflare zone setup') . dim("  ($file)") . "\n";
print dim('─' x 60) . "\n";

if ($dry) {
    print yellow('dry-run') . ": would add " . scalar(@$domains) . " zone(s)\n\n";
    for my $d (@$domains) {
        my $note = '';
        if (defined $import) {
            my $p = import_path_for($d);
            $note = defined $p ? dim("  <- import $p") : yellow('  <- no zone file found');
        } elsif ($scan) {
            $note = dim('  <- would quick-scan');
        }
        print "  $d$note\n";
    }
    unless ($scan || defined $import) {
        print "\n" . yellow('note')
            . ": no --import or --scan, so these zones would be created EMPTY.\n";
    }
    print "\n";
    exit(@$bad ? 1 : 0);
}

my $account_id = resolve_account();
print dim("account: $account_id") . "\n\n";

# Opened before the first API call so a bad path fails fast, not after
# half the zones have been created.
my $csv = defined $output ? open_csv($output) : undef;

my (@ok, @fail, @unpopulated, @deferred);
my $limit_hit = 0;
for my $i (0 .. $#$domains) {
    my $d = $domains->[$i];

    # The pending-zone cap is account-wide: once it answers 1118, every further
    # POST /zones returns the same thing. Stop and report the remainder as
    # deferred rather than generating one identical error per domain.
    if ($limit_hit) {
        push @deferred, $d;
        next;
    }

    my $r = add_zone($d, $account_id);
    if ($r->{ok}) {
        push @ok, $d;
        my $tag = $r->{existed} ? dim(' (already present)') : '';
        printf "%s %s%s\n", green('✔'), bold($d), $tag;
        printf "%s\n", dim("     status: $r->{status}") if $r->{status};

        # Populate the zone. Import wins over scan: it is exact, not a guess.
        my $populated;
        if (defined $import && $r->{id}) {
            my $path = import_path_for($d);
            if (!defined $path) {
                printf "     %s\n", yellow("no zone file for $d in $import — skipping import");
            } else {
                my $imp = import_zone($r->{id}, $path);
                if ($imp->{ok}) {
                    $populated = $imp->{added};
                    printf "     %s\n", green("imported $imp->{added} record(s) from $path");
                } else {
                    printf "     %s\n", red("import failed: $imp->{error}");
                }
            }
        }
        if ($scan && $r->{id} && !$populated) {
            my $sc = scan_zone($r->{id});
            if ($sc->{ok}) {
                $populated = $sc->{added};
                if ($sc->{added}) {
                    printf "     %s\n", green("quick scan accepted $sc->{added} of $sc->{found} record(s)");
                    printf "     %s\n", dim('scan is best-effort — verify the record set before delegating');
                } else {
                    printf "     %s\n", yellow('quick scan found nothing yet');
                    printf "     %s\n", dim('the scan keeps running server-side; re-run --scan, or use --import');
                }
            } else {
                printf "     %s\n", red("scan failed: $sc->{error}");
                printf "     %s\n", dim('prefer --import with a BIND zone file');
            }
        }
        push @unpopulated, $d unless $populated;

        if (@{ $r->{ns} }) {
            printf "     %s\n", cyan($_) for @{ $r->{ns} };
        } else {
            printf "     %s\n", yellow('no nameservers returned yet — re-run shortly');
        }
        # Only successful domains reach the CSV; ns columns stay empty when
        # Cloudflare has not assigned nameservers yet.
        print {$csv} csv_row($d, $r->{ns}[0], $r->{ns}[1]) if $csv;
    } else {
        printf "%s %s\n", red('✗'), bold($d);
        err("$d: $r->{error}");
        if ($r->{limit_hit}) {
            $limit_hit = 1;
            push @deferred, $d;   # not a real failure: it can be retried later
            my $left = $#$domains - $i;
            printf "\n%s %s\n", yellow('!'),
                bold('account pending-zone limit reached' . ($left ? " — $left domain(s) not attempted" : ''));
            print dim("     further POST /zones calls would return the same error\n");
        } else {
            push @fail, $d;
        }
    }
    print "\n";
}

if ($csv) {
    close($csv) or do { err("cannot close $output: $!"); exit 2 };
}

print dim('─' x 60) . "\n";
printf "%s %d added   %s %d failed   %s %d skipped%s\n\n",
    green('✔'), scalar(@ok),
    red('✗'),   scalar(@fail),
    yellow('!'), scalar(@$bad),
    (@deferred ? '   ' . cyan('⏸') . ' ' . scalar(@deferred) . ' deferred' : '');

printf "%s %s\n\n", green('✔'), "CSV written to $output" if $csv;

# The pending-zone cap deserves real numbers and a resumable file, not just an
# error string: the run is meant to be repeated until the backlog clears.
if ($limit_hit) {
    print red('!') . " " . bold('Account pending-zone limit reached') . "\n\n";

    my $pending = count_zones($account_id, 'pending');
    my $active  = count_zones($account_id, 'active');
    if (defined $pending) {
        print "  This account currently holds " . bold("$pending pending") . " zone(s)"
            . (defined $active ? " and $active active" : '') . ".\n";
    }
    print "  Cloudflare limits how many zones may await activation at once. The\n";
    print "  cap lifts as pending zones become active — it is not a per-run quota,\n";
    print "  so waiting without activating anything will not help.\n\n";

    print "  To clear the backlog:\n";
    print dim("    1. delegate the pending zones' nameservers at your registrar\n");
    print dim("    2. wait for DNS propagation\n");
    print dim("    3. $PROG --activate      # ask Cloudflare to re-check now\n\n");

    # A resumable remainder file: re-running the original list would work, but
    # this makes the next batch explicit and keeps already-added zones out of it.
    my $rest = "$file.remaining";
    if (open(my $rf, '>:encoding(UTF-8)', $rest)) {
        print {$rf} "# domains not added: pending-zone limit reached\n";
        print {$rf} "$_\n" for @deferred;
        close $rf;
        print "  " . scalar(@deferred) . " domain(s) not added, written to:\n";
        print "    " . cyan($rest) . "\n";
        print dim("    resume with: $PROG -f $rest"
            . (defined $import ? " --import $import" : ($scan ? ' --scan' : '')) . "\n\n");
    } else {
        err("cannot write $rest: $!");
        print "  Not added: " . join(', ', @deferred) . "\n\n";
    }
}

if (@ok) {
    if (@unpopulated) {
        print red('!') . " " . bold(scalar(@unpopulated) . " zone(s) have no records loaded by this run.\n");
        print "  A zone created through the API starts EMPTY — unlike the dashboard,\n";
        print "  the API performs no DNS discovery. Delegating an empty zone will take\n";
        print "  the domain offline.\n\n";
        print "  Load the records first:\n";
        print dim("    $PROG -f $file --import <dir-with-zone-files>\n");
        print dim("    $PROG -f $file --scan        # best-effort discovery\n");
        print dim("    ...or add them by hand in the dashboard\n\n");
    }
    print "Verify each zone's records, then point the domain at the nameservers\n";
    print "above, at your registrar.\n";
    print dim("Cloudflare activates a zone once the delegation propagates.\n\n");
}

exit((@fail || @$bad || @deferred) ? 1 : 0);

# ── self-test: offline, no API calls ────────────────────────────────────────
sub self_test {
    my $fails = 0;
    my $check = sub {
        my ($label, $got, $want) = @_;
        if ($got eq $want) { print "ok   $label\n" }
        else { print "FAIL $label (got '$got', want '$want')\n"; $fails++ }
    };

    $check->("valid: example.com",      valid_domain('example.com'),        1);
    $check->("valid: a.b.example.com",  valid_domain('a.b.example.co.uk'),  1);
    $check->("valid: punycode tld",     valid_domain('example.xn--p1ai'),   1);
    $check->("invalid: no tld",         valid_domain('localhost'),          0);
    $check->("invalid: double dot",     valid_domain('a..com'),             0);
    $check->("invalid: leading hyphen", valid_domain('-bad.com'),           0);
    $check->("invalid: trailing hyph",  valid_domain('bad-.com'),           0);
    $check->("invalid: empty",          valid_domain(''),                   0);
    $check->("invalid: space",          valid_domain('a b.com'),            0);

    my ($g, $b) = parse_domains([
        "# comment\n", "\n", "  Example.COM  \n", "example.com\n",
        "https://foo.org/path\n", "trailing.net.\n", "not a domain\n",
    ]);
    $check->("parse: dedupe+normalise", join(',', @$g), 'example.com,foo.org,trailing.net');
    $check->("parse: bad count",        scalar(@$b), 1);
    $check->("parse: bad line number",  $b->[0][0], 7);

    $check->("csv: header",     csv_row('domain','ns1','ns2'), qq{"domain","ns1","ns2"\r\n});
    $check->("csv: plain row",  csv_row('a.com','x.ns.cloudflare.com','y.ns.cloudflare.com'),
                                qq{"a.com","x.ns.cloudflare.com","y.ns.cloudflare.com"\r\n});
    $check->("csv: missing ns", csv_row('a.com', undef, undef), qq{"a.com","",""\r\n});
    $check->("csv: quote escape", csv_row('a"b'), qq{"a""b"\r\n});

    # multipart encoding: CRLF everywhere, terminating boundary has trailing --
    my $mp = multipart_body('BOUND', { proxied => 'false' }, 'file', 'import.txt', "a.com. 300 IN A 1.2.3.4\n");
    $check->("multipart: opens with boundary",
             (split /\r\n/, $mp)[0], '--BOUND');
    $check->("multipart: field part",
             ($mp =~ /name="proxied"\r\n\r\nfalse\r\n/ ? 1 : 0), 1);
    $check->("multipart: file part headers",
             ($mp =~ /name="file"; filename="import\.txt"\r\nContent-Type: text\/plain\r\n\r\n/ ? 1 : 0), 1);
    $check->("multipart: closing boundary",
             ($mp =~ /\r\n--BOUND--\r\n\z/ ? 1 : 0), 1);
    $check->("multipart: body preserved",
             ($mp =~ /a\.com\. 300 IN A 1\.2\.3\.4/ ? 1 : 0), 1);

    print $fails ? "\n$fails failed\n" : "\nall passed\n";
    return $fails ? 1 : 0;
}

__END__

=encoding utf8

=head1 NAME

cf-add-domains.pl - Bulk-add domains to Cloudflare and report their nameservers

=head1 SYNOPSIS

    ./cf-add-domains.pl --file <path> [options]

    # Check which account the token belongs to
    ./cf-add-domains.pl --whoami

    # Validate the file without changing anything
    ./cf-add-domains.pl --file domains.txt --dry-run

    # Add every domain in the file
    ./cf-add-domains.pl --file domains.txt

    # Add them and also save the nameservers as CSV
    ./cf-add-domains.pl --file domains.txt --output nameservers.csv

    # Add them and load each zone from a BIND zone file
    ./cf-add-domains.pl --file domains.txt --import ./zonefiles/

    # Add them and let Cloudflare guess the records (best-effort)
    ./cf-add-domains.pl --file domains.txt --scan

    # See which zones are still awaiting activation
    ./cf-add-domains.pl --pending

    # Ask Cloudflare to re-check them (after delegating at the registrar)
    ./cf-add-domains.pl --activate

    # Continue a run that stopped at the pending-zone limit
    ./cf-add-domains.pl --file domains.txt.remaining

    # Pick an account explicitly (token sees more than one)
    ./cf-add-domains.pl --file domains.txt --account 0123456789abcdef

=head1 DESCRIPTION

Reads a list of domains from a file and creates a Cloudflare zone for each one,
printing the pair of nameservers that must be configured at the domain's
registrar to complete the delegation.

Zones are created through the Cloudflare REST API (C<POST /zones>). Wrangler is
B<not> used for this: it manages Workers resources (KV, R2, D1, Queues, and so
on) and has no C<zone> subcommand. Consequently the script needs no Node.js
installation; C<--require-wrangler> restores a hard check for the binary when a
deployment wants to guarantee its presence.

Domains already present in the account are not treated as errors: the existing
zone is fetched and its nameservers printed, so re-running the script over the
same file is safe and idempotent.

=head2 A new zone is empty

This is the single most important thing to understand before delegating.

Adding a domain through the B<dashboard> runs two separate operations that look
like one: it creates the zone, and it then runs a DNS I<quick scan> that tries
to discover the domain's existing records and preloads them.

Adding a domain through the B<API> — which is what this script does — performs
only the first. C<POST /zones> returns a zone whose record set is empty. If the
nameservers are delegated at the registrar in that state, the domain B<stops
resolving>: Cloudflare is authoritative for it and has nothing to serve.

The correct order is therefore:

=over 4

=item 1.

Create the zone.

=item 2.

Populate its records, with B<--import> (exact) or B<--scan> (best-effort).

=item 3.

B<Verify> the record set, in the dashboard or via the API.

=item 4.

Only then point the nameservers at Cloudflare, at the registrar.

=back

The script prints a prominent warning listing any zone it finished without
loading records into, precisely to stop step 4 from happening after step 1.

=head2 The pending-zone limit

Cloudflare caps how many zones an account may hold in B<pending> state at the
same time. Exceeding it fails the creation with API error B<1118>:

    You have exceeded the limit for adding zones. Please activate some zones.

Two things about this cap are easy to misread:

=over 4

=item *

It is B<not a per-run or per-hour quota>. Waiting does not lift it. It is a
ceiling on zones I<awaiting activation>, so it frees up only as pending zones
become active — which requires delegating their nameservers at the registrar.

=item *

It is B<account-wide>, not per-domain. Once one domain reports 1118, every
remaining domain in the file will report it too.

=back

The script therefore stops at the first 1118 rather than repeating an identical
error for each remaining domain. It reports how many zones are pending, writes
the domains it did not attempt to F<< <file>.remaining >>, and prints the
command to resume. Those domains are counted as B<deferred>, not failed: nothing
about them was wrong.

A large list is thus migrated in waves:

    ./cf-add-domains.pl --file domains.txt --import ./zones/
    #  ... stops at the cap, writes domains.txt.remaining

    # delegate the added zones at the registrar, wait for propagation
    ./cf-add-domains.pl --pending      # what is still waiting?
    ./cf-add-domains.pl --activate     # ask Cloudflare to re-check now

    # once some have activated, continue where it stopped
    ./cf-add-domains.pl --file domains.txt.remaining --import ./zones/

The observed batch size is a consequence of the cap and current account
standing, not a documented constant; the script never hardcodes a number and
simply reacts to error 1118 when the API reports it.

Progress and results are written to STDOUT in a colourised report; colour is
disabled automatically when STDOUT is not a terminal. All errors go to STDERR.

=head2 Input file format

One domain per line. Blank lines and C<#> comments are ignored. Entries are
normalised before use: surrounding whitespace, a C<http://> or C<https://>
scheme, any path, and a trailing dot are stripped, and the name is lowercased.
Duplicates are collapsed. Lines that are not valid domain names are reported to
STDERR and skipped, and cause a non-zero exit status.

    # production domains
    example.com
    example.net
    https://example.org/       # normalised to example.org

=head2 CSV output format

With B<--output> the results are also written as RFC 4180 CSV: every field is
quoted, embedded quotes are doubled, and lines end with CRLF. The first line is
a header.

    "domain","ns1","ns2"
    "example.com","ada.ns.cloudflare.com","bob.ns.cloudflare.com"
    "example.net","cid.ns.cloudflare.com","dee.ns.cloudflare.com"

=head1 OPTIONS

=over 4

=item B<--file, -f> I<path>

File containing the domains to add, one per line. Required unless B<--whoami>
is used.

=item B<--output, -o> I<path>

Additionally write the results to I<path> as CSV. This does not replace the
report on STDOUT; both are produced. The file is truncated if it already
exists, and is opened before the first API call so that an unwritable path
fails immediately rather than after zones have been created.

Only domains that succeeded are written. A domain whose zone was created but
whose nameservers Cloudflare has not assigned yet produces empty C<ns1>/C<ns2>
columns; re-running the script fills them in.

=item B<--whoami, -w>

Report the identity behind C<CLOUDFLARE_API_TOKEN> and exit. Queries
C<GET /user/tokens/verify> and C<GET /accounts>, then lists the accounts the
token can see.

Note that C</user/tokens/verify> only answers for B<user-owned> tokens; an
B<account-owned> token is perfectly valid yet returns error 1000 there. The
script therefore treats a verify failure as a hint rather than a verdict, and
reports the token as unusable only when both calls fail.

=item B<--account, -a> I<id>

Cloudflare account ID that will own the new zones. Defaults to
C<CLOUDFLARE_ACCOUNT_ID>; if that is unset and the token can see exactly one
account, that account is used. When the token can see several accounts and none
was selected, the script lists them and exits rather than guessing.

=item B<--dry-run, -n>

Parse and validate the input file, print what would be done, and make no
changes. Useful before a bulk run. When combined with B<--import>, it also
reports which domains have a matching zone file and which do not, so a missing
file is discovered before any zone exists.

=item B<--scan, -s>

After creating each zone, run Cloudflare's DNS quick scan — the same discovery
the dashboard performs during onboarding — and add what it finds.

The scan is B<asynchronous and three-staged>, and this matters because the
first stage alone changes nothing:

=over 4

=item 1.

C<< POST /zones/{id}/dns_records/scan/trigger >> starts a background scan. It
explicitly does B<not> add any record to the zone.

=item 2.

C<< GET /zones/{id}/dns_records/scan/review >> lists what has been discovered
so far. These records are provisional; the scan keeps finding more behind them.

=item 3.

C<< POST /zones/{id}/dns_records/scan/review >> with an C<accepts> array
commits them. Only now do the records exist in the zone.

=back

The script performs all three, polling stage 2 a few times before giving up, and
reports how many of the discovered records were accepted. Triggering without
accepting would leave exactly the empty zone this script warns about.

The older one-shot C<< POST /zones/{id}/dns_records/scan >> is marked
B<deprecated> in Cloudflare's API schema and is not used.

The result is B<best-effort by construction>. The scan queries the currently
authoritative nameservers and probes a list of common hostnames, so it finds
only what is publicly resolvable and conventionally named; internal, unusual,
or wildcard-dependent records are missed silently. A scan that reports nothing
may simply not have finished. Always verify before delegating, and prefer
B<--import> when a zone file is available.

=item B<--import, -i> I<path>

After creating each zone, load records into it from a BIND-format zone file via
C<POST /zones/{id}/dns_records/import>. Unlike B<--scan> this reproduces the
source zone exactly, and is the recommended route for a migration.

I<path> may be either:

=over 4

=item *

a B<directory>, in which the script looks for C<< <domain>.zone >>, then
C<< <domain>.txt >>, then C<< <domain>.db >> for each domain; a domain with no
matching file is reported and left empty, or

=item *

a B<single file>, permitted only when the input file contains exactly one
domain. Allowing it for several would load identical records into every zone,
so that combination is rejected before any API call.

=back

When both B<--import> and B<--scan> are given, the import runs first and the
scan is attempted only for zones the import left empty.

=item B<--proxied>

With B<--import>, mark imported proxiable records (A, AAAA, CNAME) as proxied
through Cloudflare. The default is DNS-only, which is the safer choice for a
migration: it preserves the current behaviour of the domain, and individual
records can be proxied afterwards once traffic is confirmed healthy. Rejected
if given without B<--import>.

=item B<--pending>

List the account's zones that are awaiting activation, with their nameservers,
and exit. Useful for seeing what is holding the pending-zone cap down. Does not
require B<--file>.

=item B<--activate>

Ask Cloudflare to re-run its activation check
(C<< PUT /zones/{id}/activation_check >>) for every pending zone in the
account, and exit. Does not require B<--file>.

This only makes Cloudflare look again B<sooner> than its own schedule would; it
cannot activate a zone whose nameservers do not yet point at Cloudflare. Do the
delegation at the registrar first. Cloudflare rate-limits the check to once
every 5 minutes on paid plans and once an hour on free zones.

=item B<--require-wrangler>

Fail with exit status 2 unless the C<wrangler> binary is found in C<PATH>. Off
by default, since the script does not need it.

=item B<--self-test>

Run the built-in offline assertions covering domain validation and file
parsing. Performs no network access.

=item B<--help, -h, -?>

Print a short usage summary and exit.

=item B<--man>

Print this full documentation and exit.

=back

=head1 EXIT STATUS

=over 4

=item B<0>

All domains were added (or already existed).

=item B<1>

One or more domains failed, or the input file contained invalid entries.
Domains deferred by the pending-zone limit also produce this status: the run
was incomplete, even though nothing was wrong with those domains.

=item B<2>

Usage error, or a precondition failed: no API token, unreadable file,
ambiguous account, or C<--require-wrangler> with no binary present.

=back

=head1 ENVIRONMENT VARIABLES

=over 4

=item CLOUDFLARE_API_TOKEN

Required. Cloudflare API token used for every request. Needs B<Zone:Edit> to
create zones and B<Account:Read> to enumerate accounts. A Global API Key is not
accepted. Surrounding quotes or whitespace are trimmed automatically, and a
token containing non-printable characters is rejected with a diagnostic.

=item CLOUDFLARE_ACCOUNT_ID

Optional. Default value for B<--account>.

=back

=head1 REQUIREMENTS

=over 4

=item * Getopt::Long

=item * HTTP::Tiny

=item * JSON::PP

=item * Pod::Usage

=back

All of the above ship with core Perl, so no CPAN installation is required.
HTTPS support requires C<IO::Socket::SSL> and C<Net::SSLeay>, which are present
on most distributions; verify with:

    perl -MHTTP::Tiny -e 'print HTTP::Tiny->can_ssl ? "ok\n" : "no ssl\n"'

=head1 LIMITATIONS

=over 4

=item * Zones are created as full setup (C<type: full>); partial/CNAME setup is not offered

=item * Domains are processed sequentially, with no concurrency

=item * No retry or rate-limit backoff; a transient API failure marks that domain as failed

=item * Nameservers may be absent immediately after creation, in which case re-running the script reports them

=item * The registrar side is not automated: delegation must still be configured there

=item * Without B<--import> or B<--scan> the zone is left empty; see L</"A new zone is empty">

=item * B<--scan> only discovers publicly resolvable, conventionally named records, and its asynchronous nature means a short run can accept an incomplete set

=item * B<--import> does not verify that the zone file actually belongs to the domain; a mismatched file is loaded as given

=item * Record population is not idempotent the way zone creation is: re-running B<--import> over a populated zone can duplicate records

=item * The pending-zone cap stops a large run partway; see L</"The pending-zone limit">

=item * B<--activate> re-checks every pending zone in the account, not only those from the current file

=back

=head1 SEE ALSO

Cloudflare API reference for zone creation:
L<https://developers.cloudflare.com/api/resources/zones/methods/create/>

DNS record import (BIND zone files):
L<https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/import/>

DNS record scan, trigger and review:
L<https://developers.cloudflare.com/api/resources/dns/subresources/records/subresources/scan/>

Importing and exporting DNS records:
L<https://developers.cloudflare.com/dns/manage-dns-records/how-to/import-and-export/>

=head1 AUTHOR

Rodolfo González González

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2026 Rodolfo González González.

Licensed under the GNU General Public License v3 or later. See the L<LICENSE>
file, or L<https://www.gnu.org/licenses/gpl-3.0.en.html>.

=cut
