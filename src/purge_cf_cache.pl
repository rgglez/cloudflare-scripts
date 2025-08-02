#!/usr/bin/env perl

#    Cloudflare Cache Purge Script (Perl) - Enhanced Version
#    Copyright (C) 2025 Rodolfo González González
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

# Usage: ./purge_cf_cache.pl --zone <zone_name> [--purge-type <type>] [--targets <target1,target2,...>]
# Example: ./purge_cf_cache.pl --zone example.com --purge-type hostname --targets "www.example.com,api.example.com"

use strict;
use warnings;
use LWP::UserAgent;
use JSON;
use HTTP::Request;
use Getopt::Long;
use Pod::Usage;

# Command line options
my $zone;
my $purge_type = 'everything';  # Default to purge everything
my $targets;
my $help = 0;
my $man = 0;
my $verbose = 0;

# Parse command line options
GetOptions(
    'zone|z=s'       => \$zone,
    'purge-type|t=s' => \$purge_type,
    'targets|target=s' => \$targets,
    'verbose|v'      => \$verbose,
    'help|?'         => \$help,
    'man'            => \$man,
) or pod2usage(2);

# Show help or man page if requested
pod2usage(1) if $help;
pod2usage(-exitval => 0, -verbose => 2) if $man;

# Check if zone is provided
if (!$zone) {
    print "Error: --zone parameter is required\n";
    pod2usage(1);
}

# Validate purge type
my @valid_types = qw(everything hostname url files prefix tags);
unless (grep { $_ eq $purge_type } @valid_types) {
    print "Error: Invalid purge type '$purge_type'\n";
    print "Valid types: " . join(', ', @valid_types) . "\n";
    exit 1;
}

# Check if targets are required for specific purge types
if ($purge_type ne 'everything' && !$targets) {
    print "Error: --targets parameter is required for purge type '$purge_type'\n";
    print "Example: --targets \"url1,url2,url3\"\n";
    exit 1;
}

# Parse targets into array
my @target_list = ();
if ($targets) {
    @target_list = split(/,/, $targets);
    # Trim whitespace
    @target_list = map { s/^\s+|\s+$//gr } @target_list;
}

# Check for required environment variables
my $cf_api_token = $ENV{'CF_API_TOKEN'};
my $cf_api_key = $ENV{'CF_API_KEY'};
my $cf_email = $ENV{'CF_EMAIL'};

if (!$cf_api_token && !$cf_api_key) {
    print "Error: Either CF_API_TOKEN or CF_API_KEY must be set\n";
    print "For API Token (recommended): export CF_API_TOKEN='your-api-token'\n";
    print "For API Key: export CF_API_KEY='your-api-key' and CF_EMAIL='your-email'\n";
    exit 1;
}

if ($cf_api_key && !$cf_email) {
    print "Error: CF_EMAIL must be set when using CF_API_KEY\n";
    exit 1;
}

# Set API base URL
my $api_base = "https://api.cloudflare.com/client/v4";

# Create user agent
my $ua = LWP::UserAgent->new;
$ua->timeout(30);
$ua->agent("CloudflareCache-Purger/2.0");

# JSON parser
my $json = JSON->new;

# Function to make API calls
sub make_api_call {
    my ($endpoint, $method, $data) = @_;
    $method ||= 'GET';
    
    my $url = "$api_base$endpoint";
    my $request = HTTP::Request->new($method => $url);
    
    # Set authentication headers
    if ($cf_api_token) {
        $request->header('Authorization' => "Bearer $cf_api_token");
    } else {
        $request->header('X-Auth-Key' => $cf_api_key);
        $request->header('X-Auth-Email' => $cf_email);
    }
    
    if ($method eq 'POST' && $data) {
        $request->header('Content-Type' => 'application/json');
        $request->content($data);
        
        if ($verbose) {
            print "API Request:\n";
            print "URL: $url\n";
            print "Data: $data\n\n";
        }
    }
    
    my $response = $ua->request($request);
    
    if (!$response->is_success) {
        die "HTTP request failed: " . $response->status_line . "\n";
    }
    
    return $response->content;
}

# Function to parse JSON response and check for errors
sub parse_response {
    my ($response_text) = @_;
    
    if ($verbose) {
        print "API Response:\n$response_text\n\n";
    }
    
    my $response;
    eval {
        $response = $json->decode($response_text);
    };
    
    if ($@) {
        die "Failed to parse JSON response: $@\n";
    }
    
    if (!$response->{success}) {
        my $errors = $response->{errors} || [];
        my $error_msg = "API request failed:\n";
        
        for my $error (@$errors) {
            $error_msg .= "  - Code: $error->{code}, Message: $error->{message}\n";
        }
        
        die $error_msg;
    }
    
    return $response;
}

# Function to print with emoji (works on most modern terminals)
sub print_status {
    my ($emoji, $message) = @_;
    print "$emoji $message\n";
}

# Function to build purge data based on type
sub build_purge_data {
    my ($type, @targets) = @_;
    
    if ($type eq 'everything') {
        return $json->encode({
            purge_everything => JSON::true
        });
    }
    elsif ($type eq 'hostname') {
        return $json->encode({
            hosts => \@targets
        });
    }
    elsif ($type eq 'url' || $type eq 'files') {
        return $json->encode({
            files => \@targets
        });
    }
    elsif ($type eq 'prefix') {
        # Validate prefix count (max 30)
        if (@targets > 30) {
            die "Error: Maximum 30 prefixes allowed per request. You provided " . scalar(@targets) . "\n";
        }
        return $json->encode({
            prefixes => \@targets
        });
    }
    elsif ($type eq 'tags') {
        return $json->encode({
            tags => \@targets
        });
    }
    else {
        die "Unsupported purge type: $type\n";
    }
}

# Function to validate targets based on purge type
sub validate_targets {
    my ($type, @targets) = @_;
    
    if ($type eq 'url' || $type eq 'files') {
        for my $target (@targets) {
            unless ($target =~ /^https?:\/\//) {
                die "Error: URL '$target' must start with http:// or https://\n";
            }
        }
    }
    elsif ($type eq 'prefix') {
        for my $target (@targets) {
            unless ($target =~ /^https?:\/\//) {
                die "Error: Prefix '$target' must start with http:// or https://\n";
            }
        }
    }
    elsif ($type eq 'hostname') {
        for my $target (@targets) {
            if ($target =~ /^https?:\/\//) {
                die "Error: Hostname '$target' should not include protocol (http/https)\n";
            }
        }
    }
}

print_status("🔍", "Looking up zone ID for zone: $zone");

# Get zone ID for the zone
my $zones_response_text = make_api_call("/zones?name=$zone");
my $zones_response = parse_response($zones_response_text);

# Extract zone ID
my $zone_id;
my $zones = $zones_response->{result} || [];

if (@$zones == 0) {
    print_status("❌", "Zone not found for zone name: $zone");
    print "Make sure the zone name is correct and you have access to manage it\n";
    exit 1;
}

$zone_id = $zones->[0]->{id};

if (!$zone_id) {
    print_status("❌", "Could not extract zone ID from response");
    exit 1;
}

print_status("✅", "Found zone ID: $zone_id");

# Show purge details
if ($purge_type eq 'everything') {
    print_status("🗑", "Purging ALL cache for $zone...");
} else {
    print_status("🎯", "Purging cache ($purge_type) for $zone...");
    if ($verbose && @target_list) {
        print "Targets:\n";
        for my $target (@target_list) {
            print "  - $target\n";
        }
    }
}

# Validate targets
if (@target_list) {
    validate_targets($purge_type, @target_list);
}

# Build purge data
my $purge_data = build_purge_data($purge_type, @target_list);

# Make purge request
my $purge_response_text = make_api_call("/zones/$zone_id/purge_cache", "POST", $purge_data);
my $purge_response = parse_response($purge_response_text);

print_status("✅", "Cache purged successfully for $zone");

# Display purge details
if ($purge_response->{result}) {
    my $result = $purge_response->{result};
    
    if ($result->{id}) {
        print_status("📋", "Purge ID: $result->{id}");
    }
    
    if ($verbose && $result->{files_purged}) {
        print_status("📊", "Files purged: $result->{files_purged}");
    }
}

print_status("🎉", "Cache purge completed!");

__END__

=head1 NAME

purge_cf_cache.pl - Advanced Cloudflare cache purging tool

=head1 SYNOPSIS

    ./purge_cf_cache.pl --zone <zone_name> [options]

    # Purge everything (default)
    ./purge_cf_cache.pl --zone example.com

    # Purge by hostname
    ./purge_cf_cache.pl --zone example.com --purge-type hostname --targets "www.example.com,api.example.com"

    # Purge specific URLs
    ./purge_cf_cache.pl --zone example.com --purge-type url --targets "https://example.com/page1.html,https://example.com/image.jpg"

    # Purge by prefix
    ./purge_cf_cache.pl --zone example.com --purge-type prefix --targets "https://example.com/images/,https://example.com/css/"

    # Purge by cache tags
    ./purge_cf_cache.pl --zone example.com --purge-type tags --targets "blog-posts,user-content"

=head1 DESCRIPTION

This script provides advanced cache purging capabilities for Cloudflare using their API.
It supports multiple purge types including hostname-based, URL-based, prefix-based, and tag-based purging.

=head1 OPTIONS

=over 4

=item B<--zone, -z>

Zone name to purge cache for (required). This is the domain name registered in Cloudflare.

=item B<--purge-type, -t>

Type of purge to perform. Valid options:

=over 8

=item B<everything> (default)

Purges all cached content for the zone

=item B<hostname>

Purges all assets for specific hostnames

=item B<url> or B<files>

Purges specific URLs/files

=item B<prefix>

Purges all URLs that start with specified prefixes

=item B<tags>

Purges all content with specific cache tags

=back

=item B<--targets, --target>

Comma-separated list of targets for the purge operation. Required for all purge types except 'everything'.

Examples:
  --targets "www.example.com,api.example.com" (for hostname)
  --targets "https://example.com/file1.jpg,https://example.com/file2.css" (for url)
  --targets "https://example.com/images/,https://example.com/css/" (for prefix)
  --targets "blog-posts,user-images" (for tags)

=item B<--verbose, -v>

Enable verbose output showing API requests and responses

=item B<--help, -?>

Print a brief help message and exit

=item B<--man>

Print the manual page and exit

=back

=head1 EXAMPLES

=over 4

=item B<Purge everything (default behavior)>

    ./purge_cf_cache.pl --zone example.com

=item B<Purge specific hostnames>

    ./purge_cf_cache.pl --zone example.com --purge-type hostname --targets "www.example.com,blog.example.com"

=item B<Purge specific files>

    ./purge_cf_cache.pl --zone example.com --purge-type url --targets "https://example.com/style.css,https://example.com/app.js"

=item B<Purge by URL prefix>

    ./purge_cf_cache.pl --zone example.com --purge-type prefix --targets "https://example.com/images/,https://example.com/uploads/"

=item B<Purge by cache tags>

    ./purge_cf_cache.pl --zone example.com --purge-type tags --targets "product-images,blog-content"

=item B<Verbose mode>

    ./purge_cf_cache.pl --zone example.com --purge-type hostname --targets "www.example.com" --verbose

=back

=head1 ENVIRONMENT VARIABLES

=over 4

=item CF_API_TOKEN

Cloudflare API Token (recommended authentication method)

=item CF_API_KEY

Cloudflare API Key (legacy authentication method)

=item CF_EMAIL

Email address associated with Cloudflare account (required when using CF_API_KEY)

=back

=head1 REQUIREMENTS

=over 4

=item * LWP::UserAgent

=item * JSON

=item * HTTP::Request

=item * Getopt::Long

=item * Pod::Usage

=back

Install required modules with:
    cpan LWP::UserAgent JSON Getopt::Long Pod::Usage

=head1 LIMITATIONS

=over 4

=item * Maximum 30 prefixes per purge request

=item * URLs must include the full protocol (http:// or https://)

=item * Hostnames should not include the protocol

=item * Rate limits apply based on your Cloudflare plan

=back

=head1 AUTHOR

Enhanced Cloudflare cache purging tool

=cut
