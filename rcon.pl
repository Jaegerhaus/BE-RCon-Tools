#!/usr/bin/perl

use strict;
use IO::Socket::INET;

die "Usage: $0 <host:port> <password> <command>" if @ARGV < 3;

$| = 1;
my $DEBUG = 0;

my $peeraddr = $ARGV[0];
my $password = $ARGV[1];
my $command = $ARGV[2];


my $socket = new IO::Socket::INET (
	PeerAddr => 'localhost:2302',
	Proto => 'udp'
) or die "Error: $!\n";

my ($packet, $response);

$packet = rcon_packet("\0$password");
print unpack('H*', $packet) . "\n" if $DEBUG;
$socket->send($packet) or die "Error sending password: $!\n";
$socket->recv($response, 9);
print "Login: " . pack('H*', $response) . "\n" if $DEBUG;

$packet = rcon_packet("\1\0$command");
print unpack('H*', $packet) . "\n" if $DEBUG;
$socket->send($packet) or die "Error sending command: $!\n";
$socket->recv($response, 9);
print "Command: " . pack('H*', $response) . "\n" if $DEBUG;

$socket->close();


sub rcon_packet {
	my ($payload) = @_;

	my $break = pack('C', 0xff);
	my $packet = "BE"
		. pack('V', crc32($break . $payload))
		. $break
		. $payload;

	return $packet;
}

sub crc32 {
 my ($input, $init_value, $polynomial) = @_;

 $init_value = 0 unless (defined $init_value);
 $polynomial = 0xedb88320 unless (defined $polynomial);

 my @lookup_table;

 for (my $i=0; $i<256; $i++) {
   my $x = $i;
   for (my $j=0; $j<8; $j++) {
     if ($x & 1) {
       $x = ($x >> 1) ^ $polynomial;
     } else {
       $x = $x >> 1;
     }
   }
   push @lookup_table, $x;
 }

 my $crc = $init_value ^ 0xffffffff;

 foreach my $x (unpack ('C*', $input)) {
   $crc = (($crc >> 8) & 0xffffff) ^ $lookup_table[ ($crc ^ $x) & 0xff ];
 }

 $crc = $crc ^ 0xffffffff;

 return $crc;
}
