#!/usr/bin/env perl
# PODNAME: tcpproxy.pl
# ABSTRACT: Simple TCP proxy for debugging connections

use strict;
use warnings;

use Term::ANSIColor qw( colored );
use AnyEvent::Handle;
use AnyEvent::Socket;
use Carp qw( croak );
use DDC;
use Data::Dumper;
use Encode;

my $init_command = "1;Analyzer;123123a;1;";
my $password = 'iamabatman';
my $debug = 1;

sub logmsg {
  print colored($_[0],'yellow')."\n";
}

sub in {
  return unless $debug;  
  print colored(' IN ','yellow');
  print colored('[','blue');
  my $in = $_[0];
  Encode::from_to($in, 'cp1251', 'utf-8');
  print $in;
  print colored(']','blue')."\n";
}

sub out {
  return unless $debug;
  print colored('OUT ','yellow');
  print colored('[','blue');
  print ($_[0]);
  print colored(']','blue')."\n";
}

my %handles;
my %ips;

sub send_to_allclients {
    my $buffer = shift;
    my $args = shift;
    for my $client (values %handles) {
        next if ($args->{skip} && $args->{skip} eq $client);
        $client->push_write($buffer);
    }
}

sub close_all_clients {
    my $buffer = shift;
    for my $client (values %handles) {
        $client->push_write($buffer);
        $client->destroy;
    }
    %handles = ();
    %ips = {};
}

sub create_proxy {
  my ( $port, $remote_host, $remote_port ) = @_;

  my $ip = '127.0.0.1';

  if ($port =~ /:/) {
    ( $ip, $port ) = split(/:/,$port);
  }
  logmsg("starting proxy on $ip:$port");
  logmsg("Connecting to remote host $remote_host:$remote_port");
  my $host_h; 
  my $latest_sent_buffer = '';
  
  tcp_connect $remote_host, $remote_port, sub {
      unless(@_) {
          logmsg("connection failed: $!");
          return;
      }
      my ( $host_fh ) = @_;
      $host_h = AnyEvent::Handle->new(
          fh => $host_fh,
      );

      $host_h->on_read(sub {
        my $buffer    = $host_h->rbuf;
        $host_h->rbuf = '';
        in($buffer);
        my $input = $buffer;
        Encode::from_to($input, 'cp1251', 'utf-8');
        if (0 && $input =~ /Вы хотите есть\./) {#disabled
            $host_h->push_write("scan;\n");
        }
        send_to_allclients($buffer);
        $latest_sent_buffer = $buffer;
    });

      $host_h->on_error(sub {
        my ( undef, undef, $msg ) = @_;
        logmsg("transmission error: $msg");
        $host_h->destroy;
        close_all_clients("Server CRASHED. But ill handle it, reconnect");
        goto LETSTRYAGAIN;
        #TODO: Handle error properly  
    });

      $host_h->on_eof(sub {
        logmsg("host closed connection");
        close_all_clients("Server closed connection, I cant handle it properly, i will restart internally but i have to disconnect you. Please reconnect\n");
        goto LETSTRYAGAIN;
    });
    #$host_h->push_write($init_command);

  };

  return tcp_server $ip, $port, sub {
    my ( $client_fh, $client_host, $client_port ) = @_;
    logmsg("received connection from $client_host:$client_port");
    send_to_allclients("\nReceived connection from $client_host:$client_port\n");
    my $client_h = AnyEvent::Handle->new(
      fh => $client_fh,
    );

    $ips{$client_h} = "$client_host:$client_port";

    $client_h->on_read(sub {
        my $buffer      = $client_h->rbuf;
        $client_h->rbuf = '';
        out($buffer);
        if ($handles{$client_h}) {
            if ($host_h) {
                my $chomped = $buffer;
                chomp $chomped;
                $host_h->push_write($buffer);
                send_to_allclients("[" . $ips{$client_h} . "]: '$chomped'\n", {skip => $client_h} );
            } else {
                $client_h->push_write("I dont have connection with server, so i just ignored what you asked me to send. Try again later.\n\n");
            }
        } else {
            if ($buffer =~ /^$password/) {
                $handles{$client_h} = $client_h;
                my $ipstring = join ("\n", values %ips);
                send_to_allclients("\n\nNEW CLIENT AUTHORIZED AND CAN SEND AND RECIEVE COMMANDS NOW " . $ips{$client_h} . "\n\n");
                $client_h->push_write("Good, you are authenticated now.\n Currently online clients: $ipstring\nHere is what we have sent to the client before you connected\n\n: $latest_sent_buffer");
        } else {
                $client_h->push_write("Go away\n");
            }
        }
    });

    $client_h->on_error(sub {
        my ( undef, undef, $msg ) = @_;
        logmsg("transmission error: $msg");
        send_to_allclients("\n\n " . $ips{$client_h} . " disconnected.\n",  {skip => $client_h});
        $client_h->destroy;
        delete $handles{$client_h};
        delete $ips{$client_h};
    });

      $client_h->on_eof(sub {
        logmsg("client closed connection");
        send_to_allclients("\n\n " . $ips{$client_h} . " disconnected.\n",  {skip => $client_h});
        $client_h->destroy;

        delete $handles{$client_h};
        delete $ips{$client_h};
      });
      $client_h->push_write("Open port, yummy. Go away\n");
    };
}

my ( $port, $remote_host, $remote_port ) = (qw(37.139.4.87:5000 46.161.2.20 4000));

LETSTRYAGAIN:
while(1) {
    my $cond = AnyEvent->condvar;
    my $proxy = create_proxy($port, $remote_host, $remote_port);
    $cond->recv;
}
