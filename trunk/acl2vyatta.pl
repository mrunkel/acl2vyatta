#!/usr/bin/perl

# acl2vyatta.pl
#
# 1/29/09 - quick version to convert my acl's
# 1/30/09 - uploaded to code.google.com
# 
# things to do:
# add command line switches
# print basic help
# add sanity checking?
# add more acl constructs?
#
# Usage: pipe in cisco ACL statements, out come vyatta firewall rules.
# You can add lines starting with fwname: to rename the firewall name in the output midstream
# it will ignore lines it doesn't understand.
# if you are going to extend this, you would do it in the switch statement below and the final output at the bottom 

use Switch;

%actionxlate = ("permit" => "accept",
                "deny" => "drop");
$ruleinc = 5;  # default rule increment
$rulestart = 10; # starting rule number
$rulenum = $rulestart;
$firewallname = "fw-in"; #default firewall name
$debug = 0;  #set to one to see cisco input with generated output, 2 to see debugging commands

sub dec2bin {
    my $str = unpack("B32", pack("N", shift));
    $str =~ s/^0+(?=\d)//;   # otherwise you'll get leading zeros
    return $str;
}

while (<>) {
  chomp;
  # remove leading spaces
  s/^\s+//;
  # replace all occurances of two or more spaces with a single space
  s/[ \t]{2,}/ /g;
  $logging = 0;   # determines whether we enable logging in the final rule output
  print "\n\n" if ($debug > 1);
  print "#DEBUG: Currentline: $_\n" if $debug;
  $curline = $_;
  @ciscorule = split(/ /); # split currentline into individual tokens
  print "#DEBUG: ciscorule: $#ciscorule\n" if ($debug > 1);
  $curparam = 0;  # the current parameter we're processing (we loop through, but occasionally increment it for two (or more) token statements like 'host x.x.x.x'
  $v_src_ip = ''; # will hold the output source address in x.x.x.x/p format
  $v_src_port = ''; # will hold the output src_port
  $v_dst_ip = ''; # will hold the output destination address in x.x.x.x./p format
  $v_dst_port = ''; # will hold the output destination port
  $addr = 0; # determines which address we're processing, source (0) or destination (>0)
  $netlen = 32; # default prefix length
  $v_protocol = ""; # will hold the output protocol type (ip, icmp, tcp, udp)
  $invalid = 0;  # if we don't understand the current line, we set invalid and ignore it.
  $established = 0; # if established keyword is found, we generate the correct ruleset
  
  if (m/^fwname:/) { # change firewall rule name
    $invalid = 1;
    $firewallname = $';
    $rulenum = $rulestart;
    print "#DEBUG: Changed firewall name to: $firewallname\n" if ($debug);
  } else {
    $invalid = ($#ciscorule == -1);
  }
  #  1              2                3                        4                       5   6      7
  #  [permit|deny] [icmp|ip|tcp|udp] [addr mask|any|host ip] [addr mask|any|host ip] [eq] [port num] [log]
  # loop through each element in the cisco statement and parse it
  while ($curparam <= $#ciscorule and !$invalid) {
    print "\n#DEBUG: processing parameter $curparam: $ciscorule[$curparam]\n" if ($debug > 1);
    print "#DEBUG: addr = $addr\n" if ($debug > 1);
    switch ($ciscorule[$curparam]) {
      case ['permit', 'deny'] { $v_action = $actionxlate{$ciscorule[$curparam++]}; print "#DEBUG: action: $v_action - $curparam\n" if ($debug > 1)}
      case ['icmp','ip','tcp','udp'] { $v_protocol = $ciscorule[$curparam++]; print "#DEBUG: protocol: $v_protocol - $curparam\n" if ($debug > 1)}
      case 'log' {$logging = 1; $curparam++ ; print "#DEBUG: turn logging on for rule - $curparam\n" if ($debug > 1);}
      case 'any' { #set any to 0.0.0.0/0
        if ($addr++ == 0) {  #we're processing the source address
          $v_src_ip = "0.0.0.0/0";
          print "#DEBUG: src_ip =  $v_src_ip - $curparam\n" if ($debug > 1);
        } else {  #we're processing the target address
          $v_dst_ip = "0.0.0.0/0";
          print "#DEBUG: dst_ip =  $v_dst_ip - $curparam\n" if ($debug > 1);
        }
        $curparam++;
        print "#DEBUG: got an any, set to 0.0.0.0/0, incrementing addr to: $addr - curparam: $curparam\n" if ($debug > 1);
      } 
      case 'host' { # host means the next paramater is the host ip and there will be no netmask
        if ($addr++ == 0) {  #we're processing the source address
          $v_src_ip = $ciscorule[++$curparam];
          print "#DEBUG: src_ip =  $v_src_ip - $curparam\n" if ($debug > 1);
        } else {  #we're processing the target address
          $v_dst_ip = $ciscorule[++$curparam];
          print "#DEBUG: dst_ip =  $v_dst_ip - $curparam\n" if ($debug > 1);
        }
        $curparam++;
        print "#DEBUG: incremented curparam one more time for ip address. - $curparam\n" if ($debug > 1);
      }
      case 'eq' { #next parameter is the port number
        print "#DEBUG: got an eq: $ciscorule[$curparam] $ciscorule[$curparam+1] - $curparam\n" if ($debug > 1);
        if ($addr == 1) {  # this is the source port
          $v_src_port = $ciscorule[++$curparam];
          print "#DEBUG: src_port =  $v_src_port - $curparam\n" if ($debug > 1);
        } else {
          $v_dst_port = $ciscorule[++$curparam];
          print "#DEBUG: dst_port =  $v_dst_port - $curparam\n" if ($debug > 1);
        }
        $curparam++;
        print "#DEBUG: incremented curparam one more time for port#. - $curparam\n" if ($debug > 1);        
      }
      case 'range' { # port range
        print "#DEBUG: got an rang: $ciscorule[$curparam] $ciscorule[$curparam+1] to $ciscorule[$curparam+2]- $curparam\n" if ($debug > 1);
        if ($addr == 1) {  # this is the source port
          $v_src_port = $ciscorule[++$curparam] . '-' . $ciscorule[++$curparam];
          print "#DEBUG: src_port =  $v_src_port - $curparam\n" if ($debug > 1);
        } else {
          $v_dst_port = $ciscorule[++$curparam] . '-' . $ciscorule[++$curparam];
          print "#DEBUG: dst_port =  $v_dst_port - $curparam\n" if ($debug > 1);
        }
        $curparam++;
        print "#DEBUG: incremented curparam one more time for port#. - $curparam\n" if ($debug > 1);        
        
      }
      case /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/ { # IP Address
        print "#DEBUG: We got an IP address: $ciscorule[$curparam] - $curparam\n" if ($debug > 1);
        if ($ciscorule[$curparam+1] =~ /\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/) {
          # the next field is a subnet mask
          print "#DEBUG: We think we got a wildcard mask $ciscorule[$curparam+1] - $curparam\n" if ($debug > 1);
          # this is a bit of a hack, we're taking the invidual octets of the wildcard mask and making a long binary string of them.
          # we then count the number of ones, that's our / subnet mask.   It works, so don't knock it. :-)
          my $binary = dec2bin($1) . dec2bin($2) . dec2bin ($3) . dec2bin ($4);
          print "#DEBUG: binary: $binary\n" if ($debug > 1);
          $netlen = 32 - ($binary =~ tr/1//);
          print "#DEBUG: I think that's the same as a /$netlen\n" if ($debug > 1); 
          if ($addr++ == 0) {  #we're processing the source address
            $v_src_ip = $ciscorule[$curparam++] . "/" . $netlen;
            print "#DEBUG: src_ip =  $v_src_ip - $curparam\n" if ($debug > 1);
          } else {  #we're processing the target address
            $v_dst_ip = $ciscorule[$curparam++] . "/" . $netlen;
            print "#DEBUG: dst_ip =  $v_dst_ip - $curparam\n" if ($debug > 1);
          }
          $curparam++; # for the netmask
        } else { # no netmask, just store the address.
          if ($addr++ == 0) {  #we're processing the source address
            $v_src_ip = $ciscorule[$curparam++];
            print "#DEBUG: src_ip =  $v_src_ip - $curparam\n" if ($debug > 1);
          } else {  #we're processing the target address
            $v_dst_ip = $ciscorule[$curparam++];
            print "#DEBUG: dst_ip =  $v_dst_ip - $curparam\n" if ($debug > 1);
          }
        }
      }
      case 'established' { 
        $established = 1; 
        $curparam++; 
        print "#DEBUG: We got an established!\n" if ($debug > 1) 
      }
      else { $invalid = 1; print "#DEBUG: didn't understand parameter no:$curparam - $ciscorule[$curparam]\n" if ($debug > 1); $curparam++}
    } # switch $ciscorule($ciscoparam)
  } # while $curparam loop

# ok, now we're done analyzing the cisco rule, let's output the vyatta rule  
  # set firewall name $firewallname rule $rulenum action [accept|drop]
  if (!$invalid) {
    print "#DEBUG: Cisco input was: $curline\n" if ($debug > 1);
    print "set firewall name $firewallname rule $rulenum action $v_action\n";
  
    print "set firewall name $firewallname rule $rulenum protocol $v_protocol\n" if ($v_protocol ne 'ip');
    print "set firewall name $firewallname rule $rulenum protocol all\n" if ($v_protocol eq 'ip');
    print "set firewall name $firewallname rule $rulenum source address $v_src_ip\n" if $v_src_ip;
    print "set firewall name $firewallname rule $rulenum source port $v_src_port\n" if $v_src_port;
    print "set firewall name $firewallname rule $rulenum destination address $v_dst_ip\n" if $v_dst_ip;
    print "set firewall name $firewallname rule $rulenum destination port $v_dst_port\n" if $v_dst_port;
    if ($established) { # this is an established packet firewall rule
      print "set firewall name $firewallname rule $rulenum state established enable\n";
      print "set firewall name $firewallname rule $rulenum state related enable\n";
    }
    
    print "set firewall name $firewallname rule $rulenum log enable\n" if $logging;

    $rulenum += $ruleinc;  # increment the rule number and let's do it again!
  }
}

