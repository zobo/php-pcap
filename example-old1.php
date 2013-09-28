<?php

require("pcap.php");

if (isset($argv[1]) && $argv[1] == "-") {
	$argv[1] = "php://stdin";
} else {
	if (!isset($argv[1]) || !file_exists($argv[1])) die("Missing file\n");
}

$p = new pcap_file_reader();
$r = $p->open($argv[1]);

while ($s = $p->read_packet())
{
	$eth = parse_ethframe($s['data']);
	$ip = parse_ip($eth['data']);
	echo date("H:i:s", $s['ts_sec']).".".$s['ts_usec']." ".$ip['source_ip']." > ".$ip['destination_ip']."\n";
}
