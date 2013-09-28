<?php

require("pcap.php");

if (isset($argv[1]) && $argv[1] == "-") {
	$argv[1] = "php://stdin";
} else {
	if (!isset($argv[1]) || !file_exists($argv[1])) die("Missing file\n");
}
$filter = false;
if (isset($argv[2])) {
	$filter = $argv[2];
}

$p = new pcap_file_reader();
$r = $p->open($argv[1]);

$reg = array();
$num = array();

while ($s = $p->read_packet())
{
	$eth = parse_ethframe($s['data']);
	$ip = parse_ip($eth['data']);
	if ($ip['protocol'] == 6) {
		$tcp = parse_tcp($ip['data']);
		$data = $tcp['data'];
		$line = date("H:i:s", $s['ts_sec']).".".$s['ts_usec']." ".$ip['source_ip'].":".$tcp['source_port']." > ".$ip['destination_ip'].":".$tcp['destination_port']." TCP";
	} else if ($ip['protocol'] == 17) {
		$udp = parse_udp($ip['data']);
		$data = $udp['data'];
		$line = date("H:i:s", $s['ts_sec']).".".$s['ts_usec']." ".$ip['source_ip'].":".$udp['source_port']." > ".$ip['destination_ip'].":".$udp['destination_port']." UDP";
	} else {
		continue;
	}

	if ($filter !== false) {
		if (strpos($data,$filter) === false) continue;
	}

	echo $line."\n";
	if ($filter !== false) {
		var_dump($data);
	}
}
