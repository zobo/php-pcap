<?php


class pcap_file_reader
{

	private $f;
	private $u32 = "V";
	private $u16 = "v";
	private $global_header;
	private $count;

	function open($file)
	{
		$this->f = fopen($file, "r");
		$r = $this->read_global_header();
		$this->count = 1;
		return $r;
	}

	function close()
	{
		fclose($this->f);
	}

	private function read_global_header()
	{
		$buf = fread($this->f, 4);
		$x = unpack($this->u32."magic", $buf);
		if (sprintf("%x",$x['magic']) == "a1b2c3d4") {
			$this->u32 = "V";
			$this->u16 = "v";
		} else
		if (sprintf("%x",$x['magic']) == "d4c3b2a1") {
			$this->u32 = "N";
			$this->u16 = "n";
		} else {
			throw new Exception("Unknown file format");
		}
		$buf = fread($this->f, 20);
		$this->global_header = unpack($this->u16."version_major/".
				$this->u16."version_minor/".
				$this->u32."thiszone/".
				$this->u32."sigfigs/".
				$this->u32."snaplen/".
				$this->u32."network",
				$buf);
		return $this->global_header;
	}

	public function read_packet()
	{
		$buf = fread($this->f, 16);
		if (feof($this->f)) return false;
		$head = unpack($this->u32."ts_sec/".
				$this->u32."ts_usec/".
				$this->u32."incl_len/".
				$this->u32."orig_len/",
				$buf);
		if ($head['incl_len'] > $head['orig_len'] || $head['incl_len'] > $this->global_header['snaplen']) {
			throw new Exception("Bad packet header (incl_len)");
		}
		if ($head['incl_len'] == 0) {
			var_dump($buf);
			var_dump($head);die("0???\n");
		}
		$head['count'] = $this->count++;
		$head['data'] = fread($this->f, $head['incl_len']);
		return $head;
	}

}

class pcap_file_writer
{

	private $f;
	private $u32 = "V"; // L ?
	private $u16 = "v"; // S ?
	private $global_header;

	function open($file)
	{
		$this->f = fopen($file, "w");
	}

	public function write_global_header($head)
	{
		fwrite($this->f, pack($this->u32, 0xa1b2c3d4));
		fwrite($this->f, pack($this->u16.$this->u16.$this->u32.$this->u32.$this->u32.$this->u32,
					$head['version_major'],
					$head['version_minor'],
					$head['thiszone'],
					$head['sigfigs'],
					$head['snaplen'],
					$head['network']));
	}

	public function write_packet($head)
	{
		fwrite($this->f, pack($this->u32.$this->u32.$this->u32.$this->u32,
				$head['ts_sec'],
				$head['ts_usec'],
				$head['incl_len'],
				$head['orig_len']));
		fwrite($this->f, $head['data']); //$data
	}

}



function parse_sip($data)
{
	$lines = explode("\r\n", $data);
	$ret['command'] = $lines[0];
	unset($lines[0]);
	foreach ($lines as $line) {
		if ($line == "") break; // dont care about data
		list($k,$v) = explode(": ", $line, 2);
		$ret[$k] = $v;
	}
	list(,$ret['data']) = explode("\r\n\r\n", $data, 2);
	return $ret;
}

function cut_ip($data)
{
	return substr($data,14);
}

function parse_ethframe($data)
{
	$x = unpack("nethertype", substr($data,12,2));
	$x['destination_mac'] = bin2hex(substr($data,0,6));
	$x['source_mac'] = bin2hex(substr($data,6,6));
	$x['data'] = substr($data,14);
	return $x;
}

function parse_ip($data)
{
	$x = unpack("Cversion_ihl/Cservices/nlength/nidentification/nflags_offset/Cttl/Cprotocol/nchecksum/Nsource/Ndestination", $data);
	$x['version'] = $x['version_ihl'] >> 4;
	$x['ihl'] = $x['version_ihl'] & 0xf;
	unset($x['version_ihl']);
	$x['flags'] = $x['flags_offset'] >> 13;
	$x['offset'] = $x['flags_offset'] & 0x1fff;
	$x['source_ip'] = long2ip($x['source']);
	$x['destination_ip'] = long2ip($x['destination']);
	$x['data'] = substr($data,$x['ihl']*4,$x['length']-$x['ihl']*4); // ignoring options
	return $x;
}

function parse_udp($data)
{
	$x = unpack("nsource_port/ndestination_port/nlength/nchecksum",$data);
	$x['data'] = substr($data,8,$x['length']-8);
	return $x;
}

function get_media_port($dict)
{
	if (!isset($dict['Content-Type'])) return false;
	if ($dict['Content-Type'] != "application/sdp") return false;

	if (preg_match("/m=audio ([0-9]+) /s", $dict['data'], $match)) {
		return intval($match[1]);
	}
	return false;
}


function parse_tcp($data)
{
	$x = unpack("nsource_port/ndestination_port/Nseq/Nack/Ctmp1/Ctmp2/nwindow/nchecksum/nurgent", $data);
	$x['offset'] = ($x['tmp1']>>4)&0xf;
	$x['flag_NS'] = ($x['tmp1']&0x01) != 0;
	$x['flag_CWR'] = ($x['tmp2']&0x80) != 0;
	$x['flag_ECE'] = ($x['tmp2']&0x40) != 0;
	$x['flag_URG'] = ($x['tmp2']&0x20) != 0;
	$x['flag_ACK'] = ($x['tmp2']&0x10) != 0;
	$x['flag_PSH'] = ($x['tmp2']&0x08) != 0;
	$x['flag_RST'] = ($x['tmp2']&0x04) != 0;
	$x['flag_SYN'] = ($x['tmp2']&0x02) != 0;
	$x['flag_FIN'] = ($x['tmp2']&0x01) != 0;
	unset($x['tmp1']);
	unset($x['tmp2']);
	$x['data'] = substr($data, 4*$x['offset']);
	return $x;
}



