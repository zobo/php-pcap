<?php

namespace Monotek\PCAP\File;

class Reader
{
	private $handle;
	private $header;
	private $magic;

	public function open($file)
	{
		$this->handle = @fopen($file, "r");
		if ($this->handle === false) {
			throw new \Exception("Opening '$file' for reading failed, does the file exist?");
		}
		$this->header = $this->getHeader();
		return $this->header;
	}

	private function getHeader()
	{
		$buffer = fread($this->handle, 4);
		$row = unpack("Vmagic", $buffer);
		$this->magic = $row['magic'];

		$buffer = fread($this->handle, 20);

		$header = new \Monotek\PCAP\Header;
		$header->decode($this->magic, $buffer);

		return $header;
	}

	public function getPacket()
	{
		if (feof($this->handle)) {
			return false;
		}
		$buffer = fread($this->handle, 16);

		$packet = new \Monotek\PCAP\Packet;
		$packet->decode($this->magic, $buffer);

		if (($packet->incl_len > min($packet->orig_len, $this->header->snaplen)) || ($packet->incl_len == 0)) {
			throw new \Exception("Bad packet header (incl_len = ".$packet->incl_len.")");
		}

		$packet->setData(fread($this->handle, $head['incl_len']));
		return $packet;
	}

}
