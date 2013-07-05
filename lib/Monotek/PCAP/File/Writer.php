<?php

namespace Monotek\PCAP\File;

class Writer
{
	private $handle;
	private $magic = "a1b2c3d4";

	public function create($file)
	{
		$this->handle = @fopen($file, "w");
		if ($this->handle === false) {
			throw new \Exception("Opening '$file' failed, is the dir writable? Disk full?");
		}
	}

	public function writeHeader(\Monotek\PCAP\Header $header)
	{
		fwrite($this->handle, $header->encode($this->magic));
	}

	public function writePacket(\Monotek\PCAP\Packet $packet)
	{
		fwrite($this->handle, $packet->encode($this->magic));
	}
}
