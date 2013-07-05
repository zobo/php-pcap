<?php

namespace Monotek\PCAP;

class Header extends Encoding
{
	private $header;

	function __get($var)
	{
		if (!array_key_exists($var, $this->header)) {
			throw new \Exception("Can't find field '$var' in header data.");
		}
		return $this->header[$var];
	}

	function decode($magic, $buffer)
	{
		$encoding = $this->getEncoding($magic);

		$this->header = unpack(
				$encoding->u16 . "version_major/".
				$encoding->u16 . "version_minor/".
				$encoding->u32 . "thiszone/".
				$encoding->u32 . "sigfigs/".
				$encoding->u32 . "snaplen/".
				$encoding->u32 . "network",
				$buffer);
	}

	function encode($magic)
	{
		$encoding = $this->getEncoding($magic);

		$retval = pack($encoding->u32, hexdec($magic)));

		$retval .= pack($encoding->u16, $this->version_major);
		$retval .= pack($encoding->u16, $this->version_minor);
		$retval .= pack($encoding->u32, $this->thiszone);
		$retval .= pack($encoding->u32, $this->sigfigs);
		$retval .= pack($encoding->u32, $this->snaplen);
		$retval .= pack($encoding->u32, $this->network);

		return $retval;
	}
}