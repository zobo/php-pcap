<?php

namespace Monotek\PCAP;

class Header extends Encoding
{
	private $packet;

	function __get($var)
	{
		if (!array_key_exists($var, $this->packet)) {
			throw new \Exception("Can't find field '$var' in packet data.");
		}
		return $this->packet[$var];
	}

	function decode($magic, $buffer)
	{
		$encoding = $this->getEncoding($magic);

		$this->packet = unpack(
				$encoding->u32 . "ts_sec/".
				$encoding->u32 . "ts_usec/".
				$encoding->u32 . "incl_len/".
				$encoding->u32 . "orig_len",
				$buffer);
	}

	function setData($data)
	{
		$this->packet['data'] = $data;
	}

	function encode($magic)
	{
		$encoding = $this->getEncoding($magic);

		$retval = pack($encoding->u32, hexdec($magic)));

		$retval .= pack($encoding->u32, $this->ts_sec);
		$retval .= pack($encoding->u32, $this->ts_usec);
		$retval .= pack($encoding->u32, $this->incl_len);
		$retval .= pack($encoding->u32, $this->orig_len);
		$retval .= $this->data;

		return $retval;
	}
}