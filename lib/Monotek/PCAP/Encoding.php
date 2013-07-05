<?php

class Encoding
{
	function getEncoding($magic)
	{
		switch ($magic) {
			case "a1b2c3d4":
				$u32 = "V";
				$u16 = "v";
				break;
			case "d4c3b2a1":
				$u32 = "N";
				$u32 = "n";
				break;
			default:
				throw new \Exception("Unknown encoding: '" . $magic . "'");
				break;
		}
		return compact("u16", "u32");
	}
}