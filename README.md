php-pcap
========
A library to read pcap files.

This is a small class I wrote when I needed to parse pcap files, the idea is to add more structured protocol parsing classes and a way to easily add new "disectors".

pcap.php - The original implementation (pcap file reader and writer, some basic protocol parsers).
example-old*.php - Examples against the original implementation.
lib/ - New implementation (incomplete, only pcap reader/writer, no protocol parsers yet).
