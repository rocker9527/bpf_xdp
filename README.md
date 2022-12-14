## Требования

Чтобы запустить программу, необходимо выполнение следующих требований:

- современное ядро Linux (>4.8), поддерживающее XDP
- Python
- необходимо установить BCC и сопутствующие пакеты -> [Инструкция по установке](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

## Использование

```
python3 filter.py -h
usage: filter [-h] [-protocol PROTOCOL [PROTOCOL ...]]
                 [-p PORT [PORT ...]] [-a ACTION]
                 iface

positional arguments:
  iface                 network interface to listen
                        (e.g. eth0, see avaliable with ip a)

optional arguments:
  -h, --help            show this help message and
                        exit
  -protocol PROTOCOL [PROTOCOL ...], --protocol PROTOCOL [PROTOCOL ...]
                        Specify protocol(s) and
                        port(s), eg tcp:22, udp:53-63
  -p PORT [PORT ...], --port PORT [PORT ...]
                        Specify port(s)
  -ip IP [IP ...]
  					    Specify ip-address(es)
  -mac MAC [MAC ...]
  				    	Specify mac-address(es)                     
  -c CAPTURE, --capture CAPTURE
                        Capture to .pcap file (default dump.pcap)

```

#### Пример

Отбросить все входяшие ICMP пакеты.

```
python3 filter.py -iface enp0s6 -protocol icmp

```