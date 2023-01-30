# Projekt

Implementační dokumentace k IPK Project 2

Jméno a příjmení: Ivan Golikov

Login: xgolik00

## Účel snifferu

Účelem snifferu je analyzovat síť a filtrovat pakety v ní podle předdefinovaného filtru a předdefinovaného rozhraní.

## Kompilace

Kompilace se provádí pomocí Makefile. Pro sestavení kódu budete muset zadat `make ipk-sniffer` nebo `make`. Chcete-li odstranit vygenerované kompilované soubory, zadejte `make clean`.

## Volání programu

`./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}`

### Parametry

-i eth0 (právě jedno rozhraní, na kterém se bude poslouchat. Nebude-li tento parametr uveden, či bude-li uvedené jen -i bez hodnoty, vypíše se seznam aktivních rozhraní)

-p 23 (bude filtrování paketů na daném rozhraní podle portu; nebude-li tento parametr uveden, uvažují se všechny porty; pokud je parametr uveden, může se daný port vyskytnout jak v source, tak v destination části)

-t nebo --tcp (bude zobrazovat pouze TCP pakety)

-u nebo --udp (bude zobrazovat pouze UDP pakety)

--icmp (bude zobrazovat pouze ICMPv4 a ICMPv6 pakety)

--arp (bude zobrazovat pouze ARP rámce)

-n 10 (určuje počet paketů, které se mají zobrazit, tj. i "dobu" běhu programu; pokud není uvedeno, uvažujte zobrazení pouze jednoho paketu, tedy jakoby -n 1)

-h nebo --help (píše HELP())

### Omezení

1. Nepodařilo se implementovat filtrování ARP
2. Nelze použít filtr pro více protokolů (pokud je zadáno více protokolů, pcap_compile() vyvolá chybu)
3. Nelze kombinovat protokol ICMP a port (stejná chyba jako v druhém odstavci)

### Příklady spuštění

$ sudo ./sniffer -i eth0 -p 80 -n 2 -u
$ sudo ./sniffer -i wlp5s0 -n 80 -t
$ sudo ./sniffer -i 