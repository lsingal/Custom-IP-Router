router: router.o protocol.o main.o arp.o if.o icmp.o
	gcc -o routerex -g protocol.o main.o arp.o if.o router.o icmp.o -lpcap -lpthread
main.o: main.c
	gcc -g -c -Wall main.c main.h
router.o: router.c router.h
	gcc -g -c -Wall router.c router.h
protocol.o: protocol.c protocol.h
	gcc -g -c -Wall protocol.c if.h
arp.o: arp.c
	gcc -g -c -Wall arp.c
if.o: if.c if.h
	gcc -g -c -Wall if.c
icmp.o: icmp.c icmp.h
	gcc -g -c -Wall icmp.c
clean:
	rm -f *.o *.gch router
