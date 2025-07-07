CC=gcc
CFLAGS=-g
TARGET:_out/VirtualRouter.exe CommandParser/libcli.a _out/pkt_gen.exe
LIBS=-lpthread -L ./CommandParser -lcli 
OBJS=_out/glueThread/glthread.o	\
		_out/graph.o			\
		_out/topologies.o		\
		_out/main.o				\
		_out/net.o				\
		_out/nwcli.o				\
		_out/comm.o				\
		_out/utils.o				\
		_out/Layer2/layer2.o		\
		_out/Layer2/l2switch.o	\
		_out/Layer3/layer3.o		\
		_out/Layer3/ip.o		    \
		_out/Layer5/layer5.o		\
		_out/Layer5/spf_algo/spf.o	\
		_out/Layer5/ping.o		\
		_out/tcpip_notif.o	 	\
		_out/tcp_ip_trace.o		\
		_out/tcp_ip_stack_init.o	\
		_out/notif.o				\
		_out/WheelTimer/WheelTimer.o	\
		_out/WheelTimer/timerlib.o	\
		_out/Layer5/isis/isis_cli.o	\
		_out/Layer5/isis/isis_rtr.o	\
		_out/Layer5/isis/isis_intf.o	\
		_out/Layer5/isis/isis_pkt.o	\
		_out/Layer5/isis/isis_lsdb.o	\
		_out/Layer5/isis/isis_flood.o\
		_out/Layer5/isis/isis_l2map.o\
		_out/Layer5/isis/isis_adjacency.o	\
		_out/EventDispatcher/event_dispatcher.o	\
		_out/avlTree/avlTree.o

_out/VirtualRouter.exe:${OBJS} CommandParser/libcli.a
	${CC} ${CFLAGS} ${OBJS} -o _out/VirtualRouter.exe ${LIBS}

_out/pkt_gen.exe:_out/pkt_gen.o _out/utils.o
	$(CC) $(CFLAGS) -I tcp_public.h _out/pkt_gen.o _out/utils.o _out/Layer3/ip.o -o _out/pkt_gen.exe

_out/pkt_gen.o:pkt_gen.c
	$(CC) $(CFLAGS) -c pkt_gen.c -I . -I Layer3 -o _out/pkt_gen.o

_out/main.o:main.c
	${CC} ${CFLAGS} -c main.c -I . -o _out/main.o

_out/glueThread/glthread.o:glueThread/glthread.c
	${CC} ${CFLAGS} -c glueThread/glthread.c -I glueThread -o _out/glueThread/glthread.o 

_out/graph.o:graph.c
	${CC} ${CFLAGS} -c graph.c -I . -o _out/graph.o

_out/topologies.o:topologies.c
	${CC} ${CFLAGS} -c topologies.c -I . -o _out/topologies.o

_out/net.o:net.c
	${CC} ${CFLAGS} -c net.c -I . -o _out/net.o

_out/nwcli.o:nwcli.c
	${CC} ${CFLAGS} -c nwcli.c -I . -I BitOp/ -o _out/nwcli.o

_out/comm.o:comm.c
	${CC} ${CFLAGS} -c comm.c -I . -o _out/comm.o

_out/utils.o:utils.c
	${CC} ${CFLAGS} -c utils.c -I . -o _out/utils.o

_out/tcpip_notif.o:tcpip_notif.c
	${CC} ${CFLAGS} -c tcpip_notif.c -I . -o _out/tcpip_notif.o

_out/tcp_ip_trace.o:tcp_ip_trace.c
	${CC} ${CFLAGS} -c tcp_ip_trace.c -I . -o _out/tcp_ip_trace.o

_out/tcp_ip_stack_init.o:tcp_ip_stack_init.c
	${CC} ${CFLAGS} -c tcp_ip_stack_init.c -I . -o _out/tcp_ip_stack_init.o

_out/Layer2/layer2.o:Layer2/layer2.c
	${CC} ${CFLAGS} -c Layer2/layer2.c -I . -o _out/Layer2/layer2.o

_out/Layer2/l2switch.o:Layer2/l2switch.c
	${CC} ${CFLAGS} -c Layer2/l2switch.c -I . -o _out/Layer2/l2switch.o	

_out/Layer3/layer3.o:Layer3/layer3.c
	${CC} ${CFLAGS} -c Layer3/layer3.c -I . -o _out/Layer3/layer3.o

_out/Layer3/ip.o:Layer3/ip.c
	${CC} ${CFLAGS} -c Layer3/ip.c -I . -o _out/Layer3/ip.o

_out/Layer5/ping.o:Layer5/ping.c
	${CC} ${CFLAGS} -c Layer5/ping.c -I . -o _out/Layer5/ping.o	

_out/Layer5/layer5.o:Layer5/layer5.c
	${CC} ${CFLAGS} -c Layer5/layer5.c -I . -o _out/Layer5/layer5.o

_out/Layer5/spf_algo/spf.o:Layer5/spf_algo/spf.c
	${CC} ${CFLAGS} -c Layer5/spf_algo/spf.c -I . -o _out/Layer5/spf_algo/spf.o

_out/notif.o:notif.c
	${CC} ${CFLAGS} -c notif.c -I . -o _out/notif.o

_out/WheelTimer/WheelTimer.o:WheelTimer/WheelTimer.c
	${CC} ${CFLAGS} -c WheelTimer/WheelTimer.c -I . -I WheelTimer/ -o _out/WheelTimer/WheelTimer.o

_out/WheelTimer/timerlib.o:WheelTimer/timerlib.c
	${CC} ${CFLAGS} -c WheelTimer/timerlib.c -I . -I WheelTimer/ -o _out/WheelTimer/timerlib.o

_out/EventDispatcher/event_dispatcher.o:EventDispatcher/event_dispatcher.c
	${CC} ${CFLAGS} -c EventDispatcher/event_dispatcher.c -I . -I EventDispatcher/ -o _out/EventDispatcher/event_dispatcher.o

_out/Layer5/isis/isis_cli.o:Layer5/isis/isis_cli.c
	${CC} ${CFLAGS} -c Layer5/isis/isis_cli.c -I . -I Layer5/ -o _out/Layer5/isis/isis_cli.o

_out/Layer5/isis/isis_rtr.o:Layer5/isis/isis_rtr.c
	${CC} ${CFLAGS} -c Layer5/isis/isis_rtr.c -I . -I Layer5/ -o _out/Layer5/isis/isis_rtr.o

_out/Layer5/isis/isis_intf.o:Layer5/isis/isis_intf.c
	${CC} ${CFLAGS} -c Layer5/isis/isis_intf.c -I . -I Layer5/ -o _out/Layer5/isis/isis_intf.o

_out/Layer5/isis/isis_pkt.o:Layer5/isis/isis_pkt.c
	${CC} ${CFLAGS} -c Layer5/isis/isis_pkt.c -I . -I Layer5/ -o _out/Layer5/isis/isis_pkt.o

_out/Layer5/isis/isis_adjacency.o:Layer5/isis/isis_adjacency.c
	${CC} ${CFLAGS} -c Layer5/isis/isis_adjacency.c -I . -I Layer5/ -o _out/Layer5/isis/isis_adjacency.o

_out/Layer5/isis/isis_lsdb.o:Layer5/isis/isis_lsdb.c
	${CC} ${CFLAGS} -c Layer5/isis/isis_lsdb.c -I . -I Layer5/ -o _out/Layer5/isis/isis_lsdb.o

_out/Layer5/isis/isis_flood.o:Layer5/isis/isis_flood.c
	${CC} ${CFLAGS} -c Layer5/isis/isis_flood.c -I . -I Layer5/ -o _out/Layer5/isis/isis_flood.o

_out/Layer5/isis/isis_l2map.o:Layer5/isis/isis_l2map.c
	${CC} ${CFLAGS} -c Layer5/isis/isis_l2map.c -I . -I Layer5/ -o _out/Layer5/isis/isis_l2map.o

_out/avlTree/avlTree.o:avlTree/avlTree.c
	${CC} ${CFLAGS} -c avlTree/avlTree.c -I . -o _out/avlTree/avlTree.o

CommandParser/libcli.a:
	(cd CommandParser; make)

clean:
	rm _out/*.o
	rm _out/glueThread/glthread.o
	rm _out/Layer2/*.o
	rm _out/Layer3/*.o
	rm _out/Layer5/*.o
	rm _out/Layer5/spf_algo/*.o
	rm _out/WheelTimer/*.o
	rm _out/Layer5/isis/*.o
	rm _out/EventDispatcher/*.o
	rm _out/avlTree/*.o
	rm _out/*.exe
	#rmdir _out -r
	(cd CommandParser; make clean)

all:
	make
	(cd CommandParser; make)
