CC = g++
LDFLAGS = -lnetfilter_queue

1m-block: 1m-block.cpp
	$(CC) -o $@ 1m-block.cpp $(LDFLAGS)

clean:
	rm -f 1m-block


