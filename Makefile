
LIBS=-lfcgi++ -lfcgi -lpthread -lcurl -lconfig -lcrypto
FLAGS=-std=c++17 -Wall -Iframework
FILES=bot.cc framework/util.cc

all:	release

release:
	g++ -o bot $(FILES) $(LIBS) $(FLAGS) -O2 -ggdb

debug:
	g++ -o bot $(FILES) $(LIBS) $(FLAGS) -O0 -ggdb

