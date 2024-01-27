SRC := src
INCLUDE := include

CXX := g++
CXXFLAGS := -std=c++20 -ggdb -O0

portscanner: $(wildcard $(SRC)/*.cc)
	$(CXX) $(CXXFLAGS) $^ -o $@ -I $(INCLUDE) 