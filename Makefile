SRC := src
INCLUDE := include

CXX := g++
CXXFLAGS := -std=c++20

portscanner: $(wildcard $(SRC)/*.cc)
	$(CXX) $(CXXFLAGS) $^ -o $@ -I $(INCLUDE) 