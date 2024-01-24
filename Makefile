src_path := src
lib_path := lib

tests_path := tests
unit_tests_path := unit-tests

CXX := g++
CXXFLAGS := -ggdb -O0 -std=c++20

libConnection.so: $(src_path)/connection/connection.cc
	(mkdir -p $(lib_path) && $(CXX) $(CXXFLAGS) $^ -shared -fPIC -o $(lib_path)/$@)

portscanner: $(src_path)/portscanner.cc libConnection.so
	$(CXX) $(CXXFLAGS) $< -o $@ -I $(src_path)/connection -L $(lib_path) -lConnection

test_server: $(src_path)/test_server.cc libConnection.so
	$(CXX) $(CXXFLAGS) $< -o $(tests_path)/$@ -I $(src_path)/connection -L $(lib_path) -lConnection

unit_test1: $(unit_tests_path)/test1.cc
	$(CXX) $(CXXFLAGS) $< -o $@

unit_test2: $(unit_tests_path)/test2.cc
	$(CXX) $(CXXFLAGS) $< -o $@

unit_tests := unit_test1 unit_test2

run_unit_tests: $(unit_tests)
	for uni_test in $^ ; do \
		./$$uni_test ; \
	done

clean:
	rm -rf $(unit_tests) portscanner lib $(tests_path)/test_server