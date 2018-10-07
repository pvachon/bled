OBJ=bled.o

OFLAGS=-O0
DEFINES=
CXXFLAGS=-std=c++14 -g -I. -Wall -Wextra $(DEFINES) $(OFLAGS)

LIBS=-lboost_program_options -lboost_system -lbluetooth -lble++
LDFLAGS=$(LIBS)

inc=$(OBJ:%.o=%.d)

TARGET=bled

$(TARGET): $(OBJ)
	$(CXX) -o $(TARGET) $(OBJ) $(LDFLAGS)

-include $(inc)

.cpp.o:
	$(CXX) $(CXXFLAGS) -MMD -MP -o $@ -c $<

clean:
	$(RM) $(TARGET)
	$(RM) $(OBJ)
	$(RM) $(inc)

.PHONY: clean
