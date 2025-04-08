CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wno-deprecated-declarations -I./include
CXXFLAGS += `pkg-config --cflags Qt5Widgets`
LDFLAGS = -lssl -lcrypto -lpthread
LDFLAGS += `pkg-config --libs Qt5Widgets`
MOC = /usr/lib64/qt5/bin/moc

SRC_SERVER = src/main_server.cpp src/network_comm_server.cpp src/key_manager.cpp src/crypto_utils.cpp src/message_format.cpp
SRC_CLIENT = src/main_client.cpp src/network_comm_client.cpp src/key_manager.cpp src/crypto_utils.cpp src/message_format.cpp
SRC_CLIENT_GUI = src/main_client_gui.cpp src/network_comm_client.cpp src/key_manager.cpp src/crypto_utils.cpp src/message_format.cpp

OBJ_SERVER = $(SRC_SERVER:.cpp=.o)
OBJ_CLIENT = $(SRC_CLIENT:.cpp=.o)
OBJ_CLIENT_GUI = $(SRC_CLIENT_GUI:.cpp=.o)

TARGET_SERVER = ServerApp
TARGET_CLIENT = ClientApp
TARGET_CLIENT_GUI = GUIApp

all: $(TARGET_SERVER) $(TARGET_CLIENT) $(TARGET_CLIENT_GUI)

$(TARGET_SERVER): $(OBJ_SERVER)
	$(CXX) $(CXXFLAGS) -o $(TARGET_SERVER) $(OBJ_SERVER) $(LDFLAGS)

$(TARGET_CLIENT): $(OBJ_CLIENT)
	$(CXX) $(CXXFLAGS) -o $(TARGET_CLIENT) $(OBJ_CLIENT) $(LDFLAGS)

moc_main_client_gui.cpp: include/main_client_gui.h
	$(MOC) include/main_client_gui.h -o moc_main_client_gui.cpp

moc_main_client_gui.o: moc_main_client_gui.cpp
	$(CXX) $(CXXFLAGS) -c moc_main_client_gui.cpp -o moc_main_client_gui.o

$(TARGET_CLIENT_GUI): $(OBJ_CLIENT_GUI) moc_main_client_gui.o
	$(CXX) $(CXXFLAGS) -o $(TARGET_CLIENT_GUI) $(OBJ_CLIENT_GUI) moc_main_client_gui.o $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_SERVER) $(OBJ_CLIENT) $(OBJ_CLIENT_GUI) moc_main_client_gui.cpp moc_main_client_gui.o $(TARGET_SERVER) $(TARGET_CLIENT) $(TARGET_CLIENT_GUI)