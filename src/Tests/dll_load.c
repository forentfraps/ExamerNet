#include <Winsock2.h>

#include <Windows.h>
#include <stdio.h>

typedef int (*pWSAStartup)(DWORD, WSADATA *);

int main() {
  void *addr = LoadLibraryA("Ws2_32.dll");

  WSADATA wsaData;
  pWSAStartup wstp = GetProcAddress(addr, "WSAStartup");

  printf("Rerturn val %d\n", wstp(MAKEWORD(2, 2), &wsaData));
  return 0;
}
