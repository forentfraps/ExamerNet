#include <windows.h>

int main() {
  // Define the message box text, title, and type
  const char *message = "Hello, World!";
  const char *title = "My Message Box";
  UINT type = MB_OK | MB_ICONINFORMATION;

  // Call the MessageBoxA function
  MessageBoxA(NULL, message, title, type);

  return 0;
}
