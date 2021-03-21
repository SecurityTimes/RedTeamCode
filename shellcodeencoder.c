// argv[1] - Is our 32bit Key
// argv[2] - Raw Payload binary file generated through CS or Metasploit (payload.bin)

/* Description of Windows funtions/ API used in this program
CreateFile - To get the handle to our payload.bin file.
ReadFile - To read the contents of the payload.bin file. The handle we got from the CreateFile func will be used as input in ReadFile func.
GetFileSize - To get the size of payload.bin file
GlobalAlloc - To allocate memory buffer for the shellcode
CloseHandle - To close the handle we opened via CreateFile
GlobalFree - To Free the memory we allocated for our shellcode
*/

#include <windows.h>
#include <stdio.h>

int main (int argc, char**argv)
{
    DWORD key = atoi(argv[1]); 
    DWORD dwSize = 0;
    DWORD dwRead = 0;
    DWORD i = 0;
    char *shellcode = NULL;
    char *original = NULL;
    DWORD *current;
    DWORD dwPadding = 0;
    HANDLE hFile = NULL;

    hFile = CreateFile(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open %s\n", argv[2]);
        ExitProcess(1);
    }

    dwSize = GetFileSize(hFile, NULL);
    printf("Shellcode size is %d bytes\n", dwSize);

    dwPadding = dwSize % 4;
    if (dwPadding != 0)
    {
        dwPadding = 4 - dwPadding;
        printf("Payload will be padded with %d bytes\n", dwPadding);
    }

    shellcode = GlobalAlloc(GPTR, dwSize + dwPadding);
    original = shellcode;


    ReadFile(hFile, shellcode, dwSize, &dwRead, NULL);
    printf("dwSize %d bytes\n", dwSize + dwPadding);

    for(i = 0; i < dwPadding; i++) {
        shellcode[dwSize + i] = 0x90;
    }

    for(i = 0; i <= (dwSize + dwPadding) / 4; i++)
    {
        current = (DWORD*)shellcode;
        *current = *current ^ key;
        shellcode += 4;
    }

    printf("Encoded using the following key 0x%08x (%d)\n", key, key);
    printf("Encoded shellcode:\n");
    for(i = 0; i < (dwSize + dwPadding); i++)
    {
        printf("0x%02x, ", (unsigned char)original[i]);
    }

    printf("\nShellcode in Hex format:\n");

    for(i = 0; i < dwSize + dwPadding; i++)
    {
        printf("\\x%02x, ", (unsigned char)original[i]);
    }

    CloseHandle(hFile);
    GlobalFree(original);
    return 0;
}
