/*
This code was taken from the SPHINCS reference implementation and is public domain.
*/

#include <unistd.h>

#include <Uefi.h>
#include <Library/RngLib.h>

void randombytes(unsigned char *x, unsigned long long xlen)
{
    UINT64  Count;
    UINT16 Rest;
    UINT64 Index;

    Count = xlen / 2;
    for (Index = 0; Index < Count; Index++) {
      GetRandomNumber16 ((UINT16 *)x + Index);
    }

    if ((xlen % 2) != 0) {
      GetRandomNumber16 (&Rest);
      *((UINT8 *)x + Count * 2) = (UINT8)(Rest & 0xFF);
    }
}
