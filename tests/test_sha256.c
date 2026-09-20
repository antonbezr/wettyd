#include <stdio.h>
#include <string.h>

#include "../src/sha256.h"

static int failures = 0;

static void check(int condition, const char *description) {
  if (condition) {
    printf("PASS %s\n", description);
  } else {
    printf("FAIL %s\n", description);
    failures++;
  }
}

static void check_hex(const char *input, const char *expected, const char *description) {
  char out[WETTYD_SHA256_HEX_LEN];
  wettyd_sha256_hex(input, strlen(input), out);
  if (strcmp(out, expected) == 0) {
    printf("PASS %s\n", description);
  } else {
    printf("FAIL %s: expected %s, got %s\n", description, expected, out);
    failures++;
  }
}

int main(void) {
  check_hex("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty input");
  check_hex("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");
  check_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "56 byte input, two blocks");
  check_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318", "55 byte input, padding boundary");
  check_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb", "exactly one block");

  char a[1000001];
  memset(a, 'a', sizeof(a) - 1);
  a[sizeof(a) - 1] = '\0';
  check_hex(a, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "one million a");

  char out[WETTYD_SHA256_HEX_LEN];
  wettyd_sha256_hex("abc", 3, out);
  check(strlen(out) == WETTYD_SHA256_HEX_LEN - 1, "hex output is 64 characters plus a terminator");

  if (failures > 0) {
    printf("\n%d test(s) failed\n", failures);
    return 1;
  }
  printf("\nall tests passed\n");
  return 0;
}
