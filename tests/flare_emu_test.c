/*
Copyright (C) 2018 FireEye, Inc.

Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-BSD-3-CLAUSE or
https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be
copied, modified, or distributed except according to those terms.

Author: James T. Bennett

compiles binary for unit tests for flare-emu
tests for iterate and emulateRange features of flare-emu and emulation of VFP instructions in ARM architectures
*/

#include <stdio.h>
#include <string.h>

char text1[] = "hello";
char text2[] = "goodbye";
char text3[] = "test";

char* xorCrypt(char *text, size_t textLen, char *key, size_t keyLen){
	for(int i = 0; i < textLen; i++)
		text[i] ^= key[i % keyLen];

	return text;
}

int main(int argc, const char * argv[]) {
    double val1 = 5.5;
    int val2 = 2;
    xorCrypt(text1, strlen(text1), "\x20", 1);
    printf("%s\n", text1);
    xorCrypt(text2, strlen(text2), "\x20", 1);
    printf("%s\n", text2);
    xorCrypt(text3, strlen(text3), "\x20", 1);
    printf("%s\n", text3);
    printf("%f\n", val1 * val2);
}
