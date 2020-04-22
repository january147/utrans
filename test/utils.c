// Date: Fri Apr 17 14:58:34 2020
// Author: January

#include<stdio.h>

typedef unsigned char uint8;

int escape_data(uint8* in, int in_len, uint8* out, int out_buf_len, uint8 escape_byte, uint8 insert_byte){
    int p_in = 0;
    int p_out = 0;

    printf("receive param:");
    printf("in_len: %d\n"
          "out_buf_len: %d\n"
          "escape_byte: %02x\n"
          "insert_byte: %02x\n",
          in_len, out_buf_len, escape_byte, insert_byte);
    while (p_in < in_len && p_out < out_buf_len) {
        out[p_out] = in[p_in];
        if (in[p_in] == escape_byte) {
            p_out++;
            if (p_out > out_buf_len) {
                return -1;
            }
            out[p_out] = insert_byte;
        }
        p_in++;
        p_out++;
    }
    if (p_in < in_len) {
        return -2;
    }
    return p_out;
}

int restore_data(uint8* in, int in_len, uint8* out, int out_buf_len, uint8 escape_byte, uint8 insert_byte) {
    int p_in = 0;
    int p_out = 0;

    printf("receive param:");
    printf("in_len: %d\n"
          "out_buf_len: %d\n"
          "escape_byte: %02x\n"
          "insert_byte: %02x\n",
          in_len, out_buf_len, escape_byte, insert_byte);
    while (p_in < in_len && p_out < out_buf_len) {
        out[p_out] = in[p_in];
        if (in[p_in] == escape_byte) {
            p_in ++;
            if (p_in > in_len) {
                return -1;
            }
            if (in[p_in] != insert_byte) {
                return -2;
            }
        }
        p_in++;
        p_out++;
    }
    if (p_in < in_len) {
        return -3;
    }
    return p_out;
}

