/*
 * Copyright (c) 2026 The simple-tls Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>

#define MAX_PADDING_SIZE 256
#define MAX_MAC_SIZE 64

/* Calculate the shift amount dynamically based on the size of size_t
 * For 64-bit systems, this becomes 63. For 32-bit, it becomes 31. */
#define SHIFT_AMOUNT(v) ((sizeof(v) * CHAR_BIT) - 1)

static inline size_t ct_msb_s(size_t val)
{
    return 0 - (val >> SHIFT_AMOUNT(val));
}

/* Return SIZE_MAX if a < b, else 0, in constant time */
static inline size_t ct_lt_s(size_t a, size_t b)
{
    return ct_msb_s((a ^ ((a ^ b) | (((a - b)) ^ b))));
}

/* Return SIZE_MAX if a > b, else 0, in constant time */
static inline size_t ct_gt_s(size_t a, size_t b)
{
    return ct_lt_s(b, a);
}

/* Return SIZE_MAX if a <= b, else 0, in constant time */
static inline size_t ct_le_s(size_t a, size_t b)
{
    return ~ct_gt_s(a, b);
}

/* Return SIZE_MAX if a >= b, else 0, in constant time */
static inline size_t ct_ge_s(size_t a, size_t b)
{
    return ~ct_lt_s(a, b);
}

/* Return SIZE_MAX if val == 0, else 0, in constant time */
static inline size_t ct_is_zero_s(size_t val)
{
    return ct_msb_s(~val & (val - 1));
}

/* Return SIZE_MAX if a == b, else 0, in constant time */
static inline size_t ct_eq_s(size_t a, size_t b)
{
    return ct_is_zero_s((a ^ b) /* 0 if equal */);
}

static inline uint8_t ct_select_u8(uint8_t mask, uint8_t a, uint8_t b)
{
    return (mask & a) | (~mask & b);
}

static inline size_t ct_select_s(size_t mask, size_t a, size_t b)
{
    return (mask & a) | (~mask & b);
}

int randombytes(uint8_t *buf, size_t len)
{
    PyObject *os, *urandom, *bytes;

    os = PyImport_ImportModule("os");
    if (NULL == os)
        return -1;

    urandom = PyObject_GetAttrString(os, "urandom");
    Py_DECREF(os);
    if (NULL == urandom)
        return -1;

    bytes = PyObject_CallFunction(urandom, "n", len);
    Py_DECREF(urandom);
    if (NULL == bytes)
        return -1;

    if (PyBytes_Check(bytes))
    {
        memcpy(buf, PyBytes_AS_STRING(bytes), len);
        Py_DECREF(bytes);
        return 0;
    }

    Py_DECREF(bytes);
    PyErr_SetString(PyExc_TypeError, "os.urandom() didn't return bytes object");
    return -1;
}

static int cbc_get_mac(const uint8_t *data, size_t *data_len,
                       size_t block_size, size_t mac_size,
                       const uint8_t randmac[MAX_MAC_SIZE],
                       uint8_t mac[MAX_MAC_SIZE], size_t ori_data_len,
                       size_t bad_pad_mask)
{
    size_t pad_len, mac_start, scan_start, i, j;

    /* If it is a block cipher, the last byte is the padding length.
     * If the padding was already marked as bad, we force pad_len to 0
     * to prevent out-of-bounds math, while still returning a failure
     * later */
    pad_len = (block_size > 1) ? data[ori_data_len - 1] : 0;
    pad_len &= ~bad_pad_mask;

    /* Calculate where the MAC starts in the buffer */
    mac_start = ori_data_len - pad_len - (block_size > 1 ? 1 : 0) - mac_size;
    *data_len = mac_start; /* Update the output data length */

    if (mac_size == 0)
        return (bad_pad_mask == 0);

    /* To be perfectly constant time, we always scan the maximum
     * possible area where the MAC could be hiding (up to 256 bytes
     * of padding + MAC) */
    scan_start = 0;
    if (ori_data_len > (MAX_PADDING_SIZE + MAX_MAC_SIZE))
        scan_start = ori_data_len - (MAX_PADDING_SIZE + MAX_MAC_SIZE);

    memset(mac, 0, mac_size);

    /* Do the Matric scan */
    for (i = 0; i < mac_size; i++)
    {
        uint8_t extracted_byte = 0;
        size_t target_idx = mac_start + i;

        for (j = scan_start; j < ori_data_len; j++)
        {
            /* If the index (j) matches the target index, extract the byte */
            size_t is_match = ct_eq_s(j, target_idx);
            extracted_byte |= (data[j] & is_match);
        }

        /* If the padding was broken, replace the MAC byte with a random byte.
         * This ensures the MAC check fails later in constant time. */
        mac[i] = ct_select_u8(bad_pad_mask, randmac[i], extracted_byte);
    }

    return 1;
}

static int cbc_remove_pad_and_mac(const uint8_t *data, size_t *data_len,
                                  size_t block_size, size_t mac_size,
                                  const uint8_t randmac[MAX_MAC_SIZE],
                                  uint8_t mac[MAX_MAC_SIZE])
{
    size_t overhead, ori_data_len, pad_len, max_pad, scan_bound;
    size_t bad_pad_mask = 0;
    size_t i;

    if (mac_size > MAX_MAC_SIZE)
        return -1;

    overhead = (block_size == 1 ? 0 : 1) + mac_size;
    if (overhead > *data_len)
        return 0;

    ori_data_len = *data_len;

    if (block_size > 1)
    {
        pad_len = data[ori_data_len - 1];

        /* Check if padding length is valid */
        max_pad = ori_data_len - overhead;
        bad_pad_mask |= ct_gt_s(pad_len, max_pad);

        /* Check if padding bytes is all correct. */
        /* Scan backwards from the end of the buffer up to 256 bytes. */
        scan_bound = ((ori_data_len < MAX_PADDING_SIZE)
                          ? ori_data_len
                          : MAX_PADDING_SIZE);

        for (i = 0; i < scan_bound; i++)
        {
            size_t is_within_padding = ct_le_s(i, pad_len);
            uint8_t actual_byte = data[(ori_data_len - 1) - i];

            /* If we are inside the padding area, actual_byte XOR pad_len
             * should be 0 */
            size_t diff = actual_byte ^ pad_len;
            bad_pad_mask |= (diff & is_within_padding);
        }
    }

    return cbc_get_mac(data, data_len, block_size, mac_size, randmac, mac,
                       ori_data_len, bad_pad_mask);
}

static PyObject *Py_cbc_remove_pad_and_mac(PyObject *self, PyObject *args)
{
    Py_buffer data;
    Py_ssize_t block_size, mac_size;

    uint8_t randmac[MAX_MAC_SIZE], extracted_mac[MAX_MAC_SIZE];
    size_t output_len;
    int rv;

    block_size = 16;

    if (!PyArg_ParseTuple(args, "y*n|n", &data, &mac_size, &block_size))
    {
        return NULL;
    }

    if (mac_size > MAX_MAC_SIZE)
    {
        PyBuffer_Release(&data);
        PyErr_SetString(PyExc_ValueError, "mac_digest_size cannot larger then 64");
        return NULL;
    }

    if (randombytes(randmac, mac_size) != 0)
        return NULL;

    output_len = data.len;

    rv = cbc_remove_pad_and_mac((const uint8_t *)data.buf, &output_len, block_size,
                                mac_size, (const uint8_t *)randmac, extracted_mac);
    PyBuffer_Release(&data);
    if (rv == -1)
    {
        PyErr_SetString(PyExc_RuntimeError, "Unable to remove padding and MAC");
        return NULL;
    }
    if (rv == 0)
    {
        PyErr_SetString(PyExc_ValueError, "Data is publicly invalid");
        return NULL;
    }

    return Py_BuildValue("ny#", output_len, extracted_mac, mac_size);
}

static PyObject *Py_strxor(PyObject *self, PyObject *args)
{
    Py_buffer in1, in2;
    PyObject *ret;
    uint8_t *out_buf, *in1_buf, *in2_buf;

    if (!PyArg_ParseTuple(args, "y*y*", &in1, &in2))
        return NULL;

    ret = NULL;

    if (in1.len != in2.len)
    {
        PyErr_SetString(
            PyExc_ValueError,
            "Only byte strings of equal length can be xored");
        goto cleanup;
    }

    ret = PyBytes_FromStringAndSize(NULL, in1.len);
    if (NULL == ret)
        goto cleanup;

    out_buf = PyBytes_AS_STRING(ret);
    in1_buf = (uint8_t *)in1.buf;
    in2_buf = (uint8_t *)in2.buf;
    for (Py_ssize_t i = 0; i < in1.len; i++)
        out_buf[i] = in1_buf[i] ^ in2_buf[i];

cleanup:
    PyBuffer_Release(&in1);
    PyBuffer_Release(&in2);
    return ret;
}

static PyMethodDef utils_methods[] = {
    {"cbc_remove_pad_and_mac", (PyCFunction)Py_cbc_remove_pad_and_mac, METH_VARARGS, ""},
    {"strxor", (PyCFunction)Py_strxor, METH_VARARGS, "XOR two byte strings"},
    {NULL, NULL, 0, NULL}};

struct PyModuleDef utils_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "utils",
    .m_doc = "utils module",
    .m_size = -1,
    .m_methods = utils_methods,
};

PyObject *add_utils()
{
    PyObject *m = PyModule_Create(&utils_module);
    if (NULL == m)
        return NULL;

    return m;
}
