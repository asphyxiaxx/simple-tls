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
#include "mlkem_native/mlkem_native_all.h"

extern int randombytes(uint8_t *buf, size_t len);

static PyObject* KEM_keygen(PyObject *self, PyObject *args) 
{
    Py_buffer coins;
    int level, rv;

    /* Prepare buffers using the largest possible sizes (1024) allows us 
     * to reuse one stack variable */
    uint8_t pk[MLKEM1024_PUBLICKEYBYTES]; 
    uint8_t sk[MLKEM1024_SECRETKEYBYTES];
    size_t pk_len, sk_len;

    if (!PyArg_ParseTuple(args, "iy*", &level, &coins)) 
        return NULL;

    if ((size_t)coins.len != 2 * MLKEM_SYMBYTES) {
        PyErr_Format(PyExc_ValueError, "Expected coins length '%zu' (not '%zu')",
                     2 * MLKEM_SYMBYTES, coins.len);
        PyBuffer_Release(&coins);
        return NULL;
    }

    switch (level)
    {
    case 512:
        rv = mlkem512_keypair_derand(pk, sk, (const uint8_t *)coins.buf);
        pk_len = MLKEM512_PUBLICKEYBYTES;
        sk_len = MLKEM512_SECRETKEYBYTES;
        break;

    case 768:
        rv = mlkem768_keypair_derand(pk, sk, (const uint8_t *)coins.buf);
        pk_len = MLKEM768_PUBLICKEYBYTES;
        sk_len = MLKEM768_SECRETKEYBYTES;
        break;

    case 1024:
        rv = mlkem1024_keypair_derand(pk, sk, (const uint8_t *)coins.buf);
        pk_len = MLKEM1024_PUBLICKEYBYTES;
        sk_len = MLKEM1024_SECRETKEYBYTES;
        break;

    default:
        /* Invalid parameter level — mark as unusable */
        PyErr_Format(PyExc_ValueError, "Parameter level '%d' unavailable", level);
        PyBuffer_Release(&coins);
        return NULL;
    }

    PyBuffer_Release(&coins);
    if (rv != 0) {
        PyErr_Format(PyExc_ValueError, "keygen failed with code '%d'", rv);
        return NULL;
    }

    return Py_BuildValue("y#y#", pk, pk_len, sk, sk_len);
}

static PyObject* KEM_encaps(PyObject *self, PyObject *args) 
{
    Py_buffer pk, coins;
    PyObject *res;
    int level, rv;

    /* Prepare buffers using the largest possible sizes (1024) allows us 
     * to reuse one stack variable */
    uint8_t ct[MLKEM1024_CIPHERTEXTBYTES]; 
    uint8_t ss[MLKEM1024_BYTES];
    size_t ct_len, ss_len, pk_len;

    int (*enc_derand)(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                      const uint8_t *coins);

    if (!PyArg_ParseTuple(args, "iy*y*", &level, &pk, &coins)) 
        return NULL;

    res = NULL;

    if ((size_t)coins.len != MLKEM_SYMBYTES) {
        PyErr_Format(PyExc_ValueError, "Expected coins length '%zu' (not '%zu')",
                     MLKEM_SYMBYTES, coins.len);
        goto cleanup;
    }

    switch (level)
    {
    case 512:
        enc_derand = mlkem512_enc_derand;
        ct_len = MLKEM512_CIPHERTEXTBYTES;
        ss_len = MLKEM512_BYTES;
        pk_len = MLKEM512_PUBLICKEYBYTES;
        break;

    case 768:
        enc_derand = mlkem768_enc_derand;
        ct_len = MLKEM768_CIPHERTEXTBYTES;
        ss_len = MLKEM768_BYTES;
        pk_len = MLKEM768_PUBLICKEYBYTES;
        break;

    case 1024:
        enc_derand = mlkem1024_enc_derand;
        ct_len = MLKEM1024_CIPHERTEXTBYTES;
        ss_len = MLKEM1024_BYTES;
        pk_len = MLKEM1024_PUBLICKEYBYTES;
        break;

    default:
        /* Invalid parameter level — mark as unusable */
        PyErr_Format(PyExc_ValueError, "Parameter level '%d' unavailable", level);
        goto cleanup;
    }

    if ((size_t)pk.len != pk_len) {
        PyErr_Format(PyExc_ValueError, "Expected pk length '%d' (not '%d')",
                     pk_len, pk.len);
        goto cleanup;
    }

    rv = enc_derand(ct, ss, (const uint8_t *)pk.buf, (const uint8_t *)coins.buf);
    if (rv != 0) {
        PyErr_Format(PyExc_ValueError, "encaps failed with code '%d'", rv);
        goto cleanup;
    }

    res = Py_BuildValue("y#y#", ct, ct_len, ss, ss_len);

cleanup:
    PyBuffer_Release(&pk);
    PyBuffer_Release(&coins);
    return res;
}

static PyObject* KEM_decaps(PyObject *self, PyObject *args) 
{
    Py_buffer ct, sk;
    PyObject *res;
    int level, rv;

    /* Prepare buffers using the largest possible sizes (1024) allows us 
     * to reuse one stack variable */
    uint8_t ss[MLKEM1024_BYTES];
    size_t ss_len, ct_len, sk_len;

    int (*dec)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

    if (!PyArg_ParseTuple(args, "iy*y*", &level, &ct, &sk)) 
        return NULL;

    res = NULL;

    switch (level)
    {
    case 512:
        dec = mlkem512_dec;
        ss_len = MLKEM512_BYTES;
        sk_len = MLKEM512_SECRETKEYBYTES;
        ct_len = MLKEM512_CIPHERTEXTBYTES;
        break;

    case 768:
        dec = mlkem768_dec;
        ss_len = MLKEM768_BYTES;
        sk_len = MLKEM768_SECRETKEYBYTES;
        ct_len = MLKEM768_CIPHERTEXTBYTES;
        break;

    case 1024:
        dec = mlkem1024_dec;
        ss_len = MLKEM1024_BYTES;
        sk_len = MLKEM1024_SECRETKEYBYTES;
        ct_len = MLKEM1024_CIPHERTEXTBYTES;
        break;

    default:
        /* Invalid parameter level — mark as unusable */
        PyErr_Format(PyExc_ValueError, "Parameter level '%d' unavailable", level);
        goto cleanup;
    }

    if ((size_t)ct.len != ct_len) {
        PyErr_Format(PyExc_ValueError, "Expected ct length '%d' (not '%d')",
                     ct_len, ct.len);
        goto cleanup;
    }
    
    if ((size_t)sk.len != sk_len) {
        PyErr_Format(PyExc_ValueError, "Expected sk length '%zu' (not '%zu')",
                     sk_len, sk.len);
        goto cleanup;
    }

    rv = dec(ss, (const uint8_t *)ct.buf, (const uint8_t *)sk.buf);
    if (rv != 0) {
        PyErr_Format(PyExc_ValueError, "decaps failed with code '%d'", rv);
        goto cleanup;
    }

    res = Py_BuildValue("y#", ss, ss_len);

cleanup:
    PyBuffer_Release(&ct);
    PyBuffer_Release(&sk);
    return res;
}

static PyMethodDef mlkem_methods[] = {
    {"keygen", (PyCFunction)KEM_keygen, METH_VARARGS, ""},
    {"encaps", (PyCFunction)KEM_encaps, METH_VARARGS, ""},
    {"decaps", (PyCFunction)KEM_decaps, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef mlkem_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "mlkem",
    .m_doc = "ML-KEM module",
    .m_size = -1,
    .m_methods = mlkem_methods,
};

PyObject *add_mlkem() 
{
    PyObject *m = PyModule_Create(&mlkem_module);
    if (NULL == m)
        return NULL;
    return m;
}
