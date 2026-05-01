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

#include <Python.h>

// external module
extern PyObject *add_utils();
extern PyObject *add_mlkem();

static struct PyModuleDef crypto_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "crypto",
    .m_doc = "Unified crypto module",
    .m_size = -1,
};

PyMODINIT_FUNC PyInit__crypto(void) {
    PyObject *crypto_mod = PyModule_Create(&crypto_module);
    if (NULL == crypto_mod)
        return NULL;

    PyObject *mlkem_mod = add_mlkem();
    if (NULL == mlkem_mod)
        return NULL;
    if (PyModule_AddObject(crypto_mod, "mlkem", mlkem_mod) < 0)
        return NULL;
    
    PyObject *utils_mod = add_utils();
    if (NULL == utils_mod)
        return NULL;
    if (PyModule_AddObject(crypto_mod, "utils", utils_mod) < 0)
        return NULL;

    return crypto_mod;
}