/*
 * Copyright (c) 2017 Tobias Briones. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of Example Project: Password Key.
 *
 * This source code is licensed under the MIT License found in the LICENSE file
 * in the root directory of this source tree or at
 * https://opensource.org/licenses/MIT.
 */

package dev.tobiasbriones.ep.passwordkey.generator;

/**
 * Thrown when the data is passed to {@link MergeKeyGenerator} is not valid to
 * generate a key.
 *
 * @author Tobias Briones
 * @see MergeKeyGenerator
 */
public class UnsupportedDataKeyException extends Exception {
    private static final long serialVersionUID = 9106246786963447411L;

    protected UnsupportedDataKeyException() {
        super("It was no possible to generate a key for the input data");
    }
}
