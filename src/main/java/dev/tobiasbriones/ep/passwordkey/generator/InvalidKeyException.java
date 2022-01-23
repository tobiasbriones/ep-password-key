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
 * Thrown when a key is being opening, and it is invalid.
 *
 * @author Tobias Briones
 * @see Key
 */
public final class InvalidKeyException extends Exception {

    private static final long serialVersionUID = 3515143529683104967L;

    public InvalidKeyException() {
        super("Invalid key");
    }
}
