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

package dev.tobiasbriones.ep.passwordkey;

/**
 * Thrown when a given password is rejected because it's checked by {@link
 * PasswordProtocol}.
 *
 * @author Tobias Briones
 * @see PasswordProtocol
 */
public final class NotAcceptedByPasswordProtocolException extends Exception {

    public static final String PROTOCOL_MSG = "Password not accepted, it must"
                                              + " have a length greater than "
                                              + "7, not be too repetitive and"
                                              + " not be too poor like "
                                              + "'12345678' or 'password'";
    private static final long serialVersionUID = 8448453264509996168L;

    public NotAcceptedByPasswordProtocolException() {
        super(PROTOCOL_MSG);
    }
}
