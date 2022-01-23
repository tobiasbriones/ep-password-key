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
 * Passwords considered very usual and weak, they shouldn't be accepted since
 * they are widely used. {@link PasswordProtocol} rejects any password that
 * matches with one weak password.
 *
 * @author Tobias Briones
 * @see PasswordProtocol
 */
public final class WeakPasswordsDictionary {
    public static final String[] WEAK_LOWER_CASE_USUAL_PASSWORDS = {
        "12345678", "abcdefgh", "password",
        "01234567", "qwertyui", "abc12345",
        "0123456789", "football", "passw0rd",
        "123456789", "internet", "xyz12345",
        "1234567890", "einstein", "midnight",
        "mountain", "baseball", "sunshine",
        "princess", "superman", "qwertyuiop",
        "1q2w3e4r5t", "dolphins"
    };

    // The password in WEAK_LOWER_CASE_USUAL_PASSWORDS with the greatest length
    public static final int WEAK_PASSWORD_MAX_LENGTH = 10;

    private WeakPasswordsDictionary() {}
}
