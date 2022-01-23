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

import static dev.tobiasbriones.ep.passwordkey.WeakPasswordsDictionary.WEAK_LOWER_CASE_USUAL_PASSWORDS;
import static dev.tobiasbriones.ep.passwordkey.WeakPasswordsDictionary.WEAK_PASSWORD_MAX_LENGTH;

/**
 * Provides a significant amount of password policies to declare a password as:
 * No acceptable, Acceptable and Good.<br> A password is acceptable if:<br> -
 * Its length is not less than 8<br> - It's not in the list of weak
 * passwords<br> - It does not contain more than 40% consecutively repeated
 * characters<br> A password is good if:<br> - It's acceptable<br> - Its length
 * is not less than 16<br>
 *
 * @author Tobias Briones
 * @see WeakPasswordsDictionary
 */
public final class PasswordProtocol {
    public static final int MIN_PASSWORD_LENGTH = 8;
    public static final int GOOD_PASSWORD_LENGTH = 16;
    private static final float MAX_CONSECUTIVE_CHARACTER_REPETITION_FACTOR = 0.4F;
    public static final float MAX_CONSECUTIVE_CHARACTER_REPETITION_PERCENTAGE_INSENSITIVE = MAX_CONSECUTIVE_CHARACTER_REPETITION_FACTOR * 100;

    public enum PasswordQuality {
        UNACCEPTABLE, ACCEPTABLE, GOOD
    }

    /**
     * @param password Password to check.
     *
     * @return {@code true} if the password is considerable safe, {@code false}
     * if it is not.
     */
    public static boolean isAcceptedPassword(String password) {
        if (password == null) {
            throw new NullPointerException();
        }
        final String lowerCasePassword = password.toLowerCase();
        final char[] lowerCasePasswordArray = lowerCasePassword.toCharArray();
        final float length = password.length();
        final float characterRepetitionFactor = 1 / length;
        char previousChar = 0;
        float repetition = characterRepetitionFactor;
        // Check password length
        if (password.length() < MIN_PASSWORD_LENGTH) {
            return false;
        }
        // Check if password is weak, if password length is big enough, skip it
        if (length <= WEAK_PASSWORD_MAX_LENGTH) {
            for (String weakPassword : WEAK_LOWER_CASE_USUAL_PASSWORDS) {
                if (lowerCasePassword.equals(weakPassword)) {
                    return false;
                }
            }
        }
        // Check if contains much consecutive repeated characters
        for (char c : lowerCasePasswordArray) {
            if (c == previousChar) {
                repetition += characterRepetitionFactor;
            }
            else {
                repetition = characterRepetitionFactor;
            }
            if (repetition > MAX_CONSECUTIVE_CHARACTER_REPETITION_FACTOR) {
                return false;
            }
            previousChar = c;
        }
        return true;
    }

    /**
     * @param password Password to check.
     *
     * @return {@link PasswordQuality#UNACCEPTABLE} if the password is
     * rejected<br> {@link PasswordQuality#ACCEPTABLE} if the password is
     * accepted<br> {@link PasswordQuality#GOOD} if the password is accepted and
     * good<br>
     */
    public static PasswordQuality getPasswordQuality(String password) {
        if (password == null) {
            throw new NullPointerException();
        }
        final boolean isAccepted = isAcceptedPassword(password);
        if (!isAccepted) {
            return PasswordQuality.UNACCEPTABLE;
        }
        if (hasGoodProperties(password)) {
            return PasswordQuality.GOOD;
        }
        return PasswordQuality.ACCEPTABLE;
    }

    /**
     * @param password Password to check.
     *
     * @return {@code true} if the password is considerable good, {@code false}
     * if it is not.
     */
    public boolean isGoodPassword(String password) {
        if (password == null) {
            throw new NullPointerException();
        }
        return isAcceptedPassword(password) && hasGoodProperties(password);
    }

    private static boolean hasGoodProperties(String password) {
        return password.length() >= GOOD_PASSWORD_LENGTH;
    }

    private PasswordProtocol() {}
}
