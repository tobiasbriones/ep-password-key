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

import dev.tobiasbriones.ep.passwordkey.NotAcceptedByPasswordProtocolException;
import dev.tobiasbriones.ep.passwordkey.PasswordProtocol;
import org.mindrot.jbcrypt.BCrypt;

/**
 * It generates Merge Keys to store data in a safe way, which should always be
 * passwords or short messages.
 *
 * @author Tobias Briones
 * @see Key
 * @see MergeKeyOpener
 */
public final class MergeKeyGenerator {
    public static final int MAX_LENGTH_USER_PASSWORD = 50;
    static final int DIMENSION_REDUCTION_FACTOR = 2;
    private static final int DIMENSION_HASH_LENGTH = 100;
    private static final int HASHED_PASSWORD_SECURE_LEVEL_OIL = 5000;

    /**
     * Generates a public key.
     *
     * @param data             data to store.
     * @param keyOwnerPassword owner password.
     *
     * @return A public key with no oil and no user password.
     *
     * @throws NotAcceptedByPasswordProtocolException if keyOwnerPassword is not
     *                                                accepted by {@link
     *                                                PasswordProtocol}
     * @throws UnsupportedDataKeyException            if the data can't be
     *                                                stored, if your data
     *                                                contains line feed "\n"
     *                                                use Base64 to encode it
     *                                                first.
     * @see Key
     */
    public static Key generatePublicKey(
        String data,
        String keyOwnerPassword
    ) throws NotAcceptedByPasswordProtocolException,
             UnsupportedDataKeyException {
        return generatePublicKey(data, keyOwnerPassword, new KeyOil(0, 0));
    }

    /**
     * Generates a public key.
     *
     * @param data               data to store.
     * @param keyOwnerPassword   owner password.
     * @param dimensionLengthOil oil to generate it.
     *
     * @return A public key with oil and no user password.
     *
     * @throws NotAcceptedByPasswordProtocolException if keyOwnerPassword is not
     *                                                accepted by {@link
     *                                                PasswordProtocol}
     * @throws UnsupportedDataKeyException            if the data can't be
     *                                                stored, if your data
     *                                                contains line feed "\n"
     *                                                use Base64 to encode it
     *                                                first.
     * @see Key
     */
    public static Key generatePublicKey(
        String data, String keyOwnerPassword,
        KeyOil dimensionLengthOil
    ) throws NotAcceptedByPasswordProtocolException,
             UnsupportedDataKeyException {
        validateInput(data, keyOwnerPassword);
        return createKey(data, keyOwnerPassword, "", dimensionLengthOil);
    }

    /**
     * Generates a key.
     *
     * @param data             data to store.
     * @param keyOwnerPassword owner password.
     * @param keyUserPassword  user password.
     *
     * @return A key with no oil and no user password.
     *
     * @throws NotAcceptedByPasswordProtocolException if keyOwnerPassword is not
     *                                                accepted by {@link
     *                                                PasswordProtocol}
     * @throws UnsupportedDataKeyException            if the data can't be
     *                                                stored, if your data
     *                                                contains line feed "\n"
     *                                                use Base64 to encode it
     *                                                first.
     * @see Key
     */
    public static Key generateKey(
        String data, String keyOwnerPassword,
        String keyUserPassword
    ) throws NotAcceptedByPasswordProtocolException,
             UnsupportedDataKeyException {
        return generateKey(
            data,
            keyOwnerPassword,
            keyUserPassword,
            new KeyOil(0, 0)
        );
    }

    /**
     * Generates a key.
     *
     * @param data               data to store.
     * @param keyOwnerPassword   owner password.
     * @param keyUserPassword    user password.
     * @param dimensionLengthOil oil to generate it.
     *
     * @return A key with oil and user password.
     *
     * @throws NotAcceptedByPasswordProtocolException if keyOwnerPassword is not
     *                                                accepted by {@link
     *                                                PasswordProtocol}
     * @throws UnsupportedDataKeyException            if the data can't be
     *                                                stored, if your data
     *                                                contains line feed "\n"
     *                                                use Base64 to encode it
     *                                                first.
     * @see Key
     */
    public static Key generateKey(
        String data, String keyOwnerPassword,
        String keyUserPassword,
        KeyOil dimensionLengthOil
    ) throws NotAcceptedByPasswordProtocolException,
             UnsupportedDataKeyException {
        validateInput(data, keyOwnerPassword);
        if (!PasswordProtocol.isAcceptedPassword(keyUserPassword)) {
            throw new NotAcceptedByPasswordProtocolException();
        }
        return createKey(
            data,
            keyOwnerPassword,
            keyUserPassword,
            dimensionLengthOil
        );
    }

    private static String getHashedPassword(String password) {
        final String hashedPassword = (password.isEmpty())
                                      ? ""
                                      : BCrypt.hashpw(
                                          password,
                                          BCrypt.gensalt()
                                      );
        final char[] chars = new char[DIMENSION_HASH_LENGTH];
        for (int i = 0; i < chars.length; i++) {
            if (i < hashedPassword.length()) {
                chars[i] = hashedPassword.charAt(i);
            }
            else {
                chars[i] = ' ';
            }
        }
        return new String(chars);
    }

    private static String generateDimension(
        String data,
        KeyOil dimensionLengthOil,
        boolean keepConstantFactor
    ) {
        final StringBuilder builder = new StringBuilder();
        final char[] dataArray = data.toCharArray();
        final int factor = (keepConstantFactor)
                           ? 1
                           : DIMENSION_REDUCTION_FACTOR;
        final int typeOfData = Core.getTextType(data);
        final String dimensionText;
        int negativeDimensionValue = dimensionLengthOil.negativeOilLength;
        int positiveDimensionValue = dimensionLengthOil.positiveOilLength;
        for (char c : dataArray) {
            builder.append(Core.randomText(negativeDimensionValue, typeOfData));
            builder.append(c);
            builder.append(Core.randomText(positiveDimensionValue, typeOfData));
            negativeDimensionValue /= factor;
            positiveDimensionValue /= factor;
            if (negativeDimensionValue == 0) {
                negativeDimensionValue = dimensionLengthOil.negativeOilLength;
            }
            if (positiveDimensionValue == 0) {
                positiveDimensionValue = dimensionLengthOil.positiveOilLength;
            }
        }
        dimensionText = builder.toString();
        return dimensionText;
    }

    private static String generateFullDimension(
        String data,
        String userPassword,
        KeyOil dimensionLengthOil
    ) {
        final String hashedUserPassword = getHashedPassword(userPassword);
        final KeyOil userPasswordOil = getUserPasswordOil(dimensionLengthOil);
        return generateDimension(
            hashedUserPassword,
            userPasswordOil,
            true
        ) + generateDimension(data, dimensionLengthOil, false);
    }

    private static void validateInput(
        String data,
        String keyOwnerPassword
    ) throws NotAcceptedByPasswordProtocolException,
             UnsupportedDataKeyException {
        if (data.contains("\n")) {
            throw new UnsupportedDataKeyException();
        }
        if (!PasswordProtocol.isAcceptedPassword(keyOwnerPassword)) {
            throw new NotAcceptedByPasswordProtocolException();
        }
    }

    private static Key createKey(
        String data,
        String keyOwnerPassword,
        String keyUserPassword,
        KeyOil dimensionLengthOil
    ) throws UnsupportedDataKeyException {
        final String dimensionText = generateFullDimension(
            data,
            keyUserPassword,
            dimensionLengthOil
        );
        final Core.Encryption encryptedDimension;
        try {
            encryptedDimension = Core.encrypt(dimensionText, keyOwnerPassword);
        }
        catch (Exception e) {
            throw new UnsupportedDataKeyException();
        }
        return new Key(
            encryptedDimension.salt,
            encryptedDimension.iv,
            encryptedDimension.encryptedText
        );
    }

    static KeyOil getUserPasswordOil(KeyOil dimensionLengthOil) {
        if (dimensionLengthOil.negativeOilLength < HASHED_PASSWORD_SECURE_LEVEL_OIL
            && dimensionLengthOil.positiveOilLength < HASHED_PASSWORD_SECURE_LEVEL_OIL) {
            return new KeyOil(
                (int) (dimensionLengthOil.negativeOilLength * 0.06),
                (int) (dimensionLengthOil.positiveOilLength * 0.04)
            );
        }
        return new KeyOil(
            (int) (dimensionLengthOil.negativeOilLength * 0.012),
            (int) (dimensionLengthOil.positiveOilLength * 0.005)
        );
    }

    static int getUserHashedPasswordLengthInDimension(KeyOil userPasswordOil) {
        return DIMENSION_HASH_LENGTH
               + (userPasswordOil.negativeOilLength * DIMENSION_HASH_LENGTH)
               + (userPasswordOil.positiveOilLength * DIMENSION_HASH_LENGTH);
    }

    private MergeKeyGenerator() {}
}
