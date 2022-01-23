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

import org.mindrot.jbcrypt.BCrypt;

/**
 * It opens Merge Keys to get their data that will usually be passwords.
 *
 * @author Tobias Briones
 * @see Key
 * @see MergeKeyGenerator
 */
public final class MergeKeyOpener {
    /**
     * Opens a public key to retrieve its data.<br> If a wrong oil is provided
     * and data is returned, then that data will be wrong (random data is
     * returned), so a key is 'successfully opened' if and only if all the
     * parameters work with the key, otherwise (key and wrong passwords, oil,
     * etc) throws {@link InvalidKeyException} or returns wrong data.
     *
     * @param key              a public key to be opened.
     * @param ownerKeyPassword owner password.
     *
     * @return a string with the data if only if the key is public and opens
     * with the provided ownerKeyPassword and no oil, otherwise random data.
     *
     * @throws InvalidKeyException if a wrong key is detected.
     */
    public static final String openPublicKey(
        Key key,
        String ownerKeyPassword
    ) throws InvalidKeyException {
        return openPublicKey(key, ownerKeyPassword, new KeyOil(0, 0));
    }

    /**
     * Opens a public key to retrieve its data.<br> If a wrong oil is provided
     * and data is returned, then that data will be wrong (random data is
     * returned), so a key is 'successfully opened' if and only if all the
     * parameters work with the key, otherwise (key and wrong passwords, oil,
     * etc) throws {@link InvalidKeyException} or returns wrong data.
     *
     * @param key                a public key to be opened.
     * @param ownerKeyPassword   owner password.
     * @param dimensionLengthOil oil which the key was generate it.
     *
     * @return a string with the data if and only if the key is public and opens
     * with the provided ownerKeyPassword and oil, otherwise random data.
     *
     * @throws InvalidKeyException if a wrong key is detected.
     */
    public static String openPublicKey(
        Key key, String ownerKeyPassword,
        KeyOil dimensionLengthOil
    ) throws InvalidKeyException {
        return openKey(key, ownerKeyPassword, "", dimensionLengthOil);
    }

    /**
     * Opens key to retrieve its data.<br> If a wrong oil is provided and data
     * is returned, then that data will be wrong (random data is returned), so a
     * key is 'successfully opened' if and only if all the parameters work with
     * the key, otherwise (key and wrong passwords, oil, etc) throws {@link
     * InvalidKeyException} or returns wrong data.
     *
     * @param key              a key to be opened.
     * @param ownerKeyPassword owner password.
     * @param userKeyPassword  user password.
     *
     * @return a string with the data if and only if the key opens with the
     * provided ownerKeyPassword, userKeyPassword and no oil, otherwise random
     * data.
     *
     * @throws InvalidKeyException if a wrong key is detected.
     */
    public static String openKey(
        Key key, String ownerKeyPassword,
        String userKeyPassword
    ) throws InvalidKeyException {
        return openKey(
            key,
            ownerKeyPassword,
            userKeyPassword,
            new KeyOil(0, 0)
        );
    }

    /**
     * Opens key to retrieve its data.<br> If a wrong oil is provided and data
     * is returned, then that data will be wrong (random data is returned), so a
     * key is 'successfully opened' if and only if all the parameters work with
     * the key, otherwise (key and wrong passwords, oil, etc) throws {@link
     * InvalidKeyException} or returns wrong data.
     *
     * @param key                a key to be opened.
     * @param ownerKeyPassword   owner password.
     * @param userKeyPassword    user password.
     * @param dimensionLengthOil oil which the key was generate it.
     *
     * @return a string with the data if and only if the key opens with the
     * provided ownerKeyPassword, userKeyPassword and oil, otherwise random
     * data.
     *
     * @throws InvalidKeyException if a wrong key is detected.
     */
    public static String openKey(
        Key key, String ownerKeyPassword,
        String userKeyPassword, KeyOil dimensionLengthOil
    ) throws InvalidKeyException {
        final String dataDimension;
        try {
            final String fullDimension = Core.decrypt(
                key.encryptedDimension,
                ownerKeyPassword,
                key.salt,
                key.iv
            );
            final KeyOil userPasswordOil = MergeKeyGenerator.getUserPasswordOil(
                dimensionLengthOil);
            final int userHashedPasswordLengthInFullDimension =
                MergeKeyGenerator.getUserHashedPasswordLengthInDimension(
                    userPasswordOil);
            final String userHashedPasswordDimension = fullDimension.substring(
                0,
                userHashedPasswordLengthInFullDimension
            );
            final String userHashedPassword = retrieveDataFromDimension(
                userHashedPasswordDimension,
                userPasswordOil,
                true
            ).trim();
            dataDimension = fullDimension.substring(
                userHashedPasswordLengthInFullDimension
            );
            checkUserKeyPassword(userHashedPassword, userKeyPassword);
        }
        catch (Exception e) {
            throw new InvalidKeyException();
        }
        return retrieveDataFromDimension(
            dataDimension,
            dimensionLengthOil,
            false
        );
    }

    private static void checkUserKeyPassword(
        String userHashedKeyPassword,
        String userKeyPassword
    ) throws InvalidKeyException {
        final boolean isPublicKey = userHashedKeyPassword.trim().isEmpty();
        if (isPublicKey) {
            return;
        }
        if (!BCrypt.checkpw(userKeyPassword, userHashedKeyPassword)) {
            throw new InvalidKeyException();
        }
    }

    private static String retrieveDataFromDimension(
        String dimension,
        KeyOil dimensionLengthOil,
        boolean keepConstantFactor
    ) {
        final StringBuilder builder = new StringBuilder();
        final char[] dimentionArray = dimension.toCharArray();
        final int factor = (keepConstantFactor)
                           ? 1
                           : MergeKeyGenerator.DIMENSION_REDUCTION_FACTOR;
        final String data;
        int negativeFactor = 1;
        int positiveFactor = 1;
        int negativeStep =
            dimensionLengthOil.negativeOilLength / negativeFactor;
        int positiveStep =
            dimensionLengthOil.positiveOilLength / positiveFactor;
        int cursor = negativeStep;
        while (cursor < dimentionArray.length) {
            builder.append(dimentionArray[cursor]);
            cursor += positiveStep;
            negativeFactor *= factor;
            positiveFactor *= factor;
            negativeStep =
                dimensionLengthOil.negativeOilLength / negativeFactor;
            positiveStep =
                dimensionLengthOil.positiveOilLength / positiveFactor;
            if (negativeStep == 0) {
                negativeFactor = 1;
                negativeStep =
                    dimensionLengthOil.negativeOilLength / negativeFactor;
            }
            if (positiveStep == 0) {
                positiveFactor = 1;
                positiveStep =
                    dimensionLengthOil.positiveOilLength / positiveFactor;
            }
            cursor += negativeStep + 1;
        }
        data = builder.toString();
        return data;
    }

    private MergeKeyOpener() {}
}
