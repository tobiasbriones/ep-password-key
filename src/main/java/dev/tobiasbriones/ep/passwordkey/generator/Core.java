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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

final class Core {
    private static final int TEXT_TYPE_NUMERIC = 0;
    private static final int TEXT_TYPE_SIMPLE_MSG = 1;
    private static final int TEXT_TYPE_COMMON = 2;
    private static final int TEXT_TYPE_ANY = 3;
    private static final char[] SYMBOLS = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
        'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
        'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
        'y', 'z', '�', '�', '�',
        '�', '?', '�', '@', '[', ']', '^', '_', '{', '|',
        '}', '~', '!', '"', '#', '$', '%', '&', '(', ')',
        '*', '+', ',', '-', '.', '/', ':', ';', '<', '=',
        '>', '`', '�', '�', '�', '�',
        '�', '�', '�', '�', '�', '�', '�', '�', '�', '�',
        '�', '�', '�', '�', '�', '�', '�', '�', '�', '�',
        '�', '�', '�', '�', '�', '�', '�', '�', '�', '�',
        '�', '�', '�', '�', '�', '�', '�', '�', '�', '�',
        '�', '�', '�', '�', '�', '�', '�', '�', '�', '�',
        '�', '�', '�', '�', '�', '�', '�', '�', '�', '�',
        '�', '�', '�', '�', '�', '�', '�', '�', '�', '�',
        '�', '�', '�', '�', '�', '�', '�', '�', '�', '�',
        '�', '�', '�', '�', '�', '�', '�', '�', '�', '�',
        '�', '�', '�', '�', '�', '�', '�', '�', '�', '�',
        '�', '�', '�', '�', '�', '�', '�', '�', '�', '�',
        '�', '�', '�', '�', '', '', '', '', '', '',
        '', '', '', '', '', '', '', '',
        };
    private static final StringBuilder SB = new StringBuilder();
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 128;
    private static final int SALT_SIZE = 128;
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    private Core() {}

    private static SecretKey getSecretKey(String password, byte[] salt) throws Exception {
        final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        final KeySpec keySpec = new PBEKeySpec(
            password.toCharArray(),
            salt,
            ITERATION_COUNT,
            KEY_LENGTH
        );
        final SecretKey tmp = factory.generateSecret(keySpec);
        return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
    }

    private static byte[] generateSalt() {
        final SecureRandom secureRandom = new SecureRandom();
        final byte[] salt = new byte[SALT_SIZE];
        secureRandom.nextBytes(salt);
        return salt;
    }

    private static int getCharIndex(char c) {
        for (int i = 0; i < SYMBOLS.length; i++) {
            if (SYMBOLS[i] == c) {
                return i;
            }
        }
        return -1;
    }

    static int getTextType(String text) {
        boolean hasNumericText = false;
        boolean hasSimpleMSGText = false;
        boolean hasCommonText = false;
        boolean hasAnyText = false;
        int i = -1;
        for (char c : SYMBOLS) {
            if (text.contains(String.valueOf(c))) {
                i = getCharIndex(c);
                if (i == -1) {
                    continue;
                }
                if (i <= 9) {
                    hasNumericText = true;
                }
                else if (i <= 64) {
                    hasNumericText = true;
                    hasSimpleMSGText = true;
                }
                else if (i <= 100) {
                    hasNumericText = true;
                    hasSimpleMSGText = true;
                    hasCommonText = true;
                }
                else {
                    hasNumericText = true;
                    hasSimpleMSGText = true;
                    hasCommonText = true;
                    hasAnyText = true;
                    break;
                }
            }
        }
        if (hasAnyText) {
            return TEXT_TYPE_ANY;
        }
        if (hasCommonText) {
            return TEXT_TYPE_COMMON;
        }
        if (hasSimpleMSGText) {
            return TEXT_TYPE_SIMPLE_MSG;
        }
        if (hasNumericText) {
            return TEXT_TYPE_NUMERIC;
        }
        return TEXT_TYPE_ANY;
    }

    private static char randomSymbol(int textType) {
        final int range;
        switch (textType) {
            case TEXT_TYPE_ANY:
                range = SYMBOLS.length - 1;
                break;
            case TEXT_TYPE_COMMON:
                range = 100;
                break;
            case TEXT_TYPE_SIMPLE_MSG:
                range = 64;
                break;
            case TEXT_TYPE_NUMERIC:
                range = 9;
                break;
            default:
                range = SYMBOLS.length - 1;
                break;
        }
        return SYMBOLS[(int) (Math.random() * range)];
    }

    private static String randomText(int length) {
        return randomText(length, TEXT_TYPE_ANY);
    }

    static String randomText(int length, int textType) {
        final String randomText;
        SB.setLength(0);
        for (int i = 0; i < length; i++) {
            SB.append(randomSymbol(textType));
        }
        randomText = SB.toString();
        SB.setLength(0);
        return randomText;
    }

    static Encryption encrypt(String text, String password) throws
                                                                      Exception {
        final byte[] salt = generateSalt();
        final SecretKey secretKey = getSecretKey(password, salt);
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        final byte[] input = text.getBytes(StandardCharsets.UTF_8);
        final byte[] encripted;
        final byte[] iv;
        final AlgorithmParameters params;
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        params = cipher.getParameters();
        iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        encripted = cipher.doFinal(input);
        return new Encryption(salt, encripted, iv);
    }

    static String decrypt(
        String encryptedText,
        String password,
        byte[] salt,
        byte[] iv
    ) throws Exception {
        final SecretKey secretKey = getSecretKey(password, salt);
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        final byte[] input = Base64.getDecoder().decode(encryptedText);
        final byte[] decrypted;
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        decrypted = cipher.doFinal(input);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    static final class Encryption {
        final byte[] salt;
        final byte[] iv;
        final String encryptedText;

        private Encryption(byte[] salt, byte[] encrypted, byte[] iv) {
            this.salt = salt;
            this.iv = iv;
            this.encryptedText = Base64.getEncoder().encodeToString(encrypted);
        }
    }
}
