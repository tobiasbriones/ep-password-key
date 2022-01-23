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

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * A key is an object that contains important information most likely passwords
 * secured under encryption and a security configuration according to the
 * parameters when generating it.
 *
 * @author Tobias Briones
 * @see MergeKeyGenerator
 * @see MergeKeyOpener
 */
public final class Key {

    public static Key fromInputStream(InputStream is) throws IOException,
                                                             InvalidKeyException {
        final byte[] salt;
        final byte[] iv;
        final String encryptedDimension;
        try (
            final BufferedReader br = new BufferedReader(new InputStreamReader(
                is,
                StandardCharsets.UTF_8
            ))
        ) {
            String currentLine = br.readLine();
            if (currentLine == null) {
                throw new InvalidKeyException();
            }
            try {
                salt = Base64.getDecoder().decode(currentLine);
                currentLine = br.readLine();
                if (currentLine == null) {
                    throw new InvalidKeyException();
                }
                iv = Base64.getDecoder().decode(currentLine);
            }
            catch (IllegalArgumentException e) {
                throw new InvalidKeyException();
            }
            currentLine = br.readLine();
            if (currentLine == null) {
                throw new InvalidKeyException();
            }
            encryptedDimension = currentLine;
            currentLine = br.readLine();
            if (currentLine != null) {
                throw new InvalidKeyException();
            }
        }
        catch (IOException e) {
            throw e;
        }
        return new Key(salt, iv, encryptedDimension);
    }

    final byte[] salt;
    final byte[] iv;
    final String encryptedDimension;

    Key(byte[] salt, byte[] iv, String encryptedDimension) {
        this.salt = salt;
        this.iv = iv;
        this.encryptedDimension = encryptedDimension;
    }

    public ByteArrayOutputStream toOutputStream() throws IOException {
        final StringBuilder sb = new StringBuilder();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final String saltBase64Text = Base64.getEncoder().encodeToString(salt);
        final String ivBase64Text = Base64.getEncoder().encodeToString(iv);
        sb.append(saltBase64Text);
        sb.append("\n");
        sb.append(ivBase64Text);
        sb.append("\n");
        sb.append(encryptedDimension);
        baos.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        return baos;
    }
}
