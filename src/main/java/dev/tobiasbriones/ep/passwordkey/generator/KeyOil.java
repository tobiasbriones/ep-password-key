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
 * Parameter to generate a key.<br>
 * <strong>Warning</strong>: If the data and the oil are too big,
 * the oil could generate a huge key and be slower to open when requested.
 *
 * @author Tobias Briones
 * @see MergeKeyGenerator
 * @see MergeKeyOpener
 */
public final class KeyOil {
    final int negativeOilLength;
    final int positiveOilLength;

    /**
     * @param negativeOilLength - negative oil value
     * @param positiveOilLength - positive oil value
     */
    public KeyOil(int negativeOilLength, int positiveOilLength) {
        if (negativeOilLength < 0 || positiveOilLength < 0) {
            throw new RuntimeException("Oil can't be negative");
        }
        this.negativeOilLength = negativeOilLength;
        this.positiveOilLength = positiveOilLength;
    }

    /**
     * @return <code>true</code> if has oil, <code>false</code> if negative oil
     * and positive oil are both zero.
     */
    public boolean hasNoOil() {
        return negativeOilLength == 0 && positiveOilLength == 0;
    }
}
