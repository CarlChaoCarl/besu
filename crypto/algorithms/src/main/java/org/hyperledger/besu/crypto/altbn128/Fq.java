/*
 * Copyright ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.altbn128;

import java.math.BigInteger;
import java.util.Objects;

import com.google.common.base.MoreObjects;
import org.apache.tuweni.bytes.Bytes;

/**
 * Adapted from the pc_ecc (Apache 2 License) implementation:
 * https://github.com/ethereum/py_ecc/blob/master/py_ecc/bn128/bn128_field_elements.py
 */
public class Fq implements FieldElement<Fq> {

  private static final BigInteger TWO = BigInteger.valueOf(2);

  /** "p" field parameter of F_p, F_p2, F_p6 and F_p12 */
  protected static final BigInteger P =
      new BigInteger(
          "21888242871839275222246405745257275088696311157297823662689037894645226208583");

  @SuppressWarnings("unused")
  private static final BigInteger REDUCER =
      new BigInteger(
          "115792089237316195423570985008687907853269984665640564039457584007913129639936");

  /** The number of bits in the {@link #REDUCER} value. */
  private static final int REDUCER_BITS = 256;

  /** A precomputed value of {@link #REDUCER}^2 mod {@link #P}. */
  private static final BigInteger REDUCER_SQUARED =
      new BigInteger(
          "3096616502983703923843567936837374451735540968419076528771170197431451843209");

  /** A precomputed value of {@link #REDUCER}^3 mod {@link #P}. */
  private static final BigInteger REDUCER_CUBED =
      new BigInteger(
          "14921786541159648185948152738563080959093619838510245177710943249661917737183");

  /** A precomputed value of -{@link #P}^{-1} mod {@link #REDUCER}. */
  private static final BigInteger FACTOR =
      new BigInteger(
          "111032442853175714102588374283752698368366046808579839647964533820976443843465");

  /**
   * The MASK value is set to 2^256 - 1 and is utilized to replace the operation % 2^256 with a
   * bitwise AND using this value. This choice ensures that only the lower 256 bits of a result are
   * retained, effectively simulating the modulus operation.
   */
  private static final BigInteger MASK =
      new BigInteger(
          "115792089237316195423570985008687907853269984665640564039457584007913129639935");

  /**
   * fq that represents 0.
   *
   * @return the fq
   */
  public static Fq zero() {
    return create(0);
  }

  /**
   * fq that represents 1.
   *
   * @return the fq
   */
  public static Fq one() {
    return create(1);
  }

  private final BigInteger n;

  /**
   * Create fq.
   *
   * @param n the n
   * @return the fq
   */
  public static Fq create(final BigInteger n) {
    return new Fq(toMontgomery(n));
  }

  /**
   * Create fq.
   *
   * @param n the n
   * @return the fq
   */
  static Fq create(final long n) {
    return create(BigInteger.valueOf(n));
  }

  private Fq(final BigInteger n) {
    this.n = n;
  }

  /**
   * To bytes.
   *
   * @return the bytes
   */
  public Bytes toBytes() {
    return Bytes.wrap((fromMontgomery(n)).toByteArray()).trimLeadingZeros();
  }

  @Override
  public boolean isZero() {
    return n.compareTo(BigInteger.ZERO) == 0;
  }

  @Override
  public boolean isValid() {
    BigInteger ret = fromMontgomery(n);
    return ret.compareTo(FIELD_MODULUS) < 0;
  }

  @Override
  public Fq add(final Fq other) {
    BigInteger r = n.add(other.n);
    return new Fq(r.compareTo(P) < 0 ? r : r.subtract(P));
  }

  @Override
  public Fq subtract(final Fq other) {
    BigInteger r = n.subtract(other.n);
    return new Fq(r.compareTo(BigInteger.ZERO) < 0 ? r.add(P) : r);
  }

  @Override
  public Fq multiply(final int val) {
    return multiply(new Fq(BigInteger.valueOf(val)));
  }

  @Override
  public Fq multiply(final Fq other) {
    return new Fq(redc(n.multiply(other.n)));
  }

  @Override
  public Fq divide(final Fq other) {
    BigInteger r = redc(other.n.modInverse(P).multiply(REDUCER_CUBED));
    return new Fq(redc(n.multiply(r)));
  }

  /*
   private BigInteger inverse(final BigInteger a, final BigInteger n) {
     if (a.compareTo(BigInteger.ZERO) == 0) {
       return BigInteger.ZERO;
     }
     BigInteger lm = BigInteger.ONE;
     BigInteger hm = BigInteger.ZERO;
     BigInteger low = a.mod(n);
     BigInteger high = n;
     while (low.compareTo(BigInteger.ONE) > 0) {
       final BigInteger r = high.divide(low);
       final BigInteger nm = hm.subtract(lm.multiply(r));
       final BigInteger neww = high.subtract(low.multiply(r));
       high = low;
       hm = lm;
       low = neww;
       lm = nm;
     }
     return lm.mod(n);
   }
  */

  @Override
  public Fq negate() {
    return new Fq(n.negate().mod(P));
  }

  @Override
  public Fq power(final int n) {
    if (n == 0) {
      return one();
    } else if (n == 1) {
      return this;
    } else if (n % 2 == 0) {
      return multiply(this).power(n / 2);
    } else {
      return multiply(this).power(n / 2).multiply(this);
    }
  }

  @Override
  public Fq power(final BigInteger n) {
    if (n.compareTo(BigInteger.ZERO) == 0) {
      return one();
    }
    if (n.compareTo(BigInteger.ONE) == 0) {
      return this;
    } else if (n.mod(TWO).compareTo(BigInteger.ZERO) == 0) {
      return multiply(this).power(n.divide(TWO));
    } else {
      return multiply(this).power(n.divide(TWO)).multiply(this);
    }
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(Fq.class).add("n", n).toString();
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(n);
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof Fq)) {
      return false;
    }

    final Fq other = (Fq) obj;
    return n.compareTo(other.n) == 0;
  }

  private static BigInteger toMontgomery(final BigInteger n) {
    return redc(n.multiply(REDUCER_SQUARED));
  }

  private static BigInteger fromMontgomery(final BigInteger n) {
    return redc(n);
  }

  private static BigInteger redc(final BigInteger x) {
    BigInteger temp = x.multiply(FACTOR).and(MASK);
    BigInteger reduced = temp.multiply(P).add(x).shiftRight(REDUCER_BITS);
    return reduced.compareTo(P) < 0 ? reduced : reduced.subtract(P);
  }
}
