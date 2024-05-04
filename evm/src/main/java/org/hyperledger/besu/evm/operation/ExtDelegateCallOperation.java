/*
 * Copyright contributors to Hyperledger Besu.
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
package org.hyperledger.besu.evm.operation;

import static org.hyperledger.besu.evm.internal.Words.clampedToLong;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.account.Account;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.internal.Words;

/** The Delegate call operation. */
public class ExtDelegateCallOperation extends AbstractCallOperation {

  /**
   * Instantiates a new Delegate call operation.
   *
   * @param gasCalculator the gas calculator
   */
  public ExtDelegateCallOperation(final GasCalculator gasCalculator) {
    super(0xF9, "EXTDELEGATECALL", 3, 1, gasCalculator);
  }

  @Override
  protected long gas(final MessageFrame frame) {
    return Long.MAX_VALUE;
  }

  @Override
  protected Address to(final MessageFrame frame) {
    return Words.toAddress(frame.getStackItem(0));
  }

  @Override
  protected Wei value(final MessageFrame frame) {
    return Wei.ZERO;
  }

  @Override
  protected Wei apparentValue(final MessageFrame frame) {
    return frame.getApparentValue();
  }

  @Override
  protected long inputDataOffset(final MessageFrame frame) {
    return clampedToLong(frame.getStackItem(1));
  }

  @Override
  protected long inputDataLength(final MessageFrame frame) {
    return clampedToLong(frame.getStackItem(2));
  }

  @Override
  protected long outputDataOffset(final MessageFrame frame) {
    return 0;
  }

  @Override
  protected long outputDataLength(final MessageFrame frame) {
    return 0;
  }

  @Override
  protected Address address(final MessageFrame frame) {
    return frame.getRecipientAddress();
  }

  @Override
  protected Address sender(final MessageFrame frame) {
    return frame.getSenderAddress();
  }

  @Override
  public long gasAvailableForChildCall(final MessageFrame frame) {
    return gasCalculator().gasAvailableForChildCall(frame, gas(frame), false);
  }

  @Override
  protected boolean isStatic(final MessageFrame frame) {
    return frame.isStatic();
  }

  @Override
  protected boolean isDelegate() {
    return true;
  }

  @Override
  public long cost(final MessageFrame frame, final boolean accountIsWarm) {
    final long inputDataOffset = inputDataOffset(frame);
    final long inputDataLength = inputDataLength(frame);
    final Account recipient = frame.getWorldUpdater().get(address(frame));

    return gasCalculator()
        .callOperationGasCost(
            frame,
            Long.MAX_VALUE,
            inputDataOffset,
            inputDataLength,
            0,
            0,
            Wei.ZERO,
            recipient,
            to(frame),
            accountIsWarm);
  }
}
