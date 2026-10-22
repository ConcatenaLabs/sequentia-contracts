"""X3: the SeqDEX order, version 2 (`templates/seqdex_order_2`).

Version 2 is version 1 with one more rule: a spend carries no annex. This runs
X1 against it, every fill, refund and refusal of X1 again under the new
commitment root, and refuses a fill with an annex of 3 and of 1,000 bytes on
the order's input, in the mempool and in a block forced with `generateblock`,
beside the same fill without one. X1 offers the same annexed fills to version
1, whose mempool takes them."""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from x1_seqdex_order import X1  # noqa: E402


class X3(X1):
    NAME = "x3"
    TEMPLATE = "seqdex_order_2"
    ANNEX_REFUSED = True

    def set_test_params(self):
        X1.set_test_params(self)

    def run_test(self):
        X1.run_test(self)


if __name__ == "__main__":
    X3().main()
