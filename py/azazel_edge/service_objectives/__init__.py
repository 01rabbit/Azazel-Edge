"""Service-objective measurement harnesses owned by Azazel-Edge (Edge#414).

Each harness measures one row of the program plan's section 8 from outside the
code it measures and writes one JSON record (see ``record``). Measurement is
observation: nothing here decides, enforces, or changes arbiter behaviour, and
no target value is defined here -- the bounds are the assignment's.
"""

from .record import RECORD_SCHEMA, validate_record

__all__ = ["RECORD_SCHEMA", "validate_record"]
