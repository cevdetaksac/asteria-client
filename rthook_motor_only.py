"""Mark the frozen asteria-client artifact as motor-only before client imports."""

import os

os.environ["ASTERIA_MOTOR_ONLY"] = "1"
