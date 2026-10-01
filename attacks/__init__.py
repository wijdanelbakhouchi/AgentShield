"""AgentShield propagation-attack benchmark package.

Components:
* ``schema``     — typed attack-sample model with research metadata.
* ``catalog``    — hand-authored attack templates (direct, indirect, tool,
                   exfiltration, tool abuse, and propagation payloads).
* ``transformations`` — deterministic adaptive-obfuscation pipelines.
* ``benchmark``  — deterministic dataset builder with train/test splits.
"""

from attacks.schema import AttackSample, InjectionPoint, AttackCategory

__all__ = ["AttackSample", "InjectionPoint", "AttackCategory"]