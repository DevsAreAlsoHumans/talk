"""Application de chat chiffré de bout en bout — backend FastAPI + Redis.

Le serveur ne manipule jamais de texte clair ni de clé privée : il ne stocke
que du ciphertext, des nonces et des clés de salon enveloppées (chiffrées pour
les membres cibles).
"""

__version__ = "0.1.0"
