# Formal model

`pqs.spthy` (pqs = post-quantum stream, the working name) is a Tamarin model of QUILL with a Dolev-Yao attacker that also controls packet
loss. The ML-KEM key is modelled as public-key encryption of a fresh secret and X25519 as
Diffie-Hellman; `Quantum_DLog` and `Break_MLKEM` leak either gateway key at any time
(harvest now, decrypt later). The chain key is `chain(ck0, b)`; the attacker can step it
forward but not back. Batches carry two packets; the authenticator carries both leaves.

Tamarin 1.10.0, Maude 3.5. Each lemma is proved separately together with the two helper lemmas
(`prove-each.sh`); the outputs are in `out-<lemma>.txt` and the verdicts in `prove-each.log`.

| Lemma | Property |
|---|---|
| dev_state_origin, chain_key_index | helper lemmas (induction) |
| exec_loss | a batch with a lost packet still yields third-party evidence for the other |
| exec_judge | a disclosed record is accepted by a third party |
| session_auth | the gateway only accepts sessions the device started |
| session_secrecy_hndl | the session secret needs both the X25519 and the ML-KEM key broken |
| packet_secrecy | packets stay secret unless both keys are broken, the device state leaked at that batch or earlier, or that packet was disclosed |
| packet_key_secrecy | the attacker learns a packet key only if both gateway keys are broken, the device state leaked at that batch or earlier, or that key was disclosed |
| judge_sound | accepted evidence names a record the device really sent, whatever the gateway does |

Immediate packet authenticity at the gateway is not a separate lemma: in the symbolic model a
ciphertext under a key the attacker does not know can only come from the device, so it follows
from `packet_key_secrecy`. A direct mechanised proof did not terminate within 25 minutes.

The erasure code and the parity recovery are not in the symbolic model (they are linear algebra
over public values); the authenticator is modelled as carrying the leaves in clear, which gives
the attacker more, not less. Fragment encryption is likewise not modelled.
