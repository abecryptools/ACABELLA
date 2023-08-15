=== High-level description of the code structure based on their functionality ===

** General use **

- parse_config
- common
- access_structures
- encodings_helper

** Cryptanalysis **

- master_key
- decryption
- conditional
- attack
- analysis

** Proof generation and verification **
(Note that this functionality only works for schemes satisfying the AC17 structure.)

- security_analysis_ac17
  - ac17_correctness_checks
  - trivial_security_and_collusion
  - security_proof
    - proof_generation
    - proof_verification

Note: nice to have the trivial security and collusion check for other schemes. 
I see no reason why this functionality cannot work for schemes that don't have the 
desired structure. 