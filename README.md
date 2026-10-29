# txtoken-rs

Transaction Tokens ([draft-ietf-oauth-transaction-tokens-11](https://www.ietf.org/archive/id/draft-ietf-oauth-transaction-tokens-11.txt)) en Rust: un Txn-Token Service (perfil de token exchange de RFC 8693), validación offline con JWKS cacheado y una cadena simulada de 5 microservicios donde se mide el costo por salto y el rechazo de tokens alterados.

Transaction Tokens in Rust: a Txn-Token Service (RFC 8693 token-exchange profile), offline validation against a cached JWKS, and a simulated 5-service call chain that measures the per-hop cost and the rejection of tampered tokens.

> **ES** primero · **EN** abajo. Nivel de verificación: **B** (ver abajo).

---

## ES

### Qué hay

| Módulo | Qué hace | Sección del draft |
|---|---|---|
| `tts` | Recibe el form `application/x-www-form-urlencoded` del token exchange y emite el Txn-Token. Valida `grant_type`, `requested_token_type`, `audience`, `scope`, `subject_token(_type)`. Acepta `access_token` (firmado por un AS externo), `self_signed` y `unsigned_json`; rechaza `refresh_token` y subject tokens vencidos. Recorta el scope a la política del workload. Respuesta con `token_type: N_A`, sin `refresh_token`. Errores con los códigos de RFC 6749 §5.2. | 6, 10, 11 |
| `verify` | Valida firma JWS, `typ: txntoken+jwt`, `alg` (sólo EdDSA; `none` y otros se rechazan), `kid`, `aud` = Trust Domain, `exp`, `iat` y los claims REQUIRED (`iat aud exp txn sub scope req_wl`). | 9, 12.2 |
| `jwks` | JWK OKP/Ed25519 y caché por `kid`. Ante un `kid` desconocido refresca una vez (rotación) con cooldown para que `kid` falsos no generen un fetch por request. | 13.11 |
| `chain` | Request con exactamente un header `Txn-Token`; cada salto valida y reenvía el token tal como lo recibió. Nueve modos de ataque desde un salto intermedio. | 12.1, 12.2 |

Firma: Ed25519 con `ed25519-dalek` (`verify_strict`). No hay RS256/ES256.

### Medición

Prerregistrada en [`PREREGISTRO.md`](PREREGISTRO.md) antes de la primera corrida. Reproducir:

```sh
cargo run --release --bin txtoken-bench -- --tx 5000 --tamper-n 1000 --seed 42
```

Dos corridas en la misma máquina (VM compartida, 8 vCPU Intel Xeon, sin aislar CPU), JSON completo en [`results/`](results/):

| Id | Métrica | Corrida 1 | Corrida 2 |
|---|---|---|---|
| M1 | Tamaño Txn-Token (con `tctx`/`rctx` de la Figura 4) / access token de entrada | 651 B / 354 B | 651 B / 354 B |
| M2 | Emisión (token exchange completo) p50 / p99 | 60.2 µs / 114.5 µs | 62.1 µs / 204.6 µs |
| M3 | Validación por salto p50 / p99 (25 000 validaciones) | 39.7 µs / 69.9 µs | 39.1 µs / 121.6 µs |
| M3 | Línea base (sólo extraer y reenviar el header) p50 | 0.14 µs | 0.15 µs |
| M4 | Fetches de JWKS durante la cadena tras el warm-up | 0 | 0 |
| M5 | Ataques rechazados en el salto siguiente | 9000 / 9000 | 9000 / 9000 |
| C+ | Cadenas sin alterar aceptadas en los 5 saltos | 5000 / 5000 | 5000 / 5000 |
| C− | Verificador sin chequeo de firma engañado (por modo, de 1000) | 7 modos con 1000/1000; `duplicate_header` y `cross_domain` 0 | igual |

Lectura: validar un Txn-Token cuesta ~39 µs por salto en p50 (casi todo es la verificación Ed25519); 5 saltos suman ~0.2 ms. El p99 varía entre corridas (70 vs 122 µs) por la máquina compartida. El control negativo muestra que el arnés detecta un verificador roto: los 7 modos que sólo atacan la firma pasan si no se chequea la firma; `duplicate_header` lo frena la regla de un solo header y `cross_domain` el chequeo de `aud`.

Modos de ataque (`chain::Tamper`): `tctx_value`, `tctx_add_field`, `sub_swap`, `scope_escalate` (payload cambiado, firma original), `resign_foreign_key` (re-firma con clave del atacante bajo el `kid` del TTS), `alg_none`, `splice_signature` (firma de otro token válido), `duplicate_header` (segundo header `Txn-Token`), `cross_domain` (token válido de otro Trust Domain).

### Tests

`cargo test`: 12 tests de integración en `tests/spec.rs`, ninguno ignorado. El CI (`.github/workflows/ci.yml`) corre `fmt --check`, `clippy -D warnings`, los tests y el benchmark con `--check`, que sale con 1 si no se cumple M4 = 0, M5 = 100 %, C+ = 100 % o C− ≥ 7 modos.

### Nivel de verificación

- **A**: compila, `clippy -D warnings` limpio, 12/12 tests.
- **B**: el mecanismo está medido (M1–M5) con controles positivo y negativo.
- **No B+ / C**: no hay comparación con otra implementación de Txn-Tokens ni carga real con red.

### Límites

- La cadena corre en **un solo proceso**: no hay HTTP real, ni TLS, ni red entre saltos. M3 es el costo de validar, no la latencia de red.
- La autenticación mutua workload↔TTS (§11.5) queda fuera: el TTS recibe la identidad del workload ya autenticada.
- Sólo EdDSA/Ed25519. Sin detección de replay por `txn` (§13.2), sin discovery del TTS (§13.7).
- El draft puede cambiar; esto sigue la revisión 11 (julio 2026). Sin pruebas de interoperabilidad con otras implementaciones.
- El primer commit declara módulos que llegan en los commits siguientes; compila desde CX9-03.

### Fuentes leídas

- draft-ietf-oauth-transaction-tokens-11, texto completo de las secciones 6, 9, 10, 11, 12 y 13.1–13.2: <https://www.ietf.org/archive/id/draft-ietf-oauth-transaction-tokens-11.txt>
- Búsqueda en la API de crates.io (`q=txn-token`, `q=transaction-tokens`, `q=transaction token`) el 2026-10-28: ningún crate emisor/verificador de Txn-Tokens. El único resultado para `txn-token`, [`wimsey-httpsig`](https://crates.io/api/v1/crates/wimsey-httpsig) 0.9.0, sólo incluye el header `Txn-Token` entre los componentes firmados con HTTP Message Signatures; no emite ni valida Txn-Tokens (README y `src/signature.rs` del crate leídos).

---

## EN

### What is here

- `tts`: token-exchange endpoint logic (draft §10–11). Validates every request parameter, accepts `access_token`, `self_signed` and `unsigned_json` subject tokens, refuses `refresh_token` and expired subject tokens (§6), narrows scope to workload policy, answers `token_type: N_A` without `refresh_token`, RFC 6749 §5.2 error codes.
- `verify`: §12.2 validation plus §9 header/claim rules; EdDSA only.
- `jwks`: OKP/Ed25519 JWKS cache with one refresh on unknown `kid` and a cooldown.
- `chain`: exactly-one `Txn-Token` header, forward-as-received, nine tamper modes.

### Measurement

Pre-registered in `PREREGISTRO.md`. Command: `cargo run --release --bin txtoken-bench -- --tx 5000 --tamper-n 1000 --seed 42`. Two runs on a shared 8-vCPU VM:

- Token size 651 B (input access token 354 B).
- Issuance p50 60–62 µs, p99 115–205 µs.
- Per-hop validation p50 39–40 µs, p99 70–122 µs; forward-only baseline 0.15 µs.
- JWKS fetches during the chain after warm-up: 0.
- Tampered tokens rejected at the next hop: 9000/9000. Positive control 5000/5000 accepted. Negative control (no signature check) fooled by the 7 signature-only modes 1000/1000 each.

### Verification level

**B**: builds, lint-clean, 12/12 tests, mechanism measured with positive and negative controls. Not B+ or C: no comparison with another Txn-Token implementation and no networked load.

### Limits

Single process (no HTTP, TLS or network between hops); workload↔TTS mutual auth out of scope; Ed25519 only; no `txn` replay cache; follows draft revision 11, which may change.

## License

Apache-2.0
